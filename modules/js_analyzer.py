"""
JavaScript Static Analysis Module
-------------------------------------
Downloads same-origin JS files already discovered by the crawler and
runs regex-based pattern matching to surface interesting endpoints and
possible sensitive references. JavaScript is NEVER executed - this is
purely textual/static analysis, matching what Nuclei/LinkFinder-style
tools do without a headless browser.
"""
import re
from urllib.parse import urlparse, urljoin
from .http_recon import fetch

ENDPOINT_PATTERNS = [
    r"[\"'](/api/[a-zA-Z0-9_\-/{}]*)[\"']",
    r"[\"'](/api/v\d+/[a-zA-Z0-9_\-/{}]*)[\"']",
    r"[\"'](/graphql[a-zA-Z0-9_\-/]*)[\"']",
    r"[\"'](/(login|logout|auth|register)[a-zA-Z0-9_\-/]*)[\"']",
    r"[\"'](/admin[a-zA-Z0-9_\-/]*)[\"']",
    r"[\"'](/user[a-zA-Z0-9_\-/]*)[\"']",
    r"[\"'](/(upload|download)[a-zA-Z0-9_\-/]*)[\"']",
    r"[\"'](/debug[a-zA-Z0-9_\-/]*)[\"']",
    r"(wss?://[a-zA-Z0-9_\-./:]+)",
    r"(https?://[a-zA-Z0-9_\-./:%?=&]+)",
]

# The patterns above only match when the interesting keyword (api/,
# login, admin, ...) appears immediately after the opening quote. Real
# applications are frequently mounted under a context/app path (e.g.
# WebGoat serves "/WebGoat/api/v1/..." not "/api/v1/..."), so a
# root-anchored pattern silently misses every one of those endpoints -
# no error, just quietly incomplete results. This second pattern set
# matches the same keywords anywhere inside a quoted absolute path, so
# app-prefixed endpoints are found too.
ANY_QUOTED_PATH = r"[\"'](/[a-zA-Z0-9_\-./{}]*)[\"']"
INTERESTING_SEGMENT = re.compile(
    r"/(api(/v\d+)?|graphql|login|logout|auth|register|admin|user|upload|download|debug)(/|$|[\"'])",
    re.IGNORECASE,
)

SENSITIVE_PATTERNS = [
    (r"(?i)api[_-]?key\s*[:=]\s*[\"'][a-zA-Z0-9_\-]{10,}[\"']", "Possible API key reference"),
    (r"(?i)secret\s*[:=]\s*[\"'][a-zA-Z0-9_\-]{6,}[\"']", "Possible secret/config reference"),
    (r"(?i)aws_access_key_id", "Possible AWS credential reference"),
    (r"(?i)authorization\s*[:=]\s*[\"']bearer", "Hardcoded Authorization/Bearer reference"),
    (r"(?i)password\s*[:=]\s*[\"'][^\"']{3,}[\"']", "Possible hardcoded password reference"),
]

MAX_JS_FILES = 15
MAX_JS_BYTES = 500_000


def _scope_path(target_url):
    path = urlparse(target_url).path or "/"
    return path if path.endswith("/") else path + "/"


def _in_scope(url, target_url):
    try:
        target = urlparse(target_url)
        candidate = urlparse(url)
        if (candidate.hostname or "").lower() != (target.hostname or "").lower():
            return False
        if target.port != candidate.port and (target.port is not None or candidate.port is not None):
            return False
        scope = _scope_path(target_url)
        path = candidate.path or "/"
        return scope == "/" or path == scope.rstrip("/") or path.startswith(scope)
    except Exception:
        return False


def _normalize(value, base_url):
    if not value:
        return None
    try:
        return urljoin(base_url, value)
    except Exception:
        return value


def _analyze_single(url):
    r = fetch(url, max_body_bytes=MAX_JS_BYTES)
    record = {"url": url, "fetched": r.ok, "endpoints_found": [], "external_references": [], "sensitive_indicators": []}
    if not r.ok:
        record["error"] = r.error
        return record

    text = r.body
    found = set()
    for pattern in ENDPOINT_PATTERNS:
        for match in re.findall(pattern, text):
            m = match if isinstance(match, str) else match[0]
            if m and len(m) < 300:
                found.add(m)

    # Second pass: catch the same keywords when they appear anywhere
    # inside a quoted absolute path, not just immediately after the
    # opening quote - this is what makes app-prefixed endpoints like
    # "/WebGoat/api/v1/session" or "/App/login" detectable.
    for match in re.findall(ANY_QUOTED_PATH, text):
        if match and len(match) < 300 and INTERESTING_SEGMENT.search(match + "\""):
            found.add(match)

    record["endpoints_found"] = sorted(found)[:100]  # cap noise

    for pattern, label in SENSITIVE_PATTERNS:
        if re.search(pattern, text):
            record["sensitive_indicators"].append({
                "label": label,
                "category": "Potential sensitive client-side reference",
                "manual_verification_required": True,
            })

    return record


def run(script_urls, target_url=None):
    script_urls = list(dict.fromkeys(script_urls or []))[:MAX_JS_FILES]  # dedupe, cap
    files = [_analyze_single(u) for u in script_urls]

    all_endpoints = []
    all_external = []
    for f in files:
        if target_url:
            scoped = set()
            external = set()
            for raw in f.get("endpoints_found", []):
                resolved = _normalize(raw, f.get("url") or target_url)
                if resolved and _in_scope(resolved, target_url):
                    scoped.add(resolved)
                elif resolved:
                    external.add(resolved)
            f["endpoints_found"] = sorted(scoped)[:100]
            f["external_references"] = sorted(external)[:100]
        all_endpoints.extend(f.get("endpoints_found", []))
        all_external.extend(f.get("external_references", []))
    all_endpoints = sorted(set(all_endpoints))
    all_external = sorted(set(all_external))
    all_sensitive = [
        {"file": f["url"], **s} for f in files for s in f.get("sensitive_indicators", [])
    ]

    return {
        "files_analyzed": len(files),
        "files": files,
        "unique_endpoints_found": all_endpoints,
        "external_references": all_external,
        "total_external_references": len(all_external),
        "sensitive_indicators": all_sensitive,
    }
