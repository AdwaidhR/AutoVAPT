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
from urllib.parse import urlparse
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

SENSITIVE_PATTERNS = [
    (r"(?i)api[_-]?key\s*[:=]\s*[\"'][a-zA-Z0-9_\-]{10,}[\"']", "Possible API key reference"),
    (r"(?i)secret\s*[:=]\s*[\"'][a-zA-Z0-9_\-]{6,}[\"']", "Possible secret/config reference"),
    (r"(?i)aws_access_key_id", "Possible AWS credential reference"),
    (r"(?i)authorization\s*[:=]\s*[\"']bearer", "Hardcoded Authorization/Bearer reference"),
    (r"(?i)password\s*[:=]\s*[\"'][^\"']{3,}[\"']", "Possible hardcoded password reference"),
]

MAX_JS_FILES = 15
MAX_JS_BYTES = 500_000


def _analyze_single(url):
    r = fetch(url, max_body_bytes=MAX_JS_BYTES)
    record = {"url": url, "fetched": r.ok, "endpoints_found": [], "sensitive_indicators": []}
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
    record["endpoints_found"] = sorted(found)[:100]  # cap noise

    for pattern, label in SENSITIVE_PATTERNS:
        if re.search(pattern, text):
            record["sensitive_indicators"].append({
                "label": label,
                "category": "Potential sensitive client-side reference",
                "manual_verification_required": True,
            })

    return record


def run(script_urls):
    script_urls = list(dict.fromkeys(script_urls or []))[:MAX_JS_FILES]  # dedupe, cap
    files = [_analyze_single(u) for u in script_urls]

    all_endpoints = sorted({e for f in files for e in f.get("endpoints_found", [])})
    all_sensitive = [
        {"file": f["url"], **s} for f in files for s in f.get("sensitive_indicators", [])
    ]

    return {
        "files_analyzed": len(files),
        "files": files,
        "unique_endpoints_found": all_endpoints,
        "sensitive_indicators": all_sensitive,
    }
