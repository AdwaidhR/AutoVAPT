"""
Endpoint Discovery Module
----------------------------
Builds a scoped endpoint inventory from data already collected by the crawler,
HTML forms, JavaScript static analysis, robots.txt, and sitemap.xml.

Important: URLs discovered in JavaScript are classified against the original
target boundary. Same-host + same-application-path references are target
endpoints; third-party/external references are retained separately for
visibility and are never counted as target endpoints.
"""
import re
from urllib.parse import urlparse, parse_qs, urljoin, urldefrag


def _extract_params(url):
    try:
        return sorted(parse_qs(urlparse(url).query).keys())
    except Exception:
        return []


def _scope_path(target_url):
    path = urlparse(target_url).path or "/"
    return path if path.endswith("/") else path + "/"


def _normalize(target_url, value):
    if not value:
        return None
    value = value.strip()
    if value.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
        return None
    joined = urljoin(target_url, value)
    joined, _ = urldefrag(joined)
    return joined


def _in_scope(url, target_url):
    try:
        target = urlparse(target_url)
        candidate = urlparse(url)
        if not candidate.hostname or candidate.hostname.lower() != (target.hostname or "").lower():
            return False
        # Keep the same explicit port when either URL specifies one.
        if target.port != candidate.port and (target.port is not None or candidate.port is not None):
            return False
        scope = _scope_path(target_url)
        path = candidate.path or "/"
        return scope == "/" or path == scope.rstrip("/") or path.startswith(scope)
    except Exception:
        return False


def run(crawl_result=None, js_findings=None, robots_text=None, sitemap_text=None, target_url=None):
    endpoints = {}  # key: (url, method) -> record
    external = {}   # key: URL -> record
    target_url = target_url or (crawl_result or {}).get("base_url") or ""

    def add_external(url, source, reason="outside the assessment target"):
        if not url:
            return
        record = external.setdefault(url, {"url": url, "source": [], "reason": reason})
        if source not in record["source"]:
            record["source"].append(source)

    def add(value, method="GET", source="unknown", params=None, content_type=None, base=None):
        if not value:
            return
        url = _normalize(base or target_url, value) if target_url else value
        if not url:
            return
        if target_url and not _in_scope(url, target_url):
            add_external(url, source)
            return
        key = (url, method.upper())
        if key not in endpoints:
            endpoints[key] = {
                "url": url, "method": method.upper(), "source": [source],
                "parameters": params or _extract_params(url),
                "content_type": content_type,
            }
        else:
            if source not in endpoints[key]["source"]:
                endpoints[key]["source"].append(source)
            if params:
                endpoints[key]["parameters"] = sorted(set(endpoints[key]["parameters"]) | set(params))

    if crawl_result:
        for page in crawl_result.get("pages", []):
            add(page.get("url"), "GET", source="crawl")
        for form in crawl_result.get("forms", []):
            param_names = [i["name"] for i in form.get("inputs", []) if i.get("name")]
            add(form.get("action_resolved") or form.get("action", ""),
                form.get("method", "GET"), source="html_form", params=param_names,
                base=form.get("page") or target_url)
        # Crawler already restricts scripts to its scope. Keep this defensive
        # check so endpoint discovery cannot accidentally reintroduce external JS.
        for script_url in crawl_result.get("scripts", []):
            add(script_url, "GET", source="script_src")

    if js_findings:
        for jf in js_findings.get("files", []):
            js_base = jf.get("url") or target_url
            for path in jf.get("endpoints_found", []):
                add(path, "GET", source=f"javascript:{js_base}", base=js_base)
            for ref in jf.get("external_references", []):
                add_external(ref, f"javascript:{js_base}")

    if robots_text:
        for line in robots_text.splitlines():
            line = line.strip()
            if line.lower().startswith(("disallow:", "allow:")):
                path = line.split(":", 1)[1].strip()
                if path:
                    add(path, "GET", source="robots.txt")

    if sitemap_text:
        for loc in re.findall(r"<loc>\s*(.*?)\s*</loc>", sitemap_text, re.IGNORECASE | re.DOTALL):
            add(loc.strip(), "GET", source="sitemap.xml")

    result_list = list(endpoints.values())
    external_list = list(external.values())
    return {
        "total_endpoints": len(result_list),
        "endpoints": sorted(result_list, key=lambda e: e["url"]),
        "external_references": sorted(external_list, key=lambda e: e["url"]),
        "total_external_references": len(external_list),
    }
