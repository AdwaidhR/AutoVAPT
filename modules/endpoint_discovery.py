"""
Endpoint Discovery Module
----------------------------
Aggregates a de-duplicated endpoint inventory from every source the
framework already collected: crawled pages, HTML forms, JavaScript
static analysis, robots.txt, and sitemap.xml. Pure data-shuffling -
no new network requests are made here.
"""
import re
from urllib.parse import urlparse, parse_qs


def _extract_params(url):
    try:
        return sorted(parse_qs(urlparse(url).query).keys())
    except Exception:
        return []


def run(crawl_result=None, js_findings=None, robots_text=None, sitemap_text=None):
    endpoints = {}  # key: (url, method) -> record

    def add(url, method="GET", source="unknown", params=None, content_type=None):
        if not url:
            return
        key = (url, method)
        if key not in endpoints:
            endpoints[key] = {
                "url": url, "method": method, "source": [source],
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
            add(page["url"], "GET", source="crawl")
        for form in crawl_result.get("forms", []):
            param_names = [i["name"] for i in form.get("inputs", []) if i.get("name")]
            add(form.get("action_resolved") or form.get("action", ""),
                form.get("method", "GET").upper(), source="html_form", params=param_names)
        for script_url in crawl_result.get("scripts", []):
            add(script_url, "GET", source="script_src")

    if js_findings:
        for jf in js_findings.get("files", []):
            for path in jf.get("endpoints_found", []):
                add(path, "GET", source=f"javascript:{jf.get('url', '')}")

    if robots_text:
        for line in robots_text.splitlines():
            line = line.strip()
            if line.lower().startswith(("disallow:", "allow:")):
                path = line.split(":", 1)[1].strip()
                if path:
                    add(path, "GET", source="robots.txt")

    if sitemap_text:
        for loc in re.findall(r"<loc>(.*?)</loc>", sitemap_text, re.IGNORECASE):
            add(loc.strip(), "GET", source="sitemap.xml")

    result_list = list(endpoints.values())
    return {
        "total_endpoints": len(result_list),
        "endpoints": sorted(result_list, key=lambda e: e["url"]),
    }
