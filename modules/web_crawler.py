"""
Web Crawler Module
---------------------
A deliberately bounded, same-host crawler built on html.parser (stdlib)
- no BeautifulSoup, no Scrapy. Stays within --max-pages and
--crawl-depth by design; this is a recon aid, not a scraper.
"""
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urldefrag
from collections import deque
from .http_recon import fetch
from .utils import vlog

DEFAULT_MAX_PAGES = 50
DEFAULT_MAX_DEPTH = 2


class PageParser(HTMLParser):
    """Extracts links, forms, scripts, images, and stylesheets from one page."""

    def __init__(self):
        super().__init__()
        self.links = []
        self.forms = []
        self.scripts = []
        self.images = []
        self.stylesheets = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        elif tag == "script" and attrs.get("src"):
            self.scripts.append(attrs["src"])
        elif tag == "img" and attrs.get("src"):
            self.images.append(attrs["src"])
        elif tag == "link" and attrs.get("rel") == "stylesheet" and attrs.get("href"):
            self.stylesheets.append(attrs["href"])
        elif tag == "form":
            self._current_form = {
                "action": attrs.get("action", ""),
                "method": attrs.get("method", "get").upper(),
                "inputs": [],
            }
            self.forms.append(self._current_form)
        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": attrs.get("name", ""), "type": attrs.get("type", tag),
            })

    def handle_endtag(self, tag):
        if tag == "form":
            self._current_form = None


def _normalize(base_url, link):
    if not link or link.startswith(("javascript:", "mailto:", "tel:", "#")):
        return None
    joined = urljoin(base_url, link)
    joined, _ = urldefrag(joined)  # strip #fragment
    return joined


def _same_host(url, host):
    try:
        return urlparse(url).netloc.split(":")[0] == host
    except Exception:
        return False


def run(base_url, max_pages=DEFAULT_MAX_PAGES, max_depth=DEFAULT_MAX_DEPTH):
    host = urlparse(base_url).netloc.split(":")[0]
    visited = set()
    queue = deque([(base_url, 0)])
    pages = []
    all_forms, all_scripts = [], []
    errors = []

    while queue and len(visited) < max_pages:
        url, depth = queue.popleft()
        if url in visited or depth > max_depth:
            continue
        visited.add(url)

        r = fetch(url)
        if not r.ok:
            errors.append({"url": url, "error": r.error})
            continue

        content_type = r.headers.get("Content-Type", "")
        page_record = {
            "url": url, "status": r.status, "content_type": content_type,
            "depth": depth,
        }

        if "text/html" in content_type or content_type == "":
            parser = PageParser()
            try:
                parser.feed(r.body[:500_000])
            except Exception as e:
                vlog(f"HTML parse failed for {url}: {e}")
                pages.append(page_record)
                continue

            normalized_links = []
            for link in parser.links:
                n = _normalize(url, link)
                if n and _same_host(n, host):
                    normalized_links.append(n)
                    if n not in visited and len(visited) + len(queue) < max_pages:
                        queue.append((n, depth + 1))

            page_record["links_found"] = len(normalized_links)
            page_record["forms"] = parser.forms
            page_record["scripts"] = [_normalize(url, s) for s in parser.scripts if _normalize(url, s)]

            for form in parser.forms:
                all_forms.append({**form, "page": url,
                                   "action_resolved": _normalize(url, form["action"]) or url})
            for s in page_record["scripts"]:
                if s not in all_scripts:
                    all_scripts.append(s)

        pages.append(page_record)

    return {
        "base_url": base_url, "host": host,
        "pages_crawled": len(pages), "max_pages": max_pages, "max_depth": max_depth,
        "pages": pages, "forms": all_forms, "scripts": all_scripts,
        "errors": errors,
    }
