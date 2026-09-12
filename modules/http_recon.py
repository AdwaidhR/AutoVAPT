"""
HTTP/HTTPS Reconnaissance Module
------------------------------------
Every HTTP capability here (fetch, headers, redirect chain, cookies) is
built on `urllib.request` + `http.client` + `html.parser` from the
standard library - no `requests` dependency.

A tiny internal HTTP client (`fetch()`) is shared by this module, the
crawler, the directory brute-forcer, and the vulnerability scanner, so
timeout/redirect/TLS-error handling is consistent everywhere.
"""
import re
import ssl
import time
import socket
import http.client
import urllib.request
import urllib.error
from html.parser import HTMLParser
from .utils import vlog

DEFAULT_TIMEOUT = 8
USER_AGENT = "AutoVAPT/2.0 (+authorized security assessment)"

# Unverified context: lab targets and self-signed certs are extremely
# common in authorized testing; we still *report* cert problems
# separately in tls_analyzer.py rather than silently ignoring them.
_INSECURE_CTX = ssl.create_default_context()
_INSECURE_CTX.check_hostname = False
_INSECURE_CTX.verify_mode = ssl.CERT_NONE


class TitleParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_title = False
        self.title = ""

    def handle_starttag(self, tag, attrs):
        if tag == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title += data


def extract_title(html_text):
    try:
        parser = TitleParser()
        parser.feed(html_text[:20000])  # cap parse size
        return parser.title.strip()[:200]
    except Exception:
        return ""


class FetchResult:
    def __init__(self):
        self.ok = False
        self.status = None
        self.final_url = None
        self.headers = {}
        self.body = ""
        self.body_bytes = b""
        self.redirect_chain = []
        self.error = None
        self.elapsed_ms = None

    def to_dict(self, include_body=False):
        d = {
            "ok": self.ok, "status": self.status, "final_url": self.final_url,
            "headers": self.headers, "redirect_chain": self.redirect_chain,
            "error": self.error, "elapsed_ms": self.elapsed_ms,
            "content_length": len(self.body_bytes),
            "title": extract_title(self.body) if self.body else "",
        }
        if include_body:
            d["body"] = self.body
        return d


class _RedirectRecorder(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        self.chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append({"status": code, "location": newurl})
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, method="GET", timeout=DEFAULT_TIMEOUT, max_body_bytes=1_500_000,
          allow_redirects=True, extra_headers=None):
    """
    Single shared HTTP client for the whole framework. Never raises -
    all failure modes (DNS, TLS, timeout, connection refused, malformed
    response) are captured into FetchResult.error so callers can
    continue their scan.
    """
    result = FetchResult()
    headers = {"User-Agent": USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)

    redirector = _RedirectRecorder()
    opener = urllib.request.build_opener(
        redirector,
        urllib.request.HTTPSHandler(context=_INSECURE_CTX),
    )
    if not allow_redirects:
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=_INSECURE_CTX),
        )
        # Neuter redirects by using a handler that raises instead of following
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **kw):
                return None
        opener = urllib.request.build_opener(
            NoRedirect(), urllib.request.HTTPSHandler(context=_INSECURE_CTX),
        )

    req = urllib.request.Request(url, method=method, headers=headers)
    start = time.time()
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(max_body_bytes)
            result.ok = True
            result.status = resp.status
            result.final_url = resp.geturl()
            result.headers = dict(resp.headers.items())
            result.body_bytes = body
            result.body = body.decode(resp.headers.get_content_charset() or "utf-8",
                                       errors="ignore")
            result.redirect_chain = redirector.chain
    except urllib.error.HTTPError as e:
        # HTTPError is still a real response (401, 403, 404, 500...)
        result.status = e.code
        result.final_url = e.geturl() if hasattr(e, "geturl") else url
        result.headers = dict(e.headers.items()) if e.headers else {}
        try:
            body = e.read(max_body_bytes)
            result.body_bytes = body
            result.body = body.decode("utf-8", errors="ignore")
        except Exception:
            pass
        result.ok = True  # got a real HTTP response, just non-2xx
        result.redirect_chain = redirector.chain
    except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
        result.error = f"{type(e).__name__}: {getattr(e, 'reason', e)}"
        vlog(f"fetch({url}) failed: {result.error}")
    except (http.client.HTTPException, ssl.SSLError, ConnectionError, OSError) as e:
        result.error = f"{type(e).__name__}: {e}"
        vlog(f"fetch({url}) failed: {result.error}")
    except Exception as e:
        result.error = f"Unexpected error: {e}"
        vlog(f"fetch({url}) failed: {result.error}")
    finally:
        result.elapsed_ms = round((time.time() - start) * 1000, 1)

    return result


def _try_scheme(host_or_url):
    """Given a bare host or a full URL, return list of candidate base URLs to try."""
    if host_or_url.startswith("http://") or host_or_url.startswith("https://"):
        return [host_or_url.rstrip("/")]
    return [f"https://{host_or_url}", f"http://{host_or_url}"]


def probe_scheme(target):
    """Try https first, then http. Returns (working_base_url, FetchResult) or (None, last_error_result)."""
    last = None
    for base in _try_scheme(target):
        r = fetch(base)
        last = r
        if r.ok:
            return base.split("://")[0] + "://" + base.split("://")[1].split("/")[0], r
    return None, last


def run(target):
    result = {
        "target": target, "http": None, "https": None,
        "working_base_url": None, "robots_txt": None,
        "sitemap_xml": None, "security_txt": None,
    }

    scheme, primary = probe_scheme(target)
    base_url = None
    if scheme:
        base_url = scheme
        result["working_base_url"] = base_url
        result[scheme.split("://")[0]] = primary.to_dict()
    else:
        result["error"] = primary.error if primary else "Both http:// and https:// failed"
        return result

    # Also record the *other* scheme's result for comparison (e.g. does
    # http redirect to https, or is it not listening at all)
    other_scheme = "http" if scheme.startswith("https") else "https"
    other_host = target.split("://")[-1]
    other_result = fetch(f"{other_scheme}://{other_host}")
    result[other_scheme] = other_result.to_dict()

    for path, key in [("/robots.txt", "robots_txt"), ("/sitemap.xml", "sitemap_xml"),
                       ("/.well-known/security.txt", "security_txt")]:
        r = fetch(base_url.rstrip("/") + path)
        if r.ok and r.status == 200:
            result[key] = {"status": r.status, "size": len(r.body_bytes),
                            "excerpt": r.body[:500]}
        else:
            result[key] = {"status": r.status, "found": False}

    return result
