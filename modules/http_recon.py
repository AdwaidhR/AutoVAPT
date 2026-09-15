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
import urllib.parse
import urllib.error
import subprocess
import tempfile
import os
import shutil
from pathlib import Path
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
        else:
            d["body_excerpt"] = self.body[:200_000]
        return d


class _RedirectRecorder(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        self.chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append({"status": code, "location": newurl})
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch_with_curl(url, method, timeout, max_body_bytes, allow_redirects, headers):
    """Best-effort external fallback for targets that behave differently with urllib.

    Curl is optional. This fallback is deliberately used only after urllib fails,
    and a second attempt bypasses inherited proxy settings because public lab
    targets can reject scanner/proxy connection paths while remaining reachable
    directly.
    """
    if not shutil.which("curl"):
        return None
    try:
        with tempfile.TemporaryDirectory(prefix="autovapt-fetch-") as td:
            hdr = os.path.join(td, "headers")
            body = os.path.join(td, "body")
            cmd = ["curl", "-k", "-sS", "--max-time", str(max(1, int(timeout))),
                   "-A", headers.get("User-Agent", USER_AGENT), "-D", hdr, "-o", body]
            if method != "GET":
                cmd += ["-X", method]
            if allow_redirects:
                cmd.append("-L")
            else:
                cmd.append("--max-redirs")
                cmd.append("0")
            # First respect the environment, then retry direct if necessary.
            attempts = [cmd, cmd + ["--noproxy", "*"]]
            last_err = "curl failed"
            for attempt in attempts:
                try:
                    proc = subprocess.run(attempt + [url], capture_output=True, text=False,
                                          timeout=max(2, int(timeout) + 2))
                except Exception as exc:
                    last_err = str(exc)
                    continue
                if proc.returncode != 0:
                    last_err = proc.stderr.decode("utf-8", "ignore")[:300] or f"curl exit {proc.returncode}"
                    continue
                try:
                    raw_headers = Path(hdr).read_text(errors="ignore")
                except Exception:
                    raw_headers = ""
                try:
                    data = Path(body).read_bytes()[:max_body_bytes]
                except Exception:
                    data = b""
                # With redirects, curl writes multiple response header blocks.
                blocks = re.split(r"\r?\n\r?\n", raw_headers.strip())
                last = blocks[-1] if blocks else ""
                lines = last.splitlines()
                status = None
                response_headers = {}
                for line in lines:
                    if line.startswith("HTTP/"):
                        parts = line.split(None, 2)
                        if len(parts) >= 2 and parts[1].isdigit():
                            status = int(parts[1])
                    elif ":" in line:
                        k, v = line.split(":", 1)
                        response_headers[k.strip()] = v.strip()
                if status is None:
                    return None
                r = FetchResult()
                r.ok = True
                r.status = status
                r.final_url = url
                r.headers = response_headers
                r.body_bytes = data
                r.body = data.decode("utf-8", errors="ignore")
                return r
            vlog(f"curl fallback for {url} failed: {last_err}")
    except Exception as exc:
        vlog(f"curl fallback error for {url}: {exc}")
    return None


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
    req = urllib.request.Request(url, method=method, headers=headers)
    start = time.time()
    try:
        if allow_redirects:
            opener = urllib.request.build_opener(
                redirector, urllib.request.HTTPSHandler(context=_INSECURE_CTX),
            )
        else:
            # Neuter redirects by using a handler that raises instead of following.
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **kw):
                    return None
            opener = urllib.request.build_opener(
                NoRedirect(), urllib.request.HTTPSHandler(context=_INSECURE_CTX),
            )
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

    # Public lab targets occasionally reject urllib's connection path while
    # accepting curl. Keep urllib as the core client and use curl only as a
    # bounded compatibility fallback.
    if not result.ok:
        fallback = _fetch_with_curl(url, method, timeout, max_body_bytes, allow_redirects, headers)
        if fallback is not None:
            fallback.error = None
            fallback.elapsed_ms = round((time.time() - start) * 1000, 1)
            return fallback

    return result


def _try_scheme(host_or_url):
    """Given a bare host or a full URL, return list of candidate base URLs to try."""
    if host_or_url.startswith("http://") or host_or_url.startswith("https://"):
        # Preserve the full URL exactly, including a trailing slash that can
        # be significant for application context paths such as /WebGoat/.
        return [host_or_url]
    return [f"https://{host_or_url}", f"http://{host_or_url}"]


def probe_scheme(target):
    """Try candidate schemes while preserving any application path."""
    last = None
    for base in _try_scheme(target):
        r = fetch(base)
        last = r
        if r.ok:
            parsed = urllib.parse.urlparse(base)
            # Keep the original path as the application scope. A redirect to
            # /WebGoat/login should not turn /WebGoat/ into /.
            path = parsed.path or "/"
            if not path.startswith("/"):
                path = "/" + path
            preserved = f"{parsed.scheme}://{parsed.netloc}{path}"
            if parsed.params:
                preserved += ";" + parsed.params
            if parsed.query:
                preserved += "?" + parsed.query
            return preserved, r
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
    parsed_target = urllib.parse.urlparse(target if target.startswith(("http://", "https://")) else f"{scheme}://{target}")
    other_scheme = "http" if scheme.startswith("https") else "https"
    other_target = f"{other_scheme}://{parsed_target.netloc}{parsed_target.path or '/'}"
    if parsed_target.query:
        other_target += "?" + parsed_target.query
    other_result = fetch(other_target)
    result[other_scheme] = other_result.to_dict()

    app_root = base_url.rstrip("/") + "/"
    for path, key in [("robots.txt", "robots_txt"), ("sitemap.xml", "sitemap_xml"),
                       (".well-known/security.txt", "security_txt")]:
        r = fetch(urllib.parse.urljoin(app_root, path))
        if r.ok and r.status == 200:
            result[key] = {"status": r.status, "size": len(r.body_bytes),
                            "excerpt": r.body[:500]}
        else:
            result[key] = {"status": r.status, "found": False}

    return result
