"""
Subdomain Enumeration Module
--------------------------------
Two passive/light-active methods, both stdlib-only:

1. Certificate Transparency logs via crt.sh (urllib.request, JSON) -
   fully passive, no packets sent to the target at all.
2. Built-in common-name wordlist resolution (socket.getaddrinfo) - a
   short, curated list, not an aggressive brute force. No external
   wordlist file is required (ships in wordlists/subdomains.txt but
   falls back to an embedded list if that file is missing).
"""
import json
import socket
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from .http_recon import fetch
from .utils import vlog

CRTSH_URL = "https://crt.sh/?q=%25.{}&output=json"
TIMEOUT = 15

BUILTIN_SUBDOMAIN_LIST = [
    "www", "api", "dev", "test", "staging", "mail", "smtp", "ftp", "admin",
    "portal", "vpn", "blog", "cdn", "static", "assets", "app", "auth",
    "login", "dashboard", "support", "docs", "status", "m", "mobile",
    "webmail", "ns1", "ns2", "shop", "store", "beta", "demo", "secure",
]


def _crtsh_lookup(domain):
    url = CRTSH_URL.format(domain)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AutoVAPT/2.0"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            if resp.status != 200:
                return set(), f"crt.sh returned HTTP {resp.status}"
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        vlog(f"crt.sh lookup failed: {e}")
        return set(), f"crt.sh unreachable: {e}"
    except json.JSONDecodeError:
        return set(), "crt.sh returned invalid JSON (rate-limited or offline)"

    found = set()
    for entry in data:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower()
            if name and "*" not in name and name.endswith(domain):
                found.add(name)
    return found, None


def _load_wordlist(path):
    try:
        with open(path) as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        return BUILTIN_SUBDOMAIN_LIST


def _resolve_and_probe(hostname):
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

    record = {"hostname": hostname, "ip": ip, "http": None, "https": None}
    for scheme in ("https", "http"):
        r = fetch(f"{scheme}://{hostname}", timeout=5)
        if r.ok:
            record[scheme] = {
                "status": r.status,
                "title": r.to_dict().get("title", ""),
                "server": r.headers.get("Server", ""),
            }
    return record


def run(domain, wordlist_path="wordlists/subdomains.txt", threads=20, passive_only=False):
    result = {"domain": domain, "discovered": [], "crtsh_error": None,
              "method": []}

    all_hostnames = set()

    crt_hits, crt_error = _crtsh_lookup(domain)
    if crt_error:
        result["crtsh_error"] = crt_error
    else:
        result["method"].append("crt.sh (Certificate Transparency)")
    all_hostnames |= crt_hits

    if not passive_only:
        words = _load_wordlist(wordlist_path)
        candidates = {f"{w}.{domain}" for w in words}
        result["method"].append(f"wordlist resolution ({len(words)} candidate names)")
        # Only resolve wordlist candidates now; crt.sh hits get probed below regardless
        all_hostnames |= candidates

    all_hostnames.add(domain)  # always include the apex for probing consistency

    discovered = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_resolve_and_probe, h): h for h in all_hostnames}
        for future in as_completed(futures):
            record = future.result()
            if record:
                discovered.append(record)

    result["discovered"] = sorted(discovered, key=lambda x: x["hostname"])
    result["total_resolved"] = len(discovered)
    return result
