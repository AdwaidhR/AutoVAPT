"""
Directory / Content Discovery Module
----------------------------------------
Native engine: threaded, stdlib-only, with soft-404 baseline detection
(many apps return HTTP 200 for "not found" pages, e.g. SPA routers or
custom error pages - without a baseline check every one of those would
be misreported as a discovered path).

Optional engine: if `ffuf` is installed and --ffuf is passed, run it
with conservative settings and parse its JSON output instead/alongside.
"""
import json
import random
import string
import tempfile
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from .http_recon import fetch
from .utils import run_cmd, vlog
from .external_tools import have

INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 401, 403}
BUILTIN_FALLBACK_WORDS = [
    "admin", "login", "backup", "config", "test", ".git", "api", "uploads",
    "dashboard", "wp-admin", ".env", "server-status", "console", ".git/HEAD",
]


def _load_wordlist(path):
    try:
        with open(path) as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        return BUILTIN_FALLBACK_WORDS


def _random_path():
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=16))


def _get_baseline(base_url):
    """Request a near-certainly-nonexistent path to fingerprint soft-404 pages."""
    probe_url = base_url.rstrip("/") + "/" + _random_path()
    r = fetch(probe_url)
    return {"status": r.status, "length": len(r.body_bytes) if r.ok else 0,
            "title": "" if not r.ok else None}


def _is_soft_404(status, length, baseline, tolerance=25):
    """
    A "soft 404" is a response that claims success (e.g. HTTP 200) for a
    path that doesn't really exist - common with SPA routers and custom
    error pages. We detect it by comparing against a baseline request to
    a near-certainly-nonexistent random path.

    A genuine HTTP 404 is never "soft" by definition - it's already an
    honest not-found signal (and is filtered out upstream by
    INTERESTING_CODES before this function is even called in practice).
    """
    if status == 404:
        return False
    if baseline["status"] == status:
        return abs(length - baseline["length"]) <= tolerance
    return False


def _native_scan(base_url, words, extensions, threads, baseline):
    found = []
    candidates = []
    for w in words:
        candidates.append(w)
        for ext in extensions:
            candidates.append(f"{w}.{ext}")

    def probe(word):
        url = f"{base_url.rstrip('/')}/{word}"
        r = fetch(url, allow_redirects=False)
        if not r.ok or r.status not in INTERESTING_CODES:
            return None
        length = len(r.body_bytes)
        if _is_soft_404(r.status, length, baseline):
            return None
        return {
            "path": f"/{word}", "status": r.status, "length": length,
            "content_type": r.headers.get("Content-Type", ""),
            "redirect": r.headers.get("Location"),
            "confidence": "High" if r.status in (401, 403) else "Medium",
        }

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(probe, w): w for w in candidates}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return sorted(found, key=lambda x: x["path"])


def _ffuf_scan(base_url, wordlist_path, extensions, threads):
    out_file = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    out_file.close()
    ext_arg = ",".join(f".{e}" for e in extensions) if extensions else ""

    cmd = ["ffuf", "-u", f"{base_url.rstrip('/')}/FUZZ", "-w", wordlist_path,
           "-t", str(threads), "-of", "json", "-o", out_file.name,
           "-mc", "200,201,204,301,302,307,401,403", "-s"]
    if ext_arg:
        cmd += ["-e", ext_arg]

    ok, out, err = run_cmd(cmd, timeout=300)
    findings = []
    try:
        with open(out_file.name) as f:
            data = json.load(f)
        for r in data.get("results", []):
            findings.append({
                "path": "/" + r.get("input", {}).get("FUZZ", ""),
                "status": r.get("status"), "length": r.get("length"),
                "content_type": r.get("content-type", ""),
                "redirect": None, "confidence": "Medium (ffuf)",
            })
    except Exception as e:
        vlog(f"Failed to parse ffuf output: {e}")
    finally:
        try:
            os.unlink(out_file.name)
        except OSError:
            pass

    return findings, ok, err


def run(base_url, wordlist_path="wordlists/common_dirs.txt", threads=20,
        extensions=None, use_ffuf=False):
    extensions = extensions or []
    baseline = _get_baseline(base_url)
    words = _load_wordlist(wordlist_path)

    result = {
        "base_url": base_url, "wordlist_used": wordlist_path,
        "total_words": len(words), "baseline": baseline,
        "engine": "native (stdlib)", "discovered": [], "ffuf_note": None,
    }

    if use_ffuf and have("ffuf"):
        findings, ok, err = _ffuf_scan(base_url, wordlist_path, extensions, threads)
        if ok or findings:
            result["engine"] = "ffuf"
            result["discovered"] = findings
            return result
        result["ffuf_note"] = f"ffuf run failed ({err.strip()[:200]}); falling back to native engine"
    elif use_ffuf and not have("ffuf"):
        result["ffuf_note"] = "ffuf not installed - using native content discovery engine."

    result["discovered"] = _native_scan(base_url, words, extensions, threads, baseline)
    return result
