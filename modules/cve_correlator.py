"""
CVE Correlation Module
--------------------------
Deliberately conservative: a keyword hit on the NVD API is labeled
"Potential CVE Match" with verification_required=True unless we can
establish that the CPE version range genuinely covers the detected
version - and even then we still flag it for manual confirmation,
because banner-based version detection itself can be wrong (spoofed/
outdated banners, backported patches, etc).

Uses urllib only - no requests dependency. If the NVD API is
unreachable, the whole scan continues without CVE data rather than
failing.
"""
import json
import time
import urllib.request
import urllib.error
import urllib.parse
from .utils import vlog

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = 15
MAX_SERVICES_QUERIED = 8   # be a good citizen of the free public NVD API
RESULTS_PER_SERVICE = 5


def _query_nvd(product, version):
    if not product:
        return None
    keyword = f"{product} {version}".strip()
    params = urllib.parse.urlencode({"keywordSearch": keyword,
                                      "resultsPerPage": RESULTS_PER_SERVICE})
    url = f"{NVD_API}?{params}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AutoVAPT/2.0"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8", errors="ignore"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        vlog(f"NVD query failed for '{keyword}': {e}")
    except Exception as e:
        vlog(f"NVD query unexpected error for '{keyword}': {e}")
    return None


def _extract_cve_entries(nvd_response, detected_version):
    entries = []
    for item in nvd_response.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        metrics = cve.get("metrics", {})
        severity, score = "UNKNOWN", None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                severity = metrics[key][0]["cvssData"].get("baseSeverity", "UNKNOWN")
                score = metrics[key][0]["cvssData"].get("baseScore")
                break

        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")

        # Attempt a CPE-based version check (best-effort, conservative)
        version_confirmed = False
        configs = cve.get("configurations", [])
        for config in configs:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable") and detected_version:
                        version_start = cpe_match.get("versionStartIncluding") or cpe_match.get("versionStartExcluding")
                        version_end = cpe_match.get("versionEndIncluding") or cpe_match.get("versionEndExcluding")
                        if version_start or version_end:
                            # We deliberately do NOT implement full version-range
                            # comparison logic here (versioning schemes vary too
                            # much to do this safely/correctly without a proper
                            # library) - we surface the range for a human to check.
                            version_confirmed = "range_provided_needs_manual_check"

        entries.append({
            "cve_id": cve_id, "severity": severity, "cvss_score": score,
            "description": desc[:300],
            "match_type": "Potential CVE Match",
            "version_range_info": version_confirmed or "not available",
            "verification_required": True,  # always True by design - see module docstring
        })
    return entries


def run(open_ports):
    """
    open_ports: list of {"port", "service", "product", "version", ...}
    from port_scanner.py output.
    """
    results = []
    queried = 0

    for svc in (open_ports or []):
        product = svc.get("product", "").strip()
        version = svc.get("version", "").strip()
        if not product or queried >= MAX_SERVICES_QUERIED:
            continue

        nvd_response = _query_nvd(product, version)
        queried += 1
        time.sleep(1)  # respect public NVD rate limit

        if not nvd_response:
            results.append({
                "port": svc.get("port"), "service": svc.get("service"),
                "product": product, "version": version,
                "cves": [], "note": "NVD lookup unavailable or returned no data",
            })
            continue

        entries = _extract_cve_entries(nvd_response, version)
        results.append({
            "port": svc.get("port"), "service": svc.get("service"),
            "product": product, "version": version, "cves": entries,
        })

    return {
        "services_checked": queried,
        "results": results,
        "methodology": (
            "Keyword-matched against the NVD API by product/version. Every match is "
            "labeled 'Potential CVE Match' with verification_required=true - exact "
            "affected-version-range confirmation requires manual CPE analysis, which "
            "this tool surfaces but does not auto-resolve."
        ),
    }
