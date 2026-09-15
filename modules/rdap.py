"""
RDAP / WHOIS / ASN Module
----------------------------
RDAP (RFC 7482) is the modern successor to WHOIS and, usefully for us,
is a plain JSON-over-HTTPS protocol - so we can query it with nothing
but urllib.request, no third-party client needed.

For classic WHOIS text output (some registrars/orgs still only show
certain details there) we shell out to the system `whois` binary if
present, and skip gracefully if not.

ASN/organization info is best-effort: we query RDAP for IP allocation
data via the bootstrap service, which usually includes the responsible
network/organization without needing a dedicated ASN database.
"""
import json
import socket
import ipaddress
import urllib.request
import urllib.error
from .utils import run_cmd, vlog
from .external_tools import have

RDAP_DOMAIN_BOOTSTRAP = "https://rdap.org/domain/{}"
RDAP_IP_BOOTSTRAP = "https://rdap.org/ip/{}"
TIMEOUT = 10


def _fetch_json(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AutoVAPT/2.0"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8", errors="ignore"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, socket.timeout) as e:
        vlog(f"RDAP fetch failed for {url}: {e}")
    except Exception as e:
        vlog(f"RDAP fetch unexpected error for {url}: {e}")
    return None


def _domain_rdap(domain):
    data = _fetch_json(RDAP_DOMAIN_BOOTSTRAP.format(domain))
    if not data:
        return None
    return {
        "handle": data.get("handle"),
        "status": data.get("status"),
        "events": [{"action": e.get("eventAction"), "date": e.get("eventDate")}
                   for e in data.get("events", [])],
        "nameservers": [ns.get("ldhName") for ns in data.get("nameservers", [])],
        "entities": [
            {
                "roles": e.get("roles"),
                "handle": e.get("handle"),
            }
            for e in data.get("entities", [])
        ],
    }


def _ip_rdap(ip):
    data = _fetch_json(RDAP_IP_BOOTSTRAP.format(ip))
    if not data:
        return None
    return {
        "handle": data.get("handle"),
        "name": data.get("name"),
        "country": data.get("country"),
        "start_address": data.get("startAddress"),
        "end_address": data.get("endAddress"),
        "asn_info_source": "RDAP (rdap.org bootstrap)",
        "entities": [
            {"roles": e.get("roles"), "handle": e.get("handle")}
            for e in data.get("entities", [])
        ],
    }


def _whois_lookup(domain):
    if have("whois"):
        ok, out, _ = run_cmd(["whois", domain], timeout=12)
        if ok and out:
            return out[:4000]  # cap for report readability
    return None


def run(target, resolved_ips=None):
    try:
        ipaddress.ip_address(target)
        target_is_ip = True
    except ValueError:
        target_is_ip = False

    result = {
        "domain_rdap": None if target_is_ip else _domain_rdap(target),
        # Classic WHOIS is meaningful for both domains and IPs (RIPE/ARIN/etc.
        # publish IP allocation WHOIS too), so this still runs either way.
        "whois_text": _whois_lookup(target),
        "ip_rdap": {},
    }

    ips_to_check = list(resolved_ips or [])
    if target_is_ip and target not in ips_to_check:
        ips_to_check.insert(0, target)

    for ip in ips_to_check[:2]:  # cap lookups
        info = _ip_rdap(ip)
        if info:
            result["ip_rdap"][ip] = info

    if target_is_ip:
        result["note_target_type"] = ("Target is an IP address; domain RDAP lookup "
                                       "skipped as not applicable. See ip_rdap instead.")

    if not result["domain_rdap"] and not result["whois_text"] and not result["ip_rdap"]:
        result["note"] = ("RDAP lookup failed and `whois` binary not found/failed. "
                           "Install `whois` package for registrar-level detail.")
    return result
