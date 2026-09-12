"""
DNS Reconnaissance Module
----------------------------
Python's standard library has no general DNS-record-type resolver
(socket only does A/AAAA via getaddrinfo). For MX/NS/TXT/SOA/CNAME we
shell out to whichever of `dig` / `host` / `nslookup` is installed,
trying each in turn, and degrade gracefully to "unavailable" if none
exist - we never require dnspython.
"""
import socket
from .utils import run_cmd, vlog
from .external_tools import have


def _resolve_a_aaaa(hostname):
    ipv4, ipv6 = set(), set()
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            if family == socket.AF_INET:
                ipv4.add(sockaddr[0])
            elif family == socket.AF_INET6:
                ipv6.add(sockaddr[0])
    except socket.gaierror as e:
        vlog(f"getaddrinfo failed for {hostname}: {e}")
    return sorted(ipv4), sorted(ipv6)


def _reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _dig(hostname, rtype):
    if have("dig"):
        ok, out, _ = run_cmd(["dig", "+short", rtype, hostname], timeout=8)
        if ok:
            return [l.strip() for l in out.splitlines() if l.strip()]
    return None


def _host_cmd(hostname, rtype):
    if have("host"):
        ok, out, _ = run_cmd(["host", "-t", rtype, hostname], timeout=8)
        if ok and "not found" not in out.lower() and "no answer" not in out.lower():
            return [l.strip() for l in out.splitlines() if l.strip()]
    return None


def _nslookup(hostname, rtype):
    if have("nslookup"):
        ok, out, _ = run_cmd(["nslookup", "-type=" + rtype, hostname], timeout=8)
        if ok:
            return [l.strip() for l in out.splitlines() if l.strip()]
    return None


def _resolve_record(hostname, rtype):
    """Try dig -> host -> nslookup, in that order. Returns list[str] or None."""
    for resolver in (_dig, _host_cmd, _nslookup):
        result = resolver(hostname, rtype)
        if result:
            return result
    return None


def run(target):
    result = {
        "target": target,
        "ipv4": [], "ipv6": [], "cname": None,
        "mx": None, "ns": None, "txt": None, "soa": None,
        "reverse_dns": {}, "resolution_method": "socket (stdlib)",
        "notes": [],
    }

    ipv4, ipv6 = _resolve_a_aaaa(target)
    result["ipv4"], result["ipv6"] = ipv4, ipv6

    if not ipv4 and not ipv6:
        result["notes"].append("Host did not resolve via getaddrinfo; "
                                "target may be offline or a bare IP was given.")

    if have("dig") or have("host") or have("nslookup"):
        result["cname"] = _resolve_record(target, "CNAME")
        result["mx"] = _resolve_record(target, "MX")
        result["ns"] = _resolve_record(target, "NS")
        result["txt"] = _resolve_record(target, "TXT")
        result["soa"] = _resolve_record(target, "SOA")
        tool = "dig" if have("dig") else ("host" if have("host") else "nslookup")
        result["resolution_method"] = f"socket + {tool}"
    else:
        result["notes"].append(
            "No dig/host/nslookup found - only A/AAAA records available. "
            "Install `dnsutils` (dig/host) for full record types."
        )

    for ip in ipv4[:3]:  # cap to avoid slow reverse-lookup storms
        rdns = _reverse_dns(ip)
        if rdns:
            result["reverse_dns"][ip] = rdns

    return result
