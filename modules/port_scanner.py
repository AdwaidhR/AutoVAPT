"""
Port Scanner Module
--------------------
Native path : multi-threaded TCP-connect scan using only `socket` +
              `concurrent.futures` - always available, no dependencies.
Enhanced path: if `nmap` is installed, use `nmap -sV -Pn` for accurate
              service/version fingerprinting (a connect-scan can only
              tell you a port is open, not confidently what's on it).

We deliberately do NOT invoke aggressive NSE scripts (--script vuln,
-A, etc.) - this stays a reconnaissance scanner, not an exploitation
launcher.
"""
import socket
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from .utils import run_cmd, vlog
from .external_tools import have

TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
    49152, 49153, 49154, 49155, 49156, 49157,
]

COMMON_PORT_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    587: "submission", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s",
    1521: "oracle", 3000: "http-alt", 3306: "mysql", 3389: "ms-wbt-server",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 27017: "mongodb",
}


def expand_ports(spec):
    """
    Accepts: '1-1000', '22,80,443', '1-100,443,8080-8090', or 'top-100'.
    Returns a sorted list[int], de-duplicated, clamped to valid range.
    """
    spec = spec.strip().lower()
    if spec in ("top-100", "top-ports", "top"):
        return sorted(set(TOP_100_PORTS))

    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            start, end = int(start), int(end)
            ports.update(range(max(1, start), min(65535, end) + 1))
        else:
            ports.add(int(chunk))
    return sorted(ports)


def _socket_connect_scan(host, ports, threads, timeout=0.8):
    open_ports = []

    def check(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((host, port)) == 0:
                    banner = _grab_banner(s)
                    return {
                        "port": port, "protocol": "tcp", "state": "open",
                        "service": COMMON_PORT_NAMES.get(port, "unknown"),
                        "product": "", "version": "", "banner": banner,
                    }
        except (socket.timeout, OSError):
            return None
        return None

    def _grab_banner(sock):
        try:
            sock.settimeout(0.5)
            data = sock.recv(128)
            return data.decode(errors="ignore").strip()[:120] if data else ""
        except Exception:
            return ""

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check, p): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    return sorted(open_ports, key=lambda x: x["port"])


def _nmap_scan(host, port_spec):
    port_arg = port_spec if port_spec.lower() not in ("top-100", "top-ports", "top") else None
    cmd = ["nmap", "-sV", "-Pn", "-oX", "-"]
    if port_arg:
        cmd += ["-p", port_arg]
    else:
        cmd += ["--top-ports", "100"]
    cmd.append(host)

    ok, out, err = run_cmd(cmd, timeout=900)
    if not ok or not out:
        vlog(f"nmap scan failed or produced no output: {err}")
        return None

    open_ports = []
    try:
        root = ET.fromstring(out)
        for h in root.findall("host"):
            for port in h.findall(".//port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    service = port.find("service")
                    open_ports.append({
                        "port": int(port.get("portid")),
                        "protocol": port.get("protocol"),
                        "state": "open",
                        "service": service.get("name") if service is not None else "unknown",
                        "product": service.get("product", "") if service is not None else "",
                        "version": service.get("version", "") if service is not None else "",
                        "banner": "",
                    })
    except ET.ParseError as e:
        vlog(f"Failed to parse nmap XML: {e}")
        return None

    return sorted(open_ports, key=lambda x: x["port"])


def run(host, port_spec="1-1000", threads=50, use_nmap=True):
    result = {"target": host, "port_spec": port_spec, "engine": None,
              "open_ports": [], "error": None}

    if use_nmap and have("nmap"):
        nmap_result = _nmap_scan(host, port_spec)
        if nmap_result is not None:
            result["engine"] = "nmap"
            result["open_ports"] = nmap_result
            return result
        result["error"] = "nmap scan failed/timed out; fell back to native scanner"

    try:
        ports = expand_ports(port_spec)
    except ValueError as e:
        result["error"] = f"Invalid port spec '{port_spec}': {e}"
        return result

    result["engine"] = "python-socket (stdlib)"
    result["open_ports"] = _socket_connect_scan(host, ports, threads)
    return result
