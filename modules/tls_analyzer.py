"""
TLS Analysis Module
----------------------
Pure `ssl` + `socket` stdlib. Connects, completes a TLS handshake, and
inspects the certificate and negotiated protocol/cipher. No destructive
handshakes, no downgrade attacks - passive inspection only.
"""
import ssl
import socket
from datetime import datetime, timezone

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def _parse_cert_date(date_str):
    # Cert dates look like: 'Oct 12 23:59:59 2026 GMT'
    try:
        return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def run(hostname, port=443, timeout=8):
    result = {
        "hostname": hostname, "port": port, "reachable": False,
        "protocol": None, "cipher_suite": None, "subject": None,
        "issuer": None, "valid_from": None, "valid_until": None,
        "days_until_expiry": None, "subject_alt_names": [],
        "indicators": [], "error": None,
    }

    cert = None
    cipher = None

    # Attempt 1: validated connection using the default CA trust store.
    # Python's ssl module only returns a fully-parsed certificate dict
    # from getpeercert() when verification actually ran - with
    # CERT_NONE it silently returns {} even though a cert was
    # presented. So we validate first (the common case for public
    # sites) to get full subject/issuer/expiry detail, and only fall
    # back to an unvalidated connection if validation itself fails
    # (self-signed cert, hostname mismatch, expired cert, etc - all of
    # which are themselves valid findings for a lab/internal target).
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                result["reachable"] = True
                result["protocol"] = ssock.version()
                result["cipher_suite"] = cipher[0] if cipher else None
    except ssl.SSLCertVerificationError as e:
        result["indicators"].append({
            "finding": f"Certificate could not be automatically validated: {e.reason or e}",
            "severity": "Medium", "confidence": "High",
        })
        # Attempt 2: unvalidated, just to confirm reachability/protocol/cipher.
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    result["reachable"] = True
                    result["protocol"] = ssock.version()
                    result["cipher_suite"] = cipher[0] if cipher else None
            result["indicators"].append({
                "finding": "Certificate details (subject/issuer/expiry) unavailable "
                           "without validation succeeding - see verification error above.",
                "severity": "Info", "confidence": "High",
            })
        except (socket.timeout, ConnectionRefusedError, socket.gaierror, OSError, ssl.SSLError) as e2:
            result["error"] = f"{type(e2).__name__}: {e2}"
            return result
    except (socket.timeout, ConnectionRefusedError, socket.gaierror, OSError) as e:
        result["error"] = f"{type(e).__name__}: {e}"
        return result
    except ssl.SSLError as e:
        result["error"] = f"SSLError: {e}"
        return result

    if cert:
        result["subject"] = dict(x[0] for x in cert.get("subject", []))
        result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
        result["subject_alt_names"] = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

        not_before = _parse_cert_date(cert.get("notBefore", ""))
        not_after = _parse_cert_date(cert.get("notAfter", ""))
        result["valid_from"] = cert.get("notBefore")
        result["valid_until"] = cert.get("notAfter")

        if not_after:
            days_left = (not_after - datetime.now(timezone.utc)).days
            result["days_until_expiry"] = days_left
            if days_left < 0:
                result["indicators"].append({
                    "finding": "Certificate is EXPIRED",
                    "severity": "High", "confidence": "High",
                })
            elif days_left < 30:
                result["indicators"].append({
                    "finding": f"Certificate expires soon ({days_left} days)",
                    "severity": "Medium", "confidence": "High",
                })

        sans = result["subject_alt_names"]
        cn = result["subject"].get("commonName") if result["subject"] else None
        names = set(sans) | ({cn} if cn else set())
        if names and not any(_matches_hostname(hostname, n) for n in names):
            result["indicators"].append({
                "finding": f"Certificate hostname mismatch: {hostname} not covered by {sorted(names)}",
                "severity": "Medium", "confidence": "Medium",
            })
    else:
        result["indicators"].append({
            "finding": "No certificate details retrieved (verify_mode=CERT_NONE); "
                       "possible self-signed cert or non-standard TLS setup",
            "severity": "Info", "confidence": "Low",
        })

    if result["protocol"] in WEAK_PROTOCOLS:
        result["indicators"].append({
            "finding": f"Weak/obsolete TLS protocol in use: {result['protocol']}",
            "severity": "High", "confidence": "High",
        })

    return result


def _matches_hostname(hostname, pattern):
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return hostname.endswith(suffix) and hostname.count(".") == pattern.count(".")
    return hostname.lower() == pattern.lower()
