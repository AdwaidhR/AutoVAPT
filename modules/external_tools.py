"""
External Tool Detection
--------------------------
Central place that answers "is X installed?" for every optional
integration. Every other module imports from here instead of calling
shutil.which directly, so the availability logic (and any future
version-checks) lives in one spot.

Nothing in this project ever hard-fails because one of these is
missing - they only unlock enhanced functionality when present.
"""
from .utils import which, run_cmd

OPTIONAL_TOOLS = ["nmap", "ffuf", "nikto", "dig", "whois", "host", "nslookup", "curl"]


def check_all():
    """Returns {tool: bool} for every optional external tool, plus python3."""
    status = {"python3": True}
    for tool in OPTIONAL_TOOLS:
        status[tool] = which(tool) is not None
    return status


def print_dependency_report():
    status = check_all()
    print("=" * 55)
    print(" AutoVAPT Dependency Check")
    print("=" * 55)
    for tool, available in status.items():
        mark = "[+]" if available else "[-]"
        state = "Available" if available else "Not Installed"
        print(f" {mark} {tool:<12} {state}")
    print("-" * 55)
    print(" [+] Core framework: Ready "
          "(stdlib-only, works regardless of tools above)")
    print("=" * 55)
    missing = [t for t, ok in status.items() if not ok and t != "python3"]
    if missing:
        print("\nOptional tools not found (native fallbacks will be used):")
        for m in missing:
            print(f"  - {m}")
    return status


def have(tool):
    return which(tool) is not None


def nmap_version():
    ok, out, _ = run_cmd(["nmap", "--version"], timeout=5)
    if ok and out:
        return out.splitlines()[0]
    return None


def ffuf_version():
    ok, out, _ = run_cmd(["ffuf", "-V"], timeout=5)
    if ok and out:
        return out.strip().splitlines()[0]
    return None


def nikto_version():
    ok, out, _ = run_cmd(["nikto", "-Version"], timeout=8)
    if ok and out:
        return out.strip().splitlines()[0]
    return None


def curl_version():
    ok, out, _ = run_cmd(["curl", "--version"], timeout=5)
    if ok and out:
        return out.strip().splitlines()[0]
    return None


def run_nikto(base_url, timeout=330):
    """
    Optional Nikto integration. Only invoked when the user explicitly
    passes --nikto. Parses Nikto's plain-text output into a structured
    list of findings; never raises if Nikto is missing or fails.
    """
    if not have("nikto"):
        return {"available": False,
                "note": "Nikto not installed - skipped. Install with "
                        "`sudo apt install nikto` for this optional scan."}

    ok, out, err = run_cmd(["nikto", "-h", base_url, "-nointeractive",
                             "-maxtime", "240"], timeout=timeout)
    findings = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("+ ") and "Server:" not in line:
            findings.append({"raw": line[2:], "manual_verification_required": True})

    timeout_note = (
        "Nikto reached its configured 240-second assessment limit; partial results were retained."
        if "maximum execution time" in (err or "").lower()
        else f"Nikto exited with an error: {err.strip()[:300]}"
    )
    return {
        "available": True, "success": ok, "raw_findings": findings,
        "finding_count": len(findings),
        "note": None if ok else timeout_note,
    }

