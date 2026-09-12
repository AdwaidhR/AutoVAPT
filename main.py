#!/usr/bin/env python3
"""
AutoVAPT v2 - Automated VAPT & Reconnaissance Framework
==========================================================
Core framework runs on the Python 3 standard library ONLY - no
`pip install -r requirements.txt` is required. Nmap, FFUF, Nikto, dig,
and whois are optional integrations that unlock enhanced results when
installed; their absence never crashes a scan.

Pipeline:
  Authorization -> Target Validation -> DNS Recon -> Subdomain Discovery
  -> RDAP/WHOIS -> Port Scan -> HTTP/HTTPS Recon -> TLS Analysis
  -> Technology Fingerprinting -> Web Crawl -> Endpoint Discovery
  -> JS Analysis -> Content Discovery -> Vulnerability Indicators
  -> CVE Correlation -> Attack Surface Map -> Risk Scoring -> Report

See DISCLAIMER.md. Authorized security testing only.
"""
import argparse
import os
import sys
import time
import socket
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.utils import banner, log, set_verbose, now_iso, load_json
from modules import authorization
from modules import external_tools
from modules import dns_recon
from modules import subdomain_enum
from modules import rdap
from modules import port_scanner
from modules import http_recon
from modules import tls_analyzer
from modules import technology_fingerprint
from modules import web_crawler
from modules import endpoint_discovery
from modules import js_analyzer
from modules import directory_bruteforce
from modules import vulnerability_scanner
from modules import cve_correlator
from modules import attack_surface
from modules import report_generator


def parse_args():
    cfg = load_json(os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json"))
    scan_cfg = cfg.get("scan", {})
    report_cfg = cfg.get("report", {})

    p = argparse.ArgumentParser(
        prog="autovapt",
        description="AutoVAPT v2 - stdlib-core VAPT & reconnaissance framework "
                     "(authorized testing only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 main.py --target https://example.com --authorized
  python3 main.py --target https://example.com --authorized --deep
  python3 main.py --target https://example.com --authorized --skip-ports
  python3 main.py --target https://example.com --authorized --ports 1-65535
  python3 main.py --target https://example.com --authorized --ffuf
  python3 main.py --target https://example.com --authorized --nikto
  python3 main.py --check-dependencies

Defaults below are read from config.json when present (falls back to
built-in defaults if config.json is missing or a key is absent).
""")
    p.add_argument("-t", "--target", help="Target domain, IP, or URL")
    p.add_argument("--authorized", "--yes", dest="authorized", action="store_true",
                    help="Confirm you are authorized to test this target")
    p.add_argument("--non-interactive", action="store_true",
                    help="Skip interactive prompts (still requires --authorized)")
    p.add_argument("--deep", action="store_true",
                    help="Deeper scan: full port range, more crawl pages, more threads")
    p.add_argument("--ports", default=scan_cfg.get("default_ports", "1-1000"),
                    help="Port spec: '1-1000', '22,80,443', or 'top-100' (default: from config.json)")
    p.add_argument("--top-ports", action="store_true", help="Shortcut for --ports top-100")
    p.add_argument("--max-pages", type=int, default=scan_cfg.get("max_crawl_pages", 50),
                    help="Max pages to crawl (default: from config.json)")
    p.add_argument("--crawl-depth", type=int, default=scan_cfg.get("max_crawl_depth", 2),
                    help="Max crawl depth (default: from config.json)")
    p.add_argument("--threads", type=int, default=scan_cfg.get("threads", 30),
                    help="Thread count (default: from config.json)")
    p.add_argument("--wordlist", default=None, help="Custom wordlist for content discovery")
    p.add_argument("--extensions", default="", help="Comma-separated extensions, e.g. php,html,bak")
    p.add_argument("--ffuf", action="store_true", help="Use ffuf for content discovery if installed")
    p.add_argument("--nikto", action="store_true", help="Run Nikto if installed")
    p.add_argument("--skip-ports", action="store_true")
    p.add_argument("--skip-crawl", action="store_true")
    p.add_argument("--skip-content", action="store_true")
    p.add_argument("--skip-subdomains", action="store_true")
    p.add_argument("-o", "--output", default=report_cfg.get("output_dir", "reports"),
                    help="Output directory (default: from config.json)")
    p.add_argument("--format", choices=["html", "pdf", "both"],
                    default=report_cfg.get("default_format", "html"))
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--check-dependencies", action="store_true",
                    help="Check optional tool availability and exit")
    return p.parse_args()


def resolve_host_and_url(target):
    """Accepts a bare domain, IP, or full URL. Returns (host, url_hint)."""
    if target.startswith("http://") or target.startswith("https://"):
        return urlparse(target).netloc.split(":")[0], target
    return target, None


def main():
    args = parse_args()
    banner()

    if args.check_dependencies:
        external_tools.print_dependency_report()
        return

    if not args.target:
        log("ERR", "No target specified. Use -t/--target, or --check-dependencies.")
        sys.exit(1)

    set_verbose(args.verbose)
    host, url_hint = resolve_host_and_url(args.target)

    authorization.confirm_authorization(args.target, args.authorized, args.non_interactive)

    if args.deep:
        args.ports = "1-65535"
        args.max_pages = 150
        args.threads = max(args.threads, 60)
    if args.top_ports:
        args.ports = "top-100"

    extensions = [e.strip() for e in args.extensions.split(",") if e.strip()]
    os.makedirs(args.output, exist_ok=True)
    scan_start = time.time()

    results = {
        "target": args.target,
        "metadata": {"scan_start": now_iso(), "modules_run": []},
    }

    def ran(name):
        results["metadata"]["modules_run"].append(name)

    # --- Target validation ---
    log("PHASE", "Target validation")
    try:
        socket.gethostbyname(host)
        log("OK", f"'{host}' resolves.")
    except socket.gaierror:
        log("WARN", f"'{host}' did not resolve via DNS. Continuing anyway "
                     f"(it may be reachable via /etc/hosts or a local lab network).")

    # --- DNS Recon ---
    log("PHASE", "DNS Reconnaissance")
    results["dns"] = dns_recon.run(host)
    ran("dns_recon")

    # --- Subdomain enumeration ---
    if not args.skip_subdomains and "." in host and not host.replace(".", "").isdigit():
        log("PHASE", "Subdomain Enumeration")
        wl = "wordlists/subdomains.txt"
        results["subdomains"] = subdomain_enum.run(host, wordlist_path=wl, threads=args.threads)
        ran("subdomain_enum")
    else:
        results["subdomains"] = {}

    # --- RDAP / WHOIS ---
    log("PHASE", "RDAP / WHOIS / ASN Information")
    results["rdap"] = rdap.run(host, resolved_ips=results["dns"].get("ipv4"))
    ran("rdap")

    # --- Port scanning ---
    if not args.skip_ports:
        log("PHASE", f"Port & Service Enumeration ({args.ports})")
        results["ports"] = port_scanner.run(host, args.ports, threads=args.threads)
        ran("port_scanner")
    else:
        results["ports"] = {}

    # --- HTTP/HTTPS recon ---
    log("PHASE", "HTTP/HTTPS Reconnaissance")
    results["web"] = http_recon.run(url_hint or host)
    ran("http_recon")
    base_url = results["web"].get("working_base_url")

    if base_url:
        # --- TLS analysis ---
        if base_url.startswith("https://"):
            log("PHASE", "TLS Analysis")
            results["tls"] = tls_analyzer.run(host)
            ran("tls_analyzer")
        else:
            results["tls"] = {}

        # --- Technology fingerprinting ---
        log("PHASE", "Technology Fingerprinting")
        scheme = base_url.split("://")[0]
        primary = results["web"].get(scheme, {})
        results["technologies"] = technology_fingerprint.run(
            primary.get("headers", {}), primary.get("body", "")
        )
        ran("technology_fingerprint")

        # --- Web crawl ---
        if not args.skip_crawl:
            log("PHASE", f"Web Crawling (max {args.max_pages} pages, depth {args.crawl_depth})")
            results["crawl"] = web_crawler.run(base_url, max_pages=args.max_pages,
                                                 max_depth=args.crawl_depth)
            ran("web_crawler")
        else:
            results["crawl"] = {}

        # --- JS analysis ---
        log("PHASE", "JavaScript Static Analysis")
        results["javascript"] = js_analyzer.run(results["crawl"].get("scripts", []))
        ran("js_analyzer")

        # --- Endpoint discovery ---
        log("PHASE", "Endpoint & Parameter Discovery")
        robots_text = (results["web"].get("robots_txt") or {}).get("excerpt")
        sitemap_text = (results["web"].get("sitemap_xml") or {}).get("excerpt")
        results["endpoints"] = endpoint_discovery.run(
            crawl_result=results["crawl"], js_findings=results["javascript"],
            robots_text=robots_text, sitemap_text=sitemap_text,
        )
        ran("endpoint_discovery")

        # --- Content discovery ---
        if not args.skip_content:
            log("PHASE", "Directory / Content Discovery")
            wl = args.wordlist or "wordlists/common_dirs.txt"
            results["content_discovery"] = directory_bruteforce.run(
                base_url, wordlist_path=wl, threads=args.threads,
                extensions=extensions, use_ffuf=args.ffuf,
            )
            ran("directory_bruteforce")
        else:
            results["content_discovery"] = {}

        # --- Nikto (optional) ---
        if args.nikto:
            log("PHASE", "Nikto Scan (optional)")
            results["nikto"] = external_tools.run_nikto(base_url)
            ran("nikto")

        # --- Vulnerability indicators ---
        log("PHASE", "Vulnerability Indicator Checks")
        results["findings"] = vulnerability_scanner.run(
            base_url, http_result=results["web"], tls_result=results.get("tls")
        )
        ran("vulnerability_scanner")
    else:
        log("WARN", "No working HTTP(S) endpoint found - skipping web-layer modules "
                     "(TLS, tech fingerprint, crawl, JS, content discovery, "
                     "vulnerability indicators).")
        results.update({"tls": {}, "technologies": [], "crawl": {}, "javascript": {},
                         "endpoints": {}, "content_discovery": {}, "findings": {"findings": []}})

    # --- CVE correlation ---
    log("PHASE", "CVE Correlation")
    results["cves"] = cve_correlator.run(results.get("ports", {}).get("open_ports", []))
    ran("cve_correlator")

    # --- Attack surface map ---
    log("PHASE", "Building Attack Surface Map")
    results["attack_surface"] = attack_surface.build(results)

    # --- Finalize & report ---
    elapsed = round(time.time() - scan_start, 2)
    results["metadata"]["scan_end"] = now_iso()
    results["metadata"]["duration_seconds"] = elapsed
    results["metadata"]["generated_on"] = now_iso()

    tool_versions = {
        "nmap": external_tools.nmap_version() or "not used",
        "ffuf": external_tools.ffuf_version() or "not used",
        "nikto": external_tools.nikto_version() or "not used",
    }

    log("PHASE", "Generating Report")
    paths = report_generator.generate(results, args.output, fmt=args.format,
                                        tool_versions=tool_versions)

    log("DONE", f"Scan complete in {elapsed}s")
    log("DONE", f"HTML report: {paths['html']}")
    log("DONE", f"JSON results: {paths['json']}")
    if paths.get("pdf"):
        log("DONE", f"PDF report: {paths['pdf']}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(1)
