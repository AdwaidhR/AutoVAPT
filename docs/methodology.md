# Methodology

AutoVAPT follows a structured reconnaissance-and-assessment methodology
loosely modeled on how commercial scanners (Nessus, OpenVAS, Burp Suite,
Nuclei) and manual VAPT engagements structure their work, scaled down to
a learning/portfolio-appropriate scope.

## Pipeline

```
Authorization
    v
Target Validation
    v
DNS Reconnaissance          (A/AAAA/CNAME/MX/NS/TXT/SOA, reverse DNS)
    v
Subdomain Discovery          (crt.sh certificate transparency + wordlist)
    v
RDAP / WHOIS / Network Info  (RDAP JSON API, whois binary fallback)
    v
Port & Service Enumeration   (native TCP connect scan, or Nmap if installed)
    v
HTTP/HTTPS Reconnaissance    (headers, redirects, robots.txt, sitemap.xml)
    v
TLS Analysis                 (protocol, cipher, cert validity/expiry, SANs)
    v
Technology Fingerprinting    (evidence + confidence, never asserted blindly)
    v
Web Crawling                 (bounded, same-host, forms/links/scripts)
    v
Endpoint / Parameter Discovery (aggregated from crawl, JS, robots, sitemap)
    v
JavaScript Analysis          (static regex analysis, no execution)
    v
Directory / Content Discovery (soft-404 baseline filtering, optional FFUF)
    v
Non-destructive Vulnerability Indicators (headers, cookies, disclosure,
                                            injection indicators)
    v
CVE Correlation               (NVD product/version match; unknown versions skipped)
    v
Attack Surface Map            (structured summary tree)
    v
Risk Scoring                  (severity x confidence weighted)
    v
HTML + JSON Report
```

## Design principles

1. **Non-destructive by design.** No module performs exploitation,
   credential theft, data modification/deletion, or denial-of-service.
   Injection checks use a single harmless marker/character and read the
   response - nothing is written to the target.

2. **Evidence over assertion.** Every vulnerability finding, CVE match,
   and technology detection carries an explicit `confidence` level and,
   where applicable, `manual_verification_required: true`. The tool
   never claims "confirmed" when it only has an indicator.

3. **Dependency-free core.** The scanning/analysis engine runs on the
   Python 3 standard library alone. External tools (Nmap, FFUF, Nikto,
   dig, whois) are optional accelerants, never requirements - `--check-
   dependencies` shows what's available, and every module degrades to a
   native fallback when a tool is missing.

4. **Bounded, not exhaustive.** The crawler has hard page/depth limits,
   content discovery uses a curated (not internet-scale) wordlist by
   default, and CVE lookups are capped and rate-limited. This is a
   reconnaissance and learning framework, not a substitute for a full
   commercial engagement.

5. **Fail gracefully, always.** Every network call, subprocess
   invocation, and parse operation is wrapped so that one module's
   failure (missing tool, unreachable API, malformed response) never
   stops the rest of the scan.

## What this is not

AutoVAPT is not a replacement for Burp Suite, Nmap, Nuclei, OWASP ZAP,
or a commercial vulnerability scanner. It's an orchestration and
learning framework that demonstrates understanding of the VAPT
methodology end-to-end - useful for a portfolio, a CTF/lab workflow, or
as a first pass before deeper manual testing.
