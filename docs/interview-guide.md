# Interview Guide: Talking About AutoVAPT

A cheat sheet for discussing this project in a VAPT/SOC/pentest interview.

## 30-second pitch

"AutoVAPT is a reconnaissance and vulnerability-indicator framework I
built to understand the full VAPT methodology end-to-end - from
authorization and DNS recon through port scanning, web crawling,
content discovery, and CVE correlation - producing a client-style HTML/
PDF report. The core runs entirely on the Python standard library with
zero required dependencies; tools like Nmap, FFUF, and Nikto are
optional integrations with native fallbacks."

## Likely questions and how to answer them

**"Why did you build your own tool instead of just using Nmap/Burp/Nuclei?"**
> I wasn't trying to replace them - I use them as optional accelerants
> (Nmap for service detection, FFUF/Nikto if installed). The point was
> to understand *why* each phase of an assessment exists and how the
> outputs of one phase feed the next (e.g. detected service versions
> feeding CVE correlation, crawled JS feeding endpoint discovery).
> Building the orchestration myself forced me to actually understand
> that pipeline instead of just running tools.

**"How do you avoid false positives / how do you know a finding is real?"**
> I don't claim things are confirmed. Every finding has a `confidence`
> field and a `manual_verification_required` flag - a reflected marker
> or a SQL error signature is an *indicator*, not a confirmed
> vulnerability. That's deliberate: real scanner output (Nessus/Burp/
> Nuclei) works the same way, and conflating "the tool flagged it" with
> "it's exploitable" is a rookie mistake I wanted to avoid baking into
> my own tool.

**"What's the soft-404 problem and how did you solve it?"**
> Some apps return HTTP 200 for a "not found" page (SPA routers,
> custom error pages) instead of a real 404. I request a random,
> near-certainly-nonexistent path first to fingerprint that behavior
> (status + response length), then compare every real probe against
> that baseline before reporting it as "discovered" - otherwise you get
> a report full of false "found" directories.

**"Walk me through what happens when I run a scan."**
> Authorization gate first - nothing runs without explicit confirmation.
> Then DNS/subdomain/RDAP recon, port scanning, then the web layer
> (HTTP headers, TLS, tech fingerprinting, a bounded same-host crawl,
> JS static analysis, content discovery with soft-404 filtering), then
> vulnerability indicator checks and CVE correlation, then everything
> gets aggregated into an attack-surface map, risk-scored, and rendered
> into an HTML/PDF report plus a raw JSON file.

**"What would you add if you had more time?"**
> Authenticated scanning (session/cookie reuse across the crawler and
> content discovery), an Active Directory module (I have a companion
> project for that - Kerberoasting/BloodHound against a GOAD lab), a
> proper CPE version-range comparator for CVE correlation instead of
> flagging every match for manual review, and a lightweight web
> dashboard instead of static HTML reports.

**"What are its limitations? Don't oversell it."**
> It's a recon/indicator framework, not an exploitation engine - by
> design. The native TCP-connect scanner is slower and less accurate
> than Nmap's SYN scan and service fingerprinting. CVE correlation is
> keyword-based, not authoritative CPE matching, so every hit needs
> manual confirmation. The crawler doesn't execute JavaScript, so
> SPA-heavy sites will under-report endpoints unless FFUF/manual
> testing fills the gap. It's a learning and first-pass tool, not a
> replacement for a licensed commercial scanner or manual pentester.

## Things to have ready to show

- Live `--check-dependencies` output (shows graceful degradation)
- A generated `vapt-report.html`/`.pdf` from `examples/lab_server.py`
- `python3 -m unittest discover -s tests -v` passing
- The `DISCLAIMER.md` - shows you understand the legal/ethical side,
  which matters as much as the technical side in this field
