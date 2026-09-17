"""
Report Generator Module
--------------------------
Builds the HTML report using plain Python string building + `html`
module escaping - Jinja2 is not required. This keeps the entire core
framework dependency-free while still producing a genuinely
professional, sectioned report.

PDF export is optional: if `weasyprint` happens to be installed we use
it; otherwise we try `wkhtmltopdf` or `libreoffice --headless` as
external binaries; if none are available we simply skip PDF and say so
- the HTML report is always produced regardless.
"""
import os
import shutil
import subprocess
from html import escape as esc
from .utils import save_json, log
from . import risk_engine

CSS = """
:root{--critical:#7a1f1f;--high:#b3401a;--medium:#b8860b;--low:#2c6e49;--info:#3a4a5c;
--dark:#1a1f2b;--panel:#f5f6f8;--border:#dcdfe4;}
*{box-sizing:border-box;}
body{font-family:'Segoe UI',Arial,sans-serif;margin:0;color:#1a1f2b;background:#fff;}
.cover{background:var(--dark);color:#fff;padding:50px;}
.cover h1{font-size:28px;margin:0 0 6px;}
.cover .sub{color:#9aa4b2;font-size:14px;}
.meta-row{margin-top:24px;display:flex;flex-wrap:wrap;gap:30px;font-size:13px;}
.meta-row div span{display:block;color:#9aa4b2;font-size:11px;text-transform:uppercase;letter-spacing:.5px;}
section{padding:26px 50px;border-bottom:1px solid var(--border);}
h2{font-size:19px;border-left:4px solid var(--dark);padding-left:12px;margin-bottom:16px;}
h3{font-size:15px;margin:16px 0 8px;}
table{width:100%;border-collapse:collapse;margin-bottom:16px;font-size:13px;}
th,td{text-align:left;padding:7px 9px;border:1px solid var(--border);vertical-align:top;}
th{background:var(--panel);}
.badge{display:inline-block;padding:2px 9px;border-radius:3px;color:#fff;font-size:11px;font-weight:600;}
.Critical{background:var(--critical);} .High{background:var(--high);}
.Medium{background:var(--medium);} .Low{background:var(--low);} .Info,.Informational{background:var(--info);}
.risk-grid{display:flex;gap:14px;margin-bottom:18px;flex-wrap:wrap;}
.risk-card{flex:1;min-width:100px;padding:14px;border-radius:6px;text-align:center;color:#fff;}
.risk-card .num{font-size:24px;font-weight:700;} .risk-card .label{font-size:11px;text-transform:uppercase;}
.disclaimer{background:#fff8e6;border:1px solid #e8d28a;padding:12px 16px;border-radius:5px;font-size:12.5px;}
.mono{font-family:'Courier New',monospace;background:var(--panel);padding:2px 6px;border-radius:3px;font-size:12px;}
.empty-note{color:#7a8290;font-style:italic;font-size:13px;}
footer{padding:18px 50px;font-size:11px;color:#7a8290;}
.toc{columns:2;font-size:13px;} .toc a{color:#1a1f2b;text-decoration:none;} .toc a:hover{text-decoration:underline;}
"""


def _table(headers, rows, empty_msg="No data collected for this section."):
    if not rows:
        return f'<p class="empty-note">{esc(empty_msg)}</p>'
    out = "<table><tr>" + "".join(f"<th>{esc(h)}</th>" for h in headers) + "</tr>"
    for row in rows:
        out += "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
    out += "</table>"
    return out


def _badge(sev):
    sev = sev or "Info"
    return f'<span class="badge {esc(sev)}">{esc(sev)}</span>'


def _section(title, anchor, body_html):
    return f'<section id="{anchor}"><h2>{esc(title)}</h2>{body_html}</section>'


# ---- Individual section renderers -----------------------------------------

def _sec_target(results):
    meta = results.get("metadata", {})
    target_info = results.get("target_info", {})
    rows = [
        ["Host", esc(str(target_info.get("host") or ""))],
        ["Target port", esc(str(target_info.get("target_port") or "default"))],
        ["Application path", esc(str(target_info.get("application_path") or "/"))],
        ["Assessment target", esc(str(results.get("target", "")))],
        ["Authorization", "Confirmed by operator prior to scan execution"],
        ["Scan started", esc(str(meta.get("scan_start", "")))],
        ["Scan finished", esc(str(meta.get("scan_end", "")))],
        ["Duration", f'{meta.get("duration_seconds", "?")}s'],
        ["Modules executed", esc(", ".join(meta.get("modules_run", [])))],
    ]
    return _table(["Field", "Value"], rows)


def _sec_dns(dns):
    if not dns:
        return '<p class="empty-note">DNS module not run.</p>'
    rows = []
    for label, val in [("IPv4", dns.get("ipv4")), ("IPv6", dns.get("ipv6")),
                        ("CNAME", dns.get("cname")), ("MX", dns.get("mx")),
                        ("NS", dns.get("ns")), ("TXT", dns.get("txt")),
                        ("SOA", dns.get("soa"))]:
        rows.append([label, esc(", ".join(val)) if val else "&mdash;"])
    html = _table(["Record", "Value(s)"], rows)
    if dns.get("reverse_dns"):
        rev_rows = [[esc(ip), esc(name)] for ip, name in dns["reverse_dns"].items()]
        html += "<h3>Reverse DNS</h3>" + _table(["IP", "Hostname"], rev_rows)
    for note in dns.get("notes", []):
        html += f'<p class="empty-note">{esc(note)}</p>'
    return html


def _sec_subdomains(subdomains):
    if not subdomains:
        return '<p class="empty-note">Subdomain enumeration not run.</p>'
    rows = [
        [esc(d["hostname"]), esc(d.get("ip", "")),
         esc(str(d["https"]["status"])) if d.get("https") else "-",
         esc(str(d["http"]["status"])) if d.get("http") else "-"]
        for d in subdomains.get("discovered", [])
    ]
    html = f'<p>Discovered via: {esc(", ".join(subdomains.get("method", [])))}</p>'
    html += _table(["Hostname", "IP", "HTTPS", "HTTP"], rows, "No subdomains resolved.")
    if subdomains.get("crtsh_error"):
        html += f'<p class="empty-note">crt.sh: {esc(subdomains["crtsh_error"])}</p>'
    return html


def _sec_rdap(rdap):
    if not rdap:
        return '<p class="empty-note">RDAP/WHOIS module not run.</p>'
    html = ""
    if rdap.get("domain_rdap"):
        d = rdap["domain_rdap"]
        rows = [["Handle", esc(str(d.get("handle")))],
                ["Status", esc(", ".join(d.get("status") or []))],
                ["Nameservers", esc(", ".join(d.get("nameservers") or []))]]
        html += "<h3>Domain RDAP</h3>" + _table(["Field", "Value"], rows)
    if rdap.get("ip_rdap"):
        rows = [[esc(ip), esc(str(info.get("name"))), esc(str(info.get("country")))]
                for ip, info in rdap["ip_rdap"].items()]
        html += "<h3>IP / Network (RDAP)</h3>" + _table(["IP", "Network Name", "Country"], rows)
    if rdap.get("whois_text"):
        html += f'<h3>WHOIS (raw excerpt)</h3><pre class="mono" style="white-space:pre-wrap;">{esc(rdap["whois_text"][:1500])}</pre>'
    if rdap.get("note"):
        html += f'<p class="empty-note">{esc(rdap["note"])}</p>'
    return html or '<p class="empty-note">No RDAP/WHOIS data retrieved.</p>'


def _sec_ports(ports):
    if not ports:
        return '<p class="empty-note">Port scan not run.</p>'
    rows = [
        [p["port"], esc(p.get("protocol", "")), esc(p.get("service", "")),
         esc(p.get("product", "")), esc(p.get("version", "")), esc(p.get("banner", "") or "")]
        for p in ports.get("open_ports", [])
    ]
    html = f'<p>Engine: <span class="mono">{esc(ports.get("engine",""))}</span> | Spec: <span class="mono">{esc(ports.get("port_spec",""))}</span></p>'
    html += _table(["Port", "Proto", "Service", "Product", "Version", "Banner"], rows, "No open ports found.")
    if ports.get("error"):
        html += f'<p class="empty-note">{esc(ports["error"])}</p>'
    return html


def _sec_web(web):
    if not web:
        return '<p class="empty-note">HTTP/HTTPS recon not run.</p>'
    html = f'<p>Working base URL: <span class="mono">{esc(str(web.get("working_base_url")))}</span></p>'
    for scheme in ("https", "http"):
        r = web.get(scheme)
        if r:
            rows = [["Status", esc(str(r.get("status")))], ["Final URL", esc(str(r.get("final_url")))],
                    ["Title", esc(r.get("title", ""))], ["Content-Length", esc(str(r.get("content_length")))],
                    ["Response time", f'{r.get("elapsed_ms","?")} ms'], ["Error", esc(str(r.get("error") or "-"))]]
            html += f"<h3>{scheme.upper()}</h3>" + _table(["Field", "Value"], rows)
    for key, label in [("robots_txt", "robots.txt"), ("sitemap_xml", "sitemap.xml"),
                        ("security_txt", "security.txt")]:
        info = web.get(key) or {}
        status = "Found" if info.get("excerpt") is not None else "Not found"
        html += f'<p>{esc(label)}: {esc(status)} (HTTP {esc(str(info.get("status")))})</p>'
    return html


def _sec_tls(tls):
    if not tls:
        return '<p class="empty-note">TLS analysis not run.</p>'
    if tls.get("error"):
        return f'<p class="empty-note">{esc(tls["error"])}</p>'
    rows = [
        ["Protocol", esc(str(tls.get("protocol")))],
        ["Cipher Suite", esc(str(tls.get("cipher_suite")))],
        ["Subject", esc(str(tls.get("subject")))],
        ["Issuer", esc(str(tls.get("issuer")))],
        ["Valid Until", esc(str(tls.get("valid_until")))],
        ["Days Until Expiry", esc(str(tls.get("days_until_expiry")))],
        ["SANs", esc(", ".join(tls.get("subject_alt_names", [])))],
    ]
    html = _table(["Field", "Value"], rows)
    if tls.get("indicators"):
        ind_rows = [[esc(i["finding"]), _badge(i["severity"]), esc(i["confidence"])]
                    for i in tls["indicators"]]
        html += "<h3>TLS Indicators</h3>" + _table(["Finding", "Severity", "Confidence"], ind_rows)
    return html


def _sec_technologies(tech):
    rows = [[esc(t["technology"]), esc(t["evidence"]), esc(t["confidence"])] for t in (tech or [])]
    return _table(["Technology", "Evidence", "Confidence"], rows, "No technologies identified with sufficient evidence.")


def _sec_crawl(crawl):
    if not crawl:
        return '<p class="empty-note">Crawler not run.</p>'
    html = f'<p>{crawl.get("pages_crawled",0)} pages crawled (max_pages={crawl.get("max_pages")}, max_depth={crawl.get("max_depth")})</p>'
    rows = [[esc(p["url"]), esc(str(p.get("status"))), p.get("depth", 0)] for p in crawl.get("pages", [])[:60]]
    html += _table(["URL", "Status", "Depth"], rows, "No pages crawled.")
    return html


def _sec_endpoints(endpoints):
    if not endpoints:
        return '<p class="empty-note">Endpoint discovery not run.</p>'
    html = (f'<p>{endpoints.get("total_endpoints", 0)} in-scope target endpoints discovered; '
            f'{endpoints.get("total_external_references", 0)} external/out-of-scope references classified separately.</p>')
    rows = [[esc(e["url"]), esc(e["method"]), esc(", ".join(e["source"])), esc(", ".join(e.get("parameters", [])))]
            for e in endpoints.get("endpoints", [])[:80]]
    html += _table(["Target URL", "Method", "Source", "Parameters"], rows, "No in-scope endpoints discovered.")
    external = endpoints.get("external_references", [])
    if external:
        rows = [[esc(e["url"]), esc(", ".join(e["source"])), esc(e.get("reason", "outside assessment scope"))]
                for e in external[:80]]
        html += '<h3>External / Out-of-Scope References</h3>'
        html += _table(["Reference", "Source", "Classification"], rows)
    return html


def _sec_js(js):
    if not js:
        return '<p class="empty-note">JavaScript analysis not run.</p>'
    html = f"<p>{js.get('files_analyzed',0)} JS files analyzed.</p>"
    if js.get("unique_endpoints_found"):
        rows = [[esc(e)] for e in js["unique_endpoints_found"][:60]]
        html += "<h3>In-Scope Endpoints Found in JS</h3>" + _table(["Target Path/URL"], rows)
    if js.get("external_references"):
        rows = [[esc(e)] for e in js["external_references"][:60]]
        html += "<h3>External / Out-of-Scope References Found in JS</h3>" + _table(["Reference"], rows)
    if js.get("sensitive_indicators"):
        rows = [[esc(s["file"]), esc(s["label"])] for s in js["sensitive_indicators"]]
        html += "<h3>Potential Sensitive Client-Side References (manual verification required)</h3>"
        html += _table(["JS File", "Indicator"], rows)
    return html


def _sec_content_discovery(cd):
    if not cd:
        return '<p class="empty-note">Content discovery not run.</p>'
    html = f'<p>Engine: <span class="mono">{esc(cd.get("engine",""))}</span> | {cd.get("total_words",0)} words tested</p>'
    rows = [[esc(d["path"]), esc(str(d["status"])), esc(str(d.get("length",""))), esc(d.get("confidence",""))]
            for d in cd.get("discovered", [])]
    html += _table(["Path", "Status", "Length", "Confidence"], rows, "No paths discovered.")
    if cd.get("ffuf_note"):
        html += f'<p class="empty-note">{esc(cd["ffuf_note"])}</p>'
    return html


def _sec_headers_cookies(findings):
    cookie_findings = [f for f in findings if "Cookie" in f["title"]]
    header_findings = [f for f in findings
                        if f["category"] == "Security Misconfiguration"
                        and "Missing" in f["title"] and f not in cookie_findings]
    html = "<h3>Security Headers</h3>"
    rows = [[esc(f["title"]), _badge(f["severity"])] for f in header_findings]
    html += _table(["Finding", "Severity"], rows, "All checked security headers present.")
    html += "<h3>Cookie Security</h3>"
    rows = [[esc(f["title"]), _badge(f["severity"])] for f in cookie_findings]
    html += _table(["Finding", "Severity"], rows, "No cookie security issues detected.")
    return html


def _sec_findings(findings):
    if not findings:
        return '<p class="empty-note">No findings generated.</p>'
    html = ""
    for f in findings:
        html += f"""
        <div style="border:1px solid var(--border);border-radius:6px;padding:14px;margin-bottom:12px;">
          <h3 style="margin:0 0 6px;">{esc(f['id'])}: {esc(f['title'])} {_badge(f['severity'])}
              <span class="mono">confidence: {esc(f['confidence'])}</span></h3>
          <p><strong>Category:</strong> {esc(f['category'])} &nbsp;|&nbsp;
             <strong>Affected:</strong> <span class="mono">{esc(str(f['affected_url']))}</span></p>
          <p>{esc(f['description'])}</p>
          <p><strong>Evidence:</strong> {esc(f['evidence'])}</p>
          <p><strong>Remediation:</strong> {esc(f['remediation'])}</p>
          <p><strong>Manual verification required:</strong> {"Yes" if f['manual_verification_required'] else "No"}</p>
        </div>"""
    return html


def _sec_cves(cve_data):
    if not cve_data or (not cve_data.get("results") and not cve_data.get("skipped")):
        return '<p class="empty-note">No CVE correlation performed (no versioned services detected, or NVD unavailable).</p>'
    html = f'<p class="disclaimer">{esc(cve_data.get("methodology",""))}</p>'
    if cve_data.get("target_port") is not None:
        html += (f'<p class="empty-note"><strong>Risk-scoring boundary:</strong> only CVEs for '
                 f'target port {esc(str(cve_data.get("target_port")))} affect the application risk rating. '
                 f'Other services are retained as host-level observations.</p>')
    for svc in cve_data.get("skipped", []):
        label = svc.get("classification", "Target application service")
        html += (f'<p class="empty-note"><strong>Port {esc(str(svc.get("port")))} &mdash; '
                 f'{esc(svc.get("product", ""))}</strong> '
                 f'<span class="mono">[{esc(label)}]</span>: {esc(svc.get("reason", ""))}</p>')
    for svc in cve_data["results"]:
        label = svc.get("classification", "Target application service")
        html += (f"<h3>Port {svc.get('port')} &mdash; {esc(svc.get('product',''))} "
                 f"{esc(svc.get('version',''))} "
                 f"<span class=\"mono\">[{esc(label)}]</span></h3>")
        if svc.get("note"):
            html += f'<p class="empty-note">{esc(svc["note"])}</p>'
            continue
        rows = [[esc(c["cve_id"]), _badge(c["severity"].title() if c["severity"] else "Info"),
                 esc(str(c["cvss_score"])), esc(c["description"]), esc(c["match_type"])]
                for c in svc.get("cves", [])]
        html += _table(["CVE ID", "Severity", "CVSS", "Description", "Match Type"], rows,
                        "No CVEs correlated for this service.")
    return html


def _sec_attack_surface(surface):
    if not surface:
        return '<p class="empty-note">Attack surface map not generated.</p>'
    rows = [
        ["Resolved IPv4", esc(", ".join(surface["domains"]["resolved_ipv4"]))],
        ["Subdomains discovered", surface["subdomains"]["count"]],
        ["Open ports", surface["open_ports"]["count"]],
        ["Pages crawled", surface["web_applications"]["pages_crawled"]],
        ["Forms found", surface["web_applications"]["forms_found"]],
        ["Endpoints found", surface["web_applications"]["endpoints_found"]],
        ["Directories found", surface["web_applications"]["directories_found"]],
        ["Technologies identified", esc(", ".join(surface["web_applications"]["technologies_identified"]))],
        ["Total security findings", surface["security_findings_summary"]["total"]],
    ]
    return _table(["Metric", "Value"], rows)


def _sec_external_tools(results, tool_versions=None):
    metadata = results.get("metadata", {})
    tools = metadata.get("external_tools", {})
    versions = tool_versions or tools.get("versions", {})
    roles = {"nmap":"Port/service enumeration", "ffuf":"Web content discovery", "nikto":"Web-server assessment", "curl":"HTTP(S) compatibility fallback"}
    rows=[]
    for name in ("nmap","ffuf","nikto","curl"):
        info=tools.get(name,{})
        status="Used" if info.get("used") else ("Available" if info.get("available") else "Not installed")
        rows.append([esc(name.upper()),esc(status),esc(str(versions.get(name,"not available"))),esc(roles[name])])
    html=_table(["Tool","Status","Version","Role"],rows)
    nikto=results.get("nikto") or {}
    if nikto:
        nrows=[[esc(x.get("raw","")),"Yes" if x.get("manual_verification_required") else "No"] for x in nikto.get("raw_findings",[])]
        html += "<h3>Nikto Results</h3>" + _table(["Nikto Indicator","Manual Verification"],nrows,"Nikto ran but produced no parsed indicators.")
        if nikto.get("note"):
            html += f'<p class="empty-note">{esc(str(nikto["note"]))}</p>'
    if tools.get("curl",{}).get("used"):
        count = int(tools.get("curl",{}).get("fallback_count", 0))
        if count:
            html += f'<p><strong>cURL:</strong> The compatibility fallback was used after the primary Python HTTP client failed ({count} fallback request(s)).</p>'
        else:
            html += '<p><strong>cURL:</strong> The compatibility fallback was used after the primary Python HTTP client failed.</p>'
    return html


def _sec_methodology():
    return """
    <ol>
      <li>Authorization confirmed by operator before any active module ran.</li>
      <li>Passive/DNS reconnaissance (WHOIS, RDAP, DNS records, certificate-transparency subdomain discovery).</li>
      <li>Port and service enumeration (native TCP-connect scan, or Nmap if installed).</li>
      <li>HTTP/HTTPS reconnaissance, TLS analysis, and technology fingerprinting.</li>
      <li>Bounded same-host web crawl and endpoint/parameter inventory.</li>
      <li>Static JavaScript analysis (no code execution).</li>
      <li>Content discovery with soft-404 baseline filtering.</li>
      <li>Non-destructive vulnerability indicator checks (headers, cookies, disclosure, injection indicators).</li>
      <li>Conservative CVE correlation against the NVD database.</li>
      <li>Evidence-weighted risk scoring and reporting.</li>
    </ol>
    <p class="empty-note">This methodology mirrors, at a smaller scale, how commercial
    scanners (Nessus/OpenVAS/Burp/Nuclei) structure an automated assessment before human
    validation.</p>
    """


def generate(results, output_dir, fmt="html", tool_versions=None):
    os.makedirs(output_dir, exist_ok=True)

    findings = results.get("findings", {}).get("findings", [])
    risk = risk_engine.score(findings, results.get("cves"))
    results.setdefault("risk", {})
    results["risk"] = risk

    sections = [
        ("Assessment Target & Authorization", "scope", _sec_target(results)),
        ("Executive Summary", "exec-summary", f"""
            <p>This report presents automated reconnaissance and vulnerability-indicator
            results for <strong>{esc(str(results.get('target','')))}</strong>, produced by
            AutoVAPT. All indicator-based findings require manual verification by a
            qualified tester before being treated as confirmed vulnerabilities.</p>
            <div class="risk-grid">
              <div class="risk-card Critical"><div class="num">{risk['counts']['Critical']}</div><div class="label">Critical</div></div>
              <div class="risk-card High"><div class="num">{risk['counts']['High']}</div><div class="label">High</div></div>
              <div class="risk-card Medium"><div class="num">{risk['counts']['Medium']}</div><div class="label">Medium</div></div>
              <div class="risk-card Low"><div class="num">{risk['counts']['Low']}</div><div class="label">Low</div></div>
              <div class="risk-card Info"><div class="num">{risk['counts']['Info']}</div><div class="label">Info</div></div>
            </div>
            <p>Overall risk rating: {_badge(risk['overall_risk'])} &nbsp; (weighted score: {risk['weighted_score']})</p>
        """),
        ("Attack Surface Overview", "attack-surface", _sec_attack_surface(results.get("attack_surface"))),
        ("DNS Reconnaissance", "dns", _sec_dns(results.get("dns"))),
        ("RDAP / WHOIS", "rdap", _sec_rdap(results.get("rdap"))),
        ("Subdomain Enumeration", "subdomains", _sec_subdomains(results.get("subdomains"))),
        ("Port & Service Enumeration", "ports", _sec_ports(results.get("ports"))),
        ("HTTP/HTTPS Reconnaissance", "http", _sec_web(results.get("web"))),
        ("TLS Analysis", "tls", _sec_tls(results.get("tls"))),
        ("Technology Fingerprinting", "tech", _sec_technologies(results.get("technologies"))),
        ("Web Crawl", "crawl", _sec_crawl(results.get("crawl"))),
        ("Endpoint & Parameter Discovery", "endpoints", _sec_endpoints(results.get("endpoints"))),
        ("JavaScript Analysis", "js", _sec_js(results.get("javascript"))),
        ("Directory / Content Discovery", "content", _sec_content_discovery(results.get("content_discovery"))),
        ("Security Headers & Cookies", "headers", _sec_headers_cookies(findings)),
        ("Vulnerability Findings", "findings", _sec_findings(findings)),
        ("CVE Correlation", "cves", _sec_cves(results.get("cves"))),
        ("External Security Tools", "external-tools", _sec_external_tools(results, tool_versions)),
        ("Methodology", "methodology", _sec_methodology()),
    ]

    toc_html = "<nav class='toc'>" + "".join(
        f'<div><a href="#{anchor}">{i+1}. {esc(title)}</a></div>'
        for i, (title, anchor, _) in enumerate(sections)
    ) + "</nav>"

    body = "".join(_section(title, anchor, html) for title, anchor, html in sections)

    tool_versions = tool_versions or {}
    tool_rows = "".join(f"<li>{esc(k)}: {esc(str(v))}</li>" for k, v in tool_versions.items())

    html_doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>AutoVAPT Report - {esc(str(results.get('target','')))}</title>
<style>{CSS}</style></head><body>
<div class="cover">
  <h1>Vulnerability Assessment &amp; Reconnaissance Report</h1>
  <div class="sub">Target: {esc(str(results.get('target','')))}</div>
  <div class="meta-row">
    <div><span>Generated</span>{esc(results.get('metadata',{}).get('generated_on',''))}</div>
    <div><span>Duration</span>{results.get('metadata',{}).get('duration_seconds','?')}s</div>
    <div><span>Overall Risk</span>{_badge(risk['overall_risk'])}</div>
  </div>
</div>
<section><h2>Table of Contents</h2>{toc_html}</section>
{body}
<section><h3>Tool Versions</h3><ul>{tool_rows or '<li>No optional external tools used.</li>'}</ul></section>
<footer>Generated by AutoVAPT | For authorized security testing only |
Automated indicators require manual verification before being treated as confirmed findings.</footer>
</body></html>"""

    html_path = os.path.join(output_dir, "vapt-report.html")
    with open(html_path, "w") as f:
        f.write(html_doc)
    log("REPORT", f"HTML report written -> {html_path}")

    json_path = os.path.join(output_dir, "raw_results.json")
    save_json(results, json_path)
    log("REPORT", f"JSON results written -> {json_path}")

    pdf_path = None
    if fmt in ("pdf", "both"):
        pdf_path = os.path.join(output_dir, "vapt-report.pdf")
        if not _convert_to_pdf(html_path, pdf_path):
            pdf_path = None

    return {"html": html_path, "json": json_path, "pdf": pdf_path}


def _convert_to_pdf(html_path, pdf_path):
    """PDF is always optional. Tries weasyprint, then wkhtmltopdf, then
    libreoffice --headless. Returns True if a PDF was produced."""
    try:
        from weasyprint import HTML  # optional, not in core requirements
        HTML(html_path).write_pdf(pdf_path)
        log("REPORT", f"PDF written -> {pdf_path} (weasyprint)")
        return True
    except ImportError:
        pass
    except Exception as e:
        log("WARN", f"weasyprint failed: {e}")

    if shutil.which("wkhtmltopdf"):
        try:
            subprocess.run(["wkhtmltopdf", "--quiet", html_path, pdf_path],
                            check=True, timeout=90)
            log("REPORT", f"PDF written -> {pdf_path} (wkhtmltopdf)")
            return True
        except Exception as e:
            log("WARN", f"wkhtmltopdf failed: {e}")

    if shutil.which("libreoffice"):
        try:
            outdir = os.path.dirname(pdf_path)
            subprocess.run(["libreoffice", "--headless", "--convert-to", "pdf",
                             "--outdir", outdir, html_path], check=True, timeout=90)
            log("REPORT", f"PDF written via LibreOffice -> {outdir}")
            return True
        except Exception as e:
            log("WARN", f"libreoffice conversion failed: {e}")

    log("WARN", "No PDF engine available (weasyprint/wkhtmltopdf/libreoffice all "
                "missing or failed). PDF export skipped - HTML report is still complete.")
    return False
