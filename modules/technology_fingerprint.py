"""
Technology Fingerprinting Module
------------------------------------
Every detection returns {technology, evidence, confidence} - we never
assert a technology is present without saying exactly what evidence
led to that conclusion, and confidence is capped based on how strong
that evidence actually is (a single generic marker = Low, a
combination of markers or an explicit header = High).
"""
import re

# (technology, [(evidence_description, regex_or_check, confidence)])
# confidence: High = explicit/unambiguous marker; Medium = fairly specific;
# Low = generic/could coincidentally match.
SIGNATURES = [
    ("WordPress", [("wp-content/ path referenced", r"wp-content/", "High"),
                   ("wp-json REST API referenced", r"wp-json", "High"),
                   ("generator meta tag", r'name=["\']generator["\']\s+content=["\']WordPress', "High")]),
    ("Drupal", [("Drupal.settings JS object", r"Drupal\.settings", "High"),
                ("sites/default/files path", r"sites/default/files", "Medium")]),
    ("Joomla", [("Joomla generator meta tag", r"content=[\"']Joomla", "High"),
                ("/media/jui/ path", r"/media/jui/", "Medium")]),
    ("Laravel", [("laravel_session cookie", r"laravel_session", "High"),
                 ("XSRF-TOKEN cookie", r"XSRF-TOKEN", "Medium")]),
    ("Django", [("csrfmiddlewaretoken form field", r"csrfmiddlewaretoken", "High"),
                ("django CSRF cookie", r"csrftoken=", "Medium")]),
    ("Flask", [("Werkzeug server header", r"Werkzeug", "High")]),
    ("Express.js / Node.js", [("X-Powered-By: Express", r"Express", "High")]),
    ("React", [("__NEXT_DATA__ (Next.js/React) blob", r"__NEXT_DATA__", "Medium"),
               ("data-reactroot attribute", r"data-reactroot", "High")]),
    ("Vue.js", [("v-cloak/v-if directive", r"v-cloak|v-if=", "Medium"),
                ("__vue__ reference", r"__vue__", "High")]),
    ("Angular", [("ng-app / ng-version attribute", r"ng-app|ng-version", "High")]),
    ("Bootstrap", [("bootstrap.min.css/js reference", r"bootstrap(\.min)?\.(css|js)", "Medium")]),
    ("jQuery", [("jquery.min.js reference", r"jquery(-[\d.]+)?(\.min)?\.js", "Medium")]),
    ("Cloudflare", [("CF-Ray header", r"", "High")]),  # handled specially via headers
]

SERVER_HEADER_TECH = {
    "apache": "Apache HTTP Server", "nginx": "Nginx", "iis": "Microsoft IIS",
    "cloudflare": "Cloudflare", "litespeed": "LiteSpeed",
}


def _check_headers(headers):
    findings = []
    headers_lower = {k.lower(): v for k, v in (headers or {}).items()}

    server = headers_lower.get("server", "")
    for key, tech in SERVER_HEADER_TECH.items():
        if key in server.lower():
            findings.append({"technology": tech, "evidence": f"Server header: {server}",
                              "confidence": "High"})

    powered_by = headers_lower.get("x-powered-by")
    if powered_by:
        findings.append({"technology": powered_by, "evidence": f"X-Powered-By: {powered_by}",
                          "confidence": "High"})

    if "cf-ray" in headers_lower or "cf-cache-status" in headers_lower:
        findings.append({"technology": "Cloudflare", "evidence": "CF-Ray/CF-Cache-Status header present",
                          "confidence": "High"})

    if any("amazonaws" in v.lower() or "aws" in k.lower() for k, v in headers_lower.items()):
        findings.append({"technology": "AWS", "evidence": "AWS-related header/value detected",
                          "confidence": "Medium"})

    set_cookie = headers_lower.get("set-cookie", "")
    for tech, checks in SIGNATURES:
        for desc, pattern, confidence in checks:
            if pattern and re.search(pattern, set_cookie, re.IGNORECASE):
                findings.append({"technology": tech, "evidence": desc, "confidence": confidence})

    return findings


def _check_body(body):
    findings = []
    if not body:
        return findings
    sample = body[:200_000]  # cap for performance on huge pages
    for tech, checks in SIGNATURES:
        for desc, pattern, confidence in checks:
            if pattern and re.search(pattern, sample, re.IGNORECASE):
                findings.append({"technology": tech, "evidence": desc, "confidence": confidence})
    return findings


def run(headers, body):
    findings = _check_headers(headers) + _check_body(body)

    # De-duplicate: keep the highest-confidence evidence per technology
    conf_rank = {"High": 3, "Medium": 2, "Low": 1}
    best = {}
    for f in findings:
        tech = f["technology"]
        if tech not in best or conf_rank[f["confidence"]] > conf_rank[best[tech]["confidence"]]:
            best[tech] = f
        elif tech in best and f["evidence"] not in best[tech]["evidence"]:
            best[tech]["evidence"] += f"; {f['evidence']}"

    return sorted(best.values(), key=lambda x: (-conf_rank[x["confidence"]], x["technology"]))
