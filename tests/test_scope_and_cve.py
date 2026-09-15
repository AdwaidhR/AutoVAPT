import unittest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.directory_bruteforce import _join_base_path, _display_path
from modules.vulnerability_scanner import _join_base_path as vuln_join_base_path
from modules.cve_correlator import run as cve_run


class TestApplicationPathScope(unittest.TestCase):
    def test_directory_join_preserves_application_path(self):
        self.assertEqual(_join_base_path("http://127.0.0.1:8080/WebGoat/", ".env"),
                         "http://127.0.0.1:8080/WebGoat/.env")
        self.assertEqual(_display_path("http://127.0.0.1:8080/WebGoat/.env"), "/WebGoat/.env")

    def test_directory_join_handles_leading_slash(self):
        self.assertEqual(_join_base_path("http://example.test/app", "/admin"),
                         "http://example.test/app/admin")

    def test_vulnerability_probe_preserves_application_path(self):
        self.assertEqual(vuln_join_base_path("http://127.0.0.1:8080/WebGoat/", "/.git/HEAD"),
                         "http://127.0.0.1:8080/WebGoat/.git/HEAD")
        self.assertEqual(vuln_join_base_path("http://127.0.0.1:8080/WebGoat/", "?id=1"),
                         "http://127.0.0.1:8080/WebGoat/?id=1")


class TestCVEConservatism(unittest.TestCase):
    def test_unknown_version_is_skipped(self):
        result = cve_run([{"port": 8080, "service": "http", "product": "Apache Tomcat", "version": ""}])
        self.assertEqual(result["services_checked"], 0)
        self.assertEqual(len(result["results"]), 0)
        self.assertEqual(len(result["skipped"]), 1)
        self.assertIn("Version not detected", result["skipped"][0]["reason"])


if __name__ == "__main__":
    unittest.main()

class TestEndpointScope(unittest.TestCase):
    def test_external_js_urls_are_not_target_endpoints(self):
        result = __import__('modules.endpoint_discovery', fromlist=['run']).run(
            crawl_result={"base_url": "https://example.test/app/", "pages": [], "forms": [], "scripts": []},
            js_findings={"files": [{"url": "https://example.test/app/main.js", "endpoints_found": [
                "/app/api/users", "https://example.test/app/login", "https://cdn.example.net/lib.js",
                "https://github.com/vendor/project", "/api/root-outside-app"
            ]}]},
            target_url="https://example.test/app/",
        )
        urls = {e["url"] for e in result["endpoints"]}
        external = {e["url"] for e in result["external_references"]}
        self.assertIn("https://example.test/app/api/users", urls)
        self.assertIn("https://example.test/app/login", urls)
        self.assertNotIn("https://cdn.example.net/lib.js", urls)
        self.assertNotIn("https://github.com/vendor/project", urls)
        self.assertIn("https://cdn.example.net/lib.js", external)
        self.assertIn("https://github.com/vendor/project", external)
        self.assertIn("https://example.test/api/root-outside-app", external)
        self.assertEqual(result["total_endpoints"], 2)

    def test_root_scope_allows_same_host_paths(self):
        result = __import__('modules.endpoint_discovery', fromlist=['run']).run(
            crawl_result={"base_url": "https://example.test/", "pages": [], "forms": [], "scripts": []},
            js_findings={"files": [{"url": "https://example.test/main.js", "endpoints_found": [
                "/api/users", "https://example.test/login", "https://other.test/x"
            ]}]},
            target_url="https://example.test/",
        )
        self.assertEqual(result["total_endpoints"], 2)
        self.assertEqual(result["total_external_references"], 1)


class TestJavaScriptScope(unittest.TestCase):
    def test_js_classifies_external_references(self):
        from modules.js_analyzer import run
        import modules.js_analyzer as js_mod
        original = js_mod._analyze_single
        try:
            js_mod._analyze_single = lambda url: {
                "url": url, "fetched": True,
                "endpoints_found": ["/app/api/users", "https://github.com/x/y", "https://cdn.example.net/x.js"],
                "sensitive_indicators": [],
            }
            result = run(["https://example.test/app/main.js"], target_url="https://example.test/app/")
            self.assertEqual(result["unique_endpoints_found"], ["https://example.test/app/api/users"])
            self.assertEqual(set(result["external_references"]), {"https://cdn.example.net/x.js", "https://github.com/x/y"})
        finally:
            js_mod._analyze_single = original

class TestDirectoryBaseline(unittest.TestCase):
    def test_redirect_baseline_is_filtered(self):
        from modules.directory_bruteforce import _is_soft_404
        baseline = {"status": 302, "length": 0, "location": "/WebGoat/login"}
        self.assertTrue(_is_soft_404(302, 0, baseline, location="/WebGoat/login"))
        self.assertFalse(_is_soft_404(302, 100, baseline, location="/WebGoat/admin"))

class TestCVETargetSeparation(unittest.TestCase):
    def test_versioned_services_are_classified_by_target_port(self):
        import modules.cve_correlator as cve_mod
        original = cve_mod._query_nvd
        try:
            cve_mod._query_nvd = lambda product, version: {"vulnerabilities": []}
            result = cve_run([
                {"port": 8080, "service": "http", "product": "Apache Tomcat", "version": "10.1"},
                {"port": 80, "service": "http", "product": "Apache httpd", "version": "2.4.66"},
            ], target_port=8080)
            by_port = {x["port"]: x for x in result["results"]}
            self.assertTrue(by_port[8080]["target_service"])
            self.assertFalse(by_port[80]["target_service"])
            self.assertEqual(by_port[80]["classification"], "Host-level service outside requested target port")
        finally:
            cve_mod._query_nvd = original


class TestRDAPIgnoresDomainLookupForIPTargets(unittest.TestCase):
    def test_ip_target_skips_domain_rdap(self):
        # Regression test: rdap.run() previously called _domain_rdap() even
        # when the target was a bare IP (e.g. querying rdap.org/domain/127.0.0.1,
        # which is meaningless). It must be skipped for IP targets.
        import modules.rdap as rdap_mod
        original_domain = rdap_mod._domain_rdap
        original_ip = rdap_mod._ip_rdap
        original_whois = rdap_mod._whois_lookup
        called = {"domain_rdap": False}
        try:
            rdap_mod._domain_rdap = lambda d: called.__setitem__("domain_rdap", True) or None
            rdap_mod._ip_rdap = lambda ip: {"handle": "TEST-NET", "name": "TEST"}
            rdap_mod._whois_lookup = lambda d: None
            result = rdap_mod.run("127.0.0.1", resolved_ips=["127.0.0.1"])
            self.assertFalse(called["domain_rdap"], "_domain_rdap() must not be called for an IP target")
            self.assertIn("127.0.0.1", result["ip_rdap"])
            self.assertIn("Target is an IP address", result.get("note_target_type", ""))
        finally:
            rdap_mod._domain_rdap = original_domain
            rdap_mod._ip_rdap = original_ip
            rdap_mod._whois_lookup = original_whois


class TestJSAnalyzerAppPrefixedEndpoints(unittest.TestCase):
    """
    Regression tests for a bug where JS endpoint patterns only matched
    keywords (api/, login, admin, ...) immediately after the opening
    quote, silently missing endpoints on any app mounted under a path
    prefix - e.g. WebGoat's JS referencing "/WebGoat/api/v1/session"
    instead of a root-level "/api/v1/session".
    """

    def test_app_prefixed_api_endpoint_is_detected(self):
        import modules.js_analyzer as js_mod
        import re
        text = "const base='/WebGoat/api/v1'; fetch(base+'/session');"
        found = set()
        for pattern in js_mod.ENDPOINT_PATTERNS:
            for m in re.findall(pattern, text):
                found.add(m if isinstance(m, str) else m[0])
        for m in re.findall(js_mod.ANY_QUOTED_PATH, text):
            if js_mod.INTERESTING_SEGMENT.search(m + '"'):
                found.add(m)
        self.assertIn("/WebGoat/api/v1", found)

    def test_app_prefixed_login_and_admin_detected(self):
        import modules.js_analyzer as js_mod
        import re
        text = "var a='/App/login'; var b='/App/admin/users'; var c='/App/static/style.css';"
        found = set()
        for m in re.findall(js_mod.ANY_QUOTED_PATH, text):
            if js_mod.INTERESTING_SEGMENT.search(m + '"'):
                found.add(m)
        self.assertIn("/App/login", found)
        self.assertIn("/App/admin/users", found)
        self.assertNotIn("/App/static/style.css", found)

    def test_root_level_endpoints_still_detected(self):
        import modules.js_analyzer as js_mod
        import re
        text = "fetch('/api/v1/session');"
        found = set()
        for pattern in js_mod.ENDPOINT_PATTERNS:
            for m in re.findall(pattern, text):
                found.add(m if isinstance(m, str) else m[0])
        self.assertIn("/api/v1/session", found)


class TestTLSPortRegression(unittest.TestCase):
    """
    Regression test for a bug where TLS analysis always connected to
    port 443 even when the target explicitly specified a different
    HTTPS port, because main.py's TLS phase never passed the target's
    actual port through.
    """

    def test_explicit_port_is_used(self):
        from main import resolve_tls_port
        self.assertEqual(resolve_tls_port(8443), 8443)

    def test_defaults_to_443_when_not_specified(self):
        from main import resolve_tls_port
        self.assertEqual(resolve_tls_port(None), 443)
