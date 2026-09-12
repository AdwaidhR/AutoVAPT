import unittest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.vulnerability_scanner import _check_security_headers, _check_cookies


class TestSecurityHeaders(unittest.TestCase):
    def test_missing_headers_flagged(self):
        findings = _check_security_headers("https://example.com", {})
        titles = [f["title"] for f in findings]
        self.assertTrue(any("HSTS" in t for t in titles))
        self.assertTrue(any("Content-Security-Policy" in t for t in titles))

    def test_present_headers_not_flagged(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        findings = _check_security_headers("https://example.com", headers)
        self.assertEqual(findings, [])

    def test_hsts_not_flagged_on_plain_http(self):
        findings = _check_security_headers("http://example.com", {})
        titles = [f["title"] for f in findings]
        self.assertFalse(any("HSTS" in t for t in titles))


class TestCookies(unittest.TestCase):
    def test_missing_attributes_flagged(self):
        headers = {"Set-Cookie": "session=abc123; Path=/"}
        findings = _check_cookies("https://example.com", headers)
        self.assertEqual(len(findings), 1)
        self.assertIn("Secure", findings[0]["evidence"])
        self.assertIn("HttpOnly", findings[0]["evidence"])

    def test_secure_cookie_not_flagged(self):
        headers = {"Set-Cookie": "session=abc123; Secure; HttpOnly; SameSite=Strict"}
        findings = _check_cookies("https://example.com", headers)
        self.assertEqual(findings, [])

    def test_no_cookie_header_no_findings(self):
        findings = _check_cookies("https://example.com", {})
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
