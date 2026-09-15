import unittest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.dns_recon import _resolve_a_aaaa, run as dns_run
from modules import rdap


class TestDNSRecon(unittest.TestCase):
    def test_resolve_localhost(self):
        ipv4, ipv6 = _resolve_a_aaaa("localhost")
        self.assertIn("127.0.0.1", ipv4)

    def test_resolve_invalid_host_returns_empty(self):
        ipv4, ipv6 = _resolve_a_aaaa("this-domain-should-not-exist-autovapt-test.invalid")
        self.assertEqual(ipv4, [])
        self.assertEqual(ipv6, [])

    def test_ip_target_skips_domain_record_queries(self):
        result = dns_run("127.0.0.1")
        self.assertEqual(result["target_type"], "IPv4")
        self.assertIsNone(result["mx"])
        self.assertIsNone(result["ns"])
        self.assertIsNone(result["txt"])
        self.assertIsNone(result["soa"])


class TestRDAP(unittest.TestCase):
    def test_whois_lookup_returns_none_gracefully_if_missing(self):
        # Should never raise even if `whois` binary is absent
        result = rdap._whois_lookup("example.com")
        self.assertTrue(result is None or isinstance(result, str))


if __name__ == "__main__":
    unittest.main()
