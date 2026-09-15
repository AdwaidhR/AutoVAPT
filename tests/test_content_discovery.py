from modules.port_scanner import _merge_required_ports
import unittest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.directory_bruteforce import _is_soft_404
from modules.port_scanner import expand_ports


class TestRequiredPorts(unittest.TestCase):
    def test_required_port_is_added_without_expanding_range(self):
        self.assertEqual(_merge_required_ports("1-1000", [8080]), "1-1000,8080")

    def test_required_port_already_in_range_is_not_duplicated(self):
        self.assertEqual(_merge_required_ports("1-1000", [443]), "1-1000")


class TestSoft404(unittest.TestCase):
    def test_matches_baseline_status_and_similar_length(self):
        baseline = {"status": 200, "length": 500}
        self.assertTrue(_is_soft_404(200, 505, baseline, tolerance=25))

    def test_does_not_match_when_length_differs_significantly(self):
        baseline = {"status": 200, "length": 500}
        self.assertFalse(_is_soft_404(200, 5000, baseline, tolerance=25))

    def test_real_404_baseline_trusts_404_status(self):
        baseline = {"status": 404, "length": 0}
        self.assertFalse(_is_soft_404(404, 120, baseline))


class TestPortParsing(unittest.TestCase):
    def test_range(self):
        self.assertEqual(expand_ports("1-5"), [1, 2, 3, 4, 5])

    def test_comma_separated(self):
        self.assertEqual(expand_ports("22,80,443"), [22, 80, 443])

    def test_mixed(self):
        self.assertEqual(expand_ports("1-3,80"), [1, 2, 3, 80])

    def test_top_ports_keyword(self):
        ports = expand_ports("top-100")
        self.assertIn(80, ports)
        self.assertIn(443, ports)
        self.assertEqual(len(ports), len(set(ports)))  # de-duplicated

    def test_clamped_to_valid_range(self):
        ports = expand_ports("65530-65540")
        self.assertTrue(all(1 <= p <= 65535 for p in ports))


if __name__ == "__main__":
    unittest.main()
