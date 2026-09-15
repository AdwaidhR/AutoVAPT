import unittest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules import risk_engine


def make_finding(severity, confidence="High"):
    return {"severity": severity, "confidence": confidence}


class TestRiskEngine(unittest.TestCase):
    def test_no_findings_is_informational(self):
        result = risk_engine.score([])
        self.assertEqual(result["overall_risk"], "Informational")
        self.assertEqual(result["weighted_score"], 0)

    def test_single_critical_drives_overall_critical(self):
        result = risk_engine.score([make_finding("Critical")])
        self.assertEqual(result["overall_risk"], "Critical")

    def test_two_high_drives_overall_high(self):
        result = risk_engine.score([make_finding("High"), make_finding("High")])
        self.assertEqual(result["overall_risk"], "High")

    def test_low_confidence_reduces_weighted_score(self):
        high_conf = risk_engine.score([make_finding("Medium", "High")])
        low_conf = risk_engine.score([make_finding("Medium", "Low")])
        self.assertGreater(high_conf["weighted_score"], low_conf["weighted_score"])

    def test_counts_are_accurate(self):
        findings = [make_finding("Low"), make_finding("Low"), make_finding("Medium")]
        result = risk_engine.score(findings)
        self.assertEqual(result["counts"]["Low"], 2)
        self.assertEqual(result["counts"]["Medium"], 1)


if __name__ == "__main__":
    unittest.main()

class TestCVETargetRiskBoundary(unittest.TestCase):
    def test_unrelated_service_cve_does_not_affect_application_risk(self):
        cves = {"results": [
            {"port": 8080, "target_service": True, "cves": []},
            {"port": 80, "target_service": False, "cves": [
                {"severity": "Critical", "cvss_score": 9.8}
            ]},
        ]}
        result = risk_engine.score([], cves)
        self.assertEqual(result["overall_risk"], "Informational")
        self.assertEqual(result["weighted_score"], 0)

    def test_target_service_cve_affects_application_risk(self):
        cves = {"results": [
            {"port": 8080, "target_service": True, "cves": [
                {"severity": "High", "cvss_score": 8.1}
            ]},
        ]}
        result = risk_engine.score([], cves)
        self.assertEqual(result["overall_risk"], "Medium")
        self.assertEqual(result["counts"]["High"], 1)
