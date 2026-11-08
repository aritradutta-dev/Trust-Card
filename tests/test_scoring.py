"""Unit tests for the 7-pillar risk scoring and indicator calculation."""

from __future__ import annotations

import unittest

from app.scoring import calculate_risk_scoring
from app.verdict import decide_verdict


class TestRiskScoring(unittest.TestCase):
    def test_local_only_marks_live_pillars_unchecked(self):
        findings = []
        scoring = calculate_risk_scoring(
            findings,
            live_scan_done=False,
            has_message_context=False,
            feed_available=True,
        )

        pillars = scoring["pillars"]
        self.assertEqual(scoring["checked_count"], 3)  # Threat Intel, URL, Community
        self.assertEqual(pillars["page_content"]["status"], "not_checked")
        self.assertEqual(pillars["page_content"]["why"], "Not checked (run a live scan)")
        self.assertEqual(pillars["certificate"]["status"], "not_checked")
        self.assertEqual(pillars["certificate"]["why"], "Not checked (run a live scan)")
        self.assertEqual(pillars["web_security"]["status"], "not_checked")
        self.assertEqual(pillars["web_security"]["why"], "Not checked (run a live scan)")
        self.assertEqual(pillars["message_context"]["status"], "not_checked")
        self.assertEqual(pillars["message_context"]["why"], "Not checked (paste the message that accompanied the link)")
        self.assertEqual(scoring["score"], 0)
        self.assertIn("across 3 of 7 checks", scoring["summary"])

    def test_threat_feed_match_gives_alert_and_high_score(self):
        findings = [
            {
                "id": "feed-urlhaus",
                "category": "known_threat",
                "severity": "high",
                "summary": "Exact threat match",
                "group": "threat_intelligence",
                "confirmed": True,
            }
        ]
        scoring = calculate_risk_scoring(
            findings,
            live_scan_done=False,
            has_message_context=False,
            feed_available=True,
        )
        ti = scoring["pillars"]["threat_intelligence"]
        self.assertEqual(ti["status"], "alert")
        self.assertEqual(ti["score"], 100)
        # In local check without community findings, Threat Intel (35) + URL (20) = 55 total weight
        # Score = 100 * (35 / 55) = 64
        self.assertGreaterEqual(scoring["score"], 60)

    def test_url_lookalike_and_brand_impersonation_score(self):
        findings = [
            {
                "id": "lookalike-sbi",
                "category": "lookalike_domain",
                "severity": "medium",
                "summary": "Targeted lookalike of State Bank of India",
                "group": "url_lookalike",
            }
        ]
        scoring = calculate_risk_scoring(
            findings,
            live_scan_done=False,
            has_message_context=False,
            feed_available=True,
        )
        url_pillar = scoring["pillars"]["url_and_impersonation"]
        self.assertEqual(url_pillar["status"], "alert")
        self.assertEqual(url_pillar["score"], 80)

    def test_live_scan_checks_all_pillars_when_context_present(self):
        findings = []
        scoring = calculate_risk_scoring(
            findings,
            live_scan_done=True,
            has_message_context=True,
            feed_available=True,
        )
        self.assertEqual(scoring["checked_count"], 7)
        self.assertEqual(len(scoring["unchecked_pillars"]), 0)
        self.assertEqual(scoring["score"], 0)
        self.assertIn("across 7 of 7 checks", scoring["summary"])
        for p in scoring["pillars"].values():
            self.assertEqual(p["status"], "clear")

    def test_community_weight_rebalancing(self):
        # Clear community check has 0 weight so as not to dilute other signals
        findings_no_comm = [
            {
                "id": "feed-1",
                "category": "known_threat",
                "severity": "high",
                "group": "threat_intelligence",
                "confirmed": True,
            }
        ]
        score_no_comm = calculate_risk_scoring(
            findings_no_comm,
            live_scan_done=True,
            has_message_context=True,
            feed_available=True,
        )
        # Now with confirmed community report
        findings_with_comm = findings_no_comm + [
            {
                "id": "report-1",
                "category": "community_report",
                "severity": "high",
                "group": "community_report",
                "confirmed": True,
            }
        ]
        score_with_comm = calculate_risk_scoring(
            findings_with_comm,
            live_scan_done=True,
            has_message_context=True,
            feed_available=True,
        )
        self.assertEqual(score_with_comm["pillars"]["community"]["status"], "alert")
        self.assertEqual(score_with_comm["pillars"]["community"]["score"], 100)
        self.assertGreater(score_with_comm["score"], score_no_comm["score"])

    def test_invariant_technical_findings_never_yield_known_threat(self):
        """CRUCIAL INVARIANT: A high risk score from technical findings (headers, expiry)
        must NEVER cause decide_verdict to return 'known_threat'."""
        technical_findings = [
            {"id": "header-hsts-missing", "category": "security_header", "severity": "low", "group": "security_headers"},
            {"id": "header-csp-missing", "category": "security_header", "severity": "low", "group": "security_headers"},
            {"id": "header-xfo-missing", "category": "security_header", "severity": "low", "group": "security_headers"},
            {"id": "header-nosniff-missing", "category": "security_header", "severity": "low", "group": "security_headers"},
            {"id": "outdated-server", "category": "outdated_software", "severity": "low", "group": "security_headers"},
            {"id": "cert-expired", "category": "certificate", "severity": "medium", "group": "certificate"},
        ]

        scoring = calculate_risk_scoring(
            technical_findings,
            live_scan_done=True,
            has_message_context=False,
            feed_available=True,
        )
        # Even if certificate & web_security have elevated scores:
        self.assertGreater(scoring["score"], 0)

        # Verdict must NOT be known_threat
        verdict_result = decide_verdict(
            technical_findings,
            scan_complete=True,
            feed_stale=False,
            live_scan_done=True,
            coverage="full",
        )
        self.assertNotEqual(verdict_result["verdict"], "known_threat")
        self.assertNotEqual(verdict_result["verdict"], "suspicious")
        self.assertEqual(verdict_result["verdict"], "caution")  # Bad cert on its own gives caution!


if __name__ == "__main__":
    unittest.main()
