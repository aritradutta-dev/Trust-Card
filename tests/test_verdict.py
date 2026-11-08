import unittest

from app.verdict import decide_verdict


class VerdictTests(unittest.TestCase):
    def test_one_high_signal_behavior_is_suspicious(self):
        result = decide_verdict(
            [{"severity": "high", "group": "credential_form", "confirmed": False}],
            scan_complete=True,
        )
        self.assertEqual(result["verdict"], "suspicious")

    def test_two_independent_medium_signals_are_suspicious(self):
        result = decide_verdict(
            [
                {"severity": "medium", "group": "message_context"},
                {"severity": "medium", "group": "redirect"},
            ],
            scan_complete=True,
        )
        self.assertEqual(result["verdict"], "suspicious")

    def test_duplicate_medium_findings_in_one_group_do_not_meet_threshold(self):
        result = decide_verdict(
            [
                {"severity": "medium", "group": "message_context"},
                {"severity": "medium", "group": "message_context"},
            ],
            scan_complete=True,
            coverage="full",
        )
        self.assertEqual(result["verdict"], "no_strong_warning")

    def test_only_prd_signal_groups_count_toward_suspicious_threshold(self):
        unknown_high = decide_verdict(
            [{"severity": "high", "group": "unknown_signal"}], scan_complete=True, coverage="full"
        )
        unknown_medium = decide_verdict(
            [
                {"severity": "medium", "group": "redirect"},
                {"severity": "medium", "group": "unknown_signal"},
            ],
            scan_complete=True,
            coverage="full",
        )
        self.assertEqual(unknown_high["verdict"], "no_strong_warning")
        self.assertEqual(unknown_medium["verdict"], "no_strong_warning")

    def test_low_urgency_context_does_not_make_the_link_suspicious(self):
        result = decide_verdict(
            [{"severity": "low", "group": "message_context"}], scan_complete=True, coverage="full"
        )
        self.assertEqual(result["verdict"], "no_strong_warning")

    def test_technical_warning_alone_is_not_a_phishing_verdict(self):
        result = decide_verdict(
            [{"severity": "high", "group": "tls", "category": "certificate"}],
            scan_complete=True,
            coverage="full",
        )
        self.assertEqual(result["verdict"], "no_strong_warning")

    def test_verified_match_is_known_threat_and_incomplete_scan_is_unable(self):
        known = decide_verdict(
            [{"confirmed": True, "group": "threat_intelligence"}], scan_complete=True
        )
        incomplete = decide_verdict([], scan_complete=False)
        self.assertEqual(known["verdict"], "known_threat")
        self.assertEqual(known["confidence"], "high")
        self.assertEqual(incomplete["verdict"], "unable_to_check")
        self.assertEqual(incomplete["confidence"], "low")

    def test_unrecognized_confirmed_flag_does_not_create_known_threat(self):
        result = decide_verdict(
            [{"confirmed": True, "group": "technical"}], scan_complete=True, coverage="full"
        )
        self.assertEqual(result["verdict"], "no_strong_warning")

    def test_qualifying_signal_remains_suspicious_when_scan_is_incomplete(self):
        result = decide_verdict(
            [{"severity": "high", "group": "credential_form"}], scan_complete=False
        )
        self.assertEqual(result, {"verdict": "suspicious", "confidence": "high"})

    def test_feed_staleness_caps_confidence(self):
        fresh = decide_verdict([], scan_complete=True, coverage="full")
        stale = decide_verdict([], scan_complete=True, feed_stale=True, coverage="full")
        self.assertEqual(fresh, {"verdict": "no_strong_warning", "confidence": "medium"})
        self.assertEqual(stale, {"verdict": "no_strong_warning", "confidence": "low"})

    def test_suspicious_confidence_depends_on_feed_freshness(self):
        finding = [{"severity": "high", "group": "credential_form"}]
        fresh = decide_verdict(finding, scan_complete=True)
        stale = decide_verdict(finding, scan_complete=True, feed_stale=True)
        self.assertEqual(fresh["confidence"], "high")
        self.assertEqual(stale["confidence"], "medium")

    # --- Phase 0 new tests ---

    def test_local_only_stale_feeds_shows_not_enough_info(self):
        """Empty local-only result with no feeds must not show green check."""
        result = decide_verdict(
            [], scan_complete=True, feed_stale=True, coverage="local_only"
        )
        self.assertEqual(result["verdict"], "not_enough_info")
        self.assertEqual(result["confidence"], "low")

    def test_local_only_fresh_feeds_shows_no_strong_warning(self):
        """Local-only with fresh feeds can show no_strong_warning."""
        result = decide_verdict(
            [], scan_complete=True, feed_stale=False, coverage="local_only"
        )
        self.assertEqual(result["verdict"], "no_strong_warning")
        self.assertEqual(result["confidence"], "medium")

    def test_caution_for_certificate_problem(self):
        """A certificate problem alone must show caution, not reassurance."""
        result = decide_verdict(
            [{"severity": "medium", "group": "certificate", "category": "certificate"}],
            scan_complete=True,
            coverage="full",
        )
        self.assertEqual(result["verdict"], "caution")
        self.assertEqual(result["confidence"], "medium")

    def test_certificate_plus_another_medium_is_suspicious(self):
        """Bad cert + another medium group = suspicious."""
        result = decide_verdict(
            [
                {"severity": "medium", "group": "certificate"},
                {"severity": "medium", "group": "message_context"},
            ],
            scan_complete=True,
        )
        self.assertEqual(result["verdict"], "suspicious")

    def test_certificate_medium_in_medium_groups(self):
        """Certificate medium counts as an independent medium group."""
        result = decide_verdict(
            [
                {"severity": "medium", "group": "certificate"},
                {"severity": "medium", "group": "redirect"},
            ],
            scan_complete=True,
        )
        self.assertEqual(result["verdict"], "suspicious")

    def test_url_lookalike_medium_in_medium_groups(self):
        """url_lookalike counts as an independent medium group."""
        result = decide_verdict(
            [
                {"severity": "medium", "group": "url_lookalike"},
                {"severity": "medium", "group": "message_context"},
            ],
            scan_complete=True,
        )
        self.assertEqual(result["verdict"], "suspicious")

    def test_score_never_turns_technical_only_into_known_threat(self):
        """Technical findings alone can never produce known_threat."""
        result = decide_verdict(
            [
                {"severity": "high", "group": "tls", "category": "certificate"},
                {"severity": "medium", "group": "security_headers"},
                {"severity": "medium", "group": "certificate"},
            ],
            scan_complete=True,
            coverage="full",
        )
        self.assertNotEqual(result["verdict"], "known_threat")


if __name__ == "__main__":
    unittest.main()
