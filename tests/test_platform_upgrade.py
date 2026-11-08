"""Unit tests for the upgraded cybersecurity and threat detection platform."""

import tempfile
import unittest
from pathlib import Path

from app.ai_explainer import classify_risk, generate_security_explanation
from app.ct_service import lookup_domain_dns, search_certificate_transparency
from app.storage import (
    compare_scans,
    create_session,
    create_user,
    delete_scan,
    delete_session,
    get_dashboard_stats,
    get_forum_thread,
    get_scan,
    get_session_user,
    get_user_by_username_or_email,
    init_db,
    list_forum_threads,
    list_scans,
    record_scan,
    record_threat_intel,
    search_threat_intel,
    seed_default_forum_threads,
    upvote_forum_thread,
    create_forum_thread,
    create_forum_reply,
    verify_password,
)
from app.url_analysis import analyze_url, detect_target_category


class PlatformUpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        init_db(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_user_registration_login_and_session(self):
        # Register user
        user = create_user(self.db_path, "analyst_bob", "bob@example.com", "SecurePass@123", role="analyst")
        self.assertEqual(user["username"], "analyst_bob")
        self.assertEqual(user["role"], "analyst")

        # Lookup by username
        stored = get_user_by_username_or_email(self.db_path, "analyst_bob")
        self.assertIsNotNone(stored)
        self.assertTrue(verify_password("SecurePass@123", stored["password_hash"], stored["salt"]))
        self.assertFalse(verify_password("WrongPassword", stored["password_hash"], stored["salt"]))

        # Create session and retrieve
        token = create_session(self.db_path, user["id"])
        session_user = get_session_user(self.db_path, token)
        self.assertIsNotNone(session_user)
        self.assertEqual(session_user["username"], "analyst_bob")

        # Delete session
        delete_session(self.db_path, token)
        self.assertIsNone(get_session_user(self.db_path, token))

    def test_scan_history_recording_listing_and_deletion(self):
        user = create_user(self.db_path, "alice", "alice@test.local", "Password123")
        scan_id_1 = "scan-11111111111111111111111111111111"
        scan_id_2 = "scan-22222222222222222222222222222222"

        findings = [{"id": "url-lookalike-sbi", "group": "url_lookalike", "severity": "medium", "summary": "SBI lookalike"}]
        scoring = {"score": 75, "summary": "Risk 75/100", "checked_count": 4}

        record_scan(
            self.db_path,
            scan_id=scan_id_1,
            user_id=user["id"],
            url="https://sbi-login.fake.test/kyc",
            host="sbi-login.fake.test",
            mode="local",
            verdict="suspicious",
            confidence="medium",
            score=75,
            risk_class="high",
            checked_at="2026-11-08T12:00:00Z",
            summary="Suspicious banking impersonation detected",
            findings=findings,
            scoring=scoring,
        )

        record_scan(
            self.db_path,
            scan_id=scan_id_2,
            user_id=user["id"],
            url="https://example.com/",
            host="example.com",
            mode="full_scan",
            verdict="no_strong_warning",
            confidence="high",
            score=10,
            risk_class="safe",
            checked_at="2026-11-08T12:05:00Z",
            summary="No warning found",
            findings=[],
            scoring={"score": 10, "checked_count": 6},
        )

        # List scans
        scans, total = list_scans(self.db_path, user_id=user["id"])
        self.assertEqual(total, 2)
        self.assertEqual(len(scans), 2)

        # Filter by severity
        high_scans, high_total = list_scans(self.db_path, severity="high")
        self.assertEqual(high_total, 1)
        self.assertEqual(high_scans[0]["id"], scan_id_1)

        # Retrieve single scan
        s = get_scan(self.db_path, scan_id_1)
        self.assertIsNotNone(s)
        self.assertEqual(s["score"], 75)
        self.assertEqual(len(s["findings"]), 1)

        # Compare scans
        comp = compare_scans(self.db_path, scan_id_2, scan_id_1)
        self.assertEqual(comp["score_diff"], 65)
        self.assertEqual(len(comp["new_findings"]), 1)

        # Delete scan
        deleted = delete_scan(self.db_path, scan_id_1, user_id=user["id"])
        self.assertTrue(deleted)
        self.assertIsNone(get_scan(self.db_path, scan_id_1))

    def test_dashboard_stats_aggregation(self):
        record_scan(
            self.db_path,
            scan_id="scan-aaa",
            user_id=None,
            url="https://phish.example/login",
            host="phish.example",
            mode="local",
            verdict="known_threat",
            confidence="high",
            score=95,
            risk_class="malicious",
            checked_at="2026-11-08T12:00:00Z",
            summary="Known threat",
            findings=[],
            scoring={"score": 95, "checked_count": 3},
        )

        stats = get_dashboard_stats(self.db_path)
        self.assertEqual(stats["total_scans"], 1)
        self.assertEqual(stats["total_malicious"], 1)
        self.assertEqual(stats["severity_distribution"]["malicious"], 1)

    def test_threat_intel_search_and_recording(self):
        record_threat_intel(
            self.db_path,
            indicator="fake-sbi-portal.test",
            indicator_type="domain",
            category="fake_banking",
            severity="high",
            confidence="high",
            source="Community report",
            evidence="SMS phishing targeting SBI account holders",
            status="verified",
        )

        results = search_threat_intel(self.db_path, query="sbi")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["category"], "fake_banking")
        self.assertEqual(results[0]["status"], "verified")

    def test_ai_security_explanation_and_risk_classification(self):
        risk_info = classify_risk(score=85, verdict="known_threat", checked_count=4)
        self.assertEqual(risk_info["key"], "malicious")
        self.assertEqual(risk_info["label"], "Malicious / Critical Risk")

        exp = generate_security_explanation(
            url="https://demo-phish.trustcard.test/login",
            verdict="known_threat",
            confidence="high",
            score=85,
            risk_class="malicious",
            findings=[
                {"id": "feed-urlhaus", "group": "threat_intelligence", "summary": "Appears on URLhaus"},
                {"id": "url-lookalike-brand", "group": "url_lookalike", "summary": "Imitates Brand"},
            ],
            pillars={},
            mode="local",
        )
        self.assertIn("Malicious / Critical Risk", exp["summary"])
        self.assertTrue(len(exp["key_warning_signs"]) >= 2)
        self.assertTrue(len(exp["attack_techniques"]) >= 1)
        self.assertTrue(len(exp["recommended_remediation"]) >= 1)

    def test_new_url_analysis_signals(self):
        # 1. Plain HTTP
        http_findings = analyze_url("http://example.com/login")
        self.assertTrue(any(f["id"] == "url-structure-plain-http" for f in http_findings))

        # 2. Executable payload extension
        exe_findings = analyze_url("https://example.com/downloads/setup_invoice.exe")
        self.assertTrue(any("dangerous-ext-exe" in f["id"] for f in exe_findings))

        # 3. Open redirect parameter
        redir_findings = analyze_url("https://example.com/auth?redirect_url=https://attacker.test")
        self.assertTrue(any(f["id"] == "url-structure-open-redirect-param" for f in redir_findings))

        # 4. Target category detection
        cat = detect_target_category("https://sbi-banking-verify.in/kyc", [])
        self.assertEqual(cat, "Fake Banking Portal")

    def test_forum_threads_replies_and_upvotes(self):
        # 1. Seed default threads
        seed_default_forum_threads(self.db_path)
        threads = list_forum_threads(self.db_path)
        self.assertGreaterEqual(len(threads), 3)

        # 2. Create a custom thread
        new_th = create_forum_thread(
            self.db_path,
            title="Suspicious WhatsApp job offer claiming 5000 INR/day",
            content="Received a WhatsApp message with shortened link asking to review Google Maps places.",
            category="Scam Report",
            author_name="UserAlice",
        )
        self.assertIsNotNone(new_th["id"])
        self.assertEqual(new_th["title"], "Suspicious WhatsApp job offer claiming 5000 INR/day")
        self.assertEqual(new_th["reply_count"], 0)
        self.assertEqual(new_th["upvotes"], 0)

        # 3. Add a reply to the thread
        reply = create_forum_reply(
            self.db_path,
            thread_id=new_th["id"],
            content="Classic task scam. They ask you to deposit money in a VIP telegram group.",
            author_name="SecExpert",
        )
        self.assertIsNotNone(reply["id"])
        self.assertEqual(reply["author_name"], "SecExpert")

        # 4. Upvote thread
        upvoted = upvote_forum_thread(self.db_path, new_th["id"])
        self.assertEqual(upvoted["upvotes"], 1)

        # 5. Fetch single thread with replies
        detailed = get_forum_thread(self.db_path, new_th["id"])
        self.assertIsNotNone(detailed)
        self.assertEqual(detailed["reply_count"], 1)
        self.assertEqual(detailed["upvotes"], 1)
        self.assertEqual(len(detailed["replies"]), 1)
        self.assertEqual(detailed["replies"][0]["content"], "Classic task scam. They ask you to deposit money in a VIP telegram group.")

        # 6. Filter threads by category
        scam_threads = list_forum_threads(self.db_path, category="Scam Report")
        self.assertTrue(any(t["id"] == new_th["id"] for t in scam_threads))



if __name__ == "__main__":
    unittest.main()

