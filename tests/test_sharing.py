"""Unit tests for Phase 5 collaborative threat intelligence and sharing."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx

from app.main import create_app
from app.storage import create_report, find_reports, init_db, list_reports, review_report
from app.urls import indicator_fingerprint


class TestSharingAndCollaboration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_dir = TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.sqlite3"
        init_db(self.db_path)
        os.environ["ADMIN_USERNAME"] = "testadmin"
        os.environ["ADMIN_PASSWORD"] = "testpass"
        os.environ["SHARING_KEY"] = "secret-sharing-key-12345"
        self.app = create_app(db_path=self.db_path, scanner_call=lambda url, **kw: {"complete": True, "findings": [], "redirect_hosts": []})
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://test")
        self.auth = ("testadmin", "testpass")

    async def asyncTearDown(self):
        await self.client.aclose()
        self.temp_dir.cleanup()
        os.environ.pop("SHARING_KEY", None)
        os.environ.pop("REPORT_AUTO_APPROVE_THRESHOLD", None)

    async def test_repeat_reports_increment_count(self):
        ind = indicator_fingerprint("https://bad.example/login")
        r1 = create_report(self.db_path, ind, "bad.example", "phishing")
        self.assertEqual(r1["report_count"], 1)

        r2 = create_report(self.db_path, ind, "bad.example", "phishing")
        self.assertEqual(r2["report_count"], 2)

        reports = list_reports(self.db_path, "unverified")
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]["report_count"], 2)

    async def test_unverified_report_appears_as_low_finding_without_affecting_verdict(self):
        ind = indicator_fingerprint("https://unreviewed-site.example/test")
        create_report(self.db_path, ind, "unreviewed-site.example", "phishing")
        create_report(self.db_path, ind, "unreviewed-site.example", "phishing")

        res = await self.client.post(
            "/api/v1/analyze",
            json={"url": "https://unreviewed-site.example/test", "mode": "local"},
        )
        data = res.json()
        unverified_finding = next((f for f in data["findings"] if f["category"] == "unverified_report"), None)
        self.assertIsNotNone(unverified_finding)
        self.assertEqual(unverified_finding["severity"], "low")
        self.assertIn("Reported 2 times locally, awaiting review", unverified_finding["summary"])
        # Low finding alone must never cause known_threat
        self.assertNotEqual(data["verdict"], "known_threat")

    async def test_auto_promote_threshold(self):
        os.environ["REPORT_AUTO_APPROVE_THRESHOLD"] = "3"
        ind = indicator_fingerprint("https://crowdsourced-bad.example/pay")
        
        create_report(self.db_path, ind, "crowdsourced-bad.example", "phishing", auto_approve_threshold=3)
        r2 = create_report(self.db_path, ind, "crowdsourced-bad.example", "phishing", auto_approve_threshold=3)
        self.assertEqual(r2["state"], "unverified")

        r3 = create_report(self.db_path, ind, "crowdsourced-bad.example", "phishing", auto_approve_threshold=3)
        self.assertEqual(r3["state"], "approved")
        self.assertEqual(r3["report_count"], 3)

    async def test_host_level_reputation_multiple_approved_reports(self):
        # 2 different approved URLs on evil.example
        ind1 = indicator_fingerprint("https://evil.example/page1")
        ind2 = indicator_fingerprint("https://evil.example/page2")
        r1 = create_report(self.db_path, ind1, "evil.example", "phishing")
        r2 = create_report(self.db_path, ind2, "evil.example", "phishing")
        review_report(self.db_path, r1["id"], "approve")
        review_report(self.db_path, r2["id"], "approve")

        # Now check a third URL on that same host: evil.example/page3
        res = await self.client.post(
            "/api/v1/analyze",
            json={"url": "https://evil.example/page3", "mode": "local"},
        )
        data = res.json()
        host_finding = next((f for f in data["findings"] if f["summary"] == "Multiple verified reports on this host"), None)
        self.assertIsNotNone(host_finding)
        self.assertEqual(host_finding["severity"], "medium")
        self.assertEqual(host_finding["group"], "community_report")

    async def test_admin_state_filtering(self):
        ind1 = indicator_fingerprint("https://site1.example/")
        ind2 = indicator_fingerprint("https://site2.example/")
        r1 = create_report(self.db_path, ind1, "site1.example", "phishing")
        r2 = create_report(self.db_path, ind2, "site2.example", "malware")
        review_report(self.db_path, r1["id"], "approve")

        # Query approved
        res_appr = await self.client.get("/api/v1/admin/reports?state=approved", auth=self.auth)
        self.assertEqual(len(res_appr.json()["reports"]), 1)
        self.assertEqual(res_appr.json()["reports"][0]["id"], r1["id"])

        # Query unverified
        res_unv = await self.client.get("/api/v1/admin/reports?state=unverified", auth=self.auth)
        self.assertEqual(len(res_unv.json()["reports"]), 1)
        self.assertEqual(res_unv.json()["reports"][0]["id"], r2["id"])

        # Query all
        res_all = await self.client.get("/api/v1/admin/reports?state=all", auth=self.auth)
        self.assertEqual(len(res_all.json()["reports"]), 2)

    async def test_export_and_import_with_signature(self):
        # Create approved report
        ind = indicator_fingerprint("https://exported-bad.example/login?token=secret123")
        r = create_report(self.db_path, ind, "exported-bad.example", "phishing")
        review_report(self.db_path, r["id"], "approve")

        # Export
        export_res = await self.client.get("/api/v1/admin/export", auth=self.auth)
        self.assertEqual(export_res.status_code, 200)
        sig = export_res.headers.get("X-Signature")
        self.assertTrue(sig)
        export_body = export_res.json()
        self.assertEqual(len(export_body["reports"]), 1)
        exported_item = export_body["reports"][0]
        self.assertEqual(exported_item["host"], "exported-bad.example")
        self.assertEqual(exported_item["indicator_fingerprint"], ind)
        # Ensure NO url or query strings in export
        self.assertNotIn("url", exported_item)
        self.assertNotIn("token", json.dumps(exported_item))

        # Import into fresh database
        temp_dir2 = TemporaryDirectory()
        db_path2 = Path(temp_dir2.name) / "test2.sqlite3"
        init_db(db_path2)
        app2 = create_app(db_path=db_path2)
        client2 = httpx.AsyncClient(transport=httpx.ASGITransport(app=app2), base_url="http://test")

        # Bad signature rejected
        bad_sig_res = await client2.post(
            "/api/v1/admin/import",
            content=export_res.content,
            headers={"X-Signature": "invalid-hex-signature", "Content-Type": "application/json"},
            auth=self.auth,
        )
        self.assertEqual(bad_sig_res.status_code, 400)

        # Good signature accepted
        good_import_res = await client2.post(
            "/api/v1/admin/import",
            content=export_res.content,
            headers={"X-Signature": sig, "Content-Type": "application/json"},
            auth=self.auth,
        )
        self.assertEqual(good_import_res.status_code, 200)
        self.assertEqual(good_import_res.json()["imported"], 1)

        # Verify imported reports stay unverified with peer source
        imported_list = list_reports(db_path2, "unverified")
        self.assertEqual(len(imported_list), 1)
        self.assertEqual(imported_list[0]["state"], "unverified")
        self.assertTrue(imported_list[0]["source"].startswith("Peer: "))

        await client2.aclose()
        temp_dir2.cleanup()

    async def test_export_without_key_fails_503(self):
        os.environ.pop("SHARING_KEY", None)
        res = await self.client.get("/api/v1/admin/export", auth=self.auth)
        self.assertEqual(res.status_code, 503)

    async def test_import_oversized_payload_rejected(self):
        oversized = b"x" * (1048576 + 50)
        res = await self.client.post(
            "/api/v1/admin/import",
            content=oversized,
            headers={"X-Signature": "any", "Content-Type": "application/json"},
            auth=self.auth,
        )
        self.assertEqual(res.status_code, 413)


if __name__ == "__main__":
    unittest.main()

