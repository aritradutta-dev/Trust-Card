import tempfile
import unittest
from pathlib import Path
import sqlite3
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import httpx

try:
    from app.main import _feed_staleness, create_app
except ImportError:
    create_app = None
    _feed_staleness = None


class AppShellTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        if create_app is None:
            self.fail("the FastAPI app must be available")
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.sqlite3"
        self.scanner_calls = []
        self.scanner_findings = []
        self.feed_calls = []

        def scanner(url):
            self.scanner_calls.append(url)
            return {"complete": True, "findings": self.scanner_findings, "redirect_hosts": [], "tls": {}}

        def feed_fetcher(source):
            self.feed_calls.append(source)
            if source == "PhishTank":
                return b'[{"verified":"yes","url":"https://feed.example/phish"}]'
            return b"id,dateadded,url\n1,2026-11-07,https://feed.example/known\n"

        self.app = create_app(self.db_path, scanner_call=scanner, feed_fetcher=feed_fetcher)
        transport = httpx.ASGITransport(app=self.app)
        self.client = httpx.AsyncClient(transport=transport, base_url="http://test")

    async def asyncTearDown(self):
        await self.client.aclose()
        self.temp_dir.cleanup()

    async def test_home_page_has_a_plain_language_message_input(self):
        response = await self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn('aria-label="Paste a link or the message it came with"', response.text)
        self.assertIn("PhishTank verified phishing data", response.text)
        self.assertIn("URLhaus malware URL data", response.text)
        self.assertIn(">Refresh both feeds<", response.text)
        self.assertIn("PhishTank · not loaded", response.text)
        self.assertIn("URLhaus · not loaded", response.text)
        self.assertIn("Submitted URL", response.text)
        self.assertIn("one read-only GET", response.text)
        self.assertIn("up to five more GET requests to public destinations", response.text)
        self.assertIn("six GET requests total", response.text)
        self.assertIn("20 seconds", response.text)
        self.assertIn("2 MiB of HTML", response.text)
        self.assertIn("static password-form checks", response.text)
        self.assertIn("guessed URL variants", response.text)
        self.assertEqual(response.headers["content-security-policy"].split(";")[0], "default-src 'self'")

    async def test_feed_status_marks_missing_old_and_failed_snapshots(self):
        self.assertIsNotNone(_feed_staleness)
        stale, missing = _feed_staleness([])
        self.assertTrue(stale)
        self.assertTrue(all(item["stale"] and not item["available"] for item in missing))

        now = datetime.now(timezone.utc)
        rows = [
            {"source": "PhishTank", "updated_at": (now - timedelta(hours=25)).isoformat(), "entry_count": 3, "last_error": None},
            {"source": "URLhaus", "updated_at": now.isoformat(), "entry_count": 4, "last_error": "refresh_failed"},
        ]
        stale, annotated = _feed_staleness(rows)
        self.assertTrue(stale)
        self.assertTrue(all(item["stale"] for item in annotated))

    async def test_full_scan_without_consent_never_calls_the_scanner(self):
        response = await self.client.post(
            "/api/v1/analyze",
            json={
                "url": "https://example.com/",
                "mode": "full_scan",
                "consent": False,
                "context_flags": [],
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.scanner_calls, [])

    async def test_admin_review_fails_closed_without_both_credentials(self):
        with patch.dict("os.environ", {"ADMIN_USERNAME": "", "ADMIN_PASSWORD": "secret"}):
            response = await self.client.get("/api/v1/admin/reports")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["detail"], "admin_credentials_not_configured")
        with patch.dict("os.environ", {"ADMIN_USERNAME": "reviewer", "ADMIN_PASSWORD": ""}):
            response = await self.client.get("/api/v1/admin/reports")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["detail"], "admin_credentials_not_configured")

    async def test_api_rejects_raw_message_text(self):
        response = await self.client.post(
            "/api/v1/analyze",
            json={"url": "https://example.com/", "mode": "local", "message": "pay now"},
        )
        self.assertEqual(response.status_code, 422)

    async def test_context_plus_redirect_signal_produces_suspicious_verdict(self):
        self.scanner_findings = [{
            "category": "redirect", "severity": "medium", "summary": "The link redirects to a different site.",
            "source": "Redirect inspection", "observed_at": "2026-11-07T00:00:00+00:00", "group": "redirect",
        }]
        response = await self.client.post(
            "/api/v1/analyze",
            json={
                "url": "https://example.com/", "mode": "full_scan", "consent": True,
                "context_flags": ["credential_request"],
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["verdict"], "suspicious")
        self.assertEqual(response.json()["coverage"], "partial")
        self.assertEqual(response.json()["scan_coverage"], "full")
        self.assertTrue(response.json()["checked_at"])
        self.assertIn(response.json()["confidence"], {"high", "medium"})
        self.assertTrue(response.json()["next_steps"])
        self.assertTrue(all(item.get("source") and item.get("observed_at") for item in response.json()["findings"]))

    async def test_qualifying_finding_survives_an_incomplete_live_scan(self):
        self.app.state.scanner_call = lambda url: {
            "complete": False,
            "coverage": "partial",
            "error": "site_unreachable",
            "redirect_hosts": [],
            "findings": [{
                "category": "credential_form",
                "severity": "high",
                "summary": "A password form uses a non-web submission destination.",
                "source": "Static page inspection",
                "observed_at": "2026-11-07T00:00:00+00:00",
                "group": "credential_form",
            }],
        }
        response = await self.client.post(
            "/api/v1/analyze",
            json={"url": "https://example.com/", "mode": "full_scan", "consent": True},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["verdict"], "suspicious")
        self.assertEqual(response.json()["confidence"], "medium")
        self.assertEqual(response.json()["coverage"], "partial")

    async def test_unavailable_scanner_means_local_only_coverage(self):
        self.app.state.scanner_call = None
        response = await self.client.post(
            "/api/v1/analyze",
            json={"url": "https://example.com/", "mode": "full_scan", "consent": True},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["scan_error"], "scanner_unavailable")
        self.assertEqual(response.json()["coverage"], "local_only")
        self.assertEqual(response.json()["scan_coverage"], "local_only")

    async def test_manual_feed_refresh_uses_named_source_without_url_submission(self):
        response = await self.client.post(
            "/api/v1/intel/refresh", json={"providers": ["URLhaus"]}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.feed_calls, ["URLhaus"])
        self.assertTrue(response.json()["results"][0]["updated"])

    async def test_manual_feed_refresh_rejects_checked_url_and_message(self):
        response = await self.client.post(
            "/api/v1/intel/refresh",
            json={
                "providers": ["PhishTank"],
                "url": "https://checked.example/path?secret=1",
                "message": "Urgent, pay now",
            },
        )
        self.assertEqual(response.status_code, 422)
        self.assertEqual(self.feed_calls, [])

    async def test_fresh_local_feeds_allow_full_coverage_after_live_scan(self):
        refreshed = await self.client.post(
            "/api/v1/intel/refresh", json={"providers": ["PhishTank", "URLhaus"]}
        )
        self.assertEqual(refreshed.status_code, 200)
        result = await self.client.post(
            "/api/v1/analyze",
            json={"url": "https://example.com/", "mode": "full_scan", "consent": True},
        )
        self.assertEqual(result.json()["coverage"], "full")
        self.assertTrue(result.json()["live_scan_complete"])

    async def test_report_persists_only_query_free_fingerprint_and_stays_unverified(self):
        checked = await self.client.post(
            "/api/v1/analyze",
            json={"url": "https://example.com/pay?token=do-not-store", "mode": "local"},
        )
        session = self.app.state.scan_sessions[checked.json()["scan_id"]]
        submitted = await self.client.post(
            "/api/v1/reports",
            json={"scan_id": checked.json()["scan_id"], "category": "phishing"},
        )
        self.assertEqual(submitted.status_code, 200)
        self.assertEqual(submitted.json()["state"], "unverified")
        self.assertEqual(set(session), {"indicator_hash", "host", "created_at"})
        self.assertNotIn("do-not-store", str(session))
        with sqlite3.connect(self.db_path) as db:
            row = db.execute("SELECT indicator_hash, host, category, state FROM reports").fetchone()
            fields = {column[1] for column in db.execute("PRAGMA table_info(reports)")}
        self.assertEqual(row[1:], ("example.com", "phishing", "unverified"))
        self.assertNotIn("do-not-store", str(row))
        self.assertEqual(fields, {"id", "indicator_hash", "host", "category", "state", "created_at", "reviewed_at"})

    async def test_admin_approval_requires_credentials_and_affects_future_local_check(self):
        checked = await self.client.post(
            "/api/v1/analyze",
            json={"url": "https://reported.example/login", "mode": "local"},
        )
        submitted = await self.client.post(
            "/api/v1/reports",
            json={"scan_id": checked.json()["scan_id"], "category": "impersonation"},
        )
        self.assertEqual(submitted.status_code, 200)
        with patch.dict("os.environ", {"ADMIN_USERNAME": "reviewer", "ADMIN_PASSWORD": "local-secret"}):
            unauthenticated = await self.client.get("/api/v1/admin/reports")
            self.assertEqual(unauthenticated.status_code, 401)
            pending = await self.client.get("/api/v1/admin/reports", auth=("reviewer", "local-secret"))
            self.assertEqual(len(pending.json()["reports"]), 1)
            report_id = pending.json()["reports"][0]["id"]
            reviewed = await self.client.post(
                f"/api/v1/admin/reports/{report_id}/review",
                json={"decision": "approve"},
                auth=("reviewer", "local-secret"),
            )
            self.assertEqual(reviewed.json()["state"], "approved")
        future_check = await self.client.post(
            "/api/v1/analyze",
            json={"url": "https://reported.example/login", "mode": "local"},
        )
        self.assertEqual(future_check.json()["verdict"], "known_threat")

    async def test_unverified_report_does_not_appear_in_later_local_result(self):
        checked = await self.client.post(
            "/api/v1/analyze",
            json={"url": "https://unreviewed.example/login", "mode": "local"},
        )
        await self.client.post(
            "/api/v1/reports",
            json={"scan_id": checked.json()["scan_id"], "category": "phishing"},
        )

        later = await self.client.post(
            "/api/v1/analyze",
            json={"url": "https://unreviewed.example/login", "mode": "local"},
        )

        self.assertFalse(any(item["category"] == "community_report" for item in later.json()["findings"]))

    async def test_local_check_does_not_call_the_scanner(self):
        response = await self.client.post(
            "/api/v1/analyze",
            json={
                "url": "https://example.com/",
                "mode": "local",
                "consent": False,
                "context_flags": [],
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["coverage"], "local_only")
        self.assertTrue(response.json()["checked_at"])
        self.assertEqual(response.json()["confidence"], "low")
        self.assertTrue(response.json()["feed_stale"])
        self.assertTrue(response.json()["feed_status"])
        self.assertTrue(response.json()["next_steps"])
        # With stale feeds and no live scan, should show not_enough_info
        self.assertEqual(response.json()["verdict"], "not_enough_info")
        self.assertEqual(self.scanner_calls, [])

    async def test_rejects_non_http_schemes_before_scanning(self):
        response = await self.client.post(
            "/api/v1/analyze",
            json={
                "url": "ftp://example.com/file",
                "mode": "full_scan",
                "consent": True,
                "context_flags": [],
            },
        )
        self.assertEqual(response.status_code, 422)
        self.assertEqual(self.scanner_calls, [])
