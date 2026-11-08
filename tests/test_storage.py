import tempfile
import unittest
from pathlib import Path
import sqlite3
from unittest.mock import patch

try:
    from app.storage import (
        create_report,
        get_feed_status,
        find_reports,
        init_db,
        lookup_feed_matches,
        replace_feed,
        review_report,
    )
except ImportError:
    init_db = None

from app.urls import url_hash


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.sqlite3"
        if init_db is not None:
            init_db(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_verified_feed_match_is_exact_and_source_scoped(self):
        self.assertIsNotNone(init_db, "local storage must be available")
        replace_feed(self.db_path, "PhishTank", [
            {"url_hash": "abc", "host": "bad.example"},
        ], "2026-11-07T00:00:00+00:00")
        replace_feed(self.db_path, "URLhaus", [
            {"url_hash": "def", "host": "malware.example"},
        ], "2026-11-07T00:00:00+00:00")
        matches = lookup_feed_matches(self.db_path, "abc")
        self.assertEqual([match["source"] for match in matches], ["PhishTank"])
        self.assertEqual({item["source"] for item in get_feed_status(self.db_path)}, {"PhishTank", "URLhaus"})

    def test_storage_closes_each_database_connection(self):
        real_connect = sqlite3.connect
        connections = []

        def tracked_connect(*args, **kwargs):
            connection = real_connect(*args, **kwargs)
            connections.append(connection)
            return connection

        with patch("app.storage.sqlite3.connect", side_effect=tracked_connect):
            get_feed_status(self.db_path)

        self.assertEqual(len(connections), 1)
        with self.assertRaises(sqlite3.ProgrammingError):
            connections[0].execute("SELECT 1")

    def test_feed_match_includes_the_exact_query_string(self):
        first = "https://bad.example/login?campaign=one"
        second = "https://bad.example/login?campaign=two"
        replace_feed(self.db_path, "PhishTank", [{"url_hash": url_hash(first), "host": "bad.example"}])

        self.assertEqual(len(lookup_feed_matches(self.db_path, url_hash(first))), 1)
        self.assertEqual(lookup_feed_matches(self.db_path, url_hash(second)), [])

    def test_report_stays_unverified_until_local_review(self):
        self.assertIsNotNone(init_db, "local storage must be available")
        report = create_report(self.db_path, "indicator-hash", "bad.example", "phishing")
        self.assertEqual(report["state"], "unverified")
        reviewed = review_report(self.db_path, report["id"], "approve")
        self.assertEqual(reviewed["state"], "approved")

    def test_duplicate_report_for_same_indicator_and_category_is_deduplicated(self):
        self.assertIsNotNone(init_db, "local storage must be available")
        first = create_report(self.db_path, "indicator-hash", "bad.example", "phishing")
        second = create_report(self.db_path, "indicator-hash", "bad.example", "phishing")
        self.assertEqual(first["id"], second["id"])

    def test_only_approved_reports_are_returned_for_local_results(self):
        self.assertIsNotNone(init_db, "local storage must be available")
        indicator = "same-indicator"
        create_report(self.db_path, indicator, "bad.example", "phishing")
        rejected = create_report(self.db_path, indicator, "bad.example", "malware")
        review_report(self.db_path, rejected["id"], "reject")
        approved = create_report(self.db_path, indicator, "bad.example", "impersonation")
        review_report(self.db_path, approved["id"], "approve")

        matches = find_reports(self.db_path, indicator, "bad.example")

        self.assertEqual([(item["category"], item["state"]) for item in matches], [
            ("impersonation", "approved"),
        ])
