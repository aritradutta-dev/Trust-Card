import gzip
import json
import tempfile
import unittest
from pathlib import Path

from app.feeds import parse_feed, refresh_feed
from app.storage import get_feed_status, init_db, lookup_feed_matches, replace_feed
from app.urls import url_hash


class FeedTests(unittest.TestCase):
    def test_phishtank_keeps_only_verified_http_urls(self):
        content = json.dumps([
            {"verified": "yes", "url": "https://bad.example/login"},
            {"verified": "no", "url": "https://pending.example/login"},
            {"verified": "yes", "url": "javascript:alert(1)"},
        ]).encode()
        entries = parse_feed("PhishTank", gzip.compress(content))
        self.assertEqual([entry["host"] for entry in entries], ["bad.example"])

    def test_urlhaus_csv_is_parsed_and_failed_refresh_keeps_last_snapshot(self):
        entries = parse_feed("URLhaus", b"# URLhaus export\n# \"id\",\"dateadded\",\"url\"\n1,2026-11-07,https://malware.example/dropper\n")
        self.assertEqual(entries[0]["host"], "malware.example")
        with tempfile.TemporaryDirectory() as temp:
            db_path = Path(temp) / "feeds.sqlite3"
            init_db(db_path)
            replace_feed(db_path, "URLhaus", entries)
            with self.assertRaises(RuntimeError):
                refresh_feed(db_path, "URLhaus", lambda _source: (_ for _ in ()).throw(RuntimeError("offline")))
            self.assertEqual(lookup_feed_matches(db_path, url_hash("https://malware.example/dropper"))[0]["source"], "URLhaus")

    def test_invalid_refresh_keeps_last_valid_snapshot_and_records_error(self):
        with tempfile.TemporaryDirectory() as temp:
            db_path = Path(temp) / "feeds.sqlite3"
            init_db(db_path)
            valid = b"url\nhttps://malware.example/dropper\n"
            refresh_feed(db_path, "URLhaus", lambda _source: valid)

            with self.assertRaises(ValueError):
                refresh_feed(db_path, "URLhaus", lambda _source: b"not a URLhaus export")

            matches = lookup_feed_matches(db_path, url_hash("https://malware.example/dropper"))
            status = get_feed_status(db_path)[0]
            self.assertEqual([item["source"] for item in matches], ["URLhaus"])
            self.assertEqual(status["entry_count"], 1)
            self.assertEqual(status["last_error"], "refresh_failed")

    def test_openphish_plain_text_feed_is_parsed(self):
        payload = b"https://phish1.example/login\n# a comment\nhttps://phish2.example/account\n\nftp://invalid-scheme\nnot-a-url"
        entries = parse_feed("OpenPhish", payload)
        self.assertEqual(len(entries), 2)
        self.assertEqual({entry["host"] for entry in entries}, {"phish1.example", "phish2.example"})


if __name__ == "__main__":
    unittest.main()
