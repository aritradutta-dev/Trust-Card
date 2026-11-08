import unittest

try:
    from app.urls import canonicalize_url, indicator_fingerprint, url_hash
except ImportError:
    canonicalize_url = None


class UrlTests(unittest.TestCase):
    def test_canonical_url_normalizes_host_default_port_and_fragment(self):
        self.assertIsNotNone(canonicalize_url, "URL normalization must be available")
        self.assertEqual(
            canonicalize_url("HTTPS://ExAmple.COM:443/path?token=a#section"),
            "https://example.com/path?token=a",
        )

    def test_indicator_fingerprint_omits_query_secrets_but_full_match_hash_does_not(self):
        self.assertIsNotNone(canonicalize_url, "URL normalization must be available")
        first = "https://example.com/pay?token=secret-a"
        second = "https://example.com/pay?token=secret-b"
        self.assertEqual(indicator_fingerprint(first), indicator_fingerprint(second))
        self.assertNotEqual(url_hash(first), url_hash(second))

    def test_rejects_credentials_and_nonstandard_ports(self):
        self.assertIsNotNone(canonicalize_url, "URL normalization must be available")
        with self.assertRaises(ValueError):
            canonicalize_url("https://user:password@example.com/")
        with self.assertRaises(ValueError):
            canonicalize_url("https://example.com:8443/")
