import datetime
import unittest
from datetime import timezone
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from scanner.certs import _match_hostname, analyze_certificate_der
from scanner.ct_rdap import lookup_ct_logs, lookup_domain_age_rdap
from app.verdict import decide_verdict


def _generate_test_cert(
    *,
    common_name="test.example",
    sans=None,
    days_valid=30,
    start_days_ago=1,
    key=None,
    issuer_name=None,
    hash_algo=hashes.SHA256(),
):
    if key is None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]) if issuer_name else name

    now = datetime.datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=start_days_ago))
        .not_valid_after(now + datetime.timedelta(days=days_valid - start_days_ago))
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san) for san in sans]),
            critical=False,
        )
    return builder.sign(key, hash_algo).public_bytes(serialization.Encoding.DER)


class CertAnalysisTests(unittest.TestCase):
    def test_wildcard_matching_rules(self):
        self.assertTrue(_match_hostname("sub.example.com", "*.example.com"))
        self.assertFalse(_match_hostname("example.com", "*.example.com"))
        self.assertFalse(_match_hostname("deep.sub.example.com", "*.example.com"))
        self.assertTrue(_match_hostname("example.com", "example.com"))

    def test_expired_certificate_flagged_medium(self):
        der = _generate_test_cert(days_valid=10, start_days_ago=20)
        details, findings = analyze_certificate_der(der, "test.example")
        self.assertTrue(any(f["id"] == "cert-expired" and f["severity"] == "medium" for f in findings))

    def test_hostname_mismatch_flagged_medium(self):
        der = _generate_test_cert(sans=["other.example"])
        details, findings = analyze_certificate_der(der, "target.example")
        self.assertTrue(any(f["id"] == "cert-hostname-mismatch" and f["severity"] == "medium" for f in findings))

    def test_self_signed_flagged_medium(self):
        der = _generate_test_cert()
        details, findings = analyze_certificate_der(der, "test.example")
        self.assertTrue(any(f["id"] == "cert-self-signed" and f["severity"] == "medium" for f in findings))
        self.assertTrue(details["is_self_signed"])

    def test_sha1_signature_flagged_medium(self):
        der = _generate_test_cert()
        with patch("cryptography.x509.Certificate.signature_algorithm_oid") as mock_oid:
            mock_oid._name = "sha1WithRSAEncryption"
            details, findings = analyze_certificate_der(der, "test.example")
            self.assertTrue(any(f["id"] == "cert-weak-signature" and f["severity"] == "medium" for f in findings))

    def test_weak_rsa_key_below_2048_flagged_medium(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        der = _generate_test_cert(key=key)
        details, findings = analyze_certificate_der(der, "test.example")
        self.assertTrue(any(f["id"] == "cert-weak-rsa-key" and f["severity"] == "medium" for f in findings))

    def test_weak_key_generation_small_prime_factor(self):
        der = _generate_test_cert()
        class FakeNumbers:
            n = 3 * 65537 * 10007
            e = 65537
        class FakeKey:
            key_size = 2048
            def public_numbers(self):
                return FakeNumbers()
            def public_bytes(self, *args, **kwargs):
                return b"fake-spki"

        with patch("cryptography.x509.Certificate.public_key", return_value=FakeKey()), \
             patch("scanner.certs.isinstance", side_effect=lambda obj, cls: True if cls == rsa.RSAPublicKey else isinstance(obj, cls)):
            details, findings = analyze_certificate_der(der, "test.example")
            self.assertTrue(any(f["id"] == "cert-weak-key-generation" and f["severity"] == "medium" for f in findings))

    def test_ca_watchlist_match_flagged_conservative_medium(self):
        der = _generate_test_cert(issuer_name="eMudhra Sub-CA")
        details, findings = analyze_certificate_der(der, "test.example")
        self.assertTrue(any(
            f["group"] == "certificate" and f["severity"] == "medium" and "authority on the watchlist" in f["summary"]
            for f in findings
        ))

    def test_validity_period_longer_than_398_days_flagged_low(self):
        der = _generate_test_cert(days_valid=500)
        details, findings = analyze_certificate_der(der, "test.example")
        self.assertTrue(any(f["id"] == "cert-validity-too-long" and f["severity"] == "low" for f in findings))

    def test_ct_rdap_mock_lookups(self):
        fake_crt_json = b'[{"entry_timestamp": "2026-11-05T00:00:00", "issuer_name": "C=IN, O=eMudhra"}]'
        with patch("urllib.request.OpenerDirector.open") as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = fake_crt_json
            findings = lookup_ct_logs("test.example")
            self.assertTrue(any("watchlist" in f["summary"] for f in findings))

        fake_rdap_json = b'{"events": [{"eventAction": "registration", "eventDate": "2026-11-01T00:00:00Z"}]}'
        with patch("urllib.request.OpenerDirector.open") as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = fake_rdap_json
            findings = lookup_domain_age_rdap("young-site.com")
            self.assertTrue(any(f["group"] == "domain_age" and f["severity"] == "medium" for f in findings))

    def test_domain_age_medium_contributes_to_suspicious(self):
        findings = [
            {"severity": "medium", "group": "domain_age"},
            {"severity": "medium", "group": "message_context"},
        ]
        verdict = decide_verdict(findings, scan_complete=True)
        self.assertEqual(verdict["verdict"], "suspicious")


if __name__ == "__main__":
    unittest.main()
