import unittest

from app.url_analysis import analyze_url, get_registrable_domain
from app.verdict import decide_verdict


class UrlAnalysisTests(unittest.TestCase):
    def test_get_registrable_domain_with_public_suffix(self):
        self.assertEqual(get_registrable_domain("bank.co.uk"), "bank.co.uk")
        self.assertEqual(get_registrable_domain("sub.portal.sbi.co.in"), "sbi.co.in")
        self.assertEqual(get_registrable_domain("login.example.com"), "example.com")
        self.assertEqual(get_registrable_domain("evil.github.io"), "evil.github.io")

    def test_punycode_and_idn_homoglyph_detection(self):
        # Punycode domain
        findings = analyze_url("https://xn--pple-43d.com/login")
        self.assertTrue(any(f["group"] == "url_lookalike" and f["severity"] == "medium" for f in findings))

    def test_brand_lookalike_digit_letter_substitution(self):
        # paypa1 -> paypal
        findings = analyze_url("https://paypa1-secure-login.example.net/")
        # paypa1 is in the subdomain / host
        self.assertTrue(any(f["group"] == "url_lookalike" and "PayPal" in f["summary"] for f in findings))

    def test_brand_lookalike_rn_substitution(self):
        # rnicrosoft -> microsoft
        findings = analyze_url("https://rnicrosoft.com.attacker.test/login")
        self.assertTrue(any(f["group"] == "url_lookalike" and "Microsoft" in f["summary"] for f in findings))

    def test_brand_in_subdomain_on_unrelated_registrable_domain(self):
        # paypal in subdomain of evil.test
        findings = analyze_url("https://paypal.com.evil.test/verify")
        self.assertTrue(any(f["group"] == "url_lookalike" and f["severity"] == "medium" for f in findings))

    def test_legitimate_brand_domain_is_not_flagged(self):
        findings = analyze_url("https://www.paypal.com/signin")
        self.assertFalse(any(f["group"] == "url_lookalike" for f in findings))

        sbi_findings = analyze_url("https://retail.onlinesbi.sbi/retail/login.htm")
        self.assertFalse(any(f["group"] == "url_lookalike" for f in sbi_findings))

    def test_indian_targets_detected(self):
        # sbi impersonation
        sbi_findings = analyze_url("https://onlinesbi.secure-banking.test/login")
        self.assertTrue(any(f["group"] == "url_lookalike" for f in sbi_findings))

        # irctc impersonation
        irctc_findings = analyze_url("https://irctc-ticket-booking.fake-portal.test/pay")
        self.assertTrue(any(f["group"] == "url_lookalike" for f in irctc_findings))

    def test_ip_literal_host(self):
        findings = analyze_url("http://198.51.100.1/login")
        self.assertTrue(any(f["group"] == "url_structure" and "numeric IP" in f["summary"] for f in findings))

    def test_excessive_subdomain_depth(self):
        findings = analyze_url("https://a.b.c.d.example.com/page")
        self.assertTrue(any(f["id"] == "url-structure-excessive-subdomains" for f in findings))

    def test_url_shortener(self):
        findings = analyze_url("https://bit.ly/3xSample")
        self.assertTrue(any(f["id"] == "url-structure-shortener" for f in findings))

    def test_suspicious_tld(self):
        findings = analyze_url("https://secure-invoice.zip/file")
        self.assertTrue(any("zip" in f["id"] for f in findings))

    def test_fraud_keywords(self):
        findings = analyze_url("https://example.com/payment/kyc/verify")
        self.assertTrue(any(f["id"] == "url-structure-fraud-keywords" for f in findings))

    def test_brand_lookalike_plus_context_gives_suspicious_in_local_check(self):
        url_findings = analyze_url("https://paypa1-secure-login.example.net/")
        context_finding = {
            "id": "context-credential_request",
            "category": "message_context",
            "severity": "medium",
            "group": "message_context",
        }
        all_findings = url_findings + [context_finding]
        verdict = decide_verdict(all_findings, scan_complete=True, coverage="local_only")
        self.assertEqual(verdict["verdict"], "suspicious")


if __name__ == "__main__":
    unittest.main()

