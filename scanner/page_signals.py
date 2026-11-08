"""Static HTML and HTTP security header analysis for web security assessment."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from app.url_analysis import get_registrable_domain

_DATA_DIR = Path(__file__).resolve().parent / "data"
_APP_DATA_DIR = Path(__file__).resolve().parent.parent / "app" / "data"

try:
    with open(_DATA_DIR / "outdated_software.json", encoding="utf-8") as f:
        _OUTDATED_SOFTWARE = json.load(f)
except Exception:
    _OUTDATED_SOFTWARE = []

try:
    with open(_APP_DATA_DIR / "brands.json", encoding="utf-8") as f:
        _BRANDS = json.load(f)
except Exception:
    _BRANDS = []

_FORM_BUILDER_DOMAINS = {
    "docs.google.com",
    "forms.gle",
    "formspree.io",
    "typeform.com",
    "jotform.com",
    "cognitoforms.com",
    "pastebin.com",
    "paste.ee",
    "rentry.co",
}

_OBFUSCATION_PATTERNS = [
    (re.compile(r"eval\s*\(\s*atob\s*\(", re.IGNORECASE), "eval(atob(…)) execution pattern"),
    (re.compile(r"document\.write\s*\(\s*unescape\s*\(", re.IGNORECASE), "document.write(unescape(…)) pattern"),
    (re.compile(r"unescape\s*\(", re.IGNORECASE), "unescape(…) decoder"),
    (re.compile(r"(?:\\x[0-9a-fA-F]{2}){20,}", re.IGNORECASE), "long hex escape sequence"),
    (re.compile(r"String\.fromCharCode\s*\((?:\s*\d+\s*,){15,}", re.IGNORECASE), "fromCharCode encoded string array"),
]


def _same_site(host_a: str, host_b: str) -> bool:
    """Use public-suffix registrable domains to compare sites accurately."""
    a = host_a.rstrip(".").lower()
    b = host_b.rstrip(".").lower()
    if not a or not b:
        return False
    reg_a = get_registrable_domain(a)
    reg_b = get_registrable_domain(b)
    if reg_a and reg_b:
        return reg_a == reg_b
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def audit_security_headers(headers: dict[str, str], scheme: str) -> list[dict]:
    """Audit HTTP security headers. All findings are severity low, group security_headers."""
    findings: list[dict] = []
    now = datetime.now(timezone.utc).isoformat()

    # 1. HSTS (HTTPS only)
    if scheme == "https":
        hsts = headers.get("strict-transport-security")
        if not hsts:
            findings.append({
                "id": "header-missing-hsts",
                "category": "security_header",
                "severity": "low",
                "summary": "The site does not advertise an HTTP Strict Transport Security (HSTS) header.",
                "source": "HTTP response headers",
                "observed_at": now,
                "group": "security_headers",
            })
        else:
            max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 15552000:
                    findings.append({
                        "id": "header-short-hsts",
                        "category": "security_header",
                        "severity": "low",
                        "summary": f"HSTS max-age is set to {max_age}s, which is below the recommended 180-day baseline (15,552,000s).",
                        "source": "HTTP response headers",
                        "observed_at": now,
                        "group": "security_headers",
                    })

    # 2. Content Security Policy
    csp = headers.get("content-security-policy", "")
    if not csp:
        findings.append({
            "id": "header-missing-csp",
            "category": "security_header",
            "severity": "low",
            "summary": "The response is missing a Content-Security-Policy header.",
            "source": "HTTP response headers",
            "observed_at": now,
            "group": "security_headers",
        })
    elif "unsafe-inline" in csp and "nonce-" not in csp and "sha256-" not in csp:
        findings.append({
            "id": "header-weak-csp",
            "category": "security_header",
            "severity": "low",
            "summary": "Content Security Policy relies on unsafe-inline without nonces or hashes.",
            "source": "HTTP response headers",
            "observed_at": now,
            "group": "security_headers",
        })

    # 3. Framing / Clickjacking Protection
    xfo = headers.get("x-frame-options", "").lower()
    has_frame_ancestors = "frame-ancestors" in csp.lower()
    if not xfo and not has_frame_ancestors:
        findings.append({
            "id": "header-missing-frame-protection",
            "category": "security_header",
            "severity": "low",
            "summary": "The response does not set X-Frame-Options or CSP frame-ancestors to guard against clickjacking.",
            "source": "HTTP response headers",
            "observed_at": now,
            "group": "security_headers",
        })

    # 4. MIME Sniffing Protection
    xcto = headers.get("x-content-type-options", "").lower()
    if "nosniff" not in xcto:
        findings.append({
            "id": "header-missing-xcto",
            "category": "security_header",
            "severity": "low",
            "summary": "The response is missing X-Content-Type-Options: nosniff.",
            "source": "HTTP response headers",
            "observed_at": now,
            "group": "security_headers",
        })

    # 5. Referrer Policy
    if "referrer-policy" not in headers:
        findings.append({
            "id": "header-missing-referrer-policy",
            "category": "security_header",
            "severity": "low",
            "summary": "The response is missing a Referrer-Policy header.",
            "source": "HTTP response headers",
            "observed_at": now,
            "group": "security_headers",
        })

    # 6. Permissions Policy
    if "permissions-policy" not in headers and "feature-policy" not in headers:
        findings.append({
            "id": "header-missing-permissions-policy",
            "category": "security_header",
            "severity": "low",
            "summary": "The response is missing a Permissions-Policy header.",
            "source": "HTTP response headers",
            "observed_at": now,
            "group": "security_headers",
        })

    # 7. Information disclosure & Outdated Software
    server_str = headers.get("server", "")
    x_powered_by = headers.get("x-powered-by", "")
    combined_banner = f"{server_str} {x_powered_by}".strip()

    if combined_banner:
        if re.search(r"\d+\.\d+", combined_banner):
            findings.append({
                "id": "header-version-disclosure",
                "category": "security_header",
                "severity": "low",
                "summary": f"Server banner discloses software version details ({combined_banner[:80]}).",
                "source": "HTTP response headers",
                "observed_at": now,
                "group": "security_headers",
            })

        for entry in _OUTDATED_SOFTWARE:
            pat = entry.get("pattern", "")
            if pat and re.search(pat, combined_banner, re.IGNORECASE):
                findings.append({
                    "id": f"software-outdated-{entry.get('name', '').replace(' ', '-').lower()}",
                    "category": "security_header",
                    "severity": "low",
                    "summary": f"Server banner appears to run outdated software ({entry.get('name')}): {entry.get('note')}",
                    "source": "HTTP response headers",
                    "observed_at": now,
                    "group": "security_headers",
                })
                break

    # 8. Cookies Audit
    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        cookies = [c.strip() for c in set_cookie.split(",") if "=" in c]
        for cookie in cookies:
            cookie_lower = cookie.lower()
            missing_attrs = []
            if scheme == "https" and "secure" not in cookie_lower:
                missing_attrs.append("Secure")
            if "httponly" not in cookie_lower:
                missing_attrs.append("HttpOnly")
            if "samesite" not in cookie_lower:
                missing_attrs.append("SameSite")
            if missing_attrs:
                attrs_str = ", ".join(missing_attrs)
                findings.append({
                    "id": "cookie-insecure-attributes",
                    "category": "security_header",
                    "severity": "low",
                    "summary": f"A Set-Cookie directive lacks recommended security flags ({attrs_str}).",
                    "source": "HTTP response headers",
                    "observed_at": now,
                    "group": "security_headers",
                })
                break  # Flag once

    return findings


class _PageSignalParser(HTMLParser):
    def __init__(self, page_url: str):
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.page_host = urlsplit(page_url).hostname or ""
        self.page_scheme = urlsplit(page_url).scheme

        self.forms: list[dict] = []
        self.current_form: dict | None = None

        self.in_title = False
        self.title_text = []

        self.headings: list[str] = []
        self.in_heading = False
        self.current_heading = []

        self.og_site_name = ""
        self.hidden_iframes: list[str] = []
        self.meta_refreshes: list[str] = []
        self.http_subresources: list[str] = []

    def handle_starttag(self, tag: str, attrs):
        tag_lower = tag.lower()
        val_dict = dict(attrs)

        # Meta tags
        if tag_lower == "meta":
            prop = val_dict.get("property", "").lower()
            if prop == "og:site_name":
                self.og_site_name = val_dict.get("content", "")
            http_equiv = val_dict.get("http-equiv", "").lower()
            if http_equiv == "refresh":
                content = val_dict.get("content", "")
                m = re.search(r"url\s*=\s*['\"]?([^'\";\s>]+)", content, re.IGNORECASE)
                if m:
                    self.meta_refreshes.append(m.group(1))

        # Title
        elif tag_lower == "title":
            self.in_title = True

        # Headings
        elif tag_lower in ("h1", "h2"):
            self.in_heading = True
            self.current_heading = []

        # Forms
        elif tag_lower == "form":
            raw_action = val_dict.get("action") or self.page_url
            action = urljoin(self.page_url, raw_action)
            self.current_form = {
                "action": action,
                "has_password": False,
                "has_text": False,
            }
            self.forms.append(self.current_form)

        elif tag_lower == "input" and self.current_form is not None:
            itype = val_dict.get("type", "").lower()
            if itype == "password":
                self.current_form["has_password"] = True
            elif itype in ("text", "email", "tel", ""):
                self.current_form["has_text"] = True

        # Iframes
        elif tag_lower == "iframe":
            src = val_dict.get("src", "")
            style = val_dict.get("style", "").lower()
            w = val_dict.get("width", "")
            h = val_dict.get("height", "")
            is_hidden = (
                "display:none" in style.replace(" ", "")
                or "visibility:hidden" in style.replace(" ", "")
                or w in ("0", "1")
                or h in ("0", "1")
                or "hidden" in val_dict
            )
            if is_hidden and src:
                self.hidden_iframes.append(urljoin(self.page_url, src))

        # Mixed content detection on HTTPS
        if self.page_scheme == "https":
            src = val_dict.get("src") or val_dict.get("href")
            if src and isinstance(src, str) and src.lower().startswith("http://"):
                if tag_lower in ("script", "img", "iframe", "link", "audio", "video", "source"):
                    self.http_subresources.append(src)

    def handle_endtag(self, tag: str):
        tag_lower = tag.lower()
        if tag_lower == "form":
            self.current_form = None
        elif tag_lower == "title":
            self.in_title = False
        elif tag_lower in ("h1", "h2"):
            self.in_heading = False
            if self.current_heading:
                self.headings.append("".join(self.current_heading).strip())

    def handle_data(self, data: str):
        if self.in_title:
            self.title_text.append(data)
        elif self.in_heading:
            self.current_heading.append(data)


def audit_page_html(html: str, page_url: str) -> list[dict]:
    """Audit page HTML statically without executing script."""
    findings: list[dict] = []
    now = datetime.now(timezone.utc).isoformat()
    page_parts = urlsplit(page_url)
    page_host = (page_parts.hostname or "").lower()
    page_scheme = page_parts.scheme.lower()
    page_reg_domain = get_registrable_domain(page_host)

    parser = _PageSignalParser(page_url)
    try:
        parser.feed(html)
    except Exception:
        return []

    # 1. Form destinations & Credential Harvesting
    for form in parser.forms:
        if not form["has_password"]:
            continue
        action_url = str(form["action"])
        action_parts = urlsplit(action_url)
        action_host = (action_parts.hostname or "").lower()

        # A: Password form on plain HTTP
        if page_scheme == "http":
            findings.append({
                "id": "form-password-over-http",
                "category": "credential_form",
                "severity": "medium",
                "summary": "A password input form is served over unencrypted HTTP, leaving credentials exposed in transit.",
                "source": "Static page inspection",
                "observed_at": now,
                "group": "credential_form",
            })

        # B: Form posts to IP address
        if re.fullmatch(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", action_host) or ":" in action_host:
            findings.append({
                "id": "form-posts-to-ip",
                "category": "credential_form",
                "severity": "medium",
                "summary": f"A password form submits directly to a numeric IP address ({action_host}).",
                "source": "Static page inspection",
                "observed_at": now,
                "group": "credential_form",
            })

        # C: Form posts to free-hosting / paste / form-builder domain
        if action_host in _FORM_BUILDER_DOMAINS or get_registrable_domain(action_host) in _FORM_BUILDER_DOMAINS:
            findings.append({
                "id": "form-posts-to-form-builder",
                "category": "credential_form",
                "severity": "medium",
                "summary": f"A password form submits to a third-party form-builder or paste service ({action_host}).",
                "source": "Static page inspection",
                "observed_at": now,
                "group": "credential_form",
            })

        # D: Form posts cross-site
        if not action_parts.scheme.startswith("http"):
            findings.append({
                "id": "form-non-web-action",
                "category": "credential_form",
                "severity": "high",
                "summary": "A password form uses a non-web submission destination.",
                "source": "Static page inspection",
                "observed_at": now,
                "group": "credential_form",
            })
        elif not _same_site(action_host, page_host):
            findings.append({
                "id": "form-cross-site-submit",
                "category": "credential_form",
                "severity": "high",
                "summary": f"A password form submits credentials to a different website ({action_host}).",
                "source": "Static page inspection",
                "observed_at": now,
                "group": "credential_form",
            })

    # 2. Hidden iframes & Meta-refresh redirects
    if parser.hidden_iframes:
        for iframe_url in parser.hidden_iframes[:2]:
            iframe_host = urlsplit(iframe_url).hostname or ""
            if not _same_site(iframe_host, page_host):
                findings.append({
                    "id": "page-hidden-iframe",
                    "category": "redirect",
                    "severity": "medium",
                    "summary": f"A hidden or zero-size iframe embeds content from another site ({iframe_host}).",
                    "source": "Static page inspection",
                    "observed_at": now,
                    "group": "redirect",
                })
                break

    for refresh_url in parser.meta_refreshes:
        dest_host = urlsplit(refresh_url).hostname or ""
        if dest_host and not _same_site(dest_host, page_host):
            findings.append({
                "id": "page-meta-refresh-redirect",
                "category": "redirect",
                "severity": "medium",
                "summary": f"A meta-refresh directive redirects visitors to an external site ({dest_host}).",
                "source": "Static page inspection",
                "observed_at": now,
                "group": "redirect",
            })
            break

    # 3. Mixed content
    if parser.http_subresources:
        findings.append({
            "id": "page-mixed-content",
            "category": "security_header",
            "severity": "low",
            "summary": f"The HTTPS page loads {len(parser.http_subresources)} subresources over unencrypted HTTP (mixed content).",
            "source": "Static page inspection",
            "observed_at": now,
            "group": "security_headers",
        })

    # 4. Brand impersonation in page text (title / og:site_name / headings)
    page_text_elements = [
        "".join(parser.title_text),
        parser.og_site_name,
    ] + parser.headings
    combined_page_text = " ".join(page_text_elements).lower()

    for brand in _BRANDS:
        b_name = brand["name"]
        b_slug = brand["slug"].lower()
        b_domains = [d.lower() for d in brand.get("domains", [])]
        if page_reg_domain in b_domains:
            continue  # Legitimate domain for this brand

        # Check if brand name is prominently featured in title / heading
        if b_slug in combined_page_text or b_name.lower() in combined_page_text:
            findings.append({
                "id": f"page-brand-impersonation-{b_slug}",
                "category": "url_lookalike",
                "severity": "medium",
                "summary": f"The page title or heading displays the {b_name} brand, but the site domain ({page_host}) is not registered to this brand.",
                "source": "Static page inspection",
                "observed_at": now,
                "group": "url_lookalike",
            })
            break

    # 5. Static markers of obfuscation
    for pat, desc in _OBFUSCATION_PATTERNS:
        if pat.search(html):
            findings.append({
                "id": "page-script-obfuscation",
                "category": "page_content",
                "severity": "low",
                "summary": f"Static markers of script encoding or obfuscation were observed ({desc}).",
                "source": "Static page inspection",
                "observed_at": now,
                "group": "page_content",
            })
            break

    return findings

