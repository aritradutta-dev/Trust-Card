"""URL structure and brand impersonation analysis for local-only and live checks."""

from __future__ import annotations

import json
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit

_DATA_DIR = Path(__file__).resolve().parent / "data"

# Load vendored public suffix list
try:
    with open(_DATA_DIR / "public_suffix_list.json", encoding="utf-8") as f:
        _PUBLIC_SUFFIXES = set(json.load(f))
except Exception:
    _PUBLIC_SUFFIXES = set()

# Load bundled brands
try:
    with open(_DATA_DIR / "brands.json", encoding="utf-8") as f:
        _BRANDS = json.load(f)
except Exception:
    _BRANDS = []

_SHORTENER_HOSTS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "buff.ly",
    "ow.ly",
    "cutt.ly",
    "rb.gy",
    "goo.gl",
    "rebrand.ly",
    "bl.ink",
    "shorturl.at",
}

_SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "top",
    "xyz",
    "fit",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "work",
    "click",
    "loan",
    "buzz",
    "country",
}

_FRAUD_KEYWORDS = [
    "payment",
    "upi",
    "kyc",
    "refund",
    "verify",
    "login",
    "signin",
    "registration fee",
    "registration-fee",
    "offer letter",
    "offer-letter",
    "interview",
    "account-update",
    "secure-banking",
    "claim-reward",
    "lottery",
]

_HOMOGLYPH_MAP = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "8": "b",
    "@": "a",
    "$": "s",
}


def get_registrable_domain(host: str) -> str:
    """Extract registrable domain (e.g. example.co.uk, bank.com) using the vendored public suffix list."""
    host = host.lower().rstrip(".")
    if not host:
        return ""
    labels = host.split(".")
    if len(labels) <= 1:
        return host

    # Match longest public suffix
    for i in range(1, len(labels)):
        candidate_suffix = ".".join(labels[i:])
        if candidate_suffix in _PUBLIC_SUFFIXES:
            return ".".join(labels[i - 1:])

    # Default fallback: 2 labels (e.g. domain.com)
    return ".".join(labels[-2:])


def _levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def _normalize_substitutions(text: str) -> str:
    res = text.lower()
    res = res.replace("rn", "m")
    res = res.replace("vv", "w")
    for digit, char in _HOMOGLYPH_MAP.items():
        res = res.replace(digit, char)
    return res


def _has_mixed_scripts(text: str) -> bool:
    scripts = set()
    for char in text:
        if not char.isalpha():
            continue
        name = unicodedata.name(char, "")
        if "LATIN" in name:
            scripts.add("LATIN")
        elif "CYRILLIC" in name:
            scripts.add("CYRILLIC")
        elif "GREEK" in name:
            scripts.add("GREEK")
        elif "ARABIC" in name:
            scripts.add("ARABIC")
        elif "DEVANAGARI" in name:
            scripts.add("DEVANAGARI")
    return len(scripts) > 1


def analyze_url(canonical_url: str) -> list[dict]:
    """Pure analysis over the canonical URL without making network connections."""
    findings: list[dict] = []
    now = datetime.now(timezone.utc).isoformat()
    parts = urlsplit(canonical_url)
    host = (parts.hostname or "").lower()
    path = unquote(parts.path or "").lower()
    query = unquote(parts.query or "").lower()
    full_path_and_query = f"{path}?{query}" if query else path

    # 1. Punycode and IDN checks
    if "xn--" in host or _has_mixed_scripts(host):
        findings.append({
            "id": "url-lookalike-punycode",
            "category": "url_lookalike",
            "severity": "medium",
            "summary": "The link uses an internationalized or punycode domain (IDN), which can imitate familiar brand names using lookalike characters.",
            "source": "URL structure and brand analysis",
            "observed_at": now,
            "group": "url_lookalike",
        })

    reg_domain = get_registrable_domain(host)
    reg_domain_name = reg_domain.split(".")[0] if "." in reg_domain else reg_domain
    normalized_reg_name = _normalize_substitutions(reg_domain_name)

    # 2. Brand lookalike checks
    for brand in _BRANDS:
        brand_name = brand["name"]
        brand_slug = brand["slug"].lower()
        canonical_domains = [d.lower() for d in brand.get("domains", [])]
        aliases = [a.lower() for a in brand.get("aliases", [brand_slug])]

        # If this domain is legitimately owned by the brand, skip impersonation flagging
        if reg_domain in canonical_domains:
            continue

        matched_brand = False
        reason = ""

        # Check A: normalized lookalike (digit/letter swap) of brand slug or alias
        for alias in aliases:
            if normalized_reg_name == alias and reg_domain_name != alias:
                matched_brand = True
                reason = f"The domain '{reg_domain}' uses character substitutions to imitate {brand_name}."
                break
            if len(alias) >= 4:
                dist = _levenshtein_distance(reg_domain_name, alias)
                if dist == 1 or (len(alias) >= 6 and dist == 2):
                    matched_brand = True
                    reason = f"The domain '{reg_domain}' is visually similar (edit distance {dist}) to {brand_name}."
                    break

        # Check B: brand name / alias in subdomain of an unrelated registrable domain
        if not matched_brand and reg_domain not in canonical_domains:
            subdomain_part = host[:-len(reg_domain)].rstrip(".") if host.endswith(reg_domain) else ""
            if subdomain_part:
                sub_labels = subdomain_part.split(".")
                for label in sub_labels:
                    norm_label = _normalize_substitutions(label)
                    for alias in aliases:
                        if norm_label == alias or label == alias or (len(alias) >= 5 and alias in norm_label):
                            matched_brand = True
                            reason = f"The link places the {brand_name} brand in a subdomain of an unrelated site ({reg_domain})."
                            break
                    if matched_brand:
                        break

        # Check C: brand in path of an unrelated registrable domain with fraud keywords
        if not matched_brand and reg_domain not in canonical_domains:
            for alias in aliases:
                # Brand in path e.g. /paypal/login or /sbi-update/
                if f"/{alias}" in full_path_and_query or f"-{alias}" in full_path_and_query:
                    if any(kw in full_path_and_query for kw in ["login", "signin", "verify", "update", "pay", "secure", "kyc"]):
                        matched_brand = True
                        reason = f"The link uses the {brand_name} brand in its path on an unrelated host ({host})."
                        break

        if matched_brand:
            findings.append({
                "id": f"url-lookalike-{brand_slug}",
                "category": "url_lookalike",
                "severity": "medium",
                "summary": reason or f"The link appears to imitate {brand_name} on an unrelated domain ({reg_domain}).",
                "source": "URL structure and brand analysis",
                "observed_at": now,
                "group": "url_lookalike",
            })
            break  # Flag at most one brand lookalike finding

    # 3. Structural checks
    # IP-literal host
    is_ip = False
    clean_host = host.strip("[]")
    if re.fullmatch(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean_host) or ":" in clean_host:
        is_ip = True
        findings.append({
            "id": "url-structure-ip-literal",
            "category": "url_structure",
            "severity": "medium",
            "summary": "The link uses a numeric IP address directly instead of a registered domain name.",
            "source": "URL structure and brand analysis",
            "observed_at": now,
            "group": "url_structure",
        })

    # @ in authority (credentials or spoofing)
    if "@" in parts.netloc or "@" in canonical_url.split("?")[0].split("#")[0]:
        findings.append({
            "id": "url-structure-at-symbol",
            "category": "url_structure",
            "severity": "medium",
            "summary": "The link contains an '@' symbol in the address, which can obscure the actual destination server.",
            "source": "URL structure and brand analysis",
            "observed_at": now,
            "group": "url_structure",
        })

    # Excessive subdomain depth (> 3 subdomain labels before registrable domain)
    if not is_ip and reg_domain:
        subdomain_part = host[:-len(reg_domain)].rstrip(".") if host.endswith(reg_domain) else ""
        if subdomain_part:
            depth = len([label for label in subdomain_part.split(".") if label])
            if depth >= 3:
                findings.append({
                    "id": "url-structure-excessive-subdomains",
                    "category": "url_structure",
                    "severity": "low",
                    "summary": f"The host has an unusually high subdomain depth ({depth} levels), which can disguise the true host.",
                    "source": "URL structure and brand analysis",
                    "observed_at": now,
                    "group": "url_structure",
                })

    # Very long URL (> 150 chars)
    if len(canonical_url) > 150:
        findings.append({
            "id": "url-structure-very-long",
            "category": "url_structure",
            "severity": "low",
            "summary": "The link is unusually long (> 150 characters), which can conceal the true destination in message clients.",
            "source": "URL structure and brand analysis",
            "observed_at": now,
            "group": "url_structure",
        })

    # Known URL shortener
    if host in _SHORTENER_HOSTS:
        findings.append({
            "id": "url-structure-shortener",
            "category": "url_structure",
            "severity": "low",
            "summary": "The link uses a URL shortener service that obscures the destination until followed.",
            "source": "URL structure and brand analysis",
            "observed_at": now,
            "group": "url_structure",
        })

    # Suspicious TLD
    tld = host.split(".")[-1] if "." in host else ""
    if tld in _SUSPICIOUS_TLDS:
        findings.append({
            "id": f"url-structure-tld-{tld}",
            "category": "url_structure",
            "severity": "low",
            "summary": f"The link uses the '.{tld}' top-level domain, which has elevated abuse rates in phishing campaigns.",
            "source": "URL structure and brand analysis",
            "observed_at": now,
            "group": "url_structure",
        })

    # 4. Fraud keywords in path or host
    found_keywords = [kw for kw in _FRAUD_KEYWORDS if kw in full_path_and_query or kw in host]
    if found_keywords:
        kw_list = ", ".join(f"'{kw}'" for kw in found_keywords[:3])
        findings.append({
            "id": "url-structure-fraud-keywords",
            "category": "url_structure",
            "severity": "low",
            "summary": f"The link path or address includes fraud-pattern keywords ({kw_list}).",
            "source": "URL structure and brand analysis",
            "observed_at": now,
            "group": "url_structure",
        })

    return findings

