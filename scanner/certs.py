"""In-depth TLS certificate validation and trust assessment."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
from cryptography.x509.oid import ExtensionOID

_DATA_DIR = Path(__file__).resolve().parent / "data"

try:
    with open(_DATA_DIR / "ca_watchlist.json", encoding="utf-8") as f:
        _CA_WATCHLIST = json.load(f)
except Exception:
    _CA_WATCHLIST = []

try:
    with open(_DATA_DIR / "weak_key_fingerprints.json", encoding="utf-8") as f:
        _WEAK_SPKI_FINGERPRINTS = set(json.load(f).get("fingerprints", []))
except Exception:
    _WEAK_SPKI_FINGERPRINTS = set()


def _sieve_primes(limit: int = 10000) -> list[int]:
    is_prime = [True] * (limit + 1)
    is_prime[0] = is_prime[1] = False
    for p in range(2, int(limit**0.5) + 1):
        if is_prime[p]:
            for multiple in range(p * p, limit + 1, p):
                is_prime[multiple] = False
    return [p for p, prime in enumerate(is_prime) if prime]


_SMALL_PRIMES = _sieve_primes(10000)


def _match_hostname(hostname: str, san: str) -> bool:
    h = hostname.lower().rstrip(".")
    s = san.lower().rstrip(".")
    if s.startswith("*."):
        # Wildcard matches only one label (RFC 6125)
        suffix = s[2:]
        if "." not in h:
            return False
        prefix, host_suffix = h.split(".", 1)
        return host_suffix == suffix and "." not in prefix
    return h == s


def analyze_certificate_der(der_bytes: bytes, target_host: str) -> tuple[dict, list[dict]]:
    """Parse DER certificate bytes and return (cert_details_dict, findings_list)."""
    findings: list[dict] = []
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    try:
        cert = x509.load_der_x509_certificate(der_bytes)
    except Exception as exc:
        return {}, [{
            "category": "certificate",
            "severity": "medium",
            "summary": f"Certificate could not be parsed: {exc}",
            "source": "Certificate analysis",
            "observed_at": now_iso,
            "group": "certificate",
        }]

    # 1. Dates and Validity
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    if now > not_after:
        findings.append({
            "id": "cert-expired",
            "category": "certificate",
            "severity": "medium",
            "summary": f"The TLS certificate expired on {not_after.strftime('%Y-%m-%d')}.",
            "source": "Certificate analysis",
            "observed_at": now_iso,
            "group": "certificate",
        })
    elif now < not_before:
        findings.append({
            "id": "cert-not-yet-valid",
            "category": "certificate",
            "severity": "medium",
            "summary": f"The TLS certificate is not yet valid (valid from {not_before.strftime('%Y-%m-%d')}).",
            "source": "Certificate analysis",
            "observed_at": now_iso,
            "group": "certificate",
        })
    else:
        # Expiring soon
        days_remaining = (not_after - now).total_seconds() / 86400
        if days_remaining < 14:
            findings.append({
                "id": "cert-expiring-soon",
                "category": "certificate",
                "severity": "low",
                "summary": f"The TLS certificate expires within {int(days_remaining)} days.",
                "source": "Certificate analysis",
                "observed_at": now_iso,
                "group": "certificate",
            })

    validity_days = (not_after - not_before).days
    if validity_days > 398:
        findings.append({
            "id": "cert-validity-too-long",
            "category": "certificate",
            "severity": "low",
            "summary": f"The certificate validity period ({validity_days} days) exceeds the industry-standard 398-day limit.",
            "source": "Certificate analysis",
            "observed_at": now_iso,
            "group": "certificate",
        })

    age_days = (now - not_before).days
    if 0 <= age_days <= 7:
        findings.append({
            "id": "cert-issued-recently",
            "category": "certificate",
            "severity": "low",
            "summary": f"The certificate was issued recently ({age_days} days ago), which is common for newly created campaign domains.",
            "source": "Certificate analysis",
            "observed_at": now_iso,
            "group": "certificate",
        })

    # 2. Hostname matching against SAN
    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                sans.append(name.value)
            elif isinstance(name, x509.IPAddress):
                sans.append(str(name.value))
    except x509.ExtensionNotFound:
        pass

    target_clean = target_host.strip("[]").lower()
    matches_host = False
    if sans:
        matches_host = any(_match_hostname(target_clean, san) for san in sans)
    else:
        # Fallback to CN in Subject if SAN is absent
        cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if cn_attrs:
            cn = cn_attrs[0].value
            matches_host = _match_hostname(target_clean, cn if isinstance(cn, str) else cn.decode())

    if target_clean and not matches_host:
        findings.append({
            "id": "cert-hostname-mismatch",
            "category": "certificate",
            "severity": "medium",
            "summary": f"The certificate does not match the requested hostname '{target_clean}'.",
            "source": "Certificate analysis",
            "observed_at": now_iso,
            "group": "certificate",
        })

    # 3. Self-signed detection
    is_self_signed = cert.issuer == cert.subject
    if is_self_signed:
        findings.append({
            "id": "cert-self-signed",
            "category": "certificate",
            "severity": "medium",
            "summary": "The certificate is self-signed and not signed by a recognized Certificate Authority.",
            "source": "Certificate analysis",
            "observed_at": now_iso,
            "group": "certificate",
        })

    # 4. Signature Algorithm
    sig_algo = cert.signature_algorithm_oid._name.lower() if hasattr(cert.signature_algorithm_oid, "_name") else str(cert.signature_algorithm_oid)
    if "md5" in sig_algo or "sha1" in sig_algo:
        findings.append({
            "id": "cert-weak-signature",
            "category": "certificate",
            "severity": "medium",
            "summary": f"The certificate uses an obsolete, cryptographically broken signature algorithm ({sig_algo}).",
            "source": "Certificate analysis",
            "observed_at": now_iso,
            "group": "certificate",
        })

    # 5. Key Strength & Weak Key Generation (eMudhra theme)
    pubkey = cert.public_key()
    key_type = "Unknown"
    key_size = 0
    spki_der = b""
    try:
        spki_der = pubkey.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    except Exception:
        pass
    spki_sha256 = hashlib.sha256(spki_der).hexdigest() if spki_der else ""

    if isinstance(pubkey, rsa.RSAPublicKey):
        key_type = "RSA"
        key_size = pubkey.key_size
        numbers = pubkey.public_numbers()
        n, e = numbers.n, numbers.e

        if key_size < 2048:
            findings.append({
                "id": "cert-weak-rsa-key",
                "category": "certificate",
                "severity": "medium",
                "summary": f"The RSA key size ({key_size} bits) is below the minimum secure standard of 2048 bits.",
                "source": "Certificate analysis",
                "observed_at": now_iso,
                "group": "certificate",
            })

        if e not in (65537, 3):
            findings.append({
                "id": "cert-unusual-rsa-exponent",
                "category": "certificate",
                "severity": "low",
                "summary": f"The RSA public exponent ({e}) is non-standard.",
                "source": "Certificate analysis",
                "observed_at": now_iso,
                "group": "certificate",
            })

        # Trial division check for weak key generation (eMudhra incident theme)
        small_factor_found = False
        for p in _SMALL_PRIMES:
            if n % p == 0:
                small_factor_found = True
                break

        if small_factor_found:
            findings.append({
                "id": "cert-weak-key-generation",
                "category": "certificate",
                "severity": "medium",
                "summary": "Flawed RSA key generation detected: modulus contains small prime factors, indicating weak or compromised entropy.",
                "source": "Certificate analysis",
                "observed_at": now_iso,
                "group": "certificate",
            })

    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        key_type = "ECDSA"
        key_size = pubkey.key_size
        curve_name = pubkey.curve.name.lower()
        if curve_name not in ("secp256r1", "secp384r1", "secp521r1"):
            findings.append({
                "id": "cert-unusual-ec-curve",
                "category": "certificate",
                "severity": "medium",
                "summary": f"The elliptic curve '{curve_name}' is not in the standard secure suite (P-256, P-384, P-521).",
                "source": "Certificate analysis",
                "observed_at": now_iso,
                "group": "certificate",
            })
    elif isinstance(pubkey, ed25519.Ed25519PublicKey):
        key_type = "Ed25519"
        key_size = 256
    elif isinstance(pubkey, dsa.DSAPublicKey):
        key_type = "DSA"
        key_size = pubkey.key_size
        findings.append({
            "id": "cert-dsa-key",
            "category": "certificate",
            "severity": "medium",
            "summary": "The certificate uses a deprecated DSA public key.",
            "source": "Certificate analysis",
            "observed_at": now_iso,
            "group": "certificate",
        })

    # Compare SPKI against known weak key fingerprints
    if spki_sha256 and spki_sha256 in _WEAK_SPKI_FINGERPRINTS:
        findings.append({
            "id": "cert-known-weak-spki",
            "category": "certificate",
            "severity": "medium",
            "summary": "The public key matches a known flawed or compromised key fingerprint database.",
            "source": "Certificate analysis",
            "observed_at": now_iso,
            "group": "certificate",
        })

    # 6. Certificate Authority Watchlist Check
    issuer_str = cert.issuer.rfc4514_string()
    for entry in _CA_WATCHLIST:
        match_pattern = entry.get("issuer_match", "").lower()
        if match_pattern and match_pattern in issuer_str.lower():
            status = entry.get("status", "under_review")
            status_text = "under review" if status == "under_review" else "distrusted"
            findings.append({
                "id": f"cert-ca-watchlist-{match_pattern}",
                "category": "certificate",
                "severity": "medium",
                "summary": f"This certificate was issued by an authority on the watchlist ({status_text}). Verify the site through an official channel.",
                "source": "Certificate Authority Watchlist",
                "observed_at": now_iso,
                "group": "certificate",
            })
            break

    # 7. Embedded SCT Presence
    sct_count = 0
    try:
        sct_ext = cert.extensions.get_extension_for_oid(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        sct_count = len(sct_ext.value)
    except x509.ExtensionNotFound:
        sct_count = 0

    if sct_count == 0 and not is_self_signed:
        findings.append({
            "id": "cert-no-embedded-sct",
            "category": "certificate",
            "severity": "low",
            "summary": "The certificate contains no embedded Signed Certificate Timestamps (SCTs); it is not logged in Certificate Transparency as far as the certificate shows.",
            "source": "Certificate analysis",
            "observed_at": now_iso,
            "group": "certificate",
        })

    details = {
        "issuer": issuer_str,
        "subject": cert.subject.rfc4514_string(),
        "sans": sans,
        "valid_from": not_before.isoformat(),
        "valid_to": not_after.isoformat(),
        "key_type": key_type,
        "key_size": key_size,
        "signature_algorithm": sig_algo,
        "sct_count": sct_count,
        "serial_number": str(cert.serial_number),
        "spki_sha256": spki_sha256,
        "is_self_signed": is_self_signed,
    }

    return details, findings

