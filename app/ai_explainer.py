"""AI and deterministic security explanation layer for Trust Card.

Interprets collected technical signals, certificate status, and threat intelligence
to produce clear, human-understandable explanations without hallucinating facts.
"""

from __future__ import annotations

import os
from typing import Any


def classify_risk(score: int, verdict: str, checked_count: int = 1) -> dict[str, str]:
    """Map score and deterministic verdict to one of the 5 standardized risk classifications.
    
    Classifications:
    - Safe / Low Risk
    - Suspicious / Medium Risk
    - High Risk
    - Malicious / Critical Risk
    - Unknown / Insufficient Evidence
    """
    if verdict in ("not_enough_info", "unable_to_check") or checked_count < 2:
        return {
            "key": "unknown",
            "label": "Unknown / Insufficient Evidence",
            "badge_color": "neutral",
            "description": "Not enough evidence has been collected yet to establish trust or risk.",
        }
    if verdict == "known_threat" or score >= 80:
        return {
            "key": "malicious",
            "label": "Malicious / Critical Risk",
            "badge_color": "danger",
            "description": "Confirmed threat intelligence match or critical risk indicators present.",
        }
    if verdict == "suspicious" or score >= 50:
        return {
            "key": "high_risk",
            "label": "High Risk",
            "badge_color": "alert",
            "description": "Multiple correlated risk signals suggest active deception or risk.",
        }
    if verdict == "caution" or score >= 20:
        return {
            "key": "suspicious",
            "label": "Suspicious / Medium Risk",
            "badge_color": "warning",
            "description": "Notable technical problems, certificate anomalies, or brand lookalike indicators found.",
        }
    return {
        "key": "safe",
        "label": "Safe / Low Risk",
        "badge_color": "success",
        "description": "No threat indicators detected across checked security dimensions. Note: never an absolute guarantee.",
    }


def generate_security_explanation(
    *,
    url: str,
    verdict: str,
    confidence: str,
    score: int,
    risk_class: str,
    findings: list[dict[str, Any]],
    pillars: dict[str, Any],
    certificate: dict[str, Any] | None = None,
    page_signals: list[dict[str, Any]] | None = None,
    mode: str = "local",
) -> dict[str, Any]:
    """Produce comprehensive security explanations based strictly on verified evidence."""
    warning_signs: list[str] = []
    attack_techniques: list[str] = []
    mitigations: list[str] = []
    trust_notes: list[str] = []

    # 1. Threat Intelligence
    threat_findings = [f for f in findings if f.get("group") == "threat_intelligence"]
    if threat_findings:
        warning_signs.append("URL is listed on verified threat intelligence feeds (PhishTank, URLhaus, or OpenPhish).")
        attack_techniques.append("Known Malicious Distribution: The site was previously identified distributing malware or harvesting credentials.")
        mitigations.append("Block domain immediately at perimeter firewalls and DNS resolvers.")

    # 2. Lookalike and brand impersonation
    lookalike_findings = [f for f in findings if f.get("group") == "url_lookalike"]
    if lookalike_findings:
        for f in lookalike_findings:
            warning_signs.append(f.get("summary") or "Domain name mimics a legitimate organization or brand.")
        attack_techniques.append("Brand Impersonation / Typosquatting: Attackers construct domains that look visually identical to deceive users into disclosing secrets.")
        mitigations.append("Navigate to the organization's verified domain directly by typing it or using an official app.")

    # 3. URL structure anomalies
    struct_findings = [f for f in findings if f.get("group") == "url_structure"]
    for f in struct_findings:
        warning_signs.append(f.get("summary") or "URL structure exhibits evasion or obfuscation characteristics.")
    if any(f.get("id") == "url-structure-ip-literal" for f in struct_findings):
        attack_techniques.append("Direct IP Access: Bypasses domain reputation monitoring and TLS name matching.")
    if any("fraud-keywords" in f.get("id", "") for f in struct_findings):
        attack_techniques.append("Deceptive Semantic Pathing: Uses sensitive keywords (e.g. 'login', 'kyc', 'verify') in URL path to manufacture false authority.")

    # 4. Message Context
    msg_findings = [f for f in findings if f.get("group") == "message_context"]
    if msg_findings:
        warning_signs.append("The message accompanying this link uses high-pressure psychological triggers (urgency, payment, or credentials).")
        attack_techniques.append("Social Engineering: Fabricated urgency or financial consequences designed to induce rapid user compliance before scrutiny.")
        mitigations.append("Verify claims independently via out-of-band communication before taking action.")

    # 5. Certificate and TLS
    cert_findings = [f for f in findings if f.get("group") == "certificate"]
    if cert_findings:
        for f in cert_findings:
            warning_signs.append(f.get("summary") or "TLS Certificate trust or key generation weakness detected.")
            trust_notes.append(f.get("summary") or "Certificate problem identified.")
        attack_techniques.append("Man-in-the-Middle (MitM) Vulnerability: An invalid, expired, or weak-key certificate fails to guarantee identity or cryptographic privacy.")
        mitigations.append("Do not enter credentials, financial information, or tokens on this connection.")
    elif certificate:
        trust_notes.append(f"Certificate issued by '{certificate.get('issuer', 'Standard CA')}' is valid until {certificate.get('valid_to', 'unknown')}.")
        if certificate.get("sct_count", 0) > 0:
            trust_notes.append(f"Certificate Transparency verified with {certificate['sct_count']} embedded timestamp(s).")
    else:
        trust_notes.append("Live TLS certificate inspection was not run. Run a consented scan to inspect cryptography.")

    # 6. Page Signals & Form Harvesting
    form_findings = [f for f in findings if f.get("group") in ("credential_form", "security_headers", "page_content")]
    if any(f.get("group") == "credential_form" for f in form_findings):
        warning_signs.append("Page contains password or sensitive input forms submitting to insecure or third-party destinations.")
        attack_techniques.append("Credential Harvesting: Static web forms designed to intercept entered passwords and relay them to an external endpoint.")
        mitigations.append("Never submit passwords or authentication codes on this page.")

    # Summary synthesis
    if verdict == "known_threat":
        summary = (
            f"The link '{url}' is classified as Malicious / Critical Risk (Score: {score}/100) because it directly matches "
            "confirmed threat intelligence sources or an approved community threat report. Interacting with this link presents an immediate risk."
        )
    elif verdict == "suspicious":
        summary = (
            f"The link '{url}' is classified as High Risk (Score: {score}/100). Multiple correlated security signals—including "
            f"{', '.join(warning_signs[:2]).lower() if warning_signs else 'heuristic risk factors'}—strongly indicate a fraudulent or deceptive destination."
        )
    elif verdict == "caution":
        summary = (
            f"The link '{url}' is classified as Suspicious / Medium Risk (Score: {score}/100) due to technical and cryptographic trust defects. "
            "While not identified on active phishing blacklists, the server configuration prevents establishing a trustworthy connection."
        )
    elif verdict == "no_strong_warning":
        summary = (
            f"The link '{url}' received a Low Risk assessment (Score: {score}/100) across {len(findings)} checked signals. "
            "No known threat feeds, lookalike domains, or critical misconfigurations were flagged. However, HTTPS and a clean check do not guarantee safety."
        )
    else:
        summary = (
            f"Insufficient data was available for '{url}' (Score: {score}/100). "
            "A local-only check with limited feed data cannot confirm or dismiss security risks. A consented live check is recommended."
        )

    if not mitigations:
        mitigations.append("Confirm the website address matches the official service provider before logging in.")
        mitigations.append("Always use multi-factor authentication (MFA) to mitigate credential theft.")

    return {
        "summary": summary,
        "key_warning_signs": warning_signs,
        "attack_techniques": attack_techniques if attack_techniques else ["Standard Web Browsing (no active attack vectors observed)"],
        "trust_analysis": " ".join(trust_notes),
        "recommended_remediation": mitigations,
        "source": "Deterministic Intelligence Engine",
    }

