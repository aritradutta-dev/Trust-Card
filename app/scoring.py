"""Pillar-based risk indicator scoring and evidence explanation.

The score explains and provides transparent visibility across 7 pillars;
it does NOT override the deterministic verdict rules in verdict.py.
"""

from __future__ import annotations

from typing import Literal

PillarStatus = Literal["not_checked", "clear", "attention", "alert"]

BASE_PILLAR_WEIGHTS = {
    "threat_intelligence": 35.0,
    "url_and_impersonation": 20.0,
    "page_content": 25.0,
    "certificate": 15.0,
    "community": 25.0,
    "message_context": 15.0,
    "web_security": 5.0,  # web_security adds at most a minor 5% contribution
}


def calculate_risk_scoring(
    findings: list[dict],
    *,
    live_scan_done: bool,
    has_message_context: bool,
    feed_available: bool = True,
) -> dict:
    """Calculate subscores (0-100) and status for each of the 7 security pillars."""
    pillars = {}

    # 1. Threat Intelligence
    threat_findings = [f for f in findings if f.get("group") == "threat_intelligence"]
    if threat_findings and any(f.get("confirmed") for f in threat_findings):
        ti_status: PillarStatus = "alert"
        ti_score = 100
        ti_why = "Exact match in verified threat intelligence feeds"
    elif threat_findings:
        ti_status = "attention"
        ti_score = 50
        ti_why = "Match in threat intelligence feeds"
    elif not feed_available:
        ti_status = "not_checked"
        ti_score = 0
        ti_why = "Not checked (threat intelligence feeds missing or stale)"
    else:
        ti_status = "clear"
        ti_score = 0
        ti_why = "Checked against threat intelligence feeds (no matches)"
    pillars["threat_intelligence"] = {
        "name": "Threat Intelligence",
        "status": ti_status,
        "score": ti_score,
        "why": ti_why,
        "findings": threat_findings,
    }

    # 2. URL and Impersonation
    url_findings = [f for f in findings if f.get("group") in ("url_lookalike", "url_structure")]
    if any(f.get("severity") == "medium" and f.get("group") == "url_lookalike" for f in url_findings):
        url_status: PillarStatus = "alert"
        url_score = 80
        url_why = "Lookalike or homoglyph impersonation pattern detected"
    elif any(f.get("severity") == "medium" for f in url_findings):
        url_status = "attention"
        url_score = 50
        url_why = "Suspicious URL structure or brand keywords on unrelated domain"
    elif url_findings:
        url_status = "attention"
        url_score = 25
        url_why = "Minor URL structure anomaly or brand indicator in path"
    else:
        url_status = "clear"
        url_score = 0
        url_why = "Domain structure and brand checks clear"
    pillars["url_and_impersonation"] = {
        "name": "URL & Impersonation",
        "status": url_status,
        "score": url_score,
        "why": url_why,
        "findings": url_findings,
    }

    # 3. Page Content
    page_findings = [f for f in findings if f.get("group") in ("credential_form", "page_content", "redirect")]
    if not live_scan_done:
        page_status: PillarStatus = "not_checked"
        page_score = 0
        page_why = "Not checked (run a live scan)"
    elif any(f.get("severity") == "high" for f in page_findings):
        page_status = "alert"
        page_score = 90
        page_why = "High-risk credential harvesting or destination behavior found"
    elif any(f.get("severity") == "medium" for f in page_findings):
        page_status = "attention"
        page_score = 55
        page_why = "Suspicious form destinations, iframes, or redirects found"
    elif any(f.get("severity") == "low" for f in page_findings):
        page_status = "attention"
        page_score = 20
        page_why = "Minor script encoding or structure signals observed"
    else:
        page_status = "clear"
        page_score = 0
        page_why = "No credential harvesting or hidden iframe forms found"
    pillars["page_content"] = {
        "name": "Page Content",
        "status": page_status,
        "score": page_score,
        "why": page_why,
        "findings": page_findings if live_scan_done else [],
    }

    # 4. Certificate & Trust
    cert_findings = [f for f in findings if f.get("group") in ("certificate", "tls", "domain_age")]
    if not live_scan_done:
        cert_status: PillarStatus = "not_checked"
        cert_score = 0
        cert_why = "Not checked (run a live scan)"
    elif any(f.get("severity") == "medium" for f in cert_findings):
        cert_status = "alert"
        cert_score = 75
        cert_why = "Certificate trust, validation, or weak key generation problem detected"
    elif any(f.get("severity") == "low" for f in cert_findings):
        cert_status = "attention"
        cert_score = 25
        cert_why = "Certificate expiring soon or missing Certificate Transparency log"
    else:
        cert_status = "clear"
        cert_score = 0
        cert_why = "Valid TLS certificate issued by a recognized authority"
    pillars["certificate"] = {
        "name": "Certificate & Trust",
        "status": cert_status,
        "score": cert_score,
        "why": cert_why,
        "findings": cert_findings if live_scan_done else [],
    }

    # 5. Web Security
    sec_findings = [f for f in findings if f.get("group") == "security_headers"]
    if not live_scan_done:
        sec_status: PillarStatus = "not_checked"
        sec_score = 0
        sec_why = "Not checked (run a live scan)"
    elif any("outdated" in f.get("id", "") for f in sec_findings):
        sec_status = "attention"
        sec_score = 30
        sec_why = "Server banner indicates potentially outdated software"
    elif sec_findings:
        sec_status = "attention"
        sec_score = min(20, len(sec_findings) * 5)
        sec_why = f"{len(sec_findings)} recommended HTTP security headers or cookie flags missing"
    else:
        sec_status = "clear"
        sec_score = 0
        sec_why = "Modern HTTP security headers configured"
    pillars["web_security"] = {
        "name": "Web Security",
        "status": sec_status,
        "score": sec_score,
        "why": sec_why,
        "findings": sec_findings if live_scan_done else [],
    }

    # 6. Community Intelligence
    comm_findings = [f for f in findings if f.get("group") == "community_report"]
    if any(f.get("confirmed") for f in comm_findings):
        comm_status: PillarStatus = "alert"
        comm_score = 100
        comm_why = "Confirmed local community report matches this link"
    elif comm_findings:
        comm_status = "attention"
        comm_score = 35
        comm_why = "Unverified local community report submitted for this link"
    else:
        comm_status = "clear"
        comm_score = 0
        comm_why = "No community reports on record for this link"
    pillars["community"] = {
        "name": "Community Intelligence",
        "status": comm_status,
        "score": comm_score,
        "why": comm_why,
        "findings": comm_findings,
    }

    # 7. Message Context
    msg_findings = [f for f in findings if f.get("group") == "message_context"]
    if not has_message_context:
        msg_status: PillarStatus = "not_checked"
        msg_score = 0
        msg_why = "Not checked (paste the message that accompanied the link)"
    elif any(f.get("severity") == "medium" for f in msg_findings):
        msg_status = "attention"
        msg_score = 60
        msg_why = "Message contains high-risk credential, payment, or personal data requests"
    elif msg_findings:
        msg_status = "attention"
        msg_score = 25
        msg_why = "Message contains urgency or pressure language"
    else:
        msg_status = "clear"
        msg_score = 0
        msg_why = "No urgent or sensitive context cues detected in surrounding message"
    pillars["message_context"] = {
        "name": "Message Context",
        "status": msg_status,
        "score": msg_score,
        "why": msg_why,
        "findings": msg_findings if has_message_context else [],
    }

    # Weighted Overall Indicator
    # Community: 25% if present; rebalance. If clear (no reports on record), weight is 0.
    active_weights: dict[str, float] = {}
    for key, p in pillars.items():
        if p["status"] == "not_checked":
            continue
        if key == "community":
            if p["findings"]:
                active_weights[key] = BASE_PILLAR_WEIGHTS["community"]
        else:
            active_weights[key] = BASE_PILLAR_WEIGHTS[key]

    total_weight = sum(active_weights.values())
    if total_weight > 0:
        weighted_sum = sum(pillars[k]["score"] * (active_weights[k] / total_weight) for k in active_weights)
        overall_score = int(round(weighted_sum))
    else:
        overall_score = 0

    overall_score = max(0, min(100, overall_score))

    checked_pillars = [k for k, p in pillars.items() if p["status"] != "not_checked"]
    summary_text = f"Risk indicators: {overall_score}/100 across {len(checked_pillars)} of 7 checks"

    if overall_score >= 80:
        risk_class = "malicious"
        risk_label = "Malicious / Critical Risk"
    elif overall_score >= 50:
        risk_class = "high"
        risk_label = "High Risk"
    elif overall_score >= 20:
        risk_class = "suspicious"
        risk_label = "Suspicious / Medium Risk"
    else:
        risk_class = "safe"
        risk_label = "Safe / Low Risk"

    return {
        "score": overall_score,
        "summary": summary_text,
        "checked_count": len(checked_pillars),
        "total_pillars": 7,
        "risk_class": risk_class,
        "risk_label": risk_label,
        "pillars": pillars,
        "unchecked_pillars": [k for k, p in pillars.items() if p["status"] == "not_checked"],
    }
