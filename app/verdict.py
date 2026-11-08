"""Small, deterministic rules for turning evidence into a cautious verdict."""

from __future__ import annotations


def decide_verdict(
    findings: list[dict],
    *,
    scan_complete: bool,
    feed_stale: bool = False,
    live_scan_done: bool = False,
    coverage: str = "local_only",
) -> dict[str, str]:
    confirmed_groups = {"threat_intelligence", "community_report"}
    if any(
        item.get("confirmed") and item.get("group") in confirmed_groups
        for item in findings
    ):
        return {"verdict": "known_threat", "confidence": "high"}

    high_signal = any(
        item.get("severity") == "high"
        and item.get("group") in {"credential_form", "redirect"}
        for item in findings
    )
    medium_groups = {
        item.get("group")
        for item in findings
        if item.get("severity") == "medium"
        and item.get("group")
        in {
            "message_context",
            "redirect",
            "certificate",
            "url_lookalike",
            "young_domain",
            "domain_age",
            "credential_form",
        }
    }
    if high_signal or len(medium_groups) >= 2:
        return {"verdict": "suspicious", "confidence": "medium" if feed_stale else "high"}

    # Certificate-only technical problems: show caution, not reassurance.
    has_cert_problem = any(
        item.get("severity") in {"medium", "high"}
        and item.get("group") == "certificate"
        for item in findings
    )
    if has_cert_problem:
        return {"verdict": "caution", "confidence": "medium"}

    if not scan_complete:
        return {"verdict": "unable_to_check", "confidence": "low"}

    # Local-only check with stale or missing feeds: not enough information.
    if coverage == "local_only" and feed_stale and not live_scan_done:
        return {"verdict": "not_enough_info", "confidence": "low"}

    return {"verdict": "no_strong_warning", "confidence": "low" if feed_stale else "medium"}
