"""Consent-gated third-party Certificate Transparency (crt.sh) and RDAP lookups.

Sends the hostname ONLY (never path or query parameters) to named fixed providers.
Protected with strict timeouts, size limits, and same-host redirect guards.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

_DATA_DIR = Path(__file__).resolve().parent / "data"

try:
    with open(_DATA_DIR / "ca_watchlist.json", encoding="utf-8") as f:
        _CA_WATCHLIST = json.load(f)
except Exception:
    _CA_WATCHLIST = []

MAX_LOOKUP_BYTES = 1024 * 1024  # 1 MiB


class _StrictSameHostRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        target = urljoin(request.full_url, new_url)
        old, new = urlsplit(request.full_url), urlsplit(target)
        if new.scheme != "https" or new.hostname != old.hostname or new.username or new.password:
            raise urllib.error.HTTPError(request.full_url, code, "redirect_off_fixed_host_blocked", headers, file_pointer)
        return super().redirect_request(request, file_pointer, code, message, headers, target)


def lookup_ct_logs(hostname: str, timeout: float = 6.0) -> list[dict]:
    """Query crt.sh JSON for the hostname with strict limits. Hostname only."""
    findings: list[dict] = []
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    clean_host = hostname.strip("[]").lower()

    url = f"https://crt.sh/?q={clean_host}&output=json"
    opener = urllib.request.build_opener(_StrictSameHostRedirect())
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "TrustCard-Scanner/0.1 (hostname-only CT check)", "Accept": "application/json"},
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            data = resp.read(MAX_LOOKUP_BYTES + 1)
        if len(data) > MAX_LOOKUP_BYTES:
            return []
        entries = json.loads(data.decode("utf-8", errors="replace"))
        if not isinstance(entries, list) or not entries:
            return []
    except Exception:
        return []

    # Analyze crt.sh log entries
    earliest_seen: datetime | None = None
    issuers_30d: set[str] = set()
    watchlisted_ca_found = False

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        entry_time_str = entry.get("entry_timestamp") or entry.get("not_before")
        issuer_name = str(entry.get("issuer_name", "")).lower()

        for watch_item in _CA_WATCHLIST:
            w = watch_item.get("issuer_match", "").lower()
            if w and w in issuer_name:
                watchlisted_ca_found = True

        if entry_time_str:
            try:
                t = datetime.fromisoformat(entry_time_str)
                if t.tzinfo is None:
                    t = t.replace(tzinfo=timezone.utc)
                if earliest_seen is None or t < earliest_seen:
                    earliest_seen = t
                if (now - t).total_seconds() <= 30 * 86400:
                    issuers_30d.add(issuer_name)
            except Exception:
                pass

    if earliest_seen:
        age_days = (now - earliest_seen).total_seconds() / 86400
        if 0 <= age_days <= 7:
            findings.append({
                "id": "ct-first-logged-recently",
                "category": "certificate",
                "severity": "low",
                "summary": f"Certificate was first logged in Certificate Transparency only {int(age_days)} days ago with no earlier record.",
                "source": "Certificate Transparency (crt.sh)",
                "observed_at": now_iso,
                "group": "certificate",
            })

    if len(issuers_30d) >= 3:
        findings.append({
            "id": "ct-many-issuers-30d",
            "category": "certificate",
            "severity": "low",
            "summary": f"Host has certificates from {len(issuers_30d)} different certificate authorities logged in the last 30 days.",
            "source": "Certificate Transparency (crt.sh)",
            "observed_at": now_iso,
            "group": "certificate",
        })

    if watchlisted_ca_found:
        findings.append({
            "id": "ct-watchlist-ca-history",
            "category": "certificate",
            "severity": "medium",
            "summary": "Certificate Transparency logs show an authority on the watchlist has issued certificates for this hostname.",
            "source": "Certificate Transparency (crt.sh)",
            "observed_at": now_iso,
            "group": "certificate",
        })

    return findings


def lookup_domain_age_rdap(hostname: str, timeout: float = 6.0) -> list[dict]:
    """Query RDAP for domain registration age via rdap.org. Hostname only."""
    findings: list[dict] = []
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    clean_host = hostname.strip("[]").lower()

    # Extract base domain if possible
    labels = clean_host.split(".")
    domain_to_query = ".".join(labels[-2:]) if len(labels) >= 2 else clean_host

    url = f"https://rdap.org/domain/{domain_to_query}"
    opener = urllib.request.build_opener(_StrictSameHostRedirect())
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "TrustCard-Scanner/0.1 (hostname-only RDAP check)", "Accept": "application/json"},
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            data = resp.read(MAX_LOOKUP_BYTES + 1)
        if len(data) > MAX_LOOKUP_BYTES:
            return []
        record = json.loads(data.decode("utf-8", errors="replace"))
        if not isinstance(record, dict):
            return []
    except Exception:
        return []

    events = record.get("events", [])
    reg_date: datetime | None = None
    for ev in events:
        if isinstance(ev, dict) and ev.get("eventAction") in ("registration", "created"):
            date_str = ev.get("eventDate")
            if date_str:
                try:
                    dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    reg_date = dt
                    break
                except Exception:
                    pass

    if reg_date:
        age_days = (now - reg_date).total_seconds() / 86400
        if 0 <= age_days < 30:
            findings.append({
                "id": "rdap-young-domain",
                "category": "domain_age",
                "severity": "medium",
                "summary": f"This domain was registered only {int(age_days)} days ago (under 30 days). Recently created domains have a high incidence of fraud.",
                "source": "Domain Registration (RDAP)",
                "observed_at": now_iso,
                "group": "domain_age",
            })

    return findings
