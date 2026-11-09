"""Internal service client; called only after explicit scan consent."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


def make_scanner_client(base_url: str, token: str):
    endpoint = base_url.rstrip("/") + "/scan"

    def scan(url: str, ct_rdap_consent: bool = False) -> dict:
        body = json.dumps({"url": url, "ct_rdap_consent": ct_rdap_consent}).encode()
        request = urllib.request.Request(
            endpoint,
            data=body,
            headers={"Content-Type": "application/json", "X-Scanner-Token": token},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=24) as response:
                value = json.loads(response.read(64 * 1024))
            if not isinstance(value, dict):
                raise ValueError("invalid_scanner_response")
            return value
        except (OSError, urllib.error.URLError, ValueError):
            return {"complete": False, "findings": [], "redirect_hosts": [], "error": "scanner_unavailable"}

    return scan


def configured_scanner():
    base_url = os.environ.get("SCANNER_URL", "").strip()
    token = os.environ.get("SCANNER_TOKEN", "")
    if base_url and token:
        return make_scanner_client(base_url, token)
    # When no remote scanner microservice is configured (e.g. Vercel, single container),
    # fallback to in-process scan_url so live scans (TLS cert, headers, page signals) WORK everywhere!
    try:
        from scanner.engine import scan_url
        return scan_url
    except Exception:
        return None


def make_feed_fetcher(base_url: str, token: str):
    endpoint = base_url.rstrip("/") + "/feed"

    def fetch(source: str) -> bytes:
        body = json.dumps({"source": source}).encode()
        request = urllib.request.Request(
            endpoint,
            data=body,
            headers={"Content-Type": "application/json", "X-Scanner-Token": token},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                payload = response.read(128 * 1024 * 1024 + 1)
            if len(payload) > 128 * 1024 * 1024:
                raise ValueError("feed_too_large")
            return payload
        except (OSError, urllib.error.URLError) as exc:
            raise RuntimeError("feed_fetch_failed") from exc

    return fetch


def configured_feed_fetcher():
    base_url = os.environ.get("SCANNER_URL", "").strip()
    token = os.environ.get("SCANNER_TOKEN", "")
    if base_url and token:
        return make_feed_fetcher(base_url, token)
    try:
        from scanner.feed_fetch import provider_request
        return provider_request
    except Exception:
        return None
