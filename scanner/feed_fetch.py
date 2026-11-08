"""Fetch only the named intelligence providers; user supplied URLs are not accepted."""

from __future__ import annotations

import os
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlsplit

MAX_FEED_BYTES = 128 * 1024 * 1024


class _SameHostRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        target = urljoin(request.full_url, new_url)
        old, new = urlsplit(request.full_url), urlsplit(target)
        if new.scheme != "https" or new.hostname != old.hostname or new.username or new.password:
            raise urllib.error.HTTPError(request.full_url, code, "provider_redirect_blocked", headers, file_pointer)
        return super().redirect_request(request, file_pointer, code, message, headers, target)


def provider_request(source: str) -> bytes:
    if source == "PhishTank":
        key = os.environ.get("PHISHTANK_APP_KEY", "")
        if not key:
            raise ValueError("PhishTank app key is not configured")
        url = f"https://data.phishtank.com/data/{key}/online-valid.json.gz"
    elif source == "URLhaus":
        key = os.environ.get("URLHAUS_AUTH_KEY", "")
        if not key:
            raise ValueError("URLhaus auth key is not configured")
        url = f"https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv"
    elif source == "OpenPhish":
        # Community feed: free, plain text, no API key required
        url = "https://openphish.com/feed.txt"
    else:
        raise ValueError("unsupported_feed")
    opener = urllib.request.build_opener(_SameHostRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "TrustCard-Local/0.1", "Accept-Encoding": "identity"})
    try:
        with opener.open(request, timeout=45) as response:
            payload = response.read(MAX_FEED_BYTES + 1)
    except (OSError, urllib.error.URLError) as exc:
        raise ValueError("provider_unavailable") from exc
    if len(payload) > MAX_FEED_BYTES:
        raise ValueError("feed_too_large")
    return payload
