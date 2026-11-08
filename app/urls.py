"""URL parsing and privacy-preserving indicator fingerprints."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def canonicalize_url(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError("URL must be a non-empty HTTP or HTTPS address under 2048 characters")
    if any(ord(char) < 0x20 or char.isspace() for char in value):
        raise ValueError("URL cannot contain whitespace or control characters")

    try:
        parts = urlsplit(value)
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("Only HTTP and HTTPS URLs are supported")
        if parts.username is not None or parts.password is not None:
            raise ValueError("URLs with embedded credentials are not supported")
        port = parts.port
    except ValueError as exc:
        raise ValueError("Invalid URL") from exc

    if port is not None and port not in {80, 443}:
        raise ValueError("Only ports 80 and 443 are supported")

    raw_host = parts.hostname.rstrip(".")
    if not raw_host or "%" in raw_host:
        raise ValueError("Invalid hostname")
    try:
        address = ipaddress.ip_address(raw_host)
        host = address.compressed.lower()
        rendered_host = f"[{host}]" if address.version == 6 else host
    except ValueError:
        try:
            host = raw_host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("Invalid internationalized hostname") from exc
        if len(host) > 253 or any(not _LABEL.fullmatch(label) for label in host.split(".")):
            raise ValueError("Invalid hostname")
        rendered_host = host

    default_port = 80 if scheme == "http" else 443
    netloc = rendered_host if port is None or port == default_port else f"{rendered_host}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def url_hash(value: str) -> str:
    canonical = canonicalize_url(value)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def indicator_fingerprint(value: str) -> str:
    canonical = canonicalize_url(value)
    parts = urlsplit(canonical)
    stable_indicator = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    return hashlib.sha256(stable_indicator.encode("utf-8")).hexdigest()


def host_from_url(value: str) -> str:
    return urlsplit(canonicalize_url(value)).hostname or ""
