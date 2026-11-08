"""Parse provider snapshots and swap them into SQLite only after full validation."""

from __future__ import annotations

import csv
import gzip
import io
import json
from datetime import datetime, timezone

from app.storage import record_feed_error, replace_feed
from app.urls import canonicalize_url, host_from_url, url_hash

MAX_DECOMPRESSED_BYTES = 256 * 1024 * 1024


def parse_feed(source: str, payload: bytes) -> list[dict[str, str]]:
    entries: dict[str, dict[str, str]] = {}
    if source == "PhishTank":
        raw = payload
        if payload.startswith(b"\x1f\x8b"):
            with gzip.GzipFile(fileobj=io.BytesIO(payload)) as compressed:
                raw = compressed.read(MAX_DECOMPRESSED_BYTES + 1)
            if len(raw) > MAX_DECOMPRESSED_BYTES:
                raise ValueError("feed_too_large")
        data = json.loads(raw)
        if not isinstance(data, list):
            raise ValueError("invalid_phishtank_feed")
        for row in data:
            if not isinstance(row, dict) or str(row.get("verified", "")).lower() != "yes":
                continue
            value = row.get("url")
            if not isinstance(value, str):
                continue
            try:
                canonical = canonicalize_url(value)
            except ValueError:
                continue
            entries[url_hash(canonical)] = {"url_hash": url_hash(canonical), "host": host_from_url(canonical)}
    elif source == "URLhaus":
        text = payload.decode("utf-8-sig", errors="replace")
        lines = []
        header_found = False
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            candidate = line.lstrip("# ").strip()
            columns = next(csv.reader([candidate]), [])
            if not header_found and "url" in {column.strip().strip('"').lower() for column in columns}:
                lines.append(candidate)
                header_found = True
            elif header_found and not line.startswith("#"):
                lines.append(line)
        if not header_found:
            raise ValueError("invalid_urlhaus_feed")
        reader = csv.DictReader(lines)
        url_field = next(name for name in reader.fieldnames if name.strip().lower() == "url")
        for row in reader:
            value = row.get(url_field)
            if not value:
                continue
            try:
                canonical = canonicalize_url(value.strip())
            except ValueError:
                continue
            digest = url_hash(canonical)
            entries[digest] = {"url_hash": digest, "host": host_from_url(canonical)}
    elif source == "OpenPhish":
        text = payload.decode("utf-8", errors="replace")
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                canonical = canonicalize_url(line)
            except ValueError:
                continue
            digest = url_hash(canonical)
            entries[digest] = {"url_hash": digest, "host": host_from_url(canonical)}
    else:
        raise ValueError("unsupported_feed")
    return list(entries.values())


def refresh_feed(db_path, source: str, fetcher) -> int:
    try:
        entries = parse_feed(source, fetcher(source))
        return replace_feed(db_path, source, entries, datetime.now(timezone.utc).isoformat())
    except Exception:
        # Provider URLs may carry credentials; store a stable generic status only.
        record_feed_error(db_path, source, "refresh_failed")
        raise
