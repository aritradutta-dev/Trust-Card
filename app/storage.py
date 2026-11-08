"""Small SQLite store for threat feeds and local community reports."""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator


def _connect(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def _connection(db_path: str | Path) -> Iterator[sqlite3.Connection]:
    connection = _connect(db_path)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def init_db(db_path: str | Path) -> None:
    with _connection(db_path) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS feed_entries (
                source TEXT NOT NULL,
                url_hash TEXT NOT NULL,
                host TEXT NOT NULL,
                PRIMARY KEY (source, url_hash)
            );
            CREATE TABLE IF NOT EXISTS feed_status (
                source TEXT PRIMARY KEY,
                updated_at TEXT NOT NULL,
                entry_count INTEGER NOT NULL,
                last_error TEXT
            );
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                indicator_hash TEXT NOT NULL,
                host TEXT NOT NULL,
                category TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('unverified', 'approved', 'rejected')),
                created_at TEXT NOT NULL,
                reviewed_at TEXT,
                UNIQUE (indicator_hash, category)
            );
            CREATE INDEX IF NOT EXISTS reports_host_idx ON reports(host);
            """
        )


def hash_indicator(value: str) -> str:
    """Hash a supplied indicator so the original URL need not be persisted."""
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def replace_feed(
    db_path: str | Path,
    source: str,
    entries: Iterable[dict[str, str]],
    updated_at: str | None = None,
) -> int:
    rows = [(source, item["url_hash"], item["host"]) for item in entries]
    timestamp = updated_at or datetime.now(timezone.utc).isoformat()
    with _connection(db_path) as db:
        db.execute("DELETE FROM feed_entries WHERE source = ?", (source,))
        db.executemany(
            "INSERT INTO feed_entries(source, url_hash, host) VALUES (?, ?, ?)", rows
        )
        db.execute(
            """INSERT INTO feed_status(source, updated_at, entry_count, last_error)
               VALUES (?, ?, ?, NULL)
               ON CONFLICT(source) DO UPDATE SET
                 updated_at = excluded.updated_at,
                 entry_count = excluded.entry_count,
                 last_error = NULL""",
            (source, timestamp, len(rows)),
        )
    return len(rows)


def record_feed_error(db_path: str | Path, source: str, message: str) -> None:
    timestamp = datetime.now(timezone.utc).isoformat()
    with _connection(db_path) as db:
        db.execute(
            """INSERT INTO feed_status(source, updated_at, entry_count, last_error)
               VALUES (?, ?, 0, ?)
               ON CONFLICT(source) DO UPDATE SET last_error = excluded.last_error""",
            (source, timestamp, message[:300]),
        )


def lookup_feed_matches(db_path: str | Path, url_hash: str) -> list[dict]:
    with _connection(db_path) as db:
        rows = db.execute(
            "SELECT source, host FROM feed_entries WHERE url_hash = ? ORDER BY source",
            (url_hash,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_feed_status(db_path: str | Path) -> list[dict]:
    with _connection(db_path) as db:
        rows = db.execute(
            "SELECT source, updated_at, entry_count, last_error FROM feed_status ORDER BY source"
        ).fetchall()
    return [dict(row) for row in rows]


def create_report(
    db_path: str | Path, indicator_hash: str, host: str, category: str
) -> dict:
    report_id = hash_indicator(f"{indicator_hash}\0{category}")[:24]
    timestamp = datetime.now(timezone.utc).isoformat()
    with _connection(db_path) as db:
        db.execute(
            """INSERT OR IGNORE INTO reports
               (id, indicator_hash, host, category, state, created_at)
               VALUES (?, ?, ?, ?, 'unverified', ?)""",
            (report_id, indicator_hash, host, category, timestamp),
        )
        row = db.execute(
            "SELECT id, indicator_hash, host, category, state, created_at, reviewed_at FROM reports WHERE id = ?",
            (report_id,),
        ).fetchone()
    return dict(row)


def review_report(db_path: str | Path, report_id: str, decision: str) -> dict:
    if decision not in {"approve", "reject"}:
        raise ValueError("decision must be approve or reject")
    state = "approved" if decision == "approve" else "rejected"
    reviewed_at = datetime.now(timezone.utc).isoformat()
    with _connection(db_path) as db:
        db.execute(
            "UPDATE reports SET state = ?, reviewed_at = ? WHERE id = ?",
            (state, reviewed_at, report_id),
        )
        row = db.execute(
            "SELECT id, indicator_hash, host, category, state, created_at, reviewed_at FROM reports WHERE id = ?",
            (report_id,),
        ).fetchone()
    if row is None:
        raise KeyError(report_id)
    return dict(row)


def find_reports(db_path: str | Path, indicator_hash: str, host: str) -> list[dict]:
    with _connection(db_path) as db:
        rows = db.execute(
            """SELECT id, category, state, created_at FROM reports
               WHERE indicator_hash = ? AND state = 'approved'
               ORDER BY created_at DESC""",
            (indicator_hash,),
        ).fetchall()
    return [dict(row) for row in rows]


def list_reports(db_path: str | Path, state: str = "unverified") -> list[dict]:
    with _connection(db_path) as db:
        rows = db.execute(
            """SELECT id, indicator_hash, host, category, state, created_at, reviewed_at
               FROM reports WHERE state = ? ORDER BY created_at DESC""",
            (state,),
        ).fetchall()
    return [dict(row) for row in rows]
