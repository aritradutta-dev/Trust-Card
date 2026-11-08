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
            CREATE TABLE IF NOT EXISTS report_metadata (
                report_id TEXT PRIMARY KEY,
                report_count INTEGER NOT NULL DEFAULT 1,
                source TEXT NOT NULL DEFAULT 'local',
                FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
            );
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
    db_path: str | Path,
    indicator_hash: str,
    host: str,
    category: str,
    source: str = "local",
    auto_approve_threshold: int | None = None,
) -> dict:
    report_id = hash_indicator(f"{indicator_hash}\0{category}")[:24]
    timestamp = datetime.now(timezone.utc).isoformat()
    with _connection(db_path) as db:
        db.execute(
            """INSERT INTO reports
               (id, indicator_hash, host, category, state, created_at)
               VALUES (?, ?, ?, ?, 'unverified', ?)
               ON CONFLICT(indicator_hash, category) DO NOTHING
            """,
            (report_id, indicator_hash, host, category, timestamp),
        )
        db.execute(
            """INSERT INTO report_metadata
               (report_id, report_count, source)
               VALUES (?, 1, ?)
               ON CONFLICT(report_id) DO UPDATE SET
                 report_count = report_metadata.report_count + 1
            """,
            (report_id, source),
        )
        if auto_approve_threshold is not None and auto_approve_threshold > 0:
            db.execute(
                """UPDATE reports SET state = 'approved', reviewed_at = ?
                   WHERE id = ? AND state = 'unverified'
                     AND (SELECT report_count FROM report_metadata WHERE report_id = ?) >= ?""",
                (timestamp, report_id, report_id, auto_approve_threshold),
            )
        row = db.execute(
            """SELECT reports.id, reports.indicator_hash, reports.host, reports.category, reports.state,
                      COALESCE(report_metadata.report_count, 1) as report_count,
                      COALESCE(report_metadata.source, 'local') as source,
                      reports.created_at, reports.reviewed_at
               FROM reports
               LEFT JOIN report_metadata ON reports.id = report_metadata.report_id
               WHERE reports.id = ?""",
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
            """SELECT reports.id, reports.indicator_hash, reports.host, reports.category, reports.state,
                      COALESCE(report_metadata.report_count, 1) as report_count,
                      COALESCE(report_metadata.source, 'local') as source,
                      reports.created_at, reports.reviewed_at
               FROM reports
               LEFT JOIN report_metadata ON reports.id = report_metadata.report_id
               WHERE reports.id = ?""",
            (report_id,),
        ).fetchone()
    if row is None:
        raise KeyError(report_id)
    return dict(row)


def find_reports(db_path: str | Path, indicator_hash: str, host: str, include_unverified: bool = False) -> list[dict]:
    with _connection(db_path) as db:
        if include_unverified:
            rows = db.execute(
                """SELECT reports.id, reports.indicator_hash, reports.host, reports.category, reports.state,
                          COALESCE(report_metadata.report_count, 1) as report_count,
                          COALESCE(report_metadata.source, 'local') as source,
                          reports.created_at, reports.reviewed_at
                   FROM reports
                   LEFT JOIN report_metadata ON reports.id = report_metadata.report_id
                   WHERE reports.indicator_hash = ? AND reports.state IN ('approved', 'unverified')
                   ORDER BY reports.created_at DESC""",
                (indicator_hash,),
            ).fetchall()
        else:
            rows = db.execute(
                """SELECT reports.id, reports.indicator_hash, reports.host, reports.category, reports.state,
                          COALESCE(report_metadata.report_count, 1) as report_count,
                          COALESCE(report_metadata.source, 'local') as source,
                          reports.created_at, reports.reviewed_at
                   FROM reports
                   LEFT JOIN report_metadata ON reports.id = report_metadata.report_id
                   WHERE reports.indicator_hash = ? AND reports.state = 'approved'
                   ORDER BY reports.created_at DESC""",
                (indicator_hash,),
            ).fetchall()
    return [dict(row) for row in rows]


def get_host_approved_report_count(db_path: str | Path, host: str) -> int:
    with _connection(db_path) as db:
        row = db.execute(
            "SELECT COUNT(DISTINCT indicator_hash) as cnt FROM reports WHERE host = ? AND state = 'approved'",
            (host,),
        ).fetchone()
    return row["cnt"] if row else 0


def list_reports(db_path: str | Path, state: str = "unverified") -> list[dict]:
    with _connection(db_path) as db:
        if state == "all":
            rows = db.execute(
                """SELECT reports.id, reports.indicator_hash, reports.host, reports.category, reports.state,
                          COALESCE(report_metadata.report_count, 1) as report_count,
                          COALESCE(report_metadata.source, 'local') as source,
                          reports.created_at, reports.reviewed_at
                   FROM reports
                   LEFT JOIN report_metadata ON reports.id = report_metadata.report_id
                   ORDER BY reports.created_at DESC"""
            ).fetchall()
        else:
            rows = db.execute(
                """SELECT reports.id, reports.indicator_hash, reports.host, reports.category, reports.state,
                          COALESCE(report_metadata.report_count, 1) as report_count,
                          COALESCE(report_metadata.source, 'local') as source,
                          reports.created_at, reports.reviewed_at
                   FROM reports
                   LEFT JOIN report_metadata ON reports.id = report_metadata.report_id
                   WHERE reports.state = ?
                   ORDER BY reports.created_at DESC""",
                (state,),
            ).fetchall()
    return [dict(row) for row in rows]


def import_reports(
    db_path: str | Path,
    reports: list[dict],
    source: str = "peer",
) -> int:
    count = 0
    timestamp = datetime.now(timezone.utc).isoformat()
    with _connection(db_path) as db:
        for r in reports:
            ind_hash = r.get("indicator_fingerprint") or r.get("indicator_hash")
            host = r.get("host")
            category = r.get("category", "phishing")
            rep_count = int(r.get("report_count", 1))
            if not ind_hash or not host:
                continue
            report_id = hash_indicator(f"{ind_hash}\0{category}")[:24]
            db.execute(
                """INSERT INTO reports
                   (id, indicator_hash, host, category, state, created_at)
                   VALUES (?, ?, ?, ?, 'unverified', ?)
                   ON CONFLICT(indicator_hash, category) DO NOTHING
                """,
                (report_id, ind_hash, host, category, timestamp),
            )
            db.execute(
                """INSERT INTO report_metadata
                   (report_id, report_count, source)
                   VALUES (?, ?, ?)
                   ON CONFLICT(report_id) DO UPDATE SET
                     report_count = report_metadata.report_count + excluded.report_count,
                     source = excluded.source
                """,
                (report_id, rep_count, source),
            )
            count += 1
    return count
