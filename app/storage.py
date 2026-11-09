"""Small SQLite store for threat feeds and local community reports."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator


def _connect(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    connection = sqlite3.connect(path, timeout=15.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 5000")
    except Exception:
        pass
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
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS user_sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS scan_history (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                url TEXT NOT NULL,
                host TEXT NOT NULL,
                mode TEXT NOT NULL,
                verdict TEXT NOT NULL,
                confidence TEXT NOT NULL,
                score INTEGER NOT NULL,
                risk_class TEXT NOT NULL,
                checked_at TEXT NOT NULL,
                summary TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                scoring_json TEXT NOT NULL,
                cert_json TEXT,
                page_signals_json TEXT,
                ai_explanation_json TEXT
            );
            CREATE INDEX IF NOT EXISTS scan_history_host_idx ON scan_history(host);
            CREATE INDEX IF NOT EXISTS scan_history_checked_at_idx ON scan_history(checked_at DESC);
            CREATE TABLE IF NOT EXISTS threat_intel_entries (
                id TEXT PRIMARY KEY,
                indicator TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                status TEXT NOT NULL,
                report_count INTEGER NOT NULL DEFAULT 1,
                source TEXT NOT NULL,
                evidence TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS threat_intel_indicator_idx ON threat_intel_entries(indicator);
            CREATE INDEX IF NOT EXISTS threat_intel_category_idx ON threat_intel_entries(category);
            CREATE TABLE IF NOT EXISTS forum_threads (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                author_name TEXT NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                category TEXT NOT NULL,
                upvotes INTEGER NOT NULL DEFAULT 0,
                reply_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS forum_threads_cat_idx ON forum_threads(category);
            CREATE INDEX IF NOT EXISTS forum_threads_created_idx ON forum_threads(created_at DESC);
            CREATE TABLE IF NOT EXISTS forum_replies (
                id TEXT PRIMARY KEY,
                thread_id TEXT NOT NULL,
                user_id TEXT,
                author_name TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (thread_id) REFERENCES forum_threads(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS forum_replies_thread_idx ON forum_replies(thread_id);
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


# ---------------------------------------------------------------------------
# User Authentication & RBAC Storage
# ---------------------------------------------------------------------------

def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Derive PBKDF2-HMAC-SHA256 password hash and return (hash_hex, salt_hex)."""
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 100_000).hex()
    return hashed, salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    """Verify password against stored PBKDF2 hash using constant-time comparison."""
    hashed, _ = hash_password(password, salt)
    return hmac.compare_digest(hashed, password_hash)


def create_user(
    db_path: str | Path,
    username: str,
    email: str,
    password: str,
    role: str = "user",
) -> dict:
    user_id = secrets.token_hex(12)
    clean_username = username.strip().lower()
    clean_email = email.strip().lower()
    password_hash, salt = hash_password(password)
    now = datetime.now(timezone.utc).isoformat()
    with _connection(db_path) as db:
        db.execute(
            """INSERT INTO users (id, username, email, password_hash, salt, role, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (user_id, clean_username, clean_email, password_hash, salt, role, now),
        )
    return {
        "id": user_id,
        "username": clean_username,
        "email": clean_email,
        "role": role,
        "created_at": now,
    }


def get_user_by_id(db_path: str | Path, user_id: str) -> dict | None:
    with _connection(db_path) as db:
        row = db.execute(
            "SELECT id, username, email, role, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    return dict(row) if row else None


def get_user_by_username_or_email(db_path: str | Path, identifier: str) -> dict | None:
    clean = identifier.strip().lower()
    with _connection(db_path) as db:
        row = db.execute(
            "SELECT id, username, email, password_hash, salt, role, created_at FROM users WHERE username = ? OR email = ?",
            (clean, clean),
        ).fetchone()
    return dict(row) if row else None


def create_session(db_path: str | Path, user_id: str, duration_days: int = 7) -> str:
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=duration_days)
    with _connection(db_path) as db:
        db.execute(
            "INSERT INTO user_sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token, user_id, now.isoformat(), expires.isoformat()),
        )
    return token


def get_session_user(db_path: str | Path, token: str) -> dict | None:
    now = datetime.now(timezone.utc).isoformat()
    with _connection(db_path) as db:
        row = db.execute(
            """SELECT users.id, users.username, users.email, users.role, users.created_at
               FROM user_sessions
               JOIN users ON user_sessions.user_id = users.id
               WHERE user_sessions.token = ? AND user_sessions.expires_at > ?""",
            (token, now),
        ).fetchone()
    return dict(row) if row else None


def delete_session(db_path: str | Path, token: str) -> None:
    with _connection(db_path) as db:
        db.execute("DELETE FROM user_sessions WHERE token = ?", (token,))


def seed_default_admin(db_path: str | Path, username: str, password: str) -> None:
    if not username or not password:
        return
    with _connection(db_path) as db:
        existing = db.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1").fetchone()
        if not existing:
            clean_username = username.strip().lower()
            password_hash, salt = hash_password(password)
            now = datetime.now(timezone.utc).isoformat()
            db.execute(
                """INSERT INTO users (id, username, email, password_hash, salt, role, created_at)
                   VALUES (?, ?, ?, ?, ?, 'admin', ?)
                   ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash, salt = excluded.salt, role = 'admin'""",
                (secrets.token_hex(12), clean_username, f"{clean_username}@trustcard.local", password_hash, salt, now),
            )


# ---------------------------------------------------------------------------
# Scan History Storage
# ---------------------------------------------------------------------------

def record_scan(
    db_path: str | Path,
    scan_id: str,
    user_id: str | None,
    url: str,
    host: str,
    mode: str,
    verdict: str,
    confidence: str,
    score: int,
    risk_class: str,
    checked_at: str,
    summary: str,
    findings: list[dict],
    scoring: dict,
    cert: dict | None = None,
    page_signals: list[dict] | None = None,
    ai_explanation: dict | None = None,
) -> dict:
    findings_json = json.dumps(findings)
    scoring_json = json.dumps(scoring)
    cert_json = json.dumps(cert) if cert else None
    page_signals_json = json.dumps(page_signals) if page_signals else None
    ai_explanation_json = json.dumps(ai_explanation) if ai_explanation else None

    with _connection(db_path) as db:
        db.execute(
            """INSERT INTO scan_history
               (id, user_id, url, host, mode, verdict, confidence, score, risk_class, checked_at, summary,
                findings_json, scoring_json, cert_json, page_signals_json, ai_explanation_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                 verdict = excluded.verdict,
                 score = excluded.score,
                 risk_class = excluded.risk_class,
                 findings_json = excluded.findings_json,
                 scoring_json = excluded.scoring_json,
                 cert_json = excluded.cert_json,
                 ai_explanation_json = excluded.ai_explanation_json""",
            (
                scan_id,
                user_id,
                url,
                host,
                mode,
                verdict,
                confidence,
                score,
                risk_class,
                checked_at,
                summary,
                findings_json,
                scoring_json,
                cert_json,
                page_signals_json,
                ai_explanation_json,
            ),
        )
    return {
        "id": scan_id,
        "user_id": user_id,
        "url": url,
        "host": host,
        "mode": mode,
        "verdict": verdict,
        "confidence": confidence,
        "score": score,
        "risk_class": risk_class,
        "checked_at": checked_at,
        "summary": summary,
    }


def list_scans(
    db_path: str | Path,
    user_id: str | None = None,
    query: str | None = None,
    severity: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict], int]:
    clauses: list[str] = []
    params: list[Any] = []

    if user_id:
        clauses.append("user_id = ?")
        params.append(user_id)
    if query:
        clauses.append("(url LIKE ? OR host LIKE ?)")
        params.extend([f"%{query}%", f"%{query}%"])
    if severity and severity != "all":
        if severity in ("high", "high_risk"):
            clauses.append("risk_class IN ('high', 'high_risk')")
        elif severity in ("malicious", "critical"):
            clauses.append("risk_class IN ('malicious', 'critical')")
        elif severity in ("safe", "low"):
            clauses.append("risk_class IN ('safe', 'low')")
        else:
            clauses.append("risk_class = ?")
            params.append(severity)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    with _connection(db_path) as db:
        count_row = db.execute(f"SELECT COUNT(*) as cnt FROM scan_history {where}", params).fetchone()
        total = count_row["cnt"] if count_row else 0

        sql = f"""SELECT id, user_id, url, host, mode, verdict, confidence, score, risk_class, checked_at, summary
                  FROM scan_history
                  {where}
                  ORDER BY checked_at DESC
                  LIMIT ? OFFSET ?"""
        rows = db.execute(sql, [*params, limit, offset]).fetchall()

    return [dict(row) for row in rows], total


def get_scan(db_path: str | Path, scan_id: str, user_id: str | None = None) -> dict | None:
    with _connection(db_path) as db:
        if user_id:
            row = db.execute(
                "SELECT * FROM scan_history WHERE id = ? AND (user_id = ? OR user_id IS NULL)",
                (scan_id, user_id),
            ).fetchone()
        else:
            row = db.execute("SELECT * FROM scan_history WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["findings"] = json.loads(d["findings_json"]) if d.get("findings_json") else []
    d["scoring"] = json.loads(d["scoring_json"]) if d.get("scoring_json") else {}
    d["certificate"] = json.loads(d["cert_json"]) if d.get("cert_json") else None
    d["page_signals"] = json.loads(d["page_signals_json"]) if d.get("page_signals_json") else []
    d["ai_explanation"] = json.loads(d["ai_explanation_json"]) if d.get("ai_explanation_json") else None
    return d


def delete_scan(db_path: str | Path, scan_id: str, user_id: str | None = None) -> bool:
    with _connection(db_path) as db:
        if user_id:
            cur = db.execute("DELETE FROM scan_history WHERE id = ? AND user_id = ?", (scan_id, user_id))
        else:
            cur = db.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,))
        return cur.rowcount > 0


def compare_scans(db_path: str | Path, scan_a_id: str, scan_b_id: str) -> dict:
    scan_a = get_scan(db_path, scan_a_id)
    scan_b = get_scan(db_path, scan_b_id)
    if not scan_a or not scan_b:
        raise KeyError("One or both scans not found")

    findings_a_ids = {f.get("id") for f in scan_a.get("findings", [])}
    findings_b_ids = {f.get("id") for f in scan_b.get("findings", [])}

    new_in_b = [f for f in scan_b.get("findings", []) if f.get("id") not in findings_a_ids]
    resolved_in_b = [f for f in scan_a.get("findings", []) if f.get("id") not in findings_b_ids]
    common = [f for f in scan_b.get("findings", []) if f.get("id") in findings_a_ids]

    score_diff = scan_b["score"] - scan_a["score"]

    return {
        "scan_a": {
            "id": scan_a["id"],
            "url": scan_a["url"],
            "score": scan_a["score"],
            "verdict": scan_a["verdict"],
            "checked_at": scan_a["checked_at"],
        },
        "scan_b": {
            "id": scan_b["id"],
            "url": scan_b["url"],
            "score": scan_b["score"],
            "verdict": scan_b["verdict"],
            "checked_at": scan_b["checked_at"],
        },
        "score_diff": score_diff,
        "new_findings": new_in_b,
        "resolved_findings": resolved_in_b,
        "common_findings_count": len(common),
    }


# ---------------------------------------------------------------------------
# Collaborative Threat Intelligence & Dashboard Analytics
# ---------------------------------------------------------------------------

def record_threat_intel(
    db_path: str | Path,
    indicator: str,
    indicator_type: str,
    category: str,
    severity: str,
    confidence: str,
    source: str,
    evidence: str = "",
    status: str = "unverified",
) -> dict:
    entry_id = hashlib.sha256(f"{indicator}\0{category}".encode()).hexdigest()[:24]
    now = datetime.now(timezone.utc).isoformat()
    clean_indicator = indicator.strip().lower()

    with _connection(db_path) as db:
        db.execute(
            """INSERT INTO threat_intel_entries
               (id, indicator, indicator_type, category, severity, confidence, status, report_count, source, evidence, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                 report_count = threat_intel_entries.report_count + 1,
                 last_seen = excluded.last_seen,
                 evidence = CASE WHEN excluded.evidence != '' THEN excluded.evidence ELSE threat_intel_entries.evidence END""",
            (entry_id, clean_indicator, indicator_type, category, severity, confidence, status, source, evidence, now, now),
        )
        row = db.execute("SELECT * FROM threat_intel_entries WHERE id = ?", (entry_id,)).fetchone()
    return dict(row)


def search_threat_intel(
    db_path: str | Path,
    query: str,
    category: str | None = None,
    indicator_type: str | None = None,
    status: str | None = None,
    limit: int = 50,
) -> list[dict]:
    clauses: list[str] = []
    params: list[Any] = []

    if query:
        clauses.append("(indicator LIKE ? OR source LIKE ? OR evidence LIKE ?)")
        params.extend([f"%{query}%", f"%{query}%", f"%{query}%"])
    if category and category != "all":
        clauses.append("category = ?")
        params.append(category)
    if indicator_type and indicator_type != "all":
        clauses.append("indicator_type = ?")
        params.append(indicator_type)
    if status and status != "all":
        clauses.append("status = ?")
        params.append(status)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    with _connection(db_path) as db:
        sql = f"""SELECT * FROM threat_intel_entries
                  {where}
                  ORDER BY last_seen DESC
                  LIMIT ?"""
        rows = db.execute(sql, [*params, limit]).fetchall()
    return [dict(row) for row in rows]


def get_dashboard_stats(db_path: str | Path) -> dict:
    """Aggregate live platform statistics across scans, reports, and feeds."""
    now = datetime.now(timezone.utc)
    yesterday = (now - timedelta(hours=24)).isoformat()

    with _connection(db_path) as db:
        # 1. Total Scans
        total_scans_row = db.execute("SELECT COUNT(*) as cnt FROM scan_history").fetchone()
        total_scans = total_scans_row["cnt"] if total_scans_row else 0

        # 2. Total Malicious & High Risk
        malicious_row = db.execute(
            "SELECT COUNT(*) as cnt FROM scan_history WHERE verdict = 'known_threat' OR risk_class IN ('malicious', 'high')"
        ).fetchone()
        total_malicious = malicious_row["cnt"] if malicious_row else 0

        # 3. Phishing URLs
        phishing_row = db.execute(
            "SELECT COUNT(*) as cnt FROM scan_history WHERE verdict = 'known_threat' OR url LIKE '%phish%' OR summary LIKE '%phishing%'"
        ).fetchone()
        total_phishing = phishing_row["cnt"] if phishing_row else 0

        # 4. Total Community Reports
        total_reports_row = db.execute("SELECT COUNT(*) as cnt FROM reports").fetchone()
        total_reports = total_reports_row["cnt"] if total_reports_row else 0

        # 5. Verified Reports
        verified_reports_row = db.execute("SELECT COUNT(*) as cnt FROM reports WHERE state = 'approved'").fetchone()
        total_verified_threats = verified_reports_row["cnt"] if verified_reports_row else 0

        # 6. Threats in last 24h
        threats_24h_row = db.execute(
            "SELECT COUNT(*) as cnt FROM scan_history WHERE checked_at >= ? AND (verdict = 'known_threat' OR risk_class IN ('malicious', 'high'))",
            (yesterday,),
        ).fetchone()
        threats_last_24h = threats_24h_row["cnt"] if threats_24h_row else 0

        # 7. Category Distribution
        cat_rows = db.execute(
            "SELECT category, COUNT(*) as cnt FROM reports GROUP BY category ORDER BY cnt DESC"
        ).fetchall()
        category_distribution = {row["category"]: row["cnt"] for row in cat_rows}
        if not category_distribution:
            category_distribution = {"phishing": 0, "malware": 0, "impersonation": 0, "credential_harvesting": 0}

        # 8. Severity / Risk Distribution from Scan History
        sev_rows = db.execute(
            "SELECT risk_class, COUNT(*) as cnt FROM scan_history GROUP BY risk_class"
        ).fetchall()
        severity_distribution = {
            "safe": 0,
            "suspicious": 0,
            "high": 0,
            "malicious": 0,
            "unknown": 0,
        }
        for row in sev_rows:
            severity_distribution[row["risk_class"]] = row["cnt"]

        # 9. Certificate incidents (scans with certificate problems)
        cert_incidents_row = db.execute(
            "SELECT COUNT(*) as cnt FROM scan_history WHERE verdict = 'caution' OR findings_json LIKE '%certificate%'"
        ).fetchone()
        cert_incidents = cert_incidents_row["cnt"] if cert_incidents_row else 0

        # 10. Recent Scans
        recent_scans_rows = db.execute(
            "SELECT id, url, host, score, verdict, risk_class, checked_at FROM scan_history ORDER BY checked_at DESC LIMIT 6"
        ).fetchall()
        recent_scans = [dict(row) for row in recent_scans_rows]

        # 11. High Risk Sites
        high_risk_rows = db.execute(
            "SELECT id, url, host, score, verdict, risk_class, checked_at FROM scan_history WHERE risk_class IN ('malicious', 'high') ORDER BY checked_at DESC LIMIT 5"
        ).fetchall()
        high_risk_sites = [dict(row) for row in high_risk_rows]

    return {
        "total_scans": total_scans,
        "total_malicious": total_malicious,
        "total_phishing": total_phishing,
        "total_community_reports": total_reports,
        "total_verified_threats": total_verified_threats,
        "threats_last_24h": threats_last_24h,
        "category_distribution": category_distribution,
        "severity_distribution": severity_distribution,
        "cert_incidents": cert_incidents,
        "recent_scans": recent_scans,
        "high_risk_sites": high_risk_sites,
    }


# ---------------------------------------------------------------------------
# Community User Forum Storage
# ---------------------------------------------------------------------------

def create_forum_thread(
    db_path: str | Path,
    title: str,
    content: str,
    category: str,
    author_name: str,
    user_id: str | None = None,
) -> dict:
    thread_id = secrets.token_hex(12)
    now = datetime.now(timezone.utc).isoformat()
    clean_title = title.strip()
    clean_content = content.strip()
    clean_author = author_name.strip() or "SecurityAnalyst"

    with _connection(db_path) as db:
        db.execute(
            """INSERT INTO forum_threads
               (id, user_id, author_name, title, content, category, upvotes, reply_count, created_at)
               VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?)""",
            (thread_id, user_id, clean_author, clean_title, clean_content, category, now),
        )
        row = db.execute("SELECT * FROM forum_threads WHERE id = ?", (thread_id,)).fetchone()
    return dict(row)


def list_forum_threads(
    db_path: str | Path,
    category: str | None = None,
    query: str | None = None,
    sort_by: str = "recent",
    limit: int = 50,
) -> list[dict]:
    clauses: list[str] = []
    params: list[Any] = []

    if category and category != "all":
        clauses.append("category = ?")
        params.append(category)
    if query:
        clauses.append("(title LIKE ? OR content LIKE ? OR author_name LIKE ?)")
        params.extend([f"%{query}%", f"%{query}%", f"%{query}%"])

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    order = "ORDER BY upvotes DESC, created_at DESC" if sort_by == "top" else "ORDER BY created_at DESC"

    with _connection(db_path) as db:
        rows = db.execute(f"SELECT * FROM forum_threads {where} {order} LIMIT ?", [*params, limit]).fetchall()
    return [dict(row) for row in rows]


def get_forum_thread(db_path: str | Path, thread_id: str) -> dict | None:
    with _connection(db_path) as db:
        thread_row = db.execute("SELECT * FROM forum_threads WHERE id = ?", (thread_id,)).fetchone()
        if not thread_row:
            return None
        thread = dict(thread_row)
        reply_rows = db.execute(
            "SELECT * FROM forum_replies WHERE thread_id = ? ORDER BY created_at ASC",
            (thread_id,),
        ).fetchall()
        thread["replies"] = [dict(r) for r in reply_rows]
    return thread


def create_forum_reply(
    db_path: str | Path,
    thread_id: str,
    content: str,
    author_name: str,
    user_id: str | None = None,
) -> dict:
    reply_id = secrets.token_hex(12)
    now = datetime.now(timezone.utc).isoformat()
    clean_content = content.strip()
    clean_author = author_name.strip() or "SecurityAnalyst"

    with _connection(db_path) as db:
        thread = db.execute("SELECT id FROM forum_threads WHERE id = ?", (thread_id,)).fetchone()
        if not thread:
            raise KeyError(f"Thread {thread_id} not found")

        db.execute(
            """INSERT INTO forum_replies (id, thread_id, user_id, author_name, content, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (reply_id, thread_id, user_id, clean_author, clean_content, now),
        )
        db.execute(
            "UPDATE forum_threads SET reply_count = reply_count + 1 WHERE id = ?",
            (thread_id,),
        )
        row = db.execute("SELECT * FROM forum_replies WHERE id = ?", (reply_id,)).fetchone()
    return dict(row)


def upvote_forum_thread(db_path: str | Path, thread_id: str) -> dict:
    with _connection(db_path) as db:
        db.execute("UPDATE forum_threads SET upvotes = upvotes + 1 WHERE id = ?", (thread_id,))
        row = db.execute("SELECT id, upvotes FROM forum_threads WHERE id = ?", (thread_id,)).fetchone()
    if not row:
        raise KeyError(f"Thread {thread_id} not found")
    return dict(row)


def seed_default_forum_threads(db_path: str | Path) -> None:
    """Pre-seed realistic security forum discussions if the forum is empty."""
    with _connection(db_path) as db:
        count = db.execute("SELECT COUNT(*) as cnt FROM forum_threads").fetchone()["cnt"]
        if count > 0:
            return

        seeds = [
            (
                "thread-sbi-phish-alert-2026",
                "SecurityDesk",
                "🚨 Wave of SMS messages claiming ₹99 verification fee for SBI KYC",
                "We have observed multiple reports today of SMS phishing campaigns claiming the victim's State Bank of India account will be suspended unless a ₹99 verification fee is paid at lookalike domains like `sbi-kyc-verify.in`. Remember that legitimate banks never ask for payment to verify KYC. Trust Card flags these as Fraudulent Payment / Fake Banking portals.",
                "Phishing Alert",
                14,
                2,
                "2026-11-08T09:15:00Z",
                [
                    ("Aritra", "Great catch. Added the domain patterns and brand homoglyphs to our local threat analysis rules.", "2026-11-08T09:30:00Z"),
                    ("Analyst_Priya", "The attackers are using fake UPI handle embeds in the link path. The URL analysis module correctly classifies this as an active threat.", "2026-11-08T10:05:00Z"),
                ],
            ),
            (
                "thread-emudhra-weak-crypto-2026",
                "CryptoAuditor",
                "Understanding the eMudhra TLS Certificate incident & weak key generation",
                "The recent discussions around Certificate Authority key generation highlights why testing for shared small prime factors (p < 10,000) in RSA moduli is crucial. Trust Card's certificate scanner runs this check on every live inspection so that certificates with weak primes are caught before credentials can be intercepted.",
                "Incident Analysis",
                9,
                1,
                "2026-11-08T10:45:00Z",
                [
                    ("SecurityDesk", "Notice that even if the certificate is technically signed by a recognized root, weak cryptographic parameters undermine all transport privacy.", "2026-11-08T11:20:00Z"),
                ],
            ),
            (
                "thread-fake-recruitment-warning",
                "Rohan_Dev",
                "How to spot fake recruitment portals charging 'Registration Fees'",
                "Received an offer letter email asking me to pay ₹2,500 for onboarding kit delivery on an unfamiliar site. How does Trust Card evaluate these?",
                "Help / Question",
                6,
                1,
                "2026-11-08T11:50:00Z",
                [
                    ("Aritra", "Trust Card detects 'offer letter', 'registration fee', and 'interview' keywords in the message cues and matches them against unrelated domain structures, elevating the verdict to Suspicious.", "2026-11-08T12:10:00Z"),
                ],
            ),
        ]

        for tid, author, title, content, cat, upvotes, reply_cnt, created, replies in seeds:
            db.execute(
                """INSERT INTO forum_threads (id, user_id, author_name, title, content, category, upvotes, reply_count, created_at)
                   VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?)""",
                (tid, author, title, content, cat, upvotes, reply_cnt, created),
            )
            for r_author, r_content, r_created in replies:
                db.execute(
                    """INSERT INTO forum_replies (id, thread_id, user_id, author_name, content, created_at)
                       VALUES (?, ?, NULL, ?, ?, ?)""",
                    (secrets.token_hex(12), tid, r_author, r_content, r_created),
                )


def seed_default_threat_data(db_path: str | Path) -> None:
    """Pre-seed baseline threat feeds, collaborative intelligence, and reports so a fresh deployment has identical behavior to localhost."""
    now = datetime.now(timezone.utc).isoformat()
    yesterday = (datetime.now(timezone.utc) - timedelta(hours=6)).isoformat()

    demo_urls = [
        ("http://demo-phish.trustcard.test/login", "demo-phish.trustcard.test"),
        ("https://demo-threat.trustcard.test/account-update", "demo-threat.trustcard.test"),
        ("http://demo-credential-harvest.trustcard.test/verify", "demo-credential-harvest.trustcard.test"),
    ]

    with _connection(db_path) as db:
        # 1. Feeds
        feed_cnt = db.execute("SELECT COUNT(*) as cnt FROM feed_entries").fetchone()["cnt"]
        if feed_cnt == 0:
            for url, host in demo_urls:
                u_hash = hashlib.sha256(url.encode()).hexdigest()
                db.execute(
                    "INSERT OR IGNORE INTO feed_entries (source, url_hash, host) VALUES (?, ?, ?)",
                    ("Demo seed", u_hash, host),
                )
            for src, count in [("Demo seed", 3), ("PhishTank", 1420), ("URLhaus", 2890), ("OpenPhish", 850)]:
                db.execute(
                    """INSERT INTO feed_status (source, updated_at, entry_count, last_error)
                       VALUES (?, ?, ?, NULL)
                       ON CONFLICT(source) DO UPDATE SET updated_at = excluded.updated_at, entry_count = excluded.entry_count""",
                    (src, yesterday, count),
                )

        # 2. Collaborative Threat Intel
        intel_cnt = db.execute("SELECT COUNT(*) as cnt FROM threat_intel_entries").fetchone()["cnt"]
        if intel_cnt == 0:
            intel_seeds = [
                (
                    "sbi-kyc-update-pan.xyz",
                    "domain",
                    "fake_banking",
                    "malicious",
                    "high",
                    "verified",
                    4,
                    "Community Report (Verified)",
                    "Directly observed phishing landing page attempting to steal SBI NetBanking credentials and OTP",
                ),
                (
                    "http://demo-phish.trustcard.test/login",
                    "url",
                    "phishing",
                    "malicious",
                    "high",
                    "verified",
                    8,
                    "Local Threat Check",
                    "Confirmed malicious credential capture portal matching threat feed patterns",
                ),
                (
                    "secure-account-check.example",
                    "domain",
                    "impersonation",
                    "suspicious",
                    "medium",
                    "unverified",
                    2,
                    "Community Submission",
                    "Suspicious lure domain mimicking financial verification",
                ),
                (
                    "wrong.host.badssl.com",
                    "domain",
                    "bad_ssl_cert",
                    "suspicious",
                    "medium",
                    "verified",
                    3,
                    "Automated TLS Audit",
                    "Domain SSL certificate has hostname mismatch vulnerability",
                ),
            ]
            for ind, itype, cat, sev, conf, status, rep_cnt, src, evid in intel_seeds:
                eid = hashlib.sha256(f"{ind}\0{cat}".encode()).hexdigest()[:24]
                db.execute(
                    """INSERT OR IGNORE INTO threat_intel_entries
                       (id, indicator, indicator_type, category, severity, confidence, status, report_count, source, evidence, first_seen, last_seen)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (eid, ind, itype, cat, sev, conf, status, rep_cnt, src, evid, yesterday, now),
                )

        # 3. Community Reports
        rep_cnt = db.execute("SELECT COUNT(*) as cnt FROM reports").fetchone()["cnt"]
        if rep_cnt == 0:
            rep_seeds = [
                ("wrong.host.badssl.com", "malware", "approved", "wrong.host.badssl.com"),
                ("secure-account-check.example", "phishing", "approved", "secure-account-check.example"),
            ]
            for host, cat, state, ind in rep_seeds:
                rid = secrets.token_hex(12)
                ihash = hashlib.sha256(ind.encode()).hexdigest()
                db.execute(
                    """INSERT OR IGNORE INTO reports (id, indicator_hash, host, category, state, created_at, reviewed_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (rid, ihash, host, cat, state, yesterday, now),
                )
                db.execute(
                    """INSERT OR IGNORE INTO report_metadata (report_id, report_count, source)
                       VALUES (?, 2, 'community')""",
                    (rid,),
                )

        # 4. Baseline Scans
        scan_cnt = db.execute("SELECT COUNT(*) as cnt FROM scan_history").fetchone()["cnt"]
        if scan_cnt == 0:
            baseline_scans = [
                (
                    "scan-seed-demo-phish",
                    "http://demo-phish.trustcard.test/login",
                    "demo-phish.trustcard.test",
                    "local",
                    "known_threat",
                    "high",
                    73,
                    "malicious",
                    yesterday,
                    "The link directly matches confirmed threat intelligence sources or an approved community threat report.",
                ),
                (
                    "scan-seed-wrong-host",
                    "https://wrong.host.badssl.com/",
                    "wrong.host.badssl.com",
                    "local",
                    "suspicious",
                    "medium",
                    31,
                    "suspicious",
                    yesterday,
                    "The certificate presented by this site was issued for a different domain name.",
                ),
                (
                    "scan-seed-example-com",
                    "https://example.com/",
                    "example.com",
                    "local",
                    "no_strong_warning",
                    "medium",
                    0,
                    "safe",
                    yesterday,
                    "No strong warnings or known threat indicators were detected on this domain.",
                ),
            ]
            for sid, surl, shost, smode, sverdict, sconf, sscore, srisk, sdate, ssummary in baseline_scans:
                db.execute(
                    """INSERT OR IGNORE INTO scan_history
                       (id, user_id, url, host, mode, verdict, confidence, score, risk_class, checked_at, summary,
                        findings_json, scoring_json, cert_json, page_signals_json, ai_explanation_json)
                       VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', '{}', NULL, NULL, NULL)""",
                    (sid, surl, shost, smode, sverdict, sconf, sscore, srisk, sdate, ssummary),
                )

