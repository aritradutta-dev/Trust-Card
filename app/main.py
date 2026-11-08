"""FastAPI entry point for the local Trust Card application."""

from __future__ import annotations

import uuid
import base64
import hmac
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.feeds import refresh_feed
from app.scanner_client import configured_feed_fetcher, configured_scanner
from app.storage import create_report, find_reports, get_feed_status, init_db, list_reports, lookup_feed_matches, review_report
from app.urls import canonicalize_url, host_from_url, indicator_fingerprint, url_hash
from app.url_analysis import analyze_url
from app.verdict import decide_verdict

BASE_DIR = Path(__file__).parent
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
ContextFlag = Literal[
    "urgency",
    "credential_request",
    "payment_request",
    "personal_data_request",
]


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=8, max_length=2048)
    mode: Literal["local", "full_scan"]
    consent: bool = False
    ct_rdap_consent: bool = False
    context_flags: list[ContextFlag] = Field(default_factory=list, max_length=4)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return canonicalize_url(value)


class ReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_id: str = Field(min_length=32, max_length=32)
    category: Literal["phishing", "malware", "impersonation", "other"]


class FeedRefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    providers: list[Literal["PhishTank", "URLhaus", "OpenPhish"]] = Field(min_length=1, max_length=3)


class ReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["approve", "reject"]


def _feed_staleness(status_rows: list[dict]) -> tuple[bool, list[dict]]:
    now = datetime.now(timezone.utc)
    annotated = []
    default_sources = ("PhishTank", "URLhaus", "OpenPhish")
    if not status_rows:
        return True, [
            {"source": source, "updated_at": None, "entry_count": 0, "last_error": None, "stale": True, "available": False}
            for source in default_sources
        ]
    for row in status_rows:
        try:
            updated = datetime.fromisoformat(row["updated_at"])
            if updated.tzinfo is None:
                updated = updated.replace(tzinfo=timezone.utc)
            stale = (now - updated).total_seconds() > 24 * 60 * 60
        except (KeyError, TypeError, ValueError):
            stale = True
        stale = stale or bool(row.get("last_error"))
        annotated.append({**row, "stale": stale, "available": True})
    by_source = {row["source"]: row for row in annotated}
    for source in default_sources:
        by_source.setdefault(source, {
            "source": source, "updated_at": None, "entry_count": 0, "last_error": None, "stale": True, "available": False,
        })
    result_sources = [by_source[source] for source in default_sources]
    for row in annotated:
        if row["source"] not in default_sources and row not in result_sources:
            result_sources.append(row)
    loaded = [r for r in result_sources if r["available"] and r.get("entry_count", 0) > 0]
    overall_stale = not loaded or any(r["stale"] for r in loaded)
    return overall_stale, result_sources


def _next_steps(verdict: str) -> list[str]:
    if verdict == "known_threat":
        return ["Do not open the link or enter information.", "Use the organisation's official website or app instead."]
    if verdict == "suspicious":
        return ["Do not enter passwords, OTPs, payment details, or identity information.", "Open the organisation's official site directly to verify the request."]
    if verdict == "caution":
        return ["Technical problems were found. Be cautious and verify the site through an official channel.", "Do not enter sensitive information until the issue is resolved."]
    if verdict == "unable_to_check":
        return ["The scan could not complete. Treat the link cautiously and verify it through an official channel."]
    if verdict == "not_enough_info":
        return ["Nothing matched local data, but no live check has run and threat data is missing or stale.", "Run a live check or refresh threat feeds for a more complete result."]
    return ["No strong warning was found. This does not confirm that the link is legitimate.", "If the link claims to be from an organisation, visit its official site directly."]


def _context_findings(flags: list[str]) -> list[dict]:
    labels = {
        "urgency": ("low", "The message uses urgency or pressure language."),
        "credential_request": ("medium", "The message refers to passwords, OTPs, or other credentials."),
        "payment_request": ("medium", "The message refers to a payment, fee, deposit, or transfer."),
        "personal_data_request": ("medium", "The message refers to personal or identity information."),
    }
    return [
        {
            "id": f"context-{flag}",
            "category": "message_context",
            "severity": labels[flag][0],
            "summary": labels[flag][1],
            "source": "Message context (processed in this browser)",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "group": "message_context",
        }
        for flag in flags
    ]


def _local_result(db_path: Path, request: AnalyzeRequest) -> dict:
    host = host_from_url(request.url)
    feed_status = get_feed_status(db_path)
    stale, annotated_status = _feed_staleness(feed_status)
    matches = lookup_feed_matches(db_path, url_hash(request.url))
    reports = find_reports(db_path, indicator_fingerprint(request.url), host)
    findings = _context_findings(request.context_flags)
    findings.extend(analyze_url(request.url))

    for match in matches:
        source_display = (
            "Demo data, not real threat intelligence"
            if match["source"] == "Demo seed"
            else match["source"]
        )
        findings.append({
            "id": f"feed-{match['source']}",
            "category": "known_threat",
            "severity": "high",
            "summary": f"This exact URL appears in the {source_display} threat list.",
            "source": source_display,
            "observed_at": next((row["updated_at"] for row in feed_status if row["source"] == match["source"]), None),
            "group": "threat_intelligence",
            "confirmed": True,
        })
    for report in reports:
        findings.append({
            "id": f"report-{report['id']}",
            "category": "community_report",
            "severity": "high" if report["state"] == "approved" else "low",
            "summary": "A local reviewer confirmed a report for this link." if report["state"] == "approved" else "This link has an unverified local report.",
            "source": "Local community report",
            "observed_at": report["created_at"],
            "group": "community_report",
            "confirmed": report["state"] == "approved",
        })
    decision = decide_verdict(findings, scan_complete=True, feed_stale=stale, coverage="local_only")
    for finding in findings:
        finding.setdefault("explanation", finding.get("summary", ""))
    return {
        "scan_id": uuid.uuid4().hex,
        **decision,
        "coverage": "local_only",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
        "redirect_hosts": [],
        "feed_status": annotated_status,
        "feed_stale": stale,
        "next_steps": _next_steps(decision["verdict"]),
    }


def create_app(
    db_path: str | Path | None = None,
    scanner_call=None,
    feed_fetcher=None,
) -> FastAPI:
    configured_data_dir = Path(os.environ.get("DATA_DIR", str(DATA_DIR)))
    data_path = Path(db_path or configured_data_dir / "trust-card.sqlite3")
    init_db(data_path)
    app = FastAPI(title="Trust Card", docs_url=None, redoc_url=None)
    app.state.db_path = data_path
    app.state.scanner_call = scanner_call if scanner_call is not None else configured_scanner()
    app.state.feed_fetcher = feed_fetcher if feed_fetcher is not None else configured_feed_fetcher()
    app.state.scan_sessions = {}
    app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
    templates = Jinja2Templates(directory=BASE_DIR / "templates")

    @app.middleware("http")
    async def response_safety_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        return response

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        stale, feed_status = _feed_staleness(get_feed_status(data_path))
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={"request": request, "feed_status": feed_status, "feed_stale": stale},
        )

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/api/v1/intel/status")
    async def intel_status():
        stale, status = _feed_staleness(get_feed_status(data_path))
        return {"providers": status, "stale": stale}

    @app.post("/api/v1/intel/refresh")
    async def refresh_intelligence(payload: FeedRefreshRequest):
        if app.state.feed_fetcher is None:
            raise HTTPException(status_code=503, detail="scanner_unavailable")
        results = []
        for source in dict.fromkeys(payload.providers):
            try:
                count = await run_in_threadpool(refresh_feed, data_path, source, app.state.feed_fetcher)
                results.append({"source": source, "updated": True, "entry_count": count})
            except Exception:
                results.append({"source": source, "updated": False, "message": "Refresh failed; the last saved feed was kept."})
        stale, status = _feed_staleness(get_feed_status(data_path))
        return {"results": results, "providers": status, "stale": stale}

    def remember_scan(result: dict, url: str):
        now = time.time()
        sessions = app.state.scan_sessions
        for key, value in list(sessions.items()):
            if now - value["created_at"] > 3600:
                sessions.pop(key, None)
        sessions[result["scan_id"]] = {
            "indicator_hash": indicator_fingerprint(url),
            "host": host_from_url(url),
            "created_at": now,
        }

    @app.post("/api/v1/reports")
    async def submit_report(payload: ReportRequest):
        session = app.state.scan_sessions.pop(payload.scan_id, None)
        if session is None or time.time() - session["created_at"] > 3600:
            raise HTTPException(status_code=410, detail="scan_expired")
        report = await run_in_threadpool(
            create_report,
            data_path,
            session["indicator_hash"],
            session["host"],
            payload.category,
        )
        return {"state": report["state"], "message": "Thanks. This report is unverified until a local administrator reviews it."}

    @app.post("/api/v1/analyze")
    async def analyze(payload: AnalyzeRequest):
        if payload.mode == "full_scan" and not payload.consent:
            raise HTTPException(status_code=400, detail="consent_required")
        if payload.mode == "local":
            result = _local_result(data_path, payload)
            remember_scan(result, payload.url)
            return result

        if app.state.scanner_call is None:
            scan = {"complete": False, "findings": [], "redirect_hosts": [], "error": "scanner_unavailable"}
        else:
            try:
                import inspect
                scanner_fn = app.state.scanner_call
                try:
                    sig = inspect.signature(scanner_fn)
                    if "ct_rdap_consent" in sig.parameters:
                        scan = await run_in_threadpool(scanner_fn, payload.url, ct_rdap_consent=payload.ct_rdap_consent)
                    else:
                        scan = await run_in_threadpool(scanner_fn, payload.url)
                except Exception:
                    scan = await run_in_threadpool(scanner_fn, payload.url)
            except Exception:
                scan = {"complete": False, "findings": [], "redirect_hosts": [], "error": "scan_failed"}

        local = _local_result(data_path, payload)
        findings = local["findings"] + scan.get("findings", [])
        for finding in findings:
            finding.setdefault("explanation", finding.get("summary", ""))
        scan_coverage = scan.get("coverage", "full" if scan.get("complete") else "partial")
        if scan.get("error") == "scanner_unavailable":
            scan_coverage = "local_only"
        elif not scan.get("complete") and scan_coverage == "full":
            scan_coverage = "partial"
        coverage = scan_coverage
        if local["feed_stale"] and coverage == "full":
            coverage = "partial"
        decision = decide_verdict(
            findings,
            scan_complete=bool(scan.get("complete")),
            feed_stale=local["feed_stale"],
            live_scan_done=True,
            coverage=coverage,
        )
        result = {
            **local,
            **decision,
            "coverage": coverage,
            "scan_coverage": scan_coverage,
            "live_scan_complete": bool(scan.get("complete")),
            "findings": findings,
            "redirect_hosts": scan.get("redirect_hosts", []),
            "scan_error": scan.get("error"),
            "certificate": scan.get("certificate"),
            "next_steps": _next_steps(decision["verdict"]),
        }
        remember_scan(result, payload.url)
        return result

    def require_admin(request: Request):
        expected_password = os.environ.get("ADMIN_PASSWORD", "")
        expected_user = os.environ.get("ADMIN_USERNAME", "")
        if not expected_user or not expected_password:
            raise HTTPException(status_code=503, detail="admin_credentials_not_configured")
        authorization = request.headers.get("authorization", "")
        try:
            scheme, encoded = authorization.split(" ", 1)
            username, password = base64.b64decode(encoded, validate=True).decode("utf-8").split(":", 1)
        except (ValueError, UnicodeDecodeError):
            username, password, scheme = "", "", ""
        if scheme.lower() != "basic" or not hmac.compare_digest(username, expected_user) or not hmac.compare_digest(password, expected_password):
            raise HTTPException(status_code=401, detail="admin_auth_required", headers={"WWW-Authenticate": 'Basic realm="Trust Card reports"'})

    @app.get("/admin/reports", response_class=HTMLResponse)
    async def admin_reports(request: Request):
        require_admin(request)
        reports = await run_in_threadpool(list_reports, data_path, "unverified")
        return templates.TemplateResponse(request=request, name="reports.html", context={"request": request, "reports": reports})

    @app.get("/api/v1/admin/reports")
    async def admin_report_list(request: Request):
        require_admin(request)
        return {"reports": await run_in_threadpool(list_reports, data_path, "unverified")}

    @app.post("/api/v1/admin/reports/{report_id}/review")
    async def review_local_report(report_id: str, payload: ReviewRequest, request: Request):
        require_admin(request)
        try:
            report = await run_in_threadpool(review_report, data_path, report_id, payload.decision)
        except KeyError:
            raise HTTPException(status_code=404, detail="report_not_found")
        return {"id": report["id"], "state": report["state"], "reviewed_at": report["reviewed_at"]}

    return app


app = create_app()
