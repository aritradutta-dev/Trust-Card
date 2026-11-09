"""FastAPI entry point for the local Trust Card application."""

from __future__ import annotations

import uuid
import base64
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request, Response
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.feeds import refresh_feed
from app.scanner_client import configured_feed_fetcher, configured_scanner
from app.storage import (
    compare_scans,
    create_forum_reply,
    create_forum_thread,
    create_report,
    create_session,
    create_user,
    delete_scan,
    delete_session,
    find_reports,
    get_dashboard_stats,
    get_feed_status,
    get_forum_thread,
    get_host_approved_report_count,
    get_scan,
    get_session_user,
    get_user_by_id,
    get_user_by_username_or_email,
    import_reports,
    init_db,
    list_forum_threads,
    list_reports,
    list_scans,
    lookup_feed_matches,
    record_scan,
    record_threat_intel,
    review_report,
    search_threat_intel,
    seed_default_admin,
    seed_default_forum_threads,
    seed_default_threat_data,
    upvote_forum_thread,
    verify_password,
)
from app.urls import canonicalize_url, host_from_url, indicator_fingerprint, url_hash
from app.url_analysis import analyze_url, detect_target_category
from app.verdict import decide_verdict
from app.scoring import calculate_risk_scoring
from app.ai_explainer import classify_risk, generate_security_explanation
from app.ct_service import lookup_domain_dns, search_certificate_transparency

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
    category: Literal[
        "phishing",
        "malware",
        "impersonation",
        "fake_banking",
        "fake_recruitment",
        "fraudulent_payment",
        "other",
    ]
    description: str = Field(default="", max_length=1000)
    evidence: str = Field(default="", max_length=1000)


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=50)
    email: str = Field(min_length=5, max_length=100)
    password: str = Field(min_length=6, max_length=100)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=100)


class ThreadCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=3, max_length=200)
    content: str = Field(min_length=5, max_length=5000)
    category: str = Field(default="General Discussion", max_length=50)
    author_name: str = Field(default="", max_length=50)


class ThreadReplyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    content: str = Field(min_length=2, max_length=3000)
    author_name: str = Field(default="", max_length=50)


class IntelSubmitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    indicator: str = Field(min_length=3, max_length=500)
    indicator_type: Literal["url", "domain", "ip", "cert_fingerprint"] = "domain"
    category: str = Field(default="phishing", max_length=50)
    severity: Literal["low", "suspicious", "high", "malicious"] = "suspicious"
    evidence: str = Field(default="", max_length=1000)


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
    reports = find_reports(db_path, indicator_fingerprint(request.url), host, include_unverified=True)
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
        is_approved = report["state"] == "approved"
        rep_count = report.get("report_count", 1)
        source_display = report.get("source", "Local community report")
        if source_display == "local":
            source_display = "Local community report"
        if is_approved:
            findings.append({
                "id": f"report-{report['id']}",
                "category": "community_report",
                "severity": "high",
                "summary": "A local reviewer confirmed a report for this link.",
                "source": source_display,
                "observed_at": report["created_at"],
                "group": "community_report",
                "confirmed": True,
            })
        else:
            findings.append({
                "id": f"report-{report['id']}",
                "category": "unverified_report",
                "severity": "low",
                "summary": f"Reported {rep_count} times locally, awaiting review",
                "source": source_display,
                "observed_at": report["created_at"],
                "group": "community_report",
                "confirmed": False,
            })

    host_approved_count = get_host_approved_report_count(db_path, host)
    if host_approved_count >= 2 and not any(r["state"] == "approved" for r in reports):
        findings.append({
            "id": f"host-reputation-{host}",
            "category": "community_report",
            "severity": "medium",
            "summary": "Multiple verified reports on this host",
            "source": "Local community intelligence",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "group": "community_report",
            "confirmed": False,
        })
    decision = decide_verdict(findings, scan_complete=True, feed_stale=stale, coverage="local_only")
    for finding in findings:
        finding.setdefault("explanation", finding.get("summary", ""))
    scoring = calculate_risk_scoring(
        findings,
        live_scan_done=False,
        has_message_context=bool(request.context_flags),
        feed_available=not stale,
    )
    risk_info = classify_risk(scoring["score"], decision["verdict"], checked_count=scoring["checked_count"])
    target_category = detect_target_category(request.url, findings)
    ai_exp = generate_security_explanation(
        url=request.url,
        verdict=decision["verdict"],
        confidence=decision["confidence"],
        score=scoring["score"],
        risk_class=risk_info["key"],
        findings=findings,
        pillars=scoring.get("pillars", {}),
        certificate=None,
        mode="local",
    )
    return {
        "scan_id": uuid.uuid4().hex,
        **decision,
        "scoring": scoring,
        "risk_classification": risk_info,
        "target_category": target_category,
        "ai_explanation": ai_exp,
        "coverage": "local_only",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
        "redirect_hosts": [],
        "feed_status": annotated_status,
        "feed_stale": stale,
        "next_steps": _next_steps(decision["verdict"]),
    }


def _resolve_data_dir() -> Path:
    env_dir = os.environ.get("DATA_DIR")
    candidates = [Path(env_dir)] if env_dir else []
    candidates.extend([DATA_DIR, Path.cwd() / "data", Path("/tmp/trustcard_data")])
    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            test_file = candidate / ".tc_write_test"
            test_file.touch()
            test_file.unlink(missing_ok=True)
            return candidate
        except Exception:
            continue
    return DATA_DIR


def create_app(
    db_path: str | Path | None = None,
    scanner_call=None,
    feed_fetcher=None,
) -> FastAPI:
    configured_data_dir = _resolve_data_dir()
    data_path = Path(db_path or configured_data_dir / "trust-card.sqlite3")
    init_db(data_path)
    admin_user = os.environ.get("ADMIN_USERNAME", "AD")
    admin_pass = os.environ.get("ADMIN_PASSWORD", "Aritra@1234")
    seed_default_admin(data_path, admin_user, admin_pass)
    seed_default_forum_threads(data_path)
    should_seed = bool(
        os.environ.get("VERCEL")
        or os.environ.get("RENDER")
        or os.environ.get("RAILWAY_ENVIRONMENT")
        or os.environ.get("FLY_ALLOC_ID")
        or os.environ.get("PORT")
        or os.environ.get("SEED_DEMO") == "1"
    ) and not os.environ.get("TESTING")
    if should_seed:
        seed_default_threat_data(data_path)

    app = FastAPI(title="Trust Card", docs_url=None, redoc_url=None)
    app.state.db_path = data_path
    app.state.scanner_call = scanner_call if scanner_call is not None else configured_scanner()
    app.state.feed_fetcher = feed_fetcher if feed_fetcher is not None else configured_feed_fetcher()
    app.state.scan_sessions = {}
    app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
    templates = Jinja2Templates(directory=BASE_DIR / "templates")

    def _get_user(req: Request) -> dict | None:
        token = req.cookies.get("trustcard_session")
        if not token:
            auth = req.headers.get("authorization", "")
            if auth.lower().startswith("bearer "):
                token = auth[7:].strip()
        if not token:
            return None
        return get_session_user(data_path, token)

    @app.middleware("http")
    async def response_safety_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'; "
            "form-action 'self' https://mail.google.com"
        )
        return response

    @app.exception_handler(StarletteHTTPException)
    async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
        if exc.status_code == 404:
            if request.url.path.startswith("/api/"):
                return Response(
                    content=json.dumps({"detail": exc.detail}),
                    status_code=404,
                    media_type="application/json",
                )
            return templates.TemplateResponse(
                request=request,
                name="404.html",
                context={"request": request},
                status_code=404,
            )
        headers = dict(exc.headers) if exc.headers else None
        return Response(
            content=json.dumps({"detail": exc.detail}),
            status_code=exc.status_code,
            media_type="application/json",
            headers=headers,
        )

    @app.exception_handler(Exception)
    async def custom_general_exception_handler(request: Request, exc: Exception):
        import traceback
        traceback.print_exc()
        msg = str(exc) or "Internal server error occurred."
        return Response(
            content=json.dumps({"detail": msg}),
            status_code=500,
            media_type="application/json",
        )

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        return Response(status_code=302, headers={"Location": "/static/favicon.ico"})

    @app.get("/api", response_class=HTMLResponse)
    async def api_docs(request: Request):
        return templates.TemplateResponse(request=request, name="api.html", context={"request": request})

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
        threshold_val = os.environ.get("REPORT_AUTO_APPROVE_THRESHOLD")
        auto_threshold = int(threshold_val) if threshold_val and threshold_val.isdigit() else None
        report = await run_in_threadpool(
            create_report,
            data_path,
            session["indicator_hash"],
            session["host"],
            payload.category,
            source="local",
            auto_approve_threshold=auto_threshold,
        )
        message = (
            "This report was automatically approved based on repeated independent reports."
            if report["state"] == "approved"
            else "Thanks. This report is unverified until a local administrator reviews it."
        )
        return {
            "state": report["state"],
            "message": message,
            "report_count": report.get("report_count", 1),
        }

    @app.post("/api/v1/analyze")
    async def analyze(payload: AnalyzeRequest, request: Request):
        if payload.mode == "full_scan" and not payload.consent:
            raise HTTPException(status_code=400, detail="consent_required")
        if payload.mode == "local":
            result = _local_result(data_path, payload)
            remember_scan(result, payload.url)
            user = _get_user(request)
            await run_in_threadpool(
                record_scan,
                data_path,
                scan_id=result["scan_id"],
                user_id=user["id"] if user else None,
                url=payload.url,
                host=host_from_url(payload.url),
                mode="local",
                verdict=result["verdict"],
                confidence=result["confidence"],
                score=result["scoring"]["score"],
                risk_class=result["risk_classification"]["key"],
                checked_at=result["checked_at"],
                summary=result["ai_explanation"]["summary"],
                findings=result["findings"],
                scoring=result["scoring"],
                cert=None,
                page_signals=None,
                ai_explanation=result["ai_explanation"],
            )
            if result["verdict"] in ("known_threat", "suspicious"):
                await run_in_threadpool(
                    record_threat_intel,
                    data_path,
                    indicator=payload.url,
                    indicator_type="url",
                    category=result["target_category"],
                    severity=result["risk_classification"]["key"],
                    confidence=result["confidence"],
                    source="Local Threat Check",
                    evidence=result["ai_explanation"]["summary"],
                    status="verified" if result["verdict"] == "known_threat" else "unverified",
                )
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
        scoring = calculate_risk_scoring(
            findings,
            live_scan_done=bool(scan.get("complete")),
            has_message_context=bool(payload.context_flags),
            feed_available=not local["feed_stale"],
        )
        risk_info = classify_risk(scoring["score"], decision["verdict"], checked_count=scoring["checked_count"])
        target_category = detect_target_category(payload.url, findings)
        ai_exp = generate_security_explanation(
            url=payload.url,
            verdict=decision["verdict"],
            confidence=decision["confidence"],
            score=scoring["score"],
            risk_class=risk_info["key"],
            findings=findings,
            pillars=scoring.get("pillars", {}),
            certificate=scan.get("certificate"),
            mode="full_scan",
        )
        result = {
            **local,
            **decision,
            "scoring": scoring,
            "risk_classification": risk_info,
            "target_category": target_category,
            "ai_explanation": ai_exp,
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
        user = _get_user(request)
        await run_in_threadpool(
            record_scan,
            data_path,
            scan_id=result["scan_id"],
            user_id=user["id"] if user else None,
            url=payload.url,
            host=host_from_url(payload.url),
            mode="full_scan",
            verdict=decision["verdict"],
            confidence=decision["confidence"],
            score=scoring["score"],
            risk_class=risk_info["key"],
            checked_at=result["checked_at"],
            summary=ai_exp["summary"],
            findings=findings,
            scoring=scoring,
            cert=scan.get("certificate"),
            page_signals=scan.get("findings"),
            ai_explanation=ai_exp,
        )
        if decision["verdict"] in ("known_threat", "suspicious"):
            await run_in_threadpool(
                record_threat_intel,
                data_path,
                indicator=payload.url,
                indicator_type="url",
                category=target_category,
                severity=risk_info["key"],
                confidence=decision["confidence"],
                source="Consented Live Scan",
                evidence=ai_exp["summary"],
                status="verified" if decision["verdict"] == "known_threat" else "unverified",
            )
        return result

    # -----------------------------------------------------------------------
    # Authentication & Session Management
    # -----------------------------------------------------------------------

    @app.post("/api/v1/auth/register")
    async def auth_register(payload: RegisterRequest, response: Response):
        clean_user = payload.username.strip().lower()
        clean_email = payload.email.strip().lower()
        existing = await run_in_threadpool(get_user_by_username_or_email, data_path, clean_user)
        if existing:
            raise HTTPException(status_code=400, detail="username_or_email_taken")
        user = await run_in_threadpool(create_user, data_path, clean_user, clean_email, payload.password, "user")
        token = await run_in_threadpool(create_session, data_path, user["id"])
        response.set_cookie(key="trustcard_session", value=token, httponly=True, samesite="lax", max_age=7 * 86400)
        return {"user": user, "token": token}

    @app.post("/api/v1/auth/login")
    async def auth_login(payload: LoginRequest, response: Response):
        user = await run_in_threadpool(get_user_by_username_or_email, data_path, payload.username)
        if not user or not verify_password(payload.password, user["password_hash"], user["salt"]):
            raise HTTPException(status_code=401, detail="invalid_credentials")
        token = await run_in_threadpool(create_session, data_path, user["id"])
        response.set_cookie(key="trustcard_session", value=token, httponly=True, samesite="lax", max_age=7 * 86400)
        user_info = {"id": user["id"], "username": user["username"], "email": user["email"], "role": user["role"]}
        return {"user": user_info, "token": token}

    @app.post("/api/v1/auth/logout")
    async def auth_logout(request: Request, response: Response):
        token = request.cookies.get("trustcard_session")
        if token:
            await run_in_threadpool(delete_session, data_path, token)
        response.delete_cookie(key="trustcard_session")
        return {"ok": True}

    @app.get("/api/v1/auth/me")
    async def auth_me(request: Request):
        user = _get_user(request)
        return {"user": user}

    # -----------------------------------------------------------------------
    # Scan History & Printable Reports
    # -----------------------------------------------------------------------

    @app.get("/api/v1/scans")
    async def list_scans_endpoint(request: Request, q: str | None = None, severity: str | None = None, limit: int = 50, offset: int = 0):
        user = _get_user(request)
        user_id = user["id"] if (user and user["role"] not in ("admin", "analyst")) else None
        scans, total = await run_in_threadpool(list_scans, data_path, user_id=user_id, query=q, severity=severity, limit=limit, offset=offset)
        return {"scans": scans, "total": total}

    @app.get("/api/v1/scans/compare")
    async def compare_scans_endpoint(scan_a: str, scan_b: str):
        try:
            comparison = await run_in_threadpool(compare_scans, data_path, scan_a, scan_b)
            return comparison
        except KeyError:
            raise HTTPException(status_code=404, detail="scans_not_found")

    @app.get("/api/v1/scans/{scan_id}")
    async def get_scan_endpoint(scan_id: str, request: Request):
        user = _get_user(request)
        user_id = user["id"] if (user and user["role"] not in ("admin", "analyst")) else None
        scan = await run_in_threadpool(get_scan, data_path, scan_id, user_id=user_id)
        if not scan:
            raise HTTPException(status_code=404, detail="scan_not_found")
        return scan

    @app.delete("/api/v1/scans/{scan_id}")
    async def delete_scan_endpoint(scan_id: str, request: Request):
        user = _get_user(request)
        user_id = user["id"] if (user and user["role"] not in ("admin", "analyst")) else None
        deleted = await run_in_threadpool(delete_scan, data_path, scan_id, user_id=user_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="scan_not_found")
        return {"deleted": True, "scan_id": scan_id}

    @app.get("/scans/{scan_id}/report", response_class=HTMLResponse)
    @app.get("/api/v1/scans/{scan_id}/report", response_class=HTMLResponse)
    async def scan_report_view(scan_id: str, request: Request):
        scan = await run_in_threadpool(get_scan, data_path, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="scan_not_found")
        return templates.TemplateResponse(request=request, name="report.html", context={"request": request, "scan": scan})

    # -----------------------------------------------------------------------
    # Threat Intelligence Dashboard & CT Monitoring
    # -----------------------------------------------------------------------

    @app.get("/api/v1/dashboard/stats")
    async def dashboard_stats_endpoint():
        stats = await run_in_threadpool(get_dashboard_stats, data_path)
        return stats

    @app.get("/api/v1/ct/search")
    async def ct_search_endpoint(domain: str):
        results = await run_in_threadpool(search_certificate_transparency, domain)
        return results

    @app.get("/api/v1/domain/dns")
    async def domain_dns_endpoint(domain: str):
        results = await run_in_threadpool(lookup_domain_dns, domain)
        return results

    @app.get("/api/v1/intel/search")
    async def intel_search_endpoint(
        q: str = "",
        category: str | None = None,
        indicator_type: str | None = None,
        status: str | None = None,
        limit: int = 50,
    ):
        results = await run_in_threadpool(
            search_threat_intel,
            data_path,
            query=q,
            category=category,
            indicator_type=indicator_type,
            status=status,
            limit=limit,
        )
        return {"results": results, "count": len(results)}

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
    async def admin_reports(request: Request, state: str = "unverified"):
        require_admin(request)
        reports = await run_in_threadpool(list_reports, data_path, state)
        return templates.TemplateResponse(
            request=request,
            name="reports.html",
            context={"request": request, "reports": reports, "current_state": state},
        )

    @app.get("/api/v1/admin/reports")
    async def admin_report_list(request: Request, state: str = "unverified"):
        require_admin(request)
        return {"reports": await run_in_threadpool(list_reports, data_path, state)}

    @app.post("/api/v1/admin/reports/{report_id}/review")
    async def review_local_report(report_id: str, payload: ReviewRequest, request: Request):
        require_admin(request)
        try:
            report = await run_in_threadpool(review_report, data_path, report_id, payload.decision)
        except KeyError:
            raise HTTPException(status_code=404, detail="report_not_found")
        return {"id": report["id"], "state": report["state"], "reviewed_at": report["reviewed_at"]}

    @app.get("/api/v1/admin/export")
    async def export_reports(request: Request):
        require_admin(request)
        sharing_key = os.environ.get("SHARING_KEY", "")
        if not sharing_key:
            raise HTTPException(status_code=503, detail="sharing_not_configured")
        approved_reports = await run_in_threadpool(list_reports, data_path, "approved")
        export_data = [
            {
                "indicator_fingerprint": r["indicator_hash"],
                "host": r["host"],
                "category": r["category"],
                "created_at": r["created_at"],
                "report_count": r.get("report_count", 1),
            }
            for r in approved_reports
        ]
        instance_name = os.environ.get("INSTANCE_NAME", "trustcard-node")
        envelope = {
            "instance": instance_name,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "reports": export_data,
        }
        body_bytes = json.dumps(envelope, sort_keys=True).encode("utf-8")
        sig = hmac.new(sharing_key.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
        return Response(
            content=body_bytes,
            media_type="application/json",
            headers={"X-Signature": sig},
        )

    @app.post("/api/v1/admin/import")
    async def import_reports_endpoint(request: Request):
        require_admin(request)
        sharing_key = os.environ.get("SHARING_KEY", "")
        if not sharing_key:
            raise HTTPException(status_code=503, detail="sharing_not_configured")

        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > 1048576:
            raise HTTPException(status_code=413, detail="payload_too_large")

        body_bytes = await request.body()
        if len(body_bytes) > 1048576:
            raise HTTPException(status_code=413, detail="payload_too_large")

        try:
            data = json.loads(body_bytes)
        except Exception:
            raise HTTPException(status_code=400, detail="invalid_json")

        sig_header = request.headers.get("X-Signature")
        sig = sig_header or data.get("signature")
        if not sig:
            raise HTTPException(status_code=400, detail="missing_signature")

        if "data" in data and "signature" in data:
            reports_data = data["data"].get("reports", [])
            peer_name = data["data"].get("instance", "unknown-peer")
            canonical_bytes = json.dumps(data["data"], sort_keys=True).encode("utf-8")
        else:
            reports_data = data.get("reports", [])
            peer_name = data.get("instance", "unknown-peer")
            canonical_bytes = body_bytes

        expected_sig = hmac.new(sharing_key.encode("utf-8"), canonical_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            # Check raw body_bytes as alternative
            alt_sig = hmac.new(sharing_key.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, alt_sig):
                raise HTTPException(status_code=400, detail="invalid_signature")

        imported_count = await run_in_threadpool(
            import_reports,
            data_path,
            reports_data,
            source=f"Peer: {peer_name}",
        )
        return {
            "imported": imported_count,
            "source": f"Peer: {peer_name}",
            "message": f"Successfully imported {imported_count} unverified reports.",
        }

    # -----------------------------------------------------------------------
    # Community User Forum Routes
    # -----------------------------------------------------------------------

    @app.get("/api/v1/forum/threads")
    async def forum_list_threads(category: str | None = None, q: str | None = None, sort_by: str = "recent"):
        threads = await run_in_threadpool(list_forum_threads, data_path, category=category, query=q, sort_by=sort_by)
        return {"threads": threads, "count": len(threads)}

    @app.post("/api/v1/forum/threads")
    async def forum_create_thread(payload: ThreadCreateRequest, request: Request):
        user = _get_user(request)
        author = user["username"] if user else (payload.author_name.strip() or "SecurityAnalyst")
        user_id = user["id"] if user else None
        thread = await run_in_threadpool(
            create_forum_thread,
            data_path,
            title=payload.title,
            content=payload.content,
            category=payload.category,
            author_name=author,
            user_id=user_id,
        )
        return {"thread": thread, "message": "Discussion thread created successfully."}

    @app.get("/api/v1/forum/threads/{thread_id}")
    async def forum_get_thread(thread_id: str):
        thread = await run_in_threadpool(get_forum_thread, data_path, thread_id)
        if not thread:
            raise HTTPException(status_code=404, detail="thread_not_found")
        return thread

    @app.post("/api/v1/forum/threads/{thread_id}/replies")
    async def forum_add_reply(thread_id: str, payload: ThreadReplyRequest, request: Request):
        user = _get_user(request)
        author = user["username"] if user else (payload.author_name.strip() or "SecurityAnalyst")
        user_id = user["id"] if user else None
        try:
            reply = await run_in_threadpool(
                create_forum_reply,
                data_path,
                thread_id=thread_id,
                content=payload.content,
                author_name=author,
                user_id=user_id,
            )
            return {"reply": reply, "message": "Reply posted."}
        except KeyError:
            raise HTTPException(status_code=404, detail="thread_not_found")

    @app.post("/api/v1/forum/threads/{thread_id}/upvote")
    async def forum_upvote(thread_id: str):
        try:
            result = await run_in_threadpool(upvote_forum_thread, data_path, thread_id)
            return result
        except KeyError:
            raise HTTPException(status_code=404, detail="thread_not_found")

    # -----------------------------------------------------------------------
    # Collaborative Threat Indicator Direct Submission
    # -----------------------------------------------------------------------

    @app.post("/api/v1/intel/submit")
    async def intel_submit_endpoint(payload: IntelSubmitRequest, request: Request):
        user = _get_user(request)
        source = f"Community Report ({user['username']})" if user else "Community Report (Guest)"
        entry = await run_in_threadpool(
            record_threat_intel,
            data_path,
            indicator=payload.indicator,
            indicator_type=payload.indicator_type,
            category=payload.category,
            severity=payload.severity,
            confidence="medium",
            source=source,
            evidence=payload.evidence,
            status="unverified",
        )
        return {"entry": entry, "message": "Threat indicator submitted to collaborative intelligence database."}

    return app


app = create_app()
