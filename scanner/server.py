"""Small token-protected HTTP wrapper for the isolated scanner container."""

from __future__ import annotations

import hmac
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scanner.engine import scan_url
from scanner.feed_fetch import MAX_FEED_BYTES, provider_request

MAX_BODY = 4096
ACTIVE_SCANS = threading.BoundedSemaphore(4)
FEED_LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    server_version = "TrustCardScanner"
    sys_version = ""

    def log_message(self, format, *args):
        # Request paths include user URLs; never write them to container logs.
        return

    def log_request(self, code="-", size="-"):
        return

    def _respond(self, status: int, value: dict):
        body = json.dumps(value, separators=(",", ":")).encode()
        self._respond_bytes(status, body, "application/json")

    def _respond_bytes(self, status: int, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._respond(200, {"status": "ok"})
        else:
            self._respond(404, {"error": "not_found"})

    def do_POST(self):
        expected = os.environ.get("SCANNER_TOKEN", "")
        supplied = self.headers.get("X-Scanner-Token", "")
        if not expected or not hmac.compare_digest(supplied, expected):
            self._respond(403, {"error": "forbidden"})
            return
        if self.path == "/feed":
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 1 <= size <= 128:
                    raise ValueError
                payload = json.loads(self.rfile.read(size))
                source = payload.get("source") if isinstance(payload, dict) else None
                if source not in {"PhishTank", "URLhaus", "OpenPhish"}:
                    raise ValueError
            except (ValueError, json.JSONDecodeError):
                self._respond(400, {"error": "invalid_request"})
                return
            if not FEED_LOCK.acquire(blocking=False):
                self._respond(429, {"error": "feed_refresh_busy"})
                return
            try:
                try:
                    payload_bytes = provider_request(source)
                    if len(payload_bytes) > MAX_FEED_BYTES:
                        self._respond(413, {"error": "feed_too_large"})
                    else:
                        content_type = "application/gzip" if source == "PhishTank" else "text/csv" if source == "URLhaus" else "text/plain"
                        self._respond_bytes(200, payload_bytes, content_type)
                except ValueError as exc:
                    code = "feed_unavailable" if str(exc) == "provider_unavailable" else str(exc).replace(" ", "_")
                    self._respond(502, {"error": code})
            finally:
                FEED_LOCK.release()
            return
        if self.path != "/scan":
            self._respond(404, {"error": "not_found"})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 1 <= size <= MAX_BODY:
                raise ValueError
            payload = json.loads(self.rfile.read(size))
            url = payload.get("url") if isinstance(payload, dict) else None
            ct_rdap_consent = bool(payload.get("ct_rdap_consent", False)) if isinstance(payload, dict) else False
            if not isinstance(url, str) or len(url) > 2048:
                raise ValueError
        except (ValueError, json.JSONDecodeError):
            self._respond(400, {"error": "invalid_request"})
            return
        if not ACTIVE_SCANS.acquire(blocking=False):
            self._respond(429, {"error": "scanner_busy"})
            return
        try:
            self._respond(200, scan_url(url, ct_rdap_consent=ct_rdap_consent))
        except Exception:
            self._respond(500, {"complete": False, "findings": [], "redirect_hosts": [], "error": "scan_failed"})
        finally:
            ACTIVE_SCANS.release()


def main():
    if not os.environ.get("SCANNER_TOKEN"):
        raise SystemExit("SCANNER_TOKEN must be configured")
    server = ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("SCANNER_PORT", "8080"))), Handler)
    server.daemon_threads = True
    server.timeout = 1
    server.serve_forever()


if __name__ == "__main__":
    main()
