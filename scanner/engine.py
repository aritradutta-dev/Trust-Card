"""Bounded, read-only website checks with destination pinning and SSRF guards."""

from __future__ import annotations

import http.client
import ipaddress
import select
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from app.urls import canonicalize_url
from app.url_analysis import get_registrable_domain
from scanner.certs import analyze_certificate_der
from scanner.ct_rdap import lookup_ct_logs, lookup_domain_age_rdap
from scanner.page_signals import audit_page_html, audit_security_headers

MAX_REDIRECTS = 5
MAX_HTML_BYTES = 2 * 1024 * 1024
MAX_SCAN_SECONDS = 20
CONNECT_TIMEOUT = 5
DNS_TIMEOUT = 3
MAX_RESPONSE_HEADER_BYTES = 64 * 1024
_SYSTEM_RESOLVER = socket.getaddrinfo
_DNS_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="trust-card-dns")
_DNS_SLOTS = threading.BoundedSemaphore(4)


class UnsafeDestinationError(ValueError):
    pass


class HostResolutionError(ValueError):
    pass


class ScanDeadlineExceeded(TimeoutError):
    pass


def _is_public(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        parsed = parsed.ipv4_mapped
    return parsed.is_global and not parsed.is_multicast and not parsed.is_unspecified


def resolve_public_addresses(
    host: str, port: int, resolver=_SYSTEM_RESOLVER, timeout: float = DNS_TIMEOUT
) -> list[str]:
    """Resolve and reject the whole hostname if any answer is non-public."""
    try:
        literal = ipaddress.ip_address(host)
        candidates = [literal.compressed]
    except ValueError:
        future = None
        reserved_dns_slot = False
        try:
            if resolver is _SYSTEM_RESOLVER:
                if not _DNS_SLOTS.acquire(blocking=False):
                    raise HostResolutionError("dns_busy")
                reserved_dns_slot = True
                future = _DNS_POOL.submit(resolver, host, port, type=socket.SOCK_STREAM)
                answers = future.result(timeout=max(0.01, timeout))
            else:
                answers = resolver(host, port, type=socket.SOCK_STREAM)
        except FutureTimeout as exc:
            if future is not None:
                future.cancel()
                future.add_done_callback(lambda _done: _DNS_SLOTS.release())
                reserved_dns_slot = False
            raise HostResolutionError("host_resolution_timeout") from exc
        except HostResolutionError:
            if reserved_dns_slot:
                _DNS_SLOTS.release()
            raise
        except Exception as exc:
            if reserved_dns_slot:
                _DNS_SLOTS.release()
            if isinstance(exc, OSError):
                raise HostResolutionError("host_resolution_failed") from exc
            raise
        else:
            if reserved_dns_slot:
                _DNS_SLOTS.release()
        candidates = []
        for answer in answers:
            if isinstance(answer, str):
                candidates.append(answer)
            else:
                candidates.append(answer[4][0])
    unique = list(dict.fromkeys(candidates))
    if not unique or any(not _is_public(address) for address in unique):
        raise UnsafeDestinationError("non_public_destination")
    return unique


def _same_site(host_a: str, host_b: str) -> bool:
    """Compare sites accurately using the public suffix list for registrable domains."""
    a = host_a.rstrip(".").lower()
    b = host_b.rstrip(".").lower()
    if not a or not b:
        return False
    reg_a = get_registrable_domain(a)
    reg_b = get_registrable_domain(b)
    if reg_a and reg_b:
        return reg_a == reg_b
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _reads_html(headers: dict[str, str], status: int) -> bool:
    content_type = headers.get("content-type", "").lower()
    content_encoding = headers.get("content-encoding", "identity").lower()
    return (
        status not in {301, 302, 303, 307, 308}
        and ("text/html" in content_type or "application/xhtml+xml" in content_type)
        and content_encoding in {"", "identity"}
    )


class _DeadlineFile:
    """Socket file adapter that gives each response one absolute deadline."""

    def __init__(self, sock: socket.socket, deadline: float):
        self.sock = sock
        self.deadline = deadline
        self.buffer = bytearray()
        self.eof = False
        self.headers_complete = False
        self.header_bytes = 0

    def _fill(self) -> bool:
        if self.eof:
            return False
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ScanDeadlineExceeded
        try:
            pending = self.sock.pending() if isinstance(self.sock, ssl.SSLSocket) else 0
            if not pending:
                ready, _, _ = select.select([self.sock], [], [], remaining)
                if not ready:
                    raise ScanDeadlineExceeded
            self.sock.settimeout(remaining)
            chunk = self.sock.recv(4096)
        except TimeoutError as exc:
            raise ScanDeadlineExceeded from exc
        if not chunk:
            self.eof = True
            return False
        self.buffer.extend(chunk)
        return True

    def readline(self, size: int = -1) -> bytes:
        limit = MAX_RESPONSE_HEADER_BYTES + 1 if size is None or size < 0 else size
        while True:
            newline = self.buffer.find(b"\n")
            available = newline + 1 if newline >= 0 else len(self.buffer)
            if newline >= 0 or available >= limit or self.eof:
                count = min(available, limit)
                line = bytes(self.buffer[:count])
                del self.buffer[:count]
                if not self.headers_complete:
                    self.header_bytes += len(line)
                    if self.header_bytes > MAX_RESPONSE_HEADER_BYTES:
                        raise http.client.HTTPException("response headers exceed 64 KiB")
                    if line in {b"\r\n", b"\n"}:
                        self.headers_complete = True
                return line
            if not self.headers_complete and self.header_bytes + len(self.buffer) > MAX_RESPONSE_HEADER_BYTES:
                raise http.client.HTTPException("response headers exceed 64 KiB")
            self._fill()

    def read1(self, size: int = -1) -> bytes:
        if size == 0:
            return b""
        if not self.buffer and not self._fill():
            return b""
        count = len(self.buffer) if size is None or size < 0 else min(size, len(self.buffer))
        result = bytes(self.buffer[:count])
        del self.buffer[:count]
        return result

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            chunks = [bytes(self.buffer)]
            self.buffer.clear()
            while self._fill():
                chunks.append(bytes(self.buffer))
                self.buffer.clear()
            return b"".join(chunks)
        chunks = []
        total = 0
        while total < size:
            chunk = self.read1(size - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)

    def close(self):
        self.eof = True


class _DeadlineSocket:
    def __init__(self, sock: socket.socket, deadline: float):
        self.sock = sock
        self.deadline = deadline

    def makefile(self, mode: str):
        if mode != "rb":
            raise ValueError("read-only response stream required")
        return _DeadlineFile(self.sock, self.deadline)


def _wrap_tls_with_deadline(sock: socket.socket, host: str, deadline: float) -> ssl.SSLSocket:
    secure = ssl.create_default_context().wrap_socket(
        sock, server_hostname=host, do_handshake_on_connect=False
    )
    secure.setblocking(False)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            secure.close()
            raise ScanDeadlineExceeded
        try:
            secure.do_handshake()
            break
        except ssl.SSLWantReadError:
            ready, _, _ = select.select([secure], [], [], remaining)
            if not ready:
                secure.close()
                raise ScanDeadlineExceeded
        except ssl.SSLWantWriteError:
            _, ready, _ = select.select([], [secure], [], remaining)
            if not ready:
                secure.close()
                raise ScanDeadlineExceeded
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        secure.close()
        raise ScanDeadlineExceeded
    secure.settimeout(min(CONNECT_TIMEOUT, remaining))
    return secure


class _CredentialForms(HTMLParser):
    def __init__(self, page_url: str):
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.forms: list[dict[str, object]] = []
        self.current: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs):
        values = dict(attrs)
        if tag.lower() == "form":
            action = urljoin(self.page_url, values.get("action") or self.page_url)
            self.current = {"action": action, "credential": False}
            self.forms.append(self.current)
        elif tag.lower() == "input" and self.current is not None:
            if values.get("type", "").lower() == "password":
                self.current["credential"] = True

    def handle_endtag(self, tag: str):
        if tag.lower() == "form":
            self.current = None


def credential_form_findings(html: str, page_url: str) -> list[dict]:
    parser = _CredentialForms(page_url)
    try:
        parser.feed(html)
    except Exception:
        return []
    page_host = urlsplit(page_url).hostname or ""
    findings = []
    for form in parser.forms:
        if not form["credential"]:
            continue
        action = str(form["action"])
        try:
            action = canonicalize_url(action)
        except ValueError:
            # A non-HTTP action cannot be safely followed; it may still submit elsewhere.
            findings.append({
                "category": "credential_form",
                "severity": "high",
                "summary": "A password form uses a non-web submission destination.",
                "source": "Static page inspection",
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "group": "credential_form",
            })
            continue
        action_host = urlsplit(action).hostname or ""
        if not _same_site(action_host, page_host):
            findings.append({
                "category": "credential_form",
                "severity": "high",
                "summary": "A password form submits to a different site.",
                "source": "Static page inspection",
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "group": "credential_form",
            })
    return findings


def _connect_pinned(url: str, addresses: list[str], timeout: float, deadline: float):
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    last_error: OSError | None = None
    for address in addresses:
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ScanDeadlineExceeded
            sock = socket.create_connection((address, port), timeout=min(timeout, remaining))
            if parts.scheme == "https":
                try:
                    sock = _wrap_tls_with_deadline(sock, parts.hostname or "", deadline)
                    certificate = sock.getpeercert()
                    findings = []
                    cert_der = None
                    try:
                        cert_der = sock.getpeercert(binary_form=True)
                    except Exception:
                        pass
                    if cert_der:
                        cert_details, cert_findings = analyze_certificate_der(cert_der, parts.hostname or "")
                        findings.extend(cert_findings)
                        findings.append({"_cert_details": cert_details})
                    else:
                        expires = certificate.get("notAfter")
                        if expires:
                            expires_at = datetime.fromtimestamp(ssl.cert_time_to_seconds(expires), timezone.utc)
                            if (expires_at - datetime.now(timezone.utc)).total_seconds() < 14 * 86400:
                                findings.append({
                                    "category": "certificate",
                                    "severity": "low",
                                    "summary": "The TLS certificate expires within 14 days.",
                                    "source": "Live TLS validation",
                                    "observed_at": datetime.now(timezone.utc).isoformat(),
                                    "group": "tls",
                                })
                    return sock, findings
                except ssl.SSLCertVerificationError as exc:
                    sock.close()
                    reason = exc.verify_message.lower()
                    if "expired" in reason:
                        explanation = "The TLS certificate appears to be expired."
                    elif "hostname" in reason or "doesn't match" in reason or "not valid for" in reason:
                        explanation = "The TLS certificate does not match this site's hostname."
                    elif "issuer" in reason or "self-signed" in reason or "self signed" in reason:
                        explanation = "The TLS certificate chain is not trusted by this system."
                    else:
                        explanation = "The TLS certificate could not be validated for this site."
                    finding = {
                        "category": "certificate",
                        "severity": "medium",
                        "summary": explanation,
                        "source": "Live TLS validation",
                        "observed_at": datetime.now(timezone.utc).isoformat(),
                        "group": "certificate",
                    }
                    # Non-verifying inspection handshake: read the certificate
                    # without trusting it, for deeper analysis. No HTTP request
                    # is sent over this connection.
                    cert_findings_extra = []
                    cert_details = None
                    try:
                        remaining = deadline - time.monotonic()
                        if remaining > 0.5:
                            inspect_sock = socket.create_connection(
                                (address, port), timeout=min(timeout, remaining)
                            )
                            try:
                                inspect_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                                inspect_ctx.check_hostname = False
                                inspect_ctx.verify_mode = ssl.CERT_NONE
                                inspect_ssl = inspect_ctx.wrap_socket(
                                    inspect_sock, server_hostname=parts.hostname or ""
                                )
                                cert_der = inspect_ssl.getpeercert(binary_form=True)
                                inspect_ssl.close()
                                if cert_der:
                                    cert_details, cert_findings_extra = analyze_certificate_der(cert_der, parts.hostname or "")
                            except Exception:
                                inspect_sock.close()
                    except Exception:
                        pass
                    res_findings = [finding] + [f for f in cert_findings_extra if f.get("id") != "cert-hostname-mismatch"]
                    if cert_details:
                        res_findings.append({"_cert_details": cert_details})
                    return None, res_findings
            return sock, []
        except OSError as exc:
            last_error = exc
    if last_error:
        raise last_error
    raise OSError("connection_failed")


def _request_pinned(url: str, addresses: list[str], timeout: float, deadline: float):
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query
    sock, tls_findings = _connect_pinned(url, addresses, timeout, deadline)
    if sock is None:
        return None, b"", tls_findings, False
    connection = http.client.HTTPConnection(parts.hostname, port, timeout=timeout)
    connection.sock = sock
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ScanDeadlineExceeded
        connection.sock.settimeout(min(timeout, remaining))
        connection.request(
            "GET",
            target,
            headers={
                "Host": parts.netloc,
                "User-Agent": "TrustCard-Local-Scanner/0.1",
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ScanDeadlineExceeded
        response = http.client.HTTPResponse(
            _DeadlineSocket(connection.sock, deadline), method="GET"
        )
        response.begin()
        headers = {key.lower(): value for key, value in response.getheaders()}
        body = bytearray()
        if _reads_html(headers, response.status):
            while len(body) <= MAX_HTML_BYTES:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ScanDeadlineExceeded
                connection.sock.settimeout(min(CONNECT_TIMEOUT, remaining))
                chunk = response.read1(min(64 * 1024, MAX_HTML_BYTES + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
        truncated = len(body) > MAX_HTML_BYTES
        return (response.status, headers), bytes(body[:MAX_HTML_BYTES]), tls_findings, truncated
    finally:
        connection.close()


def scan_url(value: str, ct_rdap_consent: bool = False) -> dict:
    """Perform at most six read-only GETs; never execute page code or submit forms."""
    started = time.monotonic()
    try:
        current = canonicalize_url(value)
    except ValueError:
        return {"complete": False, "findings": [], "redirect_hosts": [], "error": "invalid_url"}

    findings: list[dict] = []
    redirect_hosts: list[str] = []
    redirect_count = 0
    page_body = b""
    content_type = ""
    cert_details = None
    while True:
        remaining = MAX_SCAN_SECONDS - (time.monotonic() - started)
        if remaining <= 0:
            return {"complete": False, "findings": findings, "redirect_hosts": redirect_hosts, "error": "scan_timeout"}
        parts = urlsplit(current)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        try:
            addresses = resolve_public_addresses(parts.hostname or "", port, timeout=min(DNS_TIMEOUT, remaining))
            response, page_body, tls_findings, body_truncated = _request_pinned(
                current, addresses, min(CONNECT_TIMEOUT, remaining), started + MAX_SCAN_SECONDS
            )
            findings.extend(tls_findings)
        except UnsafeDestinationError:
            findings.append({
                "category": "redirect",
                "severity": "high",
                "summary": "The site points to a private or restricted network address; the scanner blocked it.",
                "source": "Destination safety check",
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "group": "redirect",
            })
            return {"complete": True, "findings": findings, "redirect_hosts": redirect_hosts, "coverage": "partial"}
        except HostResolutionError:
            return {"complete": False, "findings": findings, "redirect_hosts": redirect_hosts, "error": "host_resolution_failed"}
        except ScanDeadlineExceeded:
            return {"complete": False, "findings": findings, "redirect_hosts": redirect_hosts, "error": "scan_timeout"}
        except (OSError, http.client.HTTPException, TimeoutError):
            return {"complete": False, "findings": findings, "redirect_hosts": redirect_hosts, "error": "site_unreachable"}

        if response is None:
            clean_findings = [f for f in findings if "_cert_details" not in f]
            for f in findings:
                if "_cert_details" in f:
                    cert_details = f["_cert_details"]
            return {
                "complete": True,
                "findings": clean_findings,
                "redirect_hosts": redirect_hosts,
                "coverage": "partial",
                "certificate": cert_details,
            }
        status, headers = response
        location = headers.get("location")
        if status in {301, 302, 303, 307, 308} and location:
            if redirect_count >= MAX_REDIRECTS:
                findings.append({
                    "category": "redirect",
                    "severity": "medium",
                    "summary": "The site exceeded the five-redirect inspection limit.",
                    "source": "Redirect inspection",
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                    "group": "redirect",
                })
                return {"complete": True, "findings": findings, "redirect_hosts": redirect_hosts, "coverage": "partial"}
            try:
                destination = canonicalize_url(urljoin(current, location))
            except ValueError:
                findings.append({
                    "category": "redirect",
                    "severity": "medium",
                    "summary": "A redirect uses an unsupported or invalid destination.",
                    "source": "Redirect inspection",
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                    "group": "redirect",
                })
                return {"complete": True, "findings": findings, "redirect_hosts": redirect_hosts, "coverage": "partial"}
            source_host = parts.hostname or ""
            destination_host = urlsplit(destination).hostname or ""
            if destination_host not in redirect_hosts:
                redirect_hosts.append(destination_host)
            if not _same_site(source_host, destination_host):
                findings.append({
                    "category": "redirect",
                    "severity": "medium",
                    "summary": "The link redirects to a different site.",
                    "source": "Redirect inspection",
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                    "group": "redirect",
                })
            current = destination
            redirect_count += 1
            continue

        content_type = headers.get("content-type", "")
        if urlsplit(current).scheme == "http":
            findings.append({
                "category": "certificate",
                "severity": "low",
                "summary": "This link uses unencrypted HTTP and has no TLS certificate.",
                "source": "Live TLS validation",
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "group": "tls",
            })
        findings.extend(audit_security_headers(headers, urlsplit(current).scheme))
        break

    if page_body and ("html" in content_type.lower() or page_body.lstrip().lower().startswith((b"<!doctype html", b"<html"))):
        decoded_html = page_body.decode("utf-8", errors="replace")
        findings.extend(audit_page_html(decoded_html, current))
    page_coverage = "full" if _reads_html(headers, status) and not body_truncated else "partial"
    if not _reads_html(headers, status):
        findings.append({
            "category": "page_inspection",
            "severity": "low",
            "summary": "The response was not readable HTML; password-form inspection was skipped.",
            "source": "Static page inspection",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "group": "technical",
        })
    elif body_truncated:
        findings.append({
            "category": "page_inspection",
            "severity": "low",
            "summary": "The HTML response exceeded the 2 MiB inspection limit; later content was not checked.",
            "source": "Static page inspection",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "group": "technical",
        })
    clean_findings = []
    for item in findings:
        if "_cert_details" in item:
            cert_details = item["_cert_details"]
        else:
            clean_findings.append(item)
    findings = clean_findings

    target_hostname = urlsplit(current).hostname or ""
    skipped_lookups = []
    if ct_rdap_consent and target_hostname:
        ct_findings = lookup_ct_logs(target_hostname)
        rdap_findings = lookup_domain_age_rdap(target_hostname)
        findings.extend(ct_findings)
        findings.extend(rdap_findings)
    else:
        skipped_lookups.append("Third-party CT log and RDAP lookups were skipped (requires optional consent).")

    return {
        "complete": True,
        "findings": findings,
        "redirect_hosts": redirect_hosts,
        "coverage": page_coverage,
        "certificate": cert_details,
        "skipped_lookups": skipped_lookups,
    }
