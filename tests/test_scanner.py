import unittest
import time
import socket
import threading
import http.client
import io
from contextlib import redirect_stderr, redirect_stdout

from scanner.engine import HostResolutionError, ScanDeadlineExceeded, _DeadlineFile, _DeadlineSocket, _reads_html, _request_pinned, credential_form_findings, resolve_public_addresses, scan_url


class ScannerSafetyTests(unittest.TestCase):
    def test_scanner_request_paths_are_not_written_to_process_logs(self):
        from scanner.server import Handler

        output = io.StringIO()
        handler = Handler.__new__(Handler)
        with redirect_stdout(output), redirect_stderr(output):
            handler.log_message("GET /scan?url=https://private.example/?token=secret")
            handler.log_request(200, 100)
        self.assertEqual(output.getvalue(), "")

    def test_blocks_private_literal_and_private_dns_answers(self):
        self.assertRaises(ValueError, resolve_public_addresses, "127.0.0.1", 443)
        self.assertRaises(
            ValueError,
            resolve_public_addresses,
            "public.example",
            443,
            resolver=lambda host, port, **kwargs: ["93.184.216.34", "10.0.0.8"],
        )

    def test_returns_only_validated_global_addresses(self):
        addresses = resolve_public_addresses(
            "public.example",
            443,
            resolver=lambda host, port, **kwargs: ["93.184.216.34", "93.184.216.34"],
        )
        self.assertEqual(addresses, ["93.184.216.34"])

    def test_blocks_reserved_link_local_metadata_and_private_addresses(self):
        from scanner.engine import UnsafeDestinationError

        for address in (
            "10.0.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "192.0.2.1",
            "240.0.0.1",
            "::1",
            "fe80::1",
            "fd00::1",
            "2001:db8::1",
        ):
            with self.subTest(address=address):
                with self.assertRaises(UnsafeDestinationError):
                    resolve_public_addresses(address, 443)

    def test_connects_to_validated_address_instead_of_resolving_host_again(self):
        from unittest.mock import patch
        from scanner.engine import _connect_pinned

        connected = object()
        with patch("scanner.engine.socket.create_connection", return_value=connected) as create:
            sock, findings = _connect_pinned(
                "http://public.example/path", ["93.184.216.34"], 5, time.monotonic() + 5
            )

        self.assertIs(sock, connected)
        self.assertEqual(findings, [])
        self.assertEqual(create.call_args.args[0], ("93.184.216.34", 80))

    def test_each_redirect_is_revalidated_and_private_target_is_never_requested(self):
        from unittest.mock import patch

        def mocked_resolution(host, port, **kwargs):
            if host == "public.example":
                return ["93.184.216.34"]
            return resolve_public_addresses(host, port)

        with (
            patch("scanner.engine.resolve_public_addresses", side_effect=mocked_resolution) as resolve,
            patch(
                "scanner.engine._request_pinned",
                return_value=((302, {"location": "http://169.254.169.254/latest/meta-data/"}), b"", [], False),
            ) as request,
        ):
            result = scan_url("http://public.example/start")

        self.assertEqual(request.call_count, 1)
        self.assertEqual(resolve.call_count, 2)
        self.assertEqual(resolve.call_args.args[0], "169.254.169.254")
        self.assertTrue(any(item["severity"] == "high" for item in result["findings"]))
        self.assertEqual(result["coverage"], "partial")

    def test_same_host_redirect_rechecks_dns_before_second_connection(self):
        from unittest.mock import patch
        from scanner.engine import UnsafeDestinationError

        with (
            patch(
                "scanner.engine.resolve_public_addresses",
                side_effect=[["93.184.216.34"], UnsafeDestinationError("non_public_destination")],
            ) as resolve,
            patch(
                "scanner.engine._request_pinned",
                return_value=((302, {"location": "/next"}), b"", [], False),
            ) as request,
        ):
            result = scan_url("http://public.example/start")

        self.assertEqual(resolve.call_count, 2)
        self.assertEqual(request.call_count, 1)
        self.assertTrue(any(item["severity"] == "high" for item in result["findings"]))

    def test_scanner_makes_at_most_initial_get_plus_five_explicit_redirects(self):
        from unittest.mock import patch

        requested = []

        def response_for(url, *args):
            requested.append(url)
            redirect_number = len(requested)
            return (
                (302, {"location": f"http://hop{redirect_number}.example/"}),
                b"",
                [],
                False,
            )

        with (
            patch(
                "scanner.engine.resolve_public_addresses",
                return_value=["93.184.216.34"],
            ) as resolve,
            patch("scanner.engine._request_pinned", side_effect=response_for),
        ):
            result = scan_url("http://start.example/path")

        self.assertEqual(len(requested), 6)
        self.assertEqual(resolve.call_count, 6)
        self.assertEqual(requested[0], "http://start.example/path")
        self.assertEqual(requested[1:], [f"http://hop{i}.example/" for i in range(1, 6)])
        self.assertTrue(any("five-redirect" in item["summary"] for item in result["findings"]))
        self.assertEqual(result["coverage"], "partial")

    def test_initial_request_is_get_and_reads_no_more_than_two_mib(self):
        from unittest.mock import patch
        from scanner.engine import MAX_HTML_BYTES

        class FakeSocket:
            def settimeout(self, value):
                self.timeout = value

        class FakeConnection:
            def __init__(self, host, port, timeout):
                self.sock = None
                self.request_call = None

            def request(self, *args, **kwargs):
                self.request_call = (args, kwargs)
                calls.append(self)

            def close(self):
                pass

        class FakeResponse:
            status = 200

            def __init__(self, stream, method):
                self.remaining = MAX_HTML_BYTES + 100

            def begin(self):
                pass

            def getheaders(self):
                return [("Content-Type", "text/html")]

            def read1(self, size):
                count = min(size, self.remaining)
                self.remaining -= count
                return b"x" * count

        calls = []
        deadline = time.monotonic() + 10
        with (
            patch("scanner.engine._connect_pinned", return_value=(FakeSocket(), [])),
            patch("scanner.engine.http.client.HTTPConnection", FakeConnection),
            patch("scanner.engine.http.client.HTTPResponse", FakeResponse),
        ):
            response, body, findings, truncated = _request_pinned(
                "http://public.example/path?token=one", ["93.184.216.34"], 5, deadline
            )

        self.assertEqual(response[0], 200)
        self.assertEqual(findings, [])
        self.assertTrue(truncated)
        self.assertEqual(len(body), MAX_HTML_BYTES)
        args, kwargs = calls[0].request_call
        self.assertEqual(args, ("GET", "/path?token=one"))
        self.assertNotIn("body", kwargs)

    def test_request_write_timeout_is_capped_by_remaining_scan_budget(self):
        from unittest.mock import patch

        class FakeSocket:
            def settimeout(self, value):
                timeouts.append(value)

        class FakeConnection:
            def __init__(self, host, port, timeout):
                self.sock = None

            def request(self, method, target, headers):
                timeouts_at_request.append(timeouts[-1])

            def close(self):
                pass

        class EmptyResponse:
            status = 200

            def __init__(self, stream, method):
                pass

            def begin(self):
                pass

            def getheaders(self):
                return [("Content-Type", "text/plain")]

        timeouts = []
        timeouts_at_request = []
        with (
            patch("scanner.engine._connect_pinned", return_value=(FakeSocket(), [])),
            patch("scanner.engine.http.client.HTTPConnection", FakeConnection),
            patch("scanner.engine.http.client.HTTPResponse", EmptyResponse),
            patch("scanner.engine.time.monotonic", return_value=10.0),
        ):
            _request_pinned("http://public.example/", ["93.184.216.34"], 5, 13.0)

        self.assertEqual(timeouts_at_request, [3.0])

    def test_system_dns_resolution_is_timed_and_bounded(self):
        from unittest.mock import patch

        def slow_resolver(host, port, **kwargs):
            time.sleep(0.05)
            return ["93.184.216.34"]

        with patch("scanner.engine._SYSTEM_RESOLVER", slow_resolver):
            with self.assertRaises(HostResolutionError):
                resolve_public_addresses("slow.example", 443, resolver=slow_resolver, timeout=0.005)
        time.sleep(0.06)

    def test_page_reader_accepts_only_html_and_skips_redirect_bodies(self):
        self.assertTrue(_reads_html({"content-type": "text/html; charset=utf-8"}, 200))
        self.assertFalse(_reads_html({"content-type": "application/pdf"}, 200))
        self.assertFalse(_reads_html({"content-type": "text/html"}, 302))
        self.assertFalse(_reads_html({"content-type": "text/html", "content-encoding": "gzip"}, 200))

    def test_failed_tls_handshake_still_returns_a_complete_scanner_result_shape(self):
        from unittest.mock import patch

        with patch("scanner.engine._connect_pinned", return_value=(None, [{"category": "certificate"}])):
            result = _request_pinned("https://example.com/", [], 1, time.monotonic() + 1)
        self.assertEqual(len(result), 4)
        self.assertIsNone(result[0])
        self.assertEqual(result[2][0]["category"], "certificate")

    def test_slowly_trickled_response_header_obeys_absolute_deadline(self):
        reader_socket, writer_socket = socket.socketpair()

        def trickle():
            try:
                for byte in b"HTTP/1.1 200 OK":
                    writer_socket.send(bytes([byte]))
                    time.sleep(0.03)
            except OSError:
                pass
            finally:
                writer_socket.close()

        sender = threading.Thread(target=trickle, daemon=True)
        sender.start()
        started = time.monotonic()
        stream = _DeadlineFile(reader_socket, started + 0.09)
        try:
            with self.assertRaises(ScanDeadlineExceeded):
                stream.readline(100)
            self.assertLess(time.monotonic() - started, 0.2)
        finally:
            stream.close()
            reader_socket.close()
            sender.join(timeout=1)

    def test_response_headers_have_a_total_size_limit(self):
        reader_socket, writer_socket = socket.socketpair()
        sender = threading.Thread(
            target=lambda: writer_socket.sendall(b"x" * (64 * 1024 + 1)), daemon=True
        )
        try:
            sender.start()
            stream = _DeadlineFile(reader_socket, time.monotonic() + 1)
            with self.assertRaises(http.client.HTTPException):
                stream.readline(64 * 1024 + 1)
        finally:
            reader_socket.close()
            writer_socket.close()
            sender.join(timeout=1)

    def test_deadline_response_adapter_parses_http_and_preserves_body(self):
        reader_socket, writer_socket = socket.socketpair()
        try:
            writer_socket.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 11\r\n\r\nhello world"
            )
            response = http.client.HTTPResponse(
                _DeadlineSocket(reader_socket, time.monotonic() + 1), method="GET"
            )
            response.begin()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read1(64), b"hello world")
        finally:
            reader_socket.close()
            writer_socket.close()

    def test_flags_password_form_posting_to_an_unrelated_site(self):
        findings = credential_form_findings(
            '<form action="https://collect.evil.test/login"><input type="password"></form>',
            "https://bank.example/",
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["group"], "credential_form")

    def test_does_not_flag_same_site_or_noncredential_forms(self):
        findings = credential_form_findings(
            '<form action="/login"><input type="password"></form>'
            '<form action="https://collect.evil.test/feedback"><input type="email"></form>',
            "https://bank.example/",
        )
        self.assertEqual(findings, [])

    def test_conservative_host_check_catches_different_sites_under_unlisted_suffix(self):
        findings = credential_form_findings(
            '<form action="https://collector.attacker.co.nz/login"><input type="password"></form>',
            "https://victim.co.nz/",
        )
        self.assertEqual(len(findings), 1)

    def test_invalid_password_form_action_is_reported_without_following_it(self):
        findings = credential_form_findings(
            '<form action="javascript:steal()"><input type="password"></form>',
            "https://bank.example/",
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")

    def test_dns_failure_is_unable_to_check_not_a_private_redirect_finding(self):
        from unittest.mock import patch

        with patch("scanner.engine.resolve_public_addresses", side_effect=HostResolutionError("dns")):
            result = scan_url("https://public.example/")
        self.assertFalse(result["complete"])
        self.assertEqual(result["error"], "host_resolution_failed")
        self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()
