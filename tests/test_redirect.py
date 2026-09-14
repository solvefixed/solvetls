import asyncio
import json
import os
import socket
import ssl
import unittest
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import urlsplit

from solvetls.http1 import MAX_HEAD_SIZE, HTTP1Error, parse_request
from solvetls.redirect import handle_redirect, redirect_location
from solvetls.server import SolveTLS
from tests.support import certificate_files


def request_head(target="/", *, host="localhost", method="GET"):
    return f"{method} {target} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii")


def response_parts(raw):
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        raise AssertionError("Incomplete HTTP response head")
    status, *fields = head.decode("ascii").split("\r\n")
    headers = {}
    for field in fields:
        name, value = field.split(":", 1)
        headers[name.lower()] = value.strip()
    return int(status.split(" ", 2)[1]), headers, body


class RedirectLocationTests(unittest.TestCase):
    def test_origin_targets_keep_path_query_and_use_configured_https_port(self):
        cases = [
            ("/", "example.com", 443, "https://example.com/"),
            ("/path?", "example.com", 443, "https://example.com/path?"),
            (
                "/a%2fb?x=%FF&next=/?",
                "example.com:8080",
                8443,
                "https://example.com:8443/a%2fb?x=%FF&next=/?",
            ),
            (
                "//other.example/path",
                "example.com:80",
                443,
                "https://example.com//other.example/path",
            ),
            (
                "/ipv6?q=1",
                "[2001:db8::1]:8080",
                8443,
                "https://[2001:db8::1]:8443/ipv6?q=1",
            ),
        ]
        for target, host, port, expected in cases:
            with self.subTest(target=target, host=host, port=port):
                request = parse_request(request_head(target, host=host))
                self.assertEqual(redirect_location(request, port), expected)

    def test_absolute_http_targets_use_their_own_authority(self):
        for target, expected in [
            ("http://example.com:8080/path?x=1", "https://example.com:8443/path?x=1"),
            ("https://example.com:9443/path", "https://example.com:8443/path"),
            ("http://[2001:db8::1]:80?q=%2f", "https://[2001:db8::1]:8443/?q=%2f"),
        ]:
            with self.subTest(target=target):
                request = parse_request(request_head(target, host="ignored.example"))
                self.assertEqual(redirect_location(request, 8443), expected)

    def test_targets_without_a_redirect_destination_have_http_errors(self):
        for method, target, host, status in [
            ("CONNECT", "example.com:443", "example.com", 501),
            ("OPTIONS", "*", "example.com", 400),
            ("GET", "ftp://example.com/path", "example.com", 400),
            ("GET", "/", "", 400),
        ]:
            with self.subTest(method=method, target=target, host=host):
                request = parse_request(request_head(target, host=host, method=method))
                with self.assertRaises(HTTP1Error) as caught:
                    redirect_location(request, 443)
                self.assertEqual(caught.exception.status_code, status)


class RedirectWriter:
    def __init__(self):
        self.output = bytearray()
        self.eof_written = asyncio.Event()
        self.closed = False
        self.transport = Mock()

    def write(self, data):
        self.output.extend(data)

    async def drain(self):
        await asyncio.sleep(0)

    def can_write_eof(self):
        return True

    def write_eof(self):
        self.eof_written.set()

    def close(self):
        self.closed = True

    def is_closing(self):
        return self.closed

    async def wait_closed(self):
        pass

    def get_extra_info(self, name):
        return {"peername": ("127.0.0.1", 12345)}.get(name)


class RedirectHandlerTests(unittest.IsolatedAsyncioTestCase):
    async def exchange(self, wire):
        reader = asyncio.StreamReader()
        reader.feed_data(wire)
        reader.feed_eof()
        writer = RedirectWriter()
        async with asyncio.timeout(1):
            await handle_redirect(reader, writer, 8443)
        self.assertTrue(writer.closed)
        return response_parts(bytes(writer.output))

    async def test_post_redirects_from_head_without_waiting_for_request_body(self):
        wire = (
            b"POST /submit?x=1 HTTP/1.1\r\nHost: example.com:80\r\n"
            b"Content-Length: 1000000\r\nExpect: 100-continue\r\n\r\n"
        )
        reader, writer = asyncio.StreamReader(), RedirectWriter()
        reader.feed_data(wire)
        handling = asyncio.create_task(handle_redirect(reader, writer, 8443))
        try:
            await asyncio.wait_for(writer.eof_written.wait(), 1)
            self.assertFalse(handling.done(), "The peer has not finished its body")
            status, headers, body = response_parts(bytes(writer.output))
            self.assertEqual(status, 308)
            self.assertEqual(headers["location"], "https://example.com:8443/submit?x=1")
            self.assertEqual(headers["connection"].lower(), "close")
            self.assertEqual(int(headers["content-length"]), len(body))
        finally:
            reader.feed_eof()
            await asyncio.wait_for(handling, 1)
        self.assertTrue(writer.closed)

    async def test_fragmented_head_gets_one_complete_redirect(self):
        reader, writer = asyncio.StreamReader(), RedirectWriter()
        handling = asyncio.create_task(handle_redirect(reader, writer, 443))
        wire = request_head("/fragmented?x=%2f")
        try:
            for chunk in (wire[:2], wire[2:-1], wire[-1:]):
                reader.feed_data(chunk)
                await asyncio.sleep(0)
            reader.feed_eof()
            async with asyncio.timeout(1):
                await handling
        finally:
            handling.cancel()
            await asyncio.gather(handling, return_exceptions=True)
        status, headers, _ = response_parts(bytes(writer.output))
        self.assertEqual(status, 308)
        self.assertEqual(headers["location"], "https://localhost/fragmented?x=%2f")
        self.assertTrue(writer.closed)

    async def test_invalid_host_and_header_injection_do_not_get_a_location(self):
        for wire in [
            request_head(host="bad host"),
            request_head(host="user@localhost"),
            request_head(host="localhost:99999"),
            b"GET / HTTP/1.1\r\nHost: localhost\r\nHost: other.example\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: localhost\nLocation: https://evil.example/\r\n\r\n",
        ]:
            with self.subTest(wire=wire):
                status, headers, _ = await self.exchange(wire)
                self.assertEqual(status, 400)
                self.assertNotIn("location", headers)

    async def test_oversized_target_and_fields_are_rejected(self):
        for wire, expected in [
            (b"GET /" + b"x" * MAX_HEAD_SIZE, 414),
            (
                b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Large: "
                + b"x" * MAX_HEAD_SIZE,
                431,
            ),
        ]:
            with self.subTest(expected=expected):
                status, headers, _ = await self.exchange(wire)
                self.assertEqual(status, expected)
                self.assertNotIn("location", headers)

    async def test_stalled_incomplete_head_times_out_and_closes(self):
        reader, writer = asyncio.StreamReader(), RedirectWriter()
        reader.feed_data(b"GET / HTTP/1.1\r\nHost:")
        with (
            patch("solvetls.redirect.REQUEST_TIMEOUT", 0.01),
            patch("solvetls.redirect.DRAIN_TIMEOUT", 0.01),
        ):
            async with asyncio.timeout(1):
                await handle_redirect(reader, writer, 443)
        status, headers, _ = response_parts(bytes(writer.output))
        self.assertEqual(status, 408)
        self.assertNotIn("location", headers)
        self.assertTrue(writer.closed)

    async def test_blocked_response_and_transport_close_are_bounded(self):
        async def stall():
            await asyncio.Event().wait()

        reader, writer = asyncio.StreamReader(), RedirectWriter()
        reader.feed_data(request_head())
        writer.drain = AsyncMock(side_effect=stall)
        writer.wait_closed = AsyncMock(side_effect=stall)
        with (
            patch("solvetls.redirect.REQUEST_TIMEOUT", 0.01),
            patch("solvetls.redirect.CLOSE_TIMEOUT", 0.01),
        ):
            async with asyncio.timeout(1):
                await handle_redirect(reader, writer, 443)
        self.assertTrue(writer.closed)
        writer.transport.abort.assert_called_once()

    async def test_cancellation_releases_the_http_writer(self):
        reader, writer = asyncio.StreamReader(), RedirectWriter()
        handling = asyncio.create_task(handle_redirect(reader, writer, 443))
        await asyncio.sleep(0)
        handling.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await handling
        self.assertTrue(writer.closed)


@unittest.skipUnless(
    os.getenv("SOLVETLS_NETWORK_TESTS") == "1",
    "Set SOLVETLS_NETWORK_TESTS=1 to run localhost socket tests",
)
class NetworkRedirectTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.certificate, key = certificate_files()
        self.server = SolveTLS(self.certificate, key)
        self.addAsyncCleanup(self.server.close)
        await self.server.start("127.0.0.1", 0, http_port=0)
        self.tls_port = self.server._server.sockets[0].getsockname()[1]
        self.http_port = self.server._http_server.sockets[0].getsockname()[1]

    async def exchange(self, wire, *, https=False):
        arguments = {}
        port = self.http_port
        if https:
            context = ssl.create_default_context(cafile=self.certificate)
            context.set_alpn_protocols(["http/1.1"])
            arguments = {"ssl": context, "server_hostname": "localhost"}
            port = self.tls_port
        async with asyncio.timeout(3):
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", port, **arguments
            )
            try:
                writer.write(wire)
                await writer.drain()
                return response_parts(await reader.read())
            finally:
                writer.close()
                await writer.wait_closed()

    async def test_redirect_points_to_active_tls_listener_and_fingerprint(self):
        target = "/probe%2fpath?x=1&next=/?"
        with patch("solvetls.server.save_fingerprint", new_callable=AsyncMock) as save:
            status, headers, _ = await self.exchange(
                request_head(target, host=f"localhost:{self.http_port}")
            )
            self.assertEqual(status, 308)
            location = f"https://localhost:{self.tls_port}{target}"
            self.assertEqual(headers["location"], location)
            save.assert_not_awaited()
            destination = urlsplit(location)
            status, _, body = await self.exchange(
                request_head(
                    destination.path + "?" + destination.query,
                    host=destination.netloc,
                ),
                https=True,
            )
            self.assertEqual(status, 200)
            report = json.loads(body)
            self.assertEqual(report["method"], "GET")
            self.assertIsNotNone(report["tls"])
            self.assertEqual(report["http1"]["path"], target)
            await self.server.close()
            save.assert_awaited_once()

    async def test_close_stops_idle_http_and_tls_clients_and_allows_restart(self):
        peers = []
        try:
            for port in (self.http_port, self.tls_port):
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                peers.append((reader, writer))
            with patch("solvetls.server.SHUTDOWN_TIMEOUT", 0.01):
                async with asyncio.timeout(2):
                    await self.server.close()
            for reader, _ in peers:
                self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
            self.assertFalse(self.server._clients)
            self.assertIsNone(self.server._server)
            self.assertIsNone(self.server._http_server)
            await self.server.start(
                "127.0.0.1", self.tls_port, http_port=self.http_port
            )
            status, headers, _ = await self.exchange(request_head())
            self.assertEqual(status, 308)
            self.assertEqual(headers["location"], f"https://localhost:{self.tls_port}/")
        finally:
            for _, writer in peers:
                writer.close()
                await writer.wait_closed()

    async def test_http_bind_failure_releases_the_new_tls_listener(self):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            tls_port = reservation.getsockname()[1]
        other = SolveTLS(*certificate_files())
        self.addAsyncCleanup(other.close)
        with self.assertRaises(OSError):
            await other.start("127.0.0.1", tls_port, http_port=self.http_port)
        self.assertIsNone(other._server)
        self.assertIsNone(other._http_server)
        # Rebinding the exact TLS port proves the partial startup released it.
        await other.start("127.0.0.1", tls_port, http_port=0)
        self.assertTrue(other._server.is_serving())
        self.assertTrue(other._http_server.is_serving())
        status, _, _ = await self.exchange(request_head())
        self.assertEqual(status, 308)

    async def test_cancelling_serve_forever_closes_both_listeners_and_idle_http(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.http_port)
        listeners = (self.server._server, self.server._http_server)
        serving = asyncio.create_task(self.server.serve_forever())
        try:
            await asyncio.sleep(0)
            with patch("solvetls.server.SHUTDOWN_TIMEOUT", 0.01):
                serving.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(serving, 2)
            self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
            self.assertFalse(self.server._clients)
            self.assertIsNone(self.server._server)
            self.assertIsNone(self.server._http_server)
            self.assertTrue(all(not listener.is_serving() for listener in listeners))
        finally:
            writer.close()
            await writer.wait_closed()
            serving.cancel()
            await asyncio.gather(serving, return_exceptions=True)


if __name__ == "__main__":
    unittest.main()
