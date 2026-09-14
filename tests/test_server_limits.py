import asyncio
import socket
import unittest
from unittest.mock import AsyncMock, Mock, patch

from solvetls.http1 import HTTP1Error, parse_request
from solvetls.http2.session import HTTP2_PREFACE
from solvetls.report import build_report
from solvetls.server import SolveTLS
from tests.http2 import frame, request, response, settings_frame
from tests.support import certificate_files, exchange, h2_request


def make_client():
    return Mock(
        peername=("127.0.0.1", 12345),
        sockname=("127.0.0.1", 443),
        syn_packet=None,
        client_hello=None,
        http_version="HTTP/1.1",
        http1=parse_request(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        http1_raw_head=None,
        http2=None,
        do_tls_handshake=AsyncMock(),
        handle_http=AsyncMock(),
        send_response=AsyncMock(),
        close=AsyncMock(),
    )


class ServerLimitTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.server = SolveTLS(*certificate_files())

    def assert_busy(self, client):
        client.send_response.assert_awaited_once()
        fields = client.send_response.await_args.kwargs
        self.assertEqual(fields["status_code"], 503)
        self.assertEqual(fields["content"], b"")
        self.assertEqual(fields["headers"]["cache-control"], "no-store")
        client.close.assert_awaited_once()

    async def test_client_limit_covers_tls_and_redirect_before_creating_tasks(self):
        release = asyncio.Event()

        async def handler(*_args):
            await release.wait()

        self.server._https_ports[socket.AF_INET] = 443
        redirect_writer = Mock()
        redirect_writer.get_extra_info.return_value.family = socket.AF_INET
        with (
            patch("solvetls.server.MAX_CLIENTS", 2),
            patch.object(self.server, "_handle_client", side_effect=handler) as tls,
            patch("solvetls.server.handle_redirect", side_effect=handler) as redirect,
            patch("solvetls.server.create_task", wraps=asyncio.create_task) as create,
            patch("solvetls.server.ClientConnection") as connection,
        ):
            self.server._accept_client(Mock(), Mock())
            self.server._accept_client(Mock(), redirect_writer, redirect=True)
            tasks = tuple(self.server._clients)
            try:
                # Admission must work before either accepted task starts running.
                for is_redirect in (False, True):
                    rejected = Mock()
                    self.server._accept_client(Mock(), rejected, redirect=is_redirect)
                    rejected.transport.abort.assert_called_once()
                    rejected.get_extra_info.assert_not_called()
                self.assertEqual(create.call_count, 2)
                self.assertEqual(tls.call_count, 1)
                self.assertEqual(redirect.call_count, 1)
                self.assertEqual(tuple(self.server._clients), tasks)
                connection.assert_not_called()
            finally:
                release.set()
                await asyncio.wait_for(asyncio.gather(*tasks), 1)
        self.assertFalse(self.server._clients)

    async def test_client_slot_returns_after_handler_failure_or_cancellation(self):
        for cancelled in (False, True):
            with self.subTest(cancelled=cancelled):
                entered, release = asyncio.Event(), asyncio.Event()
                calls = 0

                async def handler(
                    _reader, _writer, *, entered=entered, release=release
                ):
                    nonlocal calls
                    calls += 1
                    if calls == 1:
                        entered.set()
                        await release.wait()
                        raise RuntimeError("handler failed")

                with (
                    patch("solvetls.server.MAX_CLIENTS", 1),
                    patch.object(self.server, "_handle_client", side_effect=handler),
                    patch("solvetls.server.logger"),
                ):
                    self.server._accept_client(Mock(), Mock())
                    task = next(iter(self.server._clients))
                    try:
                        await asyncio.wait_for(entered.wait(), 1)
                        if cancelled:
                            task.cancel()
                        else:
                            release.set()
                        await asyncio.wait_for(
                            asyncio.gather(task, return_exceptions=True), 1
                        )
                        self.assertFalse(self.server._clients)
                        replacement = Mock()
                        self.server._accept_client(Mock(), replacement)
                        replacement.transport.abort.assert_not_called()
                        await asyncio.wait_for(asyncio.gather(*self.server._clients), 1)
                        self.assertEqual(calls, 2)
                    finally:
                        task.cancel()
                        release.set()
                        await asyncio.gather(task, return_exceptions=True)

    async def test_busy_reports_skip_build_and_storage_for_valid_and_invalid_http(self):
        entered = asyncio.Event()

        async def blocked_response(**_kwargs):
            entered.set()
            await asyncio.Event().wait()

        first, valid, invalid, replacement = (make_client() for _ in range(4))
        first.send_response.side_effect = blocked_response
        invalid.handle_http.side_effect = HTTP1Error("Invalid HTTP framing")
        with (
            patch("solvetls.server.MAX_REPORTS", 1),
            patch(
                "solvetls.server.ClientConnection",
                side_effect=[first, valid, invalid, replacement],
            ),
            patch("solvetls.server.build_report", wraps=build_report) as build,
            patch("solvetls.server.save_fingerprint", new_callable=AsyncMock) as save,
        ):
            task = asyncio.create_task(self.server._handle_client(Mock(), Mock()))
            try:
                await asyncio.wait_for(entered.wait(), 1)
                for busy in (valid, invalid):
                    await asyncio.wait_for(
                        self.server._handle_client(Mock(), Mock()), 1
                    )
                    self.assert_busy(busy)
                    build.assert_called_once_with(first)
                    save.assert_not_awaited()
                    self.assertFalse(task.done())
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            await self.server._handle_client(Mock(), Mock())
            self.assertEqual(
                replacement.send_response.await_args.kwargs["status_code"], 200
            )
            self.assertEqual(
                [call.args[0] for call in build.call_args_list], [first, replacement]
            )
            save.assert_awaited_once()

    async def test_report_slot_stays_reserved_through_close_and_storage(self):
        for stage in ("close", "storage"):
            with self.subTest(stage=stage):
                entered, release = asyncio.Event(), asyncio.Event()

                async def blocked(*_args, entered=entered, release=release, **_kwargs):
                    entered.set()
                    await release.wait()

                first, busy, replacement = (make_client() for _ in range(3))
                if stage == "close":
                    first.close.side_effect = blocked
                with (
                    patch("solvetls.server.MAX_REPORTS", 1),
                    patch(
                        "solvetls.server.ClientConnection",
                        side_effect=[first, busy, replacement],
                    ),
                    patch("solvetls.server.build_report", wraps=build_report) as build,
                    patch(
                        "solvetls.server.save_fingerprint", new_callable=AsyncMock
                    ) as save,
                ):
                    if stage == "storage":
                        save.side_effect = blocked
                    task = asyncio.create_task(
                        self.server._handle_client(Mock(), Mock())
                    )
                    try:
                        await asyncio.wait_for(entered.wait(), 1)
                        first.send_response.assert_awaited_once()
                        await asyncio.wait_for(
                            self.server._handle_client(Mock(), Mock()), 1
                        )
                        self.assert_busy(busy)
                        build.assert_called_once_with(first)
                        self.assertEqual(save.await_count, int(stage == "storage"))
                        self.assertFalse(task.done())
                    finally:
                        release.set()
                        await asyncio.wait_for(task, 1)
                    await self.server._handle_client(Mock(), Mock())
                    self.assertEqual(
                        replacement.send_response.await_args.kwargs["status_code"], 200
                    )
                    self.assertEqual(save.await_count, 2)

    async def test_client_limit_includes_handlers_waiting_for_storage(self):
        entered, release = asyncio.Event(), asyncio.Event()

        async def save(_report):
            entered.set()
            await release.wait()

        client = make_client()
        with (
            patch("solvetls.server.MAX_CLIENTS", 1),
            patch(
                "solvetls.server.ClientConnection", return_value=client
            ) as connection,
            patch("solvetls.server.save_fingerprint", side_effect=save),
        ):
            self.server._accept_client(Mock(), Mock())
            task = next(iter(self.server._clients))
            try:
                await asyncio.wait_for(entered.wait(), 1)
                client.close.assert_awaited_once()
                rejected = Mock()
                self.server._accept_client(Mock(), rejected)
                rejected.transport.abort.assert_called_once()
                connection.assert_called_once()
                self.assertFalse(task.done())
            finally:
                release.set()
                await asyncio.wait_for(task, 1)
        self.assertFalse(self.server._clients)

    async def test_report_slot_returns_after_build_send_close_and_storage_failures(
        self,
    ):
        for stage in ("build", "send", "close", "storage"):
            with self.subTest(stage=stage):
                first, replacement = make_client(), make_client()
                if stage == "send":
                    first.send_response.side_effect = ConnectionError("send failed")
                elif stage == "close":
                    first.close.side_effect = RuntimeError("close failed")
                with (
                    patch("solvetls.server.MAX_REPORTS", 1),
                    patch(
                        "solvetls.server.ClientConnection",
                        side_effect=[first, replacement],
                    ),
                    patch("solvetls.server.build_report", wraps=build_report) as build,
                    patch(
                        "solvetls.server.save_fingerprint", new_callable=AsyncMock
                    ) as save,
                ):
                    if stage == "build":
                        build.side_effect = [
                            ValueError("build failed"),
                            {"method": "GET"},
                        ]
                    elif stage == "storage":
                        save.side_effect = [RuntimeError("storage failed"), None]
                    result = await asyncio.gather(
                        self.server._handle_client(Mock(), Mock()),
                        return_exceptions=True,
                    )
                    if stage in ("close", "storage"):
                        self.assertIsInstance(result[0], RuntimeError)
                    else:
                        self.assertIsNone(result[0])
                    await self.server._handle_client(Mock(), Mock())
                    self.assertEqual(
                        replacement.send_response.await_args.kwargs["status_code"], 200
                    )
                    self.assertEqual(build.call_count, 2)
                    self.assertEqual(save.await_count, 2 if stage == "storage" else 1)

    async def test_report_slot_returns_when_close_or_storage_is_cancelled(self):
        for stage in ("close", "storage"):
            with self.subTest(stage=stage):
                entered = asyncio.Event()

                async def blocked(*_args, entered=entered, **_kwargs):
                    entered.set()
                    await asyncio.Event().wait()

                first, replacement = make_client(), make_client()
                if stage == "close":
                    first.close.side_effect = blocked
                with (
                    patch("solvetls.server.MAX_REPORTS", 1),
                    patch(
                        "solvetls.server.ClientConnection",
                        side_effect=[first, replacement],
                    ),
                    patch(
                        "solvetls.server.save_fingerprint", new_callable=AsyncMock
                    ) as save,
                ):
                    if stage == "storage":
                        save.side_effect = blocked
                    task = asyncio.create_task(
                        self.server._handle_client(Mock(), Mock())
                    )
                    try:
                        await asyncio.wait_for(entered.wait(), 1)
                    finally:
                        task.cancel()
                        await asyncio.gather(task, return_exceptions=True)
                    self.assertTrue(task.cancelled())
                    save.side_effect = None
                    await self.server._handle_client(Mock(), Mock())
                    self.assertEqual(
                        replacement.send_response.await_args.kwargs["status_code"], 200
                    )

    async def test_zero_window_http2_overload_finishes_without_building_another_report(
        self,
    ):
        built = asyncio.Event()

        def observe_build(client):
            report = build_report(client)
            built.set()
            return report

        # Unknown frames fit the capture limit and do not consume DATA flow credit.
        large_request = (
            HTTP2_PREFACE
            + settings_frame({4: 0})
            + frame(0xFE, b"x" * 60000) * 32
            + request()
        )
        busy_request = HTTP2_PREFACE + settings_frame({4: 0}) + request()
        with (
            patch("tests.support.SolveTLS", return_value=self.server),
            patch("solvetls.server.MAX_REPORTS", 1),
            patch("solvetls.server.build_report", side_effect=observe_build) as build,
            patch("solvetls.server.save_fingerprint", new_callable=AsyncMock) as save,
            patch("solvetls.connection.CLOSE_DRAIN_TIMEOUT", 0.01),
        ):
            first = asyncio.create_task(exchange(large_request, ("h2",)))
            try:
                await asyncio.wait_for(built.wait(), 3)
                self.assertFalse(first.done())
                headers, body = response(await exchange(busy_request, ("h2",)))
                self.assertEqual(headers[":status"], "503")
                self.assertEqual(headers["content-length"], "0")
                self.assertEqual(headers["cache-control"], "no-store")
                self.assertEqual(body, b"")
                build.assert_called_once()
                save.assert_not_awaited()
                self.assertFalse(first.done())
            finally:
                first.cancel()
                await asyncio.gather(first, return_exceptions=True)
            headers, _ = response(await exchange(h2_request(), ("h2",)))
            self.assertEqual(headers[":status"], "200")
            save.assert_awaited_once()
