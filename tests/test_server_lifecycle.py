import asyncio
import os
import socket
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from solvetls.connection import ClientConnection
from solvetls.server import SolveTLS
from tests.support import certificate_files

ENTRYPOINT = Path(__file__).resolve().parents[1] / "main.py"


class ServerLifecycleTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.server = SolveTLS(*certificate_files())

    async def test_close_waits_for_active_handler_before_returning(self):
        entered, release = asyncio.Event(), asyncio.Event()

        async def handler(_reader, _writer):
            entered.set()
            await release.wait()

        writer = Mock()
        writer.is_closing.return_value = False
        with patch.object(self.server, "_handle_client", side_effect=handler):
            self.server._accept_client(Mock(), writer)
            await entered.wait()
            closing = asyncio.create_task(self.server.close())
            try:
                await asyncio.sleep(0)
                self.assertFalse(closing.done())
                writer.transport.abort.assert_not_called()
            finally:
                release.set()
                await closing
        writer.close.assert_called_once()
        self.assertFalse(self.server._clients)
        await self.server.close()

    async def test_close_aborts_stalled_clients_after_grace_period(self):
        entered, cancelled = asyncio.Event(), asyncio.Event()

        async def handler(_reader, _writer):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        writer = Mock()
        with (
            patch.object(self.server, "_handle_client", side_effect=handler),
            patch("solvetls.server.SHUTDOWN_TIMEOUT", 0.01),
        ):
            self.server._accept_client(Mock(), writer)
            await entered.wait()
            await asyncio.wait_for(self.server.close(), 1)
        self.assertTrue(cancelled.is_set())
        writer.transport.abort.assert_called_once()
        self.assertFalse(self.server._clients)

    async def test_cancelling_close_caller_does_not_abandon_cleanup(self):
        entered, release = asyncio.Event(), asyncio.Event()

        async def handler(_reader, _writer):
            entered.set()
            await release.wait()

        writer = Mock()
        with patch.object(self.server, "_handle_client", side_effect=handler):
            self.server._accept_client(Mock(), writer)
            await entered.wait()
            closing = asyncio.create_task(self.server.close())
            await asyncio.sleep(0)
            closing.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await closing
            self.assertFalse(self.server._close_task.done())
            release.set()
            await asyncio.wait_for(self.server.close(), 1)
        self.assertFalse(self.server._clients)

    async def test_shutdown_refuses_new_clients(self):
        await self.server.close()
        writer = Mock()
        self.server._accept_client(Mock(), writer)
        writer.close.assert_called_once()
        self.assertFalse(self.server._clients)

    async def test_close_waits_for_in_progress_bind_and_closes_result(self):
        entered, release = asyncio.Event(), asyncio.Event()
        listener = Mock(sockets=[], start_serving=AsyncMock(), wait_closed=AsyncMock())

        async def bind(*_args, **_kwargs):
            entered.set()
            await release.wait()
            return listener

        with patch("solvetls.server.start_server", side_effect=bind):
            starting = asyncio.create_task(self.server.start("127.0.0.1", 0))
            await entered.wait()
            closing = asyncio.create_task(self.server.close())
            await asyncio.sleep(0)
            self.assertFalse(closing.done())
            release.set()
            await asyncio.gather(starting, closing)
        listener.close.assert_called_once()
        listener.wait_closed.assert_awaited_once()
        self.assertIsNone(self.server._server)

    async def test_old_serving_task_does_not_close_restarted_listener(self):
        entered, release = asyncio.Event(), asyncio.Event()

        async def serve_old():
            entered.set()
            await release.wait()

        old = Mock(
            sockets=[],
            start_serving=AsyncMock(),
            wait_closed=AsyncMock(),
            serve_forever=AsyncMock(side_effect=serve_old),
        )
        new = Mock(sockets=[], start_serving=AsyncMock(), wait_closed=AsyncMock())
        with patch("solvetls.server.start_server", side_effect=[old, new]):
            await self.server.start("127.0.0.1", 0)
            serving = asyncio.create_task(self.server.serve_forever())
            await entered.wait()
            await self.server.close()
            await self.server.start("127.0.0.1", 0)
            release.set()
            await asyncio.wait_for(serving, 1)
            self.assertIs(self.server._server, new)
            new.close.assert_not_called()
            await self.server.close()

    async def test_duplicate_serve_forever_does_not_stop_existing_server(self):
        entered = asyncio.Event()

        async def serve():
            entered.set()
            await asyncio.Event().wait()

        listener = Mock(
            sockets=[],
            start_serving=AsyncMock(),
            wait_closed=AsyncMock(),
            serve_forever=AsyncMock(side_effect=serve),
        )
        with patch("solvetls.server.start_server", return_value=listener):
            await self.server.start("127.0.0.1", 0)
            serving = asyncio.create_task(self.server.serve_forever())
            await entered.wait()
            try:
                with self.assertRaisesRegex(RuntimeError, "already running"):
                    await self.server.serve_forever()
                listener.close.assert_not_called()
            finally:
                serving.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await serving

    async def test_http_bind_failure_rolls_back_tls_and_allows_retry(self):
        old_tls = Mock(sockets=[], start_serving=AsyncMock(), wait_closed=AsyncMock())
        new_tls = Mock(sockets=[], start_serving=AsyncMock(), wait_closed=AsyncMock())
        http = Mock(sockets=[], start_serving=AsyncMock(), wait_closed=AsyncMock())
        with patch(
            "solvetls.server.start_server",
            side_effect=[old_tls, OSError("HTTP port unavailable"), new_tls, http],
        ):
            with self.assertRaisesRegex(OSError, "HTTP port unavailable"):
                await self.server.start("127.0.0.1", 8443, http_port=8080)
            old_tls.close.assert_called_once()
            old_tls.wait_closed.assert_awaited_once()
            self.assertIsNone(self.server._server)
            self.assertIsNone(self.server._http_server)
            await self.server.start("127.0.0.1", 8443, http_port=8080)
            self.assertIs(self.server._server, new_tls)
            self.assertIs(self.server._http_server, http)
            await self.server.close()
        new_tls.wait_closed.assert_awaited_once()
        http.wait_closed.assert_awaited_once()

    async def test_http_start_failure_closes_both_listeners(self):
        tls = Mock(sockets=[], start_serving=AsyncMock(), wait_closed=AsyncMock())
        http = Mock(
            sockets=[],
            start_serving=AsyncMock(side_effect=OSError("HTTP listen failed")),
            wait_closed=AsyncMock(),
        )
        with (
            patch("solvetls.server.start_server", side_effect=[tls, http]),
            self.assertRaisesRegex(OSError, "HTTP listen failed"),
        ):
            await self.server.start("127.0.0.1", 8443, http_port=8080)
        for listener in (tls, http):
            listener.close.assert_called_once()
            listener.wait_closed.assert_awaited_once()
        self.assertIsNone(self.server._server)
        self.assertIsNone(self.server._http_server)

    async def test_close_waits_for_http_bind_and_closes_both_results(self):
        entered, release = asyncio.Event(), asyncio.Event()
        tls = Mock(sockets=[], start_serving=AsyncMock(), wait_closed=AsyncMock())
        http = Mock(sockets=[], start_serving=AsyncMock(), wait_closed=AsyncMock())

        async def bind(_callback, *, port, **_kwargs):
            if port == 8080:
                entered.set()
                await release.wait()
                return http
            return tls

        with patch("solvetls.server.start_server", side_effect=bind):
            starting = asyncio.create_task(
                self.server.start("127.0.0.1", 8443, http_port=8080)
            )
            pending = [starting]
            try:
                await asyncio.wait_for(entered.wait(), 1)
                closing = asyncio.create_task(self.server.close())
                pending.append(closing)
                await asyncio.sleep(0)
                self.assertFalse(closing.done())
            finally:
                release.set()
                await asyncio.wait_for(asyncio.gather(*pending), 1)
        for listener in (tls, http):
            listener.close.assert_called_once()
            listener.wait_closed.assert_awaited_once()
        self.assertIsNone(self.server._server)
        self.assertIsNone(self.server._http_server)

    async def test_cancelled_startup_does_not_interrupt_bind_rollback(self):
        entered, release = asyncio.Event(), asyncio.Event()
        interrupted = asyncio.Event()

        async def wait_closed():
            entered.set()
            try:
                await release.wait()
            except asyncio.CancelledError:
                interrupted.set()
                raise

        old_tls = Mock(
            sockets=[],
            start_serving=AsyncMock(),
            wait_closed=AsyncMock(side_effect=wait_closed),
        )
        new_tls = Mock(sockets=[], start_serving=AsyncMock(), wait_closed=AsyncMock())
        http = Mock(sockets=[], start_serving=AsyncMock(), wait_closed=AsyncMock())
        with patch(
            "solvetls.server.start_server",
            side_effect=[old_tls, OSError("HTTP port unavailable"), new_tls, http],
        ):
            starting = asyncio.create_task(
                self.server.start("127.0.0.1", 8443, http_port=8080)
            )
            closing = None
            try:
                await asyncio.wait_for(entered.wait(), 1)
                starting.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(starting, 1)
                self.assertFalse(interrupted.is_set())
                closing = asyncio.create_task(self.server.close())
                await asyncio.sleep(0)
                self.assertFalse(closing.done())
            finally:
                release.set()
                await asyncio.wait_for(self.server.close(), 1)
                await asyncio.gather(
                    starting,
                    *([closing] if closing is not None else []),
                    return_exceptions=True,
                )
            old_tls.wait_closed.assert_awaited_once()
            self.assertIsNone(self.server._server)
            self.assertIsNone(self.server._http_server)
            await self.server.start("127.0.0.1", 8443, http_port=8080)
            self.assertIs(self.server._server, new_tls)
            self.assertIs(self.server._http_server, http)
            await self.server.close()


@unittest.skipUnless(
    os.getenv("SOLVETLS_NETWORK_TESTS") == "1",
    "Set SOLVETLS_NETWORK_TESTS=1 to run localhost socket tests",
)
class NetworkLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_unflushed_client_close_releases_socket_and_server(self):
        server = SolveTLS(*certificate_files())
        loop = asyncio.get_running_loop()
        accepted = loop.create_future()
        handler_done = asyncio.Event()

        async def handler(reader, writer):
            writer.get_extra_info("socket").setsockopt(
                socket.SOL_SOCKET, socket.SO_SNDBUF, 1024
            )
            # Exercise TCP cleanup with queued bytes and a peer that never reads.
            writer.write(b"x" * (2 * 1024 * 1024))
            accepted.set_result(writer)
            client = ClientConnection(reader, writer, server._tls_context)
            try:
                await client.close()
            finally:
                handler_done.set()

        peer = socket.socket()
        peer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        peer.setblocking(False)
        writer = None
        with (
            patch.object(server, "_handle_client", side_effect=handler),
            patch("solvetls.connection.CLOSE_DRAIN_TIMEOUT", 0.01),
            patch("solvetls.connection.TRANSPORT_CLOSE_TIMEOUT", 0.01),
        ):
            try:
                await server.start("127.0.0.1", 0)
                await loop.sock_connect(peer, server._server.sockets[0].getsockname())
                writer = await asyncio.wait_for(accepted, 2)
                self.assertGreater(writer.transport.get_write_buffer_size(), 0)
                await asyncio.wait_for(handler_done.wait(), 2)
                await asyncio.wait_for(server.close(), 2)
                self.assertEqual(writer.get_extra_info("socket").fileno(), -1)
                self.assertFalse(server._clients)
            finally:
                if writer is not None:
                    writer.transport.abort()
                peer.close()
                await asyncio.wait_for(server.close(), 2)

    async def test_sigterm_runs_cli_cleanup_and_exits_successfully(self):
        certificate, key = certificate_files()
        environment = {
            **os.environ,
            "SOLVETLS_HOST": "127.0.0.1",
            "SOLVETLS_PORT": "0",
            "SOLVETLS_HTTP_PORT": "",
            "SOLVETLS_CERT": certificate,
            "SOLVETLS_KEY": key,
            "SOLVETLS_MONGODB_URL": "",
            "SOLVETLS_LOG_LEVEL": "INFO",
        }
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-B",
            str(ENTRYPOINT),
            env=environment,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        output = bytearray()
        try:
            async with asyncio.timeout(10):
                while b"Serving on 127.0.0.1:0" not in output:
                    line = await process.stdout.readline()
                    self.assertTrue(line, output.decode())
                    output.extend(line)
                process.terminate()
                tail, _ = await process.communicate()
                output.extend(tail)
            self.assertEqual(process.returncode, 0, output.decode())
            self.assertNotIn(b"Traceback", output)
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()

    async def test_cancel_serving_closes_idle_socket_and_allows_restart(self):
        server = SolveTLS(*certificate_files())
        await server.start("127.0.0.1", 0)
        self.addAsyncCleanup(server.close)
        port = server._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        serving = asyncio.create_task(server.serve_forever())
        try:
            await asyncio.sleep(0)
            with patch("solvetls.server.SHUTDOWN_TIMEOUT", 0.01):
                serving.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(serving, 2)
            self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
            self.assertFalse(server._clients)
            self.assertIsNone(server._server)
            await server.start("127.0.0.1", port)
            self.assertTrue(server._server.is_serving())
        finally:
            writer.close()
            await writer.wait_closed()
            serving.cancel()
            await asyncio.gather(serving, return_exceptions=True)
