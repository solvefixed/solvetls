import asyncio
import unittest
from unittest.mock import AsyncMock, Mock, patch

from pymongo import _csot

from main import main
from solvetls.storage import (
    CLOSE_TIMEOUT,
    INIT_TIMEOUT,
    close_storage,
    init_storage,
    save_fingerprint,
)


class StorageTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        for name, value in (("_client", None), ("_enabled", False)):
            state = patch(f"solvetls.storage.{name}", value)
            state.start()
            self.addCleanup(state.stop)

    async def test_main_does_not_serve_when_storage_initialization_fails(self):
        for failure in (
            TimeoutError("database timed out"),
            RuntimeError("database unavailable"),
            FileNotFoundError("database configuration missing"),
        ):
            with self.subTest(error=type(failure).__name__):
                server = Mock(
                    start=AsyncMock(), serve_forever=AsyncMock(), close=AsyncMock()
                )
                with (
                    patch("main.SolveTLS", return_value=server),
                    patch("main.MONGODB_URL", "mongodb://localhost/solvetls"),
                    patch("main.init_storage", side_effect=failure) as initialize,
                    self.assertRaises(type(failure)),
                ):
                    await main()
                initialize.assert_awaited_once_with("mongodb://localhost/solvetls")
                server.start.assert_not_awaited()
                server.serve_forever.assert_not_awaited()
                server.close.assert_awaited_once()

    async def test_main_serves_with_initialized_or_disabled_storage(self):
        for connection_string in ("mongodb://localhost/solvetls", ""):
            with self.subTest(connection_string=connection_string):
                server = Mock(
                    start=AsyncMock(), serve_forever=AsyncMock(), close=AsyncMock()
                )
                with (
                    patch("main.SolveTLS", return_value=server),
                    patch("main.MONGODB_URL", connection_string),
                    patch(
                        "main.init_storage", return_value=bool(connection_string)
                    ) as initialize,
                ):
                    await main()
                initialize.assert_awaited_once_with(connection_string)
                server.start.assert_awaited_once()
                server.serve_forever.assert_awaited_once()
                server.close.assert_awaited_once()

    async def test_main_closes_clients_before_storage_on_bind_failure(self):
        closed = []

        async def close_server():
            closed.append("server")

        async def close_database():
            closed.append("storage")

        server = Mock(
            start=AsyncMock(side_effect=OSError("port unavailable")),
            close=AsyncMock(side_effect=close_server),
        )
        with (
            patch("main.SolveTLS", return_value=server),
            patch("main.init_storage", new_callable=AsyncMock),
            patch("main.close_storage", side_effect=close_database),
            self.assertRaisesRegex(OSError, "port unavailable"),
        ):
            await main()
        self.assertEqual(closed, ["server", "storage"])

    async def test_main_passes_optional_http_redirect_port_to_server(self):
        for http_port in (None, 0, 80):
            with self.subTest(http_port=http_port):
                server = Mock(
                    start=AsyncMock(), serve_forever=AsyncMock(), close=AsyncMock()
                )
                with (
                    patch("main.SolveTLS", return_value=server),
                    patch("main.init_storage", new_callable=AsyncMock),
                    patch("main.close_storage", new_callable=AsyncMock),
                    patch("main.HOST_IP", "127.0.0.1"),
                    patch("main.PORT", 8443),
                    patch("main.HTTP_PORT", http_port),
                ):
                    await main()
                server.start.assert_awaited_once_with(
                    host="127.0.0.1", port=8443, http_port=http_port
                )

    async def test_reinitialization_closes_previous_client(self):
        first, second = Mock(close=AsyncMock()), Mock(close=AsyncMock())
        with (
            patch("solvetls.storage.AsyncMongoClient", side_effect=[first, second]),
            patch("solvetls.storage.init_beanie", new_callable=AsyncMock),
        ):
            await init_storage("mongodb://localhost/first")
            await init_storage("mongodb://localhost/second")
            first.close.assert_awaited_once()
            second.close.assert_not_awaited()
            self.assertFalse(await init_storage(""))
            second.close.assert_awaited_once()
            await close_storage()
            second.close.assert_awaited_once()

    async def test_close_disables_writes_without_blocking_loop(self):
        started, release = asyncio.Event(), asyncio.Event()
        remaining = []

        async def close_client():
            remaining.append(_csot.remaining())
            started.set()
            await release.wait()

        client = Mock(close=AsyncMock(side_effect=close_client))
        with (
            patch("solvetls.storage._enabled", True),
            patch("solvetls.storage._client", client),
            patch("solvetls.storage.Fingerprint") as model,
        ):
            task = asyncio.create_task(close_storage())
            try:
                await asyncio.wait_for(started.wait(), 1)
                await save_fingerprint({"method": "GET"})
                model.assert_not_called()
                self.assertFalse(task.done())
                await close_storage()
            finally:
                release.set()
                await task
        client.close.assert_awaited_once()
        self.assertGreater(remaining[0], 0)
        self.assertLessEqual(remaining[0], CLOSE_TIMEOUT)

    async def test_failed_initialization_awaits_cleanup_without_blocking_loop(self):
        entered, release = asyncio.Event(), asyncio.Event()

        async def close_client():
            entered.set()
            await release.wait()

        client = Mock(close=AsyncMock(side_effect=close_client))
        with (
            patch("solvetls.storage.AsyncMongoClient", return_value=client),
            patch("solvetls.storage.init_beanie", side_effect=ValueError("bad setup")),
        ):
            task = asyncio.create_task(init_storage("mongodb://localhost/solvetls"))
            try:
                await asyncio.wait_for(entered.wait(), 1)
                self.assertFalse(task.done())
            finally:
                release.set()
                with self.assertRaisesRegex(ValueError, "bad setup"):
                    await task
        client.close.assert_awaited_once()

    async def test_successful_initialization_enables_storage_and_keeps_client(self):
        document = Mock(insert=AsyncMock())
        client = Mock(close=AsyncMock())
        with (
            patch("solvetls.storage._enabled", False),
            patch("solvetls.storage.AsyncMongoClient", return_value=client),
            patch("solvetls.storage.init_beanie", new_callable=AsyncMock) as initialize,
            patch("solvetls.storage.Fingerprint", return_value=document) as model,
        ):
            self.assertTrue(await init_storage("mongodb://localhost/solvetls"))
            initialize.assert_awaited_once_with(
                database=client.get_default_database.return_value,
                document_models=[model],
            )
            client.close.assert_not_awaited()
            await save_fingerprint({"method": "GET"})
            document.insert.assert_awaited_once()

    async def test_stalled_initialization_is_cancelled_and_disables_storage(self):
        cancelled = asyncio.Event()
        client = Mock(close=AsyncMock())

        async def stalled_initialize(**_):
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        with (
            patch("solvetls.storage._enabled", True),
            patch("solvetls.storage.INIT_TIMEOUT", 0.01),
            patch("solvetls.storage.AsyncMongoClient", return_value=client),
            patch("solvetls.storage.init_beanie", side_effect=stalled_initialize),
            patch("solvetls.storage.Fingerprint") as model,
        ):
            with self.assertRaisesRegex(
                TimeoutError, "MongoDB initialization exceeded .* seconds"
            ):
                await asyncio.wait_for(init_storage("mongodb://localhost/solvetls"), 1)
            await save_fingerprint({"method": "GET"})
            model.assert_not_called()
            client.close.assert_awaited_once()
        self.assertTrue(cancelled.is_set())

    async def test_initialization_failure_propagates_and_disables_storage(self):
        for stage in ("client", "beanie"):
            with self.subTest(stage=stage):
                failure = RuntimeError("database unavailable")
                client = Mock(close=AsyncMock())
                with (
                    patch("solvetls.storage._enabled", True),
                    patch(
                        "solvetls.storage.AsyncMongoClient", return_value=client
                    ) as client_type,
                    patch(
                        "solvetls.storage.init_beanie", new_callable=AsyncMock
                    ) as initialize,
                    patch("solvetls.storage.Fingerprint") as model,
                ):
                    if stage == "client":
                        client_type.side_effect = failure
                    else:
                        initialize.side_effect = failure
                    with self.assertRaises(RuntimeError) as raised:
                        await init_storage("mongodb://localhost/solvetls")
                    self.assertIs(raised.exception, failure)
                    await save_fingerprint({"method": "GET"})
                    model.assert_not_called()
                    if stage == "client":
                        initialize.assert_not_awaited()
                        client.close.assert_not_awaited()
                    else:
                        client.close.assert_awaited_once()

    async def test_driver_deadline_survives_initialization_cancellation(self):
        started, cancelled = asyncio.Event(), asyncio.Event()
        closing, release_close = asyncio.Event(), asyncio.Event()
        remaining = []
        cleanup_remaining = []

        async def initialize(**_):
            remaining.append(_csot.remaining())
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                remaining.append(_csot.remaining())
                cancelled.set()

        async def close_client():
            cleanup_remaining.append(_csot.remaining())
            closing.set()
            await release_close.wait()

        client = Mock(close=AsyncMock(side_effect=close_client))
        with (
            patch("solvetls.storage._enabled", False),
            patch("solvetls.storage.AsyncMongoClient", return_value=client),
            patch("solvetls.storage.init_beanie", side_effect=initialize),
        ):
            task = asyncio.create_task(init_storage("mongodb://localhost/solvetls"))
            try:
                await asyncio.wait_for(started.wait(), 1)
                task.cancel()
                await asyncio.wait_for(closing.wait(), 1)
                self.assertTrue(cancelled.is_set())
                # A second cancellation during cleanup must not abort close().
                task.cancel()
                await asyncio.sleep(0)
                self.assertFalse(task.done())
                release_close.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
            finally:
                task.cancel()
                release_close.set()
                await asyncio.gather(task, return_exceptions=True)

        self.assertIsNotNone(remaining[0])
        self.assertLessEqual(remaining[0], INIT_TIMEOUT)
        self.assertIsNotNone(remaining[1])
        self.assertLessEqual(remaining[1], remaining[0])
        self.assertIsNotNone(cleanup_remaining[0])
        self.assertLessEqual(cleanup_remaining[0], remaining[0])
        client.close.assert_awaited_once()

    async def test_cancellation_waits_for_cleanup_after_driver_deadline(self):
        started, finished = asyncio.Event(), asyncio.Event()
        remaining = []

        async def close_client():
            started.set()
            # Local cleanup must finish even after the network deadline passes.
            await asyncio.sleep(0.03)
            remaining.append(_csot.remaining())
            finished.set()

        client = Mock(close=AsyncMock(side_effect=close_client))
        with (
            patch("solvetls.storage._client", client),
            patch("solvetls.storage.CLOSE_TIMEOUT", 0.01),
        ):
            task = asyncio.create_task(close_storage())
            await asyncio.wait_for(started.wait(), 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 1)
            await close_storage()
        self.assertTrue(finished.is_set())
        self.assertLessEqual(remaining[0], 0)
        client.close.assert_awaited_once()

    async def test_stalled_insert_is_cancelled_without_escaping(self):
        cancelled = asyncio.Event()

        async def stalled_insert():
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        document = Mock(insert=AsyncMock(side_effect=stalled_insert))
        with (
            patch("solvetls.storage._enabled", True),
            patch("solvetls.storage.WRITE_TIMEOUT", 0.01),
            patch("solvetls.storage.Fingerprint", return_value=document),
            self.assertLogs("solvetls.storage", level="WARNING") as logs,
        ):
            await asyncio.wait_for(save_fingerprint({"method": "GET"}), 1)
        self.assertTrue(cancelled.is_set())
        self.assertIn("Fingerprint write exceeded", logs.output[0])

    async def test_insert_failure_does_not_escape(self):
        document = Mock(
            insert=AsyncMock(side_effect=RuntimeError("database unavailable"))
        )
        with (
            patch("solvetls.storage._enabled", True),
            patch("solvetls.storage.Fingerprint", return_value=document),
            self.assertLogs("solvetls.storage", level="ERROR"),
        ):
            await save_fingerprint({"method": "GET"})

    async def test_disabled_storage_never_constructs_document(self):
        with (
            patch("solvetls.storage._enabled", False),
            patch("solvetls.storage.Fingerprint") as model,
        ):
            await save_fingerprint({"method": "GET"})
            model.assert_not_called()

    async def test_disabling_storage_clears_previous_enabled_state(self):
        with (
            patch("solvetls.storage._enabled", True),
            patch("solvetls.storage.Fingerprint") as model,
        ):
            self.assertFalse(await init_storage(""))
            await save_fingerprint({"method": "GET"})
            model.assert_not_called()
