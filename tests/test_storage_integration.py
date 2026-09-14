import asyncio
import os
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from pymongo import AsyncMongoClient
from pymongo import timeout as database_timeout
from pymongo.errors import InvalidOperation

import solvetls.storage as storage
from solvetls.storage import close_storage, init_storage, save_fingerprint


@unittest.skipUnless(
    os.getenv("SOLVETLS_MONGODB_TESTS") == "1",
    "Set SOLVETLS_MONGODB_TESTS=1 to run the MongoDB integration test",
)
class StorageIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # Set authSource in the test URI for a separate authentication database.
        server_url = os.getenv("SOLVETLS_MONGODB_TEST_URL", "")
        self.assertTrue(
            server_url,
            "SOLVETLS_MONGODB_TEST_URL must explicitly select the test server",
        )
        parsed = urlsplit(server_url)
        self.assertIn(parsed.scheme, ("mongodb", "mongodb+srv"))
        self.assertTrue(parsed.netloc, "The test URI must include a MongoDB server")
        self.assertIn(
            parsed.path,
            ("", "/"),
            "The test URI must omit the database name; the test creates its own",
        )
        self.assertFalse(parsed.fragment, "MongoDB URIs cannot contain a fragment")

        self.database_name = "solvetls_integration_" + uuid4().hex
        self.connection_string = urlunsplit(
            parsed._replace(path="/" + self.database_name)
        )
        self.client = AsyncMongoClient(
            self.connection_string,
            tz_aware=True,
            connectTimeoutMS=5000,
            serverSelectionTimeoutMS=5000,
            socketTimeoutMS=5000,
        )
        self.database = self.client[self.database_name]

    async def asyncTearDown(self):
        try:
            await close_storage()
        finally:
            with database_timeout(5):
                try:
                    await self.client.drop_database(self.database_name)
                finally:
                    await self.client.close()

    async def test_report_round_trip_in_fingerprints_collection(self):
        report = {
            "source": "https://github.com/solvefixed/solvetls",
            "ip": "203.0.113.42:54321",
            "http_version": "HTTP/2.0",
            "method": "POST",
            "user_agent": "solvetls-storage-integration",
            "tls": {
                "ja3": "771,4865,0,,",
                "extensions": [
                    {"value": 0, "data": "000e00000b6578616d706c652e636f6d"}
                ],
            },
            "http2": {
                "headers": [
                    [":method", "POST"],
                    ["x-raw", "\u00ff"],
                    ["cookie", "a=1"],
                    ["cookie", "b=2"],
                ],
                "frames": [{"raw": "000000040000000000", "flags": 0}],
            },
            "tcpip": {"src_port": 54321, "dst_port": 443},
        }

        self.assertTrue(await init_storage(self.connection_string))
        started = datetime.now(UTC)
        await save_fingerprint(report)
        finished = datetime.now(UTC)

        with database_timeout(5):
            self.assertIn("fingerprints", await self.database.list_collection_names())
            collection = self.database["fingerprints"]
            self.assertEqual(await collection.count_documents({}), 1)
            document = await collection.find_one({})

        self.assertIsNotNone(document)
        for name, value in report.items():
            with self.subTest(field=name):
                self.assertEqual(document[name], value)
        self.assertIn("_id", document)
        created_at = document["created_at"]
        self.assertIsInstance(created_at, datetime)
        self.assertEqual(created_at.utcoffset(), timedelta(0))
        # BSON datetimes have millisecond precision.
        self.assertGreaterEqual(created_at, started - timedelta(milliseconds=1))
        self.assertLessEqual(created_at, finished)

    async def test_slow_end_sessions_does_not_interrupt_native_client_cleanup(self):
        self.assertTrue(await init_storage(self.connection_string))
        client = storage._client
        try:
            await save_fingerprint({"method": "GET"})
            with database_timeout(5):
                self.assertEqual(
                    await self.database["fingerprints"].count_documents({}), 1
                )
            servers = list(client._topology._servers.values())
            executors = [client._kill_cursors_executor]
            executors.extend(server._monitor._executor for server in servers)
            executors.extend(
                server._monitor._rtt_monitor._executor for server in servers
            )
            original_end_sessions = client._end_sessions
            close_timeout = 0.05

            async def delayed_end_sessions(session_ids):
                await asyncio.sleep(2 * close_timeout)
                await original_end_sessions(session_ids)

            with (
                patch.object(storage, "CLOSE_TIMEOUT", close_timeout),
                patch.object(
                    client, "_end_sessions", side_effect=delayed_end_sessions
                ) as end_sessions,
            ):
                async with asyncio.timeout(2):
                    await close_storage()
            end_sessions.assert_awaited_once()
            with self.assertRaises(InvalidOperation):
                await client.admin.command("ping")
            self.assertTrue(client._topology._closed)
            self.assertTrue(servers)
            for server in servers:
                self.assertTrue(server.pool.closed)
            for executor in executors:
                self.assertTrue(executor._stopped)
                if executor._task is not None:
                    self.assertTrue(executor._task.done())
        finally:
            # Also release the retained client when running against broken code.
            with database_timeout(5):
                await client.close()


if __name__ == "__main__":
    unittest.main()
