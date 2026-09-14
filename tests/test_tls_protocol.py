import asyncio
import json
import ssl
import unittest
from contextlib import suppress
from unittest.mock import patch

from solvetls.connection import ClientConnection
from solvetls.server import SolveTLS
from tests.support import MemoryWriter, certificate_files, exchange

REQUEST = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"


class TLSProtocolTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.app = SolveTLS(*certificate_files())

    async def make_tls_pair(self, version):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = version
        context.maximum_version = version
        context.set_alpn_protocols(["http/1.1"])
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        peer = context.wrap_bio(
            incoming, outgoing, server_side=False, server_hostname="localhost"
        )
        reader = asyncio.StreamReader()
        writer = MemoryWriter(incoming)
        connection = ClientConnection(reader, writer, self.app._tls_context)
        handshake = asyncio.create_task(connection.do_tls_handshake())
        peer_done = False
        try:
            async with asyncio.timeout(2):
                while not (peer_done and handshake.done()):
                    if not peer_done:
                        try:
                            peer.do_handshake()
                            peer_done = True
                        except ssl.SSLWantReadError:
                            pass
                    if outgoing.pending:
                        reader.feed_data(outgoing.read())
                    if handshake.done():
                        await handshake
                    await asyncio.sleep(0)
                await handshake
        finally:
            if not handshake.done():
                handshake.cancel()
                with suppress(asyncio.CancelledError):
                    await handshake
        self.assertEqual(connection._ssl_obj.version(), peer.version())
        return connection, peer, outgoing, reader, writer

    def assert_clean_peer_eof(self, peer):
        try:
            data = peer.read(1024)
        except ssl.SSLZeroReturnError:
            data = b""
        self.assertEqual(data, b"")
        peer.unwrap()

    async def test_tls12_peer_close_discards_response_and_answers_once(self):
        connection, peer, outgoing, reader, writer = await self.make_tls_pair(
            ssl.TLSVersion.TLSv1_2
        )
        try:
            peer.write(REQUEST)
            with self.assertRaises(ssl.SSLWantReadError):
                peer.unwrap()
            # Both records arrive before the application next reads the request.
            reader.feed_data(outgoing.read())
            with self.assertRaises(ConnectionResetError):
                await connection.read()
            self.assertTrue(connection._tls_eof)
            self.assert_clean_peer_eof(peer)
            sent_after_alert = writer.bytes_sent
            with self.assertRaises(ConnectionResetError):
                await connection.write(RESPONSE)
            self.assertEqual(writer.bytes_sent, sent_after_alert)
        finally:
            reader.feed_eof()
            await connection.close()
        self.assertEqual(writer.bytes_sent, sent_after_alert)
        self.assertTrue(writer.fin)
        self.assertTrue(writer.closed)

    async def test_tls13_peer_close_keeps_independent_response_direction(self):
        connection, peer, outgoing, reader, writer = await self.make_tls_pair(
            ssl.TLSVersion.TLSv1_3
        )
        try:
            peer.write(REQUEST)
            with self.assertRaises(ssl.SSLWantReadError):
                peer.unwrap()
            reader.feed_data(outgoing.read())
            self.assertEqual(await connection.read(), REQUEST)
            self.assertTrue(connection._tls_eof)
            await connection.write(RESPONSE)
            self.assertEqual(peer.read(1024), RESPONSE)
        finally:
            reader.feed_eof()
            await connection.close()
        self.assert_clean_peer_eof(peer)
        self.assertTrue(writer.fin)
        self.assertTrue(writer.closed)

    async def test_cancelling_close_still_closes_transport(self):
        connection, peer, _, reader, writer = await self.make_tls_pair(
            ssl.TLSVersion.TLSv1_3
        )
        fin_sent = asyncio.Event()
        write_eof = writer.write_eof

        def send_fin():
            write_eof()
            fin_sent.set()

        with patch.object(writer, "write_eof", side_effect=send_fin):
            closing = asyncio.create_task(connection.close())
            try:
                await asyncio.wait_for(fin_sent.wait(), 2)
                # Keep the peer open so shutdown is waiting for its EOF.
                self.assertFalse(closing.done())
                self.assertFalse(writer.closed)
                closing.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await closing
                self.assertTrue(writer.closed)
                self.assert_clean_peer_eof(peer)
            finally:
                reader.feed_eof()
                if not closing.done():
                    closing.cancel()
                    with suppress(asyncio.CancelledError):
                        await closing

    async def test_fragmented_clienthello_completes_handshake_and_request(self):
        for version, expected in (
            (ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
            (ssl.TLSVersion.TLSv1_3, "TLSv1.3"),
        ):
            for fragment_size in (1, 37):
                with self.subTest(version=expected, fragment_size=fragment_size):
                    result = await exchange(
                        REQUEST,
                        tls_version=version,
                        client_hello_fragment_size=fragment_size,
                    )
                    self.assertTrue(result["raw_response"].startswith(b"HTTP/1.1 200 "))
                    self.assertEqual(result["tls"], expected)
                    self.assertTrue(result["clean_tls_eof"])

    async def test_tls12_dhe_only_client_receives_fingerprint(self):
        cipher = "DHE-RSA-AES128-GCM-SHA256"
        result = await exchange(
            REQUEST, tls_version=ssl.TLSVersion.TLSv1_2, ciphers=cipher
        )
        self.assertEqual(result["tls"], "TLSv1.2")
        self.assertEqual(result["cipher"][0], cipher)
        self.assertEqual(result["alpn"], "http/1.1")
        self.assertTrue(result["clean_tls_eof"])
        head, body = result["raw_response"].split(b"\r\n\r\n", 1)
        self.assertTrue(head.startswith(b"HTTP/1.1 200 "))
        report = json.loads(body)
        self.assertEqual(report["method"], "GET")
        self.assertEqual(report["http1"]["raw_head"], REQUEST.hex())
        self.assertIn(
            0x009E, [cipher["value"] for cipher in report["tls"]["cipher_suites"]]
        )
        self.assertTrue(report["tls"]["ja3_hash"])
        self.assertTrue(report["tls"]["ja4"])

    async def assert_early_tls_response(self, wire, expected):
        reader = asyncio.StreamReader()
        reader.feed_data(wire)
        reader.feed_eof()
        incoming = ssl.MemoryBIO()
        writer = MemoryWriter(incoming)
        async with asyncio.timeout(1):
            await self.app._handle_client(reader, writer)
        self.assertEqual(incoming.read(), expected)
        self.assertTrue(writer.fin)
        self.assertTrue(writer.closed)

    async def test_unexpected_initial_record_gets_one_fatal_alert(self):
        for record_type in (20, 23, 255):
            with self.subTest(record_type=record_type):
                await self.assert_early_tls_response(
                    bytes([record_type]) + b"\x03\x03\x00\x01\x01",
                    b"\x15\x03\x03\x00\x02\x02\x0a",
                )

    async def test_wrong_initial_handshake_gets_one_fatal_alert(self):
        message = b"\x02\x00\x00\x00"
        for fragment_size in (1, len(message)):
            with self.subTest(fragment_size=fragment_size):
                wire = bytearray()
                for start in range(0, len(message), fragment_size):
                    fragment = message[start : start + fragment_size]
                    wire.extend(b"\x16\x03\x03")
                    wire.extend(len(fragment).to_bytes(2, "big"))
                    wire.extend(fragment)
                await self.assert_early_tls_response(
                    wire, b"\x15\x03\x03\x00\x02\x02\x0a"
                )

    async def test_oversized_initial_record_gets_alert_without_reading_payload(self):
        for size in (16385, 65535):
            with self.subTest(size=size):
                await self.assert_early_tls_response(
                    b"\x16\x03\x03" + size.to_bytes(2, "big"),
                    b"\x15\x03\x03\x00\x02\x02\x16",
                )

    async def test_initial_peer_alert_does_not_get_an_error_alert_in_reply(self):
        await self.assert_early_tls_response(b"\x15\x03\x03\x00\x02\x02\x28", b"")

    async def test_malformed_clienthello_gets_one_fatal_decode_error(self):
        prefix = b"\x03\x03" + bytes(32)
        bodies = {
            "odd cipher vector": prefix + b"\x00\x00\x01\xc0\x01\x00",
            "truncated session vector": prefix + b"\x20\x00",
            "truncated extensions": (
                prefix + b"\x00\x00\x02\xc0\x2f\x01\x00\x00\x04\x00\x00\x00"
            ),
        }
        for name, body in bodies.items():
            handshake = b"\x01" + len(body).to_bytes(3, "big") + body
            for fragment_size in (1, len(handshake)):
                with self.subTest(vector=name, fragment_size=fragment_size):
                    wire = bytearray()
                    for start in range(0, len(handshake), fragment_size):
                        fragment = handshake[start : start + fragment_size]
                        wire.extend(b"\x16\x03\x03")
                        wire.extend(len(fragment).to_bytes(2, "big"))
                        wire.extend(fragment)
                    reader = asyncio.StreamReader()
                    reader.feed_data(wire)
                    reader.feed_eof()
                    incoming = ssl.MemoryBIO()
                    writer = MemoryWriter(incoming)
                    await self.app._handle_client(reader, writer)
                    self.assertEqual(incoming.read(), b"\x15\x03\x03\x00\x02\x02\x32")
                    self.assertTrue(writer.fin)
                    self.assertTrue(writer.closed)

    async def test_http1_limits_distinguish_uri_from_fields_across_fragmentation(self):
        cases = (
            (b"GET /" + b"a" * 70000 + b" HTTP/1.1\r\nHost: localhost\r\n\r\n", 414),
            (
                b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: "
                + b"a" * 70000
                + b"\r\n\r\n",
                431,
            ),
        )
        for request, expected in cases:
            for chunk_size in (None, 997):
                with self.subTest(status=expected, chunk_size=chunk_size):
                    result = await exchange(request, chunk_size=chunk_size)
                    status = int(result["raw_response"].split(b" ", 2)[1])
                    self.assertEqual(status, expected)
                    self.assertTrue(result["clean_tls_eof"])
