import unittest
from types import SimpleNamespace
from unittest.mock import patch

from beanie.odm.settings.document import DocumentSettings
from beanie.odm.utils.dump import get_dict
from bson import BSON, ObjectId
from hpack import Encoder

from solvetls.connection import MAX_CLIENT_HELLO_SIZE
from solvetls.http2.session import (
    HTTP2_PREFACE,
    MAX_CAPTURE_BYTES,
    MAX_CAPTURE_ENTRIES,
    MAX_CAPTURE_FRAMES,
    SERVER_MAX_FRAME_SIZE,
)
from solvetls.report import build_report
from solvetls.storage import Fingerprint
from solvetls.tls.clienthello import ClientHelloReader
from tests.http2 import Transport, frame, settings_frame


def large_client_hello():
    # Repeated EC point formats bound report expansion conservatively, even
    # though OpenSSL rejects duplicate extensions in a real handshake.
    extension = b"\x00\x0b\x01\x00\xff" + b"\x01" * 255
    extensions = extension * 251 + b"\x00\x0b\x00\xe4\xe3" + b"\x01" * 227
    body = (
        b"\x03\x03"
        + bytes(32)
        + b"\x00\x00\x02\x13\x01\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    return body, ClientHelloReader(body).parse()


class ReportLimitTests(unittest.IsolatedAsyncioTestCase):
    maxDiff = 0

    async def test_combined_limits_keep_complete_document_below_bson_limit(self):
        settings = [
            (identifier, 0xFFFFFFFF)
            for identifier in range(32, 32 + MAX_CAPTURE_ENTRIES)
        ]
        encoder = Encoder()
        opaque_value = b"\xff" * 64000
        headers = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
            (b":path", b"/"),
            (b"user-agent", opaque_value),
        ]
        trailers = [(b"x-trailer", opaque_value)]
        packets = [
            settings_frame(settings),
            frame(1, encoder.encode(headers, huffman=False), flags=4, stream=1),
        ]
        trailer = frame(1, encoder.encode(trailers, huffman=False), flags=5, stream=1)

        # Exhaust frame count and wire bytes together. Empty malformed ALTSVC
        # frames are ignored by the server but keep diagnostic metadata; large
        # ALTSVC frames retain both decoded hex fields and their complete raw hex.
        slots = MAX_CAPTURE_FRAMES - len(packets) - 1
        payload_bytes = (
            MAX_CAPTURE_BYTES - sum(map(len, packets)) - len(trailer) - 9 * slots
        )
        full, remainder = divmod(payload_bytes, SERVER_MAX_FRAME_SIZE)
        packets.extend(frame(10) for _ in range(slots - full - bool(remainder)))
        packets.extend(
            frame(10, b"\x00\x00" + b"z" * (length - 2))
            for length in [SERVER_MAX_FRAME_SIZE] * full + [remainder]
            if length
        )
        packets.append(trailer)
        self.assertEqual(len(packets), MAX_CAPTURE_FRAMES)
        self.assertEqual(sum(map(len, packets)), MAX_CAPTURE_BYTES)

        transport = Transport(packets[1:])
        session = transport.session
        await session.initialize(HTTP2_PREFACE + packets[0])
        await session.receive_request()
        hello_body, hello = large_client_hello()
        self.assertEqual(len(hello_body), MAX_CLIENT_HELLO_SIZE - 1)
        client = SimpleNamespace(
            http_version="HTTP/2.0",
            http1=None,
            http2=session.capture,
            client_hello=hello,
            peername=("127.0.0.1", 12345),
            sockname=("127.0.0.1", 443),
            syn_packet=None,
        )
        report = build_report(client)

        # Use Beanie's actual database encoder and document defaults, including
        # MongoDB's eventual _id, without connecting a collection or doing I/O.
        with patch.object(
            Fingerprint, "_document_settings", DocumentSettings(name="fingerprints")
        ):
            document = Fingerprint(id=ObjectId(), **report)
            stored = get_dict(document, to_db=True)
        self.assertIn("_id", stored)
        self.assertIn("created_at", stored)
        # Keep at least 1 MiB spare under MongoDB's 16 MiB document limit.
        self.assertLessEqual(len(BSON.encode(stored)), 15 * 1024 * 1024)
        capture = stored["http2"]
        self.assertEqual(
            [bytes.fromhex(item["raw"]) for item in capture["frames"]], packets
        )
        self.assertEqual(
            capture["frames"][0]["payload"]["entries"],
            [list(item) for item in settings],
        )
        self.assertEqual(
            [(entry["value"], entry["setting"]) for entry in capture["settings"]],
            settings,
        )
        self.assertEqual(
            [
                [name.encode("latin-1"), value.encode("latin-1")]
                for name, value in capture["headers"]
            ],
            [list(item) for item in headers],
        )
        self.assertEqual(capture["trailers"][0][1].encode("latin-1"), opaque_value)
        self.assertEqual(stored["user_agent"].encode("latin-1"), opaque_value)
        self.assertEqual(
            [bytes.fromhex(entry["data"]) for entry in stored["tls"]["extensions"]],
            [extension.data for extension in hello.extensions],
        )
        self.assertEqual(
            [len(entry["decoded"]["formats"]) for entry in stored["tls"]["extensions"]],
            [255] * 251 + [227],
        )
