import hashlib
import json
import struct
import unittest

from hpack import Encoder

from solvetls.connection import HTTP2_PREFACE
from solvetls.fingerprints import build_akamai_fingerprint, build_ja3, build_ja4
from solvetls.http2.frames import HTTP2FrameReader
from solvetls.http2.session import HTTP2Capture
from solvetls.tls.clienthello import ClientHello, Extension
from tests.http2 import frame, headers_frame, settings_frame
from tests.http2 import response as http2_response
from tests.support import exchange


def vector(values, prefix=2):
    data = b"".join(struct.pack("!H", value) for value in values)
    return len(data).to_bytes(prefix, "big") + data


def hello(version, ciphers, extensions):
    return ClientHello(version, bytes(32), b"", ciphers, [0], extensions)


def ja4_example(grease=False):
    # https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
    ciphers = [
        0x1301,
        0x1302,
        0x1303,
        0xC02B,
        0xC02F,
        0xC02C,
        0xC030,
        0xCCA9,
        0xCCA8,
        0xC013,
        0xC014,
        0x009C,
        0x009D,
        0x002F,
        0x0035,
    ]
    extensions = [
        0x001B,
        0x0000,
        0x0033,
        0x0010,
        0x4469,
        0x0017,
        0x002D,
        0x000D,
        0x0005,
        0x0023,
        0x0012,
        0x002B,
        0xFF01,
        0x000B,
        0x000A,
        0x0015,
    ]
    signatures = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    versions = [0x0304, 0x0303]
    if grease:
        ciphers.insert(0, 0x0A0A)
        extensions.insert(0, 0x1A1A)
        signatures.insert(1, 0x2A2A)
        versions.insert(0, 0x3A3A)
    data = {43: vector(versions, 1), 13: vector(signatures), 16: b"\x00\x03\x02h2"}
    return hello(
        771,
        ciphers,
        [Extension(value, data.get(value, b"")) for value in extensions],
    )


class PublishedFingerprintTests(unittest.TestCase):
    def test_salesforce_ja3_example_and_grease_exclusion(self):
        # https://github.com/salesforce/ja3#how-does-it-work
        expected = {
            "ja3": (
                "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
            ),
            "ja3_hash": "ada70206e40642a3e4461f35503241d5",
        }
        for grease in (False, True):
            with self.subTest(grease=grease):
                ciphers = [47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4]
                groups = [23, 24, 25]
                if grease:
                    ciphers.insert(0, 0x0A0A)
                    groups.insert(1, 0x2A2A)
                extensions = [
                    Extension(0, b""),
                    Extension(10, vector(groups)),
                    Extension(11, b"\x01\x00"),
                ]
                if grease:
                    extensions.insert(1, Extension(0x1A1A, b""))
                self.assertEqual(build_ja3(hello(769, ciphers, extensions)), expected)

    def test_salesforce_ja3_example_without_extensions(self):
        sample = hello(769, [4, 5, 10, 9, 100, 98, 3, 6, 19, 18, 99], [])
        self.assertEqual(
            build_ja3(sample),
            {
                "ja3": "769,4-5-10-9-100-98-3-6-19-18-99,,,",
                "ja3_hash": "de350869b8c85de67a350c8d186f11e6",
            },
        )

    def test_foxio_ja4_example_and_grease_exclusion(self):
        for grease in (False, True):
            with self.subTest(grease=grease):
                self.assertEqual(
                    build_ja4(ja4_example(grease)),
                    "t13d1516h2_8daaf6152771_e5627efa2ab1",
                )

    def test_foxio_alpn_examples_from_encoded_extension(self):
        cases = [
            (None, "00"),
            (b"", "00"),
            (b"h", "hh"),
            (b"h2", "h2"),
            (b"http/1.1", "h1"),
            (b"\xab", "ab"),
            (b"\x20", "20"),
            (b"\xab\xcd", "ad"),
            (b"\x20\x61", "21"),
            (b"\x30\xab", "3b"),
            (b"\x61\x20", "60"),
            (b"\x30\x31\xab\xcd", "3d"),
            (b"\x30\xab\xcd\x31", "01"),
            (b"\x0a", "0a"),
            (b"\x00\x0a\x0a", "0a"),
            (b"\x0a\x0a\x00", "00"),
            (b"\x0a\x1a", "0a"),
        ]
        for protocol, expected in cases:
            with self.subTest(protocol=protocol):
                extensions = []
                if protocol is not None:
                    # The second ALPN must not influence JA4's first-ALPN signal.
                    entries = bytes([len(protocol)]) + protocol + b"\x02h2"
                    extensions = [
                        Extension(16, len(entries).to_bytes(2, "big") + entries)
                    ]
                fingerprint = build_ja4(hello(771, [0x002F], extensions))
                self.assertEqual(fingerprint.split("_")[0][-2:], expected)

    def test_ja4_ignores_grease_alpn_identifiers(self):
        grease = [bytes([value, value]) for value in range(0x0A, 0x100, 0x10)]
        cases = [([value, b"h2"], "h2") for value in grease]
        cases.extend([([*grease, b"http/1.1"], "h1"), (grease, "00")])
        for protocols, expected in cases:
            with self.subTest(protocols=protocols):
                entries = b"".join(bytes([len(value)]) + value for value in protocols)
                extension = Extension(16, len(entries).to_bytes(2, "big") + entries)
                sample = hello(771, [0x002F], [extension])
                self.assertEqual(build_ja4(sample).split("_")[0][-2:], expected)

    def test_empty_alpn_list_and_empty_hash_fields(self):
        self.assertEqual(
            build_ja4(hello(771, [], [Extension(16, b"\x00\x00")])),
            "t12i000100_000000000000_000000000000",
        )


class JA4TLSRegressionTests(unittest.IsolatedAsyncioTestCase):
    async def test_grease_alpn_keeps_ja4_stable_and_report_lossless(self):
        fingerprints = []
        for protocols in (
            ("http/1.1",),
            ("\n\n", "http/1.1"),
            ("\x1a\x1a", "http/1.1"),
        ):
            with self.subTest(protocols=protocols):
                result = await exchange(
                    b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", protocols
                )
                self.assertEqual(result["alpn"], "http/1.1")
                report = json.loads(result["raw_response"].split(b"\r\n\r\n", 1)[1])
                fingerprint = report["tls"]["ja4"]
                self.assertIsInstance(fingerprint, str)
                self.assertRegex(
                    fingerprint,
                    r"\At(?:12|13)d[0-9]{4}h1_[0-9a-f]{12}_[0-9a-f]{12}\Z",
                )
                fingerprints.append(fingerprint)
                alpn = next(
                    item for item in report["tls"]["extensions"] if item["value"] == 16
                )
                self.assertEqual(alpn["decoded"]["protocols"], list(protocols))
                entries = b"".join(
                    bytes([len(value)]) + value.encode("ascii") for value in protocols
                )
                self.assertEqual(
                    bytes.fromhex(alpn["data"]),
                    len(entries).to_bytes(2, "big") + entries,
                )
        self.assertEqual(len(set(fingerprints)), 1)


class AkamaiFingerprintTests(unittest.TestCase):
    def test_missing_initial_values_are_not_filled_from_later_frames(self):
        cases = {
            "empty initial settings": [settings_frame({}), settings_frame({1: 4096})],
            "no initial connection window update": [
                settings_frame({}),
                frame(8, struct.pack("!I", 42), stream=1),
                frame(1, flags=5, stream=1),
                frame(8, struct.pack("!I", 100000)),
            ],
        }
        for name, packets in cases.items():
            with self.subTest(case=name):
                capture = HTTP2Capture(
                    initial_settings=[],
                    frames=[
                        HTTP2FrameReader(packet).parse_frame() for packet in packets
                    ],
                    headers=[(b":method", b"GET")],
                )
                self.assertEqual(
                    build_akamai_fingerprint(capture)["akamai_fingerprint"], "|00|0|m"
                )


class AkamaiTLSRegressionTests(unittest.IsolatedAsyncioTestCase):
    async def test_initial_fingerprint_survives_later_frames_and_tls_fragmentation(
        self,
    ):
        initial_settings = [(1, 0), (2, 0), (1, 4096)]
        headers = [
            (b":authority", b"localhost"),
            (b":method", b"GET"),
            (b":path", b"/"),
            (b":scheme", b"https"),
            (b"user-agent", b"Agent/\xff"),
            (b"x-test", b"one"),
            (b"x-test", b"two"),
        ]
        packets = [
            frame(4, b"".join(struct.pack("!HI", *pair) for pair in initial_settings)),
            frame(8, struct.pack("!I", 100000)),
            frame(2, struct.pack("!IB", 0, 199), stream=3),
            settings_frame({6: 100000}),
            frame(8, struct.pack("!I", 200000)),
            headers_frame(
                1, Encoder().encode(headers), end_headers=True, end_stream=True
            ),
            frame(2, struct.pack("!IB", 0, 98), stream=5),
        ]
        reports = []
        expected = "1:0;2:0;1:4096|100000|3:0:0:200|a,m,p,s"
        for chunk_size in (None, 1):
            with self.subTest(chunk_size=chunk_size):
                result = await exchange(
                    HTTP2_PREFACE + b"".join(packets), ("h2",), chunk_size=chunk_size
                )
                report = json.loads(http2_response(result)[1])
                reports.append(report)
                self.assertTrue(result["clean_tls_eof"])
                self.assertEqual(report["http2"]["akamai_fingerprint"], expected)
                self.assertEqual(
                    report["http2"]["akamai_fingerprint_hash"],
                    hashlib.md5(expected.encode(), usedforsecurity=False).hexdigest(),
                )
                self.assertEqual(report["user_agent"].encode("latin-1"), b"Agent/\xff")
                self.assertEqual(
                    [name for name, _ in report["http2"]["headers"][:4]],
                    [":authority", ":method", ":path", ":scheme"],
                )
                self.assertEqual(
                    [
                        (entry["value"], entry["setting"])
                        for entry in report["http2"]["settings"]
                    ],
                    initial_settings,
                )
        # The full coalesced snapshot retains the later priority even though
        # that priority no longer contaminates the initial fingerprint.
        self.assertEqual(
            [bytes.fromhex(entry["raw"]) for entry in reports[0]["http2"]["frames"]],
            packets,
        )
        self.assertEqual(
            [entry["value"] for entry in reports[0]["http2"]["frames"]],
            [4, 8, 2, 4, 8, 1, 2],
        )
        self.assertEqual(reports[0]["http2"]["frames"][-1]["stream_id"], 5)


if __name__ == "__main__":
    unittest.main()
