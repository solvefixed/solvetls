import json
import struct
import unittest
from types import SimpleNamespace

from solvetls.http1 import parse_request
from solvetls.http2.frames import ErrorCode, HTTP2FrameReader, UnknownPayload
from solvetls.http2.session import HTTP2Capture
from solvetls.report import _http1_report, _http2_report, _tls_report
from solvetls.tls import ClientHello, Extension
from solvetls.tls.enums import ExtensionType
from solvetls.tls.extensions import parse_alpn_protocols
from tests.http2 import frame, settings_frame


def tls_report(extension_type, data):
    hello = ClientHello(
        version=771,
        random=bytes(32),
        session_id=b"",
        cipher_suites=[0x1301],
        compression_methods=[0],
        extensions=[Extension(extension_type, data)],
    )
    return json.loads(json.dumps(_tls_report(hello)))


class ReportTests(unittest.TestCase):
    def test_initial_settings_preserve_empty_and_repeated_entries(self):
        cases = [
            ("empty", [], "|00|0|m,p"),
            ("repeated", [(1, 0), (2, 0), (1, 4096)], "1:0;2:0;1:4096|00|0|m,p"),
        ]
        for name, pairs, fingerprint in cases:
            with self.subTest(case=name):
                parsed = HTTP2FrameReader(settings_frame(pairs)).parse_frame()
                later = HTTP2FrameReader(settings_frame({6: 100000})).parse_frame()
                capture = HTTP2Capture(
                    initial_settings=parsed.payload.entries,
                    frames=[parsed, later],
                    headers=[(b":method", b"GET"), (b":path", b"/")],
                )
                report = json.loads(json.dumps(_http2_report(capture)))
                self.assertEqual(
                    [
                        (entry["value"], entry["setting"])
                        for entry in report["settings"]
                    ],
                    pairs,
                )
                self.assertEqual(report["akamai_fingerprint"], fingerprint)
                self.assertEqual(
                    report["frames"][0]["payload"]["entries"],
                    [list(pair) for pair in pairs],
                )

    def test_settings_grease_marks_all_byte_combinations_without_changing_capture(self):
        grease = [
            int.from_bytes(bytes((high, low)))
            for high in range(0x0A, 0x100, 0x10)
            for low in range(0x0A, 0x100, 0x10)
        ]
        pairs = [(1, 4096), (0x0A0B, 1), (0x0B0A, 2), (0xFFFF, 3)]
        pairs.extend((identifier, index) for index, identifier in enumerate(grease))
        packet = settings_frame(pairs)
        parsed = HTTP2FrameReader(packet).parse_frame()
        capture = HTTP2Capture(initial_settings=parsed.payload.entries, frames=[parsed])
        report = json.loads(json.dumps(_http2_report(capture)))
        settings = report["settings"]
        self.assertEqual(len(grease), 256)
        self.assertEqual(
            [entry["value"] for entry in settings if entry.get("grease")], grease
        )
        self.assertEqual(settings[0]["name"], "HEADER_TABLE_SIZE")
        self.assertTrue(all(entry["name"] is None for entry in settings[1:]))
        self.assertEqual(
            [(entry["value"], entry["setting"]) for entry in settings], pairs
        )
        self.assertEqual(
            report["frames"][0]["payload"]["entries"], [list(pair) for pair in pairs]
        )
        self.assertEqual(bytes.fromhex(report["frames"][0]["raw"]), packet)
        self.assertEqual(
            report["akamai_fingerprint"],
            ";".join(f"{identifier}:{value}" for identifier, value in pairs) + "|00|0|",
        )

    def test_http2_grease_does_not_expand_tls_grease_metadata_or_filtering(self):
        grease = [
            int.from_bytes(bytes((value, value))) for value in range(0x0A, 0x100, 0x10)
        ]
        values = [*grease, 0x2A9A, 0x3A4A]
        hello = ClientHello(
            version=771,
            random=bytes(32),
            session_id=b"",
            cipher_suites=values,
            compression_methods=[0],
            extensions=[Extension(value, b"") for value in values],
        )
        report = json.loads(json.dumps(_tls_report(hello)))
        for section in ("cipher_suites", "extensions"):
            self.assertEqual(
                [entry["value"] for entry in report[section] if entry.get("grease")],
                grease,
            )
        self.assertEqual(report["ja3"], "771,10906-14922,10906-14922,,")
        self.assertEqual(report["ja4"].split("_")[0], "t12i020200")

    def test_later_frames_stay_in_report_but_not_akamai_fingerprint(self):
        pairs = [(1, 0), (2, 0), (1, 4096)]
        packets = [
            settings_frame(pairs),
            frame(8, struct.pack("!I", 100000)),
            frame(2, struct.pack("!IB", 0, 199), stream=3),
            settings_frame([(6, 100000)]),
            frame(8, struct.pack("!I", 200000)),
            frame(1, flags=5, stream=1),
            frame(2, struct.pack("!IB", 0, 98), stream=5),
        ]
        parsed = [HTTP2FrameReader(packet).parse_frame() for packet in packets]
        capture = HTTP2Capture(
            initial_settings=parsed[0].payload.entries,
            frames=parsed,
            headers=[(b":method", b"GET"), (b":path", b"/")],
        )
        report = _http2_report(capture)
        self.assertEqual(
            report["akamai_fingerprint"], "1:0;2:0;1:4096|100000|3:0:0:200|m,p"
        )
        self.assertEqual(len(report["frames"]), len(packets))
        self.assertEqual(report["frames"][3]["payload"]["entries"], [[6, 100000]])
        self.assertEqual(report["frames"][4]["payload"]["increment"], 200000)
        self.assertEqual(report["frames"][6]["stream_id"], 5)
        self.assertEqual(
            [(entry["value"], entry["setting"]) for entry in report["settings"]],
            pairs,
        )

    def test_tls_report_preserves_binary_alpn(self):
        values = [b"h2", b"http/1.1", b"\xff", b"\xfe", b"\xc3\xa9", bytes(range(255))]
        protocols = b"".join(bytes([len(value)]) + value for value in values)
        data = len(protocols).to_bytes(2, "big") + protocols
        report = tls_report(ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, data)
        extension = report["extensions"][0]
        self.assertEqual(bytes.fromhex(extension["data"]), data)
        decoded = extension["decoded"]
        self.assertEqual(list(decoded), ["protocols"])
        self.assertEqual(decoded["protocols"][:2], ["h2", "http/1.1"])
        self.assertEqual(
            [value.encode("latin-1") for value in decoded["protocols"]], values
        )

    def test_record_size_limit_reports_malformed_lengths_without_losing_bytes(self):
        cases = [
            ("valid", b"\x40\x00", {"limit": 16384}),
            ("empty", b"", None),
            ("truncated", b"\x40", None),
            ("trailing bytes", b"\x40\x00junk", None),
        ]
        for name, data, expected in cases:
            with self.subTest(case=name):
                report = tls_report(ExtensionType.RECORD_SIZE_LIMIT, data)
                extension = report["extensions"][0]
                self.assertEqual(extension["length"], len(data))
                self.assertEqual(bytes.fromhex(extension["data"]), data)
                if expected is None:
                    self.assertEqual(set(extension["decoded"]), {"error"})
                    self.assertTrue(extension["decoded"]["error"])
                else:
                    self.assertEqual(extension["decoded"], expected)

    def test_tls_vectors_report_trailing_bytes_without_losing_raw_data(self):
        cases = [
            (ExtensionType.SERVER_NAME, b"\x00\x0a\x00\x00\x07example", "server_names"),
            (ExtensionType.SUPPORTED_GROUPS, b"\x00\x02\x00\x1d", "groups"),
            (ExtensionType.EC_POINT_FORMATS, b"\x01\x00", "formats"),
            (ExtensionType.SIGNATURE_ALGORITHMS, b"\x00\x02\x04\x03", "algorithms"),
            (
                ExtensionType.SIGNATURE_ALGORITHMS_CERT,
                b"\x00\x02\x04\x03",
                "algorithms",
            ),
            (
                ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                b"\x00\x03\x02h2",
                "protocols",
            ),
            (ExtensionType.COMPRESS_CERTIFICATE, b"\x02\x00\x01", "algorithms"),
            (ExtensionType.SUPPORTED_VERSIONS, b"\x02\x03\x04", "versions"),
            (ExtensionType.PSK_KEY_EXCHANGE_MODES, b"\x01\x01", "modes"),
            (ExtensionType.KEY_SHARE, b"\x00\x05\x00\x1d\x00\x01x", "shares"),
        ]
        for extension_type, payload, field in cases:
            for suffix in (b"", b"\x00", b"\xff\xff"):
                with self.subTest(extension=extension_type, suffix=suffix):
                    data = payload + suffix
                    extension = tls_report(extension_type, data)["extensions"][0]
                    self.assertEqual(extension["length"], len(data))
                    self.assertEqual(bytes.fromhex(extension["data"]), data)
                    if suffix:
                        self.assertEqual(set(extension["decoded"]), {"error"})
                        self.assertIn("trailing bytes", extension["decoded"]["error"])
                    else:
                        self.assertEqual(set(extension["decoded"]), {field})

    def test_alpn_parser_rejects_bytes_outside_declared_list(self):
        for data, protocols in ((b"\x00\x00", []), (b"\x00\x03\x02h2", [b"h2"])):
            with self.subTest(data=data):
                self.assertEqual(parse_alpn_protocols(data), protocols)
                for suffix in (b"\x00", b"\x02h2"):
                    with self.assertRaisesRegex(ValueError, "trailing bytes"):
                        parse_alpn_protocols(data + suffix)

    def test_tls_presence_padding_and_unknown_payloads_keep_their_diagnostics(self):
        cases = [
            (ExtensionType.ENCRYPT_THEN_MAC, {"present": True, "unexpected_bytes": 2}),
            (
                ExtensionType.EXTENDED_MASTER_SECRET,
                {"present": True, "unexpected_bytes": 2},
            ),
            (ExtensionType.PADDING, {"length": 2, "all_zero": False}),
            (0xFFFF, None),
        ]
        for extension_type, expected in cases:
            with self.subTest(extension=extension_type):
                extension = tls_report(extension_type, b"\x00\xff")["extensions"][0]
                self.assertEqual(extension["decoded"], expected)
                self.assertEqual(extension["data"], "00ff")

    def test_header_octets_and_trailers_are_lossless_and_separate(self):
        capture = HTTP2Capture(
            initial_settings=[],
            frames=[],
            headers=[(b":method", b"POST"), (b"x-opaque", b"\xff\xc3\xa9")],
            trailers=[(b"checksum", b"\x80")],
        )
        report = json.loads(json.dumps(_http2_report(capture)))
        self.assertEqual(report["headers"][1][1].encode("latin-1"), b"\xff\xc3\xa9")
        self.assertEqual(report["headers"][0], [":method", "POST"])
        self.assertEqual(report["trailers"][0][1].encode("latin-1"), b"\x80")

    def test_http1_opaque_head_can_be_recovered(self):
        raw_head = b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Opaque: \xff\r\n\r\n"
        client = SimpleNamespace(http1=parse_request(raw_head), http1_raw_head=raw_head)
        report = _http1_report(client)
        self.assertEqual(bytes.fromhex(report["raw_head"]), raw_head)
        self.assertEqual(report["headers"][1][1].encode("latin-1"), b"\xff")

    def test_http1_spacing_is_preserved_in_raw_head(self):
        heads = [
            b"GET / HTTP/1.1\r\nhOsT: localhost\r\nX-Test: value\r\n\r\n",
            b"\r\nGET / HTTP/1.1\r\nhOsT:\tlocalhost \t\r\nX-Test:\tvalue\t\r\n\r\n",
        ]
        reports = []
        for raw_head in heads:
            client = SimpleNamespace(
                http1=parse_request(raw_head), http1_raw_head=raw_head
            )
            report = json.loads(json.dumps(_http1_report(client)))
            self.assertEqual(bytes.fromhex(report.pop("raw_head")), raw_head)
            reports.append(report)
        self.assertEqual(reports[0], reports[1])
        self.assertEqual(reports[0]["headers"][0], ["hOsT", "localhost"])

    def test_frame_raw_preserves_padding_octets_missing_from_decoded_payload(self):
        for kind, prefix, content, flags in [
            (0, b"", b"body", 0x09),
            (1, struct.pack("!IB", 0x80000007, 255), b"\x82", 0x2D),
            (5, struct.pack("!I", 2), b"\x82", 0x0C),
        ]:
            with self.subTest(kind=kind):
                reports = []
                for padding in (b"\x00\x00", b"\xff\x7f"):
                    packet = frame(
                        kind,
                        b"\x02" + prefix + content + padding,
                        flags=flags,
                        stream=1,
                    )
                    parsed = HTTP2FrameReader(
                        packet, strict_padding=False
                    ).parse_frame()
                    self.assertEqual(parsed.raw, packet)
                    report = json.loads(
                        json.dumps(_http2_report(HTTP2Capture(frames=[parsed])))
                    )
                    self.assertEqual(
                        bytes.fromhex(report["frames"][0].pop("raw")), packet
                    )
                    reports.append(report)
                self.assertEqual(reports[0], reports[1])

    def test_frame_flag_names_follow_frame_type_and_preserve_unknown_bits(self):
        cases = [
            (frame(0, b"body", flags=0x81, stream=1), "DATA", ["END_STREAM"]),
            (
                frame(1, b"\x82", flags=0x85, stream=1),
                "HEADERS",
                ["END_STREAM", "END_HEADERS"],
            ),
            (
                frame(2, struct.pack("!IB", 0, 15), flags=0x25, stream=1),
                "PRIORITY",
                [],
            ),
            (frame(4, flags=0x81), "SETTINGS", ["ACK"]),
            (frame(4), "SETTINGS", []),
            (
                frame(5, struct.pack("!I", 2) + b"\x82", flags=0x85, stream=1),
                "PUSH_PROMISE",
                ["END_HEADERS"],
            ),
            (frame(6, b"12345678", flags=0x81), "PING", ["ACK"]),
            (frame(9, b"\x82", flags=0x85, stream=1), "CONTINUATION", ["END_HEADERS"]),
            (frame(255, b"\xff", flags=0xFF, stream=1), None, []),
        ]
        for packet, name, flag_names in cases:
            with self.subTest(name=name, flags=packet[4]):
                parsed = HTTP2FrameReader(packet).parse_frame()
                capture = HTTP2Capture(frames=[parsed])
                report = json.loads(json.dumps(_http2_report(capture)))["frames"][0]
                self.assertEqual(report["name"], name)
                self.assertEqual(report["flags"], packet[4])
                self.assertEqual(report["flag_names"], flag_names)
                self.assertEqual(bytes.fromhex(report["raw"]), packet)
                self.assertTrue(
                    {"end_stream", "end_headers", "padded", "ack"}.isdisjoint(
                        report["payload"]
                    )
                )

    def test_headers_payload_keeps_priority_and_hpack_separate_from_flags(self):
        block = b"\x82\x86\x84"
        payload = b"\x02" + struct.pack("!IB", 0x80000000, 255) + block + bytes(2)
        packet = frame(1, payload, flags=0x2D, stream=1)
        parsed = HTTP2FrameReader(packet).parse_frame()
        capture = HTTP2Capture(frames=[parsed])
        report = json.loads(json.dumps(_http2_report(capture)))["frames"][0]
        self.assertEqual(report["name"], "HEADERS")
        self.assertEqual(report["flags"], 45)
        self.assertEqual(
            report["flag_names"], ["END_STREAM", "END_HEADERS", "PADDED", "PRIORITY"]
        )
        self.assertEqual(
            report["payload"],
            {
                "header_block": block.hex(),
                "priority": {"exclusive": True, "dependency": 0, "weight": 256},
            },
        )
        self.assertEqual(bytes.fromhex(report["raw"]), packet)

    def test_frame_raw_keeps_reserved_header_bit_while_stream_id_ignores_it(self):
        reports = []
        for stream in (1, 0x80000001):
            packet = frame(0, b"body", flags=1, stream=stream)
            parsed = HTTP2FrameReader(packet).parse_frame()
            self.assertEqual(parsed.header.stream_id, 1)
            report = json.loads(
                json.dumps(_http2_report(HTTP2Capture(frames=[parsed])))
            )
            self.assertEqual(bytes.fromhex(report["frames"][0].pop("raw")), packet)
            reports.append(report)
        self.assertEqual(reports[0], reports[1])

    def test_raw_frames_reconstruct_concatenated_capture_including_malformed_frame(
        self,
    ):
        packets = [
            settings_frame([(1, 0), (1, 4096)]),
            frame(1, bytes(4), flags=0x24, stream=1),
            frame(255, b"\xff", flags=0xFF, stream=0x80000001),
            frame(0, b"\x01body\xff", flags=0x09, stream=1),
        ]
        wire = b"".join(packets)
        reader = HTTP2FrameReader(wire, strict_padding=False, forensic=True)
        parsed = []
        while reader.has_more_frames():
            parsed.append(reader.parse_frame())
        self.assertEqual([item.raw for item in parsed], packets)
        self.assertIsInstance(parsed[1].payload, UnknownPayload)
        self.assertEqual(parsed[1].payload.error_code, ErrorCode.FRAME_SIZE_ERROR)
        report = json.loads(json.dumps(_http2_report(HTTP2Capture(frames=parsed))))
        restored = b"".join(bytes.fromhex(item["raw"]) for item in report["frames"])
        self.assertEqual(restored, wire)
