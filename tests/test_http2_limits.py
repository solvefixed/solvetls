import struct
import unittest
from unittest.mock import patch

from h2.exceptions import ProtocolError
from hpack import Encoder

from solvetls.http2.adapter import (
    MAX_DECODED_HEADER_BYTES,
    MAX_HEADER_LIST_SIZE,
    MAX_HEADER_TABLE_SIZE_CHANGES,
)
from solvetls.http2.frames import ErrorCode, FrameType, HTTP2FrameReader
from solvetls.http2.session import (
    HTTP2_PREFACE,
    MAX_CAPTURE_BYTES,
    MAX_CAPTURE_ENTRIES,
    MAX_CAPTURE_FRAMES,
    MAX_REQUEST_BODY,
)
from tests.http2 import (
    Transport,
    data_frame,
    frame,
    request,
    settings_frame,
    unknown_settings_flood,
)


class HTTP2CaptureLimitTests(unittest.IsolatedAsyncioTestCase):
    def assert_limit_error(self, transport, acknowledgments):
        self.assertEqual(
            [item.payload.error_code for item in transport.output(FrameType.GOAWAY)],
            [ErrorCode.ENHANCE_YOUR_CALM],
        )
        self.assertEqual(
            sum(item.payload.ack for item in transport.output(FrameType.SETTINGS)),
            acknowledgments,
        )

    async def test_settings_flood_is_rejected_before_decoding_entries(self):
        transport = Transport()
        with (
            patch.object(
                HTTP2FrameReader,
                "_read_uint16",
                side_effect=AssertionError("oversized SETTINGS entries were decoded"),
            ),
            self.assertRaises(ProtocolError),
        ):
            await transport.session.initialize(
                HTTP2_PREFACE + unknown_settings_flood()[0] + request()
            )
        self.assertEqual(transport.session.capture.frames, [])
        self.assertEqual(transport.output(FrameType.HEADERS), [])
        self.assert_limit_error(transport, 0)

    async def test_settings_and_origin_share_a_cumulative_budget(self):
        settings_count = MAX_CAPTURE_ENTRIES // 2
        packets = [
            frame(4, struct.pack("!HI", 3, 100) * settings_count),
            frame(12, b"\x00\x00" * (MAX_CAPTURE_ENTRIES - settings_count)),
        ]
        for extra in (frame(4, struct.pack("!HI", 32, 0)), frame(12, b"\x00\x00")):
            with self.subTest(extra_kind=extra[3]):
                transport = Transport()
                await transport.session.initialize(HTTP2_PREFACE + b"".join(packets))
                self.assertEqual(
                    [item.raw for item in transport.session.capture.frames], packets
                )
                with self.assertRaises(ProtocolError):
                    await transport.session._receive(extra + request())
                self.assertEqual(len(transport.session.capture.frames), len(packets))
                self.assertEqual(transport.output(FrameType.HEADERS), [])
                self.assert_limit_error(transport, 1)

    async def test_exact_budget_preserves_unknown_and_repeated_settings(self):
        pairs = [(32 + index, 0xFFFFFFFF) for index in range(MAX_CAPTURE_ENTRIES // 2)]
        pairs += [(32, 0)] * (MAX_CAPTURE_ENTRIES - len(pairs))
        settings = frame(4, b"".join(struct.pack("!HI", *pair) for pair in pairs))
        transport = Transport()
        await transport.session.initialize(HTTP2_PREFACE + settings + request())
        await transport.session.send_response(b"ok")
        self.assertEqual(transport.session.capture.frames[0].raw, settings)
        self.assertEqual(transport.session.capture.frames[0].payload.entries, pairs)
        self.assertTrue(transport.output(FrameType.HEADERS))
        self.assertEqual(transport.output(FrameType.GOAWAY), [])

    async def test_origin_limit_cannot_be_hidden_by_forensic_fallback(self):
        transport = Transport()
        await transport.session.initialize(HTTP2_PREFACE + frame(4))
        oversized = frame(12, b"\x00\x00" * (MAX_CAPTURE_ENTRIES + 1))
        with self.assertRaises(ProtocolError):
            await transport.session._receive(oversized + request())
        self.assertEqual(len(transport.session.capture.frames), 1)
        self.assert_limit_error(transport, 1)

    async def test_malformed_ignored_origin_does_not_reset_entry_accounting(self):
        transport = Transport()
        malformed = frame(12, b"\x00\x00" * MAX_CAPTURE_ENTRIES + b"\x00")
        await transport.session.initialize(HTTP2_PREFACE + frame(4) + malformed)
        self.assertTrue(transport.session.capture.frames[-1].payload.parse_error)
        with self.assertRaises(ProtocolError):
            await transport.session._receive(frame(4, struct.pack("!HI", 32, 0)))
        self.assert_limit_error(transport, 1)

    async def test_entry_budget_remains_active_while_waiting_for_response_credit(self):
        initial = frame(4, struct.pack("!HI", 4, 0))
        remaining = frame(4, struct.pack("!HI", 32, 0) * (MAX_CAPTURE_ENTRIES - 1))
        transport = Transport([remaining + frame(4, struct.pack("!HI", 32, 0))])
        await transport.session.initialize(HTTP2_PREFACE + initial + request())
        with self.assertRaises(ProtocolError):
            await transport.session.send_response(b"ok")
        self.assertEqual(transport.output(FrameType.DATA), [])
        self.assert_limit_error(transport, 2)

    async def test_single_header_list_limit_remains_a_resource_error(self):
        # One literal and repeated HPACK indexes expand past the decoded limit
        # while the encoded block stays well below the wire limit.
        incoming = request(extra=[(b"x", b"x" * 4000)] * 17)
        self.assertLess(len(incoming), MAX_HEADER_LIST_SIZE)
        transport = Transport()
        with self.assertRaises(ProtocolError):
            await transport.start(incoming)
        await transport.session.close()
        self.assert_limit_error(transport, 1)
        self.assertEqual(transport.output(FrameType.HEADERS), [])

    async def test_decoded_header_budget_includes_refused_and_closed_streams(self):
        extra = [(b"x", b"x" * 4000)] * 16
        fields = [
            (b":method", b"GET"),
            (b":authority", b"localhost"),
            (b":scheme", b"https"),
            (b":path", b"/"),
            *extra,
        ]
        decoded_size = sum(len(name) + len(value) + 32 for name, value in fields)
        self.assertLessEqual(decoded_size, MAX_HEADER_LIST_SIZE)
        count = MAX_DECODED_HEADER_BYTES // decoded_size + 1
        for closed_stream in (False, True):
            with self.subTest(closed_stream=closed_stream):
                encoder = Encoder()
                packets = [frame(4), request(encoder)]
                packets.extend(
                    request(
                        encoder,
                        stream=3 if closed_stream else 3 + 2 * index,
                        extra=extra,
                    )
                    for index in range(count)
                )
                incoming = b"".join(packets)
                self.assertLess(len(incoming), MAX_CAPTURE_BYTES)
                self.assertLess(len(packets), MAX_CAPTURE_FRAMES)
                transport = Transport()
                with self.assertRaises(ProtocolError):
                    await transport.session.initialize(HTTP2_PREFACE + incoming)
                await transport.session.close()
                self.assert_limit_error(transport, 1)
                resets = transport.output(FrameType.RST_STREAM)
                self.assertEqual(resets[0].payload.error_code, ErrorCode.REFUSED_STREAM)
                self.assertGreater(len(resets), 1)
                expected = (
                    ErrorCode.STREAM_CLOSED
                    if closed_stream
                    else ErrorCode.REFUSED_STREAM
                )
                self.assertTrue(
                    all(item.payload.error_code == expected for item in resets[1:])
                )
                self.assertEqual(transport.output(FrameType.HEADERS), [])

    async def test_decoded_header_budget_counts_raw_lengths_and_trailers_exactly(self):
        headers = [
            (b":method", b"GET"),
            (b":authority", b"localhost"),
            (b":scheme", b"https"),
            (b":path", b"/"),
            (b"content-length", b"0" * 5000),
        ]
        trailers = [(b"x-checksum", b"done")]
        budget = sum(
            len(name) + len(value) + 32 for name, value in [*headers, *trailers]
        )
        encoder = Encoder()
        incoming = frame(1, encoder.encode(headers), flags=4, stream=1)
        incoming += frame(1, encoder.encode(trailers), flags=5, stream=1)
        for overflow in (0, 1):
            with (
                self.subTest(overflow=overflow),
                patch(
                    "solvetls.http2.adapter.MAX_DECODED_HEADER_BYTES", budget - overflow
                ),
            ):
                transport = Transport()
                if overflow:
                    with self.assertRaises(ProtocolError):
                        await transport.start(incoming)
                    await transport.session.close()
                    self.assert_limit_error(transport, 1)
                else:
                    await transport.start(incoming)
                    await transport.session.send_response(b"ok")
                    self.assertEqual(transport.session.capture.headers, headers)
                    self.assertEqual(transport.session.capture.trailers, trailers)
                    self.assertEqual(transport.output(FrameType.GOAWAY), [])

    async def test_decoded_header_budget_remains_active_during_response(self):
        encoder = Encoder()
        initial = request(encoder)
        remaining = request(encoder, stream=3, extra=[(b"x", b"x" * 700)])
        with patch("solvetls.http2.adapter.MAX_DECODED_HEADER_BYTES", 1000):
            transport = Transport([remaining])
            await transport.start(initial, settings={4: 0})
            with self.assertRaises(ProtocolError):
                await transport.session.send_response(b"ok")
            await transport.session.close()
        self.assertEqual(transport.output(FrameType.DATA), [])
        self.assert_limit_error(transport, 1)


class HTTP2TableLimitTests(unittest.IsolatedAsyncioTestCase):
    async def test_table_update_limit_counts_changes_across_frames_not_noops(self):
        transport = Transport()
        await transport.session.initialize(HTTP2_PREFACE)
        payload = b"".join(
            struct.pack("!HI", 1, 0 if index % 2 == 0 else 4096)
            for index in range(MAX_HEADER_TABLE_SIZE_CHANGES)
        )
        await transport.session._receive(frame(4, payload))
        await transport.session._receive(frame(4, struct.pack("!HI", 1, 4096) * 512))
        self.assertEqual(
            sum(item.payload.ack for item in transport.output(FrameType.SETTINGS)), 2
        )
        with self.assertRaises(ProtocolError):
            await transport.session._receive(frame(4, struct.pack("!HI", 1, 0)))
        self.assertEqual(transport.output(FrameType.GOAWAY)[0].payload.error_code, 11)
        self.assertEqual(
            sum(item.payload.ack for item in transport.output(FrameType.SETTINGS)), 2
        )


class HTTP2BodyLimitTests(unittest.IsolatedAsyncioTestCase):
    async def test_oversized_declared_bodies_get_enhance_your_calm(self):
        for name, value in [
            ("one byte over the limit", str(MAX_REQUEST_BODY + 1).encode()),
            ("thousands of significant digits", b"9" * 5000),
        ]:
            with self.subTest(case=name):
                transport = Transport()
                with self.assertRaises(ProtocolError):
                    await transport.start(
                        request(
                            method=b"POST",
                            end=False,
                            extra=[(b"content-length", value)],
                        )
                    )
                await transport.session.close()
                self.assertEqual(
                    [f.payload.error_code for f in transport.output(FrameType.GOAWAY)],
                    [ErrorCode.ENHANCE_YOUR_CALM],
                )
                self.assertEqual(transport.output(FrameType.HEADERS), [])

    async def test_body_limit_applies_without_content_length(self):
        for overflow in (False, True):
            with self.subTest(overflow=overflow):
                size = MAX_REQUEST_BODY + int(overflow)
                packets = [
                    data_frame(
                        1,
                        b"x" * min(16384, size - offset),
                        end_stream=offset + 16384 >= size,
                    )
                    for offset in range(0, size, 16384)
                ]
                initial = request(method=b"POST", end=False)
                # Keep this below the independent capture limit so it proves the
                # body limit, including its exact accepted boundary.
                self.assertLess(
                    len(settings_frame()) + len(initial) + sum(map(len, packets)),
                    MAX_CAPTURE_BYTES,
                )
                transport = Transport(packets)
                if overflow:
                    with self.assertRaises(ProtocolError):
                        await transport.start(initial)
                    await transport.session.close()
                    self.assertEqual(
                        [
                            f.payload.error_code
                            for f in transport.output(FrameType.GOAWAY)
                        ],
                        [ErrorCode.ENHANCE_YOUR_CALM],
                    )
                    self.assertEqual(transport.output(FrameType.HEADERS), [])
                else:
                    await transport.start(initial)
                    await transport.session.send_response(b"ok")
                    self.assertEqual(
                        b"".join(
                            f.payload.data for f in transport.output(FrameType.DATA)
                        ),
                        b"ok",
                    )
