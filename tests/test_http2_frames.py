import unittest

from solvetls.http2.frames import (
    ErrorCode,
    HTTP2FrameParsingError,
    HTTP2FrameReader,
    SettingsPayload,
    UnknownPayload,
)
from tests.http2 import frame, settings_frame


class HTTP2FrameTests(unittest.TestCase):
    def test_invalid_overwritten_setting_is_not_hidden(self):
        packet = settings_frame([(2, 2), (2, 0)])
        with self.assertRaises(HTTP2FrameParsingError) as caught:
            HTTP2FrameReader(packet).parse_frame()
        self.assertEqual(caught.exception.code, ErrorCode.PROTOCOL_ERROR)
        observed = HTTP2FrameReader(packet, forensic=True).parse_frame()
        self.assertIsInstance(observed.payload, UnknownPayload)
        self.assertEqual(observed.payload.raw_payload, packet[9:])
        self.assertEqual(observed.payload.error_code, ErrorCode.PROTOCOL_ERROR)

    def test_malformed_ignored_extensions_do_not_consume_the_next_frame(self):
        for extension in (
            frame(10),
            frame(10, b"\x00\x08"),
            frame(12, stream=1),
            frame(12, b"\x00"),
        ):
            with self.subTest(extension=extension.hex()):
                reader = HTTP2FrameReader(extension + settings_frame())
                ignored = reader.parse_frame()
                self.assertIsInstance(ignored.payload, UnknownPayload)
                self.assertEqual(ignored.payload.raw_payload, extension[9:])
                self.assertTrue(ignored.payload.parse_error)
                next_frame = reader.parse_frame()
                self.assertIsInstance(next_frame.payload, SettingsPayload)
                self.assertFalse(reader.has_more_frames())

    def test_forensic_capture_preserves_malformed_core_frame_and_next_frame(self):
        # HEADERS with PRIORITY needs five bytes. Its parser must not borrow the
        # missing fifth byte from the following frame's header.
        malformed = frame(1, bytes(4), flags=0x24, stream=1)
        reader = HTTP2FrameReader(malformed + settings_frame(), forensic=True)
        observed = reader.parse_frame()
        self.assertEqual(observed.payload.raw_payload, bytes(4))
        self.assertEqual(observed.payload.error_code, ErrorCode.FRAME_SIZE_ERROR)
        self.assertIsInstance(reader.parse_frame().payload, SettingsPayload)
        self.assertFalse(reader.has_more_frames())

    def test_stream_zero_and_settings_bounds_rejected_with_protocol_codes(self):
        packets = [
            ("DATA on stream zero", frame(0), ErrorCode.PROTOCOL_ERROR),
            ("HEADERS on stream zero", frame(1, flags=5), ErrorCode.PROTOCOL_ERROR),
            (
                "window size overflow",
                settings_frame([(4, 0x80000000)]),
                ErrorCode.FLOW_CONTROL_ERROR,
            ),
            (
                "frame size too small",
                settings_frame([(5, 16383)]),
                ErrorCode.PROTOCOL_ERROR,
            ),
            (
                "frame size too large",
                settings_frame([(5, 0x1000000)]),
                ErrorCode.PROTOCOL_ERROR,
            ),
            ("truncated PING", frame(6, bytes(7)), ErrorCode.FRAME_SIZE_ERROR),
            ("priority target zero", frame(16, bytes(4)), ErrorCode.PROTOCOL_ERROR),
        ]
        for name, packet, code in packets:
            with self.subTest(case=name):
                with self.assertRaises(HTTP2FrameParsingError) as caught:
                    HTTP2FrameReader(packet).parse_frame()
                self.assertEqual(caught.exception.code, code)

    def test_unknown_frames_keep_bytes_and_ignored_reserved_bits(self):
        unknown = HTTP2FrameReader(
            frame(255, b"\xff", flags=0xFF, stream=0x80000001)
        ).parse_frame()
        self.assertEqual(unknown.header.stream_id, 1)
        self.assertEqual(unknown.payload.raw_payload, b"\xff")
        self.assertIsNone(unknown.payload.parse_error)
