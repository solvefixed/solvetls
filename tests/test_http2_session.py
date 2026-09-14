import struct
import unittest
from types import SimpleNamespace

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.errors import ErrorCodes
from h2.events import DataReceived
from h2.exceptions import ProtocolError
from hpack import Decoder, Encoder

from solvetls.http2.frames import FrameType
from solvetls.http2.session import HTTP2_PREFACE, HTTP2Session
from tests.http2 import (
    Transport,
    data_frame,
    frame,
    headers_frame,
    request,
    response,
    settings_frame,
    window_update_frame,
)


class HTTP2ConnectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_arbitrary_network_fragmentation_preserves_frames(self):
        packets = [settings_frame(), request()]
        wire = b"".join(packets)
        for chunk_size in (len(wire), 1):
            with self.subTest(chunk_size=chunk_size):
                transport = Transport(
                    wire[i : i + chunk_size] for i in range(0, len(wire), chunk_size)
                )
                await transport.session.initialize(HTTP2_PREFACE)
                await transport.session.receive_request()
                self.assertEqual(transport.session.capture.stream_id, 1)
                self.assertEqual(
                    [item.raw for item in transport.session.capture.frames], packets
                )


class HTTP2FlowControlTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_h2_peer_uploads_and_downloads_beyond_both_windows(self):
        for upload_size in (65536, 131072):
            with self.subTest(upload_size=upload_size):
                peer = H2Connection(
                    config=H2Configuration(client_side=True, header_encoding=None)
                )
                peer.initiate_connection()
                peer.send_headers(
                    1,
                    [
                        (b":method", b"POST"),
                        (b":scheme", b"https"),
                        (b":authority", b"localhost"),
                        (b":path", b"/"),
                        (b"content-length", str(upload_size).encode()),
                    ],
                )
                remaining = upload_size
                response = bytearray()

                async def write(data, peer=peer, response=response):
                    for event in peer.receive_data(data):
                        if isinstance(event, DataReceived):
                            response.extend(event.data)
                            peer.acknowledge_received_data(
                                event.flow_controlled_length, event.stream_id
                            )

                async def read(peer=peer):
                    nonlocal remaining
                    while remaining and peer.local_flow_control_window(1) > 0:
                        size = min(
                            remaining,
                            peer.local_flow_control_window(1),
                            peer.max_outbound_frame_size,
                        )
                        remaining -= size
                        peer.send_data(1, b"x" * size, end_stream=not remaining)
                    data = peer.data_to_send()
                    self.assertTrue(data, "client and server are deadlocked")
                    return data

                session = HTTP2Session(SimpleNamespace(read=read, write=write))
                await session.initialize(peer.data_to_send())
                await session.receive_request()
                await session.send_response(b"z" * 200000)
                await session.close()
                self.assertEqual(remaining, 0)
                self.assertEqual(response, b"z" * 200000)

    async def test_zero_stream_window_waits_for_credit(self):
        transport = Transport([window_update_frame(1, 5)])
        await transport.start(request(), {4: 0})
        await transport.session.send_response(b"hello")
        self.assertFalse(transport.incoming)
        self.assertEqual(
            b"".join(frame.payload.data for frame in transport.output(FrameType.DATA)),
            b"hello",
        )

    async def test_connection_window_waits_for_credit(self):
        transport = Transport([window_update_frame(0, 4465)])
        await transport.start(request(), {4: 1048576})
        await transport.session.send_response(b"x" * 70000)
        self.assertFalse(transport.incoming)
        self.assertEqual(
            sum(frame.header.length for frame in transport.output(FrameType.DATA)),
            70000,
        )


class HTTP2StreamTests(unittest.IsolatedAsyncioTestCase):
    async def test_client_push_is_rejected_before_waiting_for_continuation(self):
        for prefix in (b"", request()):
            for flags in (0, 4):
                with self.subTest(request_received=bool(prefix), flags=flags):
                    transport = Transport()
                    promise = frame(
                        FrameType.PUSH_PROMISE,
                        struct.pack("!I", 2),
                        flags=flags,
                        stream=1,
                    )
                    with self.assertRaises(ProtocolError):
                        await transport.session.initialize(
                            HTTP2_PREFACE + settings_frame() + prefix + promise
                        )
                    with self.assertRaises(ConnectionResetError):
                        await transport.session.send_response(b"ignored")
                    await transport.session.close()
                    self.assertEqual(transport.reads, 0)
                    self.assertEqual(transport.session.capture.frames[-1].raw, promise)
                    self.assertEqual(transport.output(FrameType.HEADERS), [])
                    self.assertEqual(
                        [
                            f.payload.error_code
                            for f in transport.output(FrameType.GOAWAY)
                        ],
                        [ErrorCodes.PROTOCOL_ERROR],
                    )

    async def test_invalid_stream_sequences_have_specific_wire_errors(self):
        cases = [
            ("even client stream", request(stream=2), ErrorCodes.PROTOCOL_ERROR, []),
            (
                "DATA before HEADERS",
                data_frame(1, b"no headers", end_stream=True),
                ErrorCodes.PROTOCOL_ERROR,
                [],
            ),
            (
                "DATA after END_STREAM",
                request() + data_frame(1, b"after end", end_stream=True),
                ErrorCodes.NO_ERROR,
                [(1, ErrorCodes.STREAM_CLOSED)],
            ),
        ]
        for name, wire, goaway, resets in cases:
            with self.subTest(case=name):
                transport = Transport()
                with self.assertRaises((ProtocolError, ConnectionResetError)):
                    await transport.start(wire)
                await transport.session.close()
                self.assertEqual(
                    [f.payload.error_code for f in transport.output(FrameType.GOAWAY)],
                    [goaway],
                )
                self.assertEqual(
                    [
                        (f.header.stream_id, f.payload.error_code)
                        for f in transport.output(FrameType.RST_STREAM)
                    ],
                    resets,
                )
                self.assertEqual(transport.output(FrameType.HEADERS), [])

    async def test_ping_ack_is_returned_with_original_payload(self):
        transport = Transport()
        await transport.start(frame(6, b"12345678") + request())
        ping = transport.output(FrameType.PING)
        self.assertEqual(len(ping), 1)
        self.assertTrue(ping[0].payload.ack)
        self.assertEqual(ping[0].payload.data, b"12345678")

    async def test_ping_ack_does_not_generate_another_ack(self):
        transport = Transport()
        await transport.start(frame(6, b"12345678", flags=1) + request())
        self.assertEqual(transport.output(FrameType.PING), [])

    async def test_reset_before_response_prevents_application_response(self):
        transport = Transport()
        with self.assertRaises(ConnectionResetError):
            await transport.start(request() + frame(3, struct.pack("!I", 8), stream=1))
        with self.assertRaises(ConnectionResetError):
            await transport.session.send_response(b"ignored")
        self.assertEqual(transport.output(FrameType.HEADERS), [])

    async def test_multiplexed_requests_are_refused_without_mixing(self):
        encoder = Encoder()
        incoming = request(encoder, 1, b"POST", b"/first", end=False)
        incoming += request(encoder, 3, b"GET", b"/third")
        incoming += data_frame(1, b"body", end_stream=True)
        transport = Transport()
        await transport.start(incoming)
        self.assertEqual(transport.session.capture.stream_id, 1)
        self.assertIn((b":path", b"/first"), transport.session.capture.headers)
        reset = transport.output(FrameType.RST_STREAM)
        self.assertEqual(
            [(frame.header.stream_id, frame.payload.error_code) for frame in reset],
            [(3, 7)],
        )
        await transport.session.send_response(b"ok")
        await transport.session.close()
        self.assertEqual(
            transport.output(FrameType.GOAWAY)[0].payload.last_stream_id, 1
        )

    async def test_continuation_and_ignored_extensions(self):
        encoder = Encoder()
        block = encoder.encode(
            [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"localhost"),
                (b":path", b"/"),
            ]
        )
        incoming = frame(FrameType.ALTSVC, b"bad")
        incoming += frame(FrameType.ORIGIN, b"bad", stream=1)
        incoming += headers_frame(1, block[:3], end_stream=True)
        incoming += frame(9, block[3:], flags=4, stream=1)
        transport = Transport()
        await transport.start(incoming)
        self.assertEqual(transport.session.capture.stream_id, 1)

    async def test_extension_cannot_interrupt_header_block(self):
        transport = Transport()
        incoming = headers_frame(1, b"", end_stream=True)
        incoming += frame(FrameType.ORIGIN, b"")
        with self.assertRaises(ProtocolError):
            await transport.start(incoming)

    async def test_h2_continuation_backlog_boundary(self):
        # h2's 64-frame backlog includes the leading HEADERS frame.
        block = request()[9:]
        for count in (63, 64):
            with self.subTest(continuations=count):
                incoming = headers_frame(1, b"", end_stream=True)
                incoming += frame(9, b"", stream=1) * (count - 1)
                incoming += frame(9, block, flags=4, stream=1)
                transport = Transport()
                if count == 63:
                    await transport.start(incoming)
                    await transport.session.send_response(b"ok")
                    self.assertEqual(transport.session.capture.stream_id, 1)
                    self.assertEqual(transport.output(FrameType.GOAWAY), [])
                else:
                    with self.assertRaisesRegex(ProtocolError, "continuation frames"):
                        await transport.start(incoming)
                    await transport.session.close()
                    self.assertEqual(transport.output(FrameType.HEADERS), [])
                    self.assertEqual(
                        [
                            f.payload.error_code
                            for f in transport.output(FrameType.GOAWAY)
                        ],
                        [ErrorCodes.PROTOCOL_ERROR],
                    )

    async def test_obsolete_priority_self_dependency_is_only_recorded(self):
        encoder = Encoder()
        block = encoder.encode(
            [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"localhost"),
                (b":path", b"/"),
            ]
        )
        incoming = frame(2, struct.pack("!IB", 1, 0), stream=1)
        incoming += frame(1, struct.pack("!IB", 1, 0) + block, flags=0x25, stream=1)
        transport = Transport()
        await transport.start(incoming)
        self.assertEqual(
            transport.session.capture.frames[-1].payload.priority.dependency, 1
        )

    async def test_goaway_allows_existing_request_to_complete(self):
        transport = Transport()
        await transport.start(request() + frame(7, struct.pack("!II", 0, 0)))
        await transport.session.send_response(b"ok")
        self.assertEqual(len(transport.output(FrameType.DATA)), 1)

    async def test_idle_resets_after_request_opening_are_connection_errors(self):
        for stream_id in (2, 3, 1000, 0x7FFFFFFF):
            with self.subTest(stream_id=stream_id):
                transport = Transport()
                with self.assertRaises(ProtocolError):
                    await transport.start(
                        request()
                        + frame(
                            3, struct.pack("!I", ErrorCodes.CANCEL), stream=stream_id
                        )
                    )
                await transport.session.close()
                self.assertEqual(transport.output(FrameType.HEADERS), [])
                self.assertEqual(
                    [f.payload.error_code for f in transport.output(FrameType.GOAWAY)],
                    [ErrorCodes.PROTOCOL_ERROR],
                )

    async def test_closed_and_refused_resets_do_not_cancel_accepted_request(self):
        for name, incoming, expected_resets in (
            (
                "implicitly closed lower stream",
                request(stream=5)
                + frame(3, struct.pack("!I", ErrorCodes.CANCEL), stream=1),
                [],
            ),
            (
                "already refused stream",
                request()
                + request(stream=3)
                + frame(3, struct.pack("!I", ErrorCodes.CANCEL), stream=3) * 2,
                [(3, ErrorCodes.REFUSED_STREAM)],
            ),
        ):
            with self.subTest(case=name):
                transport = Transport()
                await transport.start(incoming)
                await transport.session.send_response(b"ok")
                await transport.session.close()
                self.assertEqual(
                    [
                        (f.header.stream_id, f.payload.error_code)
                        for f in transport.output(FrameType.RST_STREAM)
                    ],
                    expected_resets,
                )
                self.assertEqual(
                    [f.payload.error_code for f in transport.output(FrameType.GOAWAY)],
                    [ErrorCodes.NO_ERROR],
                )
                self.assertIn(
                    (":status", "200"),
                    Decoder().decode(
                        transport.output(FrameType.HEADERS)[0].payload.header_block
                    ),
                )


class HTTP2ResponseHelperTests(unittest.TestCase):
    def test_incomplete_or_interleaved_responses_are_rejected(self):
        block = Encoder().encode([(b":status", b"200")])
        head = headers_frame(1, block, end_headers=True)
        cases = [
            ("empty response", b""),
            ("empty unfinished header block", headers_frame(1, b"", end_stream=True)),
            ("unfinished header block", headers_frame(1, block, end_stream=True)),
            ("headers without END_STREAM", head),
            ("body without END_STREAM", head + data_frame(1, b"body")),
            (
                "interrupted header block",
                headers_frame(1, b"", end_stream=True)
                + frame(6, b"12345678")
                + frame(9, block, flags=4, stream=1),
            ),
            (
                "continuation without HEADERS",
                head + frame(9, b"", flags=4, stream=1) + data_frame(1, b"", True),
            ),
            (
                "continuation on another stream",
                headers_frame(1, b"", end_stream=True)
                + frame(9, block, flags=4, stream=3),
            ),
            ("END_STREAM on another stream", head + data_frame(3, b"body", True)),
            (
                "DATA after END_STREAM",
                headers_frame(1, block, True, True) + data_frame(1, b"body", True),
            ),
        ]
        for name, wire in cases:
            with self.subTest(case=name), self.assertRaises(AssertionError):
                response({"raw_response": wire})

    def test_empty_response_can_end_on_fragmented_headers(self):
        block = Encoder().encode([(b":status", b"204")])
        for fragmented in (False, True):
            with self.subTest(fragmented=fragmented):
                wire = (
                    headers_frame(1, b"", end_stream=True)
                    + frame(9, block, flags=4, stream=1)
                    if fragmented
                    else headers_frame(1, block, True, True)
                )
                self.assertEqual(
                    response({"raw_response": wire}), ({":status": "204"}, b"")
                )

    def test_informational_headers_body_and_trailers_share_hpack_state(self):
        encoder = Encoder()
        wire = settings_frame()
        wire += headers_frame(
            1,
            encoder.encode([(b":status", b"100"), (b"x-shared", b"value")]),
            end_headers=True,
        )
        wire += headers_frame(
            1,
            encoder.encode([(b":status", b"200"), (b"x-shared", b"value")]),
            end_headers=True,
        )
        wire += data_frame(1, b"{}")
        trailers = encoder.encode([(b"x-shared", b"value")])
        wire += headers_frame(1, b"", end_stream=True)
        wire += frame(9, trailers, flags=4, stream=1)
        wire += frame(7, struct.pack("!II", 1, 0))
        self.assertEqual(
            response({"raw_response": wire}),
            ({":status": "200", "x-shared": "value"}, b"{}"),
        )


if __name__ == "__main__":
    unittest.main()
