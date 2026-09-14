import struct
import unittest
from asyncio import get_running_loop

from h2.errors import ErrorCodes
from h2.exceptions import ProtocolError
from h2.settings import SettingCodes
from hpack import Decoder
from hpack.hpack import decode_integer

from solvetls.http2.adapter import SETTINGS_BATCH_SIZE
from solvetls.http2.frames import FrameType
from solvetls.http2.session import HTTP2_PREFACE
from tests.http2 import (
    Transport,
    data_frame,
    frame,
    request,
    settings_frame,
    window_update_frame,
)


def table_settings(sizes):
    return settings_frame([(1, size) for size in sizes])


def priority_update(stream_id):
    return frame(FrameType.PRIORITY_UPDATE, struct.pack("!I", stream_id) + b"u=3")


def table_updates(block):
    updates = []
    while block and block[0] & 0xE0 == 0x20:
        value, consumed = decode_integer(block, 5)
        updates.append(value)
        block = block[consumed:]
    return updates


class HTTP2SettingsTests(unittest.IsolatedAsyncioTestCase):
    async def test_preface_and_zero_hpack_table_are_accepted(self):
        transport = Transport()
        await transport.start(request(), {1: 0})
        await transport.session.send_response(
            b"abc", {"content-type": "application/json"}
        )
        output = transport.output()
        self.assertEqual(output[0].header.type, FrameType.SETTINGS)
        self.assertFalse(output[0].payload.ack)
        self.assertTrue(output[1].payload.ack)
        decoder = Decoder()
        decoder.max_allowed_table_size = 0
        headers = decoder.decode(
            transport.output(FrameType.HEADERS)[0].payload.header_block
        )
        self.assertIn(("content-length", "3"), headers)

    async def test_subsequent_settings_are_applied_and_acknowledged(self):
        transport = Transport()
        await transport.start(settings_frame({5: 16384}) + request(), {5: 65536})
        await transport.session.send_response(b"x" * 20000)
        settings = transport.output(FrameType.SETTINGS)
        self.assertEqual(sum(frame.payload.ack for frame in settings), 2)
        self.assertEqual(
            [frame.header.length for frame in transport.output(FrameType.DATA)],
            [16384, 3616],
        )
        self.assertEqual(transport.session.capture.initial_settings, [(5, 65536)])

    async def test_invalid_overwritten_setting_is_still_rejected(self):
        bad = frame(FrameType.SETTINGS, struct.pack("!HIHI", 2, 2, 2, 0))
        transport = Transport()
        with self.assertRaises(ProtocolError):
            await transport.session.initialize(HTTP2_PREFACE + bad + request())
        self.assertEqual(transport.output(FrameType.GOAWAY)[0].payload.error_code, 1)
        await transport.session.close()
        self.assertEqual(len(transport.output(FrameType.GOAWAY)), 1)

    async def test_unknown_settings_are_captured_without_growing_protocol_state(self):
        packets = [
            frame(4, b"".join(struct.pack("!HI", key, 0) for key in range(32, 544))),
            frame(4, struct.pack("!HI", 32, 0) * 512),
        ]
        transport = Transport()
        connection = transport.session.connection
        await transport.session.initialize(HTTP2_PREFACE)
        initial_settings = dict(connection.remote_settings)
        await transport.session._receive(b"".join(packets))
        self.assertEqual(dict(connection.remote_settings), initial_settings)
        self.assertEqual(
            [item.raw for item in transport.session.capture.frames], packets
        )
        self.assertTrue(
            all(
                len(item.payload.entries) == 512
                for item in transport.session.capture.frames
            )
        )
        self.assertEqual(
            sum(item.payload.ack for item in transport.output(FrameType.SETTINGS)), 2
        )

    async def test_repeated_supported_settings_yield_before_completion(self):
        transport = Transport()
        await transport.session.initialize(HTTP2_PREFACE)
        connection = transport.session.connection
        observed = []
        get_running_loop().call_soon(
            lambda: observed.append(connection.remote_settings.max_concurrent_streams)
        )
        count = SETTINGS_BATCH_SIZE * 2 + 1
        payload = b"".join(
            struct.pack("!HI", 3, value) for value in range(1, count + 1)
        )
        await transport.session._receive(frame(4, payload))
        self.assertEqual(len(observed), 1)
        self.assertGreater(observed[0], 0)
        self.assertLess(observed[0], count)
        self.assertEqual(connection.remote_settings.max_concurrent_streams, count)
        self.assertEqual(
            sum(item.payload.ack for item in transport.output(FrameType.SETTINGS)), 1
        )

    async def test_settings_ack_is_flushed_before_yielding(self):
        transport = Transport()
        await transport.session.initialize(HTTP2_PREFACE)
        observed = []
        get_running_loop().call_soon(
            lambda: observed.extend(transport.output(FrameType.SETTINGS))
        )
        await transport.session._receive(frame(4) * 3)
        self.assertTrue(any(item.payload.ack for item in observed))

    async def test_intermediate_window_overflow_is_rejected(self):
        transport = Transport()
        await transport.start(request())
        await transport.session._receive(window_update_frame(1, 1))
        payload = struct.pack("!HIHI", 4, 0x7FFFFFFF, 4, 65535)
        with self.assertRaises(ProtocolError):
            await transport.session._receive(frame(4, payload))
        self.assertEqual(transport.output(FrameType.GOAWAY)[0].payload.error_code, 3)
        self.assertEqual(
            sum(item.payload.ack for item in transport.output(FrameType.SETTINGS)), 1
        )


class HTTP2PriorityUpdateTests(unittest.IsolatedAsyncioTestCase):
    async def test_idle_and_active_streams_share_the_advertised_limit(self):
        for request_end in (None, False, True):
            with self.subTest(request_end=request_end):
                transport = Transport()
                packets = [settings_frame({3: 1}), frame(4, flags=1)]
                active = request_end is not None
                if active:
                    packets.append(request(end=request_end))
                start = 3 if active else 1
                count = 99 if active else 100
                packets.extend(
                    priority_update(stream_id)
                    for stream_id in range(start, start + 2 * count, 2)
                )
                await transport.session.initialize(HTTP2_PREFACE + b"".join(packets))
                self.assertEqual(
                    transport.output(FrameType.SETTINGS)[0].payload.settings[3], 100
                )
                self.assertEqual(transport.output(FrameType.GOAWAY), [])
                overflow = priority_update(start + 2 * count)
                with self.assertRaisesRegex(ProtocolError, "stream limit exceeded"):
                    await transport.session._receive(overflow)
                await transport.session.close()
                self.assertEqual(
                    [item.raw for item in transport.session.capture.frames],
                    [*packets, overflow],
                )
                self.assertEqual(
                    [item.payload.error_code for item in transport.output(7)],
                    [ErrorCodes.PROTOCOL_ERROR],
                )

    async def test_opening_a_prioritized_stream_and_repeated_updates_do_not_add_slots(
        self,
    ):
        packets = [priority_update(stream_id) for stream_id in range(1, 201, 2)]
        packets.append(request(end=False))
        packets.extend([priority_update(1), priority_update(3)] * 10)
        packets.append(data_frame(1, b"", end_stream=True))
        transport = Transport()
        await transport.start(b"".join(packets))
        await transport.session.send_response(b"ok")
        self.assertEqual(transport.output(FrameType.GOAWAY), [])
        self.assertEqual(transport.output(FrameType.DATA)[0].payload.data, b"ok")
        self.assertEqual(
            [item.raw for item in transport.session.capture.frames[1:]], packets
        )

    async def test_opening_below_prioritized_ids_checks_the_combined_limit(self):
        for idle_count in (99, 100):
            with self.subTest(idle_count=idle_count):
                priorities = b"".join(
                    priority_update(stream_id)
                    for stream_id in range(3, 3 + 2 * idle_count, 2)
                )
                transport = Transport()
                await transport.session.initialize(
                    HTTP2_PREFACE + settings_frame() + priorities
                )
                if idle_count == 99:
                    await transport.session._receive(request())
                    await transport.session.receive_request()
                    await transport.session.send_response(b"ok")
                    self.assertEqual(transport.output(FrameType.GOAWAY), [])
                else:
                    with self.assertRaisesRegex(ProtocolError, "stream limit exceeded"):
                        await transport.session._receive(request())
                    self.assertEqual(transport.output(FrameType.HEADERS), [])
                    self.assertEqual(
                        transport.output(FrameType.GOAWAY)[0].payload.error_code,
                        ErrorCodes.PROTOCOL_ERROR,
                    )

    async def test_skipped_refused_and_finished_streams_release_slots(self):
        incoming = request(end=False)
        incoming += b"".join(
            priority_update(stream_id) for stream_id in range(3, 201, 2)
        )
        # Refusing stream 5 also closes skipped stream 3 and frees both idle slots.
        incoming += request(stream=5)
        incoming += frame(3, struct.pack("!I", ErrorCodes.CANCEL), stream=5)
        incoming += b"".join(
            priority_update(stream_id) for stream_id in (3, 5, 201, 203)
        )
        incoming += data_frame(1, b"", end_stream=True)
        transport = Transport()
        await transport.start(incoming)
        await transport.session.send_response(b"ok")
        # The completed response frees the accepted stream's active slot.
        await transport.session._receive(priority_update(1) + priority_update(205))
        self.assertEqual(transport.output(FrameType.GOAWAY), [])
        self.assertEqual(
            [
                (item.header.stream_id, item.payload.error_code)
                for item in transport.output(3)
            ],
            [(5, ErrorCodes.REFUSED_STREAM)],
        )
        with self.assertRaisesRegex(ProtocolError, "stream limit exceeded"):
            await transport.session._receive(priority_update(207))
        self.assertEqual(
            transport.output(FrameType.GOAWAY)[0].payload.error_code,
            ErrorCodes.PROTOCOL_ERROR,
        )

    async def test_local_limit_changes_take_effect_after_acknowledgment(self):
        transport = Transport()
        await transport.session.initialize(
            HTTP2_PREFACE + settings_frame() + frame(4, flags=1)
        )
        transport.session.connection.update_settings(
            {SettingCodes.MAX_CONCURRENT_STREAMS: 2}
        )
        await transport.session._flush()
        await transport.session._receive(
            b"".join(priority_update(stream_id) for stream_id in (1, 3, 5))
        )
        self.assertEqual(transport.output(FrameType.GOAWAY), [])
        await transport.session._receive(frame(4, flags=1))
        with self.assertRaisesRegex(ProtocolError, "stream limit exceeded"):
            await transport.session._receive(priority_update(5))
        self.assertEqual(
            transport.output(FrameType.GOAWAY)[0].payload.error_code,
            ErrorCodes.PROTOCOL_ERROR,
        )

    async def test_malformed_priority_updates_keep_their_existing_wire_errors(self):
        for packet, code in (
            (frame(16, struct.pack("!I", 1), stream=1), ErrorCodes.PROTOCOL_ERROR),
            (priority_update(0), ErrorCodes.PROTOCOL_ERROR),
            (priority_update(2), ErrorCodes.PROTOCOL_ERROR),
            (frame(16, bytes(3)), ErrorCodes.FRAME_SIZE_ERROR),
        ):
            with self.subTest(packet=packet.hex()):
                transport = Transport()
                with self.assertRaises(ProtocolError):
                    await transport.start(packet + request())
                self.assertEqual(
                    transport.output(FrameType.GOAWAY)[0].payload.error_code, code
                )
                self.assertEqual(transport.session.capture.frames[-1].raw, packet)


class HTTP2CompressionStateTests(unittest.IsolatedAsyncioTestCase):
    async def test_malformed_hpack_sends_one_compression_error_goaway(self):
        for name, block in (
            ("forbidden index zero", b"\x80"),
            ("truncated integer", b"\xff"),
            ("table size exceeds advertised limit", b"\x3f\xe2\x1f"),
        ):
            with self.subTest(case=name):
                transport = Transport()
                with self.assertRaises(ProtocolError) as caught:
                    await transport.start(frame(1, block, flags=5, stream=1))
                await transport.session.close()
                self.assertEqual(
                    [f.payload.error_code for f in transport.output(FrameType.GOAWAY)],
                    [ErrorCodes.COMPRESSION_ERROR],
                )
                self.assertEqual(
                    caught.exception.error_code, ErrorCodes.COMPRESSION_ERROR
                )
                self.assertEqual(transport.output(FrameType.HEADERS), [])

    async def test_table_updates_use_smallest_and_final_acknowledged_sizes(self):
        cases = [
            ([0, 4096], [0, 4096]),
            ([8192, 4096], [4096]),
            ([2048, 0, 4096], [0, 4096]),
            ([0, 4096, 4096], [0, 4096]),
            ([8192, 2048, 4096, 0], [0]),
        ]
        for sizes, expected in cases:
            for separate_frames in (False, True):
                with self.subTest(sizes=sizes, separate_frames=separate_frames):
                    packets = (
                        [table_settings([size]) for size in sizes]
                        if separate_frames
                        else [table_settings(sizes)]
                    )
                    expected_entries = (
                        [[(1, size)] for size in sizes]
                        if separate_frames
                        else [[(1, size) for size in sizes]]
                    )
                    ping = frame(6, b"sizeping")
                    incoming = b"".join(packets) + ping + request()
                    transport = Transport()
                    await transport.session.initialize(HTTP2_PREFACE + incoming)
                    await transport.session.receive_request()
                    await transport.session.send_response(b"ok")

                    block = transport.output(FrameType.HEADERS)[0].payload.header_block
                    self.assertEqual(table_updates(block), expected)
                    decoder = Decoder()
                    decoder.max_allowed_table_size = sizes[-1]
                    self.assertIn((":status", "200"), decoder.decode(block))
                    self.assertEqual(
                        sum(
                            f.payload.ack for f in transport.output(FrameType.SETTINGS)
                        ),
                        len(packets),
                    )
                    self.assertEqual(
                        transport.output(FrameType.PING)[0].payload.data, b"sizeping"
                    )
                    self.assertEqual(
                        [f.raw for f in transport.session.capture.frames],
                        [*packets, ping, request()],
                    )
                    self.assertEqual(
                        [
                            f.payload.entries
                            for f in transport.session.capture.frames
                            if f.header.type == FrameType.SETTINGS
                        ],
                        expected_entries,
                    )

    async def test_interim_continue_uses_the_same_table_update_rules(self):
        sizes = [8192, 2048, 0, 4096]
        transport = Transport()
        incoming = (
            table_settings(sizes)
            + request(end=False, extra=[(b"expect", b"100-continue")])
            + data_frame(1, b"body", end_stream=True)
        )
        await transport.session.initialize(HTTP2_PREFACE + incoming)
        await transport.session.receive_request()
        await transport.session.send_response(b"ok")

        blocks = [f.payload.header_block for f in transport.output(FrameType.HEADERS)]
        self.assertEqual(len(blocks), 2)
        self.assertEqual(table_updates(blocks[0]), [0, 4096])
        self.assertEqual(table_updates(blocks[1]), [])
        decoder = Decoder()
        decoder.max_allowed_table_size = 4096
        self.assertEqual(decoder.decode(blocks[0]), [(":status", "100")])
        self.assertIn((":status", "200"), decoder.decode(blocks[1]))

    async def test_shrink_then_grow_evicts_prior_response_table_entries(self):
        transport = Transport()
        await transport.start(request())
        encoder = transport.session.connection.encoder
        decoder = Decoder()
        fields = [(b"x-eviction", b"remembered")]
        self.assertEqual(decoder.decode(encoder.encode(fields), raw=True), fields)

        await transport.session._receive(table_settings([8192, 0, 4096, 4096]))
        block = encoder.encode(fields)
        self.assertEqual(table_updates(block), [0, 4096])
        # A stale indexed reference would fail after the decoder applies size 0.
        self.assertEqual(decoder.decode(block, raw=True), fields)


if __name__ == "__main__":
    unittest.main()
