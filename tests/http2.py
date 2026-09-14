import struct
from collections import deque

from hpack import Decoder, Encoder

from solvetls.http2.frames import HTTP2FrameReader
from solvetls.http2.session import HTTP2_PREFACE, HTTP2Session


def frame(kind, payload=b"", *, flags=0, stream=0):
    return (
        len(payload).to_bytes(3, "big")
        + bytes((kind, flags))
        + struct.pack("!I", stream)
        + payload
    )


def data_frame(stream_id, data, end_stream=False):
    return frame(0, data, flags=int(end_stream), stream=stream_id)


def headers_frame(stream_id, block, end_stream=False, end_headers=False):
    flags = int(end_stream) | (4 if end_headers else 0)
    return frame(1, block, flags=flags, stream=stream_id)


def settings_frame(settings=None):
    entries = settings.items() if isinstance(settings, dict) else settings or ()
    payload = b"".join(struct.pack("!HI", *item) for item in entries)
    return frame(4, payload)


def window_update_frame(stream_id, increment):
    return frame(8, struct.pack("!I", increment), stream=stream_id)


def unknown_settings_flood():
    """Previously expanded h2 state, then made it scan 60,000 keys per repeat."""
    seed = [
        frame(
            4,
            b"".join(struct.pack("!HI", key, 0) for key in range(start, start + 10000)),
        )
        for start in range(32, 60032, 10000)
    ]
    return [*seed, frame(4, struct.pack("!HI", 0xDEAD, 0) * 10000)]


def wire_frames(data):
    for kind, flags, _stream, payload in _wire_frames(data):
        yield kind, flags, payload


def _wire_frames(data):
    while data:
        if len(data) < 9:
            raise AssertionError("Incomplete HTTP/2 frame header")
        length = int.from_bytes(data[:3], "big")
        end = 9 + length
        if len(data) < end:
            raise AssertionError("Incomplete HTTP/2 frame payload")
        stream = int.from_bytes(data[5:9], "big") & 0x7FFFFFFF
        yield data[3], data[4], stream, data[9:end]
        data = data[end:]


def response(result):
    """Extract one response, requiring complete header blocks and END_STREAM."""
    headers = []
    body = bytearray()
    header_block = bytearray()
    header_block_open = False
    response_stream = None
    stream_ended = False
    decoder = Decoder()
    for kind, flags, stream, payload in _wire_frames(result["raw_response"]):
        if header_block_open and kind != 9:
            raise AssertionError("Frame interrupts HTTP/2 response headers")
        if kind not in (0, 1, 9):
            continue
        if not stream or (response_stream is not None and stream != response_stream):
            raise AssertionError("Unexpected HTTP/2 response stream")
        if response_stream is None:
            if kind != 1:
                raise AssertionError("HTTP/2 response must start with HEADERS")
            response_stream = stream
        if kind == 9:
            if not header_block_open:
                raise AssertionError("Unexpected HTTP/2 response CONTINUATION")
        else:
            if stream_ended:
                raise AssertionError("HTTP/2 response continues after END_STREAM")
            if kind == 1:
                header_block_open = True
            stream_ended = bool(flags & 1)
        if kind in (1, 9):
            header_block.extend(payload)
            if flags & 4:
                headers.extend(decoder.decode(header_block))
                header_block.clear()
                header_block_open = False
        elif kind == 0:
            body.extend(payload)
    if header_block_open:
        raise AssertionError("Incomplete HTTP/2 response headers")
    if not stream_ended:
        raise AssertionError("HTTP/2 response missing END_STREAM")
    return dict(headers), bytes(body)


def request(
    encoder=None,
    stream=1,
    method=b"GET",
    path=b"/",
    end=True,
    extra=(),
    authority=None,
):
    encoder = encoder or Encoder()
    if authority is None:
        authority = b"localhost:443" if method == b"CONNECT" else b"localhost"
    fields = [(b":method", method), (b":authority", authority)]
    if method != b"CONNECT":
        fields += [(b":scheme", b"https"), (b":path", path)]
    return headers_frame(
        stream, encoder.encode([*fields, *extra]), end_stream=end, end_headers=True
    )


def frames(data):
    """Decode complete server output; reject an incomplete trailing frame."""
    reader = HTTP2FrameReader(data, max_frame_size=16777215, strict_padding=False)
    result = []
    while reader.has_more_frames():
        result.append(reader.parse_frame())
    return result


class Transport:
    def __init__(self, incoming=()):
        self.incoming = deque(incoming)
        self.sent = []
        self.reads = 0
        self.session = HTTP2Session(self)

    async def read(self):
        self.reads += 1
        if not self.incoming:
            raise AssertionError("session waits despite no further client input")
        return self.incoming.popleft()

    async def write(self, data):
        self.sent.append(data)

    async def start(self, incoming, settings=None):
        await self.session.initialize(
            HTTP2_PREFACE + settings_frame(settings or {}) + incoming
        )
        await self.session.receive_request()

    def output(self, frame_type=None):
        result = frames(b"".join(self.sent))
        return [
            frame
            for frame in result
            if frame_type is None or frame.header.type == frame_type
        ]
