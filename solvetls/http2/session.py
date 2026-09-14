from asyncio import sleep
from dataclasses import dataclass, field
from typing import Protocol

from h2.errors import ErrorCodes
from h2.events import (
    DataReceived,
    RequestReceived,
    StreamEnded,
    StreamReset,
    TrailersReceived,
)
from h2.exceptions import ProtocolError
from h2.settings import SettingCodes, Settings

from ..http_fields import parse_expectations, prepare_response
from .adapter import (
    MAX_HEADER_LIST_SIZE,
    MAX_REQUEST_BODY,
    H2Adapter,
    bounded_content_length,
)
from .frames import (
    FRAME_HEADER_SIZE,
    FrameFlags,
    FrameType,
    HTTP2FrameBuilder,
    HTTP2FrameParsingError,
    HTTP2FrameReader,
    ParsedFrame,
    SettingsPayload,
)
from .validation import validate_fields

HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
SERVER_MAX_FRAME_SIZE = 65536
SERVER_INITIAL_WINDOW_SIZE = 1048576
MAX_CAPTURE_BYTES = 2097152
MAX_CAPTURE_FRAMES = 4096
# Bound structured report expansion as well as the captured wire bytes.
MAX_CAPTURE_ENTRIES = 1024


@dataclass
class HTTP2Capture:
    frames: list[ParsedFrame] = field(default_factory=list)
    initial_settings: list[tuple[int, int]] | None = None
    headers: list[tuple[bytes, bytes]] | None = None
    trailers: list[tuple[bytes, bytes]] = field(default_factory=list)
    stream_id: int | None = None
    expectation_failed: bool = False


class HTTP2Transport(Protocol):
    async def read(self) -> bytes: ...

    async def write(self, content: bytes) -> None: ...


class HTTP2Session:
    """A bounded HTTP/2 connection serving one request and refusing further streams.

    h2 owns HPACK, stream state, SETTINGS and flow control; the parallel parser
    preserves original frame bytes and field order for reports.
    """

    def __init__(self, transport: HTTP2Transport):
        self.transport = transport
        self.capture = HTTP2Capture()
        self.connection = H2Adapter()
        self.connection.local_settings = Settings(
            client=False,
            initial_values={
                # Allow extra streams to be refused without h2 closing the
                # connection and interrupting the accepted request.
                SettingCodes.MAX_CONCURRENT_STREAMS: 100,
                SettingCodes.MAX_HEADER_LIST_SIZE: MAX_HEADER_LIST_SIZE,
                SettingCodes.INITIAL_WINDOW_SIZE: SERVER_INITIAL_WINDOW_SIZE,
                SettingCodes.MAX_FRAME_SIZE: SERVER_MAX_FRAME_SIZE,
            },
        )
        self.connection.max_inbound_frame_size = SERVER_MAX_FRAME_SIZE
        self._buffer = bytearray()
        self._capture_bytes = 0
        self._capture_entries = 0
        self._first_frame = True
        self._continuation_stream = None
        self._header_block_bytes = 0
        self._prioritized_idle_streams: set[int] = set()
        self._request_ready = False
        self._request_bytes = 0
        self._expected_length = None
        self._cancelled = False
        self._initialized = False
        self._closed = False

    async def initialize(self, incoming_data: bytes):
        """Send our preface before acknowledging the peer's initial SETTINGS."""
        if self._initialized:
            raise RuntimeError("HTTP/2 session already initialized")
        self._initialized = True
        self.connection.initiate_connection()
        await self._flush()
        if not incoming_data.startswith(HTTP2_PREFACE):
            await self._fail("Invalid HTTP/2 connection preface")
        self.connection.receive_data(HTTP2_PREFACE)
        remaining = incoming_data[len(HTTP2_PREFACE) :]
        if remaining:
            await self._receive(remaining)

    async def receive_request(self):
        while not self._request_ready:
            await self._receive(await self.transport.read())
        self._check_cancelled()

    async def send_response(
        self, content: bytes, headers: dict | None = None, status_code: int = 200
    ):
        self._check_cancelled()
        stream_id = self.capture.stream_id
        if stream_id is None or not self._request_ready:
            raise RuntimeError("No complete HTTP/2 request")
        content, headers = prepare_response(content, headers, status_code)
        response_headers = {":status": str(status_code), **headers}
        self.connection.send_headers(
            stream_id, list(response_headers.items()), end_stream=not content
        )
        await self._flush()
        offset = 0
        while offset < len(content):
            self._check_cancelled()
            available = min(
                self.connection.local_flow_control_window(stream_id),
                self.connection.max_outbound_frame_size,
            )
            if available <= 0:
                await self._receive(await self.transport.read())
                continue
            end = min(offset + available, len(content))
            self.connection.send_data(
                stream_id, content[offset:end], end_stream=end == len(content)
            )
            await self._flush()
            offset = end

    async def close(self, error_code: int = ErrorCodes.NO_ERROR):
        """Send at most one GOAWAY; never replace a protocol failure with NO_ERROR."""
        if not self._closed:
            self.connection.close_connection(
                error_code=error_code,
                last_stream_id=self.capture.stream_id or 0,
            )
            self._closed = True
        await self._flush()

    async def _flush(self):
        data = self.connection.data_to_send()
        if data:
            await self.transport.write(data)

    async def _fail(self, message: str, error_code: int = ErrorCodes.PROTOCOL_ERROR):
        error = ProtocolError(message)
        error.error_code = error_code
        await self.close(error_code=error_code)
        raise error

    def _check_cancelled(self):
        if self._cancelled:
            raise ConnectionResetError("HTTP/2 request stream was reset")
        if self._closed:
            raise ConnectionResetError("HTTP/2 connection is closed")

    async def _receive(self, data: bytes):
        if not data:
            raise ConnectionResetError("HTTP/2 connection closed before completion")
        self._capture_bytes += len(data)
        if self._capture_bytes > MAX_CAPTURE_BYTES:
            await self._fail(
                "HTTP/2 capture limit exceeded", ErrorCodes.ENHANCE_YOUR_CALM
            )
        self._buffer.extend(data)
        while len(self._buffer) >= FRAME_HEADER_SIZE:
            length = int.from_bytes(self._buffer[:3], "big")
            maximum = self.connection.max_inbound_frame_size
            if length > maximum:
                await self._fail(
                    "HTTP/2 frame size limit exceeded", ErrorCodes.FRAME_SIZE_ERROR
                )
            frame_end = FRAME_HEADER_SIZE + length
            if len(self._buffer) < frame_end:
                break
            wire = bytes(self._buffer[:frame_end])
            del self._buffer[:frame_end]
            try:
                reader = HTTP2FrameReader(
                    wire,
                    max_frame_size=maximum,
                    strict_padding=False,
                    forensic=True,
                    max_entries=MAX_CAPTURE_ENTRIES - self._capture_entries,
                )
                frame = reader.parse_frame()
            except HTTP2FrameParsingError as error:
                await self._fail(str(error), error.code)
            self._capture_entries += reader.entries_read
            if len(self.capture.frames) >= MAX_CAPTURE_FRAMES:
                await self._fail(
                    "HTTP/2 frame count limit exceeded", ErrorCodes.ENHANCE_YOUR_CALM
                )
            self.capture.frames.append(frame)
            await self._process_frame(frame, wire)
        await self._flush()
        self._check_cancelled()

    async def _process_frame(self, frame: ParsedFrame, wire: bytes):
        frame_type = frame.header.type
        payload = frame.payload
        if self._first_frame:
            if frame_type != FrameType.SETTINGS or frame.header.flags & FrameFlags.ACK:
                await self._fail("First HTTP/2 frame must be client SETTINGS")
            self._first_frame = False
            if isinstance(payload, SettingsPayload):
                self.capture.initial_settings = payload.entries
        if self._continuation_stream is not None and (
            frame_type != FrameType.CONTINUATION
            or frame.header.stream_id != self._continuation_stream
        ):
            await self._fail("CONTINUATION on the same stream was expected")
        if frame_type in (FrameType.HEADERS, FrameType.CONTINUATION):
            self._header_block_bytes += frame.header.length
            if self._header_block_bytes > MAX_HEADER_LIST_SIZE:
                await self._fail(
                    "HTTP/2 header block limit exceeded", ErrorCodes.ENHANCE_YOUR_CALM
                )
            if frame.header.flags & FrameFlags.END_HEADERS:
                self._continuation_stream = None
                self._header_block_bytes = 0
            else:
                self._continuation_stream = frame.header.stream_id
        if frame_type in (FrameType.ALTSVC, FrameType.ORIGIN):
            # These server-to-client advertisements must be ignored here, including
            # malformed extension payloads.  Keep them in the forensic report.
            return
        if getattr(payload, "parse_error", None):
            await self._fail(payload.parse_error, payload.error_code)
        if frame_type == FrameType.PUSH_PROMISE:
            # h2 otherwise waits for END_HEADERS before rejecting client push.
            await self._fail("Clients must not send PUSH_PROMISE")
        if frame_type == FrameType.RST_STREAM:
            # h2 ignores resets for unknown streams, including idle ones. RFC
            # 9113 6.4 requires a connection error for idle IDs. Lower IDs have
            # already become closed implicitly and must retain h2's handling.
            highest = (
                self.connection.highest_inbound_stream_id
                if frame.header.stream_id % 2
                else self.connection.highest_outbound_stream_id
            )
            if frame.header.stream_id > highest:
                await self._fail("RST_STREAM refers to an idle stream")
        if frame_type == FrameType.PRIORITY:
            # RFC 9113 deprecates RFC 7540 priorities, including its self-dependency
            # restriction.  Preserve the signal but do not schedule by it.
            return
        if frame_type == FrameType.PRIORITY_UPDATE:
            stream_id = payload.prioritized_stream_id
            if stream_id % 2 == 0:
                await self._fail("PRIORITY_UPDATE refers to an idle push stream")
            if stream_id > self.connection.highest_inbound_stream_id:
                self._prioritized_idle_streams.add(stream_id)
            else:
                stream = self.connection.streams.get(stream_id)
                if stream is None or stream.closed:
                    return
            await self._check_priority_limit()
            return
        if frame_type == FrameType.GOAWAY:
            # No server-initiated streams exist.  A graceful client GOAWAY does
            # not prevent completion of its already accepted request.
            if payload.error_code != ErrorCodes.NO_ERROR:
                self._cancelled = True
            return
        if frame_type == FrameType.HEADERS and frame.header.flags & FrameFlags.PRIORITY:
            # h2 still implements the obsolete self-dependency rejection.  Only
            # remove the advisory priority/padding envelope; HPACK bytes are intact.
            wire = HTTP2FrameBuilder.build_headers_frame(
                frame.header.stream_id,
                payload.header_block,
                end_stream=payload.end_stream,
                end_headers=payload.end_headers,
            )
        try:
            if frame_type == FrameType.SETTINGS and not payload.ack:
                await self.connection.apply_settings(payload.entries)
            else:
                for event in self.connection.receive_data(wire):
                    await self._process_event(event)
        except ProtocolError:
            # receive_data has already queued a correctly classified GOAWAY.
            # Validation errors raised by our event adapter need one as well.
            if not self._closed:
                pending = self.connection.data_to_send()
                if pending:
                    await self.transport.write(pending)
                    self._closed = True
                else:
                    raise
            raise
        await self._flush()

        if frame_type == FrameType.SETTINGS and not payload.ack:
            await sleep(0)

    async def _check_priority_limit(self):
        # RFC 9218 7.1 counts distinct idle targets together with active streams,
        # even though these advisory priorities do not affect our scheduling.
        total = (
            len(self._prioritized_idle_streams) + self.connection.open_inbound_streams
        )
        if total > self.connection.local_settings.max_concurrent_streams:
            await self._fail("PRIORITY_UPDATE stream limit exceeded")

    async def _process_event(self, event):
        if isinstance(event, RequestReceived):
            # Opening this ID also closes any skipped lower IDs implicitly.
            self._prioritized_idle_streams = {
                stream_id
                for stream_id in self._prioritized_idle_streams
                if stream_id > event.stream_id
            }
            if self.capture.stream_id is not None:
                self.connection.reset_stream(event.stream_id, ErrorCodes.REFUSED_STREAM)
                return
            await self._check_priority_limit()
        if isinstance(event, (RequestReceived, TrailersReceived)):
            try:
                validate_fields(
                    event.headers, trailers=isinstance(event, TrailersReceived)
                )
            except ProtocolError as error:
                await self._fail(str(error))
        if isinstance(event, RequestReceived):
            self.capture.stream_id = event.stream_id
            self.capture.headers = list(event.headers)
            values = dict(event.headers)
            content_length = values.get(b"content-length")
            if content_length is not None:
                self._expected_length = bounded_content_length(content_length)
                if self._expected_length > MAX_REQUEST_BODY:
                    await self._fail(
                        "HTTP/2 request body limit exceeded",
                        ErrorCodes.ENHANCE_YOUR_CALM,
                    )
            try:
                expectations = parse_expectations(
                    value for name, value in event.headers if name == b"expect"
                )
            except ValueError:
                expectations = ["invalid expectation"]
            if any(value != "100-continue" for value in expectations):
                self.capture.expectation_failed = True
                self._request_ready = True
            elif values[b":method"] == b"CONNECT":
                self._request_ready = True
            elif expectations and event.stream_ended is None:
                self.connection.send_headers(event.stream_id, [(b":status", b"100")])
        elif isinstance(event, TrailersReceived):
            if event.stream_id == self.capture.stream_id:
                self.capture.trailers = list(event.headers)
        elif isinstance(event, DataReceived):
            if event.stream_id == self.capture.stream_id:
                self._request_bytes += len(event.data)
                if self._request_bytes > MAX_REQUEST_BODY:
                    await self._fail(
                        "HTTP/2 request body limit exceeded",
                        ErrorCodes.ENHANCE_YOUR_CALM,
                    )
            self.connection.acknowledge_received_data(
                event.flow_controlled_length, event.stream_id
            )
        elif (
            isinstance(event, StreamEnded) and event.stream_id == self.capture.stream_id
        ):
            # h2 checks lengths on DATA, but reinitializes its expected length
            # when decoding trailers. Keep the original request's declaration
            # and verify it here as well, including an END_STREAM on HEADERS.
            if (
                self._expected_length is not None
                and self._expected_length != self._request_bytes
            ):
                await self._fail("HTTP/2 Content-Length does not match request body")
            self._request_ready = True
        elif (
            isinstance(event, StreamReset) and event.stream_id == self.capture.stream_id
        ):
            self._cancelled = True
