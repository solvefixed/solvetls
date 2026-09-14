import struct
from dataclasses import dataclass, field
from enum import IntEnum


class FrameType(IntEnum):
    DATA = 0x00
    HEADERS = 0x01
    PRIORITY = 0x02  # Deprecated in RFC 9113
    RST_STREAM = 0x03
    SETTINGS = 0x04
    PUSH_PROMISE = 0x05
    PING = 0x06
    GOAWAY = 0x07
    WINDOW_UPDATE = 0x08
    CONTINUATION = 0x09
    ALTSVC = 0x0A  # RFC 7838
    ORIGIN = 0x0C  # RFC 8336
    PRIORITY_UPDATE = 0x10  # RFC 9218


class FrameFlags(IntEnum):
    END_STREAM = 0x01
    END_HEADERS = 0x04
    PADDED = 0x08
    PRIORITY = 0x20  # Deprecated
    ACK = 0x01


class ErrorCode(IntEnum):
    NO_ERROR = 0x00
    PROTOCOL_ERROR = 0x01
    INTERNAL_ERROR = 0x02
    FLOW_CONTROL_ERROR = 0x03
    SETTINGS_TIMEOUT = 0x04
    STREAM_CLOSED = 0x05
    FRAME_SIZE_ERROR = 0x06
    REFUSED_STREAM = 0x07
    CANCEL = 0x08
    COMPRESSION_ERROR = 0x09
    CONNECT_ERROR = 0x0A
    ENHANCE_YOUR_CALM = 0x0B
    INADEQUATE_SECURITY = 0x0C
    HTTP_1_1_REQUIRED = 0x0D


class SettingsIdentifier(IntEnum):
    HEADER_TABLE_SIZE = 0x01
    ENABLE_PUSH = 0x02
    MAX_CONCURRENT_STREAMS = 0x03
    INITIAL_WINDOW_SIZE = 0x04
    MAX_FRAME_SIZE = 0x05
    MAX_HEADER_LIST_SIZE = 0x06
    ENABLE_CONNECT_PROTOCOL = 0x08
    NO_RFC7540_PRIORITIES = 0x09


FRAME_HEADER_SIZE = 9
DEFAULT_MAX_FRAME_SIZE = 16384  # RFC 9113 6.5.2, and the floor a peer may ask for
MAX_ALLOWED_FRAME_SIZE = 16777215  # the 24-bit length field is the ceiling
MAX_STREAM_ID = 0x7FFFFFFF  # 31 bits; the top one is reserved
RESERVED_BIT_MASK = 0x80000000
PING_PAYLOAD_SIZE = 8
PRIORITY_PAYLOAD_SIZE = 5
RST_STREAM_PAYLOAD_SIZE = 4
WINDOW_UPDATE_PAYLOAD_SIZE = 4
SETTINGS_ENTRY_SIZE = 6


@dataclass
class FrameHeader:
    length: int
    type: int
    flags: int
    stream_id: int


@dataclass
class DataPayload:
    data: bytes
    end_stream: bool
    padded: bool = False


@dataclass
class PriorityInfo:
    exclusive: bool
    dependency: int
    weight: int


@dataclass
class HeadersPayload:
    header_block: bytes
    priority: PriorityInfo | None
    end_stream: bool
    end_headers: bool
    padded: bool = False


@dataclass
class RstStreamPayload:
    error_code: int


@dataclass
class SettingsPayload:
    ack: bool = False
    settings: dict[int, int] | None = None
    # Effective values alone lose repeated parameters and their wire order.
    entries: list[tuple[int, int]] = field(default_factory=list)


@dataclass
class PushPromisePayload:
    promised_stream_id: int
    header_block: bytes
    end_headers: bool
    padded: bool = False


@dataclass
class PingPayload:
    data: bytes
    ack: bool = False


@dataclass
class GoawayPayload:
    last_stream_id: int
    error_code: int
    debug_data: bytes


@dataclass
class WindowUpdatePayload:
    increment: int


@dataclass
class ContinuationPayload:
    header_block: bytes
    end_headers: bool


@dataclass
class AltSvcPayload:
    origin: bytes
    field_value: bytes


@dataclass
class OriginPayload:
    origins: list[bytes]


@dataclass
class PriorityUpdatePayload:
    prioritized_stream_id: int
    priority_field_value: bytes


@dataclass
class UnknownPayload:
    unknown_type: int
    raw_payload: bytes
    parse_error: str | None = None
    error_code: int | None = None


PayloadType = (
    DataPayload
    | HeadersPayload
    | PriorityInfo
    | RstStreamPayload
    | SettingsPayload
    | PushPromisePayload
    | PingPayload
    | GoawayPayload
    | WindowUpdatePayload
    | ContinuationPayload
    | AltSvcPayload
    | OriginPayload
    | PriorityUpdatePayload
    | UnknownPayload
)


@dataclass
class ParsedFrame:
    header: FrameHeader
    payload: PayloadType
    raw: bytes = b""


class HTTP2FrameParsingError(Exception):
    def __init__(self, message: str, code: int = ErrorCode.PROTOCOL_ERROR):
        super().__init__(message)
        self.code = int(code)


class HTTP2FrameReader:
    def __init__(
        self,
        data: bytes,
        max_frame_size: int = DEFAULT_MAX_FRAME_SIZE,
        strict_padding: bool = True,
        forensic: bool = False,
        max_entries: int | None = None,
    ):
        self._data = data
        self._pos = 0
        self._max_frame_size = min(max_frame_size, MAX_ALLOWED_FRAME_SIZE)
        self._strict_padding = strict_padding
        self._forensic = forensic
        self._payload_end: int | None = None
        self._max_entries = max_entries
        self.entries_read = 0

    def _reserve_entries(self, count: int) -> None:
        if (
            self._max_entries is not None
            and self.entries_read + count > self._max_entries
        ):
            raise HTTP2FrameParsingError(
                "HTTP/2 decoded entry limit exceeded", ErrorCode.ENHANCE_YOUR_CALM
            )
        self.entries_read += count

    def _read(self, n: int) -> bytes:
        end = self._payload_end if self._payload_end is not None else len(self._data)
        if n < 0 or self._pos + n > end:
            raise HTTP2FrameParsingError(
                f"Insufficient data: need {n} bytes, have {end - self._pos}",
                ErrorCode.FRAME_SIZE_ERROR,
            )
        result = self._data[self._pos : self._pos + n]
        self._pos += n
        return result

    def _read_uint8(self) -> int:
        return struct.unpack("!B", self._read(1))[0]

    def _read_uint16(self) -> int:
        return struct.unpack("!H", self._read(2))[0]

    def _read_uint24(self) -> int:
        data = self._read(3)
        return struct.unpack("!I", b"\x00" + data)[0]

    def _read_uint32(self) -> int:
        return struct.unpack("!I", self._read(4))[0]

    def _read_uint32_with_reserved(self) -> int:
        # RFC 9113 4.1: the reserved bit MUST be ignored on receipt, not rejected.
        return self._read_uint32() & MAX_STREAM_ID

    def _read_priority(self) -> PriorityInfo:
        raw_dependency = self._read_uint32()
        return PriorityInfo(
            exclusive=bool(raw_dependency & RESERVED_BIT_MASK),
            dependency=raw_dependency & MAX_STREAM_ID,
            weight=self._read_uint8() + 1,
        )

    def _read_padding_length(self, header: FrameHeader) -> int:
        if not header.flags & FrameFlags.PADDED:
            return 0
        length = self._read_uint8()
        if length >= header.length:
            raise HTTP2FrameParsingError("Invalid padding length")
        return length

    def _skip_padding(self, length: int) -> None:
        padding = self._read(length)
        if self._strict_padding and any(padding):
            raise HTTP2FrameParsingError("Padding must be zero")

    def parse_frame(self) -> ParsedFrame:
        frame_start = self._pos
        if len(self._data) - self._pos < FRAME_HEADER_SIZE:
            raise HTTP2FrameParsingError(
                "Incomplete frame header", ErrorCode.FRAME_SIZE_ERROR
            )

        frame_length = self._read_uint24()
        frame_type = self._read_uint8()
        frame_flags = self._read_uint8()
        stream_id = self._read_uint32_with_reserved()

        if frame_length > self._max_frame_size:
            raise HTTP2FrameParsingError(
                f"Frame size {frame_length} exceeds maximum {self._max_frame_size}",
                ErrorCode.FRAME_SIZE_ERROR,
            )

        if frame_length > len(self._data) - self._pos:
            raise HTTP2FrameParsingError(
                "Incomplete frame payload", ErrorCode.FRAME_SIZE_ERROR
            )

        header = FrameHeader(frame_length, frame_type, frame_flags, stream_id)

        payload_start = self._pos
        payload_end = payload_start + frame_length
        self._payload_end = payload_end
        try:
            payload_data = self._parse_payload_by_type(header)
            bytes_read = self._pos - payload_start
            if bytes_read != frame_length:
                raise HTTP2FrameParsingError(
                    f"Payload: expected {frame_length} bytes, read {bytes_read}",
                    ErrorCode.FRAME_SIZE_ERROR,
                )
        except HTTP2FrameParsingError as error:
            if error.code == ErrorCode.ENHANCE_YOUR_CALM:
                raise
            # These extensions are ignored by a server. Their diagnostic decoder
            # must not turn an ignorable frame into a connection failure.
            # Forensic capture also preserves malformed core frames; the protocol
            # state machine remains responsible for rejecting their wire bytes.
            if not self._forensic and frame_type not in (
                FrameType.ALTSVC,
                FrameType.ORIGIN,
            ):
                raise
            self._pos = payload_end
            payload_data = UnknownPayload(
                unknown_type=frame_type,
                raw_payload=self._data[payload_start:payload_end],
                parse_error=str(error),
                error_code=error.code,
            )
        finally:
            self._payload_end = None

        return ParsedFrame(header, payload_data, self._data[frame_start:payload_end])

    def _parse_payload_by_type(self, header: FrameHeader) -> PayloadType:
        parsers = {
            FrameType.DATA: self._parse_data,
            FrameType.HEADERS: self._parse_headers,
            FrameType.PRIORITY: self._parse_priority,
            FrameType.RST_STREAM: self._parse_rst_stream,
            FrameType.SETTINGS: self._parse_settings,
            FrameType.PUSH_PROMISE: self._parse_push_promise,
            FrameType.PING: self._parse_ping,
            FrameType.GOAWAY: self._parse_goaway,
            FrameType.WINDOW_UPDATE: self._parse_window_update,
            FrameType.CONTINUATION: self._parse_continuation,
            FrameType.ALTSVC: self._parse_altsvc,
            FrameType.ORIGIN: self._parse_origin,
            FrameType.PRIORITY_UPDATE: self._parse_priority_update,
        }

        parser = parsers.get(header.type)
        if parser:
            return parser(header)
        # RFC 9113 requires ignoring unknown frame types. Preserve their raw
        # payload bytes for the diagnostic report.
        return UnknownPayload(
            unknown_type=header.type, raw_payload=self._read(header.length)
        )

    def _parse_data(self, header: FrameHeader) -> DataPayload:
        if header.stream_id == 0:
            raise HTTP2FrameParsingError("DATA frame must have non-zero stream ID")
        pad_length = self._read_padding_length(header)
        data_length = (
            header.length - (1 if header.flags & FrameFlags.PADDED else 0) - pad_length
        )
        if data_length < 0:
            raise HTTP2FrameParsingError("Invalid data length")

        data = self._read(data_length)
        self._skip_padding(pad_length)

        return DataPayload(
            data=data,
            end_stream=bool(header.flags & FrameFlags.END_STREAM),
            padded=bool(header.flags & FrameFlags.PADDED),
        )

    def _parse_headers(self, header: FrameHeader) -> HeadersPayload:
        if header.stream_id == 0:
            raise HTTP2FrameParsingError("HEADERS frame must have non-zero stream ID")
        pad_length = self._read_padding_length(header)
        priority_data = (
            self._read_priority() if header.flags & FrameFlags.PRIORITY else None
        )

        header_block_length = header.length
        if header.flags & FrameFlags.PADDED:
            header_block_length -= 1
        if header.flags & FrameFlags.PRIORITY:
            header_block_length -= 5
        header_block_length -= pad_length

        if header_block_length < 0:
            raise HTTP2FrameParsingError("Invalid header block length")

        header_block = self._read(header_block_length)
        self._skip_padding(pad_length)

        return HeadersPayload(
            header_block=header_block,
            priority=priority_data,
            end_stream=bool(header.flags & FrameFlags.END_STREAM),
            end_headers=bool(header.flags & FrameFlags.END_HEADERS),
            padded=bool(header.flags & FrameFlags.PADDED),
        )

    def _parse_priority(self, header: FrameHeader) -> PriorityInfo:
        if header.length != PRIORITY_PAYLOAD_SIZE:
            raise HTTP2FrameParsingError(
                f"PRIORITY frame must be {PRIORITY_PAYLOAD_SIZE} bytes",
                ErrorCode.FRAME_SIZE_ERROR,
            )

        if header.stream_id == 0:
            raise HTTP2FrameParsingError("PRIORITY frame must have non-zero stream ID")

        return self._read_priority()

    def _parse_rst_stream(self, header: FrameHeader) -> RstStreamPayload:
        if header.length != RST_STREAM_PAYLOAD_SIZE:
            raise HTTP2FrameParsingError(
                f"RST_STREAM frame must be {RST_STREAM_PAYLOAD_SIZE} bytes",
                ErrorCode.FRAME_SIZE_ERROR,
            )

        if header.stream_id == 0:
            raise HTTP2FrameParsingError(
                "RST_STREAM frame must have non-zero stream ID"
            )

        error_code = self._read_uint32()
        return RstStreamPayload(error_code=error_code)

    def _parse_settings(self, header: FrameHeader) -> SettingsPayload:
        if header.stream_id != 0:
            raise HTTP2FrameParsingError("SETTINGS frame must have stream ID = 0")

        if header.flags & FrameFlags.ACK:
            if header.length != 0:
                raise HTTP2FrameParsingError(
                    "SETTINGS ACK must have empty payload", ErrorCode.FRAME_SIZE_ERROR
                )
            return SettingsPayload(ack=True)

        if header.length % SETTINGS_ENTRY_SIZE != 0:
            raise HTTP2FrameParsingError(
                "Invalid SETTINGS payload length", ErrorCode.FRAME_SIZE_ERROR
            )

        self._reserve_entries(header.length // SETTINGS_ENTRY_SIZE)
        settings = {}
        entries = []
        for _ in range(header.length // SETTINGS_ENTRY_SIZE):
            setting_id = self._read_uint16()
            setting_value = self._read_uint32()
            # Validate every occurrence, including a value overwritten later in
            # this frame. RFC 9113 requires processing parameters in wire order.
            if setting_id == SettingsIdentifier.ENABLE_PUSH and setting_value not in (
                0,
                1,
            ):
                raise HTTP2FrameParsingError("SETTINGS_ENABLE_PUSH must be 0 or 1")
            if (
                setting_id == SettingsIdentifier.INITIAL_WINDOW_SIZE
                and setting_value > MAX_STREAM_ID
            ):
                raise HTTP2FrameParsingError(
                    "SETTINGS_INITIAL_WINDOW_SIZE exceeds maximum",
                    ErrorCode.FLOW_CONTROL_ERROR,
                )
            if setting_id == SettingsIdentifier.MAX_FRAME_SIZE and not (
                DEFAULT_MAX_FRAME_SIZE <= setting_value <= MAX_ALLOWED_FRAME_SIZE
            ):
                raise HTTP2FrameParsingError(
                    "SETTINGS_MAX_FRAME_SIZE is outside the allowed range"
                )
            entries.append((setting_id, setting_value))
            settings[setting_id] = setting_value

        return SettingsPayload(settings=settings, entries=entries)

    def _parse_push_promise(self, header: FrameHeader) -> PushPromisePayload:
        if header.stream_id == 0:
            raise HTTP2FrameParsingError(
                "PUSH_PROMISE frame must have non-zero stream ID"
            )

        pad_length = self._read_padding_length(header)

        promised_stream_id = self._read_uint32_with_reserved()
        if promised_stream_id == 0:
            raise HTTP2FrameParsingError("Promised stream ID must be non-zero")

        header_block_length = header.length
        if header.flags & FrameFlags.PADDED:
            header_block_length -= 1
        header_block_length -= 4
        header_block_length -= pad_length

        if header_block_length < 0:
            raise HTTP2FrameParsingError("Invalid header block length")

        header_block = self._read(header_block_length)
        self._skip_padding(pad_length)

        return PushPromisePayload(
            promised_stream_id=promised_stream_id,
            header_block=header_block,
            end_headers=bool(header.flags & FrameFlags.END_HEADERS),
            padded=bool(header.flags & FrameFlags.PADDED),
        )

    def _parse_ping(self, header: FrameHeader) -> PingPayload:
        if header.stream_id != 0:
            raise HTTP2FrameParsingError("PING frame must have stream ID = 0")

        if header.length != PING_PAYLOAD_SIZE:
            raise HTTP2FrameParsingError(
                f"PING frame must be {PING_PAYLOAD_SIZE} bytes",
                ErrorCode.FRAME_SIZE_ERROR,
            )

        data = self._read(PING_PAYLOAD_SIZE)
        return PingPayload(data=data, ack=bool(header.flags & FrameFlags.ACK))

    def _parse_goaway(self, header: FrameHeader) -> GoawayPayload:
        if header.stream_id != 0:
            raise HTTP2FrameParsingError("GOAWAY frame must have stream ID = 0")

        if header.length < 8:
            raise HTTP2FrameParsingError(
                "GOAWAY frame must be at least 8 bytes", ErrorCode.FRAME_SIZE_ERROR
            )

        last_stream_id = self._read_uint32_with_reserved()
        error_code = self._read_uint32()
        debug_data_length = header.length - 8
        debug_data = self._read(debug_data_length) if debug_data_length > 0 else b""

        return GoawayPayload(
            last_stream_id=last_stream_id, error_code=error_code, debug_data=debug_data
        )

    def _parse_window_update(self, header: FrameHeader) -> WindowUpdatePayload:
        if header.length != WINDOW_UPDATE_PAYLOAD_SIZE:
            raise HTTP2FrameParsingError(
                f"WINDOW_UPDATE frame must be {WINDOW_UPDATE_PAYLOAD_SIZE} bytes",
                ErrorCode.FRAME_SIZE_ERROR,
            )

        increment = self._read_uint32_with_reserved()
        if increment == 0:
            raise HTTP2FrameParsingError("Window size increment must not be 0")

        return WindowUpdatePayload(increment=increment)

    def _parse_continuation(self, header: FrameHeader) -> ContinuationPayload:
        if header.stream_id == 0:
            raise HTTP2FrameParsingError(
                "CONTINUATION frame must have non-zero stream ID"
            )

        header_block = self._read(header.length)
        return ContinuationPayload(
            header_block=header_block,
            end_headers=bool(header.flags & FrameFlags.END_HEADERS),
        )

    def _parse_altsvc(self, header: FrameHeader) -> AltSvcPayload:
        if header.length < 2:
            raise HTTP2FrameParsingError("ALTSVC frame too short")

        origin_len = self._read_uint16()
        if origin_len > header.length - 2:
            raise HTTP2FrameParsingError("Invalid origin length in ALTSVC")

        origin = self._read(origin_len)
        field_value_len = header.length - 2 - origin_len
        field_value = self._read(field_value_len)

        return AltSvcPayload(origin=origin, field_value=field_value)

    def _parse_origin(self, header: FrameHeader) -> OriginPayload:
        if header.stream_id != 0:
            raise HTTP2FrameParsingError("ORIGIN frame must have stream ID = 0")

        origins = []
        bytes_read = 0

        while bytes_read < header.length:
            if bytes_read + 2 > header.length:
                raise HTTP2FrameParsingError("Invalid ORIGIN frame format")

            origin_len = self._read_uint16()
            bytes_read += 2

            if bytes_read + origin_len > header.length:
                raise HTTP2FrameParsingError("Invalid origin length in ORIGIN frame")

            self._reserve_entries(1)
            origin = self._read(origin_len)
            origins.append(origin)
            bytes_read += origin_len

        return OriginPayload(origins=origins)

    def _parse_priority_update(self, header: FrameHeader) -> PriorityUpdatePayload:
        if header.stream_id != 0:
            raise HTTP2FrameParsingError(
                "PRIORITY_UPDATE frame must have stream ID = 0"
            )

        if header.length < 4:
            raise HTTP2FrameParsingError(
                "PRIORITY_UPDATE frame too short", ErrorCode.FRAME_SIZE_ERROR
            )

        prioritized_stream_id = self._read_uint32_with_reserved()
        if prioritized_stream_id == 0:
            raise HTTP2FrameParsingError("Prioritized stream ID must be non-zero")
        priority_field_value_len = header.length - 4
        priority_field_value = self._read(priority_field_value_len)

        return PriorityUpdatePayload(
            prioritized_stream_id=prioritized_stream_id,
            priority_field_value=priority_field_value,
        )

    def has_more_frames(self) -> bool:
        return self._pos < len(self._data)


class HTTP2FrameBuilder:
    @staticmethod
    def _build_frame(
        frame_type: int, flags: int, stream_id: int, payload: bytes
    ) -> bytes:
        if len(payload) > MAX_ALLOWED_FRAME_SIZE:
            raise ValueError(f"Frame length exceeds maximum ({MAX_ALLOWED_FRAME_SIZE})")
        if not 0 <= stream_id <= MAX_STREAM_ID:
            raise ValueError(f"Stream ID must be between 0 and {MAX_STREAM_ID}")

        header = struct.pack("!I", len(payload))[1:]  # 24-bit length
        header += struct.pack("!BB", frame_type, flags)
        header += struct.pack("!I", stream_id)
        return header + payload

    @staticmethod
    def build_headers_frame(
        stream_id: int,
        header_block: bytes,
        end_stream: bool = False,
        end_headers: bool = False,
    ) -> bytes:
        flags = 0
        if end_stream:
            flags |= FrameFlags.END_STREAM
        if end_headers:
            flags |= FrameFlags.END_HEADERS
        return HTTP2FrameBuilder._build_frame(
            FrameType.HEADERS, flags, stream_id, header_block
        )

    @staticmethod
    def build_settings_frame(
        settings: dict[int, int] | None = None, ack: bool = False
    ) -> bytes:
        flags = FrameFlags.ACK if ack else 0
        payload = b""

        if not ack and settings:
            for setting_id, value in settings.items():
                payload += struct.pack("!HI", setting_id, value)

        return HTTP2FrameBuilder._build_frame(FrameType.SETTINGS, flags, 0, payload)
