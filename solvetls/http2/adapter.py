from asyncio import sleep

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.errors import ErrorCodes
from h2.events import RequestReceived, TrailersReceived
from h2.exceptions import DenialOfServiceError, ProtocolError
from h2.settings import SettingCodes
from hpack import Decoder, Encoder
from hpack.exceptions import HPACKError, OversizedHeaderListError

from .frames import HTTP2FrameBuilder

MAX_REQUEST_BODY = 1048576
MAX_HEADER_LIST_SIZE = 65536
MAX_DECODED_HEADER_BYTES = 1048576
SUPPORTED_SETTINGS = frozenset(SettingCodes)
SETTINGS_BATCH_SIZE = 128
MAX_HEADER_TABLE_SIZE_CHANGES = 128


def bounded_content_length(value: bytes) -> int:
    """Bound decimal text without Python's integer digit limit."""
    significant = value.lstrip(b"0") or b"0"
    if len(significant) > len(str(MAX_REQUEST_BODY)):
        return MAX_REQUEST_BODY + 1
    return min(int(significant), MAX_REQUEST_BODY + 1)


class _RequestDecoder(Decoder):
    """Keep HPACK's table untouched while adapting h2's request event input."""

    def __init__(self):
        super().__init__(MAX_HEADER_LIST_SIZE)
        self.original_headers = None
        self.decoded_bytes = 0

    def decode(self, data, raw=False):
        try:
            headers = super().decode(data, raw=raw)
        except OversizedHeaderListError:
            # Let h2 retain ENHANCE_YOUR_CALM for decoded header limits.
            raise
        except HPACKError as error:
            # Classify before h2 converts HPACK errors into PROTOCOL_ERROR and
            # queues GOAWAY. RFC 9113 requires COMPRESSION_ERROR instead.
            failure = ProtocolError(f"Error decoding header block: {error}")
            failure.error_code = ErrorCodes.COMPRESSION_ERROR
            raise failure from error
        # Count even blocks h2 discards on closed/refused streams.
        self.decoded_bytes += sum(
            len(name) + len(value) + 32 for name, value in headers
        )
        if self.decoded_bytes > MAX_DECODED_HEADER_BYTES:
            raise OversizedHeaderListError("HTTP/2 decoded header budget exceeded")
        # super().decode() has already updated the dynamic table with the exact
        # wire values. Rewrite only the separate list passed to h2, never that
        # table or the captured fields: later blocks may reference these entries.
        self.original_headers = headers
        if not raw:
            return headers
        working_headers = []
        for header in headers:
            name, value = header
            # h2 converts Content-Length to int before emitting request events.
            if name == b"content-length" and value.isdigit():
                value = str(bounded_content_length(value)).encode("ascii")
                header = type(header)(name, value)
            working_headers.append(header)
        return working_headers


class _ResponseEncoder(Encoder):
    def encode(self, headers, huffman=True):
        if self.table_size_changes:
            # RFC 7541 permits only the smallest and final size updates.
            smallest = min(self.table_size_changes)
            final = self.table_size_changes[-1]
            self.table_size_changes = (
                [smallest] if smallest == final else [smallest, final]
            )
        return super().encode(headers, huffman=huffman)


class H2Adapter(H2Connection):
    def __init__(self):
        super().__init__(
            config=H2Configuration(
                client_side=False,
                header_encoding=None,
                normalize_inbound_headers=False,
                validate_inbound_headers=False,
                normalize_outbound_headers=False,
            )
        )
        self.decoder = _RequestDecoder()
        self.encoder = _ResponseEncoder()
        self._header_table_size_changes = 0

    def receive_data(self, data):
        """Accept at most one frame, as enforced by HTTP2Session.

        One call can finish only one header block, so original_headers belongs
        to its request/trailer event. Passing several complete HEADERS frames
        together would associate every event with the last decoded block.
        """
        events = super().receive_data(data)
        for event in events:
            if isinstance(event, (RequestReceived, TrailersReceived)):
                event.headers = self.decoder.original_headers
        return events

    async def apply_settings(self, entries):
        working = []
        table_size = self.remote_settings.header_table_size
        table_changes = 0
        for identifier, value in entries:
            # Unknown identifiers must not grow h2's state.
            if identifier not in SUPPORTED_SETTINGS:
                continue
            if identifier == SettingCodes.HEADER_TABLE_SIZE:
                # A no-op assignment clears hpack's resized flag, suppressing
                # queued size updates without removing them.
                if value == table_size:
                    continue
                table_size = value
                table_changes += 1
            working.append((identifier, value))
        if (
            self._header_table_size_changes + table_changes
            > MAX_HEADER_TABLE_SIZE_CHANGES
        ):
            error = DenialOfServiceError("HTTP/2 header table update limit exceeded")
            self.close_connection(error_code=error.error_code)
            raise error
        self._header_table_size_changes += table_changes
        if len(working) == len(dict(working)):
            self.receive_data(HTTP2FrameBuilder.build_settings_frame(dict(working)))
            return

        # h2 represents a SETTINGS frame as a dict, which drops duplicate IDs.
        # Replay entries in wire order so intermediate values still take effect
        # (including window overflow and HPACK table eviction). The session has
        # already flushed prior output; discard only these synthetic ACKs and
        # retain one ACK for the actual wire frame.
        for index, (identifier, value) in enumerate(working):
            self.receive_data(
                HTTP2FrameBuilder.build_settings_frame({identifier: value})
            )
            if index != len(working) - 1:
                acknowledgment = self.data_to_send()
                if acknowledgment != HTTP2FrameBuilder.build_settings_frame(ack=True):
                    raise RuntimeError("Unexpected response while applying SETTINGS")
                if (index + 1) % SETTINGS_BATCH_SIZE == 0:
                    await sleep(0)
