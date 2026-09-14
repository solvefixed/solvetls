import logging
import ssl
import struct
from asyncio import (
    CancelledError,
    IncompleteReadError,
    StreamReader,
    StreamWriter,
    timeout,
    wait_for,
)
from contextlib import suppress
from email.utils import formatdate
from http import HTTPStatus

from .http1 import HEAD_END, HTTP1Request, check_head_size, parse_request
from .http2 import ErrorCode
from .http2.session import HTTP2_PREFACE, HTTP2Capture, HTTP2Session
from .http_fields import prepare_response
from .tcpip import read_saved_syn
from .tls import ClientHello, ClientHelloReader
from .tls.enums import ExtensionType
from .tls.extensions import parse_alpn_protocols

logger = logging.getLogger(__name__)

TLS_RECORD_HEADER_SIZE = 5
TLS_ALERT_CONTENT_TYPE = 0x15
TLS_HANDSHAKE_CONTENT_TYPE = 0x16
TLS_CLIENT_HELLO_TYPE = 0x01
TLS_MESSAGE_HEADER_SIZE = 4
MAX_TLS_RECORD_SIZE = 16384
MAX_CLIENT_HELLO_SIZE = 65536
CLOSE_DRAIN_TIMEOUT = 1.0
TRANSPORT_CLOSE_TIMEOUT = 5.0
PLAINTEXT_CHUNK_SIZE = 65536
REQUEST_TIMEOUT = 30.0
RESPONSE_TIMEOUT = 30.0
MAX_HANDSHAKE_BYTES = 1048576
SUPPORTED_ALPN = (b"h2", b"http/1.1")


class ClientConnection:
    """Captures SYN and ClientHello, then one HTTP request before closing.

    HTTP/2 observations are owned by the session and exposed through http2.
    """

    def __init__(
        self, reader: StreamReader, writer: StreamWriter, tls_context: ssl.SSLContext
    ):
        self.peername = writer.get_extra_info("peername")
        self.sockname = writer.get_extra_info("sockname")
        self.syn_packet = read_saved_syn(writer.get_extra_info("socket"))
        self.http_version: str | None = None
        self.client_hello: ClientHello | None = None
        self.http1: HTTP1Request | None = None
        self.http1_raw_head: bytes | None = None
        self.http2: HTTP2Capture | None = None
        self._http2_session: HTTP2Session | None = None
        self._reader = reader
        self._writer = writer
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self._ssl_obj = tls_context.wrap_bio(
            self._incoming, self._outgoing, server_side=True
        )
        self._tls_eof = False
        self._tls_shutdown_sent = False
        self._tls_fatal_alert_sent = False

    async def handle_http(self):
        """Use the TLS-negotiated protocol; do not override ALPN by sniffing."""
        async with timeout(REQUEST_TIMEOUT):
            if self._ssl_obj.selected_alpn_protocol() == "h2":
                self.http_version = "HTTP/2.0"
                incoming_data = await self._read_protocol_preface()
                self._http2_session = HTTP2Session(self)
                self.http2 = self._http2_session.capture
                await self._http2_session.initialize(incoming_data)
                await self._http2_session.receive_request()
            else:
                self.http_version = "HTTP/1.1"
                self.http1_raw_head = await self._read_http1_head(await self.read())
                self.http1 = parse_request(self.http1_raw_head)

    async def send_response(
        self,
        content: bytes,
        headers: dict | None = None,
        status_code: int = 200,
    ):
        """Reply on the negotiated protocol, within a bounded send deadline."""
        response_headers = {
            "date": formatdate(usegmt=True),
            **{name.lower(): value for name, value in (headers or {}).items()},
        }
        async with timeout(RESPONSE_TIMEOUT):
            if self.http_version == "HTTP/2.0":
                if self._http2_session is None:
                    raise RuntimeError("HTTP/2 handshake must run first")
                await self._http2_session.send_response(
                    content, response_headers, status_code
                )
            elif self.http_version == "HTTP/1.1":
                await self._send_http1_response(content, response_headers, status_code)
            else:
                raise ValueError("Protocol is not supported")

    async def _send_http1_response(
        self,
        content: bytes,
        headers: dict | None = None,
        status_code: int = 200,
    ):
        content, headers = prepare_response(content, headers, status_code)
        headers = {"connection": "close", **headers}

        try:
            reason = HTTPStatus(status_code).phrase
        except ValueError:
            reason = "Unknown"

        status_line = f"HTTP/1.1 {status_code} {reason}\r\n"
        header_lines = "".join(f"{key}: {value}\r\n" for key, value in headers.items())

        await self.write(
            (status_line + header_lines + "\r\n").encode("utf-8") + content
        )

    async def _read_protocol_preface(self) -> bytes:
        """Accept a preface split across any number of TLS records."""
        buffered = bytearray()
        while len(buffered) < len(HTTP2_PREFACE):
            buffered.extend(await self.read())
            prefix = buffered[: len(HTTP2_PREFACE)]
            if not HTTP2_PREFACE.startswith(prefix):
                # Initialize the HTTP/2 handler so it reports PROTOCOL_ERROR.
                break
        return bytes(buffered)

    async def _read_http1_head(self, buffered: bytes) -> bytes:
        """Limit header bytes, independent of TLS/network fragmentation."""
        data = bytearray(buffered)
        while True:
            check_head_size(data, incomplete=True)
            end = data.find(HEAD_END)
            if end >= 0:
                end += len(HEAD_END)
                return bytes(data[:end])
            data.extend(await self.read())

    async def do_tls_handshake(self):
        async with timeout(REQUEST_TIMEOUT):
            incoming_data = await wait_for(self._read_client_hello(), timeout=10.0)
            if not self._has_shared_alpn():
                await self._send_plaintext_alert(120)  # no_application_protocol
                raise ssl.SSLError("No shared ALPN protocol")
            self._incoming.write(incoming_data)
            received = len(incoming_data)
            while True:
                try:
                    self._ssl_obj.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    await self._handle_outgoing_data()
                    data = await self._reader.read(PLAINTEXT_CHUNK_SIZE)
                    if not data:
                        raise ConnectionResetError("Closed during handshake") from None
                    received += len(data)
                    if received > MAX_HANDSHAKE_BYTES:
                        raise ssl.SSLError("Handshake too large") from None
                    self._incoming.write(data)
                except ssl.SSLWantWriteError:
                    await self._handle_outgoing_data()
            await self._handle_outgoing_data()

        cipher = self._ssl_obj.cipher()
        logger.debug(
            "Negotiated %s %s alpn=%s",
            self._ssl_obj.version(),
            cipher[0] if cipher else None,
            self._ssl_obj.selected_alpn_protocol(),
        )

    def _has_shared_alpn(self) -> bool:
        """Python ssl has no server ALPN callback; reject a disjoint offer early."""
        for extension in self.client_hello.extensions:
            if extension.type != ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
                continue
            try:
                protocols = parse_alpn_protocols(extension.data)
            except ValueError:
                # OpenSSL validates malformed extensions during the handshake.
                return True
            return not protocols or any(
                protocol in SUPPORTED_ALPN for protocol in protocols
            )
        return True

    async def read(self, n: int = 4096) -> bytes:
        """Decrypted application data, blocking until there is some.

        n caps the ciphertext taken from the socket per round, not the plaintext
        returned: several TLS records may come back at once. Raises
        ConnectionResetError once the peer is done.
        """
        n = min(n, PLAINTEXT_CHUNK_SIZE)

        # Decrypt first: the handshake read may have pulled in application data.
        while True:
            plaintext = self._drain_plaintext()
            # Reading a KeyUpdate with update_requested may queue an outbound reply.
            await self._handle_outgoing_data()
            if self._must_answer_peer_close():
                await self._answer_peer_close()
                raise ConnectionResetError("Peer sent TLS close_notify")
            if plaintext:
                return plaintext
            if self._tls_eof:
                raise ConnectionResetError("Connection closed")

            try:
                encrypted_data = await wait_for(self._reader.read(n), timeout=30.0)
            except TimeoutError as e:
                raise ConnectionResetError("Read timeout") from e

            if not encrypted_data:
                raise ConnectionResetError("Connection closed")
            self._incoming.write(encrypted_data)

    async def write(self, content: bytes):
        """Encrypt and send. SSLObject.write() only fills the BIO; the flush sends."""
        if self._must_answer_peer_close():
            await self._answer_peer_close()
            raise ConnectionResetError("Peer sent TLS close_notify")
        self._ssl_obj.write(content)
        await self._handle_outgoing_data()

    def _must_answer_peer_close(self) -> bool:
        # RFC 5246 7.2.1 requires closing immediately and discarding pending
        # writes. TLS 1.3 explicitly permits independent read/write closure.
        return self._tls_eof and self._ssl_obj.version() != "TLSv1.3"

    async def _answer_peer_close(self):
        if not self._tls_shutdown_sent:
            with suppress(ssl.SSLWantReadError):
                self._ssl_obj.unwrap()
            self._tls_shutdown_sent = True
        await self._handle_outgoing_data()

    async def _send_plaintext_alert(self, description: int):
        """Send one fatal alert before handing the first ClientHello to OpenSSL."""
        if self._tls_fatal_alert_sent:
            return
        self._tls_fatal_alert_sent = True
        self._writer.write(b"\x15\x03\x03\x00\x02\x02" + bytes([description]))
        await wait_for(self._writer.drain(), timeout=10.0)

    async def close(self, http2_error_code: int = ErrorCode.NO_ERROR):
        """Close HTTP/2, TLS and TCP, even when graceful shutdown is cancelled."""
        try:
            try:
                if self._http2_session is not None:
                    await self._http2_session.close(error_code=http2_error_code)
            except Exception as e:
                logger.debug("GOAWAY skipped: %r", e)

            try:
                # Send close_notify without waiting for a peer expecting reuse.
                if not self._tls_shutdown_sent and not self._tls_fatal_alert_sent:
                    self._tls_shutdown_sent = True
                    self._ssl_obj.unwrap()
            except ssl.SSLWantReadError:
                pass
            except Exception as e:
                logger.debug("TLS shutdown skipped: %r", e)

            try:
                await self._handle_outgoing_data()
                # Send FIN before draining so cooperative peers close promptly.
                if self._writer.can_write_eof():
                    self._writer.write_eof()
                await wait_for(self._drain_peer(), timeout=CLOSE_DRAIN_TIMEOUT)
            except Exception as e:
                logger.debug("Close drain: %r", e)

        finally:
            try:
                if not self._writer.is_closing():
                    self._writer.close()
                await wait_for(
                    self._writer.wait_closed(), timeout=TRANSPORT_CLOSE_TIMEOUT
                )
            except CancelledError:
                self._writer.transport.abort()
                raise
            except Exception as e:
                # close() can still be flushing a buffer that the peer never reads.
                self._writer.transport.abort()
                logger.debug("Transport close failed: %r", e)

    async def _drain_peer(self):
        """Read the peer out to EOF and throw it away.

        Closing on top of unread bytes makes the kernel answer with RST, and an RST
        discards whatever is still queued to send — the client loses a response the
        log has already recorded as a 200.
        """
        while await self._reader.read(PLAINTEXT_CHUNK_SIZE):
            pass

    def _drain_plaintext(self) -> bytes:
        """Take every decrypted byte OpenSSL currently holds, across TLS records."""
        chunks = []
        while True:
            try:
                chunk = self._ssl_obj.read(PLAINTEXT_CHUNK_SIZE)
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                break
            if not chunk:
                self._tls_eof = True
                break
            chunks.append(chunk)
        return b"".join(chunks)

    async def _handle_outgoing_data(self):
        while self._outgoing.pending:
            encrypted_data = self._outgoing.read()
            self._writer.write(encrypted_data)
            try:
                await wait_for(self._writer.drain(), timeout=10.0)
            except TimeoutError as e:
                raise ConnectionError("Write timeout") from e

    async def _read_exactly(self, n: int) -> bytes:
        try:
            return await wait_for(self._reader.readexactly(n), timeout=10.0)
        except IncompleteReadError as e:
            raise ConnectionError("Incomplete handshake data") from e

    async def _read_client_hello(self) -> bytes:
        """Parse the Client Hello, and return its bytes to be replayed into the BIO.

        Python's public ssl API does not expose the Client Hello, so we read it
        off the wire first and hand the same bytes over afterwards.
        """
        raw = bytearray()
        message = bytearray()
        message_length = None

        while (
            message_length is None
            or len(message) < message_length + TLS_MESSAGE_HEADER_SIZE
        ):
            header = await self._read_exactly(TLS_RECORD_HEADER_SIZE)
            if header[0] != TLS_HANDSHAKE_CONTENT_TYPE:
                # A peer's fatal alert must not trigger another error alert.
                if header[0] != TLS_ALERT_CONTENT_TYPE:
                    await self._send_plaintext_alert(10)  # unexpected_message
                raise ssl.SSLError("Invalid SSL handshake")
            record_length = struct.unpack("!H", header[3:5])[0]
            if not 0 < record_length <= MAX_TLS_RECORD_SIZE:
                if record_length > MAX_TLS_RECORD_SIZE:
                    await self._send_plaintext_alert(22)  # record_overflow
                raise ssl.SSLError("Invalid handshake record length")
            payload = await self._read_exactly(record_length)
            raw.extend(header)
            raw.extend(payload)
            message.extend(payload)
            if message_length is None and len(message) >= TLS_MESSAGE_HEADER_SIZE:
                if message[0] != TLS_CLIENT_HELLO_TYPE:
                    await self._send_plaintext_alert(10)  # unexpected_message
                    raise ssl.SSLError("Not Client Hello")
                message_length = int.from_bytes(message[1:4], "big")
                if message_length > MAX_CLIENT_HELLO_SIZE:
                    raise ssl.SSLError("Client Hello too large")

        body = bytes(
            message[TLS_MESSAGE_HEADER_SIZE : TLS_MESSAGE_HEADER_SIZE + message_length]
        )
        try:
            self.client_hello = ClientHelloReader(body).parse()
        except ValueError as error:
            # Our observational parser runs before OpenSSL receives these bytes.
            # A malformed vector must still produce the fatal decode_error that
            # TLS 1.2 requires, rather than a silent transport close.
            await self._send_plaintext_alert(50)  # decode_error
            raise ssl.SSLError("Malformed ClientHello") from error
        return bytes(raw)
