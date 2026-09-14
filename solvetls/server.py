import json
import logging
import ssl
import time
from asyncio import (
    Lock,
    Server,
    StreamReader,
    StreamWriter,
    Task,
    create_task,
    gather,
    shield,
    start_server,
    wait,
)
from functools import partial
from pathlib import Path

from h2.exceptions import H2Error
from hpack.exceptions import HPACKError

from solvetls.connection import SUPPORTED_ALPN, ClientConnection
from solvetls.http1 import HTTP1Error
from solvetls.http2 import ErrorCode
from solvetls.http2.frames import HTTP2FrameParsingError
from solvetls.http_fields import parse_expectations
from solvetls.logs import connection_id, loggable
from solvetls.redirect import handle_redirect
from solvetls.report import (
    build_report,
    format_address,
    request_method,
    request_path,
    routing_path,
)
from solvetls.storage import save_fingerprint
from solvetls.tcpip import enable_save_syn

logger = logging.getLogger(__name__)

FAVICON_PATH = "/favicon.ico"
REPORT_HEADERS = {"content-type": "application/json", "cache-control": "no-store"}
SHUTDOWN_TIMEOUT = 5.0
MAX_CLIENTS = 32
MAX_REPORTS = 4


def _response_policy(client: ClientConnection) -> tuple[int, str | None]:
    if routing_path(client) == FAVICON_PATH:
        return 204, None

    headers = client.http1.headers if client.http1 else []
    try:
        expectations = parse_expectations(
            value for name, value in headers if name.lower() == "expect"
        )
        expectation_failed = any(value != "100-continue" for value in expectations)
    except ValueError:
        expectation_failed = True
    if expectation_failed or (client.http2 and client.http2.expectation_failed):
        return 417, "Unsupported expectation"
    if request_method(client) == "CONNECT":
        return 501, "CONNECT tunnels are not supported"
    return 200, None


async def _send_json(client: ClientConnection, report: dict, status_code: int) -> int:
    # HEAD intentionally returns the fingerprint body too.
    content = json.dumps(report, indent=2).encode("utf-8")
    await client.send_response(
        content=content, headers=REPORT_HEADERS, status_code=status_code
    )
    return len(content)


class SolveTLS:
    _tls_context: ssl.SSLContext
    _server: Server | None

    def __init__(self, cert_file: str, key_file: str):
        self._tls_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self._tls_context.load_cert_chain(cert_file, key_file)
        self._tls_context.set_alpn_protocols(
            [protocol.decode("ascii") for protocol in SUPPORTED_ALPN]
        )
        self._tls_context.options |= ssl.OP_NO_RENEGOTIATION
        self._tls_context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM")
        self._tls_context.load_dh_params(
            Path(__file__).parent / "tls" / "ffdhe2048.pem"
        )
        self._server = None
        self._http_server: Server | None = None
        self._https_ports: dict[int, int] = {}
        self._clients: dict[Task, StreamWriter] = {}
        self._report_clients: set[ClientConnection] = set()
        self._serving: set[Server] = set()
        self._close_task: Task | None = None
        self._closing = False
        self._lifecycle_lock = Lock()

    async def start(
        self,
        host: str = "0.0.0.0",  # noqa: S104
        port: int = 443,
        *,
        http_port: int | None = None,
    ):
        async with self._lifecycle_lock:
            await self._start(host, port, http_port)

    async def _start(self, host: str, port: int, http_port: int | None):
        if (
            self._server is not None
            or self._http_server is not None
            or (self._close_task is not None and not self._close_task.done())
        ):
            raise RuntimeError("Server is already started or still closing")
        self._close_task = None
        self._closing = False

        # Set TCP_SAVE_SYN before listen() starts accepting handshakes.
        self._server = await start_server(
            self._accept_client, host=host, port=port, start_serving=False
        )
        try:
            self._https_ports = {
                sock.family: sock.getsockname()[1] for sock in self._server.sockets
            }
            if http_port is not None:
                self._http_server = await start_server(
                    partial(self._accept_client, redirect=True),
                    host=host,
                    port=http_port,
                    start_serving=False,
                )
            saved = [enable_save_syn(sock) for sock in self._server.sockets]
            if not all(saved):
                logger.info(
                    "TCP_SAVE_SYN unavailable: tcpip will report addresses only"
                )

            await self._server.start_serving()
            if self._http_server is not None:
                await self._http_server.start_serving()
        except BaseException:
            # _start holds _lifecycle_lock; calling _close() here would deadlock.
            # Keep rollback joinable and shielded from startup cancellation.
            self._closing = True
            self._close_task = create_task(self._shutdown())
            await shield(self._close_task)
            raise
        logger.info("Serving on %s:%s", host, port)
        if self._http_server is not None:
            logger.info("Redirecting HTTP to HTTPS on %s:%s", host, http_port)

    async def serve_forever(self):
        """Serve until cancelled, then finish accepted clients and close sockets."""
        if self._server is None:
            raise RuntimeError("start() must run first")

        server = self._server
        if server in self._serving:
            raise RuntimeError("serve_forever() is already running")
        self._serving.add(server)
        listeners = [server]
        if self._http_server is not None:
            listeners.append(self._http_server)
        tasks = [create_task(listener.serve_forever()) for listener in listeners]
        serving = gather(*tasks)
        try:
            # asyncio.Server waits for live sockets when cancelled. Shield it so
            # our bounded client shutdown can run before that wait completes.
            await shield(serving)
        finally:
            try:
                # A caller may already have closed and restarted this instance.
                # An old serving task must never close the replacement listener.
                await self._close(server)
            finally:
                for task in tasks:
                    task.cancel()
                await gather(serving, *tasks, return_exceptions=True)
                self._serving.discard(server)

    async def close(self):
        """Stop accepting, allow pending reports to finish, then close clients.

        Repeated calls join the same cleanup. Cancelling one caller does not
        abandon socket cleanup; another caller may await close() to join it.
        """
        await self._close()

    async def _close(self, expected_server: Server | None = None):
        async with self._lifecycle_lock:
            if expected_server is not None and self._server is not expected_server:
                return
            if self._close_task is None:
                self._closing = True
                self._close_task = create_task(self._shutdown())
            closing = self._close_task
        await shield(closing)

    async def _shutdown(self):
        servers = [
            server for server in (self._server, self._http_server) if server is not None
        ]
        for server in servers:
            server.close()
        clients = dict(self._clients)
        try:
            if clients:
                await wait(clients, timeout=SHUTDOWN_TIMEOUT)
        finally:
            for task, writer in clients.items():
                if not task.done():
                    # A stalled peer must not extend shutdown by blocking a TLS
                    # flush. Completed requests had the grace period to finish.
                    writer.transport.abort()
                    task.cancel()
            await gather(*clients, return_exceptions=True)
            await gather(*(server.wait_closed() for server in servers))
            self._server = None
            self._http_server = None

    def _accept_client(
        self, reader: StreamReader, writer: StreamWriter, *, redirect: bool = False
    ):
        if self._closing:
            writer.close()
            return
        if len(self._clients) >= MAX_CLIENTS:
            # Reject before creating a task or TLS state; do not queue sockets.
            writer.transport.abort()
            return
        if redirect:
            sock = writer.get_extra_info("socket")
            https_port = self._https_ports.get(
                sock.family, next(iter(self._https_ports.values()))
            )
            handler = handle_redirect(reader, writer, https_port)
        else:
            handler = self._handle_client(reader, writer)
        task = create_task(handler)
        self._clients[task] = writer
        task.add_done_callback(self._client_done)

    def _client_done(self, task: Task):
        writer = self._clients.pop(task)
        # Also cover failures before ClientConnection enters its own try/finally.
        if not writer.is_closing():
            writer.close()
        if not task.cancelled() and (error := task.exception()) is not None:
            logger.error("Client handler failed", exc_info=error)

    async def _handle_client(self, reader: StreamReader, writer: StreamWriter):
        client = ClientConnection(
            reader=reader, writer=writer, tls_context=self._tls_context
        )
        connection_id.set(format_address(client.peername) or "-")
        try:
            await self._serve_client(client)
        finally:
            # Keep the slot through send, close and storage, including cancellation.
            self._report_clients.discard(client)

    async def _send_report(
        self, client: ClientConnection, status: int, error: str | None = None
    ) -> tuple[int, int, dict | None]:
        if client not in self._report_clients:
            if len(self._report_clients) >= MAX_REPORTS:
                await client.send_response(
                    content=b"", headers={"cache-control": "no-store"}, status_code=503
                )
                return 503, 0, None
            self._report_clients.add(client)
        report = build_report(client)
        if error:
            report["error"] = error
        content_length = await _send_json(client, report, status)
        return status, content_length, report

    async def _serve_client(self, client: ClientConnection):
        started = time.monotonic()
        report_to_save = None
        http2_error_code = ErrorCode.NO_ERROR

        try:
            await client.do_tls_handshake()
            await client.handle_http()

            status, error = _response_policy(client)
            if status == 204:
                await client.send_response(content=b"", status_code=status)
                content_length = 0
            else:
                status, content_length, report_to_save = await self._send_report(
                    client, status, error
                )

            logger.info(
                "%s %s %s -> %d %d bytes in %.0f ms",
                loggable(request_method(client)),
                loggable(request_path(client)),
                client.http_version,
                status,
                content_length,
                (time.monotonic() - started) * 1000,
            )
        except HTTP1Error as e:
            logger.info("Bad HTTP/1.1 request: %s", loggable(str(e)))
            try:
                _, _, report_to_save = await self._send_report(
                    client, e.status_code, str(e)
                )
            except (ConnectionError, TimeoutError, ssl.SSLError):
                logger.debug("Could not send HTTP/1.1 error response")
        except (H2Error, HTTP2FrameParsingError) as e:
            http2_error_code = getattr(
                e, "error_code", getattr(e, "code", ErrorCode.PROTOCOL_ERROR)
            )
            logger.info("Bad HTTP/2 request: %s", loggable(str(e)))
        except ssl.SSLError as e:
            logger.debug("TLS handshake failed: %r", e)
        except (ConnectionError, TimeoutError) as e:
            logger.debug("Connection lost: %r", e)
        except (ValueError, HPACKError) as e:
            http2_error_code = (
                ErrorCode.COMPRESSION_ERROR
                if isinstance(e, HPACKError)
                else ErrorCode.PROTOCOL_ERROR
            )
            logger.info("Bad request: %s", loggable(str(e)))
        except Exception:
            http2_error_code = ErrorCode.INTERNAL_ERROR
            logger.exception("Unhandled error while serving")
        finally:
            await client.close(http2_error_code=http2_error_code)

        # Close before database I/O so clients can retry unprocessed streams promptly.
        if report_to_save is not None:
            await save_fingerprint(report_to_save)
