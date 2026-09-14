import asyncio
import atexit
import shutil
import ssl
import subprocess
import tempfile
from contextlib import suppress
from functools import cache
from pathlib import Path

from hpack import Encoder

from solvetls.connection import HTTP2_PREFACE
from solvetls.server import SolveTLS
from tests.http2 import headers_frame, settings_frame, wire_frames


@cache
def certificate_files() -> tuple[str, str]:
    """Generate a temporary localhost certificate once per test process."""
    openssl = shutil.which("openssl")
    if openssl is None:
        raise RuntimeError("OpenSSL is required to run TLS tests")
    temporary = tempfile.TemporaryDirectory(prefix="solvetls-test-certs-")
    cert_file = str(Path(temporary.name) / "cert.pem")
    key_file = str(Path(temporary.name) / "key.pem")
    subprocess.run(  # noqa: S603 — local test certificate generation
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-days",
            "1",
            "-nodes",
            "-keyout",
            key_file,
            "-out",
            cert_file,
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "keyUsage=critical,digitalSignature,keyEncipherment",
            "-addext",
            "extendedKeyUsage=serverAuth",
        ],
        check=True,
        capture_output=True,
        timeout=10,
    )
    atexit.register(temporary.cleanup)
    return cert_file, key_file


class MemoryWriter:
    def __init__(self, incoming):
        self.incoming = incoming
        self.closed = False
        self.fin = False
        self.bytes_sent = 0

    def get_extra_info(self, name):
        return {"peername": ("127.0.0.1", 12345), "sockname": ("127.0.0.1", 443)}.get(
            name
        )

    def write(self, data):
        self.bytes_sent += len(data)
        self.incoming.write(data)

    async def drain(self):
        await asyncio.sleep(0)

    def can_write_eof(self):
        return True

    def write_eof(self):
        self.fin = True

    def is_closing(self):
        return self.closed

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


def h2_request(method="GET", path="/"):
    block = Encoder().encode(
        [
            (":method", method),
            (":scheme", "https"),
            (":authority", "localhost"),
            (":path", path),
        ]
    )
    return (
        HTTP2_PREFACE
        + settings_frame({})
        + headers_frame(1, block, end_headers=True, end_stream=True)
    )


def _fragment_client_hello(data, size):
    records = []
    while data:
        if len(data) < 5 or data[0] != 0x16:
            raise AssertionError("Expected a ClientHello handshake record")
        end = 5 + int.from_bytes(data[3:5], "big")
        if end > len(data):
            raise AssertionError("Incomplete ClientHello record")
        payload = data[5:end]
        for offset in range(0, len(payload), size):
            chunk = payload[offset : offset + size]
            records.append(data[:3] + len(chunk).to_bytes(2, "big") + chunk)
        data = data[end:]
    return b"".join(records)


async def exchange(
    request,
    alpn=("http/1.1",),
    tls_version=None,
    chunk_size=None,
    *,
    client_hello_fragment_size=None,
    ciphers=None,
):
    cert_file, key_file = await asyncio.to_thread(certificate_files)
    app = SolveTLS(cert_file, key_file)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if tls_version is not None:
        context.minimum_version = tls_version
        context.maximum_version = tls_version
    if ciphers is not None:
        context.set_ciphers(ciphers)
    if alpn:
        context.set_alpn_protocols(list(alpn))
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = context.wrap_bio(
        incoming, outgoing, server_side=False, server_hostname="localhost"
    )
    reader = asyncio.StreamReader()
    writer = MemoryWriter(incoming)
    task = asyncio.create_task(app._handle_client(reader, writer))
    response = bytearray()
    position = 0
    completed = False
    hello_sent = False
    eof = False
    try:
        async with asyncio.timeout(5):
            while True:
                if not completed:
                    try:
                        client.do_handshake()
                        completed = True
                    except ssl.SSLWantReadError:
                        pass
                if completed and position < len(request):
                    end = len(request) if chunk_size is None else position + chunk_size
                    chunk = request[position:end]
                    client.write(chunk)
                    position += len(chunk)
                if outgoing.pending:
                    data = outgoing.read()
                    if not hello_sent and client_hello_fragment_size is not None:
                        data = _fragment_client_hello(data, client_hello_fragment_size)
                    hello_sent = True
                    reader.feed_data(data)
                if completed:
                    while True:
                        try:
                            data = client.read(1 << 20)
                        except ssl.SSLWantReadError:
                            break
                        if not data:
                            eof = True
                            break
                        response.extend(data)
                if eof:
                    with suppress(ssl.SSLWantReadError):
                        client.unwrap()
                    if outgoing.pending:
                        reader.feed_data(outgoing.read())
                    reader.feed_eof()
                    await task
                    break
                if task.done():
                    await task
                    break
                await asyncio.sleep(0)
    finally:
        if not task.done():
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
    raw = bytes(response)
    frames = []
    if not raw.startswith(b"HTTP/"):
        frames = [
            {"type": kind, "flags": flags, "length": len(payload)}
            for kind, flags, payload in wire_frames(raw)
        ]
    return {
        "raw_response": raw,
        "alpn": client.selected_alpn_protocol(),
        "tls": client.version(),
        "cipher": client.cipher(),
        "clean_tls_eof": eof,
        "frames": frames,
    }
