import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from hpack import Encoder

from tests.http2 import frame, response, unknown_settings_flood, wire_frames
from tests.support import certificate_files

ROOT = Path(__file__).resolve().parents[1]
HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
REQUEST_HEADERS = [
    (b":method", b"GET"),
    (b":scheme", b"https"),
    (b":authority", b"localhost"),
    (b":path", b"/"),
]


def read_to_eof(connection):
    data = bytearray()
    while chunk := connection.recv(65536):
        data.extend(chunk)
    return bytes(data)


@unittest.skipUnless(
    os.getenv("SOLVETLS_NETWORK_TESTS") == "1",
    "Set SOLVETLS_NETWORK_TESTS=1 to run localhost socket tests",
)
class NetworkProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_file, key_file = certificate_files()
        temporary = tempfile.TemporaryDirectory(prefix="solvetls-network-")
        cls.addClassCleanup(temporary.cleanup)
        log_path = Path(temporary.name) / "server.log"
        log = log_path.open("wb")
        cls.addClassCleanup(log.close)

        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            cls.port = reservation.getsockname()[1]

        environment = os.environ.copy()
        environment.pop("SOLVETLS_MONGODB_URL", None)
        environment.update(
            SOLVETLS_HOST="127.0.0.1",
            SOLVETLS_PORT=str(cls.port),
            SOLVETLS_HTTP_PORT="",
            SOLVETLS_CERT=cls.cert_file,
            SOLVETLS_KEY=key_file,
            SOLVETLS_LOG_LEVEL="INFO",
        )
        cls.server = subprocess.Popen(  # noqa: S603 — trusted local entry point
            [sys.executable, "-B", str(ROOT / "main.py")],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        cls.addClassCleanup(cls.stop_server)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            output = log_path.read_text()
            if cls.server.poll() is not None:
                raise RuntimeError(f"Local server exited during startup:\n{output}")
            if f"Serving on 127.0.0.1:{cls.port}" in output:
                return
            time.sleep(0.05)
        raise TimeoutError(f"Local server did not start:\n{log_path.read_text()}")

    @classmethod
    def stop_server(cls):
        if cls.server.poll() is None:
            cls.server.terminate()
            try:
                cls.server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.server.kill()
                cls.server.wait(timeout=5)

    def tls_exchange(self, request, protocol):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(self.cert_file)
        context.set_alpn_protocols([protocol])
        with (
            socket.create_connection(("127.0.0.1", self.port), timeout=5) as tcp,
            context.wrap_socket(
                tcp, server_hostname="localhost", suppress_ragged_eofs=False
            ) as tls,
        ):
            self.assertEqual(tls.selected_alpn_protocol(), protocol)
            tls.sendall(request)
            result = read_to_eof(tls)
            tls.unwrap().close()
            return result

    def test_http1_ascii_head_is_returned_byte_for_byte(self):
        request = (
            b"\r\nGET / HTTP/1.1\r\nhOsT:\tlocalhost \t\r\nX-Test:\tvalue\t\r\n\r\n"
        )
        head, _, body = self.tls_exchange(request, "http/1.1").partition(b"\r\n\r\n")
        self.assertTrue(head.startswith(b"HTTP/1.1 200 "))
        report = json.loads(body)
        self.assertEqual(bytes.fromhex(report["http1"]["raw_head"]), request)
        self.assertEqual(report["http1"]["headers"][0], ["hOsT", "localhost"])

    def test_http2_padding_and_reserved_bits_survive_raw_capture(self):
        block = Encoder().encode(REQUEST_HEADERS)
        packets = [
            frame(4),
            frame(255, b"\xff\x00", flags=0xFF, stream=0x80000001),
            frame(1, b"\x02" + block + b"\x00\x7f", flags=0x0D, stream=1),
        ]
        raw = self.tls_exchange(HTTP2_PREFACE + b"".join(packets), "h2")
        headers, body = response({"raw_response": raw})
        self.assertEqual(headers[":status"], "200")
        report = json.loads(body)["http2"]
        self.assertEqual(
            [bytes.fromhex(item["raw"]) for item in report["frames"]], packets
        )
        self.assertEqual(report["frames"][1]["stream_id"], 1)
        self.assertIn("PADDED", report["frames"][2]["flag_names"])
        self.assertEqual(
            report["headers"],
            [[key.decode(), value.decode()] for key, value in REQUEST_HEADERS],
        )

    def test_malformed_clienthello_gets_fatal_decode_error(self):
        body = b"\x03\x03" + bytes(32) + b"\x00\x00\x01\xc0\x01\x00"
        handshake = b"\x01" + len(body).to_bytes(3, "big") + body
        record = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as tcp:
            tcp.sendall(record)
            tcp.shutdown(socket.SHUT_WR)
            self.assertEqual(read_to_eof(tcp), b"\x15\x03\x03\x00\x02\x02\x32")

    def test_settings_flood_keeps_other_connections_responsive(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(self.cert_file)
        context.set_alpn_protocols(["h2"])
        flood = unknown_settings_flood()[0]
        request = frame(1, Encoder().encode(REQUEST_HEADERS), flags=5, stream=1)
        with (
            socket.create_connection(("127.0.0.1", self.port), timeout=5) as tcp,
            context.wrap_socket(
                tcp, server_hostname="localhost", suppress_ragged_eofs=False
            ) as tls,
            tls.makefile("rb") as reader,
            ThreadPoolExecutor(max_workers=1) as executor,
        ):

            def receive_frame():
                header = reader.read(9)
                self.assertEqual(len(header), 9)
                length = int.from_bytes(header[:3], "big")
                payload = reader.read(length)
                self.assertEqual(len(payload), length)
                return header[3], header[4], payload

            self.assertEqual(tls.selected_alpn_protocol(), "h2")
            tls.sendall(HTTP2_PREFACE)
            kind, flags, payload = receive_frame()
            self.assertEqual((kind, flags), (4, 0))
            advertised = dict(struct.iter_unpack("!HI", payload))
            self.assertGreaterEqual(advertised[5], 60000)
            # A zero response window exposes a retained report on rejection.
            # The 60,000-byte payload fits the acknowledged frame-size limit.
            tls.sendall(
                frame(4, struct.pack("!HI", 4, 0)) + frame(4, flags=1) + flood + request
            )
            healthy = executor.submit(
                self.tls_exchange,
                b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                "http/1.1",
            )
            output = list(wire_frames(reader.read()))
            self.assertEqual(
                [
                    int.from_bytes(payload[4:8], "big")
                    for kind, _, payload in output
                    if kind == 7
                ],
                [11],
            )
            self.assertFalse(any(kind == 1 for kind, _, _ in output))
            self.assertEqual(
                [(flags, payload) for kind, flags, payload in output if kind == 4],
                [(1, b"")],
            )
            self.assertTrue(healthy.result(timeout=5).startswith(b"HTTP/1.1 200 "))


if __name__ == "__main__":
    unittest.main()
