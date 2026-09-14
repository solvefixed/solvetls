import asyncio
import json
import ssl
import unittest
from email.utils import parsedate_to_datetime
from unittest.mock import patch

from hpack import Encoder

from solvetls.connection import HTTP2_PREFACE
from tests.http2 import headers_frame, settings_frame
from tests.http2 import response as http2_response
from tests.support import MemoryWriter, exchange, h2_request


def http1_response(result):
    head, _, body = result["raw_response"].partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    headers = dict(line.split(": ", 1) for line in lines[1:])
    return int(lines[0].split()[1]), headers, body


class ServerProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_http1_response_and_date(self):
        result = await exchange(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        status, headers, body = http1_response(result)
        self.assertEqual(status, 200)
        self.assertIsNotNone(parsedate_to_datetime(headers["date"]))
        self.assertEqual(int(headers["content-length"]), len(body))
        self.assertEqual(json.loads(body)["http_version"], "HTTP/1.1")
        self.assertTrue(result["clean_tls_eof"])
        self.assertEqual(headers["cache-control"], "no-store")

    async def test_fingerprint_errors_also_disable_caching(self):
        for request, expected in (
            (b"GET / HTTP/1.1\r\n\r\n", 400),
            (b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n", 501),
        ):
            with self.subTest(status=expected):
                status, headers, _ = http1_response(await exchange(request))
                self.assertEqual(status, expected)
                self.assertEqual(headers["cache-control"], "no-store")

    async def test_http2_fingerprint_disables_caching(self):
        headers, _ = http2_response(await exchange(h2_request(), ("h2",)))
        self.assertEqual(headers["cache-control"], "no-store")

    async def test_storage_wait_starts_after_transport_is_closed(self):
        entered, release = asyncio.Event(), asyncio.Event()
        writers = []

        def make_writer(incoming):
            writer = MemoryWriter(incoming)
            writers.append(writer)
            return writer

        async def delayed_save(_report):
            entered.set()
            await release.wait()

        with (
            patch("tests.support.MemoryWriter", side_effect=make_writer),
            patch("solvetls.server.save_fingerprint", side_effect=delayed_save),
        ):
            task = asyncio.create_task(exchange(h2_request(), ("h2",)))
            try:
                await asyncio.wait_for(entered.wait(), 2)
                self.assertTrue(writers[0].closed)
                self.assertTrue(writers[0].fin)
                self.assertFalse(task.done())
            finally:
                release.set()
                result = await asyncio.wait_for(task, 2)
        self.assertTrue(result["clean_tls_eof"])
        self.assertTrue(any(frame["type"] == 7 for frame in result["frames"]))
        self.assertEqual(http2_response(result)[0][":status"], "200")

    async def test_http1_expectation_lists_preserve_raw_fields(self):
        for value in (b"100-continue, 100-continue", b",100-continue,", b""):
            with self.subTest(value=value):
                result = await exchange(
                    b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n"
                    b"Expect: " + value + b"\r\n\r\nx"
                )
                status, _, body = http1_response(result)
                self.assertEqual(status, 200)
                self.assertIn(
                    ["Expect", value.decode("ascii")],
                    json.loads(body)["http1"]["headers"],
                )

    async def test_http1_unsupported_and_malformed_expectations_return_417(self):
        for value in (
            b"100-continue, custom",
            b'custom="unterminated',
            b"100-continue;x=1",
        ):
            with self.subTest(value=value):
                result = await exchange(
                    b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n"
                    b"Expect: " + value + b"\r\n\r\nx"
                )
                status, headers, body = http1_response(result)
                self.assertEqual(status, 417)
                self.assertEqual(headers["cache-control"], "no-store")
                self.assertEqual(json.loads(body)["error"], "Unsupported expectation")

    async def test_http1_head_keeps_explicit_fingerprint_body(self):
        result = await exchange(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        status, _, body = http1_response(result)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["method"], "HEAD")

    async def test_http2_head_keeps_explicit_fingerprint_body(self):
        result = await exchange(h2_request("HEAD"), ("h2",))
        headers, body = http2_response(result)
        self.assertEqual(headers[":status"], "200")
        self.assertEqual(json.loads(body)["method"], "HEAD")

    async def test_connect_is_rejected_with_fingerprint(self):
        result = await exchange(
            b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n"
        )
        status, _, body = http1_response(result)
        self.assertEqual(status, 501)
        self.assertEqual(json.loads(body)["method"], "CONNECT")

    async def test_http2_connect_without_end_stream_returns_fingerprint_error(self):
        block = Encoder().encode(
            [(":method", "CONNECT"), (":authority", "localhost:443")]
        )
        request = (
            HTTP2_PREFACE
            + settings_frame({})
            + headers_frame(1, block, end_headers=True)
        )
        result = await exchange(request, ("h2",))
        headers, body = http2_response(result)
        self.assertEqual(headers[":status"], "501")
        self.assertEqual(json.loads(body)["method"], "CONNECT")
        self.assertIsNotNone(parsedate_to_datetime(headers["date"]))

    async def test_tls12_and_tls13_close_cleanly(self):
        for version, expected in (
            (ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
            (ssl.TLSVersion.TLSv1_3, "TLSv1.3"),
        ):
            with self.subTest(version=version):
                result = await exchange(
                    b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                    tls_version=version,
                )
                self.assertEqual(http1_response(result)[0], 200)
                self.assertEqual(result["tls"], expected)
                self.assertTrue(result["clean_tls_eof"])

    async def test_http1_bad_framing_returns_400(self):
        for fields in (
            b"",
            b"Host : localhost\r\n",
            b"Host: localhost\r\nContent-Length: -1\r\n",
        ):
            with self.subTest(fields=fields):
                result = await exchange(b"GET / HTTP/1.1\r\n" + fields + b"\r\n")
                status, headers, _ = http1_response(result)
                self.assertEqual(status, 400)
                self.assertIn("date", headers)

    async def test_http1_fragmentation_is_not_a_read_count_limit(self):
        request = (
            b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Pad: " + b"x" * 4096 + b"\r\n\r\n"
        )
        result = await exchange(request, chunk_size=1)
        status, _, body = http1_response(result)
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(json.loads(body)["http1"]["raw_head"]), request)

    async def test_http2_fragmented_preface(self):
        result = await exchange(h2_request(), ("h2",), chunk_size=1)
        headers, body = http2_response(result)
        self.assertEqual(headers[":status"], "200")
        self.assertEqual(json.loads(body)["http_version"], "HTTP/2.0")

    async def test_http2_without_alpn_is_not_accepted(self):
        result = await exchange(h2_request(), ())
        status, _, body = http1_response(result)
        self.assertEqual(status, 505)
        self.assertEqual(json.loads(body)["http_version"], "HTTP/1.1")
        self.assertTrue(result["clean_tls_eof"])

    async def test_selected_h2_does_not_fall_back_to_http1(self):
        result = await exchange(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", ("h2",))
        self.assertFalse(result["raw_response"].startswith(b"HTTP/1.1"))
        self.assertTrue(any(f["type"] == 7 for f in result["frames"]))

    async def test_disjoint_alpn_fails_tls(self):
        outbound = bytearray()

        class RecordingWriter(MemoryWriter):
            def write(self, data):
                outbound.extend(data)
                super().write(data)

        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            with self.subTest(version=version):
                outbound.clear()
                with (
                    patch("tests.support.MemoryWriter", RecordingWriter),
                    self.assertRaises(ssl.SSLError),
                ):
                    await exchange(
                        b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                        ("unsupported",),
                        tls_version=version,
                    )
                # OpenSSL error text varies; check the fatal alert's wire code.
                self.assertEqual(outbound, b"\x15\x03\x03\x00\x02\x02\x78")

    async def test_favicon_204_has_no_content_length(self):
        result = await exchange(b"GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\n\r\n")
        status, headers, body = http1_response(result)
        self.assertEqual(status, 204)
        self.assertEqual(body, b"")
        self.assertNotIn("content-length", headers)
        self.assertIn("date", headers)

    async def test_absolute_form_favicon_does_not_create_a_report(self):
        for authority in ["localhost", "[v1.ab:c]", "[V1.ab:c]"]:
            with (
                self.subTest(authority=authority),
                patch("solvetls.server.save_fingerprint") as save,
            ):
                result = await exchange(
                    f"GET https://{authority}/favicon.ico?cache=1 HTTP/1.1\r\n"
                    f"Host: {authority}\r\n\r\n".encode()
                )
                status, headers, body = http1_response(result)
                self.assertEqual(status, 204)
                self.assertEqual(body, b"")
                self.assertNotIn("content-length", headers)
                save.assert_not_called()

    async def test_routing_keeps_the_original_absolute_target_in_report(self):
        for authority in ["localhost", "[v1.ab:c]", "[V1.ab:c]"]:
            with self.subTest(authority=authority):
                target = f"https://{authority}/path?q=1"
                raw = f"GET {target} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode()
                result = await exchange(raw)
                status, _, body = http1_response(result)
                self.assertEqual(status, 200)
                report = json.loads(body)["http1"]
                self.assertEqual(report["path"], target)
                self.assertEqual(report["headers"], [["Host", authority]])
                self.assertEqual(bytes.fromhex(report["raw_head"]), raw)
        # An origin-form target starting with // is a path, not an authority.
        result = await exchange(
            b"GET //localhost/favicon.ico HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        self.assertEqual(http1_response(result)[0], 200)


if __name__ == "__main__":
    unittest.main()
