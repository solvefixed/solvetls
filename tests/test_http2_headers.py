import unittest

from h2.exceptions import ProtocolError
from hpack import Decoder, Encoder

from solvetls.http2.frames import ErrorCode, FrameType
from tests.http2 import Transport, data_frame, headers_frame, request


class HTTP2HeaderTests(unittest.IsolatedAsyncioTestCase):
    async def test_invalid_request_fields_get_protocol_error(self):
        cases = [
            ("uppercase field name", request(extra=[(b"Connection", b"close")])),
            ("connection-specific field", request(extra=[(b"connection", b"close")])),
            ("missing declared body", request(extra=[(b"content-length", b"1")])),
            ("signed Content-Length", request(extra=[(b"content-length", b"+0")])),
            (
                "conflicting Content-Length fields",
                request(extra=[(b"content-length", b"0"), (b"content-length", b"1")]),
            ),
            ("leading field whitespace", request(extra=[(b"x-bad", b" leading")])),
            ("invalid method token", request(method=b"INVALID METHOD")),
        ]
        for name, wire in cases:
            with self.subTest(case=name):
                transport = Transport()
                with self.assertRaises(ProtocolError):
                    await transport.start(wire)
                await transport.session.close()
                self.assertEqual(
                    [f.payload.error_code for f in transport.output(FrameType.GOAWAY)],
                    [ErrorCode.PROTOCOL_ERROR],
                )
                self.assertEqual(transport.output(FrameType.RST_STREAM), [])
                self.assertEqual(transport.output(FrameType.HEADERS), [])

    async def test_trailers_and_raw_non_utf8_headers_are_preserved_separately(self):
        encoder = Encoder()
        incoming = request(
            encoder,
            method=b"POST",
            end=False,
            extra=[(b"x-raw", b"\xff"), (b"cookie", b"a=1"), (b"cookie", b"b=2")],
        )
        incoming += data_frame(1, b"data")
        incoming += headers_frame(
            1, encoder.encode([(b"x-checksum", b"1234")]), True, True
        )
        transport = Transport()
        await transport.start(incoming)
        self.assertIn((b":method", b"POST"), transport.session.capture.headers)
        self.assertIn((b"x-raw", b"\xff"), transport.session.capture.headers)
        self.assertEqual(
            [
                pair
                for pair in transport.session.capture.headers
                if pair[0] == b"cookie"
            ],
            [(b"cookie", b"a=1"), (b"cookie", b"b=2")],
        )
        self.assertEqual(transport.session.capture.trailers, [(b"x-checksum", b"1234")])

    async def test_ordinary_connect_returns_to_application_without_request_body(self):
        transport = Transport()
        await transport.start(request(method=b"CONNECT", end=False))
        await transport.session.send_response(b"unsupported", status_code=501)
        self.assertIn(
            (":status", "501"),
            Decoder().decode(
                transport.output(FrameType.HEADERS)[0].payload.header_block
            ),
        )

    async def test_invalid_authorities_are_rejected(self):
        for method, authority in [
            (b"GET", b"bad host"),
            (b"GET", b"user@localhost"),
            (b"GET", b"localhost:99999"),
            (b"GET", b"[invalid-ipv6]"),
            (b"GET", b"bad%escape"),
            (b"CONNECT", b"localhost"),
            (b"CONNECT", b"localhost:0"),
        ]:
            with self.subTest(method=method, authority=authority):
                fields = [(b":method", method), (b":authority", authority)]
                if method != b"CONNECT":
                    fields += [(b":scheme", b"https"), (b":path", b"/")]
                wire = headers_frame(1, Encoder().encode(fields), True, True)
                transport = Transport()
                with self.assertRaises(ProtocolError):
                    await transport.start(wire)

    async def test_equal_content_lengths_preserve_original_decimal_text(self):
        transport = Transport()
        await transport.start(
            request(extra=[(b"content-length", b"00"), (b"content-length", b"0")])
        )
        self.assertEqual(
            [
                pair
                for pair in transport.session.capture.headers
                if pair[0] == b"content-length"
            ],
            [(b"content-length", b"00"), (b"content-length", b"0")],
        )

    async def test_equivalent_authorities_preserve_their_original_spelling(self):
        for authority, host in [
            (b"localhost", b"localhost"),
            (b"localhost", b"LOCALHOST"),
            (b"LOCALHOST", b"localhost:443"),
            (b"localhost:", b"localhost:00443"),
            (b"[2001:db8::1]", b"[2001:0DB8:0000:0000:0000:0000:0000:0001]:443"),
            (b"%6cocalhost", b"localhost"),
            (b"host%2Dname", b"HOST-name"),
            (b"host%2fpart", b"host%2Fpart"),
            (b"[v1.example]", b"[V1.EXAMPLE]:443"),
            (b"localhost:8443", b"LOCALHOST:08443"),
        ]:
            with self.subTest(authority=authority, host=host):
                transport = Transport()
                await transport.start(
                    request(authority=authority, extra=[(b"host", host)])
                )
                self.assertIn(
                    (b":authority", authority), transport.session.capture.headers
                )
                self.assertIn((b"host", host), transport.session.capture.headers)

    async def test_different_authorities_are_rejected_after_normalization(self):
        for authority, host in [
            (b"localhost", b"otherhost"),
            (b"localhost", b"localhost:8443"),
            (b"localhost:80", b"localhost:443"),
            (b"[::1]", b"[::2]"),
            (b"host%2fname", b"host/name"),
            (b"[v1.example]", b"v1.example"),
            (b"localhost", b"localhost,localhost"),
            (b"localhost", b" localhost"),
            (b"localhost", b"localhost\t"),
            (b"localhost", b"local\x00host"),
        ]:
            with self.subTest(authority=authority, host=host):
                transport = Transport()
                with self.assertRaises(ProtocolError):
                    await transport.start(
                        request(authority=authority, extra=[(b"host", host)])
                    )

    async def test_connect_compares_explicit_authority_ports(self):
        transport = Transport()
        await transport.start(
            request(method=b"CONNECT", extra=[(b"host", b"LOCALHOST:00443")], end=False)
        )
        failed = Transport()
        with self.assertRaises(ProtocolError):
            await failed.start(
                request(method=b"CONNECT", extra=[(b"host", b"localhost")], end=False)
            )

    async def test_authority_default_port_depends_on_request_scheme(self):
        for host, valid in [(b"LOCALHOST:00080", True), (b"localhost:443", False)]:
            with self.subTest(host=host):
                fields = [
                    (b":method", b"GET"),
                    (b":authority", b"localhost"),
                    (b":scheme", b"http"),
                    (b":path", b"/"),
                    (b"host", host),
                ]
                wire = headers_frame(1, Encoder().encode(fields), True, True)
                transport = Transport()
                if valid:
                    await transport.start(wire)
                    self.assertEqual(transport.session.capture.headers, fields)
                else:
                    with self.assertRaises(ProtocolError):
                        await transport.start(wire)

    async def test_extended_connect_remains_disabled(self):
        transport = Transport()
        with self.assertRaises(ProtocolError):
            await transport.start(
                request(
                    method=b"CONNECT", extra=[(b":protocol", b"websocket")], end=False
                )
            )

    async def test_path_uses_uri_path_and_query_grammar(self):
        for path in [b"/", b"/ok%FF", b"/path?x=%ff&next=/?", b"/a:@!$&'()*+,;=-._~"]:
            with self.subTest(path=path):
                transport = Transport()
                await transport.start(request(path=path))
                self.assertIn((b":path", path), transport.session.capture.headers)
        for path in [
            b"/bad%GG",
            b"/bad%",
            b"/bad\\path",
            b"/bad\xff",
            b"/path#fragment",
            b"/path?bad=%GG",
            b"/path?bad=\\",
            b"/path?bad=\xff",
            b"/brackets[]",
        ]:
            with self.subTest(path=path):
                transport = Transport()
                with self.assertRaises(ProtocolError):
                    await transport.start(request(path=path))

    async def test_te_combines_list_members_and_preserves_raw_fields(self):
        for fields in [
            [(b"te", b"trailers, trailers")],
            [(b"te", b",Trailers,,"), (b"te", b"trailers")],
            [(b"te", b"")],
            [(b"te", b",,,")],
        ]:
            with self.subTest(fields=fields):
                transport = Transport()
                await transport.start(request(extra=fields))
                self.assertEqual(
                    [
                        pair
                        for pair in transport.session.capture.headers
                        if pair[0] == b"te"
                    ],
                    fields,
                )

    async def test_te_rejects_unsupported_members_and_malformed_original_values(self):
        for value in [
            b"gzip",
            b"trailers,gzip",
            b'"trailers"',
            b"trailers; q=1",
            b" trailers",
            b"trailers\t",
            b",\x00,trailers",
            b",\r,trailers",
            b",\n,trailers",
            b'"unfinished',
        ]:
            with self.subTest(value=value):
                transport = Transport()
                with self.assertRaises(ProtocolError):
                    await transport.start(request(extra=[(b"te", value)]))

    async def test_leading_zeroes_do_not_hit_python_integer_limit(self):
        for body in (b"", b"x"):
            with self.subTest(body=body):
                value = b"0" * 5000 + str(len(body)).encode()
                transport = Transport()
                wire = request(
                    method=b"POST", end=not body, extra=[(b"content-length", value)]
                )
                if body:
                    wire += data_frame(1, body, end_stream=True)
                await transport.start(wire)
                self.assertIn(
                    (b"content-length", value), transport.session.capture.headers
                )
                await transport.session.send_response(b"ok")
                self.assertEqual(
                    b"".join(f.payload.data for f in transport.output(FrameType.DATA)),
                    b"ok",
                )

    async def test_content_length_mismatch_is_rejected_when_trailers_end_the_body(self):
        encoder = Encoder()
        wire = request(
            encoder,
            method=b"POST",
            end=False,
            extra=[(b"content-length", b"2")],
        )
        wire += data_frame(1, b"x")
        wire += headers_frame(1, encoder.encode([(b"x-checksum", b"done")]), True, True)
        transport = Transport()
        with self.assertRaises(ProtocolError):
            await transport.start(wire)
        await transport.session.close()
        self.assertEqual(
            [f.payload.error_code for f in transport.output(FrameType.GOAWAY)],
            [ErrorCode.PROTOCOL_ERROR],
        )
        self.assertEqual(transport.output(FrameType.HEADERS), [])

    async def test_canonical_length_does_not_change_hpack_indexes_or_trailers(self):
        encoder = Encoder()
        value = b"0" * 1000
        wire = request(encoder, end=False, extra=[(b"content-length", value)])
        wire += request(encoder, stream=3, extra=[(b"content-length", value)])
        # This block is decoded for HPACK state, but h2 emits no header event
        # because stream 3 was refused. The next block must not get its fields.
        wire += headers_frame(
            3, encoder.encode([(b"x-ignored", b"closed-stream")]), True, True
        )
        wire += headers_frame(
            1, encoder.encode([(b"x-checksum", b"original")]), True, True
        )
        transport = Transport()
        await transport.start(wire)
        self.assertIn((b"content-length", value), transport.session.capture.headers)
        self.assertEqual(
            transport.session.capture.trailers, [(b"x-checksum", b"original")]
        )
        resets = transport.output(FrameType.RST_STREAM)
        self.assertTrue(any(frame.header.stream_id == 3 for frame in resets))

    async def test_large_conflicting_lengths_remain_protocol_error(self):
        transport = Transport()
        with self.assertRaises(ProtocolError):
            await transport.start(
                request(
                    end=False,
                    extra=[
                        (b"content-length", b"9" * 5000),
                        (b"content-length", b"8" * 5000),
                    ],
                )
            )
        self.assertEqual(transport.output(FrameType.GOAWAY)[0].payload.error_code, 1)

    async def test_empty_te_does_not_hide_pseudo_header_ordering_error(self):
        fields = [
            (b"te", b""),
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
            (b":path", b"/"),
        ]
        transport = Transport()
        with self.assertRaises(ProtocolError):
            await transport.start(
                headers_frame(1, Encoder().encode(fields), True, True)
            )

    async def test_expectation_lists_send_one_continue_and_preserve_fields(self):
        cases = [
            ("single expectation", [(b"expect", b"100-continue")], b"body"),
            (
                "repeated list members",
                [(b"expect", b",100-Continue,,"), (b"expect", b"100-continue,")],
                b"x",
            ),
        ]
        for name, fields, body in cases:
            with self.subTest(case=name):
                transport = Transport([data_frame(1, body, end_stream=True)])
                await transport.start(request(method=b"POST", end=False, extra=fields))
                headers = transport.output(FrameType.HEADERS)
                self.assertEqual(len(headers), 1)
                self.assertEqual(
                    Decoder().decode(headers[0].payload.header_block),
                    [(":status", "100")],
                )
                self.assertFalse(transport.session.capture.expectation_failed)
                self.assertEqual(
                    [
                        pair
                        for pair in transport.session.capture.headers
                        if pair[0] == b"expect"
                    ],
                    fields,
                )

    async def test_empty_expectation_list_is_ignored(self):
        transport = Transport()
        await transport.start(request(extra=[(b"expect", b",,,")]))
        self.assertFalse(transport.session.capture.expectation_failed)
        self.assertEqual(transport.output(FrameType.HEADERS), [])

    async def test_unsupported_and_malformed_expectations_fail_without_waiting(self):
        for name, method, value in [
            ("unsupported token", b"POST", b"other"),
            (
                "unsupported quoted parameter",
                b"GET",
                b'custom; value="a,b",100-continue',
            ),
            ("unterminated quoted parameter", b"GET", b'custom; value="unfinished'),
        ]:
            with self.subTest(case=name):
                transport = Transport()
                await transport.start(
                    request(method=method, end=False, extra=[(b"expect", value)])
                )
                self.assertTrue(transport.session.capture.expectation_failed)
                self.assertEqual(transport.output(FrameType.HEADERS), [])

    async def test_head_body_remains_enabled_by_explicit_product_policy(self):
        transport = Transport()
        await transport.start(request(method=b"HEAD"))
        await transport.session.send_response(b'{"method":"HEAD"}')
        self.assertEqual(
            transport.output(FrameType.DATA)[0].payload.data, b'{"method":"HEAD"}'
        )


if __name__ == "__main__":
    unittest.main()
