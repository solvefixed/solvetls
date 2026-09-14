import unittest

from solvetls.http1 import MAX_HEAD_SIZE, HTTP1Error, check_head_size, parse_request
from solvetls.http_fields import parse_expectations


def request(method="GET", target="/", headers=b"Host: localhost\r\n"):
    return f"{method} {target} HTTP/1.1\r\n".encode() + headers + b"\r\n"


class HTTP1ParserTests(unittest.TestCase):
    def assert_status(self, data, status=400):
        with self.assertRaises(HTTP1Error) as caught:
            parse_request(data)
        self.assertEqual(caught.exception.status_code, status)

    def test_preserves_header_order_casing_and_non_utf8_octets(self):
        data = request(
            headers=b"hOsT: localhost\r\nX-Test: \xff\xa0\r\nx-test:\t two \t\r\n"
        )
        parsed = parse_request(data)
        self.assertEqual(parsed.method, "GET")
        self.assertEqual(parsed.path, "/")
        self.assertEqual(
            parsed.headers,
            [("hOsT", "localhost"), ("X-Test", "\xff\xa0"), ("x-test", "two")],
        )
        self.assertEqual(parsed.raw_head, data)

    def test_content_and_pipeline_tail_do_not_change_head(self):
        head = request(
            method="POST", headers=b"Host: localhost\r\nContent-Length: 70000\r\n"
        )
        parsed = parse_request(head + b"x" * 70000 + request())
        self.assertEqual(parsed.raw_head, head)

    def test_header_limit_applies_to_complete_head(self):
        prefix = b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: "
        data = prefix + b"a" * (MAX_HEAD_SIZE - len(prefix) - 4) + b"\r\n\r\n"
        self.assertEqual(len(parse_request(data).raw_head), MAX_HEAD_SIZE)
        self.assert_status(data[:-4] + b"a\r\n\r\n", 431)

    def test_header_limit_applies_to_incomplete_head(self):
        self.assert_status(b"x" * (MAX_HEAD_SIZE + 1), 431)

    def test_oversized_uri_returns_414_for_complete_and_partial_heads(self):
        self.assert_status(request(target="/" + "a" * MAX_HEAD_SIZE), 414)
        partial = b"GET /" + b"a" * MAX_HEAD_SIZE
        for data in (partial, b"\r\n" + partial):
            with self.subTest(leading_blank=data.startswith(b"\r\n")):
                with self.assertRaises(HTTP1Error) as caught:
                    check_head_size(data, incomplete=True)
                self.assertEqual(caught.exception.status_code, 414)

    def test_incremental_head_limit_distinguishes_uri_and_fields(self):
        for prefix, status in (
            (b"GET /", 414),
            (b"\r\nGET /", 414),
            (b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Large: ", 431),
        ):
            with self.subTest(status=status):
                partial = prefix + b"a" * (MAX_HEAD_SIZE - len(prefix))
                check_head_size(partial[:-1], incomplete=True)
                with self.assertRaises(HTTP1Error) as caught:
                    check_head_size(partial, incomplete=True)
                self.assertEqual(caught.exception.status_code, status)

    def test_oversized_method_and_version_are_not_uri_overflow(self):
        lines = [
            b"M" * 70000 + b" / HTTP/1.1",
            b"GET / HTTP/" + b"1" * 70000,
        ]
        for line in lines:
            with self.subTest(line_prefix=line[:20]):
                self.assert_status(line + b"\r\nHost: localhost\r\n\r\n", 431)
                for partial in (line, line[:MAX_HEAD_SIZE]):
                    with self.assertRaises(HTTP1Error) as caught:
                        check_head_size(partial, incomplete=True)
                    self.assertEqual(caught.exception.status_code, 431)

    def test_incremental_limit_ignores_body_after_complete_head(self):
        check_head_size(request() + b"body" * MAX_HEAD_SIZE, incomplete=True)

    def test_host_required_once(self):
        for headers in [b"", b"Host: localhost\r\nhost: localhost\r\n"]:
            with self.subTest(headers=headers):
                self.assert_status(request(headers=headers))

    def test_invalid_host_values(self):
        for host in [
            "bad host",
            "user@host",
            "host/path",
            "host?x",
            "host#x",
            "host:abc",
            "host:65536",
            "[::1",
            "[::1]bad",
            "::1",
            "[bogus]",
            "[fe80::1%en0]",
            "host%xx",
        ]:
            with self.subTest(host=host):
                self.assert_status(request(headers=f"Host: {host}\r\n".encode()))

    def test_valid_host_grammar(self):
        for host in [
            "localhost",
            "localhost.",
            "127.0.0.1:443",
            "[::1]",
            "[2001:db8::1]:443",
            "[v1.ab:c]:443",
            "host%2dname",
            "",
            "localhost:",
        ]:
            with self.subTest(host=host):
                self.assertEqual(
                    parse_request(
                        request(headers=f"Host: {host}\r\n".encode())
                    ).headers,
                    [("Host", host)],
                )

    def test_invalid_header_syntax(self):
        for header in [
            b"X-Test : value",
            b" X-Test: value",
            b"X-Test\t: value",
            b"Bad Name: x",
            b"NoColon",
            b": value",
            b"X-Test: a\x00b",
            b"X-Test: a\rb",
            b"X-Test: a\nb",
            b"X-Test: a\x7fb",
            b"X-Test: a\x0bb",
            b"X-Test: a\r\n b",
        ]:
            with self.subTest(header=header):
                self.assert_status(
                    request(headers=b"Host: localhost\r\n" + header + b"\r\n")
                )

    def test_invalid_content_lengths(self):
        for value in [
            b"",
            b"-1",
            b"+1",
            b"one",
            b"1.0",
            b"1, 2",
            b"1 1",
            b"1\t1",
            b"\xff",
        ]:
            with self.subTest(value=value):
                self.assert_status(
                    request(
                        headers=b"Host: localhost\r\nContent-Length: " + value + b"\r\n"
                    )
                )
        self.assert_status(
            request(
                headers=b"Host: localhost\r\nContent-Length: 1\r\ncontent-length: 2\r\n"
            )
        )

    def test_equal_content_lengths_preserve_values(self):
        headers = (
            b"Host: localhost\r\nContent-Length: 00042, 42\r\ncontent-length: 42\r\n"
        )
        self.assertEqual(
            parse_request(request(headers=headers)).headers[1:],
            [("Content-Length", "00042, 42"), ("content-length", "42")],
        )

    def test_large_decimal_content_length_has_no_conversion_overflow(self):
        parse_request(
            request(
                headers=b"Host: localhost\r\nContent-Length: " + b"9" * 5000 + b"\r\n"
            )
        )

    def test_leading_zeroes_in_content_length_are_preserved(self):
        value = "0" * 5000
        parsed = parse_request(
            request(headers=f"Host: localhost\r\nContent-Length: {value}\r\n".encode())
        )
        self.assertEqual(parsed.headers[-1], ("Content-Length", value))

    def test_transfer_encoding_content_length_conflict(self):
        self.assert_status(
            request(
                headers=(
                    b"Host: localhost\r\nTransfer-Encoding: chunked\r\n"
                    b"Content-Length: 0\r\n"
                )
            )
        )

    def test_transfer_encoding_framing(self):
        for encoding in [
            b"",
            b"gzip",
            b"chunked, gzip",
            b"chunked, chunked",
            b"chunked; q=1",
            b"chunked;",
            b"gzip; bad, chunked",
            b'gzip; q="unfinished, chunked',
        ]:
            with self.subTest(encoding=encoding):
                self.assert_status(
                    request(
                        headers=b"Host: localhost\r\nTransfer-Encoding: "
                        + encoding
                        + b"\r\n"
                    )
                )

    def test_known_transfer_codings_and_list_parsing(self):
        for encoding in [
            b"chunked",
            b"GZIP, Chunked",
            b",gzip,,chunked,",
            b'gzip; example="a,b", chunked',
        ]:
            with self.subTest(encoding=encoding):
                parse_request(
                    request(
                        method="POST",
                        headers=b"Host: localhost\r\nTransfer-Encoding: "
                        + encoding
                        + b"\r\n",
                    )
                )

    def test_unknown_transfer_coding_with_valid_framing(self):
        self.assert_status(
            request(
                headers=b"Host: localhost\r\nTransfer-Encoding: custom, chunked\r\n"
            ),
            501,
        )

    def test_repeated_transfer_encoding_is_one_list(self):
        parse_request(
            request(
                headers=(
                    b"Host: localhost\r\nTransfer-Encoding: gzip\r\n"
                    b"transfer-encoding: chunked\r\n"
                )
            )
        )

    def test_expectation_list_ignores_empty_members_and_combines_fields(self):
        self.assertEqual(
            parse_expectations([b",100-Continue,,", "100-continue,"]),
            ["100-continue", "100-continue"],
        )
        self.assertEqual(parse_expectations([b"", ",,,"]), [])

    def test_expectation_list_keeps_quoted_commas_and_escapes(self):
        self.assertEqual(
            parse_expectations([b'custom; value="a,\\"b", 100-continue']),
            ['custom; value="a,\\"b"', "100-continue"],
        )
        with self.assertRaises(ValueError):
            parse_expectations([b'custom; value="unfinished'])

    def test_valid_method_tokens_are_case_sensitive_and_preserved(self):
        for method in ["HEAD", "XYZ", "FOO-BAR", "get", "M!#$%&'*+-.^_`|~09"]:
            with self.subTest(method=method):
                self.assertEqual(parse_request(request(method=method)).method, method)

    def test_malformed_request_lines(self):
        for line in [
            b"GET /bad target HTTP/1.1",
            b"GET\t/ HTTP/1.1",
            b"GET  HTTP/1.1",
            b"GET / HTTP/1.1 extra",
            b"GE(T / HTTP/1.1",
            b"GET /caf\xff HTTP/1.1",
            b"GET / HTTP/1.01",
        ]:
            with self.subTest(line=line):
                self.assert_status(line + b"\r\nHost: localhost\r\n\r\n")

    def test_unsupported_http_version(self):
        self.assert_status(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n", 505)

    def test_crlf_required(self):
        self.assert_status(b"GET / HTTP/1.1\nHost: localhost\n\n")

    def test_leading_empty_line(self):
        self.assertEqual(parse_request(b"\r\n" + request()).method, "GET")

    def test_request_target_forms(self):
        for target in [
            "/",
            "/path?one=two",
            "//double/path",
            "/caf%C3%A9?x=%FF",
            "https://localhost/path?q=one",
            "http://[::1]:8080/",
            "ftp://name:password@localhost/path",
            "ftp://name:password@[V1.ab:c]/path",
            "urn:example:object",
        ]:
            with self.subTest(target=target):
                self.assertEqual(parse_request(request(target=target)).path, target)
        self.assertEqual(parse_request(request(method="OPTIONS", target="*")).path, "*")

    def test_absolute_ipvfuture_authorities_keep_their_spelling(self):
        for authority in ["[v1.ab:c]", "[V1.ab:c]", "[VF.aB:c]:00443"]:
            with self.subTest(authority=authority):
                target = f"https://{authority}/path?q=1"
                raw = request(target=target, headers=f"Host: {authority}\r\n".encode())
                parsed = parse_request(raw)
                self.assertEqual(parsed.path, target)
                self.assertEqual(parsed.headers, [("Host", authority)])
                self.assertEqual(parsed.raw_head, raw)

    def test_invalid_request_targets(self):
        for target in [
            "relative",
            "localhost:443/path#fragment",
            "/path#fragment",
            "/bad%xx",
            "/bad%",
            "/bad\\path",
            "http:///path",
            "http://:80/path",
            "http://user@localhost/path",
            "http://localhost:bad/",
            "http://[VG.a]/",
            "http://[V1.]/",
            "http://[V1.a%20]/",
            "http://[V1.a]suffix/",
            "http://[V1.a]:bad/",
            "http://[V1.a]]/",
            "http://[V1.a/",
            "ftp://[V1.a]@localhost/",
            "*",
        ]:
            with self.subTest(target=target):
                self.assert_status(request(target=target))

    def test_connect_authority(self):
        for target in ["localhost:443", "[::1]:443", "[2001:db8::1]:00443"]:
            with self.subTest(target=target):
                self.assertEqual(
                    parse_request(request(method="CONNECT", target=target)).path, target
                )
        for target in [
            "localhost",
            "localhost:",
            ":443",
            "localhost:0",
            "localhost:65536",
            "/path",
            "http://localhost:443",
            "::1:443",
        ]:
            with self.subTest(target=target):
                self.assert_status(request(method="CONNECT", target=target))


if __name__ == "__main__":
    unittest.main()
