import re

from h2.exceptions import ProtocolError
from h2.utilities import HeaderValidationFlags, validate_headers

from ..http_fields import parse_http_list
from ..uri import normalize_authority, validate_authority, validate_path_query

TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
SCHEME = re.compile(rb"[A-Za-z][A-Za-z0-9+.-]*\Z")


def validate_fields(headers: list[tuple[bytes, bytes]], *, trailers: bool = False):
    """Check raw fields first, then use an equivalent working copy for h2.

    h2 accepts only TE: trailers (case-insensitive) and compares Host/:authority
    byte-for-byte. Validate list and authority semantics before adapting its copy.
    """
    values = dict(headers)
    _validate_raw_fields(headers, trailers=trailers)
    _validate_field_lists(headers)
    if not trailers:
        _validate_request_target(values)
    validation_headers = _headers_for_h2(headers, values, trailers=trailers)
    list(
        validate_headers(
            validation_headers,
            HeaderValidationFlags(
                is_client=False,
                is_trailer=trailers,
                is_response_header=False,
                is_push_promise=False,
            ),
        )
    )


def _validate_raw_fields(headers, *, trailers):
    for name, value in headers:
        if any(byte in value for byte in (0, 10, 13)) or (
            value and (value[:1] in (b" ", b"\t") or value[-1:] in (b" ", b"\t"))
        ):
            raise ProtocolError("Invalid HTTP field value")
        if not name.startswith(b":") and not TOKEN.fullmatch(name):
            raise ProtocolError("Invalid HTTP field name")
        if name == b"content-length" and (not value or not value.isdigit() or trailers):
            raise ProtocolError("Invalid Content-Length field")


def _validate_field_lists(headers):
    lengths = [value for name, value in headers if name == b"content-length"]
    if lengths and any(
        value.lstrip(b"0") != lengths[0].lstrip(b"0") for value in lengths
    ):
        raise ProtocolError("Conflicting Content-Length fields")
    if sum(name == b"host" for name, _ in headers) > 1:
        raise ProtocolError("Duplicate Host fields")
    try:
        transfer_options = parse_http_list(
            value for name, value in headers if name == b"te"
        )
    except ValueError as error:
        raise ProtocolError(str(error)) from error
    if any(value.lower() != "trailers" for value in transfer_options):
        raise ProtocolError("Invalid TE field")


def _validate_request_target(values):
    method = values.get(b":method", b"")
    if not TOKEN.fullmatch(method):
        raise ProtocolError("Invalid request method")
    if b":protocol" in values:
        raise ProtocolError("Extended CONNECT was not enabled")
    scheme = values.get(b":scheme", b"")
    if method != b"CONNECT":
        path = values.get(b":path", b"")
        if not SCHEME.fullmatch(scheme):
            raise ProtocolError("Invalid request scheme")
        if scheme.lower() in (b"http", b"https") and not (
            path.startswith(b"/") or (path == b"*" and method == b"OPTIONS")
        ):
            raise ProtocolError("Invalid request path")
        try:
            path_text, _, query = path.decode("ascii").partition("?")
            validate_path_query(path_text, query)
        except ValueError as error:
            raise ProtocolError("Invalid request path") from error
    elif not values.get(b":authority"):
        raise ProtocolError("CONNECT requires an authority")
    _validate_request_authority(values, connect=method == b"CONNECT", scheme=scheme)


def _validate_request_authority(values, *, connect, scheme):
    authority = values.get(b":authority", values.get(b"host", b"")).decode("latin-1")
    try:
        host = validate_authority(authority, connect=connect)
        if b":authority" in values and b"host" in values:
            scheme_text = scheme.decode("latin-1")
            normalized_authority = normalize_authority(
                authority, scheme_text, connect=connect
            )
            normalized_host = normalize_authority(
                values[b"host"].decode("latin-1"), scheme_text, connect=connect
            )
            if normalized_authority != normalized_host:
                raise ProtocolError("Host and :authority do not match")
    except ValueError as error:
        raise ProtocolError(str(error)) from error
    if not host:
        raise ProtocolError("Invalid request authority")


def _headers_for_h2(headers, values, *, trailers):
    # Keep every field in place: pseudo-header ordering and duplicate checks
    # must still see the original sequence, including an empty TE list.
    result = []
    for name, value in headers:
        if name == b"te":
            value = b"trailers"
        elif name == b"host" and b":authority" in values and not trailers:
            value = values[b":authority"]
        result.append((name, value))
    return result
