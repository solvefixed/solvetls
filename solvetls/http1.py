import re
from dataclasses import dataclass

from .http_fields import parse_http_list
from .uri import split_absolute_uri, validate_authority, validate_path_query

MAX_HEAD_SIZE = 65536
HEAD_END = b"\r\n\r\n"
_TCHAR_PATTERN = r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
_TOKEN_RE = re.compile(_TCHAR_PATTERN)
_VERSION_RE = re.compile(rb"HTTP/[0-9]\.[0-9]")
_USER_INFO_RE = re.compile(r"(?:[A-Za-z0-9\-._~!$&'()*+,;=:]|%[0-9A-Fa-f]{2})*")
_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
_TRANSFER_CODING_RE = re.compile(
    rf"({_TCHAR_PATTERN})(?:[ \t]*;[ \t]*{_TCHAR_PATTERN}[ \t]*=[ \t]*"
    rf'(?:{_TCHAR_PATTERN}|"(?:[^"\\]|\\.)*"))*[ \t]*'
)
_KNOWN_TRANSFER_CODINGS = frozenset({"chunked", "compress", "deflate", "gzip"})


class HTTP1Error(ValueError):
    """A request that requires an HTTP error response before the connection closes."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


@dataclass
class HTTP1Request:
    method: str
    path: str
    headers: list[tuple[str, str]]
    raw_head: bytes


def check_head_size(data: bytes | bytearray, *, incomplete: bool = False) -> None:
    """Bound a head, distinguishing an oversized request line from its fields.

    Bytes following the terminating CRLFCRLF are content, not part of the head.
    An incomplete head already at the limit cannot fit its remaining terminator.
    """
    end = data.find(HEAD_END)
    head_size = len(data) if end < 0 else end + len(HEAD_END)
    too_large = head_size > MAX_HEAD_SIZE or (
        incomplete and end < 0 and head_size >= MAX_HEAD_SIZE
    )
    if not too_large:
        return
    start = 2 if data.startswith(b"\r\n") else 0
    line_end = data.find(b"\r\n", start)
    request_line = data[start : len(data) if line_end < 0 else line_end]
    line_too_large = line_end < 0 or line_end + len(HEAD_END) > MAX_HEAD_SIZE
    method, separator, remainder = request_line.partition(b" ")
    target = remainder.partition(b" ")[0]
    # Reserve only the supported version and terminating line breaks. A huge
    # method or version must not make a short target look oversized.
    framing_size = start + len(method) + len(b"  HTTP/1.1\r\n\r\n")
    if line_too_large and separator and 0 < MAX_HEAD_SIZE - framing_size < len(target):
        raise HTTP1Error("Request target too long", status_code=414)
    raise HTTP1Error("Request head too large", status_code=431)


def parse_request(raw_head: bytes) -> HTTP1Request:
    """Validate the first complete head; preserve header names and order.

    ``raw_head`` may include content already received with the head. Only the
    bytes through the first terminating CRLFCRLF belong to the returned request.
    Values trim surrounding SP/HTAB, then use reversible Latin-1 decoding.
    ``raw_head`` preserves the original bytes, including whitespace.
    """
    check_head_size(raw_head)
    end = raw_head.find(HEAD_END)
    head_size = len(raw_head) if end < 0 else end + len(HEAD_END)
    if end < 0:
        raise HTTP1Error("Request head was not terminated")

    raw_head = raw_head[:head_size]
    lines = raw_head[: -len(HEAD_END)].split(b"\r\n")
    # RFC 9112 2.2 recommends ignoring an initial empty line.
    if lines and lines[0] == b"":
        lines = lines[1:]
    if not lines or any(b"\r" in line or b"\n" in line for line in lines):
        raise HTTP1Error("Invalid request line ending")

    parts = lines[0].split(b" ")
    if len(parts) != 3 or not all(parts):
        raise HTTP1Error("Invalid request line")
    raw_method, raw_target, version = parts
    try:
        method = raw_method.decode("ascii")
        target = raw_target.decode("ascii")
    except UnicodeDecodeError as exc:
        raise HTTP1Error("Request line must be ASCII") from exc
    if not _TOKEN_RE.fullmatch(method):
        raise HTTP1Error("Invalid request method")
    if version != b"HTTP/1.1":
        status = 505 if _VERSION_RE.fullmatch(version) else 400
        raise HTTP1Error("HTTP version is not supported", status_code=status)
    try:
        _validate_target(method, target)
    except ValueError as exc:
        raise HTTP1Error(str(exc)) from exc

    headers = []
    fields: dict[str, list[str]] = {}
    for line in lines[1:]:
        if line.startswith((b" ", b"\t")):
            raise HTTP1Error("Folded or whitespace-prefixed header field")
        name, separator, value = line.partition(b":")
        if not separator:
            raise HTTP1Error("Header field has no colon")
        try:
            name_text = name.decode("ascii")
        except UnicodeDecodeError as exc:
            raise HTTP1Error("Invalid header field name") from exc
        if not _TOKEN_RE.fullmatch(name_text):
            raise HTTP1Error("Invalid header field name")
        if any((byte < 32 and byte != 9) or byte == 127 for byte in value):
            raise HTTP1Error("Invalid control character in header field")
        value_text = value.strip(b" \t").decode("latin-1")
        headers.append((name_text, value_text))
        fields.setdefault(name_text.lower(), []).append(value_text)

    hosts = fields.get("host", [])
    if len(hosts) != 1:
        raise HTTP1Error("Exactly one Host header field is required")
    try:
        validate_authority(hosts[0])
    except ValueError as exc:
        raise HTTP1Error(str(exc)) from exc
    _validate_framing(fields)
    return HTTP1Request(method, target, headers, raw_head)


def _validate_target(method: str, target: str):
    if method == "CONNECT":
        validate_authority(target, connect=True)
        return
    if target == "*":
        if method != "OPTIONS":
            raise ValueError("Asterisk target is only valid for OPTIONS")
        return
    if target.startswith("/"):
        path, _, query = target.partition("?")
        validate_path_query(path, query)
        return
    if not _SCHEME_RE.match(target) or "#" in target:
        raise ValueError("Invalid request target")
    # urlsplit strips some control characters; validate the original first.
    if any(ord(char) <= 32 or ord(char) >= 127 for char in target):
        raise ValueError("Invalid character in request target")
    try:
        parsed = split_absolute_uri(target)
    except ValueError as exc:
        raise ValueError("Invalid absolute-form request target") from exc
    validate_path_query(parsed.path, parsed.query)
    has_authority = target.split(":", 1)[1].startswith("//")
    http_scheme = parsed.scheme.lower() in {"http", "https"}
    host = None
    if has_authority:
        authority = parsed.netloc
        if "@" in authority:
            user_info, authority = authority.rsplit("@", 1)
            if http_scheme or not _USER_INFO_RE.fullmatch(user_info):
                raise ValueError("Invalid user information in absolute-form target")
        host = validate_authority(authority)
    if http_scheme and not host:
        raise ValueError("HTTP absolute-form target requires an authority")


def _validate_framing(fields: dict[str, list[str]]):
    """Validate framing even though the endpoint replies without consuming content."""
    lengths = fields.get("content-length", [])
    encodings = fields.get("transfer-encoding", [])
    if lengths and encodings:
        raise HTTP1Error("Transfer-Encoding and Content-Length cannot be combined")
    if lengths:
        values = [part.strip(" \t") for value in lengths for part in value.split(",")]
        if any(
            not value or not value.isascii() or not value.isdecimal()
            for value in values
        ):
            raise HTTP1Error("Invalid Content-Length")
        # Compare decimal values without an int conversion limit or losing raw text.
        if len({value.lstrip("0") or "0" for value in values}) != 1:
            raise HTTP1Error("Conflicting Content-Length values")
    if encodings:
        codings = []
        try:
            coding_values = parse_http_list(encodings)
        except ValueError as exc:
            raise HTTP1Error(str(exc)) from exc
        for value in coding_values:
            match = _TRANSFER_CODING_RE.fullmatch(value)
            if not match:
                raise HTTP1Error("Invalid Transfer-Encoding")
            coding = match[1].lower()
            if coding == "chunked" and ";" in value:
                raise HTTP1Error("Chunked transfer coding cannot have parameters")
            codings.append(coding)
        if not codings or codings[-1] != "chunked" or codings.count("chunked") != 1:
            raise HTTP1Error(
                "Request Transfer-Encoding must end with one chunked coding"
            )
        if any(coding not in _KNOWN_TRANSFER_CODINGS for coding in codings):
            raise HTTP1Error("Transfer coding is not supported", status_code=501)
