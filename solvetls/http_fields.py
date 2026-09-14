from collections.abc import Iterable


def as_text(value: str | bytes) -> str:
    """Map HTTP field octets reversibly to JSON characters."""
    return value.decode("latin-1") if isinstance(value, bytes) else value


def prepare_response(
    content: bytes, headers: dict | None, status_code: int
) -> tuple[bytes, dict[str, str]]:
    normalized = {key.lower(): str(value) for key, value in (headers or {}).items()}
    # RFC 9110 8.6 forbids Content-Length on 1xx/204; we also omit it on 304.
    if status_code in (204, 304) or 100 <= status_code < 200:
        content = b""
        normalized.pop("content-length", None)
    else:
        normalized["content-length"] = str(len(content))
    return content, normalized


def parse_http_list(values: Iterable[str | bytes]) -> list[str]:
    """Split comma-separated members, respecting quoted strings and escapes.

    Empty members are ignored as required by RFC 9110 5.6.1.2. Field-size limits
    are enforced by the callers. Returned members retain their original case.
    """
    combined = ",".join(as_text(value) for value in values)
    result = []
    start = 0
    quoted = False
    escaped = False
    for index, char in enumerate(combined):
        if escaped:
            escaped = False
        elif quoted and char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == "," and not quoted:
            member = combined[start:index].strip(" \t")
            if member:
                result.append(member)
            start = index + 1
    if quoted or escaped:
        raise ValueError("Unterminated quoted HTTP list member")
    member = combined[start:].strip(" \t")
    if member:
        result.append(member)
    return result


def parse_expectations(values: Iterable[str | bytes]) -> list[str]:
    """Return lowercase Expect members without splitting quoted parameters."""
    return [member.lower() for member in parse_http_list(values)]
