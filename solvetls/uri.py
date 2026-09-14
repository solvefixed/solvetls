import ipaddress
import re
from urllib.parse import SplitResult, urlsplit

_REG_NAME_RE = re.compile(r"(?:[A-Za-z0-9\-._~!$&'()*+,;=]|%[0-9A-Fa-f]{2})*")
_IPV_FUTURE_RE = re.compile(r"v[0-9A-Fa-f]+\.[A-Za-z0-9\-._~!$&'()*+,;=:]+", re.I)
_PATH_RE = re.compile(r"(?:[A-Za-z0-9\-._~!$&'()*+,;=:@/]|%[0-9A-Fa-f]{2})*")
_QUERY_RE = re.compile(r"(?:[A-Za-z0-9\-._~!$&'()*+,;=:@/?]|%[0-9A-Fa-f]{2})*")


def split_absolute_uri(target: str) -> SplitResult:
    """Split an absolute URI without changing its authority's spelling."""
    match = re.match(r"[A-Za-z][A-Za-z0-9+.-]*://([^/?#]*)", target)
    if match:
        authority = match[1]
        host_start = authority.rfind("@") + 1
        if authority[host_start:].startswith("[V"):
            # urlsplit recognizes only a lowercase IPvFuture prefix.
            position = match.start(1) + host_start + 1
            parsed = urlsplit(target[:position] + "v" + target[position + 1 :])
            return parsed._replace(netloc=authority)
    return urlsplit(target)


def validate_authority(authority: str, *, connect: bool = False) -> str:
    """Validate uri-host and optional port, or the mandatory CONNECT host:port."""
    if authority.startswith("["):
        closing = authority.find("]")
        if closing < 0:
            raise ValueError("Invalid IP literal in authority")
        host = authority[1:closing]
        suffix = authority[closing + 1 :]
        if suffix and not suffix.startswith(":"):
            raise ValueError("Invalid authority after IP literal")
        if not _IPV_FUTURE_RE.fullmatch(host):
            try:
                if "%" in host:
                    raise ValueError("Scoped IPv6 address is not a URI IP literal")
                ipaddress.IPv6Address(host)
            except ValueError as exc:
                raise ValueError("Invalid IP literal in authority") from exc
        port = suffix[1:] if suffix else None
    else:
        host, separator, port_text = authority.partition(":")
        if not _REG_NAME_RE.fullmatch(host):
            raise ValueError("Invalid host in authority")
        port = port_text if separator else None

    if connect and (not host or port is None or not port):
        raise ValueError("CONNECT requires a host and explicit port")
    if port is not None:
        if port and (not port.isascii() or not port.isdecimal()):
            raise ValueError("Invalid port in authority")
        # Avoid converting arbitrarily many digits to int.
        significant = port.lstrip("0") or "0"
        if len(significant) > 5 or int(significant) > 65535:
            raise ValueError("Port is out of range")
        if connect and significant == "0":
            raise ValueError("CONNECT port must be nonzero")
    return host


def normalize_authority(
    authority: str, scheme: str, *, connect: bool = False
) -> tuple[str, int | None]:
    """Compare URI authorities without changing the reported spelling."""
    host = validate_authority(authority, connect=connect)
    if authority.startswith("["):
        suffix = authority[authority.index("]") + 1 :]
        port_text = suffix[1:] if suffix else ""
        if _IPV_FUTURE_RE.fullmatch(host):
            normalized_host = host.lower()
        else:
            normalized_host = ipaddress.IPv6Address(host).compressed
        normalized_host = f"[{normalized_host}]"
    else:
        _, _, port_text = authority.partition(":")

        def normalize_escape(match):
            char = chr(int(match[0][1:], 16))
            if char.isascii() and (char.isalnum() or char in "-._~"):
                return char.lower()
            return match[0].upper()

        normalized_host = re.sub(r"%[0-9a-f]{2}", normalize_escape, host.lower())
    port = int(port_text.lstrip("0") or "0") if port_text else None
    default_port = {"http": 80, "https": 443}.get(scheme.lower())
    if port is None:
        port = default_port
    return normalized_host, port


def validate_path_query(path: str, query: str = "") -> None:
    """Validate URI path/query octets, including complete percent escapes."""
    if not _PATH_RE.fullmatch(path) or not _QUERY_RE.fullmatch(query):
        raise ValueError("Invalid path or query")
