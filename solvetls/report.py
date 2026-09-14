from dataclasses import fields, is_dataclass
from typing import TYPE_CHECKING

from .fingerprints import (
    build_akamai_fingerprint,
    build_ja3,
    build_ja4,
)
from .http2 import FrameType, ParsedFrame, SettingsIdentifier
from .http2.frames import FrameFlags
from .http_fields import as_text
from .tcpip import parse_syn
from .tls import ClientHello
from .tls.enums import CipherSuite, ExtensionType, TLSVersion
from .tls.extensions import decode_extension
from .uri import split_absolute_uri
from .wire.naming import describe

if TYPE_CHECKING:
    from .connection import ClientConnection
    from .http2.session import HTTP2Capture

SOURCE_URL = "https://github.com/solvefixed/solvetls"

# Flag meanings depend on the frame type; ACK aliases END_STREAM in FrameFlags.
_FRAME_FLAG_NAMES = {
    FrameType.DATA: ("END_STREAM", "PADDED"),
    FrameType.HEADERS: ("END_STREAM", "END_HEADERS", "PADDED", "PRIORITY"),
    FrameType.SETTINGS: ("ACK",),
    FrameType.PUSH_PROMISE: ("END_HEADERS", "PADDED"),
    FrameType.PING: ("ACK",),
    FrameType.CONTINUATION: ("END_HEADERS",),
}


def build_report(client: "ClientConnection") -> dict:
    report = {
        "source": SOURCE_URL,
        "ip": format_address(client.peername),
        "http_version": client.http_version,
        "method": request_method(client),
        "user_agent": _user_agent(client),
        "tls": _tls_report(client.client_hello),
    }

    if client.http_version == "HTTP/2.0":
        report["http2"] = _http2_report(client.http2)
    elif client.http_version == "HTTP/1.1":
        report["http1"] = _http1_report(client)

    report["tcpip"] = _tcpip_report(client)

    return report


def format_address(name: tuple | None) -> str | None:
    if not name:
        return None

    host, port = name[0], name[1]
    # RFC 3986 requires brackets around IPv6 when appending a port.
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _tcpip_report(client: "ClientConnection") -> dict:
    parsed = parse_syn(client.syn_packet)
    if parsed:
        return parsed

    peername, sockname = client.peername, client.sockname
    return {
        "cap_length": None,
        "dst_port": sockname[1] if sockname else None,
        "src_port": peername[1] if peername else None,
        "ip": {
            "id": None,
            "ttl": None,
            "ip_version": 6 if peername and ":" in peername[0] else 4,
            "dst_ip": sockname[0] if sockname else None,
            "src_ip": peername[0] if peername else None,
        },
        "tcp": {"ack": None, "checksum": None, "seq": None, "window": None},
    }


def request_method(client: "ClientConnection") -> str | None:
    if client.http2 is not None:
        return _header(client.http2.headers, ":method")
    return client.http1.method if client.http1 else None


def request_path(client: "ClientConnection") -> str | None:
    if client.http2 is not None:
        return _header(client.http2.headers, ":path")
    return client.http1.path if client.http1 else None


def routing_path(client: "ClientConnection") -> str | None:
    """Route by URI path while preserving the original request target in reports."""
    target = request_path(client)
    if not target or request_method(client) == "CONNECT":
        return None
    if client.http_version == "HTTP/2.0" or target.startswith("/") or target == "*":
        # Do not treat a valid origin-form //path as a network-path reference.
        return target.split("?", 1)[0]
    return split_absolute_uri(target).path or "/"


def _user_agent(client: "ClientConnection") -> str | None:
    request = client.http2 if client.http2 is not None else client.http1
    return _header(request.headers, "user-agent") if request else None


def _header(headers: list | None, name: str) -> str | None:
    for key, value in headers or []:
        if as_text(key).lower() == name:
            return as_text(value)
    return None


def _tls_report(client_hello: ClientHello | None) -> dict | None:
    if not client_hello:
        return None

    return {
        **build_ja3(client_hello),
        "ja4": build_ja4(client_hello),
        # Legacy field: a TLS 1.3 client still writes TLS_1_2 here and puts the real
        # list in the supported_versions extension.
        "version": describe(client_hello.version, TLSVersion),
        "random": client_hello.random.hex(),
        "session_id": client_hello.session_id.hex(),
        "cipher_suites": [
            describe(cipher, CipherSuite) for cipher in client_hello.cipher_suites
        ],
        "compression_methods": list(client_hello.compression_methods),
        "extensions": [
            {
                **describe(extension.type, ExtensionType),
                "length": len(extension.data),
                "decoded": decode_extension(extension.type, extension.data),
                "data": extension.data.hex(),
            }
            for extension in client_hello.extensions
        ],
    }


def _http1_report(client: "ClientConnection") -> dict:
    request = client.http1
    report = {
        "method": request.method if request else None,
        "path": request.path if request else None,
        "headers": [
            [as_text(key), as_text(value)]
            for key, value in (request.headers if request else [])
        ],
    }
    raw_head = client.http1_raw_head
    if raw_head is not None:
        report["raw_head"] = raw_head.hex()
    return report


def _http2_report(capture: "HTTP2Capture | None") -> dict:
    report = build_akamai_fingerprint(capture)
    if capture is None:
        return report

    if capture.initial_settings is not None:
        report["settings"] = [
            _setting_report(setting_id, value)
            for setting_id, value in capture.initial_settings
        ]

    if capture.headers is not None:
        report["headers"] = [
            [as_text(key), as_text(value)] for key, value in capture.headers
        ]

    if capture.trailers:
        report["trailers"] = [
            [as_text(key), as_text(value)] for key, value in capture.trailers
        ]

    report["frames"] = [_frame_report(frame) for frame in capture.frames]

    return report


def _setting_report(identifier: int, value: int) -> dict:
    entry = describe(identifier, SettingsIdentifier)
    # Chromium SETTINGS GREASE permits different bytes, unlike TLS's 16 values.
    if 0 <= identifier <= 0xFFFF and (identifier & 0x0F0F) == 0x0A0A:
        entry["grease"] = True
    return {**entry, "setting": value}


def _frame_report(frame: ParsedFrame) -> dict:
    payload = _plain(frame.payload)
    # These fields decode the frame header, not bytes from its payload.
    for name in ("end_stream", "end_headers", "padded", "ack"):
        payload.pop(name, None)
    return {
        **describe(frame.header.type, FrameType),
        "flags": frame.header.flags,
        "flag_names": [
            name
            for name in _FRAME_FLAG_NAMES.get(frame.header.type, ())
            if frame.header.flags & FrameFlags[name]
        ],
        "stream_id": frame.header.stream_id,
        "length": frame.header.length,
        "payload": payload,
        "raw": frame.raw.hex(),
    }


def _plain(value):
    """Convert payload values to JSON-compatible types, encoding bytes as hex."""
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if is_dataclass(value):
        return {
            field.name: _plain(getattr(value, field.name)) for field in fields(value)
        }
    return value
