import hashlib
from typing import TYPE_CHECKING

from .http2 import FrameType
from .http2.frames import UnknownPayload
from .http_fields import as_text
from .tls import ClientHello
from .tls.enums import ExtensionType
from .tls.extensions import parse_alpn_protocols
from .wire.naming import GREASE_VALUES
from .wire.reader import ByteReader

if TYPE_CHECKING:
    from .http2.session import HTTP2Capture

JA4_VERSIONS = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
    0x0002: "s2",
}
JA4_EMPTY_HASH = "000000000000"
JA4_HASH_LENGTH = 12

# SNI and ALPN count toward ja4_a but their IDs are excluded from ja4_c.
JA4_UNHASHED_EXTENSIONS = (
    ExtensionType.SERVER_NAME,
    ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
)


def build_ja3(client_hello: ClientHello | None) -> dict:
    """Salesforce JA3, GREASE stripped."""
    if not client_hello:
        return {"ja3": None, "ja3_hash": None}

    ja3 = ",".join(
        [
            str(client_hello.version),
            _dashed(_no_grease(client_hello.cipher_suites)),
            _dashed(_no_grease(_extension_types(client_hello))),
            _dashed(_no_grease(_supported_groups(client_hello))),
            _dashed(_ec_point_formats(client_hello)),
        ]
    )
    return {"ja3": ja3, "ja3_hash": _md5(ja3)}


def build_ja4(client_hello: ClientHello | None) -> str | None:
    """FoxIO JA4, the TLS half: ja4_a _ ja4_b _ ja4_c."""
    if not client_hello:
        return None

    # TLS 1.3 uses supported_versions; ClientHello.legacy_version is 0x0303.
    versions = _no_grease(_supported_versions(client_hello))
    version = max(versions) if versions else client_hello.version

    ciphers = sorted(f"{value:04x}" for value in _no_grease(client_hello.cipher_suites))
    extensions = _no_grease(_extension_types(client_hello))
    # JA4 requires signature algorithms in their original order.
    signatures = [
        f"{value:04x}" for value in _no_grease(_signature_algorithms(client_hello))
    ]
    protocols = _alpn_protocols(client_hello)

    ja4_a = (
        "t"  # this server only ever sees TCP; QUIC would be 'q'
        + JA4_VERSIONS.get(version, "00")
        + (
            "d"
            if _extension_data(client_hello, ExtensionType.SERVER_NAME) is not None
            else "i"
        )
        + f"{min(len(ciphers), 99):02d}"
        + f"{min(len(extensions), 99):02d}"
        + _ja4_alpn(protocols)
    )

    ja4_b = _truncated_sha256(",".join(ciphers)) if ciphers else JA4_EMPTY_HASH

    hashed = sorted(
        f"{value:04x}" for value in extensions if value not in JA4_UNHASHED_EXTENSIONS
    )
    if hashed:
        tail = ",".join(hashed)
        if signatures:
            tail += "_" + ",".join(signatures)
        ja4_c = _truncated_sha256(tail)
    else:
        ja4_c = JA4_EMPTY_HASH

    return f"{ja4_a}_{ja4_b}_{ja4_c}"


def build_akamai_fingerprint(capture: "HTTP2Capture | None") -> dict:
    """Combine initial connection frames with request pseudo-header order."""
    if capture is None or not capture.frames:
        return {"akamai_fingerprint": None, "akamai_fingerprint_hash": None}

    settings = [
        f"{setting_id}:{value}" for setting_id, value in capture.initial_settings or []
    ]
    window_update = "00"
    window_update_seen = False
    priorities = []

    for frame in capture.frames:
        # Later frames stay in the report, but must not change the fingerprint
        # depending on whether the TLS read also contained post-request traffic.
        if frame.header.type == FrameType.HEADERS:
            break
        if isinstance(frame.payload, UnknownPayload):
            continue
        if (
            frame.header.type == FrameType.WINDOW_UPDATE
            and frame.header.stream_id == 0
            and not window_update_seen
        ):
            window_update_seen = True
            window_update = str(frame.payload.increment)
        elif frame.header.type == FrameType.PRIORITY:
            priorities.append(
                f"{frame.header.stream_id}:{int(frame.payload.exclusive)}:"
                f"{frame.payload.dependency}:{frame.payload.weight}"
            )

    # Akamai names each pseudo-header by the letter after its colon. A malformed
    # lone colon can appear in forensic captures and must not crash reporting.
    pseudo_headers = []
    for name, _ in capture.headers or []:
        name = as_text(name)
        if name.startswith(":") and len(name) > 1:
            pseudo_headers.append(name[1])

    fingerprint = "|".join(
        [
            ";".join(settings),
            window_update,
            ",".join(priorities) if priorities else "0",
            ",".join(pseudo_headers),
        ]
    )
    return {
        "akamai_fingerprint": fingerprint,
        "akamai_fingerprint_hash": _md5(fingerprint),
    }


def _ja4_alpn(protocols: list[bytes]) -> str:
    """First and last byte of the first non-GREASE ALPN value."""
    protocols = [
        protocol
        for protocol in protocols
        if len(protocol) != 2 or int.from_bytes(protocol, "big") not in GREASE_VALUES
    ]
    if not protocols or not protocols[0]:
        return "00"

    first = protocols[0]
    # Non-alphanumeric ends are reported as the ends of the hex instead.
    if not (_ja4_alphanumeric(first[0]) and _ja4_alphanumeric(first[-1])):
        encoded = first.hex()
        return encoded[0] + encoded[-1]
    return chr(first[0]) + chr(first[-1])


def _ja4_alphanumeric(byte: int) -> bool:
    return 0x30 <= byte <= 0x39 or 0x41 <= byte <= 0x5A or 0x61 <= byte <= 0x7A


def _md5(value: str) -> str:
    # JA3 and Akamai specify MD5; changing it would break every published hash.
    return hashlib.md5(value.encode(), usedforsecurity=False).hexdigest()


def _truncated_sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:JA4_HASH_LENGTH]


def _no_grease(values) -> list:
    return [value for value in values if value not in GREASE_VALUES]


def _dashed(values) -> str:
    return "-".join(str(value) for value in values)


def _extension_types(client_hello: ClientHello) -> list:
    return [extension.type for extension in client_hello.extensions]


def _extension_data(client_hello: ClientHello, ext_type: int) -> bytes | None:
    for extension in client_hello.extensions:
        if extension.type == ext_type:
            return extension.data
    return None


def _supported_groups(client_hello: ClientHello) -> list:
    return _uint16_vector(client_hello, ExtensionType.SUPPORTED_GROUPS, 2)


def _supported_versions(client_hello: ClientHello) -> list:
    return _uint16_vector(client_hello, ExtensionType.SUPPORTED_VERSIONS, 1)


def _signature_algorithms(client_hello: ClientHello) -> list:
    return _uint16_vector(client_hello, ExtensionType.SIGNATURE_ALGORITHMS, 2)


def _uint16_vector(client_hello: ClientHello, ext_type: int, length_bytes: int) -> list:
    data = _extension_data(client_hello, ext_type)
    if data is None:
        return []

    try:
        reader = ByteReader(ByteReader(data).read_vector(length_bytes))
        values = []
        while reader.has_more():
            values.append(reader.read_uint16())
        return values
    except ValueError:
        return []


def _ec_point_formats(client_hello: ClientHello) -> list:
    data = _extension_data(client_hello, ExtensionType.EC_POINT_FORMATS)
    if data is None:
        return []

    try:
        return list(ByteReader(data).read_vector(1))
    except ValueError:
        return []


def _alpn_protocols(client_hello: ClientHello) -> list:
    data = _extension_data(
        client_hello, ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION
    )
    if data is None:
        return []

    # Left as bytes: JA4 has a rule for non-text ALPN that decoding would hide.
    try:
        return parse_alpn_protocols(data)
    except ValueError:
        return []
