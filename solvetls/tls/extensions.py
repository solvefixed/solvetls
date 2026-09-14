from ..wire.naming import describe
from ..wire.reader import ByteReader
from .enums import (
    CertificateCompressionAlgorithm,
    ECPointFormat,
    ExtensionType,
    NamedGroup,
    PskKeyExchangeMode,
    ServerNameType,
    SignatureScheme,
    TLSVersion,
)


def decode_extension(ext_type: int, data: bytes) -> dict | None:
    """Decode the complete payload, report malformed data, or None if unsupported."""
    decoder = _DECODERS.get(ext_type)
    if decoder is None:
        return None

    try:
        reader = ByteReader(data)
        decoded = decoder(reader)
        if reader.has_more():
            raise ValueError("Unexpected trailing bytes in extension payload")
        return decoded
    except (ValueError, IndexError) as e:
        return {"error": str(e)}


def _decode_server_name(reader: ByteReader) -> dict:
    names = []
    names_reader = ByteReader(reader.read_vector(2))
    while names_reader.has_more():
        name_type = names_reader.read_uint8()
        host = names_reader.read_vector(2)
        names.append(
            {
                "type": describe(name_type, ServerNameType),
                "host": host.decode("utf-8", "replace"),
            }
        )
    return {"server_names": names}


def _decode_supported_groups(reader: ByteReader) -> dict:
    return {"groups": _uint16_list(reader.read_vector(2), NamedGroup)}


def _decode_ec_point_formats(reader: ByteReader) -> dict:
    formats = reader.read_vector(1)
    return {"formats": [describe(value, ECPointFormat) for value in formats]}


def _decode_signature_algorithms(reader: ByteReader) -> dict:
    return {"algorithms": _uint16_list(reader.read_vector(2), SignatureScheme)}


def parse_alpn_protocols(data: bytes) -> list[bytes]:
    """Read opaque ALPN identifiers; callers choose presentation and error policy."""
    protocols = []
    reader = ByteReader(data)
    list_reader = ByteReader(reader.read_vector(2))
    if reader.has_more():
        raise ValueError("Unexpected trailing bytes in ALPN extension payload")
    while list_reader.has_more():
        protocols.append(list_reader.read_vector(1))
    return protocols


def _decode_alpn(reader: ByteReader) -> dict:
    # Latin-1 preserves all identifier bytes while keeping the JSON string schema.
    return {
        "protocols": [
            protocol.decode("latin-1")
            for protocol in parse_alpn_protocols(reader.read_remaining())
        ]
    }


def _decode_supported_versions(reader: ByteReader) -> dict:
    return {"versions": _uint16_list(reader.read_vector(1), TLSVersion)}


def _decode_psk_key_exchange_modes(reader: ByteReader) -> dict:
    modes = reader.read_vector(1)
    return {"modes": [describe(value, PskKeyExchangeMode) for value in modes]}


def _decode_key_share(reader: ByteReader) -> dict:
    shares = []
    shares_reader = ByteReader(reader.read_vector(2))
    while shares_reader.has_more():
        group = shares_reader.read_uint16()
        key_exchange = shares_reader.read_vector(2)
        shares.append(
            {
                "group": describe(group, NamedGroup),
                "key_exchange_length": len(key_exchange),
                "key_exchange": key_exchange.hex(),
            }
        )
    return {"shares": shares}


def _decode_record_size_limit(reader: ByteReader) -> dict:
    limit = reader.read_uint16()
    if reader.has_more():
        raise ValueError("record_size_limit must contain exactly 2 bytes")
    return {"limit": limit}


def _decode_compress_certificate(reader: ByteReader) -> dict:
    return {
        "algorithms": _uint16_list(
            reader.read_vector(1), CertificateCompressionAlgorithm
        )
    }


def _decode_padding(reader: ByteReader) -> dict:
    padding = reader.read_remaining()
    return {"length": len(padding), "all_zero": not any(padding)}


def _decode_empty(reader: ByteReader) -> dict:
    # Presence is the entire message; a payload here means the client is unusual.
    return {"present": True, "unexpected_bytes": len(reader.read_remaining())}


def _uint16_list(data: bytes, enum_type) -> list:
    reader = ByteReader(data)
    values = []
    while reader.has_more():
        values.append(describe(reader.read_uint16(), enum_type))
    return values


_DECODERS = {
    ExtensionType.SERVER_NAME: _decode_server_name,
    ExtensionType.SUPPORTED_GROUPS: _decode_supported_groups,
    ExtensionType.EC_POINT_FORMATS: _decode_ec_point_formats,
    ExtensionType.SIGNATURE_ALGORITHMS: _decode_signature_algorithms,
    ExtensionType.SIGNATURE_ALGORITHMS_CERT: _decode_signature_algorithms,
    ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION: _decode_alpn,
    ExtensionType.PADDING: _decode_padding,
    ExtensionType.ENCRYPT_THEN_MAC: _decode_empty,
    ExtensionType.EXTENDED_MASTER_SECRET: _decode_empty,
    ExtensionType.COMPRESS_CERTIFICATE: _decode_compress_certificate,
    ExtensionType.RECORD_SIZE_LIMIT: _decode_record_size_limit,
    ExtensionType.SUPPORTED_VERSIONS: _decode_supported_versions,
    ExtensionType.PSK_KEY_EXCHANGE_MODES: _decode_psk_key_exchange_modes,
    ExtensionType.KEY_SHARE: _decode_key_share,
}
