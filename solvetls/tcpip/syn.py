import socket
import sys

from ..wire.reader import ByteReader

# Linux 4.3+ exposes the original SYN headers through these options.
# Values from include/uapi/linux/tcp.h; socket only exposes them on Python 3.12+.
TCP_SAVE_SYN = getattr(socket, "TCP_SAVE_SYN", 27)
TCP_SAVED_SYN = getattr(socket, "TCP_SAVED_SYN", 28)
SAVE_SYN_SUPPORTED = sys.platform.startswith("linux")

IPV4_HEADER_SIZE = 20
IPPROTO_TCP = 6
# IPv6 (40) plus TCP with every option (60) still fits.
SYN_BUFFER_SIZE = 256


def enable_save_syn(sock: socket.socket) -> bool:
    if not SAVE_SYN_SUPPORTED:
        return False

    try:
        sock.setsockopt(socket.IPPROTO_TCP, TCP_SAVE_SYN, 1)
        return True
    except OSError:
        return False


def read_saved_syn(sock: socket.socket | None) -> bytes | None:
    """Take the saved SYN. Read once: the kernel frees the buffer afterwards.

    Comes back empty when the listener never enabled saving, or when the kernel
    was in SYN cookie mode and so had nothing to keep.
    """
    if not SAVE_SYN_SUPPORTED or sock is None:
        return None

    try:
        return (
            sock.getsockopt(socket.IPPROTO_TCP, TCP_SAVED_SYN, SYN_BUFFER_SIZE) or None
        )
    except OSError:
        return None


def parse_syn(data: bytes | None) -> dict | None:
    """Split a saved SYN into its IP and TCP headers. None if it cannot be read."""
    if not data:
        return None

    try:
        return _parse(data)
    except (ValueError, IndexError, OSError):
        return None


def _parse(data: bytes) -> dict | None:
    reader = ByteReader(data)
    version = data[0] >> 4

    if version == 4:
        ip = _parse_ipv4(reader)
    elif version == 6:
        ip = _parse_ipv6(reader)
    else:
        return None

    if ip is None:
        return None

    tcp = _parse_tcp(reader)
    return {
        # Saved SYN data excludes the link-layer header.
        "cap_length": len(data),
        "dst_port": tcp.pop("dst_port"),
        "src_port": tcp.pop("src_port"),
        "ip": ip,
        "tcp": tcp,
    }


def _parse_ipv4(reader: ByteReader) -> dict:
    header_length = (reader.read_uint8() & 0x0F) * 4
    reader.read_uint8()  # DSCP + ECN
    reader.read_uint16()  # total length
    identification = reader.read_uint16()
    reader.read_uint16()  # flags + fragment offset
    ttl = reader.read_uint8()
    reader.read_uint8()  # protocol
    reader.read_uint16()  # header checksum
    src = reader.read(4)
    dst = reader.read(4)
    reader.read(max(header_length - IPV4_HEADER_SIZE, 0))  # options

    return {
        "id": identification,
        "ttl": ttl,
        "ip_version": 4,
        "dst_ip": socket.inet_ntop(socket.AF_INET, dst),
        "src_ip": socket.inet_ntop(socket.AF_INET, src),
    }


def _parse_ipv6(reader: ByteReader) -> dict | None:
    reader.read(4)  # version + traffic class + flow label
    reader.read_uint16()  # payload length
    next_header = reader.read_uint8()
    hop_limit = reader.read_uint8()
    src = reader.read(16)
    dst = reader.read(16)

    # Extension headers would sit between here and the TCP header.
    if next_header != IPPROTO_TCP:
        return None

    return {
        "id": None,  # IPv6 dropped the identification field
        "ttl": hop_limit,  # same role, renamed by the RFC
        "ip_version": 6,
        "dst_ip": socket.inet_ntop(socket.AF_INET6, dst),
        "src_ip": socket.inet_ntop(socket.AF_INET6, src),
    }


def _parse_tcp(reader: ByteReader) -> dict:
    src_port = reader.read_uint16()
    dst_port = reader.read_uint16()
    seq = reader.read_uint32()
    ack = reader.read_uint32()  # ignored by the peer unless the ACK flag is set
    reader.read_uint8()  # data offset + reserved
    reader.read_uint8()  # flags
    window = reader.read_uint16()
    checksum = reader.read_uint16()
    reader.read_uint16()  # urgent pointer

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "ack": ack,
        "checksum": checksum,
        "seq": seq,
        "window": window,
    }
