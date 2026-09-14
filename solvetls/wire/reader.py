import struct


class ByteReader:
    """Sequential big-endian reader over a fixed buffer."""

    _data: bytes
    _pos: int

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    def has_more(self) -> bool:
        return self._pos < len(self._data)

    def read(self, n: int) -> bytes:
        if n < 0:
            raise ValueError("Read length must be non-negative")
        if self._pos + n > len(self._data):
            raise ValueError("Insufficient data")
        result = self._data[self._pos : self._pos + n]
        self._pos += n
        return result

    def read_remaining(self) -> bytes:
        return self.read(len(self._data) - self._pos)

    def read_uint8(self) -> int:
        return struct.unpack(">B", self.read(1))[0]

    def read_uint16(self) -> int:
        return struct.unpack(">H", self.read(2))[0]

    def read_uint24(self) -> int:
        return struct.unpack(">I", b"\x00" + self.read(3))[0]

    def read_uint32(self) -> int:
        return struct.unpack(">I", self.read(4))[0]

    def read_vector(self, length_bytes: int) -> bytes:
        """Read a length-prefixed blob; TLS writes the length in 1, 2 or 3 bytes."""
        if length_bytes == 1:
            length = self.read_uint8()
        elif length_bytes == 2:
            length = self.read_uint16()
        elif length_bytes == 3:
            length = self.read_uint24()
        else:
            raise ValueError("Invalid length_bytes")
        return self.read(length)
