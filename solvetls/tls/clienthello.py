from dataclasses import dataclass

from ..wire.reader import ByteReader


@dataclass
class Extension:
    type: int
    data: bytes


@dataclass
class ClientHello:
    version: int
    random: bytes
    session_id: bytes
    cipher_suites: list[int]
    compression_methods: list[int]
    extensions: list[Extension]


class ClientHelloReader(ByteReader):
    """Extract ClientHello fields for capture; OpenSSL validates the TLS message.

    Reads enforce buffer bounds and vector element widths, but do not check every
    TLS constraint, such as session ID limits or whether all bytes were consumed.
    The connection replays the original message into OpenSSL before serving HTTP.
    """

    def parse(self) -> ClientHello:
        client_version = self.read_uint16()
        random = self.read(32)
        session_id = self.read_vector(1)

        ciphers = ByteReader(self.read_vector(2))
        cipher_suites = []
        while ciphers.has_more():
            cipher_suites.append(ciphers.read_uint16())

        compression_methods = list(self.read_vector(1))

        extensions = []
        if self.has_more():
            ext_reader = ByteReader(self.read_vector(2))
            while ext_reader.has_more():
                ext_type = ext_reader.read_uint16()
                extensions.append(Extension(ext_type, ext_reader.read_vector(2)))

        return ClientHello(
            version=client_version,
            random=random,
            session_id=session_id,
            cipher_suites=cipher_suites,
            compression_methods=compression_methods,
            extensions=extensions,
        )
