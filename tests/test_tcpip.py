import unittest
from types import SimpleNamespace

from solvetls.report import _tcpip_report
from solvetls.tcpip import parse_syn

IPV4_SYN = bytes.fromhex(
    "450000281234400033063770cb00712ac0000201d43101bb01020304000000005002faf0dcd20000"
)
IPV6_SYN = bytes.fromhex(
    "600000000014063320010db8000000000000000000000042"
    "20010db8000000000000000000000001"
    "d43101bb01020304000000005002faf07f4a0000"
)


class TCPIPTests(unittest.TestCase):
    def test_saved_syn_fields(self):
        cases = [
            (IPV4_SYN, "203.0.113.42", "192.0.2.1", 4, 40, 4660, 56530),
            (IPV6_SYN, "2001:db8::42", "2001:db8::1", 6, 60, None, 32586),
        ]
        for (
            packet,
            source,
            destination,
            version,
            size,
            identification,
            checksum,
        ) in cases:
            with self.subTest(ip_version=version):
                self.assertEqual(
                    parse_syn(packet),
                    {
                        "cap_length": size,
                        "src_port": 54321,
                        "dst_port": 443,
                        "ip": {
                            "id": identification,
                            "ttl": 51,
                            "ip_version": version,
                            "src_ip": source,
                            "dst_ip": destination,
                        },
                        "tcp": {
                            "seq": 16909060,
                            "ack": 0,
                            "window": 64240,
                            "checksum": checksum,
                        },
                    },
                )

    def test_missing_or_truncated_syn_has_no_packet_data(self):
        for packet in (None, b"", IPV4_SYN[:15], IPV6_SYN[:45]):
            with self.subTest(packet=packet):
                self.assertIsNone(parse_syn(packet))

    def test_report_uses_socket_addresses_when_syn_is_unavailable(self):
        for source, destination, version in (
            ("203.0.113.42", "192.0.2.1", 4),
            ("2001:db8::42", "2001:db8::1", 6),
        ):
            with self.subTest(ip_version=version):
                client = SimpleNamespace(
                    peername=(source, 54321),
                    sockname=(destination, 443),
                    syn_packet=None,
                )
                report = _tcpip_report(client)
                self.assertEqual(report["src_port"], 54321)
                self.assertEqual(report["dst_port"], 443)
                self.assertEqual(
                    report["ip"],
                    {
                        "id": None,
                        "ttl": None,
                        "ip_version": version,
                        "src_ip": source,
                        "dst_ip": destination,
                    },
                )
                self.assertIsNone(report["cap_length"])
                self.assertEqual(
                    report["tcp"],
                    {"ack": None, "checksum": None, "seq": None, "window": None},
                )
