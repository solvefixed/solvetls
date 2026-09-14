import unittest

from solvetls.wire.reader import ByteReader


class ByteReaderTests(unittest.TestCase):
    def test_failed_reads_preserve_position_for_following_reads(self):
        data = b"abc"
        for position in (0, 1, len(data)):
            for length in (-1, len(data) + 1):
                with self.subTest(position=position, length=length):
                    reader = ByteReader(data)
                    self.assertEqual(reader.read(position), data[:position])
                    with self.assertRaises(ValueError):
                        reader.read(length)
                    self.assertEqual(reader.read_remaining(), data[position:])
                    self.assertFalse(reader.has_more())


if __name__ == "__main__":
    unittest.main()
