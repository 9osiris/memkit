"""Tests for string scans. Buffer scans are pure; the live process
scan uses a known ctypes buffer in our own address space."""
import ctypes
import os
import unittest

from memkit.process import Process
from memkit.strings import (
    StringHit,
    filter_strings,
    find_ascii,
    find_strings,
    find_utf8,
    find_utf16le,
    scan_strings,
)


class AsciiTest(unittest.TestCase):
    def test_finds_run(self):
        data = b"\x00\x01hello world\x00\x02"
        hits = find_ascii(data, 0x1000, min_length=4)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].address, 0x1002)
        self.assertEqual(hits[0].value, "hello world")
        self.assertEqual(hits[0].encoding, "ascii")
        self.assertEqual(hits[0].length, 11)

    def test_min_length(self):
        data = b"abc\x00abcdef"
        hits = find_ascii(data, 0, min_length=4)
        self.assertEqual([h.value for h in hits], ["abcdef"])

    def test_no_hits(self):
        self.assertEqual(find_ascii(b"\x00\x01\x02\xff", 0), [])

    def test_hit_equality_and_repr(self):
        a = StringHit(0x10, "ascii", "hi")
        b = StringHit(0x10, "ascii", "hi")
        self.assertEqual(a, b)
        self.assertEqual(hash(a), hash(b))
        self.assertIn("0x10", repr(a))
        self.assertNotEqual(a, StringHit(0x11, "ascii", "hi"))


class Utf8Test(unittest.TestCase):
    def test_finds_multibyte(self):
        text = "héllo wörld"
        data = b"\x00" + text.encode("utf-8") + b"\xff"
        hits = find_utf8(data, 0, min_length=4)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].value, text)
        self.assertEqual(hits[0].address, 1)

    def test_rejects_invalid_sequence(self):
        # lone continuation bytes are not text
        data = b"\x80\x81\x82\x83hello"
        hits = find_utf8(data, 0, min_length=4)
        self.assertEqual([h.value for h in hits], ["hello"])

    def test_rejects_overlong(self):
        # overlong encoding of "/" is invalid utf-8
        data = b"\xc0\xaf\xc0\xafhello!"
        hits = find_utf8(data, 0, min_length=4)
        self.assertEqual([h.value for h in hits], ["hello!"])

    def test_counts_characters(self):
        text = "ääää"  # 4 chars, 8 bytes
        hits = find_utf8(text.encode("utf-8"), 0, min_length=4)
        self.assertEqual(len(hits), 1)
        hits = find_utf8(text.encode("utf-8"), 0, min_length=5)
        self.assertEqual(hits, [])


class Utf16Test(unittest.TestCase):
    def test_finds_string(self):
        data = b"\x00\x00" + "hello".encode("utf-16-le") + b"\x00\x00"
        hits = find_utf16le(data, 0x2000, min_length=4)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].value, "hello")
        self.assertEqual(hits[0].address, 0x2002)
        self.assertEqual(hits[0].encoding, "utf-16le")

    def test_odd_base_address_scans_odd_offsets(self):
        # alignment follows the address, not the buffer start
        data = b"X" + "hello".encode("utf-16-le") + b"\x00\x00"
        hits = find_utf16le(data, 0x2001, min_length=4)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].value, "hello")
        self.assertEqual(hits[0].address, 0x2002)

    def test_skips_short_runs(self):
        # only one full utf-16le unit here, below min_length
        self.assertEqual(find_utf16le(b"abc", 0, min_length=2), [])

    def test_bare_ascii_pairs_are_cjk(self):
        # honest behavior of a dedicated utf-16le scan: paired ascii
        # bytes read as printable CJK. combined scans dedupe this.
        hits = find_utf16le(b"hello\x00", 0, min_length=2)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].encoding, "utf-16le")

    def test_min_length(self):
        data = "abc".encode("utf-16-le")
        self.assertEqual(find_utf16le(data, 0, min_length=4), [])
        self.assertEqual(len(find_utf16le(data, 0, min_length=2)), 1)

    def test_surrogate_pair(self):
        text = "a\U0001F600bcd"  # emoji needs a surrogate pair
        data = text.encode("utf-16-le")
        hits = find_utf16le(data, 0, min_length=4)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].value, text)


class FindStringsTest(unittest.TestCase):
    def test_combined_and_sorted(self):
        data = (b"\x00\x00" + b"ascii string" + b"\x00\x00"
                + "wörld".encode("utf-16-le") + b"\x00\x00")
        hits = find_strings(data, 0x100, min_length=4)
        addrs = [h.address for h in hits]
        self.assertEqual(addrs, sorted(addrs))
        values = [h.value for h in hits]
        self.assertIn("ascii string", values)
        self.assertIn("wörld", values)
        # the ascii bytes are not also misreported as CJK
        self.assertEqual(len(hits), 2)

    def test_dedupe_by_address(self):
        data = b"hello world"
        hits = find_strings(data, 0, min_length=4,
                            encodings=("ascii", "utf-8"))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].encoding, "ascii")

    def test_unknown_encoding(self):
        with self.assertRaises(ValueError):
            find_strings(b"hello", 0, encodings=("ebcdic",))

    def test_filter_strings(self):
        hits = [StringHit(1, "ascii", "hello world"),
                StringHit(2, "ascii", "goodbye")]
        self.assertEqual(len(filter_strings(hits, r"hello")), 1)
        self.assertEqual(filter_strings(hits, r"^good"), [hits[1]])
        self.assertEqual(filter_strings(hits, r"zzz"), [])


class LiveScanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proc = Process.attach_pid(os.getpid())

    @classmethod
    def tearDownClass(cls):
        cls.proc.close()

    def test_scan_finds_planted_strings(self):
        # one buffer so both markers share a region and the scan range
        blob = (b"memkit-ascii-marker\x00" + b"\x00" * 16
                + "memkit-wide-marker".encode("utf-16-le") + b"\x00\x00")
        buf = ctypes.create_string_buffer(blob)
        addr = ctypes.addressof(buf)
        waddr = addr + len(b"memkit-ascii-marker\x00") + 16
        hits = scan_strings(self.proc, min_length=8,
                            start=addr - 0x100, end=addr + len(blob) + 0x100)
        by_value = {h.value: h for h in hits}
        self.assertIn("memkit-ascii-marker", by_value)
        self.assertIn("memkit-wide-marker", by_value)
        self.assertEqual(by_value["memkit-ascii-marker"].address, addr)
        self.assertEqual(by_value["memkit-wide-marker"].address, waddr)


if __name__ == "__main__":
    unittest.main()
