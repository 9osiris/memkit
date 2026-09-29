"""Tests for AoB pattern scans: parsing, matching, and scanning the tool's
own process for planted byte patterns."""
import ctypes
import os
import unittest

from memkit.aob import Pattern, PatternError, scan_pattern
from memkit.process import Process
from memkit.regions import list_regions


def region_of(addr):
    for r in list_regions(os.getpid()):
        if r.readable and r.contains(addr):
            return r
    raise AssertionError("no readable region contains %#x" % addr)


class PatternParseTest(unittest.TestCase):
    def test_basic_parse(self):
        p = Pattern.parse("48 8B ?? 74 10")
        self.assertEqual(p.bytes, b"\x48\x8b\x00\x74\x10")
        self.assertEqual(p.mask, b"\xff\xff\x00\xff\xff")
        self.assertEqual(len(p), 5)

    def test_single_question_mark(self):
        p = Pattern.parse("48 ? 10")
        self.assertEqual(p.mask, b"\xff\x00\xff")

    def test_nibble_wildcards(self):
        p = Pattern.parse("4? ?0")
        self.assertEqual(p.bytes, b"\x40\x00")
        self.assertEqual(p.mask, b"\xf0\x0f")

    def test_case_insensitive(self):
        self.assertEqual(Pattern.parse("ab cd"), Pattern.parse("AB CD"))

    def test_round_trip(self):
        for text in ("48 8B ?? 74 10", "4? ?0 AB"):
            self.assertEqual(Pattern.parse(text).to_text(), text)

    def test_empty_raises(self):
        with self.assertRaises(PatternError):
            Pattern.parse("")

    def test_bad_token_raises(self):
        for bad in ("48 ZZ 10", "4", "484", "GH"):
            with self.assertRaises(PatternError):
                Pattern.parse(bad)

    def test_from_bytes(self):
        p = Pattern.from_bytes(b"\x48\x8b")
        self.assertEqual(p.mask, b"\xff\xff")
        p = Pattern.from_bytes(b"\x48\x8b", mask=b"\xff\x00")
        self.assertTrue(p.matches_at(b"\x48\x00", 0))
        self.assertFalse(p.matches_at(b"\x49\x8b", 0))

    def test_mismatched_mask_raises(self):
        with self.assertRaises(PatternError):
            Pattern(b"\x48", b"\xff\xff")


class PatternMatchTest(unittest.TestCase):
    def test_find_all(self):
        p = Pattern.parse("DE AD ?? EF")
        data = b"\x00\xde\xad\x01\xef\xde\xad\xff\xef"
        self.assertEqual(p.find_all(data), [1, 5])

    def test_find_all_with_base(self):
        p = Pattern.parse("AA BB")
        self.assertEqual(p.find_all(b"\x00\xaa\xbb", base=0x1000), [0x1001])

    def test_all_wildcards_match_everywhere(self):
        p = Pattern.parse("?? ??")
        self.assertEqual(p.find_all(b"\x01\x02\x03"), [0, 1])

    def test_no_match(self):
        p = Pattern.parse("FF FF FF")
        self.assertEqual(p.find_all(b"\x00" * 16), [])

    def test_pattern_longer_than_data(self):
        p = Pattern.parse("AA BB CC DD")
        self.assertEqual(p.find_all(b"\xaa\xbb"), [])

    def test_matches_at_bounds(self):
        p = Pattern.parse("AA BB")
        self.assertFalse(p.matches_at(b"\xaa", 0))
        self.assertFalse(p.matches_at(b"\x00\xaa\xbb", -1))
        self.assertTrue(p.matches_at(b"\x00\xaa\xbb", 1))

    def test_nibble_match(self):
        p = Pattern.parse("4?")
        self.assertTrue(p.matches_at(b"\x4f", 0))
        self.assertFalse(p.matches_at(b"\x5f", 0))

    def test_solid_count(self):
        self.assertEqual(Pattern.parse("48 ?? 10").solid_count, 2)


class ScanProcessTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proc = Process.attach_pid(os.getpid())

    @classmethod
    def tearDownClass(cls):
        cls.proc.close()

    def setUp(self):
        # a buffer with a recognizable pattern planted twice
        self.buf = (ctypes.c_ubyte * 64)(*([0xCC] * 64))
        self.pat = bytes([0x48, 0x8B, 0x11, 0x22, 0x74, 0x10])
        self.buf[8:14] = (ctypes.c_ubyte * 6)(*self.pat)
        self.buf[40:46] = (ctypes.c_ubyte * 6)(*self.pat)
        self.addr = ctypes.addressof(self.buf)
        region = region_of(self.addr)
        self.start, self.end = region.start, region.end

    def test_scan_finds_planted_pattern(self):
        found = scan_pattern(self.proc, "48 8B ?? ?? 74 10",
                             self.start, self.end)
        self.assertIn(self.addr + 8, found)
        self.assertIn(self.addr + 40, found)

    def test_scan_accepts_pattern_object(self):
        found = scan_pattern(self.proc, Pattern.parse("11 22"),
                             self.start, self.end)
        self.assertIn(self.addr + 10, found)

    def test_alignment_filters(self):
        # 0x11 sits at addr+10; align to 16 keeps only 16-aligned hits
        found = scan_pattern(self.proc, "48 8B 11 22 74 10",
                             self.start, self.end, alignment=16)
        for hit in found:
            self.assertEqual(hit % 16, 0)

    def test_max_results(self):
        found = scan_pattern(self.proc, "CC", self.start, self.end,
                             max_results=3)
        self.assertEqual(len(found), 3)

    def test_no_duplicates_across_chunks(self):
        found = scan_pattern(self.proc, "48 8B 11 22 74 10",
                             self.start, self.end, chunk_size=32)
        hits = [h for h in found if h in (self.addr + 8, self.addr + 40)]
        self.assertEqual(sorted(hits), [self.addr + 8, self.addr + 40])

    def test_pattern_spanning_chunk_edge(self):
        # plant the pattern so it straddles a 32 byte chunk boundary
        self.buf[30:36] = (ctypes.c_ubyte * 6)(*self.pat)
        found = scan_pattern(self.proc, "48 8B 11 22 74 10",
                             self.start, self.end, chunk_size=32)
        self.assertIn(self.addr + 30, found)

    def test_bad_alignment_raises(self):
        with self.assertRaises(ValueError):
            scan_pattern(self.proc, "AA", self.start, self.end, alignment=0)


if __name__ == "__main__":
    unittest.main()
