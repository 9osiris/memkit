"""Tests scan the tool's own process: allocate ctypes buffers with known
values, attach to our own pid, and verify scans, reads, writes, pointer
chains, freezing and dumps all work."""
import ctypes
import os
import struct
import tempfile
import time
import unittest

from memkit import (
    Freezer,
    Process,
    Scanner,
    UnsupportedPlatformError,
    dump_region,
    find_processes,
    list_regions,
    platform_name,
    resolve,
)
from memkit.types import TYPES

MAGIC = 0xDEADBEEF
BUF_LEN = 16
buf = (ctypes.c_uint32 * BUF_LEN)(*([MAGIC] * BUF_LEN))
BUF_ADDR = ctypes.addressof(buf)


def region_of(addr):
    for r in list_regions(os.getpid()):
        if r.readable and r.contains(addr):
            return r
    raise AssertionError("no readable region contains %#x" % addr)


@unittest.skipIf(platform_name() == "macos", "macos is not supported")
class MemkitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proc = Process.attach_pid(os.getpid())
        region = region_of(BUF_ADDR)
        cls.start, cls.end = region.start, region.end

    @classmethod
    def tearDownClass(cls):
        cls.proc.close()

    def setUp(self):
        for i in range(BUF_LEN):
            buf[i] = MAGIC

    def test_platform_detected(self):
        self.assertEqual(platform_name(), "linux")

    def test_attach_self(self):
        with Process.attach_pid(os.getpid()) as p:
            self.assertEqual(p.pid, os.getpid())

    def test_find_processes_sees_self(self):
        pids = [pid for pid, _ in find_processes("python")]
        self.assertIn(os.getpid(), pids)

    def test_regions_sane(self):
        regions = list_regions(os.getpid())
        self.assertTrue(len(regions) > 10)
        for r in regions:
            self.assertLess(r.start, r.end)
            self.assertGreater(r.size, 0)
        self.assertTrue(any(r.readable for r in regions))

    def test_exact_scan_finds_buffer(self):
        scanner = Scanner(self.proc, "u32")
        found = scanner.scan_exact(MAGIC, self.start, self.end)
        self.assertIn(BUF_ADDR, found)
        # narrowing to a value nothing has kills every candidate
        found = scanner.scan_exact(0x12345678, self.start, self.end)
        self.assertNotIn(BUF_ADDR, found)

    def test_changed_scan(self):
        buf[0] = 1
        scanner = Scanner(self.proc, "u32")
        scanner.scan_initial(self.start, self.end)
        buf[0] = 2
        found = scanner.scan_changed()
        self.assertIn(BUF_ADDR, found)

    def test_unchanged_scan(self):
        scanner = Scanner(self.proc, "u32")
        scanner.scan_initial(self.start, self.end)
        found = scanner.scan_unchanged()
        self.assertIn(BUF_ADDR, found)

    def test_increased_scan(self):
        buf[2] = 10
        scanner = Scanner(self.proc, "u32")
        scanner.scan_initial(self.start, self.end)
        buf[2] = 20
        found = scanner.scan_increased()
        self.assertIn(BUF_ADDR + 8, found)

    def test_decreased_scan(self):
        buf[3] = 20
        scanner = Scanner(self.proc, "u32")
        scanner.scan_initial(self.start, self.end)
        buf[3] = 10
        found = scanner.scan_decreased()
        self.assertIn(BUF_ADDR + 12, found)

    def test_pointer_chain(self):
        target = ctypes.c_uint32(777)
        level1 = ctypes.c_uint64(ctypes.addressof(target))
        level2 = ctypes.c_uint64(ctypes.addressof(level1))
        addr = resolve(self.proc, ctypes.addressof(level2), [0, 0])
        self.assertEqual(addr, ctypes.addressof(target))
        self.assertEqual(self.proc.read_value("u32", addr), 777)

    def test_typed_read_write_roundtrip(self):
        scratch = ctypes.create_string_buffer(16)
        addr = ctypes.addressof(scratch)
        cases = [
            ("u8", 200), ("i8", -100),
            ("u16", 60000), ("i16", -30000),
            ("u32", 3000000000), ("i32", -2000000000),
            ("u64", 2 ** 63), ("i64", -(2 ** 62)),
            ("f32", 2.5), ("f64", -3.25),
        ]
        for type_name, value in cases:
            self.proc.write_value(type_name, addr, value)
            got = self.proc.read_value(type_name, addr)
            if type_name.startswith("f"):
                self.assertAlmostEqual(got, value, places=5, msg=type_name)
            else:
                self.assertEqual(got, value, msg=type_name)

    def test_string_roundtrip(self):
        scratch = ctypes.create_string_buffer(64)
        addr = ctypes.addressof(scratch)
        self.proc.write_string(addr, "hello memkit")
        self.assertEqual(self.proc.read_string(addr), "hello memkit")

    def test_freeze_holds_value(self):
        scratch = ctypes.c_uint32(1)
        addr = ctypes.addressof(scratch)
        freezer = Freezer(self.proc)
        try:
            fid = freezer.add(addr, "u32", 42, interval=0.05)
            self.assertEqual(len(freezer), 1)
            scratch.value = 99
            time.sleep(0.3)
            self.assertEqual(scratch.value, 42)
            freezer.remove(fid)
            self.assertEqual(len(freezer), 0)
        finally:
            freezer.stop_all()

    def test_dump_contains_magic(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            dump_region(self.proc, BUF_ADDR, BUF_LEN * 4, path)
            with open(path, "rb") as f:
                data = f.read()
            self.assertEqual(len(data), BUF_LEN * 4)
            self.assertIn(struct.pack("<I", MAGIC), data)
        finally:
            os.unlink(path)

    def test_scan_without_snapshot_raises(self):
        scanner = Scanner(self.proc, "u32")
        with self.assertRaises(RuntimeError):
            scanner.scan_changed()


if __name__ == "__main__":
    unittest.main()
