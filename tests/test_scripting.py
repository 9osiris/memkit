"""Tests for user scripting."""
import ctypes
import os
import tempfile
import unittest

from memkit.process import Process
from memkit.scripting import ScriptTarget, run_script, run_script_file


class ScriptingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proc = Process.attach_pid(os.getpid())

    @classmethod
    def tearDownClass(cls):
        cls.proc.close()

    def test_run_script_read_write(self):
        buf = (ctypes.c_uint32 * 2)(100, 200)
        addr = ctypes.addressof(buf)
        ns = run_script(
            "before = target.read('u32', %d)\n"
            "target.write('u32', %d, 999)\n"
            "after = target.read('u32', %d)\n" % (addr, addr, addr),
            self.proc)
        self.assertEqual(ns["before"], 100)
        self.assertEqual(ns["after"], 999)
        self.assertEqual(buf[0], 999)
        self.assertIsInstance(ns["target"], ScriptTarget)

    def test_run_script_returns_namespace(self):
        ns = run_script("x = 1 + 1\ntarget", self.proc)
        self.assertEqual(ns["x"], 2)
        self.assertIsInstance(ns["target"], ScriptTarget)

    def test_run_script_file(self):
        buf = ctypes.c_uint32(7)
        addr = ctypes.addressof(buf)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "patch.py")
            with open(path, "w") as f:
                f.write("target.write('u32', %d, 1234)\n" % addr)
                f.write("result = target.read('u32', %d)\n" % addr)
            ns = run_script_file(path, self.proc)
        self.assertEqual(ns["result"], 1234)
        self.assertEqual(buf.value, 1234)

    def test_run_script_file_missing(self):
        with self.assertRaises(FileNotFoundError):
            run_script_file("/nope/missing.py", self.proc)

    def test_script_error_propagates(self):
        with self.assertRaises(ZeroDivisionError):
            run_script("1 / 0", self.proc)
        with self.assertRaises(SyntaxError):
            run_script("def broken(:", self.proc)

    def test_target_scan(self):
        buf = (ctypes.c_uint32 * 8)(*([0xBEEF] * 8))
        addr = ctypes.addressof(buf)
        target = ScriptTarget(self.proc)
        hits = target.scan("u32", 0xBEEF, start=addr, end=addr + 32)
        self.assertEqual(sorted(hits),
                         [addr + i * 4 for i in range(8)])

    def test_target_scan_aob(self):
        buf = ctypes.create_string_buffer(b"\x00\xde\xad\xbe\xef\x00")
        addr = ctypes.addressof(buf)
        target = ScriptTarget(self.proc)
        hits = target.scan_aob("de ad be ef", start=addr, end=addr + 6)
        self.assertEqual(hits, [addr + 1])

    def test_target_find_strings(self):
        buf = ctypes.create_string_buffer(b"script-marker-123\x00")
        addr = ctypes.addressof(buf)
        target = ScriptTarget(self.proc)
        hits = target.find_strings(min_length=8, start=addr - 0x80,
                                   end=addr + 0x80)
        by_value = {h.value: h for h in hits}
        self.assertIn("script-marker-123", by_value)
        self.assertEqual(by_value["script-marker-123"].address, addr)

    def test_target_regions_and_snapshot(self):
        target = ScriptTarget(self.proc)
        regions = target.regions()
        self.assertTrue(len(regions) > 0)
        buf = (ctypes.c_uint32 * 2)(5, 6)
        addr = ctypes.addressof(buf)
        snap = target.snapshot([addr, addr + 4], "u32")
        self.assertEqual(snap.values, {addr: 5, addr + 4: 6})

    def test_target_read_write_bytes(self):
        buf = ctypes.create_string_buffer(b"\x00" * 8)
        addr = ctypes.addressof(buf)
        target = ScriptTarget(self.proc)
        target.write_bytes(addr, b"\x01\x02\x03")
        self.assertEqual(target.read_bytes(addr, 3), b"\x01\x02\x03")

    def test_target_repr(self):
        self.assertIn("ScriptTarget", repr(ScriptTarget(self.proc)))


if __name__ == "__main__":
    unittest.main()
