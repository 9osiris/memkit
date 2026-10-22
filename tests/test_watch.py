"""Tests for watchpoint-style polling: poll an address, print changes."""
import ctypes
import ctypes.util
import io
import os
import sys
import time
import unittest
from contextlib import redirect_stdout

from memkit import Process, Watcher, platform_name
from memkit.cli import Shell


def run_commands(shell, *lines):
    out = io.StringIO()
    with redirect_stdout(out):
        for line in lines:
            shell.execute(line)
    return out.getvalue()


@unittest.skipIf(platform_name() == "macos", "macos is not supported")
class WatcherTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proc = Process.attach_pid(os.getpid())

    @classmethod
    def tearDownClass(cls):
        cls.proc.close()

    def setUp(self):
        self.watcher = Watcher(self.proc)

    def tearDown(self):
        self.watcher.stop_all()

    def test_change_printed(self):
        buf = ctypes.c_uint32(1)
        addr = ctypes.addressof(buf)
        out = io.StringIO()
        with redirect_stdout(out):
            wid = self.watcher.add(addr, "u32", 0.01)
            buf.value = 2
            time.sleep(0.3)
            self.watcher.remove(wid)
        text = out.getvalue()
        self.assertIn("1 -> 2", text)
        self.assertIn("%#x" % addr, text)

    def test_no_change_no_output(self):
        buf = ctypes.c_uint32(9)
        addr = ctypes.addressof(buf)
        out = io.StringIO()
        with redirect_stdout(out):
            self.watcher.add(addr, "u32", 0.01)
            time.sleep(0.25)
        self.assertNotIn("->", out.getvalue())

    def test_unknown_type(self):
        buf = ctypes.c_uint32(0)
        with self.assertRaises(ValueError):
            self.watcher.add(ctypes.addressof(buf), "nope")

    def test_bad_interval(self):
        buf = ctypes.c_uint32(0)
        addr = ctypes.addressof(buf)
        with self.assertRaises(ValueError):
            self.watcher.add(addr, "u32", 0)
        with self.assertRaises(ValueError):
            self.watcher.add(addr, "u32", -0.5)

    def test_unmapped_address_fails_fast(self):
        with self.assertRaises(OSError):
            self.watcher.add(0x1, "u32")

    def test_add_remove_list(self):
        buf = ctypes.c_uint32(5)
        addr = ctypes.addressof(buf)
        wid = self.watcher.add(addr, "u32", 0.5)
        self.assertEqual(len(self.watcher), 1)
        listed = self.watcher.list()
        self.assertEqual(listed[wid][:2], (addr, "u32"))
        self.assertEqual(listed[wid][2], 5)  # last seen value
        self.watcher.remove(wid)
        self.assertEqual(len(self.watcher), 0)
        with self.assertRaises(KeyError):
            self.watcher.remove(wid)

    @unittest.skipIf(not sys.platform.startswith("linux"), "needs mmap")
    def test_munmap_prints_note(self):
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        libc.mmap.restype = ctypes.c_void_p
        libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                              ctypes.c_int, ctypes.c_int, ctypes.c_int64]
        libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        addr = libc.mmap(None, 4096, 3, 0x22, -1, 0)
        self.assertNotEqual(addr, ctypes.c_void_p(-1).value)
        try:
            ctypes.c_uint32.from_address(addr).value = 7
            out = io.StringIO()
            with redirect_stdout(out):
                wid = self.watcher.add(addr, "u32", 0.01)
                time.sleep(0.15)
                libc.munmap(addr, 4096)
                time.sleep(0.3)
                self.watcher.remove(wid)
        finally:
            pass
        self.assertIn("unreadable", out.getvalue())

    @unittest.skipIf(not sys.platform.startswith("linux"), "needs mmap")
    def test_remap_prints_readable_again(self):
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        libc.mmap.restype = ctypes.c_void_p
        libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                              ctypes.c_int, ctypes.c_int, ctypes.c_int64]
        libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        addr = libc.mmap(None, 4096, 3, 0x22, -1, 0)
        self.assertNotEqual(addr, ctypes.c_void_p(-1).value)
        try:
            ctypes.c_uint32.from_address(addr).value = 1
            out = io.StringIO()
            with redirect_stdout(out):
                wid = self.watcher.add(addr, "u32", 0.01)
                time.sleep(0.15)
                libc.munmap(addr, 4096)
                time.sleep(0.15)
                # remap at the exact address with MAP_FIXED
                fixed = libc.mmap(addr, 4096, 3, 0x22 | 0x10, -1, 0)
                self.assertEqual(fixed, addr)
                ctypes.c_uint32.from_address(addr).value = 2
                time.sleep(0.25)
                self.watcher.remove(wid)
        finally:
            libc.munmap(addr, 4096)
        text = out.getvalue()
        self.assertIn("unreadable", text)
        self.assertIn("readable again", text)
        self.assertIn("-> 2", text)


@unittest.skipIf(platform_name() == "macos", "macos is not supported")
class WatchCliTest(unittest.TestCase):
    def setUp(self):
        self.shell = Shell()
        run_commands(self.shell, "attach pid %d" % os.getpid())
        self.assertIsNotNone(self.shell.watcher)

    def tearDown(self):
        self.shell._cleanup()

    def test_watch_unwatch_watches(self):
        buf = ctypes.c_uint32(10)
        addr = ctypes.addressof(buf)
        out = io.StringIO()
        with redirect_stdout(out):
            self.shell.execute("watch u32 %#x 0.01" % addr)
            buf.value = 11
            time.sleep(0.3)
            self.shell.execute("watches")
            self.shell.execute("unwatch 1")
        text = out.getvalue()
        self.assertIn("10 -> 11", text)
        self.assertIn("1: u32", text)
        self.assertIn("unwatched", text)

    def test_watch_unmapped_prints_note(self):
        out = run_commands(self.shell, "watch u32 0x1")
        self.assertIn("unreadable", out)
        # shell still works after the failure
        out = run_commands(self.shell, "watches")
        self.assertIn("nothing watched", out)

    def test_watch_bad_type_is_clean_error(self):
        buf = ctypes.c_uint32(0)
        out = run_commands(self.shell,
                           "watch nope %#x" % ctypes.addressof(buf))
        self.assertIn("error:", out)

    def test_help_mentions_watch(self):
        out = run_commands(self.shell, "help")
        self.assertIn("watch <type> <addr>", out)


if __name__ == "__main__":
    unittest.main()
