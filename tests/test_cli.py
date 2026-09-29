"""Tests for the cli shell: new commands and batch file execution."""
import ctypes
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from memkit.cli import Shell, main


def run_commands(shell, *lines):
    out = io.StringIO()
    with redirect_stdout(out):
        for line in lines:
            shell.execute(line)
    return out.getvalue()


class CliTest(unittest.TestCase):
    def setUp(self):
        self.shell = Shell()
        run_commands(self.shell, "attach pid %d" % os.getpid())
        self.assertIsNotNone(self.shell.process)

    def tearDown(self):
        self.shell._cleanup()

    def test_attach_and_read_write(self):
        buf = ctypes.c_uint32(0)
        addr = ctypes.addressof(buf)
        out = run_commands(self.shell,
                           "write u32 %#x 12345" % addr,
                           "read u32 %#x" % addr)
        self.assertIn("12345", out)
        self.assertEqual(buf.value, 12345)

    def test_aob_command(self):
        buf = ctypes.create_string_buffer(b"\x00\xde\xad\xbe\xef\x00")
        addr = ctypes.addressof(buf)
        out = run_commands(
            self.shell,
            "aob \"de ad be ef\" %#x %#x" % (addr, addr + 6))
        self.assertIn("%#x" % (addr + 1), out)
        self.assertIn("1 hits", out)

    def test_strings_command(self):
        buf = ctypes.create_string_buffer(b"cli-string-marker\x00")
        addr = ctypes.addressof(buf)
        out = run_commands(
            self.shell,
            "strings 8 %#x %#x" % (addr - 0x40, addr + 0x40))
        self.assertIn("cli-string-marker", out)

    def test_ptrscan_command(self):
        target = ctypes.c_uint32(0x12345678)
        slot = (ctypes.c_void_p * 1)(ctypes.addressof(target))
        taddr = ctypes.addressof(target)
        saddr = ctypes.addressof(slot)
        out = run_commands(
            self.shell,
            "ptrscan %#x 1 0x100 %#x %#x" % (taddr, saddr - 0x40,
                                            saddr + 0x40))
        self.assertIn("%#x" % saddr, out)
        self.assertIn("1 chains", out)

    def test_script_command(self):
        buf = ctypes.c_uint32(1)
        addr = ctypes.addressof(buf)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "s.py")
            with open(path, "w") as f:
                f.write("target.write('u32', %d, 777)\n" % addr)
            out = run_commands(self.shell, "script %s" % path)
        self.assertIn("ran %s" % path, out)
        self.assertEqual(buf.value, 777)

    def test_session_commands(self):
        buf = (ctypes.c_uint32 * 2)(10, 20)
        a1 = ctypes.addressof(buf)
        a2 = a1 + 4
        out = run_commands(
            self.shell,
            "session new clitest",
            "session snapaddr s1 u32 %#x %#x" % (a1, a2),
            "write u32 %#x 11" % a1,
            "session snapaddr s2 u32 %#x %#x" % (a1, a2),
            "session diff s1 s2",
            "session list")
        self.assertIn("new session 'clitest'", out)
        self.assertIn("%#x: 10 -> 11" % a1, out)
        self.assertIn("1 changed, 0 added, 0 removed", out)
        self.assertIn("snapshot 's1'", out)

    def test_session_save_load(self):
        buf = ctypes.c_uint32(5)
        addr = ctypes.addressof(buf)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "s.json")
            run_commands(
                self.shell,
                "session new savetest",
                "session snapaddr s1 u32 %#x" % addr,
                "session save %s" % path)
            self.assertTrue(os.path.isfile(path))
            shell2 = Shell()
            try:
                out = run_commands(
                    shell2,
                    "attach pid %d" % os.getpid(),
                    "session load %s" % path,
                    "session list")
            finally:
                shell2._cleanup()
        self.assertIn("loaded session 'savetest'", out)
        self.assertIn("snapshot 's1'", out)

    def test_unknown_command(self):
        out = run_commands(self.shell, "frobnicate")
        self.assertIn("unknown command", out)

    def test_execute_quit_returns_false(self):
        self.assertFalse(self.shell.execute("quit"))
        self.assertTrue(self.shell.execute("help"))

    def test_needs_attach(self):
        shell = Shell()
        out = run_commands(shell, "read u32 0x1000")
        self.assertIn("not attached", out)


class BatchTest(unittest.TestCase):
    def test_run_batch(self):
        buf = ctypes.c_uint32(0)
        addr = ctypes.addressof(buf)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "job.mk")
            with open(path, "w") as f:
                f.write("# a comment line\n")
                f.write("\n")
                f.write("attach pid %d\n" % os.getpid())
                f.write("write u32 %#x 4242\n" % addr)
                f.write("read u32 %#x\n" % addr)
                f.write("quit\n")
                f.write("read u32 %#x\n" % addr)  # never runs
            shell = Shell()
            out = io.StringIO()
            with redirect_stdout(out):
                code = shell.run_batch(path)
        self.assertEqual(code, 0)
        self.assertIn("4242", out.getvalue())
        self.assertEqual(out.getvalue().count("4242"), 2)
        self.assertEqual(buf.value, 4242)

    def test_run_batch_bad_command_keeps_going(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "job.mk")
            with open(path, "w") as f:
                f.write("frobnicate\n")
                f.write("help\n")
            shell = Shell()
            out = io.StringIO()
            with redirect_stdout(out):
                code = shell.run_batch(path)
        self.assertEqual(code, 0)
        text = out.getvalue()
        self.assertIn("unknown command", text)
        self.assertIn("commands:", text)

    def test_main_with_batch(self):
        buf = ctypes.c_uint32(0)
        addr = ctypes.addressof(buf)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "job.mk")
            with open(path, "w") as f:
                f.write("attach pid %d\n" % os.getpid())
                f.write("write u32 %#x 31337\n" % addr)
            out = io.StringIO()
            with redirect_stdout(out):
                code = main(["--batch", path])
        self.assertEqual(code, 0)
        self.assertEqual(buf.value, 31337)

    def test_main_batch_missing_file(self):
        err = io.StringIO()
        import sys
        old = sys.stderr
        sys.stderr = err
        try:
            code = main(["--batch", "/nonexistent/job.mk"])
        finally:
            sys.stderr = old
        self.assertEqual(code, 1)
        self.assertIn("batch file not found", err.getvalue())


if __name__ == "__main__":
    unittest.main()
