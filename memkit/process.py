"""Attach to a process and read/write its memory.

linux goes through /proc/<pid>/mem with pread/pwrite.
windows uses ReadProcessMemory/WriteProcessMemory via ctypes.
macos raises UnsupportedPlatformError.
"""
import os
import struct
import sys

from memkit.types import POINTER_FMT, POINTER_SIZE, pack, unpack


class UnsupportedPlatformError(RuntimeError):
    pass


def platform_name():
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform.startswith("darwin"):
        return "macos"
    return "unknown"


def find_processes(name):
    # returns [(pid, label)] where the name matches, case-insensitive
    plat = platform_name()
    if plat == "linux":
        return _find_processes_linux(name)
    if plat == "windows":
        return _find_processes_windows(name)
    raise UnsupportedPlatformError("process search is not supported here")


def _find_processes_linux(name):
    needle = name.lower()
    found = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            with open("/proc/%d/comm" % pid) as f:
                comm = f.read().strip()
            with open("/proc/%d/cmdline" % pid, "rb") as f:
                cmd = f.read().replace(b"\x00", b" ").decode(errors="replace").strip()
        except OSError:
            continue
        label = cmd or comm
        if needle in comm.lower() or needle in label.lower():
            found.append((pid, comm))
    return found


def _find_processes_windows(name):
    import ctypes
    from ctypes import wintypes

    needle = name.lower()
    TH32CS_SNAPPROCESS = 0x2

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_ulonglong),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.CHAR * 260),
        ]

    k32 = ctypes.windll.kernel32
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == wintypes.HANDLE(-1).value:
        raise OSError("CreateToolhelp32Snapshot failed")
    found = []
    try:
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(entry)
        ok = k32.Process32First(snap, ctypes.byref(entry))
        while ok:
            exe = entry.szExeFile.decode(errors="replace")
            if needle in exe.lower():
                found.append((entry.th32ProcessID, exe))
            ok = k32.Process32Next(snap, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snap)
    return found


class Process:
    """Open handle to a target process for memory access."""

    def __init__(self, pid):
        self.pid = int(pid)
        self._plat = platform_name()
        if self._plat == "macos":
            raise UnsupportedPlatformError("macos is not supported by memkit")
        if self._plat == "unknown":
            raise UnsupportedPlatformError("unsupported platform: %s" % sys.platform)
        if self._plat == "linux":
            self._open_linux()
        else:
            self._open_windows()

    @classmethod
    def attach_pid(cls, pid):
        return cls(pid)

    @classmethod
    def attach_name(cls, name):
        matches = find_processes(name)
        if not matches:
            raise ProcessLookupError("no process matching %r" % name)
        if len(matches) > 1:
            descs = ", ".join("%d (%s)" % (pid, label) for pid, label in matches)
            raise ProcessLookupError("multiple processes match: %s" % descs)
        return cls(matches[0][0])

    # linux backend
    def _open_linux(self):
        self._fd = os.open("/proc/%d/mem" % self.pid, os.O_RDWR)

    def _read_linux(self, address, size):
        return os.pread(self._fd, size, address)

    def _write_linux(self, address, data):
        written = 0
        view = memoryview(data)
        while written < len(view):
            n = os.pwrite(self._fd, view[written:], address + written)
            if n == 0:
                raise OSError("short write at %#x" % address)
            written += n

    def _close_linux(self):
        os.close(self._fd)

    # windows backend
    def _open_windows(self):
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.windll.kernel32
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.OpenProcess.restype = wintypes.HANDLE
        access = 0x0010 | 0x0020 | 0x0008 | 0x0400  # vm read/write/operation + query
        handle = k32.OpenProcess(access, False, self.pid)
        if not handle:
            raise OSError("OpenProcess failed for pid %d" % self.pid)
        self._k32 = k32
        self._handle = handle

    def _read_windows(self, address, size):
        import ctypes

        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t(0)
        ok = self._k32.ReadProcessMemory(
            self._handle, ctypes.c_void_p(address), buf, size, ctypes.byref(got)
        )
        if not ok:
            raise OSError("ReadProcessMemory failed at %#x" % address)
        return buf.raw[: got.value]

    def _write_windows(self, address, data):
        import ctypes

        got = ctypes.c_size_t(0)
        ok = self._k32.WriteProcessMemory(
            self._handle, ctypes.c_void_p(address), bytes(data), len(data), ctypes.byref(got)
        )
        if not ok or got.value != len(data):
            raise OSError("WriteProcessMemory failed at %#x" % address)

    def _close_windows(self):
        self._k32.CloseHandle(self._handle)

    # public api
    def read(self, address, size):
        if address < 0 or size < 0:
            raise ValueError("address and size must be non-negative")
        if size == 0:
            return b""
        if self._plat == "linux":
            return self._read_linux(address, size)
        return self._read_windows(address, size)

    def write(self, address, data):
        data = bytes(data)
        if not data:
            return
        if self._plat == "linux":
            self._write_linux(address, data)
        else:
            self._write_windows(address, data)

    def read_value(self, type_name, address):
        from memkit.types import check_type

        _, size = check_type(type_name)
        return unpack(type_name, self.read(address, size))

    def write_value(self, type_name, address, value):
        self.write(address, pack(type_name, value))

    def read_pointer(self, address):
        return struct.unpack(POINTER_FMT, self.read(address, POINTER_SIZE))[0]

    def read_string(self, address, max_length=256):
        data = self.read(address, max_length)
        return data.split(b"\x00", 1)[0].decode(errors="replace")

    def write_string(self, address, text):
        self.write(address, text.encode() + b"\x00")

    def close(self):
        if self._plat == "linux":
            self._close_linux()
        else:
            self._close_windows()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
