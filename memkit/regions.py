"""List readable memory regions of a target process.

linux parses /proc/<pid>/maps.
windows walks VirtualQueryEx.
"""
from memkit.process import UnsupportedPlatformError, platform_name


class Region:
    def __init__(self, start, end, perms, name=""):
        self.start = start
        self.end = end
        self.perms = perms
        self.name = name

    @property
    def size(self):
        return self.end - self.start

    @property
    def readable(self):
        return "r" in self.perms

    @property
    def writable(self):
        return "w" in self.perms

    @property
    def executable(self):
        return "x" in self.perms

    def contains(self, address):
        return self.start <= address < self.end

    def __repr__(self):
        return "Region(%#x-%#x %s %s)" % (self.start, self.end, self.perms, self.name)


def list_regions(pid):
    plat = platform_name()
    if plat == "linux":
        return _linux_regions(pid)
    if plat == "windows":
        return _windows_regions(pid)
    raise UnsupportedPlatformError("region listing is not supported here")


def _linux_regions(pid):
    regions = []
    with open("/proc/%d/maps" % pid) as f:
        for line in f:
            parts = line.split()
            if len(parts) < 2:
                continue
            span, perms = parts[0], parts[1]
            try:
                start_s, end_s = span.split("-", 1)
                start, end = int(start_s, 16), int(end_s, 16)
            except ValueError:
                continue
            name = parts[5] if len(parts) > 5 else ""
            regions.append(Region(start, end, perms, name))
    return regions


def _protect_to_perms(protect):
    # windows page protection constants to an rwx string
    PAGE_NOACCESS = 0x01
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_WRITECOPY = 0x08
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80
    PAGE_GUARD = 0x100
    if protect & PAGE_GUARD or protect & PAGE_NOACCESS:
        return "---"
    perms = ""
    perms += "r" if protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                               PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                               PAGE_EXECUTE_WRITECOPY) else "-"
    perms += "w" if protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                               PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) else "-"
    perms += "x" if protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                               PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) else "-"
    return perms


def _windows_regions(pid):
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.windll.kernel32
    access = 0x0400  # query information only, no read needed
    handle = k32.OpenProcess(access, False, pid)
    if not handle:
        raise OSError("OpenProcess failed for pid %d" % pid)

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    MEM_COMMIT = 0x1000
    regions = []
    try:
        addr = 0
        mbi = MEMORY_BASIC_INFORMATION()
        while True:
            ret = k32.VirtualQueryEx(
                handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if not ret:
                break
            if mbi.State == MEM_COMMIT:
                base = mbi.BaseAddress
                regions.append(
                    Region(base, base + mbi.RegionSize, _protect_to_perms(mbi.Protect))
                )
            addr = mbi.BaseAddress + mbi.RegionSize
            if addr >= (1 << 47):
                break
    finally:
        k32.CloseHandle(handle)
    return regions
