"""Parse PE files from raw bytes.

Covers the DOS header, NT headers (COFF + optional header for both
PE32 and PE32+), the section table, the import directory (DLL names and
imported function names, including ordinal-only imports) and the export
directory (names, ordinals, RVAs, forwarder detection).

Everything works on a plain bytes object, so it parses files from disk
or dumps pulled out of a target process with dump_region.
"""
import struct


class PEFormatError(ValueError):
    """Raised when the bytes do not look like a PE file."""


# image file machine types
MACHINE_TYPES = {
    0x0: "unknown",
    0x184: "alpha",
    0x284: "alpha64",
    0x1C0: "arm",
    0x1C4: "armv7",
    0xAA64: "arm64",
    0x1C2: "thumb2",
    0x14C: "i386",
    0x8664: "x86-64",
    0x162: "r3000",
    0x166: "r4000",
    0x168: "r10000",
    0x169: "wcemipsv2",
    0x266: "mips16",
    0x366: "mipsfpu",
    0x466: "mipsfpu16",
    0x1F0: "powerpc",
    0x1F1: "powerpcfp",
    0x1F2: "powerpc64",
    0x520: "sh3",
    0x521: "sh3dsp",
    0x523: "sh3e",
    0x524: "sh4",
    0x525: "sh5",
}

# coff header characteristics bits
COFF_CHARACTERISTICS = [
    (0x0001, "relocs_stripped"),
    (0x0002, "executable"),
    (0x0004, "line_numbers_stripped"),
    (0x0008, "local_symbols_stripped"),
    (0x0010, "aggressive_ws_trim"),
    (0x0020, "large_address_aware"),
    (0x0040, "reserved_0040"),
    (0x0080, "bytes_reversed_lo"),
    (0x0100, "32bit"),
    (0x0200, "debug_stripped"),
    (0x0400, "removable_run_from_swap"),
    (0x0800, "net_run_from_swap"),
    (0x1000, "system"),
    (0x2000, "dll"),
    (0x4000, "up_system_only"),
    (0x8000, "bytes_reversed_hi"),
]

# dll characteristics bits from the optional header
DLL_CHARACTERISTICS = [
    (0x0040, "dynamic_base"),
    (0x0080, "force_integrity"),
    (0x0100, "nx_compat"),
    (0x0200, "no_isolation"),
    (0x0400, "no_seh"),
    (0x0800, "no_bind"),
    (0x1000, "appcontainer"),
    (0x2000, "wdm_driver"),
    (0x4000, "guard_cf"),
    (0x8000, "terminal_server_aware"),
]

# section characteristics bits
SECTION_CHARACTERISTICS = [
    (0x00000008, "no_pad"),
    (0x00000020, "code"),
    (0x00000040, "initialized_data"),
    (0x00000080, "uninitialized_data"),
    (0x00000200, "no_defer_spec_exc"),
    (0x00001000, "gp_rel"),
    (0x01000000, "extended_relocs"),
    (0x02000000, "discardable"),
    (0x04000000, "no_cache"),
    (0x08000000, "pageable"),
    (0x10000000, "shared"),
    (0x20000000, "executable"),
    (0x40000000, "readable"),
    (0x80000000, "writable"),
]

# data directory indices in order
DIRECTORY_NAMES = [
    "export",
    "import",
    "resource",
    "exception",
    "security",
    "basereloc",
    "debug",
    "copyright",
    "globalptr",
    "tls",
    "loadconfig",
    "boundimport",
    "iat",
    "delayimport",
    "clr",
    "reserved",
]

IMAGE_ORDINAL_FLAG32 = 0x80000000
IMAGE_ORDINAL_FLAG64 = 0x8000000000000000


def flag_names(value, table):
    # decode a bitmask into a list of names, leftovers become hex
    names = [name for bit, name in table if value & bit]
    known = 0
    for bit, _ in table:
        known |= bit
    leftover = value & ~known
    if leftover:
        names.append("unknown_%#x" % leftover)
    return names


class DosHeader:
    """The 64 byte DOS stub header, only e_magic and e_lfanew matter."""

    SIZE = 64

    def __init__(self, magic, lfanew):
        self.magic = magic
        self.lfanew = lfanew

    @classmethod
    def parse(cls, data):
        if len(data) < cls.SIZE:
            raise PEFormatError("too short for a dos header")
        magic, lfanew = struct.unpack_from("<2s58xI", data, 0)
        if magic != b"MZ":
            raise PEFormatError("bad dos magic %r, want b'MZ'" % magic)
        return cls(magic, lfanew)

    def __repr__(self):
        return "DosHeader(lfanew=%#x)" % self.lfanew


class CoffHeader:
    """The 20 byte COFF file header after the PE signature."""

    SIZE = 20

    def __init__(self, machine, num_sections, timestamp, characteristics,
                 size_of_optional_header):
        self.machine = machine
        self.num_sections = num_sections
        self.timestamp = timestamp
        self.characteristics = characteristics
        self.size_of_optional_header = size_of_optional_header

    @classmethod
    def parse(cls, data, offset):
        if len(data) < offset + cls.SIZE:
            raise PEFormatError("too short for a coff header")
        (machine, num_sections, timestamp, _sym_ptr, _num_sym,
         size_of_optional_header, characteristics) = struct.unpack_from(
            "<HHIIIHH", data, offset)
        return cls(machine, num_sections, timestamp, characteristics,
                   size_of_optional_header)

    @property
    def machine_name(self):
        return MACHINE_TYPES.get(self.machine, "unknown_%#x" % self.machine)

    @property
    def characteristic_names(self):
        return flag_names(self.characteristics, COFF_CHARACTERISTICS)

    def __repr__(self):
        return "CoffHeader(machine=%s, sections=%d)" % (
            self.machine_name, self.num_sections)


class DataDirectory:
    def __init__(self, name, rva, size):
        self.name = name
        self.rva = rva
        self.size = size

    @property
    def present(self):
        return self.rva != 0 or self.size != 0

    def __repr__(self):
        return "DataDirectory(%s, rva=%#x, size=%#x)" % (
            self.name, self.rva, self.size)


class OptionalHeader:
    """Optional header, parsed for both PE32 (magic 0x10b) and PE32+ (0x20b)."""

    MAGIC_PE32 = 0x10B
    MAGIC_PE32_PLUS = 0x20B

    def __init__(self, magic, entry_point, image_base, section_alignment,
                 file_alignment, dll_characteristics, directories,
                 size_of_image, size_of_headers, subsystem):
        self.magic = magic
        self.entry_point = entry_point
        self.image_base = image_base
        self.section_alignment = section_alignment
        self.file_alignment = file_alignment
        self.dll_characteristics = dll_characteristics
        self.directories = directories
        self.size_of_image = size_of_image
        self.size_of_headers = size_of_headers
        self.subsystem = subsystem

    @classmethod
    def parse(cls, data, offset):
        if len(data) < offset + 2:
            raise PEFormatError("too short for an optional header")
        (magic,) = struct.unpack_from("<H", data, offset)
        if magic == cls.MAGIC_PE32:
            return cls._parse32(data, offset)
        if magic == cls.MAGIC_PE32_PLUS:
            return cls._parse64(data, offset)
        raise PEFormatError("bad optional header magic %#x" % magic)

    @classmethod
    def _directories(cls, data, offset, count):
        dirs = []
        for i in range(min(count, len(DIRECTORY_NAMES))):
            rva, size = struct.unpack_from("<II", data, offset + i * 8)
            name = DIRECTORY_NAMES[i]
            dirs.append(DataDirectory(name, rva, size))
        return dirs

    @classmethod
    def _parse32(cls, data, offset):
        # standard fields, then windows fields, then data directories at +96
        if len(data) < offset + 96:
            raise PEFormatError("too short for a pe32 optional header")
        (entry_point, _base_code, _base_data, image_base, section_alignment,
         file_alignment) = struct.unpack_from("<IIIIII", data, offset + 16)
        (size_of_image, size_of_headers, _checksum, subsystem,
         dll_characteristics) = struct.unpack_from("<IIHHH", data, offset + 56)
        (num_dirs,) = struct.unpack_from("<I", data, offset + 92)
        dirs = cls._directories(data, offset + 96, num_dirs)
        return cls(cls.MAGIC_PE32, entry_point, image_base, section_alignment,
                   file_alignment, dll_characteristics, dirs, size_of_image,
                   size_of_headers, subsystem)

    @classmethod
    def _parse64(cls, data, offset):
        if len(data) < offset + 112:
            raise PEFormatError("too short for a pe32+ optional header")
        (entry_point, _base_code, image_base, section_alignment,
         file_alignment) = struct.unpack_from("<IIQII", data, offset + 16)
        (size_of_image, size_of_headers, _checksum, subsystem,
         dll_characteristics) = struct.unpack_from("<IIHHH", data, offset + 56)
        (num_dirs,) = struct.unpack_from("<I", data, offset + 108)
        dirs = cls._directories(data, offset + 112, num_dirs)
        return cls(cls.MAGIC_PE32_PLUS, entry_point, image_base,
                   section_alignment, file_alignment, dll_characteristics,
                   dirs, size_of_image, size_of_headers, subsystem)

    @property
    def is_64bit(self):
        return self.magic == self.MAGIC_PE32_PLUS

    @property
    def dll_characteristic_names(self):
        return flag_names(self.dll_characteristics, DLL_CHARACTERISTICS)

    def directory(self, name):
        for d in self.directories:
            if d.name == name:
                return d
        return None

    def __repr__(self):
        bits = 64 if self.is_64bit else 32
        return "OptionalHeader(pe%d, entry=%#x, image_base=%#x)" % (
            bits, self.entry_point, self.image_base)


class Section:
    """One 40 byte section table entry."""

    SIZE = 40

    def __init__(self, name, virtual_size, virtual_address, raw_size,
                 raw_ptr, characteristics):
        self.name = name
        self.virtual_size = virtual_size
        self.virtual_address = virtual_address
        self.raw_size = raw_size
        self.raw_ptr = raw_ptr
        self.characteristics = characteristics

    @classmethod
    def parse(cls, data, offset):
        if len(data) < offset + cls.SIZE:
            raise PEFormatError("too short for a section header")
        (raw_name, virtual_size, virtual_address, raw_size, raw_ptr,
         _reloc_ptr, _line_ptr, _num_reloc, _num_line,
         characteristics) = struct.unpack_from("<8sIIIIIIHHI", data, offset)
        name = raw_name.split(b"\x00", 1)[0].decode(errors="replace")
        return cls(name, virtual_size, virtual_address, raw_size, raw_ptr,
                   characteristics)

    @property
    def characteristic_names(self):
        return flag_names(self.characteristics, SECTION_CHARACTERISTICS)

    def contains_rva(self, rva):
        span = max(self.virtual_size, self.raw_size)
        return self.virtual_address <= rva < self.virtual_address + span

    def __repr__(self):
        return "Section(%r, vaddr=%#x, raw=%#x+%#x)" % (
            self.name, self.virtual_address, self.raw_ptr, self.raw_size)


class ImportFunction:
    def __init__(self, name, hint, ordinal, is_ordinal):
        self.name = name
        self.hint = hint
        self.ordinal = ordinal
        self.is_ordinal = is_ordinal

    def __repr__(self):
        if self.is_ordinal:
            return "ImportFunction(ordinal %d)" % self.ordinal
        return "ImportFunction(%r, hint %d)" % (self.name, self.hint)


class ImportDll:
    def __init__(self, name, functions):
        self.name = name
        self.functions = functions

    def __repr__(self):
        return "ImportDll(%r, %d functions)" % (self.name, len(self.functions))


class ExportFunction:
    def __init__(self, name, ordinal, rva, forwarder):
        self.name = name
        self.ordinal = ordinal
        self.rva = rva
        self.forwarder = forwarder

    def __repr__(self):
        if self.name is not None:
            return "ExportFunction(%r, ordinal %d, rva %#x)" % (
                self.name, self.ordinal, self.rva)
        return "ExportFunction(ordinal %d, rva %#x)" % (self.ordinal, self.rva)


class ExportDirectory:
    def __init__(self, dll_name, functions):
        self.dll_name = dll_name
        self.functions = functions

    def by_name(self, name):
        for f in self.functions:
            if f.name == name:
                return f
        return None

    def by_ordinal(self, ordinal):
        for f in self.functions:
            if f.ordinal == ordinal:
                return f
        return None

    def __repr__(self):
        return "ExportDirectory(%r, %d functions)" % (
            self.dll_name, len(self.functions))


class PEFile:
    """A parsed PE file. Use parse() to build one from raw bytes."""

    def __init__(self, data, dos, coff, optional, sections):
        self._data = bytes(data)
        self.dos = dos
        self.coff = coff
        self.optional = optional
        self.sections = sections
        self._imports = None
        self._exports = None

    @classmethod
    def parse(cls, data):
        data = bytes(data)
        dos = DosHeader.parse(data)
        sig_off = dos.lfanew
        if len(data) < sig_off + 6:
            raise PEFormatError("too short for a pe signature")
        if data[sig_off:sig_off + 4] != b"PE\x00\x00":
            raise PEFormatError("bad pe signature")
        coff = CoffHeader.parse(data, sig_off + 4)
        opt_off = sig_off + 4 + CoffHeader.SIZE
        optional = OptionalHeader.parse(data, opt_off)
        sec_off = opt_off + coff.size_of_optional_header
        sections = []
        for i in range(coff.num_sections):
            sections.append(Section.parse(data, sec_off + i * Section.SIZE))
        return cls(data, dos, coff, optional, sections)

    # address translation helpers
    def section_at_rva(self, rva):
        for s in self.sections:
            if s.contains_rva(rva):
                return s
        return None

    def rva_to_file_offset(self, rva):
        section = self.section_at_rva(rva)
        if section is None:
            return None
        return section.raw_ptr + (rva - section.virtual_address)

    def read_rva(self, rva, size):
        off = self.rva_to_file_offset(rva)
        if off is None or off + size > len(self._data):
            raise PEFormatError("rva %#x out of range" % rva)
        return self._data[off:off + size]

    def read_cstring_at(self, file_offset, max_length=512):
        end = min(len(self._data), file_offset + max_length)
        raw = self._data[file_offset:end]
        return raw.split(b"\x00", 1)[0].decode(errors="replace")

    def read_cstring_rva(self, rva, max_length=512):
        off = self.rva_to_file_offset(rva)
        if off is None:
            raise PEFormatError("rva %#x out of range" % rva)
        return self.read_cstring_at(off, max_length)

    # imports
    @property
    def imports(self):
        if self._imports is None:
            self._imports = self._parse_imports()
        return self._imports

    def _parse_imports(self):
        directory = self.optional.directory("import")
        if directory is None or not directory.present:
            return []
        is64 = self.optional.is_64bit
        entry_size = 20
        dlls = []
        index = 0
        while True:
            raw = self.read_rva(directory.rva + index * entry_size, entry_size)
            (ilt_rva, _ts, _fwd, name_rva, iat_rva) = struct.unpack("<IIIII", raw)
            if ilt_rva == 0 and name_rva == 0 and iat_rva == 0:
                break
            dll_name = self.read_cstring_rva(name_rva)
            table_rva = ilt_rva or iat_rva
            functions = self._parse_thunk_table(table_rva, is64)
            dlls.append(ImportDll(dll_name, functions))
            index += 1
            if index > 4096:
                raise PEFormatError("import directory looks corrupt")
        return dlls

    def _parse_thunk_table(self, table_rva, is64):
        ordinal_flag = IMAGE_ORDINAL_FLAG64 if is64 else IMAGE_ORDINAL_FLAG32
        step = 8 if is64 else 4
        fmt = "<Q" if is64 else "<I"
        functions = []
        index = 0
        while True:
            (value,) = struct.unpack(fmt, self.read_rva(
                table_rva + index * step, step))
            if value == 0:
                break
            if value & ordinal_flag:
                functions.append(ImportFunction(
                    None, 0, value & 0xFFFF, True))
            else:
                hint_rva = value & 0x7FFFFFFF
                off = self.rva_to_file_offset(hint_rva)
                if off is None:
                    raise PEFormatError("bad hint/name rva %#x" % hint_rva)
                (hint,) = struct.unpack_from("<H", self._data, off)
                name = self.read_cstring_at(off + 2)
                functions.append(ImportFunction(name, hint, 0, False))
            index += 1
            if index > 65536:
                raise PEFormatError("thunk table looks corrupt")
        return functions

    # exports
    @property
    def exports(self):
        if self._exports is None:
            self._exports = self._parse_exports()
        return self._exports

    def _parse_exports(self):
        directory = self.optional.directory("export")
        if directory is None or not directory.present:
            return None
        raw = self.read_rva(directory.rva, 40)
        (_chars, _ts, _major, _minor, name_rva, base, num_functions,
         num_names, addr_functions, addr_names,
         addr_ordinals) = struct.unpack("<IIHHIIIIIII", raw)
        dll_name = self.read_cstring_rva(name_rva)
        func_rvas = struct.unpack("<%dI" % num_functions, self.read_rva(
            addr_functions, num_functions * 4))
        name_rvas = struct.unpack("<%dI" % num_names, self.read_rva(
            addr_names, num_names * 4))
        ord_indexes = struct.unpack("<%dH" % num_names, self.read_rva(
            addr_ordinals, num_names * 2))
        functions = []
        named = {}
        for i in range(num_names):
            # each entry is a hint/name pair, skip the 2 byte hint
            off = self.rva_to_file_offset(name_rvas[i])
            if off is None:
                raise PEFormatError("bad export name rva %#x" % name_rvas[i])
            name = self.read_cstring_at(off + 2)
            ordinal = base + ord_indexes[i]
            named[ord_indexes[i]] = name
        for i in range(num_functions):
            rva = func_rvas[i]
            forwarder = None
            # a function rva pointing back into the export directory is a forwarder
            if directory.rva <= rva < directory.rva + directory.size:
                forwarder = self.read_cstring_rva(rva)
            functions.append(ExportFunction(
                named.get(i), base + i, rva, forwarder))
        return ExportDirectory(dll_name, functions)

    # convenience
    @property
    def is_64bit(self):
        return self.optional.is_64bit

    @property
    def machine_name(self):
        return self.coff.machine_name

    def summary(self):
        lines = []
        bits = 64 if self.is_64bit else 32
        lines.append("pe%d %s" % (bits, self.machine_name))
        lines.append("entry point: %#x" % self.optional.entry_point)
        lines.append("image base: %#x" % self.optional.image_base)
        lines.append("sections: %d" % len(self.sections))
        for s in self.sections:
            lines.append("  %-8s vaddr=%#x vsize=%#x raw=%#x+%#x %s" % (
                s.name, s.virtual_address, s.virtual_size, s.raw_ptr,
                s.raw_size, ",".join(s.characteristic_names)))
        if self.imports:
            lines.append("imports: %d dlls" % len(self.imports))
            for dll in self.imports:
                lines.append("  %s (%d)" % (dll.name, len(dll.functions)))
        exports = self.exports
        if exports is not None:
            lines.append("exports: %s (%d)" % (
                exports.dll_name, len(exports.functions)))
        return "\n".join(lines)


def parse(data):
    """Parse raw PE bytes into a PEFile."""
    return PEFile.parse(data)


def parse_file(path):
    """Read a file from disk and parse it as a PE."""
    with open(path, "rb") as f:
        return PEFile.parse(f.read())
