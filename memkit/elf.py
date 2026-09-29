"""Parse ELF files from raw bytes.

Covers the ELF header (32 and 64 bit, little and big endian), program
headers, section headers with name resolution, symbol tables
(.symtab and .dynsym), relocations (.rel/.rela), the dynamic section
and note sections (including the GNU build id).

Works on a plain bytes object, so it parses files from disk or dumps
pulled out of a target process.
"""
import struct


class ELFFormatError(ValueError):
    """Raised when the bytes do not look like an ELF file."""


ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1
ELFDATA2MSB = 2

ET_TYPES = {
    0: "none",
    1: "rel",
    2: "exec",
    3: "dyn",
    4: "core",
}

EM_MACHINES = {
    2: "sparc",
    3: "x86",
    8: "mips",
    20: "ppc",
    21: "ppc64",
    22: "s390",
    40: "arm",
    42: "sh",
    50: "ia64",
    62: "x86-64",
    183: "aarch64",
    243: "riscv",
    224: "amdgpu",
    164: "hexagon",
}

PT_TYPES = {
    0: "null",
    1: "load",
    2: "dynamic",
    3: "interp",
    4: "note",
    5: "shlib",
    6: "phdr",
    7: "tls",
    0x6474E550: "gnu_eh_frame",
    0x6474E551: "gnu_stack",
    0x6474E552: "gnu_relro",
    0x6474E553: "gnu_property",
}

SH_TYPES = {
    0: "null",
    1: "progbits",
    2: "symtab",
    3: "strtab",
    4: "rela",
    5: "hash",
    6: "dynamic",
    7: "note",
    8: "nobits",
    9: "rel",
    10: "shlib",
    11: "dynsym",
    14: "init_array",
    15: "fini_array",
    16: "preinit_array",
    17: "group",
    18: "symtab_shndx",
    0x6FFFFFF6: "gnu_hash",
    0x6FFFFFF7: "gnu_liblist",
    0x6FFFFFFD: "gnu_verdef",
    0x6FFFFFFE: "gnu_verneed",
    0x6FFFFFFF: "gnu_versym",
}

SH_FLAGS = [
    (0x1, "write"),
    (0x2, "alloc"),
    (0x4, "execinstr"),
    (0x10, "merge"),
    (0x20, "strings"),
    (0x40, "info_link"),
    (0x80, "link_order"),
    (0x100, "os_nonconforming"),
    (0x200, "group"),
    (0x400, "tls"),
]

STB_BINDS = {
    0: "local",
    1: "global",
    2: "weak",
    10: "gnu_unique",
}

STT_TYPES = {
    0: "notype",
    1: "object",
    2: "func",
    3: "section",
    4: "file",
    5: "common",
    6: "tls",
    10: "gnu_ifunc",
}

DT_TAGS = {
    0: "null",
    1: "needed",
    2: "pltrelsz",
    3: "pltgot",
    4: "hash",
    5: "strtab",
    6: "symtab",
    7: "rela",
    8: "relasz",
    9: "relaent",
    10: "strsz",
    11: "syment",
    12: "init",
    13: "fini",
    14: "soname",
    15: "rpath",
    16: "symbolic",
    17: "rel",
    18: "relsz",
    19: "relent",
    20: "pltrel",
    21: "debug",
    22: "textrel",
    23: "jmprel",
    24: "bind_now",
    25: "init_array",
    26: "fini_array",
    27: "init_arraysz",
    28: "fini_arraysz",
    29: "runpath",
    30: "flags",
    32: "preinit_array",
    33: "preinit_arraysz",
    0x6FFFFDF5: "gnu_hash",
    0x6FFFFDF6: "tlsoffset",
    0x6FFFFFFA: "flags_1",
    0x6FFFFFFC: "verdef",
    0x6FFFFFFD: "verdefnum",
    0x6FFFFFFE: "verneed",
    0x6FFFFFFF: "versym",
}

NT_GNU_BUILD_ID = 3


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


class ElfHeader:
    """The ELF header. is_64 and little_endian describe the layout."""

    def __init__(self, is_64, little_endian, obj_type, machine, entry,
                 phoff, shoff, flags, phentsize, phnum, shentsize, shnum,
                 shstrndx):
        self.is_64 = is_64
        self.little_endian = little_endian
        self.obj_type = obj_type
        self.machine = machine
        self.entry = entry
        self.phoff = phoff
        self.shoff = shoff
        self.flags = flags
        self.phentsize = phentsize
        self.phnum = phnum
        self.shentsize = shentsize
        self.shnum = shnum
        self.shstrndx = shstrndx

    @classmethod
    def parse(cls, data):
        if len(data) < 52:
            raise ELFFormatError("too short for an elf header")
        if data[0:4] != b"\x7fELF":
            raise ELFFormatError("bad elf magic")
        ei_class = data[4]
        ei_data = data[5]
        if ei_class == ELFCLASS32:
            is_64 = False
        elif ei_class == ELFCLASS64:
            is_64 = True
        else:
            raise ELFFormatError("bad elf class %d" % ei_class)
        if is_64 and len(data) < 64:
            raise ELFFormatError("too short for an elf64 header")
        if ei_data == ELFDATA2LSB:
            little_endian = True
        elif ei_data == ELFDATA2MSB:
            little_endian = False
        else:
            raise ELFFormatError("bad elf data encoding %d" % ei_data)
        endian = "<" if little_endian else ">"
        if is_64:
            (obj_type, machine, _version, entry, phoff, shoff, flags,
             _ehsize, phentsize, phnum, shentsize, shnum,
             shstrndx) = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
        else:
            (obj_type, machine, _version, entry, phoff, shoff, flags,
             _ehsize, phentsize, phnum, shentsize, shnum,
             shstrndx) = struct.unpack_from(endian + "HHIIIIIHHHHHH", data, 16)
        return cls(is_64, little_endian, obj_type, machine, entry, phoff,
                   shoff, flags, phentsize, phnum, shentsize, shnum, shstrndx)

    @property
    def type_name(self):
        return ET_TYPES.get(self.obj_type, "unknown_%#x" % self.obj_type)

    @property
    def machine_name(self):
        return EM_MACHINES.get(self.machine, "unknown_%#x" % self.machine)

    def __repr__(self):
        bits = 64 if self.is_64 else 32
        return "ElfHeader(elf%d %s %s)" % (bits, self.type_name,
                                           self.machine_name)


class ProgramHeader:
    """One program header (segment)."""

    def __init__(self, seg_type, flags, offset, vaddr, filesz, memsz, align):
        self.seg_type = seg_type
        self.flags = flags
        self.offset = offset
        self.vaddr = vaddr
        self.filesz = filesz
        self.memsz = memsz
        self.align = align

    @classmethod
    def parse(cls, data, offset, is_64, endian):
        if is_64:
            (seg_type, flags, off, vaddr, _paddr, filesz, memsz,
             align) = struct.unpack_from(endian + "IIQQQQQQ", data, offset)
        else:
            (seg_type, off, vaddr, _paddr, filesz, memsz, flags,
             align) = struct.unpack_from(endian + "IIIIIIII", data, offset)
        return cls(seg_type, flags, off, vaddr, filesz, memsz, align)

    @property
    def type_name(self):
        return PT_TYPES.get(self.seg_type, "unknown_%#x" % self.seg_type)

    @property
    def readable(self):
        return bool(self.flags & 4)

    @property
    def writable(self):
        return bool(self.flags & 2)

    @property
    def executable(self):
        return bool(self.flags & 1)

    def __repr__(self):
        return "ProgramHeader(%s, vaddr=%#x, filesz=%#x)" % (
            self.type_name, self.vaddr, self.filesz)


class SectionHeader:
    """One section header. name is filled in after the string table loads."""

    def __init__(self, name_index, sec_type, flags, addr, offset, size,
                 link, info, align, entsize):
        self.name_index = name_index
        self.sec_type = sec_type
        self.flags = flags
        self.addr = addr
        self.offset = offset
        self.size = size
        self.link = link
        self.info = info
        self.align = align
        self.entsize = entsize
        self.name = ""

    @classmethod
    def parse(cls, data, offset, is_64, endian):
        if is_64:
            (name_index, sec_type, flags, addr, off, size, link, info,
             align, entsize) = struct.unpack_from(
                endian + "IIQQQQIIQQ", data, offset)
        else:
            (name_index, sec_type, flags, addr, off, size, link, info,
             align, entsize) = struct.unpack_from(
                endian + "IIIIIIIIII", data, offset)
        return cls(name_index, sec_type, flags, addr, off, size, link, info,
                   align, entsize)

    @property
    def type_name(self):
        return SH_TYPES.get(self.sec_type, "unknown_%#x" % self.sec_type)

    @property
    def flag_names(self):
        return flag_names(self.flags, SH_FLAGS)

    def __repr__(self):
        return "SectionHeader(%r, %s, size=%#x)" % (
            self.name, self.type_name, self.size)


class Symbol:
    """One symbol table entry. name is filled in from the linked strtab."""

    def __init__(self, name_index, value, size, bind, sym_type, shndx):
        self.name_index = name_index
        self.value = value
        self.size = size
        self.bind = bind
        self.sym_type = sym_type
        self.shndx = shndx
        self.name = ""

    @classmethod
    def parse(cls, data, offset, is_64, endian):
        if is_64:
            (name_index, info, _other, shndx, value,
             size) = struct.unpack_from(endian + "IBBHQQ", data, offset)
        else:
            (name_index, value, size, info, _other,
             shndx) = struct.unpack_from(endian + "IIIBBH", data, offset)
        return cls(name_index, value, size, info >> 4, info & 0xF, shndx)

    @property
    def bind_name(self):
        return STB_BINDS.get(self.bind, "unknown_%d" % self.bind)

    @property
    def type_name(self):
        return STT_TYPES.get(self.sym_type, "unknown_%d" % self.sym_type)

    def __repr__(self):
        return "Symbol(%r, %s %s, value=%#x)" % (
            self.name, self.bind_name, self.type_name, self.value)


class DynamicEntry:
    """One dynamic section entry. str_value is resolved for string tags."""

    STRING_TAGS = {"needed", "soname", "rpath", "runpath"}

    def __init__(self, tag, value):
        self.tag = tag
        self.value = value
        self.str_value = None

    @classmethod
    def parse(cls, data, offset, is_64, endian):
        if is_64:
            tag, value = struct.unpack_from(endian + "QQ", data, offset)
        else:
            tag, value = struct.unpack_from(endian + "II", data, offset)
        return cls(tag, value)

    @property
    def tag_name(self):
        return DT_TAGS.get(self.tag, "unknown_%#x" % self.tag)

    def __repr__(self):
        if self.str_value is not None:
            return "DynamicEntry(%s, %r)" % (self.tag_name, self.str_value)
        return "DynamicEntry(%s, %#x)" % (self.tag_name, self.value)


class Relocation:
    """One .rel/.rela entry."""

    def __init__(self, offset, sym_index, rel_type, addend):
        self.offset = offset
        self.sym_index = sym_index
        self.rel_type = rel_type
        self.addend = addend

    @classmethod
    def parse(cls, data, offset, is_64, endian, with_addend):
        if is_64:
            addr, info = struct.unpack_from(endian + "QQ", data, offset)
            sym_index, rel_type = info >> 32, info & 0xFFFFFFFF
            size = 16
        else:
            addr, info = struct.unpack_from(endian + "II", data, offset)
            sym_index, rel_type = info >> 8, info & 0xFF
            size = 8
        addend = 0
        if with_addend:
            (addend,) = struct.unpack_from(
                endian + ("Q" if is_64 else "I"), data, offset + size)
            size += 8 if is_64 else 4
        return cls(addr, sym_index, rel_type, addend), size

    def __repr__(self):
        return "Relocation(offset=%#x, sym=%d, type=%d, addend=%d)" % (
            self.offset, self.sym_index, self.rel_type, self.addend)


class Note:
    """One note section entry."""

    def __init__(self, name, note_type, desc):
        self.name = name
        self.note_type = note_type
        self.desc = desc

    def __repr__(self):
        return "Note(%r, type=%d, %d bytes)" % (
            self.name, self.note_type, len(self.desc))


class ELFFile:
    """A parsed ELF file. Use parse() to build one from raw bytes."""

    def __init__(self, data, header, program_headers, sections):
        self._data = bytes(data)
        self.header = header
        self.program_headers = program_headers
        self.sections = sections
        self._symbols = None
        self._dynamic = None

    @classmethod
    def parse(cls, data):
        data = bytes(data)
        header = ElfHeader.parse(data)
        endian = "<" if header.little_endian else ">"
        program_headers = []
        for i in range(header.phnum):
            off = header.phoff + i * header.phentsize
            program_headers.append(ProgramHeader.parse(
                data, off, header.is_64, endian))
        sections = []
        for i in range(header.shnum):
            off = header.shoff + i * header.shentsize
            sections.append(SectionHeader.parse(
                data, off, header.is_64, endian))
        elf = cls(data, header, program_headers, sections)
        elf._resolve_section_names()
        return elf

    # raw access
    def read_at(self, offset, size):
        if offset < 0 or offset + size > len(self._data):
            raise ELFFormatError("offset %#x out of range" % offset)
        return self._data[offset:offset + size]

    def read_cstring_at(self, offset, max_length=512):
        raw = self.read_at(offset, min(max_length, len(self._data) - offset))
        return raw.split(b"\x00", 1)[0].decode(errors="replace")

    # sections
    def _resolve_section_names(self):
        if not self.sections or self.header.shstrndx >= len(self.sections):
            return
        strtab = self.sections[self.header.shstrndx]
        for s in self.sections:
            try:
                raw = self.read_at(strtab.offset + s.name_index, 128)
            except ELFFormatError:
                s.name = ""
                continue
            s.name = raw.split(b"\x00", 1)[0].decode(errors="replace")

    def section(self, name):
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def section_at_address(self, addr):
        for s in self.sections:
            if s.addr and s.addr <= addr < s.addr + s.size:
                return s
        return None

    def section_data(self, section):
        if section.sec_type == 8:  # nobits, like .bss: no bytes in the file
            return b"\x00" * section.size
        return self.read_at(section.offset, section.size)

    # symbols
    @property
    def symbols(self):
        # symbols from every symtab and dynsym section, in file order
        if self._symbols is None:
            self._symbols = self._parse_symbols()
        return self._symbols

    def _parse_symbols(self):
        endian = "<" if self.header.little_endian else ">"
        is_64 = self.header.is_64
        found = []
        for sec in self.sections:
            if sec.sec_type not in (2, 11):  # symtab, dynsym
                continue
            if sec.link >= len(self.sections):
                continue
            strtab = self.sections[sec.link]
            entry_size = 24 if is_64 else 16
            count = sec.size // entry_size if entry_size else 0
            for i in range(count):
                off = sec.offset + i * entry_size
                try:
                    sym = Symbol.parse(self._data, off, is_64, endian)
                except struct.error:
                    break
                try:
                    raw = self.read_at(strtab.offset + sym.name_index, 256)
                except ELFFormatError:
                    raw = b""
                sym.name = raw.split(b"\x00", 1)[0].decode(errors="replace")
                found.append(sym)
        return found

    def symbol(self, name):
        for sym in self.symbols:
            if sym.name == name:
                return sym
        return None

    # dynamic section
    @property
    def dynamic(self):
        if self._dynamic is None:
            self._dynamic = self._parse_dynamic()
        return self._dynamic

    def _parse_dynamic(self):
        section = self.section_by_type(6)  # dynamic
        if section is None:
            # fall back to the pt_dynamic segment
            for ph in self.program_headers:
                if ph.seg_type == 2:
                    return self._parse_dynamic_at(ph.offset)
            return []
        return self._parse_dynamic_at(section.offset)

    def _parse_dynamic_at(self, offset):
        endian = "<" if self.header.little_endian else ">"
        is_64 = self.header.is_64
        entry_size = 16 if is_64 else 8
        entries = []
        strtab_addr = None
        index = 0
        while True:
            entry = DynamicEntry.parse(
                self._data, offset + index * entry_size, is_64, endian)
            entries.append(entry)
            if entry.tag_name == "strtab":
                strtab_addr = entry.value
            if entry.tag == 0:
                break
            index += 1
            if index > 4096:
                raise ELFFormatError("dynamic section looks corrupt")
        if strtab_addr is not None:
            strtab_off = self.vaddr_to_offset(strtab_addr)
            for entry in entries:
                if entry.tag_name in DynamicEntry.STRING_TAGS:
                    if strtab_off is not None:
                        entry.str_value = self.read_cstring_at(
                            strtab_off + entry.value)
        return entries

    def section_by_type(self, sec_type):
        for s in self.sections:
            if s.sec_type == sec_type:
                return s
        return None

    def vaddr_to_offset(self, vaddr):
        # translate a virtual address through the load segments
        for ph in self.program_headers:
            if ph.seg_type != 1:  # load
                continue
            if ph.vaddr <= vaddr < ph.vaddr + ph.filesz:
                return ph.offset + (vaddr - ph.vaddr)
        section = self.section_at_address(vaddr)
        if section is not None and section.addr:
            return section.offset + (vaddr - section.addr)
        return None

    def needed_libraries(self):
        return [e.str_value for e in self.dynamic
                if e.tag_name == "needed" and e.str_value]

    @property
    def soname(self):
        for e in self.dynamic:
            if e.tag_name == "soname":
                return e.str_value
        return None

    # relocations
    def relocations(self, section_name=None):
        # all relocations, or only from one named .rel/.rela section
        endian = "<" if self.header.little_endian else ">"
        is_64 = self.header.is_64
        found = []
        for sec in self.sections:
            if sec.sec_type not in (4, 9):  # rela, rel
                continue
            if section_name is not None and sec.name != section_name:
                continue
            with_addend = sec.sec_type == 4
            off = sec.offset
            end = sec.offset + sec.size
            while off < end:
                reloc, size = Relocation.parse(
                    self._data, off, is_64, endian, with_addend)
                found.append(reloc)
                off += size
        return found

    # notes
    def notes(self, section_name=None):
        endian = "<" if self.header.little_endian else ">"
        found = []
        for sec in self.sections:
            if sec.sec_type != 7:  # note
                continue
            if section_name is not None and sec.name != section_name:
                continue
            data = self.section_data(sec)
            off = 0
            while off + 12 <= len(data):
                namesz, descsz, note_type = struct.unpack_from(
                    endian + "III", data, off)
                off += 12
                name = data[off:off + namesz].split(b"\x00", 1)[0].decode(
                    errors="replace")
                off += (namesz + 3) & ~3
                desc = data[off:off + descsz]
                off += (descsz + 3) & ~3
                found.append(Note(name, note_type, desc))
        return found

    @property
    def build_id(self):
        for note in self.notes():
            if note.name == "GNU" and note.note_type == NT_GNU_BUILD_ID:
                return note.desc.hex()
        return None

    # convenience
    @property
    def is_64bit(self):
        return self.header.is_64

    def summary(self):
        lines = []
        bits = 64 if self.header.is_64 else 32
        lines.append("elf%d %s %s" % (
            bits, self.header.type_name, self.header.machine_name))
        lines.append("entry: %#x" % self.header.entry)
        lines.append("program headers: %d" % len(self.program_headers))
        for ph in self.program_headers:
            lines.append("  %-12s vaddr=%#x filesz=%#x" % (
                ph.type_name, ph.vaddr, ph.filesz))
        lines.append("sections: %d" % len(self.sections))
        for s in self.sections:
            lines.append("  %-20s %-10s size=%#x" % (
                s.name, s.type_name, s.size))
        needed = self.needed_libraries()
        if needed:
            lines.append("needed: %s" % ", ".join(needed))
        build_id = self.build_id
        if build_id:
            lines.append("build id: %s" % build_id)
        return "\n".join(lines)


def parse(data):
    """Parse raw ELF bytes into an ELFFile."""
    return ELFFile.parse(data)


def parse_file(path):
    """Read a file from disk and parse it as an ELF."""
    with open(path, "rb") as f:
        return ELFFile.parse(f.read())
