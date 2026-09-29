"""Tests for the ELF parser: a synthetic minimal ELF64 and ELF32 built in
memory, a big-endian header check, and a parse of the real /bin/true."""
import os
import struct
import unittest

from memkit.elf import ELFFormatError, parse, parse_file


def build_minimal_elf64():
    blob = bytearray(336)
    # ident
    blob[0:4] = b"\x7fELF"
    blob[4] = 2  # 64 bit
    blob[5] = 1  # little endian
    blob[6] = 1  # version
    # ehdr: type exec, x86-64, entry, phoff=64, shoff=144
    struct.pack_into("<HHIQQQIHHHHHH", blob, 16,
                     2, 62, 1, 0x400000, 64, 144, 0, 64, 56, 1, 64, 3, 2)
    # one load program header at 64
    struct.pack_into("<IIQQQQQQ", blob, 64,
                     1, 5, 0, 0x400000, 0, 0x1000, 0x1000, 0x1000)
    # shstrtab contents at 120
    shstr = b"\x00.text\x00.shstrtab\x00"
    blob[120:120 + len(shstr)] = shstr
    # section headers at 144: null, .text, .shstrtab
    struct.pack_into("<IIQQQQIIQQ", blob, 144,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    struct.pack_into("<IIQQQQIIQQ", blob, 208,
                     1, 1, 0x6, 0x401000, 0x200, 0x100, 0, 0, 16, 0)
    struct.pack_into("<IIQQQQIIQQ", blob, 272,
                     7, 3, 0, 0, 120, len(shstr), 0, 0, 1, 0)
    return bytes(blob)


def build_minimal_elf32(big_endian=False):
    endian = ">" if big_endian else "<"
    blob = bytearray(52)
    blob[0:4] = b"\x7fELF"
    blob[4] = 1  # 32 bit
    blob[5] = 2 if big_endian else 1
    blob[6] = 1
    struct.pack_into(endian + "HHIIIIIHHHHHH", blob, 16,
                     3, 3, 1, 0x8048000, 0, 0, 0, 52, 0, 0, 0, 0, 0)
    return bytes(blob)


class ELF64Test(unittest.TestCase):
    def setUp(self):
        self.elf = parse(build_minimal_elf64())

    def test_header(self):
        h = self.elf.header
        self.assertTrue(h.is_64)
        self.assertTrue(h.little_endian)
        self.assertEqual(h.type_name, "exec")
        self.assertEqual(h.machine_name, "x86-64")
        self.assertEqual(h.entry, 0x400000)
        self.assertEqual(self.elf.is_64bit, True)

    def test_program_headers(self):
        self.assertEqual(len(self.elf.program_headers), 1)
        ph = self.elf.program_headers[0]
        self.assertEqual(ph.type_name, "load")
        self.assertEqual(ph.vaddr, 0x400000)
        self.assertTrue(ph.readable)
        self.assertTrue(ph.executable)
        self.assertFalse(ph.writable)

    def test_section_names_resolved(self):
        self.assertEqual(len(self.elf.sections), 3)
        self.assertEqual(self.elf.sections[1].name, ".text")
        self.assertEqual(self.elf.sections[2].name, ".shstrtab")

    def test_section_lookup(self):
        text = self.elf.section(".text")
        self.assertIsNotNone(text)
        self.assertEqual(text.type_name, "progbits")
        self.assertIn("execinstr", text.flag_names)
        self.assertIsNone(self.elf.section(".nope"))
        self.assertIs(text, self.elf.section_at_address(0x401010))
        self.assertIsNone(self.elf.section_at_address(0x999999))

    def test_vaddr_to_offset(self):
        self.assertEqual(self.elf.vaddr_to_offset(0x400100), 0x100)

    def test_dynamic_empty(self):
        self.assertEqual(self.elf.dynamic, [])
        self.assertEqual(self.elf.needed_libraries(), [])

    def test_summary(self):
        text = self.elf.summary()
        self.assertIn("elf64", text)
        self.assertIn("x86-64", text)
        self.assertIn(".text", text)


class ELF32Test(unittest.TestCase):
    def test_little_endian_header(self):
        elf = parse(build_minimal_elf32())
        self.assertFalse(elf.is_64bit)
        self.assertTrue(elf.header.little_endian)
        self.assertEqual(elf.header.type_name, "dyn")
        self.assertEqual(elf.header.machine_name, "x86")
        self.assertEqual(elf.header.entry, 0x8048000)

    def test_big_endian_header(self):
        elf = parse(build_minimal_elf32(big_endian=True))
        self.assertFalse(elf.header.little_endian)
        self.assertEqual(elf.header.type_name, "dyn")
        self.assertEqual(elf.header.entry, 0x8048000)

    def test_bad_magic(self):
        with self.assertRaises(ELFFormatError):
            parse(b"NOPE" + b"\x00" * 60)

    def test_bad_class(self):
        blob = bytearray(build_minimal_elf32())
        blob[4] = 9
        with self.assertRaises(ELFFormatError):
            parse(bytes(blob))

    def test_truncated(self):
        with self.assertRaises(ELFFormatError):
            parse(b"\x7fELF\x02\x01")


@unittest.skipUnless(os.path.exists("/bin/true"), "needs /bin/true")
class RealBinaryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = parse_file("/bin/true")

    def test_real_header(self):
        self.assertTrue(self.elf.is_64bit)
        self.assertEqual(self.elf.header.machine_name, "x86-64")
        self.assertEqual(self.elf.header.type_name, "dyn")

    def test_real_sections(self):
        names = [s.name for s in self.elf.sections]
        self.assertIn(".text", names)
        self.assertIn(".dynsym", names)
        text = self.elf.section(".text")
        self.assertIn("execinstr", text.flag_names)

    def test_real_program_headers(self):
        kinds = [p.type_name for p in self.elf.program_headers]
        self.assertIn("load", kinds)
        self.assertIn("interp", kinds)

    def test_real_dynamic(self):
        needed = self.elf.needed_libraries()
        self.assertTrue(any("libc" in n for n in needed))

    def test_real_symbols(self):
        self.assertGreater(len(self.elf.symbols), 0)
        for sym in self.elf.symbols[:50]:
            self.assertIsInstance(sym.name, str)

    def test_real_notes_have_build_id(self):
        notes = self.elf.notes()
        self.assertTrue(any(n.name == "GNU" for n in notes))
        self.assertIsNotNone(self.elf.build_id)

    def test_real_relocations(self):
        relocs = self.elf.relocations()
        self.assertGreater(len(relocs), 0)
        for r in relocs[:20]:
            self.assertGreaterEqual(r.offset, 0)


if __name__ == "__main__":
    unittest.main()
