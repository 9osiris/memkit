"""Tests for the PE parser build a minimal synthetic PE blob in memory and
assert the headers, sections, imports and exports all parse correctly."""
import struct
import unittest

from memkit.pe import (
    PEFormatError,
    flag_names,
    parse,
)


def build_test_pe():
    # layout: dos header, nt headers, 2 sections, .text raw, .idata raw
    # holding one export and one import descriptor
    blob = bytearray(0x800)

    def put(offset, fmt, *values):
        struct.pack_into(fmt, blob, offset, *values)

    # dos header
    blob[0:2] = b"MZ"
    put(0x3C, "<I", 0x80)
    # pe signature + coff header
    blob[0x80:0x84] = b"PE\x00\x00"
    put(0x84, "<HHIIIHH", 0x14C, 2, 0x12345678, 0, 0, 0xE0, 0x010F)
    # optional header (pe32), 224 bytes at 0x98
    opt = 0x98
    put(opt, "<H", 0x10B)
    put(opt + 16, "<IIIIII", 0x1000, 0x1000, 0x2000, 0x400000, 0x1000, 0x200)
    put(opt + 56, "<IIHHH", 0x3000, 0x200, 0, 3, 0x8160)
    put(opt + 92, "<I", 16)
    # data directories: export at index 0, import at index 1
    put(opt + 96, "<II", 0x2000, 0x100)
    put(opt + 104, "<II", 0x2100, 0x40)
    # section headers at 0x178
    sec = 0x178
    blob[sec:sec + 8] = b".text\x00\x00\x00"
    put(sec + 8, "<IIIIIIHHI", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0,
        0x60000020)
    sec += 40
    blob[sec:sec + 8] = b".idata\x00\x00"
    put(sec + 8, "<IIIIIIHHI", 0x400, 0x2000, 0x400, 0x400, 0, 0, 0, 0,
        0xC0000040)

    # export directory at rva 0x2000 -> file offset 0x400
    exp = 0x400
    put(exp, "<IIHHIIIIIII", 0, 0, 0, 0, 0x2060, 1, 1, 1, 0x2028, 0x202C,
        0x2030)
    put(0x428, "<I", 0x1000)          # address of functions (points at .text)
    put(0x42C, "<I", 0x2070)          # address of names
    put(0x430, "<H", 0)               # ordinals
    blob[0x460:0x460 + 9] = b"test.dll\x00"
    put(0x470, "<H", 7)               # hint
    blob[0x472:0x472 + 7] = b"MyFunc\x00"

    # import descriptor at rva 0x2100 -> file offset 0x500
    imp = 0x500
    put(imp, "<IIIII", 0x2130, 0, 0, 0x2160, 0x2140)
    # import lookup table: named import then an ordinal-only import
    put(0x530, "<III", 0x2150, 0x80000005, 0)
    put(0x540, "<III", 0x2150, 0x80000005, 0)
    put(0x550, "<H", 0)
    blob[0x552:0x552 + 12] = b"ExitProcess\x00"
    blob[0x560:0x560 + 13] = b"KERNEL32.dll\x00"
    return bytes(blob)


TEST_PE = build_test_pe()


class PETest(unittest.TestCase):
    def setUp(self):
        self.pe = parse(TEST_PE)

    def test_dos_header(self):
        self.assertEqual(self.pe.dos.magic, b"MZ")
        self.assertEqual(self.pe.dos.lfanew, 0x80)

    def test_coff_header(self):
        self.assertEqual(self.pe.machine_name, "i386")
        self.assertEqual(self.pe.coff.num_sections, 2)
        self.assertEqual(self.pe.coff.timestamp, 0x12345678)
        self.assertIn("executable", self.pe.coff.characteristic_names)

    def test_optional_header(self):
        self.assertFalse(self.pe.is_64bit)
        self.assertEqual(self.pe.optional.entry_point, 0x1000)
        self.assertEqual(self.pe.optional.image_base, 0x400000)
        self.assertIn("nx_compat", self.pe.optional.dll_characteristic_names)

    def test_sections(self):
        self.assertEqual(len(self.pe.sections), 2)
        text, idata = self.pe.sections
        self.assertEqual(text.name, ".text")
        self.assertEqual(text.virtual_address, 0x1000)
        self.assertEqual(text.raw_ptr, 0x200)
        self.assertIn("executable", text.characteristic_names)
        self.assertIn("readable", text.characteristic_names)
        self.assertEqual(idata.name, ".idata")
        self.assertIn("writable", idata.characteristic_names)

    def test_rva_translation(self):
        self.assertEqual(self.pe.rva_to_file_offset(0x2000), 0x400)
        self.assertEqual(self.pe.rva_to_file_offset(0x2060), 0x460)
        self.assertEqual(self.pe.rva_to_file_offset(0x1000), 0x200)
        self.assertIsNone(self.pe.rva_to_file_offset(0x9000))
        self.assertIs(self.pe.section_at_rva(0x1000), self.pe.sections[0])
        self.assertIsNone(self.pe.section_at_rva(0x9000))

    def test_imports(self):
        imports = self.pe.imports
        self.assertEqual(len(imports), 1)
        dll = imports[0]
        self.assertEqual(dll.name, "KERNEL32.dll")
        self.assertEqual(len(dll.functions), 2)
        named, ordinal = dll.functions
        self.assertEqual(named.name, "ExitProcess")
        self.assertEqual(named.hint, 0)
        self.assertFalse(named.is_ordinal)
        self.assertTrue(ordinal.is_ordinal)
        self.assertEqual(ordinal.ordinal, 5)
        self.assertIsNone(ordinal.name)

    def test_exports(self):
        exports = self.pe.exports
        self.assertIsNotNone(exports)
        self.assertEqual(exports.dll_name, "test.dll")
        self.assertEqual(len(exports.functions), 1)
        func = exports.functions[0]
        self.assertEqual(func.name, "MyFunc")
        self.assertEqual(func.ordinal, 1)
        self.assertEqual(func.rva, 0x1000)
        self.assertIsNone(func.forwarder)
        self.assertIs(exports.by_name("MyFunc"), func)
        self.assertIs(exports.by_ordinal(1), func)
        self.assertIsNone(exports.by_name("Nope"))

    def test_summary_mentions_key_parts(self):
        text = self.pe.summary()
        self.assertIn("pe32", text)
        self.assertIn("i386", text)
        self.assertIn(".text", text)
        self.assertIn("KERNEL32.dll", text)
        self.assertIn("test.dll", text)

    def test_forwarder_detected(self):
        blob = bytearray(TEST_PE)
        # point the function rva back into the export directory: a forwarder
        struct.pack_into("<I", blob, 0x428, 0x2080)
        blob[0x480:0x480 + 12] = b"other.Func\x00"
        pe = parse(bytes(blob))
        func = pe.exports.functions[0]
        self.assertEqual(func.forwarder, "other.Func")

    def test_bad_magic_raises(self):
        bad = bytearray(TEST_PE)
        bad[0:2] = b"ZZ"
        with self.assertRaises(PEFormatError):
            parse(bytes(bad))

    def test_bad_pe_signature_raises(self):
        bad = bytearray(TEST_PE)
        bad[0x80:0x84] = b"XX\x00\x00"
        with self.assertRaises(PEFormatError):
            parse(bytes(bad))

    def test_truncated_raises(self):
        with self.assertRaises(PEFormatError):
            parse(b"MZ" + b"\x00" * 10)

    def test_flag_names_leftover(self):
        names = flag_names(0xFFFF, [(0x0001, "one")])
        self.assertIn("one", names)
        self.assertTrue(any(n.startswith("unknown_") for n in names))

    def test_no_import_directory_gives_empty(self):
        blob = bytearray(TEST_PE)
        struct.pack_into("<II", blob, 0x98 + 104, 0, 0)
        pe = parse(bytes(blob))
        self.assertEqual(pe.imports, [])

    def test_no_export_directory_gives_none(self):
        blob = bytearray(TEST_PE)
        struct.pack_into("<II", blob, 0x98 + 96, 0, 0)
        pe = parse(bytes(blob))
        self.assertIsNone(pe.exports)


if __name__ == "__main__":
    unittest.main()
