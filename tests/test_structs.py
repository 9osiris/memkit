"""Tests for the struct dissector: dsl layout, c parsing, pack/unpack,
rendering, and live pointer dereferencing in the tool's own process."""
import ctypes
import os
import unittest

from memkit.process import Process
from memkit.structs import (
    Array,
    BitField,
    Char,
    CString,
    Enum,
    Field,
    Pointer,
    Primitive,
    Ptr,
    Struct,
    StructError,
    Union,
    WChar,
    WString,
    dissect,
    lookup,
    parse_c,
    render,
    resolve_spec,
    values,
)
from memkit.types import pack as pack_type
from memkit.types import unpack as unpack_type


class Vec3(Struct):
    x = "f32"
    y = "f32"
    z = "f32"


class LayoutTest(unittest.TestCase):
    def test_primitive_offsets_and_padding(self):
        s = Struct("TLayout1", [("a", "u8"), ("b", "u32"), ("c", "u16")])
        self.assertEqual(s.field("a").offset, 0)
        self.assertEqual(s.field("b").offset, 4)
        self.assertEqual(s.field("c").offset, 8)
        self.assertEqual(s.size, 12)

    def test_trailing_padding(self):
        s = Struct("TLayout2", [("a", "u32"), ("b", "u8")])
        self.assertEqual(s.size, 8)

    def test_class_dsl(self):
        v = Vec3()
        self.assertEqual([f.name for f in v.fields], ["x", "y", "z"])
        self.assertEqual(v.size, 12)
        self.assertEqual(v.field("z").offset, 8)

    def test_nested_struct(self):
        s = Struct("TLayout3", [("id", "u32"), ("pos", Vec3())])
        self.assertEqual(s.field("pos").offset, 4)
        self.assertEqual(s.size, 16)

    def test_array_in_struct(self):
        s = Struct("TLayout4", [("vals", Array("u16", 4)), ("tag", "u8")])
        self.assertEqual(s.field("vals").offset, 0)
        self.assertEqual(s.field("tag").offset, 8)
        self.assertEqual(s.size, 10)

    def test_string_shorthand(self):
        self.assertIsInstance(resolve_spec("u32[4]"), Array)
        self.assertIsInstance(resolve_spec("u8*"), Pointer)
        self.assertIsInstance(resolve_spec("char"), Char)
        self.assertEqual(resolve_spec("u8*").target_name, "u8")

    def test_pack_alignment(self):
        plain = Struct("TLayout5a", [("a", "u8"), ("b", "u32")])
        packed = Struct("TLayout5b", [("a", "u8"), ("b", "u32")], pack=1)
        self.assertEqual(plain.size, 8)
        self.assertEqual(packed.size, 5)
        self.assertEqual(packed.field("b").offset, 1)

    def test_union_overlaps(self):
        u = Union("TUnion1", [("i", "u32"), ("f", "f32")])
        self.assertEqual(u.field("i").offset, 0)
        self.assertEqual(u.field("f").offset, 0)
        self.assertEqual(u.size, 4)

    def test_unknown_type_raises(self):
        with self.assertRaises(StructError):
            Struct("TBad1", [("x", "u33")])
        with self.assertRaises(StructError):
            lookup("no_such_type_xyz")

    def test_field_lookup_raises(self):
        s = Struct("TLayout6", [("a", "u8")])
        with self.assertRaises(StructError):
            s.field("zzz")


class PackTest(unittest.TestCase):
    def setUp(self):
        self.player = Struct("TPackPlayer", [
            ("health", "u32"),
            ("name", "char[16]"),
            ("pos", Vec3()),
            ("flags", BitField("u32", [("alive", 0, 1), ("team", 1, 2)])),
        ])

    def test_pack_unpack_roundtrip(self):
        blob = self.player.pack({
            "health": 100,
            "name": "Osiris",
            "pos": {"x": 1.5, "y": 2.5, "z": 3.5},
            "flags": {"alive": 1, "team": 2},
        })
        self.assertEqual(len(blob), self.player.size)
        vals = values(blob, self.player)
        self.assertEqual(vals["health"], 100)
        self.assertEqual(vals["name"], b"Osiris")
        self.assertAlmostEqual(vals["pos"]["x"], 1.5)
        self.assertEqual(vals["flags"], {"alive": 1, "team": 2})

    def test_char_array_truncates_at_nul(self):
        blob = self.player.pack({"name": "ab"})
        vals = values(blob, self.player)
        self.assertEqual(vals["name"], b"ab")

    def test_char_array_too_long_raises(self):
        with self.assertRaises(StructError):
            self.player.pack({"name": "x" * 17})

    def test_bitfield_too_wide_raises(self):
        with self.assertRaises(StructError):
            self.player.pack({"flags": {"alive": 1, "team": 9}})


class StringTypesTest(unittest.TestCase):
    def test_dsl_shorthands(self):
        self.assertIsInstance(resolve_spec("cstring"), CString)
        self.assertIsInstance(resolve_spec("wstring"), WString)
        self.assertIsInstance(resolve_spec("wchar_t"), WChar)
        self.assertIsInstance(resolve_spec("char16_t"), WChar)
        self.assertIsInstance(resolve_spec("f16"), Primitive)

    def test_f16_roundtrip(self):
        self.assertEqual(unpack_type("f16", pack_type("f16", 1.5)), 1.5)
        s = Struct("TF16", [("h", "f16")])
        blob = s.pack({"h": 1.5})
        self.assertEqual(len(blob), 2)
        self.assertAlmostEqual(values(blob, s)["h"], 1.5)
        blob = s.pack({"h": 0.1})
        self.assertAlmostEqual(values(blob, s)["h"], 0.1, places=2)

    def test_cstring_follows_pointer_in_blob(self):
        s = Struct("TCStr", [("name", "cstring"), ("id", "u32")])
        text = b"hello\x00"
        blob = s.pack({"name": s.size, "id": 7}) + text
        vals = values(blob, s)
        self.assertEqual(vals["name"], "hello")
        self.assertEqual(vals["id"], 7)
        self.assertIn("name: cstring = 'hello'", render(blob, s))

    def test_cstring_null_renders_null(self):
        s = Struct("TCStrNull", [("name", "cstring")])
        blob = s.pack({"name": 0})
        self.assertIsNone(values(blob, s)["name"])
        self.assertIn("name: cstring = null", render(blob, s))

    def test_cstring_unterminated_raises(self):
        s = Struct("TCStrBad", [("name", "cstring")])
        blob = s.pack({"name": s.size}) + b"no nul here"
        with self.assertRaises(StructError):
            values(blob, s)

    def test_wstring_follows_pointer_in_blob(self):
        s = Struct("TWStr", [("tag", "wstring")])
        text = "hi".encode("utf-16-le") + b"\x00\x00"
        blob = s.pack({"tag": s.size}) + text
        self.assertEqual(values(blob, s)["tag"], "hi")
        self.assertIn("tag: wstring = 'hi'", render(blob, s))

    def test_wstring_null_renders_null(self):
        s = Struct("TWStrNull", [("tag", "wstring")])
        blob = s.pack({"tag": 0})
        self.assertIsNone(values(blob, s)["tag"])
        self.assertIn("tag: wstring = null", render(blob, s))

    def test_wchar_single_char(self):
        s = Struct("TWChar", [("c", "wchar_t")])
        blob = s.pack({"c": "z"})
        vals = values(blob, s)
        self.assertEqual(vals["c"], ord("z"))
        self.assertIn("c: wchar_t = 122 ('z')", render(blob, s))
        with self.assertRaises(StructError):
            s.pack({"c": "zz"})

    def test_cstring_array_of_pointers(self):
        s = Struct("TCStrArr", [("names", Array("cstring", 2))])
        first = b"one\x00"
        second = b"two\x00"
        base = s.size
        blob = s.pack({"names": [base, base + len(first)]}) + first + second
        self.assertEqual(values(blob, s)["names"], ["one", "two"])


class RenderTest(unittest.TestCase):
    def setUp(self):
        self.player = Struct("TRenderPlayer", [
            ("health", "u32"),
            ("name", "char[16]"),
            ("pos", Vec3()),
            ("flags", BitField("u32", [("alive", 0, 1), ("team", 1, 2)])),
            ("state", Enum("u32", {"idle": 0, "run": 1}, "TState")),
            ("next", Ptr("TRenderPlayer")),
        ])
        self.blob = self.player.pack({
            "health": 100,
            "name": "Osiris",
            "pos": {"x": 1.5, "y": 2.5, "z": -0.5},
            "flags": {"alive": 1, "team": 2},
            "state": "run",
            "next": 0,
        })

    def test_render_header(self):
        lines = dissect(self.blob, self.player, 0x1000)
        self.assertTrue(lines[0].startswith("TRenderPlayer @ 0x1000"))

    def test_render_primitives(self):
        text = render(self.blob, self.player)
        self.assertIn("health: u32 = 100 (0x64)", text)
        self.assertIn("name: char[16] = 'Osiris'", text)

    def test_render_nested(self):
        text = render(self.blob, self.player)
        self.assertIn("pos: Vec3 @ 0x14 (12 bytes)", text)
        self.assertIn("x: f32 = 1.5", text)

    def test_render_bitfield(self):
        text = render(self.blob, self.player)
        self.assertIn("flags: bits<u32> = 0x5 <alive, team=2>", text)

    def test_render_enum_known(self):
        text = render(self.blob, self.player)
        self.assertIn("state: TState = run (1)", text)

    def test_render_enum_unknown_value(self):
        blob = self.player.pack({"state": 99})
        text = render(blob, self.player)
        self.assertIn("99 (0x63)", text)

    def test_render_null_pointer(self):
        text = render(self.blob, self.player)
        self.assertIn("next: TRenderPlayer* = 0x0", text)

    def test_render_by_name(self):
        text = render(self.blob, "TRenderPlayer")
        self.assertIn("health", text)

    def test_render_bad_spec_raises(self):
        with self.assertRaises(StructError):
            render(self.blob, "u32")


class LiveDerefTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proc = Process.attach_pid(os.getpid())

    @classmethod
    def tearDownClass(cls):
        cls.proc.close()

    def test_pointer_deref_renders_target(self):
        class Node(ctypes.Structure):
            _fields_ = [("value", ctypes.c_uint32),
                        ("next", ctypes.c_void_p)]

        parse_c("struct TDerefNode { uint32_t value; struct TDerefNode *next; };")
        n2 = Node(200, 0)
        n1 = Node(100, ctypes.addressof(n2))
        text = render(self.proc, "TDerefNode", ctypes.addressof(n1))
        self.assertIn("value: u32 = 100", text)
        self.assertIn("value: u32 = 200", text)
        # keep the ctypes objects alive for the whole render
        self.assertTrue(n1.value == 100 and n2.value == 200)

    def test_dangling_pointer_shows_unreadable(self):
        parse_c("struct TDeref2 { uint32_t v; struct TDeref2 *next; };")
        node = (ctypes.c_uint32 * 2)(10, 0xFFFFFFFF)
        ctypes.cast(node, ctypes.POINTER(ctypes.c_void_p))[1] = 0x1
        text = render(self.proc, "TDeref2", ctypes.addressof(node),
                      max_depth=3)
        self.assertIn("<unreadable>", text)

    def test_cstring_live_process(self):
        text_buf = ctypes.create_string_buffer(b"live string\x00")

        class Holder(ctypes.Structure):
            _fields_ = [("name", ctypes.c_void_p)]

        holder = Holder(ctypes.addressof(text_buf))
        parse_c("struct TLiveStr { char *name; };")
        out = render(self.proc, "TLiveStr", ctypes.addressof(holder))
        self.assertIn("name: cstring = 'live string'", out)
        self.assertTrue(holder.name and text_buf.value == b"live string")

    def test_wstring_live_process(self):
        # hand-built utf-16le buffer: ctypes unicode buffers are utf-32
        # on linux, so a real wchar_t* would not read right here
        text_buf = ctypes.create_string_buffer(
            "wide hi".encode("utf-16-le") + b"\x00\x00")

        class Holder(ctypes.Structure):
            _fields_ = [("tag", ctypes.c_void_p)]

        holder = Holder(ctypes.addressof(text_buf))
        parse_c("struct TLiveWStr { wchar_t *tag; };")
        out = render(self.proc, "TLiveWStr", ctypes.addressof(holder))
        self.assertIn("tag: wstring = 'wide hi'", out)
        self.assertTrue(holder.tag and text_buf.raw.startswith(b"w\x00i\x00"))


class ParseCTest(unittest.TestCase):
    def test_basic_struct(self):
        defs = parse_c("""
            struct TBasic {
                uint32_t health;
                int16_t armor;
                float speed;
                char name[16];
            };
        """)
        s = defs["TBasic"]
        self.assertEqual(s.field("health").offset, 0)
        self.assertEqual(s.field("armor").offset, 4)
        self.assertEqual(s.field("speed").offset, 8)
        self.assertEqual(s.field("name").offset, 12)
        self.assertEqual(s.size, 28)

    def test_bitfields_pack_together(self):
        defs = parse_c("""
            struct TBits {
                unsigned alive : 1;
                unsigned team : 2;
                unsigned reserved : 5;
                uint32_t other;
            };
        """)
        s = defs["TBits"]
        self.assertEqual(s.field("alive").offset, 0)
        self.assertEqual(s.field("other").offset, 4)
        blob = s.pack({"alive": {"alive": 1, "team": 2, "reserved": 0},
                       "other": 9})
        vals = values(blob, s)
        self.assertEqual(vals["alive"]["team"], 2)

    def test_self_referential_pointer(self):
        defs = parse_c("""
            struct TSelf {
                int value;
                struct TSelf *next;
            };
        """)
        s = defs["TSelf"]
        self.assertIsInstance(s.field("next").spec, Pointer)
        self.assertEqual(s.field("next").spec.target_name, "TSelf")

    def test_nested_struct_reference(self):
        defs = parse_c("""
            struct TInner { int x; int y; };
            struct TOuter { int id; struct TInner pos; };
        """)
        outer = defs["TOuter"]
        self.assertEqual(outer.field("pos").offset, 4)
        self.assertIsInstance(outer.field("pos").spec, Struct)

    def test_typedef_struct(self):
        defs = parse_c("""
            typedef struct {
                uint32_t a;
                uint32_t b;
            } TPair;
        """)
        self.assertEqual(defs["TPair"].size, 8)

    def test_typedef_alias(self):
        defs = parse_c("typedef unsigned int TMyUint;")
        s = Struct("TUseAlias", [("x", "TMyUint")])
        self.assertEqual(s.field("x").spec.size, 4)

    def test_enum(self):
        defs = parse_c("enum TColor { RED, GREEN = 5, BLUE };")
        enum = defs["TColor"]
        self.assertEqual(enum.mapping, {"RED": 0, "GREEN": 5, "BLUE": 6})

    def test_typedef_enum(self):
        defs = parse_c("typedef enum { TA, TB } TMyEnum;")
        self.assertEqual(defs["TMyEnum"].mapping["TB"], 1)

    def test_union(self):
        defs = parse_c("union TU { uint32_t i; float f; };")
        u = defs["TU"]
        self.assertEqual(u.field("i").offset, 0)
        self.assertEqual(u.field("f").offset, 0)

    def test_comments_ignored(self):
        defs = parse_c("""
            // a line comment
            struct TComment { /* block */ uint32_t x; /* trailing */ };
        """)
        self.assertEqual(defs["TComment"].size, 4)

    def test_multiword_types(self):
        defs = parse_c("""
            struct TWords {
                unsigned long a;
                long long b;
                unsigned short c;
            };
        """)
        s = defs["TWords"]
        self.assertEqual(s.field("a").spec.size, 8)
        self.assertEqual(s.field("b").spec.size, 8)
        self.assertEqual(s.field("c").spec.size, 2)

    def test_errors(self):
        with self.assertRaises(StructError):
            parse_c("struct TErr1 { uint32_t x }")  # missing semicolon
        with self.assertRaises(StructError):
            parse_c("struct TErr2 { frobnicate x; };")  # unknown type
        with self.assertRaises(StructError):
            parse_c("struct TErr3 { uint32_t *x : 3; };")  # bitfield pointer
        with self.assertRaises(StructError):
            parse_c("nonsense here")

    def test_const_ignored(self):
        defs = parse_c("struct TConst { const uint32_t x; };")
        self.assertEqual(defs["TConst"].size, 4)

    def test_c_char_pointer_is_cstring(self):
        defs = parse_c("struct TCParse { char *name; uint32_t id; };")
        s = defs["TCParse"]
        self.assertIsInstance(s.field("name").spec, CString)
        self.assertEqual(s.field("name").spec.size, 8)

    def test_c_wchar_pointer_is_wstring(self):
        defs = parse_c("""
            struct TWParse { wchar_t *a; char16_t *b; wchar_t c; };
        """)
        s = defs["TWParse"]
        self.assertIsInstance(s.field("a").spec, WString)
        self.assertIsInstance(s.field("b").spec, WString)
        self.assertIsInstance(s.field("c").spec, WChar)
        self.assertEqual(s.field("c").spec.size, 2)

    def test_typedef_char_pointer(self):
        defs = parse_c("typedef char *TCStr;")
        self.assertIsInstance(defs["TCStr"], CString)
        defs = parse_c("typedef wchar_t *TWStr;")
        self.assertIsInstance(defs["TWStr"], WString)


if __name__ == "__main__":
    unittest.main()
