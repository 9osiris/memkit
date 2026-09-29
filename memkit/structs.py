"""C-like struct definitions and memory dissection.

Define structs with a small DSL or by parsing C declarations, then render
memory at an address as typed fields: nested structs, arrays, pointers,
bitfields and enums. Works on raw bytes or on a live Process.

DSL example:

    class Vec3(Struct):
        x = "f32"
        y = "f32"
        z = "f32"

    player = Struct("Player", [
        ("health", "u32"),
        ("name", "char[16]"),
        ("pos", Vec3),
        ("flags", BitField("u32", [("alive", 0, 1), ("team", 1, 2)])),
        ("next", Ptr("Player")),
    ])
    print(player.render(memory_bytes, 0))

C parsing example:

    defs = parse_c("struct Vec3 { float x; float y; float z; };")
    vec3 = defs["Vec3"]
"""
import re
import struct as struct_module

from memkit.types import POINTER_FMT, POINTER_SIZE, TYPES


class StructError(ValueError):
    """Raised for bad struct definitions or bad C syntax."""


def align_up(value, alignment):
    return (value + alignment - 1) // alignment * alignment


# type specs
class Spec:
    """Base class for anything that can sit in a struct field."""

    size = 0
    alignment = 1

    def read_value(self, reader, address):
        raise NotImplementedError

    def pack_value(self, value):
        raise NotImplementedError

    def render_value(self, value):
        return repr(value)


class Primitive(Spec):
    def __init__(self, name):
        if name not in TYPES:
            raise StructError("unknown primitive type %r" % name)
        self.name = name
        self.fmt, self.size = TYPES[name]
        self.alignment = self.size

    def read_value(self, reader, address):
        return struct_module.unpack(self.fmt, reader.read(address, self.size))[0]

    def pack_value(self, value):
        return struct_module.pack(self.fmt, value)

    def render_value(self, value):
        if self.name.startswith("f"):
            return "%r" % value
        return "%d (%#x)" % (value, value)

    def __repr__(self):
        return "Primitive(%r)" % self.name


class Char(Spec):
    """A single C char: stored like u8, rendered as a character."""

    size = 1
    alignment = 1
    name = "char"

    def read_value(self, reader, address):
        return reader.read(address, 1)[0]

    def pack_value(self, value):
        if isinstance(value, str):
            if len(value) != 1:
                raise StructError("char field needs one character")
            value = ord(value)
        return bytes([value & 0xFF])

    def render_value(self, value):
        ch = chr(value)
        if ch.isprintable():
            return "%d (%r)" % (value, ch)
        return "%d" % value


class Bool(Spec):
    size = 1
    alignment = 1
    name = "bool"

    def read_value(self, reader, address):
        return bool(reader.read(address, 1)[0])

    def pack_value(self, value):
        return bytes([1 if value else 0])

    def render_value(self, value):
        return "true" if value else "false"


class Pointer(Spec):
    """A native pointer. target is a Spec, a registered name, or None."""

    def __init__(self, target=None):
        self.target = target
        self.size = POINTER_SIZE
        self.alignment = POINTER_SIZE

    def read_value(self, reader, address):
        return struct_module.unpack(POINTER_FMT, reader.read(address, self.size))[0]

    def pack_value(self, value):
        return struct_module.pack(POINTER_FMT, value or 0)

    def render_value(self, value):
        return "%#x" % value

    @property
    def target_name(self):
        target = self.target
        if target is None:
            return "void"
        if isinstance(target, str):
            return target
        return target.name

    def __repr__(self):
        return "Pointer(%s)" % self.target_name


def Ptr(target=None):
    # short alias matching the dsl style
    return Pointer(target)


class Array(Spec):
    def __init__(self, elem, count):
        self.elem = resolve_spec(elem)
        self.count = int(count)
        if self.count <= 0:
            raise StructError("array count must be positive")
        self.size = self.elem.size * self.count
        self.alignment = self.elem.alignment

    def read_value(self, reader, address):
        # char arrays come back as bytes, everything else as a list
        if isinstance(self.elem, Char):
            return reader.read(address, self.size).split(b"\x00", 1)[0]
        return [self.elem.read_value(reader, address + i * self.elem.size)
                for i in range(self.count)]

    def pack_value(self, value):
        if isinstance(self.elem, Char):
            if isinstance(value, str):
                value = value.encode()
            value = bytes(value)
            if len(value) > self.size:
                raise StructError("char array value too long")
            return value + b"\x00" * (self.size - len(value))
        if len(value) != self.count:
            raise StructError("need %d elements, got %d" % (
                self.count, len(value)))
        return b"".join(self.elem.pack_value(v) for v in value)

    def render_value(self, value):
        if isinstance(value, bytes):
            try:
                text = value.decode()
            except UnicodeDecodeError:
                text = value.decode(errors="replace")
            return "%r" % text
        if len(value) <= 8:
            return "[%s]" % ", ".join(self.elem.render_value(v) for v in value)
        head = ", ".join(self.elem.render_value(v) for v in value[:8])
        return "[%s, ... (%d total)]" % (head, len(value))

    @property
    def name(self):
        return "%s[%d]" % (getattr(self.elem, "name", "?"), self.count)

    def __repr__(self):
        return "Array(%r, %d)" % (self.elem, self.count)


class BitField(Spec):
    """Bit flags packed into one integer of bits_type."""

    def __init__(self, bits_type, fields):
        self.bits = resolve_spec(bits_type)
        if not isinstance(self.bits, (Primitive,)):
            raise StructError("bitfield storage must be an integer primitive")
        if self.bits.name.startswith("f"):
            raise StructError("bitfield storage must be an integer primitive")
        self.size = self.bits.size
        self.alignment = self.bits.alignment
        self.fields = []
        for item in fields:
            name, lsb, width = item
            if width <= 0 or lsb < 0 or lsb + width > self.size * 8:
                raise StructError("bad bit range for %r" % name)
            self.fields.append((name, lsb, width))

    def read_value(self, reader, address):
        raw = self.bits.read_value(reader, address)
        return {name: (raw >> lsb) & ((1 << width) - 1)
                for name, lsb, width in self.fields}

    def pack_value(self, value):
        raw = 0
        for name, lsb, width in self.fields:
            bits = value.get(name, 0) if isinstance(value, dict) else 0
            if bits >= (1 << width):
                raise StructError("value %#x too wide for %r" % (bits, name))
            raw |= (bits & ((1 << width) - 1)) << lsb
        if isinstance(value, int):
            raw = value
        return self.bits.pack_value(raw)

    def render_value(self, value):
        if isinstance(value, int):
            return self.bits.render_value(value)
        parts = []
        for name, lsb, width in self.fields:
            bits = value[name]
            if width == 1:
                if bits:
                    parts.append(name)
            else:
                parts.append("%s=%d" % (name, bits))
        flags = ", ".join(parts) if parts else "none"
        raw = sum(value[n] << l for n, l, _ in self.fields)
        return "%#x <%s>" % (raw, flags)

    @property
    def name(self):
        return "bits<%s>" % self.bits.name

    def __repr__(self):
        return "BitField(%r, %r)" % (self.bits.name, self.fields)


class Enum(Spec):
    """An integer with named values, rendered as the name when known."""

    def __init__(self, base, mapping, name="enum"):
        self.base = resolve_spec(base)
        self.mapping = dict(mapping)
        self.reverse = {v: k for k, v in self.mapping.items()}
        self.size = self.base.size
        self.alignment = self.base.alignment
        self.name = name

    def read_value(self, reader, address):
        return self.base.read_value(reader, address)

    def pack_value(self, value):
        if isinstance(value, str):
            if value not in self.mapping:
                raise StructError("unknown enum name %r" % value)
            value = self.mapping[value]
        return self.base.pack_value(value)

    def render_value(self, value):
        if value in self.reverse:
            return "%s (%d)" % (self.reverse[value], value)
        return self.base.render_value(value)

    def __repr__(self):
        return "Enum(%r, %d values)" % (self.name, len(self.mapping))


# registry of named structs, unions and enums for string references
REGISTRY = {}


def register(spec):
    REGISTRY[spec.name] = spec
    return spec


def lookup(name):
    try:
        return REGISTRY[name]
    except KeyError:
        raise StructError("unknown type %r" % name)


_ARRAY_RE = re.compile(r"^(.+)\[(\d+)\]$")
_PTR_RE = re.compile(r"^(.+)\*$")


def resolve_spec(spec):
    # turn dsl shorthand into a Spec: Specs pass through, strings resolve
    if isinstance(spec, Spec):
        return spec
    if not isinstance(spec, str):
        raise StructError("bad type spec %r" % (spec,))
    text = spec.strip()
    if text == "ptr":
        return Pointer(None)
    if text == "char":
        return Char()
    if text == "bool":
        return Bool()
    match = _ARRAY_RE.match(text)
    if match:
        return Array(match.group(1), int(match.group(2)))
    match = _PTR_RE.match(text)
    if match:
        return Pointer(match.group(1).strip())
    if text in TYPES:
        return Primitive(text)
    return lookup(text)


class Field:
    def __init__(self, name, spec):
        self.name = name
        self.spec = resolve_spec(spec)
        self.offset = 0

    def __repr__(self):
        return "Field(%r, %r, offset=%#x)" % (self.name, self.spec, self.offset)


class Struct(Spec):
    """An ordered set of fields with C layout rules.

    Fields can be given as (name, spec) tuples or Field objects. Set pack
    to cap alignment like #pragma pack(n). Subclassing collects Field
    attributes as fields in definition order.
    """

    def __init__(self, name=None, fields=None, pack=None):
        # name/fields may come from the class-dsl instead of arguments
        if fields is None:
            fields = getattr(self, "_dsl_fields", None) or []
        if name is None:
            name = type(self).__name__
        self.name = name
        self.pack_align = pack
        self.fields = []
        for item in fields:
            if isinstance(item, Field):
                self.fields.append(item)
            else:
                fname, fspec = item
                self.fields.append(Field(fname, fspec))
        self._layout()
        register(self)

    def __init_subclass__(cls, **kwargs):
        # collect field-ish attributes so `class Vec3(Struct)` works, in order
        super().__init_subclass__(**kwargs)
        dsl = []
        for attr, value in list(cls.__dict__.items()):
            if attr.startswith("__") and attr.endswith("__"):
                continue  # __module__, __doc__, __qualname__
            if isinstance(value, Field):
                if not value.name:
                    value.name = attr
                dsl.append(value)
                delattr(cls, attr)
            elif isinstance(value, (Spec, str)):
                dsl.append(Field(attr, value))
                delattr(cls, attr)
        cls._dsl_fields = dsl

    def _layout(self):
        offset = 0
        max_align = 1
        for field in self.fields:
            align = field.spec.alignment
            if self.pack_align:
                align = min(align, self.pack_align)
            max_align = max(max_align, align)
            offset = align_up(offset, align)
            field.offset = offset
            offset += field.spec.size
        if self.pack_align:
            max_align = min(max_align, self.pack_align)
        self.alignment = max_align
        self.size = align_up(offset, max_align)

    def field(self, name):
        for f in self.fields:
            if f.name == name:
                return f
        raise StructError("%s has no field %r" % (self.name, name))

    def read_value(self, reader, address):
        return {f.name: f.spec.read_value(reader, address + f.offset)
                for f in self.fields}

    def pack_value(self, values):
        blob = bytearray(self.size)
        for f in self.fields:
            if f.name not in values:
                continue
            packed = f.spec.pack_value(values[f.name])
            blob[f.offset:f.offset + len(packed)] = packed
        return bytes(blob)

    pack = pack_value  # pack({...}) reads nicer than pack_value({...})

    def __repr__(self):
        return "Struct(%r, %d fields, size %d)" % (
            self.name, len(self.fields), self.size)


class Union(Spec):
    """All fields overlap at offset zero, size is the largest field."""

    def __init__(self, name, fields):
        self.name = name
        self.fields = []
        for item in fields:
            if isinstance(item, Field):
                self.fields.append(item)
            else:
                fname, fspec = item
                self.fields.append(Field(fname, fspec))
        self.size = 0
        self.alignment = 1
        for f in self.fields:
            f.offset = 0
            self.size = max(self.size, f.spec.size)
            self.alignment = max(self.alignment, f.spec.alignment)
        self.size = align_up(self.size, self.alignment)
        register(self)

    def field(self, name):
        for f in self.fields:
            if f.name == name:
                return f
        raise StructError("%s has no field %r" % (self.name, name))

    def read_value(self, reader, address):
        return {f.name: f.spec.read_value(reader, address)
                for f in self.fields}

    def pack_value(self, values):
        blob = bytearray(self.size)
        for f in self.fields:
            if f.name not in values:
                continue
            packed = f.spec.pack_value(values[f.name])
            blob[0:len(packed)] = packed
        return bytes(blob)

    pack = pack_value

    def __repr__(self):
        return "Union(%r, %d fields, size %d)" % (
            self.name, len(self.fields), self.size)


# readers: where the bytes come from
class Reader:
    def read(self, address, size):
        raise NotImplementedError

    @property
    def can_deref(self):
        return False


class BytesReader(Reader):
    """Read from a bytes-like object, address is an offset."""

    def __init__(self, data):
        self._data = bytes(data)

    def read(self, address, size):
        if address < 0 or address + size > len(self._data):
            raise StructError("read %#x+%d out of range" % (address, size))
        return self._data[address:address + size]


class ProcessReader(Reader):
    """Read from a live process through its read method."""

    def __init__(self, process):
        self._process = process

    def read(self, address, size):
        return self._process.read(address, size)

    @property
    def can_deref(self):
        return True


def make_reader(source):
    if isinstance(source, Reader):
        return source
    if hasattr(source, "read") and hasattr(source, "pid"):
        return ProcessReader(source)
    return BytesReader(source)


# dissection: turning bytes into readable field trees
def _spec_type_name(spec):
    if isinstance(spec, Pointer):
        return "%s*" % spec.target_name
    return getattr(spec, "name", type(spec).__name__)


def _read_field(reader, spec, address):
    try:
        return (True, spec.read_value(reader, address))
    except Exception:
        return (False, None)


def _render_struct_lines(spec, reader, address, indent, max_depth, depth):
    lines = []
    pad = "  " * indent
    addr_text = "%#x" % address
    lines.append("%s%s @ %s (%d bytes)" % (pad, spec.name, addr_text,
                                           spec.size))
    for field in spec.fields:
        lines.extend(_render_field_lines(field, reader, address + field.offset,
                                         indent + 1, max_depth, depth))
    return lines


def _render_field_lines(field, reader, address, indent, max_depth, depth):
    pad = "  " * indent
    spec = field.spec
    ok, value = _read_field(reader, spec, address)
    label = "%s%s: %s = " % (pad, field.name, _spec_type_name(spec))
    if not ok:
        return [label + "<unreadable>"]
    # nested struct or union: expand inline
    if isinstance(spec, (Struct, Union)):
        lines = ["%s%s: %s @ %#x (%d bytes)" % (
            pad, field.name, spec.name, address, spec.size)]
        for sub in spec.fields:
            lines.extend(_render_field_lines(sub, reader,
                                             address + sub.offset,
                                             indent + 1, max_depth, depth))
        return lines
    # small arrays of structs expand per element
    if (isinstance(spec, Array) and isinstance(spec.elem, (Struct, Union))
            and spec.count <= 8):
        lines = ["%s%s: %s" % (pad, field.name, _spec_type_name(spec))]
        for i in range(spec.count):
            lines.extend(_render_struct_lines(
                spec.elem, reader, address + i * spec.elem.size,
                indent + 1, max_depth, depth))
        return lines
    # pointers: show the address, deref into structs when possible
    if isinstance(spec, Pointer):
        lines = [label + spec.render_value(value)]
        target = spec.target
        if isinstance(target, str):
            target = REGISTRY.get(target)
        if (target is not None and isinstance(target, (Struct, Union))
                and value and depth < max_depth and reader.can_deref):
            ok2, _ = _read_field(reader, target, value)
            if ok2:
                lines.append("%s  -> %s @ %#x" % (pad, target.name, value))
                for sub in target.fields:
                    lines.extend(_render_field_lines(
                        sub, reader, value + sub.offset, indent + 2,
                        max_depth, depth + 1))
            else:
                lines.append("%s  -> <unreadable>" % pad)
        return lines
    return [label + spec.render_value(value)]


def dissect(source, spec, address=0, max_depth=2):
    """Render memory as a list of lines describing each field.

    source is bytes (address is an offset) or a Process (real addresses).
    spec is a Struct, Union, or a registered type name.
    """
    if isinstance(spec, str):
        spec = lookup(spec)
    if not isinstance(spec, (Struct, Union)):
        raise StructError("dissect needs a struct or union, got %r" % spec)
    reader = make_reader(source)
    return _render_struct_lines(spec, reader, address, 0, max_depth, 0)


def render(source, spec, address=0, max_depth=2):
    """dissect() joined into one string."""
    return "\n".join(dissect(source, spec, address, max_depth))


def values(source, spec, address=0):
    """Read memory into nested dicts/lists instead of rendering text."""
    if isinstance(spec, str):
        spec = lookup(spec)
    reader = make_reader(source)
    return spec.read_value(reader, address)


# c declaration parsing
# c long is fixed at 64 bit (lp64, like linux and macos). on windows
# long is 32 bit, so c parsed there can disagree with msvc layouts.

_C_TYPE_WORDS = {
    "void", "char", "short", "int", "long", "float", "double",
    "signed", "unsigned", "bool", "_Bool",
    "int8_t", "uint8_t", "int16_t", "uint16_t",
    "int32_t", "uint32_t", "int64_t", "uint64_t",
    "size_t",
}

_C_IGNORED_WORDS = {"const", "volatile", "static", "extern", "register"}

_TOKEN_RE = re.compile(r"""
    (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<number>0[xX][0-9a-fA-F]+|[0-9]+)
  | (?P<sym>[{};\[\]:*,=\-\(\)])
  | (?P<bad>\S)
""", re.VERBOSE)


def _strip_comments(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", " ", text)


def _tokenize(text):
    tokens = []
    for match in _TOKEN_RE.finditer(_strip_comments(text)):
        kind = match.lastgroup
        word = match.group()
        if kind == "bad":
            raise StructError("bad character %r in c source" % word)
        if kind == "ident" and word in _C_IGNORED_WORDS:
            continue
        tokens.append(word)
    return tokens


def _c_primitive(words):
    key = tuple(words)
    if key == ("size_t",):
        return Primitive("u64" if POINTER_SIZE == 8 else "u32")
    table = {
        ("char",): Char(),
        ("signed", "char"): Primitive("i8"),
        ("unsigned", "char"): Primitive("u8"),
        ("short",): Primitive("i16"),
        ("short", "int"): Primitive("i16"),
        ("signed", "short"): Primitive("i16"),
        ("signed", "short", "int"): Primitive("i16"),
        ("unsigned", "short"): Primitive("u16"),
        ("unsigned", "short", "int"): Primitive("u16"),
        ("int",): Primitive("i32"),
        ("signed",): Primitive("i32"),
        ("signed", "int"): Primitive("i32"),
        ("unsigned",): Primitive("u32"),
        ("unsigned", "int"): Primitive("u32"),
        ("long",): Primitive("i64"),
        ("long", "int"): Primitive("i64"),
        ("signed", "long"): Primitive("i64"),
        ("signed", "long", "int"): Primitive("i64"),
        ("unsigned", "long"): Primitive("u64"),
        ("unsigned", "long", "int"): Primitive("u64"),
        ("long", "long"): Primitive("i64"),
        ("long", "long", "int"): Primitive("i64"),
        ("signed", "long", "long"): Primitive("i64"),
        ("unsigned", "long", "long"): Primitive("u64"),
        ("unsigned", "long", "long", "int"): Primitive("u64"),
        ("float",): Primitive("f32"),
        ("double",): Primitive("f64"),
        ("bool",): Bool(),
        ("_Bool",): Bool(),
        ("int8_t",): Primitive("i8"),
        ("uint8_t",): Primitive("u8"),
        ("int16_t",): Primitive("i16"),
        ("uint16_t",): Primitive("u16"),
        ("int32_t",): Primitive("i32"),
        ("uint32_t",): Primitive("u32"),
        ("int64_t",): Primitive("i64"),
        ("uint64_t",): Primitive("u64"),
        ("void",): None,
    }
    try:
        return table[key]
    except KeyError:
        raise StructError("unknown c type %r" % " ".join(words))


class _CParser:
    def __init__(self, text):
        self.tokens = _tokenize(text)
        self.pos = 0
        self.defs = {}
        self._anon = 0
        self._def_stack = []  # names of structs currently being defined

    # token helpers
    def peek(self):
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def peek2(self):
        if self.pos + 1 < len(self.tokens):
            return self.tokens[self.pos + 1]
        return None

    def peek3(self):
        if self.pos + 2 < len(self.tokens):
            return self.tokens[self.pos + 2]
        return None

    def peek_is_ident(self):
        tok = self.peek()
        return tok is not None and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*",
                                                tok) is not None

    def next(self):
        tok = self.peek()
        if tok is None:
            raise StructError("unexpected end of c source")
        self.pos += 1
        return tok

    def expect(self, what):
        tok = self.next()
        if tok != what:
            raise StructError("want %r, got %r" % (what, tok))
        return tok

    def expect_ident(self):
        if not self.peek_is_ident():
            raise StructError("want an identifier, got %r" % self.peek())
        return self.next()

    def expect_number(self):
        negative = False
        if self.peek() == "-":
            self.next()
            negative = True
        tok = self.next()
        if not re.fullmatch(r"(0[xX][0-9a-fA-F]+|[0-9]+)", tok or ""):
            raise StructError("want a number, got %r" % tok)
        value = int(tok, 0)
        return -value if negative else value

    def anon_name(self, kind):
        self._anon += 1
        return "anon_%s_%d" % (kind, self._anon)

    def _remember(self, spec):
        self.defs[spec.name] = spec
        return spec

    # top level
    def parse(self):
        while self.peek() is not None:
            tok = self.peek()
            if tok == "typedef":
                self.parse_typedef()
            elif tok in ("struct", "union"):
                self.parse_struct_def()
            elif tok == "enum":
                self.parse_enum_def()
            elif tok == ";":
                self.next()  # stray semicolon
            else:
                raise StructError(
                    "unexpected %r, want struct, union, enum or typedef" % tok)
        return self.defs

    def _parse_struct_or_union(self):
        # parses [name] [{ body }], returns (kind, name, fields or None)
        kind = self.next()
        name = None
        if self.peek_is_ident() and self.peek2() == "{":
            name = self.next()
        fields = None
        if self.peek() == "{":
            self.next()
            if name is not None:
                self._def_stack.append(name)
            try:
                fields = self.parse_members()
            finally:
                if name is not None:
                    self._def_stack.pop()
            self.expect("}")
        elif name is None:
            name = self.expect_ident()
        return kind, name, fields

    def _build_struct(self, kind, name, fields):
        if name is None:
            name = self.anon_name(kind)
        if kind == "struct":
            return Struct(name, fields)
        return Union(name, fields)

    def parse_struct_def(self):
        kind, name, fields = self._parse_struct_or_union()
        if fields is None:
            raise StructError("struct %s needs a body" % name)
        if self.peek() == ";":
            self.next()
        return self._remember(self._build_struct(kind, name, fields))

    def parse_enum_def(self):
        self.next()  # enum
        name = None
        if self.peek_is_ident() and self.peek2() == "{":
            name = self.next()
        self.expect("{")
        mapping = {}
        next_value = 0
        while self.peek() != "}":
            key = self.expect_ident()
            if self.peek() == "=":
                self.next()
                next_value = self.expect_number()
            mapping[key] = next_value
            next_value += 1
            if self.peek() == ",":
                self.next()
            else:
                break
        self.expect("}")
        if self.peek() == ";":
            self.next()
        spec = Enum("i32", mapping, name or self.anon_name("enum"))
        REGISTRY[spec.name] = spec
        return self._remember(spec)

    def parse_typedef(self):
        self.next()  # typedef
        if self.peek() in ("struct", "union"):
            kind, _, fields = self._parse_struct_or_union()
            if fields is None:
                raise StructError("typedef needs a struct body")
            name = self.expect_ident()
            self.expect(";")
            spec = self._build_struct(kind, name, fields)
            return self._remember(spec)
        if self.peek() == "enum":
            self.parse_enum_def()
            old_name = list(self.defs)[-1]
            spec = self.defs.pop(old_name)
            name = self.expect_ident()
            self.expect(";")
            del REGISTRY[spec.name]
            spec.name = name
            REGISTRY[name] = spec
            self.defs[name] = spec
            return spec
        base = self.parse_type()
        while self.peek() == "*":
            self.next()
            base = Pointer(base)
        name = self.expect_ident()
        if self.peek() == "[":
            self.next()
            count = self.expect_number()
            self.expect("]")
            base = Array(base, count)
        self.expect(";")
        REGISTRY[name] = base
        self.defs[name] = base
        return base

    # member parsing
    def _is_nested_def(self):
        # struct { ... } or struct Name { ... } (same for union/enum)
        if self.peek() in ("struct", "union", "enum"):
            if self.peek2() == "{":
                return True
            ident2 = self.peek2()
            if (ident2 is not None and self.peek3() == "{" and
                    re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", ident2)):
                return True
        return False

    def _apply_declarator(self, base, allow_bitfield=True):
        # parses *name, *name[n], name : bits after a type, returns spec info
        pointer_depth = 0
        while self.peek() == "*":
            self.next()
            pointer_depth += 1
        name = self.expect_ident()
        spec = base
        for _ in range(pointer_depth):
            spec = Pointer(spec)
        if self.peek() == "[":
            self.next()
            count = self.expect_number()
            self.expect("]")
            spec = Array(spec, count)
        bit_width = None
        if allow_bitfield and self.peek() == ":":
            self.next()
            bit_width = self.expect_number()
        return name, spec, bit_width

    def parse_members(self):
        fields = []
        bit_run = []  # (name, width, base_spec)

        def flush_bits():
            if not bit_run:
                return
            first_name = bit_run[0][0]
            base_spec = bit_run[0][2]
            lsb = 0
            parts = []
            for name, width, bspec in bit_run:
                if bspec is not base_spec and getattr(bspec, "name", None) != getattr(base_spec, "name", None):
                    raise StructError("bitfield run mixes types")
                parts.append((name, lsb, width))
                lsb += width
            fields.append(Field(first_name, BitField(base_spec, parts)))
            bit_run.clear()

        while self.peek() != "}":
            if self.peek() is None:
                raise StructError("unexpected end inside struct body")
            if self._is_nested_def():
                tok = self.peek()
                if tok == "enum":
                    spec = self.parse_enum_def()
                else:
                    kind, name, nested = self._parse_struct_or_union()
                    spec = self._build_struct(kind, name, nested)
                    self._remember(spec)
                flush_bits()
                name, spec, _bits = self._apply_declarator(spec)
                fields.append(Field(name, spec))
                self.expect(";")
                continue
            base = self.parse_type()
            while True:
                if base is None:
                    raise StructError("void is only valid for pointers")
                name, spec, bit_width = self._apply_declarator(base)
                if isinstance(base, str) and not isinstance(spec, Pointer):
                    raise StructError(
                        "field %r has incomplete type %r" % (name, base))
                if bit_width is not None:
                    if isinstance(spec, (Pointer, Array)):
                        raise StructError("bitfield on non-integer type")
                    bit_run.append((name, bit_width, base))
                else:
                    flush_bits()
                    fields.append(Field(name, spec))
                if self.peek() == ",":
                    self.next()
                    continue
                break
            self.expect(";")
        flush_bits()
        return fields

    def parse_type(self):
        tok = self.peek()
        if tok in ("struct", "union"):
            self.next()
            name = self.expect_ident()
            try:
                spec = lookup(name)
            except StructError:
                if name in self._def_stack:
                    return name  # lazy self reference, must sit behind a *
                raise
            if not isinstance(spec, (Struct, Union)):
                raise StructError("%r is not a struct or union" % name)
            return spec
        if tok == "enum":
            self.next()
            name = self.expect_ident()
            spec = lookup(name)
            if not isinstance(spec, Enum):
                raise StructError("%r is not an enum" % name)
            return spec
        words = []
        while self.peek_is_ident() and self.peek() in _C_TYPE_WORDS:
            words.append(self.next())
        if not words:
            return lookup(self.expect_ident())
        return _c_primitive(words)


def parse_c(text):
    """Parse C struct/union/enum declarations into Struct objects.

    Returns a dict of name to spec. Everything defined is also registered,
    so later parse_c calls and string type references can use the names.
    """
    return _CParser(text).parse()
