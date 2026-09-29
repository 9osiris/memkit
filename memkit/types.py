"""Value types for typed reads, writes and scans."""
import struct


TYPES = {
    "u8": ("<B", 1),
    "i8": ("<b", 1),
    "u16": ("<H", 2),
    "i16": ("<h", 2),
    "u32": ("<I", 4),
    "i32": ("<i", 4),
    "u64": ("<Q", 8),
    "i64": ("<q", 8),
    "f32": ("<f", 4),
    "f64": ("<d", 8),
}

POINTER_SIZE = struct.calcsize("P")
POINTER_FMT = "<Q" if POINTER_SIZE == 8 else "<I"


def check_type(type_name):
    if type_name not in TYPES:
        raise ValueError(
            "unknown type %r, pick one of: %s" % (type_name, ", ".join(sorted(TYPES)))
        )
    return TYPES[type_name]


def pack(type_name, value):
    fmt, _ = check_type(type_name)
    return struct.pack(fmt, value)


def unpack(type_name, data):
    fmt, size = check_type(type_name)
    if len(data) != size:
        raise ValueError("need %d bytes for %s, got %d" % (size, type_name, len(data)))
    return struct.unpack(fmt, data)[0]


def parse_value(type_name, text):
    # parse cli input into a typed value, 0x prefix works for ints
    check_type(type_name)
    text = text.strip()
    if type_name.startswith("f"):
        return float(text)
    return int(text, 0)
