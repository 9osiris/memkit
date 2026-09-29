"""String scans: ascii, utf-8 and utf-16le runs in raw memory.

The find_* functions work on a bytes buffer and are pure. scan_strings
runs the same logic over a live process's readable regions.
"""
import re

DEFAULT_MIN_LENGTH = 4


class StringHit:
    """One string found in memory."""
    __slots__ = ("address", "encoding", "value")

    def __init__(self, address, encoding, value):
        self.address = address
        self.encoding = encoding
        self.value = value

    @property
    def length(self):
        return len(self.value)

    def __eq__(self, other):
        return (isinstance(other, StringHit)
                and self.address == other.address
                and self.encoding == other.encoding
                and self.value == other.value)

    def __hash__(self):
        return hash((self.address, self.encoding, self.value))

    def __repr__(self):
        shown = self.value if len(self.value) <= 48 else self.value[:45] + "..."
        return "StringHit(%#x, %r, %r)" % (self.address, self.encoding, shown)


def _is_ascii_text(byte):
    return 32 <= byte < 127


def find_ascii(data, base_addr=0, min_length=DEFAULT_MIN_LENGTH):
    # runs of printable ascii
    data = bytes(data)
    hits = []
    i, n = 0, len(data)
    while i < n:
        if _is_ascii_text(data[i]):
            start = i
            while i < n and _is_ascii_text(data[i]):
                i += 1
            if i - start >= min_length:
                value = data[start:i].decode("ascii")
                hits.append(StringHit(base_addr + start, "ascii", value))
        else:
            i += 1
    return hits


def _utf8_char_len(data, i):
    # length in bytes of the utf-8 char at i, or 0 when not text
    b = data[i]
    if _is_ascii_text(b):
        return 1
    if 0xC2 <= b <= 0xDF:
        size = 2
    elif 0xE0 <= b <= 0xEF:
        size = 3
    elif 0xF0 <= b <= 0xF4:
        size = 4
    else:
        return 0
    chunk = data[i:i + size]
    if len(chunk) != size:
        return 0
    try:
        text = chunk.decode("utf-8")
    except UnicodeDecodeError:
        return 0
    if not text.isprintable():
        return 0
    return size


def find_utf8(data, base_addr=0, min_length=DEFAULT_MIN_LENGTH):
    # runs of valid printable utf-8, counted in characters
    data = bytes(data)
    hits = []
    i, n = 0, len(data)
    while i < n:
        size = _utf8_char_len(data, i)
        if size:
            start, chars = i, 0
            while i < n:
                size = _utf8_char_len(data, i)
                if not size:
                    break
                i += size
                chars += 1
            if chars >= min_length:
                value = data[start:i].decode("utf-8")
                hits.append(StringHit(base_addr + start, "utf-8", value))
        else:
            i += 1
    return hits


def _utf16le_char(data, i):
    # (text, width_in_bytes) of the utf-16le char at i, or (None, 2)
    if i + 2 > len(data):
        return None, 0
    unit = data[i] | (data[i + 1] << 8)
    if 0xD800 <= unit <= 0xDBFF and i + 4 <= len(data):
        low = data[i + 2] | (data[i + 3] << 8)
        if 0xDC00 <= low <= 0xDFFF:
            try:
                text = bytes(((data[i], data[i + 1],
                               data[i + 2], data[i + 3]))).decode("utf-16-le")
            except UnicodeDecodeError:
                return None, 0
            return (text, 4) if text.isprintable() else (None, 0)
    char = chr(unit)
    if char.isprintable():
        return char, 2
    return None, 0


def _byte_len(hit):
    # how many raw bytes this hit covers
    if hit.encoding == "utf-16le":
        return len(hit.value.encode("utf-16-le"))
    return len(hit.value.encode("utf-8"))


def _overlaps(start, end, ranges):
    return any(start < r_end and r_start < end for r_start, r_end in ranges)


def _dedupe_overlaps(hits):
    # one byte range, one hit; earlier hits win
    ranges = []
    kept = []
    for hit in hits:
        start, end = hit.address, hit.address + _byte_len(hit)
        if not _overlaps(start, end, ranges):
            ranges.append((start, end))
            kept.append(hit)
    kept.sort(key=lambda h: h.address)
    return kept


def _find_utf16le_parity(data, base_addr, min_length, parity):
    # utf-16le scan over one alignment parity
    hits = []
    i, n = parity, len(data)
    while i < n:
        text, width = _utf16le_char(data, i)
        if text is not None:
            start, chars, pieces = i, 0, []
            while i < n:
                text, width = _utf16le_char(data, i)
                if text is None:
                    break
                pieces.append(text)
                i += width
                chars += 1
            if chars >= min_length:
                hits.append(StringHit(base_addr + start, "utf-16le",
                                      "".join(pieces)))
        else:
            i += 2
    return hits


def find_utf16le(data, base_addr=0, min_length=DEFAULT_MIN_LENGTH):
    # runs of printable utf-16le chars. alignment follows the true
    # address, so pairs stay address-aligned even when the buffer was
    # read from an odd address. scan_strings always passes page
    # aligned buffers, and real wide strings are 2-byte aligned.
    data = bytes(data)
    return _find_utf16le_parity(data, base_addr, min_length, base_addr & 1)


_SCANNERS = {
    "ascii": find_ascii,
    "utf-8": find_utf8,
    "utf8": find_utf8,
    "utf-16le": find_utf16le,
    "utf16le": find_utf16le,
    "utf16": find_utf16le,
}


def find_strings(data, base_addr=0, min_length=DEFAULT_MIN_LENGTH,
                 encodings=("ascii", "utf-8", "utf-16le")):
    """Run several string scans. One byte range gets one interpretation:
    hits that overlap an already accepted hit are dropped, so earlier
    encodings win (ascii before utf-16le avoids CJK misreadings of
    plain ascii bytes)."""
    all_hits = []
    for encoding in encodings:
        try:
            scanner = _SCANNERS[encoding.lower()]
        except KeyError:
            raise ValueError("unknown string encoding %r" % encoding)
        all_hits.extend(scanner(data, base_addr, min_length))
    return _dedupe_overlaps(all_hits)


def filter_strings(hits, pattern):
    """Keep hits whose value matches a regex pattern."""
    regex = re.compile(pattern)
    return [h for h in hits if regex.search(h.value)]


def _spans(start, end, chunk_size):
    addr = start
    while addr < end:
        yield addr, min(addr + chunk_size, end)
        addr += chunk_size


def scan_strings(process, min_length=DEFAULT_MIN_LENGTH,
                 encodings=("ascii", "utf-8", "utf-16le"),
                 start=None, end=None, max_hits=100000,
                 chunk_size=4 * 1024 * 1024):
    """Scan readable regions of a process for strings.

    Reads in chunks with a small overlap so strings crossing a chunk
    edge are still found; hits are only reported from the chunk's own
    fresh bytes, never the overlap tail.
    """
    from memkit.regions import list_regions
    overlap = 1024
    hits = []
    for region in list_regions(process.pid):
        if not region.readable:
            continue
        rstart = region.start if start is None else max(region.start, start)
        rend = region.end if end is None else min(region.end, end)
        if rend <= rstart:
            continue
        tail = b""
        for cstart, cend in _spans(rstart, rend, chunk_size):
            try:
                fresh = process.read(cstart, cend - cstart)
            except OSError:
                tail = b""
                continue
            buf = tail + fresh
            base = cstart - len(tail)
            for hit in find_strings(buf, base, min_length, encodings):
                if hit.address >= cstart:
                    hits.append(hit)
                    if len(hits) >= max_hits:
                        return hits
            tail = fresh[-overlap:] if len(fresh) >= overlap else fresh
    return hits
