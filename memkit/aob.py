"""Array-of-bytes pattern scans with wildcards.

Patterns look like cheat engine byte strings: "48 8B ?? ?? 74 10".
"??" (or "?") matches any byte, and nibble wildcards like "4?" or "?0"
match half a byte. An explicit mask form is available too for callers
that build patterns programmatically.
"""
from memkit.regions import list_regions


class PatternError(ValueError):
    """Raised when a pattern string does not parse."""


WILDCARD_BYTE = 0x00
SOLID_BYTE = 0xFF


def _parse_token(token):
    # returns (byte, mask) for one pattern token
    token = token.strip().lower()
    if token in ("?", "??"):
        return 0x00, 0x00
    if len(token) != 2:
        raise PatternError("bad pattern token %r" % token)
    byte = 0
    mask = 0
    for i, ch in enumerate(token):
        shift = 4 if i == 0 else 0
        if ch == "?":
            continue
        if ch not in "0123456789abcdef":
            raise PatternError("bad pattern token %r" % token)
        byte |= int(ch, 16) << shift
        mask |= 0xF << shift
    if mask == 0:
        raise PatternError("bad pattern token %r" % token)
    return byte, mask


class Pattern:
    """A byte pattern plus a per-byte mask. Mask 0xFF means exact match."""

    def __init__(self, pattern, mask):
        pattern = bytes(pattern)
        mask = bytes(mask)
        if len(pattern) != len(mask):
            raise PatternError("pattern and mask lengths differ")
        if not pattern:
            raise PatternError("pattern is empty")
        self.bytes = pattern
        self.mask = mask

    @classmethod
    def parse(cls, text):
        """Parse "48 8B ?? 74 10" style text into a Pattern."""
        tokens = text.split()
        if not tokens:
            raise PatternError("pattern is empty")
        pattern = bytearray()
        mask = bytearray()
        for token in tokens:
            byte, bits = _parse_token(token)
            pattern.append(byte)
            mask.append(bits)
        return cls(pattern, mask)

    @classmethod
    def from_bytes(cls, data, mask=None):
        """Build a pattern from raw bytes, with an optional explicit mask."""
        data = bytes(data)
        if mask is None:
            mask = b"\xff" * len(data)
        return cls(data, mask)

    def __len__(self):
        return len(self.bytes)

    def __eq__(self, other):
        return (isinstance(other, Pattern) and self.bytes == other.bytes
                and self.mask == other.mask)

    def __repr__(self):
        return "Pattern(%r)" % self.to_text()

    def to_text(self):
        # render back to "48 8B ??" style text
        parts = []
        for byte, bits in zip(self.bytes, self.mask):
            if bits == 0x00:
                parts.append("??")
            elif bits == 0xFF:
                parts.append("%02X" % byte)
            else:
                hi = "%X" % (byte >> 4) if bits & 0xF0 else "?"
                lo = "%X" % (byte & 0xF) if bits & 0x0F else "?"
                parts.append(hi + lo)
        return " ".join(parts)

    @property
    def solid_count(self):
        return sum(1 for m in self.mask if m == 0xFF)

    def matches_at(self, data, offset):
        """True if the pattern matches data starting at offset."""
        n = len(self.bytes)
        if offset < 0 or offset + n > len(data):
            return False
        view = memoryview(data)
        for i in range(n):
            bits = self.mask[i]
            if bits and (view[offset + i] & bits) != (self.bytes[i] & bits):
                return False
        return True

    def _anchor(self):
        # index of the first fully solid byte, for fast skipping
        for i, bits in enumerate(self.mask):
            if bits == 0xFF:
                return i
        return None

    def find_all(self, data, base=0):
        """All match offsets in data. base shifts the reported offsets."""
        data = bytes(data)
        n = len(self.bytes)
        stop = len(data) - n
        if stop < 0:
            return []
        anchor = self._anchor()
        if anchor is None:
            return [base + i for i in range(stop + 1)]
        needle = self.bytes[anchor:anchor + 1]
        out = []
        pos = data.find(needle, 0, stop + anchor + 1)
        while pos != -1:
            start = pos - anchor
            if start <= stop and self.matches_at(data, start):
                out.append(base + start)
            pos = data.find(needle, pos + 1, stop + anchor + 1)
        return out


def _spans(pid, start, end):
    spans = []
    for region in list_regions(pid):
        if not region.readable:
            continue
        lo = max(region.start, start or 0)
        hi = min(region.end, end if end else region.end)
        if hi > lo:
            spans.append((lo, hi))
    return spans


def scan_pattern(process, pattern, start=None, end=None, alignment=1,
                 max_results=None, chunk_size=1 << 16):
    """Scan readable regions for a Pattern, return matching addresses.

    alignment keeps only matches at addresses divisible by it. Reads are
    chunked with overlap so patterns straddling a chunk edge are found.
    """
    if isinstance(pattern, str):
        pattern = Pattern.parse(pattern)
    if alignment < 1:
        raise ValueError("alignment must be >= 1")
    overlap = len(pattern) - 1
    found = []
    for lo, hi in _spans(process.pid, start, end):
        addr = lo
        carry = b""
        while addr < hi:
            chunk_start = addr
            n = min(chunk_size, hi - addr)
            try:
                # carry holds the tail of the previous chunk, so patterns
                # straddling the boundary are still found
                data = carry + process.read(addr, n)
            except OSError:
                addr += n
                carry = b""
                continue
            base = addr - len(carry)
            for off in pattern.find_all(data):
                hit = base + off
                if hit < chunk_start:
                    continue  # already reported from the previous chunk
                if alignment != 1 and hit % alignment:
                    continue
                found.append(hit)
                if max_results is not None and len(found) >= max_results:
                    return found
            carry = data[-overlap:] if overlap else b""
            addr += n
    return found
