"""Automatic pointer scanner.

Given a target address, find pointer chains leading to it: scan memory
for slots holding values near the target, then recurse outward to a
configurable depth. Chains are deduplicated and ranked by depth, so the
most useful (deepest, smallest offset) chains come first.
"""
import struct
from bisect import bisect_right

from memkit.regions import list_regions
from memkit.types import POINTER_FMT, POINTER_SIZE

CHUNK_SIZE = 1 << 16


class Chain:
    """One pointer chain, outermost slot first.

    steps is a list of (address, offset) where reading the pointer at
    address and adding offset gives the next address in the chain, and
    the last step lands on the scan target.
    """

    def __init__(self, steps):
        self.steps = list(steps)

    @property
    def depth(self):
        return len(self.steps)

    @property
    def base_address(self):
        return self.steps[0][0] if self.steps else None

    @property
    def total_offset(self):
        return sum(off for _, off in self.steps)

    @property
    def addresses(self):
        return [addr for addr, _ in self.steps]

    def resolve(self, process):
        """Walk the chain in the target process, return the final address."""
        current = None
        for address, offset in self.steps:
            current = process.read_pointer(address) + offset
        return current

    def describe(self, target=None):
        parts = []
        for address, offset in self.steps:
            parts.append("%#x + %#x" % (address, offset))
        if target is not None:
            parts.append("-> %#x" % target)
        return " ".join(parts)

    def __repr__(self):

        return "Chain(depth=%d, base=%#x)" % (self.depth,
                                              self.base_address or 0)

    def __eq__(self, other):
        return isinstance(other, Chain) and self.steps == other.steps

    def __hash__(self):
        return hash(tuple(self.steps))


def _mapped_ranges(pid):
    # sorted (start, end) of every mapped region for the mapped check
    ranges = [(r.start, r.end) for r in list_regions(pid)]
    ranges.sort()
    return ranges


def _is_mapped(ranges, value):
    # binary search for a range containing value
    starts = [s for s, _ in ranges]
    i = bisect_right(starts, value) - 1
    return i >= 0 and ranges[i][0] <= value < ranges[i][1]


def _iter_pointer_slots(process, ranges, start, end, writable_only):
    # yield (slot_address, value) for each aligned pointer-sized slot
    for region in list_regions(process.pid):
        if not region.readable:
            continue
        if writable_only and not region.writable:
            continue
        lo = max(region.start, start or 0)
        hi = min(region.end, end if end else region.end)
        if hi <= lo:
            continue
        addr = lo + (-lo % POINTER_SIZE)
        while addr < hi:
            n = min(CHUNK_SIZE, hi - addr)
            try:
                data = process.read(addr, n)
            except OSError:
                addr += n
                continue
            for i in range(0, len(data) - POINTER_SIZE + 1, POINTER_SIZE):
                (value,) = struct.unpack_from(POINTER_FMT, data, i)
                yield addr + i, value
            addr += n


def scan_pointers(process, target, max_offset=0x1000, depth=3, start=None,
                  end=None, writable_only=True, require_mapped=True,
                  max_results=10000):
    """Find pointer chains leading to target.

    A slot holding value v links to target when target - max_offset <= v
    <= target, with offset target - v. Each level outward repeats the
    search using the previous level's slots as new targets. Returns
    chains ranked deepest first, then by smallest total offset.
    """
    if max_offset < 0:
        raise ValueError("max_offset must be non-negative")
    if depth < 1:
        raise ValueError("depth must be at least 1")
    ranges = _mapped_ranges(process.pid) if require_mapped else []
    found = []
    # current maps each target address to the chains that end there
    current = {int(target): [Chain([])]}
    for _ in range(depth):
        next_targets = {}
        for slot, value in _iter_pointer_slots(process, ranges, start, end,
                                               writable_only):
            if require_mapped and not _is_mapped(ranges, value):
                continue
            for taddr, suffixes in current.items():
                if not taddr - max_offset <= value <= taddr:
                    continue
                offset = taddr - value
                for suffix in suffixes:
                    if slot in suffix.addresses:
                        continue  # would be a cycle
                    chain = Chain([(slot, offset)] + suffix.steps)
                    found.append(chain)
                    next_targets.setdefault(slot, []).append(chain)
                    if len(found) >= max_results:
                        break
                if len(found) >= max_results:
                    break
            if len(found) >= max_results:
                break
        if not next_targets:
            break
        current = next_targets
    found.sort(key=lambda c: (-c.depth, c.total_offset))
    return found[:max_results]
