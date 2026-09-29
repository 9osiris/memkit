"""Multi-pass value scanner, cheat-engine style.

First pass walks readable regions in chunks and records candidate addresses.
Later passes only re-read the candidates, so narrowing is fast.
"""
from memkit.regions import list_regions
from memkit.types import check_type, pack, unpack

CHUNK_SIZE = 1 << 16


class Scanner:
    def __init__(self, process, type_name="u32"):
        check_type(type_name)
        self.process = process
        self.type_name = type_name
        _, self.size = check_type(type_name)
        self.candidates = []
        self._snapshot = {}
        self._primed = False

    def _spans(self, start, end):
        spans = []
        for region in list_regions(self.process.pid):
            if not region.readable:
                continue
            lo = max(region.start, start or 0)
            hi = min(region.end, end if end else region.end)
            if hi > lo:
                spans.append((lo, hi))
        return spans

    def _iter_slots(self, start, end):
        # yield (address, raw bytes) for each aligned slot in the spans
        for lo, hi in self._spans(start, end):
            addr = lo
            while addr < hi:
                n = min(CHUNK_SIZE, hi - addr)
                try:
                    data = self.process.read(addr, n)
                except OSError:
                    addr += n
                    continue
                off = (-addr) % self.size
                stop = len(data) - self.size + 1
                for i in range(off, stop, self.size):
                    yield addr + i, data[i : i + self.size]
                addr += n

    def scan_exact(self, value, start=None, end=None):
        """First pass finds every match. Later passes keep still-matching ones."""
        needle = pack(self.type_name, value)
        if not self._primed:
            self.candidates = []
            self._snapshot = {}
            for addr, raw in self._iter_slots(start, end):
                if raw == needle:
                    self.candidates.append(addr)
                    self._snapshot[addr] = raw
            self._primed = True
        else:
            alive = {}
            for addr in self.candidates:
                try:
                    alive[addr] = self.process.read(addr, self.size)
                except OSError:
                    continue
            self.candidates = [a for a in alive if alive[a] == needle]
            self._snapshot = alive
        return self.candidates

    def scan_initial(self, start=None, end=None):
        """Snapshot every value in range, for changed/unchanged style scans."""
        self.candidates = []
        self._snapshot = {}
        for addr, raw in self._iter_slots(start, end):
            self.candidates.append(addr)
            self._snapshot[addr] = raw
        self._primed = True
        return self.candidates

    def _narrow(self, predicate):
        if not self._primed:
            raise RuntimeError("run scan_exact or scan_initial first")
        old = self._snapshot
        alive = {}
        for addr in self.candidates:
            try:
                alive[addr] = self.process.read(addr, self.size)
            except OSError:
                continue
        self.candidates = [a for a in alive if predicate(old[a], alive[a])]
        self._snapshot = alive
        return self.candidates

    def scan_changed(self):
        return self._narrow(lambda o, n: o != n)

    def scan_unchanged(self):
        return self._narrow(lambda o, n: o == n)

    def scan_increased(self):
        return self._narrow(
            lambda o, n: unpack(self.type_name, n) > unpack(self.type_name, o)
        )

    def scan_decreased(self):
        return self._narrow(
            lambda o, n: unpack(self.type_name, n) < unpack(self.type_name, o)
        )

    def clear(self):
        self.candidates = []
        self._snapshot = {}

    def __len__(self):
        return len(self.candidates)
