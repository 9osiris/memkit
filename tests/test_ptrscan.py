"""Tests for the automatic pointer scanner: synthetic multi-level pointer
layouts are built with ctypes in the tool's own process."""
import ctypes
import os
import unittest

from memkit.process import Process
from memkit.ptrscan import Chain, scan_pointers
from memkit.regions import list_regions


class Slot(ctypes.Structure):
    _fields_ = [("pad", ctypes.c_uint64), ("ptr", ctypes.c_void_p)]


def region_of(addr):
    for r in list_regions(os.getpid()):
        if r.readable and r.contains(addr):
            return r
    raise AssertionError("no readable region contains %#x" % addr)


class ChainTest(unittest.TestCase):
    def test_resolve_walks_steps(self):
        target = ctypes.c_uint32(0xBEEF)
        mid = Slot(0, ctypes.addressof(target))
        outer = Slot(0, ctypes.addressof(mid) + Slot.ptr.offset)
        proc = Process.attach_pid(os.getpid())
        try:
            chain = Chain([
                (ctypes.addressof(outer) + Slot.ptr.offset, 0),
                (ctypes.addressof(mid) + Slot.ptr.offset, 0),
            ])
            self.assertEqual(chain.resolve(proc), ctypes.addressof(target))
            self.assertEqual(chain.depth, 2)
            self.assertEqual(chain.total_offset, 0)
            self.assertIn("->", chain.describe(ctypes.addressof(target)))
        finally:
            proc.close()

    def test_chain_equality_and_hash(self):
        a = Chain([(0x1000, 0x10)])
        b = Chain([(0x1000, 0x10)])
        self.assertEqual(a, b)
        self.assertEqual(hash(a), hash(b))
        self.assertNotEqual(a, Chain([(0x1000, 0x20)]))


class ScanPointersTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proc = Process.attach_pid(os.getpid())

    @classmethod
    def tearDownClass(cls):
        cls.proc.close()

    def setUp(self):
        # one contiguous buffer so every address shares a memory region:
        # target u32 at +0x40, mid slot at +0x48 -> target,
        # outer slot at +0x50 -> mid slot, mid2 slot at +0x58 -> target-0x20
        self.layout = (ctypes.c_uint64 * 16)()
        base = ctypes.addressof(self.layout)
        self.taddr = base + 0x40
        self.mslot = base + 0x48
        self.oslot = base + 0x50
        self.mslot2 = base + 0x58
        ctypes.cast(self.taddr, ctypes.POINTER(ctypes.c_uint32))[0] = 0x12345678
        ptrs = ctypes.cast(self.mslot, ctypes.POINTER(ctypes.c_void_p))
        ptrs[0] = self.taddr          # mid -> target
        ptrs[1] = self.mslot         # outer -> mid slot
        ptrs[2] = self.taddr - 0x20  # mid2 -> 0x20 before target
        region = region_of(base)
        self.start, self.end = region.start, region.end

    def kwargs(self, **over):
        base = dict(start=self.start, end=self.end, max_offset=0x100,
                    writable_only=False)
        base.update(over)
        return base

    def test_finds_direct_pointer(self):
        chains = scan_pointers(self.proc, self.taddr, depth=1,
                               **self.kwargs())
        hit = [c for c in chains if c.steps == [(self.mslot, 0)]]
        self.assertTrue(hit, "no chain found for the mid slot")
        self.assertEqual(hit[0].resolve(self.proc), self.taddr)

    def test_finds_two_level_chain(self):
        chains = scan_pointers(self.proc, self.taddr, depth=2,
                               **self.kwargs())
        wanted = [(self.oslot, 0), (self.mslot, 0)]
        hit = [c for c in chains if c.steps == wanted]
        self.assertTrue(hit, "two level chain not found")
        self.assertEqual(hit[0].resolve(self.proc), self.taddr)

    def test_depth_ranking(self):
        chains = scan_pointers(self.proc, self.taddr, depth=2,
                               **self.kwargs())
        depths = [c.depth for c in chains]
        self.assertEqual(depths, sorted(depths, reverse=True))
        self.assertIn(2, depths)

    def test_offset_within_range(self):
        chains = scan_pointers(self.proc, self.taddr, depth=1,
                               **self.kwargs())
        hit = [c for c in chains if c.steps == [(self.mslot2, 0x20)]]
        self.assertTrue(hit, "offset chain not found")
        self.assertEqual(hit[0].resolve(self.proc), self.taddr)

    def test_max_offset_zero_needs_exact(self):
        chains = scan_pointers(self.proc, self.taddr, depth=1,
                               **self.kwargs(max_offset=0))
        self.assertFalse([c for c in chains if c.base_address == self.mslot2])
        self.assertTrue([c for c in chains
                         if c.steps == [(self.mslot, 0)]])

    def test_max_results_caps_output(self):
        chains = scan_pointers(self.proc, self.taddr, depth=1,
                               **self.kwargs(max_results=5))
        self.assertLessEqual(len(chains), 5)

    def test_no_cycle_in_chains(self):
        # a slot pointing at itself must not produce a cyclic chain
        target = ctypes.c_uint32(9)
        taddr = ctypes.addressof(target)
        slot = Slot(0, 0)
        saddr = ctypes.addressof(slot) + Slot.ptr.offset
        ctypes.cast(saddr, ctypes.POINTER(ctypes.c_void_p))[0] = saddr
        region = region_of(saddr)
        chains = scan_pointers(self.proc, saddr, depth=3,
                               start=region.start, end=region.end,
                               max_offset=0x100, writable_only=False)
        for chain in chains:
            addrs = chain.addresses
            self.assertEqual(len(addrs), len(set(addrs)))
        self.assertGreater(taddr, 0)  # keep alive

    def test_bad_args_raise(self):
        with self.assertRaises(ValueError):
            scan_pointers(self.proc, self.taddr, max_offset=-1)
        with self.assertRaises(ValueError):
            scan_pointers(self.proc, self.taddr, depth=0)


if __name__ == "__main__":
    unittest.main()
