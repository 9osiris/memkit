"""Tests for scan sessions and snapshots."""
import ctypes
import json
import os
import tempfile
import unittest

from memkit.process import Process
from memkit.session import (
    FORMAT,
    ScanRecord,
    Session,
    Snapshot,
    take_snapshot,
)


class ScanRecordTest(unittest.TestCase):
    def test_add_and_lookup(self):
        session = Session("hunt")
        session.add_scan("coins", "u32", [(0x100, 10), (0x200, 10)])
        session.add_scan("coins", "u32", [(0x100, 20)])
        self.assertEqual(session.labels(), ["coins", "coins"])
        self.assertEqual(len(session.get_scans("coins")), 2)
        self.assertEqual(len(session.latest("coins")), 1)
        self.assertEqual(session.latest("coins").addresses, [0x100])

    def test_latest_missing_label(self):
        session = Session()
        with self.assertRaises(KeyError):
            session.latest("nope")

    def test_record_dict_roundtrip(self):
        record = ScanRecord("hp", "i32", [(1, -5), (2, 99)])
        clone = ScanRecord.from_dict(record.to_dict())
        self.assertEqual(record, clone)
        self.assertEqual(clone.addresses, [1, 2])

    def test_result_dict_input(self):
        record = ScanRecord("x", "u8", [{"address": 9, "value": 3}])
        self.assertEqual(record.results, [(9, 3)])

    def test_repr(self):
        self.assertIn("2 results", repr(ScanRecord("x", "u8", [(1, 2), (3, 4)])))


class SnapshotTest(unittest.TestCase):
    def test_diff_changed(self):
        old = Snapshot("u32", {0x100: 10, 0x200: 20})
        new = Snapshot("u32", {0x100: 15, 0x200: 20})
        diff = old.diff(new)
        self.assertEqual(diff["changed"], [(0x100, 10, 15)])
        self.assertEqual(diff["added"], [])
        self.assertEqual(diff["removed"], [])

    def test_diff_added_removed(self):
        old = Snapshot("u32", {0x100: 1})
        new = Snapshot("u32", {0x200: 2})
        diff = old.diff(new)
        self.assertEqual(diff["added"], [0x200])
        self.assertEqual(diff["removed"], [0x100])
        self.assertEqual(diff["changed"], [])

    def test_diff_type_mismatch(self):
        with self.assertRaises(ValueError):
            Snapshot("u32", {}).diff(Snapshot("f32", {}))

    def test_diff_unreadable(self):
        old = Snapshot("u32", {1: 1}, errors={2: "boom"})
        new = Snapshot("u32", {1: 1, 3: 3}, errors={4: "boom"})
        diff = old.diff(new)
        self.assertEqual(diff["unreadable"], [2, 4])
        self.assertEqual(diff["added"], [3])

    def test_snapshot_roundtrip(self):
        snap = Snapshot("u32", {1: 2}, errors={3: "nope"})
        clone = Snapshot.from_dict(snap.to_dict())
        self.assertEqual(snap, clone)


class TakeSnapshotTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proc = Process.attach_pid(os.getpid())

    @classmethod
    def tearDownClass(cls):
        cls.proc.close()

    def test_take_snapshot_live(self):
        buf = (ctypes.c_uint32 * 4)(10, 20, 30, 40)
        base = ctypes.addressof(buf)
        addrs = [base + i * 4 for i in range(4)]
        snap = take_snapshot(self.proc, addrs, "u32")
        self.assertEqual(snap.values, {addrs[i]: (i + 1) * 10
                                       for i in range(4)})
        self.assertEqual(snap.errors, {})
        # change one value and diff
        buf[2] = 99
        diff = snap.diff(take_snapshot(self.proc, addrs, "u32"))
        self.assertEqual(diff["changed"], [(addrs[2], 30, 99)])

    def test_unreadable_address_goes_to_errors(self):
        snap = take_snapshot(self.proc, [0x10], "u32")
        self.assertEqual(snap.values, {})
        self.assertIn(0x10, snap.errors)


class SessionFileTest(unittest.TestCase):
    def test_save_load_roundtrip(self):
        session = Session("hunt")
        session.add_scan("coins", "u32", [(0x100, 10), (0x200, 0xFFFFFFFF)])
        session.add_scan("name", "string", [(0x300, "héllo")])
        session.add_scan("raw", "bytes", [(0x400, b"\xde\xad\xbe\xef")])
        session.add_snapshot("s1", Snapshot("f32", {1: 2.5}))
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sub", "hunt.json")
            session.save(path)
            with open(path, encoding="utf-8") as f:
                raw = json.load(f)
            self.assertEqual(raw["format"], FORMAT)
            loaded = Session.load(path)
        self.assertEqual(loaded.name, "hunt")
        self.assertEqual(len(loaded), 2 + 1)
        coins = loaded.latest("coins")
        self.assertEqual(coins.results, [(0x100, 10), (0x200, 0xFFFFFFFF)])
        self.assertEqual(loaded.latest("raw").results,
                         [(0x400, b"\xde\xad\xbe\xef")])
        self.assertEqual(loaded.latest("name").results, [(0x300, "héllo")])
        snap = loaded.get_snapshot("s1")
        self.assertAlmostEqual(snap.values[1], 2.5)

    def test_load_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            Session.load("/nonexistent-dir/nope.json")

    def test_load_wrong_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.json")
            with open(path, "w") as f:
                json.dump({"format": "nope"}, f)
            with self.assertRaises(ValueError):
                Session.load(path)

    def test_add_snapshot_type_check(self):
        session = Session()
        with self.assertRaises(ValueError):
            session.add_snapshot("s", "not a snapshot")
        with self.assertRaises(KeyError):
            session.get_snapshot("missing")


if __name__ == "__main__":
    unittest.main()
