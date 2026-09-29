"""Scan sessions and memory snapshots.

A Session collects labeled scan results and snapshots in memory and
saves them as JSON so a hunt can continue later. Snapshots record the
values at a set of addresses; diffing two snapshots shows what changed.
"""
import json
import os
from datetime import datetime, timezone

FORMAT = "memkit-session/1"


def _utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _encode_value(value):
    if isinstance(value, bytes):
        return {"__bytes__": value.hex()}
    return value


def _decode_value(value):
    if isinstance(value, dict) and "__bytes__" in value:
        return bytes.fromhex(value["__bytes__"])
    return value


def _norm_result(result):
    # accept (address, value) tuples or {"address":.., "value":..} dicts
    if isinstance(result, dict):
        return (result["address"], result["value"])
    address, value = result
    return (address, value)


class ScanRecord:
    """One labeled scan: addresses matched for a value type."""
    def __init__(self, label, value_type, results, time=None):
        self.label = label
        self.value_type = value_type
        self.results = [_norm_result(r) for r in results]
        self.time = time or _utcnow()

    @property
    def addresses(self):
        return [address for address, _ in self.results]

    def to_dict(self):
        return {
            "label": self.label,
            "value_type": self.value_type,
            "time": self.time,
            "results": [[a, _encode_value(v)] for a, v in self.results],
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            data["label"],
            data["value_type"],
            [(a, _decode_value(v)) for a, v in data["results"]],
            data.get("time"),
        )

    def __len__(self):
        return len(self.results)

    def __eq__(self, other):
        return (isinstance(other, ScanRecord)
                and self.label == other.label
                and self.value_type == other.value_type
                and self.results == other.results)

    def __repr__(self):
        return "ScanRecord(%r, %r, %d results)" % (self.label,
                                                   self.value_type,
                                                   len(self.results))


class Snapshot:
    """Values read at a set of addresses at one point in time."""
    def __init__(self, value_type, values, errors=None, time=None):
        self.value_type = value_type
        self.values = dict(values)
        self.errors = dict(errors or {})
        self.time = time or _utcnow()

    def diff(self, other):
        """Compare an older snapshot (self) to a newer one (other).

        Returns a dict with changed (address, old, new) triples,
        added and removed address lists, and addresses that failed
        to read in either snapshot."""
        if self.value_type != other.value_type:
            raise ValueError("cannot diff %r against %r snapshots"
                             % (self.value_type, other.value_type))
        changed, added, removed = [], [], []
        for address, new_value in other.values.items():
            if address in self.values:
                if self.values[address] != new_value:
                    changed.append((address, self.values[address], new_value))
            else:
                added.append(address)
        for address in self.values:
            if address not in other.values:
                removed.append(address)
        unreadable = sorted(set(self.errors) | set(other.errors))
        return {
            "changed": sorted(changed),
            "added": sorted(added),
            "removed": sorted(removed),
            "unreadable": unreadable,
        }

    def to_dict(self):
        return {
            "value_type": self.value_type,
            "time": self.time,
            "values": [[a, _encode_value(v)] for a, v in self.values.items()],
            "errors": [[a, e] for a, e in self.errors.items()],
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            data["value_type"],
            {a: _decode_value(v) for a, v in data["values"]},
            {a: e for a, e in data.get("errors", [])},
            data.get("time"),
        )

    def __len__(self):
        return len(self.values)

    def __eq__(self, other):
        return (isinstance(other, Snapshot)
                and self.value_type == other.value_type
                and self.values == other.values
                and self.errors == other.errors)


def take_snapshot(process, addresses, value_type):
    """Read value_type at each address. Unreadable addresses land in
    the snapshot's errors instead of aborting the whole snapshot."""
    values, errors = {}, {}
    for address in addresses:
        try:
            values[address] = process.read_value(value_type, address)
        except (OSError, ValueError) as e:
            errors[address] = str(e)
    return Snapshot(value_type, values, errors)


class Session:
    """A named collection of scan records and snapshots on disk as JSON."""
    def __init__(self, name="session"):
        self.name = name
        self.created = _utcnow()
        self.scans = []
        self.snapshots = []  # list of (label, Snapshot)

    def add_scan(self, label, value_type, results):
        record = ScanRecord(label, value_type, results)
        self.scans.append(record)
        return record

    def add_snapshot(self, label, snapshot):
        if not isinstance(snapshot, Snapshot):
            raise ValueError("expected a Snapshot")
        self.snapshots.append((label, snapshot))
        return snapshot

    def labels(self):
        return [record.label for record in self.scans]

    def get_scans(self, label):
        return [r for r in self.scans if r.label == label]

    def latest(self, label):
        matches = self.get_scans(label)
        if not matches:
            raise KeyError("no scan labeled %r" % label)
        return matches[-1]

    def get_snapshot(self, label):
        for snap_label, snapshot in self.snapshots:
            if snap_label == label:
                return snapshot
        raise KeyError("no snapshot labeled %r" % label)

    def to_dict(self):
        return {
            "format": FORMAT,
            "name": self.name,
            "created": self.created,
            "scans": [r.to_dict() for r in self.scans],
            "snapshots": [[label, snap.to_dict()]
                          for label, snap in self.snapshots],
        }

    def save(self, path):
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("format") != FORMAT:
            raise ValueError("%r is not a memkit session file" % path)
        session = cls(data.get("name", "session"))
        session.created = data.get("created", session.created)
        session.scans = [ScanRecord.from_dict(r) for r in data["scans"]]
        session.snapshots = [(label, Snapshot.from_dict(s))
                             for label, s in data["snapshots"]]
        return session

    def __len__(self):
        return len(self.scans)

    def __repr__(self):
        return "Session(%r, %d scans, %d snapshots)" % (self.name,
                                                        len(self.scans),
                                                        len(self.snapshots))
