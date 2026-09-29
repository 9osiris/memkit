"""Freeze values: a background thread keeps rewriting a value on an interval."""
import threading

from memkit.types import check_type, pack


class Freezer:
    def __init__(self, process):
        self.process = process
        self._entries = {}
        self._errors = {}
        self._next_id = 1
        self._lock = threading.Lock()

    def add(self, address, type_name, value, interval=0.1):
        check_type(type_name)
        blob = pack(type_name, value)
        stop = threading.Event()
        with self._lock:
            fid = self._next_id
            self._next_id += 1

        def loop():
            while not stop.wait(interval):
                try:
                    self.process.write(address, blob)
                except OSError as e:
                    with self._lock:
                        count, _ = self._errors.get(fid, (0, ""))
                        self._errors[fid] = (count + 1, str(e))

        thread = threading.Thread(target=loop, daemon=True)
        with self._lock:
            self._entries[fid] = (stop, thread, address, type_name, value, interval)
        thread.start()
        return fid

    def errors(self, fid):
        """(failed_write_count, last_error) for one frozen value."""
        with self._lock:
            if fid not in self._entries:
                raise KeyError("no frozen value with id %d" % fid)
            return self._errors.get(fid, (0, ""))

    def remove(self, fid):
        with self._lock:
            entry = self._entries.pop(fid, None)
            self._errors.pop(fid, None)
        if entry is None:
            raise KeyError("no frozen value with id %d" % fid)
        stop, thread, _, _, _, _ = entry
        stop.set()
        thread.join(timeout=2)

    def stop_all(self):
        for fid in list(self._entries):
            self.remove(fid)

    def list(self):
        with self._lock:
            return {
                fid: (address, type_name, value, interval)
                for fid, (_, _, address, type_name, value, interval)
                in self._entries.items()
            }

    def __len__(self):
        return len(self._entries)
