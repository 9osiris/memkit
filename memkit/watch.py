"""Watchpoint-style polling: print a note whenever a typed value changes."""
import threading
import time

from memkit.types import check_type, unpack


class Watcher:
    def __init__(self, process):
        self.process = process
        self._entries = {}
        self._last = {}
        self._next_id = 1
        self._lock = threading.Lock()

    def add(self, address, type_name, interval=0.1):
        check_type(type_name)
        if interval <= 0:
            raise ValueError("interval must be positive")
        _, size = check_type(type_name)
        # first read is synchronous so a bad address fails fast
        first = unpack(type_name, self.process.read(address, size))
        stop = threading.Event()
        with self._lock:
            wid = self._next_id
            self._next_id += 1
            self._last[wid] = first

        def loop():
            last = first
            unreadable = False
            while not stop.wait(interval):
                try:
                    cur = unpack(type_name, self.process.read(address, size))
                except OSError:
                    if not unreadable:
                        print("watch %d: %#x unreadable, keeping an eye on it"
                              % (wid, address))
                        unreadable = True
                    continue
                if unreadable:
                    print("watch %d: %#x readable again" % (wid, address))
                    unreadable = False
                if cur != last:
                    stamp = time.strftime("%H:%M:%S")
                    print("watch %d: [%s] %#x: %s -> %s"
                          % (wid, stamp, address, last, cur))
                    last = cur
                    with self._lock:
                        self._last[wid] = cur

        thread = threading.Thread(target=loop, daemon=True)
        with self._lock:
            self._entries[wid] = (stop, thread, address, type_name, interval)
        thread.start()
        return wid

    def remove(self, wid):
        with self._lock:
            entry = self._entries.pop(wid, None)
            self._last.pop(wid, None)
        if entry is None:
            raise KeyError("no watch with id %d" % wid)
        stop, thread, _, _, _ = entry
        stop.set()
        thread.join(timeout=2)

    def stop_all(self):
        for wid in list(self._entries):
            self.remove(wid)

    def list(self):
        # wid -> (address, type_name, last seen value, interval)
        with self._lock:
            return {
                wid: (address, type_name, self._last.get(wid), interval)
                for wid, (_, _, address, type_name, interval)
                in self._entries.items()
            }

    def __len__(self):
        with self._lock:
            return len(self._entries)
