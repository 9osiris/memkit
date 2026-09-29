"""Scripting: run user python against a target through a convenience api.

Scripts are plain python files. They get one global, ``target``, a
ScriptTarget wrapping the attached process. This is not a sandbox:
scripts run with your full python and your privileges, so only run
scripts you trust, the same deal as cheat engine lua scripts.

Example script:

    hits = target.scan("u32", 100)
    for address in hits:
        target.write("u32", address, 999)
    print("patched", len(hits), "addresses")
"""
import os


class ScriptTarget:
    """The only object a script touches. It wraps a Process and exposes
    a curated set of operations: typed reads and writes, scans, string
    search, regions and snapshots."""

    def __init__(self, process):
        self._process = process

    @property
    def pid(self):
        return self._process.pid

    # reads and writes
    def read(self, type_name, address):
        return self._process.read_value(type_name, address)

    def write(self, type_name, address, value):
        self._process.write_value(type_name, address, value)

    def read_bytes(self, address, size):
        return self._process.read(address, size)

    def write_bytes(self, address, data):
        self._process.write(address, data)

    def read_pointer(self, address):
        return self._process.read_pointer(address)

    def read_string(self, address, max_length=256):
        return self._process.read_string(address, max_length)

    # regions
    def regions(self):
        from memkit.regions import list_regions
        return list_regions(self._process.pid)

    # scans
    def scan(self, type_name, value, start=None, end=None):
        """Exact value scan, returns a list of matching addresses."""
        from memkit.scan import Scanner
        scanner = Scanner(self._process, type_name)
        return list(scanner.scan_exact(value, start, end))

    def scan_aob(self, pattern, start=None, end=None):
        from memkit.aob import scan_pattern
        return list(scan_pattern(self._process, pattern, start, end))

    def find_strings(self, min_length=4, start=None, end=None):
        from memkit.strings import scan_strings
        return scan_strings(self._process, min_length,
                            start=start, end=end)

    def snapshot(self, addresses, type_name):
        from memkit.session import take_snapshot
        return take_snapshot(self._process, addresses, type_name)

    def __repr__(self):
        return "ScriptTarget(pid=%r)" % (self.pid,)


def run_script(source, process, script_name="<script>"):
    """Compile and run script source with ``target`` bound to a
    ScriptTarget for process. Returns the script's globals dict."""
    target = ScriptTarget(process)
    namespace = {
        "target": target,
        "__name__": "__memkit_script__",
        "__script__": script_name,
    }
    code = compile(source, script_name, "exec")
    exec(code, namespace)
    return namespace


def run_script_file(path, process):
    """Read a .py file and run it against process."""
    if not os.path.isfile(path):
        raise FileNotFoundError("no script at %r" % path)
    with open(path, "r", encoding="utf-8") as f:
        source = f.read()
    return run_script(source, process, script_name=path)
