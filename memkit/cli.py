"""Interactive memkit shell."""
import argparse
import shlex
import sys

from memkit import __version__
from memkit.dump import dump_region
from memkit.freeze import Freezer
from memkit.pointer import resolve
from memkit.process import Process, UnsupportedPlatformError, find_processes
from memkit.regions import list_regions
from memkit.scan import Scanner
from memkit.types import TYPES, parse_value

HELP = """commands:
  attach pid <pid>            attach to a process id
  attach name <name>          attach by process name (must match exactly one)
  regions                     list readable memory regions
  scan exact <type> <value>   first pass: find every match, or narrow existing
  scan init [<type>]          snapshot all values for changed/unchanged scans
  scan changed|unchanged|increased|decreased
  results [n]                 show up to n candidate addresses (default 20)
  clear                       drop scan results
  read <type> <addr>          read a typed value
  readstr <addr> [maxlen]     read a null-terminated string
  write <type> <addr> <value> write a typed value
  writestr <addr> <text>      write a null-terminated string
  pointer <base> <off...>     resolve a pointer chain
  freeze <type> <addr> <value> [interval]
  unfreeze <id>               stop a frozen value
  freezes                     list frozen values
  dump <addr> <size> <path>   dump a region to a file
  aob <pattern> [start] [end] array-of-bytes scan, e.g. aob "48 8b ? ?"
  strings [minlen] [start] [end]
                              scan for ascii/utf-8/utf-16le strings
  ptrscan <addr> <depth> [max_offset] [start] [end]
                              find pointer chains leading to addr
  script <path>               run a python script with `target` bound
  hexview <addr> [size]       open the curses hex viewer
  session new <name>          start a scan session
  session save <path>         save the session as json
  session load <path>         load a saved session
  session scan <label>        save current scan results into the session
  session snap <label>        snapshot values at current scan results
  session snapaddr <label> <type> <addr>...
                              snapshot values at explicit addresses
  session diff <label1> <label2>
                              diff two snapshots
  session list                list saved scans and snapshots
  help                        this text
  quit                        exit
types: %s
addresses and ints accept hex with a 0x prefix.""" % ", ".join(sorted(TYPES))


def parse_addr(text):
    return int(text, 0)


class Shell:
    def __init__(self):
        self.process = None
        self.scanner = None
        self.freezer = None
        self.session = None

    def need_process(self):
        if self.process is None:
            raise RuntimeError("not attached, use: attach pid <pid>")
        return self.process

    def need_scanner(self):
        if self.scanner is None:
            raise RuntimeError("no scan yet, use: scan exact <type> <value>")
        return self.scanner

    def need_session(self):
        if self.session is None:
            raise RuntimeError("no session, use: session new <name>")
        return self.session

    def cmd_attach(self, args):
        if len(args) != 2 or args[0] not in ("pid", "name"):
            print("usage: attach pid <pid> | attach name <name>")
            return
        if args[0] == "pid":
            proc = Process.attach_pid(int(args[1], 0))
        else:
            proc = Process.attach_name(args[1])
        if self.process is not None:
            self.process.close()
        self.process = proc
        self.freezer = Freezer(proc)
        self.scanner = None
        print("attached to pid %d" % proc.pid)

    def cmd_regions(self, args):
        proc = self.need_process()
        for r in list_regions(proc.pid):
            if r.readable:
                print("%#x-%#x %s %d bytes %s" % (r.start, r.end, r.perms, r.size, r.name))

    def cmd_scan(self, args):
        proc = self.need_process()
        if not args:
            print("usage: scan exact <type> <value> | scan init [type] | scan changed|...")
            return
        kind = args[0]
        if kind == "exact":
            if len(args) != 3:
                print("usage: scan exact <type> <value>")
                return
            type_name, value = args[1], parse_value(args[1], args[2])
            if self.scanner is None or self.scanner.type_name != type_name:
                self.scanner = Scanner(proc, type_name)
            found = self.scanner.scan_exact(value)
            print("%d candidates" % len(found))
        elif kind == "init":
            type_name = args[1] if len(args) > 1 else "u32"
            self.scanner = Scanner(proc, type_name)
            self.scanner.scan_initial()
            print("%d values snapshotted" % len(self.scanner))
        elif kind in ("changed", "unchanged", "increased", "decreased"):
            found = getattr(self.need_scanner(), "scan_" + kind)()
            print("%d candidates" % len(found))
        else:
            print("unknown scan kind: %s" % kind)

    def cmd_results(self, args):
        scanner = self.need_scanner()
        n = int(args[0]) if args else 20
        for addr in scanner.candidates[:n]:
            print("%#x" % addr)
        if len(scanner) > n:
            print("... and %d more" % (len(scanner) - n))

    def cmd_clear(self, args):
        if self.scanner:
            self.scanner.clear()
        print("scan cleared")

    def cmd_read(self, args):
        proc = self.need_process()
        if len(args) != 2:
            print("usage: read <type> <addr>")
            return
        print(proc.read_value(args[0], parse_addr(args[1])))

    def cmd_readstr(self, args):
        proc = self.need_process()
        if not 1 <= len(args) <= 2:
            print("usage: readstr <addr> [maxlen]")
            return
        maxlen = int(args[1]) if len(args) == 2 else 256
        print(proc.read_string(parse_addr(args[0]), maxlen))

    def cmd_write(self, args):
        proc = self.need_process()
        if len(args) != 3:
            print("usage: write <type> <addr> <value>")
            return
        proc.write_value(args[0], parse_addr(args[1]), parse_value(args[0], args[2]))
        print("wrote %s to %#x" % (args[2], parse_addr(args[1])))

    def cmd_writestr(self, args):
        proc = self.need_process()
        if len(args) < 2:
            print("usage: writestr <addr> <text>")
            return
        proc.write_string(parse_addr(args[0]), " ".join(args[1:]))
        print("wrote string to %#x" % parse_addr(args[0]))

    def cmd_pointer(self, args):
        proc = self.need_process()
        if len(args) < 1:
            print("usage: pointer <base> <off...>")
            return
        base = parse_addr(args[0])
        offsets = [int(a, 0) for a in args[1:]]
        print("%#x" % resolve(proc, base, offsets))

    def cmd_freeze(self, args):
        proc = self.need_process()
        if not 3 <= len(args) <= 4:
            print("usage: freeze <type> <addr> <value> [interval]")
            return
        interval = float(args[3]) if len(args) == 4 else 0.1
        fid = self.freezer.add(
            parse_addr(args[1]), args[0], parse_value(args[0], args[2]), interval
        )
        print("frozen as id %d" % fid)

    def cmd_unfreeze(self, args):
        self.need_process()
        if len(args) != 1:
            print("usage: unfreeze <id>")
            return
        self.freezer.remove(int(args[0]))
        print("unfrozen")

    def cmd_freezes(self, args):
        self.need_process()
        frozen = self.freezer.list()
        if not frozen:
            print("nothing frozen")
            return
        for fid, (addr, type_name, value, interval) in frozen.items():
            print("%d: %s %#x = %s every %ss" % (fid, type_name, addr, value, interval))

    def cmd_dump(self, args):
        proc = self.need_process()
        if len(args) != 3:
            print("usage: dump <addr> <size> <path>")
            return
        dump_region(proc, parse_addr(args[0]), int(args[1], 0), args[2])
        print("dumped %s bytes to %s" % (args[1], args[2]))

    def cmd_aob(self, args):
        proc = self.need_process()
        if not 1 <= len(args) <= 3:
            print("usage: aob <pattern> [start] [end]")
            return
        from memkit.aob import scan_pattern
        start = parse_addr(args[1]) if len(args) > 1 else None
        end = parse_addr(args[2]) if len(args) > 2 else None
        hits = list(scan_pattern(proc, args[0], start, end))
        for addr in hits[:20]:
            print("%#x" % addr)
        print("%d hits" % len(hits))

    def cmd_strings(self, args):
        proc = self.need_process()
        if len(args) > 3:
            print("usage: strings [minlen] [start] [end]")
            return
        from memkit.strings import scan_strings
        minlen = int(args[0]) if len(args) > 0 else 4
        start = parse_addr(args[1]) if len(args) > 1 else None
        end = parse_addr(args[2]) if len(args) > 2 else None
        hits = scan_strings(proc, minlen, start=start, end=end)
        for hit in hits[:20]:
            shown = hit.value if len(hit.value) <= 60 else hit.value[:57] + "..."
            print("%#x [%s] %s" % (hit.address, hit.encoding, shown))
        print("%d strings" % len(hits))

    def cmd_ptrscan(self, args):
        proc = self.need_process()
        if not 2 <= len(args) <= 5:
            print("usage: ptrscan <addr> <depth> [max_offset] [start] [end]")
            return
        from memkit.ptrscan import scan_pointers
        target = parse_addr(args[0])
        depth = int(args[1], 0)
        max_offset = int(args[2], 0) if len(args) > 2 else 0x1000
        start = parse_addr(args[3]) if len(args) > 3 else None
        end = parse_addr(args[4]) if len(args) > 4 else None
        chains = scan_pointers(proc, target, max_offset=max_offset,
                               depth=depth, start=start, end=end)
        for chain in chains[:20]:
            print(chain.describe())
        print("%d chains" % len(chains))

    def cmd_script(self, args):
        proc = self.need_process()
        if len(args) != 1:
            print("usage: script <path>")
            return
        from memkit.scripting import run_script_file
        run_script_file(args[0], proc)
        print("ran %s" % args[0])

    def cmd_hexview(self, args):
        proc = self.need_process()
        if not 1 <= len(args) <= 2:
            print("usage: hexview <addr> [size]")
            return
        try:
            from memkit.tui import HexViewer
        except ImportError as e:
            print("hexview needs curses: %s" % e)
            return
        size = int(args[1], 0) if len(args) == 2 else 0x10000
        HexViewer(proc, parse_addr(args[0]), size).run()

    def cmd_session(self, args):
        if not args:
            print("usage: session new|save|load|scan|snap|snapaddr|diff|list ...")
            return
        handler = getattr(self, "cmd_session_" + args[0], None)
        if handler is None:
            print("unknown session command: %s" % args[0])
            return
        handler(args[1:])

    def cmd_session_new(self, args):
        from memkit.session import Session
        self.session = Session(args[0] if args else "session")
        print("new session %r" % self.session.name)

    def cmd_session_save(self, args):
        session = self.need_session()
        if len(args) != 1:
            print("usage: session save <path>")
            return
        session.save(args[0])
        print("saved to %s" % args[0])

    def cmd_session_load(self, args):
        from memkit.session import Session
        if len(args) != 1:
            print("usage: session load <path>")
            return
        self.session = Session.load(args[0])
        print("loaded session %r" % self.session.name)

    def cmd_session_scan(self, args):
        # save current scan candidates as a labeled scan record
        session, proc, scanner = self.need_session(), self.need_process(), self.need_scanner()
        if len(args) != 1:
            print("usage: session scan <label>")
            return
        addresses = scanner.candidates[:10000]
        results = [(a, proc.read_value(scanner.type_name, a))
                   for a in addresses]
        session.add_scan(args[0], scanner.type_name, results)
        print("saved %d results as %r" % (len(results), args[0]))

    def cmd_session_snap(self, args):
        # snapshot values at the current scan candidates
        from memkit.session import take_snapshot
        session, scanner = self.need_session(), self.need_scanner()
        if len(args) != 1:
            print("usage: session snap <label>")
            return
        snap = take_snapshot(self.need_process(),
                             scanner.candidates[:10000], scanner.type_name)
        session.add_snapshot(args[0], snap)
        print("snapshot %r: %d values" % (args[0], len(snap)))

    def cmd_session_snapaddr(self, args):
        from memkit.session import take_snapshot
        session = self.need_session()
        if len(args) < 3:
            print("usage: session snapaddr <label> <type> <addr>...")
            return
        label, type_name = args[0], args[1]
        addresses = [parse_addr(a) for a in args[2:]]
        snap = take_snapshot(self.need_process(), addresses, type_name)
        session.add_snapshot(label, snap)
        print("snapshot %r: %d values" % (label, len(snap)))

    def cmd_session_diff(self, args):
        session = self.need_session()
        if len(args) != 2:
            print("usage: session diff <label1> <label2>")
            return
        old = session.get_snapshot(args[0])
        new = session.get_snapshot(args[1])
        diff = old.diff(new)
        for addr, before, after in diff["changed"]:
            print("%#x: %r -> %r" % (addr, before, after))
        for addr in diff["added"]:
            print("%#x: added" % addr)
        for addr in diff["removed"]:
            print("%#x: removed" % addr)
        print("%d changed, %d added, %d removed" % (len(diff["changed"]),
                                                    len(diff["added"]),
                                                    len(diff["removed"])))

    def cmd_session_list(self, args):
        session = self.need_session()
        for record in session.scans:
            print("scan %r: %s %d results" % (record.label,
                                              record.value_type,
                                              len(record)))
        for label, snap in session.snapshots:
            print("snapshot %r: %s %d values" % (label, snap.value_type,
                                                 len(snap)))
        if not session.scans and not session.snapshots:
            print("session is empty")

    def execute(self, line):
        """Run one command line. Returns False when the shell should exit."""
        try:
            parts = shlex.split(line)
        except ValueError as e:
            print("parse error: %s" % e)
            return True
        if not parts:
            return True
        cmd, args = parts[0], parts[1:]
        if cmd in ("quit", "exit"):
            return False
        if cmd == "help":
            print(HELP)
            return True
        handler = getattr(self, "cmd_" + cmd, None)
        if handler is None:
            print("unknown command: %s" % cmd)
            return True
        try:
            handler(args)
        except Exception as e:
            print("error: %s" % e)
        return True

    def run(self):
        print("memkit %s, type 'help' for commands" % __version__)
        while True:
            try:
                line = input("memkit> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not self.execute(line):
                break
        self._cleanup()

    def run_batch(self, path):
        """Run commands from a file, one per line. # starts a comment."""
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for lineno, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if not self.execute(line):
                break
        self._cleanup()
        return 0

    def _cleanup(self):
        if self.freezer is not None:
            self.freezer.stop_all()
        if self.process is not None:
            self.process.close()
            self.process = None


def main(argv=None):
    parser = argparse.ArgumentParser(prog="memkit", description="process memory toolkit")
    parser.add_argument("--pid", type=int, default=None)
    parser.add_argument("--name", default=None)
    parser.add_argument("--batch", default=None,
                        help="run commands from a file non-interactively")
    ns = parser.parse_args(argv)
    shell = Shell()
    try:
        if ns.pid is not None:
            shell.cmd_attach(["pid", str(ns.pid)])
        elif ns.name is not None:
            shell.cmd_attach(["name", ns.name])
        if ns.batch is not None:
            return shell.run_batch(ns.batch)
    except FileNotFoundError as e:
        print("batch file not found: %s" % e, file=sys.stderr)
        return 1
    except (OSError, ProcessLookupError, UnsupportedPlatformError) as e:
        print("attach failed: %s" % e, file=sys.stderr)
        return 1
    shell.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
