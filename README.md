# memkit

a process memory toolkit for debugging and reverse engineering. attach to a
running process, list its memory regions, scan for values cheat-engine style,
follow pointer chains, read and write typed values, freeze values in place,
and dump regions to disk.

zero dependencies. python 3.8+, standard library only.

## quick start

```bash
python -m memkit --pid 1234
```

inside the cli:

```
memkit> regions
memkit> scan exact u32 100
memkit> results
memkit> scan decreased
memkit> read u32 0x7f3a2b1c
memkit> write u32 0x7f3a2b1c 999
memkit> freeze u32 0x7f3a2b1c 999 0.1
memkit> aob "48 8b ? ? 74 10"
memkit> strings 8
memkit> ptrscan 0x7f3a2b1c 3
memkit> dump 0x7f3a2b1c 4096 heap.bin
memkit> quit
```

batch mode runs a command file non-interactively:

```bash
python -m memkit --batch hunt.mk
```

## what is here

- value scans: multi-pass exact/changed/increased/decreased scans over every
  readable region (`memkit/scan.py`)
- array-of-bytes scans with `?` wildcards, alignment and chunked reads
  (`memkit/aob.py`, cli: `aob`)
- automatic pointer scanning: finds multi-level chains leading to a target
  address, with cycle protection and chain ranking (`memkit/ptrscan.py`,
  cli: `ptrscan`)
- string scans: ascii, utf-8 and utf-16le runs with overlap dedup so one
  byte range gets one reading (`memkit/strings.py`, cli: `strings`)
- struct dissector: describe c-like structs/unions/enums/bitfields in
  python, or parse real c declarations, then read them from raw bytes or a
  live process (`memkit/structs.py`)
- pe and elf parsers: headers, sections, imports, exports, symbols,
  relocations, notes (`memkit/pe.py`, `memkit/elf.py`)
- scan sessions: save scan results and value snapshots as json, reload
  them later, diff snapshots to see what changed (`memkit/session.py`,
  cli: `session ...`)
- scripting: run your own python files against the target through a
  convenience `target` api object (not a sandbox: scripts run as full
  python, only run ones you trust) (`memkit/scripting.py`, cli: `script`)
- curses hex viewer with goto, in-place hex editing and pointer following
  (`memkit/tui.py`, cli: `hexview`)
- typed reads/writes, pointer chain resolution, value freezing, region
  dumps (`memkit/process.py`, `memkit/pointer.py`, `memkit/freeze.py`,
  `memkit/dump.py`)

## python api

```python
from memkit import Process, Scanner, scan_pattern, scan_pointers

proc = Process.attach_pid(1234)
scanner = Scanner(proc, "u32")
print(scanner.scan_exact(100))          # first pass
print(scan_pattern(proc, "48 8b ? ?")) # aob hits
print(scan_pointers(proc, 0x7f3a2b1c, depth=3))  # pointer chains
proc.close()
```

scripts get a `target` object instead of raw process access:

```python
# patch.py, run with: memkit> script patch.py
for addr in target.scan("u32", 100):
    target.write("u32", addr, 999)
```

## platform notes

- linux: reads through `/proc/<pid>/maps` and `/proc/<pid>/mem`. you usually
  need to run as the same user as the target, or as root. the kernel's yama
  `ptrace_scope` setting matters too: with the common `scope=1` default you
  can only open your own process or processes you spawned (parent to child),
  anything else gives a clean permission error instead of garbage data.
- windows: uses `ReadProcessMemory` / `WriteProcessMemory` / `VirtualQueryEx`
  through ctypes. run elevated if the target needs it.
- macos: not supported, memkit raises a clean error instead of failing weirdly.

## how scans work

a scan is multi-pass. the first pass (`scan exact <type> <value>`, or
`scan init` to snapshot everything) walks every readable region in chunked
reads and records candidate addresses. every pass after that only re-reads
the candidates, so narrowing from millions of hits to a handful is fast.

- `scan exact` keeps candidates still equal to the value
- `scan changed` / `scan unchanged` compare against the previous snapshot
- `scan increased` / `scan decreased` compare numerically

typical flow: `scan exact u32 100`, go change the value in the target,
`scan decreased`, repeat until one address is left.

## license

do whatever you want with it.
