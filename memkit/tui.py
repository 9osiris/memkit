"""Curses hex viewer.

All rendering and formatting lives in pure functions below so it can be
tested headless. Only HexViewer._main touches curses, and it stays thin:
it draws rows produced by format_row and translates key presses into
move_cursor actions and small commands.
"""
import struct

BYTES_PER_ROW = 16


def format_row(data, base_addr, row, bytes_per_row=BYTES_PER_ROW, cursor=None):
    """One hexdump row: address, hex bytes, ascii. cursor is an absolute
    offset into data; the byte under it renders as [48]."""
    offset = row * bytes_per_row
    chunk = bytes(data[offset:offset + bytes_per_row])
    addr = base_addr + offset
    cells = ["%02x" % b for b in chunk]
    if cursor is not None and 0 <= cursor - offset < len(chunk):
        cells[cursor - offset] = "[%s]" % cells[cursor - offset]
    groups = []
    for g in range(0, len(cells), 8):
        groups.append(" ".join(cells[g:g + 8]))
    hexpart = "  ".join(groups)
    full_width = bytes_per_row * 3
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    return "%016x  %-*s |%s|" % (addr, full_width, hexpart, ascii_part)


def render_page(data, base_addr, rows, bytes_per_row=BYTES_PER_ROW,
                cursor=None):
    """Format a page of rows. Returns a list of strings."""
    return [format_row(data, base_addr, row, bytes_per_row, cursor)
            for row in range(rows)]


def rows_for_height(screen_rows, reserved=2):
    # how many data rows fit, leaving room for status and prompt lines
    return max(1, screen_rows - reserved)


def clamp_cursor(cursor, size):
    if size <= 0:
        return 0
    return max(0, min(cursor, size - 1))


def move_cursor(cursor, action, size, cols=BYTES_PER_ROW, page_rows=16):
    """Move the cursor. Actions: left right up down row_home row_end
    page_up page_down top bottom. Result is clamped into the buffer."""
    if size <= 0:
        return 0
    if action == "left":
        cursor -= 1
    elif action == "right":
        cursor += 1
    elif action == "up":
        cursor -= cols
    elif action == "down":
        cursor += cols
    elif action == "row_home":
        cursor -= cursor % cols
    elif action == "row_end":
        cursor += cols - 1 - cursor % cols
    elif action == "page_up":
        cursor -= cols * page_rows
    elif action == "page_down":
        cursor += cols * page_rows
    elif action == "top":
        cursor = 0
    elif action == "bottom":
        cursor = size - 1
    else:
        raise ValueError("unknown cursor action %r" % action)
    return clamp_cursor(cursor, size)


def parse_address(text):
    """Parse 0x1234, 1234 or decimal into an int."""
    text = text.strip()
    if not text:
        raise ValueError("empty address")
    try:
        return int(text, 0)
    except ValueError:
        raise ValueError("bad address %r" % text)


def parse_hex_bytes(text):
    """Parse '48 8b 0f' into bytes. Tokens are 1 or 2 hex digits."""
    tokens = text.split()
    if not tokens:
        raise ValueError("no hex bytes given")
    out = bytearray()
    for token in tokens:
        token = token.strip()
        if token.lower().startswith("0x"):
            token = token[2:]
        if len(token) not in (1, 2):
            raise ValueError("bad hex byte %r" % token)
        try:
            out.append(int(token, 16))
        except ValueError:
            raise ValueError("bad hex byte %r" % token)
    return bytes(out)


def apply_edit(buf, offset, new_bytes):
    """Write new_bytes into a mutable buffer at offset, bounds checked."""
    if offset < 0 or offset + len(new_bytes) > len(buf):
        raise ValueError("edit at %#x out of range" % offset)
    buf[offset:offset + len(new_bytes)] = new_bytes


def pointer_at(data, offset, size=8):
    """Read a little-endian pointer value from data at offset."""
    if size == 8:
        fmt = "<Q"
    elif size == 4:
        fmt = "<I"
    else:
        raise ValueError("pointer size must be 4 or 8")
    if offset < 0 or offset + size > len(data):
        raise ValueError("pointer read out of range")
    return struct.unpack_from(fmt, bytes(data), offset)[0]


def decode_preview(data, offset):
    """Typed interpretations of the bytes at offset, for the status line."""
    data = bytes(data)
    out = {}

    def take(size):
        if offset + size <= len(data):
            return data[offset:offset + size]
        return None

    raw8 = take(8)
    if raw8 is not None:
        out["u64"] = struct.unpack("<Q", raw8)[0]
        out["i64"] = struct.unpack("<q", raw8)[0]
        out["f64"] = struct.unpack("<d", raw8)[0]
    raw4 = take(4)
    if raw4 is not None:
        out["u32"] = struct.unpack("<I", raw4)[0]
        out["i32"] = struct.unpack("<i", raw4)[0]
        out["f32"] = struct.unpack("<f", raw4)[0]
    raw2 = take(2)
    if raw2 is not None:
        out["u16"] = struct.unpack("<H", raw2)[0]
        out["i16"] = struct.unpack("<h", raw2)[0]
    raw1 = take(1)
    if raw1 is not None:
        out["u8"] = raw1[0]
        out["i8"] = struct.unpack("<b", raw1)[0]
    text = []
    for b in data[offset:offset + 16]:
        if 32 <= b < 127:
            text.append(chr(b))
        else:
            break
    out["ascii"] = "".join(text)
    return out


def status_text(base_addr, cursor, size, bytes_per_row=BYTES_PER_ROW):
    addr = base_addr + cursor
    return "0x%016x  byte %d/%d  row %d col %d" % (
        addr, cursor, size, cursor // bytes_per_row, cursor % bytes_per_row)


def adjust_visible_top(top, cursor, rows, bytes_per_row=BYTES_PER_ROW):
    # scroll the window so the cursor stays on screen
    cur_row = cursor // bytes_per_row
    if cur_row < top:
        top = cur_row
    elif cur_row >= top + rows:
        top = cur_row - rows + 1
    return max(0, top)


class HexViewer:
    """Hex + ascii viewer over a window of a process's memory.

    Loads window_size bytes at start_address, lets you move around,
    edit bytes in place, jump to addresses and follow pointers.
    """

    def __init__(self, process, start_address, window_size=0x10000,
                 bytes_per_row=BYTES_PER_ROW):
        self.process = process
        self.base = start_address
        self.window_size = window_size
        self.cols = bytes_per_row
        self.data = bytearray()
        self.cursor = 0
        self.top = 0
        self.message = ""

    def load(self):
        try:
            self.data = bytearray(self.process.read(self.base,
                                                    self.window_size))
        except OSError as e:
            self.data = bytearray()
            self.message = "read failed: %s" % e
        self.cursor = clamp_cursor(self.cursor, len(self.data))
        self.top = 0

    def run(self):
        import curses
        curses.wrapper(self._main)

    # the curses event loop, kept thin on purpose
    def _main(self, stdscr):
        import curses
        curses.curs_set(0)
        stdscr.keypad(True)
        self.load()
        while True:
            if self._draw(stdscr):
                break
            if self._handle_key(stdscr):
                break

    def _draw(self, stdscr):
        import curses
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        rows = rows_for_height(height)
        self.top = adjust_visible_top(self.top, self.cursor, rows, self.cols)
        top = self.top
        stdscr.addstr(0, 0, status_text(self.base, self.cursor,
                                       len(self.data), self.cols)[:width - 1],
                      curses.A_REVERSE)
        preview = decode_preview(self.data, self.cursor)
        bits = "u8=%d u32=%d i32=%d u64=%#x f32=%r ascii=%r" % (
            preview.get("u8", 0), preview.get("u32", 0),
            preview.get("i32", 0), preview.get("u64", 0),
            preview.get("f32", 0.0), preview.get("ascii", ""))
        if height > 2:
            stdscr.addstr(1, 0, bits[:width - 1])
        for i in range(rows):
            row = top + i
            offset = row * self.cols
            if offset >= len(self.data):
                break
            line = format_row(self.data, self.base, row, self.cols,
                              cursor=self.cursor)
            y = i + 2
            if y >= height - 1:
                break
            attr = curses.A_REVERSE if offset <= self.cursor < offset + self.cols else 0
            try:
                stdscr.addstr(y, 0, line[:width - 1], attr)
            except Exception:
                pass
        if self.message:
            try:
                stdscr.addstr(height - 1, 0,
                              self.message[:width - 1], curses.A_BOLD)
            except Exception:
                pass
            self.message = ""
        stdscr.refresh()
        return False

    def _prompt(self, stdscr, text):
        import curses
        height, width = stdscr.getmaxyx()
        curses.curs_set(1)
        curses.echo()
        try:
            stdscr.addstr(height - 1, 0, text[:width - 1])
            stdscr.clrtoeol()
            stdscr.refresh()
            answer = stdscr.getstr(height - 1, len(text), 64)
        finally:
            curses.noecho()
            curses.curs_set(0)
        if isinstance(answer, bytes):
            answer = answer.decode(errors="replace")
        return answer

    def _handle_key(self, stdscr):
        import curses
        key = stdscr.getch()
        rows = rows_for_height(stdscr.getmaxyx()[0])
        size = len(self.data)
        actions = {
            curses.KEY_LEFT: "left", ord("h"): "left",
            curses.KEY_RIGHT: "right", ord("l"): "right",
            curses.KEY_UP: "up", ord("k"): "up",
            curses.KEY_DOWN: "down", ord("j"): "down",
            curses.KEY_HOME: "row_home", ord("0"): "row_home",
            curses.KEY_END: "row_end", ord("$"): "row_end",
            curses.KEY_PPAGE: "page_up", ord("b"): "page_up",
            curses.KEY_NPAGE: "page_down", ord(" "): "page_down",
        }
        if key in actions:
            self.cursor = move_cursor(self.cursor, actions[key], size,
                                      self.cols, rows)
        elif key == ord("g"):
            self._cmd_goto(stdscr)
        elif key == ord("G"):
            self.cursor = move_cursor(self.cursor, "bottom", size,
                                      self.cols, rows)
        elif key == ord("e"):
            self._cmd_edit(stdscr)
        elif key == ord("p"):
            self._cmd_follow_pointer()
        elif key == ord("r"):
            self.load()
        elif key in (ord("q"), 27):
            return True
        return False

    def _cmd_goto(self, stdscr):
        answer = self._prompt(stdscr, "goto address: ")
        try:
            addr = parse_address(answer)
        except ValueError as e:
            self.message = str(e)
            return
        if self.base <= addr < self.base + len(self.data):
            self.cursor = addr - self.base
        else:
            self.base = addr
            self.cursor = 0
            self.load()

    def _cmd_edit(self, stdscr):
        addr = self.base + self.cursor
        current = self.data[self.cursor:self.cursor + 1].hex()
        answer = self._prompt(stdscr, "hex bytes at %#x [%s]: " % (addr,
                                                                  current))
        if not answer.strip():
            return
        try:
            new = parse_hex_bytes(answer)
        except ValueError as e:
            self.message = str(e)
            return
        try:
            self.process.write(addr, new)
        except OSError as e:
            self.message = "write failed: %s" % e
            return
        apply_edit(self.data, self.cursor, new)
        self.message = "wrote %d bytes at %#x" % (len(new), addr)

    def _cmd_follow_pointer(self):
        try:
            target = pointer_at(self.data, self.cursor)
        except ValueError as e:
            self.message = str(e)
            return
        if self.base <= target < self.base + len(self.data):
            self.cursor = target - self.base
        else:
            self.base = target
            self.cursor = 0
            self.load()
