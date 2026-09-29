"""Tests for the hex viewer. Only the pure formatting and navigation
functions are tested; the curses event loop cannot run headless."""
import unittest

from memkit.tui import (
    adjust_visible_top,
    apply_edit,
    clamp_cursor,
    decode_preview,
    format_row,
    move_cursor,
    parse_address,
    parse_hex_bytes,
    pointer_at,
    render_page,
    rows_for_height,
    status_text,
)


class FormatTest(unittest.TestCase):
    def test_format_row_basic(self):
        data = bytes(range(16))
        line = format_row(data, 0x1000, 0)
        self.assertTrue(line.startswith("0000000000001000"))
        self.assertIn("00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f", line)
        self.assertTrue(line.rstrip().endswith("|................|"))

    def test_format_row_ascii(self):
        data = b"ABCDEFGHIJKLMNOP"
        line = format_row(data, 0, 0)
        self.assertIn("|ABCDEFGHIJKLMNOP|", line)

    def test_format_row_second_row(self):
        data = bytes(32)
        line = format_row(data, 0x1000, 1)
        self.assertTrue(line.startswith("0000000000001010"))

    def test_format_row_short_tail(self):
        data = bytes(20)
        lines = render_page(data, 0, 2)
        self.assertEqual(len(lines), 2)
        self.assertIn("|....|", lines[1])

    def test_format_row_cursor_marks_byte(self):
        data = bytes([0x48, 0x8B, 0x00])
        line = format_row(data, 0, 0, cursor=0)
        self.assertIn("[48]", line)
        line = format_row(data, 0, 0, cursor=2)
        self.assertIn("[00]", line)
        line = format_row(data, 0, 0, cursor=99)
        self.assertNotIn("[", line.split("|")[0])

    def test_format_row_custom_width(self):
        data = bytes(8)
        line = format_row(data, 0x200, 0, bytes_per_row=8)
        self.assertTrue(line.startswith("0000000000000200"))

    def test_render_page_count(self):
        data = bytes(64)
        lines = render_page(data, 0x5000, 4)
        self.assertEqual(len(lines), 4)
        self.assertTrue(lines[3].startswith("0000000000005030"))

    def test_rows_for_height(self):
        self.assertEqual(rows_for_height(24), 22)
        self.assertEqual(rows_for_height(2), 1)


class CursorTest(unittest.TestCase):
    def test_moves(self):
        self.assertEqual(move_cursor(10, "left", 100), 9)
        self.assertEqual(move_cursor(10, "right", 100), 11)
        self.assertEqual(move_cursor(20, "up", 100), 4)
        self.assertEqual(move_cursor(20, "down", 100), 36)

    def test_row_home_end(self):
        self.assertEqual(move_cursor(20, "row_home", 100), 16)
        self.assertEqual(move_cursor(20, "row_end", 100), 31)

    def test_pages(self):
        self.assertEqual(move_cursor(100, "page_up", 1000, page_rows=4), 36)
        self.assertEqual(move_cursor(100, "page_down", 1000, page_rows=4), 164)

    def test_top_bottom(self):
        self.assertEqual(move_cursor(50, "top", 100), 0)
        self.assertEqual(move_cursor(50, "bottom", 100), 99)

    def test_clamping(self):
        self.assertEqual(move_cursor(0, "left", 100), 0)
        self.assertEqual(move_cursor(99, "right", 100), 99)
        self.assertEqual(move_cursor(5, "down", 10), 9)
        self.assertEqual(move_cursor(95, "page_down", 100), 99)

    def test_empty_buffer(self):
        self.assertEqual(move_cursor(10, "right", 0), 0)
        self.assertEqual(clamp_cursor(10, 0), 0)

    def test_bad_action(self):
        with self.assertRaises(ValueError):
            move_cursor(0, "sideways", 100)

    def test_custom_cols(self):
        self.assertEqual(move_cursor(10, "down", 100, cols=8), 18)


class ParseTest(unittest.TestCase):
    def test_parse_address(self):
        self.assertEqual(parse_address("0x1234"), 0x1234)
        self.assertEqual(parse_address("1234"), 1234)
        self.assertEqual(parse_address("0XAB"), 0xAB)
        self.assertEqual(parse_address("  0x10  "), 0x10)

    def test_parse_address_bad(self):
        for bad in ("", "xyz", "0x"):
            with self.assertRaises(ValueError):
                parse_address(bad)

    def test_parse_hex_bytes(self):
        self.assertEqual(parse_hex_bytes("48 8b 0f"), b"\x48\x8b\x0f")
        self.assertEqual(parse_hex_bytes("0x48 0X8B"), b"\x48\x8b")
        self.assertEqual(parse_hex_bytes("f"), b"\x0f")

    def test_parse_hex_bytes_bad(self):
        for bad in ("", "zz", "123", "48 8b zz"):
            with self.assertRaises(ValueError):
                parse_hex_bytes(bad)


class EditTest(unittest.TestCase):
    def test_apply_edit(self):
        buf = bytearray(b"\x00" * 16)
        apply_edit(buf, 4, b"\xde\xad")
        self.assertEqual(buf[4:6], b"\xde\xad")
        self.assertEqual(buf[0:4], b"\x00" * 4)

    def test_apply_edit_out_of_range(self):
        buf = bytearray(4)
        with self.assertRaises(ValueError):
            apply_edit(buf, 3, b"\x01\x02")
        with self.assertRaises(ValueError):
            apply_edit(buf, -1, b"\x01")

    def test_pointer_at(self):
        data = b"\x00" * 8 + b"\x78\x56\x34\x12\x00\x00\x00\x00"
        self.assertEqual(pointer_at(data, 8), 0x12345678)
        self.assertEqual(pointer_at(data, 8, size=4), 0x12345678)
        with self.assertRaises(ValueError):
            pointer_at(data, 14)
        with self.assertRaises(ValueError):
            pointer_at(data, 0, size=2)


class PreviewTest(unittest.TestCase):
    def test_decode_preview(self):
        data = b"\x01\x00\x00\x00" + b"hi!"
        prev = decode_preview(data, 0)
        self.assertEqual(prev["u32"], 1)
        self.assertEqual(prev["i32"], 1)
        self.assertEqual(prev["u8"], 1)
        self.assertEqual(prev["ascii"], "")

    def test_decode_preview_ascii(self):
        prev = decode_preview(b"hello\x00world", 0)
        self.assertEqual(prev["ascii"], "hello")

    def test_decode_preview_short_tail(self):
        prev = decode_preview(b"\x05", 0)
        self.assertEqual(prev["u8"], 5)
        self.assertNotIn("u32", prev)

    def test_decode_preview_float(self):
        import struct
        data = struct.pack("<f", 2.5)
        prev = decode_preview(data, 0)
        self.assertAlmostEqual(prev["f32"], 2.5)

    def test_status_text(self):
        text = status_text(0x1000, 20, 256)
        self.assertIn("0x0000000000001014", text)
        self.assertIn("row 1 col 4", text)

    def test_adjust_visible_top(self):
        self.assertEqual(adjust_visible_top(0, 0, 10), 0)
        # cursor far below scrolls just enough to show it
        self.assertEqual(adjust_visible_top(0, 20 * 16, 10), 11)
        # cursor above the window scrolls up
        self.assertEqual(adjust_visible_top(5, 3 * 16, 10), 3)
        # cursor inside the window keeps the top where it is
        self.assertEqual(adjust_visible_top(5, 7 * 16, 10), 5)
        self.assertEqual(adjust_visible_top(5, 5 * 16, 10), 5)


if __name__ == "__main__":
    unittest.main()
