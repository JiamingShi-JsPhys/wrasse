"""Raw keys and redraw — stdlib only.

The session needs two things `input()` cannot do: show the matching commands
while you type, and let arrow keys move through a list. Both are ANSI redraws
over a raw key reader. Where that is not possible (no TTY, no VT support on
Windows) every entry point falls back to a plain `input()`, so a pipe still
works and nothing hangs.
"""

from __future__ import annotations

import os
import shutil
import sys

UP, DOWN, LEFT, RIGHT = "up", "down", "left", "right"
ENTER, TAB, ESC, BACKSPACE, DELETE, HOME, END = "enter", "tab", "esc", "backspace", "delete", "home", "end"

_WIN_KEYS = {"H": UP, "P": DOWN, "K": LEFT, "M": RIGHT, "G": HOME, "O": END, "S": DELETE,
             "R": "insert", "Q": "f2"}
_POSIX_KEYS = {"[A": UP, "[B": DOWN, "[C": RIGHT, "[D": LEFT, "[H": HOME, "[F": END,
               "[3~": DELETE, "OA": UP, "OB": DOWN, "OC": RIGHT, "OD": LEFT}


def _enable_vt() -> bool:
    """Windows only: without this the console prints escape codes literally."""
    if os.name != "nt":
        return True
    try:
        import ctypes
        handle = ctypes.windll.kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        enable_virtual_terminal = 0x0004
        return bool(ctypes.windll.kernel32.SetConsoleMode(handle, mode.value | enable_virtual_terminal))
    except Exception:
        return False


def usable() -> bool:
    """True when we can draw and read keys without an `input()` line."""
    try:
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            return False
    except (ValueError, OSError):
        return False
    return _enable_vt()


def getkey() -> str:
    """One key as a name or a single character. Raises KeyboardInterrupt on Ctrl-C."""
    if os.name == "nt":
        import msvcrt
        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):
            return _WIN_KEYS.get(msvcrt.getwch(), "")
        if ch == "\r":
            return ENTER
        if ch == "\t":
            return TAB
        if ch == "\x1b":
            return ESC
        if ch == "\x08":
            return BACKSPACE
        if ch == "\x04":
            return "eof"
        if ch == "\x03":
            raise KeyboardInterrupt
        return ch

    import select
    import termios
    import tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        first = os.read(fd, 1).decode("utf-8", "ignore")
        if first == "\x1b":
            seq = ""
            while select.select([fd], [], [], 0.02)[0]:
                seq += os.read(fd, 1).decode("utf-8", "ignore")
            return _POSIX_KEYS.get(seq, ESC)
        if first in ("\r", "\n"):
            return ENTER
        if first == "\t":
            return TAB
        if first in ("\x7f", "\x08"):
            return BACKSPACE
        if first == "\x04":
            return "eof"
        if not first:
            return "eof"
        return first
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def clear_lines(count: int) -> None:
    """Erase `count` lines below the cursor and come back to where we were."""
    if count <= 0:
        return
    for _ in range(count):
        sys.stdout.write("\x1b[B\x1b[2K")
    sys.stdout.write(f"\x1b[{count}A")


def fit(text: str, width: int) -> str:
    if width <= 0 or len(text) <= width:
        return text
    return text[: max(0, width - 1)] + "…"


def _size() -> tuple[int, int]:
    try:
        return shutil.get_terminal_size()
    except OSError:                      # not a terminal we can measure
        return os.terminal_size((80, 24))


def read_line(prompt: str, complete=None, width: int | None = None,
              limit: int | None = None) -> str:
    """A line with a scrolling dropdown of completions. Off a TTY, plain input()."""
    if complete is None or not usable():
        return input(prompt)

    buf: list[str] = []
    cursor = 0
    drawn = 0
    index = 0
    closed = False

    def matches() -> list[tuple[str, str]]:
        return [] if closed or not buf else complete("".join(buf))

    def draw() -> int:
        nonlocal drawn
        cols, lines_available = _size()
        cols = width or max(20, cols - 2)
        rows_visible = limit or max(4, min(12, lines_available - 6))
        clear_lines(drawn)
        sys.stdout.write("\x1b[2K\r" + prompt + "".join(buf))
        rows = matches()
        total = len(rows)
        # Keep the selection inside the window: the list scrolls, it never just ends.
        start = 0 if total <= rows_visible else min(max(0, index - rows_visible + 1),
                                                    total - rows_visible)
        out: list[str] = []
        if start:
            out.append("\x1b[90m" + f"  ↑ {start} more" + "\x1b[0m")
        for i in range(start, min(start + rows_visible, total)):
            name, text = rows[i]
            head = f"  {'›' if i == index else ' '} {name:<13}"
            body = fit(text, cols - len(head) - 1)
            if i == index:
                out.append("\x1b[36m" + head + "\x1b[0m\x1b[90m" + body + "\x1b[0m")
            else:
                out.append(head + "\x1b[90m" + body + "\x1b[0m")
        if start + rows_visible < total:
            out.append("\x1b[90m" + f"  ↓ {total - start - rows_visible} more" + "\x1b[0m")
        if out:
            sys.stdout.write("\n" + "\n".join(out))
        drawn = len(out)
        if drawn:
            sys.stdout.write(f"\x1b[{drawn}A")
        sys.stdout.write("\r\x1b[{}C".format(len(prompt) + cursor))
        sys.stdout.flush()
        return total

    while True:
        total = draw()
        if total:
            index = min(index, total - 1)
        key = getkey()
        if key == ENTER:
            choice = matches()[index][0] if total and index < total else None
            clear_lines(drawn)
            sys.stdout.write("\x1b[2K\r" + prompt + (choice or "".join(buf)) + "\n")
            sys.stdout.flush()
            return choice or "".join(buf)
        if key == TAB and total:
            buf = list(matches()[index][0])
            cursor = len(buf)
            closed = True
            continue
        if key == ESC:
            closed = True
            continue
        closed = False
        if key == UP and total:
            index = (index - 1) % total
            continue
        if key == DOWN and total:
            index = (index + 1) % total
            continue
        if key == "eof":
            raise EOFError
        if key == BACKSPACE:
            if cursor:
                del buf[cursor - 1]
                cursor -= 1
            index = 0
            continue
        if key == DELETE:
            if cursor < len(buf):
                del buf[cursor]
            index = 0
            continue
        if key == LEFT:
            cursor = max(0, cursor - 1)
            continue
        if key == RIGHT:
            cursor = min(len(buf), cursor + 1)
            continue
        if key == HOME:
            cursor = 0
            continue
        if key == END:
            cursor = len(buf)
            continue
        if isinstance(key, str) and len(key) == 1 and key.isprintable():
            buf.insert(cursor, key)
            cursor += 1
            index = 0
