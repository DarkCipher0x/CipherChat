"""The terminal look of CipherChat's setup: the DarkCipher Systems installer template (the same as ParallelPath's
server setup). 24-bit colours on a terminal; plain text when NO_COLOR is set or output isn't a terminal."""
import os
import re
import sys

ACCENT, WARM, OK, BAD, DIM, BOLD, RESET = ("\x1b[38;2;61;214;208m", "\x1b[38;2;242;166;90m", "\x1b[38;2;88;214;141m",
                                           "\x1b[38;2;242;102;122m", "\x1b[38;2;138;164;167m", "\x1b[1m", "\x1b[0m")
COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
if not COLOR:
    ACCENT = WARM = OK = BAD = DIM = BOLD = RESET = ""


class Cancelled(Exception):
    """The person stopped the setup (Ctrl+C, q, or answered no). Nothing after that point was changed."""


def p(text=""):
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def interactive():
    return sys.stdin.isatty() and sys.stdout.isatty()


def banner(sub, version):
    inner = 58
    line = "─" * inner
    p("\n  %s╭%s╮%s" % (ACCENT, line, RESET))
    p("  %s│%s  %sCipher%s%s%sChat%s  %s%s%s%s│%s" % (ACCENT, RESET, BOLD, RESET, BOLD, ACCENT, RESET, DIM,
                                                   (sub + "  " + version).ljust(inner - 14), RESET, ACCENT, RESET))
    p("  %s│%s  %s%s│%s" % (ACCENT, RESET, "End-to-end encrypted, post-quantum chat server".ljust(inner - 2), ACCENT, RESET))
    p("  %s│%s  %s%s%s%s│%s" % (ACCENT, RESET, DIM, "ML-KEM-1024 · ML-DSA-87 · AES-256-GCM · SHA-3".ljust(inner - 2), RESET, ACCENT, RESET))
    p("  %s╰%s╯%s" % (ACCENT, line, RESET))
    p("  %sBuilt by DarkCipher0x at DarkCipher Systems · MIT licence%s\n" % (DIM, RESET))


def section(title):
    p("\n  %s%s%s%s\n  %s%s%s" % (BOLD, ACCENT, title, RESET, DIM, "─" * len(title), RESET))


def kv(k, v):
    p("  %s%-14s%s %s" % (DIM, k, RESET, v))


MARKS = {"ok": (OK, "✓"), "warn": (WARM, "!"), "fail": (BAD, "✗"), "info": (ACCENT, "i")}


def checks(items):
    for c in items:
        colour, mark = MARKS[c.state]
        p("  %s%s%s %-38s %s%s%s" % (colour, mark, RESET, c.title, DIM, c.detail, RESET))


def note(text, colour=None):
    p("  %s%s%s" % (colour or DIM, text, RESET))


def _read(prompt):
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        p("")
        raise Cancelled()


def ask(label, default="", check=None):
    """A line of text (Enter keeps the default), asked again until check(answer) returns None."""
    while True:
        hint = " %s[%s]%s" % (DIM, default, RESET) if default else ""
        answer = _read("  %s›%s %s%s: " % (ACCENT, RESET, label, hint)).strip() or default
        problem = check(answer) if check else None
        if problem is None:
            return answer
        p("    %s%s%s" % (BAD, problem, RESET))


def ask_int(label, default, lo, hi):
    def check(s):
        return None if s.isdigit() and lo <= int(s) <= hi else "Enter a number from %d to %d." % (lo, hi)
    return int(ask(label, str(default), check))


def confirm(label, default=True):
    hint = "Y/n" if default else "y/N"
    while True:
        a = _read("  %s?%s %s %s[%s]%s " % (WARM, RESET, label, DIM, hint, RESET)).strip().lower()
        if a == "":
            return default
        if a in ("y", "yes"):
            return True
        if a in ("n", "no"):
            return False


class Feature:
    """One tick box: label, a line of help, and whether it's ticked. Unavailable ones show why and can't be ticked."""

    def __init__(self, key, label, help_, on, why_not=None):
        self.key, self.label, self.help, self.on, self.why_not = key, label, help_, on and not why_not, why_not


class _Keys:
    """Key presses in raw mode, one at a time even when several arrive together (fast typing, a paste): an arrow is
    one escape sequence, anything else one character. The terminal is raw from creation until close()."""

    def __init__(self, fd, old):
        import tty
        self.fd, self.old, self.pending = fd, old, ""
        tty.setraw(fd)

    def __iter__(self):
        while True:
            if not self.pending:
                self.pending = os.read(self.fd, 64).decode("utf-8", "replace")
                if not self.pending:
                    return
            m = re.match(r"\x1b\[[0-9;]*[A-Za-z~]|\x1bO[A-Za-z]|.", self.pending, re.S)
            key, self.pending = m.group(0), self.pending[m.end():]
            yield key.replace("\x1bO", "\x1b[")

    def close(self):
        import termios
        termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old)


def _keys():
    """Raw key presses, or None if this terminal can't do raw mode."""
    try:
        import termios
    except ImportError:
        return None
    fd = sys.stdin.fileno()
    try:
        return _Keys(fd, termios.tcgetattr(fd))
    except (termios.error, OSError):
        return None


def checklist(items):
    """↑/↓ move · space tick/untick · Enter continue. Falls back to typing numbers."""
    keys = _keys() if COLOR else None
    if keys is None:
        return _checklist_numbers(items)
    cur = 0

    def draw(first):
        out = [] if first else ["\x1b[%dA" % (len(items) * 2 + 1)]
        for i, it in enumerate(items):
            box = (ACCENT + "[✓]" + RESET) if it.on else (DIM + "[ ]" + RESET)
            ptr, label = (ACCENT + "›" + RESET + " ", BOLD + it.label + RESET) if i == cur else ("  ", it.label)
            help_ = it.why_not and (WARM + "not available: " + it.why_not + RESET) or (DIM + it.help + RESET)
            out.append("\x1b[2K  %s%s %s\r\n\x1b[2K        %s\r\n" % (ptr, box, label, help_))
        out.append("\x1b[2K  %s↑/↓ move · space tick/untick · Enter continue%s\r\n" % (DIM, RESET))
        sys.stdout.write("".join(out))
        sys.stdout.flush()
    draw(True)
    try:
        for k in keys:
            if k in ("\x1b[A", "k"):
                cur = (cur - 1) % len(items)
            elif k in ("\x1b[B", "j", "\t"):
                cur = (cur + 1) % len(items)
            elif k in (" ", "x"):
                if not items[cur].why_not:
                    items[cur].on = not items[cur].on
            elif k in ("\r", "\n"):
                return
            elif k in ("\x03", "q"):
                raise Cancelled()
            draw(False)
    finally:
        keys.close()


def _checklist_numbers(items):
    while True:
        for i, it in enumerate(items, 1):
            p("  %d. [%s] %s%s" % (i, "x" if it.on else " ", it.label, "  (not available: %s)" % it.why_not if it.why_not else ""))
        a = ask("Number to tick/untick, or Enter to continue")
        if a == "":
            return
        if a.isdigit() and 1 <= int(a) <= len(items) and not items[int(a) - 1].why_not:
            items[int(a) - 1].on = not items[int(a) - 1].on


def choose(options, default=0):
    """One of several (label, help) options: ↑/↓ and Enter, or a number. Returns the index."""
    keys = _keys() if COLOR else None
    if keys is None:
        for i, (label, help_) in enumerate(options, 1):
            p("  %d. %s  %s%s%s" % (i, label, DIM, help_, RESET))
        a = ask("Choose", str(default + 1), lambda s: None if s.isdigit() and 1 <= int(s) <= len(options) else "Enter 1 to %d." % len(options))
        return int(a) - 1
    cur = default

    def draw(first):
        out = [] if first else ["\x1b[%dA" % (len(options) * 2 + 1)]
        for i, (label, help_) in enumerate(options):
            dot = (ACCENT + "(●)" + RESET) if i == cur else (DIM + "( )" + RESET)
            ptr, lab = (ACCENT + "›" + RESET + " ", BOLD + label + RESET) if i == cur else ("  ", label)
            out.append("\x1b[2K  %s%s %s\r\n\x1b[2K        %s%s%s\r\n" % (ptr, dot, lab, DIM, help_, RESET))
        out.append("\x1b[2K  %s↑/↓ choose · Enter continue%s\r\n" % (DIM, RESET))
        sys.stdout.write("".join(out))
        sys.stdout.flush()
    draw(True)
    try:
        for k in keys:
            if k in ("\x1b[A", "k"):
                cur = (cur - 1) % len(options)
            elif k in ("\x1b[B", "j", "\t"):
                cur = (cur + 1) % len(options)
            elif k in ("\r", "\n"):
                return cur
            elif k in ("\x03", "q"):
                raise Cancelled()
            draw(False)
    finally:
        keys.close()
    return cur


class Reporter:
    """Prints the install steps as they run: "…" while running, then ✓ / – / ✗ in its place."""

    def __init__(self):
        self.title = ""

    def _clear(self):
        return "\r\x1b[2K" if COLOR else ""

    def step(self, title):
        self.title = title
        if COLOR:
            sys.stdout.write("  %s…%s %s" % (ACCENT, RESET, title))
            sys.stdout.flush()

    def done(self, detail=""):
        sys.stdout.write("%s  %s✓%s %s  %s%s%s\n" % (self._clear(), OK, RESET, self.title, DIM, detail, RESET))
        self.title = ""

    def skip(self, title, reason):
        sys.stdout.write("  %s– %s (%s)%s\n" % (DIM, title, reason, RESET))

    def fail(self, err):
        sys.stdout.write("%s  %s✗ %s%s\n" % (self._clear(), BAD, self.title, RESET))
        for line in str(err).splitlines():
            sys.stdout.write("      %s\n" % line)
        self.title = ""

    def info(self, text):
        sys.stdout.write("%s  %si%s %s\n" % (self._clear(), ACCENT, RESET, text))
        if COLOR and self.title:
            sys.stdout.write("  %s…%s %s" % (ACCENT, RESET, self.title))
        sys.stdout.flush()
