"""Reading and (carefully) changing nginx configuration for CipherChat's setup.

The setup only ever does three things to a site that isn't CipherChat's own: add one marked include line inside a
server block, optionally change that block's ssl_ecdh_curve line so it offers post-quantum key exchange, and remove
exactly what it added. Every change is backed up first, checked with `nginx -t`, and put back if the check fails.
"""
import os
import re
import shutil
import subprocess
import time

MARK_BEGIN = "# >>> CipherChat (added by cipherchat-setup; `cipherchat-admin uninstall` removes it)"
MARK_END = "# <<< CipherChat"
LOCATIONS = "/etc/nginx/snippets/cipherchat-locations.conf"
PQ_CURVES = "X25519MLKEM768:X25519:secp384r1"
BACKUPS = "/var/lib/cipherchat-setup/nginx-backups"


class Token:
    __slots__ = ("kind", "text", "start", "end")

    def __init__(self, kind, text, start, end):
        self.kind, self.text, self.start, self.end = kind, text, start, end


def tokens(src):
    """Words, strings, ';', '{' and '}' with their offsets; comments skipped."""
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c.isspace():
            i += 1
        elif c == "#":
            while i < n and src[i] != "\n":
                i += 1
        elif c in "{};":
            yield Token(c, c, i, i + 1)
            i += 1
        elif c in "\"'":
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            yield Token("word", src[i + 1:j], i, j + 1)
            i = j + 1
        else:
            j = i
            while j < n and not src[j].isspace() and src[j] not in "{};#\"'":
                j += 2 if src[j] == "\\" else 1
            yield Token("word", src[i:j], i, j)
            i = j


class Directive:
    def __init__(self, name, args, start, end, children=None, open_=None, close=None):
        self.name, self.args, self.start, self.end = name, args, start, end
        self.children, self.open, self.close = children, open_, close   # blocks only


def parse(src):
    """The directive tree of one file. Raises ValueError on unbalanced braces."""
    stack, cur, words, first = [[]], None, [], None
    blocks = []
    for t in tokens(src):
        if t.kind == "word":
            if not words:
                first = t.start
            words.append(t.text)
        elif t.kind == ";":
            if words:
                stack[-1].append(Directive(words[0], words[1:], first, t.end))
            words = []
        elif t.kind == "{":
            if not words:
                raise ValueError("a block without a name")
            d = Directive(words[0], words[1:], first, None, [], t.start)
            stack[-1].append(d)
            stack.append(d.children)
            blocks.append(d)
            words = []
        else:
            if len(stack) == 1:
                raise ValueError("an extra closing brace")
            stack.pop()
            d = blocks.pop()
            d.close, d.end = t.start, t.end
    if len(stack) != 1:
        raise ValueError("a block isn't closed")
    return stack[0]


class Site:
    """One http server block: where it is and what it serves."""

    def __init__(self, path, d, src):
        self.path, self.block, self.src = path, d, src
        kids = d.children
        self.names = [a for c in kids if c.name == "server_name" for a in c.args]
        self.listens = [" ".join(c.args) for c in kids if c.name == "listen"]
        self.tls = any(re.search(r"(^|\s)(ssl|quic)(\s|$)", l) for l in self.listens) or any(c.name == "ssl_certificate" for c in kids)
        self.curves = next((c for c in kids if c.name == "ssl_ecdh_curve"), None)
        self.locations = [" ".join(c.args) for c in kids if c.name == "location"]
        self.cert = next((c.args[0] for c in kids if c.name == "ssl_certificate" and c.args), None)
        self.key = next((c.args[0] for c in kids if c.name == "ssl_certificate_key" and c.args), None)
        self.merged = MARK_BEGIN in src[d.open:d.close]

    @property
    def label(self):
        names = [n for n in self.names if n not in ("_", "")] or ["(default server)"]
        return "%s  (%s, %s)" % (", ".join(names[:3]), "https" if self.tls else "http only", self.path)

    def claims_chat(self):
        """True when the site already serves something under /chat (a DarkCipher portal does, for one)."""
        for loc in self.locations:
            path = loc.split()[-1]
            if path.startswith("/chat") and not self.merged:
                return True
        return False


def _walk(nodes, inside=()):
    for d in nodes:
        if d.children is not None:
            yield d, inside
            yield from _walk(d.children, inside + (d.name,))


def http_server_blocks(src):
    """server { } blocks that belong to http (not stream or mail): they have server_name or locations."""
    for d, inside in _walk(parse(src)):
        if d.name == "server" and "stream" not in inside and "mail" not in inside and "upstream" not in inside:
            if any(c.name in ("server_name", "location") for c in d.children):
                yield d


def dump():
    """`nginx -T`: every configuration file nginx reads, {path: text}. Raises RuntimeError if nginx -t fails."""
    r = subprocess.run(["nginx", "-T"], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("nginx's current configuration doesn't pass `nginx -t`:\n" + r.stderr.strip()[-800:])
    files, cur, buf = {}, None, []
    for line in r.stdout.splitlines(keepends=True):
        m = re.match(r"# configuration file (.+):\s*$", line)
        if m:
            if cur:
                files[cur] = "".join(buf)
            cur, buf = m.group(1), []
        elif cur:
            buf.append(line)
    if cur:
        files[cur] = "".join(buf)
    return files


def sites(files=None):
    """Every http server block nginx loads, read from the files on disk (positions are the file's own)."""
    out = []
    for path in sorted((files or dump()).keys()):
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8", errors="surrogateescape") as f:
            src = f.read()
        try:
            for d in http_server_blocks(src):
                out.append(Site(path, d, src))
        except ValueError:
            continue
    return out


def http_curves(files):
    """ssl_ecdh_curve values set outside any server block (the http level), which servers inherit."""
    vals = []
    for path, src in files.items():
        try:
            tree = parse(src)
        except ValueError:
            continue
        stack = [(tree, False)]
        while stack:
            nodes, in_server = stack.pop()
            for d in nodes:
                if d.children is not None:
                    stack.append((d.children, in_server or d.name == "server"))
                elif d.name == "ssl_ecdh_curve" and not in_server:
                    vals.append(" ".join(d.args))
    return vals


def offers_pq(curves):
    return curves is None or "X25519MLKEM768" in curves.upper().replace("-", "")


# ------------------------------------------------------------------ changes (always backed up and checked)
def backup(path):
    os.makedirs(BACKUPS, mode=0o700, exist_ok=True)
    dest = os.path.join(BACKUPS, path.strip("/").replace("/", "__") + "." + time.strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(path, dest)
    return dest


def _indent(src, at):
    line_start = src.rfind("\n", 0, at) + 1
    return re.match(r"[ \t]*", src[line_start:]).group(0)


def with_include(site, set_pq=False):
    """The site's file with CipherChat's include (and, if asked, a post-quantum ssl_ecdh_curve) in its server block."""
    src, d = site.src, site.block
    inner = _indent(src, d.start) + "    "
    lines = [MARK_BEGIN]
    if set_pq and site.curves is None:
        lines.append("ssl_ecdh_curve %s;" % PQ_CURVES)
    lines += ["include %s;" % LOCATIONS, MARK_END]
    text = "".join("%s%s\n" % (inner, l) for l in lines)
    close_line = src.rfind("\n", 0, d.close) + 1
    out = src[:close_line] + text + src[close_line:]
    if set_pq and site.curves is not None and not offers_pq(" ".join(site.curves.args)):
        c = site.curves
        out = out[:c.start] + ("ssl_ecdh_curve %s;" + CURVE_NOTE) % (PQ_CURVES, " ".join(c.args)) + out[c.end:]
    return out


CURVE_NOTE = "  # CipherChat: post-quantum first (was: %s)"


def without_include(src):
    """The file exactly as it was before CipherChat's setup: its marked lines out, any ssl_ecdh_curve it changed back."""
    src = re.sub(r"[ \t]*%s\n(?:.*\n)*?[ \t]*%s\n" % (re.escape(MARK_BEGIN), re.escape(MARK_END)), "", src)
    return re.sub(r"ssl_ecdh_curve [^;\n]*;" + re.escape(CURVE_NOTE).replace(re.escape("%s"), r"([^)\n]*)") + r"\)?",
                  lambda m: "ssl_ecdh_curve %s;" % m.group(1), src)


def test():
    r = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    return r.returncode == 0, (r.stderr or r.stdout).strip()


def apply(changes):
    """Writes {path: new text} (None deletes the file or link), then `nginx -t`. On failure every file goes back as it
    was and RuntimeError is raised. Returns the backups made. An edit through a symlink (sites-enabled -> sites-available)
    changes the file it points to and keeps the link."""
    changes = {(os.path.realpath(p) if t is not None else p): t for p, t in changes.items()}
    saved, links = {}, {}
    for path in changes:
        if os.path.islink(path):
            links[path] = os.readlink(path)
        saved[path] = backup(path) if os.path.isfile(path) and not os.path.islink(path) else None
    try:
        for path, text in changes.items():
            if text is None:
                if os.path.lexists(path):
                    os.remove(path)
                continue
            mode = os.stat(path).st_mode & 0o777 if os.path.exists(path) else 0o644
            tmp = path + ".cipherchat-new"
            with open(tmp, "w", encoding="utf-8", errors="surrogateescape") as f:
                f.write(text)
            os.chmod(tmp, mode)
            os.replace(tmp, path)
        ok, out = test()
        if not ok:
            raise RuntimeError("nginx refused the change, so it was undone:\n" + out[-800:])
    except BaseException:
        for path, b in saved.items():
            if os.path.lexists(path) and (b or path in links or changes[path] is not None):
                os.remove(path)
            if b:
                shutil.copy2(b, path)
            elif path in links:
                os.symlink(links[path], path)
        raise
    return [b for b in saved.values() if b]


def reload():
    subprocess.run(["systemctl", "reload", "nginx"], check=True, capture_output=True)
