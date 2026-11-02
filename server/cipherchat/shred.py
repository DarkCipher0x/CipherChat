"""Shredding old database copies (PREKEYS-DESIGN.md §4.5).

Deleting a wrap protects against a compromise after the deletion, but a copy of the database or a backup taken
earlier still holds it. So every stored wrap is sealed under a rolling storage key: a new one each day, kept in its
own file outside the database and its backups (CIPHERCHAT_SHRED_DIR, default <state dir>-shred), with the live wraps
re-sealed under the newest key and keys older than KEEP_DAYS erased. Once a key is gone, a database copy from that
time can't open its wraps, even with the server key and every passphrase.

A wrap is sealed with sealbox's construction (SHAKE256 keystream, HMAC-SHA3-256), bound to its row (sequence number
and recipient), so it can't be moved to another room key or person:

    z1.<day>.<nonce>.<ciphertext>.<tag>          (day = days since 1970-01-01, UTC)

What it doesn't do: a server that is itself malicious keeps whatever it likes (phase 2 covers that), and a wrap
someone copied while its key was still on the server opens with that key. Erasing a line from a file isn't erasing
it from every disk block (journals, SSD wear levelling), so the key file belongs on encrypted storage too.
"""
import os
import re
import secrets
import threading
import time

import sealbox

PREFIX = "z1"
KEEP_DAYS = 3                       # yesterday's backup still opens for this long (a restore right after a failure)
FILE = "shred.keys"
_LINE = re.compile(r"^\s*(\d{1,7})\s+([0-9a-f]{64})\s*$")

DIR = None
KEYS = {}                           # day -> 32-byte key
_lock = threading.Lock()
chat = None


def bind(chat_module, folder):
    """Load (or create) the key file and take over how chat.py stores wraps."""
    global chat, DIR
    chat, DIR = chat_module, folder
    os.makedirs(DIR, mode=0o700, exist_ok=True)
    _read()
    rotate()
    chat.WRAP_SEAL, chat.WRAP_OPEN = seal, open_
    if sweep not in chat.EXTRA_SWEEPS:
        chat.EXTRA_SWEEPS.append(sweep)


def today():
    return int(time.time()) // 86400


def _path():
    return os.path.join(DIR, FILE)


def _read():
    KEYS.clear()
    try:
        with open(_path()) as fh:
            for line in fh:
                m = _LINE.match(line)
                if m:
                    KEYS[int(m.group(1))] = bytes.fromhex(m.group(2))
    except FileNotFoundError:
        pass


def _write():
    """Replace the key file atomically, after overwriting the old one in place (best effort, see above)."""
    path, part = _path(), _path() + ".part"
    fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write("".join("%d %s\n" % (d, KEYS[d].hex()) for d in sorted(KEYS)))
        fh.flush()
        os.fsync(fh.fileno())
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as fh:
            fh.write(b"\0" * size)
            fh.flush()
            os.fsync(fh.fileno())
    except FileNotFoundError:
        pass
    os.replace(part, path)
    if hasattr(os, "O_DIRECTORY"):
        dfd = os.open(DIR, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


def rotate(now_day=None):
    """Make today's key if there isn't one and erase the ones past KEEP_DAYS. True if the file changed."""
    d = today() if now_day is None else now_day
    with _lock:
        changed = False
        if d not in KEYS:
            KEYS[d] = secrets.token_bytes(32)
            changed = True
        for old in [k for k in KEYS if k <= d - KEEP_DAYS]:
            del KEYS[old]
            changed = True
        if changed:
            _write()
        return changed


def current():
    return max(KEYS)


def _purpose(seq, user):
    return "chat-wrap|%d|%s" % (seq, user)


def seal(seq, user, w):
    day = current()
    purpose = _purpose(seq, user)
    return sealbox.seal_with(PREFIX, day, sealbox._derive(KEYS[day], purpose), w.encode(), purpose)


def _keys_for(purpose):
    def get(day):
        key = KEYS.get(day)
        if key is None:
            raise sealbox.SealError("that storage key has been erased")
        return sealbox._derive(key, purpose)
    return get


def open_(seq, user, stored):
    """The wrap as the client sent it, or None if its storage key is gone or it was changed (the client then reads
    it as deleted). Rows from before shredding (plain base64) are returned as they are until the sweep seals them."""
    if not stored.startswith(PREFIX + "."):
        return stored
    try:
        return sealbox.open_with(PREFIX, _keys_for(_purpose(seq, user)), stored, _purpose(seq, user)).decode()
    except (sealbox.SealError, UnicodeDecodeError):
        return None


def sweep(c, now_day=None):
    """Rotate, then re-seal every wrap that isn't under the newest key; wraps whose key is gone can't be opened by
    anyone any more, so their rows go too. Returns how many rows went."""
    rotate(now_day)
    day = current()
    fresh = "%s.%d.%%" % (PREFIX, day)
    gone = []
    rows = c.execute("SELECT seq, username, w FROM chat_wraps WHERE w NOT LIKE ?", (fresh,)).fetchall()
    for r in rows:
        w = open_(r["seq"], r["username"], r["w"])
        if w is None:
            gone.append((r["seq"], r["username"]))
        else:
            c.execute("UPDATE chat_wraps SET w=? WHERE seq=? AND username=?", (seal(r["seq"], r["username"], w), r["seq"], r["username"]))
    c.executemany("DELETE FROM chat_wraps WHERE seq=? AND username=?", gone)
    # per-device wraps (protocol 2), bound to "user|dev"
    dgone = []
    has_dev = c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='chat_dev_wraps'").fetchone()
    for r in c.execute("SELECT seq, username, dev, w FROM chat_dev_wraps WHERE w NOT LIKE ?", (fresh,)).fetchall() if has_dev else ():
        who = "%s|%s" % (r["username"], r["dev"])
        w = open_(r["seq"], who, r["w"])
        if w is None:
            dgone.append((r["seq"], r["username"], r["dev"]))
        else:
            c.execute("UPDATE chat_dev_wraps SET w=? WHERE seq=? AND username=? AND dev=?", (seal(r["seq"], who, w), r["seq"], r["username"], r["dev"]))
    if dgone:
        c.executemany("DELETE FROM chat_dev_wraps WHERE seq=? AND username=? AND dev=?", dgone)
    return len(gone) + len(dgone)
