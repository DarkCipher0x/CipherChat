"""DarkCipher secure chat: the server half of the end-to-end encrypted, post-quantum chat (/admin/api/chat/*).

The server is a store-and-forward relay. It never sees a plaintext message, a room key or a private key: every
key is made, used and kept in the members' browsers (portal chat/crypto.js), and the server only holds what they
upload, which is public keys, ciphertext and signatures. See docs/CHAT.md for the protocol and threat model.

What the server does decide (and enforces on every request, like the rest of the portal):
  - who may use the chat at all (permission chat.access.use) and create rooms (chat.rooms.create);
  - room membership, and that only members receive a room's items;
  - that an upload is well formed: sizes, base64, the plaintext header fields (room, epoch, sender) match the
    request and the signed-in user, and a new room key ("epoch") is wrapped for exactly the members who should
    get it. The browsers check the cryptography (signatures, owner certificates, key commitments) themselves,
    so a compromised server can withhold or drop, but not forge, read or silently re-key.

Identities: each member's browser creates one hybrid identity (ML-DSA-87 + Ed25519 to sign, ML-KEM-1024 + X25519
to receive keys). Its private part is stored here only sealed with the member's chat passphrase (Argon2id) AND a
per-user "server key share" derived from the storage encryption key, so a copy of the database alone (a backup, a
rebuild kit) can't even be guessed at offline. The platform owner certifies each member's identity after
comparing safety numbers out of band; members trust identities through those certificates.

Long polling (GET poll) waits up to POLL_WAIT seconds for new items, so a chat page costs one request per ~25s
when idle. Polls do not count as activity for the portal's idle sign-out.
"""
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sys
import threading
import time

import authz
from authz import audit, tx, is_owner, OWNER

core = None          # the server module, bound at start-up (db, now, STATE_DIR)
storage = None       # the storage module (its KEYRING holds the key the server key share is derived from)


def bind(server_module, storage_module):
    global core, storage
    core, storage = server_module, storage_module


# ------------------------------------------------------------------------------------------- limits
# Byte sizes of the algorithms the browsers use (FIPS 203 / FIPS 204 / RFC 7748 / RFC 8032).
KEM_PQ_PK, KEM_EC_PK, SIG_PQ_PK, SIG_EC_PK = 1568, 32, 2592, 32
SIG_LEN = 4627 + 64                     # ML-DSA-87 signature || Ed25519 signature
WRAP_LEN = 1568 + 32 + 12 + 32 + 16     # ML-KEM-1024 ciphertext || X25519 ephemeral || nonce || AES-256-GCM(32-byte key)
HEADER_MAX = 2048                       # signed plaintext header of a message (bytes)
EPOCH_HEADER_MAX = 64 * 1024            # signed header of a room key (has one line per recipient)
CIPHER_MAX = 12 + 16384 + 16 + 16       # nonce || padded plaintext (largest bucket 16 KiB) || tag (+ slack)
BACKUP_MAX = 4096                       # sealed private identity (seeds, pinned owner fingerprint)
BODY_MAX = 256 * 1024                   # one chat API request (nginx allows the same)
MAX_MEMBERS = 64                        # per room (a room key is wrapped once per member)
MAX_ROOMS = 200                         # rooms + direct messages per user
POLL_WAIT = 25                          # seconds a poll waits for news (nginx proxy_read_timeout is 40s)
POLL_PATH = "/admin/api/chat/poll"      # the one request that doesn't count as activity (server.has_2fa touch=False)
POLL_PATHS = (POLL_PATH, "/chat/api/poll")   # ...as the service sees it, and as nginx's auth check reports the chat portal's
DEVICE_MAX = 10                         # paired phones per user
DEVICE_DAYS = 180                       # a pairing ends after this long whatever happens
DEVICE_IDLE_DAYS = 30                   # ...or after this long unused
DEVICE_BAD = "This phone's pairing isn't valid any more. Sign in and pair it again."
# Attachments (files, pictures, videos, GIFs): encrypted on the device in 64 KiB chunks, each chunk AES-256-GCM
# (+16 bytes), the plaintext padded to whole chunks, so a valid blob is always a whole number of sealed chunks and the
# server learns only the size in 64 KiB steps. Keys travel inside the end-to-end encrypted, signed message.
BLOB_CHUNK = 65536 + 16
BLOB_MAX = 1600 * BLOB_CHUNK            # 100 MiB of plaintext per file
BLOB_ROOM_CAP = 5 * 1024 ** 3           # per room
BLOB_TOTAL_CAP = 10 * 1024 ** 3         # all rooms together (protects the site's disk)
BLOB_RATE = (120, 3600)                 # uploads per user per hour
BLOB_ORPHAN_S = 3600                    # uploaded but never sent: removed after this long
BLOBS_PER_MSG = 20                      # 10 files + a preview for each
BLOB_ID_RE = re.compile(r"[0-9a-f]{24}")
BURN_MAX_S = 7 * 86400                  # a burn message nobody opened is destroyed after this long anyway
EXTRA_SWEEPS = []                       # fn(c) -> rows removed, run inside the retention sweep's transaction
EXTRA_ROUTES = []                       # fn(h, method, path, q, data) -> (status, payload) or None (calls.py)
EXTRA_POLL = []                         # fn(user, q) -> (key, list): live extras for a poll, e.g. call signals (calls.py)
PAGE = 200                              # items per poll or history page
SEND_RATE = (60, 30)                    # messages: at most 60 per 30 s per user
KEY_RATE = (30, 3600)                   # room keys: at most 30 per hour per user
ROOM_RATE = (30, 86400)                 # new rooms / direct messages: 30 per day per user
MIN_FREE = 512 * 1024 * 1024            # refuse new data when the disk is this close to full
RETENTION_CHOICES = (0, 1, 7, 30, 90, 365)    # days; 0 = keep until deleted
PURGE_EVERY = 600                       # seconds between retention sweeps

ROOM_ID_RE = re.compile(r"[0-9a-f]{16}")
ROOM_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
B64_RE = re.compile(r"[A-Za-z0-9+/]*={0,2}")
FP_RE = re.compile(r"[0-9a-f]{64}")
MSG_ID_RE = re.compile(r"[A-Za-z0-9_-]{22}")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")

_cv = threading.Condition()             # notified after every commit that pollers should see
_rate = {}                              # (user, kind) -> [timestamps]
_rate_lock = threading.Lock()


class Refuse(Exception):
    def __init__(self, code, message, **extra):
        super().__init__(message)
        self.code, self.message, self.extra = code, message, extra


def migrate(c):
    """Additive schema (safe on every start; older releases ignore these tables)."""
    c.executescript("""
    CREATE TABLE IF NOT EXISTS chat_identities(
        username TEXT PRIMARY KEY REFERENCES admins(username) ON DELETE CASCADE,
        fp TEXT NOT NULL, bundle TEXT NOT NULL, backup TEXT NOT NULL, pepper_ver INTEGER NOT NULL,
        created TEXT NOT NULL, updated TEXT NOT NULL,
        cert TEXT, cert_fp TEXT, cert_by TEXT, cert_at TEXT);
    CREATE TABLE IF NOT EXISTS chat_rooms(
        id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('room','dm')), name TEXT NOT NULL,
        topic TEXT NOT NULL DEFAULT '', dm_key TEXT, retention_days INTEGER NOT NULL DEFAULT 0,
        epoch INTEGER NOT NULL DEFAULT 0, epoch_recipients TEXT NOT NULL DEFAULT '[]', epoch_at INTEGER NOT NULL DEFAULT 0,
        created TEXT NOT NULL, created_by TEXT NOT NULL);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_chat_rooms_name ON chat_rooms(name) WHERE kind='room';
    CREATE UNIQUE INDEX IF NOT EXISTS idx_chat_rooms_dm ON chat_rooms(dm_key) WHERE kind='dm';
    CREATE TABLE IF NOT EXISTS chat_members(
        room_id TEXT NOT NULL REFERENCES chat_rooms(id) ON DELETE CASCADE,
        username TEXT NOT NULL REFERENCES admins(username) ON DELETE CASCADE,
        role TEXT NOT NULL CHECK(role IN ('admin','member')), since_seq INTEGER NOT NULL,
        added_by TEXT NOT NULL, added_at TEXT NOT NULL, PRIMARY KEY(room_id, username));
    CREATE INDEX IF NOT EXISTS idx_chat_members_user ON chat_members(username);
    CREATE TABLE IF NOT EXISTS chat_items(
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id TEXT NOT NULL REFERENCES chat_rooms(id) ON DELETE CASCADE,
        kind TEXT NOT NULL CHECK(kind IN ('msg','epoch','event','redact','gone')),
        epoch INTEGER NOT NULL DEFAULT 0, sender TEXT NOT NULL, created INTEGER NOT NULL, msg_id TEXT,
        body TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_chat_items_room ON chat_items(room_id, seq);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_chat_items_msgid ON chat_items(room_id, msg_id) WHERE msg_id IS NOT NULL;
    CREATE TABLE IF NOT EXISTS chat_devices(
        id TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES admins(username) ON DELETE CASCADE,
        name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, created INTEGER NOT NULL, last_used INTEGER NOT NULL,
        expires INTEGER NOT NULL, revoked_at INTEGER);
    CREATE INDEX IF NOT EXISTS idx_chat_devices_user ON chat_devices(username);
    CREATE TABLE IF NOT EXISTS chat_blobs(
        id TEXT PRIMARY KEY, room_id TEXT NOT NULL REFERENCES chat_rooms(id) ON DELETE CASCADE,
        uploader TEXT NOT NULL, size INTEGER NOT NULL, sha3 TEXT NOT NULL, created INTEGER NOT NULL, item_seq INTEGER);
    CREATE INDEX IF NOT EXISTS idx_chat_blobs_room ON chat_blobs(room_id);
    CREATE INDEX IF NOT EXISTS idx_chat_blobs_item ON chat_blobs(item_seq);
    """)
    authz._add_col(c, "sessions", "device_id", "TEXT")      # set on sessions a paired phone opened (revoking ends them)
    # Burn messages: destroyed on the server once every recipient has opened them (or BURN_MAX_S unread)
    authz._add_col(c, "chat_items", "burn", "INTEGER NOT NULL DEFAULT 0")
    authz._add_col(c, "chat_items", "burn_for", "TEXT")      # JSON list of who must open it before it's destroyed
    c.execute("""CREATE TABLE IF NOT EXISTS chat_burn_reads(
        seq INTEGER NOT NULL REFERENCES chat_items(seq) ON DELETE CASCADE, username TEXT NOT NULL,
        read_at INTEGER NOT NULL, PRIMARY KEY(seq, username))""")
    if c.execute("SELECT 1 FROM kv WHERE k='chat_dir_rev'").fetchone() is None:
        c.execute("INSERT INTO kv(k, v) VALUES('chat_dir_rev', '1')")


# ------------------------------------------------------------------------------------------- helpers
def _notify():
    with _cv:
        _cv.notify_all()


def _bump_dir(c):
    """The member directory, certificates or room list changed: pollers re-read the state."""
    c.execute("UPDATE kv SET v = CAST(v AS INTEGER) + 1 WHERE k='chat_dir_rev'")


def _dir_rev(c):
    row = c.execute("SELECT v FROM kv WHERE k='chat_dir_rev'").fetchone()
    return int(row[0]) if row else 0


def _limit(user, kind, rule):
    n, window = rule
    t = time.monotonic()
    with _rate_lock:
        q = [x for x in _rate.get((user, kind), []) if t - x < window]
        if len(q) >= n:
            raise Refuse(429, "Slow down: too many %s. Try again in a little while." % kind)
        q.append(t)
        _rate[(user, kind)] = q


def _disk_ok():
    try:
        if shutil.disk_usage(core.STATE_DIR).free < MIN_FREE:
            raise Refuse(507, "The server is nearly out of disk space, so new chat data is refused for now.")
    except OSError:
        pass


def b64(value, size=None, max_len=None, name="value"):
    """Strict standard base64 (with padding) -> bytes; Refuse(400) on anything else."""
    if not isinstance(value, str) or len(value) % 4 or not B64_RE.fullmatch(value):
        raise Refuse(400, "Malformed %s." % name)
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise Refuse(400, "Malformed %s." % name)
    if size is not None and len(raw) != size:
        raise Refuse(400, "%s has the wrong length." % name.capitalize())
    if max_len is not None and len(raw) > max_len:
        raise Refuse(400, "%s is too large." % name.capitalize())
    return raw


def signed_json(value, max_len, name):
    """A signed header: base64 of canonical JSON bytes. Returns (raw bytes, parsed dict)."""
    raw = b64(value, max_len=max_len, name=name)
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Refuse(400, "Malformed %s." % name)
    if not isinstance(obj, dict) or obj.get("v") != 1:
        raise Refuse(400, "Unsupported %s version." % name)
    return raw, obj


def _int(v, lo, hi):
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def _text(v, limit):
    return CONTROL.sub("", v).strip()[:limit] if isinstance(v, str) else ""


def has_access(c, user):
    return authz.decide(c, user, "chat.access.use")[0]


def need(c, h, perm):
    ok, why = authz.decide(c, h.user, perm)
    if not ok:
        raise Refuse(403, "You don't have permission to do that (%s)." % perm, denied=True)


def need_reauth(c, h):
    mins = authz.settings(c)["reauth_minutes"]
    if int(time.time()) - int((h.session or {}).get("reauth_at") or 0) > mins * 60:
        raise Refuse(401, "Confirm it's you: enter the current code from your authenticator app.", reauth=True,
                     reauth_minutes=mins)


def pepper(user, version):
    """The per-user server key share mixed into the passphrase key. Derived (never stored) from the storage
    encryption key, which lives in its own credential file and not in the database or its backups."""
    ring = storage.KEYRING
    if ring is None:
        raise Refuse(503, "The server key share isn't available (storage encryption key not loaded). "
                          "Ask the owner to check the portal service.")
    try:
        key = ring.get(version)
    except Exception:
        raise Refuse(503, "The server key share for this identity (key version %d) isn't available." % version)
    return hmac.new(key, b"dcx-chat-backup-pepper/v1|" + user.encode(), hashlib.sha256).digest()


def identity(c, user):
    return c.execute("SELECT * FROM chat_identities WHERE username=?", (user,)).fetchone()


def certified(row):
    """Server-side view: an identity counts once the owner certified this exact fingerprint (the owner's own
    identity is the trust anchor and needs none). Browsers verify the certificate signature themselves."""
    return row is not None and (is_owner(row["username"]) or (row["cert"] is not None and row["cert_fp"] == row["fp"]))


def eligible(c, room_id):
    """Members who should hold the room key: chat access, an identity, and certified."""
    out = []
    for r in c.execute("SELECT username FROM chat_members WHERE room_id=? ORDER BY username", (room_id,)):
        if has_access(c, r[0]) and certified(identity(c, r[0])):
            out.append(r[0])
    return out


def needs_rotation(c, room):
    return room["epoch"] == 0 or json.loads(room["epoch_recipients"]) != eligible(c, room["id"])


def room_for(c, h, room_id, admin=False):
    """The room, if the user is a member (owner: any room). 404 for anything else, so ids reveal nothing."""
    if not isinstance(room_id, str) or not ROOM_ID_RE.fullmatch(room_id):
        raise Refuse(404, "No such room.")
    room = c.execute("SELECT * FROM chat_rooms WHERE id=?", (room_id,)).fetchone()
    mem = c.execute("SELECT * FROM chat_members WHERE room_id=? AND username=?", (room_id, h.user)).fetchone()
    if room is None or (mem is None and not (admin and is_owner(h.user))):
        raise Refuse(404, "No such room.")
    if admin:
        if room["kind"] == "dm":
            raise Refuse(400, "Direct messages have no members to manage.")
        if not (is_owner(h.user) or (mem is not None and mem["role"] == "admin")):
            raise Refuse(403, "Only the room's admins can do that.", denied=True)
    return room, mem


def _item(c, room_id, kind, sender, body, epoch=0, msg_id=None):
    cur = c.execute("INSERT INTO chat_items(room_id, kind, epoch, sender, created, msg_id, body) VALUES(?,?,?,?,?,?,?)",
                    (room_id, kind, epoch, sender, int(time.time()), msg_id, json.dumps(body, separators=(",", ":"))))
    return cur.lastrowid


def _event(c, room_id, actor, **body):
    """A server-written notice (membership, renames). Shown to members as server metadata, never as a message."""
    return _item(c, room_id, "event", actor, dict(body, by=actor))


def _max_seq(c):
    return c.execute("SELECT COALESCE(MAX(seq), 0) FROM chat_items").fetchone()[0]


def _out(r, user):
    body = json.loads(r["body"])
    if r["kind"] == "epoch":                    # each member gets only their own wrapped copy of the room key
        body = {"h": body["h"], "s": body["s"], "w": body["w"].get(user)}
    out = {"seq": r["seq"], "room": r["room_id"], "kind": r["kind"], "epoch": r["epoch"], "from": r["sender"],
           "at": r["created"], "body": body}
    if "burn" in r.keys() and r["burn"]:
        out["burn"] = True
    return out


def _destroy(c, room_id, seq, by):
    """Remove a message's ciphertext and attachments for everyone and tell every device (a redact event)."""
    c.execute("UPDATE chat_items SET kind='gone', body='{}' WHERE seq=?", (seq,))
    gone = c.execute("SELECT * FROM chat_blobs WHERE item_seq=?", (seq,)).fetchall()
    c.execute("DELETE FROM chat_blobs WHERE item_seq=?", (seq,))
    c.execute("DELETE FROM chat_burn_reads WHERE seq=?", (seq,))
    _unlink_blobs(gone)
    _item(c, room_id, "redact", by, {"target": seq, "by": by})


def run(h, fn, write=True):
    try:
        if write:
            with tx(core.db) as c:
                out = fn(c)
            _notify()
            return out
        with core.db() as c:
            return fn(c)
    except Refuse as e:
        payload = {"error": e.message}
        payload.update(e.extra)
        return e.code, payload


def read_body(h):
    try:
        length = int(h.headers.get("Content-Length", "0"))
    except ValueError:
        return None
    if length <= 0 or length > BODY_MAX or "application/json" not in (h.headers.get("Content-Type") or ""):
        return None
    try:
        data = json.loads(h.rfile.read(length).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


# ------------------------------------------------------------------------------------------- state
def state(h):
    def go(c):
        need(c, h, "chat.access.use")
        me = identity(c, h.user)
        directory = []
        for a in c.execute("SELECT username FROM admins WHERE disabled=0 ORDER BY username").fetchall():
            u = a[0]
            if not has_access(c, u):
                continue
            acc = authz.account(c, u) or {}
            row = identity(c, u)
            directory.append({
                "user": u, "display_name": acc.get("display_name") or "", "owner": is_owner(u),
                "addon": authz.role_of(acc) == "addon",                      # a program (addons.py): shown as such
                "identity": dict(json.loads(row["bundle"]), fp=row["fp"]) if row else None,
                "cert": json.loads(row["cert"]) if row and row["cert"] and row["cert_fp"] == row["fp"] else None})
        rooms = []
        for r in c.execute("""SELECT r.*, m.role FROM chat_rooms r JOIN chat_members m ON m.room_id=r.id AND m.username=?
                              ORDER BY r.kind, r.name""", (h.user,)).fetchall():
            members = [{"user": m["username"], "role": m["role"]} for m in
                       c.execute("SELECT username, role FROM chat_members WHERE room_id=? ORDER BY username", (r["id"],))]
            rooms.append({"id": r["id"], "kind": r["kind"], "name": r["name"], "topic": r["topic"],
                          "retention_days": r["retention_days"], "epoch": r["epoch"], "epoch_at": r["epoch_at"],
                          "epoch_recipients": json.loads(r["epoch_recipients"]), "eligible": eligible(c, r["id"]),
                          "needs_rotation": needs_rotation(c, r), "my_role": r["role"], "members": members,
                          "created_by": r["created_by"]})
        ring = storage.KEYRING
        return 200, {
            "me": {"user": h.user, "owner": is_owner(h.user), "can_create": authz.decide(c, h.user, "chat.rooms.create")[0],
                   "identity_fp": me["fp"] if me else None, "pepper_ver": me["pepper_ver"] if me else None,
                   "certified": certified(me)},
            "owner": OWNER, "server_key_share": bool(ring), "directory": directory, "rooms": rooms,
            "dir_rev": _dir_rev(c), "last_seq": _max_seq(c),
            "limits": {"members": MAX_MEMBERS, "retention": list(RETENTION_CHOICES)}}
    return run(h, go, write=False)


def get_pepper(h):
    """Current server key share, for creating an identity or changing the passphrase."""
    def go(c):
        need(c, h, "chat.access.use")
        ring = storage.KEYRING
        if ring is None:
            raise Refuse(503, "The server key share isn't available (storage encryption key not loaded).")
        return 200, {"pepper": base64.b64encode(pepper(h.user, ring.current)).decode(), "pepper_ver": ring.current}
    return run(h, go, write=False)


def get_backup(h):
    """Your sealed identity plus the server key share it was sealed with. Every fetch is audited: it's what an
    attacker holding a session would need for an offline passphrase guess."""
    def go(c):
        need(c, h, "chat.access.use")
        row = identity(c, h.user)
        if row is None:
            raise Refuse(404, "You don't have a chat identity yet.", no_identity=True)
        audit(c, h.user, "chat.backup_fetch", "user", h.user, ctx=h.ctx())
        return 200, {"backup": json.loads(row["backup"]), "bundle": json.loads(row["bundle"]), "fp": row["fp"],
                     "pepper": base64.b64encode(pepper(h.user, row["pepper_ver"])).decode(), "pepper_ver": row["pepper_ver"]}
    return run(h, go)


# ------------------------------------------------------------------------------------------- identities
def check_bundle(user, bundle):
    if not isinstance(bundle, dict):
        raise Refuse(400, "Malformed identity.")
    raw, obj = signed_json(bundle.get("b"), 16384, "identity")
    b64(bundle.get("s"), size=SIG_LEN, name="identity signature")
    if obj.get("t") != "identity" or obj.get("user") != user:
        raise Refuse(400, "That identity isn't for this account.")
    for key, size in (("kem_pq", KEM_PQ_PK), ("kem_ec", KEM_EC_PK), ("sig_pq", SIG_PQ_PK), ("sig_ec", SIG_EC_PK)):
        b64(obj.get(key), size=size, name=key)
    if not _int(obj.get("at"), 0, 2 ** 53):
        raise Refuse(400, "Malformed identity.")
    return hashlib.sha3_256(raw).hexdigest()


def check_backup(backup, pepper_ver):
    if not isinstance(backup, dict) or backup.get("v") != 1 or backup.get("pepper_ver") != pepper_ver:
        raise Refuse(400, "Malformed identity backup.")
    kdf = backup.get("kdf")
    if not (isinstance(kdf, dict) and kdf.get("alg") == "argon2id" and _int(kdf.get("m"), 65536, 1048576)
            and _int(kdf.get("t"), 2, 16) and _int(kdf.get("p"), 1, 4)):
        raise Refuse(400, "The passphrase key settings are below the minimum (Argon2id, 64 MiB, 2 passes).")
    b64(kdf.get("salt"), size=32, name="salt")
    b64(backup.get("n"), size=12, name="nonce")
    b64(backup.get("c"), max_len=BACKUP_MAX, name="sealed identity")
    return json.dumps(backup, separators=(",", ":"), sort_keys=True)


def save_identity(h, data):
    """Create your identity, or replace it (a reset: its certificate ends and your rooms get new keys)."""
    def go(c):
        need(c, h, "chat.access.use")
        need_reauth(c, h)
        ring = storage.KEYRING
        if ring is None:
            raise Refuse(503, "The server key share isn't available (storage encryption key not loaded).")
        fp = check_bundle(h.user, data.get("bundle"))
        old = identity(c, h.user)
        if getattr(h, "addon", None):
            # an add-on keeps its keys on its own machine (no sealed copy here), and gets one identity, ever
            if old is not None:
                raise Refuse(403, "This add-on already has an identity. The owner removes the add-on to start again.", denied=True)
            backup = ""
        else:
            backup = check_backup(data.get("backup"), ring.current)
        bundle = json.dumps({"b": data["bundle"]["b"], "s": data["bundle"]["s"]}, separators=(",", ":"))
        t = core.now()
        if old is None:
            c.execute("""INSERT INTO chat_identities(username, fp, bundle, backup, pepper_ver, created, updated)
                         VALUES(?,?,?,?,?,?,?)""", (h.user, fp, bundle, backup, ring.current, t, t))
            audit(c, h.user, "chat.identity_create", "user", h.user, detail={"fp": fp[:16]}, ctx=h.ctx())
        else:
            if data.get("confirm_reset") is not True:
                raise Refuse(409, "You already have a chat identity. Resetting it is permanent: set confirm_reset.", exists=True)
            c.execute("""UPDATE chat_identities SET fp=?, bundle=?, backup=?, pepper_ver=?, updated=?, cert=NULL, cert_fp=NULL,
                         cert_by=NULL, cert_at=NULL WHERE username=?""", (fp, bundle, backup, ring.current, t, h.user))
            n = 0
            if is_owner(h.user):
                # The owner's key signs every certificate: a new owner key means nobody is certified any more.
                n = c.execute("UPDATE chat_identities SET cert=NULL, cert_fp=NULL, cert_by=NULL, cert_at=NULL WHERE cert IS NOT NULL").rowcount
            audit(c, h.user, "chat.identity_reset", "user", h.user, detail={"old_fp": old["fp"][:16], "fp": fp[:16],
                                                                           "certificates_ended": n}, ctx=h.ctx())
        _bump_dir(c)
        return 200, {"ok": True, "fp": fp}
    return run(h, go)


def save_backup(h, data):
    """Re-sealed identity after a passphrase change. Same identity (fingerprint) only."""
    def go(c):
        need(c, h, "chat.access.use")
        need_reauth(c, h)
        row = identity(c, h.user)
        if row is None:
            raise Refuse(404, "You don't have a chat identity yet.")
        if data.get("fp") != row["fp"]:
            raise Refuse(409, "Your identity changed in another window. Reload the page.")
        ring = storage.KEYRING
        if ring is None:
            raise Refuse(503, "The server key share isn't available.")
        backup = check_backup(data.get("backup"), ring.current)
        c.execute("UPDATE chat_identities SET backup=?, pepper_ver=?, updated=? WHERE username=?",
                  (backup, ring.current, core.now(), h.user))
        audit(c, h.user, "chat.backup_update", "user", h.user, ctx=h.ctx())
        return 200, {"ok": True}
    return run(h, go)


def certify(h, data):
    """The owner signs a member's identity after comparing safety numbers with them."""
    def go(c):
        if not is_owner(h.user):
            raise Refuse(403, "Only the platform owner certifies chat identities.", denied=True)
        need_reauth(c, h)
        user = data.get("user")
        row = identity(c, user) if isinstance(user, str) else None
        if row is None or is_owner(user):
            raise Refuse(404, "That user has no chat identity to certify.")
        if not has_access(c, user):
            raise Refuse(400, "%s doesn't have chat access." % user)
        cert = data.get("cert")
        if not isinstance(cert, dict):
            raise Refuse(400, "Malformed certificate.")
        _, obj = signed_json(cert.get("b"), 1024, "certificate")
        b64(cert.get("s"), size=SIG_LEN, name="certificate signature")
        owner_id = identity(c, OWNER)
        if (obj.get("t") != "cert" or obj.get("user") != user or obj.get("fp") != row["fp"] or obj.get("by") != OWNER
                or owner_id is None or obj.get("by_fp") != owner_id["fp"] or not _int(obj.get("at"), 0, 2 ** 53)):
            raise Refuse(409, "That certificate doesn't match the current identities. Reload and compare again.")
        c.execute("UPDATE chat_identities SET cert=?, cert_fp=?, cert_by=?, cert_at=? WHERE username=?",
                  (json.dumps({"b": cert["b"], "s": cert["s"]}, separators=(",", ":")), row["fp"], h.user, core.now(), user))
        audit(c, h.user, "chat.certify", "user", user, detail={"fp": row["fp"][:16]}, ctx=h.ctx())
        _bump_dir(c)
        return 200, {"ok": True}
    return run(h, go)


def revoke(h, data):
    def go(c):
        if not is_owner(h.user):
            raise Refuse(403, "Only the platform owner revokes chat certificates.", denied=True)
        need_reauth(c, h)
        user = data.get("user")
        n = c.execute("UPDATE chat_identities SET cert=NULL, cert_fp=NULL, cert_by=NULL, cert_at=NULL WHERE username=? AND cert IS NOT NULL",
                      (user if isinstance(user, str) else "",)).rowcount
        if not n:
            raise Refuse(404, "That user has no certificate.")
        audit(c, h.user, "chat.revoke", "user", user, ctx=h.ctx())
        _bump_dir(c)
        return 200, {"ok": True}
    return run(h, go)


# ------------------------------------------------------------------------------------------- rooms
def _usernames(c, h, names, limit=MAX_MEMBERS):
    if not isinstance(names, list) or len(names) > limit or not all(isinstance(n, str) and authz.USER_RE.fullmatch(n) for n in names):
        raise Refuse(400, "Give a list of usernames.")
    out = []
    for n in dict.fromkeys(names):
        if not has_access(c, n):
            raise Refuse(400, "%s doesn't have chat access." % n)
        out.append(n)
    return out


def _room_count(c, user):
    if c.execute("SELECT COUNT(*) FROM chat_members WHERE username=?", (user,)).fetchone()[0] >= MAX_ROOMS:
        raise Refuse(400, "That's the most rooms one user can be in (%d)." % MAX_ROOMS)


def create_room(h, data):
    def go(c):
        need(c, h, "chat.access.use")
        need(c, h, "chat.rooms.create")
        _limit(h.user, "new rooms", ROOM_RATE)
        name = data.get("name")
        if not isinstance(name, str) or not ROOM_NAME_RE.fullmatch(name):
            raise Refuse(400, "Room names are 1-32 lower-case letters, digits, - or _, starting with a letter or digit.")
        if c.execute("SELECT 1 FROM chat_rooms WHERE kind='room' AND name=?", (name,)).fetchone():
            raise Refuse(409, "There's already a room called #%s." % name)
        retention = data.get("retention_days", 0)
        if retention not in RETENTION_CHOICES or isinstance(retention, bool):
            raise Refuse(400, "Keep messages for one of: %s days (0 = until deleted)." % ", ".join(map(str, RETENTION_CHOICES)))
        members = [m for m in _usernames(c, h, data.get("members", []), MAX_MEMBERS - 1) if m != h.user]
        _room_count(c, h.user)
        rid = secrets.token_hex(8)
        t = core.now()
        c.execute("""INSERT INTO chat_rooms(id, kind, name, topic, retention_days, created, created_by)
                     VALUES(?, 'room', ?, ?, ?, ?, ?)""", (rid, name, _text(data.get("topic"), 200), retention, t, h.user))
        since = _max_seq(c)
        c.execute("INSERT INTO chat_members VALUES(?,?, 'admin', ?,?,?)", (rid, h.user, since, h.user, t))
        for m in members:
            c.execute("INSERT INTO chat_members VALUES(?,?, 'member', ?,?,?)", (rid, m, since, h.user, t))
        _event(c, rid, h.user, e="created", name=name, members=[h.user] + members)
        audit(c, h.user, "chat.room_create", "chat_room", rid, detail={"name": name, "members": len(members) + 1,
                                                                         "retention_days": retention}, ctx=h.ctx())
        _bump_dir(c)
        return 200, {"ok": True, "id": rid}
    return run(h, go)


def open_dm(h, data):
    """The direct-message room with one other user (created on first use; the same one every time)."""
    def go(c):
        need(c, h, "chat.access.use")
        need(c, h, "chat.dm.start")
        other = data.get("user")
        if not isinstance(other, str) or other == h.user or not authz.USER_RE.fullmatch(other) or not has_access(c, other):
            raise Refuse(400, "Choose another user who has chat access.")
        key = "|".join(sorted((h.user, other)))
        row = c.execute("SELECT id FROM chat_rooms WHERE kind='dm' AND dm_key=?", (key,)).fetchone()
        if row:
            if not c.execute("SELECT 1 FROM chat_members WHERE room_id=? AND username=?", (row[0], h.user)).fetchone():
                raise Refuse(409, "You left this conversation; it can't be reopened. Ask %s to delete it and start again." % other)
            return 200, {"ok": True, "id": row[0]}
        _limit(h.user, "new rooms", ROOM_RATE)
        _room_count(c, h.user)
        rid = secrets.token_hex(8)
        t = core.now()
        c.execute("""INSERT INTO chat_rooms(id, kind, name, dm_key, created, created_by) VALUES(?, 'dm', ?, ?, ?, ?)""",
                  (rid, "dm-" + rid[:8], key, t, h.user))
        since = _max_seq(c)
        for u in sorted((h.user, other)):
            c.execute("INSERT INTO chat_members VALUES(?,?, 'member', ?,?,?)", (rid, u, since, h.user, t))
        _event(c, rid, h.user, e="created", members=sorted((h.user, other)))
        audit(c, h.user, "chat.dm_create", "chat_room", rid, detail={"with": other}, ctx=h.ctx())
        _bump_dir(c)
        return 200, {"ok": True, "id": rid}
    return run(h, go)


def update_room(h, room_id, data):
    def go(c):
        need(c, h, "chat.access.use")
        room, _ = room_for(c, h, room_id, admin=True)
        changes = {}
        if "name" in data:
            name = data["name"]
            if not isinstance(name, str) or not ROOM_NAME_RE.fullmatch(name):
                raise Refuse(400, "Room names are 1-32 lower-case letters, digits, - or _.")
            if name != room["name"] and c.execute("SELECT 1 FROM chat_rooms WHERE kind='room' AND name=?", (name,)).fetchone():
                raise Refuse(409, "There's already a room called #%s." % name)
            changes["name"] = name
        if "topic" in data:
            changes["topic"] = _text(data["topic"], 200)
        if "retention_days" in data:
            if data["retention_days"] not in RETENTION_CHOICES or isinstance(data["retention_days"], bool):
                raise Refuse(400, "Keep messages for one of: %s days." % ", ".join(map(str, RETENTION_CHOICES)))
            changes["retention_days"] = data["retention_days"]
        if not changes:
            raise Refuse(400, "Nothing to change.")
        c.execute("UPDATE chat_rooms SET %s WHERE id=?" % ", ".join("%s=?" % k for k in changes), (*changes.values(), room["id"]))
        _event(c, room["id"], h.user, e="updated", **changes)
        audit(c, h.user, "chat.room_update", "chat_room", room["id"], detail=changes, ctx=h.ctx())
        _bump_dir(c)
        return 200, {"ok": True}
    return run(h, go)


def members_action(h, room_id, data):
    """{add: [...], remove: [...], admin: [...], member: [...]} by a room admin (or the owner)."""
    def go(c):
        need(c, h, "chat.access.use")
        room, _ = room_for(c, h, room_id, admin=True)
        add = _usernames(c, h, data.get("add", []))
        remove = data.get("remove", [])
        if not isinstance(remove, list) or not all(isinstance(x, str) for x in remove):
            raise Refuse(400, "Give a list of usernames to remove.")
        promote, demote = data.get("admin", []), data.get("member", [])
        if not all(isinstance(x, list) and all(isinstance(u, str) for u in x) for x in (promote, demote)):
            raise Refuse(400, "Give lists of usernames.")
        current = {r[0]: r[1] for r in c.execute("SELECT username, role FROM chat_members WHERE room_id=?", (room["id"],))}
        add = [u for u in add if u not in current]
        remove = [u for u in dict.fromkeys(remove) if u in current]
        if len(current) + len(add) - len(remove) > MAX_MEMBERS:
            raise Refuse(400, "A room can have at most %d members." % MAX_MEMBERS)
        since, t = _max_seq(c), core.now()
        for u in add:
            if c.execute("SELECT COUNT(*) FROM chat_members WHERE username=?", (u,)).fetchone()[0] >= MAX_ROOMS:
                raise Refuse(400, "%s is already in the most rooms one user can be in." % u)
            c.execute("INSERT INTO chat_members VALUES(?,?, 'member', ?,?,?)", (room["id"], u, since, h.user, t))
        for u in remove:
            c.execute("DELETE FROM chat_members WHERE room_id=? AND username=?", (room["id"], u))
        for u in promote:
            if u.startswith("addon."):
                raise Refuse(400, "An add-on can't be a room admin.")
            c.execute("UPDATE chat_members SET role='admin' WHERE room_id=? AND username=?", (room["id"], u))
        for u in demote:
            c.execute("UPDATE chat_members SET role='member' WHERE room_id=? AND username=?", (room["id"], u))
        if not c.execute("SELECT 1 FROM chat_members WHERE room_id=? AND role='admin'", (room["id"],)).fetchone():
            raise Refuse(400, "A room needs at least one admin.")
        if not (add or remove or promote or demote):
            raise Refuse(400, "Nothing to change.")
        _event(c, room["id"], h.user, e="members", add=add, remove=remove, admin=promote, member=demote)
        audit(c, h.user, "chat.members", "chat_room", room["id"], detail={"add": add, "remove": remove,
                                                                            "admin": promote, "member": demote}, ctx=h.ctx())
        _bump_dir(c)
        return 200, {"ok": True}
    return run(h, go)


def leave_room(h, room_id):
    def go(c):
        need(c, h, "chat.access.use")
        room, mem = room_for(c, h, room_id)
        c.execute("DELETE FROM chat_members WHERE room_id=? AND username=?", (room["id"], h.user))
        left = [r[0] for r in c.execute("SELECT username FROM chat_members WHERE room_id=? ORDER BY since_seq, username", (room["id"],))]
        people = [u for u in left if not u.startswith("addon.")]          # an add-on never inherits a room
        if left and not people and room["kind"] == "room":
            for u in left:
                c.execute("DELETE FROM chat_members WHERE room_id=? AND username=?", (room["id"], u))
            left = []
        if not left:
            c.execute("DELETE FROM chat_rooms WHERE id=?", (room["id"],))      # items, members and blob rows cascade
            shutil.rmtree(os.path.join(blob_dir(), room["id"]), ignore_errors=True)
        else:
            if room["kind"] == "room" and not c.execute("SELECT 1 FROM chat_members WHERE room_id=? AND role='admin'", (room["id"],)).fetchone():
                c.execute("UPDATE chat_members SET role='admin' WHERE room_id=? AND username=?", (room["id"], people[0]))
            _event(c, room["id"], h.user, e="left")
        audit(c, h.user, "chat.leave", "chat_room", room["id"], ctx=h.ctx())
        _bump_dir(c)
        return 200, {"ok": True}
    return run(h, go)


def delete_room(h, room_id):
    """Rooms: their admins (or the owner). Direct messages: either participant."""
    def go(c):
        need(c, h, "chat.access.use")
        if is_owner(h.user) and isinstance(room_id, str) and ROOM_ID_RE.fullmatch(room_id) and \
                c.execute("SELECT 1 FROM chat_rooms WHERE id=? AND kind='room'", (room_id,)).fetchone():
            room, mem = room_for(c, h, room_id, admin=True)
        else:
            room, mem = room_for(c, h, room_id)
            if room["kind"] == "room" and mem["role"] != "admin":
                raise Refuse(403, "Only the room's admins can delete it.", denied=True)
        n = c.execute("SELECT COUNT(*) FROM chat_items WHERE room_id=?", (room["id"],)).fetchone()[0]
        c.execute("DELETE FROM chat_rooms WHERE id=?", (room["id"],))
        shutil.rmtree(os.path.join(blob_dir(), room["id"]), ignore_errors=True)
        audit(c, h.user, "chat.room_delete", "chat_room", room["id"], detail={"name": room["name"], "items": n}, ctx=h.ctx())
        _bump_dir(c)
        return 200, {"ok": True}
    return run(h, go)


# ------------------------------------------------------------------------------------------- keys and messages
def post_epoch(h, room_id, data):
    """A new room key, wrapped for each member who should hold it, signed by the member who made it."""
    def go(c):
        need(c, h, "chat.access.use")
        _disk_ok()
        room, _ = room_for(c, h, room_id)
        me = identity(c, h.user)
        if not certified(me):
            raise Refuse(403, "Your chat identity isn't certified yet, so you can't hand out room keys.", denied=True)
        _limit(h.user, "room keys", KEY_RATE)
        pkg = data.get("pkg")
        if not isinstance(pkg, dict) or not isinstance(pkg.get("w"), dict):
            raise Refuse(400, "Malformed room key.")
        _, hdr = signed_json(pkg.get("h"), EPOCH_HEADER_MAX, "room key header")
        b64(pkg.get("s"), size=SIG_LEN, name="room key signature")
        epoch = room["epoch"] + 1
        if hdr.get("t") != "epoch" or hdr.get("room") != room["id"] or hdr.get("by") != h.user or hdr.get("by_fp") != me["fp"]:
            raise Refuse(400, "That room key header doesn't match this room and account.")
        if hdr.get("epoch") != epoch:
            raise Refuse(409, "Someone else changed the room key first. Reload and try again.", stale=True)
        want = eligible(c, room["id"])
        rec = hdr.get("recipients")
        if not isinstance(rec, list) or [r.get("u") if isinstance(r, dict) else None for r in rec] != want:
            raise Refuse(409, "The member list changed. Reload and try again.", stale=True)
        if set(pkg["w"]) != set(want):
            raise Refuse(400, "The room key must be wrapped once for each recipient.")
        for r in rec:
            row = identity(c, r["u"])
            if r.get("fp") != row["fp"] or not isinstance(r.get("w"), str) or not FP_RE.fullmatch(r["w"]):
                raise Refuse(409, "%s's identity changed. Reload and try again." % r["u"], stale=True)
            wrap = b64(pkg["w"][r["u"]], size=WRAP_LEN, name="wrapped key")
            if hashlib.sha3_256(wrap).hexdigest() != r["w"]:
                raise Refuse(400, "A wrapped key doesn't match its header line.")
        body = {"h": pkg["h"], "s": pkg["s"], "w": {u: pkg["w"][u] for u in want}}
        _item(c, room["id"], "epoch", h.user, body, epoch=epoch)
        c.execute("UPDATE chat_rooms SET epoch=?, epoch_recipients=?, epoch_at=? WHERE id=?",
                  (epoch, json.dumps(want), int(time.time()), room["id"]))
        audit(c, h.user, "chat.rotate", "chat_room", room["id"], detail={"epoch": epoch, "recipients": len(want)}, ctx=h.ctx())
        _bump_dir(c)
        return 200, {"ok": True, "epoch": epoch}
    return run(h, go)


def send(h, room_id, data):
    def go(c):
        need(c, h, "chat.access.use")
        _disk_ok()
        room, _ = room_for(c, h, room_id)
        msg = data.get("msg")
        if not isinstance(msg, dict):
            raise Refuse(400, "Malformed message.")
        _, hdr = signed_json(msg.get("h"), HEADER_MAX, "message header")
        b64(msg.get("c"), max_len=CIPHER_MAX, name="ciphertext")
        b64(msg.get("s"), size=SIG_LEN, name="message signature")
        me = identity(c, h.user)
        if me is None:
            raise Refuse(403, "Set up your chat keys first.", denied=True)
        if (hdr.get("t") != "msg" or hdr.get("room") != room["id"] or hdr.get("from") != h.user or hdr.get("from_fp") != me["fp"]
                or not isinstance(hdr.get("id"), str) or not MSG_ID_RE.fullmatch(hdr["id"]) or not _int(hdr.get("at"), 0, 2 ** 53)):
            raise Refuse(400, "That message header doesn't match this room and account.")
        # First: a resend of a message that already arrived (the client's outbox retries after a lost answer). Checked
        # before any key-change refusal, so the client never re-seals and delivers the same message twice.
        if c.execute("SELECT 1 FROM chat_items WHERE room_id=? AND msg_id=?", (room["id"], hdr["id"])).fetchone():
            raise Refuse(409, "That message was already sent.", duplicate=True)
        if needs_rotation(c, room):
            raise Refuse(409, "This room needs a new key first.", rotate=True)
        if h.user not in json.loads(room["epoch_recipients"]):
            raise Refuse(403, "You don't hold this room's current key yet.", denied=True)
        _limit(h.user, "messages", SEND_RATE)
        if hdr.get("epoch") != room["epoch"]:
            raise Refuse(409, "The room key changed. Reload and try again.", stale=True)
        # Attachments this message carries (their keys and hashes are inside the ciphertext; this only tells the server
        # which blobs live and die with the message)
        blobs = data.get("blobs", [])
        if not (isinstance(blobs, list) and len(blobs) <= BLOBS_PER_MSG and all(isinstance(b, str) and BLOB_ID_RE.fullmatch(b) for b in blobs)):
            raise Refuse(400, "Malformed attachment list.")
        for b in dict.fromkeys(blobs):
            row = c.execute("SELECT * FROM chat_blobs WHERE id=?", (b,)).fetchone()
            if row is None or row["room_id"] != room["id"] or row["uploader"] != h.user or row["item_seq"] is not None:
                raise Refuse(400, "An attachment isn't yours to send here (upload it again).")
        if data.get("burn") not in (None, True, False):
            raise Refuse(400, "Malformed burn flag.")
        seq = _item(c, room["id"], "msg", h.user, {"h": msg["h"], "c": msg["c"], "s": msg["s"]}, epoch=room["epoch"], msg_id=hdr["id"])
        for b in dict.fromkeys(blobs):
            c.execute("UPDATE chat_blobs SET item_seq=? WHERE id=?", (seq, b))
        if data.get("burn") is True:
            # who must open it: everyone holding the key except the sender (their own devices don't count)
            readers = [u for u in json.loads(room["epoch_recipients"]) if u != h.user]
            if not readers:
                raise Refuse(400, "Nobody else is in this room yet, so a burn message would never be read.")
            c.execute("UPDATE chat_items SET burn=1, burn_for=? WHERE seq=?", (json.dumps(readers), seq))
        return 200, {"ok": True, "seq": seq}
    return run(h, go)


def burn_read(h, room_id, data):
    """A recipient opened a burn message: once everyone it was for (and who is still in the room) has, it's destroyed."""
    def go(c):
        need(c, h, "chat.access.use")
        room, _ = room_for(c, h, room_id)
        seq = data.get("seq")
        row = c.execute("SELECT * FROM chat_items WHERE seq=? AND room_id=? AND kind='msg' AND burn=1",
                        (seq if _int(seq, 1, 2 ** 62) else 0, room["id"])).fetchone()
        if row is None:
            return 200, {"ok": True, "destroyed": True}          # already gone (another reader, another device)
        if row["sender"] == h.user:
            raise Refuse(400, "You sent this message; it burns when the others open it.")
        readers = set(json.loads(row["burn_for"] or "[]"))
        if h.user not in readers:
            raise Refuse(403, "This message wasn't for you.", denied=True)
        c.execute("INSERT OR IGNORE INTO chat_burn_reads(seq, username, read_at) VALUES(?,?,?)", (row["seq"], h.user, int(time.time())))
        members = {r[0] for r in c.execute("SELECT username FROM chat_members WHERE room_id=?", (room["id"],))}
        done = {r[0] for r in c.execute("SELECT username FROM chat_burn_reads WHERE seq=?", (row["seq"],))}
        if (readers & members) <= done:
            _destroy(c, room["id"], row["seq"], h.user)
            return 200, {"ok": True, "destroyed": True}
        return 200, {"ok": True, "destroyed": False}
    return run(h, go)


# ------------------------------------------------------------------------------------------- attachments
def blob_dir():
    return os.path.join(core.STATE_DIR, "chat-blobs")


def _blob_path(room_id, blob_id):
    return os.path.join(blob_dir(), room_id, blob_id)


def _unlink_blobs(rows):
    for r in rows:
        try:
            os.unlink(_blob_path(r["room_id"], r["id"]))
        except FileNotFoundError:
            pass


def upload_blob(h, room_id):
    """POST chat/upload/<room>: raw ciphertext body (a whole number of sealed 64 KiB chunks). Streamed to disk while
    the server hashes it (SHA3-256); the sender puts the same hash inside the signed message, so a swapped blob fails."""
    try:
        length = int(h.headers.get("Content-Length", "0"))
    except ValueError:
        length = 0
    if length <= 0 or length > BLOB_MAX or length % BLOB_CHUNK:
        return 400, {"error": "That isn't an encrypted attachment (or it's over 100 MB)."}
    def check(c):
        need(c, h, "chat.access.use")
        need(c, h, "chat.files.send")
        if length > authz.settings(c)["upload_max_mb"] * 1024 * 1024 + (length // BLOB_CHUNK + 1) * 16:
            raise Refuse(413, "Attachments on this server can be up to %d MB." % authz.settings(c)["upload_max_mb"])
        _disk_ok()
        room, _ = room_for(c, h, room_id)
        used_room = c.execute("SELECT COALESCE(SUM(size), 0) FROM chat_blobs WHERE room_id=?", (room["id"],)).fetchone()[0]
        used_all = c.execute("SELECT COALESCE(SUM(size), 0) FROM chat_blobs").fetchone()[0]
        if used_room + length > BLOB_ROOM_CAP or used_all + length > BLOB_TOTAL_CAP:
            raise Refuse(507, "Attachment storage for the chat is full. Delete old files or ask the owner.")
        if shutil.disk_usage(core.STATE_DIR).free - length < MIN_FREE:
            raise Refuse(507, "The server is nearly out of disk space, so attachments are refused for now.")
        _limit(h.user, "uploads", BLOB_RATE)
        return 200, room
    code, room = run(h, check, write=False)
    if code != 200:
        return code, room
    bid = secrets.token_hex(12)
    folder = os.path.join(blob_dir(), room["id"])
    os.makedirs(folder, mode=0o700, exist_ok=True)
    tmp = os.path.join(folder, "." + bid + ".part")
    digest = hashlib.sha3_256()
    left = length
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            while left:
                chunk = h.rfile.read(min(left, 1 << 20))
                if not chunk:
                    raise OSError("upload ended early")
                digest.update(chunk)
                fh.write(chunk)
                left -= len(chunk)
        want = getattr(h, "body_sha3", None)           # an add-on signed the body's hash (addons.py)
        if want is not None and not hmac.compare_digest(digest.hexdigest(), want):
            os.unlink(tmp)
            return 401, {"error": "Add-on authentication failed: the upload isn't what was signed."}
        os.replace(tmp, os.path.join(folder, bid))
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return 400, {"error": "The upload didn't arrive completely. Try again."}
    def save(c):
        c.execute("INSERT INTO chat_blobs(id, room_id, uploader, size, sha3, created) VALUES(?,?,?,?,?,?)",
                  (bid, room["id"], h.user, length, digest.hexdigest(), int(time.time())))
        return 200, {"ok": True, "id": bid, "size": length, "sha3": digest.hexdigest()}
    return run(h, save)


def send_blob(h, room_id, blob_id):
    """GET chat/blob/<room>/<blob>: the ciphertext, streamed. Members of the room only; never cached or rendered."""
    def check(c):
        need(c, h, "chat.access.use")
        room, _ = room_for(c, h, room_id)
        row = c.execute("SELECT * FROM chat_blobs WHERE id=? AND room_id=?", (blob_id, room["id"])).fetchone()
        if row is None or (row["item_seq"] is None and row["uploader"] != h.user):
            raise Refuse(404, "That attachment isn't here any more.")
        return 200, row
    if not (isinstance(blob_id, str) and BLOB_ID_RE.fullmatch(blob_id)):
        return 404, {"error": "not found"}
    code, row = run(h, check, write=False)
    if code != 200:
        return code, row
    try:
        fh = open(_blob_path(row["room_id"], row["id"]), "rb")
    except OSError:
        return 404, {"error": "That attachment isn't here any more."}
    with fh:
        h.send_response(200)
        h.send_header("Content-Type", "application/octet-stream")
        h.send_header("Content-Length", str(row["size"]))
        h.send_header("Cache-Control", "no-store, private")
        h.send_header("X-Content-Type-Options", "nosniff")
        h.send_header("Content-Security-Policy", "default-src 'none'; sandbox")
        h.end_headers()
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            h.wfile.write(chunk)
    return "sent"


def redact(h, room_id, data):
    """Delete a message for everyone: your own, or any in a room you administer."""
    def go(c):
        need(c, h, "chat.access.use")
        room, mem = room_for(c, h, room_id)
        seq = data.get("seq")
        row = c.execute("SELECT * FROM chat_items WHERE seq=? AND room_id=? AND kind='msg'", (seq if _int(seq, 1, 2 ** 62) else 0, room["id"])).fetchone()
        if row is None:
            raise Refuse(404, "No such message.")
        if row["sender"] != h.user and not (mem["role"] == "admin" and room["kind"] == "room"):
            raise Refuse(403, "You can only delete your own messages.", denied=True)
        c.execute("UPDATE chat_items SET kind='gone', body='{}' WHERE seq=?", (row["seq"],))
        gone = c.execute("SELECT * FROM chat_blobs WHERE item_seq=?", (row["seq"],)).fetchall()
        c.execute("DELETE FROM chat_blobs WHERE item_seq=?", (row["seq"],))
        _unlink_blobs(gone)                     # the message's attachments go with it
        _item(c, room["id"], "redact", h.user, {"target": row["seq"], "by": h.user})
        if row["sender"] != h.user:
            audit(c, h.user, "chat.redact", "chat_room", room["id"], detail={"seq": row["seq"], "sender": row["sender"]}, ctx=h.ctx())
        return 200, {"ok": True}
    return run(h, go)


def history(h, room_id, q):
    def go(c):
        need(c, h, "chat.access.use")
        room, mem = room_for(c, h, room_id)
        try:
            before = min(max(0, int(q.get("before") or 2 ** 62)), 2 ** 62)
        except ValueError:
            raise Refuse(400, "Bad position.")
        # (a burn message you already opened never comes back, on any of your devices)
        rows = c.execute("""SELECT * FROM chat_items i WHERE room_id=? AND seq<? AND seq>? AND kind<>'gone'
                            AND NOT EXISTS (SELECT 1 FROM chat_burn_reads b WHERE b.seq=i.seq AND b.username=?)
                            ORDER BY seq DESC LIMIT ?""", (room["id"], before, mem["since_seq"], h.user, PAGE)).fetchall()
        return 200, {"items": [_out(r, h.user) for r in reversed(rows)], "more": len(rows) == PAGE}
    return run(h, go, write=False)


def epochs(h, room_id):
    """Every room key in this room that was wrapped for you (to read older messages)."""
    def go(c):
        need(c, h, "chat.access.use")
        room, mem = room_for(c, h, room_id)
        rows = c.execute("SELECT * FROM chat_items WHERE room_id=? AND kind='epoch' ORDER BY seq", (room["id"],)).fetchall()
        return 200, {"items": [x for x in (_out(r, h.user) for r in rows) if x["body"]["w"]]}
    return run(h, go, write=False)


def poll(h, q):
    """New items in your rooms after `since` (a global sequence number), waiting up to POLL_WAIT seconds."""
    try:
        since = min(max(0, int(q.get("since") or 0)), 2 ** 62)          # SQLite integers are 64-bit
        rev = min(max(-1, int(q.get("rev") or 0)), 2 ** 62)
    except ValueError:
        return 400, {"error": "Bad position."}
    deadline = time.monotonic() + POLL_WAIT
    while True:
        with core.db() as c:
            if not has_access(c, h.user):
                return 403, {"error": "You don't have permission to do that (chat.access.use).", "denied": True}
            rows = c.execute("""SELECT i.* FROM chat_items i JOIN chat_members m ON m.room_id=i.room_id AND m.username=?
                                WHERE i.seq>? AND i.seq>m.since_seq AND i.kind<>'gone'
                                AND NOT EXISTS (SELECT 1 FROM chat_burn_reads b WHERE b.seq=i.seq AND b.username=m.username)
                                ORDER BY i.seq LIMIT ?""",
                             (h.user, since, PAGE)).fetchall()
            cur = _dir_rev(c)
            extras = {k: v for k, v in (fn(h.user, q) for fn in EXTRA_POLL) if v}
            if rows or cur != rev or extras:
                return 200, dict(extras, items=[_out(r, h.user) for r in rows], dir_rev=cur,
                                 last_seq=rows[-1]["seq"] if rows else max(since, _max_seq(c)))
        left = deadline - time.monotonic()
        if left <= 0:
            return 200, {"items": [], "dir_rev": rev, "last_seq": since}
        with _cv:
            _cv.wait(min(left, 5))          # also wakes every 5 s, so a lost notify costs at most that


# ------------------------------------------------------------------------------------------- paired phones
# The DarkCipher Chat app pairs once with a full sign-in (password + authenticator code, then a fresh code for the
# pairing itself) and gets a random 256-bit device token, of which only a SHA-256 is stored. Later the app trades the
# token for a session with scope "chat": that session can use the chat API and confirm-it's-you, and nothing else in
# the portal. Revoking a device (or its 30-day idle / 180-day absolute expiry) ends it and every session it opened.
def scopes_for(uri):
    """Session scopes a request may use: chat-only (paired phone) sessions work on the chat API and re-auth only."""
    uri = (uri or "").split("?")[0]
    return ("full", "chat") if (uri.startswith("/admin/api/chat/") or uri == "/admin/api/auth/reauth"
                                or uri == "/chat/" or uri.startswith("/chat/app/") or uri.startswith("/chat/api/")) else ("full",)


def _device_live(row, t):
    return row["revoked_at"] is None and row["expires"] > t and row["last_used"] > t - DEVICE_IDLE_DAYS * 86400


def register_device(h, data):
    def go(c):
        need(c, h, "chat.access.use")
        need(c, h, "chat.devices.pair")
        # from a password + authenticator sign-in (either portal), never from another paired phone's session
        if (h.session or {}).get("device_id") or (h.session or {}).get("scope") not in ("full", "chat"):
            raise Refuse(403, "Pair a phone from a sign-in with your password and authenticator code.", denied=True)
        need_reauth(c, h)
        name = _text(data.get("name"), 40) or "Phone"
        t = int(time.time())
        live = [r for r in c.execute("SELECT * FROM chat_devices WHERE username=?", (h.user,)) if _device_live(r, t)]
        if len(live) >= DEVICE_MAX:
            raise Refuse(400, "You already have %d paired phones. Remove one first." % DEVICE_MAX)
        did, token = secrets.token_hex(8), secrets.token_urlsafe(32)
        c.execute("INSERT INTO chat_devices(id, username, name, token_hash, created, last_used, expires) VALUES(?,?,?,?,?,?,?)",
                  (did, h.user, name, hashlib.sha256(token.encode()).hexdigest(), t, t, t + DEVICE_DAYS * 86400))
        audit(c, h.user, "chat.device_add", "chat_device", did, detail={"name": name}, ctx=h.ctx())
        mailer = getattr(core, "mail_api", None)
        if mailer is not None:
            mailer.notify(c, "device_paired", "An app was paired to your account",
                          "\"%s\" was paired to the account %s just now. If that wasn't you, remove it in the chat (/devices) "
                          "and tell your administrator." % (name, h.user), user=h.user)
        return 200, {"ok": True, "id": did, "token": token, "expires": t + DEVICE_DAYS * 86400,
                     "idle_days": DEVICE_IDLE_DAYS, "name": name}
    return run(h, go)


def list_devices(h):
    def go(c):
        need(c, h, "chat.access.use")
        t = int(time.time())
        rows = c.execute("SELECT * FROM chat_devices WHERE username=? ORDER BY created DESC", (h.user,)).fetchall()
        return 200, {"devices": [{"id": r["id"], "name": r["name"], "created": r["created"], "last_used": r["last_used"],
                                  "expires": min(r["expires"], r["last_used"] + DEVICE_IDLE_DAYS * 86400),
                                  "this": (h.session or {}).get("device_id") == r["id"]}
                                 for r in rows if _device_live(r, t)]}
    return run(h, go, write=False)


def revoke_device(h, device_id):
    """Your own phone, or (the owner) anyone's. Its sessions end at once."""
    def go(c):
        need(c, h, "chat.access.use")
        row = c.execute("SELECT * FROM chat_devices WHERE id=?", (device_id if isinstance(device_id, str) else "",)).fetchone()
        if row is None or row["revoked_at"] is not None or (row["username"] != h.user and not is_owner(h.user)):
            raise Refuse(404, "No such paired phone.")
        c.execute("UPDATE chat_devices SET revoked_at=? WHERE id=?", (int(time.time()), row["id"]))
        n = c.execute("DELETE FROM sessions WHERE device_id=?", (row["id"],)).rowcount
        audit(c, h.user, "chat.device_revoke", "chat_device", row["id"], detail={"user": row["username"], "sessions_ended": n}, ctx=h.ctx())
        return 200, {"ok": True}
    return run(h, go)


def device_signin(h, data):
    """POST /admin/api/auth/device {token}: no session needed (the token is the credential; nginx rate-limits this
    like the password sign-in and fail2ban counts its 401s). Returns (status, payload, session token or None)."""
    token = data.get("token")
    if not isinstance(token, str) or not 30 <= len(token) <= 100:
        return 401, {"error": DEVICE_BAD}, None
    th = hashlib.sha256(token.encode()).hexdigest()
    t = int(time.time())
    with tx(core.db) as c:
        row = c.execute("SELECT * FROM chat_devices WHERE token_hash=?", (th,)).fetchone()
        acc = authz.account(c, row["username"]) if row else None
        admin = c.execute("SELECT disabled FROM admins WHERE username=?", (row["username"],)).fetchone() if row else None
        ok = (row is not None and _device_live(row, t) and acc is not None and not authz.inactive_reason(acc)
              and admin is not None and not admin["disabled"] and not acc.get("must_change_pw") and has_access(c, row["username"]))
        if not ok:
            audit(c, row["username"] if row else "?", "chat.device_signin", "chat_device", row["id"] if row else "", "failed", ctx=h.ctx())
            return 401, {"error": DEVICE_BAD}, None
        session = core.new_session(row["username"], "chat", h.headers.get("User-Agent", ""), c)
        c.execute("UPDATE sessions SET device_id=? WHERE token_hash=?", (row["id"], hashlib.sha256(session.encode()).hexdigest()))
        c.execute("UPDATE chat_devices SET last_used=? WHERE id=?", (t, row["id"]))
        audit(c, row["username"], "chat.device_signin", "chat_device", row["id"], ctx=h.ctx())
    return 200, {"ok": True, "user": row["username"], "device": row["id"]}, session


# ------------------------------------------------------------------------------------------- retention
def purge_once():
    """Delete messages past each room's retention, and room keys no remaining message needs (the current key
    always stays). Run by a background thread; also callable from tests."""
    n = 0
    with tx(core.db) as c:
        for room in c.execute("SELECT * FROM chat_rooms WHERE retention_days > 0").fetchall():
            cutoff = int(time.time()) - room["retention_days"] * 86400
            n += c.execute("DELETE FROM chat_items WHERE room_id=? AND created<? AND kind IN ('msg','gone','event','redact')",
                           (room["id"], cutoff)).rowcount
            oldest = c.execute("SELECT MIN(epoch) FROM chat_items WHERE room_id=? AND kind='msg'", (room["id"],)).fetchone()[0]
            keep_from = min(oldest if oldest is not None else room["epoch"], room["epoch"])
            n += c.execute("DELETE FROM chat_items WHERE room_id=? AND kind='epoch' AND epoch<?", (room["id"], keep_from)).rowcount
        # Burn messages nobody opened in time
        for r in c.execute("SELECT seq, room_id FROM chat_items WHERE kind='msg' AND burn=1 AND created<?",
                           (int(time.time()) - BURN_MAX_S,)).fetchall():
            _destroy(c, r["room_id"], r["seq"], "server")
            n += 1
        # Attachments whose message is gone (retention, redaction) or that were uploaded but never sent
        dead = c.execute("""SELECT * FROM chat_blobs WHERE (item_seq IS NOT NULL AND item_seq NOT IN
                            (SELECT seq FROM chat_items WHERE kind='msg')) OR (item_seq IS NULL AND created<?)""",
                         (int(time.time()) - BLOB_ORPHAN_S,)).fetchall()
        c.executemany("DELETE FROM chat_blobs WHERE id=?", [(r["id"],) for r in dead])
        _unlink_blobs(dead)
        n += len(dead)
        for sweep in EXTRA_SWEEPS:                # other chat housekeeping (chat_requests.purge)
            n += sweep(c)
        # Files with no row (a room deleted while a copy was being written, a crash mid-upload)
        known = {(r["room_id"], r["id"]) for r in c.execute("SELECT room_id, id FROM chat_blobs")}
        rooms = {r[0] for r in c.execute("SELECT id FROM chat_rooms")}
    try:
        for rid in os.listdir(blob_dir()):
            folder = os.path.join(blob_dir(), rid)
            if rid not in rooms:
                shutil.rmtree(folder, ignore_errors=True)
                continue
            for name in os.listdir(folder):
                stale = name.startswith(".") and time.time() - os.path.getmtime(os.path.join(folder, name)) > BLOB_ORPHAN_S
                if stale or (not name.startswith(".") and (rid, name) not in known):
                    os.unlink(os.path.join(folder, name))
                    n += 1
    except FileNotFoundError:
        pass
    return n


def purge_loop():
    while True:
        time.sleep(PURGE_EVERY)
        try:
            n = purge_once()
            if n:
                sys.stderr.write("chat retention: removed %d item(s)\n" % n)
        except Exception as e:                  # never let the sweep kill the service; it retries next round
            sys.stderr.write("chat retention sweep failed: %s\n" % type(e).__name__)


# ------------------------------------------------------------------------------------------- router
def route(h, method, path, query):
    """Returns (status, payload). The session, admin key and (for POST) CSRF checks have already passed."""
    if h.ctl:
        return 403, {"error": "The chat isn't available over the Control API.", "denied": True}
    q = {}
    for part in query.split("&"):
        k, _, v = part.partition("=")
        if k:
            q[k] = core.unquote(v)[:40]
    p = path[len("/admin/api/chat/"):]
    m = re.fullmatch(r"rooms/([^/]{1,40})/([a-z]+)", p)
    if method == "GET":
        if p == "state":
            return state(h)
        if p == "poll":
            return poll(h, q)
        if p == "pepper":
            return get_pepper(h)
        if p == "devices":
            return list_devices(h)
        if m and m.group(2) == "items":
            return history(h, m.group(1), q)
        if m and m.group(2) == "epochs":
            return epochs(h, m.group(1))
        mb = re.fullmatch(r"blob/([0-9a-f]{16})/([0-9a-f]{24})", p)
        if mb:
            return send_blob(h, mb.group(1), mb.group(2))
        for fn in EXTRA_ROUTES:
            out = fn(h, "GET", p, q, None)
            if out is not None:
                return out
        return 404, {"error": "not found"}
    mu = re.fullmatch(r"upload/([0-9a-f]{16})", p)
    if mu:                                      # raw ciphertext body, streamed (not JSON)
        return upload_blob(h, mu.group(1))
    data = read_body(h)                         # always read first: an unread body would corrupt the next keep-alive request
    if data is None:
        return 400, {"error": "Invalid request."}
    if p == "backup/fetch":                     # a POST: it is audited and must not be prefetched or cached
        return get_backup(h)
    if p == "identity":
        return save_identity(h, data)
    if p == "backup":
        return save_backup(h, data)
    if p == "certify":
        return certify(h, data)
    if p == "revoke":
        return revoke(h, data)
    if p == "rooms":
        return create_room(h, data)
    if p == "dm":
        return open_dm(h, data)
    if p == "devices":
        return register_device(h, data)
    md = re.fullmatch(r"devices/([0-9a-f]{16})/revoke", p)
    if md:
        return revoke_device(h, md.group(1))
    if m:
        fn = {"send": send, "epoch": post_epoch, "redact": redact, "update": update_room, "members": members_action,
              "burn": burn_read}.get(m.group(2))
        if fn:
            return fn(h, m.group(1), data)
        if m.group(2) == "leave":
            return leave_room(h, m.group(1))
        if m.group(2) == "delete":
            return delete_room(h, m.group(1))
    for fn in EXTRA_ROUTES:
        out = fn(h, "POST", p, q, data)
        if out is not None:
            return out
    return 404, {"error": "not found"}
