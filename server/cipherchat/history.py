"""CipherChat history: device lists, acknowledgements, wrap deletion and history sync (PROTOCOL.md §10).

Room keys stop living on the server. Each device keeps the keys it has opened in its own sealed key store and says so;
the server then deletes that person's wrapped copy, so a stolen identity can't open the room's archive. A new device
gets older keys only from another of the same person's devices, sealed to its own device key. The server never makes
a wrap or a package itself, and it can't read either: it only stores and deletes.

  POST /chat/api/keydevices          {"list": {"b", "s"}, "dev"?}   publish your signed device list (seq + 1)
  POST /chat/api/store/hello         {"dev"}                        this session's device keeps a key store
  POST /chat/api/rooms/<id>/ack      {"dev", "epochs": [n, ...]}    this device stored these room keys
  GET  /chat/api/sync?dev=           requests from your other devices, and packages waiting for this one
  POST /chat/api/sync/request        {"dev"}                        a new device asks for older keys
  POST /chat/api/sync/send           {"to", "from", "blob", "last"} a sealed package for a device that asked
  POST /chat/api/sync/done           {"id"}                         the package arrived: delete it
  POST /chat/api/sync/decline        {"id"}                         turn a request down
  POST /chat/api/keydevices/prekey   {"dev", "prekey": {"b", "s"}}  a device's new signed prekey (protocol 2, §11)

A person with no device list is in compatibility mode: nothing of theirs is deleted. While any of their chat sessions
or paired devices hasn't said it keeps a key store (an app from before this release), nothing is deleted either.
"""
import json
import re
import secrets
import time

import authz

core = None          # the server module (db, session_idle)
chat = None          # chat.py: Refuse, run, need, room_for, identity, signed_json, b64, limits

DEV_RE = re.compile(r"[0-9a-f]{16}")
MAX_DEVICES = 16
LIST_MAX = 16 * 1024 + 4096                 # 16 devices with their public keys, as canonical JSON
NAME_MAX = 40
GRACE_S = 7 * 86400                         # a wrap no device acknowledged is deleted after this long anyway
SYNC_KEEP_S = 7 * 86400                     # requests and packages nobody collected
PACKAGE_MAX = 192 * 1024                    # one sealed package (a request body is at most chat.BODY_MAX)
PACKAGES_MAX = 64                           # waiting for one device
FRESH_SESSION_S = 600                       # a new session has this long to say it keeps a key store
LIST_RATE = (30, 3600)
SYNC_RATE = (120, 3600)
PREKEY_RATE = (48, 86400)                   # a device publishes one a day; this allows 16 devices three times over
PREKEYS_KEPT = 4                            # newest prekeys kept per device
PREKEY_LIFE_MAX_MS = 8 * 86400 * 1000       # exp - at (a prekey lives 7 days)
PREKEY_MAX = 4096                           # one signed prekey, as base64 canonical JSON

def bind(server_module, chat_module):
    global core, chat
    core, chat = server_module, chat_module
    for hooks, fn in ((chat.EXTRA_ROUTES, route), (chat.EXTRA_SWEEPS, sweep), (chat.DIRECTORY_EXTRA, directory_extra),
                      (chat.ME_EXTRA, me_extra)):
        if fn not in hooks:
            hooks.append(fn)
    chat.DEVICES_OF, chat.PREKEY_OK, chat.HELD = _devices, prekey_ok, held

def migrate(c):
    c.executescript("""
    CREATE TABLE IF NOT EXISTS chat_device_lists(
        username TEXT PRIMARY KEY REFERENCES admins(username) ON DELETE CASCADE,
        seq INTEGER NOT NULL, fp TEXT NOT NULL, list TEXT NOT NULL, devices TEXT NOT NULL, updated INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS chat_acks(
        room_id TEXT NOT NULL REFERENCES chat_rooms(id) ON DELETE CASCADE, epoch INTEGER NOT NULL,
        username TEXT NOT NULL, dev TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY(room_id, epoch, username, dev));
    CREATE TABLE IF NOT EXISTS chat_sync(
        id TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES admins(username) ON DELETE CASCADE,
        kind TEXT NOT NULL CHECK(kind IN ('request','package')), dev TEXT NOT NULL, from_dev TEXT,
        blob TEXT, created INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_chat_sync_user ON chat_sync(username, kind);
    CREATE TABLE IF NOT EXISTS chat_prekeys(
        username TEXT NOT NULL REFERENCES admins(username) ON DELETE CASCADE, dev TEXT NOT NULL, id TEXT NOT NULL,
        at INTEGER NOT NULL, exp INTEGER NOT NULL, prekey TEXT NOT NULL, PRIMARY KEY(username, dev, id));
    CREATE TABLE IF NOT EXISTS chat_device_seen(
        username TEXT NOT NULL REFERENCES admins(username) ON DELETE CASCADE, dev TEXT NOT NULL, at INTEGER NOT NULL,
        PRIMARY KEY(username, dev));
    """)
    authz._add_col(c, "sessions", "store_dev", "TEXT")          # the key-store device this session belongs to
    authz._add_col(c, "chat_devices", "store_dev", "TEXT")      # ...and the one a paired phone or PC runs

# ------------------------------------------------------------------------------------------- helpers
def _devices(c, user):
    row = c.execute("SELECT devices FROM chat_device_lists WHERE username=?", (user,)).fetchone()
    return json.loads(row[0]) if row else None

def _dev(value, c, user):
    devs = _devices(c, user)
    if not isinstance(value, str) or not DEV_RE.fullmatch(value) or devs is None or value not in devs:
        raise chat.Refuse(400, "That device isn't on your device list.")
    return value

def _mark(c, h, dev):
    """Remember that this session (and the paired device that opened it) keeps a key store."""
    s = h.session or {}
    c.execute("INSERT INTO chat_device_seen(username, dev, at) VALUES(?,?,?) ON CONFLICT(username, dev) DO UPDATE SET at=excluded.at",
              (h.user, dev, int(time.time()) // 86400 * 86400))       # to the day: enough to spot a device nobody uses
    if s.get("token_hash"):
        c.execute("UPDATE sessions SET store_dev=? WHERE token_hash=?", (dev, s["token_hash"]))
    if s.get("device_id"):
        c.execute("UPDATE chat_devices SET store_dev=? WHERE id=?", (dev, s["device_id"]))

def held(c, user):
    """True while something of this person's may still need the server's wraps: a live chat session or paired device
    that hasn't said it keeps a key store (an older app), or a device list that doesn't exist (compatibility mode)."""
    if _devices(c, user) is None:
        return True
    t = int(time.time())
    if c.execute("""SELECT 1 FROM sessions WHERE user=? AND scope='chat' AND store_dev IS NULL AND expires>?
                    AND last_seen>? AND created<?""", (user, t, t - core.session_idle(), t - FRESH_SESSION_S)).fetchone():
        return True
    for r in c.execute("SELECT * FROM chat_devices WHERE username=? AND store_dev IS NULL", (user,)).fetchall():
        if chat._device_live(r, t):
            return True
    return False

def drop_wraps(c, user):
    """Delete this person's wraps that every listed device has acknowledged, and any older than the grace period.
    Returns how many went."""
    if held(c, user):
        return 0
    devs = _devices(c, user)
    cutoff = int(time.time()) - GRACE_S
    gone = []
    for r in c.execute("""SELECT w.seq, i.room_id, i.epoch, i.created FROM chat_wraps w JOIN chat_items i ON i.seq=w.seq
                          WHERE w.username=?""", (user,)).fetchall():
        acked = {a[0] for a in c.execute("SELECT dev FROM chat_acks WHERE room_id=? AND epoch=? AND username=?",
                                         (r["room_id"], r["epoch"], user))}
        if r["created"] < cutoff or set(devs) <= acked:
            gone.append(r["seq"])
    c.executemany("DELETE FROM chat_wraps WHERE seq=? AND username=?", [(s, user) for s in gone])
    return len(gone)

def drop_dev_wraps(c, user):
    """Per-device wraps (protocol 2) go as soon as their own device acknowledges, or after the grace period. Older
    apps can't read them, so nothing holds them back."""
    cutoff = int(time.time()) - GRACE_S
    n = c.execute("DELETE FROM chat_dev_wraps WHERE username=? AND seq IN (SELECT seq FROM chat_items WHERE created<?)",
                  (user, cutoff)).rowcount
    n += c.execute("""DELETE FROM chat_dev_wraps WHERE username=? AND EXISTS (SELECT 1 FROM chat_items i JOIN chat_acks a
                      ON a.room_id=i.room_id AND a.epoch=i.epoch AND a.username=chat_dev_wraps.username AND a.dev=chat_dev_wraps.dev
                      WHERE i.seq=chat_dev_wraps.seq)""", (user,)).rowcount
    return n

def sweep(c):
    """Retention sweep (chat.purge_once): wraps that may go, and sync requests and packages nobody collected."""
    n = 0
    for (user,) in c.execute("SELECT username FROM chat_device_lists").fetchall():
        n += drop_wraps(c, user) + drop_dev_wraps(c, user)
    n += c.execute("DELETE FROM chat_prekeys WHERE exp<?", (int(time.time() * 1000),)).rowcount
    n += c.execute("DELETE FROM chat_sync WHERE created<?", (int(time.time()) - SYNC_KEEP_S,)).rowcount
    n += c.execute("DELETE FROM chat_acks WHERE NOT EXISTS (SELECT 1 FROM chat_items i WHERE i.room_id=chat_acks.room_id "
                   "AND i.kind='epoch' AND i.epoch=chat_acks.epoch)").rowcount
    return n

def directory_extra(c, user):
    row = c.execute("SELECT list FROM chat_device_lists WHERE username=?", (user,)).fetchone()
    pre = [json.loads(r[0]) for r in c.execute("SELECT prekey FROM chat_prekeys WHERE username=? AND exp>? ORDER BY dev, at",
                                               (user, int(time.time() * 1000)))]
    # v2: whether per-device room keys can reach every app of theirs (clients still check every prekey themselves)
    return {"devices": json.loads(row[0]) if row else None, "prekeys": pre, "v2": bool(row) and not held(c, user)}

def prekey_ok(c, user, dev, pid):
    return c.execute("SELECT 1 FROM chat_prekeys WHERE username=? AND dev=? AND id=? AND exp>?",
                     (user, dev, pid, int(time.time() * 1000))).fetchone() is not None

def me_extra(c, h):
    t = int(time.time()) - SYNC_KEEP_S
    n = c.execute("SELECT COUNT(*) FROM chat_sync WHERE username=? AND created>=?", (h.user, t)).fetchone()[0]
    seen = {r[0]: r[1] for r in c.execute("SELECT dev, at FROM chat_device_seen WHERE username=?", (h.user,))}
    return {"sync_waiting": n, "device_seen": seen}

# ------------------------------------------------------------------------------------------- device list
def check_list(c, user, value):
    """A device list as the server can check it (clients verify the signature). Returns (stored json, seq, ids, fp)."""
    if not isinstance(value, dict):
        raise chat.Refuse(400, "Malformed device list.")
    raw, obj = chat.signed_json(value.get("b"), LIST_MAX, "device list")
    chat.b64(value.get("s"), size=chat.SIG_LEN, name="device list signature")
    me = chat.identity(c, user)
    if obj.get("t") != "devices" or obj.get("user") != user or me is None or obj.get("fp") != me["fp"]:
        raise chat.Refuse(409, "That device list isn't for your current identity. Reload and try again.", stale=True)
    if not chat._int(obj.get("seq"), 1, 2 ** 40) or not chat._int(obj.get("at"), 0, 2 ** 53):
        raise chat.Refuse(400, "Malformed device list.")
    devs = obj.get("devices")
    if not isinstance(devs, list) or not 1 <= len(devs) <= MAX_DEVICES:
        raise chat.Refuse(400, "A device list has 1 to %d devices." % MAX_DEVICES)
    ids = []
    for d in devs:
        if not isinstance(d, dict) or set(d) != {"id", "name", "kem_pq", "kem_ec", "added"}:
            raise chat.Refuse(400, "Malformed device in the list.")
        if not isinstance(d["id"], str) or not DEV_RE.fullmatch(d["id"]) or not isinstance(d["name"], str) \
                or not 1 <= len(d["name"]) <= NAME_MAX or chat.CONTROL.search(d["name"]) or not chat._int(d["added"], 0, 2 ** 53):
            raise chat.Refuse(400, "Malformed device in the list.")
        chat.b64(d["kem_pq"], size=chat.KEM_PQ_PK, name="device key")
        chat.b64(d["kem_ec"], size=chat.KEM_EC_PK, name="device key")
        ids.append(d["id"])
    if ids != sorted(set(ids)):
        raise chat.Refuse(400, "Devices are listed once each, sorted by id.")
    return json.dumps({"b": value["b"], "s": value["s"]}, separators=(",", ":")), obj["seq"], ids, obj["fp"]

def publish_list(h, data):
    def go(c):
        chat.need(c, h, "chat.access.use")
        chat._limit(h.user, "device list changes", LIST_RATE)
        stored, seq, ids, fp = check_list(c, h.user, data.get("list"))
        old = c.execute("SELECT seq, fp FROM chat_device_lists WHERE username=?", (h.user,)).fetchone()
        # A new identity starts its own list; otherwise each change is exactly the next number.
        want = 1 if old is None or old["fp"] != fp else old["seq"] + 1
        if seq != want:
            raise chat.Refuse(409, "Your device list changed on another device. Reload and try again.", stale=True, seq=want - 1)
        c.execute("""INSERT INTO chat_device_lists(username, seq, fp, list, devices, updated) VALUES(?,?,?,?,?,?)
                     ON CONFLICT(username) DO UPDATE SET seq=excluded.seq, fp=excluded.fp, list=excluded.list,
                     devices=excluded.devices, updated=excluded.updated""",
                  (h.user, seq, fp, stored, json.dumps(ids), int(time.time())))
        gone = c.execute("DELETE FROM chat_acks WHERE username=? AND dev NOT IN (%s)" % ",".join("?" * len(ids)),
                         (h.user, *ids)).rowcount
        c.execute("DELETE FROM chat_sync WHERE username=? AND (dev NOT IN (%s))" % ",".join("?" * len(ids)), (h.user, *ids))
        c.execute("DELETE FROM chat_device_seen WHERE username=? AND dev NOT IN (%s)" % ",".join("?" * len(ids)), (h.user, *ids))
        c.execute("DELETE FROM chat_prekeys WHERE username=? AND dev NOT IN (%s)" % ",".join("?" * len(ids)), (h.user, *ids))
        # a removed device's per-device wraps open for nobody else: they go with it
        c.execute("DELETE FROM chat_dev_wraps WHERE username=? AND dev NOT IN (%s)" % ",".join("?" * len(ids)), (h.user, *ids))
        if data.get("dev") is not None:
            _mark(c, h, _dev(data["dev"], c, h.user))
        chat.audit(c, h.user, "chat.device_list", "user", h.user, detail={"seq": seq, "devices": len(ids), "acks_dropped": gone},
                   ctx=h.ctx())
        drop_wraps(c, h.user)
        chat._bump_dir(c)
        return 200, {"ok": True, "seq": seq}
    return chat.run(h, go)

def hello(h, data):
    def go(c):
        chat.need(c, h, "chat.access.use")
        _mark(c, h, _dev(data.get("dev"), c, h.user))
        return 200, {"ok": True, "deleted": drop_wraps(c, h.user) + drop_dev_wraps(c, h.user)}
    return chat.run(h, go)

def ack(h, room_id, data):
    def go(c):
        chat.need(c, h, "chat.access.use")
        room, _ = chat.room_for(c, h, room_id)
        dev = _dev(data.get("dev"), c, h.user)
        epochs = data.get("epochs")
        if not isinstance(epochs, list) or not 1 <= len(epochs) <= 1000 or not all(chat._int(e, 1, 2 ** 40) for e in epochs):
            raise chat.Refuse(400, "Give the room key numbers this device stored.")
        have = {r[0] for r in c.execute("SELECT epoch FROM chat_items WHERE room_id=? AND kind='epoch'", (room["id"],))}
        t = int(time.time())
        c.executemany("INSERT OR IGNORE INTO chat_acks(room_id, epoch, username, dev, at) VALUES(?,?,?,?,?)",
                      [(room["id"], e, h.user, dev, t) for e in set(epochs) if e in have])
        _mark(c, h, dev)
        return 200, {"ok": True, "deleted": drop_wraps(c, h.user) + drop_dev_wraps(c, h.user)}
    return chat.run(h, go)

# ------------------------------------------------------------------------------------------- prekeys (protocol 2)
def publish_prekey(h, data):
    """A device's new signed prekey. The server checks what it can (clients check the signature): it's for this person's
    current identity and a device on their list, its keys have the right sizes, and it lives at most 8 days."""
    def go(c):
        chat.need(c, h, "chat.access.use")
        chat._limit(h.user, "prekeys", PREKEY_RATE)
        dev = _dev(data.get("dev"), c, h.user)
        value = data.get("prekey")
        if not isinstance(value, dict):
            raise chat.Refuse(400, "Malformed prekey.")
        _, obj = chat.signed_json(value.get("b"), PREKEY_MAX, "prekey", versions=(2,))
        chat.b64(value.get("s"), size=chat.SIG_LEN, name="prekey signature")
        me = chat.identity(c, h.user)
        now = int(time.time() * 1000)
        if set(obj) != {"v", "t", "user", "fp", "dev", "id", "at", "exp", "kem_pq", "kem_ec"} or obj["t"] != "prekey" \
                or obj["user"] != h.user or me is None or obj["fp"] != me["fp"] or obj["dev"] != dev:
            raise chat.Refuse(409, "That prekey isn't for this device and your current identity.", stale=True)
        if not isinstance(obj["id"], str) or not DEV_RE.fullmatch(obj["id"]) or not chat._int(obj["at"], 0, now + 300000) \
                or not chat._int(obj["exp"], now + 1, obj["at"] + PREKEY_LIFE_MAX_MS):
            raise chat.Refuse(400, "Malformed prekey (an id, and a lifetime of at most 8 days from now).")
        chat.b64(obj["kem_pq"], size=chat.KEM_PQ_PK, name="prekey")
        chat.b64(obj["kem_ec"], size=chat.KEM_EC_PK, name="prekey")
        stored = json.dumps({"b": value["b"], "s": value["s"]}, separators=(",", ":"))
        c.execute("INSERT OR IGNORE INTO chat_prekeys(username, dev, id, at, exp, prekey) VALUES(?,?,?,?,?,?)",
                  (h.user, dev, obj["id"], obj["at"], obj["exp"], stored))
        c.execute("""DELETE FROM chat_prekeys WHERE username=? AND dev=? AND id NOT IN
                     (SELECT id FROM chat_prekeys WHERE username=? AND dev=? ORDER BY at DESC LIMIT ?)""",
                  (h.user, dev, h.user, dev, PREKEYS_KEPT))
        c.execute("DELETE FROM chat_prekeys WHERE username=? AND exp<?", (h.user, now))
        _mark(c, h, dev)
        chat._bump_dir(c)
        return 200, {"ok": True}
    return chat.run(h, go)

# ------------------------------------------------------------------------------------------- history sync
def sync_state(h, q):
    def go(c):
        chat.need(c, h, "chat.access.use")
        dev = _dev(q.get("dev"), c, h.user)
        rows = c.execute("SELECT * FROM chat_sync WHERE username=? ORDER BY created", (h.user,)).fetchall()
        return 200, {
            "requests": [{"id": r["id"], "dev": r["dev"], "at": r["created"]} for r in rows
                         if r["kind"] == "request" and r["dev"] != dev],
            "waiting": any(r["kind"] == "request" and r["dev"] == dev for r in rows),
            "packages": [{"id": r["id"], "from": r["from_dev"], "blob": r["blob"], "at": r["created"]} for r in rows
                         if r["kind"] == "package" and r["dev"] == dev]}
    return chat.run(h, go, write=False)

def sync_request(h, data):
    def go(c):
        chat.need(c, h, "chat.access.use")
        chat._limit(h.user, "history requests", SYNC_RATE)
        dev = _dev(data.get("dev"), c, h.user)
        c.execute("DELETE FROM chat_sync WHERE username=? AND kind='request' AND dev=?", (h.user, dev))
        c.execute("INSERT INTO chat_sync(id, username, kind, dev, created) VALUES(?,?, 'request', ?,?)",
                  (secrets.token_hex(8), h.user, dev, int(time.time())))
        chat.audit(c, h.user, "chat.sync_request", "user", h.user, detail={"dev": dev}, ctx=h.ctx())
        chat._bump_dir(c)
        return 200, {"ok": True}
    return chat.run(h, go)

def sync_send(h, data):
    def go(c):
        chat.need(c, h, "chat.access.use")
        chat._disk_ok()
        chat._limit(h.user, "history packages", SYNC_RATE)
        to, frm = _dev(data.get("to"), c, h.user), _dev(data.get("from"), c, h.user)
        if to == frm:
            raise chat.Refuse(400, "A device can't send its history to itself.")
        req = c.execute("SELECT id FROM chat_sync WHERE username=? AND kind='request' AND dev=?", (h.user, to)).fetchone()
        if req is None:
            raise chat.Refuse(409, "That device isn't asking for history (any more).", stale=True)
        blob = data.get("blob")
        chat.b64(blob, max_len=PACKAGE_MAX, name="history package")
        if c.execute("SELECT COUNT(*) FROM chat_sync WHERE username=? AND kind='package' AND dev=?", (h.user, to)).fetchone()[0] >= PACKAGES_MAX:
            raise chat.Refuse(400, "Too many history packages are waiting for that device.")
        c.execute("INSERT INTO chat_sync(id, username, kind, dev, from_dev, blob, created) VALUES(?,?, 'package', ?,?,?,?)",
                  (secrets.token_hex(8), h.user, to, frm, blob, int(time.time())))
        if data.get("last") is True:
            c.execute("DELETE FROM chat_sync WHERE id=?", (req["id"],))
        _mark(c, h, frm)
        chat.audit(c, h.user, "chat.sync_send", "user", h.user, detail={"to": to, "from": frm, "bytes": len(blob)}, ctx=h.ctx())
        chat._bump_dir(c)
        return 200, {"ok": True}
    return chat.run(h, go)

def sync_close(h, data, kind):
    def go(c):
        chat.need(c, h, "chat.access.use")
        sid = data.get("id")
        n = c.execute("DELETE FROM chat_sync WHERE id=? AND username=? AND kind=?",
                      (sid if isinstance(sid, str) else "", h.user, kind)).rowcount
        if not n:
            raise chat.Refuse(404, "Nothing like that is waiting.")
        chat._bump_dir(c)
        return 200, {"ok": True}
    return chat.run(h, go)

def route(h, method, path, q, data):
    if method == "GET":
        return sync_state(h, q) if path == "sync" else None
    if path == "keydevices":
        return publish_list(h, data)
    if path == "store/hello":
        return hello(h, data)
    if path == "keydevices/prekey":
        return publish_prekey(h, data)
    if path == "sync/request":
        return sync_request(h, data)
    if path == "sync/send":
        return sync_send(h, data)
    if path == "sync/done":
        return sync_close(h, data, "package")
    if path == "sync/decline":
        return sync_close(h, data, "request")
    m = re.fullmatch(r"rooms/([^/]{1,40})/ack", path)
    if m:
        return ack(h, m.group(1), data)
    return None
