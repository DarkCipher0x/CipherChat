"""CipherChat add-ons: programs (bots, connectors to other systems) that take part in the chat with an identity of their
own, never with a person's. See docs/ADDONS.md.

What makes them safe:
  * End to end, unchanged. An add-on is a chat member like any other: its own hybrid post-quantum identity (ML-DSA-87 +
    Ed25519, ML-KEM-1024 + X25519), made on the add-on's machine and certified by the owner after comparing safety
    numbers. It reads only rooms a room admin added it to, and everyone sees it's an add-on. The server never gets
    plaintext or keys, so an add-on can't be used to read the chat through the server either.
  * Signed requests, no bearer tokens. Each request carries HMAC-SHA3-256 over the method, path, server origin,
    add-on, time, a one-time nonce and the SHA3-256 of the body, keyed with a 256-bit secret. A copied request can't be
    replayed (nonce + 90 s window) or altered, and the secret never travels after it's handed over once. Symmetric
    256-bit keys and SHA-3 keep their strength against quantum computers; the connection itself is TLS 1.3 with
    X25519MLKEM768 only.
  * No stored secret. The secret is derived from the server key (CIPHERCHAT_KEY_FILE, never in the database) with
    HMAC-SHA3-256; the database holds only a salt and a version, so a copy of it gives nothing. Rotating changes the
    salt; disabling stops it at once.
  * Least privilege. Add-ons reach only the routes in ROUTES (state, poll, history, room keys, sending, attachments,
    direct messages), each behind its scope; never accounts, devices, backups, certificates, room settings or calls.
    Optional IP allowlist, expiry and a per-add-on rate limit; every refusal and every management step is audited.
  * Owner only. Only the owner creates, changes or removes add-ons, after confirming with their authenticator code.
"""
import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import threading
import time
from collections import deque

import authz
from authz import audit, tx, is_owner

core = None        # the server module (db, ORIGIN, ...), set by bind()
chat = None
storage = None

PREFIX = "addon."
NAME_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,24}[a-z0-9])?")
SCOPES = ("send", "files", "dm")
WINDOW = 90                         # seconds a signed request stays valid either side of the server's clock
NONCE_RE = re.compile(r"[A-Za-z0-9_-]{22,64}")
SIG_RE = re.compile(r"[0-9a-f]{64}")
HASH_RE = re.compile(r"[0-9a-f]{64}")
EMPTY_SHA3 = hashlib.sha3_256(b"").hexdigest()
MAX_DAYS = 730
RATE_MIN, RATE_MAX, RATE_DEFAULT = 10, 1200, 240
MAX_IPS = 16
CODE_PREFIX = "ccaddon1."
LABEL = b"cipherchat-addon/v1"

# (method, route pattern after /chat/api/, scope or None = read)
ROUTES = [
    ("GET", re.compile(r"state"), None),
    ("GET", re.compile(r"poll"), None),
    ("GET", re.compile(r"rooms/[^/]{1,40}/items"), None),
    ("GET", re.compile(r"rooms/[^/]{1,40}/epochs"), None),
    ("GET", re.compile(r"blob/[0-9a-f]{16}/[0-9a-f]{24}"), "files"),
    ("POST", re.compile(r"identity"), None),                   # once: the add-on's own identity (never a reset)
    ("POST", re.compile(r"rooms/[^/]{1,40}/send"), "send"),
    ("POST", re.compile(r"rooms/[^/]{1,40}/burn"), None),      # "I opened this burn-after-reading message"
    ("POST", re.compile(r"rooms/[^/]{1,40}/leave"), None),
    ("POST", re.compile(r"upload/[0-9a-f]{16}"), "files"),
    ("POST", re.compile(r"dm"), "dm"),
]

_rate_lock = threading.Lock()
_rates = {}


class Refuse(Exception):
    def __init__(self, code, message, **extra):
        super().__init__(message)
        self.code, self.message, self.extra = code, message, extra


def bind(server_module, chat_module, storage_module):
    global core, chat, storage
    core, chat, storage = server_module, chat_module, storage_module


def migrate(c):
    c.executescript("""
    CREATE TABLE IF NOT EXISTS addons(
        username TEXT PRIMARY KEY REFERENCES admins(username) ON DELETE CASCADE,
        salt TEXT NOT NULL, key_ver INTEGER NOT NULL, scopes TEXT NOT NULL DEFAULT '[]',
        ip_allow TEXT NOT NULL DEFAULT '[]', rate INTEGER NOT NULL DEFAULT 240, expires INTEGER NOT NULL,
        description TEXT NOT NULL DEFAULT '', created TEXT NOT NULL, created_by TEXT NOT NULL,
        rotated TEXT, last_used INTEGER NOT NULL DEFAULT 0, last_ip TEXT NOT NULL DEFAULT '');
    CREATE TABLE IF NOT EXISTS addon_nonces(
        username TEXT NOT NULL, nonce TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY(username, nonce));
    CREATE INDEX IF NOT EXISTS idx_addon_nonces_at ON addon_nonces(at);
    """)


def is_addon(username):
    return isinstance(username, str) and username.startswith(PREFIX)


# ------------------------------------------------------------------------------------------- the secret
def _b64u(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def secret_for(row):
    """The add-on's 256-bit request key: HMAC-SHA3-256 under the server key, so the database never holds it."""
    ring = storage.KEYRING
    if ring is None:
        raise Refuse(503, "The server key isn't loaded, so add-ons can't be checked.")
    ver = int(row["key_ver"])
    if ver not in ring.keys:
        raise Refuse(401, "Add-on authentication failed.")
    msg = LABEL + b"|" + row["username"].encode() + b"|" + str(ver).encode() + b"|" + row["salt"].encode()
    return hmac.new(ring.get(ver), msg, hashlib.sha3_256).digest()


def canonical(method, target, user, ts, nonce, body_sha3):
    """The exact bytes an add-on signs (docs/ADDONS.md)."""
    return "\n".join(["CIPHERCHAT-ADDON-V1", core.ORIGIN, method, target, user, ts, nonce, body_sha3]).encode()


def connector_code(user, secret):
    blob = json.dumps({"o": core.ORIGIN, "u": user, "k": _b64u(secret)}, separators=(",", ":")).encode()
    return CODE_PREFIX + _b64u(blob)


# ------------------------------------------------------------------------------------------- request checks
def _rate_ok(user, per_minute):
    t = time.time()
    with _rate_lock:
        q = _rates.setdefault(user, deque())
        while q and q[0] < t - 60:
            q.popleft()
        if len(q) >= per_minute:
            return False
        q.append(t)
        if len(_rates) > 10000:
            _rates.clear()
        return True


def _ip_ok(ip, allow):
    if not allow:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in allow:
        try:
            if addr in ipaddress.ip_network(net, strict=False):
                return True
        except ValueError:
            continue
    return False


def route_scope(method, rest):
    """(allowed, scope needed) for an add-on calling /chat/api/<rest>."""
    for m, pat, scope in ROUTES:
        if m == method and pat.fullmatch(rest):
            return True, scope
    return False, None


def authenticate(h, method, target, rest):
    """Checks an add-on's signed request. On success sets h.user / h.session / h.addon and returns None; otherwise
    (status, payload). For a JSON POST the body is read and checked here (h.rfile is replaced by the checked bytes);
    an upload's body hash is checked by the upload as it streams (h.body_sha3)."""
    fail = (401, {"error": "Add-on authentication failed."})
    hdr = h.headers
    user = (hdr.get("X-CipherChat-Addon") or "").strip()
    ts = (hdr.get("X-CipherChat-Time") or "").strip()
    nonce = (hdr.get("X-CipherChat-Nonce") or "").strip()
    sig = (hdr.get("X-CipherChat-Signature") or "").strip().lower()
    body_sha3 = (hdr.get("X-CipherChat-Content-SHA3") or "").strip().lower()
    ip = h.client_ip()
    if core.limited("addon", ip):
        h.drain()
        return 429, {"error": "Too many add-on requests from this address. Slow down."}
    if hdr.get("Cookie") or hdr.get("Authorization"):
        h.drain()
        return 400, {"error": "Add-on requests carry no cookies or other credentials."}
    if (not is_addon(user) or not authz.USER_RE.fullmatch(user) or not ts.isascii() or not ts.isdigit() or len(ts) > 12
            or not NONCE_RE.fullmatch(nonce) or not SIG_RE.fullmatch(sig) or not HASH_RE.fullmatch(body_sha3)):
        h.drain()
        return fail
    t = int(time.time())
    if abs(t - int(ts)) > WINDOW:
        h.drain()
        _deny(h, user, "clock")
        return 401, {"error": "Add-on authentication failed: the request's time is off by more than %d s." % WINDOW,
                     "server_time": t}
    with core.db() as c:
        row = c.execute("SELECT * FROM addons WHERE username=?", (user,)).fetchone()
        acc = authz.account(c, user) if row else None
    if row is None or acc is None or acc.get("cred_disabled") or authz.inactive_reason(acc) or row["expires"] <= t:
        h.drain()
        _deny(h, user, "inactive" if row else "unknown")
        return fail
    try:
        secret = secret_for(row)
    except Refuse as e:
        h.drain()
        return e.code, {"error": e.message}
    want = hmac.new(secret, canonical(method, target, user, ts, nonce, body_sha3), hashlib.sha3_256).hexdigest()
    if not hmac.compare_digest(want, sig):
        h.drain()
        _deny(h, user, "signature")
        return fail
    if not _ip_ok(ip, json.loads(row["ip_allow"])):
        h.drain()
        _deny(h, user, "ip")
        return 403, {"error": "This add-on isn't allowed to connect from this address.", "denied": True}
    allowed, scope = route_scope(method, rest)
    scopes = json.loads(row["scopes"])
    if not allowed or (scope and scope not in scopes):
        h.drain()
        _deny(h, user, "route", rest=rest[:60])
        return 403, {"error": "Add-ons can't do that%s." % ("" if not allowed else " without the '%s' scope" % scope), "denied": True}
    if not _rate_ok(user, row["rate"]):
        h.drain()
        return 429, {"error": "This add-on went over its rate limit (%d requests a minute)." % row["rate"]}
    # the body: what was signed must be what arrived
    try:
        length = int(hdr.get("Content-Length", "0") or "0")
    except ValueError:
        length = -1
    if method == "GET":
        if length != 0 or body_sha3 != EMPTY_SHA3:
            h.drain()
            return fail
    elif rest.startswith("upload/"):
        h.body_sha3 = body_sha3                      # checked by chat.upload_blob while it streams
    else:
        if length <= 0 or length > chat.BODY_MAX:
            h.drain()
            return 400, {"error": "Invalid request."}
        body = h.rfile.read(length)
        if len(body) != length or not hmac.compare_digest(hashlib.sha3_256(body).hexdigest(), body_sha3):
            _deny(h, user, "body")
            return fail
        h.rfile = core._Body(_Bytes(body), length)
    # one use only: the nonce is remembered for longer than the window
    try:
        with tx(core.db) as c:
            c.execute("DELETE FROM addon_nonces WHERE at < ?", (t - 3 * WINDOW,))
            c.execute("INSERT INTO addon_nonces(username, nonce, at) VALUES(?,?,?)", (user, nonce, t))
            tag = core.ip_tag(ip)                       # never the address itself
            if t - row["last_used"] > 60 or row["last_ip"] != tag:
                c.execute("UPDATE addons SET last_used=?, last_ip=? WHERE username=?", (t, tag, user))
    except core.sqlite3.IntegrityError:
        _deny(h, user, "replay")
        return fail
    h.user = user
    h.addon = {"user": user, "scopes": scopes}
    # A signed request is a fresh proof of the key, but add-ons never reach the steps that ask for re-authentication
    # (only their first identity, which the server allows once).
    h.session = {"sid": "addon", "reauth_at": t, "scope": "addon", "token_hash": "", "device_id": None}
    return None


class _Bytes:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def read(self, n=-1):
        if n is None or n < 0:
            n = len(self.data) - self.pos
        out = self.data[self.pos:self.pos + n]
        self.pos += len(out)
        return out


def _deny(h, user, why, **detail):
    try:
        with tx(core.db) as c:
            audit(c, user if is_addon(user) else "?", "addon.request_refused", "addon", user[:40], "denied",
                  dict(detail, why=why), h.ctx())
    except Exception:                                # the refusal stands even if the audit write fails
        pass


# ------------------------------------------------------------------------------------------- management (owner)
def _run(h, fn):
    try:
        with tx(core.db) as c:
            out = fn(c)
        chat._notify()
        return out
    except Refuse as e:
        payload = {"error": e.message}
        payload.update(e.extra)
        return e.code, payload
    except chat.Refuse as e:
        payload = {"error": e.message}
        payload.update(e.extra)
        return e.code, payload


def _owner(c, h, fresh=True):
    if getattr(h, "addon", None) or not is_owner(h.user):
        raise Refuse(403, "Only the owner manages add-ons.", denied=True)
    if fresh:
        chat.need_reauth(c, h)


def _scopes(v):
    if not isinstance(v, list) or len(v) > len(SCOPES) or not all(isinstance(s, str) and s in SCOPES for s in v):
        raise Refuse(400, "Scopes are any of: %s." % ", ".join(SCOPES))
    return sorted(set(v))


def _ips(v):
    if v is None:
        return []
    if not isinstance(v, list) or len(v) > MAX_IPS:
        raise Refuse(400, "Give up to %d addresses or networks." % MAX_IPS)
    out = []
    for item in v:
        try:
            out.append(str(ipaddress.ip_network(str(item).strip(), strict=False)))
        except ValueError:
            raise Refuse(400, "%s isn't an IP address or network." % str(item)[:50])
    return out


def _int(v, lo, hi, default):
    if v is None:
        return default
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise Refuse(400, "A number from %d to %d, please." % (lo, hi))
    return v


def _view(c, r):
    ident = chat.identity(c, r["username"])
    acc = authz.account(c, r["username"]) or {}
    rooms = [x[0] for x in c.execute("SELECT room_id FROM chat_members WHERE username=?", (r["username"],))]
    return {"user": r["username"], "display_name": acc.get("display_name") or "", "description": r["description"],
            "scopes": json.loads(r["scopes"]), "ip_allow": json.loads(r["ip_allow"]), "rate": r["rate"],
            "expires": r["expires"], "enabled": not acc.get("cred_disabled") and not authz.inactive_reason(acc),
            "created": r["created"], "rotated": r["rotated"], "last_used": r["last_used"],
            "identity_fp": ident["fp"] if ident else None, "certified": chat.certified(ident), "rooms": len(rooms)}


def list_all(h):
    def go(c):
        _owner(c, h, fresh=False)
        rows = c.execute("SELECT * FROM addons ORDER BY username").fetchall()
        return 200, {"addons": [_view(c, r) for r in rows], "scopes": list(SCOPES)}
    return _run(h, go)


def create(h, data):
    def go(c):
        _owner(c, h)
        name = data.get("name")
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise Refuse(400, "Add-on names are 1-26 of a-z, 0-9 and '-' (not starting or ending with '-').")
        user = PREFIX + name
        if c.execute("SELECT 1 FROM admins WHERE username=?", (user,)).fetchone():
            raise Refuse(409, "There's already an add-on called %s." % name)
        if c.execute("SELECT COUNT(*) FROM addons").fetchone()[0] >= 50:
            raise Refuse(400, "A chat can have up to 50 add-ons.")
        scopes = _scopes(data.get("scopes", ["send"]))
        ips = _ips(data.get("ip_allow"))
        days = _int(data.get("days"), 1, MAX_DAYS, 365)
        rate = _int(data.get("rate"), RATE_MIN, RATE_MAX, RATE_DEFAULT)
        t = core.now()
        # no password, no authenticator, no passkeys: an add-on can't sign in as a person
        c.execute("INSERT INTO admins(username, pw_hash, totp_secret, created) VALUES(?,?,?,?)",
                  (user, "!addon", secrets.token_hex(20), t))
        c.execute("""INSERT INTO accounts(username, display_name, status, role, created, created_by, updated, updated_by, notes)
                     VALUES(?,?,?,?,?,?,?,?,?)""", (user, core.clean(data.get("display_name") or name, 60), "active", "addon",
                                                    t, h.user, t, h.user, "add-on"))
        row = {"username": user, "salt": secrets.token_hex(16), "key_ver": storage.KEYRING.current if storage.KEYRING else 0}
        secret = secret_for(row)
        c.execute("""INSERT INTO addons(username, salt, key_ver, scopes, ip_allow, rate, expires, description, created, created_by)
                     VALUES(?,?,?,?,?,?,?,?,?,?)""", (user, row["salt"], row["key_ver"], json.dumps(scopes), json.dumps(ips), rate,
                                                     int(time.time()) + days * 86400, core.clean(data.get("description"), 200), t, h.user))
        audit(c, h.user, "addon.create", "addon", user, detail={"scopes": scopes, "ips": len(ips), "days": days, "rate": rate}, ctx=h.ctx())
        chat._bump_dir(c)
        return 200, {"ok": True, "user": user, "code": connector_code(user, secret),
                     "note": "Shown once. Give it to the add-on's configuration only; it can't be shown again (rotate for a new one)."}
    return _run(h, go)


def _target(c, user):
    row = c.execute("SELECT * FROM addons WHERE username=?", (user,)).fetchone() if is_addon(user) else None
    if row is None:
        raise Refuse(404, "No such add-on.")
    return row


def action(h, user, what, data):
    def go(c):
        _owner(c, h)
        row = _target(c, user)
        t = core.now()
        if what == "update":
            sets, detail = {}, {}
            if "scopes" in data:
                sets["scopes"] = json.dumps(_scopes(data["scopes"]))
                detail["scopes"] = json.loads(sets["scopes"])
            if "ip_allow" in data:
                sets["ip_allow"] = json.dumps(_ips(data["ip_allow"]))
                detail["ips"] = len(json.loads(sets["ip_allow"]))
            if "rate" in data:
                sets["rate"] = _int(data["rate"], RATE_MIN, RATE_MAX, RATE_DEFAULT)
                detail["rate"] = sets["rate"]
            if "days" in data:
                sets["expires"] = int(time.time()) + _int(data["days"], 1, MAX_DAYS, 365) * 86400
                detail["days"] = data["days"]
            if "description" in data:
                sets["description"] = core.clean(data["description"], 200)
            if not sets:
                raise Refuse(400, "Nothing to change.")
            c.execute("UPDATE addons SET %s WHERE username=?" % ", ".join(k + "=?" for k in sets), (*sets.values(), user))
            audit(c, h.user, "addon.update", "addon", user, detail=detail, ctx=h.ctx())
            return 200, {"ok": True}
        if what == "rotate":
            row = dict(row, salt=secrets.token_hex(16), key_ver=storage.KEYRING.current if storage.KEYRING else 0)
            secret = secret_for(row)
            c.execute("UPDATE addons SET salt=?, key_ver=?, rotated=? WHERE username=?", (row["salt"], row["key_ver"], t, user))
            c.execute("DELETE FROM addon_nonces WHERE username=?", (user,))
            audit(c, h.user, "addon.rotate", "addon", user, ctx=h.ctx())
            return 200, {"ok": True, "code": connector_code(user, secret),
                         "note": "The old code stopped working just now. Shown once."}
        if what in ("disable", "enable"):
            c.execute("UPDATE admins SET disabled=? WHERE username=?", (1 if what == "disable" else 0, user))
            c.execute("UPDATE accounts SET status=?, updated=?, updated_by=? WHERE username=?",
                      ("disabled" if what == "disable" else "active", t, h.user, user))
            audit(c, h.user, "addon." + what, "addon", user, ctx=h.ctx())
            chat._bump_dir(c)
            return 200, {"ok": True}
        if what == "delete":
            # out of every room (they get new keys without it), identity gone, then the account
            for (room_id,) in c.execute("SELECT room_id FROM chat_members WHERE username=?", (user,)).fetchall():
                c.execute("DELETE FROM chat_members WHERE room_id=? AND username=?", (room_id, user))
                if not c.execute("SELECT 1 FROM chat_members WHERE room_id=?", (room_id,)).fetchone():
                    c.execute("DELETE FROM chat_rooms WHERE id=?", (room_id,))
                else:
                    chat._event(c, room_id, h.user, e="members", add=[], remove=[user], admin=[], member=[])
            c.execute("DELETE FROM chat_identities WHERE username=?", (user,))
            c.execute("DELETE FROM addon_nonces WHERE username=?", (user,))
            c.execute("DELETE FROM addons WHERE username=?", (user,))
            c.execute("DELETE FROM sessions WHERE user=?", (user,))
            c.execute("DELETE FROM accounts WHERE username=?", (user,))
            c.execute("DELETE FROM admins WHERE username=?", (user,))
            audit(c, h.user, "addon.delete", "addon", user, ctx=h.ctx())
            chat._bump_dir(c)
            return 200, {"ok": True}
        raise Refuse(404, "not found")
    return _run(h, go)


def route(h, method, rest, data):
    """/chat/api/addons... for the owner (a person's session, never an add-on's)."""
    if method == "GET" and rest == "addons":
        return list_all(h)
    if method == "POST" and rest == "addons":
        return create(h, data)
    m = re.fullmatch(r"addons/(addon\.[a-z0-9-]{1,26})/(update|rotate|disable|enable|delete)", rest)
    if method == "POST" and m:
        return action(h, m.group(1), m.group(2), data)
    return 404, {"error": "not found"}
