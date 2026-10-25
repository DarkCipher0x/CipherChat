"""CipherChat accounts, roles and the audit log.

The chat server modules (chat.py, chat_requests.py) are shared with the DarkCipher Systems portal and were written
against its `authz` module; this is CipherChat's own, much smaller implementation of the same interface:

  OWNER, USER_RE, WRITE_LOCK, now(), is_owner(), tx(), _add_col(), account(), inactive_reason(), decide(),
  settings(), audit()

Roles (one per account):
  owner   the single account named by CIPHERCHAT_OWNER: the chat's trust anchor, and everything below
  admin   reviews access requests and manages accounts (never the owner's), plus member
  member  uses the chat and creates rooms
  guest   uses the chat (joins rooms and direct messages others start); can't create rooms
"""
import hashlib
import json
import os
import re
import secrets
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

OWNER = os.environ.get("CIPHERCHAT_OWNER", "owner").strip().lower()
USER_RE = re.compile(r"[a-z0-9._-]{3,32}")
ROLE_RE = re.compile(r"[a-z][a-z0-9-]{1,23}")
STATUSES = ("pending", "active", "suspended", "disabled", "deleted")
WRITE_LOCK = threading.RLock()

# Every permission, one switch each (id, group, label). Roles are sets of these; a person can also be granted or denied
# single permissions on top of their role. Things only the owner may ever do are not permissions at all: certifying
# identities, add-ons, the owner account itself.
PERMISSIONS = [
    ("chat.access.use", "Chat", "Use the chat"),
    ("chat.rooms.create", "Chat", "Create rooms"),
    ("chat.dm.start", "Chat", "Start direct messages"),
    ("chat.files.send", "Chat", "Send files, pictures and videos"),
    ("chat.calls.start", "Chat", "Start voice and video calls"),
    ("chat.devices.pair", "Chat", "Pair the CipherChat apps"),
    ("admin.requests.review", "Administration", "Review access requests"),
    ("admin.users.view", "Administration", "See people and their access"),
    ("admin.users.create", "Administration", "Invite people"),
    ("admin.users.update", "Administration", "Suspend, reactivate, sign out and send reset links"),
    ("admin.users.delete", "Administration", "Delete accounts"),
    ("admin.users.roles", "Administration", "Change people's roles and permissions"),
    ("admin.roles.manage", "Administration", "Create and edit roles"),
    ("admin.audit.view", "Administration", "Read the audit log"),
    ("admin.settings.manage", "Administration", "Change server settings"),
    ("admin.mail.manage", "Administration", "Set up email and notifications"),
]
CATALOG = [p[0] for p in PERMISSIONS]
_CHAT = {"chat.access.use", "chat.dm.start", "chat.files.send", "chat.calls.start", "chat.devices.pair"}
# Built-in roles (their permissions can be edited by whoever may manage roles; the roles themselves can't be deleted)
BUILTIN_ROLES = {
    "guest": ("Guest", _CHAT),
    "member": ("Member", _CHAT | {"chat.rooms.create"}),
    "admin": ("Admin", set(CATALOG) - {"admin.roles.manage"}),
}
ROLES = tuple(BUILTIN_ROLES)                           # the built-in names (more can be created)
ADDON_PERMS = frozenset({"chat.access.use", "chat.files.send", "chat.dm.start"})   # their scopes (addons.py) narrow these per add-on

# Server settings with their types and limits (settings_api.py edits them; everything reads them through settings()).
# (default, kind, low, high): kind int | bool | str
SETTINGS_SCHEMA = {
    "invite_hours": (72, "int", 1, 720), "reauth_minutes": (10, "int", 1, 60), "password_min": (14, "int", 12, 128),
    "session_hours": (12, "int", 1, 72), "session_idle_minutes": (120, "int", 5, 1440),
    "lockout_attempts": (5, "int", 3, 20), "lockout_minutes": (15, "int", 1, 1440),
    "upload_max_mb": (100, "int", 1, 100), "access_requests": (True, "bool", 0, 0), "request_role": ("member", "str", 0, 24),
    "name": ("", "str", 0, 60),
}
SETTINGS_DEFAULTS = {k: v[0] for k, v in SETTINGS_SCHEMA.items()}

if not USER_RE.fullmatch(OWNER):
    raise SystemExit("CIPHERCHAT_OWNER must be a valid username (3-32 of a-z 0-9 . _ -)")


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_owner(username):
    return username == OWNER


@contextmanager
def tx(connect):
    """Write transaction holding SQLite's write lock from the start (BEGIN IMMEDIATE) and the process-wide
    WRITE_LOCK, so multi-step changes and the audit chain are atomic."""
    with WRITE_LOCK:
        c = connect()
        c.isolation_level = None
        try:
            c.execute("BEGIN IMMEDIATE")
            yield c
            c.execute("COMMIT")
        except BaseException:
            if c.in_transaction:
                c.execute("ROLLBACK")
            raise
        finally:
            c.close()


def _cols(c, table):
    return [r[1] for r in c.execute("PRAGMA table_info(%s)" % table)]


def _add_col(c, table, col, decl):
    if col not in _cols(c, table):
        c.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, col, decl))


def migrate(c):
    """Idempotent schema. Credentials live in `admins` and the account state in `accounts` (the table names the
    shared chat modules use)."""
    c.executescript("""
    CREATE TABLE IF NOT EXISTS admins(
        username TEXT PRIMARY KEY, pw_hash TEXT NOT NULL, totp_secret TEXT NOT NULL,
        totp_last INTEGER NOT NULL DEFAULT 0, fails INTEGER NOT NULL DEFAULT 0,
        fail_start INTEGER NOT NULL DEFAULT 0, disabled INTEGER NOT NULL DEFAULT 0,
        created TEXT NOT NULL, last_login TEXT);
    CREATE TABLE IF NOT EXISTS accounts(
        username TEXT PRIMARY KEY REFERENCES admins(username) ON DELETE CASCADE,
        display_name TEXT NOT NULL DEFAULT '', email TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending', role TEXT NOT NULL DEFAULT 'member',
        must_change_pw INTEGER NOT NULL DEFAULT 0, locked INTEGER NOT NULL DEFAULT 0, expires_at TEXT,
        notes TEXT NOT NULL DEFAULT '', created TEXT NOT NULL, created_by TEXT NOT NULL DEFAULT '',
        updated TEXT, updated_by TEXT);
    CREATE TABLE IF NOT EXISTS sessions(
        token_hash TEXT PRIMARY KEY, user TEXT NOT NULL, expires INTEGER NOT NULL, last_seen INTEGER NOT NULL,
        sid TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL DEFAULT 0, ua TEXT NOT NULL DEFAULT '',
        scope TEXT NOT NULL DEFAULT 'chat', reauth_at INTEGER NOT NULL DEFAULT 0, api_key TEXT);
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user);
    CREATE TABLE IF NOT EXISTS enrolments(
        token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, kind TEXT NOT NULL, created TEXT NOT NULL,
        created_by TEXT NOT NULL, expires INTEGER NOT NULL, used_at TEXT, attempts INTEGER NOT NULL DEFAULT 0,
        pending_pw TEXT, pending_secret TEXT);
    CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS roles(
        name TEXT PRIMARY KEY, label TEXT NOT NULL, perms TEXT NOT NULL, builtin INTEGER NOT NULL DEFAULT 0,
        created TEXT NOT NULL, updated TEXT NOT NULL, updated_by TEXT NOT NULL DEFAULT '');
    CREATE TABLE IF NOT EXISTS audit_log(
        seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL, at TEXT NOT NULL, actor TEXT NOT NULL,
        action TEXT NOT NULL, target_type TEXT NOT NULL, target_id TEXT NOT NULL, outcome TEXT NOT NULL,
        detail TEXT NOT NULL, request_id TEXT NOT NULL, ip TEXT NOT NULL, ua TEXT NOT NULL,
        prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
    """)
    _add_col(c, "accounts", "grants", "TEXT NOT NULL DEFAULT '[]'")       # single permissions on top of the role
    _add_col(c, "accounts", "denies", "TEXT NOT NULL DEFAULT '[]'")       # single permissions taken away from the role
    t = now()
    for name, (label, perms) in BUILTIN_ROLES.items():
        if not c.execute("SELECT 1 FROM roles WHERE name=?", (name,)).fetchone():
            c.execute("INSERT INTO roles(name, label, perms, builtin, created, updated, updated_by) VALUES(?,?,?,1,?,?,'setup')",
                      (name, label, json.dumps(sorted(perms)), t, t))


# ------------------------------------------------------------------------------------------- permissions
def _perm_list(raw):
    try:
        v = json.loads(raw or "[]")
    except ValueError:
        return set()
    return {p for p in v if p in CATALOG} if isinstance(v, list) else set()


def role_perms(c, name):
    row = c.execute("SELECT perms FROM roles WHERE name=?", (name,)).fetchone()
    return _perm_list(row[0]) if row else None


def role_names(c):
    return [r[0] for r in c.execute("SELECT name FROM roles ORDER BY builtin DESC, name")]


def effective(c, acc):
    """Everything this account may do: its role's permissions, plus its grants, minus its denies. The owner holds all;
    an add-on only uses the chat. An unknown role counts as guest."""
    if acc is None:
        return set()
    role = role_of(acc)
    if role == "owner":
        return set(CATALOG)
    if role == "addon":
        return set(ADDON_PERMS)
    perms = role_perms(c, role)
    if perms is None:
        perms = role_perms(c, "guest") or set()
    return (perms | _perm_list(acc.get("grants"))) - _perm_list(acc.get("denies"))


def may_grant(c, actor, perms):
    """Escalation guard: nobody hands out a permission they don't hold themselves (the owner holds all)."""
    if is_owner(actor):
        return True
    mine = effective(c, account(c, actor))
    return "admin.users.roles" in mine and set(perms) <= mine


def may_manage(c, actor, target_acc):
    """Someone may change another account only if that account's permissions are a strict subset of theirs, so equals
    can't lock each other out and nobody can touch someone more powerful. The owner may change anyone but themself
    in these ways; nobody may change the owner."""
    if target_acc is None or is_owner(target_acc["username"]):
        return False
    if is_owner(actor):
        return True
    mine = effective(c, account(c, actor))
    return effective(c, target_acc) < mine


def account(c, username):
    """Credentials + account state (no secrets), or None."""
    r = c.execute("""SELECT a.username, a.disabled AS cred_disabled, a.fails, a.fail_start, a.last_login,
                     a.created AS cred_created, x.* FROM admins a LEFT JOIN accounts x ON x.username = a.username
                     WHERE a.username=?""", (username,)).fetchone()
    if r is None:
        return None
    d = dict(r)
    d["username"] = r[0]
    if d.get("status") is None:                    # credentials without an account row: no access at all
        d.update({"status": "disabled", "role": "guest", "locked": 0, "must_change_pw": 0, "expires_at": None,
                  "display_name": "", "email": "", "notes": "", "created": d["cred_created"], "created_by": ""})
    # the shared modules read these two: CipherChat has no admin console or storage area
    d["console_access"] = 0
    d["storage_access"] = 0
    return d


def expired(acc, at=None):
    e = acc.get("expires_at")
    return bool(e) and e <= (at or now())


def inactive_reason(acc):
    """None if the account may act, else a short reason."""
    if acc is None:
        return "no such account"
    if acc["cred_disabled"] or acc["status"] != "active":
        return "account %s" % (acc["status"] if acc["status"] != "active" else "disabled")
    if acc["locked"]:
        return "account locked"
    if expired(acc):
        return "account expired"
    return None


def role_of(acc):
    if acc is None:
        return None
    if is_owner(acc["username"]):
        return "owner"
    if acc.get("role") == "addon" and acc["username"].startswith("addon."):
        return "addon"                                     # addons.py: a program, never a person's role
    role = acc.get("role")
    return role if isinstance(role, str) and ROLE_RE.fullmatch(role) and role != "addon" else "guest"


def decide(c, username, perm, space_id=None, acc=None):
    """(allowed, reason) for an account that may act right now."""
    acc = acc or account(c, username)
    why = inactive_reason(acc)
    if why:
        return False, why
    role = role_of(acc)
    if role == "owner":
        return True, "owner"
    if perm in effective(c, acc):
        return True, "role " + role
    label = dict((p[0], p[2]) for p in PERMISSIONS).get(perm, perm)
    return False, "you don't have the \"%s\" permission" % label


def password_problems(pw, username, minimum=14):
    probs = []
    if not isinstance(pw, str) or len(pw) < minimum:
        probs.append("at least %d characters" % minimum)
    elif len(pw) > 1024:
        probs.append("at most 1024 characters")
    elif username and username.lower() in pw.lower():
        probs.append("must not contain the username")
    elif len(set(pw)) < 6:
        probs.append("too repetitive")
    return probs


def setting_ok(key, v):
    """True if v is a valid value for this setting (SETTINGS_SCHEMA)."""
    default, kind, lo, hi = SETTINGS_SCHEMA[key]
    if kind == "int":
        return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi
    if kind == "bool":
        return isinstance(v, bool)
    return isinstance(v, str) and len(v) <= hi and not any(ord(ch) < 32 for ch in v)


def settings(c):
    row = c.execute("SELECT v FROM kv WHERE k='settings'").fetchone()
    out = dict(SETTINGS_DEFAULTS)
    try:
        stored = json.loads(row[0]) if row else {}
    except ValueError:
        stored = {}
    for k in out:
        v = stored.get(k) if isinstance(stored, dict) else None
        if v is not None and setting_ok(k, v):
            out[k] = v
    return out


_policy_cache = {"at": 0.0, "v": None}


def policy(connect):
    """settings() for hot paths (every request): read at most once every 3 seconds."""
    import time as _t
    if _policy_cache["v"] is None or _t.monotonic() - _policy_cache["at"] > 3:
        with connect() as c:
            _policy_cache["v"] = settings(c)
        _policy_cache["at"] = _t.monotonic()
    return _policy_cache["v"]


def forget_policy():
    _policy_cache["v"] = None


_SECRETISH = re.compile(r"pass|secret|token|key|code|backup|pepper", re.I)


def _scrub(d):
    return {k: ("[redacted]" if _SECRETISH.search(str(k)) else v) for k, v in d.items()} if isinstance(d, dict) else {}


def audit(c, actor, action, target_type="", target_id="", outcome="ok", detail=None, ctx=None):
    """Append one event to the hash-chained audit log, inside the caller's transaction where there is one."""
    ctx = ctx or {}
    ev = {"id": secrets.token_hex(12), "at": now(), "actor": (actor or "-")[:40], "action": action[:60],
          "target_type": (target_type or "")[:20], "target_id": str(target_id or "")[:80], "outcome": outcome,
          "detail": json.dumps(_scrub(detail or {}), separators=(",", ":"), sort_keys=True)[:4000],
          "request_id": str(ctx.get("request_id", ""))[:32], "ip": str(ctx.get("ip", ""))[:45],
          "ua": str(ctx.get("ua", ""))[:120]}
    own = not c.in_transaction
    if own:
        c.execute("BEGIN IMMEDIATE")
    try:
        prev = c.execute("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        ev["prev_hash"] = prev[0] if prev else "0" * 64
        ev["hash"] = hashlib.sha256(json.dumps(ev, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        c.execute("""INSERT INTO audit_log(id, at, actor, action, target_type, target_id, outcome, detail, request_id,
                     ip, ua, prev_hash, hash) VALUES(:id,:at,:actor,:action,:target_type,:target_id,:outcome,:detail,
                     :request_id,:ip,:ua,:prev_hash,:hash)""", ev)
        if own:
            c.execute("COMMIT")
    except BaseException:
        if own and c.in_transaction:
            c.execute("ROLLBACK")
        raise
