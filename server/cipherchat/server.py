#!/usr/bin/env python3
"""CipherChat by DarkCipher Systems: the server.

An end-to-end encrypted, post-quantum chat relay. It stores public keys, ciphertext and signatures; every key is made,
used and kept on the members' devices (web portal, Windows and Android apps). See docs/ for the protocol and the threat
model. Python 3.10+ standard library only.

Run behind nginx (TLS 1.3 with post-quantum hybrid key exchange, deploy/nginx/cipherchat.conf), listening on loopback:
    python3 -I server.py serve
    python3 -I server.py owner-invite        # first run: prints the owner's one-time set-up link
    python3 -I server.py backup <folder> <keep>   # a consistent snapshot (database + encrypted attachments)

Configuration (environment, see deploy/cipherchat.env):
  CIPHERCHAT_ORIGIN      https://chat.example.com   (the public origin; CSRF checks and links use it)
  CIPHERCHAT_NAME        display name of this instance (default "CipherChat")
  CIPHERCHAT_OWNER       the owner's username: the chat's trust anchor (default "owner")
  CIPHERCHAT_STATE_DIR   database and encrypted attachments (default /var/lib/cipherchat)
  CIPHERCHAT_KEY_FILE    the server key (default /etc/cipherchat/server.key): keep it out of database backups
  CIPHERCHAT_LISTEN      127.0.0.1:8787
  CIPHERCHAT_WEB_DIR     the web portal's files (default ../web next to this server)
  CIPHERCHAT_TRUST_PROXY 1 = take the client address from X-Real-IP set by nginx on loopback (default 1)
  CIPHERCHAT_DEV         1 = local development over plain http://127.0.0.1 (cookie without Secure). Never in production.
  plus the optional SMTP settings in mail_api.py

HTTP surface (the web portal and the apps use the same paths):
  /chat/ /chat/login/ /chat/public/ /chat/admin/ /chat/app/     the web portal (static files)
  POST /chat/api/auth/{login,logout,reauth,device,password,enrol/check,enrol/start,enrol/finish}   GET /chat/api/auth/status
  /chat/api/...                                                 the chat API (chat.py)
  POST /chat/api/request (or /api/chat-request)                 public access requests (chat_requests.py)
  /chat/api/admin/{users,requests,audit}                        owner and admins (access_api.py, chat_requests.py)
"""
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import struct
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, unquote

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

VERSION = "0.1.2"
ORIGIN = os.environ.get("CIPHERCHAT_ORIGIN", "http://127.0.0.1:8787").rstrip("/")
NAME = (os.environ.get("CIPHERCHAT_NAME") or "CipherChat").strip()[:60]
STATE_DIR = os.environ.get("CIPHERCHAT_STATE_DIR", "/var/lib/cipherchat")
KEY_FILE = os.environ.get("CIPHERCHAT_KEY_FILE", "/etc/cipherchat/server.key")
LISTEN = os.environ.get("CIPHERCHAT_LISTEN", "127.0.0.1:8787")
WEB_DIR = os.path.realpath(os.environ.get("CIPHERCHAT_WEB_DIR", os.path.join(HERE, "..", "..", "web")))
TRUST_PROXY = os.environ.get("CIPHERCHAT_TRUST_PROXY", "1") == "1"
DEV = os.environ.get("CIPHERCHAT_DEV", "0") == "1"
DB_PATH = os.path.join(STATE_DIR, "cipherchat.db")

import authz                    # noqa: E402  accounts, roles, audit (CipherChat's implementation of the portal interface)
import storage                  # noqa: E402  the server key the per-user key share is derived from
import mail_api                 # noqa: E402  optional SMTP
import access_api               # noqa: E402  invites and account management
import chat                     # noqa: E402  the chat itself (shared with the DarkCipher Systems portal)
import chat_requests            # noqa: E402  public access requests (shared)
import passkeys                 # noqa: E402  passkey (WebAuthn) sign-in, e.g. a passkey kept in Bitwarden
import calls                    # noqa: E402  voice and video calls: signal relay and TURN credentials (shared)
import addons                   # noqa: E402  add-ons: programs with their own identity, signed requests (docs/ADDONS.md)
import settings_api             # noqa: E402  server settings, email, notifications and roles (admin page)

# session lifetime, idle time and the sign-in lockout come from the server settings (authz.SETTINGS_SCHEMA)
MAX_BODY = 16 * 1024
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
ENROL_MAX_TRIES = 5
# __Secure- (not __Host-): the cookie is scoped to Path=/chat/ so it never reaches anything else on the domain, and
# browsers silently drop a __Host- cookie whose Path isn't "/". No Domain attribute, so it stays host-only.
COOKIE = "cipherchat_dev" if DEV else "__Secure-cipherchat"
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
GENERIC_FAIL = "Sign-in failed. Check your username, password and code (codes change every 30 seconds and work once)."
BAD_LINK = "This link is invalid, already used or expired. Ask an administrator for a new one."
_hash_gate = threading.Semaphore(2)          # scrypt is memory-hard: at most two at once
_lock = authz.WRITE_LOCK

if not DEV and not ORIGIN.startswith("https://"):
    raise SystemExit("CIPHERCHAT_ORIGIN must be https:// (set CIPHERCHAT_DEV=1 only for local development)")


# ------------------------------------------------------------------ database
class _Conn(sqlite3.Connection):
    """'with db() as c:' commits/rolls back AND closes (no connections left for the GC to find)."""
    def __exit__(self, *exc):
        try:
            return super().__exit__(*exc)
        finally:
            self.close()


def db():
    conn = sqlite3.connect(DB_PATH, timeout=10, factory=_Conn)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    with db() as c:
        c.execute("PRAGMA journal_mode=WAL")
    with _lock, db() as c:
        authz.migrate(c)
        chat.migrate(c)
        chat_requests.migrate(c)
        mail_api.migrate(c)
        passkeys.migrate(c)
        addons.migrate(c)
        _scrub_addresses(c)


_ADDRESS = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*)$")


def _scrub_addresses(c):
    """Older versions stored client addresses in the audit log and an add-on's last address. Replace them (once) and
    re-seal the audit log's hash chain over the changed rows, noting that it happened."""
    rows = c.execute("SELECT * FROM audit_log ORDER BY seq").fetchall()
    dirty = [r for r in rows if r["ip"] and _ADDRESS.match(r["ip"])]
    c.execute("UPDATE addons SET last_ip='' WHERE last_ip != '' AND last_ip NOT LIKE 'net-%'")
    if not dirty:
        c.commit()
        return
    prev = "0" * 64
    for r in rows:
        ev = {k: r[k] for k in ("id", "at", "actor", "action", "target_type", "target_id", "outcome", "detail", "request_id", "ip", "ua")}
        if ev["ip"] and _ADDRESS.match(ev["ip"]):
            ev["ip"] = "net-removed"
        ev["prev_hash"] = prev
        ev["hash"] = hashlib.sha256(json.dumps(ev, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        c.execute("UPDATE audit_log SET ip=?, prev_hash=?, hash=? WHERE seq=?", (ev["ip"], ev["prev_hash"], ev["hash"], r["seq"]))
        prev = ev["hash"]
    c.commit()
    authz.audit(c, "system", "audit.addresses_removed", "audit_log", "", detail={"rows": len(dirty)})


def now():
    return authz.now()


def clean(value, limit):
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return CONTROL_RE.sub("", value).strip()[:limit]


# ------------------------------------------------------------------ passwords (scrypt) and TOTP (RFC 6238)
def hash_password(password):
    salt = secrets.token_bytes(16)
    with _hash_gate:
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=64 * 1024 * 1024, dklen=32)
    return "scrypt$%d$%d$%d$%s$%s" % (SCRYPT_N, SCRYPT_R, SCRYPT_P, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def verify_password(password, stored):
    try:
        alg, n, r, p, salt, want = stored.split("$")
        n, r, p = int(n), int(r), int(p)
        if alg != "scrypt" or n > 2 ** 17 or r > 16 or p > 4:
            return False
        salt, want = base64.b64decode(salt), base64.b64decode(want)
    except (ValueError, AttributeError):
        return False
    with _hash_gate:
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, maxmem=160 * 1024 * 1024, dklen=len(want))
    return hmac.compare_digest(dk, want)


_DUMMY = None


def dummy_hash():
    global _DUMMY
    if _DUMMY is None:
        _DUMMY = hash_password(secrets.token_urlsafe(16))
    return _DUMMY


def totp_code(secret_b32, step):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    return "%06d" % ((struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % 1000000)


def totp_match(secret, code, last_step):
    """The matched time step (> last_step, so a code can't be replayed), or 0."""
    if not secret or not re.fullmatch(r"\d{6}", code or ""):
        return 0
    step_now = int(time.time()) // 30
    for step in (step_now - 1, step_now, step_now + 1):
        if step > last_step and hmac.compare_digest(totp_code(secret, step), code):
            return step
    return 0


def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def otpauth_uri(user, secret):
    issuer = re.sub(r"[^A-Za-z0-9]+", "%20", server_name()).strip("%20") or "CipherChat"
    return "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30" % (issuer, user, secret, issuer)


def ip_tag(ip):
    """What gets stored instead of an address: a keyed hash that changes every UTC day ("net-" + 10 hex). Repeated
    attempts from one source on one day still show as one tag; nobody can read the address back, look it up, or link
    tags across days. The key comes from the server key file. Addresses are used only in memory (rate limits, an
    add-on's IP allowlist) and never written anywhere."""
    ring = storage.KEYRING
    if not ip or ring is None:
        return ""
    day = time.strftime("%Y-%m-%d", time.gmtime())
    key = hmac.new(ring.get(ring.current), ("cipherchat-ip-tag/v1|" + day).encode(), hashlib.sha3_256).digest()
    return "net-" + hmac.new(key, ip.encode(), hashlib.sha3_256).hexdigest()[:10]


def pol():
    return authz.policy(db)


def server_name():
    """The name shown to people (titles, emails, authenticator apps): the setting, else CIPHERCHAT_NAME."""
    return pol()["name"] or NAME


def fail_window():
    return pol()["lockout_minutes"] * 60


def session_idle():
    return pol()["session_idle_minutes"] * 60


def _locked(row, t):
    return row["fails"] >= pol()["lockout_attempts"] and t - row["fail_start"] < fail_window()


def _record_fail(c, row, t):
    fails, start = row["fails"], row["fail_start"]
    if t - start > fail_window():
        fails, start = 0, t
    c.execute("UPDATE admins SET fails=?, fail_start=? WHERE username=?", (fails + 1, start, row["username"]))
    if fails + 1 == pol()["lockout_attempts"]:                    # just locked: tell the account and the admins
        mail_api.notify(c, "signin_locked", "%s was locked after failed sign-ins" % row["username"],
                        "The account %s was locked for %d minutes after %d failed sign-ins." % (row["username"], pol()["lockout_minutes"], fails + 1),
                        user=row["username"])


def login(username, password, code, ctx):
    """(username or None, message). All three factors are always checked; unknown users cost the same time."""
    t = int(time.time())
    username = (username or "").strip().lower()
    password = password if isinstance(password, str) else ""
    row = None
    if authz.USER_RE.fullmatch(username) and 1 <= len(password) <= 1024:
        with db() as c:
            row = c.execute("SELECT * FROM admins WHERE username=?", (username,)).fetchone()
    pw_ok = verify_password(password, row["pw_hash"] if row else dummy_hash()) and row is not None
    with authz.tx(db) as c:
        if row is None:
            authz.audit(c, username or "?", "auth.signin", "user", username, "failed", ctx=ctx)
            return None, GENERIC_FAIL
        row = c.execute("SELECT * FROM admins WHERE username=?", (username,)).fetchone()
        acc = authz.account(c, username)
        why = authz.inactive_reason(acc)
        if row is None or row["disabled"] or why:
            authz.audit(c, username, "auth.signin_refused", "user", username, "failed", {"why": why or "disabled"}, ctx)
            return None, GENERIC_FAIL
        if _locked(row, t):
            authz.audit(c, username, "auth.signin_refused", "user", username, "failed", {"why": "locked"}, ctx)
            mins = max(1, (fail_window() - (t - row["fail_start"])) // 60)
            return None, "Too many failed attempts. This account is locked for %d more minute%s." % (mins, "" if mins == 1 else "s")
        step = totp_match(row["totp_secret"], (code or "").strip(), row["totp_last"]) if pw_ok else 0
        if not (pw_ok and step):
            _record_fail(c, row, t)
            authz.audit(c, username, "auth.signin", "user", username, "failed", ctx=ctx)
            return None, GENERIC_FAIL
        c.execute("UPDATE admins SET totp_last=?, fails=0, fail_start=0, last_login=? WHERE username=?", (step, now(), username))
        authz.audit(c, username, "auth.signin", "user", username, "ok", ctx=ctx)
    return username, ("change" if acc["must_change_pw"] else "ok")


def verify_user_totp(username, code):
    t = int(time.time())
    with authz.tx(db) as c:
        row = c.execute("SELECT * FROM admins WHERE username=?", (username,)).fetchone()
        if row is None or row["disabled"]:
            return False, "Not signed in."
        if _locked(row, t):
            return False, "Too many failed attempts. Try again later."
        step = totp_match(row["totp_secret"], (code or "").strip(), row["totp_last"])
        if not step:
            _record_fail(c, row, t)
            authz.audit(c, username, "auth.reauth", "user", username, "failed")
            return False, "That code isn't valid. Codes change every 30 seconds and can only be used once."
        c.execute("UPDATE admins SET totp_last=?, fails=0 WHERE username=?", (step, username))
    return True, "ok"


# ------------------------------------------------------------------ sessions
def ua_label(ua):
    ua = ua or ""
    if ua.startswith("CipherChat/"):                       # the apps say what they are
        return ua.split(" ")[0][:40]
    browser = next((b for b, k in (("Edge", "Edg/"), ("Firefox", "Firefox/"), ("Chrome", "Chrome/"), ("Safari", "Safari/")) if k in ua), "Browser")
    system = next((s for s, k in (("Windows", "Windows"), ("Android", "Android"), ("iOS", "iPhone"), ("macOS", "Mac OS"), ("Linux", "Linux")) if k in ua), "")
    return (browser + (" on " + system if system else ""))[:40]


def new_session(user, scope="chat", ua="", c=None, fresh=None):
    """A new random session token (only its SHA-256 is stored). fresh = counts as a fresh authenticator code (a
    password + code sign-in does; a paired device's token sign-in doesn't)."""
    token = secrets.token_urlsafe(32)
    t = int(time.time())
    fresh = scope == "full" if fresh is None else fresh

    def put(c):
        c.execute("DELETE FROM sessions WHERE expires < ? OR last_seen < ?", (t, t - session_idle()))
        c.execute("""INSERT INTO sessions(token_hash, user, expires, last_seen, sid, created, ua, scope, reauth_at)
                     VALUES(?,?,?,?,?,?,?,?,?)""", (hashlib.sha256(token.encode()).hexdigest(), user, t + pol()["session_hours"] * 3600, t,
                                                    secrets.token_hex(8), t, ua_label(ua), scope, t if fresh else 0))
    if c is not None:
        put(c)
    else:
        with authz.tx(db) as c2:
            put(c2)
    return token


def cookie_for(token, hours=None):
    secure = "" if DEV else " Secure;"
    hours = pol()["session_hours"] if hours is None else hours
    return "%s=%s; Path=/chat/; Max-Age=%d;%s HttpOnly; SameSite=Strict" % (COOKIE, token, hours * 3600, secure)


EXPIRE_COOKIE = "%s=; Path=/chat/; Max-Age=0;%s HttpOnly; SameSite=Strict" % (COOKIE, "" if DEV else " Secure;")


# ------------------------------------------------------------------ invite / reset links
def enrol(step, data, ctx):
    """Invite and reset links (no session; the 256-bit token in the link is the authorisation).
      check  {token}                       -> what the page needs to ask for
      start  {token, password, [code]}     invite: new password -> new authenticator key (confirmed in finish)
                                           reset_password: new password + current authenticator code -> done
                                           reset_mfa: current password -> new authenticator key
      finish {token, code}                 confirms the new authenticator; the account becomes usable
    A wrong code ENROL_MAX_TRIES times kills the link. Nothing here signs anyone in."""
    token = str(data.get("token", ""))
    if not 20 <= len(token) <= 100:
        return 400, {"error": BAD_LINK}
    th = hashlib.sha256(token.encode()).hexdigest()
    pw = data.get("password")
    pw_hash = None
    if step == "start" and isinstance(pw, str) and 1 <= len(pw) <= 1024:
        pw_hash = hash_password(pw)                        # slow: outside the write lock
    with authz.tx(db) as c:
        e = c.execute("SELECT * FROM enrolments WHERE token_hash=?", (th,)).fetchone()
        if e is None or e["used_at"] or e["expires"] < time.time() or (e["attempts"] or 0) >= ENROL_MAX_TRIES:
            return 400, {"error": BAD_LINK}
        user, kind = e["username"], e["kind"]
        acc = authz.account(c, user)
        if acc is None or acc["status"] in ("deleted", "disabled", "suspended"):
            return 400, {"error": BAD_LINK}
        minimum = authz.settings(c)["password_min"]
        if step == "check":
            return 200, {"username": user, "kind": kind, "password_min": minimum, "name": server_name(),
                         "needs": {"invite": ["new_password", "authenticator"], "reset_password": ["new_password", "code"],
                                   "reset_mfa": ["password", "authenticator"]}[kind]}
        row = c.execute("SELECT * FROM admins WHERE username=?", (user,)).fetchone()
        if step == "start":
            if kind in ("invite", "reset_password"):
                probs = authz.password_problems(pw, user, minimum)
                if probs:
                    return 400, {"error": "Password not accepted: " + ", ".join(probs) + "."}
            if kind == "reset_password":
                step_ok = totp_match(row["totp_secret"], str(data.get("code", "")).strip(), row["totp_last"])
                if not step_ok:
                    c.execute("UPDATE enrolments SET attempts=attempts+1 WHERE token_hash=?", (th,))
                    authz.audit(c, user, "auth.reset_password", "user", user, "failed", {"reason": "wrong code"}, ctx)
                    return 401, {"error": "That code isn't valid. Codes change every 30 seconds and work once."}
                c.execute("UPDATE admins SET pw_hash=?, totp_last=?, fails=0, fail_start=0 WHERE username=?", (pw_hash, step_ok, user))
                c.execute("UPDATE accounts SET must_change_pw=0, updated=?, updated_by=? WHERE username=?", (now(), user, user))
                c.execute("UPDATE enrolments SET used_at=? WHERE token_hash=?", (now(), th))
                c.execute("DELETE FROM sessions WHERE user=?", (user,))
                authz.audit(c, user, "auth.reset_password", "user", user, "ok", {"link_by": e["created_by"]}, ctx)
                mail_api.notify(c, "password_changed", "Your password was changed",
                                "The password for %s was reset with a one-time link just now. If that wasn't you, tell your administrator." % user, user=user)
                return 200, {"done": True}
            if kind == "reset_mfa" and not (pw_hash and verify_password(pw, row["pw_hash"])):
                c.execute("UPDATE enrolments SET attempts=attempts+1 WHERE token_hash=?", (th,))
                authz.audit(c, user, "auth.reset_mfa", "user", user, "failed", {"reason": "wrong password"}, ctx)
                return 401, {"error": "That password isn't right."}
            secret = new_totp_secret()
            c.execute("UPDATE enrolments SET pending_pw=?, pending_secret=? WHERE token_hash=?",
                      (pw_hash if kind == "invite" else None, secret, th))
            return 200, {"secret": secret, "otpauth": otpauth_uri(user, secret), "username": user}
        if step == "finish":
            if not e["pending_secret"] or (kind == "invite" and not e["pending_pw"]):
                return 400, {"error": "Start again from the link."}
            step_ok = totp_match(e["pending_secret"], str(data.get("code", "")).strip(), 0)
            if not step_ok:
                c.execute("UPDATE enrolments SET attempts=attempts+1 WHERE token_hash=?", (th,))
                return 401, {"error": "That code doesn't match. Check the key was added correctly and your phone's clock is automatic."}
            if kind == "invite":
                c.execute("UPDATE admins SET pw_hash=?, totp_secret=?, totp_last=?, fails=0, fail_start=0 WHERE username=?",
                          (e["pending_pw"], e["pending_secret"], step_ok, user))
                c.execute("UPDATE accounts SET status='active', updated=?, updated_by=? WHERE username=? AND status='pending'", (now(), user, user))
            else:
                c.execute("UPDATE admins SET totp_secret=?, totp_last=?, fails=0, fail_start=0 WHERE username=?", (e["pending_secret"], step_ok, user))
            c.execute("UPDATE enrolments SET used_at=?, pending_pw=NULL, pending_secret=NULL WHERE token_hash=?", (now(), th))
            c.execute("DELETE FROM sessions WHERE user=?", (user,))
            authz.audit(c, user, "auth.enrolled" if kind == "invite" else "auth.reset_mfa", "user", user, "ok", {"link_by": e["created_by"]}, ctx)
            if kind == "invite":
                mail_api.notify(c, "account_ready", "%s set up their account" % user,
                                "%s finished setting up their account (invited by %s)." % (user, e["created_by"]))
            return 200, {"done": True}
    return 404, {"error": "not found"}


def change_own_password(user, data, ctx):
    """Current password + current code + new password. Ends every session of the account; the caller issues a fresh one."""
    cur, new = data.get("current"), data.get("new")
    if not (isinstance(cur, str) and 1 <= len(cur) <= 1024):
        return 400, {"error": "Enter your current password."}
    with db() as c:
        row = c.execute("SELECT * FROM admins WHERE username=?", (user,)).fetchone()
        minimum = authz.settings(c)["password_min"]
    pw_ok = verify_password(cur, row["pw_hash"])
    probs = authz.password_problems(new, user, minimum)
    new_hash = hash_password(new) if not probs else None
    with authz.tx(db) as c:
        row = c.execute("SELECT * FROM admins WHERE username=?", (user,)).fetchone()
        if _locked(row, int(time.time())):
            return 401, {"error": "Too many failed attempts. Try again later."}
        step = totp_match(row["totp_secret"], str(data.get("code", "")).strip(), row["totp_last"]) if pw_ok else 0
        if not (pw_ok and step):
            _record_fail(c, row, int(time.time()))
            authz.audit(c, user, "auth.password_change", "user", user, "failed", ctx=ctx)
            return 401, {"error": "Your current password or code isn't right."}
        if not probs and hmac.compare_digest(str(new), str(cur)):
            probs = ["must be different from the current one"]
        if probs:
            return 400, {"error": "New password not accepted: " + ", ".join(probs) + "."}
        c.execute("UPDATE admins SET pw_hash=?, totp_last=?, fails=0, fail_start=0 WHERE username=?", (new_hash, step, user))
        c.execute("UPDATE accounts SET must_change_pw=0, updated=?, updated_by=? WHERE username=?", (now(), user, user))
        n = c.execute("DELETE FROM sessions WHERE user=?", (user,)).rowcount
        authz.audit(c, user, "auth.password_change", "user", user, "ok", {"sessions_ended": n}, ctx)
        mail_api.notify(c, "password_changed", "Your password was changed",
                        "The password for %s was changed just now. If that wasn't you, tell your administrator." % user, user=user)
    return 200, {"ok": True}


# ------------------------------------------------------------------ rate limits (per client address)
_buckets = {}
_bucket_lock = threading.Lock()
LIMITS = {"auth": (6, 60), "request": (5, 600), "upload": (60, 60), "addon": (1200, 60)}


def limited(kind, key):
    """True if this client went over the limit for kind (n per window seconds)."""
    n, window = LIMITS[kind]
    t = time.time()
    with _bucket_lock:
        q = _buckets.setdefault((kind, key), deque())
        while q and q[0] < t - window:
            q.popleft()
        if len(q) >= n:
            return True
        q.append(t)
        if len(_buckets) > 50000:                       # never grows without bound
            _buckets.clear()
        return False


# ------------------------------------------------------------------ HTTP
PAGE_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
CHAT_CSP = PAGE_CSP.replace("img-src 'self' data:;", "img-src 'self' data: blob:; media-src blob:;")
API_CSP = "default-src 'none'; frame-ancestors 'none'"
BLOB_CSP = "default-src 'none'; sandbox; frame-ancestors 'none'"
TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
         ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon", ".json": "application/json",
         ".woff2": "font/woff2", ".txt": "text/plain; charset=utf-8", ".webmanifest": "application/manifest+json"}
# pages that only make sense signed in: without a session the server redirects to the sign-in page instead
SIGNED_IN_PAGES = ("/chat/", "/chat/index.html", "/chat/account/", "/chat/account/index.html", "/chat/admin/", "/chat/admin/index.html")
AUTH_POSTS = ("login", "logout", "reauth", "device", "password", "enrol/check", "enrol/start", "enrol/finish", "passkey/begin", "passkey/finish")


class _Body:
    """One request's body: reads stop at its Content-Length, and .left says how much the handler didn't read."""

    def __init__(self, f, length):
        self.f, self.left = f, length

    def read(self, n=-1):
        if self.left <= 0:
            return b""
        n = self.left if n is None or n < 0 else min(n, self.left)
        out = bytearray()
        while n > 0:
            chunk = self.f.read(min(n, 1 << 20))
            if not chunk:
                self.left = 0
                break
            out += chunk
            n -= len(chunk)
            self.left -= len(chunk)
        return bytes(out)


class Handler(BaseHTTPRequestHandler):
    server_version = "cipherchat"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    user = ""
    session = None
    ctl = None                                   # the shared chat module asks; CipherChat has no control API

    def log_message(self, fmt, *args):           # quiet, address-free logging
        sys.stderr.write("%s %s %s\n" % (self.command, self.path.split("?")[0][:120], args[1] if len(args) > 1 else ""))

    def setup(self):
        super().setup()
        self.request.settimeout(60)

    # ---- the request's context
    def client_ip(self):
        peer = self.client_address[0]
        if TRUST_PROXY and ipaddress.ip_address(peer).is_loopback:
            ip = (self.headers.get("X-Real-IP") or "").strip()
            try:
                return str(ipaddress.ip_address(ip))
            except ValueError:
                return peer
        return peer

    def ctx(self):
        if not getattr(self, "_rid", None):
            self._rid = secrets.token_hex(8)
        ip = "" if getattr(self, "_no_ip", False) else ip_tag(self.client_ip())
        return {"request_id": self._rid, "ip": ip, "ua": ua_label(self.headers.get("User-Agent", ""))}

    def chat_portal(self):
        return True

    # ---- responses (security headers on every one)
    def end_headers(self):
        for k, v in (("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"), ("Referrer-Policy", "no-referrer"),
                     ("Cross-Origin-Opener-Policy", "same-origin"), ("Cross-Origin-Resource-Policy", "same-origin"),
                     ("Permissions-Policy", "camera=(self), microphone=(self), display-capture=(self), geolocation=(), payment=(), usb=(), interest-cohort=()"),
                     ("Content-Security-Policy", getattr(self, "_csp", API_CSP))):
            self.send_header(k, v)
        if ORIGIN.startswith("https://"):
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        super().end_headers()

    def send_json(self, code, payload, cookie=None):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0 or length > MAX_BODY or "application/json" not in (self.headers.get("Content-Type") or ""):
            if 0 < length <= 1024 * 1024:
                self.rfile.read(length)                  # keep the connection usable
            return None
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def drain(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if 0 < length <= 1024 * 1024:
            self.rfile.read(length)

    def csrf_ok(self):
        return self.headers.get("Origin") == ORIGIN and self.headers.get("X-Requested-With") == "dcx-portal"

    # ---- sessions
    def session_token(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE and value:
                return value
        return None

    def has_session(self, touch=True):
        self.user, self.session = "", None
        token = self.session_token()
        if not token or len(token) > 100:
            return False
        th = hashlib.sha256(token.encode()).hexdigest()
        t = int(time.time())
        with db() as c:
            row = c.execute("""SELECT s.* FROM sessions s JOIN admins a ON a.username = s.user AND a.disabled = 0
                               WHERE s.token_hash=?""", (th,)).fetchone()
            if not row or row["expires"] <= t or row["last_seen"] < t - session_idle():
                return False
            if authz.inactive_reason(authz.account(c, row["user"])):
                return False
        if touch and t - row["last_seen"] > 60:
            with authz.tx(db) as c:
                c.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (t, th))
        self.user = row["user"]
        self.session = {"sid": row["sid"], "reauth_at": row["reauth_at"], "scope": row["scope"] or "chat", "token_hash": th,
                        "device_id": row["device_id"] if "device_id" in row.keys() else None}
        return True

    # ---- routing
    def do_GET(self):
        self.guard(self.handle_get)

    def do_HEAD(self):
        self.guard(self.handle_get)

    def do_POST(self):
        self.guard(self.handle_post)

    def guard(self, fn):
        # The body is read through a reader that stops at Content-Length. Whatever a handler leaves unread (a refused
        # upload, a request turned away before its body mattered) is drained if small, or the connection is closed:
        # nginx keeps upstream connections alive, and left-over bytes must never be parsed as the next request (that
        # would desync nginx and the server, a response-smuggling hole). Chunked bodies aren't supported at all.
        if self.headers.get("Transfer-Encoding") is not None:
            self.close_connection = True
            self.send_json(400, {"error": "Send a Content-Length (no Transfer-Encoding)."})
            return self._linger()
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = -1
        if length < 0 or length > (1 << 40):
            self.close_connection = True
            self.send_json(400, {"error": "Invalid Content-Length."})
            return self._linger()
        sock_file = self.rfile
        self.rfile = _Body(sock_file, length)
        try:
            self._run(fn)
        finally:
            left = self.rfile.left
            self.rfile = sock_file
            if left:
                if left <= 64 * 1024 and not self.close_connection:
                    try:
                        _Body(sock_file, left).read()
                    except OSError:
                        self.close_connection = True
                else:
                    self.close_connection = True
                    self._linger()

    def _linger(self):
        """A lingering close (as Apache and nginx do): stop sending, then read and drop what the client is still sending
        for a moment. Closing with unread data makes the OS send a reset, which can destroy the answer just written."""
        try:
            self.wfile.flush()
            self.connection.shutdown(socket.SHUT_WR)
            self.connection.settimeout(1)
            deadline = time.monotonic() + 2
            got = 0
            while time.monotonic() < deadline and got < 4 << 20:
                chunk = self.connection.recv(65536)
                if not chunk:
                    break
                got += len(chunk)
        except OSError:
            pass

    def _run(self, fn):
        try:
            fn()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:                   # never leak internals; the journal gets the type
            sys.stderr.write("UNHANDLED %s\n" % type(e).__name__)
            import traceback
            traceback.print_exc()
            try:
                self.send_json(500, {"error": "Something went wrong on the server."})
            except Exception:
                pass

    def handle_get(self):
        path, _, query = self.path.partition("?")
        if path == "/.well-known/assetlinks.json" and passkeys.ANDROID_APPS:      # Android passkeys (passkeys.py)
            return self.send_json(200, passkeys.assetlinks())
        if path == "/healthz":
            return self.send_json(200, {"ok": True, "version": VERSION})
        if path in ("/", "/chat"):
            self.send_response(302 if path == "/" else 301)
            self.send_header("Location", "/chat/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/chat/api/auth/status":
            return self.send_json(200, self.status())
        if path.startswith("/chat/api/") and self.headers.get("X-CipherChat-Addon") is not None:
            return self.addon_request("GET")
        if path.startswith("/chat/api/"):
            rest = path[len("/chat/api/"):]
            if not self.has_session(touch=rest != "poll"):
                return self.send_json(403, {"error": "Sign in first."})
            if rest == "addons":
                return self.send_json(*addons.route(self, "GET", rest, None))
            out = settings_api.route(self, "GET", rest, None) if rest in ("admin/settings", "admin/roles") else None
            if out is not None:
                return self.send_json(*out)
            if rest == "admin/users":
                return self.send_json(*access_api.list_users(self))
            if rest == "admin/requests":
                return self.send_json(*chat_requests.list_requests(self, query))
            if rest == "passkeys":
                return self.send_json(*passkeys.list_mine(self))
            if rest == "admin/audit":
                return self.send_json(*self.audit_view())
            if rest.startswith("blob/"):
                self._csp = BLOB_CSP
            result = chat.route(self, "GET", "/admin/api/chat/" + rest, query)
            if result == "sent":                 # an attachment was streamed
                return
            return self.send_json(*result)
        if path in SIGNED_IN_PAGES and not self.has_session(touch=False):
            # straight to sign-in: a signed-out visitor never gets (or briefly sees) the chat page
            self.send_response(302)
            self.send_header("Location", "/chat/login/?next=" + quote(path, safe=""))
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return
        if path.startswith("/chat/"):
            return self.static(path[len("/chat/"):])
        return self.send_json(404, {"error": "not found"})

    def handle_post(self):
        path = self.path.partition("?")[0]
        ip = self.client_ip()
        # the public access-request form; /chat/api/request keeps all of CipherChat under /chat/ (so it can be merged
        # into an existing site), /api/chat-request is the DarkCipher portal's path for the same form
        if path in ("/chat/api/request", "/api/chat-request"):
            self._no_ip = True                   # the request is stored without the sender's address
            if limited("request", ip):
                self.drain()
                return self.send_json(429, {"error": "Too many requests from this connection. Try again in a few minutes."})
            return self.send_json(*chat_requests.submit(self))
        if not path.startswith("/chat/api/"):
            self.drain()
            return self.send_json(404, {"error": "not found"})
        if self.headers.get("X-CipherChat-Addon") is not None:
            # signed per request and never carrying cookies, so there is no ambient credential for CSRF to abuse
            return self.addon_request("POST")
        if not self.csrf_ok():
            self.drain()
            return self.send_json(403, {"error": "csrf"})
        rest = path[len("/chat/api/"):]
        if rest.startswith("auth/") and rest[5:] in AUTH_POSTS:
            return self.auth_post(rest[5:], ip)
        if not self.has_session():
            self.drain()
            return self.send_json(403, {"error": "Sign in first."})
        if rest.startswith("passkeys/"):
            data = self.read_json()
            if data is None:
                return self.send_json(400, {"error": "Invalid request."})
            if rest == "passkeys/register/begin":
                return self.send_json(*passkeys.register_begin(self))
            if rest == "passkeys/register/finish":
                return self.send_json(*passkeys.register_finish(self, data))
            m = re.fullmatch(r"passkeys/([A-Za-z0-9_-]{16,1400})/delete", rest)
            if m:
                return self.send_json(*passkeys.delete(self, m.group(1)))
            return self.send_json(404, {"error": "not found"})
        if rest == "addons" or rest.startswith("addons/"):
            data = self.read_json()
            if data is None:
                return self.send_json(400, {"error": "Invalid request."})
            return self.send_json(*addons.route(self, "POST", rest, data))
        if rest.startswith("admin/"):
            data = self.read_json()
            if data is None:
                return self.send_json(400, {"error": "Invalid request."})
            out = settings_api.route(self, "POST", rest, data)
            if out is not None:
                return self.send_json(*out)
            if rest == "admin/users/invite":
                return self.send_json(*access_api.invite(self, data))
            m = re.fullmatch(r"admin/users/([a-z0-9._-]{3,32})/([a-z_]{3,20})", rest)
            if m:
                return self.send_json(*access_api.user_action(self, m.group(1), m.group(2), data))
            m = re.fullmatch(r"admin/requests/(\d{1,9})", rest)
            if m:
                return self.send_json(*chat_requests.decide(self, int(m.group(1)), data))
            return self.send_json(404, {"error": "not found"})
        if rest.startswith("upload/") and limited("upload", self.user):
            self.drain()
            return self.send_json(429, {"error": "Too many uploads at once. Wait a minute and try again."})
        return self.send_json(*chat.route(self, "POST", "/admin/api/chat/" + rest, ""))

    def addon_request(self, method):
        """An add-on's signed request (addons.py): checked, then limited to the add-on routes."""
        path, _, query = self.path.partition("?")
        rest = path[len("/chat/api/"):]
        out = addons.authenticate(self, method, self.path, rest)
        if out is not None:
            return self.send_json(*out)
        if method == "POST" and rest.startswith("upload/") and limited("upload", self.user):
            self.drain()
            return self.send_json(429, {"error": "Too many uploads at once. Wait a minute and try again."})
        if rest.startswith("blob/"):
            self._csp = BLOB_CSP
        result = chat.route(self, method, "/admin/api/chat/" + rest, query)
        if result == "sent":
            return
        return self.send_json(*result)

    def auth_post(self, name, ip):
        if name in ("login", "device", "reauth", "enrol/start", "enrol/finish", "password", "passkey/finish") and limited("auth", ip):
            self.drain()
            return self.send_json(429, {"error": "Too many attempts from this connection. Wait a minute and try again."})
        if name == "logout":
            self.drain()
            token = self.session_token()
            if token:
                th = hashlib.sha256(token.encode()).hexdigest()
                with authz.tx(db) as c:
                    row = c.execute("SELECT user FROM sessions WHERE token_hash=?", (th,)).fetchone()
                    c.execute("DELETE FROM sessions WHERE token_hash=?", (th,))
                    if row:
                        authz.audit(c, row["user"], "auth.signout", "user", row["user"], ctx=self.ctx())
            return self.send_json(200, {"ok": True}, EXPIRE_COOKIE)
        data = self.read_json()
        if data is None:
            return self.send_json(400, {"error": "Invalid request."})
        if name == "login":
            user, msg = login(str(data.get("username", ""))[:64], data.get("password"), str(data.get("code", ""))[:12], self.ctx())
            if not user:
                sys.stderr.write("login-fail\n")
                return self.send_json(401, {"error": msg}, EXPIRE_COOKIE)
            if msg == "change":
                return self.send_json(403, {"error": "Your account needs a new password first. Ask an administrator for a reset link.",
                                            "denied": True, "password_change": True})
            with db() as c:
                if not authz.decide(c, user, "chat.access.use")[0]:
                    return self.send_json(403, {"error": "This account can't use the chat.", "denied": True})
            token = new_session(user, "chat", self.headers.get("User-Agent", ""), fresh=True)
            return self.send_json(200, {"ok": True, "user": user}, cookie_for(token))
        if name == "device":
            code, out, token = chat.device_signin(self, data)
            if token is None:
                sys.stderr.write("device-fail\n")
            return self.send_json(code, out, cookie_for(token) if token else None)
        if name.startswith("enrol/"):
            return self.send_json(*enrol(name[6:], data, self.ctx()))
        if name == "passkey/begin":
            return self.send_json(*passkeys.auth_begin(self, data))
        if name == "passkey/finish":
            purpose = data.get("purpose") if data.get("purpose") in ("login", "reauth") else "login"
            if purpose == "reauth" and not self.has_session():
                return self.send_json(403, {"error": "Sign in first."})
            session_user = self.user
            code, out, user = passkeys.auth_finish(self, dict(data, purpose=purpose))
            if user is None:
                return self.send_json(code, out)
            if purpose == "reauth":
                if user != session_user:
                    return self.send_json(401, {"error": "That passkey belongs to another account."})
                with authz.tx(db) as c:
                    c.execute("UPDATE sessions SET reauth_at=? WHERE token_hash=?", (int(time.time()), self.session["token_hash"]))
                return self.send_json(200, {"ok": True})
            # a passkey with user verification is multi-factor on its own: a fresh session, like password + code
            return self.send_json(200, out, cookie_for(new_session(user, "chat", self.headers.get("User-Agent", ""), fresh=True)))
        if not self.has_session():
            return self.send_json(403, {"error": "Sign in first."})
        if name == "reauth":
            ok, msg = verify_user_totp(self.user, str(data.get("code", "")))
            if not ok:
                return self.send_json(401, {"error": msg})
            with authz.tx(db) as c:
                c.execute("UPDATE sessions SET reauth_at=? WHERE token_hash=?", (int(time.time()), self.session["token_hash"]))
                authz.audit(c, self.user, "auth.reauth", "user", self.user, ctx=self.ctx())
            return self.send_json(200, {"ok": True})
        if name == "password":
            code, out = change_own_password(self.user, data, self.ctx())
            if code != 200:
                return self.send_json(code, out)
            return self.send_json(200, out, cookie_for(new_session(self.user, "chat", self.headers.get("User-Agent", ""), fresh=True)))
        return self.send_json(404, {"error": "not found"})

    def status(self):
        signed_in = self.has_session(touch=False)
        out = {"signed_in": signed_in, "user": self.user if signed_in else None, "idle_minutes": session_idle() // 60,
               "name": server_name(), "version": VERSION}
        if signed_in:
            with db() as c:
                acc = authz.account(c, self.user)
                mins = authz.settings(c)["reauth_minutes"]
                perms = [p for p in authz.CATALOG if authz.decide(c, self.user, p)[0]]
            out.update({"owner": authz.is_owner(self.user), "display_name": acc.get("display_name") or "",
                        "role": authz.role_of(acc), "permissions": perms, "admin": any(p.startswith("admin.") for p in perms),
                        "device": bool(self.session.get("device_id")),
                        "reauth_valid_for": max(0, mins * 60 - (int(time.time()) - int(self.session["reauth_at"] or 0)))})
        return out

    def audit_view(self):
        with db() as c:
            if not authz.decide(c, self.user, "admin.audit.view")[0]:
                return 403, {"error": "You don't have permission to see the audit log.", "denied": True}
            rows = c.execute("SELECT * FROM audit_log ORDER BY seq DESC LIMIT 300").fetchall()
        return 200, {"events": [{k: r[k] for k in ("seq", "at", "actor", "action", "target_type", "target_id", "outcome", "ip")} for r in rows]}

    # ---- the web portal's files
    def static(self, rel):
        if rel == "" or rel.endswith("/"):
            rel += "index.html"
        full = os.path.realpath(os.path.join(WEB_DIR, rel))
        if not full.startswith(WEB_DIR + os.sep) or not os.path.isfile(full):
            return self.send_json(404, {"error": "not found"})
        ext = os.path.splitext(full)[1].lower()
        self._csp = CHAT_CSP if rel in ("index.html",) or rel.startswith("app/") else PAGE_CSP
        with open(full, "rb") as fh:
            body = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", TYPES.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache" if ext in (".js", ".mjs", ".css", ".svg", ".png", ".woff2") else "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128


def bind_modules():
    storage.load(KEY_FILE)
    me = sys.modules[__name__]
    chat.bind(me, storage)
    mail_api.bind(me)
    settings_api.bind(me)
    access_api.bind(me, mail_api)
    chat_requests.bind(me, access_api, mail_api)
    passkeys.bind(me)
    calls.bind(me, chat)
    addons.bind(me, chat, storage)
    if chat_requests.purge not in chat.EXTRA_SWEEPS:
        chat.EXTRA_SWEEPS.append(chat_requests.purge)


# ------------------------------------------------------------------ command line
class _Cli:
    """Stands in for a signed-in owner when the server's own command line issues a link."""
    user = authz.OWNER
    session = {"reauth_at": int(time.time())}

    def ctx(self):
        return {"request_id": "cli", "ip": "", "ua": "command line"}


def owner_invite():
    """First run, or the owner lost their password or authenticator: a one-time link that sets both up (again).
    Only someone with root on the server can run this. The owner's chat identity is untouched (it's sealed with the
    chat passphrase, which this doesn't change)."""
    with authz.tx(db) as c:
        t = now()
        if authz.account(c, authz.OWNER) is None:
            c.execute("INSERT INTO admins(username, pw_hash, totp_secret, created) VALUES(?,?,?,?)", (authz.OWNER, "!", "", t))
            c.execute("INSERT INTO accounts(username, status, role, created, created_by) VALUES(?,?,?,?,?)",
                      (authz.OWNER, "pending", "admin", t, "cli"))
        else:
            c.execute("UPDATE admins SET pw_hash='!', totp_secret='', totp_last=0, fails=0, fail_start=0, disabled=0 WHERE username=?", (authz.OWNER,))
            c.execute("UPDATE accounts SET status='pending', locked=0, updated=?, updated_by='cli' WHERE username=?", (t, authz.OWNER))
            c.execute("DELETE FROM sessions WHERE user=?", (authz.OWNER,))
        link = access_api.new_link(c, _Cli(), authz.OWNER, "invite")
        authz.audit(c, "cli", "user.owner_link", "user", authz.OWNER, ctx=_Cli().ctx())
    print("Open this link once to set up the owner account (%s). It expires in %d hours:\n%s"
          % (authz.OWNER, link["expires_hours"], link["url"]))


def backup(folder, keep):
    """A consistent snapshot (SQLite's online backup, so the server keeps running) plus the encrypted attachments, as
    one tar in folder (mode 0600), keeping the newest `keep`. Everything in it is what the server already stores:
    ciphertext, public keys, password hashes. The server key is NOT in it: back that up separately, offline."""
    import tarfile
    import tempfile
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    final = os.path.join(folder, "cipherchat-%s.tar" % stamp)
    with tempfile.TemporaryDirectory(dir=folder) as tmp:
        snap = os.path.join(tmp, "cipherchat.db")
        src, dst = sqlite3.connect(DB_PATH), sqlite3.connect(snap)
        try:
            src.backup(dst)
        finally:
            dst.close(); src.close()
        part = final + ".part"
        fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f, tarfile.open(fileobj=f, mode="w") as tar:
            tar.add(snap, arcname="cipherchat.db")
            blobs = os.path.join(STATE_DIR, "chat-blobs")
            if os.path.isdir(blobs):
                tar.add(blobs, arcname="chat-blobs")
        os.replace(part, final)
    old = sorted(n for n in os.listdir(folder) if re.fullmatch(r"cipherchat-\d{8}-\d{6}\.tar", n))
    for n in old[:-keep]:
        os.remove(os.path.join(folder, n))
    print("backup written: %s (%d kept)" % (final, min(len(old), keep)))


def main(argv):
    cmd = argv[1] if len(argv) > 1 else "serve"
    init_db()
    bind_modules()
    if cmd == "owner-invite":
        return owner_invite()
    if cmd == "backup" and len(argv) == 4 and argv[3].isdigit() and int(argv[3]) >= 1:
        return backup(argv[2], int(argv[3]))
    if cmd != "serve":
        if cmd == "mailer":                      # the separate, jailed mailer (cipherchat-mailer.service)
            sys.stderr.write("CipherChat mailer running\n")
            return mail_api.mailer_loop()
        raise SystemExit("usage: server.py [serve | owner-invite | mailer | backup <folder> <how many to keep>]")
    host, _, port = LISTEN.rpartition(":")
    srv = Server((host.strip("[]") or "127.0.0.1", int(port)), Handler)
    threading.Thread(target=chat.purge_loop, name="chat-retention", daemon=True).start()
    if os.environ.get("CIPHERCHAT_MAILER", "inline") != "separate":
        mail_api.start_inline()             # Linux runs it as its own jailed service instead (CIPHERCHAT_MAILER=separate)
    sys.stderr.write("%s %s listening on %s (origin %s)%s\n" % (NAME, VERSION, LISTEN, ORIGIN, " [DEV]" if DEV else ""))
    srv.serve_forever()


if __name__ == "__main__":
    main(sys.argv)
