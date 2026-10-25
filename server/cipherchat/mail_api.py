"""Email for CipherChat: invitation and reset links, and notifications (access requests, security events). Optional:
everything works without it (links are then shown to the admin to pass on).

Settings live in the database and are edited on the admin page (settings_api.py) by people with admin.mail.manage; the
CIPHERCHAT_SMTP_* environment settings are only the starting values. The SMTP password is sealed (sealbox.py) and is
never sent back to a browser.

Sending is separate from the web server: messages go into mail_queue, sealed (they can carry one-time links), and a
mailer sends them with retries. On Linux the mailer is its own jailed service (cipherchat-mailer, the only CipherChat
process allowed out to the internet; the web-facing server stays loopback-only); elsewhere it's a thread. TLS is always
required and certificates verified (STARTTLS on 587, implicit TLS on 465); the SMTP server's addresses must be public
(no loopback or private networks, so the mail settings can't be used to probe the inside of the network) unless
CIPHERCHAT_SMTP_ALLOW_PRIVATE=1.
"""
import hashlib
import ipaddress
import json
import os
import re
import smtplib
import socket
import ssl
import sys
import threading
import time
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

import authz
import sealbox
from authz import audit, tx

core = None
EMAIL_RE = re.compile(r"^[^@\s<>\"',;]{1,64}@[^@\s<>\"',;]{1,190}\.[A-Za-z]{2,24}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
SECURITY = ("starttls", "tls")
ALLOW_PRIVATE = os.environ.get("CIPHERCHAT_SMTP_ALLOW_PRIVATE", "0") == "1"
BACKOFF = (60, 300, 900, 3600, 3 * 3600, 6 * 3600, 12 * 3600)       # then given up (about a day in all)
LOG_KEEP = 500

MAIL_DEFAULTS = {"host": "", "port": 587, "security": "starttls", "user": "", "from": "", "from_name": "", "reply_to": ""}

# Notifications people can switch on and off, and who gets each (settings_api.py edits them)
EVENTS = {
    "access_request": ("Someone asked for access", {"enabled": True, "admins": True, "user": False}),
    "account_ready": ("Someone finished setting up their account", {"enabled": False, "admins": True, "user": False}),
    "signin_locked": ("An account was locked after failed sign-ins", {"enabled": True, "admins": True, "user": True}),
    "device_paired": ("An app was paired to an account", {"enabled": True, "admins": False, "user": True}),
    "password_changed": ("A password was changed", {"enabled": True, "admins": False, "user": True}),
    "access_changed": ("Someone's role, permissions or status was changed", {"enabled": True, "admins": False, "user": True}),
}
# who counts as an admin for each event: people holding this permission (and an email address)
EVENT_ADMINS = {"access_request": "admin.requests.review", "account_ready": "admin.users.view", "signin_locked": "admin.users.update",
                "device_paired": "admin.users.update", "password_changed": "admin.users.update", "access_changed": "admin.users.roles"}

KINDS = {
    "invite": ("You're invited to {name}",
               "{who} has invited you to {name}, an end-to-end encrypted, post-quantum chat.\n\n"
               "Open this link to choose your password and set up your authenticator app (the page shows your username):\n"
               "{url}\n\nThe link works once and expires in {hours} hours.\n\n"
               "If you weren't expecting this, ignore this email: nothing happens unless the link is used."),
    "reset_password": ("Reset your {name} password",
                       "{who} has issued a password reset for your {name} account.\n\nChoose a new password here:\n{url}\n\n"
                       "The link works once and expires in {hours} hours. Until you use it, your old password no longer works.\n\n"
                       "If you didn't expect this, contact your administrator."),
    "reset_mfa": ("Set up your authenticator again for {name}",
                  "{who} has reset the authenticator for your {name} account.\n\nSet it up again here:\n{url}\n\n"
                  "The link works once and expires in {hours} hours.\n\nIf you didn't expect this, contact your administrator."),
}


def bind(server_module):
    global core
    core = server_module


def migrate(c):
    c.executescript("""
    CREATE TABLE IF NOT EXISTS mail_queue(
        id INTEGER PRIMARY KEY AUTOINCREMENT, created INTEGER NOT NULL, kind TEXT NOT NULL, msg TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0, next_at INTEGER NOT NULL, last_error TEXT NOT NULL DEFAULT '');
    CREATE TABLE IF NOT EXISTS mail_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, kind TEXT NOT NULL, to_masked TEXT NOT NULL,
        outcome TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '');
    """)


# ------------------------------------------------------------------------------------------- settings
def _kv(c, key, default):
    row = c.execute("SELECT v FROM kv WHERE k=?", (key,)).fetchone()
    try:
        v = json.loads(row[0]) if row else None
    except ValueError:
        v = None
    return v if isinstance(v, type(default)) else default


def _env_defaults():
    pw_file = os.environ.get("CIPHERCHAT_SMTP_PASSWORD_FILE", "").strip()
    try:
        port = int(os.environ.get("CIPHERCHAT_SMTP_PORT", "587") or 587)
    except ValueError:
        port = 587
    return {"host": os.environ.get("CIPHERCHAT_SMTP_HOST", "").strip(), "port": port,
            "security": "tls" if port == 465 else "starttls", "user": os.environ.get("CIPHERCHAT_SMTP_USER", "").strip(),
            "from": os.environ.get("CIPHERCHAT_MAIL_FROM", "").strip(), "from_name": "", "reply_to": "", "pw_file": pw_file}


def config(c):
    """The SMTP settings in force: the saved ones, else the environment's. Never includes the password."""
    saved = _kv(c, "mail", {})
    if saved.get("host"):
        out = dict(MAIL_DEFAULTS)
        out.update({k: saved[k] for k in MAIL_DEFAULTS if k in saved})
        out["source"] = "settings"
        out["has_password"] = c.execute("SELECT 1 FROM kv WHERE k='smtp_password'").fetchone() is not None
        return out
    env = _env_defaults()
    env["source"] = "environment" if env["host"] else "none"
    env["has_password"] = bool(env.pop("pw_file"))
    return env


def password(c):
    row = c.execute("SELECT v FROM kv WHERE k='smtp_password'").fetchone()
    if row:
        return sealbox.open_text(json.loads(row[0]), "smtp-password")
    if not _kv(c, "mail", {}).get("host"):
        pw_file = os.environ.get("CIPHERCHAT_SMTP_PASSWORD_FILE", "").strip()
        if pw_file:
            with open(pw_file) as fh:
                return fh.read().strip()
    return ""


def notify_config(c):
    saved = _kv(c, "notify", {})
    out = {}
    for ev, (_, default) in EVENTS.items():
        cur = dict(default, extra=[])
        s = saved.get(ev) if isinstance(saved.get(ev), dict) else {}
        for k in ("enabled", "admins", "user"):
            if isinstance(s.get(k), bool):
                cur[k] = s[k]
        if isinstance(s.get("extra"), list):
            cur["extra"] = [e for e in s["extra"] if isinstance(e, str) and EMAIL_RE.match(e)][:5]
        out[ev] = cur
    return out


def ready(c):
    cfg = config(c)
    return bool(cfg["host"]) and bool(EMAIL_RE.match(cfg["from"] or ""))


def not_ready():
    """A reason email can't be sent, or None."""
    with core.db() as c:
        return None if ready(c) else "Email isn't set up on this server."


def check_account_email(email):
    if not_ready():
        return "Email isn't set up on this server, so the link can't be emailed. Untick it and pass the link on yourself."
    if not email or not EMAIL_RE.match(email):
        return "This account has no usable email address."
    return None


def mask(addr):
    local, _, domain = addr.partition("@")
    return (local[:1] + "***@" + domain) if domain else "***"


def log(c, kind, to, outcome, detail=""):
    c.execute("INSERT INTO mail_log(at, kind, to_masked, outcome, detail) VALUES(?,?,?,?,?)",
              (int(time.time()), kind[:30], ", ".join(mask(t) for t in to)[:200], outcome[:20], str(detail)[:200]))
    c.execute("DELETE FROM mail_log WHERE id <= (SELECT MAX(id) FROM mail_log) - ?", (LOG_KEEP,))


# ------------------------------------------------------------------------------------------- queue
def _clean_header(v, n):
    return re.sub(r"[\r\n\x00-\x1f\x7f]", " ", str(v or ""))[:n].strip()


def enqueue(c, kind, to, subject, body):
    """Queues one email (inside the caller's transaction). Recipients are checked; the message is sealed."""
    to = sorted({t.strip().lower() for t in to if isinstance(t, str) and EMAIL_RE.match(t.strip())})[:20]
    if not to or not ready(c):
        return False
    msg = json.dumps({"to": to, "subject": _clean_header(subject, 200), "body": str(body)[:20000]})
    c.execute("INSERT INTO mail_queue(created, kind, msg, next_at) VALUES(?,?,?,?)",
              (int(time.time()), kind[:30], sealbox.seal(msg, "mail-queue"), int(time.time())))
    wake()
    return True


def recipients(c, event, user=None):
    """Who gets this event: per the notification settings, people with the event's admin permission, the account
    itself, and any extra addresses."""
    cfg = notify_config(c).get(event)
    if not cfg or not cfg["enabled"]:
        return []
    out = set(cfg["extra"])
    if cfg["admins"]:
        perm = EVENT_ADMINS.get(event, "admin.users.view")
        for (u,) in c.execute("SELECT username FROM accounts WHERE status='active' AND email != ''").fetchall():
            acc = authz.account(c, u)
            if acc and not authz.inactive_reason(acc) and perm in authz.effective(c, acc) and EMAIL_RE.match(acc["email"] or ""):
                out.add(acc["email"].lower())
    if cfg["user"] and user:
        acc = authz.account(c, user)
        if acc and EMAIL_RE.match(acc.get("email") or ""):
            out.add(acc["email"].lower())
    return sorted(out)


def notify(c, event, subject, body, user=None):
    """A notification for event (inside the caller's transaction); nothing if it's switched off or nobody qualifies."""
    to = recipients(c, event, user)
    name = core.server_name()
    return enqueue(c, event, to, "[%s] %s" % (name, subject), body + "\n\n-- %s (%s)\n" % (name, core.ORIGIN)) if to else False


def send_account_link(h, username, kind, link):
    with tx(core.db) as c:
        acc = authz.account(c, username) or {}
        who_acc = authz.account(c, h.user) or {}
        email = (acc.get("email") or "").strip()
        if not ready(c):
            return {"sent": False, "error": "Email isn't set up on this server, so the link can't be emailed. Untick it and pass the link on yourself."}
        if not EMAIL_RE.match(email):
            return {"sent": False, "error": "This account has no usable email address."}
        subject, text = KINDS[kind]
        who = (who_acc.get("display_name") or h.user or "An administrator").strip()
        name = core.server_name()
        body = ("Hello %s,\n\n" % acc["display_name"] if acc.get("display_name") else "Hello,\n\n") + \
            text.format(who=who, url=link["url"], hours=link["expires_hours"], name=name)
        enqueue(c, kind, [email.lower()], subject.format(name=name), body)
    return {"sent": True, "to": [email.lower()], "queued": True}


def _drop(queue, payload):
    """Kept for chat_requests.py (written for the portal's queue): an access request becomes a notification."""
    with tx(core.db) as c:
        notify(c, "access_request", payload.get("subject", "New request for access"), payload.get("body", ""))


# ------------------------------------------------------------------------------------------- sending
class Refused(Exception):
    pass


def _public_addrs(host, port):
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addrs = []
    for fam, _, _, _, sa in infos:
        ip = ipaddress.ip_address(sa[0])
        if not ALLOW_PRIVATE and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
                                  or ip.is_unspecified or (ip.version == 6 and ip.ipv4_mapped is not None and not ip.ipv4_mapped.is_global)):
            raise Refused("the SMTP server's address %s isn't public" % sa[0])
        addrs.append((fam, sa))
    if not addrs:
        raise Refused("the SMTP server's name doesn't resolve")
    return addrs


def _vetted_socket(host, port, timeout):
    last = None
    for fam, sa in _public_addrs(host, port):
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(sa)
            return s
        except OSError as e:
            last = e
            s.close()
    raise last or Refused("couldn't connect")


class _SMTP(smtplib.SMTP):
    def _get_socket(self, host, port, timeout):
        return _vetted_socket(host, port, timeout)


class _SMTPS(smtplib.SMTP_SSL):
    def _get_socket(self, host, port, timeout):
        return self.context.wrap_socket(_vetted_socket(host, port, timeout), server_hostname=self._host)


def _tls():
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def deliver(cfg, pw, to, subject, body):
    msg = EmailMessage()
    msg["From"] = formataddr((_clean_header(cfg.get("from_name"), 60), cfg["from"])) if cfg.get("from_name") else cfg["from"]
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject
    msg["Message-ID"] = make_msgid(domain=cfg["from"].split("@")[1])
    if cfg.get("reply_to") and EMAIL_RE.match(cfg["reply_to"]):
        msg["Reply-To"] = cfg["reply_to"]
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(body)
    if not HOST_RE.match(cfg["host"] or "") and not ALLOW_PRIVATE:
        raise Refused("the SMTP server must be a host name")
    if cfg["security"] == "tls":
        s = _SMTPS(cfg["host"], cfg["port"], context=_tls(), timeout=20)
    else:
        s = _SMTP(cfg["host"], cfg["port"], timeout=20)
        s.starttls(context=_tls())                      # refuses if the server doesn't offer it: never plaintext
    try:
        if cfg["user"]:
            s.login(cfg["user"], pw)
        s.send_message(msg)
    finally:
        try:
            s.quit()
        except (smtplib.SMTPException, OSError):
            pass


_wake = threading.Event()


def wake():
    _wake.set()


def _describe(e):
    if isinstance(e, Refused):
        return str(e)
    if isinstance(e, smtplib.SMTPAuthenticationError):
        return "the SMTP server refused the username or password"
    if isinstance(e, smtplib.SMTPNotSupportedError):
        return "the SMTP server doesn't offer STARTTLS"
    if isinstance(e, ssl.SSLCertVerificationError):
        return "the SMTP server's certificate didn't verify"
    if isinstance(e, smtplib.SMTPRecipientsRefused):
        return "the SMTP server refused the recipient"
    if isinstance(e, smtplib.SMTPSenderRefused):
        return "the SMTP server refused the From address"
    if isinstance(e, smtplib.SMTPServerDisconnected):
        return "the SMTP server closed the connection (often a wrong username or password)"
    if isinstance(e, smtplib.SMTPResponseException):
        return "the SMTP server answered %d" % e.smtp_code
    if isinstance(e, ssl.SSLError):
        return "TLS with the SMTP server failed"
    if isinstance(e, (socket.timeout, TimeoutError)):
        return "the SMTP server didn't answer in time"
    if isinstance(e, OSError):
        return "couldn't connect to the SMTP server"
    return type(e).__name__


def run_once():
    """Sends what's due. Returns how many were handled."""
    t = int(time.time())
    with core.db() as c:
        rows = c.execute("SELECT * FROM mail_queue WHERE next_at <= ? ORDER BY id LIMIT 20", (t,)).fetchall()
        if not rows:
            return 0
        cfg = config(c)
        try:
            pw = password(c)
        except (sealbox.SealError, OSError, ValueError):
            pw = None
    for r in rows:
        to, err = [], None
        try:
            m = json.loads(sealbox.open_text(r["msg"], "mail-queue"))
            to = m["to"]
            if pw is None:
                raise Refused("the SMTP password can't be opened (server key changed?)")
            if not ready_cfg(cfg):
                raise Refused("email isn't set up")
            deliver(cfg, pw, to, m["subject"], m["body"])
        except Exception as e:                            # the reason, never the content
            err = _describe(e)
        with tx(core.db) as c:
            if err is None:
                c.execute("DELETE FROM mail_queue WHERE id=?", (r["id"],))
                log(c, r["kind"], to, "sent")
            elif r["attempts"] + 1 >= len(BACKOFF) + 1 or isinstance(err, str) and "isn't public" in err:
                c.execute("DELETE FROM mail_queue WHERE id=?", (r["id"],))
                log(c, r["kind"], to, "failed", err)
            else:
                c.execute("UPDATE mail_queue SET attempts=attempts+1, next_at=?, last_error=? WHERE id=?",
                          (int(time.time()) + BACKOFF[min(r["attempts"], len(BACKOFF) - 1)], err[:200], r["id"]))
                log(c, r["kind"], to, "retrying", err)
    return len(rows)


def ready_cfg(cfg):
    return bool(cfg.get("host")) and bool(EMAIL_RE.match(cfg.get("from") or ""))


def mailer_loop(stop=None):
    """The mailer: wakes when something is queued (in-process) or every 5 seconds (a separate process)."""
    while not (stop and stop.is_set()):
        try:
            if run_once():
                continue
        except Exception as e:
            sys.stderr.write("mailer: %s\n" % type(e).__name__)
        _wake.wait(5)
        _wake.clear()


def start_inline():
    threading.Thread(target=mailer_loop, daemon=True, name="mailer").start()
