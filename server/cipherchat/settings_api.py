"""Server settings, email, notifications and roles, from the admin page. Every change is checked here (never trust the
page), needs the matching permission and a fresh authenticator code, and is audited (secrets redacted).

  GET  /chat/api/admin/settings          admin.settings.manage or admin.mail.manage (each sees its own part)
  POST /chat/api/admin/settings          {key: value, ...}                       admin.settings.manage
  POST /chat/api/admin/mail              {host, port, security, user, password?, clear_password?, from, from_name, reply_to}
  POST /chat/api/admin/mail/test         {to?}                                   admin.mail.manage
  POST /chat/api/admin/notify            {event: {enabled, admins, user, extra}} admin.mail.manage
  GET  /chat/api/admin/roles             admin.users.view or admin.roles.manage
  POST /chat/api/admin/roles             {name, label, perms}                    admin.roles.manage
  POST /chat/api/admin/roles/<name>      {label?, perms?}                        admin.roles.manage
  POST /chat/api/admin/roles/<name>/delete                                       admin.roles.manage

Escalation rules (authz.may_grant): a role or a person can only be given permissions the person giving them holds, and
nobody edits a role more powerful than they are.
"""
import ipaddress
import json
import re
import time

import authz
import mail_api
import sealbox
from authz import audit, tx, is_owner

core = None
RESERVED_ROLES = {"owner", "addon"}
_test_times = {}


def bind(server_module):
    global core
    core = server_module


class Refuse(Exception):
    def __init__(self, code, message, **extra):
        super().__init__(message)
        self.code, self.message, self.extra = code, message, extra


def _run(h, fn):
    try:
        with tx(core.db) as c:
            out = fn(c)
        authz.forget_policy()
        return out
    except Refuse as e:
        payload = {"error": e.message}
        if e.code == 403:
            payload["denied"] = True
        payload.update(e.extra)
        return e.code, payload


def _has(c, h, perm):
    return authz.decide(c, h.user, perm)[0]


def _need(c, h, perm):
    if not _has(c, h, perm):
        raise Refuse(403, "You don't have permission to do that.")


def _fresh(c, h):
    mins = authz.settings(c)["reauth_minutes"]
    if int(time.time()) - int((h.session or {}).get("reauth_at") or 0) > mins * 60:
        raise Refuse(401, "Confirm it's you: enter the current code from your authenticator app.", reauth=True, reauth_minutes=mins)


def _kv_put(c, key, value):
    c.execute("INSERT INTO kv(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (key, json.dumps(value)))


# ------------------------------------------------------------------------------------------- read
def get_all(h):
    def go(c):
        s_ok, m_ok = _has(c, h, "admin.settings.manage"), _has(c, h, "admin.mail.manage")
        if not (s_ok or m_ok):
            raise Refuse(403, "You don't have permission to see the server settings.")
        out = {"can_settings": s_ok, "can_mail": m_ok}
        if s_ok:
            out["settings"] = authz.settings(c)
            out["schema"] = {k: {"kind": v[1], "min": v[2], "max": v[3], "default": v[0]} for k, v in authz.SETTINGS_SCHEMA.items()}
            out["roles"] = authz.role_names(c)
            out["env_name"] = core.NAME
        if m_ok:
            out["mail"] = mail_api.config(c)
            out["notify"] = mail_api.notify_config(c)
            out["events"] = {k: v[0] for k, v in mail_api.EVENTS.items()}
            out["queue"] = c.execute("SELECT COUNT(*) FROM mail_queue").fetchone()[0]
            out["log"] = [dict(r) for r in c.execute("SELECT at, kind, to_masked, outcome, detail FROM mail_log ORDER BY id DESC LIMIT 50")]
            out["allow_private"] = mail_api.ALLOW_PRIVATE
        return 200, out
    return _run(h, go)


# ------------------------------------------------------------------------------------------- settings
def put_settings(h, data):
    def go(c):
        _need(c, h, "admin.settings.manage")
        _fresh(c, h)
        cur = authz.settings(c)
        changed = {}
        for k, v in data.items():
            if k not in authz.SETTINGS_SCHEMA:
                raise Refuse(400, "Unknown setting: %s" % str(k)[:40])
            if isinstance(v, str):
                v = v.strip()                       # too long or control characters: refused below, never trimmed quietly
            if not authz.setting_ok(k, v):
                d, kind, lo, hi = authz.SETTINGS_SCHEMA[k]
                raise Refuse(400, "%s: %s" % (k, "%d to %d" % (lo, hi) if kind == "int" else kind))
            if k == "request_role":
                perms = authz.role_perms(c, v)
                if perms is None or v in RESERVED_ROLES:
                    raise Refuse(400, "request_role: no role called %s." % v)
                if not is_owner(h.user) and not perms < authz.effective(c, authz.account(c, h.user)):
                    raise Refuse(403, "Approved requests can't get a role with permissions you don't have.")
            if cur.get(k) != v:
                changed[k] = v
        if not changed:
            raise Refuse(400, "Nothing to change.")
        cur.update(changed)
        _kv_put(c, "settings", cur)
        audit(c, h.user, "settings.update", "settings", "server", detail=changed, ctx=h.ctx())
        return 200, {"ok": True, "settings": cur}
    return _run(h, go)


# ------------------------------------------------------------------------------------------- email
def put_mail(h, data):
    def go(c):
        _need(c, h, "admin.mail.manage")
        _fresh(c, h)
        cfg = {k: data.get(k, v) for k, v in mail_api.MAIL_DEFAULTS.items()}
        for k, v in cfg.items():
            if k != "port" and (not isinstance(v, str) or any(ord(ch) < 32 or ord(ch) == 127 for ch in v)):
                raise Refuse(400, "%s: plain text on one line." % k)        # no header injection, ever
        cfg["host"] = core.clean(cfg["host"], 253).lower()
        if cfg["host"]:
            if not mail_api.HOST_RE.match(cfg["host"]):
                ip = None
                try:
                    ip = ipaddress.ip_address(cfg["host"])
                except ValueError:
                    pass
                if ip is None or not mail_api.ALLOW_PRIVATE:
                    raise Refuse(400, "SMTP server: a host name like smtp.example.com.")
            if not isinstance(cfg["port"], int) or isinstance(cfg["port"], bool) or not 1 <= cfg["port"] <= 65535:
                raise Refuse(400, "Port: 1 to 65535 (587 for STARTTLS, 465 for TLS).")
            if cfg["security"] not in mail_api.SECURITY:
                raise Refuse(400, "Security: STARTTLS or TLS (plain SMTP is never used).")
            if not mail_api.EMAIL_RE.match(cfg["from"] or ""):
                raise Refuse(400, "From: a full email address.")
        cfg["user"] = core.clean(cfg["user"], 200)
        cfg["from_name"] = core.clean(cfg["from_name"], 60)
        cfg["reply_to"] = core.clean(cfg["reply_to"], 200)
        if cfg["reply_to"] and not mail_api.EMAIL_RE.match(cfg["reply_to"]):
            raise Refuse(400, "Reply-to: a full email address, or empty.")
        detail = {k: v for k, v in cfg.items() if k != "user"}
        pw = data.get("password")
        if isinstance(pw, str) and pw:
            if len(pw) > 512 or any(ord(ch) < 32 for ch in pw):
                raise Refuse(400, "That password can't be right.")
            _kv_put(c, "smtp_password", sealbox.seal(pw, "smtp-password"))
            detail["password"] = "changed"
        elif data.get("clear_password") is True:
            c.execute("DELETE FROM kv WHERE k='smtp_password'")
            detail["password"] = "removed"
        _kv_put(c, "mail", cfg)
        audit(c, h.user, "mail.settings", "settings", "mail", detail=detail, ctx=h.ctx())
        return 200, {"ok": True, "mail": mail_api.config(c)}
    return _run(h, go)


def test_mail(h, data):
    def go(c):
        _need(c, h, "admin.mail.manage")
        _fresh(c, h)
        last = _test_times.get(h.user, 0)
        if time.time() - last < 20:
            raise Refuse(429, "Wait a few seconds between test emails.")
        to = data.get("to") or (authz.account(c, h.user) or {}).get("email") or ""
        if not isinstance(to, str) or not mail_api.EMAIL_RE.match(to):
            raise Refuse(400, "Give an address to send the test to (your account has none).")
        if not mail_api.ready(c):
            raise Refuse(400, "Save the SMTP settings first.")
        _test_times[h.user] = time.time()
        mail_api.enqueue(c, "test", [to], "[%s] Test email" % core.server_name(),
                         "This is a test from %s (%s), sent by %s.\n\nIf you got it, email works.\n" % (core.server_name(), core.ORIGIN, h.user))
        audit(c, h.user, "mail.test", "settings", "mail", detail={"to": mail_api.mask(to)}, ctx=h.ctx())
        return 200, {"ok": True, "to": mail_api.mask(to)}
    return _run(h, go)


def put_notify(h, data):
    def go(c):
        _need(c, h, "admin.mail.manage")
        _fresh(c, h)
        cur = mail_api.notify_config(c)
        for ev, v in data.items():
            if ev not in mail_api.EVENTS or not isinstance(v, dict):
                raise Refuse(400, "Unknown notification: %s" % str(ev)[:40])
            for k in ("enabled", "admins", "user"):
                if k in v:
                    if not isinstance(v[k], bool):
                        raise Refuse(400, "%s.%s: true or false" % (ev, k))
                    cur[ev][k] = v[k]
            if "extra" in v:
                extra = v["extra"]
                if not isinstance(extra, list) or len(extra) > 5 or not all(isinstance(e, str) and mail_api.EMAIL_RE.match(e.strip()) for e in extra):
                    raise Refuse(400, "%s: up to 5 full email addresses" % ev)
                cur[ev]["extra"] = sorted({e.strip().lower() for e in extra})
        _kv_put(c, "notify", cur)
        audit(c, h.user, "mail.notifications", "settings", "notify", detail={"events": sorted(data)}, ctx=h.ctx())
        return 200, {"ok": True, "notify": cur}
    return _run(h, go)


# ------------------------------------------------------------------------------------------- roles
def _perms(v):
    if not isinstance(v, list) or not all(isinstance(p, str) and p in authz.CATALOG for p in v):
        raise Refuse(400, "Permissions: a list of known permission ids.")
    return set(v)


def _mine(c, h):
    return set(authz.CATALOG) if is_owner(h.user) else authz.effective(c, authz.account(c, h.user))


def get_roles(h):
    def go(c):
        if not (_has(c, h, "admin.users.view") or _has(c, h, "admin.roles.manage")):
            raise Refuse(403, "You don't have permission to see roles.")
        roles = []
        for r in c.execute("SELECT * FROM roles ORDER BY builtin DESC, name"):
            n = c.execute("SELECT COUNT(*) FROM accounts WHERE role=? AND status != 'deleted'", (r["name"],)).fetchone()[0]
            roles.append({"name": r["name"], "label": r["label"], "perms": sorted(authz._perm_list(r["perms"])),
                          "builtin": bool(r["builtin"]), "people": n, "updated": r["updated"], "updated_by": r["updated_by"]})
        return 200, {"roles": roles, "permissions": [{"id": p, "group": g, "label": l} for p, g, l in authz.PERMISSIONS],
                     "mine": sorted(_mine(c, h)), "can_manage": _has(c, h, "admin.roles.manage")}
    return _run(h, go)


def create_role(h, data):
    def go(c):
        _need(c, h, "admin.roles.manage")
        _fresh(c, h)
        name = data.get("name")
        if not isinstance(name, str) or not authz.ROLE_RE.fullmatch(name) or name in RESERVED_ROLES:
            raise Refuse(400, "Role names: 2-24 of a-z, 0-9 and -, starting with a letter.")
        if c.execute("SELECT 1 FROM roles WHERE name=?", (name,)).fetchone():
            raise Refuse(409, "There's already a role called %s." % name)
        if c.execute("SELECT COUNT(*) FROM roles").fetchone()[0] >= 50:
            raise Refuse(400, "Up to 50 roles.")
        perms = _perms(data.get("perms", []))
        if not perms <= _mine(c, h):
            raise Refuse(403, "A role can only have permissions you hold yourself.")
        label = core.clean(data.get("label") or name, 40)
        t = authz.now()
        c.execute("INSERT INTO roles(name, label, perms, builtin, created, updated, updated_by) VALUES(?,?,?,0,?,?,?)",
                  (name, label, json.dumps(sorted(perms)), t, t, h.user))
        audit(c, h.user, "role.create", "role", name, detail={"perms": sorted(perms)}, ctx=h.ctx())
        return 200, {"ok": True}
    return _run(h, go)


def update_role(h, name, data, delete=False):
    def go(c):
        _need(c, h, "admin.roles.manage")
        _fresh(c, h)
        row = c.execute("SELECT * FROM roles WHERE name=?", (name,)).fetchone()
        if row is None:
            raise Refuse(404, "No such role.")
        mine, current = _mine(c, h), authz._perm_list(row["perms"])
        if not current <= mine:
            raise Refuse(403, "You can't change a role with permissions you don't hold.")
        if delete:
            if row["builtin"]:
                raise Refuse(400, "Built-in roles can't be deleted (edit their permissions instead).")
            n = c.execute("SELECT COUNT(*) FROM accounts WHERE role=? AND status != 'deleted'", (name,)).fetchone()[0]
            if n:
                raise Refuse(409, "%d account(s) have this role. Give them another role first." % n)
            c.execute("DELETE FROM roles WHERE name=?", (name,))
            audit(c, h.user, "role.delete", "role", name, ctx=h.ctx())
            return 200, {"ok": True}
        sets, detail = {}, {}
        if "perms" in data:
            perms = _perms(data["perms"])
            if not perms <= mine:
                raise Refuse(403, "A role can only have permissions you hold yourself.")
            if name == authz.settings(c)["request_role"] and not is_owner(h.user) and not perms < mine:
                raise Refuse(403, "That role is given to approved requests, so it must stay below your own permissions.")
            sets["perms"] = json.dumps(sorted(perms))
            detail = {"added": sorted(perms - current), "removed": sorted(current - perms)}
        if "label" in data:
            sets["label"] = core.clean(data["label"], 40) or name
        if not sets:
            raise Refuse(400, "Nothing to change.")
        sets.update({"updated": authz.now(), "updated_by": h.user})
        c.execute("UPDATE roles SET %s WHERE name=?" % ", ".join(k + "=?" for k in sets), (*sets.values(), name))
        audit(c, h.user, "role.update", "role", name, detail=detail, ctx=h.ctx())
        return 200, {"ok": True}
    return _run(h, go)


def route(h, method, rest, data):
    if method == "GET" and rest == "admin/settings":
        return get_all(h)
    if method == "GET" and rest == "admin/roles":
        return get_roles(h)
    if method != "POST":
        return None
    if rest == "admin/settings":
        return put_settings(h, data)
    if rest == "admin/mail":
        return put_mail(h, data)
    if rest == "admin/mail/test":
        return test_mail(h, data)
    if rest == "admin/notify":
        return put_notify(h, data)
    if rest == "admin/roles":
        return create_role(h, data)
    m = re.fullmatch(r"admin/roles/([a-z][a-z0-9-]{1,23})(/delete)?", rest)
    if m:
        return update_role(h, m.group(1), data, delete=bool(m.group(2)))
    return None
