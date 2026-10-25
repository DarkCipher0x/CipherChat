"""Account management for CipherChat: invites, one-time links, roles, suspending and removing people.

Owner and admins use it from the admin page (/chat/admin/); chat_requests.py calls invite() when a request is approved.
Every change is checked here (never trust the page), audited, and needs a fresh authenticator code (re-auth).

  GET  /chat/api/admin/users                       admin.users.view
  POST /chat/api/admin/users/invite                {username, display_name?, email?, role?, send_email?}
  POST /chat/api/admin/users/<u>/<action>          role {role} | suspend | activate | reset_password | reset_mfa
                                                   | new_invite | sign_out | delete
"""
import hashlib
import json
import re
import secrets
import time

import authz
from authz import audit, tx, is_owner

core = None
mail_api = None
EMAIL_RE = re.compile(r"^[^@\s<>\"']{1,64}@[^@\s<>\"']{1,190}\.[A-Za-z]{2,24}$")
ROLE_ALIASES = {"chat-user": "member"}          # what chat_requests.py asks for, from the portal it was written for


def bind(server_module, mail_module):
    global core, mail_api
    core, mail_api = server_module, mail_module


class Refuse(Exception):
    def __init__(self, code, message, log=False, action="authz.denied", target=("", ""), detail=None, outcome="denied", **extra):
        super().__init__(message)
        self.code, self.message, self.log, self.action, self.outcome = code, message, log, action, outcome
        self.target, self.detail, self.extra = target, detail or {}, extra


def run(h, fn):
    """fn(c) in a write transaction -> (status, payload). Refusals roll back, then get audited if asked."""
    try:
        with tx(core.db) as c:
            return fn(c)
    except Refuse as e:
        if e.log:
            with tx(core.db) as c:
                audit(c, h.user, e.action, e.target[0], e.target[1], e.outcome, dict(e.detail, reason=e.message), h.ctx())
        payload = {"error": e.message}
        if e.code == 403:
            payload["denied"] = True
        payload.update(e.extra)
        return e.code, payload


def need(c, h, perm):
    ok, why = authz.decide(c, h.user, perm)
    if not ok:
        raise Refuse(403, "You don't have permission to do that (%s)." % why)


def need_reauth(c, h):
    mins = authz.settings(c)["reauth_minutes"]
    if int(time.time()) - int((h.session or {}).get("reauth_at") or 0) > mins * 60:
        raise Refuse(401, "Confirm it's you: enter the current code from your authenticator app.", reauth=True,
                     reauth_minutes=mins)


def clean(v, n):
    return core.clean(v, n)


def new_link(c, h, username, kind):
    """One-time link (shown once). Only a SHA-256 of the token is stored; the token travels in the URL fragment, so it
    never reaches server or proxy logs."""
    c.execute("DELETE FROM enrolments WHERE username=? AND used_at IS NULL", (username,))
    token = secrets.token_urlsafe(32)
    hours = authz.settings(c)["invite_hours"]
    c.execute("INSERT INTO enrolments(token_hash, username, kind, created, created_by, expires) VALUES(?,?,?,?,?,?)",
              (hashlib.sha256(token.encode()).hexdigest(), username, kind, authz.now(), h.user, int(time.time()) + hours * 3600))
    return {"url": "%s/chat/login/#enrol=%s" % (core.ORIGIN, token), "expires_hours": hours}


def email_link(h, data, kind, result):
    """After the change is committed: email the link to the account's own address if asked. The link is still returned
    to the admin, so a failed email never loses it."""
    code, out = result
    if code < 300 and data.get("send_email") is True and isinstance(out.get("link"), dict) and out.get("username"):
        out["email"] = mail_api.send_account_link(h, out["username"], kind, out["link"])
    return code, out


def target_user(c, h, username, perm):
    need(c, h, perm)
    acc = authz.account(c, username) if isinstance(username, str) and authz.USER_RE.fullmatch(username) else None
    if acc is None or acc["status"] == "deleted":
        raise Refuse(404, "No such user.")
    if authz.role_of(acc) == "addon":
        raise Refuse(403, "That's an add-on: the owner manages it under Add-ons (/addons).")
    if is_owner(username) and not is_owner(h.user):
        raise Refuse(403, "The owner's account can only be changed by the owner.", log=True, action="owner.protected",
                     target=("user", username))
    if username != h.user and not authz.may_manage(c, h.user, acc):
        raise Refuse(403, "You can only change accounts with fewer permissions than you have.", log=True, target=("user", username))
    return acc


def below(c, h, perms):
    """True if perms is strictly less than what h.user holds (the owner may give anything)."""
    return is_owner(h.user) or set(perms) < authz.effective(c, authz.account(c, h.user))


def invite(h, data):
    def go(c):
        need(c, h, "admin.users.create")
        need_reauth(c, h)
        username = str(data.get("username", "")).strip().lower()
        if not authz.USER_RE.fullmatch(username):
            raise Refuse(400, "Username: 3-32 characters, lowercase letters, digits, . _ -")
        if username.startswith("addon."):
            raise Refuse(400, "Names starting with 'addon.' are kept for add-ons.")
        reused = False
        if c.execute("SELECT 1 FROM admins WHERE username=?", (username,)).fetchone():
            prev = c.execute("SELECT status FROM accounts WHERE username=?", (username,)).fetchone()
            if not prev or prev["status"] != "deleted":
                raise Refuse(409, "That username is taken.")
            # A deleted account only keeps its name reserved: free it. Its identity, devices, passkeys, room
            # memberships and sessions were removed on delete (and cascade here); the new person starts with a new
            # identity that the owner has to verify and certify again, so nothing of the old one carries over.
            c.execute("DELETE FROM sessions WHERE user=?", (username,))
            c.execute("DELETE FROM enrolments WHERE username=?", (username,))
            c.execute("DELETE FROM admins WHERE username=?", (username,))
            reused = True
        email = clean(data.get("email"), 120).lower()
        if email and not EMAIL_RE.match(email):
            raise Refuse(400, "That email address doesn't look right.")
        if data.get("send_email") is True:
            why = mail_api.check_account_email(email)
            if why:
                raise Refuse(400, why)
        roles = data.get("roles") or [data.get("role") or "member"]
        role = ROLE_ALIASES.get(roles[0], roles[0]) if isinstance(roles, list) and roles and isinstance(roles[0], str) else "member"
        perms = authz.role_perms(c, role)
        if perms is None or role in ("owner", "addon"):
            raise Refuse(400, "No role called %s." % role[:30])
        if not below(c, h, perms):
            raise Refuse(403, "You can only invite people into a role with fewer permissions than you have.")
        t = authz.now()
        c.execute("INSERT INTO admins(username, pw_hash, totp_secret, created) VALUES(?,?,?,?)", (username, "!", "", t))
        c.execute("""INSERT INTO accounts(username, display_name, email, status, role, created, created_by, updated, updated_by)
                     VALUES(?,?,?,?,?,?,?,?,?)""", (username, clean(data.get("display_name"), 80), email, "pending", role, t, h.user, t, h.user))
        link = new_link(c, h, username, "invite")
        audit(c, h.user, "user.invite", "user", username, detail={"role": role, "reused_deleted_name": reused} if reused else {"role": role}, ctx=h.ctx())
        return 201, {"ok": True, "username": username, "link": link}
    return email_link(h, data, "invite", run(h, go))


def list_users(h):
    def go(c):
        need(c, h, "admin.users.view")
        t = int(time.time())
        out = []
        for r in c.execute("SELECT username FROM admins ORDER BY username").fetchall():
            acc = authz.account(c, r[0])
            if acc["status"] == "deleted" or authz.role_of(acc) == "addon":       # add-ons are listed under /addons
                continue
            ident = c.execute("SELECT fp, cert_fp FROM chat_identities WHERE username=?", (r[0],)).fetchone()
            out.append({"username": r[0], "display_name": acc["display_name"], "email": acc["email"], "role": authz.role_of(acc),
                        "status": acc["status"], "locked": bool(acc["locked"]), "last_login": acc["last_login"],
                        "created": acc["created"], "chat_identity": bool(ident),
                        "certified": bool(ident and (is_owner(r[0]) or ident["cert_fp"] == ident["fp"])),
                        "sessions": c.execute("SELECT COUNT(*) FROM sessions WHERE user=? AND expires>?", (r[0], t)).fetchone()[0],
                        "grants": sorted(authz._perm_list(acc.get("grants"))), "denies": sorted(authz._perm_list(acc.get("denies"))),
                        "permissions": sorted(authz.effective(c, acc)),
                        "manageable": r[0] != h.user and authz.may_manage(c, h.user, acc)})
        return 200, {"users": out, "me": h.user, "owner": authz.OWNER, "roles": authz.role_names(c),
                     "mine": sorted(authz.effective(c, authz.account(c, h.user)))}
    return run(h, go)


def user_action(h, username, action, data):
    kinds = {"reset_password": "reset_password", "reset_mfa": "reset_mfa", "new_invite": "invite"}

    perm = {"role": "admin.users.roles", "permissions": "admin.users.roles", "delete": "admin.users.delete"}.get(action, "admin.users.update")

    def go(c):
        acc = target_user(c, h, username, perm)
        need_reauth(c, h)
        if username == h.user and action in ("suspend", "delete", "role", "permissions"):
            raise Refuse(400, "You can't do that to your own account.")
        t = authz.now()
        out = {"ok": True, "username": username}
        detail = {}
        if action in ("role", "permissions"):
            # the account's new permissions must stay strictly below the person changing them
            role = data.get("role", acc.get("role")) if action == "role" else acc.get("role")
            perms = authz.role_perms(c, role) if isinstance(role, str) else None
            if perms is None or role in ("owner", "addon"):
                raise Refuse(400, "No role called %s." % str(role)[:30])
            grants, denies = authz._perm_list(acc.get("grants")), authz._perm_list(acc.get("denies"))
            if action == "permissions":
                for k in ("grants", "denies"):
                    v = data.get(k)
                    if not isinstance(v, list) or not all(isinstance(p, str) and p in authz.CATALOG for p in v):
                        raise Refuse(400, "%s: a list of known permission ids." % k)
                grants, denies = set(data["grants"]), set(data["denies"]) - set(data["grants"])
            new = (perms | grants) - denies
            if not below(c, h, new):
                raise Refuse(403, "You can only give someone fewer permissions than you have.", log=True, target=("user", username),
                             detail={"wanted": sorted(new - authz.effective(c, authz.account(c, h.user)))})
            c.execute("UPDATE accounts SET role=?, grants=?, denies=?, updated=?, updated_by=? WHERE username=?",
                      (role, json.dumps(sorted(grants)), json.dumps(sorted(denies)), t, h.user, username))
            detail = {"role": role, "grants": sorted(grants), "denies": sorted(denies)}
            mail_api.notify(c, "access_changed", "Your access changed",
                            "Your access to %s was changed by %s: role %s%s." % (core.server_name(), h.user, role,
                            (", extra: " + ", ".join(sorted(grants))) if grants else ""), user=username)
        elif action in ("suspend", "activate"):
            if action == "activate" and acc["status"] == "pending":
                raise Refuse(409, "This account hasn't been set up yet: send a new invite link instead.")
            c.execute("UPDATE accounts SET status=?, updated=?, updated_by=? WHERE username=?",
                      ("suspended" if action == "suspend" else "active", t, h.user, username))
            if action == "suspend":
                c.execute("DELETE FROM sessions WHERE user=?", (username,))
        elif action == "sign_out":
            out["ended"] = c.execute("DELETE FROM sessions WHERE user=?", (username,)).rowcount
        elif action in kinds:
            if action == "new_invite" and acc["status"] != "pending":
                raise Refuse(409, "This account is already set up.")
            if action == "reset_password":
                c.execute("UPDATE admins SET pw_hash='!' WHERE username=?", (username,))
                c.execute("DELETE FROM sessions WHERE user=?", (username,))
            out["link"] = new_link(c, h, username, kinds[action])
        elif action == "delete":
            c.execute("DELETE FROM sessions WHERE user=?", (username,))
            c.execute("DELETE FROM chat_members WHERE username=?", (username,))
            c.execute("DELETE FROM chat_identities WHERE username=?", (username,))
            c.execute("DELETE FROM chat_devices WHERE username=?", (username,))
            c.execute("DELETE FROM enrolments WHERE username=?", (username,))
            c.execute("UPDATE accounts SET status='deleted', email='', updated=?, updated_by=? WHERE username=?", (t, h.user, username))
            c.execute("UPDATE admins SET disabled=1, pw_hash='!', totp_secret='' WHERE username=?", (username,))
        else:
            raise Refuse(404, "Unknown action.")
        if action in ("suspend", "activate"):
            mail_api.notify(c, "access_changed", "Your account was %s" % ("suspended" if action == "suspend" else "reactivated"),
                            "Your %s account was %s by %s." % (core.server_name(), "suspended" if action == "suspend" else "reactivated", h.user),
                            user=username)
        audit(c, h.user, "user." + action, "user", username, detail=detail, ctx=h.ctx())
        return 200, out
    result = run(h, go)
    return email_link(h, data, kinds.get(action, ""), result) if action in kinds else result
