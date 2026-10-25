"""Requests for access to the secure chat: the public "Request access" form (/chat/public/request.html) and their review
in the admin portal (Access > Chat requests).

  POST /api/chat-request                 public: {name, email, message, agree, website (trap), elapsed}
  GET  /admin/api/chat-requests          admin.users.view: the requests (newest first)
  POST /admin/api/chat-requests/<id>     {action: approve|decline|delete, username?}
                                         approve = a normal portal invite (access_api.invite) with the Chat User role,
                                         its link emailed to the requester; decline/delete need admin.users.update

Same bot traps and daily cap as the other public forms; the requester's IP address is never stored with a request. The
owner gets an alert email that names the requester only (no address or message: those stay in the portal). Requests
are deleted 90 days after a decision, or after 180 days undecided (as the chat's privacy statement says).
"""
import re
import time

import authz
from authz import audit, tx

core = None
access_api = None
mail_api = None


def bind(server_module, access_module, mail_module):
    global core, access_api, mail_api
    core, access_api, mail_api = server_module, access_module, mail_module


DAILY_CAP = 30
MIN_FILL_MS = 3000
KEEP_DECIDED_S = 90 * 86400
KEEP_OPEN_S = 180 * 86400
EMAIL_RE = re.compile(r"^[^@\s<>\"']{1,64}@[^@\s<>\"']{1,190}\.[A-Za-z]{2,24}$")
STATUSES = ("new", "approved", "declined")


def migrate(c):
    c.execute("""CREATE TABLE IF NOT EXISTS chat_requests(
        id INTEGER PRIMARY KEY AUTOINCREMENT, created INTEGER NOT NULL, name TEXT NOT NULL, email TEXT NOT NULL,
        message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new','approved','declined')),
        decided_at INTEGER, decided_by TEXT, username TEXT)""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_chat_requests_status ON chat_requests(status, id)")


def submit(h):
    data = h.read_json()
    if data is None:
        return 400, {"error": "Invalid request."}
    try:
        elapsed = int(data.get("elapsed", 0))
    except (TypeError, ValueError):
        elapsed = 0
    if data.get("website") or elapsed < MIN_FILL_MS:
        return 201, {"ok": True}                                   # bots get a fake success
    with core.db() as c:
        if not authz.settings(c)["access_requests"]:
            return 403, {"error": "This chat isn't taking access requests at the moment."}
    name, email, message = core.clean(data.get("name"), 60), core.clean(data.get("email"), 120).lower(), core.clean(data.get("message"), 1000)
    if len(name) < 2:
        return 400, {"error": "Please tell us your name.", "field": "name"}
    if not EMAIL_RE.match(email):
        return 400, {"error": "That email address doesn't look right.", "field": "email"}
    if len(message) < 10:
        return 400, {"error": "Please add a short note about who you are and why you'd like access (10 characters or more).", "field": "message"}
    if data.get("agree") is not True:
        return 400, {"error": "Please read the privacy & security statement and tick the box to accept it.", "field": "agree"}
    t = int(time.time())
    with tx(core.db) as c:
        if c.execute("SELECT 1 FROM chat_requests WHERE email=? AND status='new'", (email,)).fetchone():
            return 201, {"ok": True}                               # already waiting: no duplicate, no second alert
        today = c.execute("SELECT COUNT(*) FROM chat_requests WHERE created>=?", (t - t % 86400,)).fetchone()[0]
        if today >= DAILY_CAP:
            return 503, {"error": "We're receiving a lot of requests right now. Please try again tomorrow."}
        rid = c.execute("INSERT INTO chat_requests(created, name, email, message) VALUES(?,?,?,?)", (t, name, email, message)).lastrowid
        audit(c, "public", "chat.access_request", "chat_request", rid, ctx=h.ctx())
    if not mail_api.not_ready():                                   # a short alert to the owner; details stay in the portal
        mail_api._drop("mail-out", {"service": "Chat", "event": "chat.access-request", "sender": "alerts", "sensitive": False,
                                    "subject": "New request for access to the secure chat",
                                    "body": "%s has asked for access to the secure chat.\n\nReview it in the portal: Access > Chat requests.\n" % name})
    return 201, {"ok": True}


def _need(c, h, perm):
    ok, _ = authz.decide(c, h.user, perm)
    if not ok:
        raise access_api.Refuse(403, "You don't have permission to do that (%s)." % perm)


def list_requests(h, query):
    status = "new"
    for part in query.split("&"):
        k, _, v = part.partition("=")
        if k == "status":
            status = v
    def go(c):
        _need(c, h, "admin.requests.review")
        if status == "all":
            rows = c.execute("SELECT * FROM chat_requests ORDER BY id DESC LIMIT 300").fetchall()
        elif status in STATUSES:
            rows = c.execute("SELECT * FROM chat_requests WHERE status=? ORDER BY id DESC LIMIT 300", (status,)).fetchall()
        else:
            raise access_api.Refuse(400, "bad status")
        counts = {r["status"]: r["n"] for r in c.execute("SELECT status, COUNT(*) n FROM chat_requests GROUP BY status")}
        return 200, {"requests": [dict(r) for r in rows], "counts": counts}
    return access_api.run(h, go)


def decide(h, rid, data):
    action = data.get("action")
    with core.db() as c:
        row = c.execute("SELECT * FROM chat_requests WHERE id=?", (rid,)).fetchone()
    if row is None:
        return 404, {"error": "No such request."}
    if action == "approve":
        with core.db() as c:
            if not authz.decide(c, h.user, "admin.requests.review")[0]:
                return 403, {"error": "You don't have permission to review access requests.", "denied": True}
            role = authz.settings(c)["request_role"]
        if row["status"] != "new":
            return 409, {"error": "This request was already decided."}
        # a normal invite (permission checks, fresh authenticator code, audit) with the Chat User role, link emailed
        # (with email not set up yet, the invite link is shown to the admin instead of emailed)
        send = data.get("send_email") is not False and not mail_api.not_ready()
        code, out = access_api.invite(h, {"username": data.get("username"), "email": row["email"], "display_name": row["name"],
                                          "roles": [role], "send_email": send})
        if code < 300:
            with tx(core.db) as c:
                c.execute("UPDATE chat_requests SET status='approved', decided_at=?, decided_by=?, username=? WHERE id=?",
                          (int(time.time()), h.user, out.get("username"), rid))
        return code, out
    if action in ("decline", "delete"):
        def go(c):
            _need(c, h, "admin.requests.review")
            if action == "decline":
                c.execute("UPDATE chat_requests SET status='declined', decided_at=?, decided_by=? WHERE id=?", (int(time.time()), h.user, rid))
            else:
                c.execute("DELETE FROM chat_requests WHERE id=?", (rid,))
            audit(c, h.user, "chat.access_request_" + action, "chat_request", rid, ctx=h.ctx())
            return 200, {"ok": True}
        return access_api.run(h, go)
    return 400, {"error": "Choose approve, decline or delete."}


def purge(c):
    t = int(time.time())
    return c.execute("DELETE FROM chat_requests WHERE (status<>'new' AND decided_at<?) OR (status='new' AND created<?)",
                     (t - KEEP_DECIDED_S, t - KEEP_OPEN_S)).rowcount
