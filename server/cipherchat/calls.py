"""CipherChat calls: the server's part (docs/CALLS.md). Shared with the DarkCipher Systems portal like chat.py.

The server never sees a call key or a picture. It does two things:

  * relays call signals (ring, accept, offer/answer, ICE candidates, the wrapped call key, leave, end) between the
    members of a room. Each signal is a header signed by the sender's identity (ML-DSA-87 + Ed25519, verified by every
    client); the server checks only that it's well-formed, that sender and recipients are members, and the rate.
    Signals live in memory for SIGNAL_TTL seconds and are delivered through the chat's own long poll
    (`poll?...&sig=<last signal id>`), so a phone or PC rings without a second connection. They are never written
    to disk; a room event "<user> started a call" is the only lasting trace (shown in the room like other events).
  * hands out short-lived TURN credentials (coturn's shared-secret scheme) so calls get through any NAT. TURN relays
    frames that are already encrypted end to end.

  GET  /chat/api/calls/turn        -> {"ice_servers": [...], "ttl": s, "relay_only": bool}
  POST /chat/api/calls/signal      {"room", "to": [users], "sig": {"h", "s"}} -> {"ok", "sid"}

Settings (environment):
  CIPHERCHAT_TURN_URLS          comma-separated turn:/turns: URLs (empty: no relay; calls then need a direct path)
  CIPHERCHAT_TURN_SECRET_FILE   coturn's static-auth-secret, one line (root:cipherchat 0640)
  CIPHERCHAT_CALLS_RELAY_ONLY   1 = clients send media only through TURN, never revealing their addresses to peers
  CIPHERCHAT_STUN_URLS          comma-separated stun: URLs (address discovery only, no relay)
"""
import base64
import collections
import hashlib
import hmac
import json
import os
import re
import threading
import time

core = None          # the server module (db, ...)
chat = None          # chat.py: room checks, rate limits, the poll's condition variable

SIGNAL_MAX = 48 * 1024                    # one signed header (an SDP offer is ~6 KiB; a call key for 8 people ~15 KiB)
SIGNAL_TTL = 60                           # seconds a signal waits to be fetched
SIGNAL_RATE = (900, 60)                   # per user per minute (ICE trickle is chatty during set-up)
QUEUE_MAX = 600                           # signals waiting per user (oldest dropped first)
MAX_PARTICIPANTS = 8                      # a call is a mesh: every participant sends to every other
TURN_TTL = 4 * 3600
KINDS = ("ring", "accept", "decline", "busy", "offer", "answer", "ice", "key", "leave", "end", "state")
CALL_ID_RE = re.compile(r"[A-Za-z0-9_-]{22}")
DEVICE_RE = re.compile(r"[A-Za-z0-9_-]{8,22}")

_lock = threading.Lock()
_queues = collections.defaultdict(collections.deque)     # user -> deque[(sid, expires, item)]
_next = [int(time.time() * 1000)]                        # signal ids keep rising across restarts


def bind(server_module, chat_module):
    global core, chat
    core, chat = server_module, chat_module
    if poll_extra not in chat.EXTRA_POLL:
        chat.EXTRA_POLL.append(poll_extra)
    if route not in chat.EXTRA_ROUTES:
        chat.EXTRA_ROUTES.append(route)


# ------------------------------------------------------------------ the in-memory relay
def _push(users, item):
    now = time.time()
    with _lock:
        _next[0] += 1
        sid = _next[0]
        for u in users:
            q = _queues[u]
            while q and (q[0][1] < now or len(q) >= QUEUE_MAX):
                q.popleft()
            q.append((sid, now + SIGNAL_TTL, dict(item, sid=sid)))
    chat._notify()
    return sid


def poll_extra(user, q):
    """For chat.poll: signals newer than the client's `sig` cursor. Clients that don't send `sig` get none."""
    cursor = q.get("sig")
    if cursor is None or not re.fullmatch(r"[0-9]{1,19}", str(cursor)):         # ASCII digits only (str.isdigit() accepts other scripts)
        return "signals", []
    cursor, now = int(cursor), time.time()
    with _lock:
        q_ = _queues.get(user)
        if not q_:
            return "signals", []
        while q_ and q_[0][1] < now:
            q_.popleft()
        return "signals", [it for sid, exp, it in q_ if sid > cursor]


def forget(user):
    """Signed out or removed from the chat: drop what was waiting for them."""
    with _lock:
        _queues.pop(user, None)


# ------------------------------------------------------------------ requests
def signal(h, data):
    room_id, to, sig = data.get("room"), data.get("to"), data.get("sig")
    if not isinstance(to, list) or not 1 <= len(to) <= MAX_PARTICIPANTS - 1 or not all(isinstance(u, str) for u in to) \
            or len(set(to)) != len(to) or h.user in to:
        return 400, {"error": "Choose who the signal is for (up to %d others)." % (MAX_PARTICIPANTS - 1)}
    if not isinstance(sig, dict):
        return 400, {"error": "Malformed call signal."}

    def go(c):
        chat.need(c, h, "chat.access.use")
        room, _ = chat.room_for(c, h, room_id)
        members = {r[0] for r in c.execute("SELECT username FROM chat_members WHERE room_id=?", (room["id"],))}
        if not set(to) <= members:
            raise chat.Refuse(403, "Everyone in a call must be in the room.", denied=True)
        chat._limit(h.user, "signals", SIGNAL_RATE)
        _, hdr = chat.signed_json(sig.get("h"), SIGNAL_MAX, "call signal")
        chat.b64(sig.get("s"), size=chat.SIG_LEN, name="call signal signature")
        me = chat.identity(c, h.user)
        if me is None:
            raise chat.Refuse(409, "Set up your chat identity first.")
        if (hdr.get("t") != "call" or hdr.get("room") != room["id"] or hdr.get("from") != h.user or hdr.get("from_fp") != me["fp"]
                or hdr.get("kind") not in KINDS or not isinstance(hdr.get("call"), str) or not CALL_ID_RE.fullmatch(hdr["call"])
                or not isinstance(hdr.get("dev"), str) or not DEVICE_RE.fullmatch(hdr["dev"])
                or hdr.get("to") != to or not chat._int(hdr.get("at"), 0, 2 ** 53)):
            raise chat.Refuse(400, "That call signal doesn't match this room and account.")
        if abs(hdr["at"] / 1000 - time.time()) > 120:
            raise chat.Refuse(400, "That call signal is too old (check this device's clock).")
        if hdr["kind"] == "ring":
            chat.need(c, h, "chat.calls.start")                 # answering needs only chat access; starting a call this
            media = hdr.get("media") if hdr.get("media") in ("audio", "video") else "audio"
            chat._event(c, room["id"], h.user, e="call", media=media, call=hdr["call"])
        return {"room": room["id"], "from": h.user, "at": int(time.time()), "kind": hdr["kind"], "call": hdr["call"],
                "sig": {"h": sig["h"], "s": sig["s"]}}

    out = chat.run(h, go, write=True)
    if isinstance(out, tuple):
        return out
    # the sender's own other devices see it too (to stop ringing when another of them answers)
    sid = _push(to + [h.user], out)
    return 200, {"ok": True, "sid": sid}


def _secret():
    path = os.environ.get("CIPHERCHAT_TURN_SECRET_FILE", "")
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as f:
            s = f.read().strip()
        return s or None
    except OSError:
        return None


def turn(h):
    def go(c):
        chat.need(c, h, "chat.access.use")
        return True
    out = chat.run(h, go, write=False)
    if isinstance(out, tuple):
        return out
    urls = [u.strip() for u in os.environ.get("CIPHERCHAT_TURN_URLS", "").split(",") if re.fullmatch(r"turns?:[A-Za-z0-9.:\[\]_-]+(\?transport=(udp|tcp))?", u.strip())]
    stun = [u.strip() for u in os.environ.get("CIPHERCHAT_STUN_URLS", "").split(",") if re.fullmatch(r"stun:[A-Za-z0-9.:\[\]_-]+", u.strip())]
    relay_only = os.environ.get("CIPHERCHAT_CALLS_RELAY_ONLY", "0") == "1"
    secret = _secret()
    servers = [{"urls": stun}] if stun else []
    if not urls or not secret:
        return 200, {"ice_servers": servers, "ttl": 0, "relay_only": False}
    expires = int(time.time()) + TURN_TTL
    # coturn's REST scheme: username "<expiry>:<anything>", password base64(HMAC-SHA1(secret, username)). The name part
    # is a keyed hash, so coturn's logs never carry account names.
    who = hmac.new(secret.encode(), b"cipherchat-turn-user|" + h.user.encode(), hashlib.sha256).hexdigest()[:16]
    username = "%d:%s" % (expires, who)
    password = base64.b64encode(hmac.new(secret.encode(), username.encode(), hashlib.sha1).digest()).decode()
    servers.append({"urls": urls, "username": username, "credential": password})
    return 200, {"ice_servers": servers, "ttl": TURN_TTL, "relay_only": relay_only}


def route(h, method, path, q, data):
    if path == "calls/turn" and method == "GET":
        return turn(h)
    if path == "calls/signal" and method == "POST":
        return signal(h, data)
    return None
