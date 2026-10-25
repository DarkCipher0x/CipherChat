"""Passkeys (WebAuthn) for CipherChat: one-tap sign-in and "confirm it's you" with a passkey kept in a password manager
such as Bitwarden, or in Windows Hello / Android. A passkey with user verification (biometric or PIN on the device) is
phishing-resistant multi-factor authentication, so it counts like password + authenticator code.

  GET  /chat/api/passkeys                          your passkeys
  POST /chat/api/passkeys/register/begin           {}                 -> creation options (needs a fresh code or passkey)
  POST /chat/api/passkeys/register/finish          {flow, name, credential}
  POST /chat/api/passkeys/<id>/delete              {}                 (needs a fresh code or passkey)
  POST /chat/api/auth/passkey/begin                {purpose: login|reauth} -> request options
  POST /chat/api/auth/passkey/finish               {flow, credential} -> a session (login) or a fresh re-auth (reauth)

What is checked on every assertion: the challenge (single use, 5 minutes), the origin (this server, or an app origin
listed in CIPHERCHAT_PASSKEY_APP_ORIGINS), the RP ID hash, user presence AND user verification, the signature
(ES256 or EdDSA, webauthn_verify.py), and that the signature counter never goes backwards (a cloned authenticator).
Attestation is not required ("none"): which authenticator someone uses is their choice.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time

import authz
import storage
import webauthn_verify as wv
from authz import audit, tx

core = None
CHALLENGE_S = 300
MAX_PER_USER = 10
def _android_apps(text):
    """CIPHERCHAT_ANDROID_APPS: "<package>=<SHA-256 of the app's signing certificate, AA:BB:..>" entries, comma-separated
    (the CipherChat Android app, or your own build of it). Malformed entries are ignored."""
    apps = []
    for part in text.split(","):
        pkg, _, fp = part.strip().partition("=")
        fp = fp.strip().upper()
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+", pkg.strip()) and re.fullmatch(r"([0-9A-F]{2}:){31}[0-9A-F]{2}", fp):
            apps.append((pkg.strip(), fp))
    return tuple(apps)


ANDROID_APPS = _android_apps(os.environ.get("CIPHERCHAT_ANDROID_APPS", ""))
# Android's Credential Manager signs clientDataJSON with the app's origin, "android:apk-key-hash:<base64url(cert sha256)>"
APP_ORIGINS = tuple(o.strip() for o in os.environ.get("CIPHERCHAT_PASSKEY_APP_ORIGINS", "").split(",") if o.strip()) + tuple(
    "android:apk-key-hash:" + base64.urlsafe_b64encode(bytes.fromhex(fp.replace(":", ""))).rstrip(b"=").decode() for _, fp in ANDROID_APPS)
_flows = {}


def assetlinks():
    """/.well-known/assetlinks.json: lets the listed Android apps use this server's passkeys (Digital Asset Links)."""
    return [{"relation": ["delegate_permission/common.get_login_creds"],
             "target": {"namespace": "android_app", "package_name": pkg, "sha256_cert_fingerprints": [fp]}} for pkg, fp in ANDROID_APPS]
_flow_lock = threading.Lock()


def bind(server_module):
    global core
    core = server_module


def migrate(c):
    c.execute("""CREATE TABLE IF NOT EXISTS passkeys(
        id TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES admins(username) ON DELETE CASCADE,
        alg INTEGER NOT NULL, pub TEXT NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0, name TEXT NOT NULL DEFAULT '',
        created TEXT NOT NULL, last_used TEXT)""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(username)")


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    if not isinstance(s, str) or len(s) > 4096:
        raise ValueError("bad base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def rp_id():
    return core.ORIGIN.split("://", 1)[1].split(":")[0].split("/")[0]


def user_handle(username):
    """A stable, non-identifying user id for authenticators (never the username itself)."""
    key = storage.KEYRING.get(storage.KEYRING.current)
    return hmac.new(key, b"cipherchat-passkey-user/v1|" + username.encode(), hashlib.sha256).digest()[:16]


def _new_flow(purpose, user):
    t = time.time()
    flow, challenge = secrets.token_urlsafe(18), secrets.token_bytes(32)
    with _flow_lock:
        for k in [k for k, v in _flows.items() if v["exp"] < t]:
            del _flows[k]
        if len(_flows) > 10000:
            _flows.clear()
        _flows[flow] = {"purpose": purpose, "user": user, "challenge": challenge, "exp": t + CHALLENGE_S}
    return flow, challenge


def _take_flow(flow, purpose):
    with _flow_lock:
        f = _flows.pop(flow, None) if isinstance(flow, str) else None
    if f is None or f["purpose"] != purpose or f["exp"] < time.time():
        raise ValueError("This passkey request expired. Try again.")
    return f


def _client_data(cred, kind, challenge):
    raw = unb64u(cred["response"]["clientDataJSON"])
    cd = json.loads(raw.decode("utf-8"))
    if cd.get("type") != kind:
        raise ValueError("wrong ceremony type")
    if not hmac.compare_digest(unb64u(cd.get("challenge", "")), challenge):
        raise ValueError("wrong challenge")
    if cd.get("origin") != core.ORIGIN and cd.get("origin") not in APP_ORIGINS:
        raise ValueError("wrong origin")
    if cd.get("crossOrigin") is True:
        raise ValueError("cross-origin request")
    return raw


def _auth_data(ad, need_attested=False):
    if len(ad) < 37:
        raise ValueError("authenticator data too short")
    if not hmac.compare_digest(ad[:32], hashlib.sha256(rp_id().encode()).digest()):
        raise ValueError("wrong RP ID")
    flags = ad[32]
    if not flags & 0x01:
        raise ValueError("user presence missing")
    if not flags & 0x04:
        raise ValueError("user verification missing (the passkey must ask for your biometric or PIN)")
    count = int.from_bytes(ad[33:37], "big")
    if need_attested and not flags & 0x40:
        raise ValueError("no credential in the registration")
    return flags, count


def _cose(key):
    """COSE public key -> (alg, stored public key string)."""
    kty, alg = key.get(1), key.get(3)
    if alg == -7 and kty == 2 and key.get(-1) == 1:              # EC2, P-256, ES256
        x, y = key.get(-2), key.get(-3)
        if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == 32 and len(y) == 32):
            raise ValueError("bad P-256 key")
        if not wv._on_curve((int.from_bytes(x, "big"), int.from_bytes(y, "big"))):
            raise ValueError("P-256 key not on the curve")
        return -7, b64u(x + y)
    if alg == -8 and kty == 1 and key.get(-1) == 6:              # OKP, Ed25519, EdDSA
        x = key.get(-2)
        if not (isinstance(x, bytes) and len(x) == 32):
            raise ValueError("bad Ed25519 key")
        return -8, b64u(x)
    raise ValueError("unsupported passkey type (use a P-256 or Ed25519 passkey)")


def _verify(alg, pub, signed, sig):
    raw = unb64u(pub)
    if alg == -7:
        r, s = wv.der_signature(sig)
        return wv.p256_verify(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"), signed, r, s)
    if alg == -8:
        return wv.ed25519_verify(raw, signed, sig)
    return False


# ------------------------------------------------------------------ registration (signed in)
def list_mine(h):
    with core.db() as c:
        rows = c.execute("SELECT id, name, created, last_used, alg FROM passkeys WHERE username=? ORDER BY created", (h.user,)).fetchall()
    return 200, {"passkeys": [{"id": r["id"], "name": r["name"], "created": r["created"], "last_used": r["last_used"],
                               "type": "ES256" if r["alg"] == -7 else "EdDSA"} for r in rows], "rp_id": rp_id()}


def register_begin(h):
    def go(c):
        core.access_api.need_reauth(c, h)
        n = c.execute("SELECT COUNT(*) FROM passkeys WHERE username=?", (h.user,)).fetchone()[0]
        if n >= MAX_PER_USER:
            raise core.access_api.Refuse(400, "You already have %d passkeys. Remove one first." % MAX_PER_USER)
        acc = authz.account(c, h.user)
        flow, challenge = _new_flow("register", h.user)
        exclude = [{"type": "public-key", "id": r[0]} for r in c.execute("SELECT id FROM passkeys WHERE username=?", (h.user,))]
        return 200, {"flow": flow, "publicKey": {
            "challenge": b64u(challenge), "rp": {"id": rp_id(), "name": core.server_name()},
            "user": {"id": b64u(user_handle(h.user)), "name": h.user, "displayName": acc.get("display_name") or h.user},
            "pubKeyCredParams": [{"type": "public-key", "alg": -8}, {"type": "public-key", "alg": -7}],
            "authenticatorSelection": {"residentKey": "required", "requireResidentKey": True, "userVerification": "required"},
            "attestation": "none", "timeout": CHALLENGE_S * 1000, "excludeCredentials": exclude}}
    return core.access_api.run(h, go)


def register_finish(h, data):
    try:
        f = _take_flow(data.get("flow"), "register")
        if f["user"] != h.user:
            raise ValueError("This passkey request was for another account.")
        cred = data["credential"]
        _client_data(cred, "webauthn.create", f["challenge"])
        att, _ = wv.cbor_decode(unb64u(cred["response"]["attestationObject"]))
        ad = att.get("authData") if isinstance(att, dict) else None
        if not isinstance(ad, bytes):
            raise ValueError("bad attestation")
        _, count = _auth_data(ad, need_attested=True)
        if len(ad) < 55:
            raise ValueError("bad credential data")
        n = int.from_bytes(ad[53:55], "big")
        cred_id = ad[55:55 + n]
        if n < 16 or n > 1023 or len(cred_id) != n or b64u(cred_id) != cred.get("id"):
            raise ValueError("credential id mismatch")
        key, end = wv.cbor_decode(ad, 55 + n)
        alg, pub = _cose(key)
    except (ValueError, KeyError, TypeError, UnicodeDecodeError, wv.CborError) as e:
        return 400, {"error": "That passkey couldn't be registered: %s." % e}
    name = core.clean(data.get("name"), 60) or "Passkey"
    with tx(core.db) as c:
        if c.execute("SELECT 1 FROM passkeys WHERE id=?", (b64u(cred_id),)).fetchone():
            return 409, {"error": "That passkey is already registered."}
        c.execute("INSERT INTO passkeys(id, username, alg, pub, sign_count, name, created) VALUES(?,?,?,?,?,?,?)",
                  (b64u(cred_id), h.user, alg, pub, count, name, authz.now()))
        audit(c, h.user, "auth.passkey_add", "passkey", b64u(cred_id)[:24], detail={"name": name, "alg": alg}, ctx=h.ctx())
    return 200, {"ok": True, "id": b64u(cred_id), "name": name}


def delete(h, cred_id):
    def go(c):
        core.access_api.need_reauth(c, h)
        n = c.execute("DELETE FROM passkeys WHERE id=? AND username=?", (cred_id, h.user)).rowcount
        if not n:
            raise core.access_api.Refuse(404, "No such passkey.")
        audit(c, h.user, "auth.passkey_remove", "passkey", cred_id[:24], ctx=h.ctx())
        return 200, {"ok": True}
    return core.access_api.run(h, go)


# ------------------------------------------------------------------ sign-in and re-auth
def auth_begin(h, data):
    purpose = data.get("purpose") if data.get("purpose") in ("login", "reauth") else "login"
    allow = []
    user = None
    if purpose == "reauth":
        if not h.has_session():
            return 403, {"error": "Sign in first."}
        user = h.user
        with core.db() as c:
            allow = [{"type": "public-key", "id": r[0]} for r in c.execute("SELECT id FROM passkeys WHERE username=?", (user,))]
        if not allow:
            return 400, {"error": "You haven't added a passkey yet."}
    flow, challenge = _new_flow(purpose, user)
    return 200, {"flow": flow, "publicKey": {"challenge": b64u(challenge), "rpId": rp_id(), "timeout": CHALLENGE_S * 1000,
                                            "userVerification": "required", "allowCredentials": allow}}


def auth_finish(h, data):
    """(status, payload, username or None). The caller issues the session for a login."""
    fail = (401, {"error": "That passkey didn't work. Try again, or sign in with your password and code."}, None)
    try:
        f = _take_flow(data.get("flow"), data.get("purpose") or "login")
        cred = data["credential"]
        cd_raw = _client_data(cred, "webauthn.get", f["challenge"])
        ad = unb64u(cred["response"]["authenticatorData"])
        sig = unb64u(cred["response"]["signature"])
        cred_id = cred.get("id")
        _, count = _auth_data(ad)
    except (ValueError, KeyError, TypeError, UnicodeDecodeError) as e:
        sys_note(h, "passkey refused: %s" % type(e).__name__)
        return fail
    with tx(core.db) as c:
        row = c.execute("SELECT * FROM passkeys WHERE id=?", (cred_id,)).fetchone()
        if row is None or (f["user"] is not None and row["username"] != f["user"]):
            return fail
        handle = cred["response"].get("userHandle")
        if handle and unb64u(handle) != user_handle(row["username"]):
            return fail
        if not _verify(row["alg"], row["pub"], ad + hashlib.sha256(cd_raw).digest(), sig):
            audit(c, row["username"], "auth.passkey", "user", row["username"], "failed", {"reason": "bad signature"}, h.ctx())
            return fail
        if (count or row["sign_count"]) and count <= row["sign_count"]:
            audit(c, row["username"], "auth.passkey", "user", row["username"], "failed", {"reason": "signature counter went back"}, h.ctx())
            return 401, {"error": "This passkey looks cloned (its counter went backwards), so it was refused. Remove it and add it again."}, None
        if not authz.decide(c, row["username"], "chat.access.use")[0]:
            return 403, {"error": "This account can't use the chat.", "denied": True}, None
        c.execute("UPDATE passkeys SET sign_count=?, last_used=? WHERE id=?", (count, authz.now(), cred_id))
        audit(c, row["username"], "auth.passkey", "user", row["username"], "ok", {"purpose": f["purpose"], "name": row["name"]}, h.ctx())
    return 200, {"ok": True, "user": row["username"]}, row["username"]


def sys_note(h, msg):
    import sys
    sys.stderr.write(msg + "\n")
