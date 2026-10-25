#!/usr/bin/env python3
"""CipherChat server: end-to-end tests over real HTTP (a server on 127.0.0.1 with a throwaway state directory).

Covers the parts that are CipherChat's own (accounts, sign-in, invite links, roles, admin API, access requests, device
pairing, rate limits, the web portal's files and headers) and a chat round trip through the shared chat module.
    python3 -I server/tests/test_server.py
"""
import base64
import hashlib
import hmac
import http.client
import json
import os
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "..", "cipherchat", "server.py")
OWNER = "olivia"
PW = "a long test password 2026"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def totp(secret, offset=0):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    d = hmac.new(key, struct.pack(">Q", int(time.time()) // 30 + offset), hashlib.sha1).digest()
    o = d[-1] & 15
    return "%06d" % ((struct.unpack(">I", d[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


def b64(b):
    return base64.b64encode(b).decode()


def rnd(n):
    return b64(secrets.token_bytes(n))


def bundle(user):
    obj = {"v": 1, "t": "identity", "user": user, "at": int(time.time() * 1000), "kem_pq": rnd(1568), "kem_ec": rnd(32),
           "sig_pq": rnd(2592), "sig_ec": rnd(32)}
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    return {"b": b64(raw), "s": rnd(4627 + 64)}, hashlib.sha3_256(raw).hexdigest()


def backup():
    return {"v": 1, "kdf": {"alg": "argon2id", "m": 65536, "t": 3, "p": 1, "salt": rnd(32)}, "pepper_ver": 1, "n": rnd(12), "c": rnd(300)}


ANDROID_FP = "14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5"
ANDROID_ORIGIN = "android:apk-key-hash:" + base64.urlsafe_b64encode(bytes.fromhex(ANDROID_FP.replace(":", ""))).rstrip(b"=").decode()


class Server(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="cipherchat-test-")
        cls.port = free_port()
        cls.origin = "http://127.0.0.1:%d" % cls.port
        cls.env = dict(os.environ, CIPHERCHAT_DEV="1", CIPHERCHAT_ORIGIN=cls.origin, CIPHERCHAT_OWNER=OWNER,
                       CIPHERCHAT_STATE_DIR=os.path.join(cls.tmp, "state"), CIPHERCHAT_KEY_FILE=os.path.join(cls.tmp, "keys", "server.key"),
                       CIPHERCHAT_LISTEN="127.0.0.1:%d" % cls.port, CIPHERCHAT_NAME="Test Chat", CIPHERCHAT_TRUST_PROXY="1",
                       CIPHERCHAT_TURN_URLS="turns:turn.example.net:5349?transport=tcp, turn:turn.example.net:3478?transport=udp, http://bad",
                       CIPHERCHAT_TURN_SECRET_FILE=os.path.join(cls.tmp, "turn-secret"),
                       CIPHERCHAT_ANDROID_APPS="systems.darkcipher.cipherchat=14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5, bad entry, x=12:34")
        with open(cls.env["CIPHERCHAT_TURN_SECRET_FILE"], "w") as f:
            f.write("test-turn-secret-0123456789\n")
        out = subprocess.run([sys.executable, "-I", SERVER, "owner-invite"], env=cls.env, capture_output=True, text=True, timeout=60)
        assert out.returncode == 0, out.stderr
        cls.owner_link = out.stdout.strip().splitlines()[-1]
        cls.proc = subprocess.Popen([sys.executable, "-I", SERVER, "serve"], env=cls.env, stderr=subprocess.PIPE, text=True)
        # read the server's log as it comes: a full pipe (4 KiB on Windows) would otherwise block every request
        cls.log = []
        cls.reader = threading.Thread(target=lambda: cls.log.extend(iter(cls.proc.stderr.readline, "")), daemon=True)
        cls.reader.start()
        for _ in range(100):
            try:
                if cls.raw("GET", "/healthz")[0] == 200:
                    break
            except OSError:
                time.sleep(0.1)
        cls.secrets = {}

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(10)
        finally:
            cls.reader.join(5)
            err = "".join(cls.log)
            if "UNHANDLED" in err:
                print(err, file=sys.stderr)
            shutil.rmtree(cls.tmp, ignore_errors=True)

    # ------------------------------------------------------------------ HTTP helpers
    @classmethod
    def raw(cls, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=40)
        h = dict(headers or {})
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            h.setdefault("Content-Type", "application/json")
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        payload = r.read()
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        c.close()
        return r.status, payload, hdrs

    def call(self, path, body=None, cookie=None, csrf=True, headers=None):
        h = {"X-Requested-With": "dcx-portal", "Origin": self.origin} if csrf else {}
        h["X-Real-IP"] = "10.%d.%d.%d" % tuple(secrets.randbelow(250) + 1 for _ in range(3))   # rate limits are per address
        if cookie:
            h["Cookie"] = "cipherchat_dev=" + cookie
        h.update(headers or {})
        code, payload, hdrs = self.raw("GET" if body is None else "POST", path, body, h)
        try:
            j = json.loads(payload or b"{}")
        except ValueError:
            j = {}
        return code, j, hdrs

    def api(self, path, body=None, cookie=None, **kw):
        return self.call("/chat/api/" + path, body, cookie, **kw)[:2]

    def enrol(self, link, user):
        token = link.split("#enrol=")[1]
        code, j = self.api("auth/enrol/check", {"token": token})
        self.assertEqual((code, j["username"]), (200, user), j)
        code, j = self.api("auth/enrol/start", {"token": token, "password": PW})
        self.assertEqual(code, 200, j)
        self.secrets[user] = j["secret"]
        self.assertIn("issuer=Test%20Chat", j["otpauth"])
        self.assertEqual(self.api("auth/enrol/finish", {"token": token, "code": totp(j["secret"], -1)})[0], 200)

    def login(self, user, offset=0):
        code, j, h = self.call("/chat/api/auth/login", {"username": user, "password": PW, "code": totp(self.secrets[user], offset)})
        self.assertEqual(code, 200, j)
        self.assertIn("HttpOnly", h["set-cookie"])
        return h["set-cookie"].split("=", 1)[1].split(";")[0]

    def owner(self):
        if not hasattr(Server, "_owner"):
            self.enrol(self.owner_link, OWNER)
            Server._owner = self.login(OWNER)
        return Server._owner

    def invite(self, user, role="member"):
        code, j = self.api("admin/users/invite", {"username": user, "role": role}, self.owner())
        self.assertEqual(code, 201, j)
        self.enrol(j["link"]["url"], user)
        return self.login(user)

    # ------------------------------------------------------------------ tests
    def test_01_owner_sets_up_from_the_command_line_link(self):
        self.assertIn("/chat/login/#enrol=", self.owner_link)
        tok = self.owner()
        code, j = self.api("auth/status", None, tok)
        self.assertTrue(j["signed_in"])
        self.assertEqual((j["user"], j["role"], j["owner"], j["admin"], j["name"]), (OWNER, "owner", True, True, "Test Chat"))
        self.assertGreater(j["reauth_valid_for"], 0)                              # password + code just now = fresh
        self.assertEqual(self.api("auth/enrol/check", {"token": self.owner_link.split("#enrol=")[1]})[0], 400)   # single use

    def test_02_sign_in_is_three_factor_and_csrf_guarded(self):
        self.owner()
        code, j, _ = self.call("/chat/api/auth/login", {"username": OWNER, "password": "wrong password here 1", "code": totp(self.secrets[OWNER])})
        self.assertEqual(code, 401)
        self.assertEqual(self.call("/chat/api/auth/login", {"username": OWNER, "password": PW, "code": "000000"}, csrf=False)[0], 403)
        self.assertEqual(self.call("/chat/api/rooms", {"name": "x"}, self.owner(), headers={"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(self.api("state")[0], 403)                                # no session

    def test_03_roles_and_admin_api(self):
        mem = self.invite("max")
        self.assertEqual(self.api("admin/users", None, mem)[0], 403)
        code, j = self.api("admin/users", None, self.owner())
        self.assertEqual(code, 200)
        names = {u["username"]: u for u in j["users"]}
        self.assertEqual(names["max"]["role"], "member")
        self.assertEqual(names[OWNER]["role"], "owner")
        guest = self.invite("gail", role="guest")
        self.assertEqual(self.api("state", None, guest)[0], 200)
        self.assertEqual(self.api("rooms", {"name": "nope", "members": []}, guest)[0], 403)      # guests can't create rooms
        adm = self.invite("ada", role="admin")
        self.assertEqual(self.api("admin/users", None, adm)[0], 200)
        self.assertEqual(self.api("admin/users/%s/suspend" % OWNER, {}, adm)[0], 403)          # owner protected
        self.assertEqual(self.api("admin/users/invite", {"username": "adm2", "role": "admin"}, adm)[0], 403)  # only the owner makes admins
        # suspending ends the sessions at once
        self.assertEqual(self.api("admin/users/gail/suspend", {}, self.owner())[0], 200)
        self.assertEqual(self.api("state", None, guest)[0], 403)
        self.assertEqual(self.api("admin/users/gail/activate", {}, self.owner())[0], 200)

    def test_04_access_requests_become_invitations(self):
        body = {"name": "Nora Test", "email": "nora@example.com", "message": "I'd like to join the dev chat please.", "agree": True,
                "website": "", "elapsed": 9000}
        self.assertEqual(self.raw("POST", "/api/chat-request", body, {"X-Real-IP": "203.0.113.7"})[0], 201)
        self.assertEqual(self.raw("POST", "/chat/api/request", body, {"X-Real-IP": "203.0.113.8"})[0], 201)
        code, j = self.api("admin/requests", None, self.owner())
        self.assertEqual(code, 200)
        r = j["requests"][0]
        self.assertEqual(r["email"], "nora@example.com")
        code, j = self.api("admin/requests/%d" % r["id"], {"action": "approve", "username": "nora", "send_email": False}, self.owner())
        self.assertEqual(code, 201, j)
        self.assertIn("/chat/login/#enrol=", j["link"]["url"])
        code, j = self.api("admin/users", None, self.owner())
        self.assertEqual({u["username"]: u["role"] for u in j["users"]}["nora"], "member")
        events = self.api("admin/audit", None, self.owner())[1]["events"]
        req = [e for e in events if e["action"] == "chat.access_request"]
        self.assertTrue(req and req[0]["ip"] == "")                               # stored without the sender's address

    def test_05_chat_round_trip_through_the_shared_module(self):
        owner, kim = self.owner(), self.invite("kim")
        ob, ofp = bundle(OWNER)
        self.assertEqual(self.api("identity", {"bundle": ob, "backup": backup()}, owner)[0], 200)
        kb, kfp = bundle("kim")
        self.assertEqual(self.api("identity", {"bundle": kb, "backup": backup()}, kim)[0], 200)
        st = self.api("state", None, kim)[1]
        self.assertEqual(st["owner"], OWNER)
        self.assertTrue(st["server_key_share"])
        self.assertEqual(self.api("pepper", None, kim)[0], 200)
        code, j = self.api("backup/fetch", {}, kim)
        self.assertEqual((code, j["fp"]), (200, kfp))
        code, j = self.api("rooms", {"name": "dev", "members": ["kim"], "retention_days": 0}, owner)
        self.assertEqual(code, 200, j)
        rid = j["id"]
        code, j = self.call("/chat/api/poll?since=0&rev=-1", None, kim)[:2]
        self.assertEqual(code, 200)

    def test_06_device_pairing(self):
        tok = self.invite("pia")
        code, j = self.api("devices", {"name": "Pixel"}, tok)
        self.assertEqual(code, 200, j)                                            # fresh sign-in: no extra code needed
        device = j["token"]
        code, j, h = self.call("/chat/api/auth/device", {"token": device})
        self.assertEqual(code, 200, j)
        dev = h["set-cookie"].split("=", 1)[1].split(";")[0]
        self.assertEqual(self.api("state", None, dev)[0], 200)
        self.assertTrue(self.api("auth/status", None, dev)[1]["device"])
        self.assertEqual(self.api("devices", {"name": "x"}, dev)[0], 403)          # a paired device can't pair more
        code, j = self.api("identity", {"bundle": bundle("pia")[0], "backup": backup()}, dev)
        self.assertEqual(code, 401)                                               # key changes need a fresh code
        self.assertEqual(self.api("auth/reauth", {"code": totp(self.secrets["pia"], 1)}, dev)[0], 200)
        self.assertEqual(self.api("identity", {"bundle": bundle("pia")[0], "backup": backup()}, dev)[0], 200)
        self.assertEqual(self.call("/chat/api/auth/device", {"token": "x" * 43})[0], 401)

    def test_07_web_portal_files_and_headers(self):
        code, body, h = self.raw("GET", "/chat/", headers={"Cookie": "cipherchat_dev=" + self.owner()})   # signed in (signed out: test_15)
        self.assertEqual(code, 200)
        self.assertIn(b"cipher</b>chat", body)
        self.assertIn("blob:", h["content-security-policy"])
        self.assertNotIn("unsafe", h["content-security-policy"])
        for k in ("x-content-type-options", "x-frame-options", "referrer-policy", "cross-origin-opener-policy"):
            self.assertIn(k, h)
        self.assertEqual(self.raw("GET", "/chat/app/crypto.js")[0], 200)
        self.assertTrue(self.raw("GET", "/chat/public/vendor/qrcode/qrcode.mjs")[2]["content-type"].startswith("text/javascript"))   # module scripts need a JS type
        self.assertEqual(self.raw("GET", "/chat/login/")[0], 200)
        self.assertEqual(self.raw("GET", "/chat/admin/", headers={"Cookie": "cipherchat_dev=" + self.owner()})[0], 200)
        self.assertEqual(self.raw("GET", "/chat/public/privacy.html")[0], 200)
        self.assertEqual(self.raw("GET", "/chat/../server/cipherchat/server.py")[0], 404)
        self.assertEqual(self.raw("GET", "/chat/%2e%2e/%2e%2e/etc/passwd")[0], 404)
        self.assertEqual(self.raw("GET", "/")[0], 302)
        code, _, h = self.raw("GET", "/chat/api/auth/status")
        self.assertEqual(h["cache-control"], "no-store")

    def test_08_rate_limits(self):
        codes = [self.call("/chat/api/auth/login", {"username": "nobody", "password": "x" * 20, "code": "123456"},
                           headers={"X-Real-IP": "198.51.100.9"})[0] for _ in range(8)]
        self.assertIn(429, codes)
        self.assertEqual(self.call("/chat/api/auth/login", {"username": "nobody", "password": "x" * 20, "code": "123456"},
                                   headers={"X-Real-IP": "198.51.100.10"})[0], 401)   # another address isn't affected

    def test_09_password_change_and_links(self):
        tok = self.invite("rae")
        code, j = self.api("auth/password", {"current": PW, "new": "another long password 77", "code": totp(self.secrets["rae"], 1)}, tok)
        self.assertEqual(code, 200, j)
        self.assertEqual(self.api("state", None, tok)[0], 403)                    # every old session ends
        code, j = self.api("admin/users/rae/reset_mfa", {"send_email": False}, self.owner())
        self.assertEqual(code, 200, j)
        self.assertIn("#enrol=", j["link"]["url"])


    # ------------------------------------------------------------------ passkeys (e.g. kept in Bitwarden)
    def test_10_passkeys(self):
        sys.path.insert(0, os.path.join(HERE, "..", "cipherchat"))
        import webauthn_verify as wv
        auth = SoftAuthenticator(wv, "127.0.0.1", self.origin)
        tok = self.invite("pam")
        code, j = self.api("passkeys/register/begin", {}, tok)
        self.assertEqual(code, 200, j)
        opts = j["publicKey"]
        self.assertEqual(opts["authenticatorSelection"]["userVerification"], "required")
        self.assertNotIn(b"pam", base64.urlsafe_b64decode(opts["user"]["id"] + "=="))        # the user handle isn't the username
        code, j = self.api("passkeys/register/finish", {"flow": j["flow"], "name": "Bitwarden", "credential": auth.create(opts)}, tok)
        self.assertEqual(code, 200, j)
        self.assertEqual(self.api("passkeys", None, tok)[1]["passkeys"][0]["name"], "Bitwarden")

        def login(**bad):
            code, j = self.api("auth/passkey/begin", {"purpose": "login"})
            self.assertEqual(code, 200)
            self.assertEqual(j["publicKey"]["allowCredentials"], [])                        # discoverable: no username typed
            return self.call("/chat/api/auth/passkey/finish", {"flow": j["flow"], "purpose": "login", "credential": auth.get(j["publicKey"], **bad)})
        code, j, h = login()
        self.assertEqual((code, j.get("user")), (200, "pam"), j)
        cookie = h["set-cookie"].split("=", 1)[1].split(";")[0]
        st = self.api("auth/status", None, cookie)[1]
        self.assertEqual(st["user"], "pam")
        self.assertGreater(st["reauth_valid_for"], 0)                                        # a passkey is multi-factor on its own
        # the Android app listed in CIPHERCHAT_ANDROID_APPS signs with its own origin; any other app origin is refused
        self.assertEqual(login(origin=ANDROID_ORIGIN)[0], 200)
        self.assertEqual(login(origin="android:apk-key-hash:" + "A" * 43)[0], 401)
        self.assertEqual(login(origin="https://evil.example")[0], 401)
        self.assertEqual(login(uv=False)[0], 401)
        self.assertEqual(login(sig_flip=True)[0], 401)
        self.assertEqual(login(counter=1)[0], 401)                                            # counter went backwards: a clone
        # a passkey also answers "confirm it's you"
        code, j = self.api("auth/passkey/begin", {"purpose": "reauth"}, cookie)
        self.assertEqual(len(j["publicKey"]["allowCredentials"]), 1)
        code, j, _ = self.call("/chat/api/auth/passkey/finish", {"flow": j["flow"], "purpose": "reauth", "credential": auth.get(j["publicKey"])}, cookie)
        self.assertEqual(code, 200, j)
        pid = self.api("passkeys", None, cookie)[1]["passkeys"][0]["id"]
        self.assertEqual(self.api("passkeys/%s/delete" % pid, {}, cookie)[0], 200)
        self.assertEqual(login()[0], 401)

    def test_12_android_app_links(self):
        # Digital Asset Links for the configured app only (malformed entries are dropped)
        code, body, h = self.raw("GET", "/.well-known/assetlinks.json")
        self.assertEqual(code, 200)
        self.assertTrue(h["content-type"].startswith("application/json"))
        self.assertEqual(json.loads(body), [{"relation": ["delegate_permission/common.get_login_creds"],
            "target": {"namespace": "android_app", "package_name": "systems.darkcipher.cipherchat", "sha256_cert_fingerprints": [ANDROID_FP]}}])

    # ------------------------------------------------------------------ calls (calls.py)
    def test_11_call_signals_and_turn(self):
        owner, cid = self.owner(), self.invite("cid")
        self.api("identity", {"bundle": bundle(OWNER)[0], "backup": backup()}, owner)       # (already set by test 5 when run in order)
        cb, cfp = bundle("cid")
        self.assertEqual(self.api("identity", {"bundle": cb, "backup": backup()}, cid)[0], 200)
        ofp = self.api("state", None, owner)[1]["me"]["identity_fp"]
        code, j = self.api("rooms", {"name": "calls", "members": ["cid"], "retention_days": 0}, owner)
        self.assertEqual(code, 200, j)
        rid = j["id"]
        call_id = "C" * 22

        def sig(**over):
            hdr = {"v": 1, "t": "call", "room": rid, "from": OWNER, "from_fp": ofp, "kind": "ring", "call": call_id,
                   "dev": "devAAAA1", "to": ["cid"], "at": int(time.time() * 1000), "media": "video"}
            hdr.update(over)
            raw = json.dumps(hdr, sort_keys=True, separators=(",", ":")).encode()
            return {"room": rid, "to": hdr["to"] if "to_body" not in over else over["to_body"], "sig": {"h": b64(raw), "s": rnd(4627 + 64)}}

        # cid's poll position before the ring
        st = self.call("/chat/api/poll?since=0&rev=-1", None, cid)[1]
        since, rev = st["last_seq"], st["dir_rev"]
        code, j = self.api("calls/signal", sig(), owner)
        self.assertEqual(code, 200, j)
        code, j = self.call("/chat/api/poll?since=%d&rev=%d&sig=0" % (since, rev), None, cid)[:2]
        self.assertEqual(code, 200)
        ring = [s for s in j["signals"] if s["call"] == call_id]
        self.assertEqual([(s["kind"], s["from"], s["room"]) for s in ring], [("ring", OWNER, rid)])
        self.assertIn({"e": "call", "media": "video", "call": call_id, "by": OWNER}, [i["body"] for i in j["items"] if i["kind"] == "event"])
        last = ring[0]["sid"]
        self.assertNotIn("signals", self.call("/chat/api/poll?since=%d&rev=-1" % j["last_seq"], None, cid)[1])   # old clients: none
        # the caller's own other devices see it too; nobody outside the room does
        self.assertTrue(any(s["call"] == call_id for s in self.call("/chat/api/poll?since=%d&rev=-1&sig=0" % 10 ** 9, None, owner)[1].get("signals", [])))
        code, j = self.api("calls/signal", sig(kind="offer"), owner)
        self.assertEqual(code, 200)
        j = self.call("/chat/api/poll?since=%d&rev=-1&sig=%d" % (10 ** 9, last), None, cid)[1]
        self.assertEqual([s["kind"] for s in j["signals"]], ["offer"])                    # only what's newer than the cursor

        refused = {
            "a non-member": sig(to=["max"]),
            "the caller themself": sig(to=[OWNER]),
            "someone else's name": sig(**{"from": "cid"}),
            "a wrong fingerprint": sig(from_fp="0" * 64),
            "a stale clock": sig(at=int(time.time() * 1000) - 600_000),
            "an unknown kind": sig(kind="pwn"),
            "a bad call id": sig(call="x"),
            "recipients that differ from the signed ones": sig(to_body=["cid", "max"]),
            "too many people": sig(to=["u%d" % i for i in range(8)]),
        }
        for why, body in refused.items():
            code, j = self.api("calls/signal", body, owner)
            self.assertIn(code, (400, 403), "%s was accepted: %s" % (why, j))
        bad_sig = sig()
        bad_sig["sig"]["s"] = rnd(10)
        self.assertEqual(self.api("calls/signal", bad_sig, owner)[0], 400)
        self.assertEqual(self.api("calls/signal", sig(), None)[0], 403)                      # signed in only

        # TURN: coturn's shared-secret credentials, valid URLs only, no account names in them
        code, j = self.api("calls/turn", None, cid)
        self.assertEqual(code, 200, j)
        ice = j["ice_servers"][-1]
        self.assertEqual(ice["urls"], ["turns:turn.example.net:5349?transport=tcp", "turn:turn.example.net:3478?transport=udp"])
        expiry, who = ice["username"].split(":")
        self.assertGreater(int(expiry), time.time() + 3600)
        self.assertNotIn("cid", ice["username"])
        expect = base64.b64encode(hmac.new(b"test-turn-secret-0123456789", ice["username"].encode(), hashlib.sha1).digest()).decode()
        self.assertEqual(ice["credential"], expect)
        self.assertEqual(self.api("calls/turn", None, None)[0], 403)


    def test_14_production_cookie_obeys_browser_prefix_rules(self):
        # The test server runs in DEV with a plain cookie name, so check the PRODUCTION cookie the way a browser would:
        # __Host- needs Secure, Path=/ and no Domain; __Secure- needs Secure. A cookie that breaks these is silently
        # dropped and sign-in loops (that happened once: __Host- with Path=/chat/).
        code = ("import sys; sys.path.insert(0, %r); import server as s; "
                "print(s.cookie_for('T', 12)); print(s.EXPIRE_COOKIE)" % os.path.dirname(SERVER))
        env = dict(self.env, CIPHERCHAT_DEV="0", CIPHERCHAT_ORIGIN="https://chat.example.com")
        out = subprocess.run([sys.executable, "-I", "-c", code], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        for line in out.stdout.strip().splitlines():
            name = line.split("=", 1)[0]
            attrs = [a.strip() for a in line.split(";")[1:]]
            self.assertIn("Secure", attrs, line)
            self.assertIn("HttpOnly", attrs, line)
            self.assertIn("SameSite=Strict", attrs, line)
            self.assertFalse(any(a.lower().startswith("domain=") for a in attrs), line)
            path = next(a for a in attrs if a.startswith("Path="))
            if name.startswith("__Host-"):
                self.assertEqual(path, "Path=/", line)
            self.assertTrue(name.startswith(("__Host-", "__Secure-")), line)

    def test_15_signed_out_visitors_go_straight_to_sign_in(self):
        for page in ("/chat/", "/chat/index.html", "/chat/account/", "/chat/admin/"):
            code, _, h = self.raw("GET", page)
            self.assertEqual((code, h.get("location")), (302, "/chat/login/?next=" + urllib.parse.quote(page, safe="")), page)
        self.assertEqual(self.raw("GET", "/chat/login/")[0], 200)
        code, body, _ = self.raw("GET", "/chat/", headers={"Cookie": "cipherchat_dev=" + self.owner()})
        self.assertEqual(code, 200)
        self.assertIn(b'id="term"', body)

    # ------------------------------------------------------------------ settings, email, roles, permissions
    def db_bytes(self):
        """The raw database files (what a stolen copy would hold)."""
        out = b""
        for f in os.listdir(os.path.join(self.tmp, "state")):
            if f.startswith("cipherchat.db"):
                with open(os.path.join(self.tmp, "state", f), "rb") as fh:
                    out += fh.read()
        return out

    def test_16_sealbox(self):
        code = ("import sys; sys.path.insert(0, %r); import storage, sealbox; storage.load(%r); "
                "s = sealbox.seal('top secret smtp', 'smtp-password'); assert 'top secret' not in s; "
                "assert sealbox.open_text(s, 'smtp-password') == 'top secret smtp'; "
                "bad = [s[:-2] + ('AA' if s[-2:] != 'AA' else 'BB'), s.replace('.', '.x', 1)]; "
                "import itertools\n"
                "for b in bad:\n"
                "    try: sealbox.open_(b, 'smtp-password'); raise SystemExit('tamper accepted')\n"
                "    except sealbox.SealError: pass\n"
                "try: sealbox.open_(s, 'mail-queue'); raise SystemExit('moved value accepted')\n"
                "except sealbox.SealError: pass\n"
                "assert sealbox.seal('x', 'p') != sealbox.seal('x', 'p'); print('ok')") % (os.path.dirname(SERVER), self.env["CIPHERCHAT_KEY_FILE"])
        out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60)
        self.assertEqual((out.returncode, out.stdout.strip()), (0, "ok"), out.stderr)

    def test_17_settings_email_and_notifications(self):
        owner, adm, mem = self.owner(), self.invite("setadm", role="admin"), self.invite("setmem")
        # members see nothing; the built-in admin role may change settings and email
        for path in ("admin/settings", "admin/roles"):
            self.assertEqual(self.api(path, None, mem)[0], 403)
        self.assertEqual(self.api("admin/settings", {"invite_hours": 24}, mem)[0], 403)
        code, j = self.api("admin/settings", None, adm)
        self.assertEqual(code, 200, j)
        self.assertEqual(j["settings"]["lockout_attempts"], 5)
        for bad in ({"invite_hours": 0}, {"invite_hours": "24"}, {"nope": 1}, {"password_min": 6}, {"access_requests": "no"},
                    {"request_role": "owner"}, {"request_role": "admin"}, {"name": "x\ny"}):
            self.assertIn(self.api("admin/settings", bad, adm)[0], (400, 403), bad)
        code, j = self.api("admin/settings", {"invite_hours": 48, "name": "Test Chat Two"}, adm)
        self.assertEqual(code, 200, j)
        self.assertEqual(self.api("auth/status")[1]["name"], "Test Chat Two")
        self.api("admin/settings", {"name": ""}, adm)
        # access requests can be switched off
        self.assertEqual(self.api("admin/settings", {"access_requests": False}, adm)[0], 200)
        body = {"name": "Off Test", "email": "off@example.com", "message": "please let me in, thanks", "agree": True, "website": "", "elapsed": 9000}
        self.assertEqual(self.raw("POST", "/chat/api/request", body, {"X-Real-IP": "203.0.113.70"})[0], 403)
        self.assertEqual(self.api("admin/settings", {"access_requests": True}, adm)[0], 200)
        # email: validated, the password sealed and never shown, plain SMTP impossible
        for bad in ({"host": "127.0.0.1", "port": 25, "security": "starttls", "from": "c@example.com"},
                    {"host": "smtp.example.com", "port": 25, "security": "none", "from": "c@example.com"},
                    {"host": "smtp.example.com", "port": 70000, "security": "tls", "from": "c@example.com"},
                    {"host": "smtp.example.com", "port": 587, "security": "starttls", "from": "not-an-address"},
                    {"host": "smtp.example.com", "port": 587, "security": "starttls", "from": "c@example.com", "password": "a\nb"}):
            self.assertEqual(self.api("admin/mail", bad, adm)[0], 400, bad)
        secret = "SmtpPw-" + secrets.token_hex(8)
        cfg = {"host": "smtp.cipherchat.invalid", "port": 587, "security": "starttls", "user": "chat@example.com",
               "password": secret, "from": "chat@example.com", "from_name": "Test Chat"}
        code, j = self.api("admin/mail", cfg, adm)
        self.assertEqual(code, 200, j)
        code, j = self.api("admin/settings", None, adm)
        self.assertTrue(j["mail"]["has_password"])
        self.assertNotIn(secret, json.dumps(j))
        self.assertNotIn(secret.encode(), self.db_bytes())                        # sealed at rest, never in the audit log
        # a test email and a notification are queued sealed, then tried (the host doesn't exist, so: retrying)
        self.assertEqual(self.api("admin/mail/test", {"to": "probe-" + secret + "@example.com"}, adm)[0], 200)
        self.assertEqual(self.api("admin/mail/test", {}, adm)[0], 429)                  # one per 20 s
        for _ in range(60):
            log = self.api("admin/settings", None, adm)[1]["log"]
            if log:
                break
            time.sleep(0.25)
        self.assertTrue(log and log[0]["kind"] == "test" and log[0]["outcome"] in ("retrying", "failed"), log)
        self.assertNotIn(("probe-" + secret).encode(), self.db_bytes())
        self.assertIn("***@example.com", log[0]["to_masked"])
        # notifications: validated, saved
        self.assertEqual(self.api("admin/notify", {"bogus": {"enabled": True}}, adm)[0], 400)
        self.assertEqual(self.api("admin/notify", {"access_request": {"extra": ["x"]}}, adm)[0], 400)
        code, j = self.api("admin/notify", {"device_paired": {"enabled": False}, "access_request": {"extra": ["Ops@Example.com"]}}, adm)
        self.assertEqual((code, j["notify"]["device_paired"]["enabled"], j["notify"]["access_request"]["extra"]), (200, False, ["ops@example.com"]))
        self.assertEqual(self.api("admin/mail", {"host": ""}, adm)[0], 200)            # switched off again
        events = [e["action"] for e in self.api("admin/audit", None, owner)[1]["events"]]
        for a in ("settings.update", "mail.settings", "mail.test", "mail.notifications"):
            self.assertIn(a, events)

    def test_18_granular_permissions_and_escalation(self):
        owner, adm, adm2 = self.owner(), self.invite("permadm", role="admin"), self.invite("permadm2", role="admin")
        mem = self.invite("permmem")
        # the built-in admin can't manage roles, can't make admins, can't touch an equal
        self.assertEqual(self.api("admin/roles", {"name": "mod", "perms": []}, adm)[0], 403)
        self.assertEqual(self.api("admin/users/invite", {"username": "permx", "role": "admin"}, adm)[0], 403)
        self.assertEqual(self.api("admin/users/permadm2/suspend", {}, adm)[0], 403)
        self.assertEqual(self.api("admin/users/permadm2/role", {"role": "guest"}, adm)[0], 403)
        # ...but can give a member something it holds, as long as the member stays below
        code, j = self.api("admin/users/permmem/permissions", {"grants": ["admin.audit.view"], "denies": []}, adm)
        self.assertEqual(code, 200, j)
        self.assertEqual(self.api("admin/audit", None, mem)[0], 200)
        self.assertEqual(self.api("admin/users/permmem/permissions", {"grants": ["admin.roles.manage"], "denies": []}, adm)[0], 403)   # not held
        allp = [p for p in self.api("admin/roles", None, owner)[1]["mine"] if p != "admin.roles.manage"]
        self.assertEqual(self.api("admin/users/permmem/permissions", {"grants": allp, "denies": []}, adm)[0], 403)   # equal: refused
        self.assertEqual(self.api("admin/users/permmem/permissions", {"grants": ["nope.perm"], "denies": []}, adm)[0], 400)
        self.assertEqual(self.api("admin/users/%s/role" % OWNER, {"role": "guest"}, adm)[0], 403)
        # the owner makes a custom role with roles.manage; its holder can only build roles below themself
        code, j = self.api("admin/roles", {"name": "rolesmith", "label": "Role smith",
                                           "perms": ["chat.access.use", "admin.users.view", "admin.roles.manage", "admin.users.roles"]}, owner)
        self.assertEqual(code, 200, j)
        for bad in ({"name": "owner", "perms": []}, {"name": "addon", "perms": []}, {"name": "Bad Name", "perms": []},
                    {"name": "x2", "perms": ["made.up"]}):
            self.assertEqual(self.api("admin/roles", bad, owner)[0], 400, bad)
        self.assertEqual(self.api("admin/roles", {"name": "rolesmith", "perms": []}, owner)[0], 409)
        smith = self.invite("smith", role="rolesmith")
        self.assertEqual(self.api("admin/roles", {"name": "lesser", "perms": ["chat.access.use"]}, smith)[0], 200)
        self.assertEqual(self.api("admin/roles", {"name": "greater", "perms": ["admin.settings.manage"]}, smith)[0], 403)
        self.assertEqual(self.api("admin/roles/admin", {"perms": ["chat.access.use"]}, smith)[0], 403)        # more powerful role
        self.assertEqual(self.api("admin/roles/lesser", {"perms": ["chat.access.use", "chat.rooms.create"]}, smith)[0], 403)
        self.assertEqual(self.api("admin/roles/member/delete", {}, owner)[0], 400)                           # built-in
        self.assertEqual(self.api("admin/roles/rolesmith/delete", {}, owner)[0], 409)                        # in use
        self.assertEqual(self.api("admin/roles/lesser/delete", {}, owner)[0], 200)
        # denies take effect at once, on every chat route they cover
        self.assertEqual(self.api("admin/users/permmem/permissions",
                                  {"grants": [], "denies": ["chat.rooms.create", "chat.dm.start", "chat.files.send", "chat.devices.pair"]}, owner)[0], 200)
        self.assertEqual(self.api("identity", {"bundle": bundle("permmem")[0], "backup": backup()}, mem)[0], 200)
        self.assertEqual(self.api("rooms", {"name": "nope", "members": []}, mem)[0], 403)
        self.assertEqual(self.api("dm", {"user": OWNER}, mem)[0], 403)
        self.assertEqual(self.api("devices", {"name": "x"}, mem)[0], 403)
        st = self.api("state", None, mem)[1]
        self.assertFalse(st["me"]["can_create"])
        self.assertNotIn("chat.rooms.create", self.api("auth/status", None, mem)[1]["permissions"])
        # role changes are audited; listing shows the effective permissions
        users = {u["username"]: u for u in self.api("admin/users", None, owner)[1]["users"]}
        self.assertNotIn("chat.rooms.create", users["permmem"]["permissions"])
        self.assertTrue(users["permmem"]["manageable"])
        self.assertFalse({u["username"]: u for u in self.api("admin/users", None, adm)[1]["users"]}["permadm2"]["manageable"])
        events = [e["action"] for e in self.api("admin/audit", None, owner)[1]["events"]]
        for a in ("role.create", "role.delete", "user.permissions", "authz.denied"):
            self.assertIn(a, events)

    def test_19_lockout_follows_the_settings(self):
        owner = self.owner()
        self.invite("lockme")
        self.assertEqual(self.api("admin/settings", {"lockout_attempts": 3, "lockout_minutes": 2}, owner)[0], 200)
        try:
            for i in range(3):
                self.call("/chat/api/auth/login", {"username": "lockme", "password": "wrong password number %d" % i, "code": "000000"})
            time.sleep(3.2)                                                            # settings are cached for 3 s
            code, j, _ = self.call("/chat/api/auth/login", {"username": "lockme", "password": PW, "code": totp(self.secrets["lockme"])})
            self.assertEqual(code, 401)
            self.assertIn("locked", j["error"])
        finally:
            self.api("admin/settings", {"lockout_attempts": 5, "lockout_minutes": 15}, owner)

    def test_20_no_client_addresses_are_stored(self):
        owner = self.owner()
        ip = "203.0.113.199"
        for _ in range(2):                                                         # audited failures from one address
            self.call("/chat/api/auth/login", {"username": OWNER, "password": "wrong password here 9", "code": "000000"}, headers={"X-Real-IP": ip})
        events = self.api("admin/audit", None, owner)[1]["events"]
        mine = [e for e in events if e["action"] == "auth.signin" and e["outcome"] == "failed"][:2]
        self.assertEqual(len({e["ip"] for e in mine}), 1)                          # the same source still shows as one tag...
        self.assertTrue(mine[0]["ip"].startswith("net-") and len(mine[0]["ip"]) == 14, mine[0])
        self.assertNotIn(ip, json.dumps(events))                                   # ...but never as an address
        time.sleep(1.5)                                                            # WAL checkpoint isn't needed: raw files are read
        self.assertNotIn(ip.encode(), self.db_bytes())
        self.assertNotIn(b"198.51.100.", self.db_bytes())                          # add-on tests use this range
        # an old database with addresses in it is cleaned once, and the audit chain still links up
        tmp = tempfile.mkdtemp(prefix="cipherchat-scrub-")
        try:
            code = ("import os, sys, json, hashlib; sys.path.insert(0, %r); os.environ['CIPHERCHAT_STATE_DIR'] = %r\n"
                    "import server as s, authz\n"
                    "s.init_db(); s.bind_modules()\n"
                    "with authz.tx(s.db) as c:\n"
                    "    authz.audit(c, 'x', 'a.one', ctx={'ip': '192.0.2.44'}); authz.audit(c, 'x', 'a.two', ctx={'ip': '2001:db8::7'})\n"
                    "s.init_db()\n"
                    "with s.db() as c:\n"
                    "    rows = c.execute('SELECT * FROM audit_log ORDER BY seq').fetchall()\n"
                    "prev = '0' * 64\n"
                    "for r in rows:\n"
                    "    ev = {k: r[k] for k in ('id','at','actor','action','target_type','target_id','outcome','detail','request_id','ip','ua')}\n"
                    "    assert r['prev_hash'] == prev, 'chain broken'\n"
                    "    ev['prev_hash'] = prev\n"
                    "    assert hashlib.sha256(json.dumps(ev, sort_keys=True, separators=(',', ':')).encode()).hexdigest() == r['hash'], 'hash'\n"
                    "    prev = r['hash']\n"
                    "assert [r['ip'] for r in rows[:2]] == ['net-removed', 'net-removed'], [r['ip'] for r in rows]\n"
                    "assert rows[-1]['action'] == 'audit.addresses_removed'\n"
                    "print('ok')") % (os.path.dirname(SERVER), os.path.join(tmp, "state"))
            env = dict(self.env, CIPHERCHAT_KEY_FILE=os.path.join(tmp, "k", "server.key"))
            out = subprocess.run([sys.executable, "-I", "-c", code], env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual((out.returncode, out.stdout.strip()[-2:]), (0, "ok"), out.stderr[-800:])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_21_a_deleted_name_can_be_invited_again(self):
        owner = self.owner()
        old = self.invite("rita")
        self.assertEqual(self.api("admin/users/rita/delete", {}, owner)[0], 200)
        self.assertEqual(self.api("state", None, old)[0], 403)                     # the old session is gone
        code, j = self.api("admin/users/invite", {"username": "rita", "role": "member"}, owner)
        self.assertEqual(code, 201, j)                                              # the name is free again...
        self.enrol(j["link"]["url"], "rita")
        new = self.login("rita")
        code, st = self.api("state", None, new)
        self.assertEqual(code, 200, st)
        users = {u["username"]: u for u in self.api("admin/users", None, owner)[1]["users"]}
        self.assertEqual(users["rita"]["status"], "active")                         # ...as a fresh account
        self.assertEqual(self.api("admin/users/invite", {"username": "rita", "role": "member"}, owner)[0], 409)   # a live name stays taken
        time.sleep(1.5)                                                             # the reuse is audited
        self.assertIn(b"reused_deleted_name", self.db_bytes())

    # ------------------------------------------------------------------ add-ons (addons.py)
    def addon_call(self, user, key, method, target, body=None, ts=None, nonce=None, sign_hash=None, headers=None, ip=None):
        raw = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        ts = str(int(time.time()) if ts is None else ts)
        nonce = nonce or base64.urlsafe_b64encode(secrets.token_bytes(24)).decode().rstrip("=")
        bh = hashlib.sha3_256(raw if sign_hash is None else sign_hash).hexdigest()
        msg = "\n".join(["CIPHERCHAT-ADDON-V1", self.origin, method, target, user, ts, nonce, bh]).encode()
        h = {"X-CipherChat-Addon": user, "X-CipherChat-Time": ts, "X-CipherChat-Nonce": nonce,
             "X-CipherChat-Content-SHA3": bh, "X-CipherChat-Signature": hmac.new(key, msg, hashlib.sha3_256).hexdigest(),
             "X-Real-IP": ip or "198.51.100.%d" % (secrets.randbelow(250) + 1)}
        if raw and not target.startswith("/chat/api/upload/"):
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        code, payload, _ = self.raw(method, target, raw if method == "POST" else None, h)
        try:
            j = json.loads(payload or b"{}")
        except ValueError:
            j = {}
        return code, j, (method, target, raw, ts, nonce, h)

    @staticmethod
    def decode_code(code):
        assert code.startswith("ccaddon1.")
        blob = json.loads(base64.urlsafe_b64decode(code[9:] + "=" * (-len(code[9:]) % 4)))
        return blob["u"], base64.urlsafe_b64decode(blob["k"] + "=" * (-len(blob["k"]) % 4)), blob["o"]

    def test_13_addons(self):
        owner, ann = self.owner(), self.invite("ann")
        # only the owner manages add-ons
        self.assertEqual(self.api("addons", {"name": "cc"}, ann)[0], 403)
        self.assertEqual(self.api("addons", None, ann)[0], 403)
        for bad in ({"name": "-x"}, {"name": "UPPER"}, {"name": "a" * 27}, {"name": "ok", "scopes": ["admin"]},
                    {"name": "ok", "ip_allow": ["not-an-ip"]}, {"name": "ok", "rate": 5}, {"name": "ok", "days": 9999}):
            self.assertEqual(self.api("addons", bad, owner)[0], 400, bad)
        code, j = self.api("addons", {"name": "commandcentre", "display_name": "CommandCentre", "scopes": ["send", "files"],
                                      "description": "fleet status"}, owner)
        self.assertEqual(code, 200, j)
        user, key, origin = self.decode_code(j["code"])
        self.assertEqual((user, origin, len(key)), ("addon.commandcentre", self.origin, 32))
        self.assertEqual(self.api("addons", {"name": "commandcentre"}, owner)[0], 409)
        lst = self.api("addons", None, owner)[1]["addons"]
        self.assertEqual([(a["user"], a["scopes"], a["enabled"]) for a in lst], [(user, ["files", "send"], True)])
        self.assertNotIn("code", json.dumps(lst))                                  # never shown again

        # signed requests work; the directory says it's an add-on
        code, st, _ = self.addon_call(user, key, "GET", "/chat/api/state")
        self.assertEqual(code, 200, st)
        self.assertEqual(st["me"]["user"], user)
        self.assertTrue({d["user"]: d for d in st["directory"]}[user]["addon"])
        self.assertFalse({d["user"]: d for d in st["directory"]}["ann"]["addon"])

        # its identity: once, no server-side backup, never a reset
        ab, afp = bundle(user)
        code, j, _ = self.addon_call(user, key, "POST", "/chat/api/identity", {"bundle": ab})
        self.assertEqual((code, j.get("fp")), (200, afp), j)
        code, j, _ = self.addon_call(user, key, "POST", "/chat/api/identity", {"bundle": bundle(user)[0], "confirm_reset": True})
        self.assertEqual(code, 403, j)
        self.assertEqual(self.addon_call(user, key, "POST", "/chat/api/backup/fetch", {})[0], 403)
        self.assertEqual(self.addon_call(user, key, "GET", "/chat/api/pepper")[0], 403)

        # forged, replayed, altered, late, early, mixed with a cookie, wrong origin: all refused
        _, _, (m, t, raw, ts, nonce, h) = self.addon_call(user, key, "GET", "/chat/api/state")
        self.assertEqual(self.raw(m, t, None, h)[0], 401)                                   # replay of a used nonce
        self.assertEqual(self.addon_call(user, b"\x00" * 32, "GET", "/chat/api/state")[0], 401)
        self.assertEqual(self.addon_call("addon.nobody", key, "GET", "/chat/api/state")[0], 401)
        self.assertEqual(self.addon_call("ann", key, "GET", "/chat/api/state")[0], 401)      # people never sign like add-ons
        code, j, _ = self.addon_call(user, key, "GET", "/chat/api/state", ts=int(time.time()) - 600)
        self.assertEqual(code, 401)
        self.assertIn("server_time", j)
        self.assertEqual(self.addon_call(user, key, "GET", "/chat/api/state", ts=int(time.time()) + 600)[0], 401)
        self.assertEqual(self.addon_call(user, key, "POST", "/chat/api/identity", {"bundle": ab}, sign_hash=b"other")[0], 401)
        self.assertEqual(self.addon_call(user, key, "GET", "/chat/api/state", headers={"Cookie": "cipherchat_dev=" + owner})[0], 400)
        self.assertEqual(self.addon_call(user, key, "GET", "/chat/api/state", nonce="short")[0], 401)
        _, _, (m, t, raw, ts, nonce, h) = self.addon_call(user, key, "GET", "/chat/api/poll?since=0")
        h2 = dict(h, **{"X-CipherChat-Nonce": base64.urlsafe_b64encode(secrets.token_bytes(24)).decode().rstrip("=")})
        self.assertEqual(self.raw(m, "/chat/api/poll?since=1", None, h2)[0], 401)              # query is signed too

        # least privilege: none of the people's routes
        for method, target, body in (("POST", "/chat/api/rooms", {"name": "x", "members": []}), ("GET", "/chat/api/admin/users", None),
                                     ("POST", "/chat/api/devices", {"name": "x"}), ("POST", "/chat/api/certify", {}),
                                     ("POST", "/chat/api/auth/login", {}), ("GET", "/chat/api/addons", None),
                                     ("POST", "/chat/api/addons", {"name": "evil"}), ("POST", "/chat/api/calls/signal", {}),
                                     ("GET", "/chat/api/calls/turn", None), ("POST", "/chat/api/dm", {"user": "ann"})):
            code, j, _ = self.addon_call(user, key, method, target, body)
            self.assertEqual(code, 403, (target, j))

        # people's account tools can't touch it, and it can't sign in as a person
        self.assertEqual(self.api("admin/users/%s/reset_password" % user, {}, owner)[0], 403)
        self.assertEqual(self.api("admin/users/invite", {"username": "addon.fake", "role": "member"}, owner)[0], 400)
        self.assertNotIn(user, [u["username"] for u in self.api("admin/users", None, owner)[1]["users"]])
        self.assertEqual(self.call("/chat/api/auth/login", {"username": user, "password": "!addon", "code": "000000"})[0], 401)

        # in a room the owner made, it can send (the message itself is checked as usual) and upload what it signed
        self.api("identity", {"bundle": bundle(OWNER)[0], "backup": backup()}, owner)
        code, j = self.api("rooms", {"name": "ops", "members": [user], "retention_days": 0}, owner)
        self.assertEqual(code, 200, j)
        rid = j["id"]
        code, j, _ = self.addon_call(user, key, "POST", "/chat/api/rooms/%s/send" % rid, {"msg": {"h": "x"}})
        self.assertEqual(code, 400, j)                                                       # reached the route; malformed
        blob = secrets.token_bytes(65536 + 16)
        code, j, _ = self.addon_call(user, key, "POST", "/chat/api/upload/%s" % rid, blob, sign_hash=b"something else")
        self.assertEqual(code, 401, j)
        code, j, _ = self.addon_call(user, key, "POST", "/chat/api/upload/%s" % rid, blob)
        self.assertEqual((code, j.get("sha3")), (200, hashlib.sha3_256(blob).hexdigest()), j)
        # an add-on is never a room admin, and never inherits a room
        self.assertEqual(self.api("rooms/%s/members" % rid, {"admin": [user]}, owner)[0], 400)

        # scopes, IP allowlist, disable, rotate, delete (each with the owner's fresh code)
        self.assertEqual(self.api("addons/%s/update" % user, {"scopes": []}, owner)[0], 200)
        self.assertEqual(self.addon_call(user, key, "POST", "/chat/api/rooms/%s/send" % rid, {"msg": {}})[0], 403)
        self.assertEqual(self.api("addons/%s/update" % user, {"scopes": ["send"], "ip_allow": ["192.0.2.0/24"]}, owner)[0], 200)
        self.assertEqual(self.addon_call(user, key, "GET", "/chat/api/state", ip="198.51.100.9")[0], 403)
        self.assertEqual(self.addon_call(user, key, "GET", "/chat/api/state", ip="192.0.2.77")[0], 200)
        self.assertEqual(self.api("addons/%s/update" % user, {"ip_allow": []}, owner)[0], 200)
        self.assertEqual(self.api("addons/%s/disable" % user, {}, owner)[0], 200)
        self.assertEqual(self.addon_call(user, key, "GET", "/chat/api/state")[0], 401)
        self.assertEqual(self.api("addons/%s/enable" % user, {}, owner)[0], 200)
        code, j = self.api("addons/%s/rotate" % user, {}, owner)
        self.assertEqual(code, 200, j)
        _, key2, _ = self.decode_code(j["code"])
        self.assertEqual(self.addon_call(user, key, "GET", "/chat/api/state")[0], 401)       # the old key is dead
        self.assertEqual(self.addon_call(user, key2, "GET", "/chat/api/state")[0], 200)
        self.assertEqual(self.api("addons/%s/delete" % user, {}, owner)[0], 200)
        self.assertEqual(self.addon_call(user, key2, "GET", "/chat/api/state")[0], 401)
        self.assertNotIn(user, [m["user"] for r in self.api("state", None, owner)[1]["rooms"] for m in r["members"]])
        events = [e["action"] for e in self.api("admin/audit", None, owner)[1]["events"]]
        for a in ("addon.create", "addon.update", "addon.rotate", "addon.disable", "addon.delete", "addon.request_refused"):
            self.assertIn(a, events)


class SoftAuthenticator:
    """A minimal software passkey (Ed25519, discoverable, user-verifying) for the tests, built on the server's own curve
    code. Never used outside tests."""
    def __init__(self, wv, rp_id, origin):
        self.wv, self.rp_id, self.origin = wv, rp_id, origin
        self.seed = secrets.token_bytes(32)
        h = hashlib.sha512(self.seed).digest()
        self.a = int.from_bytes(h[:32], "little") & ((1 << 254) - 8) | (1 << 254)
        self.prefix = h[32:]
        self.pub = wv._encode_point(wv._edmul(self.a, wv._EBASE))
        self.cred_id = secrets.token_bytes(32)
        self.count = 0
        self.handle = None

    def sign(self, msg):
        wv = self.wv
        r = int.from_bytes(hashlib.sha512(self.prefix + msg).digest(), "little") % wv._l
        R = wv._encode_point(wv._edmul(r, wv._EBASE))
        k = int.from_bytes(hashlib.sha512(R + self.pub + msg).digest(), "little") % wv._l
        return R + ((r + k * self.a) % wv._l).to_bytes(32, "little")

    @staticmethod
    def u(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    @staticmethod
    def cbor(v):
        def head(major, n):
            if n < 24:
                return bytes([major << 5 | n])
            for info, size in ((24, 1), (25, 2), (26, 4)):
                if n < 1 << (8 * size):
                    return bytes([major << 5 | info]) + n.to_bytes(size, "big")
        if isinstance(v, int):
            return head(0, v) if v >= 0 else head(1, -1 - v)
        if isinstance(v, bytes):
            return head(2, len(v)) + v
        if isinstance(v, str):
            return head(3, len(v.encode())) + v.encode()
        if isinstance(v, dict):
            return head(5, len(v)) + b"".join(SoftAuthenticator.cbor(k) + SoftAuthenticator.cbor(x) for k, x in v.items())
        raise TypeError

    def client_data(self, kind, challenge, origin=None):
        return json.dumps({"type": kind, "challenge": challenge, "origin": origin or self.origin, "crossOrigin": False}).encode()

    def create(self, opts):
        self.handle = opts["user"]["id"]
        cd = self.client_data("webauthn.create", opts["challenge"])
        key = self.cbor({1: 1, 3: -8, -1: 6, -2: self.pub})
        ad = hashlib.sha256(self.rp_id.encode()).digest() + bytes([0x45]) + (0).to_bytes(4, "big") + bytes(16) + \
            len(self.cred_id).to_bytes(2, "big") + self.cred_id + key
        att = self.cbor({"fmt": "none", "attStmt": {}, "authData": ad})
        return {"id": self.u(self.cred_id), "rawId": self.u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": self.u(cd), "attestationObject": self.u(att)}}

    def get(self, opts, origin=None, uv=True, sig_flip=False, counter=None):
        if counter is None:
            self.count += 1
        cd = self.client_data("webauthn.get", opts["challenge"], origin)
        ad = hashlib.sha256(self.rp_id.encode()).digest() + bytes([0x05 if uv else 0x01]) + (counter or self.count).to_bytes(4, "big")
        sig = self.sign(ad + hashlib.sha256(cd).digest())
        if sig_flip:
            sig = sig[:-1] + bytes([sig[-1] ^ 1])
        return {"id": self.u(self.cred_id), "rawId": self.u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": self.u(cd), "authenticatorData": self.u(ad), "signature": self.u(sig), "userHandle": self.handle}}


if __name__ == "__main__":
    unittest.main(verbosity=1)
