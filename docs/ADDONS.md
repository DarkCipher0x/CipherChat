# CipherChat add-ons

Add-ons are programs, such as bots and integrations with your other systems, that take part in CipherChat with an
identity of their own. They're built on the .NET SDK below, or on the signed-request protocol from any language.

Add-ons don't weaken anything about the chat. The rest of this page is how.

## How it's secured

| Layer | What protects it |
|---|---|
| Content | Unchanged end-to-end encryption. An add-on is a chat member with its own hybrid post-quantum identity (ML-DSA-87 + Ed25519 signatures, ML-KEM-1024 + X25519 key wrapping), made **on the add-on's machine**. The server never gets plaintext or private keys, so an add-on can't be used to read the chat through the server either. |
| Trust | The owner certifies the add-on after comparing its 60-digit safety number, exactly like a person. Until then nobody's client wraps a room key for it. The add-on pins the owner from its add-on code, which the **owner's own client** stamps with the owner's fingerprint — it never has to believe the server about who the owner is. |
| Visibility | Add-on accounts are always named `addon.<name>` (people can't take such names) and every client shows an **add-on** tag. |
| Requests | No bearer tokens, no cookies. Every request is signed: HMAC-SHA3-256 over the method, path and query, server origin, add-on, time, a one-time 192-bit nonce and the SHA3-256 of the body, with a 256-bit key. A captured request can't be replayed (nonce + 90 s window) or changed (body, query, method, target all signed); uploads are checked against the signed hash as they stream. 256-bit symmetric keys and SHA-3 keep their strength against quantum computers; the connection itself is TLS 1.3 with X25519MLKEM768 only. |
| Key storage | **Server:** the add-on's key isn't stored at all — it's derived (HMAC-SHA3-256) from the server key file, which never goes in the database or its backups; the database holds only a salt and a version, so a stolen database is useless. **Add-on machine:** the add-on code and the identity's master secret are sealed together with DPAPI for the Windows account that runs it. |
| Least privilege | Add-ons reach only: directory/state, polling, history and room keys **of rooms they were added to**, sending (`send` scope), attachments (`files`), starting direct messages (`dm`), leaving. Never accounts, devices, backups, certificates, room settings, room-key rotation or calls. An add-on can't be a room admin or inherit a room, can't replace its identity, and can't sign in as a person (no password, authenticator or passkey). |
| Control | Only the owner creates, edits, re-keys, disables or removes add-ons, each after confirming with their authenticator code. Optional IP allowlist, expiry (1–730 days) and per-add-on rate limit. Disable stops it at once; a new key kills the old one at once; removing it takes it out of every room (the rooms get new keys without it). |
| Audit | Every management step and every refused add-on request (bad signature, replay, clock, IP, route, scope) goes to the tamper-evident audit log (`/admin/audit`). |

Tests: `server/tests/test_server.py` (test_13: forgery, replay, tampered body and query, clock skew, cookie mixing,
route isolation, scopes, IP allowlist, disable, rotate, delete, audit), `server/tests/pentest_server.py` (pt_19:
IDOR, cross-add-on and person-name swaps, header injection, oversized and mismatched bodies, privilege escalation),
`windows/tests/CipherChat.Addons.Tests` (HMAC-SHA3 test vector shared with Python, add-on code parsing).

## Owner: add an add-on

1. In the web chat type `/addons` → **New add-on**. Give it a name (it becomes `addon.<name>`), what it may do
   (`send` is enough for an add-on that answers questions), optionally the addresses it may connect from and how long
   it's valid. Confirm with your authenticator code.
2. Copy the **add-on code** (shown once). It's the add-on's key: give it only to the add-on's setup, never to a
   chat or an email. Lost it? `/addons` → **new key** (the old one stops working at once).
3. Set the add-on up (below). It makes its keys and prints its safety number.
4. `/verify addon.<name>` → compare the safety number with the one the add-on printed → **Certify**.
5. Add it to the rooms it should serve (`/invite addon.<name>` in the room, or name it when you create the room). Room
   keys are renewed automatically to include it.

## Writing your own add-on (.NET)

`CipherChat.Addons` (windows/src) is the SDK: `ConnectorCode`, `RequestSigner`, `KeyStore` and `AddonHost`, which runs
the full chat engine as the add-on and raises `MessageReceived` only for live messages from verified people (never from
other add-ons):

```csharp
var (codeText, master) = KeyStore.Load("mybot");
var host = new AddonHost(ConnectorCode.Parse(codeText));
host.MessageReceived += m => m.Text == "!ping" ? host.ReplyAsync(m, "pong") : Task.CompletedTask;
await host.StartAsync(master);          // wipes the master once the keys are derived
```

## The signed-request protocol (for other languages)

Headers on every request (no cookies, no `Authorization`):

```
X-CipherChat-Addon:        addon.<name>
X-CipherChat-Time:         unix seconds (within 90 s of the server; a refusal carries server_time)
X-CipherChat-Nonce:        22-64 base64url characters, never reused
X-CipherChat-Content-SHA3: hex SHA3-256 of the exact body bytes (of "" for GET)
X-CipherChat-Signature:    hex HMAC-SHA3-256(key, canonical)

canonical = "CIPHERCHAT-ADDON-V1\n" + origin + "\n" + METHOD + "\n" + path?query + "\n" + addon + "\n"
            + time + "\n" + nonce + "\n" + body_sha3
```

The key is the 32 bytes in the add-on code (`ccaddon1.` + base64url JSON `{o, u, k, a}`; `a` is the owner's identity
fingerprint to pin). The routes are the chat's own (`/chat/api/state`, `poll`, `rooms/<id>/items|epochs|send|burn|leave`,
`upload/<room>`, `blob/<room>/<id>`, `dm`, and `identity` once with `{bundle}` only); messages and room keys follow
docs/PROTOCOL.md exactly.
