# The CipherChat protocol, version 1

CipherChat by DarkCipher Systems. This is the wire and cryptographic format every client implements identically: the
web portal (`web/app/crypto.js`, `callcrypto.js`), Windows (`windows/src/CipherChat.Crypto`) and Android
(`android/core/crypto`). Interop is proven with shared fixtures (INTEROP.md); a new client (Mac/iOS) must pass them.
Domain-separation labels start `dcx-chat/v1/` (the protocol began in the DarkCipher portal's chat and is unchanged).

## 1. Principles

* **Hybrid everywhere.** Every step stays secure while either the post-quantum or the classical half holds.
  Key encapsulation ML-KEM-1024 (FIPS 203) + X25519; signatures ML-DSA-87 (FIPS 204, hedged, context = the label) +
  Ed25519, valid only if **both** verify; AES-256-GCM; SHA3-256/512; HKDF-SHA-512; Argon2id.
* **The server is untrusted for content.** It stores ciphertext and signed headers, relays signals and enforces
  membership and rate limits. It can withhold or delay, never read, forge or reorder undetectably.
* **One root of trust**: the owner's identity, pinned by every member after comparing a safety number out of band.
* **Canonical JSON** for everything signed: UTF-8, keys sorted by code point, no whitespace, integers only (no floats),
  strings with the minimal JSON escapes. A parser re-encodes and refuses anything not already canonical.

## 2. Primitives

| Name | Definition |
|---|---|
| `hkdf32(ikm, salt, info)` | HKDF-SHA-512 → 32 bytes |
| `aesSeal(k, p, aad)` | nonce(12, random) ‖ AES-256-GCM(p) ‖ tag(16) |
| `sign(id, label, m)` | ML-DSA-87.Sign(sk, m, ctx=label) (4627) ‖ Ed25519.Sign(sk, label ‖ 0x00 ‖ m) (64) = 4691 bytes |
| `wrap(k32, pk, aad)` | ct ← ML-KEM-1024.Encaps(pk.kem_pq) (1568); eph ← X25519 key; ssEc = X25519(eph, pk.kem_ec) (refuse all-zero); `wk = hkdf32(ssPq ‖ ssEc, SHA3-512("dcx-chat/v1/wrap-transcript\|" ‖ ct ‖ eph.pub ‖ pk.kem_pq ‖ pk.kem_ec), "dcx-chat/v1/wrap-key")`; output ct ‖ eph.pub ‖ aesSeal(wk, k32, aad) = 1676 bytes |

## 3. Identities

A person's identity comes from a 32-byte master secret, so every device rebuilds identical keys:
`seed(label, n) = SHA3-(n·8)("dcx-chat/v1/seed/" ‖ label ‖ "|" ‖ master)` with labels `kem-pq` (64 → ML-KEM d‖z),
`sig-pq` (32 → ML-DSA ξ), `kem-ec` (32), `sig-ec` (32).

Published bundle (`b` = base64 of canonical JSON, `s` = `sign(id, "dcx-chat/v1/identity", raw)`):
`{"v":1,"t":"identity","user":…,"at":ms,"kem_pq":b64,"kem_ec":b64,"sig_pq":b64,"sig_ec":b64}`.
**Fingerprint** = hex SHA3-256(raw). A client opening someone's bundle checks the self-signature, the user name and
that the fingerprint matches.

**Safety number** of two fingerprints: `h = SHA3-512("dcx-chat/v1/safety|" ‖ min ‖ "|" ‖ max)`; twelve 5-digit groups,
each the big-endian 40-bit integer of 5 bytes of `h`, mod 100000.

**Certificate** (owner → member): `{"v":1,"t":"cert","user":…,"fp":…,"by":owner,"by_fp":…,"at":ms}`, signed
`dcx-chat/v1/cert`. A client trusts a person only if their bundle verifies **and** a certificate from the pinned owner
fingerprint covers exactly that fingerprint. The server's directory is advice; changes it makes are refused.

## 4. Sealed backup (identity on the server)

`key = hkdf32(Argon2id(NFKC(passphrase), salt, m=64 MiB, t=3, p=1, v=0x13, 32 bytes) ‖ pepper, salt,
"dcx-chat/v1/backup-key|" ‖ user ‖ "|" ‖ pepper_ver)` where **pepper** is the server key share,
HMAC-SHA-256(storage key[ver], "dcx-chat-backup-pepper/v1|" ‖ user) — derived, never stored, from a key kept outside
the database and its backups. The payload `{"v":1,"master":b64,"anchor_fp":owner fp or null,"created":ms}` is sealed
with AAD `dcx-chat/v1/backup|user|pepper_ver`. Stored `{"v":1,"kdf":{"alg":"argon2id","m","t","p","salt"},
"pepper_ver","n","c"}`. Openers accept m 64 MiB–1 GiB, t 2–16, p 1–4 only. A stolen database alone can't be attacked
offline (no pepper); a stolen pepper alone opens nothing (no passphrase).

## 5. Rooms and room keys (epochs)

Each room has numbered keys ("epochs"). The member who makes epoch *n* draws a random 32-byte key and publishes:
header `{"v":1,"t":"epoch","room","epoch":n,"by","by_fp","at","prev":SHA3-256 hex of epoch n−1's header or "",
"recipients":[{"u","fp","w":hex SHA3-256 of that recipient's wrapped key}],"commit":hex SHA3-256("dcx-chat/v1/epoch-commit|room|n|" ‖ key)}`
signed `dcx-chat/v1/epoch`, plus one `wrap(key, recipient, "dcx-chat/v1/wrap|room|n|user|fp")` per recipient (the
server hands each person only theirs). Accepted only when the signer is trusted, the person's own line names their
current fingerprint, the wrap hash and the commitment match. A key given to any identity the device doesn't trust is
marked and replaced before that device sends. Keys are renewed when members change (admins do it at once), weekly,
or on request. The `prev` chain exposes a rewritten history.

## 6. Messages

Header `{"v":1,"t":"msg","room","epoch","from","from_fp","id":22-char base64url random,"at":ms}`.
Message key `hkdf32(roomKey, id, "dcx-chat/v1/msg|room|epoch")`; plaintext = u32 length ‖ canonical payload, zero-padded
to 256 / 1024 / 4096 / 16384 bytes; `c = aesSeal(msgKey, padded, AAD = header)`; `s = sign(id, "dcx-chat/v1/msg",
u32(len(header)) ‖ header ‖ c)`. Receivers verify against the trusted sender, check room/epoch/sender match the
server's envelope, refuse a message id seen before (server replay), then decrypt.

Payload kinds (unknown kinds and malformed fields are refused):

| `k` | Fields |
|---|---|
| `text` (default) | `text`, optional `re` (reply-to id), optional `burn` 10–300 s |
| `me` | `text` (an action line), optional `burn` |
| `file` | `text` (caption), `files`: 1–10 file refs, optional `re`, `burn` |
| `react` | `text:""`, `target` id, `emoji` (1–16 chars), `on` bool — newest per person+emoji by server order wins |
| `edit` | `text`, `target` id — only the author's, newest wins |

Burn messages: shown only when opened, for their seconds, then wiped from the device; the server destroys the
ciphertext once every recipient has opened it (or after 7 days unread). No reactions or edits on them.

Sending (the outbox, every client): a message is sealed once and that exact sealed message is resent until the server
has it. The server checks a send's message id **before** anything else; an id it already stored answers
`{"error", "duplicate": true}`, which the client treats as delivered, so a send whose answer was lost never becomes two
messages. The client re-seals (new id) only when the server answers `rotate` or `stale` (the room key changed) for a
message it hasn't stored. Offline, status 0, 408, 429 and 5xx are retried with backoff (1 s doubling to 30 s, and at
once when the network comes back); any other refusal is final and shown to the person with Retry / Discard. Messages
go one at a time, in the order written.

## 7. Attachments

A random 32-byte key; the file is split into 64 KiB chunks (the last zero-padded, a 0-byte file is one chunk), each
`AES-256-GCM(key, nonce = 0x00000000 ‖ u32 index ‖ 0x00000000, AAD "dcx-chat/v1/file|index|last?1:0")` without the
nonce in the output: 65552 bytes per chunk. Uploaded as raw ciphertext; the server returns its SHA3-256 and size,
which the sender checks. The file ref inside the signed message: `{"blob","key","sha3","size","name","mime","kind"
("image"/"video"/"audio"/"file"),"thumb"?:ref,"w"?,"h"?,"dur"?}`. Receivers check the hash before decrypting, refuse
a size that implies an extra chunk, and decide image/video from the decrypted bytes (never the label). Up to 100 MiB.

## 8. Calls

See CALLS.md: signed call signals (`dcx-chat/v1/call-signal`, 2-minute freshness, replay set), per-sender keys
wrapped with AAD `dcx-chat/v1/call-key|call|from|dev|epoch|to|toFp`, per-link frame keys
`HKDF-SHA-512(senderKey, salt "dcx-chat/v1/call-frame|" ‖ call, info binding sender/receiver/epoch/stream)`,
AES-256-GCM frames with a 12-byte trailer, and the call words SHA3-256("dcx-chat/v1/call-words|call|" ‖ sorted
"user:fp" lines) → 4 words of a fixed 256-word list.

## 9. Transport and API

All requests go to `/chat/api/…` on the server's origin. Writes need `Origin: <server origin>` and
`X-Requested-With: dcx-portal`. Sign-in: password + TOTP (codes work once), a passkey (WebAuthn, user verification
required, counters checked, app origins listed by the server), or a paired device token (chat-only, revocable).
Sensitive steps ("confirm it's you") need a fresh code or passkey. The session is an `HttpOnly; SameSite=Strict;
Secure` cookie scoped to `/chat/`. Updates arrive by long polling (`poll?since=&rev=&sig=`, 25 s).

The apps speak only **TLS 1.3 with X25519MLKEM768** (no classical group offered, the negotiated group checked again
after the handshake) with the platform's certificate validation and RFC 6125 host matching; the servers' fronts
(nginx with OpenSSL 3.5 or newer) prefer it and can be set to require it. Browsers use what they
offer (current Chrome, Edge and Firefox negotiate X25519MLKEM768).

Pairing code: `cipherchat:pair/v1?server=<https origin>&token=<43-char one-time token>` (older `dcxchat:` accepted).
