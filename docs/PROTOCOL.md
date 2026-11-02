# The CipherChat protocol, versions 1 and 2

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

## 10. Devices, the key store and history (protocol 1.1)

Room keys stop living on the server: each device keeps the ones it has opened and the server deletes the wraps
(PREKEYS-DESIGN.md phase 1). Epochs (§5) are unchanged. A person with no device list is in **compatibility mode**
and keeps today's behaviour.

**Device key.** Every device that keeps room keys (an app install, a browser *installation*) makes a random
16-hex device id and a random ML-KEM-1024 + X25519 key pair (not derived from the master). Its private part never
leaves the device.

**Device list**, published by any of the person's devices (`b` = base64 of canonical JSON, `s` = `sign(id,
"dcx-chat/v1/devices", raw)`): `{"v":1,"t":"devices","user","fp","seq":n,"at":ms,"devices":[{"id","name","kem_pq",
"kem_ec","added":ms}]}`, devices sorted by id, at most 16, names 1–40 characters. `fp` is the publisher's current
identity fingerprint, `seq` starts at 1 and grows by exactly one per change. Clients accept a list only if it
verifies against the person's trusted identity, `fp` is that identity's, and `seq` is not lower than the last one
they saw (no rollback). A device that appears or disappears is shown to the person's other devices and to everyone
who shares a room with them.

**Key store.** Room keys are stored on the device as `aesSeal(deviceKey, aesSeal(storeKey, key, aad), aad)` with
`aad = "dcx-chat/v1/store|" ‖ user ‖ "|" ‖ room ‖ "|" ‖ epoch`, where `storeKey = hkdf32(master, user,
"dcx-chat/v1/store-key")` and `deviceKey` never leaves the device: in the web chat a non-extractable WebCrypto key
in IndexedDB; in the apps a random 32-byte key inside the store file, which the platform seals as a whole (Windows
DPAPI for that Windows account, a non-exportable Android Keystore key that only works while the phone is unlocked;
the Secure Enclave/Keychain on Apple). The device key pair's seed is kept the same way, as room `device`, epoch 0.
Opening a stored key needs both the device and the unlocked identity. The store is never uploaded, synced to a cloud
or included in a backup.

**Acknowledgement.** After a device has stored room keys it sends `POST rooms/<id>/ack {"dev","epochs":[n,…]}`.
The server deletes a person's wrap of epoch *n* once every device on their list has acknowledged it, or when the
wrap is 7 days old, whichever is first, but only while every phone or PC paired to that account has a listed device
(so an app that predates this release keeps its wraps). Epoch headers and signatures are kept, so the `prev` chain
and commitments can still be checked: `GET rooms/<id>/epochs?all=1` returns every header, with `w` null where the
wrap is gone.

**History window.** A room setting `history_days` (0 = as long as the room keeps messages, or 7, 30, 90, 365), set
by its admins. Devices erase stored keys whose epoch header `at` is older than the window (never the current epoch).
A second setting `history_sync` (default on) allows new devices to receive the room's older keys.

**History sync.** A new device asks with `POST sync/request {"dev"}`. One of the person's other devices shows the
request with the new device's name and its **device code** (first 16 hex of SHA3-256(kem_pq ‖ kem_ec), in groups of
four, shown on both devices), and on approval sends one or more sealed packages (each blob at most 192 KiB, split
by room; the last one sent with `"last": true`, which closes the request):

* payload `{"v":1,"t":"key-sync","user","from","to","at","keys":[{"room","epoch","key":b64}]}` (canonical),
  only rooms with `history_sync` on and only keys inside each room's window;
* `p = canon(payload)`, `s = sign(id, "dcx-chat/v1/key-sync", p)`, `k` = random 32 bytes,
  `aad = "dcx-chat/v1/key-sync|" ‖ user ‖ "|" ‖ from ‖ "|" ‖ to`;
* blob = `wrap(k, targetDevice, aad) ‖ aesSeal(k, u32(len(p)) ‖ p ‖ s, aad)`, base64, uploaded with
  `POST sync/send {"to","from","blob","last"}`.

The new device fetches it (`GET sync?dev=`), unwraps with its device key, checks the signature against its own
identity, then accepts each key only if its epoch header verifies and the header's `commit` matches the key; it
stores them, acknowledges, and confirms with `POST sync/done {"id"}`, after which the server deletes the package.
Unfetched packages and requests are deleted after 7 days. The server never makes a wrap or a package itself.

## 11. Device prekeys and per-device room keys (protocol 2)

Phase 2 of PREKEYS-DESIGN.md: a room key is wrapped to each recipient **device's** short-lived prekey instead of to
the person's identity, so a stolen identity secret opens no stored room key, and a stolen device stops opening new
ones within a prekey's lifetime. Everything in §10 stays (device list, key store, acknowledgement, history sync).

**Prekeys.** Each device makes random ML-KEM-1024 + X25519 key pairs (a 96-byte seed each, as for the device key;
never derived from the master) and publishes them, signed by the identity (`s = sign(id, "dcx-chat/v2/prekey", raw)`):
`{"v":2,"t":"prekey","user","fp","dev","id":16 hex,"at":ms,"exp":ms,"kem_pq","kem_ec"}` with `exp = at + 7 days`.
A device publishes a new prekey when its newest is a day old (`POST keydevices/prekey {"dev","prekey":{"b","s"}}`;
the server keeps the newest four per device and drops expired ones and those of devices that leave the list). The
prekey's seed is kept in the device's key store (as room `prekey:<id>`, epoch 0) and **erased when the prekey
expires**, after the device has opened and stored every room key wrapped to it. The directory lists each person's
current prekeys (`"prekeys": [{"b","s"}]`).

A client accepts someone's prekey only if it verifies against their trusted identity, `fp` is that identity's, `dev`
is on their trusted device list, `exp − at` is at most 8 days and `exp` is still at least an hour away.

**Epoch v2.** Header `{"v":2,"t":"epoch","room","epoch":n,"by","by_fp","at","prev","recipients":[{"u","fp","dev",
"prekey","w"}],"commit"}`, recipients sorted by `u` then `dev`, signed `dcx-chat/v2/epoch`; `prev` and `commit` as
in §5. A device that can't open epoch n−1 (it was sealed to other devices, or made before this one joined) still
checks that header's signature against its trusted maker and names its hash as `prev`. One `wrap(key, prekey, "dcx-chat/v2/wrap|room|n|u|fp|dev|prekey")` per recipient device, to that device's
newest acceptable prekey; the package's `w` maps `"u|dev"` to the wrap. A device accepts the key only if the header
verifies against the trusted maker, its own line names its current fingerprint, device id and one of its own
prekeys, the wrap hash and the commitment match. Every member's **every listed device** must have a line: the server
refuses the epoch unless each recipient's devices equal their current device list and each prekey id is one it
holds for that device.

**Choosing v1 or v2.** A client makes a v2 epoch only when every recipient has a trusted device list, every listed
device has an acceptable prekey, the server's directory says the person has no older app signed in (`"v2": true`),
and there are at most 64 recipient devices. Otherwise it makes a v1 epoch (§5, deleted after acknowledgement as in
§10) and says the room key is in compatibility mode. The server refuses a v2 epoch for anyone with an older app
signed in (`409`, `"v1": true`), and the client then makes a v1 one. A room whose current key is v2 reports
`needs_rotation` when a recipient's devices change, and also while a recipient has an older app signed in (that app
can't open a v2 key), so the next sender makes a v1 key; a v1 key ends both.

**Fetching and deleting.** `GET rooms/<id>/epochs?dev=<id>` returns, for v2 epochs, the wrap for that device (or
`w` null); v1 epochs are unchanged. A v2 wrap is deleted as soon as its device acknowledges the epoch, or after 7
days. History sync (§10) is unchanged and carries v1 and v2 keys alike; `checkEpoch` accepts both header versions.
