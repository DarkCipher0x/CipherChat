# CipherChat security design report

Release 0.1.2, October 2026. Companion to [PROTOCOL.md](../PROTOCOL.md) (exact formats) and
[PENTEST-2026-10.md](PENTEST-2026-10.md) (what was attacked). Written for reviewers and for owners deciding whether
CipherChat fits their threat model.

## 1. Threat model

| Adversary | Can | CipherChat's answer |
|---|---|---|
| Network attacker (Wi-Fi, ISP, state) recording traffic now, decrypting later with a quantum computer | read and keep everything on the wire | apps: TLS 1.3 with **X25519MLKEM768 only**; content: hybrid ML-KEM-1024 + X25519 key wrapping and AES-256-GCM inside; calls: frame encryption inside DTLS-SRTP |
| Active network attacker | change, replay, inject | TLS; every message, key and call signal is signed (ML-DSA-87 + Ed25519, both must verify) and checked for freshness and replay |
| The server (or whoever takes it over) | read its database, serve anything, change any field, drop or delay | ciphertext only; signatures by identities the server can't forge; trust anchored in the owner's key that each member pinned themselves; key history chained (`prev`); message ids unique; attachments bound by their hash inside the signed message. It **can** deny service and see metadata (§6) |
| Another member of a room | read what they were sent | room keys renew when members change, so a leaver can't read what follows and a newcomer can't read what came before |
| Someone with a stolen database backup | attack passphrases offline | backups are sealed with Argon2id **and** a per-user server key share derived from a key kept outside the database |
| Someone with a stolen phone / PC | use the app | Android: vault behind a Class 3 fingerprint or the screen lock, per use, StrongBox/TEE key destroyed on new fingerprint enrolment, chat keys only after the passphrase, auto-lock; Windows: DPAPI plus optional Windows Hello; both wipe keys on lock |
| Malicious web page / app on the same device | reach the app's data or call page | Android: no exported components except the launcher, WebView limited to its own APK files with an origin-checked channel; Windows: WebView2 limited to a virtual host and an allowlist of operations; private keys never enter either page |

Out of scope: a compromised operating system or a keylogger on the user's device; traffic analysis of timing and
volume; an owner who certifies the wrong person without comparing the safety number.

## 2. Cryptography

* **Algorithms.** ML-KEM-1024 and ML-DSA-87 (NIST category 5) combined with X25519 and Ed25519; AES-256-GCM;
  SHA3-256/512; HKDF-SHA-512; Argon2id (64 MiB, 3 passes). Signatures are valid only when both halves verify; key
  wrapping feeds both shared secrets and the whole transcript into HKDF ("KitchenSink"), so either half alone keeps the
  key secret.
* **Implementations.** Web: `@noble/post-quantum`, `@noble/curves`, `@noble/hashes` (vendored, integrity-pinned) and
  WebCrypto; Windows: BouncyCastle .NET 2.7.0 + Windows CNG AES-GCM; Android: BouncyCastle Java 1.86 (TLS 1.86.2),
  SHA-256-pinned in Gradle's verification metadata. Every client runs OpenSSL 3.5 known-answer tests at start-up and
  refuses to run if any fails; three-way interop fixtures prove byte-identical behaviour.
* **Randomness.** Platform CSPRNGs (WebCrypto `getRandomValues`, `RandomNumberGenerator`, `SecureRandom`). ML-DSA
  signing is hedged (fresh randomness with the deterministic seed).
* **Key separation.** Every use has its own label (`dcx-chat/v1/...`) as the ML-DSA context, the Ed25519 prefix, the
  HKDF info or the AES-GCM AAD; a signature or key from one context is refused in every other.

## 2a. Forward secrecy and its limits

What stays post-quantum, and what doesn't, over the life of a conversation:

* **Every key change is post-quantum.** CipherChat has no Double Ratchet and no classical-only step. A room's key
  (its "epoch", PROTOCOL.md §5) is a fresh random 32-byte key, wrapped separately for each member with hybrid
  ML-KEM-1024 + X25519, and replaced when members change, weekly and on request. Each message has its own key derived
  from the room key. A conversation that has run for a year is exactly as post-quantum as on its first day: an
  adversary recording traffic today can't recover a room key later without breaking both ML-KEM-1024 and X25519.
* **Forward secrecy is per key period, not per message.** Room keys are wrapped to each member's long-term
  identity encryption key (the `kem_pq` / `kem_ec` keys in their identity bundle), not to short-lived keys. So if a
  member's identity secret is ever stolen (from a device while it's unlocked, or from their sealed backup together
  with both their passphrase and the server's key share, §4), the thief can unwrap **every room key that member was
  given that the server still holds**, and read the messages under them. Signal-style protocols limit this to a few
  messages; CipherChat limits it only by:
  * **retention**: a room with a retention period deletes old messages, and with them the room keys no remaining
    message needs (rooms without one keep history until deleted);
  * **resetting the identity** (`/reset-identity`): a new identity makes the old secret useless for anything new,
    though not for wraps already stored.
* **Recovery after a compromise.** A stolen room key is useless from the next key change on (members, weekly, or on
  request). A stolen identity secret isn't: the thief can also unwrap future room keys until that person resets their
  identity and the owner certifies the new one.
* **Calls** wrap per-call sender keys the same way. The server keeps call signals only in memory (60 s), so a later
  identity theft exposes a past call only if someone also recorded its signals at the time (a malicious server or
  the server's own TLS endpoint).

Why it's built this way: one identity per person, rebuilt on every device from the sealed backup, means history and
new devices simply work, and the web chat needs nothing stored in the browser. The cost is coarser forward secrecy.
The planned change (short-lived post-quantum device prekeys, so a stolen identity no longer opens stored room keys)
is in [PREKEYS-DESIGN.md](../PREKEYS-DESIGN.md); until it ships, this section is the honest statement of the limit.

## 3. Identity and trust

The owner's identity is the only root. Each member compares a 60-digit safety number with the owner once and pins
the owner's fingerprint inside their own sealed backup (so a new device inherits the pin). The owner certifies members
after the same comparison. A client trusts exactly the identities certified by its pinned owner; the server's
directory is only a hint, and a changed owner key raises a loud warning instead of being followed. Room keys are only
accepted from and given to trusted identities; a key that reached anyone untrusted is replaced before the next send.

## 3a. Permissions (docs/ADMIN.md)

* Sixteen single permissions; roles are editable sets of them; per-person grants and denies on top.
* Anti-escalation enforced on the server: nobody grants, or builds a role with, a permission they don't hold; an
  account can only be changed by someone holding strictly more permissions; nobody edits their own; the owner (all
  permissions, the trust anchor) can't be changed by anyone. Certifying identities and add-ons are owner-only and are
  not permissions at all.
* Every route checks its permission (rooms, DMs, files, calls, app pairing, each admin area), changes need a fresh
  authenticator code, refusals of privilege changes are audited.
* Settings are validated against a typed schema and refused whole (never quietly trimmed); SMTP fields can't carry line
  breaks (no header injection); the SMTP host must resolve to public addresses (no SSRF into the network).

## 4. Accounts and sessions

Three-factor sign-in (password, TOTP, then the chat passphrase locally) or a passkey (WebAuthn with user verification;
counters checked; foreign origins refused; app origins only when the owner lists the app). TOTP codes work once.
Sensitive actions need a fresh code or passkey ("confirm it's you"). Sessions: random 256-bit tokens stored hashed,
`HttpOnly; Secure; SameSite=Strict; Path=/chat/`, idle and absolute expiry, ended at once by sign-out, suspension,
password change or device revocation. Paired devices get chat-only tokens that can't pair further devices or reach
administration. CSRF: exact Origin plus a custom header on every write. Rate limits per address (nginx and the server).

## 5. Server hardening

* **Linux:** dedicated `cipherchat` user; systemd sandbox (no capabilities, `ProtectSystem=strict`, read-only program
  and settings, private /tmp and devices, `MemoryDenyWriteExecute`, syscall filter, loopback-only networking,
  memory/task limits, private user namespace); nginx in front (TLS 1.3, X25519MLKEM768 first or only, request size
  and rate limits, strict headers); coturn with short-lived HMAC credentials, private address ranges blocked, no CLI,
  and its own systemd jail (no capabilities, read-only system, syscall filter); installer verifies the download's
  checksums, keeps settings `0640 root:cipherchat`, backs up nightly. `systemd-analyze security` rates the chat server
  0.9 ("SAFE") and the jailed coturn 1.3 ("OK") on Ubuntu 26.04.
* **At rest:** messages, attachments and room keys are stored only as post-quantum end-to-end ciphertext (the server
  has no key that opens them); identities are sealed with Argon2id + AES-256-GCM and a server key share that lives in
  a separate key file, never in the database or its backups; add-on keys aren't stored at all; the SMTP password and
  queued emails (which can carry one-time links) are sealed with SHAKE256 + HMAC-SHA3-256 (encrypt-then-MAC) under keys
  derived from that same key file.
* **No addresses kept:** CipherChat stores and logs no client IP addresses. The audit log, add-on records and refusals
  keep a keyed tag that changes every UTC day (HMAC-SHA3-256 under a key from the server key file), so repeated
  attempts from one source on one day are visible as one tag, but nobody can read an address back or link tags across
  days. nginx keeps no access log for CipherChat and logs only critical errors; the call relay (coturn) logs nothing;
  the server's journal lines are method, path and status only. Addresses exist only in memory (rate limits, an
  add-on's IP allowlist). Usernames, and the email addresses needed to send invites and notifications, are the only
  identifying data kept. Existing addresses are removed once on upgrade (the audit chain is re-sealed and the
  removal itself is audited).
* **Mail:** sent by a separate jailed service (`cipherchat-mailer`, outbound only, `SocketBindDeny=any`, no access to
  anything but its state), so the web-facing server keeps its loopback-only network jail. What remains readable to
  someone with the disk is metadata (section 6), kept `0700` to the service account.
* **Application:** parameterised SQL only; every body read through a bounded reader (no desync); generic errors to
  clients; strict CSP without `unsafe-*` on every page; `no-store` on the API; audit log of sensitive actions
  (without the content of anything).

## 6. Metadata the server necessarily sees

Account names, room membership, message and call timing and sizes (messages padded to 256 B / 1 / 4 / 16 KiB
buckets), attachment sizes (64 KiB granularity), device addresses (relay-only calls hide them from peers but not from
the server and relay). Retention per room (1 day to a year, or until deleted) and burn messages limit how long
ciphertext and its metadata live.

## 7. Clients

* **Android:** minSdk 31; vault key in StrongBox/TEE with per-use biometric-or-credential auth, invalidated on new
  enrolment; no backups or device transfer of app data; `FLAG_SECURE` in release; notifications never carry message
  text; foreground connection only while unlocked; auto-lock; call WebView served from the APK only, no file access,
  no navigation, origin-restricted message channel; R8-minified signed release with RSA-4096 key.
* **Windows:** identity keys only in memory between unlock and lock; vault under DPAPI with optional Windows Hello;
  call window in WebView2 with a virtual host, CSP and an operation allowlist; idle lock.
* **Web:** the strongest browser defaults (CSP, COOP, CORP, frame denial, no referrer); keys in memory only; the code
  is served by the server (see SECURITY.md, "Honest limits").
* **Outbox (all clients):** queued messages are already end-to-end sealed; plaintext previews stay in memory. While
  locked, Android keeps unsent sealed messages inside the biometric vault and Windows under DPAPI (this user) in
  memory only; nothing unsent is written to disk in the clear, and the web keeps them in the tab only. Resends reuse
  the signed message id, and the server checks it first, so retries can't duplicate or replay a message.

## 7a. Add-ons and connectors (docs/ADDONS.md)

* Add-ons are chat members with their own hybrid PQ identity made on their own machine and certified by the owner;
  end-to-end encryption and the trust model are unchanged, and every client labels them (`addon.` names are reserved).
* Requests are signed per request with HMAC-SHA3-256 (256-bit key) over method, target, origin, add-on, time, a
  one-time nonce and the body's SHA3-256: no bearer token to steal, no replay, no tampering; no cookies, so no CSRF.
* The server never stores the key: it's HMAC-SHA3-256-derived from the server key file per salt/version; rotation is
  instant. On the add-on's PC the key and identity seed are DPAPI-sealed.
* A route allowlist (state, poll, history, room keys of its own rooms, send, attachments, DMs, leave) with per-add-on
  scopes, IP allowlist, expiry and rate limit; no account, device, backup, certificate, room-admin, key-rotation or call
  routes; no password/passkey sign-in; owner-only management behind a fresh authenticator code; every refusal audited.
* Connectors (CommandCentre via MCP) answer only verified people, read-only unless the configuration names operators,
  never pass chat text into scripts, commands or file paths, and leave the connected system's own approvals in place.

## 8. Supply chain and release

Pinned dependencies with hashes (NuGet lock files, Gradle verification metadata, vendored JS with SRI hashes), no
dependencies at all on the Linux server beyond Python's standard library and distribution packages, release checksums
(`SHA256SUMS`) checked by the Linux installer, Android signing certificate published, no debug symbols or build paths
in releases. Not yet: Authenticode signing of the Windows installers, reproducible builds.

## 9. Verification

Unit and interop tests on every client (web 29 call checks + self-tests; Windows 58; Android 25), server functional (12)
and penetration (18) suites, a real Linux install with nginx and coturn, a Windows Sandbox install/uninstall of both
MSIs, and live end-to-end runs between web, Windows and Android (messages, files, trust set-up, calls both ways).
Details and findings: [PENTEST-2026-10.md](PENTEST-2026-10.md).
