# Security policy

## Reporting a vulnerability

Please report privately through **darkciphersystems.com** (the contact form, marked "CipherChat security") rather
than in a public issue. Include the version, the component (server, web, Windows, Android, installer) and steps to
reproduce. You'll get an answer within a few days; fixes are released as soon as they're ready and credited if you
wish.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

## What CipherChat protects, and what it doesn't

**Protected**, even against the server operator, a network attacker and a future quantum computer recording today:

* the content of messages, edits, reactions and attachments (end-to-end encrypted and signed);
* call audio, video and screen sharing (every frame encrypted end to end inside WebRTC; DTLS-SRTP is not relied on);
* who said what, inside a room (every message signed; the server can't forge or alter one undetectably);
* the identity keys (sealed with your passphrase plus a server key share; neither alone opens them).

**Visible to the server** (it needs these to work): account names, who is in which room, when messages and calls
happen and how big they are, and the IP address of each connection while it lasts. CipherChat never stores or logs
addresses: its records keep a tag that changes daily and can't be turned back into an address (unless relay-only
calls are on, peers in a call see each other's addresses). Burn messages and retention limits delete ciphertext on the server on schedule.

**Your responsibilities:** compare the safety number with the owner once (in person or on a call you trust), keep
your chat passphrase secret and memorable (it can't be recovered), keep your devices locked and up to date, and as an
owner, back up the server key file offline.

## Honest limits

* `@noble/post-quantum`, used by the web chat, hasn't had an independent audit. That's why everything is hybrid
  (classical X25519/Ed25519 alongside ML-KEM/ML-DSA, both required) and why every client checks itself against
  OpenSSL 3.5 known answers at start-up. The apps use BouncyCastle.
* A browser can only be as trustworthy as the server that delivers its code. For the strongest protection use the
  Windows or Android app, whose code doesn't come from the server.
* The installers aren't Authenticode-signed yet; Windows SmartScreen warns and Smart App Control blocks them. Check
  `SHA256SUMS` from the download page before running them.
* Calls in groups are a mesh (up to 8); each participant uploads their stream to every other.

Design detail: [docs/security/SECURITY-DESIGN.md](docs/security/SECURITY-DESIGN.md). Latest test:
[docs/security/PENTEST-2026-10.md](docs/security/PENTEST-2026-10.md).
