# Design: short-lived post-quantum device prekeys

Status: **proposal**, not implemented. Target: a protocol v2 release after 0.1.2. Current behaviour and its limits:
[security/SECURITY-DESIGN.md §2a](security/SECURITY-DESIGN.md).

## 1. The problem

Room keys (epochs) are wrapped to each member's long-term identity encryption key. Every wrap is hybrid
ML-KEM-1024 + X25519, so nothing here is weak against a quantum adversary. But a member's identity secret opens
every wrap ever made for them, and the server keeps those wraps for as long as the messages they protect. Stealing
one identity secret (an unlocked device, or the sealed backup plus passphrase plus server key share) therefore
exposes that member's whole stored history, and keeps exposing new room keys until the identity is reset.

## 2. Goals

1. **Forward secrecy against identity theft**: a stolen identity secret alone opens no stored room key.
2. **Post-compromise security**: a stolen device secret stops opening new room keys within one prekey lifetime.
3. **Stay hybrid post-quantum** at every step (no classical-only shortcut, the property 0.1 already has).
4. **Keep what works**: several devices per person, the web chat, rooms of up to the current member limit, the
   outbox and offline delivery.

Non-goals: per-message forward secrecy (a full post-quantum ratchet); hiding metadata from the server.

## 3. Proposal

### 3.1 Device prekeys

* Every device that holds chat keys (the Windows and Android apps, and each web chat *installation*, see §4) makes
  its own **random** ML-KEM-1024 + X25519 key pairs. They are not derived from the identity master, so the master
  can't rebuild them.
* It publishes a small set (say 3) as **signed prekeys**: `{"v":2,"t":"prekey","user","dev","id","at","exp",
  "kem_pq","kem_ec"}`, signed by the identity (`dcx-chat/v2/prekey`, ML-DSA-87 + Ed25519). Lifetime 7 days, a new
  one published daily, so there is always a fresh one.
* Each device is listed in a signed **device list** (`dcx-chat/v2/devices`) the person's devices maintain, so a
  member can see when a new device appears, and the server can't add one silently.

### 3.2 Wrapping room keys

* An epoch-v2 header lists recipients per device: `{"u","dev","prekey","fp","w"}`. The epoch creator wraps the room
  key once per recipient device, to that device's newest valid prekey, with the same hybrid `wrap()` (new label
  `dcx-chat/v2/wrap`, the AAD binding room, epoch, user, device and prekey id).
* A recipient device unwraps it, then **keeps the room key itself** in its local key store (§3.3) and acknowledges
  the epoch to the server. Once every listed device has acknowledged (or after a grace period, e.g. 30 days), the
  server **deletes the wraps**. Only ciphertext remains, which no long-lived key can open.
* Prekey secrets are deleted by the device as soon as they expire. From then on nothing the device holds can open
  wraps made to that prekey, even if the wraps were copied.

### 3.3 The local key store

* Each device keeps the room keys it received, sealed under a device-local key: Android Keystore (StrongBox/TEE),
  Windows DPAPI (+ Windows Hello when on), and the browser's non-extractable WebCrypto key in IndexedDB for web
  installations.
* This is what reading history needs, so it's where the remaining exposure lives: a stolen *unlocked* device still
  reads what that device could read. A stolen identity secret, or the server's database, no longer does.

### 3.4 New devices and history

A fresh device has no room keys. Two options, chosen per room by its admins (the default is a decision for the
release):

* **Forward secret (Signal-like)**: a new device reads only from the next key change on.
* **History sync**: an existing device of the same person seals the room keys it holds for the new device's
  prekey (`dcx-chat/v2/key-sync`, one-time, deleted on acknowledgement). Convenient, and still never opened by the
  identity secret alone, but it needs another of that person's devices online.

## 4. The web chat

Today the web chat keeps nothing in the browser and rebuilds everything from the sealed backup each time. With
prekeys it becomes an *installation*: a non-extractable device key in IndexedDB, its own prekeys, its own key store.
Signing in on a browser that has never been used becomes "a new device" (§3.4). Private/incognito windows can't keep
an installation, so they would read only what history sync gives them for that session. This is the largest
user-visible change and the main reason the design needs a decision before implementation.

## 5. Compatibility and migration

* Protocol v2 epochs are only made when every recipient device has published prekeys. Otherwise the creator falls
  back to a v1 epoch (identity wraps, as today), and the room shows that it's in compatibility mode.
* Old v1 epochs stay readable. A one-time "re-key" step after upgrading lets rooms drop their v1 wraps: devices
  import the room keys they can open into their key store, acknowledge, and the server deletes the v1 wraps.
* The interop fixtures (INTEROP.md) gain prekey, device-list, epoch-v2 and key-sync fixtures; all three clients must
  pass them byte for byte before release.

## 6. Security review points

* **Rogue device**: someone with the identity signing key can publish a device and prekeys of their own. The signed
  device list makes that visible to the person's other devices and to every member ("sam added a device"); it's an
  active, noisy attack rather than silent reading of history.
* **Prekey exhaustion / replay**: prekeys are reusable within their lifetime (KEM, not one-time DH), so exhaustion
  isn't an issue; freshness comes from expiry and the wrap's AAD.
* **Server withholding acknowledgements or deleting late**: the server can only delay deletion, never read. Clients
  can check, per room, that no wraps for them older than the grace period remain.
* **Size**: a v2 epoch for a full room grows with devices, about 1.7 KB per recipient device (one ML-KEM-1024
  ciphertext, one X25519 key, one AES-GCM wrap), so 8 people with 3 devices each is about 41 KB per key change.

## 7. Alternatives considered

* **MLS (RFC 9420) with a post-quantum ciphersuite**: built for groups, with tree-based forward secrecy and
  post-compromise security; a larger change and a newer, less settled ecosystem for post-quantum suites. Worth
  revisiting for large rooms.
* **A post-quantum ratchet per pair (Signal-style)**: per-message forward secrecy, but a poor fit for room-key
  epochs and multi-device, and much more state.
* **Deleting old wraps only (no prekeys)**: cheap, but a stolen identity still opens every wrap that hasn't been
  deleted yet and every future one.

## 8. Rough plan

1. Protocol spec and fixtures (prekey, device list, epoch v2, acknowledgement, key sync).
2. Server: device list and prekey storage, epoch acknowledgements, wrap deletion, per-room history policy.
3. Clients: key store, prekey rotation, v2 epochs with v1 fallback, history sync; web installations.
4. Interop across all three clients, a pentest of the new surface, then a release with a migration note.
