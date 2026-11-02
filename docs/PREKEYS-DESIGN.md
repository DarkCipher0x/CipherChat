# Design: wrap deletion and short-lived post-quantum device prekeys

Status: **phase 1 implemented, pentested and released in 0.2.0** (as protocol 1.1, [PROTOCOL.md §10](PROTOCOL.md):
server, web chat, Windows and Android, with interop fixtures; see §11 for what's left). **Phase 2
implemented, pentested and released in 0.2.0** (protocol 2, [PROTOCOL.md §11](PROTOCOL.md): the same four parts,
fixtures, live tests).
Current behaviour and its limits: [security/SECURITY-DESIGN.md §2a](security/SECURITY-DESIGN.md).

Where phase 1 as built differs from the text below: it uses `v1` labels (`dcx-chat/v1/devices`,
`dcx-chat/v1/key-sync`), since epochs don't change; and history sync goes to the new device's long-lived **device
key** (listed in its signed device-list entry) rather than to a one-time transfer key, because that key also seals
nothing else and is wiped with the device's store when it's removed.

## 1. The problem

Room keys (epochs) are wrapped to each member's long-term identity encryption key. Every wrap is hybrid
ML-KEM-1024 + X25519, so nothing here is weak against a quantum adversary. But a member's identity secret opens
every wrap ever made for them, and the server keeps those wraps for as long as the messages they protect. Stealing
one identity secret (an unlocked device, or the sealed backup plus passphrase plus server key share) therefore
exposes that member's whole stored history, and keeps exposing new room keys until the identity is reset.

What sets the size of that exposure is **how long the wraps are kept**, not how often the room key changes. A weekly
key change doesn't help while every old period's wrap is still on the server. The wraps are kept today because they
are how clients read history: every device rebuilds the identity from the sealed backup, and the web chat keeps
nothing in the browser, so all of them read history by unwrapping the stored wraps.

## 2. Goals

1. **Phase 1, no stored archive**: a stolen identity secret opens only the room keys whose wraps haven't been
   acknowledged and deleted yet (in practice the current key period), not the whole history.
2. **Phase 2, forward secrecy against identity theft**: a stolen identity secret alone opens no stored room key.
3. **Post-compromise security** (phase 2): a stolen device secret stops opening new room keys within one prekey
   lifetime.
4. **Stay hybrid post-quantum** at every step (no classical-only shortcut, the property 0.1 already has).
5. **Keep what works**: several devices per person, the web chat, rooms of up to the current member limit, the
   outbox and offline delivery.

Non-goals: per-message forward secrecy (a full post-quantum ratchet); hiding metadata from the server.

## 3. Rules for both phases

Each of these, if broken, puts the wraps back and cancels the deletion:

* **The server never re-wraps.** No path lets the server, a room admin or the owner make a new wrap of an old room
  key for a device. History reaches a new device only from another of the same person's devices (§4.4).
* **The local key store is never backed up** to the server, into the sealed backup, or under the identity or any
  key the identity can rebuild. Losing every device loses the history it held; that is the intended trade.
* **Deleted means deleted.** Wraps are removed from the database and from server backups on their normal rotation;
  the server keeps no "recovery" copy.

The first rule is already enforced: a room key can only be stored as the next key period, for the current members,
and a stored one is never rewritten. `test_22_no_path_rewraps_an_old_room_key` in `server/tests/test_server.py`
checks this over HTTP and in the source, so a later feature that adds a re-wrap path fails the tests.

## 4. Phase 1: wrap deletion

Epochs keep today's v1 identity wraps. What changes is that the wraps stop being the long-term copy of the room key.

### 4.1 Devices

* Every device that holds chat keys (the Windows and Android apps, the future Apple app, and each web chat
  *installation*, §6) gets a device id and a **signed device list** entry (`dcx-chat/v2/devices`) that the person's
  devices maintain, so a member can see when a new device appears and the server can't add one silently.

### 4.2 Acknowledge, then delete

* A recipient device unwraps the room key, **keeps it in its local key store** (§4.3) and acknowledges the epoch to
  the server.
* Once every device on the person's list has acknowledged, the server **deletes that person's wrap**. A device that
  hasn't acknowledged within a short grace period (**7 days**) loses the wrap anyway; it gets that period's key from
  history sync (§4.4) or doesn't read it.
* Clients check, per room, that no wraps for them older than the grace period remain, and show a warning if any do.

### 4.3 The local key store

* Each device keeps the room keys it received, sealed under a **device-local key**: Android Keystore (StrongBox/TEE),
  Windows DPAPI (+ Windows Hello when on), the Secure Enclave and Keychain on Apple devices, and the browser's
  non-extractable WebCrypto key in IndexedDB for web installations.
* This is what reading history needs, so it's where the remaining exposure lives: a stolen *unlocked* device still
  reads what that device could read. The server's database and the sealed backup no longer do.

### 4.4 New devices and history

A fresh device has no room keys. Two options, chosen per room by its admins (the default is a decision for the
release):

* **Forward secret (Signal-like)**: a new device reads only from the next key change on.
* **History sync**: an existing device of the same person seals the room keys it holds to the new device
  (`dcx-chat/v2/key-sync`, hybrid `wrap()`, one-time, deleted on acknowledgement). In phase 1 the target is a
  one-time **transfer key**: a random ML-KEM-1024 + X25519 pair the new device makes for this, listed in its signed
  device-list entry and deleted once the sync is acknowledged. In phase 2 it's the device's prekey. Either way the
  identity secret alone never opens a key-sync, and it needs another of that person's devices online.

### 4.5 Shredding old database copies

Deletion is a promise from the server, not a property of the crypto: it protects against a compromise *after* the
deletion, but a copy of the database or a backup taken earlier still holds the wraps. To narrow that, the server
seals stored wraps under a **rolling storage key** (a new one daily, in a key file kept outside the database and
its backups, like the server key file), re-seals the live ones under the newest key, and erases storage keys older
than a few days. An old database copy or backup then can't be read once its storage key is gone.

Built as `server/cipherchat/shred.py`: one key per day in `CIPHERCHAT_SHRED_DIR` (default `/var/lib/cipherchat-shred`,
outside the state folder, so outside every backup and upgrade snapshot), the last three kept; each wrap sealed with
the server's SHA-3 construction and bound to its row. The retention sweep re-seals live wraps under the newest key and
drops rows whose key is gone.

This only fits *after* acknowledge-and-delete: today the stored wraps are the only copy of history, so a server
restored from a backup would lose every room's history with its storage keys. It doesn't help against a server
that is itself malicious, which phase 2 covers.

### 4.6 History window on devices

Deletion moves the archive into the device key store, and an unlocked device is the usual place an identity is
stolen from. So rooms get a **history window** set by their admins (for example 30 days, a year, or forever): devices
erase room keys older than the window, and older messages stop opening on every device too. It works with the
existing room retention setting (which deletes the ciphertext on the server) and can be shorter than it.

### 4.7 What phase 1 still leaves

A stolen identity secret opens every wrap not yet deleted (the current period, plus anything inside the grace
period), and every future wrap until the identity is reset. A wrap someone copied before it was deleted still opens
with the identity. Phase 2 closes all three.

## 5. Phase 2: device prekeys

### 5.1 Device prekeys

* Each device makes its own **random** ML-KEM-1024 + X25519 key pairs. They are not derived from the identity
  master, so the master can't rebuild them.
* It publishes a small set (say 3) as **signed prekeys**: `{"v":2,"t":"prekey","user","dev","id","at","exp",
  "kem_pq","kem_ec"}`, signed by the identity (`dcx-chat/v2/prekey`, ML-DSA-87 + Ed25519). Lifetime 7 days, a new
  one published daily, so there is always a fresh one.

### 5.2 Wrapping room keys

* An epoch-v2 header lists recipients per device: `{"u","dev","prekey","fp","w"}`. The epoch creator wraps the room
  key once per recipient device, to that device's newest valid prekey, with the same hybrid `wrap()` (new label
  `dcx-chat/v2/wrap`, the AAD binding room, epoch, user, device and prekey id).
* Acknowledgement, deletion and the key store work exactly as in phase 1 (§4.2, §4.3).
* Prekey secrets are deleted by the device as soon as they expire. From then on nothing the device holds can open
  wraps made to that prekey, even if the wraps were copied.

## 6. The web chat

Today the web chat keeps nothing in the browser and rebuilds everything from the sealed backup each time. From
phase 1 it becomes an *installation*: a non-extractable device key in IndexedDB and its own key store (and, in
phase 2, its own prekeys). Signing in on a browser that has never been used becomes "a new device" (§4.4).
Private/incognito windows can't keep an installation, so they would read only what history sync gives them for that
session. This is the largest user-visible change and the main reason the design needs a decision before
implementation.

## 7. Compatibility and migration

* Phase 1 needs no new epoch format: v1 epochs gain acknowledgements and deletion. A one-time step after upgrading
  lets rooms drop their stored v1 wraps: devices import the room keys they can open into their key store,
  acknowledge, and the server deletes the wraps.
* Phase 2 v2 epochs are only made when every recipient device has published prekeys. Otherwise the creator falls
  back to a v1 epoch (identity wraps, deleted after acknowledgement as in phase 1), and the room shows that it's in
  compatibility mode.
* The interop fixtures (INTEROP.md) gain device-list, acknowledgement and key-sync fixtures in phase 1, and prekey
  and epoch-v2 fixtures in phase 2; every client must pass them byte for byte before release.

## 8. Security review points

* **Rogue device**: someone with the identity signing key can publish a device (and, in phase 2, prekeys) of their
  own. The signed device list makes that visible to the person's other devices and to every member ("sam added a
  device"); it's an active, noisy attack rather than silent reading of history. A rogue device can also ask for
  history sync, so a sync needs the person to approve it on the sending device.
* **Prekey exhaustion / replay**: prekeys are reusable within their lifetime (KEM, not one-time DH), so exhaustion
  isn't an issue; freshness comes from expiry and the wrap's AAD.
* **Server withholding acknowledgements or deleting late**: the server can only delay deletion, never read. Clients
  check that no wraps for them older than the grace period remain (§4.2).
* **A device that never acknowledges holds deletion back** for up to the grace period (7 days): a device on the
  list that's switched off, or a session kept open without a store, keeps the server's wraps for that long. The
  server deletes them at 7 days regardless, and the device list shows when each device was last active, so a
  forgotten one can be removed.
* **Re-wrap or backup paths creeping back**: any later feature (account recovery, admin restore, "sync history from
  backup") that re-creates wraps or backs up the key store breaks §3 and needs a security review before it's built.
* **Size**: a v2 epoch for a full room grows with devices, about 1.7 KB per recipient device (one ML-KEM-1024
  ciphertext, one X25519 key, one AES-GCM wrap), so 8 people with 3 devices each is about 41 KB per key change.

## 9. Alternatives considered

* **MLS (RFC 9420) with a post-quantum ciphersuite**: built for groups, with tree-based forward secrecy and
  post-compromise security; a larger change and a newer, less settled ecosystem for post-quantum suites. Worth
  revisiting for large rooms.
* **A post-quantum ratchet per pair (Signal-style)**: per-message forward secrecy, but a poor fit for room-key
  epochs and multi-device, and much more state.
* **Wrap deletion alone, without prekeys**: adopted as phase 1. It's the cheaper change and removes the stored
  archive, but on its own it leaves the current period and future wraps open to a stolen identity, hence phase 2.

## 10. Decisions for phase 1 (taken)

1. **The web chat** (§6) is an installation; a never-used browser or a private window reads only what history sync
   gives it.
2. **New devices** (§4.4) get history only after approval on an existing device (device codes compared); admins can
   turn history sync off per room.
3. **The history window** (§4.6) defaults to as long as the room keeps messages, with 7, 30, 90 and 365 days.
4. **The grace period** for devices that never acknowledge (§4.2): 7 days.

## 11. Rough plan

1. Done: the no-re-wrap rule is enforced and tested (§3).
2. Done: phase 1 spec (PROTOCOL.md §10) and fixtures (device list, key store, key sync; INTEROP.md).
3. Done: phase 1 server: device list, epoch acknowledgements, wrap deletion with the grace period, per-room history
   policy.
4. Done: phase 1 clients (web, Windows, Android): key store, acknowledgement, history sync, history window; web
   installations; stored v1 wraps are imported into the store on first unlock and then acknowledged; each client
   warns in a room when the server still has wraps for it more than 8 days old (§4.2: the grace period plus a day for
   the server's sweep).
5. Done: interop across all clients (fixtures, plus live flows from Windows and Android) and a pentest of the new
   surface (security/PENTEST-2026-10.md, "protocol 1.1"). Released in 0.2.0 with a migration note.
6. Done (server, `shred.py`, 0.2.0): shredding of old database copies (§4.5), new storage key daily, three
   kept; `test_24`.
7. Done (0.2.0): phase 2 spec (PROTOCOL.md §11) and server (`test_25`); prekey rotation (a new one daily,
   erased at expiry after importing every key still wrapped to it) and v2 epochs with v1 fallback in all three
   clients; v2 sections in the history fixtures, opened by every client; live per-device flows from Windows and
   Android; pentest (security/PENTEST-2026-10.md, "protocol 2"); the apps hand-tested; released in 0.2.0 with a
   migration note (update every app, or rooms stay in compatibility mode).
