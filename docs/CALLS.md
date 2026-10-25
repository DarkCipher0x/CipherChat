# CipherChat calls: voice and full-HD video, post-quantum end to end

Status: in every release since 0.1.1 (2026-10-25) — web portal, Windows app (WebView2) and Android app (WebView) run the same
call engine (`web/app/call.js`, `callworker.js`, `callcrypto.js`, `callui.js`, `glitch.js`); the apps host it through
`web/callhost/` and keep every private key outside the page. Mac/iOS later on the same rules.

## The problem with "just WebRTC"

WebRTC encrypts media with DTLS-SRTP. Its key exchange is classical (ECDHE) and the browser picks the groups, so a
WebRTC call on its own is **not** post-quantum: a recording of today's call could be decrypted by a future quantum
computer. CipherChat never relies on DTLS-SRTP for confidentiality; it is only the outer transport (and does NAT
traversal). The protection is CipherChat's own layer inside it.

## How a call is protected

1. **Signals.** Ring, accept, decline, busy, offer, answer, ICE, key, state, leave and end are canonical-JSON headers
   signed by the sender's identity (ML-DSA-87 + Ed25519, both must verify; label `dcx-chat/v1/call-signal`), carrying
   the call id, the sender's device id, a random nonce and a time. Receivers accept only signals from identities they
   trust (owner-certified), at most 2 minutes old, never twice (call|device|nonce replay set). The server relays them
   (`server/cipherchat/calls.py`) between members of the room only and can't forge, alter or replay them; the apps send
   them over their post-quantum-only TLS.
2. **Sender keys.** Each device makes a random 256-bit sender key per key epoch and wraps it to every other
   participant's identity with the same hybrid as room keys (ML-KEM-1024 + X25519; AAD binds call, sender, device,
   epoch, recipient and the recipient's fingerprint), inside a signed `key` signal. A new epoch starts whenever
   someone joins or leaves and at least every 10 minutes; the new key goes out first and frames switch to it 400 ms
   later, so nobody drops a frame. No key is made until there is someone to share it with.
3. **Frame encryption.** Every encoded audio and video frame is encrypted in a Worker (`RTCRtpScriptTransform`, or
   Chromium's encoded streams) with AES-256-GCM under a per-link key: HKDF-SHA-512 of the sender key, salted with the
   call id and bound to sender, receiver, epoch and stream (mic / cam / screen). Layout:
   `codec header in clear (VP8 key frame 10 bytes, delta 3, Opus 1) | AES-GCM ciphertext | 12-byte trailer`
   (counter 8 | epoch 1 | stream 1 | clear length 1 | 0xCC); the nonce is the stream id and the counter. Frames are
   authenticated before any freshness check; old or replayed frames (more than 512 behind) are dropped. VP8 is forced
   for video because its packetiser works on encrypted payloads. The TURN relay, the server and the network see only
   ciphertext.
4. **Call words.** Every screen shows four words from SHA3-256 over the call id and every participant's identity
   fingerprint (256-word list, identical in JS, C# and Kotlin). Reading them aloud confirms nobody is in the middle, on
   top of the owner-anchored trust the chat already has.

## Media

- Video: up to 1920×1080 at 30 fps (camera and screen), bitrate and resolution stepped down as more people join;
  screen sharing at 3 Mbit/s keeping resolution. Opus voice with echo cancellation, noise suppression and automatic
  gain (on the device).
- Groups: mesh, up to 8 people; for each pair the device with the lexicographically smaller `user|device` makes the
  offer. Three fixed transceivers (mic, cam, screen) per connection, swapped with `replaceTrack`.
- NAT: the server hands out short-lived TURN credentials (coturn's shared-secret scheme, `calls/turn`) and STUN URLs;
  "relay only" mode sends media only through TURN so peers never learn each other's addresses. The Linux setup
  installs coturn (private networks blocked).
- Rings time out after 45 s; a phone answers from Android's incoming-call notification (CallStyle) or a full-screen
  ring screen, the Windows app from its own ring pop-up.

## Features

| Feature | How |
|---|---|
| Voice and video calls, 1:1 and groups up to 8 | as above |
| Screen sharing (web, Windows) | the same frame encryption, 1080p; hidden where the platform can't share a screen (phones) |
| Call words | spoken verification |
| Connect glitch | when a video connects the picture tears in (RGB split, sliced bands, scanlines) then settles and "ML-KEM-1024 + X25519 · encrypted" types in; ~0.9 s on a 2D canvas; a plain fade for "reduce motion" (`glitch.js`) |
| Mute, camera off, device choice, push-to-talk (hold Space) | on the device |
| Raise hand, emoji reactions | signed `state` signals |
| Background blur | where the camera offers it (`backgroundBlur` constraint), on the device |
| Picture-in-picture (Android video calls) | leaving the app keeps the call in a small window |
| Proximity screen-off (Android voice calls) | the screen goes dark against your ear |
| Move between devices | every device has its own id; "answered on another device" stops the others ringing |

Not built: server-side recording, transcription or anything else that would need the server to see content.

## Tests

`web/tests/calltest.html` (29 checks: interop fixture from Windows, frame format, tamper and replay refusal, 1:1,
extras, screen sharing, a 3-person mesh with joins and leaves and key rotation), `CallTests.cs` (Windows, writes the
interop fixture), `CallAndFileTest.kt` (Android), `server/tests/test_server.py` test 11 and
`server/tests/pentest_server.py` `pt_09` (signals stay inside the room). End to end: web ⇄ Windows and web ⇄ Android
calls in both directions with matching call words and frames decrypted on both sides (2026-10-24).
