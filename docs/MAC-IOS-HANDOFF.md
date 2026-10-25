# Mac and iOS: hand-off notes

For building CipherChat for macOS and iOS later (on an Apple Silicon Mac with Xcode). Everything here is what the
existing clients already do; a Swift client must match it byte for byte.

## What to port

| Piece | Reference implementation | Notes for Apple platforms |
|---|---|---|
| Protocol crypto | `android/core/crypto` (Kotlin, ~800 lines) or `windows/src/CipherChat.Crypto` | ML-KEM-1024 and ML-DSA-87: Apple CryptoKit has ML-KEM and ML-DSA from iOS/macOS 26 (check `MLKEM1024`, `MLDSA87`); otherwise liboqs or a vetted Swift package. X25519/Ed25519, AES-GCM, HKDF (SHA-512) and SHA-3: CryptoKit has the first three; SHA-3 needs CryptoKit 26+ or a small Keccak. Argon2id: libsodium (`crypto_pwhash` with ALG_ARGON2ID13, 64 MiB, 3 passes) — check it equals the fixtures |
| Interop proof | `android/core/crypto/src/test/resources/interop/*.json`, docs/INTEROP.md | open `browser-made`, `phone-made`, `windows-made`, the file and call fixtures; write `apple-made.json` for the others to open |
| Known-answer self-test | `Kat.kt` / `kat.js` (OpenSSL 3.5 vectors) | run at launch; refuse to work if it fails |
| PQ-only TLS | `android/core/client/Transport.kt` | `Network.framework` with `sec_protocol_options` set to TLS 1.3 and the X25519MLKEM768 group only (iOS/macOS 26 offer it), then verify the negotiated group; else a BoringSSL/OpenSSL 3.5 build. Never fall back to classical groups |
| API, trust, chat engine | `android/core/client` (ChatApi, Trust, Gate, ChatEngine, Calls) — a direct port of the Windows engine | async/await maps 1:1 to the Kotlin suspend functions |
| Calls | `web/callhost/` + `web/app/call*.js` in a `WKWebView` | serve the files with a `WKURLSchemeHandler` (`cipherchat-call://`), talk through `WKScriptMessageHandler` limited to the same operations as `CallBridge.kt` (seal, open, wrapKey, unwrapKey, words, calls/signal, calls/turn). Check `RTCRtpScriptTransform` in WKWebView (Safari supports it) |
| Vault | `android/core/security/Vault.kt` | Keychain item with `kSecAttrAccessControl` = `.biometryCurrentSet` or `.userPresence`, Secure Enclave key wrapping the data key; `ThisDeviceOnly` |
| Passkeys | `Passkeys.kt` | `ASAuthorizationPlatformPublicKeyCredentialProvider`; the server needs `/.well-known/apple-app-site-association` with `webcredentials` — add an `CIPHERCHAT_APPLE_APPS` setting beside `CIPHERCHAT_ANDROID_APPS` (`passkeys.py`) |
| Notifications / ringing | `ChatService.kt` | no background socket on iOS: either CallKit + VoIP push (needs a push relay that carries **no content** — only "wake up") or polling while foregrounded. Decide before building |

## Rules the port must keep

Hybrid everywhere (both signature halves must verify); canonical JSON exactly; keys only in memory between unlock and
lock; no message text in notifications; screenshots blocked where the platform allows; owner-anchored trust with the
safety number; pinned dependencies with hashes; brand "CipherChat by DarkCipher Systems", the DarkCipher theme
(teal on near-black, the terminal look; see `android/core/designsystem`).
