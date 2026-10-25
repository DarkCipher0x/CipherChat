# CipherChat for Windows

CipherChat by DarkCipher Systems for Windows 10 (2004+) and 11. The same protocol and the same post-quantum principles
as the web chat and the Android app: hybrid ML-KEM-1024 + X25519 key wrapping, ML-DSA-87 + Ed25519 signatures (both
must verify), AES-256-GCM, SHA-3, Argon2id-sealed identity backups, and the server owner as the only trust anchor.
It talks to a CipherChat server (Linux, `/chat/api`).

## Layout

One small project per concern; only the app knows about WPF, and nothing below the app knows about the screen.

| Project | Job |
| --- | --- |
| `src/CipherChat.Crypto` | the protocol's cryptography, a line-by-line port of `android/core/crypto` (no UI, no network): identities, certificates, backups, room keys, messages, attachments, OpenSSL known-answer self-test |
| `src/CipherChat.Transport` | **PQ-only TLS 1.3** (BouncyCastle, X25519MLKEM768 only: a classical-only server is refused) with Windows certificate validation, and a small HTTP/1.1 client over it |
| `src/CipherChat.Api` | the server API: session cookie, CSRF headers, "confirm it's you" (passkey first, then the authenticator code), device sign-in, uploads, long polling |
| `src/CipherChat.Engine` | the chat itself (a port of the web chat's app/gate/trust/messages code): trust decisions, rooms, keys, messages, reactions, edits, burn messages, attachments, set-up / unlock |
| `src/CipherChat.Vault` | what this PC remembers (server, account, paired device token) under DPAPI, plus an optional Windows Hello layer. Never the chat passphrase or chat keys |
| `src/CipherChat.Passkeys` | passkeys through Windows' own WebAuthn API (`webauthn.dll`): Windows Hello, a phone or security key, or a passkey provider such as Bitwarden |
| `src/CipherChat.App` | the WPF app in the DarkCipher Systems theme (`Themes/Theme.xaml`, shared with the other DarkCipher apps; `Themes/Chat.xaml` adds the chat's own pieces) |
| `tests/CipherChat.Crypto.Tests` | self-test, canonical JSON, identities, certificates, backups, rooms, attachments, three-way interop fixtures (`../docs/INTEROP.md`) |
| `tests/CipherChat.Transport.Tests` | refuses classical-only TLS, accepts PQ TLS, certificate and hostname checks; optional live check (`CIPHERCHAT_LIVE_ORIGIN`) |
| `tests/CipherChat.Engine.Tests` | against a real server (`CIPHERCHAT_DEV_*`, skipped otherwise): two people chatting end to end, and passkey sign-in with clone and phishing refusals |
| `tools/make-icon.ps1` | renders the brand mark into `Assets/cipherchat.ico` |

## Build and test

```powershell
dotnet test CipherChat.sln
```

.NET 8 SDK (`global.json`), packages only from nuget.org (`nuget.config` source mapping), every package pinned by
content hash in `packages.lock.json` (`-p:LockedRestore=true` for release builds), NuGet audit on, nullability
warnings are errors. BouncyCastle.Cryptography is pinned to exactly 2.7.0.

Against a development server on loopback or an SSH tunnel (never a public address):

```powershell
CipherChat.exe --dev-server http://localhost:8094
```

## Signing in

- **Pair this PC** (recommended): in the web chat type `/pair`, paste the code here. The PC then signs in on its own,
  chat only, until the pairing is removed; Windows Hello can guard the saved pairing.
- **Passkey**: only the server address. Windows shows its passkey dialog; with Bitwarden (or another provider)
  registered as a Windows passkey provider, the passkey can live in the password manager. Add passkeys on the
  server's Account page.
- **Password and authenticator code**: a one-off session; nothing is remembered.

## Notes

- BouncyCastle's private key objects can't be wiped in place; identities are kept only in memory while unlocked and
  dropped on lock (and after the auto-lock time without activity), like the other clients.
- The JSON parser walks the whole tree on parse, so a duplicate key is a protocol refusal, never a late exception.
- Pasting a file copied in Explorer, or a screenshot, attaches it (encrypted before upload).
