# Cross-client interop checks

Three independent clients speak the DarkCipher chat protocol, and each one must open what the other two make,
byte for byte:

| Client | Crypto | Where |
| --- | --- | --- |
| Web chat | `@noble/post-quantum`, `@noble/hashes` + the browser's WebCrypto | `web/app/crypto.js` |
| Android | BouncyCastle Java 1.86 (pinned in `gradle/verification-metadata.xml`) | `android/core/crypto` |
| Windows | BouncyCastle .NET 2.7.0 (pinned in `packages.lock.json`) + Windows' AES-GCM | `windows/src/CipherChat.Crypto` |

All three also check themselves against the same OpenSSL 3.5 known answers (`kat.js`, `Kat.kt`, `Kat.cs`, one source).

## The fixtures

Each fixture holds two master secrets and, made from them: both published identities, a certificate, the safety
number, a sealed backup (Argon2id + server key share), a room key wrapped for alice, and a message under it. The
other clients re-derive the identities and must get identical bytes, then verify, unseal, unwrap and open everything.

| Fixture | Made by | Lives in |
| --- | --- | --- |
| `browser-made.json` | the real crypto.js in a browser | `android/core/crypto/src/test/resources/interop/` |
| `phone-made.json` | `InteropTest.phoneMakesAFixtureForTheBrowser` (Android, regenerated on every test run) | same folder |
| `windows-made.json` | `InteropTests.WindowsMakesAFixtureForTheOthers` (writes `windows/tests/CipherChat.Crypto.Tests/interop/`) | copy it into the Android folder above |

Fixtures hold fresh random bytes every time they're made, so ordinary test runs write the new ones into the build
output (`bin/.../made/`, `android/core/crypto/build/interop-made/`) and the committed files only change on purpose:
set `CIPHERCHAT_WRITE_FIXTURES=1` for that run, then check the result with the release's privacy scan before
committing (random base64 can contain any word by chance).

## Running them

```powershell
# Windows: opens browser-made + phone-made, writes windows-made
cd windows; dotnet test CipherChat.sln
copy tests\CipherChat.Crypto.Tests\interop\windows-made.json ..\android\core\crypto\src\test\resources\interop\

# Android: opens browser-made + windows-made, writes phone-made
cd android; . .\tools\env.ps1; .\gradlew.bat :core:crypto:test
```

Browser side: serve `web/` on 127.0.0.1 (any static server), open `/app/selftest.html` (the OpenSSL known answers),
then in the console fetch each fixture and run `identityFromMaster`, `publishIdentity`, `openIdentity`, `verifyCert`,
`safetyNumber`, `openBackup`, `openEpoch`, `openMessage` from `/app/crypto.js`, plus one tampered ciphertext that must
be refused. Calls have their own fixture (`windows-call.json`, checked by `web/tests/calltest.html` and
`CallAndFileTest.kt`); attachments too (`browser-files.json`, `windows-files.json`).

## Results

- 2026-10-24: browser opens phone-made and windows-made (every check true, tamper refused); Android opens
  browser-made and windows-made; Windows opens browser-made and phone-made. All nine directions pass.
