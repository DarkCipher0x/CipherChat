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

Devices and history (PROTOCOL.md §10) have their own fixtures, each holding a signed device list, a key-store entry
and the device seed sealed under it, a device code, and a key-sync package to the other client's device (plus a
tampered one that must be refused): `browser-history.json` (made by `web/tests/historytest.html`),
`windows-history.json` (`HistoryInteropTests`) and `phone-history.json` (`HistoryInteropTest`). Each client opens
the other two: `historytest.html` reads them from `web/tests/fixtures/`, Windows and Android from their interop
folders. The full flow (acknowledge and wrap deletion, an approved sync with matching codes, removal wiping the
store) runs against a real local server in `HistoryLiveTests` (Windows) and `HistoryLiveTest` (Android), with the
same `CIPHERCHAT_DEV_*` switches as the other live tests.

Protocol 2 (PROTOCOL.md §11) adds a `v2` section to each history fixture: a signed prekey for each of the two devices,
the seed of the second one's, and a v2 room key (epoch 2) wrapped to both, with the second device's wrap in the item,
the first's beside it and a tampered copy. Each client checks that the prekey verifies and its seed rebuilds to it,
that a prekey of an unlisted device or past its expiry is refused, that the second device opens the room key with its
prekey and the key passes the header's commitment, and that a changed wrap, the other device's wrap, a missing
(erased) prekey and reading the v2 header as a v1 key are all refused. A fixture without the section (made before
protocol 2) is skipped. Live, `NewRoomKeysAreSealedToEachDevicesPrekey` (Windows) and its Android twin seal a key to
three devices' prekeys and check each device gets only its own wrap.

## Results

- 2026-10-24: browser opens phone-made and windows-made (every check true, tamper refused); Android opens
  browser-made and windows-made; Windows opens browser-made and phone-made. All nine directions pass.
- 2026-10-26, devices and history: the browser opens windows-history and phone-history (41/41); Windows opens
  browser-history and phone-history (4/4); Android opens browser-history and windows-history (4/4). The live flow
  passes from Windows and from Android against a local server.
- 2026-10-30, protocol 2: every history fixture has its v2 section; the browser opens windows-history and
  phone-history with theirs (69/69, nothing skipped); Windows and Android open the other two (4/4 each). Both live
  tests (history, per-device keys) pass from Windows and from Android against a local server.
- 2026-10-30, protocol 2 by hand in the web app against a local server, with a Windows engine as the other member:
  the browser publishes its prekey and fetches with its device id; it opens a Windows-made v2 key and the Windows
  engine opens a browser-made one (`/rotate`), both sealed to one device each; after a reload the browser reopens all
  its keys from its own store. With an older-app session holding the other member, the server refuses the browser's
  v2 key and the browser falls back to v1, saying "compatibility mode" in the room.
- 2026-10-30, the same by hand in the Android app on the emulator (debug build, adb reverse): the phone enrols,
  publishes its prekey, opens a Windows-made v2 key, makes one with "Renew the key now" that the Windows engine
  opens, and falls back to v1 with the "compatibility mode" line while an older-app session holds the other member.
- 2026-10-30, after the sweep fixes: a room made right after a new device unlocks gets a v2 key on every client (the
  live per-device test no longer publishes prekeys by hand); fixtures as before (69/69, 4/4, 4/4), both live tests
  pass from Windows and from Android, and no test session is left signed in.
- 2026-10-30, key history across devices (P-6): "New key now" pressed by hand as a plain member in the Windows app
  made a v2 key sealed to all three devices, which showed the bug (its `prev` was empty, since that PC never got the
  key before it). After the fix, a browser signed in as a new device that holds none of the earlier keys renews the
  key with `/rotate` and the new key links to the one before it; the live per-device test checks the same from a
  third Windows PC and a third Android device. Fixtures as before (browser 75/75 with the new header checks, 4/4, 4/4).
- 2026-10-30, a 0.1.2 Windows engine (built from the 0.1.2 source) against this server, signed in as a member of a
  room whose key is per-device: it shows that key as "not for you" and the message under it as "wasn't made for you".
  Once its session counts as an older app, the room asks for a new key; the owner's next message comes with a
  compatibility key, which the 0.1.2 engine opens and reads, and the message after that needs no further key (P-7).
