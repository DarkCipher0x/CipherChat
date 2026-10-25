# CipherChat for Android

CipherChat by DarkCipher Systems for Android 12 and later. Chat, files and HD voice and video calls with your own
CipherChat server, post-quantum end to end; the phone talks to the server only over TLS 1.3 with X25519MLKEM768.

## Install

Download `CipherChat-0.1.1.apk` and check it:

* SHA-256 of the file: in `CipherChat-0.1.1.apk.sha256` (and `SHA256SUMS`);
* signing certificate SHA-256 `836CC51C98A1F3175A7AECE2B5A8C6779E90908F116042F6E9122C6D164C02F5`
  (`apksigner verify --print-certs CipherChat-0.1.1.apk`). Every future update is signed with the same key; Android
  refuses an update signed by anyone else.

Allow "Install unknown apps" for your browser or file manager when asked.

## First start

1. **Set up / Unlock** — the app keeps its pairings in a vault opened by your fingerprint (or face, if it's Class 3)
   or your screen lock, every time. The key lives in the phone's secure hardware (StrongBox where present) and is
   destroyed if someone enrols a new fingerprint. A screen lock is required.
2. **Connect** — scan or paste a **pairing code** (web chat: type `/pair`; it works once), sign in with your password
   and authenticator code, or **sign in with a passkey** (the phone's own, or one in a password manager such as
   Bitwarden — see "Passkeys" below). Pairing remembers the server; signing in doesn't.
3. **Your chat keys** — first time: choose a chat passphrase (16+ characters; a few random words). After that, the
   passphrase unlocks your keys on the phone. It's never stored or sent.
4. **Verify the owner** — compare the 60-digit safety number with your server's owner in person or on a call, tick
   "the numbers are the same", and tap **Trust the owner**.

## Using it

Rooms and direct messages; long-press a message to react, reply, copy, edit (yours) or delete; the paperclip attaches
files and pictures (up to 10, 100 MB each; pictures get an encrypted preview); the flame sends **burn after reading**
(10 s to 5 min after it's opened). The phone and camera icons start a voice or video call; the call screen shows the
four **call words** — read them aloud with the other side. `/me`, `/call` and `/video` work in the message box.

People shows who you can trust and why; the owner certifies people there after comparing safety numbers. Room info
shows members, the current room key, and (for admins) members, name, topic and how long messages are kept.

## Background, notifications and calls

While the chat is unlocked a small "CipherChat is unlocked" notification keeps the connection to your server open, so
messages and calls arrive. There is no push service: nothing passes through Google or anyone else. Notifications say
only "New encrypted message" — never the text.

Incoming calls ring with Android's call notification (Answer / Decline). To have them ring **full screen over the lock
screen** on Android 14+, open Settings → Calls → **Allow full-screen calls**. Video calls continue in a small window
when you leave the app; voice calls turn the screen off against your ear.

**Auto-lock:** after you leave the app for the chosen time (Settings → Lock: 1 min to 4 h, default 15 min; never
during a call) every key is wiped and the vault needs your fingerprint again.

## Passkeys

Android's Credential Manager signs passkey requests with the app's identity, so the server must vouch for the app.
The server owner adds the app's certificate:

* Linux: `CIPHERCHAT_ANDROID_APPS=systems.darkcipher.cipherchat=83:6C:C5:1C:98:A1:F3:17:5A:7A:EC:E2:B5:A8:C6:77:9E:90:90:8F:11:60:42:F6:E9:12:2C:6D:16:4C:02:F5`
  in `/etc/cipherchat/cipherchat.env`, then `sudo systemctl restart cipherchat`.

The server then publishes `https://<your server>/.well-known/assetlinks.json` and accepts the app's passkeys. Add a
passkey from the web chat (Account → Passkeys) or any signed-in client; it then works on the phone too.

## Privacy and security

No backups or device-to-device transfer of app data; screenshots and the recents preview are blocked; the app only
needs the camera and microphone during calls and asks for them then. Source: `android/` (modules in
`settings.gradle.kts`); security design: `docs/security/SECURITY-DESIGN.md`.

## Building

```powershell
cd android
. .\tools\env.ps1                                   # JDK 21 + Android SDK paths
.\gradlew.bat :core:crypto:test :core:client:test   # host tests (live server tests need CIPHERCHAT_DEV_*)
powershell -File tools\release.ps1                  # tests, lint, signed R8 release -> dist\<version>\
```
