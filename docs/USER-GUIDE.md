# CipherChat user guide

CipherChat by DarkCipher Systems: chat, files and calls that only the people in the conversation can read or hear —
not the server, not the network, and not a future quantum computer. Same features on the web, Windows and Android.

## 1. Getting in

Your server's owner (or an admin) invites you; you get a one-time link. Open it, choose a password, and add the
authenticator code it shows to an authenticator app (or your password manager). Then sign in with password + code, or
add a **passkey** (Account → Passkeys: Windows Hello, a phone, a security key, or a password manager such as
Bitwarden) and sign in with that alone.

**Pair** the Windows or Android app with a code from the web chat (`/pair`): the app then signs itself in, chat only,
until you remove it (Settings → Paired devices, or `/devices`).

## 2. Your chat keys

The first time, choose a **chat passphrase** (16+ characters; four or more random words is ideal). It seals your keys
on the server with Argon2id and a server key share, so neither the server nor someone with a copy of its database can
open them. Every device unlocks with the same passphrase. **It can't be recovered**: if you lose it, you start over
with new keys and can't read your old messages.

## 3. Trust: one safety number, once

The owner is the chat's trust anchor. Compare the 60-digit **safety number** with the owner — in person or on a call
you trust, never in the chat or by email — and confirm it. The owner then certifies you after the same comparison.
From then on everyone the owner certified is verified for you automatically. If anything changes (a key the owner
didn't certify, the owner's key itself), you get a warning and those messages are hidden or refused.

## 4. Rooms and messages

* **Rooms** have members and admins; **direct messages** are between two people. Admins add or remove people, rename
  the room and set how long messages are kept (1 day to a year, or until deleted).
* Each room has its own key; it's renewed when people join or leave (so newcomers can't read the past and leavers
  can't read the future), weekly, and on request.
* Reply, react, edit your own messages, delete (yours, or any as an admin). `/me` writes an action line.
* **Files and pictures**: up to 10 per message, 100 MB each, end-to-end encrypted with their own keys.
* **Emoji** show in full colour on every client (Windows' own Fluent emoji in the Windows app, the system's emoji on the
  web and Android), whole sequences included: skin tones, families, keycaps. A message of just one to three emoji
  shows them large. The picker (☺ beside the message box; on Android the smiley inside it) has smileys, people,
  gestures, hearts, animals and nature, food, travel, activities, work and symbols, with search, and the same set on
  every client. Reactions: nine quick ones, or "More reactions…" for the whole picker. Windows has no flag emoji, so
  flags show as their letters there (GB).
* **GIFs** play right in the chat (up to 16 MB; larger ones show a still you can open). Send one like any picture, by
  paste, drop or the **GIF** button (on Android: the paperclip → GIF…): it lists the GIFs of this session (ones you
  sent, ones that played in your rooms) so you can send one back in a click, or choose a GIF file. On Android, the
  keyboard's GIF and sticker buttons (Gboard, SwiftKey, Samsung Keyboard) work too. A GIF is encrypted like any attachment; CipherChat itself uses no GIF search
  service, so nobody else sees what you look for. The session list is kept in memory only and never includes GIFs from
  burn-after-reading messages. GIFs stay still if your system has animations turned off.
* **Text size**: 90% to 200%. Web: the **Aa** button at the bottom right of the terminal, or `/size + / - / 0`.
  Windows: Settings → Text size, or Ctrl+= / Ctrl+- / Ctrl+0. Android: Settings → Text size (on top of Android's own
  font size). Each device remembers its own.
* **Burn after reading** (the flame): the message shows only when opened, for 10 seconds to 5 minutes, then
  disappears from your device; the server deletes it once everyone has read it.
* **Bad connections**: anything you send (messages, files, reactions, edits) goes into an **outbox** first. If the
  connection drops, it waits — shown greyed with "queued" — and sends itself, in order, as soon as the connection is
  back (it retries after 1 s, then up to every 30 s, and at once when the network returns). A send whose answer got
  lost is never duplicated. Something the server refuses for good is marked "not sent" with **Retry** and
  **Discard**. Attachments already uploaded aren't uploaded again. Unsent messages survive locking the app (Android
  and Windows keep them sealed until you unlock); the apps warn you before closing with messages still waiting, and the
  web chat keeps them only while its tab is open.

* **Add-ons** (tagged *add-on*, named `addon.…`) are programs, such as bots: talk to one the way it
  describes, in a room it's in. They only see rooms they were added to and the owner certifies them like
  people. The owner manages them with `/addons` (docs/ADDONS.md).

## 5. Calls

Voice or video, up to 8 people, in any room or direct message. Every audio and video frame is encrypted end to end on
top of the usual call encryption. When someone joins you'll see the **call words** — four words that are the same on
every screen only if nobody is listening in the middle. Read them to each other.

In a call: mute, camera off, choose devices, push-to-talk (hold Space), raise your hand, send a reaction, share your
screen (web and Windows), blur your background where the camera supports it. On Android, video calls keep going in a
small window when you leave the app.

## 6. Keeping it safe

* Lock the app when you leave it (it also locks itself after a while). Locking wipes every key from memory.
* Remove devices you no longer use (Settings → Paired devices).
* If you're warned that a key changed, ask the person (or the owner) on a call before trusting it again.
* The owner: keep the server key backed up offline, keep the server up to date, and certify people only after
  comparing safety numbers.
