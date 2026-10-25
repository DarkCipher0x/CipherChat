# Running a CipherChat server: the admin page

Everything here is at `/chat/admin/` and shows only the parts your permissions cover. Every change is checked by the
server (never trust the page), needs a fresh authenticator code (or a passkey), and is written to the tamper-evident
audit log. Nothing on the admin page can read anyone's messages: they're end-to-end encrypted.

## Permissions

Each permission is one switch:

| Group | Permission | Lets someone |
|---|---|---|
| Chat | `chat.access.use` | use the chat at all |
| | `chat.rooms.create` | create private rooms |
| | `chat.dm.start` | start direct messages (anyone can answer one) |
| | `chat.files.send` | send files, pictures and videos |
| | `chat.calls.start` | start voice and video calls (anyone can answer one) |
| | `chat.devices.pair` | pair the CipherChat apps to their account |
| Administration | `admin.requests.review` | review access requests |
| | `admin.users.view` | see people and their access |
| | `admin.users.create` | invite people |
| | `admin.users.update` | suspend, reactivate, sign people out, send reset links |
| | `admin.users.delete` | delete accounts |
| | `admin.users.roles` | change people's roles and permissions |
| | `admin.roles.manage` | create and edit roles |
| | `admin.audit.view` | read the audit log |
| | `admin.settings.manage` | change server settings |
| | `admin.mail.manage` | set up email and notifications |

A **role** is a named set of permissions. Built in: **guest** (chat, DMs, files, calls, apps; no rooms), **member**
(guest + create rooms) and **admin** (everything except managing roles). Anyone with `admin.roles.manage` can create more
roles (say *moderator*, or *read-only auditor*) and edit the built-in ones' permissions. On top of their role, a person
can be given (**always**) or refused (**never**) single permissions on the People page.

**Rules that can't be switched off:**
* Nobody can give a permission they don't hold, put it in a role, or give someone a role with it.
* You can only change accounts with **fewer** permissions than you have, so equals can't lock each other out and nobody
  can touch someone more powerful. Nobody edits their own permissions.
* Some things aren't permissions at all: only the **owner** certifies identities, manages add-ons, and can't be
  changed by anyone. The owner holds every permission.

All rooms are **private**: only the people added can see or read a room (its key is made for them alone).

## Settings

| Setting | Default | |
|---|---|---|
| Server name | the installer's | page titles, emails, authenticator app entries |
| Access requests | on | the public "request access" page; and which role an approved request gets |
| Shortest password | 14 | 12-128 characters |
| "Confirm it's you" | 10 min | how long a fresh authenticator code counts for sensitive steps |
| Sign-ins last | 12 h | then sign in again; and idle sign-out after 120 min |
| Lockout | 5 tries, 15 min | failed sign-ins before an account is locked, and for how long |
| Invite/reset links | 72 h | how long one-time links work |
| Largest attachment | 100 MB | 1-100 |

## Email and notifications

**SMTP:** server, port, STARTTLS or TLS (plain SMTP is never used, and certificates are always verified), username,
password, From address and name, Reply-To. The password is **sealed** on the server (SHAKE256 and HMAC-SHA3-256 under a
key derived from the server key file, which never goes in the database or its backups) and is never shown again. **Send a
test email** to check, and the **Delivery** list shows what was sent, retried or failed (addresses masked).

The SMTP server must have a public address, so the mail settings can't be used to reach machines inside your network
(`CIPHERCHAT_SMTP_ALLOW_PRIVATE=1` in the environment file allows a private relay). On Linux, email is sent by its own
jailed service, `cipherchat-mailer`: the only CipherChat process allowed out to the internet, with no listening sockets.
The chat server itself stays loopback-only. Queued emails are sealed too, since they can carry one-time links.

**Notifications** (each on or off; to the admins it concerns, to the person it's about, and up to 5 extra addresses):

| Event | Default | "Admins" means people with |
|---|---|---|
| Someone asked for access | on, admins | `admin.requests.review` |
| Someone finished setting up their account | off | `admin.users.view` |
| An account was locked after failed sign-ins | on, admins + the person | `admin.users.update` |
| An app was paired to an account | on, the person | `admin.users.update` |
| A password was changed | on, the person | `admin.users.update` |
| Someone's role, permissions or status changed | on, the person | `admin.users.roles` |

Notifications never contain messages (the server can't read them anyway).
