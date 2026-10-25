# CipherChat Server for Linux

CipherChat by DarkCipher Systems. Your own post-quantum end-to-end encrypted chat and calls server: the server
(Python standard library), the web chat, and the call relay (coturn), behind nginx.

## Requirements

* Debian 12+ / Ubuntu 22.04+ (or similar with systemd), Python 3.10+, root.
* nginx and coturn — the setup installs them from your distribution if you allow it.
* **For the apps: nginx built with OpenSSL 3.5 or newer**, so TLS can offer X25519MLKEM768 (the Windows and Android
  apps connect only with post-quantum TLS). Browsers work with older OpenSSL. The setup tells you which you have.
* A domain name pointing at the machine (for Let's Encrypt: port 80 reachable) or your own certificate files.
* For calls through NAT: UDP/TCP 3478, TLS 5349 and the relay port range (default 49160–49260) open.

## Install

```sh
tar xzf cipherchat-server-0.1.2-linux.tar.gz
sudo sh cipherchat-server-0.1.2/install.sh
```

`install.sh` first checks every file against `SHA256SUMS` (a damaged or altered download is refused), then asks:

1. **Server** — its name and the owner's username (the chat's trust anchor).
2. **Web server** — CipherChat's own nginx site for its own domain, **or** under `/chat/` on an https site nginx
   already serves (your site's file is backed up and restored byte for byte on uninstall), **or** your own reverse
   proxy (the setup shows what to add).
3. **Certificate** — Let's Encrypt through certbot (renewed automatically), or files you have.
4. **Features** — post-quantum-only TLS (refuses browsers without X25519MLKEM768), the call relay (coturn,
   private networks blocked), the firewall (ufw), nightly backups.

Nothing changes until you confirm the summary. At the end you get the **owner's one-time set-up link**: open it, choose
a password and authenticator, then set up your chat keys. Invite people from **Admin → Users** in the web chat.

Unattended: `sudo sh install.sh --plan plan.json` (`--check` validates only). The plan's fields are in
`deploy/setup/plan.py` (`domain`, `name`, `owner`, `web`, `tls`, `cert`/`key` or `certbot_email` + `agree_le_terms`,
`pq_only`, `turn`, `firewall`, `backups`, `android_apps`, …).

## Running it

| Command | What |
|---|---|
| `sudo cipherchat-admin status` | health, versions, post-quantum TLS check, last backup |
| `sudo cipherchat-admin owner-invite` | a new owner set-up link (lost password or authenticator) |
| `sudo cipherchat-admin backup` | a backup now (`/var/backups/cipherchat`, daily by timer) |
| `sudo cipherchat-admin uninstall [--purge]` | remove it; data kept unless `--purge` |
| `journalctl -u cipherchat` | the server's log (no message content is ever logged) |

**Upgrade**: unpack the new release and run its `install.sh`; it offers "Upgrade to <version>" and keeps every
setting, all data and the server key (`sudo sh install.sh --plan /etc/cipherchat/setup.json` does it unattended with
your saved answers). Before anything changes it:

1. checks the download against its `SHA256SUMS`;
2. refuses a release **older** than the one installed (its code may not understand the database the newer version
   left; `CIPHERCHAT_ALLOW_DOWNGRADE=1` overrides this, after you restore a matching backup);
3. stops the service and copies the database to `/var/backups/cipherchat-upgrades/<time>-<old>-to-<new>/` (root only,
   the newest five kept). The attachments, the server key and the settings aren't changed by an upgrade, so they stay
   where they are.

Then it swaps the program files and starts the new version. If the new version doesn't answer its health check, the
upgrade is **rolled back by itself**: the previous program files and the database copy are put back and the previous
version starts again, and the setup says so. Running the same version again repairs an install.

Where things are: program `/opt/cipherchat` (read-only to the service), settings `/etc/cipherchat/cipherchat.env`,
data `/var/lib/cipherchat`, server key `/etc/cipherchat/server.key` — **back this key up offline**: without it no
sealed identity can be opened. The database backups deliberately don't contain it.

## Options in `/etc/cipherchat/cipherchat.env`

* `CIPHERCHAT_ANDROID_APPS` — lets the Android app use this server's passkeys:
  `systems.darkcipher.cipherchat=<SHA-256 of the app's signing certificate>` (published with each release in
  `android-signing-certificate.sha256`). The server then serves `/.well-known/assetlinks.json`. If CipherChat lives
  inside another site of yours, that site must pass `/.well-known/assetlinks.json` to CipherChat (one `location` line,
  see `deploy/nginx/cipherchat-site-tls.conf`).
* `CIPHERCHAT_CALLS_RELAY_ONLY=1` — call media only through the relay (peers never see each other's addresses).
* Email: set it on the admin page (Email & notifications; docs/ADMIN.md). `CIPHERCHAT_SMTP_*` here are only the
  starting values. Mail goes out through the separate, jailed `cipherchat-mailer` service; the chat server stays
  loopback-only. `CIPHERCHAT_SMTP_ALLOW_PRIVATE=1` allows an SMTP relay on a private address.
* Everything else people need to change day to day (server name, sign-up, password and session policy, lockout,
  attachment size, roles and permissions, notifications) is on the admin page, not in this file.

After editing: `sudo systemctl restart cipherchat`.

## Security

The service runs as its own user in a tight systemd sandbox (no capabilities, read-only system, loopback-only
network, syscall filter, memory limits). Details: SECURITY.md and docs/security/ in the source.
