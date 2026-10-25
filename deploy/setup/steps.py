"""What the setup does, step by step. Nothing here asks questions: it carries out a checked Plan and reports each step.
Every step can run again safely (re-running the setup repairs or reconfigures). The server key is created once and
never overwritten; data is never deleted except by `uninstall --purge`."""
import datetime
import grp
import json
import os
import pwd
import re
import secrets
import shutil
import subprocess
import time
import urllib.request

import nginxconf
from probe import version_at_least as probe_version_at_least

OPT = "/opt/cipherchat"
ETC = "/etc/cipherchat"
ENV = ETC + "/cipherchat.env"
KEY = ETC + "/server.key"
SAVED_PLAN = ETC + "/setup.json"
STATE = "/var/lib/cipherchat"
UNIT = "/etc/systemd/system/cipherchat.service"
MAILER_UNIT = "/etc/systemd/system/cipherchat-mailer.service"
BACKUP_UNIT = "/etc/systemd/system/cipherchat-backup.service"
BACKUP_TIMER = "/etc/systemd/system/cipherchat-backup.timer"
SNAPSHOTS = "/var/backups/cipherchat-upgrades"        # database copies taken before each upgrade (root only, newest 5)
ADMIN = "/usr/local/sbin/cipherchat-admin"
NGINX_HTTP = "/etc/nginx/conf.d/cipherchat.conf"
SNIPPETS = "/etc/nginx/snippets"
SITE_AVAILABLE = "/etc/nginx/sites-available/cipherchat.conf"
SITE_ENABLED = "/etc/nginx/sites-enabled/cipherchat.conf"
SITE_CONFD = "/etc/nginx/conf.d/cipherchat-site.conf"
ACME_ROOT = "/var/www/letsencrypt"
RENEW_HOOK = "/etc/letsencrypt/renewal-hooks/deploy/cipherchat-reload-nginx"
TURN_CONF = "/etc/turnserver.conf"
TURN_CERTS = "/etc/coturn/certs"
TURN_SECRET = ETC + "/turn-secret"
TURN_HOOK = "/etc/letsencrypt/renewal-hooks/deploy/cipherchat-coturn"
TURN_ORIG = "/var/lib/cipherchat-setup/turnserver.conf.orig"
TURN_MARK = "# CipherChat by DarkCipher Systems: coturn"
TURN_JAIL = "/etc/systemd/system/coturn.service.d/cipherchat-hardening.conf"
# coturn only relays already-encrypted call media (DTLS-SRTP plus CipherChat's own post-quantum frame encryption), but
# it faces the internet, so it runs jailed like the chat server: no privileges, read-only system, its own temp and
# devices, a syscall filter, IPv4/IPv6/unix sockets only.
TURN_JAIL_TEXT = """# CipherChat by DarkCipher Systems: coturn sandbox (removed by `install.sh uninstall`)
[Service]
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
PrivateTmp=true
PrivateDevices=true
PrivateIPC=true
ProtectSystem=strict
ReadWritePaths=-/var/lib/turn -/var/run/turnserver -/run/turnserver
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount @debug
SystemCallErrorNumber=EPERM
UMask=0077
LimitNOFILE=65536
MemoryMax=512M
"""
LOG = "/var/log/cipherchat-setup.log"
USER = "cipherchat"


class StepFailed(Exception):
    pass


def log(text):
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write("%s %s\n" % (datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), text))


def run(cmd, check=True, **kw):
    log("+ " + " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.stdout.strip() or r.stderr.strip():
        log((r.stdout + r.stderr).strip()[-4000:])
    if check and r.returncode != 0:
        raise StepFailed("%s failed:\n%s" % (cmd[0], (r.stderr or r.stdout).strip()[-1200:]))
    return r


def release_version(src):
    with open(os.path.join(src, "server", "cipherchat", "server.py"), encoding="utf-8") as f:
        return re.search(r'^VERSION = "([^"]+)"', f.read(), re.M).group(1)


def write(path, text, mode=0o644, owner=None):
    tmp = path + ".cipherchat-new"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, mode)
    if owner:
        os.chown(tmp, pwd.getpwnam(owner[0]).pw_uid if owner[0] != "root" else 0, grp.getgrnam(owner[1]).gr_gid)
    os.replace(tmp, path)


def template(src, name, **values):
    with open(os.path.join(src, "deploy", name), encoding="utf-8") as f:
        text = f.read()
    for k, v in values.items():
        text = text.replace("@%s@" % k, str(v))
    return text


def env_with(text, values):
    """The env file with these keys set (replacing their lines, or appended), every other line as it was."""
    lines = text.splitlines()
    for k, v in values.items():
        line = "%s=%s" % (k, v)
        for i, l in enumerate(lines):
            if re.match(r"\s*%s=" % k, l):            # commented-out examples stay as they are
                lines[i] = line
                break
        else:
            lines.append(line)
    return "\n".join(lines) + "\n"


def owner_active(owner):
    """True once the owner has finished setting up (a set-up link would reset their password and authenticator)."""
    import sqlite3
    db = os.path.join(STATE, "cipherchat.db")
    if not os.path.exists(db):
        return False
    try:
        c = sqlite3.connect("file:%s?mode=ro" % db, uri=True, timeout=5)
        try:
            row = c.execute("SELECT status FROM accounts WHERE username=?", (owner,)).fetchone()
        finally:
            c.close()
    except sqlite3.Error:
        return True                                   # unsure: never reset
    return bool(row) and row[0] != "pending"


def health(port, tries=60):
    for _ in range(tries):
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d/healthz" % port, timeout=2) as r:
                return json.loads(r.read().decode())
        except (OSError, ValueError):
            time.sleep(0.5)
    return None


def _group_exists(name):
    try:
        grp.getgrnam(name)
        return True
    except KeyError:
        return False


def turn_urls(p):
    """The relay addresses the server hands out: TLS on 5349 (when there's a certificate) and plain on 3478."""
    return ["turns:%s:5349?transport=tcp" % p.domain, "turn:%s:3478?transport=udp" % p.domain, "turn:%s:3478?transport=tcp" % p.domain]


def remove_relay():
    """Stop coturn and put back the configuration it had before CipherChat's setup (or none)."""
    run(["systemctl", "disable", "--now", "--quiet", "coturn"], check=False)
    if os.path.exists(TURN_ORIG):
        shutil.copy2(TURN_ORIG, TURN_CONF)
        os.remove(TURN_ORIG)
    elif os.path.exists(TURN_CONF):
        os.remove(TURN_CONF)
    for f in (os.path.join(TURN_CERTS, "cipherchat.crt"), os.path.join(TURN_CERTS, "cipherchat.key"), TURN_HOOK, TURN_JAIL):
        if os.path.exists(f):
            os.remove(f)
    run(["systemctl", "daemon-reload"], check=False)
    return "coturn stopped, its earlier configuration put back"


def stale_nginx(files, keep_site, keep_merge):
    """The changes that take out CipherChat's nginx pieces from an earlier choice: its own site (unless keep_site) and
    its marked lines in any site but keep_merge (a path). {path: new text, or None to delete}."""
    out = {}
    if not keep_site:
        for f in (SITE_ENABLED, SITE_AVAILABLE, SITE_CONFD):
            if os.path.lexists(f):
                out[f] = None
    for path, dumped in files.items():
        if nginxconf.MARK_BEGIN in dumped and os.path.isfile(path) and (keep_merge is None or os.path.realpath(path) != os.path.realpath(keep_merge)):
            with open(path, encoding="utf-8", errors="surrogateescape") as f:     # the file itself: nginx -T pads its copy
                out[path] = nginxconf.without_include(f.read())
    return out


# ------------------------------------------------------------------ the steps
class Installer:
    def __init__(self, plan, facts, src, rep):
        self.plan, self.facts, self.src, self.rep = plan, facts, src, rep
        self.version = release_version(src)
        self.result = {}

    def do(self, title, fn):
        self.rep.step(title)
        log("== " + title)
        try:
            detail = fn()
        except Exception as e:
            self.rep.fail(e)
            log("FAIL: %s" % e)
            raise StepFailed(str(e)) from None
        self.rep.done(detail or "")

    def all(self):
        p = self.plan
        upgrading = bool(self.facts.installed)
        if upgrading:
            self.do("Version", self.version_check)
            self.do("Snapshot before upgrade", self.snapshot)
        if p.install_packages:
            self.do("Packages", self.packages)
        self.do("Service account", self.account)
        self.do("Program files", self.files)
        self.do("Settings", self.settings)
        self.do("Server key", self.server_key)
        try:
            self.do("Service", self.service)
        except StepFailed as e:
            # The new version didn't come up: put the previous program and database back and start it again
            if not (upgrading and self.result.get("snapshot")):
                raise
            self.do("Roll back to " + self.facts.installed, self.rollback)
            raise StepFailed("%s didn't start (%s), so the upgrade was rolled back: %s is running again with the data it had. "
                             "Nothing else was changed." % (self.version, e, self.facts.installed)) from None
        if p.web == "site":
            self.do("nginx site for " + p.domain, self.nginx_site)
        elif p.web == "merge":
            self.do("CipherChat in " + (p.merge_name or p.merge_file), self.nginx_merge)
        else:
            stale = stale_nginx(nginxconf.dump(), keep_site=False, keep_merge=None) if shutil.which("nginx") else {}
            if stale:
                self.do("Remove CipherChat from nginx (an earlier choice)", lambda: (nginxconf.apply(stale), nginxconf.reload()) and "done")
            self.rep.skip("nginx", "your own reverse proxy (instructions below)")
        if p.turn:
            self.do("Call relay (coturn)", self.relay)
        else:
            self.disable_relay()
        if p.web == "site" and p.firewall:
            if self.facts.ufw_active:
                self.do("Firewall", self.firewall)
            else:
                self.rep.skip("Firewall", "ufw isn't active")
        if p.backups:
            self.do("Daily backups", self.backups)
        else:
            self.disable_backups()
        if p.web != "proxy":
            self.do("Post-quantum TLS check", self.verify)
        self.save_plan()
        if p.owner_link:
            self.do("Owner set-up link", self.owner_link)
        return self.result

    def packages(self):
        want = []
        if self.plan.web != "proxy" and not self.facts.nginx:
            want.append("nginx")
        if self.plan.web == "site" and self.plan.tls == "certbot" and not self.facts.certbot:
            want.append("certbot")
        if self.plan.turn and not shutil.which("turnserver"):
            want.append("coturn")
        if not want:
            return "nothing missing"
        run(["apt-get", "update", "-q"], env=dict(os.environ, DEBIAN_FRONTEND="noninteractive"))
        run(["apt-get", "install", "-y", "-q"] + want, env=dict(os.environ, DEBIAN_FRONTEND="noninteractive"))
        return "installed " + ", ".join(want)

    # ---- upgrades: version check, snapshot, rollback
    def version_check(self):
        have, new = self.facts.installed, self.version
        if not probe_version_at_least(new, have):
            if os.environ.get("CIPHERCHAT_ALLOW_DOWNGRADE") != "1":
                raise StepFailed("%s is installed and this release is %s. The database may already be in %s's format, so an "
                                 "older release isn't installed over it (set CIPHERCHAT_ALLOW_DOWNGRADE=1 to do it anyway, "
                                 "after restoring a matching backup)." % (have, new, have))
            return "%s over %s: downgrade allowed by CIPHERCHAT_ALLOW_DOWNGRADE=1" % (new, have)
        return ("%s again (repair)" % new) if new == have else ("%s -> %s" % (have, new))

    def snapshot(self):
        """Stops the service and copies the database (the only thing a new version changes when it starts) to a root-only
        folder, so a failed upgrade can be undone. Attachments are write-once ciphertext and the server key and settings
        are kept as they are, so they aren't copied."""
        run(["systemctl", "stop", "cipherchat-mailer", "cipherchat"], check=False)
        db = os.path.join(STATE, "cipherchat.db")
        if not os.path.exists(db):
            return "no database yet"
        os.makedirs(SNAPSHOTS, mode=0o700, exist_ok=True)
        os.chown(SNAPSHOTS, 0, 0); os.chmod(SNAPSHOTS, 0o700)
        name = "%s-%s-to-%s" % (datetime.datetime.now().strftime("%Y%m%d-%H%M%S"), self.facts.installed, self.version)
        dst = os.path.join(SNAPSHOTS, name)
        os.makedirs(dst, mode=0o700)
        import sqlite3
        src_c, dst_c = sqlite3.connect(db), sqlite3.connect(os.path.join(dst, "cipherchat.db"))
        try:
            src_c.backup(dst_c)
        finally:
            dst_c.close(); src_c.close()
        os.chmod(os.path.join(dst, "cipherchat.db"), 0o600)
        for old in sorted(os.listdir(SNAPSHOTS))[:-5]:               # the newest five are kept
            shutil.rmtree(os.path.join(SNAPSHOTS, old), ignore_errors=True)
        self.result["snapshot"] = dst
        return dst

    def rollback(self):
        run(["systemctl", "stop", "cipherchat-mailer", "cipherchat"], check=False)
        for part in ("server", "web", "setup"):
            cur, old = os.path.join(OPT, part), os.path.join(OPT, part + ".old")
            if os.path.isdir(old):
                shutil.rmtree(cur, ignore_errors=True)
                os.rename(old, cur)
        write(os.path.join(OPT, "VERSION"), self.facts.installed + "\n")
        db = os.path.join(STATE, "cipherchat.db")
        for extra in ("-wal", "-shm"):
            if os.path.exists(db + extra):
                os.remove(db + extra)
        shutil.copy2(os.path.join(self.result["snapshot"], "cipherchat.db"), db)
        u = pwd.getpwnam(USER)
        os.chown(db, u.pw_uid, u.pw_gid); os.chmod(db, 0o600)
        run(["systemctl", "restart", "cipherchat"])
        run(["systemctl", "restart", "cipherchat-mailer"], check=False)
        h = health(self.plan.port)
        if not h:
            raise StepFailed("the previous version didn't start either; the database snapshot is in %s" % self.result["snapshot"])
        return "%s running again (database from %s)" % (h.get("version", "?"), self.result["snapshot"])

    def account(self):
        try:
            pwd.getpwnam(USER)
            return "%s (already there)" % USER
        except KeyError:
            run(["useradd", "--system", "--home-dir", STATE, "--shell", "/usr/sbin/nologin", "--user-group", USER])
            return "created %s (no login, no shell)" % USER

    def files(self):
        os.makedirs(OPT, mode=0o755, exist_ok=True)
        for part in ("server", "web", "setup"):
            new, cur, old = os.path.join(OPT, part + ".new"), os.path.join(OPT, part), os.path.join(OPT, part + ".old")
            shutil.rmtree(new, ignore_errors=True)
            shutil.copytree(os.path.join(self.src, "deploy", "setup") if part == "setup" else os.path.join(self.src, part), new,
                            ignore=shutil.ignore_patterns("__pycache__", "tests", "*.pyc"))
            for root, dirs, names in os.walk(new):
                os.chown(root, 0, 0); os.chmod(root, 0o755)
                for n in names:
                    fp = os.path.join(root, n)
                    os.chown(fp, 0, 0); os.chmod(fp, 0o644)
            shutil.rmtree(old, ignore_errors=True)
            if os.path.isdir(cur):
                os.rename(cur, old)
            os.rename(new, cur)
        shutil.copytree(os.path.join(self.src, "deploy"), os.path.join(OPT, "deploy.new"), ignore=shutil.ignore_patterns("setup", "__pycache__"))
        shutil.rmtree(os.path.join(OPT, "deploy"), ignore_errors=True)
        os.rename(os.path.join(OPT, "deploy.new"), os.path.join(OPT, "deploy"))
        write(os.path.join(OPT, "VERSION"), self.version + "\n")
        with open(os.path.join(self.src, "deploy", "cipherchat-admin"), encoding="utf-8") as f:
            write(ADMIN, f.read(), 0o755)
        return "%s in %s (root-owned, read-only to the service)" % (self.version, OPT)

    def settings(self):
        p = self.plan
        os.makedirs(ETC, mode=0o750, exist_ok=True)
        os.chown(ETC, 0, grp.getgrnam(USER).gr_gid); os.chmod(ETC, 0o750)
        existing = open(ENV, encoding="utf-8").read() if os.path.exists(ENV) else template(self.src, "cipherchat.env.example")
        turn = {"CIPHERCHAT_TURN_URLS": ",".join(turn_urls(p)), "CIPHERCHAT_TURN_SECRET_FILE": TURN_SECRET} if p.turn else \
               {"CIPHERCHAT_TURN_URLS": "", "CIPHERCHAT_TURN_SECRET_FILE": ""}
        values = {**turn, "CIPHERCHAT_ORIGIN": p.origin, "CIPHERCHAT_NAME": '"%s"' % p.name.replace('"', "'"), "CIPHERCHAT_OWNER": p.owner,
                  "CIPHERCHAT_LISTEN": "127.0.0.1:%d" % p.port, "CIPHERCHAT_STATE_DIR": STATE, "CIPHERCHAT_KEY_FILE": KEY,
                  "CIPHERCHAT_WEB_DIR": OPT + "/web", "CIPHERCHAT_TRUST_PROXY": "1", "CIPHERCHAT_ANDROID_APPS": p.android_apps,
                  "CIPHERCHAT_MAILER": "separate"}
        write(ENV, env_with(existing, values), 0o640, ("root", USER))
        return ENV

    def server_key(self):
        if os.path.exists(KEY):
            os.chown(KEY, 0, grp.getgrnam(USER).gr_gid); os.chmod(KEY, 0o640)
            return "kept the existing key"
        old = os.umask(0o077)
        try:
            fd = os.open(KEY, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write("1 %s\n" % secrets.token_hex(32))
        finally:
            os.umask(old)
        os.chown(KEY, 0, grp.getgrnam(USER).gr_gid); os.chmod(KEY, 0o640)
        self.result["new_key"] = True
        return "created %s (back it up offline)" % KEY

    def service(self):
        write(UNIT, template(self.src, "cipherchat.service"))
        write(MAILER_UNIT, template(self.src, "cipherchat-mailer.service"))
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "enable", "--quiet", "cipherchat"])
        run(["systemctl", "enable", "--quiet", "cipherchat-mailer"])
        run(["systemctl", "restart", "cipherchat"])
        run(["systemctl", "restart", "cipherchat-mailer"])
        h = health(self.plan.port)
        if not h:
            raise StepFailed("The server didn't answer on 127.0.0.1:%d. See: journalctl -u cipherchat -n 50" % self.plan.port)
        return "running %s, sandboxed, on 127.0.0.1:%d" % (h.get("version", "?"), self.plan.port)

    # ---- nginx
    def _shared_nginx(self, files):
        main = files.get("/etc/nginx/nginx.conf", "")
        if not re.search(r"^\s*include\s+/etc/nginx/conf\.d/\*\.conf\s*;", main, re.M):
            raise StepFailed("nginx.conf doesn't include /etc/nginx/conf.d/*.conf in its http block, where CipherChat's "
                             "rate limits and upstream go. Add `include /etc/nginx/conf.d/*.conf;` there and run the setup again.")
        os.makedirs(SNIPPETS, exist_ok=True)
        return {
            NGINX_HTTP: template(self.src, "nginx/cipherchat-http.conf", PORT=self.plan.port),
            SNIPPETS + "/cipherchat-locations.conf": template(self.src, "nginx/cipherchat-locations.conf"),
            SNIPPETS + "/cipherchat-proxy.inc": template(self.src, "nginx/cipherchat-proxy.inc"),
        }

    def _site_path(self, files):
        uses_sites = any(f.startswith("/etc/nginx/sites-enabled/") for f in files) or os.path.isdir("/etc/nginx/sites-enabled")
        return (SITE_AVAILABLE, SITE_ENABLED) if uses_sites else (SITE_CONFD, None)

    def _site_text(self, tls):
        p = self.plan
        block = ""
        if tls:
            cert, key = (("/etc/letsencrypt/live/%s/fullchain.pem" % p.domain, "/etc/letsencrypt/live/%s/privkey.pem" % p.domain)
                         if p.tls == "certbot" else (p.cert, p.key))
            listen = ("listen 443 ssl;\n    listen [::]:443 ssl;\n    http2 on;" if self.facts.http2_directive
                      else "listen 443 ssl http2;\n    listen [::]:443 ssl http2;")
            block = template(self.src, "nginx/cipherchat-site-tls.conf", LISTEN_TLS=listen, DOMAIN=p.domain, CERT=cert, KEY=key,
                             CURVES="X25519MLKEM768" if p.pq_only else nginxconf.PQ_CURVES)
        return template(self.src, "nginx/cipherchat-site.conf", DOMAIN=p.domain, TLS_BLOCK=block)

    def _write_site(self, tls):
        files = nginxconf.dump()
        path, link = self._site_path(files)
        changes = stale_nginx(files, keep_site=True, keep_merge=None)
        changes.update(self._shared_nginx(files))
        changes[path] = self._site_text(tls)
        if link:
            self._apply_with_link(changes, path, link)
        else:
            nginxconf.apply(changes)
        nginxconf.reload()

    def _apply_with_link(self, changes, path, link):
        created = not os.path.lexists(link)
        if created:
            os.symlink(path, link)
        try:
            nginxconf.apply(changes)
        except BaseException:
            if created:
                os.remove(link)
            raise

    def nginx_site(self):
        p = self.plan
        os.makedirs(ACME_ROOT, exist_ok=True)
        if p.tls == "certbot" and not os.path.exists("/etc/letsencrypt/live/%s/fullchain.pem" % p.domain):
            self._write_site(tls=False)                       # port 80 first, for the ACME challenge
            cmd = ["certbot", "certonly", "--webroot", "-w", ACME_ROOT, "-d", p.domain, "--non-interactive", "--agree-tos",
                   "--key-type", "ecdsa", "--keep-until-expiring"]
            cmd += ["-m", p.certbot_email] if p.certbot_email else ["--register-unsafely-without-email"]
            self.rep.info("asking Let's Encrypt for a certificate for %s" % p.domain)
            run(cmd)
        if p.tls == "certbot":
            os.makedirs(os.path.dirname(RENEW_HOOK), exist_ok=True)
            write(RENEW_HOOK, "#!/bin/sh\n# CipherChat: reload nginx after certbot renews a certificate\nsystemctl reload nginx\n", 0o755)
        elif not (os.path.exists(p.cert) and os.path.exists(p.key)):
            raise StepFailed("The certificate files aren't there: %s, %s" % (p.cert, p.key))
        self._write_site(tls=True)
        return "https://%s/chat/ (TLS 1.3, %s)" % (p.domain, "post-quantum only" if p.pq_only else "post-quantum first")

    def nginx_merge(self):
        p = self.plan
        files = nginxconf.dump()
        site = next((s for s in nginxconf.sites(files) if s.path == p.merge_file and (not p.merge_name or p.merge_name in s.names)), None)
        if site is None:
            raise StepFailed("That site isn't in nginx's configuration any more: %s %s" % (p.merge_file, p.merge_name))
        if site.claims_chat():
            raise StepFailed("That site already serves /chat (%s). Choose another site, or CipherChat's own site." % ", ".join(site.locations))
        if not site.tls:
            raise StepFailed("That site is http only. CipherChat needs https: choose a site with TLS, or CipherChat's own site.")
        changes = stale_nginx(files, keep_site=False, keep_merge=site.path)
        changes.update(self._shared_nginx(files))
        if not site.merged:
            inherited = nginxconf.http_curves(files)
            needs_pq = site.curves is None and any(not nginxconf.offers_pq(c) for c in inherited) or \
                site.curves is not None and not nginxconf.offers_pq(" ".join(site.curves.args))
            changes[site.path] = nginxconf.with_include(site, set_pq=needs_pq and p.set_pq_curve)
            self.result["pq_unchanged"] = needs_pq and not p.set_pq_curve
        nginxconf.apply(changes)
        nginxconf.reload()
        return "https://%s/chat/ beside the site's own pages (backup in %s)" % (p.domain, nginxconf.BACKUPS)

    # ---- coturn
    def _cert_source(self):
        p = self.plan
        if p.web == "site":
            return (("/etc/letsencrypt/live/%s/fullchain.pem" % p.domain, "/etc/letsencrypt/live/%s/privkey.pem" % p.domain)
                    if p.tls == "certbot" else (p.cert, p.key))
        if p.web == "merge":
            site = next((s for s in nginxconf.sites() if s.path == p.merge_file and (not p.merge_name or p.merge_name in s.names)), None)
            if site and site.cert and site.key:
                return site.cert, site.key
        return None, None

    def relay(self):
        p = self.plan
        if not shutil.which("turnserver"):
            raise StepFailed("coturn isn't installed (tick 'install missing packages', or apt install coturn).")
        if not os.path.exists(TURN_SECRET):
            old = os.umask(0o077)
            try:
                with open(TURN_SECRET, "w") as f:
                    f.write(secrets.token_hex(32) + "\n")
            finally:
                os.umask(old)
        os.chown(TURN_SECRET, 0, grp.getgrnam(USER).gr_gid); os.chmod(TURN_SECRET, 0o640)
        with open(TURN_SECRET, encoding="utf-8") as f:
            secret = f.read().strip()
        cert, key = self._cert_source()
        tls = bool(cert and key and os.path.exists(cert) and os.path.exists(key))
        tgroup = "turnserver" if _group_exists("turnserver") else "root"
        os.makedirs(TURN_CERTS, exist_ok=True)
        os.chown(TURN_CERTS, 0, grp.getgrnam(tgroup).gr_gid); os.chmod(TURN_CERTS, 0o750)
        if tls:
            for src, name in ((cert, "cipherchat.crt"), (key, "cipherchat.key")):
                dst = os.path.join(TURN_CERTS, name)
                shutil.copyfile(src, dst)
                os.chown(dst, 0, grp.getgrnam(tgroup).gr_gid); os.chmod(dst, 0o640)
            if p.web == "site" and p.tls == "certbot":
                os.makedirs(os.path.dirname(TURN_HOOK), exist_ok=True)
                write(TURN_HOOK, "#!/bin/sh\n# CipherChat: give coturn the renewed certificate\nset -e\n"
                                 "install -m 0640 -g %s %s %s/cipherchat.crt\ninstall -m 0640 -g %s %s %s/cipherchat.key\nsystemctl restart coturn\n"
                                 % (tgroup, cert, TURN_CERTS, tgroup, key, TURN_CERTS), 0o755)
        if os.path.exists(TURN_CONF) and not os.path.exists(TURN_ORIG):
            with open(TURN_CONF, encoding="utf-8", errors="replace") as f:
                theirs = TURN_MARK not in f.read()
            if theirs:
                os.makedirs(os.path.dirname(TURN_ORIG), exist_ok=True)
                shutil.copy2(TURN_CONF, TURN_ORIG)
        conf = template(self.src, "coturn/turnserver.conf", MIN_PORT=p.turn_min_port, MAX_PORT=p.turn_max_port, DOMAIN=p.domain, SECRET=secret)
        if not tls:
            conf = conf.replace("tls-listening-port=5349\n", "no-tls\nno-dtls\n").replace(
                "cert=/etc/coturn/certs/cipherchat.crt\npkey=/etc/coturn/certs/cipherchat.key\n", "")
        write(TURN_CONF, conf, 0o640, ("root", tgroup))
        if os.path.exists("/etc/default/coturn"):
            with open("/etc/default/coturn", encoding="utf-8") as f:
                d = f.read()
            if not re.search(r"^TURNSERVER_ENABLED=1", d, re.M):
                write("/etc/default/coturn", re.sub(r"^#?\s*TURNSERVER_ENABLED=\d", "TURNSERVER_ENABLED=1", d, flags=re.M)
                      if "TURNSERVER_ENABLED" in d else d + "TURNSERVER_ENABLED=1\n")
        os.makedirs(os.path.dirname(TURN_JAIL), exist_ok=True)
        write(TURN_JAIL, TURN_JAIL_TEXT, 0o644)
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "enable", "--quiet", "coturn"])
        run(["systemctl", "restart", "coturn"])
        if self.facts.ufw_active and p.firewall:
            for rule in ("3478/udp", "3478/tcp", "5349/tcp", "%d:%d/udp" % (p.turn_min_port, p.turn_max_port)):
                run(["ufw", "allow", rule, "comment", "CipherChat call relay"])
        run(["systemctl", "restart", "cipherchat"])                   # it hands out the relay's addresses from now on
        return "3478%s, relay ports %d-%d, private networks blocked" % (
            " and TLS on 5349" if tls else " (no certificate found, so no TLS)", p.turn_min_port, p.turn_max_port)

    def disable_relay(self):
        if os.path.exists(TURN_CONF):
            with open(TURN_CONF, encoding="utf-8", errors="replace") as f:
                ours = TURN_MARK in f.read()
            if ours:
                remove_relay()

    def firewall(self):
        for port in ("80/tcp", "443/tcp"):
            run(["ufw", "allow", port, "comment", "CipherChat (nginx)"])
        return "allowed 80 and 443 (https, and http for certificate renewals)"

    def backups(self):
        p = self.plan
        os.makedirs(p.backup_dir, mode=0o700, exist_ok=True)
        u = pwd.getpwnam(USER)
        os.chown(p.backup_dir, u.pw_uid, u.pw_gid); os.chmod(p.backup_dir, 0o700)
        write(BACKUP_UNIT, template(self.src, "cipherchat-backup.service", BACKUP_DIR=p.backup_dir, BACKUP_KEEP=p.backup_keep))
        write(BACKUP_TIMER, template(self.src, "cipherchat-backup.timer"))
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "enable", "--now", "--quiet", "cipherchat-backup.timer"])
        run(["systemctl", "start", "cipherchat-backup.service"])
        return "daily into %s, newest %d kept (the server key is not in them)" % (p.backup_dir, p.backup_keep)

    def disable_backups(self):
        if os.path.exists(BACKUP_TIMER):
            run(["systemctl", "disable", "--now", "--quiet", "cipherchat-backup.timer"], check=False)

    def verify(self):
        """Through nginx on this machine: X25519MLKEM768 negotiated, and the chat answers at the public address."""
        p = self.plan
        if not self.facts.openssl_cli or not probe_version_at_least(self.facts.openssl_cli, "3.5"):
            self.result["pq"] = None
            return "skipped: this machine's openssl command (%s) is too old to test X25519MLKEM768" % (self.facts.openssl_cli or "missing")
        r = run(["openssl", "s_client", "-connect", "127.0.0.1:443", "-servername", p.domain, "-tls1_3", "-groups", "X25519MLKEM768"],
                check=False, input="", timeout=20)
        group = re.search(r"Negotiated TLS1\.3 group: (\S+)", r.stdout or "")
        self.result["pq"] = bool(group and group.group(1) == "X25519MLKEM768")
        ok_http = False
        if shutil.which("curl"):
            c = run(["curl", "-fsS", "--max-time", "10", "--resolve", "%s:443:127.0.0.1" % p.domain, p.origin + "/chat/api/auth/status"], check=False)
            ok_http = c.returncode == 0 and '"' in (c.stdout or "")
            self.result["https_ok"] = ok_http
        if not self.result["pq"]:
            return "NOT negotiated: browsers work, the CipherChat apps will refuse this server (see below)"
        return "X25519MLKEM768 negotiated" + ("; the chat answers at " + p.origin if ok_http else "; check the certificate (curl couldn't verify it)")

    def save_plan(self):
        write(SAVED_PLAN, self.plan.to_json() + "\n", 0o640, ("root", USER))

    def owner_link(self):
        if owner_active(self.plan.owner):
            return "skipped: %s is already set up (a new link resets their password: cipherchat-admin owner-invite)" % self.plan.owner
        r = run([ADMIN, "owner-invite"])
        m = re.search(r"https://\S+", r.stdout)
        self.result["owner_link"] = m.group(0) if m else r.stdout.strip()
        return "for %s (works once)" % self.plan.owner


# ------------------------------------------------------------------ uninstall
def uninstall(purge, rep):
    def step(title, fn):
        rep.step(title)
        try:
            rep.done(fn() or "")
        except Exception as e:
            rep.fail(e)
            raise StepFailed(str(e)) from None

    def services():
        for unit in ("cipherchat-backup.timer", "cipherchat-backup.service", "cipherchat-mailer.service", "cipherchat.service"):
            run(["systemctl", "disable", "--now", "--quiet", unit], check=False)
        for f in (UNIT, MAILER_UNIT, BACKUP_UNIT, BACKUP_TIMER):
            if os.path.exists(f):
                os.remove(f)
        run(["systemctl", "daemon-reload"], check=False)
        return "stopped and removed"

    def nginx():
        if not shutil.which("nginx"):
            return "nginx isn't installed"
        edited = stale_nginx(nginxconf.dump(), keep_site=False, keep_merge=None)
        mine = {f: None for f in (NGINX_HTTP, SNIPPETS + "/cipherchat-locations.conf", SNIPPETS + "/cipherchat-proxy.inc") if os.path.lexists(f)}
        nginxconf.apply(dict(edited, **mine))
        nginxconf.reload()
        lines = [p for p, t in edited.items() if t is not None]
        return "removed CipherChat's nginx files%s (backups in %s)" % (" and its lines in " + ", ".join(lines) if lines else "", nginxconf.BACKUPS)

    def program():
        shutil.rmtree(OPT, ignore_errors=True)
        for f in (ADMIN, RENEW_HOOK):
            if os.path.exists(f):
                os.remove(f)
        return "removed %s and cipherchat-admin" % OPT

    step("Services", services)
    step("nginx", nginx)
    if os.path.exists(TURN_CONF):
        with open(TURN_CONF, encoding="utf-8", errors="replace") as f:
            ours = TURN_MARK in f.read()
        if ours:
            step("Call relay", remove_relay)
    step("Program files", program)
    if purge:
        def data():
            saved = {}
            try:
                with open(SAVED_PLAN, encoding="utf-8") as f:
                    saved = json.load(f)
            except (OSError, ValueError):
                pass
            for d in (STATE, ETC, saved.get("backup_dir") or "/var/backups/cipherchat", SNAPSHOTS):
                shutil.rmtree(d, ignore_errors=True)
            run(["userdel", USER], check=False)
            return "deleted the database, attachments, settings, server key and backups"
        step("Data", data)
