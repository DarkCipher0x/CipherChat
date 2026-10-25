"""Every answer the setup needs, in one place. The terminal questions fill it in; `--plan plan.json` gives it directly
(unattended installs, the DarkCipher deploy apps). The same checks apply either way."""
import json
import os
import re

DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
USER_RE = re.compile(r"^[a-z0-9._-]{3,32}$")
ANDROID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+=([0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$")
WEB_MODES = ("site", "merge", "proxy")
TLS_MODES = ("certbot", "files")


class Plan:
    FIELDS = {
        "domain": "", "name": "CipherChat", "owner": "owner",
        "web": "site",                      # site: CipherChat's own nginx site; merge: into a site of yours; proxy: none
        "merge_file": "", "merge_name": "", # merge: which server block (its file and first server_name)
        "set_pq_curve": True,               # merge: let that site offer X25519MLKEM768 if it doesn't yet
        "tls": "certbot", "cert": "", "key": "", "certbot_email": "", "agree_le_terms": False,
        "pq_only": False,                   # site: no classical fallback (the apps don't need one; old browsers do)
        "port": 8787,
        "firewall": True, "backups": True, "backup_dir": "/var/backups/cipherchat", "backup_keep": 14,
        "install_packages": False, "owner_link": True,
        "turn": True, "turn_min_port": 49160, "turn_max_port": 49260,   # coturn, the relay for calls behind NAT
        "android_apps": "",                 # passkeys in the Android app: "package=SHA-256 of its signing cert (AA:BB:..)", comma-separated
    }

    def __init__(self, **kw):
        for k, v in self.FIELDS.items():
            setattr(self, k, kw.get(k, v))
        unknown = set(kw) - set(self.FIELDS)
        if unknown:
            raise ValueError("Unknown plan settings: " + ", ".join(sorted(unknown)))

    @classmethod
    def load(cls, path):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("The plan must be a JSON object.")
        return cls(**data)

    def to_json(self):
        return json.dumps({k: getattr(self, k) for k in self.FIELDS}, indent=2, sort_keys=True)

    @property
    def origin(self):
        return "https://" + self.domain

    def problems(self):
        """Everything wrong with the plan, one line each (empty when it can be installed)."""
        out = []
        if not DOMAIN_RE.match(self.domain or ""):
            out.append("domain: enter the name people open, like chat.example.com")
        if not isinstance(self.name, str) or not 1 <= len(self.name.strip()) <= 60 or any(ord(c) < 32 for c in self.name):
            out.append("server name: 1 to 60 characters")
        if not USER_RE.match(self.owner or ""):
            out.append("owner: 3 to 32 of a-z 0-9 . _ -")
        if self.web not in WEB_MODES:
            out.append("web: one of " + ", ".join(WEB_MODES))
        if self.web == "merge" and not (self.merge_file and os.path.isabs(self.merge_file)):
            out.append("merge: choose the site to add CipherChat to")
        if self.web == "site":
            if self.tls not in TLS_MODES:
                out.append("tls: certbot or files")
            if self.tls == "certbot" and not self.agree_le_terms:
                out.append("certificate: Let's Encrypt's terms must be accepted to use certbot")
            if self.tls == "files" and not (os.path.isabs(self.cert or "") and os.path.isabs(self.key or "")):
                out.append("certificate: give the full paths of the certificate chain and its key")
            if self.certbot_email and not re.match(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", self.certbot_email, re.I):
                out.append("certbot email: that address doesn't look right")
        if not isinstance(self.port, int) or not 1024 <= self.port <= 65535:
            out.append("port: 1024 to 65535 (the server listens on 127.0.0.1 only)")
        if not isinstance(self.backup_keep, int) or not 1 <= self.backup_keep <= 365:
            out.append("backups: keep 1 to 365")
        if self.backups and not os.path.isabs(self.backup_dir or ""):
            out.append("backups: the folder must be a full path")
        if self.turn and not (isinstance(self.turn_min_port, int) and isinstance(self.turn_max_port, int)
                              and 1024 <= self.turn_min_port < self.turn_max_port <= 65535 and self.turn_max_port - self.turn_min_port <= 10000):
            out.append("call relay ports: a range between 1024 and 65535 (at most 10000 ports)")
        if not isinstance(self.android_apps, str) or (self.android_apps and not all(ANDROID_RE.match(a.strip()) for a in self.android_apps.split(","))):
            out.append("android apps: package=SHA-256 of its signing certificate (AA:BB:...), comma-separated")
        for k in ("set_pq_curve", "agree_le_terms", "pq_only", "firewall", "backups", "install_packages", "owner_link", "turn"):
            if not isinstance(getattr(self, k), bool):
                out.append("%s: true or false" % k)
        return out
