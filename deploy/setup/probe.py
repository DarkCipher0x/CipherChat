"""What the setup finds on this machine before it asks anything. Read-only."""
import json
import os
import re
import shutil
import socket
import subprocess
import sys

OPT = "/opt/cipherchat"
SAVED_PLAN = "/etc/cipherchat/setup.json"
DB = "/var/lib/cipherchat/cipherchat.db"


class Check:
    def __init__(self, state, title, detail=""):
        self.state, self.title, self.detail = state, title, detail


def _out(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return (r.stdout + r.stderr).strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def version_at_least(have, want):
    def parts(v):
        return [int(x) for x in re.findall(r"\d+", v)[:3]] + [0, 0, 0]
    return parts(have)[:3] >= parts(want)[:3]


class Facts:
    def __init__(self, port=8787):
        osr = {}
        try:
            with open("/etc/os-release", encoding="utf-8") as f:
                for line in f:
                    k, _, v = line.strip().partition("=")
                    osr[k] = v.strip('"')
        except OSError:
            pass
        self.os_name = osr.get("PRETTY_NAME", "unknown")
        self.debian_like = "debian" in (osr.get("ID", "") + " " + osr.get("ID_LIKE", ""))
        self.systemd = os.path.isdir("/run/systemd/system")
        self.python = "%d.%d.%d" % sys.version_info[:3]
        self.nginx = shutil.which("nginx")
        v = _out(["nginx", "-V"]) if self.nginx else ""
        self.nginx_version = (re.search(r"nginx/([\d.]+)", v) or [None, ""])[1]
        self.nginx_openssl = (re.search(r"built with OpenSSL ([\d.]+)", v) or [None, ""])[1]
        self.nginx_pq = bool(self.nginx_openssl) and version_at_least(self.nginx_openssl, "3.5")
        self.http2_directive = bool(self.nginx_version) and version_at_least(self.nginx_version, "1.25.1")
        self.openssl_cli = (re.search(r"OpenSSL ([\d.]+)", _out(["openssl", "version"])) or [None, ""])[1]
        self.certbot = shutil.which("certbot")
        self.ufw_active = bool(shutil.which("ufw")) and "Status: active" in _out(["ufw", "status"])
        self.port = port
        self.port_free = self._free(port)
        st = shutil.disk_usage("/var/lib" if os.path.isdir("/var/lib") else "/")
        self.free_mb = st.free // (1024 * 1024)
        self.installed = None
        try:
            with open(os.path.join(OPT, "VERSION"), encoding="utf-8") as f:
                self.installed = f.read().strip()
        except OSError:
            pass
        self.saved = None
        try:
            with open(SAVED_PLAN, encoding="utf-8") as f:
                self.saved = json.load(f)
        except (OSError, ValueError):
            pass
        self.has_data = os.path.exists(DB)
        self.root = os.geteuid() == 0

    @staticmethod
    def _free(port):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # as the server binds: old TIME_WAIT connections don't count
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False
        finally:
            s.close()

    def service_running(self):
        return _out(["systemctl", "is-active", "cipherchat"]) == "active"

    def checks(self):
        c = []
        c.append(Check("ok" if self.debian_like else "warn", "Operating system", self.os_name +
                       ("" if self.debian_like else " (made for Debian and Ubuntu; other systems may need changes)")))
        c.append(Check("ok" if self.systemd else "fail", "systemd", "running" if self.systemd else "not running: the server runs as a systemd service"))
        c.append(Check("ok" if version_at_least(self.python, "3.10") else "fail", "Python", self.python + ("" if version_at_least(self.python, "3.10") else " (3.10 or newer needed)")))
        if not self.nginx:
            c.append(Check("warn", "nginx", "not installed (the setup can install it, or choose no web server)"))
        elif self.nginx_pq:
            c.append(Check("ok", "nginx post-quantum TLS", "nginx %s with OpenSSL %s: X25519MLKEM768 available" % (self.nginx_version, self.nginx_openssl)))
        else:
            c.append(Check("warn", "nginx post-quantum TLS", "nginx %s with OpenSSL %s: needs OpenSSL 3.5+; the apps refuse servers without it"
                           % (self.nginx_version or "?", self.nginx_openssl or "unknown")))
        c.append(Check("ok" if self.certbot else "info", "certbot", self.certbot or "not installed (only needed for a Let's Encrypt certificate)"))
        c.append(Check("ok" if self.ufw_active else "info", "Firewall (ufw)", "active" if self.ufw_active else "not active (nothing to open)"))
        if self.installed:
            c.append(Check("info", "CipherChat", "%s installed%s" % (self.installed, ", running" if self.service_running() else "")))
        elif self.port_free:
            c.append(Check("ok", "Port %d on 127.0.0.1" % self.port, "free"))
        else:
            c.append(Check("fail", "Port %d on 127.0.0.1" % self.port, "in use by another program (choose another port)"))
        c.append(Check("ok" if self.free_mb >= 2048 else "warn", "Free disk space", "%d MB%s" % (self.free_mb, "" if self.free_mb >= 2048 else " (2 GB or more recommended for attachments)")))
        return c
