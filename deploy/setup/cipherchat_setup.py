#!/usr/bin/env python3
"""CipherChat by DarkCipher Systems: the Linux server setup.

  sudo sh install.sh                          interactive install, upgrade or reconfigure (from the unpacked release)
  sudo sh install.sh --plan plan.json         unattended, every answer from the plan (see plan.py)
  sudo sh install.sh --plan plan.json --check only validate the plan against this machine; change nothing
  sudo cipherchat-admin status                what's installed and whether it's healthy
  sudo cipherchat-admin uninstall [--purge]   remove it (data kept unless --purge)
  sudo sh install.sh uninstall --purge        the same from the release folder (after a plain uninstall, say)

Nothing is changed until every question is answered and the summary confirmed. A log goes to
/var/log/cipherchat-setup.log. Python 3.10+ standard library only, like the server.
"""
import argparse
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import nginxconf  # noqa: E402
import steps  # noqa: E402
import tui  # noqa: E402
from plan import DOMAIN_RE, USER_RE, Plan  # noqa: E402
from probe import Facts  # noqa: E402
from tui import ACCENT, BAD, BOLD, DIM, OK, RESET, WARM, Cancelled  # noqa: E402


def release_dir():
    return os.path.dirname(os.path.dirname(HERE))       # <release>/deploy/setup -> <release>


# ------------------------------------------------------------------ questions
def ask_plan(facts):
    p = Plan()

    tui.section("Server")
    p.name = tui.ask("Server name (shown in the apps and in authenticator apps)", "CipherChat",
                     lambda s: None if 1 <= len(s) <= 60 else "1 to 60 characters.")
    tui.note("The owner is the chat's trust anchor: every member compares a safety number with this account once.")
    p.owner = tui.ask("Owner's username", "owner", lambda s: None if USER_RE.match(s) else "3 to 32 of a-z 0-9 . _ -")

    tui.section("Web server")
    https_sites = []
    if facts.nginx:
        try:
            https_sites = [s for s in nginxconf.sites() if s.tls]
        except RuntimeError as e:
            tui.note(str(e), WARM)
    options = [("CipherChat's own site", "a new nginx site for its own domain, with a Let's Encrypt or your own certificate"),
               ("Add it to one of your nginx sites", "CipherChat appears under /chat/ on a site nginx already serves"
                + ("" if https_sites else " (no https site found)")),
               ("My own reverse proxy", "nothing changes in nginx; the setup shows what to add to your proxy")]
    while True:
        mode = tui.choose(options, 0)
        if mode == 1 and not https_sites:
            tui.note("nginx serves no https site to add CipherChat to.", BAD)
            continue
        break
    p.web = ("site", "merge", "proxy")[mode]

    if p.web == "merge":
        usable = [s for s in https_sites if not s.claims_chat()]
        for s in https_sites:
            if s.claims_chat():
                tui.note("not offered: %s already serves /chat" % s.label)
        if not usable:
            raise SystemExit("  %sEvery https site already serves /chat. Choose CipherChat's own site instead.%s" % (BAD, RESET))
        tui.p("")
        i = tui.choose([(s.label.split("  ")[0], s.label.split("  ")[1]) for s in usable])
        site = usable[i]
        p.merge_file, p.merge_name = site.path, (site.names or [""])[0]
        names = [n for n in site.names if DOMAIN_RE.match(n)]
        p.domain = tui.ask("The address people open (one of that site's names)", names[0] if names else "",
                           lambda s: None if s in site.names and DOMAIN_RE.match(s) else "Use one of: " + ", ".join(site.names))
    else:
        p.domain = tui.ask("The address people open (a domain pointing at this machine)", "",
                           lambda s: None if DOMAIN_RE.match(s.lower()) else "Like chat.example.com").lower()

    if p.web == "site":
        tui.p("")
        tls = tui.choose([("A Let's Encrypt certificate (certbot)", "free, renewed automatically; %s must already point here and port 80 be reachable" % p.domain),
                          ("Certificate files I already have", "the full chain and its key, e.g. from your own CA or another ACME client")])
        p.tls = ("certbot", "files")[tls]
        if p.tls == "certbot":
            p.certbot_email = tui.ask("Email for expiry warnings from Let's Encrypt (Enter for none)", "",
                                      lambda s: None if not s or "@" in s else "That doesn't look like an email address.")
            tui.note("Let's Encrypt's terms: https://letsencrypt.org/repository/")
            p.agree_le_terms = tui.confirm("Do you accept Let's Encrypt's subscriber agreement?", True)
            if not p.agree_le_terms:
                raise Cancelled()
        else:
            p.cert = tui.ask("Certificate chain (fullchain) file", "", lambda s: None if os.path.isfile(s) else "No such file.")
            p.key = tui.ask("Its private key file", "", lambda s: None if os.path.isfile(s) else "No such file.")

    tui.section("Features")
    if p.web != "proxy" and not facts.nginx_pq and facts.nginx:
        tui.note("! nginx here is built with OpenSSL %s. The CipherChat apps need X25519MLKEM768 (OpenSSL 3.5+), so until "
                 "nginx is upgraded only browsers can connect." % (facts.nginx_openssl or "unknown"), WARM)
        tui.p("")
    have_coturn = bool(shutil.which("turnserver"))
    merge_site = None
    if p.web == "merge":
        files = nginxconf.dump()
        merge_site = next(s for s in nginxconf.sites(files) if s.path == p.merge_file and p.merge_name in (s.names or [""]))
        own = merge_site.curves and " ".join(merge_site.curves.args)
        needs_pq = (own is not None and not nginxconf.offers_pq(own)) or (own is None and any(not nginxconf.offers_pq(c) for c in nginxconf.http_curves(files)))
    feats = [
        tui.Feature("backups", "Daily backups", "database snapshot + encrypted attachments; the server key is kept out of them", True),
        tui.Feature("turn", "Call relay (coturn)", "gets calls through home routers and strict networks; it only relays frames that are already encrypted", True),
        tui.Feature("firewall", "Open https (443) and http (80) in ufw", "only CipherChat's own site needs this", p.web == "site",
                    None if p.web == "site" and facts.ufw_active else ("ufw isn't active" if p.web == "site" else "not needed for this choice")),
    ]
    if not steps.owner_active(p.owner):
        feats.append(tui.Feature("owner_link", "The owner's set-up link", "a one-time link to choose the owner's password and authenticator", True))
    else:
        p.owner_link = False
    if p.web == "merge" and needs_pq:
        feats.insert(0, tui.Feature("set_pq_curve", "Offer post-quantum key exchange on that site",
                                    "its ssl_ecdh_curve leaves out X25519MLKEM768; browsers keep working", True))
    if p.web == "site":
        feats.append(tui.Feature("pq_only", "Post-quantum TLS only", "no X25519 fallback: the apps and new browsers connect, old browsers can't", False))
    missing = [x for x, need in (("nginx", p.web != "proxy" and not facts.nginx),
                                 ("certbot", p.web == "site" and p.tls == "certbot" and not facts.certbot),
                                 ("coturn", not have_coturn)) if need]
    if missing:
        feats.append(tui.Feature("install_packages", "Install " + ", ".join(missing) + " with apt", "needed for your choices (coturn only if the call relay is ticked)", True))
    tui.checklist(feats)
    for f in feats:
        setattr(p, f.key, f.on)
    if not p.turn and "coturn" in missing:
        missing.remove("coturn")
    if missing and not p.install_packages:
        raise SystemExit("  %s%s is needed for these choices. Install it, or tick the option, and run the setup again.%s" % (BAD, " and ".join(missing), RESET))
    if p.backups:
        p.backup_dir = tui.ask("Backup folder", p.backup_dir, lambda s: None if s.startswith("/") else "A full path, starting with /")
        p.backup_keep = tui.ask_int("Daily backups to keep", p.backup_keep, 1, 365)
    return p


def summary(p, facts):
    tui.section("Ready to install")
    tui.kv("Name", p.name)
    tui.kv("Address", p.origin + "/chat/")
    tui.kv("Owner", p.owner)
    tui.kv("Web server", {"site": "CipherChat's own nginx site", "merge": "added to %s (%s)" % (p.merge_name, p.merge_file),
                          "proxy": "your own reverse proxy"}[p.web])
    if p.web == "site":
        tui.kv("Certificate", "Let's Encrypt (certbot)" if p.tls == "certbot" else p.cert)
    tui.kv("Server", "127.0.0.1:%d, systemd service under its own account, sandboxed" % p.port)
    for k, label in (("backups", "daily backups to %s, keep %d" % (p.backup_dir, p.backup_keep)), ("firewall", "ufw: allow 80, 443"),
                     ("turn", "call relay (coturn) on 3478 / 5349, relay ports %d-%d" % (p.turn_min_port, p.turn_max_port)),
                     ("set_pq_curve", "post-quantum key exchange on that site"), ("pq_only", "post-quantum TLS only"),
                     ("install_packages", "install missing packages"), ("owner_link", "owner set-up link")):
        if getattr(p, k) and not (k == "firewall" and (p.web != "site" or not facts.ufw_active)) and not (k == "set_pq_curve" and p.web != "merge"):
            tui.kv("✓", label)


def show_result(p, res, version):
    tui.p("\n  %s%sCipherChat is running%s\n" % (BOLD, OK, RESET))
    tui.kv("Address", p.origin + "/chat/")
    tui.kv("Version", version)
    if p.web != "proxy":
        pq = res.get("pq")
        tui.kv("TLS", "%sX25519MLKEM768 (post-quantum) ✓%s" % (OK, RESET) if pq else
               ("not checked here" if pq is None else "%sclassical only: the apps will refuse this server%s" % (BAD, RESET)))
    if res.get("pq") is False:
        tui.note("\n  nginx must be built with OpenSSL 3.5 or newer, and the site's ssl_ecdh_curve must include X25519MLKEM768.", WARM)
    if res.get("new_key"):
        tui.p("\n  %s%sBack up the server key now%s, somewhere offline: %s" % (BOLD, WARM, RESET, steps.KEY))
        tui.note("  Without it no one's chat identity can be unlocked again. It is deliberately not in the daily backups.")
    if res.get("owner_link"):
        tui.p("\n  %sOwner set-up link%s for %s (works once; keep it private):\n\n      %s%s%s" % (BOLD, RESET, p.owner, ACCENT, res["owner_link"], RESET))
    if p.web == "proxy":
        proxy_help(p)
    tui.p("")
    tui.kv("Status", "sudo cipherchat-admin status")
    tui.kv("Owner link", "sudo cipherchat-admin owner-invite")
    tui.kv("Logs", "journalctl -u cipherchat")
    tui.kv("Upgrade", "run the new release's install.sh")
    tui.kv("Uninstall", "sudo cipherchat-admin uninstall")
    tui.p("")


def proxy_help(p):
    tui.section("Add this to your reverse proxy")
    tui.note("The server listens on 127.0.0.1:%d, so the proxy must run on this machine and send X-Real-IP." % p.port)
    tui.note("It must offer TLS 1.3 with X25519MLKEM768 (OpenSSL 3.5+, Go 1.24+, Caddy 2.10+): the apps refuse anything else.")
    tui.p("\n  %snginx%s (in the server block for %s; the http-level part goes in conf.d):" % (BOLD, RESET, p.domain))
    tui.p("      include %s/deploy/nginx/cipherchat-http.conf;      # http level (replace @PORT@ with %d)" % (steps.OPT, p.port))
    tui.p("      include %s/deploy/nginx/cipherchat-locations.conf; # in the server block" % steps.OPT)
    tui.p("\n  %sCaddy%s:" % (BOLD, RESET))
    tui.p("      %s {\n          handle /chat* {\n              reverse_proxy 127.0.0.1:%d {\n                  header_up X-Real-IP {remote_host}\n"
          "                  header_up -X-Forwarded-For\n              }\n          }\n      }" % (p.domain, p.port))


# ------------------------------------------------------------------ commands
def cmd_install(args):
    src = release_dir()
    version = steps.release_version(src)
    if not args.plan:
        tui.banner("Server Setup", version)
    if os.geteuid() != 0:
        raise SystemExit("Run the setup as root: sudo sh install.sh")
    facts = Facts()
    if args.plan:
        p = Plan.load(args.plan)
        facts = Facts(p.port)
        problems = p.problems() + [("%s: %s" % (c.title, c.detail)) for c in facts.checks() if c.state == "fail" and not (facts.installed and c.title.startswith("Port"))]
        if problems:
            raise SystemExit("The plan can't be installed here:\n  " + "\n  ".join(problems))
        if args.check:
            print("The plan is valid for this machine. Nothing was changed.")
            return
        rep = tui.Reporter()
        res = steps.Installer(p, facts, src, rep).all()
        show_result(p, res, version)
        return
    if not tui.interactive():
        raise SystemExit("Run the setup in a terminal, or give the answers with --plan plan.json.")

    tui.section("This machine")
    tui.checks(facts.checks())
    hard = [c for c in facts.checks() if c.state == "fail" and not (facts.installed and c.title.startswith("Port"))]
    if hard:
        raise SystemExit("\n  %sFix the ✗ above, then run the setup again.%s" % (BAD, RESET))

    p = None
    if facts.installed and facts.saved:
        saved = Plan(**facts.saved)
        tui.section("Already installed")
        tui.kv("Installed", facts.installed + (" (running)" if facts.service_running() else " (stopped)"))
        tui.kv("Address", saved.origin + "/chat/")
        tui.p("")
        what = tui.choose([("Upgrade to %s" % version, "keeps every setting and all data"),
                           ("Change the settings", "asks everything again (data and the server key are kept)"),
                           ("Cancel", "change nothing")])
        if what == 2:
            raise Cancelled()
        if what == 0:
            saved.owner_link, saved.install_packages = False, False
            p = saved
    if p is None:
        p = ask_plan(facts)
        if facts.saved and facts.saved.get("owner") and facts.saved["owner"] != p.owner and facts.has_data:
            raise SystemExit("  %sThe owner can't be changed once the chat has data (every member's trust starts there). "
                             "Keep %s, or start over with uninstall --purge.%s" % (BAD, facts.saved["owner"], RESET))
    problems = p.problems()
    if problems:
        raise SystemExit("  " + "\n  ".join(problems))
    summary(p, facts)
    if not tui.confirm("Install now?", True):
        raise Cancelled()
    tui.section("Installing")
    res = steps.Installer(p, Facts(p.port), src, tui.Reporter()).all()
    show_result(p, res, version)


def cmd_status(_args):
    facts = Facts()
    tui.banner("Status", facts.installed or "not installed")
    if not facts.installed:
        raise SystemExit("CipherChat isn't installed here.")
    p = Plan(**(facts.saved or {}))
    h = steps.health(p.port, tries=4)
    tui.kv("Service", "%srunning%s" % (OK, RESET) if facts.service_running() else "%sstopped%s (journalctl -u cipherchat)" % (BAD, RESET))
    tui.kv("Answers", "yes, %s" % h.get("version") if h else "%sno answer on 127.0.0.1:%d%s" % (BAD, p.port, RESET))
    tui.kv("Address", p.origin + "/chat/")
    tui.kv("Web server", {"site": "CipherChat's own nginx site", "merge": "in %s" % p.merge_file, "proxy": "your own proxy"}[p.web])
    if p.web != "proxy":
        inst = steps.Installer(p, facts, steps.OPT, tui.Reporter())
        try:
            inst.verify()
            pq = inst.result.get("pq")
            tui.kv("TLS", "X25519MLKEM768 ✓" if pq else ("not checked" if pq is None else "%sno post-quantum key exchange%s" % (BAD, RESET)))
        except steps.StepFailed as e:
            tui.kv("TLS", str(e))
    if p.backups and os.path.isdir(p.backup_dir):
        names = sorted(n for n in os.listdir(p.backup_dir) if n.endswith(".tar"))
        tui.kv("Last backup", names[-1] if names else "%snone yet%s" % (WARM, RESET))
    tui.p("")


def cmd_uninstall(args):
    if os.geteuid() != 0:
        raise SystemExit("Run as root: sudo cipherchat-admin uninstall")
    facts = Facts()
    tui.banner("Uninstall", facts.installed or "")
    saved = Plan(**(facts.saved or {}))
    if args.purge:
        tui.note("This deletes ALL chat data, the settings, the server key and the backups. It can't be undone.", BAD)
        if not args.yes:
            tui.ask("Type the address (%s) to confirm" % (saved.domain or "cipherchat"), "",
                    lambda s: None if s == (saved.domain or "cipherchat") else "That isn't it. Ctrl+C to stop.")
    elif not args.yes and not tui.confirm("Remove CipherChat? The data, settings and server key stay in %s and %s" % (steps.STATE, steps.ETC), False):
        raise Cancelled()
    steps.uninstall(args.purge, tui.Reporter())
    tui.p("\n  %sCipherChat was removed.%s%s\n" % (OK, RESET, "" if args.purge else " Its data is still in %s and %s." % (steps.STATE, steps.ETC)))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="cipherchat-setup", description="CipherChat by DarkCipher Systems: server setup")
    sub = ap.add_subparsers(dest="cmd")
    i = sub.add_parser("install")
    i.add_argument("--plan", help="answers as JSON (unattended)")
    i.add_argument("--check", action="store_true", help="with --plan: validate only, change nothing")
    sub.add_parser("status")
    u = sub.add_parser("uninstall")
    u.add_argument("--purge", action="store_true", help="also delete all data, settings, the server key and backups")
    u.add_argument("--yes", action="store_true", help="don't ask")
    args = ap.parse_args(argv)
    try:
        {"install": cmd_install, "status": cmd_status, "uninstall": cmd_uninstall, None: cmd_install}[args.cmd](
            args if args.cmd else ap.parse_args(["install"]))
    except Cancelled:
        tui.p("\n  %sStopped. Nothing after this point was changed.%s\n" % (DIM, RESET))
        sys.exit(1)
    except steps.StepFailed:
        tui.p("\n  %sThe setup stopped.%s Finished steps are kept and it is safe to run again. Details: %s\n" % (BAD, RESET, steps.LOG))
        sys.exit(1)


if __name__ == "__main__":
    main()
