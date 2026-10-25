#!/bin/sh
# CipherChat by DarkCipher Systems: the Linux server setup. From the unpacked release, run:
#     sudo sh install.sh                      interactive: install, upgrade or change settings
#     sudo sh install.sh --plan plan.json     unattended (add --check to only validate it)
#     sudo sh install.sh status               what's installed and whether it's healthy
#     sudo sh install.sh uninstall [--purge]  remove it (data kept unless --purge)
# Checks the download, then starts the setup (deploy/setup/cipherchat_setup.py, Python standard library only).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
# the release root is this folder when install.sh sits at the top, or its parent when run as deploy/install.sh
if [ -f "$here/deploy/setup/cipherchat_setup.py" ]; then root=$here; else root=$(dirname "$here"); fi
if [ "$(id -u)" != "0" ]; then
  exec sudo sh "$here/$(basename "$0")" "$@"
fi
if [ -f "$root/SHA256SUMS" ]; then
  if ! (cd "$root" && sha256sum --check --quiet SHA256SUMS); then
    echo "The download is damaged (checksum mismatch). Please download it again." >&2
    exit 1
  fi
fi
if ! command -v python3 >/dev/null 2>&1 || ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
  echo "CipherChat needs Python 3.10 or newer (Debian 12+, Ubuntu 22.04+ have it: apt install python3)." >&2
  exit 1
fi
case "${1:-}" in
  status|uninstall) exec python3 -I "$root/deploy/setup/cipherchat_setup.py" "$@" ;;
  *) exec python3 -I "$root/deploy/setup/cipherchat_setup.py" install "$@" ;;
esac
