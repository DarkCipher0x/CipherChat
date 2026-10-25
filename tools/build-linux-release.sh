#!/bin/sh
# CipherChat by DarkCipher Systems: the Linux server release, dist/<version>/cipherchat-server-<version>-linux.tar.gz
# (run on Linux or in WSL from the repository root). The archive unpacks to cipherchat-server-<version>/ with install.sh
# at the top; SHA256SUMS inside lists every file and install.sh checks it before doing anything.
#     sh tools/build-linux-release.sh 0.1.1
set -eu
version=${1:?usage: build-linux-release.sh <version>}
repo=$(cd "$(dirname "$0")/.." && pwd)
name=cipherchat-server-$version
out=$repo/dist/$version
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

served=$(sed -n 's/^VERSION = "\([^"]*\)"$/\1/p' "$repo/server/cipherchat/server.py")
[ "$served" = "$version" ] || { echo "server.py says VERSION = $served, not $version" >&2; exit 1; }

dst=$work/$name
mkdir -p "$dst/server" "$dst/deploy"
cp "$repo/deploy/install.sh" "$dst/install.sh"
cp -r "$repo/deploy/." "$dst/deploy/"
cp -r "$repo/server/cipherchat" "$dst/server/cipherchat"
cp -r "$repo/web" "$dst/web"
cp "$repo/LICENSE" "$repo/THIRD-PARTY-NOTICES.md" "$repo/SECURITY.md" "$dst/"
cp -r "$repo/docs" "$dst/docs"
rm -rf "$dst/docs/screenshots"                 # the README gallery images: not needed on a server
[ -f "$repo/docs/LINUX-SERVER.md" ] && cp "$repo/docs/LINUX-SERVER.md" "$dst/README.md"
rm -rf "$dst/web/tests"
find "$dst" -name __pycache__ -type d -prune -exec rm -rf {} +
find "$dst" -name '*.pyc' -delete

# server files are ASCII with LF endings; refuse a build that would ship anything else
bad=$(find "$dst" -type f \( -name '*.py' -o -name '*.sh' -o -name '*.conf' -o -name '*.inc' -o -name '*.service' -o -name '*.timer' -o -name '*.example' -o -name 'cipherchat-admin' \) -exec grep -lI "$(printf '\r')" {} + || true)
[ -z "$bad" ] || { echo "CRLF line endings in: $bad" >&2; exit 1; }

find "$dst" -type d -exec chmod 755 {} +
find "$dst" -type f -exec chmod 644 {} +
chmod 755 "$dst/install.sh" "$dst/deploy/install.sh" "$dst/deploy/cipherchat-admin"
(cd "$dst" && find . -type f ! -name SHA256SUMS | LC_ALL=C sort | sed 's|^\./||' | xargs sha256sum > SHA256SUMS)

mkdir -p "$out"
tar --owner=0 --group=0 --numeric-owner --sort=name --mtime="@$(date +%s)" -C "$work" -czf "$out/$name-linux.tar.gz" "$name"
(cd "$out" && sha256sum "$name-linux.tar.gz")
echo "$out/$name-linux.tar.gz ($(du -h "$out/$name-linux.tar.gz" | cut -f1)), $(wc -l < "$dst/SHA256SUMS") files"
