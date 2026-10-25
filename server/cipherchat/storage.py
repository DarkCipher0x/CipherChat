"""The server key: the secret the per-user "server key share" is derived from (chat.pepper()).

It lives in its own file (CIPHERCHAT_KEY_FILE, root/service-only, never in the database or its backups), so a copy of
the database alone can't even be used to guess passphrases offline. One line per version, "<version> <64 hex>"; the
highest version is current. Lose it and every sealed identity becomes unopenable: back it up offline.
"""
import os
import re
import secrets

KEYRING = None
_LINE = re.compile(r"^\s*(\d{1,6})\s+([0-9a-fA-F]{64})\s*$")


class Keyring:
    def __init__(self, keys):
        self.keys = keys
        self.current = max(keys)

    def get(self, version):
        return self.keys[version]


def load(path):
    """Loads the key file (creating it with one fresh key, mode 0600, if it doesn't exist). Returns the keyring."""
    global KEYRING
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write("1 %s\n" % secrets.token_hex(32))
    keys = {}
    with open(path) as fh:
        for line in fh:
            m = _LINE.match(line)
            if m:
                keys[int(m.group(1))] = bytes.fromhex(m.group(2))
    if not keys:
        raise SystemExit("no valid key in %s" % path)
    KEYRING = Keyring(keys)
    return KEYRING
