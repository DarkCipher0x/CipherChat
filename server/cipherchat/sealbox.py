"""Sealing the few secrets the server itself must keep (the SMTP password, queued emails that carry one-time links).

Keys come from the server key file (storage.py, never in the database or its backups) with HMAC-SHA3-256 and a purpose
label, separate keys for encryption and authentication. A value is sealed with a SHAKE256 keystream (key, purpose and
a fresh 192-bit nonce in, as many bytes as the plaintext out) and authenticated encrypt-then-MAC with HMAC-SHA3-256 over
the version, purpose, nonce and ciphertext. Only SHA-3 from Python's standard library is used (no third-party
cryptography), and 256-bit symmetric keys keep their strength against quantum computers. A copy of the database alone
opens nothing; the purpose label stops a sealed value being moved into another field.

    s1.<server key version>.<nonce>.<ciphertext>.<tag>      (base64url parts)
"""
import base64
import hashlib
import hmac
import secrets

import storage

PREFIX = "s1"


class SealError(Exception):
    pass


def _b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _keys(version, purpose):
    ring = storage.KEYRING
    if ring is None or version not in ring.keys:
        raise SealError("the server key for this value isn't loaded")
    return _derive(ring.get(version), purpose)


def _derive(base, purpose):
    label = b"cipherchat-seal/v1|" + purpose.encode()
    return (hmac.new(base, label + b"|enc", hashlib.sha3_256).digest(),
            hmac.new(base, label + b"|mac", hashlib.sha3_256).digest())


def _xor(data, key, nonce, purpose):
    stream = hashlib.shake_256(key + nonce + purpose.encode()).digest(len(data))
    return (int.from_bytes(data, "big") ^ int.from_bytes(stream, "big")).to_bytes(len(data), "big") if data else b""


def seal(plaintext, purpose):
    """str or bytes -> sealed text. purpose: a fixed label for where the value lives (e.g. "smtp-password")."""
    data = plaintext.encode("utf-8") if isinstance(plaintext, str) else bytes(plaintext)
    ring = storage.KEYRING
    if ring is None:
        raise SealError("the server key isn't loaded")
    return seal_with(PREFIX, ring.current, _keys(ring.current, purpose), data, purpose)


def open_(sealed, purpose):
    """Sealed text -> bytes. Raises SealError if it was changed, moved to another purpose or the key is missing."""
    return open_with(PREFIX, lambda version: _keys(version, purpose), sealed, purpose)


def seal_with(prefix, version, keys, data, purpose):
    """The same construction under a caller's own key (shred.py's rolling storage keys): keys = _derive(base, purpose)."""
    enc, mac = keys
    nonce = secrets.token_bytes(24)
    ct = _xor(data, enc, nonce, purpose)
    tag = hmac.new(mac, b"|".join([prefix.encode(), str(version).encode(), purpose.encode(), nonce, ct]), hashlib.sha3_256).digest()
    return ".".join([prefix, str(version), _b64(nonce), _b64(ct), _b64(tag)])


def version_of(sealed, prefix):
    """The key version a sealed value names, or None if it isn't one of `prefix`."""
    parts = sealed.split(".") if isinstance(sealed, str) else ()
    return int(parts[1]) if len(parts) == 5 and parts[0] == prefix and parts[1].isdigit() and parts[1].isascii() else None


def open_with(prefix, keys_for, sealed, purpose):
    """keys_for(version) -> (enc, mac), raising SealError when that key is gone."""
    try:
        pre, ver, n, c, t = sealed.split(".")
        if not (ver.isdigit() and ver.isascii()):
            raise ValueError
        version, nonce, ct, tag = int(ver), _unb64(n), _unb64(c), _unb64(t)
    except (AttributeError, ValueError):
        raise SealError("not a sealed value")
    if pre != prefix or len(nonce) != 24 or len(tag) != 32:
        raise SealError("not a sealed value")
    enc, mac = keys_for(version)
    want = hmac.new(mac, b"|".join([prefix.encode(), str(version).encode(), purpose.encode(), nonce, ct]), hashlib.sha3_256).digest()
    if not hmac.compare_digest(want, tag):
        raise SealError("the sealed value doesn't verify")
    return _xor(ct, enc, nonce, purpose)


def open_text(sealed, purpose):
    return open_(sealed, purpose).decode("utf-8")
