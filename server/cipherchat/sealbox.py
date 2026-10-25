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
    base = ring.get(version)
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
    version = ring.current
    enc, mac = _keys(version, purpose)
    nonce = secrets.token_bytes(24)
    ct = _xor(data, enc, nonce, purpose)
    tag = hmac.new(mac, b"|".join([PREFIX.encode(), str(version).encode(), purpose.encode(), nonce, ct]), hashlib.sha3_256).digest()
    return ".".join([PREFIX, str(version), _b64(nonce), _b64(ct), _b64(tag)])


def open_(sealed, purpose):
    """Sealed text -> bytes. Raises SealError if it was changed, moved to another purpose or the key is missing."""
    try:
        prefix, ver, n, c, t = sealed.split(".")
        version, nonce, ct, tag = int(ver), _unb64(n), _unb64(c), _unb64(t)
    except (AttributeError, ValueError):
        raise SealError("not a sealed value")
    if prefix != PREFIX or len(nonce) != 24 or len(tag) != 32:
        raise SealError("not a sealed value")
    enc, mac = _keys(version, purpose)
    want = hmac.new(mac, b"|".join([PREFIX.encode(), str(version).encode(), purpose.encode(), nonce, ct]), hashlib.sha3_256).digest()
    if not hmac.compare_digest(want, tag):
        raise SealError("the sealed value doesn't verify")
    return _xor(ct, enc, nonce, purpose)


def open_text(sealed, purpose):
    return open_(sealed, purpose).decode("utf-8")
