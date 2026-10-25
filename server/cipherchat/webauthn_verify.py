"""Signature checks for passkeys (WebAuthn), Python standard library only: ECDSA P-256 with SHA-256 ("ES256", COSE -7)
and Ed25519 ("EdDSA", COSE -8), plus the small CBOR subset authenticators use. Verification only: the server never
holds a passkey's private key, so no secret ever goes through this code and timing can't leak one.

Checked in tests/test_webauthn.py against published vectors (RFC 8032 section 7.1, NIST/RFC 6979 P-256) and tamper cases.
"""
import hashlib

# ------------------------------------------------------------------ CBOR (RFC 8949): just what COSE keys and attestation use
class CborError(ValueError):
    pass


def cbor_decode(data, offset=0, depth=0):
    """(value, next offset). Maps, arrays, ints, byte/text strings, bools, null. Indefinite lengths are refused."""
    if depth > 16 or offset >= len(data):
        raise CborError("bad CBOR")
    ib = data[offset]
    major, info = ib >> 5, ib & 31
    offset += 1
    if info < 24:
        val = info
    elif info in (24, 25, 26, 27):
        n = 1 << (info - 24)
        if offset + n > len(data):
            raise CborError("bad CBOR")
        val = int.from_bytes(data[offset:offset + n], "big")
        offset += n
    else:
        raise CborError("unsupported CBOR")
    if major == 0:
        return val, offset
    if major == 1:
        return -1 - val, offset
    if major in (2, 3):
        if offset + val > len(data):
            raise CborError("bad CBOR")
        raw = bytes(data[offset:offset + val])
        return (raw if major == 2 else raw.decode("utf-8")), offset + val
    if major == 4:
        out = []
        for _ in range(val):
            item, offset = cbor_decode(data, offset, depth + 1)
            out.append(item)
        return out, offset
    if major == 5:
        out = {}
        for _ in range(val):
            k, offset = cbor_decode(data, offset, depth + 1)
            v, offset = cbor_decode(data, offset, depth + 1)
            out[k] = v
        return out, offset
    if major == 7:
        if info in (20, 21):
            return info == 21, offset
        if info == 22:
            return None, offset
    raise CborError("unsupported CBOR")


# ------------------------------------------------------------------ ECDSA P-256 (FIPS 186-5), verify only
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = P - 3
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


def _on_curve(pt):
    x, y = pt
    return 0 <= x < P and 0 <= y < P and (y * y - (x * x * x + A * x + B)) % P == 0


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def _mul(k, pt):
    out = None
    while k:
        if k & 1:
            out = _add(out, pt)
        pt = _add(pt, pt)
        k >>= 1
    return out


def p256_verify(x, y, msg, r, s):
    """True if (r, s) is a valid ECDSA P-256/SHA-256 signature of msg under the public point (x, y)."""
    q = (x, y)
    if not _on_curve(q) or not (1 <= r < N and 1 <= s < N):
        return False
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    w = pow(s, -1, N)
    pt = _add(_mul(e * w % N, G), _mul(r * w % N, q))
    return pt is not None and pt[0] % N == r


def der_signature(sig):
    """DER-encoded ECDSA signature (what authenticators send) -> (r, s). Strict: no trailing data, minimal ints."""
    def read_int(b, i):
        if b[i] != 0x02:
            raise ValueError
        n = b[i + 1]
        if n == 0 or n > 33 or i + 2 + n > len(b) or b[i + 2] >= 0x80 or (n > 1 and b[i + 2] == 0 and b[i + 3] < 0x80):
            raise ValueError
        return int.from_bytes(b[i + 2:i + 2 + n], "big"), i + 2 + n
    try:
        if len(sig) < 8 or sig[0] != 0x30 or sig[1] != len(sig) - 2:
            raise ValueError
        r, i = read_int(sig, 2)
        s, i = read_int(sig, i)
        if i != len(sig):
            raise ValueError
        return r, s
    except (ValueError, IndexError):
        raise ValueError("bad ECDSA signature encoding")


# ------------------------------------------------------------------ Ed25519 (RFC 8032), verify only
_q = 2 ** 255 - 19
_l = 2 ** 252 + 27742317777372353535851937790883648493
_d = -121665 * pow(121666, -1, _q) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _xrecover(y):
    xx = (y * y - 1) * pow(_d * y * y + 1, -1, _q)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if (x * x - xx) % _q != 0:
        return None
    return x


def _edd(p1, p2):
    (x1, y1, z1, t1), (x2, y2, z2, t2) = p1, p2
    a = (y1 - x1) * (y2 - x2) % _q
    b = (y1 + x1) * (y2 + x2) % _q
    c = t1 * 2 * _d * t2 % _q
    dd = z1 * 2 * z2 % _q
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return e * f % _q, g * h % _q, f * g % _q, e * h % _q


def _edmul(s, pt):
    out = (0, 1, 1, 0)
    while s:
        if s & 1:
            out = _edd(out, pt)
        pt = _edd(pt, pt)
        s >>= 1
    return out


def _decode_point(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    sign = b[31] >> 7
    if y >= _q:
        return None
    x = _xrecover(y)
    if x is None or (x == 0 and sign):
        return None
    if x & 1 != sign:
        x = _q - x
    return x, y, 1, x * y % _q


def _encode_point(p):
    x, y, z, _ = p
    zi = pow(z, -1, _q)
    x, y = x * zi % _q, y * zi % _q
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_EB = (15112221349535400772501151409588531511454012693041857206046113283949847762202,
       46316835694926478169428394003475163141307993866256225615783033603165251855960)
_EBASE = (_EB[0], _EB[1], 1, _EB[0] * _EB[1] % _q)


def ed25519_verify(pub, msg, sig):
    """True if sig (64 bytes) is a valid Ed25519 signature of msg under pub (32 bytes). Rejects non-canonical S."""
    if len(pub) != 32 or len(sig) != 64:
        return False
    a = _decode_point(pub)
    r = _decode_point(sig[:32])
    s = int.from_bytes(sig[32:], "little")
    if a is None or r is None or s >= _l:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % _l
    return _encode_point(_edmul(s, _EBASE)) == _encode_point(_edd(r, _edmul(h, a)))
