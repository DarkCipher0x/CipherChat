#!/usr/bin/env python3
"""Passkey signature checks against published vectors, and tamper cases.
    python3 -I server/tests/test_webauthn.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "cipherchat"))
import webauthn_verify as wv  # noqa: E402

H = bytes.fromhex


class Ed25519(unittest.TestCase):
    # RFC 8032 section 7.1, TEST 1 and TEST 2
    V = [("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
          "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
         ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
          "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")]

    def test_rfc8032_vectors(self):
        for pub, msg, sig in self.V:
            self.assertTrue(wv.ed25519_verify(H(pub), H(msg), H(sig)))

    def test_tampering(self):
        pub, msg, sig = (H(x) for x in self.V[1])
        self.assertFalse(wv.ed25519_verify(pub, msg + b"x", sig))
        self.assertFalse(wv.ed25519_verify(pub, msg, sig[:63] + bytes([sig[63] ^ 1])))
        self.assertFalse(wv.ed25519_verify(H(self.V[0][0]), msg, sig))
        # a non-canonical S (S + L) must be refused (malleability)
        s = int.from_bytes(sig[32:], "little") + wv._l
        self.assertFalse(wv.ed25519_verify(pub, msg, sig[:32] + s.to_bytes(32, "little")))
        self.assertFalse(wv.ed25519_verify(pub, msg, sig[:10]))


class P256(unittest.TestCase):
    # RFC 6979 appendix A.2.5 (P-256, SHA-256), messages "sample" and "test"
    X = int("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6", 16)
    Y = int("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299", 16)
    V = [(b"sample", "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716", "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"),
         (b"test", "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367", "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083")]

    def test_rfc6979_vectors(self):
        for msg, r, s in self.V:
            self.assertTrue(wv.p256_verify(self.X, self.Y, msg, int(r, 16), int(s, 16)))

    def test_tampering(self):
        msg, r, s = self.V[0]
        r, s = int(r, 16), int(s, 16)
        self.assertFalse(wv.p256_verify(self.X, self.Y, b"samplf", r, s))
        self.assertFalse(wv.p256_verify(self.X, self.Y, msg, r, s ^ 1))
        self.assertFalse(wv.p256_verify(self.X, self.Y, msg, 0, s))
        self.assertFalse(wv.p256_verify(self.X, self.Y + 1, msg, r, s))                   # not on the curve

    def test_der(self):
        r, s = 0x7f, 0x80
        der = bytes([0x30, 7, 0x02, 1, 0x7f, 0x02, 2, 0x00, 0x80])
        self.assertEqual(wv.der_signature(der), (r, s))
        for bad in (der + b"\x00", bytes([0x30, 6, 0x02, 1, 0x7f, 0x02, 1, 0x80]), bytes([0x30, 8, 0x02, 2, 0x00, 0x7f, 0x02, 2, 0x00, 0x80])):
            with self.assertRaises(ValueError):
                wv.der_signature(bad)


class Cbor(unittest.TestCase):
    def test_cose_key(self):
        key = bytes([0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20]) + bytes(32)
        v, end = wv.cbor_decode(key)
        self.assertEqual(v, {1: 1, 3: -8, -1: 6, -2: bytes(32)})
        self.assertEqual(end, len(key))
        with self.assertRaises(wv.CborError):
            wv.cbor_decode(bytes([0x5f]))                                                     # indefinite length
        with self.assertRaises(wv.CborError):
            wv.cbor_decode(bytes([0x58, 0x20, 1, 2]))                                         # truncated


if __name__ == "__main__":
    unittest.main(verbosity=1)
