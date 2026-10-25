using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using static CipherChat.Crypto.Bytes;
using static CipherChat.Crypto.Hybrid;

namespace CipherChat.Crypto;

/// <summary>
/// Power-on self-test, the same checks as the web chat's selfTest() and the phone's SelfTest: OpenSSL known answers (an
/// implementation independent of BouncyCastle), round trips and tamper cases. The app refuses to unlock if any check fails.
/// </summary>
public static class SelfTest
{
    public sealed record Check(string Name, bool Ok);

    public static IReadOnlyList<Check> Run()
    {
        var out_ = new List<Check>();
        void Check(string name, bool ok) { out_.Add(new Check(name, ok)); if (!ok) throw new CryptoFail("self-test failed: " + name); }

        Check("SHA3-256 known answer", Hex(Sha3_256(Utf8("abc"))) == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
        var seed = FromHex(Kat.seed32);
        var kem = MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_1024, Concat(seed, seed));
        Check("ML-KEM-1024 key generation matches OpenSSL", Hex(Sha3_256(kem.GetPublicKeyEncoded())) == Kat.mlkem1024_pk_sha3);
        var dec = new MLKemDecapsulator(MLKemParameters.ml_kem_1024);
        dec.Init(kem);
        var ct = Unb64(Kat.mlkem1024_ct, Sizes.KemCt);
        var ss = new byte[dec.SecretLength];
        dec.Decapsulate(ct, 0, ct.Length, ss, 0, ss.Length);
        Check("ML-KEM-1024 decapsulates OpenSSL's ciphertext", Hex(ss) == Kat.mlkem1024_ss);
        var dsa = MLDsaPrivateKeyParameters.FromSeed(MLDsaParameters.ml_dsa_87, seed);
        Check("ML-DSA-87 key generation matches OpenSSL", Hex(Sha3_256(dsa.GetPublicKeyEncoded())) == Kat.mldsa87_pk_sha3);
        bool KatVerify(string ctx)
        {
            var v = new MLDsaSigner(MLDsaParameters.ml_dsa_87, deterministic: false);
            v.Init(false, new ParametersWithContext(dsa.GetPublicKey(), Utf8(ctx)));
            var m = Utf8(Kat.mldsa87_msg);
            v.BlockUpdate(m, 0, m.Length);
            return v.VerifySignature(Unb64(Kat.mldsa87_sig, Sizes.SigPqLen));
        }
        Check("ML-DSA-87 verifies OpenSSL's signature", KatVerify(Kat.mldsa87_context));
        Check("ML-DSA-87 refuses it under another context", !KatVerify("dcx-chat/v1/other"));

        var a = IdentityFromMaster("selftest-a", Random(32));
        var b = IdentityFromMaster("selftest-b", Random(32));
        var k = Random(32);
        var w = WrapKey(k, b.KemPqPk, b.KemEcPk, Utf8("t"));
        Check("hybrid key wrap round trip", Same(UnwrapKey(w, b, Utf8("t")), k));
        bool refused;
        try { UnwrapKey(w, a, Utf8("t")); refused = false; } catch (CryptoFail) { refused = true; }
        Check("hybrid key wrap refuses the wrong recipient", refused);
        var msg = Utf8("dcx");
        var s = Sign(a, "t", msg);
        Check("hybrid signature verifies", Verify(a.SigPqPk, a.SigEcPk, "t", msg, s));
        var s1 = (byte[])s.Clone(); s1[10] ^= 1;
        Check("hybrid signature refuses a changed ML-DSA part", !Verify(a.SigPqPk, a.SigEcPk, "t", msg, s1));
        var s2 = (byte[])s.Clone(); s2[^1] ^= 1;
        Check("hybrid signature refuses a changed Ed25519 part", !Verify(a.SigPqPk, a.SigEcPk, "t", msg, s2));
        Check("hybrid signature is bound to its context", !Verify(a.SigPqPk, a.SigEcPk, "u", msg, s));
        return out_;
    }
}
