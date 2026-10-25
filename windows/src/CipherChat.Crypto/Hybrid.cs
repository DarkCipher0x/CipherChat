using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using static CipherChat.Crypto.Bytes;

namespace CipherChat.Crypto;

/// <summary>
/// The DarkCipher chat protocol's cryptography: a C# port of the web chat's crypto.js and the Android app's Hybrid.kt,
/// byte-for-byte compatible with both (tests: OpenSSL known answers, browser-made and phone-made fixtures).
///
/// Hybrid post-quantum throughout, so each step stays secure while EITHER half holds:
///   key wrapping   ML-KEM-1024 (FIPS 203) + X25519, both secrets and the whole transcript through HKDF-SHA-512
///   signatures     ML-DSA-87 (FIPS 204, with a context string) + Ed25519; valid only if BOTH verify
///   symmetric      AES-256-GCM; SHA3-256/512 for fingerprints and commitments
/// All of it is BouncyCastle (pinned by content hash in packages.lock.json) except AES-GCM, which is Windows' own (CNG).
/// </summary>
public static class Sizes
{
    public const int KemPq = 1568, KemEc = 32, SigPq = 2592, SigEc = 32;
    public const int KemCt = 1568, SigPqLen = 4627, SigEcLen = 64;
    public const int Sig = SigPqLen + SigEcLen;
    public const int Wrap = 1568 + 32 + 12 + 32 + 16;
}

/// <summary>A person's private identity, derived from one 32-byte master secret (so a new device rebuilds identical keys).</summary>
public sealed class Identity
{
    public string User { get; }
    internal MLKemPrivateKeyParameters KemPq { get; }
    public byte[] KemPqPk { get; }
    internal X25519PrivateKeyParameters KemEc { get; }
    public byte[] KemEcPk { get; }
    internal MLDsaPrivateKeyParameters SigPq { get; }
    public byte[] SigPqPk { get; }
    internal Ed25519PrivateKeyParameters SigEc { get; }
    public byte[] SigEcPk { get; }

    internal Identity(string user, MLKemPrivateKeyParameters kemPq, X25519PrivateKeyParameters kemEc,
                      MLDsaPrivateKeyParameters sigPq, Ed25519PrivateKeyParameters sigEc)
    {
        User = user;
        KemPq = kemPq; KemPqPk = kemPq.GetPublicKeyEncoded();
        KemEc = kemEc; KemEcPk = kemEc.GeneratePublicKey().GetEncoded();
        SigPq = sigPq; SigPqPk = sigPq.GetPublicKeyEncoded();
        SigEc = sigEc; SigEcPk = sigEc.GeneratePublicKey().GetEncoded();
    }
}

/// <summary>Someone's verified public identity (self-signature checked by <see cref="Hybrid.OpenIdentity"/>).</summary>
public sealed record PublicIdentity(string User, string Fp, long At, byte[] KemPq, byte[] KemEc, byte[] SigPq, byte[] SigEc);

public sealed record Published(string B, string S, string Fp);

public sealed record Signed64(string B, string S);

public static class Hybrid
{
    public const string Suite = "ML-KEM-1024+X25519 / ML-DSA-87+Ed25519 / AES-256-GCM / SHA-3";

    internal static readonly SecureRandom Rng = new();

    // -------------------------------------------------------------------------------------------- primitives
    public static byte[] Sha3_256(params byte[][] parts) => Sha3(256, parts);
    public static byte[] Sha3_512(params byte[][] parts) => Sha3(512, parts);

    private static byte[] Sha3(int bits, byte[][] parts)
    {
        var d = new Sha3Digest(bits);
        foreach (var p in parts) d.BlockUpdate(p, 0, p.Length);
        var out_ = new byte[bits / 8];
        d.DoFinal(out_, 0);
        return out_;
    }

    /// <summary>HKDF-SHA-512 to a 32-byte AES-256 key (what WebCrypto's deriveKey(HKDF -> AES-GCM 256) produces).</summary>
    internal static byte[] Hkdf32(byte[] ikm, byte[] salt, string info)
    {
        var g = new HkdfBytesGenerator(new Sha512Digest());
        g.Init(new HkdfParameters(ikm, salt, Utf8(info)));
        var out_ = new byte[32];
        g.GenerateBytes(out_, 0, 32);
        return out_;
    }

    /// <summary>AES-256-GCM: nonce(12) || ciphertext || tag(16).</summary>
    internal static byte[] AesSeal(byte[] key, byte[] plain, byte[] aad)
    {
        var nonce = Random(12);
        var ct = new byte[plain.Length];
        var tag = new byte[16];
        using (var g = new AesGcm(key, 16)) g.Encrypt(nonce, plain, ct, tag, aad);
        return Concat(nonce, ct, tag);
    }

    internal static byte[] AesOpen(byte[] key, byte[] sealed_, byte[] aad)
    {
        if (sealed_.Length < 12 + 16) throw new CryptoFail("ciphertext too short");
        var plain = new byte[sealed_.Length - 28];
        try
        {
            using var g = new AesGcm(key, 16);
            g.Decrypt(sealed_.AsSpan(0, 12), sealed_.AsSpan(12, plain.Length), sealed_.AsSpan(sealed_.Length - 16), plain, aad);
            return plain;
        }
        catch (CryptographicException) { throw new CryptoFail("decryption failed (wrong key or the data was changed)"); }
    }

    private static byte[] X25519(X25519PrivateKeyParameters priv, byte[] pub)
    {
        var out_ = new byte[32];
        try
        {
            var a = new X25519Agreement();
            a.Init(priv);
            a.CalculateAgreement(new X25519PublicKeyParameters(pub, 0), out_, 0);
        }
        catch (InvalidOperationException) { throw new CryptoFail("invalid X25519 key"); }   // BouncyCastle refuses a low-order result
        if (out_.All(b => b == 0)) throw new CryptoFail("invalid X25519 key");
        return out_;
    }

    // -------------------------------------------------------------------------------------------- identities
    private static byte[] Derive(byte[] master, string label, int len)
    {
        var input = Concat(Utf8("dcx-chat/v1/seed/" + label + "|"), master);
        return len == 64 ? Sha3_512(input) : Sha3_256(input);
    }

    public static Identity IdentityFromMaster(string user, byte[] master)
    {
        if (master.Length != 32) throw new CryptoFail("bad master secret");
        var kemSeed = Derive(master, "kem-pq", 64);
        var sigSeed = Derive(master, "sig-pq", 32);
        var xSeed = Derive(master, "kem-ec", 32);
        var edSeed = Derive(master, "sig-ec", 32);
        try
        {
            return new Identity(user,
                MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_1024, kemSeed),     // FIPS 203 keygen from d || z
                new X25519PrivateKeyParameters(xSeed, 0),
                MLDsaPrivateKeyParameters.FromSeed(MLDsaParameters.ml_dsa_87, sigSeed),       // FIPS 204 keygen from xi
                new Ed25519PrivateKeyParameters(edSeed, 0));
        }
        finally { Wipe(kemSeed, sigSeed, xSeed, edSeed); }
    }

    /// <summary>The signed public half everyone else uses.</summary>
    public static Published PublishIdentity(Identity id, long at)
    {
        var raw = Canon.Bytes(new JsonObject
        {
            ["v"] = 1, ["t"] = "identity", ["user"] = id.User, ["at"] = at,
            ["kem_pq"] = B64(id.KemPqPk), ["kem_ec"] = B64(id.KemEcPk), ["sig_pq"] = B64(id.SigPqPk), ["sig_ec"] = B64(id.SigEcPk),
        });
        return new Published(B64(raw), B64(Sign(id, "dcx-chat/v1/identity", raw)), Hex(Sha3_256(raw)));
    }

    /// <summary>Someone else's published identity -> verified public keys. WHO it belongs to comes from the owner's certificate.</summary>
    public static PublicIdentity OpenIdentity(string b, string s, string expectUser, string? expectFp = null)
    {
        var sig = Canon.ParseSigned(b, 16384);
        var o = sig.Obj;
        if (o.Str("t") != "identity" || o.Str("user") != expectUser) throw new CryptoFail("identity is for someone else");
        var fp = Hex(Sha3_256(sig.Raw));
        if (expectFp is not null && expectFp != fp) throw new CryptoFail("fingerprint mismatch");
        var pub = new PublicIdentity(expectUser, fp, o.Long("at"),
            Unb64(o.Str("kem_pq"), Sizes.KemPq), Unb64(o.Str("kem_ec"), Sizes.KemEc),
            Unb64(o.Str("sig_pq"), Sizes.SigPq), Unb64(o.Str("sig_ec"), Sizes.SigEc));
        if (!Verify(pub.SigPq, pub.SigEc, "dcx-chat/v1/identity", sig.Raw, Unb64(s))) throw new CryptoFail("identity self-signature is invalid");
        return pub;
    }

    // -------------------------------------------------------------------------------------------- hybrid signatures
    public static byte[] Sign(Identity id, string label, byte[] msg)
    {
        var pq = new MLDsaSigner(MLDsaParameters.ml_dsa_87, deterministic: false);
        // hedged signing (fresh randomness), with the FIPS 204 context string = the purpose label
        pq.Init(true, new ParametersWithContext(new ParametersWithRandom(id.SigPq, Rng), Utf8(label)));
        pq.BlockUpdate(msg, 0, msg.Length);
        var s1 = pq.GenerateSignature();
        var ec = new Ed25519Signer();
        ec.Init(true, id.SigEc);
        var m2 = Concat(Utf8(label), [0], msg);
        ec.BlockUpdate(m2, 0, m2.Length);
        return Concat(s1, ec.GenerateSignature());
    }

    public static bool Verify(PublicIdentity pub, string label, byte[] msg, byte[] sig) => Verify(pub.SigPq, pub.SigEc, label, msg, sig);

    /// <summary>BOTH halves must verify; a malformed signature is simply false.</summary>
    public static bool Verify(byte[] sigPqPk, byte[] sigEcPk, string label, byte[] msg, byte[] sig)
    {
        if (sig.Length != Sizes.Sig) return false;
        bool pq, ec;
        try
        {
            var v = new MLDsaSigner(MLDsaParameters.ml_dsa_87, deterministic: false);
            v.Init(false, new ParametersWithContext(MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_87, sigPqPk), Utf8(label)));
            v.BlockUpdate(msg, 0, msg.Length);
            pq = v.VerifySignature(sig[..Sizes.SigPqLen]);
        }
        catch (Exception) { pq = false; }
        try
        {
            var v = new Ed25519Signer();
            v.Init(false, new Ed25519PublicKeyParameters(sigEcPk, 0));
            var m2 = Concat(Utf8(label), [0], msg);
            v.BlockUpdate(m2, 0, m2.Length);
            ec = v.VerifySignature(sig[Sizes.SigPqLen..]);
        }
        catch (Exception) { ec = false; }
        return pq && ec;
    }

    // -------------------------------------------------------------------------------------------- hybrid key wrapping
    /// <summary>Wraps a 32-byte key for one recipient: ML-KEM ct (1568) || X25519 ephemeral (32) || nonce (12) || GCM (48).</summary>
    public static byte[] WrapKey(byte[] key32, byte[] rcptKemPq, byte[] rcptKemEc, byte[] aad)
    {
        var enc = new MLKemEncapsulator(MLKemParameters.ml_kem_1024);
        enc.Init(new ParametersWithRandom(MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_1024, rcptKemPq), Rng));
        var ct = new byte[enc.EncapsulationLength];
        var ssPq = new byte[enc.SecretLength];
        enc.Encapsulate(ct, 0, ct.Length, ssPq, 0, ssPq.Length);
        var eph = new X25519PrivateKeyParameters(Rng);
        var ephPub = eph.GeneratePublicKey().GetEncoded();
        var ssEc = X25519(eph, rcptKemEc);
        var wk = WrapKdf(ssPq, ssEc, ct, ephPub, rcptKemPq, rcptKemEc);
        Wipe(ssPq, ssEc);
        try { return Concat(ct, ephPub, AesSeal(wk, key32, aad)); }
        finally { Wipe(wk); }
    }

    public static byte[] UnwrapKey(byte[] wrapped, Identity id, byte[] aad)
    {
        if (wrapped.Length != Sizes.Wrap) throw new CryptoFail("wrapped key has the wrong length");
        var ct = wrapped[..1568];
        var ephPub = wrapped[1568..1600];
        var sealed_ = wrapped[1600..];
        var dec = new MLKemDecapsulator(MLKemParameters.ml_kem_1024);
        dec.Init(id.KemPq);
        var ssPq = new byte[dec.SecretLength];
        dec.Decapsulate(ct, 0, ct.Length, ssPq, 0, ssPq.Length);   // implicit rejection: a wrong ct gives a random secret
        var ssEc = X25519(id.KemEc, ephPub);
        var wk = WrapKdf(ssPq, ssEc, ct, ephPub, id.KemPqPk, id.KemEcPk);
        Wipe(ssPq, ssEc);
        try
        {
            var key = AesOpen(wk, sealed_, aad);
            if (key.Length != 32) throw new CryptoFail("wrapped key has the wrong length");
            return key;
        }
        finally { Wipe(wk); }
    }

    /// <summary>"KitchenSink" combiner: both secrets are the key material; both ciphertexts and both recipient keys are in the salt.</summary>
    private static byte[] WrapKdf(byte[] ssPq, byte[] ssEc, byte[] ct, byte[] ephPub, byte[] kemPq, byte[] kemEc)
    {
        var salt = Sha3_512(Utf8("dcx-chat/v1/wrap-transcript|"), ct, ephPub, kemPq, kemEc);
        var ikm = Concat(ssPq, ssEc);
        try { return Hkdf32(ikm, salt, "dcx-chat/v1/wrap-key"); }
        finally { Wipe(ikm); }
    }

    // -------------------------------------------------------------------------------------------- fingerprints
    public static string FpGroups(string fp) => string.Join(' ', fp.Chunk(4).Select(c => new string(c)));

    /// <summary>60 digits both people see identically; reading them to each other verifies both keys at once.</summary>
    public static string SafetyNumber(string fpA, string fpB)
    {
        var (x, y) = string.CompareOrdinal(fpA, fpB) <= 0 ? (fpA, fpB) : (fpB, fpA);
        var h = Sha3_512(Utf8("dcx-chat/v1/safety|" + x + "|" + y));
        return string.Join(' ', Enumerable.Range(0, 12).Select(i =>
        {
            long n = 0;
            for (var j = 0; j < 5; j++) n = n * 256 + h[i * 5 + j];
            return (n % 100000).ToString("D5", System.Globalization.CultureInfo.InvariantCulture);
        }));
    }

    // -------------------------------------------------------------------------------------------- certificates
    public static Signed64 MakeCert(Identity owner, string ownerFp, string user, string fp, long at)
    {
        var raw = Canon.Bytes(new JsonObject
        {
            ["v"] = 1, ["t"] = "cert", ["user"] = user, ["fp"] = fp, ["by"] = owner.User, ["by_fp"] = ownerFp, ["at"] = at,
        });
        return new Signed64(B64(raw), B64(Sign(owner, "dcx-chat/v1/cert", raw)));
    }

    public static bool VerifyCert(Signed64 cert, PublicIdentity ownerPub, string user, string fp)
    {
        Canon.Signed s;
        byte[] sig;
        try { s = Canon.ParseSigned(cert.B, 1024); sig = Unb64(cert.S); } catch (CryptoFail) { return false; }
        var o = s.Obj;
        if (o.StrOrNull("t") != "cert" || o.StrOrNull("user") != user || o.StrOrNull("fp") != fp ||
            o.StrOrNull("by") != ownerPub.User || o.StrOrNull("by_fp") != ownerPub.Fp) return false;
        return Verify(ownerPub, "dcx-chat/v1/cert", s.Raw, sig);
    }
}
