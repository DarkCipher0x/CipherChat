using System.Text;
using System.Text.Json.Nodes;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using static CipherChat.Crypto.Bytes;

namespace CipherChat.Crypto;

/// <summary>
/// The sealed identity backup on the server, identical to the web chat's and the phone's: AES-256-GCM under
/// HKDF-SHA-512(Argon2id(passphrase) || server key share). Argon2id: 64 MiB, 3 passes, 1 lane, version 0x13.
/// The same passphrase opens it in a browser, on the phone and here.
/// </summary>
public static class Backup
{
    public const int MKib = 65536, T = 3, P = 1;

    public static JsonObject Seal(string user, string passphrase, byte[] pepper, int pepperVer, JsonObject payload)
    {
        var salt = Random(32);
        var key = Key(user, passphrase, pepper, pepperVer, salt, MKib, T, P);
        try
        {
            var sealed_ = Hybrid.AesSeal(key, Canon.Bytes(payload), Utf8("dcx-chat/v1/backup|" + user + "|" + pepperVer));
            return new JsonObject
            {
                ["v"] = 1,
                ["kdf"] = new JsonObject { ["alg"] = "argon2id", ["m"] = MKib, ["t"] = T, ["p"] = P, ["salt"] = B64(salt) },
                ["pepper_ver"] = pepperVer,
                ["n"] = B64(sealed_[..12]),
                ["c"] = B64(sealed_[12..]),
            };
        }
        finally { Wipe(key); }
    }

    public static JsonObject Open(string user, string passphrase, byte[] pepper, JsonObject backup)
    {
        var kdf = backup["kdf"] as JsonObject ?? throw new CryptoFail("unsupported backup format");
        var m = kdf.LongOrNull("m"); var t = kdf.LongOrNull("t"); var p = kdf.LongOrNull("p");
        if (backup.LongOrNull("v") != 1 || kdf.StrOrNull("alg") != "argon2id" || m is null || t is null || p is null ||
            m < 65536 || m > 1048576 || t < 2 || t > 16 || p < 1 || p > 4) throw new CryptoFail("unsupported backup format");
        var ver = (int)backup.Long("pepper_ver");
        var key = Key(user, passphrase, pepper, ver, Unb64(kdf.Str("salt"), 32), (int)m, (int)t, (int)p);
        try
        {
            byte[] plain;
            try { plain = Hybrid.AesOpen(key, Concat(Unb64(backup.Str("n"), 12), Unb64(backup.Str("c"))), Utf8("dcx-chat/v1/backup|" + user + "|" + ver)); }
            catch (CryptoFail) { throw new CryptoFail("wrong passphrase"); }
            try { return Canon.Parse(Encoding.UTF8.GetString(plain)) as JsonObject ?? throw new CryptoFail("malformed backup"); }
            finally { Wipe(plain); }
        }
        finally { Wipe(key); }
    }

    private static byte[] Key(string user, string passphrase, byte[] pepper, int pepperVer, byte[] salt, int m, int t, int p)
    {
        // NFKC like String.prototype.normalize("NFKC") in the browser, then UTF-8
        var pw = Utf8(passphrase.Normalize(NormalizationForm.FormKC));
        var a = new byte[32];
        try
        {
            var g = new Argon2BytesGenerator();
            g.Init(new Argon2Parameters.Builder(Argon2Parameters.Argon2id).WithVersion(Argon2Parameters.Version13)
                .WithMemoryAsKB(m).WithIterations(t).WithParallelism(p).WithSalt(salt).Build());
            g.GenerateBytes(pw, a);
            var ikm = Concat(a, pepper);
            try { return Hybrid.Hkdf32(ikm, salt, "dcx-chat/v1/backup-key|" + user + "|" + pepperVer); }
            finally { Wipe(ikm); }
        }
        finally { Wipe(pw, a); }
    }
}
