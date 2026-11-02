using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Parameters;
using static CipherChat.Crypto.Bytes;
using static CipherChat.Crypto.Hybrid;

namespace CipherChat.Crypto;

/// <summary>
/// One installation's own key pair (PROTOCOL.md §10). Random, never derived from the master, so the identity alone can't
/// rebuild it; its 96-byte seed (ML-KEM d‖z, then the X25519 private key) stays on the device, sealed by the key store.
/// </summary>
public sealed class Device
{
    internal MLKemPrivateKeyParameters KemPq { get; }
    public byte[] KemPqPk { get; }
    internal X25519PrivateKeyParameters KemEc { get; }
    public byte[] KemEcPk { get; }

    private Device(MLKemPrivateKeyParameters kemPq, X25519PrivateKeyParameters kemEc)
    {
        KemPq = kemPq; KemPqPk = kemPq.GetPublicKeyEncoded();
        KemEc = kemEc; KemEcPk = kemEc.GeneratePublicKey().GetEncoded();
    }

    public static Device FromSeed(byte[] seed)
    {
        if (seed.Length != 96) throw new CryptoFail("bad device seed");
        var d = seed[..64];
        try { return new Device(MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_1024, d), new X25519PrivateKeyParameters(seed, 64)); }
        finally { Wipe(d); }
    }
}

/// <summary>A line on someone's signed device list.</summary>
public sealed record DeviceEntry(string Id, string Name, string KemPq, string KemEc, long Added);

/// <summary>Someone's device list, checked against their trusted identity.</summary>
public sealed record DeviceList(string User, string Fp, long Seq, long At, IReadOnlyList<DeviceEntry> Devices);

public sealed record SyncedKey(string Room, long Epoch, byte[] Key);

/// <summary>Device lists, the key store's double seal and history-sync packages, as the web chat and the phone make them.</summary>
public static partial class Devices
{
    public static byte[] NewSeed() => Random(96);
    public static string NewId() => Hex(Random(8));

    /// <summary>Shown on both devices before history moves: the first 16 hex of SHA3-256(kem_pq ‖ kem_ec), in groups of four.</summary>
    public static string Code(byte[] kemPq, byte[] kemEc) => FpGroups(Hex(Sha3_256(kemPq, kemEc))[..16]);

    public static DeviceEntry Entry(string id, string name, Device d, long added) => new(id, name, B64(d.KemPqPk), B64(d.KemEcPk), added);

    [GeneratedRegex("^[0-9a-f]{16}$")]
    private static partial Regex IdRe();

    public static Signed64 Publish(Identity id, string fp, long seq, IEnumerable<DeviceEntry> devices, long at)
    {
        var list = new JsonArray();
        foreach (var d in devices.OrderBy(d => d.Id, StringComparer.Ordinal))
            list.Add(new JsonObject { ["id"] = d.Id, ["name"] = d.Name, ["kem_pq"] = d.KemPq, ["kem_ec"] = d.KemEc, ["added"] = d.Added });
        var raw = Canon.Bytes(new JsonObject
        {
            ["v"] = 1, ["t"] = "devices", ["user"] = id.User, ["fp"] = fp, ["seq"] = seq, ["at"] = at, ["devices"] = list,
        });
        return new Signed64(B64(raw), B64(Sign(id, "dcx-chat/v1/devices", raw)));
    }

    public static DeviceList Open(Signed64 entry, PublicIdentity pub)
    {
        var sig = Canon.ParseSigned(entry.B, 16384 + 4096);
        var o = sig.Obj;
        if (o.StrOrNull("t") != "devices" || o.StrOrNull("user") != pub.User || o.StrOrNull("fp") != pub.Fp ||
            o.LongOrNull("seq") is not { } seq || seq < 1 || o["devices"] is not JsonArray arr)
            throw new CryptoFail("device list doesn't match the identity");
        if (!Verify(pub, "dcx-chat/v1/devices", sig.Raw, Unb64(entry.S))) throw new CryptoFail("device list signature is invalid");
        var list = new List<DeviceEntry>();
        string? prev = null;
        foreach (var n in arr)
        {
            if (n is not JsonObject d || d.StrOrNull("id") is not { } id || !IdRe().IsMatch(id) ||
                (prev is not null && string.CompareOrdinal(prev, id) >= 0)) throw new CryptoFail("malformed device list");
            Unb64(d.Str("kem_pq"), Sizes.KemPq); Unb64(d.Str("kem_ec"), Sizes.KemEc);
            list.Add(new DeviceEntry(id, d.StrOrNull("name") ?? "", d.Str("kem_pq"), d.Str("kem_ec"), d.LongOrNull("added") ?? 0));
            prev = id;
        }
        return new DeviceList(pub.User, pub.Fp, seq, o.LongOrNull("at") ?? 0, list);
    }

    // ------------------------------------------------------------------------------------------- the key store
    // aesSeal(deviceKey, aesSeal(storeKey, key, aad), aad). deviceKey never leaves this PC (DPAPI-protected on disk);
    // storeKey comes from the master, so a copy of the profile without the passphrase opens nothing either.
    public static byte[] StoreKey(byte[] master, string user) => Hkdf32(master, Utf8(user), "dcx-chat/v1/store-key");

    private static byte[] StoreAad(string user, string room, long epoch) => Utf8($"dcx-chat/v1/store|{user}|{room}|{epoch}");

    public static byte[] SealStored(byte[] deviceKey, byte[] storeKey, string user, string room, long epoch, byte[] key)
    {
        var aad = StoreAad(user, room, epoch);
        return AesSeal(deviceKey, AesSeal(storeKey, key, aad), aad);
    }

    public static byte[] OpenStored(byte[] deviceKey, byte[] storeKey, string user, string room, long epoch, byte[] sealed_, int len = 32)
    {
        var aad = StoreAad(user, room, epoch);
        var inner = AesOpen(deviceKey, sealed_, aad);
        try
        {
            var key = AesOpen(storeKey, inner, aad);
            if (key.Length != len) throw new CryptoFail("stored key has the wrong length");
            return key;
        }
        finally { Wipe(inner); }
    }

    /// <summary>The device's own seed is sealed the same way under a fixed name.</summary>
    public static byte[] SealSeed(byte[] deviceKey, byte[] storeKey, string user, byte[] seed) => SealStored(deviceKey, storeKey, user, "device", 0, seed);
    public static byte[] OpenSeed(byte[] deviceKey, byte[] storeKey, string user, byte[] sealed_) => OpenStored(deviceKey, storeKey, user, "device", 0, sealed_, 96);

    // ------------------------------------------------------------------------------------------- history sync
    private static byte[] SyncAad(string user, string from, string to) => Utf8($"dcx-chat/v1/key-sync|{user}|{from}|{to}");

    /// <summary>Room keys for another of my devices: wrap(k, target) ‖ aesSeal(k, u32(len p) ‖ p ‖ sig(p)). Returns base64.</summary>
    public static string SealKeySync(Identity id, string from, string to, byte[] targetKemPq, byte[] targetKemEc, IEnumerable<SyncedKey> keys, long at)
    {
        var arr = new JsonArray();
        foreach (var k in keys) arr.Add(new JsonObject { ["room"] = k.Room, ["epoch"] = k.Epoch, ["key"] = B64(k.Key) });
        var p = Canon.Bytes(new JsonObject { ["v"] = 1, ["t"] = "key-sync", ["user"] = id.User, ["from"] = from, ["to"] = to, ["at"] = at, ["keys"] = arr });
        var s = Sign(id, "dcx-chat/v1/key-sync", p);
        var k32 = Random(32);
        var aad = SyncAad(id.User, from, to);
        try { return B64(Concat(WrapKey(k32, targetKemPq, targetKemEc, aad), AesSeal(k32, Concat(U32be(p.Length), p, s), aad))); }
        finally { Wipe(k32, p); }
    }

    /// <summary><paramref name="myPub"/> is my own trusted identity: the package must be signed by it.</summary>
    public static List<SyncedKey> OpenKeySync(Device dev, PublicIdentity myPub, string from, string to, string blob)
    {
        var raw = Unb64(blob);
        if (raw.Length < Sizes.Wrap + 12 + 4 + 16) throw new CryptoFail("history package too short");
        var aad = SyncAad(myPub.User, from, to);
        var k32 = UnwrapKey(raw[..Sizes.Wrap], dev.KemPq, dev.KemPqPk, dev.KemEc, dev.KemEcPk, aad);
        byte[] inner;
        try { inner = AesOpen(k32, raw[Sizes.Wrap..], aad); }
        finally { Wipe(k32); }
        try
        {
            if (inner.Length < 4) throw new CryptoFail("malformed history package");
            var n = ((long)inner[0] << 24) | ((long)inner[1] << 16) | ((long)inner[2] << 8) | inner[3];
            if (n + 4 + Sizes.Sig != inner.Length) throw new CryptoFail("malformed history package");
            var p = inner[4..(4 + (int)n)];
            if (!Verify(myPub, "dcx-chat/v1/key-sync", p, inner[(4 + (int)n)..])) throw new CryptoFail("history package signature is invalid");
            string text;
            try { text = new UTF8Encoding(false, true).GetString(p); } catch (DecoderFallbackException) { throw new CryptoFail("malformed history package"); }
            if (Canon.Parse(text) is not JsonObject o || Canon.Encode(o) != text || o.LongOrNull("v") != 1 || o.StrOrNull("t") != "key-sync" ||
                o.StrOrNull("user") != myPub.User || o.StrOrNull("from") != from || o.StrOrNull("to") != to || o["keys"] is not JsonArray arr)
                throw new CryptoFail("history package doesn't match");
            return arr.Select(x => x is JsonObject k
                    ? new SyncedKey(k.Str("room"), k.Long("epoch"), Unb64(k.Str("key"), 32))
                    : throw new CryptoFail("history package doesn't match")).ToList();
        }
        finally { Wipe(inner); }
    }
}
