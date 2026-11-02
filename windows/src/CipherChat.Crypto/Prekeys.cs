using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using static CipherChat.Crypto.Bytes;
using static CipherChat.Crypto.Hybrid;

namespace CipherChat.Crypto;

/// <summary>Someone's published prekey, checked against their trusted identity and device list. Raw public keys.</summary>
public sealed record Prekey(string Dev, string Id, long At, long Exp, byte[] KemPq, byte[] KemEc);

/// <summary>
/// Prekeys (PROTOCOL.md §11): a random ML-KEM-1024 + X25519 pair like the device key (same 96-byte seed, Device.FromSeed),
/// published signed for 7 days and erased by its device when it expires, so nothing the identity can rebuild opens a v2 wrap.
/// </summary>
public static partial class Prekeys
{
    public const long LifeMs = 7 * 86400 * 1000L;
    private const long LifeMaxMs = 8 * 86400 * 1000L;
    private const long MarginMs = 3600 * 1000L;          // an hour of life left, at least, to be used for a new room key
    private static readonly long[] V2 = [2];

    public static string NewId() => Hex(Random(8));

    [GeneratedRegex("^[0-9a-f]{16}$")]
    private static partial Regex IdRe();

    public static Signed64 Publish(Identity id, string fp, string dev, string pid, Device pre, long at)
    {
        var raw = Canon.Bytes(new JsonObject
        {
            ["v"] = 2, ["t"] = "prekey", ["user"] = id.User, ["fp"] = fp, ["dev"] = dev, ["id"] = pid, ["at"] = at,
            ["exp"] = at + LifeMs, ["kem_pq"] = B64(pre.KemPqPk), ["kem_ec"] = B64(pre.KemEcPk),
        });
        return new Signed64(B64(raw), B64(Sign(id, "dcx-chat/v2/prekey", raw)));
    }

    /// <summary><paramref name="listedIds"/>: the device ids on the owner's verified device list.</summary>
    public static Prekey Open(Signed64 entry, PublicIdentity pub, IReadOnlyCollection<string> listedIds, long now)
    {
        var sig = Canon.ParseSigned(entry.B, 4096, V2);
        var o = sig.Obj;
        if (o.StrOrNull("t") != "prekey" || o.StrOrNull("user") != pub.User || o.StrOrNull("fp") != pub.Fp ||
            o.StrOrNull("dev") is not { } dev || !listedIds.Contains(dev) || o.StrOrNull("id") is not { } pid || !IdRe().IsMatch(pid) ||
            o.LongOrNull("at") is not { } at || o.LongOrNull("exp") is not { } exp || exp - at > LifeMaxMs || exp - now < MarginMs)
            throw new CryptoFail("prekey doesn't match or has expired");
        var kemPq = Unb64(o.Str("kem_pq"), Sizes.KemPq);
        var kemEc = Unb64(o.Str("kem_ec"), Sizes.KemEc);
        if (!Verify(pub, "dcx-chat/v2/prekey", sig.Raw, Unb64(entry.S))) throw new CryptoFail("prekey signature is invalid");
        return new Prekey(dev, pid, at, exp, kemPq, kemEc);
    }
}
