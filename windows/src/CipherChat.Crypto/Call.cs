using System.Text.Json.Nodes;
using static CipherChat.Crypto.Bytes;

namespace CipherChat.Crypto;

/// <summary>
/// The cryptography of calls, line for line the same as web/app/callcrypto.js (docs/CALLS.md): signed call signals,
/// per-sender media keys wrapped with ML-KEM-1024 + X25519, and the call words. The Windows app's call screen
/// (WebView2) asks for these through its bridge, so the identity's private keys never enter the WebView.
/// </summary>
public static class Call
{
    public const string SignalLabel = "dcx-chat/v1/call-signal";
    public const int SignalMax = 48 * 1024;
    private const long FreshMs = 120_000;
    private static readonly string[] Kinds = ["ring", "accept", "decline", "busy", "offer", "answer", "ice", "key", "leave", "end", "state"];
    private static readonly System.Text.RegularExpressions.Regex IdRe = new("^[A-Za-z0-9_-]{22}$");
    private static readonly System.Text.RegularExpressions.Regex DevRe = new("^[A-Za-z0-9_-]{8,22}$");

    private static string B64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    public static string NewCallId() => B64Url(Random(16));
    public static string NewDeviceId() => B64Url(Random(12));

    /// <summary>fields: kind, room, call, dev, to and the kind's own fields. Returns the {h, s} the server relays.</summary>
    public static JsonObject Seal(Identity me, string myFp, JsonObject fields)
    {
        var hdr = new JsonObject { ["v"] = 1, ["t"] = "call", ["from"] = me.User, ["from_fp"] = myFp,
                                   ["at"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), ["n"] = B64Url(Random(9)) };
        foreach (var (k, v) in fields) hdr[k] = v?.DeepClone();
        var raw = Canon.Bytes(hdr);
        if (raw.Length > SignalMax) throw new CryptoFail("call signal too large");
        return new JsonObject { ["h"] = B64(raw), ["s"] = B64(Hybrid.Sign(me, SignalLabel, raw)) };
    }

    /// <summary>One entry of poll().signals -> the verified header. trusted(user) is the identity this device trusts, or null.</summary>
    public static JsonObject Open(JsonObject item, Func<string, PublicIdentity?> trusted, ISet<string> seen, long? nowMs = null)
    {
        var sig = item.Obj("sig");
        var signed = Canon.ParseSigned(sig.Str("h"), SignalMax);
        var o = signed.Obj;
        if (o.StrOrNull("t") != "call" || o.StrOrNull("from") != item.StrOrNull("from") || o.StrOrNull("room") != item.StrOrNull("room")
            || o.StrOrNull("kind") != item.StrOrNull("kind") || o.StrOrNull("call") != item.StrOrNull("call"))
            throw new CryptoFail("call signal doesn't match its envelope");
        if (!Kinds.Contains(o.Str("kind")) || !IdRe.IsMatch(o.Str("call")) || !DevRe.IsMatch(o.StrOrNull("dev") ?? "") || o["to"] is not JsonArray)
            throw new CryptoFail("malformed call signal");
        if (Math.Abs((nowMs ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()) - o.Long("at")) > FreshMs) throw new CryptoFail("call signal is stale");
        var who = trusted(o.Str("from"));
        if (who is null || who.Fp != o.StrOrNull("from_fp")) throw new CryptoFail("call signal from an identity you don't trust");
        if (!Hybrid.Verify(who, SignalLabel, signed.Raw, Unb64(sig.Str("s")))) throw new CryptoFail("call signal signature is invalid");
        var tag = o.Str("call") + "|" + o.Str("dev") + "|" + o.Str("n");
        lock (seen)
        {
            if (!seen.Add(tag)) throw new CryptoFail("replayed call signal");
            if (seen.Count > 5000) seen.Remove(seen.First());
        }
        return o;
    }

    private static byte[] KeyAad(string call, string from, string dev, long epoch, string to, string toFp) =>
        Utf8(string.Join('|', "dcx-chat/v1/call-key", call, from, dev, epoch.ToString(System.Globalization.CultureInfo.InvariantCulture), to, toFp));

    /// <summary>The fields of a "key" signal: this device's sender key for an epoch, wrapped to each recipient.</summary>
    public static JsonObject WrapSenderKey(byte[] key32, string call, Identity me, string dev, long epoch, IEnumerable<PublicIdentity> recipients)
    {
        var keys = new JsonObject();
        foreach (var r in recipients) keys[r.User] = B64(Hybrid.WrapKey(key32, r.KemPq, r.KemEc, KeyAad(call, me.User, dev, epoch, r.User, r.Fp)));
        return new JsonObject { ["epoch"] = epoch, ["keys"] = keys };
    }

    public static byte[] UnwrapSenderKey(JsonObject sig, Identity me, string myFp)
    {
        var w = (sig["keys"] as JsonObject)?.StrOrNull(me.User);
        var epoch = sig.LongOrNull("epoch");
        if (w is null || epoch is null or < 0) throw new CryptoFail("no call key for you in this signal");
        return Hybrid.UnwrapKey(Unb64(w), me, KeyAad(sig.Str("call"), sig.Str("from"), sig.Str("dev"), epoch.Value, me.User, myFp));
    }

    private static readonly string[] Words = (
        "acorn agent alpha amber anchor angel apple arrow atlas autumn badge baker bamboo banjo barrel basin beacon " +
        "beaver bishop blanket blossom bonus border bottle bounty bracket bridge bronze bubble bucket buffalo butter cabin cactus " +
        "camel candle canyon captain carbon carpet castle cedar cello chalk channel cherry chess chimney cider cinema circus citrus " +
        "clover cobalt cocoa comet compass copper coral cotton coyote crater crayon cricket crystal cupcake cyclone dancer delta " +
        "denim desert diamond dingo dolphin domino dragon dream drum eagle easel echo eclipse ember emerald engine falcon feather fennel " +
        "ferry fiddle finch flame flint forest fossil fountain fox galaxy garden garlic gazelle gecko geyser ginger glacier globe goblet " +
        "granite gravel guitar hammer harbor harvest hazel helmet hickory honey horizon hornet iceberg igloo indigo island ivory " +
        "jacket jaguar jasmine jelly jewel jungle kayak kernel kettle kiwi koala ladder lagoon lantern laser lemon lentil leopard lilac " +
        "linen lobster locket lotus magnet mango maple marble meadow melon meteor mint mirror mitten monsoon mosaic muffin nectar needle " +
        "nickel nugget oasis ocean olive onyx opal orbit orchid otter oyster paddle palace panda paper parrot pebble pepper piano " +
        "pilot pine planet plaza pocket pollen pony poppy prism pumpkin puzzle quartz quill rabbit radar raven reef ribbon river " +
        "robin rocket ruby saddle saffron salmon satin scarlet scooter shadow shell signal silver sketch sparrow spice spiral sprout " +
        "squirrel star stone sugar summit sunset swan tango teapot temple thistle thunder tiger timber toffee topaz torch tower tulip " +
        "tundra turtle umbrella valley velvet violet volcano wagon walnut walrus willow window winter wizard yacht yarrow zebra zephyr zinc").Split(' ');

    /// <summary>Four words from the call id and every participant's identity: the same on every screen only if nobody is in the middle.</summary>
    public static string[] CallWords(string call, IEnumerable<(string User, string Fp)> participants)
    {
        if (Words.Length != 256 || Words.Distinct().Count() != 256) throw new CryptoFail("call word list must be 256 distinct words");
        var lines = participants.Select(p => p.User + ":" + p.Fp).OrderBy(x => x, StringComparer.Ordinal);
        var h = Hybrid.Sha3_256(Utf8(string.Join('|', new[] { "dcx-chat/v1/call-words", call }.Concat(lines))));
        return [Words[h[0]], Words[h[1]], Words[h[2]], Words[h[3]]];
    }
}
