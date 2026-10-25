using System.Text;
using System.Text.Json.Nodes;
using static CipherChat.Crypto.Bytes;
using static CipherChat.Crypto.Hybrid;

namespace CipherChat.Crypto;

/// <summary>Room keys ("epochs") and messages, exactly as the web chat and the phone make and check them.</summary>
public static class Room
{
    private static readonly int[] PadBuckets = [256, 1024, 4096, 16384];
    public static readonly int MaxTextBytes = PadBuckets[^1] - 4 - 64;

    private static byte[] WrapAad(string room, long epoch, string u, string fp) => Utf8($"dcx-chat/v1/wrap|{room}|{epoch}|{u}|{fp}");
    private static string CommitOf(string room, long epoch, byte[] key) => Hex(Sha3_256(Utf8($"dcx-chat/v1/epoch-commit|{room}|{epoch}|"), key));
    public static string HeaderHash(byte[] raw) => Hex(Sha3_256(raw));

    public sealed record Recipient(string U, string Fp, PublicIdentity Pub);
    public sealed record EpochPkg(string H, string S, IReadOnlyDictionary<string, string> W);
    public sealed record Built(EpochPkg Pkg, byte[] Key);
    public sealed record Opened(byte[] Key, JsonObject Header, byte[] Raw);

    private static long NowMs() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    public static Built BuildEpoch(Identity me, string myFp, string room, long epoch, IReadOnlyList<Recipient> recipients, string prev)
    {
        var key = Random(32);
        var w = new Dictionary<string, string>();
        var lines = new JsonArray();
        foreach (var r in recipients)
        {
            var wrapped = WrapKey(key, r.Pub.KemPq, r.Pub.KemEc, WrapAad(room, epoch, r.U, r.Fp));
            w[r.U] = B64(wrapped);
            lines.Add(new JsonObject { ["u"] = r.U, ["fp"] = r.Fp, ["w"] = Hex(Sha3_256(wrapped)) });
        }
        var raw = Canon.Bytes(new JsonObject
        {
            ["v"] = 1, ["t"] = "epoch", ["room"] = room, ["epoch"] = epoch, ["by"] = me.User, ["by_fp"] = myFp,
            ["at"] = NowMs(), ["prev"] = prev, ["recipients"] = lines, ["commit"] = CommitOf(room, epoch, key),
        });
        return new Built(new EpochPkg(B64(raw), B64(Sign(me, "dcx-chat/v1/epoch", raw)), w), key);
    }

    /// <summary>
    /// An epoch item from the server (only MY wrapped copy, <paramref name="myWrap"/>). <paramref name="signer"/> must be the
    /// TRUSTED identity of the item's sender; the caller checks trust. Refuses unless the signature, my line, the wrap hash
    /// and the key commitment all match.
    /// </summary>
    public static Opened OpenEpoch(Identity me, string myFp, string room, long itemEpoch, string itemFrom,
                                   string h, string s, string? myWrap, PublicIdentity signer)
    {
        var sig = Canon.ParseSigned(h, 65536);
        var o = sig.Obj;
        if (o.Str("t") != "epoch" || o.Str("room") != room || o.Long("epoch") != itemEpoch || o.Str("by") != itemFrom ||
            o.Str("by") != signer.User || o.Str("by_fp") != signer.Fp) throw new CryptoFail("room key header doesn't match");
        if (!Verify(signer, "dcx-chat/v1/epoch", sig.Raw, Unb64(s))) throw new CryptoFail("room key signature is invalid");
        var line = o.Arr("recipients").Select(n => n as JsonObject ?? throw new CryptoFail("malformed recipients"))
                    .FirstOrDefault(l => l.StrOrNull("u") == me.User);
        if (line is null || line.Str("fp") != myFp || myWrap is null) throw new CryptoFail("this room key wasn't made for your current identity");
        var wrapped = Unb64(myWrap, Sizes.Wrap);
        if (Hex(Sha3_256(wrapped)) != line.Str("w")) throw new CryptoFail("wrapped key doesn't match the signed header");
        var key = UnwrapKey(wrapped, me, WrapAad(room, itemEpoch, me.User, myFp));
        if (CommitOf(room, itemEpoch, key) != o.Str("commit")) throw new CryptoFail("room key commitment mismatch");
        return new Opened(key, o, sig.Raw);
    }

    // ------------------------------------------------------------------------------------------- messages
    private static byte[] Pad(byte[] data)
    {
        var size = PadBuckets.FirstOrDefault(b => b >= data.Length + 4);
        if (size == 0) throw new CryptoFail("message too long");
        var out_ = new byte[size];
        U32be(data.Length).CopyTo(out_, 0);
        data.CopyTo(out_, 4);
        return out_;
    }

    private static byte[] Unpad(byte[] p)
    {
        if (p.Length < 4) throw new CryptoFail("bad padding");
        var n = ((long)p[0] << 24) | ((long)p[1] << 16) | ((long)p[2] << 8) | p[3];
        if (n > p.Length - 4) throw new CryptoFail("bad padding");
        return p[4..(4 + (int)n)];
    }

    private static byte[] MsgKey(byte[] roomKey, string room, long epoch, string id) => Hkdf32(roomKey, Utf8(id), $"dcx-chat/v1/msg|{room}|{epoch}");
    private static byte[] SigInput(byte[] h, byte[] c) => Concat(U32be(h.Length), h, c);

    public sealed record SealedMsg(string H, string C, string S);

    public sealed record OpenedMsg(JsonObject Header, JsonObject Payload)
    {
        public string Text => Payload.Str("text");
        public string Kind => Payload.StrOrNull("k") ?? "text";
        public string Id => Header.Str("id");
    }

    public static SealedMsg SealMessage(Identity me, string myFp, string room, long epoch, byte[] roomKey, JsonObject payload)
    {
        var id = B64Url(Random(16));
        var h = Canon.Bytes(new JsonObject
        {
            ["v"] = 1, ["t"] = "msg", ["room"] = room, ["epoch"] = epoch, ["from"] = me.User, ["from_fp"] = myFp,
            ["id"] = id, ["at"] = NowMs(),
        });
        var mk = MsgKey(roomKey, room, epoch, id);
        try
        {
            var c = AesSeal(mk, Pad(Canon.Bytes(payload)), h);
            return new SealedMsg(B64(h), B64(c), B64(Sign(me, "dcx-chat/v1/msg", SigInput(h, c))));
        }
        finally { Wipe(mk); }
    }

    public static JsonObject Text(string text, string kind = "text") => new() { ["k"] = kind, ["text"] = text };

    /// <summary><paramref name="sender"/> must be the TRUSTED identity of the item's sender.</summary>
    public static OpenedMsg OpenMessage(string itemRoom, long itemEpoch, string itemFrom, string h, string c, string s,
                                        byte[] roomKey, PublicIdentity sender)
    {
        var sig = Canon.ParseSigned(h, 2048);
        var o = sig.Obj;
        if (o.Str("t") != "msg" || o.Str("room") != itemRoom || o.Long("epoch") != itemEpoch || o.Str("from") != itemFrom ||
            o.Str("from") != sender.User || o.Str("from_fp") != sender.Fp) throw new CryptoFail("message header doesn't match");
        var ct = Unb64(c);
        if (!Verify(sender, "dcx-chat/v1/msg", SigInput(sig.Raw, ct), Unb64(s))) throw new CryptoFail("message signature is invalid");
        var mk = MsgKey(roomKey, itemRoom, itemEpoch, o.Str("id"));
        try
        {
            var plain = AesOpen(mk, ct, sig.Raw);
            JsonNode? payload;
            try { payload = Canon.Parse(new UTF8Encoding(false, true).GetString(Unpad(plain))); }
            catch (Exception e) when (e is CryptoFail or DecoderFallbackException) { throw new CryptoFail("malformed message"); }
            if (payload is not JsonObject po || po.StrOrNull("text") is null) throw new CryptoFail("malformed message");
            Payload.Check(po);
            return new OpenedMsg(o, po);
        }
        finally { Wipe(mk); }
    }
}
