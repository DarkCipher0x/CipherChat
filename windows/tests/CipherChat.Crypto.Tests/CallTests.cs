using System.Text.Json.Nodes;
using CipherChat.Crypto;
using static CipherChat.Crypto.Bytes;

namespace CipherChat.Crypto.Tests;

/// <summary>
/// Calls (Call.cs, the twin of web/app/callcrypto.js): signed signals, wrapped sender keys, call words. The call words
/// are checked against values the browser computed; windows-call.json is written for the browser's own check
/// (web/tests/calltest.js).
/// </summary>
public class CallTests
{
    private static (Identity Id, PublicIdentity Pub) Person(string user, byte[]? master = null)
    {
        var id = Hybrid.IdentityFromMaster(user, master ?? Random(32));
        var p = Hybrid.PublishIdentity(id, 1_790_000_000_000);
        return (id, Hybrid.OpenIdentity(p.B, p.S, user));
    }

    private static JsonObject Envelope(JsonObject sig, string from, string room, string kind, string call) =>
        new() { ["sid"] = 1, ["room"] = room, ["from"] = from, ["at"] = 0, ["kind"] = kind, ["call"] = call, ["sig"] = sig.DeepClone() };

    [Fact]
    public void SignalsVerifyOnlyFromTrustedFreshUnchangedSenders()
    {
        var alice = Person("alice");
        var eve = Person("eve");
        var call = Call.NewCallId();
        var room = new string('r', 16);
        var fields = new JsonObject { ["kind"] = "ring", ["room"] = room, ["call"] = call, ["dev"] = Call.NewDeviceId(), ["to"] = new JsonArray("bob"), ["media"] = "video" };
        var sig = Call.Seal(alice.Id, alice.Pub.Fp, fields);
        PublicIdentity? Trusted(string u) => u == "alice" ? alice.Pub : null;

        var seen = new HashSet<string>();
        var hdr = Call.Open(Envelope(sig, "alice", room, "ring", call), Trusted, seen);
        Assert.Equal("video", hdr.Str("media"));
        Assert.Throws<CryptoFail>(() => Call.Open(Envelope(sig, "alice", room, "ring", call), Trusted, seen));                  // replay
        Assert.Throws<CryptoFail>(() => Call.Open(Envelope(sig, "alice", room, "ring", call), Trusted, new HashSet<string>(),
                                                  DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + 600_000));                    // stale
        Assert.Throws<CryptoFail>(() => Call.Open(Envelope(sig, "alice", room, "offer", call), Trusted, new HashSet<string>()));   // envelope differs
        var forged = Call.Seal(eve.Id, eve.Pub.Fp, fields);
        Assert.Throws<CryptoFail>(() => Call.Open(Envelope(forged, "eve", room, "ring", call), Trusted, new HashSet<string>()));   // untrusted
        var flipped = Unb64(sig.Str("s")); flipped[10] ^= 1;
        Assert.Throws<CryptoFail>(() => Call.Open(Envelope(new JsonObject { ["h"] = sig.Str("h"), ["s"] = B64(flipped) }, "alice", room, "ring", call),
                                                  Trusted, new HashSet<string>()));                                              // bad signature
    }

    [Fact]
    public void SenderKeysOpenOnlyForTheirRecipient()
    {
        var alice = Person("alice");
        var bob = Person("bob");
        var carol = Person("carol");
        var key = Random(32);
        var call = Call.NewCallId();
        var dev = Call.NewDeviceId();
        var pkg = Call.WrapSenderKey(key, call, alice.Id, dev, 3, [bob.Pub]);
        pkg["call"] = call; pkg["from"] = "alice"; pkg["dev"] = dev;
        Assert.True(Same(key, Call.UnwrapSenderKey(pkg, bob.Id, bob.Pub.Fp)));
        Assert.Throws<CryptoFail>(() => Call.UnwrapSenderKey(pkg, carol.Id, carol.Pub.Fp));
        pkg["epoch"] = 4;                                                                              // a different epoch: the AAD no longer matches
        Assert.ThrowsAny<Exception>(() => Call.UnwrapSenderKey(pkg, bob.Id, bob.Pub.Fp));
    }

    [Fact]
    public void CallWordsMatchTheBrowser()
    {
        Assert.Equal("coyote meadow willow pebble", string.Join(' ', Call.CallWords(new string('A', 22), [("bob", new string('b', 64)), ("alice", new string('a', 64))])));
        Assert.Equal("oyster autumn amber hazel", string.Join(' ', Call.CallWords("Zq0-_x".PadRight(22, '9'), [("owner.demo", string.Concat(Enumerable.Repeat("0123456789abcdef", 4)))])));
    }

    /// <summary>A "key" signal from Windows for the browser to verify and open (web/tests/calltest.js, fixtures/windows-call.json).</summary>
    [Fact]
    public void WindowsMakesACallFixtureForTheBrowser()
    {
        var bobMaster = Random(32);
        var alice = Person("alice");
        var bob = Person("bob", bobMaster);
        var alicePub = Hybrid.PublishIdentity(alice.Id, 1_790_000_000_000);
        var key = Random(32);
        var call = Call.NewCallId();
        var dev = Call.NewDeviceId();
        var room = new string('f', 16);
        var fields = Call.WrapSenderKey(key, call, alice.Id, dev, 7, [bob.Pub]);
        fields["kind"] = "key"; fields["room"] = room; fields["call"] = call; fields["dev"] = dev; fields["to"] = new JsonArray("bob");
        var sig = Call.Seal(alice.Id, alice.Pub.Fp, fields);
        var fixture = new JsonObject
        {
            ["alice"] = new JsonObject { ["b"] = alicePub.B, ["s"] = alicePub.S, ["fp"] = alicePub.Fp },
            ["bob_master"] = Hex(bobMaster),
            ["item"] = Envelope(sig, "alice", room, "key", call),
            ["key"] = Hex(key),
            ["made_at"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        };
        var dir = Path.Combine(AppContext.BaseDirectory, "interop");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "windows-call.json"), fixture.ToJsonString());
        // and Windows itself opens it, as a sanity check
        var opened = Call.Open((JsonObject)fixture["item"]!, u => u == "alice" ? alice.Pub : null, new HashSet<string>());
        Assert.True(Same(key, Call.UnwrapSenderKey(opened, bob.Id, bob.Pub.Fp)));
    }
}
