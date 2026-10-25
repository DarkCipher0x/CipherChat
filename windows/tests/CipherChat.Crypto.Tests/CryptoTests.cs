using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using CipherChat.Crypto;
using static CipherChat.Crypto.Bytes;
using static CipherChat.Crypto.Hybrid;

namespace CipherChat.Crypto.Tests;

/// <summary>The protocol on its own (same cases as the web chat's selftest.html and the phone's CryptoTest). Interop is in InteropTests.</summary>
public class CryptoTests
{
    private static void Refuses(string what, Action block)
    {
        try { block(); Assert.Fail(what + " was accepted"); }
        catch (CryptoFail) { /* refused, as it must be */ }
    }

    [Fact]
    public void SelfTestPasses()
    {
        var checks = SelfTest.Run();
        Assert.True(checks.Count >= 12);
        Assert.All(checks, c => Assert.True(c.Ok, c.Name));
    }

    [Fact]
    public void CanonicalJsonMatchesJavaScript()
    {
        var o = new JsonObject { ["b"] = "x\"y\\\n\u0001é😀", ["a"] = 12, ["c"] = true };
        Assert.Equal("{\"a\":12,\"b\":\"x\\\"y\\\\\\n\\u0001é😀\",\"c\":true}", Canon.Encode(o));
        Assert.Equal("\"\\ud800x\"", Canon.Encode(JsonValue.Create("\ud800x")));         // lone surrogate, like JSON.stringify
        Refuses("a non-integer", () => Canon.Encode(new JsonObject { ["x"] = 1.5 }));
        Refuses("a number past JavaScript's safe range", () => Canon.Encode(new JsonObject { ["x"] = 9007199254740992L }));
        Refuses("a non-canonical header", () => Canon.ParseSigned(B64(Utf8("{\"v\":1, \"a\":2}")), 100));
        Refuses("a header with keys out of order", () => Canon.ParseSigned(B64(Utf8("{\"v\":1,\"a\":2}")), 100));
        Refuses("a header with a duplicate key", () => Canon.ParseSigned(B64(Utf8("{\"a\":2,\"a\":3,\"v\":1}")), 100));
        Refuses("1.0 for 1", () => Canon.ParseSigned(B64(Utf8("{\"v\":1.0}")), 100));
        Assert.Equal(1L, Canon.ParseSigned(B64(Utf8("{\"a\":2,\"v\":1}")), 100).Obj.Long("v"));
    }

    [Fact]
    public void IdentitiesAreDeterministicAndSelfSigned()
    {
        var master = Random(32);
        var a1 = PublishIdentity(IdentityFromMaster("carol", master), 7);
        var a2 = PublishIdentity(IdentityFromMaster("carol", master), 7);
        Assert.Equal(a1.Fp, a2.Fp);                                    // new device -> same identity
        Assert.NotEqual(a1.S, a2.S);                                   // hedged signatures
        var pub = OpenIdentity(a1.B, a1.S, "carol", a1.Fp);
        Assert.Equal(1568, pub.KemPq.Length);
        Refuses("an identity claimed for someone else", () => OpenIdentity(a1.B, a1.S, "bob"));
        var other = PublishIdentity(IdentityFromMaster("carol", Random(32)), 7);
        Refuses("an identity with someone else's signature", () => OpenIdentity(a1.B, other.S, "carol"));
        Refuses("a wrong expected fingerprint", () => OpenIdentity(a1.B, a1.S, "carol", other.Fp));
    }

    [Fact]
    public void CertificatesAndSafetyNumbers()
    {
        var owner = IdentityFromMaster("dcx-admin", Random(32)); var o = PublishIdentity(owner, 1);
        var alice = IdentityFromMaster("alice", Random(32)); var a = PublishIdentity(alice, 1);
        var ownerPub = OpenIdentity(o.B, o.S, "dcx-admin");
        var cert = MakeCert(owner, o.Fp, "alice", a.Fp, 5);
        Assert.True(VerifyCert(cert, ownerPub, "alice", a.Fp));
        Assert.False(VerifyCert(cert, ownerPub, "alice", o.Fp));
        Assert.False(VerifyCert(MakeCert(alice, a.Fp, "alice", a.Fp, 5), ownerPub, "alice", a.Fp));
        var sn = SafetyNumber(o.Fp, a.Fp);
        Assert.Equal(sn, SafetyNumber(a.Fp, o.Fp));
        Assert.Matches(new Regex(@"^(\d{5} ){11}\d{5}$"), sn);
    }

    [Fact]
    public void BackupSealsAndRefusesTheWrongInputs()
    {
        var pepper = Random(32);
        var payload = new JsonObject { ["v"] = 1, ["master"] = B64(Random(32)), ["anchor_fp"] = string.Concat(Enumerable.Repeat("ab", 32)) };
        var sealed_ = Backup.Seal("alice", "correct horse battery staple 42", pepper, 1, payload);
        Assert.Equal(Canon.Encode(payload), Canon.Encode(Backup.Open("alice", "correct horse battery staple 42", pepper, sealed_)));
        Refuses("a wrong passphrase", () => Backup.Open("alice", "correct horse battery staple 43", pepper, sealed_));
        Refuses("a wrong server key share", () => Backup.Open("alice", "correct horse battery staple 42", Random(32), sealed_));
        Refuses("another account", () => Backup.Open("mallory", "correct horse battery staple 42", pepper, sealed_));
        var weak = (JsonObject)sealed_.DeepClone();
        weak.Obj("kdf")["m"] = 1024;
        Refuses("weakened settings", () => Backup.Open("alice", "x", pepper, weak));
    }

    [Fact]
    public void RoomKeysAndMessages()
    {
        var owner = IdentityFromMaster("dcx-admin", Random(32)); var o = PublishIdentity(owner, 1);
        var alice = IdentityFromMaster("alice", Random(32)); var a = PublishIdentity(alice, 1);
        var oPub = OpenIdentity(o.B, o.S, "dcx-admin"); var aPub = OpenIdentity(a.B, a.S, "alice");
        const string room = "0123456789abcdef";
        var built = Room.BuildEpoch(owner, o.Fp, room, 1, [new Room.Recipient("alice", a.Fp, aPub), new Room.Recipient("dcx-admin", o.Fp, oPub)], "");
        var got = Room.OpenEpoch(alice, a.Fp, room, 1, "dcx-admin", built.Pkg.H, built.Pkg.S, built.Pkg.W["alice"], oPub);
        Assert.True(Same(built.Key, got.Key));
        Refuses("someone else's copy", () => Room.OpenEpoch(alice, a.Fp, room, 1, "dcx-admin", built.Pkg.H, built.Pkg.S, built.Pkg.W["dcx-admin"], oPub));
        Refuses("a key signed by another identity", () => Room.OpenEpoch(alice, a.Fp, room, 1, "dcx-admin", built.Pkg.H, built.Pkg.S, built.Pkg.W["alice"], aPub));
        Refuses("a key replayed into another room", () => Room.OpenEpoch(alice, a.Fp, "fedcba9876543210", 1, "dcx-admin", built.Pkg.H, built.Pkg.S, built.Pkg.W["alice"], oPub));
        foreach (var at in new[] { 5, 1580, 1640 })
        {
            var w = Unb64(built.Pkg.W["alice"]);
            w[at] ^= 1;
            Refuses("a changed wrapped key at " + at, () => Room.OpenEpoch(alice, a.Fp, room, 1, "dcx-admin", built.Pkg.H, built.Pkg.S, B64(w), oPub));
        }
        var m = Room.SealMessage(alice, a.Fp, room, 1, got.Key, Room.Text("hello from Windows ✓"));
        var opened = Room.OpenMessage(room, 1, "alice", m.H, m.C, m.S, built.Key, aPub);
        Assert.Equal("hello from Windows ✓", opened.Text);
        Assert.Equal(12 + 256 + 16, Unb64(m.C).Length);
        var c = Unb64(m.C); c[20] ^= 1;
        Refuses("a changed ciphertext", () => Room.OpenMessage(room, 1, "alice", m.H, B64(c), m.S, built.Key, aPub));
        Refuses("another sender", () => Room.OpenMessage(room, 1, "dcx-admin", m.H, m.C, m.S, built.Key, oPub));
        Refuses("the wrong room key", () => Room.OpenMessage(room, 1, "alice", m.H, m.C, m.S, Random(32), aPub));
        Refuses("another epoch", () => Room.OpenMessage(room, 2, "alice", m.H, m.C, m.S, built.Key, aPub));
    }
}
