using System.Text.Json.Nodes;
using CipherChat.Crypto;
using static CipherChat.Crypto.Bytes;
using static CipherChat.Crypto.Hybrid;

namespace CipherChat.Crypto.Tests;

/// <summary>
/// Byte compatibility with the other two clients, in every direction.
///   browser-made.json  made by the real crypto.js in a browser (noble + WebCrypto)
///   phone-made.json    made by the Android app's core:crypto (BouncyCastle Java)
///   windows-made.json  written here (<see cref="WindowsMakesAFixtureForTheOthers"/>) for the browser check and the
///                      Android tests to open; kept in the repo next to this file.
/// </summary>
public class InteropTests
{
    /// <summary>Where fixtures made by Windows go: the committed interop folder only when CIPHERCHAT_WRITE_FIXTURES=1
    /// (they hold fresh random bytes, which must be checked before they're committed); otherwise the build output.</summary>
    internal static string FixtureDir() =>
        Environment.GetEnvironmentVariable("CIPHERCHAT_WRITE_FIXTURES") == "1"
            ? Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "interop"))
            : Path.Combine(AppContext.BaseDirectory, "made");

    private static JsonObject Load(string name) =>
        (JsonObject)(Canon.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "interop", name))) ?? throw new InvalidOperationException(name));

    [Theory]
    [InlineData("browser-made.json")]
    [InlineData("phone-made.json")]
    public void WindowsOpensWhatTheOthersMade(string fixture)
    {
        var f = Load(fixture);
        var at = f.Long("at");
        // Same master secret -> byte-identical public identity (ML-KEM, ML-DSA, X25519, Ed25519 and the SHA-3 seed derivation)
        var owner = IdentityFromMaster("dcx-admin", Unb64(f.Str("owner_master"), 32));
        var alice = IdentityFromMaster("alice", Unb64(f.Str("alice_master"), 32));
        Assert.Equal(f.Obj("owner").Str("fp"), PublishIdentity(owner, at).Fp);
        Assert.Equal(f.Obj("alice").Str("fp"), PublishIdentity(alice, at).Fp);
        Assert.Equal(f.Obj("owner").Str("b"), PublishIdentity(owner, at).B);
        // Their hybrid signatures verify here
        var oPub = OpenIdentity(f.Obj("owner").Str("b"), f.Obj("owner").Str("s"), "dcx-admin", f.Obj("owner").Str("fp"));
        var aPub = OpenIdentity(f.Obj("alice").Str("b"), f.Obj("alice").Str("s"), "alice", f.Obj("alice").Str("fp"));
        Assert.True(VerifyCert(new Signed64(f.Obj("cert").Str("b"), f.Obj("cert").Str("s")), oPub, "alice", aPub.Fp));
        Assert.Equal(f.Str("safety"), SafetyNumber(oPub.Fp, aPub.Fp));
        // Argon2id + server key share + HKDF + AES-GCM: their sealed backup opens with the same passphrase
        var bk = f.Obj("backup");
        var payload = Backup.Open("alice", bk.Str("passphrase"), Unb64(bk.Str("pepper"), 32), bk.Obj("sealed"));
        Assert.Equal(Canon.Encode(bk.Obj("payload")), Canon.Encode(payload));
        // Their room key (ML-KEM-1024 encapsulation + X25519 + combiner) unwraps for alice
        var e = f.Obj("epoch");
        var ep = Room.OpenEpoch(alice, aPub.Fp, e.Str("room"), e.Long("epoch"), e.Str("from"), e.Str("h"), e.Str("s"), e.Str("w_alice"), oPub);
        Assert.Equal(e.Str("key_sha3"), Hex(Sha3_256(ep.Key)));
        // ...and their message under it opens and verifies
        var m = f.Obj("message");
        var opened = Room.OpenMessage(m.Str("room"), m.Long("epoch"), m.Str("from"), m.Str("h"), m.Str("c"), m.Str("s"), ep.Key, oPub);
        Assert.Equal(m.Str("text"), opened.Text);
    }

    [Fact]
    public void WindowsMakesAFixtureForTheOthers()
    {
        const long at = 1792800000000L;
        var ownerMaster = Random(32); var aliceMaster = Random(32);
        var owner = IdentityFromMaster("dcx-admin", ownerMaster); var alice = IdentityFromMaster("alice", aliceMaster);
        var o = PublishIdentity(owner, at); var a = PublishIdentity(alice, at);
        var oPub = OpenIdentity(o.B, o.S, "dcx-admin"); var aPub = OpenIdentity(a.B, a.S, "alice");
        var cert = MakeCert(owner, o.Fp, "alice", a.Fp, at + 1);
        var pepper = Random(32); const string passphrase = "interop passphrase éè 2026";
        var payload = new JsonObject { ["v"] = 1, ["master"] = B64(aliceMaster), ["anchor_fp"] = o.Fp, ["created"] = at };
        var sealed_ = Backup.Seal("alice", passphrase, pepper, 1, payload);
        const string room = "0123456789abcdef";
        var ep = Room.BuildEpoch(owner, o.Fp, room, 1, [new Room.Recipient("alice", a.Fp, aPub), new Room.Recipient("dcx-admin", o.Fp, oPub)], "");
        const string text = "from Windows: ```code``` ✓ 😀 <b>x</b>";
        var msg = Room.SealMessage(owner, o.Fp, room, 1, ep.Key, Room.Text(text));
        var fixture = new JsonObject
        {
            ["made_by"] = "CipherChat for Windows, CipherChat.Crypto (BouncyCastle .NET)", ["at"] = at,
            ["owner_master"] = B64(ownerMaster), ["alice_master"] = B64(aliceMaster),
            ["owner"] = new JsonObject { ["b"] = o.B, ["s"] = o.S, ["fp"] = o.Fp },
            ["alice"] = new JsonObject { ["b"] = a.B, ["s"] = a.S, ["fp"] = a.Fp },
            ["cert"] = new JsonObject { ["b"] = cert.B, ["s"] = cert.S },
            ["safety"] = SafetyNumber(o.Fp, a.Fp),
            ["backup"] = new JsonObject { ["user"] = "alice", ["passphrase"] = passphrase, ["pepper"] = B64(pepper), ["sealed"] = sealed_, ["payload"] = payload.DeepClone() },
            ["epoch"] = new JsonObject { ["room"] = room, ["epoch"] = 1, ["from"] = "dcx-admin", ["h"] = ep.Pkg.H, ["s"] = ep.Pkg.S,
                                         ["w_alice"] = ep.Pkg.W["alice"], ["key_sha3"] = Hex(Sha3_256(ep.Key)) },
            ["message"] = new JsonObject { ["room"] = room, ["epoch"] = 1, ["from"] = "dcx-admin", ["h"] = msg.H, ["c"] = msg.C, ["s"] = msg.S, ["text"] = text },
        };
        // Fresh randomness every run, so it goes into the build output; the committed copy the browser check and the
        // Android tests open is only replaced on purpose (CIPHERCHAT_WRITE_FIXTURES=1, docs/INTEROP.md)
        var dir = FixtureDir();
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "windows-made.json"), fixture.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        // sanity: Windows opens its own fixture too
        var key = Room.OpenEpoch(alice, a.Fp, room, 1, "dcx-admin", ep.Pkg.H, ep.Pkg.S, ep.Pkg.W["alice"], oPub).Key;
        Assert.Equal(text, Room.OpenMessage(room, 1, "dcx-admin", msg.H, msg.C, msg.S, key, oPub).Text);
    }
}
