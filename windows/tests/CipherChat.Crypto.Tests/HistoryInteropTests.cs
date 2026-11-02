using System.Text.Json.Nodes;
using CipherChat.Crypto;
using static CipherChat.Crypto.Bytes;
using static CipherChat.Crypto.Hybrid;

namespace CipherChat.Crypto.Tests;

/// <summary>
/// Devices, the key store and history sync (PROTOCOL.md §10) across clients: browser-history.json (crypto.js) and
/// phone-history.json (Android core:crypto) opened here; windows-history.json written for them, same rules as
/// <see cref="InteropTests.FixtureDir"/>.
/// </summary>
public class HistoryInteropTests
{
    private const string User = "alice", RoomId = "0123456789abcdef";

    private static JsonObject? Load(string name)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "interop", name);
        return File.Exists(path) ? (JsonObject)Canon.Parse(File.ReadAllText(path))! : null;
    }

    private static void Refused(Action a) => Assert.Throws<CryptoFail>(a);

    /// <summary>What every client checks on a fixture any client made (the same list as web/tests/historytest.js).</summary>
    private static void OpenFixture(JsonObject f)
    {
        var master = FromHex(f.Str("master"));
        var user = f.Str("user");
        var id = IdentityFromMaster(user, master);
        var bundle = f.Obj("bundle");
        var at = Canon.ParseSigned(bundle.Str("b"), 16384).Obj.Long("at");
        Assert.Equal(f.Str("fp"), PublishIdentity(id, at).Fp);
        var pub = OpenIdentity(bundle.Str("b"), bundle.Str("s"), user, f.Str("fp"));
        var dl = f.Obj("devices");
        var list = Devices.Open(new Signed64(dl.Str("b"), dl.Str("s")), pub);
        Assert.Equal(1, list.Seq);
        Assert.Equal(2, list.Devices.Count);
        var to = Device.FromSeed(Unb64(f.Str("device_seed_to"), 96));
        var listed = list.Devices.Single(d => d.Id == f.Str("to"));
        Assert.Equal(listed.KemPq, B64(to.KemPqPk));
        Assert.Equal(listed.KemEc, B64(to.KemEcPk));
        Assert.Equal(f.Str("code_to"), Devices.Code(to.KemPqPk, to.KemEcPk));
        var keys = Devices.OpenKeySync(to, pub, f.Str("from"), f.Str("to"), f.Str("sync_blob"));
        Assert.Single(keys);
        Assert.Equal(f.Str("room"), keys[0].Room);
        Assert.Equal(f.Str("room_key"), Hex(keys[0].Key));
        // the key passes the signed header's commitment without its wrap; a different key doesn't
        var e = f.Obj("epoch_item");
        var body = e.Obj("body");
        Room.CheckEpoch(f.Str("room"), e.Long("epoch"), e.Str("from"), body.Str("h"), body.Str("s"), pub, keys[0].Key);
        Refused(() => Room.CheckEpoch(f.Str("room"), e.Long("epoch"), e.Str("from"), body.Str("h"), body.Str("s"), pub, Random(32)));
        Refused(() => Devices.OpenKeySync(to, pub, f.Str("from"), f.Str("to"), f.Str("sync_tampered")));
        Refused(() => Devices.OpenKeySync(to, pub, f.Str("to"), f.Str("from"), f.Str("sync_blob")));   // no replay between other devices
        Refused(() => Devices.OpenKeySync(Device.FromSeed(Devices.NewSeed()), pub, f.Str("from"), f.Str("to"), f.Str("sync_blob")));
        // the key store's double seal
        var st = f.Obj("store");
        var sk = Devices.StoreKey(master, user);
        var dk = Unb64(st.Str("device_key"), 32);
        var sealed_ = Unb64(st.Str("sealed"));
        Assert.Equal(f.Str("room_key"), Hex(Devices.OpenStored(dk, sk, user, st.Str("room"), st.Long("epoch"), sealed_)));
        Refused(() => Devices.OpenStored(dk, sk, user, st.Str("room"), 2, sealed_));
        Refused(() => Devices.OpenStored(dk, Devices.StoreKey(Random(32), user), user, st.Str("room"), st.Long("epoch"), sealed_));
        if (f["v2"] is not JsonObject v) return;        // made before protocol 2
        // protocol 2: prekeys and a per-device room key
        static Signed64 S64(JsonNode? n) => new(n!["b"]!.GetValue<string>(), n["s"]!.GetValue<string>());
        static long AtOf(Signed64 x) => Canon.ParseSigned(x.B, 4096, [2]).Obj.Long("at");
        var ids = list.Devices.Select(d => d.Id).ToList();
        var pkTo = S64(v["prekey_to"]);
        var pTo = Prekeys.Open(pkTo, pub, ids, AtOf(pkTo));
        var pre = Device.FromSeed(Unb64(v.Str("prekey_seed_to"), 96));
        Assert.Equal(f.Str("to"), pTo.Dev);
        Assert.Equal(B64(pre.KemPqPk), B64(pTo.KemPq));
        Assert.Equal(B64(pre.KemEcPk), B64(pTo.KemEc));
        Prekeys.Open(S64(v["prekey_from"]), pub, ids, AtOf(pkTo));
        Refused(() => Prekeys.Open(pkTo, pub, [f.Str("from")], AtOf(pkTo)));                   // device not listed
        Refused(() => Prekeys.Open(pkTo, pub, ids, AtOf(pkTo) + Prekeys.LifeMs));              // expired
        Device? Mine(string pid) => pid == pTo.Id ? pre : null;
        var it = v.Obj("epoch_item");
        var b2 = it.Obj("body");
        var e2 = Room.OpenEpochV2(id, f.Str("fp"), f.Str("to"), f.Str("room"), it.Long("epoch"), it.Str("from"), b2.Str("h"), b2.Str("s"), b2.Str("w"), pub, Mine);
        Assert.Equal(v.Str("room_key"), Hex(e2.Key));
        Assert.Equal(2, e2.Header.Long("v"));
        Room.CheckEpoch(f.Str("room"), it.Long("epoch"), it.Str("from"), b2.Str("h"), b2.Str("s"), pub, e2.Key);
        Refused(() => Room.OpenEpochV2(id, f.Str("fp"), f.Str("to"), f.Str("room"), it.Long("epoch"), it.Str("from"), b2.Str("h"), b2.Str("s"), v.Str("w_tampered"), pub, Mine));
        Refused(() => Room.OpenEpochV2(id, f.Str("fp"), f.Str("from"), f.Str("room"), it.Long("epoch"), it.Str("from"), b2.Str("h"), b2.Str("s"), v.Str("w_from"), pub, Mine));
        Refused(() => Room.OpenEpochV2(id, f.Str("fp"), f.Str("to"), f.Str("room"), it.Long("epoch"), it.Str("from"), b2.Str("h"), b2.Str("s"), b2.Str("w"), pub, _ => null));
        Refused(() => Room.OpenEpoch(id, f.Str("fp"), f.Str("room"), it.Long("epoch"), it.Str("from"), b2.Str("h"), b2.Str("s"), b2.Str("w"), pub));
    }

    [Theory]
    [InlineData("browser-history.json")]
    [InlineData("phone-history.json")]
    public void WindowsOpensTheOthersHistoryFixtures(string name)
    {
        var f = Load(name);
        if (f is null) return;          // the phone's fixture lands once the Android tests have made it
        OpenFixture(f);
    }

    [Fact]
    public void ForgedAndMismatchedDeviceListsAreRefused()
    {
        var master = Random(32);
        var id = IdentityFromMaster(User, master);
        var p = PublishIdentity(id, 1792800000000L);
        var pub = OpenIdentity(p.B, p.S, User);
        var dev = Device.FromSeed(Devices.NewSeed());
        var ok = Devices.Publish(id, p.Fp, 1, [Devices.Entry("00000000000000ff", "PC", dev, 1)], 2);
        Assert.Single(Devices.Open(ok, pub).Devices);
        Refused(() => Devices.Open(Devices.Publish(IdentityFromMaster(User, Random(32)), p.Fp, 2, [], 3), pub));
        Refused(() => Devices.Open(Devices.Publish(id, new string('0', 64), 2, [], 3), pub));
        Refused(() => Devices.Open(new Signed64(ok.B, Devices.Publish(id, p.Fp, 2, [], 3).S), pub));
        // the device seed is sealed like a key, under its own name
        var dk = Random(32); var sk = Devices.StoreKey(master, User); var seed = Devices.NewSeed();
        var sealedSeed = Devices.SealSeed(dk, sk, User, seed);
        Assert.Equal(seed, Devices.OpenSeed(dk, sk, User, sealedSeed));
        Refused(() => Devices.OpenStored(dk, sk, User, "device", 0, sealedSeed));   // wrong length for a room key
    }

    [Fact]
    public void WindowsMakesAHistoryFixtureForTheOthers()
    {
        var at = 1792800000000L;
        var master = Random(32);
        var id = IdentityFromMaster(User, master);
        var p = PublishIdentity(id, at);
        var pub = OpenIdentity(p.B, p.S, User);
        var seedFrom = Devices.NewSeed(); var seedTo = Devices.NewSeed();
        var devFrom = Device.FromSeed(seedFrom); var devTo = Device.FromSeed(seedTo);
        var from = Devices.NewId(); var to = Devices.NewId();
        var list = Devices.Publish(id, p.Fp, 1, [Devices.Entry(from, "Old laptop", devFrom, 1790000000000L), Devices.Entry(to, "New phone", devTo, 1790000000000L)], at);
        var ep = Room.BuildEpoch(id, p.Fp, RoomId, 1, [new Room.Recipient(User, p.Fp, pub)], "");
        var blob = Devices.SealKeySync(id, from, to, devTo.KemPqPk, devTo.KemEcPk, [new SyncedKey(RoomId, 1, ep.Key)], at);
        var tampered = Unb64(blob); tampered[^20] ^= 1;
        var deviceKey = Random(32);
        var sealed_ = Devices.SealStored(deviceKey, Devices.StoreKey(master, User), User, RoomId, 1, ep.Key);
        // protocol 2: a prekey for each device, and a per-device room key (epoch 2) wrapped to them
        var preSeedTo = Devices.NewSeed();
        var preFrom = Device.FromSeed(Devices.NewSeed()); var preTo = Device.FromSeed(preSeedTo);
        var pkFrom = Prekeys.Publish(id, p.Fp, from, Prekeys.NewId(), preFrom, at);
        var pkTo = Prekeys.Publish(id, p.Fp, to, Prekeys.NewId(), preTo, at);
        var ids = new[] { from, to };
        var e2 = Room.BuildEpochV2(id, p.Fp, RoomId, 2,
            [new Room.DeviceLine(User, p.Fp, to, Prekeys.Open(pkTo, pub, ids, at)), new Room.DeviceLine(User, p.Fp, from, Prekeys.Open(pkFrom, pub, ids, at))], "");
        var bad = Unb64(e2.Pkg.W[User + "|" + to]); bad[^5] ^= 1;
        var v2 = new JsonObject
        {
            ["prekey_from"] = new JsonObject { ["b"] = pkFrom.B, ["s"] = pkFrom.S },
            ["prekey_to"] = new JsonObject { ["b"] = pkTo.B, ["s"] = pkTo.S },
            ["prekey_seed_to"] = B64(preSeedTo),
            ["epoch_item"] = new JsonObject { ["epoch"] = 2, ["from"] = User, ["body"] = new JsonObject { ["v"] = 2, ["h"] = e2.Pkg.H, ["s"] = e2.Pkg.S, ["w"] = e2.Pkg.W[User + "|" + to] } },
            ["w_from"] = e2.Pkg.W[User + "|" + from],
            ["w_tampered"] = B64(bad),
            ["room_key"] = Hex(e2.Key),
        };
        var f = new JsonObject
        {
            ["v"] = 1, ["made_by"] = "windows", ["user"] = User, ["master"] = Hex(master), ["fp"] = p.Fp,
            ["bundle"] = new JsonObject { ["b"] = p.B, ["s"] = p.S },
            ["devices"] = new JsonObject { ["b"] = list.B, ["s"] = list.S },
            ["from"] = from, ["to"] = to, ["v2"] = v2,
            ["device_seed_to"] = B64(seedTo), ["code_to"] = Devices.Code(devTo.KemPqPk, devTo.KemEcPk),
            ["room"] = RoomId,
            ["epoch_item"] = new JsonObject { ["epoch"] = 1, ["from"] = User, ["body"] = new JsonObject { ["h"] = ep.Pkg.H, ["s"] = ep.Pkg.S } },
            ["room_key"] = Hex(ep.Key),
            ["sync_blob"] = blob, ["sync_tampered"] = B64(tampered),
            ["store"] = new JsonObject { ["device_key"] = B64(deviceKey), ["sealed"] = B64(sealed_), ["room"] = RoomId, ["epoch"] = 1 },
        };
        OpenFixture(f);        // Windows opens its own fixture by the same rules
        var dir = InteropTests.FixtureDir();
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "windows-history.json"), f.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
    }
}
