using System.Security.Cryptography;
using System.Text.Json.Nodes;
using CipherChat.Api;
using CipherChat.Crypto;
using CipherChat.Engine;
using CipherChat.Transport;
using static CipherChat.Engine.Tests.LiveServerTests;

namespace CipherChat.Engine.Tests;

/// <summary>
/// Devices, the key store and history (PROTOCOL.md §10) against a REAL server, same switches as
/// <see cref="LiveServerTests"/>. A fresh person on a first PC keeps the room key it opens and the server deletes its
/// wrap; a second PC asks for history, the first approves it after the device codes match, and the second reads the
/// older message from its own store with no wrap left on the server; removing the second PC wipes its store.
/// </summary>
[Collection(LiveServer)]
public class HistoryLiveTests
{
    private sealed class PlainGuard : IStoreGuard
    {
        public byte[] Protect(byte[] plain) => (byte[])plain.Clone();
        public byte[] Unprotect(byte[] sealed_) => (byte[])sealed_.Clone();
    }

    [Fact]
    public async Task APcKeepsKeysAndHandsHistoryToANewOne()
    {
        var origin = Env("CIPHERCHAT_DEV_ORIGIN");
        if (string.IsNullOrEmpty(origin)) return;
        var uri = new Uri(origin);
        ITransport T() => uri.Scheme == "https" ? new PqTlsTransport(uri) : new LoopbackDevTransport(uri);
        var dir = Path.Combine(Path.GetTempPath(), "cipherchat-history-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(4)));
        ChatApi? ownerApi = null, api1 = null, api2 = null;
        try
        {
            // ---- the owner, and a fresh person with an identity, pinned and certified
            ownerApi = new ChatApi(T(), "CipherChat/0.1 (Windows; tests)");
            await Paced(async () => await ownerApi.LoginAsync(Env("CIPHERCHAT_DEV_OWNER")!, Env("CIPHERCHAT_DEV_OWNER_PASSWORD")!, await OwnerTotpAsync()));
            var ownerMe = await Gate.UnlockAsync(ownerApi, await ownerApi.CallAsync("state"), Env("CIPHERCHAT_DEV_OWNER_PASSPHRASE")!);
            var user = "hist" + Convert.ToHexString(RandomNumberGenerator.GetBytes(3)).ToLowerInvariant();
            var inv = await ownerApi.CallAsync("admin/users/invite", new JsonObject { ["username"] = user, ["role"] = "member" });
            var token = inv.Obj("link").Str("url").Split("#enrol=")[1];
            api1 = new ChatApi(T(), "CipherChat/0.1 (Windows; tests)");
            const string pw = "windows history test password 1";
            var start = await Paced(() => api1.CallAsync("auth/enrol/start", new JsonObject { ["token"] = token, ["password"] = pw }));
            var secret = start.Str("secret");
            await Paced(() => api1.CallAsync("auth/enrol/finish", new JsonObject { ["token"] = token, ["code"] = Totp(secret, -1) }));
            await Paced(() => api1.LoginAsync(user, pw, Totp(secret)));
            const string pass = "windows history test chat passphrase";
            var me1 = await Gate.SetupAsync(api1, await api1.CallAsync("state"), pass, reset: false, ask: _ => Task.FromResult<string?>(null));
            var owner = new ChatEngine(ownerApi, ownerMe);
            await owner.RefreshAsync();
            await Gate.PinOwnerAsync(api1, await api1.CallAsync("state"), me1, pass, _ => Task.FromResult<string?>(null));
            await owner.CertifyAsync(owner.People[user]);

            // ---- PC 1 joins the device list and keeps the key it opens; its wrap is deleted
            var pc1 = new ChatEngine(api1, me1);
            pc1.UseStore(me1.OpenStore(Path.Combine(dir, "pc1.bin"), new PlainGuard()));
            await owner.StartAsync();
            await pc1.StartAsync();
            Assert.Single(pc1.KeyDevices()!.Devices);
            var room = await owner.CreateRoomAsync("hist-" + user, "history test", 0, [user]);
            await owner.OpenRoomAsync(room);
            await owner.SendTextAsync(room, "before the new PC");
            await Until(() => room.Timeline.Any(e => e.Message?.Text == "before the new PC"), "the owner's own message");
            await pc1.RefreshAsync();
            var r1 = pc1.RoomById(room.Id)!;
            await pc1.OpenRoomAsync(r1);
            await Until(() => r1.Timeline.Any(e => e.Message?.Text == "before the new PC"), "the message on PC 1");
            Assert.True(pc1.Store!.Has(room.Id, 1));
            async Task<bool> WrapGone(ChatApi api) =>
                (await api.CallAsync("rooms/" + room.Id + "/epochs?all=1")).Arr("items").OfType<JsonObject>().All(it => it.Obj("body")["w"] is null);
            for (var i = 0; i < 50 && !await WrapGone(api1); i++) await Task.Delay(100);
            Assert.True(await WrapGone(api1), "the wrap PC 1 acknowledged is deleted");

            // ---- PC 2 signs in, joins, asks for history; PC 1 approves after the codes match
            api2 = new ChatApi(T(), "CipherChat/0.1 (Windows; tests)");
            await Paced(() => api2.LoginAsync(user, pw, Totp(secret, 1)));
            var me2 = await Gate.UnlockAsync(api2, await api2.CallAsync("state"), pass);
            var pc2 = new ChatEngine(api2, me2);
            pc2.UseStore(me2.OpenStore(Path.Combine(dir, "pc2.bin"), new PlainGuard()));
            string? shown = null;
            pc1.ConfirmSync = (name, _, code) => { shown = code; return Task.FromResult<bool?>(true); };
            await pc2.StartAsync();
            Assert.Equal(2, pc2.KeyDevices()!.Devices.Count);
            var r2 = pc2.RoomById(room.Id)!;
            await Until(() => pc2.Store!.Has(room.Id, 1), "the history package on PC 2", 60);
            Assert.Equal(pc2.Store!.Code(), shown);
            await pc2.OpenRoomAsync(r2);
            await Until(() => r2.Timeline.Any(e => e.Message?.Text == "before the new PC"), "the older message on PC 2");
            Assert.True(await WrapGone(api2), "PC 2 read it from its own store, with no wrap on the server");

            // ---- removing PC 2 on PC 1 wipes PC 2's store the next time it looks
            var list = pc1.KeyDevices()!;
            await pc1.RemoveKeyDeviceAsync(list, list.Devices.Single(d => d.Id == pc2.Store!.Dev));
            await pc2.RefreshAsync();
            await Until(() => pc2.Store is null, "PC 2 to notice it was removed");
            Assert.False(File.Exists(Path.Combine(dir, "pc2.bin")));
            Assert.True(File.Exists(Path.Combine(dir, "pc1.bin")));
            owner.Lock(); pc1.Lock(); pc2.Lock();
        }
        finally
        {
            await SignOutAsync(ownerApi, api1, api2);
            try { Directory.Delete(dir, true); } catch (IOException) { }
        }
    }

    /// <summary>
    /// Protocol 2 (PROTOCOL.md §11) against a real server: with the owner and a person on two PCs, all keeping key stores
    /// and prekeys, a new room key is sealed to each of the three devices' prekeys; each device gets only its own wrap
    /// (none without ?dev=), reads the message, and the wraps go once acknowledged.
    /// </summary>
    [Fact]
    public async Task NewRoomKeysAreSealedToEachDevicesPrekey()
    {
        var origin = Env("CIPHERCHAT_DEV_ORIGIN");
        if (string.IsNullOrEmpty(origin)) return;
        var uri = new Uri(origin);
        ITransport T() => uri.Scheme == "https" ? new PqTlsTransport(uri) : new LoopbackDevTransport(uri);
        var dir = Path.Combine(Path.GetTempPath(), "cipherchat-v2-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(4)));
        ChatApi? ownerApi = null, api1 = null, api2 = null, api3 = null;
        try
        {
            ownerApi = new ChatApi(T(), "CipherChat/0.1 (Windows; tests)");
            await Paced(async () => await ownerApi.LoginAsync(Env("CIPHERCHAT_DEV_OWNER")!, Env("CIPHERCHAT_DEV_OWNER_PASSWORD")!, await OwnerTotpAsync()));
            var ownerMe = await Gate.UnlockAsync(ownerApi, await ownerApi.CallAsync("state"), Env("CIPHERCHAT_DEV_OWNER_PASSPHRASE")!);
            var user = "pk" + Convert.ToHexString(RandomNumberGenerator.GetBytes(3)).ToLowerInvariant();
            var inv = await ownerApi.CallAsync("admin/users/invite", new JsonObject { ["username"] = user, ["role"] = "member" });
            var token = inv.Obj("link").Str("url").Split("#enrol=")[1];
            api1 = new ChatApi(T(), "CipherChat/0.1 (Windows; tests)");
            const string pw = "windows prekey test password 1";
            var start = await Paced(() => api1.CallAsync("auth/enrol/start", new JsonObject { ["token"] = token, ["password"] = pw }));
            var secret = start.Str("secret");
            await Paced(() => api1.CallAsync("auth/enrol/finish", new JsonObject { ["token"] = token, ["code"] = Totp(secret, -1) }));
            await Paced(() => api1.LoginAsync(user, pw, Totp(secret)));
            const string pass = "windows prekey test chat passphrase";
            var me1 = await Gate.SetupAsync(api1, await api1.CallAsync("state"), pass, reset: false, ask: _ => Task.FromResult<string?>(null));
            var owner = new ChatEngine(ownerApi, ownerMe);
            owner.UseStore(ownerMe.OpenStore(Path.Combine(dir, "owner.bin"), new PlainGuard()));
            await owner.RefreshAsync();
            await Gate.PinOwnerAsync(api1, await api1.CallAsync("state"), me1, pass, _ => Task.FromResult<string?>(null));
            await owner.CertifyAsync(owner.People[user]);
            await owner.StartAsync();
            // (this test server's owner may have devices from earlier runs, with no fresh prekeys: only this one stays)
            for (var list = owner.KeyDevices()!; list.Devices.Count > 1; list = owner.KeyDevices()!)
                await owner.RemoveKeyDeviceAsync(list, list.Devices.First(d => d.Id != owner.Store!.Dev));

            var pc1 = new ChatEngine(api1, me1);
            pc1.UseStore(me1.OpenStore(Path.Combine(dir, "pc1.bin"), new PlainGuard()));
            await pc1.StartAsync();
            api2 = new ChatApi(T(), "CipherChat/0.1 (Windows; tests)");
            await Paced(() => api2.LoginAsync(user, pw, Totp(secret, 1)));
            var me2 = await Gate.UnlockAsync(api2, await api2.CallAsync("state"), pass);
            var pc2 = new ChatEngine(api2, me2);
            pc2.UseStore(me2.OpenStore(Path.Combine(dir, "pc2.bin"), new PlainGuard()));
            pc1.ConfirmSync = (_, _, _) => Task.FromResult<bool?>(false);
            await pc2.StartAsync();
            // straight away, as an app would: each device published its prekey while unlocking, and the owner's
            // cached directory (older than PC 2's prekey) is looked at again before settling for compatibility mode
            var room = await owner.CreateRoomAsync("v2-" + user, "prekey test", 0, [user]);
            await owner.OpenRoomAsync(room);
            await owner.SendTextAsync(room, "sealed to each device");
            await Until(() => room.Timeline.Any(e => e.Message?.Text == "sealed to each device"), "the owner's own message");
            Assert.Contains(room.Timeline, e => e.Text.Contains("sealed to each of their 3 devices"));
            Assert.Equal(2, room.Headers[1].Long("v"));

            // each PC gets its own wrap, and none without saying which device it is
            async Task<JsonObject> Item(ChatApi api, string q) =>
                (await api.CallAsync("rooms/" + room.Id + "/epochs?all=1" + q)).Arr("items").OfType<JsonObject>().Single(it => it.Long("epoch") == 1);
            Assert.Null((await Item(api1, ""))["body"]!["w"]);
            await pc1.RefreshAsync(); await pc2.RefreshAsync();
            foreach (var (pc, name) in new[] { (pc1, "PC 1"), (pc2, "PC 2") })
            {
                var r = pc.RoomById(room.Id)!;
                await pc.OpenRoomAsync(r);
                await Until(() => r.Timeline.Any(e => e.Message?.Text == "sealed to each device"), "the message on " + name);
                Assert.True(pc.Store!.Has(room.Id, 1));
            }
            var w1 = (await Item(api1, "&dev=" + pc1.Store!.Dev))["body"]!["w"];
            var w2 = (await Item(api2, "&dev=" + pc2.Store!.Dev))["body"]!["w"];
            Assert.True(w1 is null || w2 is null || w1.GetValue<string>() != w2.GetValue<string>(), "two devices never get the same wrap");
            for (var i = 0; i < 50 && ((await Item(api1, "&dev=" + pc1.Store!.Dev))["body"]!["w"] is not null || (await Item(api2, "&dev=" + pc2.Store!.Dev))["body"]!["w"] is not null); i++)
                await Task.Delay(100);
            Assert.Null((await Item(api1, "&dev=" + pc1.Store!.Dev))["body"]!["w"]);
            Assert.Null((await Item(api2, "&dev=" + pc2.Store!.Dev))["body"]!["w"]);

            // PC 3 joins after key #1 (nobody hands it older keys) and, as a plain member, renews the key straight away:
            // the new key still follows on from #1, whose header PC 3 checked but can't open
            pc2.ConfirmSync = (_, _, _) => Task.FromResult<bool?>(false);
            var used = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30 + 1;        // PC 2's code was for the next window at most
            while (DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30 < used) await Task.Delay(1000);
            api3 = new ChatApi(T(), "CipherChat/0.1 (Windows; tests)");
            await Paced(() => api3.LoginAsync(user, pw, Totp(secret, 1)));
            var me3 = await Gate.UnlockAsync(api3, await api3.CallAsync("state"), pass);
            var pc3 = new ChatEngine(api3, me3);
            pc3.UseStore(me3.OpenStore(Path.Combine(dir, "pc3.bin"), new PlainGuard()));
            await pc3.StartAsync();
            var r3 = pc3.RoomById(room.Id)!;
            await pc3.OpenRoomAsync(r3);
            var before = r3.Epoch;
            Assert.False(pc3.Store!.Has(room.Id, before), "PC 3 doesn't hold the current key");
            await pc3.RotateNowAsync(r3);
            var next = before + 1;
            await Until(() => room.Headers.ContainsKey(next), "the owner opening PC 3's key");
            Assert.Equal(room.Hashes[before], room.Headers[next].Str("prev"));
            Assert.DoesNotContain(room.Timeline, e => e.Text.Contains("doesn't follow on"));
            var line = room.Timeline.Last(e => e.Text.StartsWith("new room key #" + next + " ", StringComparison.Ordinal)).Text;
            var names = line.Split(" for ")[1].Split(" (")[0].Split(", ");
            Assert.Equal(names.Length, names.Distinct().Count());               // one name per person, not one per device
            Assert.Contains(user, names);
            pc3.Lock();
            owner.Lock(); pc1.Lock(); pc2.Lock();
        }
        finally
        {
            await SignOutAsync(ownerApi, api1, api2, api3);
            try { Directory.Delete(dir, true); } catch (IOException) { }
        }
    }
}
