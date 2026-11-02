using System.Text.Json.Nodes;
using CipherChat.Api;
using CipherChat.Crypto;
using static CipherChat.Crypto.Bytes;

namespace CipherChat.Engine;

/// <summary>
/// Devices, the key store and history (history.js; PROTOCOL.md §10, PREKEYS-DESIGN.md phase 1):
///   - this PC joins the person's signed device list, keeps the room keys it opens, and acknowledges them, so the server
///     can delete its wrapped copies;
///   - a new PC asks the person's other devices for older keys; they ask the person first and show a device code;
///   - device lists are checked against the owner's trust like everything else, and changes are shown;
///   - each room's history window is applied to the keys kept here.
/// </summary>
internal sealed class KeyHistory(ChatEngine e)
{
    public const int MaxDevices = 16;
    private const int PackKeys = 1500;                 // keys per history package (stays under the server's 192 KiB per blob)
    private const long PrekeyEveryMs = 86400 * 1000L;  // a new prekey each day (each lives 7 days)
    private const long PrekeyCheckMs = 3600 * 1000L;   // how often a long-running session looks again
    public const int V2MaxDevices = 64;                // per-device room keys for at most this many devices (the server's limit)
    private static readonly long[] V2 = [2];

    private readonly Dictionary<string, HashSet<long>> _pending = new();
    private readonly HashSet<string> _asked = new();
    private readonly SemaphoreSlim _busy = new(1, 1);
    private CancellationTokenSource? _ackTimer;
    private readonly Dictionary<string, Device> _preCache = new();     // prekey id -> its key pair, while unlocked
    private long _preChecked;

    private KeyStore? Store => e.Store;
    private PublicIdentity MyPub => new(e.Me.User, e.Me.Fp, 0, e.Me.Id.KemPqPk, e.Me.Id.KemEcPk, e.Me.Id.SigPqPk, e.Me.Id.SigEcPk);

    private JsonObject? EntryOf(string user) =>
        e.State.Arr("directory").OfType<JsonObject>().FirstOrDefault(d => d.StrOrNull("user") == user)?["devices"] as JsonObject;

    private static Signed64 Signed(JsonObject o) => new(o.Str("b"), o.Str("s"));

    public DeviceList? MyList()
    {
        var entry = EntryOf(e.MyUser);
        if (entry is null) return null;
        try { return Devices.Open(Signed(entry), MyPub); }
        catch (CryptoFail x)
        {
            e.Say(null, LineKind.Err, "Your device list on the server doesn't verify (" + x.Message + "). It won't be used or changed until that's fixed.");
            throw;
        }
    }

    private static JsonObject ListJson(Signed64 s) => new() { ["b"] = s.B, ["s"] = s.S };

    /// <summary>Joins this PC to the device list (once), says hello, and asks other devices for history if it's new here.</summary>
    public async Task EnrollAsync()
    {
        var s = Store;
        if (s is null) return;
        List<DeviceEntry> others = [];
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var list = MyList();
            if (list is not null && list.Devices.Any(d => d.Id == s.Dev)) { others = []; break; }
            if (list is not null && s.ListedSeq > 0 && list.Seq > s.ListedSeq) { Removed(); return; }   // another device removed this PC
            others = list?.Devices.ToList() ?? [];
            if (others.Count >= MaxDevices)
            {
                var seen = e.State["me"]?["device_seen"] as JsonObject;
                var gone = others.OrderBy(d => seen?[d.Id]?.GetValue<long>() ?? 0).First();
                others.Remove(gone);
                e.Say(null, LineKind.Warn, "Your device list was full, so the least recently used device (" + gone.Name + ") was removed from it.");
            }
            var seq = (list?.Seq ?? 0) + 1;
            var signed = Devices.Publish(e.Me.Id, e.Me.Fp, seq, [.. others, s.Entry()], NowMs());
            try
            {
                await e.Api.CallAsync("keydevices", new JsonObject { ["list"] = ListJson(signed), ["dev"] = s.Dev }).ConfigureAwait(false);
                s.Listed(seq);
                await e.RefreshAsync().ConfigureAwait(false);
                break;
            }
            catch (ApiException x) when (x.Flag("stale")) { await e.RefreshAsync().ConfigureAwait(false); }
        }
        await e.Api.CallAsync("store/hello", new JsonObject { ["dev"] = s.Dev }).ConfigureAwait(false);
        if (s.IsNew)
        {
            if (others.Count > 0)
            {
                await e.Api.CallAsync("sync/request", new JsonObject { ["dev"] = s.Dev }).ConfigureAwait(false);
                e.Say(null, LineKind.Sys, "Asked your other devices for this PC's history. Approve it on one of them, and check it shows this code: " + s.Code());
            }
            s.NotNew();
        }
    }

    /// <summary>Every state change: device lists (shown when they change), my own membership, sync work.</summary>
    public async Task OnStateAsync()
    {
        if (!await _busy.WaitAsync(0).ConfigureAwait(false)) return;
        try
        {
            CheckLists();
            if (Store is not null && (e.State["me"]?["sync_waiting"]?.GetValue<long>() ?? 0) > 0) await SyncWorkAsync().ConfigureAwait(false);
            if (Store is not null && _preChecked > 0 && NowMs() - _preChecked > PrekeyCheckMs) await PrekeysAsync().ConfigureAwait(false);
        }
        catch (Exception x) when (x is ApiException or CryptoFail or InvalidOperationException or KeyNotFoundException)
        {
            e.Say(null, LineKind.Err, "Device and history check failed: " + x.Message);
        }
        finally { _busy.Release(); }
    }

    private void CheckLists()
    {
        var s = Store;
        var seen = s?.Seen ?? new Dictionary<string, (long Seq, List<string> Ids)>();
        var changed = false;
        foreach (var d in e.State.Arr("directory").OfType<JsonObject>())
        {
            if (d["devices"] is not JsonObject entry) continue;
            var user = d.Str("user");
            var mine = user == e.MyUser;
            var pub = mine ? MyPub : e.Trusted(user)?.Pub;
            if (pub is null) continue;
            DeviceList list;
            try { list = Devices.Open(Signed(entry), pub); }
            catch (CryptoFail x) { e.Say(null, LineKind.Warn, user + "'s device list doesn't verify (" + x.Message + "): ignored."); continue; }
            var ids = list.Devices.Select(x => x.Id).ToList();
            var had = seen.TryGetValue(user, out var before);
            if (had && list.Seq < before.Seq)
            {
                e.Say(null, LineKind.Warn, user + "'s device list went back to an older version (" + list.Seq + " after " + before.Seq + "). The server may be replaying it.");
                continue;
            }
            if (had && before.Seq != list.Seq)
            {
                var added = list.Devices.Where(x => !before.Ids.Contains(x.Id)).Select(x => x.Name).ToList();
                var removed = before.Ids.Count - ids.Count(before.Ids.Contains);
                if (added.Count > 0)
                    e.Say(null, mine ? LineKind.Warn : LineKind.Sys, (mine ? "A device was added to your account" : user + " added a device") + ": " + string.Join(", ", added) +
                          (mine ? ". If that wasn't you, reset your identity." : "."));
                if (removed > 0) e.Say(null, LineKind.Sys, (mine ? "You" : user) + " removed " + removed + " device" + (removed > 1 ? "s" : "") + ".");
            }
            if (!had || before.Seq != list.Seq) { seen[user] = (list.Seq, ids); changed = true; }
            if (mine && s is not null && s.ListedSeq > 0 && list.Seq > s.ListedSeq && !ids.Contains(s.Dev)) { Removed(); return; }
        }
        if (s is not null && changed) s.SaveSeen();
    }

    // ------------------------------------------------------------------------------------------- keys: kept, acknowledged, windowed
    public const int GraceDays = 7;                 // the server deletes a wrap no device acknowledged after this long

    /// <summary>Wraps for me the server still has past the grace period (PREKEYS-DESIGN §4.2), from an epochs?all=1
    /// listing. One day of slack covers the server's sweep interval and clock drift.</summary>
    public static int Leftover(JsonArray items)
    {
        var cutoff = NowMs() / 1000 - (GraceDays + 1) * 86400L;
        return items.OfType<JsonObject>().Count(it => it["body"] is JsonObject b && b.StrOrNull("w") is not null && (it.LongOrNull("at") ?? long.MaxValue) < cutoff);
    }

    public static string LeftoverWarning(int n) =>
        "The server still holds " + n + (n == 1 ? " copy" : " copies") + " of this room's keys for you that are more than " + GraceDays +
        " days old; it should have deleted them. That happens while an older CipherChat app of yours is still signed in or paired: " +
        "update or remove it (Settings → Paired devices). If none is, the server isn't deleting them as it should.";

    public static bool InWindow(JsonObject? info, long epoch, long atMs)
    {
        if (info is null) return false;
        var days = info.LongOrNull("history_days") ?? 0;
        if (epoch == (info.LongOrNull("epoch") ?? 0) || days == 0) return true;
        return atMs >= NowMs() - days * 86400 * 1000;
    }

    public byte[]? Kept(string room, long epoch) => Store?.Get(room, epoch);

    public void Keep(string room, long epoch, byte[] key, long at)
    {
        var s = Store;
        if (s is null) return;
        s.Put(room, epoch, key, at);
        PendingAdd(room, epoch);
        var t = new CancellationTokenSource();
        Interlocked.Exchange(ref _ackTimer, t)?.Cancel();
        _ = Task.Delay(300, t.Token).ContinueWith(_ => FlushAcksAsync(), t.Token, TaskContinuationOptions.OnlyOnRanToCompletion, TaskScheduler.Default);
    }

    private void PendingAdd(string room, long epoch)
    {
        lock (_pending)
        {
            if (!_pending.TryGetValue(room, out var set)) _pending[room] = set = [];
            set.Add(epoch);
        }
    }

    public async Task FlushAcksAsync()
    {
        var s = Store;
        if (s is null) return;
        List<(string Room, List<long> Epochs)> work;
        lock (_pending) { work = _pending.Select(p => (p.Key, p.Value.ToList())).ToList(); _pending.Clear(); }
        foreach (var (room, epochs) in work)
            for (var i = 0; i < epochs.Count; i += 1000)
            {
                var part = epochs.Skip(i).Take(1000).ToList();
                try
                {
                    await e.Api.CallAsync("rooms/" + room + "/ack", new JsonObject { ["dev"] = s.Dev, ["epochs"] = new JsonArray(part.Select(x => (JsonNode)x).ToArray()) }).ConfigureAwait(false);
                }
                catch (ApiException x) { if (x.Status != 404) foreach (var ep in part) PendingAdd(room, ep); }
            }
    }

    /// <summary>Keys past a room's history window (never the current one) and keys of rooms I'm no longer in are erased.</summary>
    public List<(string Room, long Epoch)> ApplyWindow()
    {
        var s = Store;
        if (s is null) return [];
        var rooms = e.State.Arr("rooms").OfType<JsonObject>().ToDictionary(r => r.Str("id"));
        var gone = s.List().Where(x => !InWindow(rooms.GetValueOrDefault(x.Room), x.Epoch, x.At)).Select(x => (x.Room, x.Epoch)).ToList();
        s.Drop(gone);
        return gone;
    }

    // ------------------------------------------------------------------------------------------- prekeys (protocol 2, PROTOCOL.md §11)
    public Device? PrekeyOf(string id)
    {
        var s = Store;
        if (s is null) return null;
        lock (_preCache) if (_preCache.TryGetValue(id, out var d)) return d;
        var seed = s.GetPrekey(id);
        if (seed is null) return null;
        Device pair;
        try { pair = Device.FromSeed(seed); } finally { Wipe(seed); }
        lock (_preCache) _preCache[id] = pair;
        return pair;
    }

    public void ForgetPrekeys() { lock (_preCache) _preCache.Clear(); }

    /// <summary>Publishes a new prekey when the newest is a day old (or the server lost it), and erases expired ones, but
    /// only after opening and keeping every room key still wrapped to them. After unlocking, then hourly. Without
    /// <paramref name="erase"/> it only publishes (at unlock, before the import has run).</summary>
    public async Task PrekeysAsync(bool erase = true)
    {
        var s = Store;
        if (s is null) return;
        var now = NowMs();
        _preChecked = now;
        var mine = s.ListPrekeys();
        var expired = mine.Where(p => p.Exp <= now).Select(p => p.Id).ToList();
        if (erase && expired.Count > 0)
        {
            await e.ImportAllAsync().ConfigureAwait(false);
            s.DropPrekeys(expired);
            lock (_preCache) foreach (var id in expired) _preCache.Remove(id);
        }
        var live = mine.Where(p => p.Exp > now).OrderByDescending(p => p.Exp).ToList();
        var entry = e.State.Arr("directory").OfType<JsonObject>().FirstOrDefault(d => d.StrOrNull("user") == e.MyUser);
        var onServer = new HashSet<string>();
        foreach (var x in (entry?["prekeys"] as JsonArray ?? []).OfType<JsonObject>())
        {
            try { onServer.Add(Canon.ParseSigned(x.Str("b"), 4096, V2).Obj.Str("id")); }
            catch (Exception ex) when (ex is CryptoFail or KeyNotFoundException or InvalidOperationException or FormatException) { }
        }
        (string Id, Device Pair, long At)? pub = null;
        if (live.Count == 0 || now - (live[0].Exp - Prekeys.LifeMs) >= PrekeyEveryMs)
        {
            var id = Prekeys.NewId();
            var seed = Devices.NewSeed();
            Device pair;
            try { s.PutPrekey(id, seed, now + Prekeys.LifeMs); pair = Device.FromSeed(seed); }
            finally { Wipe(seed); }
            lock (_preCache) _preCache[id] = pair;
            pub = (id, pair, now);
        }
        else if (!onServer.Contains(live[0].Id) && PrekeyOf(live[0].Id) is { } pair) pub = (live[0].Id, pair, live[0].Exp - Prekeys.LifeMs);
        if (pub is { } p)
        {
            var signed = Prekeys.Publish(e.Me.Id, e.Me.Fp, s.Dev, p.Id, p.Pair, p.At);
            await e.Api.CallAsync("keydevices/prekey", new JsonObject { ["dev"] = s.Dev, ["prekey"] = ListJson(signed) }).ConfigureAwait(false);
            await e.RefreshAsync().ConfigureAwait(false);
        }
    }

    /// <summary>True unless a verified device list of this person (seen here) leaves the device out.</summary>
    public bool DeviceListed(string user, string dev) =>
        Store is not { } s || !s.Seen.TryGetValue(user, out var seen) || seen.Ids.Contains(dev);

    /// <summary>
    /// The lines of a per-device room key for these people, or why it can't be made (PROTOCOL.md §11): each person's
    /// device list and every listed device's newest prekey must verify against their trusted identity.
    /// </summary>
    public (List<CipherChat.Crypto.Room.DeviceLine>? Lines, string? Why) V2Lines(IEnumerable<string> users)
    {
        if (Store is null) return (null, "this PC keeps no room keys");
        var lines = new List<CipherChat.Crypto.Room.DeviceLine>();
        var now = NowMs();
        foreach (var u in users)
        {
            var d = e.State.Arr("directory").OfType<JsonObject>().FirstOrDefault(x => x.StrOrNull("user") == u);
            var pub = u == e.MyUser ? MyPub : e.Trusted(u)?.Pub;
            if (d is null || pub is null) return (null, u + " isn't verified");
            if (d["devices"] is not JsonObject devs) return (null, u + " has no device list yet");
            if (d["v2"]?.GetValue<bool>() != true) return (null, u + " has an older app signed in");
            DeviceList list;
            try { list = Devices.Open(Signed(devs), pub); } catch (CryptoFail) { return (null, u + "'s device list doesn't verify"); }
            var ids = list.Devices.Select(x => x.Id).ToList();
            var best = new Dictionary<string, Prekey>();
            foreach (var x in (d["prekeys"] as JsonArray ?? []).OfType<JsonObject>())
            {
                Prekey pk;
                try { pk = Prekeys.Open(Signed(x), pub, ids, now); }
                catch (Exception ex) when (ex is CryptoFail or KeyNotFoundException or InvalidOperationException or FormatException) { continue; }
                if (!best.TryGetValue(pk.Dev, out var cur) || pk.At > cur.At) best[pk.Dev] = pk;
            }
            foreach (var x in list.Devices)
            {
                if (!best.TryGetValue(x.Id, out var pk)) return (null, u + "'s device “" + x.Name + "” has no fresh prekey");
                lines.Add(new CipherChat.Crypto.Room.DeviceLine(u, pub.Fp, x.Id, pk));
            }
        }
        if (lines.Count > V2MaxDevices) return (null, "the room has more than " + V2MaxDevices + " devices");
        return (lines, null);
    }

    // ------------------------------------------------------------------------------------------- history sync
    private async Task SyncWorkAsync()
    {
        var s = Store!;
        var st = await e.Api.CallAsync("sync?dev=" + s.Dev).ConfigureAwait(false);
        var byId = (MyList()?.Devices ?? []).ToDictionary(d => d.Id);
        foreach (var p in st.Arr("packages").OfType<JsonObject>()) await ReceiveAsync(p, byId.GetValueOrDefault(p.Str("from"))).ConfigureAwait(false);
        foreach (var r in st.Arr("requests").OfType<JsonObject>())
        {
            var id = r.Str("id");
            if (!_asked.Add(id)) continue;
            if (!byId.TryGetValue(r.Str("dev"), out var d) || e.ConfirmSync is not { } ask) continue;
            var code = Devices.Code(Unb64(d.KemPq), Unb64(d.KemEc));
            var answer = await ask(d.Name, DateTimeOffset.FromUnixTimeMilliseconds(d.Added).ToLocalTime(), code).ConfigureAwait(false);
            if (answer == true) await SendAsync(d).ConfigureAwait(false);
            else if (answer == false) { try { await e.Api.CallAsync("sync/decline", new JsonObject { ["id"] = id }).ConfigureAwait(false); } catch (ApiException) { } }
        }
    }

    private async Task SendAsync(DeviceEntry d)
    {
        var s = Store!;
        var rooms = e.State.Arr("rooms").OfType<JsonObject>().ToDictionary(r => r.Str("id"));
        var keys = new List<SyncedKey>();
        foreach (var x in s.List())
        {
            var info = rooms.GetValueOrDefault(x.Room);
            if (info is null || info["history_sync"]?.GetValue<bool>() == false || !InWindow(info, x.Epoch, x.At)) continue;
            if (s.Get(x.Room, x.Epoch) is { } key) keys.Add(new SyncedKey(x.Room, x.Epoch, key));
        }
        keys = keys.OrderBy(k => k.Room, StringComparer.Ordinal).ThenBy(k => k.Epoch).ToList();
        var kemPq = Unb64(d.KemPq, Sizes.KemPq); var kemEc = Unb64(d.KemEc, Sizes.KemEc);
        try
        {
            var parts = keys.Chunk(PackKeys).ToList();
            if (parts.Count == 0) parts.Add([]);
            for (var i = 0; i < parts.Count; i++)
            {
                var blob = Devices.SealKeySync(e.Me.Id, s.Dev, d.Id, kemPq, kemEc, parts[i], NowMs());
                await e.Api.CallAsync("sync/send", new JsonObject { ["to"] = d.Id, ["from"] = s.Dev, ["blob"] = blob, ["last"] = i == parts.Count - 1 }).ConfigureAwait(false);
            }
        }
        finally { foreach (var k in keys) Wipe(k.Key); }
        e.Say(null, LineKind.Ok, "Sent " + keys.Count + " room key" + (keys.Count == 1 ? "" : "s") + " to " + d.Name + ", sealed to that device.");
    }

    private async Task DoneAsync(string id)
    {
        try { await e.Api.CallAsync("sync/done", new JsonObject { ["id"] = id }).ConfigureAwait(false); } catch (ApiException) { }
    }

    private async Task ReceiveAsync(JsonObject p, DeviceEntry? from)
    {
        var s = Store!;
        var id = p.Str("id");
        if (from is null) { await DoneAsync(id).ConfigureAwait(false); return; }
        List<SyncedKey> keys;
        try { keys = Devices.OpenKeySync(s.Device, MyPub, from.Id, s.Dev, p.Str("blob")); }
        catch (CryptoFail x)
        {
            e.Say(null, LineKind.Warn, "A history package from " + from.Name + " was refused: " + x.Message + ".");
            await DoneAsync(id).ConfigureAwait(false);
            return;
        }
        // Each key is accepted only if its room's signed header commits to it (a package can't plant a key)
        var n = 0;
        foreach (var group in keys.GroupBy(k => k.Room))
        {
            var info = e.RoomById(group.Key)?.Info;
            if (info is null) continue;
            JsonObject res;
            try { res = await e.Api.CallAsync("rooms/" + group.Key + "/epochs?all=1").ConfigureAwait(false); } catch (ApiException) { continue; }
            var headers = res.Arr("items").OfType<JsonObject>().ToDictionary(it => it.Long("epoch"));
            var kept = new List<(string, long, byte[], long)>();
            foreach (var k in group)
            {
                if (!headers.TryGetValue(k.Epoch, out var it) || e.Trusted(it.Str("from")) is not { } signer) continue;
                try
                {
                    var b = it.Obj("body");
                    var o = CipherChat.Crypto.Room.CheckEpoch(group.Key, k.Epoch, it.Str("from"), b.Str("h"), b.Str("s"), signer.Pub!, k.Key);
                    var at = o.Header.Long("at");
                    if (!InWindow(info, k.Epoch, at)) continue;
                    kept.Add((group.Key, k.Epoch, k.Key, at));
                }
                catch (CryptoFail) { /* not this room's key: dropped */ }
            }
            s.PutMany(kept);                                   // saved first: an ack lets the server delete its wrap
            foreach (var k in kept) PendingAdd(group.Key, k.Item2);
            n += kept.Count;
        }
        foreach (var k in keys) Wipe(k.Key);
        await FlushAcksAsync().ConfigureAwait(false);
        await DoneAsync(id).ConfigureAwait(false);
        await e.KeysArrivedAsync().ConfigureAwait(false);
        e.Say(null, LineKind.Ok, "Received " + n + " older room key" + (n == 1 ? "" : "s") + " from " + from.Name + ".");
    }

    public void Removed()
    {
        Store?.Wipe();
        e.StoreRemoved();
        e.Say(null, LineKind.Warn, "This PC was removed from your devices on another device, so the room keys it kept have been wiped (on disk and in memory).");
    }

    // ------------------------------------------------------------------------------------------- the person's own actions
    public async Task AskAgainAsync()
    {
        var s = Store ?? throw new InvalidOperationException("This PC keeps no room keys.");
        await e.Api.CallAsync("sync/request", new JsonObject { ["dev"] = s.Dev }).ConfigureAwait(false);
        e.Say(null, LineKind.Sys, "Asked your other devices again. Approve it on one of them; this PC's code is " + s.Code() + ".");
    }

    public async Task RemoveAsync(DeviceList list, DeviceEntry d)
    {
        var rest = list.Devices.Where(x => x.Id != d.Id).ToList();
        if (rest.Count == 0) throw new InvalidOperationException("A device list needs at least one device. Keep this one, or reset your identity to start again.");
        var signed = Devices.Publish(e.Me.Id, e.Me.Fp, list.Seq + 1, rest, NowMs());
        await e.Api.CallAsync("keydevices", new JsonObject { ["list"] = ListJson(signed) }).ConfigureAwait(false);
        if (Store is { } s && d.Id == s.Dev)
        {
            s.Wipe();
            e.StoreRemoved();
            e.Say(null, LineKind.Warn, "This PC's key store is wiped; this session keeps nothing from now on.");
        }
        else e.Say(null, LineKind.Ok, d.Name + " was removed from your devices.");
        await e.RefreshAsync().ConfigureAwait(false);
    }

    private static long NowMs() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
}
