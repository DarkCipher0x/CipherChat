using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CipherChat.Api;
using CipherChat.Crypto;
using static CipherChat.Crypto.Bytes;

namespace CipherChat.Engine;

/// <summary>
/// The chat (app.js + messages.js, without the screen). Security rules this class keeps:
///   - nothing is shown as a message unless its hybrid signature verifies under a TRUSTED identity (Trust);
///   - room keys are only accepted from trusted identities, and only handed to trusted identities;
///   - a room key that went to anyone this device doesn't trust is replaced before the next message is sent;
///   - room keys in memory are wiped by <see cref="Lock"/>; the ones this PC keeps (so the server can delete its
///     wrapped copies) are in its <see cref="KeyStore"/>, sealed to this PC and the passphrase (KeyHistory.cs).
/// Events are raised on background threads; the UI marshals them.
/// </summary>
public sealed class ChatEngine(ChatApi api, Me me)
{
    private static readonly long RotateAfterS = 7 * 86400;
    private readonly Trust _trust = new();
    private readonly Dictionary<string, Room> _rooms = new();
    private readonly object _gate = new();
    private CancellationTokenSource? _poll;
    private long _lastSeq, _rev, _sig;
    private Calls? _calls;
    private bool _autoBusy;
    private KeyHistory? _hist;
    private bool _histReady;

    /// <summary>This PC's key store (set with <see cref="UseStore"/> before <see cref="StartAsync"/>); null keeps nothing.</summary>
    public KeyStore? Store { get; private set; }
    internal KeyHistory History => _hist ??= new KeyHistory(this);
    public void UseStore(KeyStore? store) => Store = store;

    /// <summary>
    /// Another of my devices asks for this PC's room keys: (its name, when it was added, its device code). True sends,
    /// false declines, null asks again later. Unset: requests wait for a device that asks the person.
    /// </summary>
    public Func<string, DateTimeOffset, string, Task<bool?>>? ConfirmSync { get; set; }

    /// <summary>A room's log was cleared to be shown again from the start (older keys arrived from another device).</summary>
    public event Action<Room>? RoomReset;
    public IReadOnlyList<long> HistoryChoices => State["limits"]?["history"] is JsonArray a ? a.Select(x => x!.GetValue<long>()).ToList() : [0];

    public ChatApi Api { get; } = api;
    public Me Me { get; } = me;
    public JsonObject State { get; private set; } = [];
    public IReadOnlyDictionary<string, Person> People { get; private set; } = new Dictionary<string, Person>();
    public string OwnerProblem { get; private set; } = "";
    public bool Online { get; private set; }
    public AskCode? Ask { get => Api.Ask; set => Api.Ask = value; }
    public string MyUser => Me.User;
    /// <summary>Voice and video calls: signals, keys and ringing (Calls.cs).</summary>
    public Calls Calls => _calls ??= new Calls(this);
    public bool IAmOwner => State["me"] is JsonObject m && m["owner"]?.GetValue<bool>() == true;
    public bool CanCreateRooms => State["me"] is JsonObject m && m["can_create"]?.GetValue<bool>() == true;
    public IReadOnlyList<long> RetentionChoices => State["limits"]?["retention"] is JsonArray a ? a.Select(x => x!.GetValue<long>()).ToList() : [0];

    public event Action? RoomsChanged;                   // the room list, unread counts or people changed

    /// <summary>The room on screen while the window is active: new messages there don't count as unread.</summary>
    public Room? Viewing { get; set; }

    public void MarkRead(Room r)
    {
        if (r.Unread == 0) return;
        r.Unread = 0;
        RoomsChanged?.Invoke();
    }
    public event Action<bool>? OnlineChanged;
    public event Action<Room, Entry>? EntryAdded;
    public event Action<Room, Entry>? EntryChanged;
    public event Action<Room, Entry>? EntryRemoved;
    public event Action<Room?, LineKind, string>? Notice; // a line for the current room (or none)

    public IReadOnlyList<Room> Rooms { get { lock (_gate) return _rooms.Values.ToList(); } }
    public Room? RoomById(string id) { lock (_gate) return _rooms.GetValueOrDefault(id); }

    // ------------------------------------------------------------------------------------------- state
    public async Task StartAsync()
    {
        await RefreshAsync().ConfigureAwait(false);
        _lastSeq = State.LongOrNull("last_seq") ?? 0;
        _rev = State.LongOrNull("dir_rev") ?? 0;
        Online = true;
        OnlineChanged?.Invoke(true);
        if (Me.AnchorFp is null) Say(null, LineKind.Warn, "You haven't verified the owner yet, so nobody can be trusted. Compare safety numbers to pin the owner's identity.");
        if (Store is not null)
        {
            try { await History.EnrollAsync().ConfigureAwait(false); }
            catch (Exception e) when (e is ApiException or CryptoFail or InvalidOperationException or KeyNotFoundException)
            {
                Say(null, LineKind.Err, "Couldn't add this PC to your devices: " + e.Message + ". Its keys are used for this session only.");
                Store?.Close();
                Store = null;
            }
        }
        else if (!AddonIdentity.IsAddon(MyUser)) Say(null, LineKind.Sys, "This session keeps no room keys on this PC. It reads what the server still holds for you; your other devices hold the rest.");
        // A fresh prekey before anything can make a room key, so the first key after unlocking is per-device too;
        // erasing expired ones waits for the import below.
        if (Store is not null) await PrekeysOrWarnAsync(erase: false).ConfigureAwait(false);
        _histReady = true;
        _ = History.OnStateAsync();
        _poll = new CancellationTokenSource();
        _ = Task.Run(() => PollLoopAsync(_poll.Token));
        _outbox.Start(_poll.Token);
        if (Store is not null) _ = Task.Run(ImportThenPrekeysAsync);
    }

    private async Task ImportThenPrekeysAsync()
    {
        await ImportAllAsync().ConfigureAwait(false);
        await PrekeysOrWarnAsync(erase: true).ConfigureAwait(false);
    }

    private async Task PrekeysOrWarnAsync(bool erase)
    {
        try { await History.PrekeysAsync(erase).ConfigureAwait(false); }
        catch (Exception e) when (e is ApiException or CryptoFail or InvalidOperationException or KeyNotFoundException or IOException)
        {
            Say(null, LineKind.Warn, "Couldn't publish this PC's prekey (" + e.Message + "): new room keys use compatibility mode until it's done.");
        }
    }

    /// <summary>This PC's device id on fetches, so per-device room keys (protocol 2) come back for it.</summary>
    private string DevQ(string sep) => Store is { } s ? sep + "dev=" + s.Dev : "";

    /// <summary>Opens every room's wraps once, so this PC holds (and acknowledges) every key it can and the server can
    /// delete them; then each room's history window is applied to the keys kept here.</summary>
    internal async Task ImportAllAsync()
    {
        foreach (var r in Rooms)
        {
            await r.Lock.WaitAsync().ConfigureAwait(false);
            try { await LoadEpochsAsync(r).ConfigureAwait(false); }
            catch (Exception e) when (e is ApiException or CryptoFail or KeyNotFoundException or InvalidOperationException) { /* retried when the room is opened */ }
            finally { r.Lock.Release(); }
        }
        await History.FlushAcksAsync().ConfigureAwait(false);
        ApplyWindowNow();
    }

    private void ApplyWindowNow()
    {
        foreach (var (room, epoch) in History.ApplyWindow())
        {
            if (RoomById(room) is not { } r) continue;
            if (r.Keys.Remove(epoch, out var k)) Wipe(k);
            r.Expired.Add(epoch);
        }
    }

    /// <summary>Older keys arrived from another of my devices: every room is shown again from the start.</summary>
    internal async Task KeysArrivedAsync()
    {
        foreach (var r in Rooms)
        {
            await r.Lock.WaitAsync().ConfigureAwait(false);
            try
            {
                lock (r.Timeline) r.Timeline.Clear();
                r.Seqs.Clear(); r.MsgIds.Clear(); r.EpochTried.Clear(); r.Msgs.Clear(); r.Pending.Clear();
                r.Oldest = long.MaxValue;
                r.Loaded = false;
                lock (r) r.Loading = null;
            }
            finally { r.Lock.Release(); }
            RoomReset?.Invoke(r);
        }
    }

    /// <summary>This PC is no longer one of my devices: its store is gone, and so are the keys in memory.</summary>
    internal void StoreRemoved()
    {
        _hist?.ForgetPrekeys();
        Store = null;
        lock (_gate) foreach (var r in _rooms.Values) r.Wipe();
    }

    // ------------------------------------------------------------------------------------------- devices holding my keys
    /// <summary>My signed device list (null in compatibility mode: no device has joined yet).</summary>
    public DeviceList? KeyDevices() => History.MyList();
    public IReadOnlyDictionary<string, long> DeviceSeen =>
        State["me"]?["device_seen"] is JsonObject o ? o.ToDictionary(p => p.Key, p => p.Value!.GetValue<long>()) : new Dictionary<string, long>();
    public Task AskHistoryAgainAsync() => History.AskAgainAsync();
    public Task RemoveKeyDeviceAsync(DeviceList list, DeviceEntry d) => History.RemoveAsync(list, d);

    public async Task RefreshAsync() => ApplyState(await Api.CallAsync("state").ConfigureAwait(false));

    private void ApplyState(JsonObject st)
    {
        State = st;
        var t = _trust.Evaluate(st.Arr("directory"), st.Str("owner"), Me.AnchorFp);
        People = t.People;
        if (t.OwnerProblem.Length > 0 && OwnerProblem != t.OwnerProblem && Me.AnchorFp is not null) Say(null, LineKind.Warn, "Trust problem: " + t.OwnerProblem + ".");
        OwnerProblem = t.OwnerProblem;
        lock (_gate)
        {
            var seen = new HashSet<string>();
            foreach (var info in st.Arr("rooms").OfType<JsonObject>())
            {
                var id = info.Str("id");
                seen.Add(id);
                if (_rooms.TryGetValue(id, out var r)) r.Info = info; else _rooms[id] = new Room(id, info);
            }
            foreach (var id in _rooms.Keys.Where(k => !seen.Contains(k)).ToList()) { _rooms[id].Wipe(); _rooms.Remove(id); }
        }
        RoomsChanged?.Invoke();
        if (_histReady) _ = History.OnStateAsync();
    }

    internal Person? Trusted(string user) => People.TryGetValue(user, out var p) && p.Trust == TrustLevel.Ok && p.Pub is not null ? p : null;

    internal void Say(Room? r, LineKind k, string text)
    {
        if (r is null) { Notice?.Invoke(null, k, text); return; }
        Add(r, new Entry { At = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), Kind = k, Who = k == LineKind.Err ? "!!" : "--", Text = text });
    }

    private void Add(Room r, Entry e)
    {
        lock (r.Timeline)
        {
            if (e.Seq == 0) r.Timeline.Add(e);
            else
            {
                var i = r.Timeline.FindIndex(x => x.Seq == 0 || x.Seq > e.Seq);
                if (i < 0) r.Timeline.Add(e); else r.Timeline.Insert(i, e);
            }
        }
        EntryAdded?.Invoke(r, e);
    }

    // ------------------------------------------------------------------------------------------- rooms
    /// <summary>Loads a room's keys and recent history (once); later items arrive through polling.</summary>
    public Task OpenRoomAsync(Room r)
    {
        r.Unread = 0;
        RoomsChanged?.Invoke();
        lock (r) r.Loading ??= LoadRoomAsync(r);
        return r.Loading;
    }

    private async Task LoadRoomAsync(Room r)
    {
        try
        {
            await LoadEpochsAsync(r).ConfigureAwait(false);
            var res = await Api.CallAsync("rooms/" + r.Id + "/items" + DevQ("?")).ConfigureAwait(false);
            r.MoreHistory = res["more"]?.GetValue<bool>() == true;
            foreach (var it in res.Arr("items").OfType<JsonObject>()) await HandleAsync(r, it, live: false).ConfigureAwait(false);
            r.Loaded = true;
            List<JsonObject> q;
            lock (r.Queue) { q = r.Queue.ToList(); r.Queue.Clear(); }
            foreach (var it in q) await HandleAsync(r, it, live: true).ConfigureAwait(false);
            if (res.Arr("items").Count == 0) Say(r, LineKind.Sys, "Nothing here yet. Messages are end-to-end encrypted with this room's key; the server only stores ciphertext.");
        }
        catch (Exception e) when (e is ApiException or CryptoFail)
        {
            Say(r, LineKind.Err, "Couldn't load this room: " + e.Message);
            lock (r) r.Loading = null;
        }
    }

    public async Task LoadOlderAsync(Room r)
    {
        var res = await Api.CallAsync("rooms/" + r.Id + "/items?before=" + r.Oldest + DevQ("&")).ConfigureAwait(false);
        foreach (var it in res.Arr("items").OfType<JsonObject>().Reverse()) await HandleAsync(r, it, live: false).ConfigureAwait(false);
        r.MoreHistory = res["more"]?.GetValue<bool>() == true;
    }

    private async Task LoadEpochsAsync(Room r)
    {
        // With a key store, every signed header comes back (the wrap may be gone because a device of mine holds the key)
        var res = await Api.CallAsync("rooms/" + r.Id + "/epochs" + (Store is not null ? "?all=1" + DevQ("&") : "")).ConfigureAwait(false);
        foreach (var it in res.Arr("items").OfType<JsonObject>()) OpenEpochItem(r, it, announce: false);
        if (Store is not null) await History.FlushAcksAsync().ConfigureAwait(false);
        var old = Store is not null ? KeyHistory.Leftover(res.Arr("items")) : 0;
        if (old > 0 && !r.LeftoverWarned) { r.LeftoverWarned = true; Say(r, LineKind.Warn, KeyHistory.LeftoverWarning(old)); }
    }

    /// <summary>Accept a room key only if a trusted identity signed it, it was made for MY current identity (or this PC
    /// already holds it), and its commitment matches. Note anyone it went to whom this device doesn't trust: that key
    /// won't be used to send. A key opened from its wrap is kept and acknowledged, so the server can delete the wrap.</summary>
    private bool OpenEpochItem(Room r, JsonObject it, bool announce)
    {
        var epoch = it.Long("epoch");
        if (r.Keys.ContainsKey(epoch)) return true;
        if (r.Expired.Contains(epoch)) return false;
        var from = it.Str("from");
        var signer = Trusted(from);
        if (signer is null) { if (announce) Say(r, LineKind.Warn, "Ignored room key #" + epoch + " from " + from + ": that identity isn't verified."); return false; }
        var body = it.Obj("body");
        var w = body.StrOrNull("w");
        var held = Store is not null ? History.Kept(r.Id, epoch) : null;
        if (held is null && w is null)
        {
            // not for this device, but the next key made here must still follow on from it
            try { r.Hashes.TryAdd(epoch, CipherChat.Crypto.Room.HeaderHashOf(r.Id, epoch, from, body.Str("h"), body.Str("s"), signer.Pub!)); }
            catch (Exception e) when (e is CryptoFail or KeyNotFoundException or InvalidOperationException or FormatException) { }
            return false;
        }
        try
        {
            CipherChat.Crypto.Room.Opened? o = null;
            if (held is not null)
            {
                try { o = CipherChat.Crypto.Room.CheckEpoch(r.Id, epoch, from, body.Str("h"), body.Str("s"), signer.Pub!, held); }
                catch (CryptoFail) { Wipe(held); held = null; }
            }
            if (o is null && w is not null)
                o = body.LongOrNull("v") == 2
                    ? CipherChat.Crypto.Room.OpenEpochV2(Me.Id, Me.Fp, Store?.Dev ?? "", r.Id, epoch, from, body.Str("h"), body.Str("s"), w, signer.Pub!, History.PrekeyOf)
                    : CipherChat.Crypto.Room.OpenEpoch(Me.Id, Me.Fp, r.Id, epoch, from, body.Str("h"), body.Str("s"), w, signer.Pub!);
            if (o is null) throw new CryptoFail("the key this PC holds doesn't match the signed header");
            var at = o.Header.LongOrNull("at") ?? 0;
            if (Store is not null && !KeyHistory.InWindow(r.Info, epoch, at)) { Wipe(o.Key); r.Expired.Add(epoch); return false; }
            if (held is null && Store is not null) History.Keep(r.Id, epoch, o.Key, at);
            r.Keys[epoch] = o.Key;
            r.Hashes[epoch] = CipherChat.Crypto.Room.HeaderHash(o.Raw);
            r.Headers[epoch] = o.Header;
            // (a per-device key also names devices: one missing from that person's verified device list counts the same)
            var v2 = o.Header.LongOrNull("v") == 2;
            var odd = o.Header.Arr("recipients").OfType<JsonObject>()
                       .Where(x => Trusted(x.Str("u")) is not { } p || p.Fp != x.Str("fp") || (v2 && !History.DeviceListed(x.Str("u"), x.Str("dev"))))
                       .Select(x => x.Str("u")).Distinct().ToList();
            if (odd.Count > 0)
            {
                r.Untrusted.Add(epoch);
                Say(r, LineKind.Warn, "Room key #" + epoch + " was also given to identities or devices you can't verify: " + string.Join(", ", odd) + ". It will be replaced before you send.");
            }
            if (epoch > 1 && r.Hashes.TryGetValue(epoch - 1, out var prev) && o.Header.StrOrNull("prev") != prev)
                Say(r, LineKind.Warn, "Room key #" + epoch + " doesn't follow on from key #" + (epoch - 1) + " (key history was altered).");
            return true;
        }
        catch (CryptoFail e)
        {
            if (announce) Say(r, LineKind.Err, "Room key #" + epoch + " from " + from + " was refused: " + e.Message);
            return false;
        }
    }

    private async Task HandleAsync(Room r, JsonObject it, bool live)
    {
        await r.Lock.WaitAsync().ConfigureAwait(false);
        try { await HandleLockedAsync(r, it, live).ConfigureAwait(false); }
        catch (Exception e) when (e is CryptoFail or ApiException or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            Say(r, LineKind.Err, "Internal error: " + e.Message);
        }
        finally { r.Lock.Release(); }
    }

    private async Task HandleLockedAsync(Room r, JsonObject it, bool live)
    {
        var seq = it.Long("seq");
        if (!r.Seqs.Add(seq)) return;
        r.Oldest = Math.Min(r.Oldest, seq);
        var kind = it.Str("kind");
        var from = it.StrOrNull("from") ?? "?";
        var at = it.LongOrNull("at") ?? 0;
        Entry Line(LineKind k, string who, string text) => new() { Seq = seq, At = at, Kind = k, Who = who, Text = text };
        if (kind == "msg")
        {
            var epoch = it.Long("epoch");
            if (!r.Keys.ContainsKey(epoch) && r.EpochTried.Add(epoch))
            {
                try { await LoadEpochsAsync(r).ConfigureAwait(false); } catch (ApiException) { }
            }
            var who = Trusted(from);
            if (!r.Keys.TryGetValue(epoch, out var key))
            {
                Add(r, Line(LineKind.Warn, from, r.Expired.Contains(epoch) ? "[older than this room's history window: its key was erased from your devices]"
                    : "[encrypted with room key #" + epoch + ", which " + (Store is not null ? "this PC doesn't hold (another of your devices can send it: Settings, Devices holding your keys)" : "wasn't made for you") + "]"));
                return;
            }
            if (who is null) { Add(r, Line(LineKind.Warn, from, "[hidden: " + from + "'s identity isn't verified]")); return; }
            CipherChat.Crypto.Room.OpenedMsg m;
            try
            {
                var b = it.Obj("body");
                m = CipherChat.Crypto.Room.OpenMessage(r.Id, epoch, from, b.Str("h"), b.Str("c"), b.Str("s"), key, who.Pub!);
            }
            catch (CryptoFail e) { Add(r, Line(LineKind.Err, from, "[refused: " + e.Message + "]")); return; }
            // signed message ids are unique: a second copy is the server replaying an old message
            if (!r.MsgIds.Add(m.Id)) { Add(r, Line(LineKind.Warn, from, "[ignored: replayed copy of an earlier message]")); return; }
            var shown = Show(r, seq, from, at, m);
            if (shown && live && from != MyUser && r != Viewing) { r.Unread++; RoomsChanged?.Invoke(); }
        }
        else if (kind == "epoch")
        {
            var got = OpenEpochItem(r, it, live);
            var epoch = it.Long("epoch");
            var recips = got && r.Headers.TryGetValue(epoch, out var h) ? string.Join(", ", h.Arr("recipients").OfType<JsonObject>().Select(x => x.Str("u")).Distinct()) : "";   // one name per person, however many devices
            Add(r, Line(LineKind.Sys, "--", got ? "new room key #" + epoch + " from " + from + " for " + recips + " (signed, ML-KEM-1024 + X25519)"
                                              : "room key #" + epoch + " from " + from + (it.Obj("body").StrOrNull("w") is not null ? " (not accepted)"
                                                  : r.Expired.Contains(epoch) ? " (past this room's history window)"
                                                  : Store is not null && MadeForMe(it) ? " (made for you; this PC doesn't hold it)" : " (not for you)")));
        }
        else if (kind == "event") Add(r, Line(LineKind.Server, "server", Describe(it.Obj("body"))));
        else if (kind == "redact")
        {
            var target = long.Parse(it.Obj("body")["target"]!.ToJsonString().Trim('"'), System.Globalization.CultureInfo.InvariantCulture);
            // the server deletes a burn message once everyone has opened it; one still being read here waits for its countdown
            Entry? e;
            lock (r.Timeline) e = r.Timeline.FirstOrDefault(x => x.Seq == target);
            if (e?.Message is { Burn: > 0, Revealed: true, Mine: false, Burned: false }) return;
            Remove(r, target);
        }
    }

    private bool MadeForMe(JsonObject it)
    {
        try { return Canon.ParseSigned(it.Obj("body").Str("h"), 65536).Obj.Arr("recipients").OfType<JsonObject>().Any(x => x.StrOrNull("u") == MyUser); }
        catch (CryptoFail) { return false; }
    }

    private void Remove(Room r, long seq)
    {
        Entry? e;
        lock (r.Timeline)
        {
            e = r.Timeline.FirstOrDefault(x => x.Seq == seq);
            if (e is not null) r.Timeline.Remove(e);
        }
        if (e?.Message is { } m) r.Msgs.Remove(m.Id);
        if (e is not null) EntryRemoved?.Invoke(r, e);
    }

    private static string Describe(JsonObject b)
    {
        string List(string k) => b[k] is JsonArray a ? string.Join(", ", a.Select(x => x!.GetValue<string>())) : "";
        var by = b.StrOrNull("by") ?? "?";
        switch (b.StrOrNull("e"))
        {
            case "created": return by + " created " + (b.StrOrNull("name") is { Length: > 0 } n ? "#" + n : "this conversation") + (List("members") is { Length: > 0 } m ? " with " + m : "");
            case "members":
                return string.Join("; ", new[] { List("add") is { Length: > 0 } a ? by + " added " + a : "", List("remove") is { Length: > 0 } rm ? by + " removed " + rm : "",
                    List("admin") is { Length: > 0 } ad ? by + " made " + ad + " admin" : "", List("member") is { Length: > 0 } me ? by + " made " + me + " a member" : "" }.Where(s => s.Length > 0));
            case "updated": return by + " changed " + string.Join(", ", b.Where(p => p.Key is not "e" and not "by").Select(p => p.Key.Replace('_', ' ') + " to " + p.Value?.ToJsonString()));
            case "left": return by + " left";
            case "call": return by + " started a " + (b.StrOrNull("media") == "video" ? "video" : "voice") + " call";
            default: return by + ": " + b.StrOrNull("e");
        }
    }

    // ------------------------------------------------------------------------------------------- messages, reactions, edits
    private bool Show(Room r, long seq, string from, long at, CipherChat.Crypto.Room.OpenedMsg opened)
    {
        var p = opened.Payload;
        var kind = p.StrOrNull("k") ?? "text";
        if (kind is "react" or "edit")
        {
            var target = p.Str("target");
            if (r.Msgs.TryGetValue(target, out var tm)) Apply(r, tm, kind, from, seq, p);
            else
            {
                if (!r.Pending.TryGetValue(target, out var list)) r.Pending[target] = list = [];
                list.Add((kind, from, seq, p));
            }
            return false;                                     // nothing new to show in the log
        }
        var m = new ChatMessage
        {
            Id = opened.Id, Seq = seq, From = from, At = at, Mine = from == MyUser, Kind = kind, Text = p.Str("text"),
            ReplyTo = p.StrOrNull("re"), Burn = (int)(p.LongOrNull("burn") ?? 0),
            Files = p["files"] is JsonArray fa ? fa.OfType<JsonObject>().Select(FileRef.From).ToList() : [],
        };
        r.Msgs[m.Id] = m;
        var e = new Entry { Seq = seq, At = at, Message = m, Who = from };
        Add(r, e);
        if (m.Mine) _outbox.Delivered(m.Id);                                    // its "sending" placeholder goes
        if (m.Burn == 0 && r.Pending.Remove(m.Id, out var ops)) foreach (var o in ops) Apply(r, m, o.Kind, o.From, o.Seq, o.Payload);
        return true;
    }

    /// <summary>The newest operation (by server order) for each person+emoji wins; edits only from the author.</summary>
    private void Apply(Room r, ChatMessage m, string kind, string from, long seq, JsonObject p)
    {
        if (m.Burn > 0) return;                                // no reactions or edits on burn messages
        if (kind == "edit")
        {
            if (from != m.From || seq <= m.EditedSeq) return;
            m.EditedSeq = seq;
            m.Text = p.Str("text");
        }
        else
        {
            var emoji = p.Str("emoji");
            var k = from + "|" + emoji;
            if (m.Ops.TryGetValue(k, out var prev) && prev.Seq >= seq) return;
            m.Ops[k] = (seq, p["on"]?.GetValue<bool>() == true, from, emoji);
        }
        Entry? e;
        lock (r.Timeline) e = r.Timeline.FirstOrDefault(x => x.Message == m);
        if (e is not null) EntryChanged?.Invoke(r, e);
    }

    public ChatMessage? MessageById(Room r, string id) => r.Msgs.GetValueOrDefault(id);

    // ------------------------------------------------------------------------------------------- room keys and sending
    // A per-device key (protocol 2) when every recipient device has a fresh prekey, otherwise a compatibility key (v1),
    // also when the server says someone still has an older app signed in.
    private async Task<byte[]> RotateAsync(Room r, string reason)
    {
        var v1Only = false;
        var refreshed = false;
        for (var attempt = 0; attempt < 4; attempt++)
        {
            // the new key names the current one's header: fetch it if this device hasn't seen it yet
            if (r.Epoch > 0 && !r.Hashes.ContainsKey(r.Epoch)) await LoadEpochsAsync(r).ConfigureAwait(false);
            // what's cached may be older than a prekey or a sign-out: look once more before settling for compatibility
            if (!v1Only && !refreshed && Store is not null && History.V2Lines(r.Eligible).Lines is null)
            {
                refreshed = true;
                await RefreshAsync().ConfigureAwait(false);
            }
            var recips = r.Eligible.Select(u =>
            {
                var p = Trusted(u) ?? throw new InvalidOperationException("Can't give " + u + " the room key: " + (People.GetValueOrDefault(u)?.Why ?? "no verified identity") + ".");
                return new CipherChat.Crypto.Room.Recipient(u, p.Fp!, p.Pub!);
            }).ToList();
            if (recips.All(x => x.U != MyUser)) throw new InvalidOperationException("Your identity isn't certified yet, so you can't hold this room's key.");
            var v2 = v1Only ? (null, "someone has an older app signed in") : History.V2Lines(r.Eligible);
            var prev = r.Hashes.GetValueOrDefault(r.Epoch) ?? "";
            var built = v2.Lines is { } lines
                ? CipherChat.Crypto.Room.BuildEpochV2(Me.Id, Me.Fp, r.Id, r.Epoch + 1, lines, prev)
                : CipherChat.Crypto.Room.BuildEpoch(Me.Id, Me.Fp, r.Id, r.Epoch + 1, recips, prev);
            var w = new JsonObject();
            foreach (var (u, v) in built.Pkg.W) w[u] = v;
            try
            {
                var res = await Api.CallAsync("rooms/" + r.Id + "/epoch", new JsonObject { ["pkg"] = new JsonObject { ["h"] = built.Pkg.H, ["s"] = built.Pkg.S, ["w"] = w } }).ConfigureAwait(false);
                var epoch = res.Long("epoch");
                r.Keys[epoch] = built.Key;
                var raw = Unb64(built.Pkg.H);
                r.Hashes[epoch] = CipherChat.Crypto.Room.HeaderHash(raw);
                r.Headers[epoch] = (JsonObject)Canon.Parse(Encoding.UTF8.GetString(raw))!;
                if (Store is not null)
                {
                    History.Keep(r.Id, epoch, built.Key, r.Headers[epoch].LongOrNull("at") ?? 0);
                    await History.FlushAcksAsync().ConfigureAwait(false);
                }
                var how = v2.Lines is { } l ? ", sealed to each of their " + l.Count + " devices" : Store is not null ? "; compatibility mode: " + v2.Why : "";
                Say(r, LineKind.Sys, "Made room key #" + epoch + " for " + string.Join(", ", recips.Select(x => x.U)) + " (" + reason + how + ").");
                await RefreshAsync().ConfigureAwait(false);
                return built.Key;
            }
            catch (ApiException e) when (e.Flag("v1") && !v1Only)
            {
                Wipe(built.Key);
                v1Only = true;
                await RefreshAsync().ConfigureAwait(false);
            }
            catch (ApiException e) when (e.Flag("stale"))
            {
                await RefreshAsync().ConfigureAwait(false);
                if (!r.NeedsRotation && r.Keys.TryGetValue(r.Epoch, out var k)) return k;
            }
        }
        throw new InvalidOperationException("The room kept changing while making a new key. Try again.");
    }

    private async Task<byte[]> KeyForAsync(Room r)
    {
        if (Me.AnchorFp is null) throw new InvalidOperationException("Verify the owner first.");
        if (!r.NeedsRotation && r.Epoch > 0 && !r.Keys.ContainsKey(r.Epoch)) await LoadEpochsAsync(r).ConfigureAwait(false);
        var stale = r.Epoch > 0 && DateTimeOffset.UtcNow.ToUnixTimeSeconds() - r.EpochAt > RotateAfterS;
        if (!r.NeedsRotation && r.Epoch > 0 && r.Keys.TryGetValue(r.Epoch, out var key) && !r.Untrusted.Contains(r.Epoch) && !stale) return key;
        var why = r.Epoch == 0 ? "first key" : r.NeedsRotation ? "members changed" : r.Untrusted.Contains(r.Epoch) ? "replacing a key given to unverified identities"
                : stale ? "weekly renewal" : "you didn't hold the current key";
        return await RotateAsync(r, why).ConfigureAwait(false);
    }

    /// <summary>Admins renew keys as soon as members change, so newcomers can read without waiting for someone to speak.</summary>
    public async Task MaybeAutoRotateAsync(Room r)
    {
        if (_autoBusy || Me.AnchorFp is null || !r.NeedsRotation || AddonIdentity.IsAddon(MyUser)) return;   // add-ons never make room keys
        var admin = r.Kind == "dm" || r.MyRole == "admin";
        if (!admin || !r.Eligible.Contains(MyUser) || !r.Eligible.All(u => Trusted(u) is not null)) return;
        _autoBusy = true;
        try { await RotateAsync(r, "members changed").ConfigureAwait(false); }
        catch (Exception e) when (e is ApiException or InvalidOperationException) { /* the next send retries and reports */ }
        finally { _autoBusy = false; }
    }

    // ------------------------------------------------------------------------------------------- the outbox
    private Outbox? _outboxField;
    private Outbox _outbox => _outboxField ??= new Outbox(this);

    /// <summary>Messages still on their way (queued, sending, or failed with a reason).</summary>
    public IReadOnlyList<Outgoing> Outgoing => _outbox.Pending;
    public void Retry(Outgoing o) => _outbox.Retry(o);
    public bool Discard(Outgoing o) => _outbox.Discard(o);
    /// <summary>Try queued messages now (the app calls this when Windows reports the network is back).</summary>
    public void NetworkChanged() => _outbox.Wake();
    /// <summary>Text messages still waiting, sealed where they already were, for the app's vault across a lock.</summary>
    public JsonArray OutboxSnapshot() => _outbox.Snapshot();
    public int OutboxDroppedOnLock => _outbox.DroppedOnLock;
    /// <summary>Put messages saved by <see cref="OutboxSnapshot"/> back in the queue (after <see cref="StartAsync"/>).</summary>
    public void RestoreOutbox(JsonArray saved) => _outbox.Restore(saved);

    private static readonly JsonObject PlaceholderRef = new()
    {
        ["blob"] = new string('0', 24), ["key"] = new string('A', 43) + "=", ["sha3"] = new string('0', 64), ["size"] = 0,
        ["name"] = "x", ["mime"] = "x", ["kind"] = "file",
    };

    /// <summary>Queues any payload kind: it's sealed and sent by the outbox, in order, through dropped connections.</summary>
    private void Enqueue(Room r, string kind, string preview, JsonObject payload, IReadOnlyList<OutgoingFile>? files = null)
    {
        files ??= [];
        var check = (JsonObject)payload.DeepClone();
        if (files.Count > 0) check["files"] = new JsonArray(PlaceholderRef.DeepClone());
        Payload.Check(check);
        if (Canon.Bytes(payload).Length > CipherChat.Crypto.Room.MaxTextBytes - 600 * files.Count)
            throw new InvalidOperationException("That message is too long (" + CipherChat.Crypto.Room.MaxTextBytes + " bytes at most).");
        if (Me.AnchorFp is null) throw new InvalidOperationException("Verify the owner first.");
        var o = new Outgoing(r, kind, preview, payload, files);
        OutgoingAdded(o);
        _outbox.Add(o);
    }

    internal async Task<CipherChat.Crypto.Room.SealedMsg> SealAsync(Room r, JsonObject payload)
    {
        if (Canon.Bytes(payload).Length > CipherChat.Crypto.Room.MaxTextBytes) throw new InvalidOperationException("That message is too long (" + CipherChat.Crypto.Room.MaxTextBytes + " bytes at most).");
        var key = await KeyForAsync(r).ConfigureAwait(false);
        return CipherChat.Crypto.Room.SealMessage(Me.Id, Me.Fp, r.Id, r.Epoch, key, payload);
    }

    internal void OutgoingAdded(Outgoing o)
    {
        if (!o.Visible) return;
        var e = new Entry { At = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), Who = MyUser, Outgoing = o };
        o.Entry = e;
        Add(o.Room, e);
    }

    internal void OutgoingChanged(Outgoing o) { if (o.Entry is { } e) EntryChanged?.Invoke(o.Room, e); }

    internal void OutgoingGone(Outgoing o)
    {
        if (o.Entry is not { } e) return;
        o.Entry = null;
        lock (o.Room.Timeline) o.Room.Timeline.Remove(e);
        EntryRemoved?.Invoke(o.Room, e);
    }

    /// <summary>Queues a message; it's sent as soon as the server can be reached (see <see cref="Outgoing"/>).</summary>
    public Task SendTextAsync(Room r, string text, string? replyTo = null, int burn = 0, bool action = false)
    {
        var p = new JsonObject { ["k"] = action ? "me" : "text", ["text"] = text };
        if (replyTo is not null) p["re"] = replyTo;
        if (burn > 0) p["burn"] = burn;
        Enqueue(r, action ? "me" : "text", text, p);
        return Task.CompletedTask;
    }

    public Task ReactAsync(Room r, ChatMessage m, string emoji, bool on)
    {
        Enqueue(r, "react", emoji, new JsonObject { ["k"] = "react", ["text"] = "", ["target"] = m.Id, ["emoji"] = emoji, ["on"] = on });
        return Task.CompletedTask;
    }

    public Task EditAsync(Room r, ChatMessage m, string text)
    {
        if (!m.Mine) throw new InvalidOperationException("You can only edit your own messages.");
        Enqueue(r, "edit", text, new JsonObject { ["k"] = "edit", ["text"] = text, ["target"] = m.Id });
        return Task.CompletedTask;
    }

    public Task RedactAsync(Room r, long seq) => Api.CallAsync("rooms/" + r.Id + "/redact", new JsonObject { ["seq"] = seq });

    /// <summary>The person opened a burn message: tell the server (it destroys the ciphertext once everyone has).</summary>
    public async Task RevealBurnAsync(Room r, ChatMessage m)
    {
        if (m.Burn == 0 || m.Revealed) return;
        m.Revealed = true;
        if (!m.Mine)
        {
            try { await Api.CallAsync("rooms/" + r.Id + "/burn", new JsonObject { ["seq"] = m.Seq }).ConfigureAwait(false); }
            catch (ApiException e) { Say(r, LineKind.Err, "Couldn't tell the server to burn it: " + e.Message); }
        }
    }

    /// <summary>The countdown ended: wipe the text and drop the message from this device.</summary>
    public void BurnOut(Room r, ChatMessage m)
    {
        m.Text = "";
        m.Burned = true;
        Remove(r, m.Seq);
    }

    // ------------------------------------------------------------------------------------------- attachments
    public sealed record OutgoingFile(string Name, byte[] Bytes, string? Mime = null, byte[]? Thumb = null, int? W = null, int? H = null, int? Dur = null);

    private async Task<FileRef> SealAndUploadAsync(Room r, byte[] bytes, Action<long, long>? progress)
    {
        var s = await Task.Run(() => Files.Seal(bytes)).ConfigureAwait(false);
        var res = await Api.UploadAsync(r.Id, s.Data, progress).ConfigureAwait(false);
        if (res.StrOrNull("sha3") != s.Sha3 || res.LongOrNull("size") != s.Data.Length)
            throw new InvalidOperationException("The server stored something other than what was sent. Not sending.");
        return new FileRef(res.Str("id"), s.Key, s.Sha3, s.Size, "", "", "", null, null, null, null);
    }

    /// <summary>Queues files (1-10, 100 MB each) with a caption; each is encrypted and uploaded once, then the message is sent.</summary>
    public Task SendFilesAsync(Room r, string caption, IReadOnlyList<OutgoingFile> files, string? replyTo = null, int burn = 0, IProgress<string>? status = null)
    {
        if (files.Count is 0 or > 10) throw new InvalidOperationException("Attach 1 to 10 files per message.");
        var big = files.FirstOrDefault(f => f.Bytes.LongLength > Files.Max);
        if (big is not null) throw new InvalidOperationException(big.Name + " is over the 100 MB limit.");
        var p = new JsonObject { ["k"] = "file", ["text"] = caption };
        if (replyTo is not null) p["re"] = replyTo;
        if (burn > 0) p["burn"] = burn;
        var preview = (caption.Length > 0 ? caption + "\n" : "") + string.Join(", ", files.Select(f => "📎 " + f.Name));
        Enqueue(r, "file", preview, p, files);
        return Task.CompletedTask;
    }

    /// <summary>One attachment (and its preview picture) encrypted and uploaded: its ref for the message and the blob ids.</summary>
    internal async Task<(JsonObject Ref, List<string> Blobs)> UploadFileAsync(Room r, OutgoingFile f)
    {
        var sniff = Files.Sniff(f.Bytes);
        var kind = sniff.StartsWith("image/", StringComparison.Ordinal) ? "image" : sniff.StartsWith("video/", StringComparison.Ordinal) ? "video"
                 : (f.Mime ?? "").StartsWith("audio/", StringComparison.Ordinal) ? "audio" : "file";
        var mime = kind is "image" or "video" ? sniff : (f.Mime ?? "application/octet-stream")[..Math.Min(100, (f.Mime ?? "application/octet-stream").Length)];
        var main = await SealAndUploadAsync(r, f.Bytes, null).ConfigureAwait(false);
        var blobs = new List<string> { main.Blob };
        FileRef? thumb = null;
        if (f.Thumb is not null && kind is "image" or "video")
        {
            thumb = await SealAndUploadAsync(r, f.Thumb, null).ConfigureAwait(false);
            blobs.Add(thumb.Blob);
        }
        return ((main with { Name = f.Name[..Math.Min(200, f.Name.Length)], Mime = mime, Kind = kind, Thumb = thumb, W = f.W, H = f.H, Dur = f.Dur }).ToJson(), blobs);
    }

    /// <summary>Downloads and decrypts an attachment (checks its signed hash and every chunk).</summary>
    public async Task<byte[]> FetchFileAsync(Room r, FileRef f)
    {
        var sealed_ = await Api.DownloadAsync(r.Id, f.Blob, f.Size).ConfigureAwait(false);
        return await Task.Run(() => Files.Open(sealed_, f.Key, f.Size, f.Sha3)).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------------------------------- rooms, people, devices
    public async Task<Room> CreateRoomAsync(string name, string topic, long retentionDays, IReadOnlyList<string> members)
    {
        var res = await Api.CallAsync("rooms", new JsonObject { ["name"] = name.TrimStart('#'), ["topic"] = topic, ["retention_days"] = retentionDays,
            ["members"] = new JsonArray(members.Select(m => (JsonNode)m).ToArray()) }).ConfigureAwait(false);
        await RefreshAsync().ConfigureAwait(false);
        return RoomById(res.Str("id")) ?? throw new InvalidOperationException("The new room didn't appear.");
    }

    public async Task<Room> OpenDmAsync(string user)
    {
        var res = await Api.CallAsync("dm", new JsonObject { ["user"] = user }).ConfigureAwait(false);
        await RefreshAsync().ConfigureAwait(false);
        return RoomById(res.Str("id")) ?? throw new InvalidOperationException("The conversation didn't appear.");
    }

    public async Task ChangeMembersAsync(Room r, IReadOnlyList<string> add, IReadOnlyList<string> remove)
    {
        await Api.CallAsync("rooms/" + r.Id + "/members", new JsonObject { ["add"] = new JsonArray(add.Select(x => (JsonNode)x).ToArray()),
            ["remove"] = new JsonArray(remove.Select(x => (JsonNode)x).ToArray()) }).ConfigureAwait(false);
        await RefreshAsync().ConfigureAwait(false);
        await MaybeAutoRotateAsync(r).ConfigureAwait(false);
    }

    public async Task UpdateRoomAsync(Room r, string name, string topic, long retentionDays, long? historyDays = null, bool? historySync = null)
    {
        var body = new JsonObject { ["name"] = name.TrimStart('#'), ["topic"] = topic, ["retention_days"] = retentionDays };
        if (historyDays is { } hd) body["history_days"] = hd;
        if (historySync is { } hs) body["history_sync"] = hs;
        await Api.CallAsync("rooms/" + r.Id + "/update", body).ConfigureAwait(false);
        await RefreshAsync().ConfigureAwait(false);
        if (historyDays is not null) ApplyWindowNow();
    }

    public async Task LeaveAsync(Room r) { await Api.CallAsync("rooms/" + r.Id + "/leave", new JsonObject()).ConfigureAwait(false); await RefreshAsync().ConfigureAwait(false); }
    public async Task DeleteRoomAsync(Room r) { await Api.CallAsync("rooms/" + r.Id + "/delete", new JsonObject()).ConfigureAwait(false); await RefreshAsync().ConfigureAwait(false); }
    public async Task RotateNowAsync(Room r) => await RotateAsync(r, "by request").ConfigureAwait(false);

    public string SafetyNumber(Person p) => p.Fp is null ? "" : Hybrid.SafetyNumber(Me.Fp, p.Fp);

    /// <summary>Owner only: certify someone after comparing the safety number out of band.</summary>
    public async Task CertifyAsync(Person p)
    {
        if (p.Fp is null) throw new InvalidOperationException(p.User + " hasn't set up the chat yet.");
        var cert = Hybrid.MakeCert(Me.Id, Me.Fp, p.User, p.Fp, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        await Api.CallAsync("certify", new JsonObject { ["user"] = p.User, ["cert"] = new JsonObject { ["b"] = cert.B, ["s"] = cert.S } }).ConfigureAwait(false);
        await RefreshAsync().ConfigureAwait(false);
    }

    public async Task RevokeAsync(Person p) { await Api.CallAsync("revoke", new JsonObject { ["user"] = p.User }).ConfigureAwait(false); await RefreshAsync().ConfigureAwait(false); }

    public Task<JsonObject> DevicesAsync() => Api.CallAsync("devices");

    /// <summary>Pairs another app (needs a fresh code); returns the one-time pairing code to show.</summary>
    public async Task<string> PairDeviceAsync(string name)
    {
        var j = await Api.CallAsync("devices", new JsonObject { ["name"] = name }).ConfigureAwait(false);
        return Pairing.Format(Api.Origin, j.Str("token"));
    }

    public Task RevokeDeviceAsync(string id) => Api.CallAsync("devices/" + id + "/revoke", new JsonObject());

    // ------------------------------------------------------------------------------------------- polling and locking
    private async Task PollLoopAsync(CancellationToken ct)
    {
        var backoff = TimeSpan.FromSeconds(1);
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var res = await Api.PollAsync(_lastSeq, _rev, _sig, Store?.Dev, ct).ConfigureAwait(false);
                if (res["signals"] is JsonArray signals && signals.Count > 0)
                {
                    _sig = Math.Max(_sig, signals.OfType<JsonObject>().Max(s => s.LongOrNull("sid") ?? 0));
                    Calls.OnSignals(signals);
                }
                if (!Online) { Online = true; OnlineChanged?.Invoke(true); _outbox.Wake(); }      // queued messages go now
                backoff = TimeSpan.FromSeconds(1);
                var rev = res.LongOrNull("dir_rev") ?? _rev;
                if (rev != _rev) { _rev = rev; await RefreshAsync().ConfigureAwait(false); }
                foreach (var it in res.Arr("items").OfType<JsonObject>())
                {
                    var r = RoomById(it.Str("room"));
                    if (r is null) continue;
                    if (!r.Loaded)
                    {
                        if (r.Loading is not null) { lock (r.Queue) r.Queue.Add(it); }
                        else if (it.StrOrNull("kind") == "msg") { r.Unread++; RoomsChanged?.Invoke(); }
                        continue;
                    }
                    await HandleAsync(r, it, live: true).ConfigureAwait(false);
                }
                _lastSeq = Math.Max(_lastSeq, res.LongOrNull("last_seq") ?? _lastSeq);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (ApiException e) when (e.Denied) { Say(null, LineKind.Err, "Your chat access was removed."); break; }
            catch (Exception e) when (e is ApiException or IOException or JsonException or KeyNotFoundException or InvalidOperationException)
            {
                if (Online) { Online = false; OnlineChanged?.Invoke(false); }
                try { await Task.Delay(backoff, ct).ConfigureAwait(false); } catch (OperationCanceledException) { break; }
                backoff = TimeSpan.FromSeconds(Math.Min(30, backoff.TotalSeconds * 2));
            }
        }
    }

    /// <summary>Stops polling and wipes every room key from memory. The engine can't be used afterwards.</summary>
    public void Lock()
    {
        _poll?.Cancel();
        lock (_gate)
        {
            foreach (var r in _rooms.Values) r.Wipe();
            _rooms.Clear();
        }
        _hist?.ForgetPrekeys();
        Store?.Close();
        Store = null;
        Me.ForgetStoreKey();
    }
}
