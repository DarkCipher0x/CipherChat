using System.Text.Json.Nodes;
using CipherChat.Crypto;

namespace CipherChat.Engine;

/// <summary>An incoming call, already verified (signed by a trusted identity, fresh).</summary>
public sealed record IncomingCall(string Call, string Room, string From, string Media, IReadOnlyList<string> People);

/// <summary>
/// Calls for the Windows app (docs/CALLS.md). The call itself (WebRTC, frame encryption, the call screen) runs in
/// the call window's WebView2 from the same JavaScript as the web portal; this class is everything it may ask of the
/// app, so the identity's private keys stay here:
///   seal / open signals, wrap / unwrap sender keys, the call words, and sending "calls/signal" / "calls/turn" over
///   this app's PQ-only TLS connection. Ringing is handled natively (no browser engine runs until a call is answered),
///   and every signal of a ringing or active call is kept so the call window can be given them when it opens.
/// </summary>
public sealed class Calls
{
    private static readonly TimeSpan Keep = TimeSpan.FromMinutes(2);
    private readonly ChatEngine _e;
    private readonly HashSet<string> _seenNative = [];
    private readonly HashSet<string> _seenWindow = [];
    private readonly object _gate = new();
    private readonly Dictionary<string, List<(DateTime At, JsonObject Item)>> _byCall = new();
    private readonly Dictionary<string, IncomingCall> _ringing = new();
    private string? _active;                                            // the call the window is showing

    internal Calls(ChatEngine e) => _e = e;

    /// <summary>This app instance's device id in calls.</summary>
    public string Device { get; } = Call.NewDeviceId();

    public event Action<IncomingCall>? Ringing;
    /// <summary>(call id, why): answered elsewhere, missed, the caller hung up...</summary>
    public event Action<string, string>? RingStopped;
    /// <summary>Signals for the active call, to pass to the call window as they come.</summary>
    public event Action<JsonArray>? Signals;

    public IReadOnlyList<string> TrustedUsers => _e.People.Values.Where(p => p.Trust == TrustLevel.Ok && p.Pub is not null).Select(p => p.User).ToList();

    // ------------------------------------------------------------------------------------------- from the poll
    internal void OnSignals(JsonArray items)
    {
        var forWindow = new JsonArray();
        foreach (var it in items.OfType<JsonObject>())
        {
            var call = it.StrOrNull("call");
            if (call is null) continue;
            lock (_gate)
            {
                if (!_byCall.TryGetValue(call, out var list)) _byCall[call] = list = [];
                list.Add((DateTime.UtcNow, (JsonObject)it.DeepClone()));
                foreach (var k in _byCall.Keys.ToList()) { _byCall[k].RemoveAll(x => DateTime.UtcNow - x.At > Keep); if (_byCall[k].Count == 0 && k != _active) _byCall.Remove(k); }
                if (call == _active) { forWindow.Add(it.DeepClone()); continue; }
            }
            Native(it);
        }
        if (forWindow.Count > 0) Signals?.Invoke(forWindow);
    }

    private void Native(JsonObject it)
    {
        JsonObject h;
        try { h = Call.Open(it, u => _e.Trusted(u)?.Pub, _seenNative); }
        catch (CryptoFail) { return; }                                  // unverifiable: ignored
        var call = h.Str("call");
        var kind = h.Str("kind");
        var mine = h.Str("from") == _e.MyUser;
        if (kind == "ring" && !mine)
        {
            if (_active is not null) { _ = SendBusyAsync(h); return; }
            var people = (h["people"] as JsonArray ?? []).Select(x => x?.GetValueKind() == System.Text.Json.JsonValueKind.String ? x.GetValue<string>() : null)
                .OfType<string>().Take(8).ToList();
            var inc = new IncomingCall(call, h.Str("room"), h.Str("from"), h.StrOrNull("media") == "video" ? "video" : "audio", people);
            lock (_gate)
            {
                if (_ringing.ContainsKey(call)) return;
                _ringing[call] = inc;
            }
            Ringing?.Invoke(inc);
            _ = Task.Delay(TimeSpan.FromSeconds(45)).ContinueWith(_ => StopRing(call, "missed"), TaskScheduler.Default);
        }
        else if (kind == "accept" && mine) StopRing(call, "answered on another device");
        else if (kind == "decline" && mine) StopRing(call, "declined on another device");
        else if (kind == "end" && !mine) StopRing(call, "missed");
    }

    private void StopRing(string call, string why)
    {
        lock (_gate) { if (!_ringing.Remove(call)) return; }
        RingStopped?.Invoke(call, why);
    }

    private async Task SendBusyAsync(JsonObject ring)
    {
        try
        {
            var to = new JsonArray(ring.Str("from"));
            var sig = Seal(new JsonObject { ["kind"] = "busy", ["room"] = ring.Str("room"), ["call"] = ring.Str("call"), ["dev"] = Device, ["to"] = to });
            await SignalAsync(new JsonObject { ["room"] = ring.Str("room"), ["to"] = to.DeepClone(), ["sig"] = sig }).ConfigureAwait(false);
        }
        catch (Exception e) when (e is Api.ApiException or CryptoFail) { }
    }

    // ------------------------------------------------------------------------------------------- the call window
    /// <summary>The window opens a call: it gets every signal kept for it so far (the ring, early ICE...) and all that follow.</summary>
    public JsonArray Open(string call)
    {
        lock (_gate)
        {
            _active = call;
            _ringing.Remove(call);
            _seenWindow.Clear();
            return new JsonArray(_byCall.TryGetValue(call, out var l) ? l.Select(x => (JsonNode)x.Item.DeepClone()).ToArray() : []);
        }
    }

    /// <summary>A call the window starts: from now on its signals go to the window.</summary>
    public void Started(string call)
    {
        lock (_gate)
        {
            if (_active == call) return;
            _active = call;
            _seenWindow.Clear();
        }
    }

    public void Closed() { lock (_gate) _active = null; }

    public void Decline(IncomingCall inc)
    {
        StopRing(inc.Call, "declined");
        _ = Task.Run(async () =>
        {
            try
            {
                var to = new JsonArray(inc.From);
                var sig = Seal(new JsonObject { ["kind"] = "decline", ["room"] = inc.Room, ["call"] = inc.Call, ["dev"] = Device, ["to"] = to });
                await SignalAsync(new JsonObject { ["room"] = inc.Room, ["to"] = to.DeepClone(), ["sig"] = sig }).ConfigureAwait(false);
            }
            catch (Exception e) when (e is Api.ApiException or CryptoFail) { }
        });
    }

    // ------------------------------------------------------------------------------------------- what the window may ask
    public JsonObject Seal(JsonObject fields)
    {
        if (fields.StrOrNull("dev") != Device) throw new CryptoFail("a call signal must carry this device's id");
        return Call.Seal(_e.Me.Id, _e.Me.Fp, fields);
    }

    public JsonObject OpenSignal(JsonObject item) => Call.Open(item, u => _e.Trusted(u)?.Pub, _seenWindow);

    public JsonObject WrapKey(byte[] key32, string call, long epoch, IEnumerable<string> users)
    {
        var people = users.Select(u => _e.Trusted(u)?.Pub ?? throw new CryptoFail(u + " isn't verified")).ToList();
        return Call.WrapSenderKey(key32, call, _e.Me.Id, Device, epoch, people);
    }

    public byte[] UnwrapKey(JsonObject sig) => Call.UnwrapSenderKey(sig, _e.Me.Id, _e.Me.Fp);

    public string[] Words(string call, IEnumerable<string> users) =>
        Call.CallWords(call, users.Select(u => (u, u == _e.MyUser ? _e.Me.Fp : _e.Trusted(u)?.Fp ?? throw new CryptoFail(u + " isn't verified"))));

    public Task<JsonObject> SignalAsync(JsonObject body) => _e.Api.CallAsync("calls/signal", body);

    public Task<JsonObject> TurnAsync() => _e.Api.CallAsync("calls/turn");
}
