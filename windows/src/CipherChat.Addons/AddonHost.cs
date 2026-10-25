using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using CipherChat.Api;
using CipherChat.Crypto;
using CipherChat.Engine;
using CipherChat.Transport;
using Room = CipherChat.Engine.Room;

namespace CipherChat.Addons;

/// <summary>A live message for the add-on: from a verified person (never another add-on), in a room it was added to.</summary>
public sealed record AddonMessage(Room Room, ChatMessage Message)
{
    public string From => Message.From;
    public string Text => Message.Text;
}

/// <summary>
/// Runs the chat as an add-on (docs/ADDONS.md): signs every request, opens its own identity (made on this machine, pinned
/// to the owner from the connector code), keeps every room it's in open, and raises <see cref="MessageReceived"/> for
/// messages that arrive while it runs. The chat engine does all the end-to-end cryptography and the trust checks, so a
/// message only gets here once its ML-DSA-87 + Ed25519 signature verified against a sender the owner certified.
/// </summary>
public sealed class AddonHost
{
    public const string UserAgent = "CipherChat-Addon/0.1.2";

    private readonly ConnectorCode _code;
    private readonly RequestSigner _signer;
    private readonly ChatApi _api;
    private readonly ConcurrentDictionary<string, byte> _seen = new();
    private readonly ConcurrentDictionary<string, byte> _opened = new();
    private long _liveFrom;

    public ChatEngine? Engine { get; private set; }
    public string User => _code.User;
    /// <summary>The 60 digits the owner compares before certifying this add-on (/verify addon.name).</summary>
    public string SafetyNumber => Engine is null ? "" : Hybrid.SafetyNumber(Engine.Me.Fp, _code.OwnerFp);
    public bool Certified => Engine?.State["me"]?["certified"]?.GetValue<bool>() == true;

    public event Func<AddonMessage, Task>? MessageReceived;
    public event Action<string>? Log;

    public AddonHost(ConnectorCode code, ITransport? transport = null)
    {
        _code = code;
        _signer = new RequestSigner(code);
        _api = new ChatApi(transport ?? new PqTlsTransport(code.Server), UserAgent) { Sign = _signer.Sign };
    }

    /// <summary>Signs in (calibrating to the server's clock if needed), opens the identity and starts the chat.</summary>
    public async Task StartAsync(byte[] master, CancellationToken ct = default)
    {
        JsonObject state;
        try { state = await _api.CallAsync("state", ct: ct).ConfigureAwait(false); }
        catch (ApiException e) when (e.Status == 401 && e.Body["server_time"] is JsonValue st)
        {
            _signer.ClockOffset = st.GetValue<long>() - DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Log?.Invoke("This PC's clock is off by " + _signer.ClockOffset + " s; using the server's time.");
            state = await _api.CallAsync("state", ct: ct).ConfigureAwait(false);
        }
        Me me;
        try { me = await AddonIdentity.OpenAsync(_api, state, master, _code.OwnerFp, ct).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(master); }
        var engine = new ChatEngine(_api, me);
        engine.EntryAdded += OnEntry;
        engine.RoomsChanged += () => _ = Task.Run(OpenAllAsync);
        engine.Notice += (_, kind, text) => Log?.Invoke(kind + ": " + text);
        Engine = engine;
        _liveFrom = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + _signer.ClockOffset - 5;
        await engine.StartAsync().ConfigureAwait(false);
        await OpenAllAsync().ConfigureAwait(false);
        if (!Certified) Log?.Invoke("Waiting for the owner to verify and certify " + User + " (safety number " + SafetyNumber + ").");
    }

    private async Task OpenAllAsync()
    {
        var e = Engine;
        if (e is null) return;
        // each room once (opening a room raises RoomsChanged, which lands back here)
        foreach (var r in e.Rooms.Where(r => !r.Loaded && _opened.TryAdd(r.Id, 0)))
        {
            try { await e.OpenRoomAsync(r).ConfigureAwait(false); }
            catch (Exception ex) when (ex is ApiException or CryptoFail)
            {
                _opened.TryRemove(r.Id, out _);
                Log?.Invoke("Couldn't open " + r.Id + ": " + ex.Message);
            }
        }
    }

    private void OnEntry(Room r, Entry entry)
    {
        var m = entry.Message;
        if (m is null || m.Mine || m.Kind is not ("text" or "file") || m.At < _liveFrom) return;
        if (AddonIdentity.IsAddon(m.From)) return;                         // add-ons never drive each other
        if (Engine?.People.TryGetValue(m.From, out var p) != true || p!.Trust != TrustLevel.Ok) return;
        if (!_seen.TryAdd(r.Id + "|" + m.Id, 0)) return;
        if (_seen.Count > 20000) _seen.Clear();
        var handler = MessageReceived;
        if (handler is null) return;
        _ = Task.Run(async () =>
        {
            try { await handler(new AddonMessage(r, m)).ConfigureAwait(false); }
            catch (Exception ex) { Log?.Invoke("Handler failed: " + ex.GetType().Name + ": " + ex.Message); }
        });
    }

    /// <summary>Replies in the same room, as a reply to the message (and burning the same way if it was a burn message).</summary>
    public Task ReplyAsync(AddonMessage to, string text) =>
        Engine!.SendTextAsync(to.Room, text, to.Message.Id, to.Message.Burn);

    public Task SayAsync(Room room, string text) => Engine!.SendTextAsync(room, text);

    public void Stop()
    {
        Engine?.Lock();
        _signer.Wipe();
    }
}
