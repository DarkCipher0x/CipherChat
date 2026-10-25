using System.Text.Json.Nodes;
using CipherChat.Api;
using CipherChat.Crypto;
using CipherChat.Engine;
using CipherChat.Passkeys;
using CipherChat.Transport;
using CipherChat.Vault;

namespace CipherChat.App.Shell;

/// <summary>
/// Everything one window needs: which server, how this PC signs in to it (a paired device token, or password + code),
/// the unlocked identity and the running chat. Keys live here only between unlock and <see cref="Lock"/>.
/// </summary>
public sealed class Session(Uri? devServer)
{
    public const string UserAgent = "CipherChat/0.1.1 (Windows)";

    public VaultStore Vault { get; } = new();
    public VaultStore.Contents Saved { get; private set; } = new();
    public Uri? DevServer { get; } = devServer;
    public ChatApi? Api { get; private set; }
    public JsonObject? State { get; private set; }
    public ChatEngine? Engine { get; private set; }
    public SavedServer? Server { get; private set; }
    public IReadOnlyList<SelfTest.Check> SelfTestResults { get; private set; } = [];
    public bool HelloOn => Vault.UsesHello;
    /// <summary>The window Windows' passkey dialog belongs to.</summary>
    public Func<IntPtr> Owner { get; set; } = () => IntPtr.Zero;

    /// <summary>Runs the OpenSSL known-answer self-test; the app refuses to go further if it fails.</summary>
    public void RunSelfTest() => SelfTestResults = SelfTest.Run();

    public async Task LoadSavedAsync() => Saved = await Vault.LoadAsync().ConfigureAwait(false);

    private ITransport TransportFor(Uri origin)
    {
        if (DevServer is not null && origin.Scheme == Uri.UriSchemeHttp) return new LoopbackDevTransport(origin);
        return new PqTlsTransport(origin);
    }

    private ChatApi NewApi(Uri origin)
    {
        var api = new ChatApi(TransportFor(origin), UserAgent);
        // a paired PC signs itself back in when its session ends (sessions idle out; the device token lasts much longer)
        api.Resume = async () =>
        {
            if (Server is null) return false;
            try { await api.DeviceSignInAsync(Server.DeviceToken).ConfigureAwait(false); return true; }
            catch (ApiException) { return false; }
        };
        if (WindowsPasskey.Available) api.Passkey = SignWithPasskey;
        return api;
    }

    private Task<JsonObject?> SignWithPasskey(JsonObject publicKey, string origin)
    {
        var owner = Owner();                                   // the dialog blocks, so it runs on a worker
        return Task.Run(() => WindowsPasskey.Sign(owner, publicKey, origin));
    }

    /// <summary>A passkey (Windows Hello, a phone, or a password manager such as Bitwarden): nothing is remembered on this PC.</summary>
    public async Task PasskeySignInAsync(Uri origin)
    {
        if (origin.Scheme != Uri.UriSchemeHttps && DevServer is null) throw new ArgumentException("CipherChat servers are https:// only.");
        Server = null;
        Api = NewApi(origin);
        await Api.PasskeyLoginAsync(SignWithPasskey).ConfigureAwait(false);
        State = await Api.CallAsync("state").ConfigureAwait(false);
    }

    /// <summary>Signs in with a saved pairing (device token).</summary>
    public async Task ResumeAsync(SavedServer s)
    {
        Server = s;
        Api = NewApi(new Uri(s.Origin));
        await Api.DeviceSignInAsync(s.DeviceToken).ConfigureAwait(false);
        State = await Api.CallAsync("state").ConfigureAwait(false);
    }

    /// <summary>A pairing code from the web chat (/pair): sign in with it and remember this PC.</summary>
    public async Task PairAsync(string code, bool useHello)
    {
        var parsed = Pairing.Parse(code) ?? throw new ArgumentException("That isn't a CipherChat pairing code. In the web chat type /pair to make one.");
        if (parsed.Server.Scheme == Uri.UriSchemeHttp && DevServer is null) throw new ArgumentException("That code is for a development server. CipherChat only connects to https:// servers.");
        Api = NewApi(parsed.Server);
        var (user, device) = await Api.DeviceSignInAsync(parsed.Token).ConfigureAwait(false);
        Server = new SavedServer(parsed.Server.GetLeftPart(UriPartial.Authority), user, device, parsed.Token, parsed.Server.Host);
        Saved.Servers.RemoveAll(x => x.Origin == Server.Origin && x.User == user);
        Saved.Servers.Insert(0, Server);
        await Vault.SaveAsync(Saved, useHello).ConfigureAwait(false);
        State = await Api.CallAsync("state").ConfigureAwait(false);
    }

    /// <summary>Password + authenticator code (no pairing: nothing is remembered on this PC).</summary>
    public async Task SignInAsync(Uri origin, string user, string password, string code)
    {
        if (origin.Scheme != Uri.UriSchemeHttps && DevServer is null) throw new ArgumentException("CipherChat servers are https:// only.");
        Server = null;
        Api = NewApi(origin);
        await Api.LoginAsync(user, password, code).ConfigureAwait(false);
        State = await Api.CallAsync("state").ConfigureAwait(false);
    }

    public async Task RefreshStateAsync() => State = await Api!.CallAsync("state").ConfigureAwait(false);

    public void Start(Me me, AskCode ask)
    {
        Api!.Ask = ask;
        Engine = new ChatEngine(Api, me) { Ask = ask };
        if (!_netHooked)
        {
            // a network came back: queued messages go now instead of after the outbox's backoff
            _netHooked = true;
            System.Net.NetworkInformation.NetworkChange.NetworkAvailabilityChanged += (_, e) => { if (e.IsAvailable) Engine?.NetworkChanged(); };
            System.Net.NetworkInformation.NetworkChange.NetworkAddressChanged += (_, _) => Engine?.NetworkChanged();
        }
    }

    private bool _netHooked;

    /// <summary>Wipes the keys from memory; the PC stays paired.</summary>
    public void Lock()
    {
        ParkOutbox();
        Engine?.Lock();
        Engine = null;
    }

    // Messages that hadn't reached the server when the chat locked wait here, sealed with DPAPI (this Windows user, no
    // prompt), and go back in the queue after the next unlock. Only text messages; they're gone if the app closes.
    private byte[]? _parked;
    private string? _parkedFor;
    private static readonly byte[] ParkEntropy = "CipherChat outbox"u8.ToArray();

    private void ParkOutbox()
    {
        if (Engine is null || Api is null) return;
        var waiting = Engine.OutboxSnapshot();
        if (waiting.Count == 0) return;
        _parked = System.Security.Cryptography.ProtectedData.Protect(System.Text.Encoding.UTF8.GetBytes(waiting.ToJsonString()), ParkEntropy,
            System.Security.Cryptography.DataProtectionScope.CurrentUser);
        _parkedFor = Api.Origin.GetLeftPart(UriPartial.Authority) + "|" + Engine.MyUser;
    }

    /// <summary>After the engine started: messages parked at the last lock (same server and person) go back in the queue.</summary>
    public void RestoreParkedOutbox()
    {
        if (_parked is null || Engine is null || Api is null) return;
        if (_parkedFor == Api.Origin.GetLeftPart(UriPartial.Authority) + "|" + Engine.MyUser)
        {
            var json = System.Security.Cryptography.ProtectedData.Unprotect(_parked, ParkEntropy, System.Security.Cryptography.DataProtectionScope.CurrentUser);
            try { if (JsonNode.Parse(json) is JsonArray a) Engine.RestoreOutbox(a); }
            finally { Array.Clear(json); }
        }
        _parked = null; _parkedFor = null;
    }

    /// <summary>Messages that would be lost if the app closed now.</summary>
    public int Unsent => (Engine?.Outgoing.Count(o => o.State != Outgoing.States.Sent) ?? 0) + (_parked is null ? 0 : 1);

    public async Task SignOutAsync(bool forgetPc)
    {
        Lock();
        if (Api is not null) { try { await Api.LogoutAsync().ConfigureAwait(false); } catch (ApiException) { } }
        if (forgetPc && Server is not null)
        {
            Saved.Servers.RemoveAll(x => x.Origin == Server.Origin && x.User == Server.User);
            if (Saved.Servers.Count == 0) await Vault.ForgetAsync().ConfigureAwait(false);
            else await Vault.SaveAsync(Saved, HelloOn).ConfigureAwait(false);
        }
        Api = null; State = null; Server = null;
    }

    public async Task SetHelloAsync(bool on) => await Vault.SaveAsync(Saved, on).ConfigureAwait(false);
    public async Task SetAutoLockAsync(int minutes) { Saved.AutoLockMinutes = minutes; await Vault.SaveAsync(Saved, HelloOn).ConfigureAwait(false); }
}
