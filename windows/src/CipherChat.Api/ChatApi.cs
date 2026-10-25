using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CipherChat.Transport;

namespace CipherChat.Api;

/// <summary>A refused request: the server's message plus its flags (reauth, denied, stale, rotate...).</summary>
public sealed class ApiException(int status, JsonObject data, string message) : Exception(message)
{
    public int Status { get; } = status;
    /// <summary>The server's JSON answer (error text and flags).</summary>
    public JsonObject Body { get; } = data;
    public bool Flag(string name) => Body[name] is JsonValue v && v.GetValueKind() == JsonValueKind.True;
    public bool Denied => Flag("denied");
    public bool Offline => Status == 0;
}

/// <summary>Asks the person for their current authenticator code (shows <paramref name="error"/> after a wrong one); null = cancelled.</summary>
public delegate Task<string?> AskCode(string? error);

/// <summary>
/// Gets a passkey assertion for the server's WebAuthn request options (<c>publicKey</c>), as the browser's
/// <c>PublicKeyCredential</c> JSON (id, type, response.clientDataJSON / authenticatorData / signature / userHandle,
/// base64url). <paramref name="origin"/> goes into clientDataJSON. Null = cancelled or no passkey.
/// </summary>
public delegate Task<JsonObject?> SignPasskey(JsonObject publicKey, string origin);

/// <summary>
/// The CipherChat server API. One session cookie (whatever the server sets: the standalone server's or a portal's chat
/// cookie), sent only to this server's origin. Every write carries the CSRF headers the server requires. When the
/// session is gone and a resume function is set (a paired device's token), it signs in again once and retries.
/// </summary>
public sealed class ChatApi(ITransport transport, string userAgent)
{
    private static readonly TimeSpan Normal = TimeSpan.FromSeconds(30);
    private readonly object _gate = new();
    private string? _cookie;                              // "name=value"

    public Uri Origin => transport.Origin;
    public AskCode? Ask { get; set; }
    /// <summary>When set, "confirm it's you" tries a passkey first and falls back to the authenticator code.</summary>
    public SignPasskey? Passkey { get; set; }
    /// <summary>Re-establishes a session (e.g. device sign-in); true if it worked.</summary>
    public Func<Task<bool>>? Resume { get; set; }
    public bool HasSession { get { lock (_gate) return _cookie is not null; } }
    /// <summary>
    /// Set for an add-on (CipherChat.Addons): every request is signed (method, target, body) instead of carrying a session
    /// cookie, Origin and the CSRF header. Returns the X-CipherChat-* headers.
    /// </summary>
    public Func<string, string, byte[], IReadOnlyDictionary<string, string>>? Sign { get; set; }

    // ---------------------------------------------------------------- plumbing
    private Dictionary<string, string> Headers(string? contentType, string method, string path, byte[]? body)
    {
        if (Sign is { } sign)
        {
            var s = new Dictionary<string, string>(sign(method, path, body ?? []))
            {
                ["User-Agent"] = userAgent, ["Accept"] = "application/json", ["Cache-Control"] = "no-store",
            };
            if (contentType is not null) s["Content-Type"] = contentType;
            return s;
        }
        var h = new Dictionary<string, string>
        {
            ["X-Requested-With"] = "dcx-portal",
            ["Origin"] = Origin.GetLeftPart(UriPartial.Authority),
            ["User-Agent"] = userAgent,
            ["Accept"] = "application/json",
            ["Cache-Control"] = "no-store",
        };
        if (contentType is not null) h["Content-Type"] = contentType;
        lock (_gate) if (_cookie is not null) h["Cookie"] = _cookie;
        return h;
    }

    private void TakeCookies(HttpResult r)
    {
        foreach (var sc in r.All("Set-Cookie"))
        {
            var first = sc.Split(';')[0].Trim();
            var eq = first.IndexOf('=', StringComparison.Ordinal);
            if (eq <= 0) continue;
            var expired = sc.Contains("Max-Age=0", StringComparison.OrdinalIgnoreCase) || eq == first.Length - 1;
            lock (_gate) _cookie = expired ? null : first;
        }
    }

    private async Task<(int Status, JsonObject Data, HttpResult Raw)> RawAsync(string method, string path, byte[]? body, string? contentType, TimeSpan timeout,
                                                                                Action<long, long>? progress, CancellationToken ct)
    {
        HttpResult r;
        try
        {
            r = await transport.SendAsync(new HttpRequest(method, path, Headers(contentType, method, path, body), body) { Timeout = timeout, Progress = progress }, ct).ConfigureAwait(false);
        }
        catch (PqTlsException e) { throw new ApiException(0, new JsonObject(), e.Message); }
        catch (Exception e) when (e is IOException or System.Net.Sockets.SocketException or TimeoutException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            throw new ApiException(0, new JsonObject(), "Couldn't reach the server. Check your connection and try again.");
        }
        TakeCookies(r);
        JsonObject data = [];
        var type = r.Header("Content-Type") ?? "";
        if (type.StartsWith("application/json", StringComparison.OrdinalIgnoreCase) && r.Body.Length > 0)
        {
            try { data = JsonNode.Parse(r.Body) as JsonObject ?? []; } catch (JsonException) { data = []; }
        }
        return (r.Status, data, r);
    }

    private static ApiException Fail(int status, JsonObject data) =>
        new(status, data, data["error"] is JsonValue v && v.GetValueKind() == JsonValueKind.String ? v.GetValue<string>() : "The server refused that (HTTP " + status + ").");

    /// <summary>GET (body null) or POST to /chat/api/&lt;path&gt;, with the reauth and resume retries.</summary>
    public async Task<JsonObject> CallAsync(string path, JsonObject? body = null, AskCode? ask = null, TimeSpan? timeout = null, CancellationToken ct = default)
    {
        var bytes = body is null ? null : Encoding.UTF8.GetBytes(body.ToJsonString());
        var full = "/chat/api/" + path;
        for (var attempt = 0; ; attempt++)
        {
            var (status, data, _) = await RawAsync(body is null ? "GET" : "POST", full, bytes, body is null ? null : "application/json", timeout ?? Normal, null, ct).ConfigureAwait(false);
            if (status is >= 200 and < 300) return data;
            if (status == 401 && Flag(data, "reauth") && attempt < 2)
            {
                if (attempt == 0 && Passkey is not null && await PasskeyReauthAsync(Passkey, ct).ConfigureAwait(false)) continue;
                await ReauthAsync(ask ?? Ask ?? throw Fail(status, data), ct).ConfigureAwait(false);
                continue;
            }
            if (status == 403 && !Flag(data, "denied") && attempt == 0 && Resume is not null && await Resume().ConfigureAwait(false)) continue;
            throw Fail(status, data);
        }
    }

    private static bool Flag(JsonObject d, string k) => d[k] is JsonValue v && v.GetValueKind() == JsonValueKind.True;

    // ---------------------------------------------------------------- sign-in
    public async Task<JsonObject> StatusAsync(CancellationToken ct = default) =>
        (await RawAsync("GET", "/chat/api/auth/status", null, null, Normal, null, ct).ConfigureAwait(false)).Data;

    public async Task<string> LoginAsync(string username, string password, string code, CancellationToken ct = default)
    {
        var body = Encoding.UTF8.GetBytes(new JsonObject { ["username"] = username, ["password"] = password, ["code"] = code }.ToJsonString());
        var (status, data, _) = await RawAsync("POST", "/chat/api/auth/login", body, "application/json", Normal, null, ct).ConfigureAwait(false);
        if (status != 200) throw Fail(status, data);
        return data["user"]?.GetValue<string>() ?? username;
    }

    /// <summary>A paired device's token for a chat-only session. Returns (user, device id).</summary>
    public async Task<(string User, string Device)> DeviceSignInAsync(string token, CancellationToken ct = default)
    {
        var body = Encoding.UTF8.GetBytes(new JsonObject { ["token"] = token }.ToJsonString());
        var (status, data, _) = await RawAsync("POST", "/chat/api/auth/device", body, "application/json", Normal, null, ct).ConfigureAwait(false);
        if (status != 200) throw Fail(status, data);
        return (data["user"]!.GetValue<string>(), data["device"]!.GetValue<string>());
    }

    public async Task LogoutAsync(CancellationToken ct = default)
    {
        try { await RawAsync("POST", "/chat/api/auth/logout", "{}"u8.ToArray(), "application/json", Normal, null, ct).ConfigureAwait(false); }
        finally { lock (_gate) _cookie = null; }
    }

    /// <summary>A fresh authenticator code for the next few minutes of sensitive actions.</summary>
    public async Task ReauthAsync(AskCode ask, CancellationToken ct = default)
    {
        string? err = null;
        for (var i = 0; i < 5; i++)
        {
            var code = await ask(err).ConfigureAwait(false) ?? throw new OperationCanceledException("Cancelled: nothing was changed.");
            var body = Encoding.UTF8.GetBytes(new JsonObject { ["code"] = code }.ToJsonString());
            var (status, data, _) = await RawAsync("POST", "/chat/api/auth/reauth", body, "application/json", Normal, null, ct).ConfigureAwait(false);
            if (status == 200) return;
            err = data["error"]?.GetValue<string>() ?? "That code isn't valid.";
        }
        throw new ApiException(401, new JsonObject(), "Too many wrong codes. Wait a moment and try again.");
    }

    // ---------------------------------------------------------------- passkeys (passkeys.py on the server)
    private string OriginText => Origin.GetLeftPart(UriPartial.Authority);

    private async Task<(int Status, JsonObject Data)> PasskeyCeremonyAsync(string purpose, SignPasskey sign, CancellationToken ct)
    {
        var begin = Encoding.UTF8.GetBytes(new JsonObject { ["purpose"] = purpose }.ToJsonString());
        var (status, opts, _) = await RawAsync("POST", "/chat/api/auth/passkey/begin", begin, "application/json", Normal, null, ct).ConfigureAwait(false);
        if (status != 200) throw Fail(status, opts);
        var cred = await sign(opts["publicKey"]!.AsObject(), OriginText).ConfigureAwait(false) ?? throw new OperationCanceledException("Cancelled.");
        var finish = Encoding.UTF8.GetBytes(new JsonObject { ["purpose"] = purpose, ["flow"] = opts["flow"]!.DeepClone(), ["credential"] = cred }.ToJsonString());
        var (s2, data, _) = await RawAsync("POST", "/chat/api/auth/passkey/finish", finish, "application/json", Normal, null, ct).ConfigureAwait(false);
        return (s2, data);
    }

    /// <summary>Signs in with a passkey (Windows Hello, a phone, or a password manager such as Bitwarden). Returns the user.</summary>
    public async Task<string> PasskeyLoginAsync(SignPasskey sign, CancellationToken ct = default)
    {
        var (status, data) = await PasskeyCeremonyAsync("login", sign, ct).ConfigureAwait(false);
        if (status != 200) throw Fail(status, data);
        return data["user"]!.GetValue<string>();
    }

    /// <summary>"Confirm it's you" with a passkey. False when there's none to use (not added, cancelled, not offered by this server).</summary>
    public async Task<bool> PasskeyReauthAsync(SignPasskey sign, CancellationToken ct = default)
    {
        try { return (await PasskeyCeremonyAsync("reauth", sign, ct).ConfigureAwait(false)).Status == 200; }
        catch (ApiException e) when (!e.Offline) { return false; }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return false; }
    }

    // ---------------------------------------------------------------- attachments and polling
    /// <summary>Uploads sealed ciphertext; returns {id, size, sha3} as the server computed them.</summary>
    public async Task<JsonObject> UploadAsync(string roomId, byte[] sealed_, Action<long, long>? progress, CancellationToken ct = default)
    {
        var timeout = TimeSpan.FromSeconds(30 + Math.Ceiling(sealed_.Length / 262144.0));
        for (var attempt = 0; ; attempt++)
        {
            var (status, data, _) = await RawAsync("POST", "/chat/api/upload/" + roomId, sealed_, "application/octet-stream", timeout, progress, ct).ConfigureAwait(false);
            if (status == 200) return data;
            if (status == 403 && !Flag(data, "denied") && attempt == 0 && Resume is not null && await Resume().ConfigureAwait(false)) continue;
            throw Fail(status, data);
        }
    }

    public async Task<byte[]> DownloadAsync(string roomId, string blobId, long size, CancellationToken ct = default)
    {
        var timeout = TimeSpan.FromSeconds(30 + Math.Ceiling(size / 262144.0));
        var (status, data, raw) = await RawAsync("GET", "/chat/api/blob/" + roomId + "/" + blobId, null, null, timeout, null, ct).ConfigureAwait(false);
        if (status == 200) return raw.Body;
        throw status == 404 ? new ApiException(404, data, "That attachment isn't on the server any more.") : Fail(status, data);
    }

    /// <summary>
    /// The server holds a poll for up to 25 s; 45 s without an answer means the connection is dead. sig = the last call
    /// signal seen (calls.py): newer signals come back in "signals".
    /// </summary>
    public Task<JsonObject> PollAsync(long since, long rev, long sig, CancellationToken ct = default) =>
        CallAsync("poll?since=" + since + "&rev=" + rev + "&sig=" + sig, null, null, TimeSpan.FromSeconds(45), ct);
}
