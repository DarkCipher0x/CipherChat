using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using CipherChat.Api;
using CipherChat.Crypto;
using CipherChat.Engine;
using CipherChat.Transport;

namespace CipherChat.Engine.Tests;

/// <summary>
/// The Windows engine against a REAL CipherChat server (dev mode on loopback or an SSH tunnel to one). Skipped unless
/// CIPHERCHAT_DEV_ORIGIN, CIPHERCHAT_DEV_OWNER, CIPHERCHAT_DEV_OWNER_PASSWORD, CIPHERCHAT_DEV_OWNER_TOTP and
/// CIPHERCHAT_DEV_OWNER_PASSPHRASE are set (a throwaway demo owner whose identity already exists).
///
/// The owner invites a fresh person, that person enrols, signs in, creates an identity and pins the owner; the owner
/// certifies them; then they exchange text, an encrypted file, a reaction, an edit and a burn message, each side
/// decrypting and verifying what the other sent.
/// </summary>
public class LiveServerTests
{
    private static string? Env(string k) => Environment.GetEnvironmentVariable(k);

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5350", Justification = "RFC 6238 TOTP is defined over HMAC-SHA1")]
    private static string Totp(string secret, int offset = 0)
    {
        var key = Base32(secret);
        var step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30 + offset;
        var msg = BitConverter.GetBytes(step); if (BitConverter.IsLittleEndian) Array.Reverse(msg);
        var h = HMACSHA1.HashData(key, msg);
        var o = h[^1] & 15;
        var n = ((h[o] & 0x7f) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1_000_000;
        return n.ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }

    private static byte[] Base32(string s)
    {
        const string A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bits = 0; var val = 0; var out_ = new List<byte>();
        foreach (var c in s.TrimEnd('=')) { val = val << 5 | A.IndexOf(c); bits += 5; if (bits >= 8) { out_.Add((byte)(val >> (bits - 8))); bits -= 8; } }
        return out_.ToArray();
    }

    // The server allows 6 sign-in attempts a minute per connection, and every test request comes through one; wait it out
    private static async Task<T> Paced<T>(Func<Task<T>> call)
    {
        try { return await call(); }
        catch (ApiException e) when (e.Status == 429) { await Task.Delay(TimeSpan.FromSeconds(61)); return await call(); }
    }

    private static Task<bool> Paced(Func<Task> call) => Paced(async () => { await call(); return true; });

    private static async Task Until(Func<bool> cond, string what, int seconds = 30)
    {
        for (var i = 0; i < seconds * 10; i++) { if (cond()) return; await Task.Delay(100); }
        Assert.Fail("timed out waiting for " + what);
    }

    [Fact]
    public async Task TwoPeopleChatThroughTheRealServer()
    {
        var origin = Env("CIPHERCHAT_DEV_ORIGIN");
        if (string.IsNullOrEmpty(origin)) return;
        var ownerUser = Env("CIPHERCHAT_DEV_OWNER")!;
        var uri = new Uri(origin);
        ITransport T() => uri.Scheme == "https" ? new PqTlsTransport(uri) : new LoopbackDevTransport(uri);

        // ---- the owner signs in and unlocks
        var ownerApi = new ChatApi(T(), "CipherChat/0.1 (Windows; tests)");
        await Paced(() => ownerApi.LoginAsync(ownerUser, Env("CIPHERCHAT_DEV_OWNER_PASSWORD")!, Totp(Env("CIPHERCHAT_DEV_OWNER_TOTP")!)));
        var st = await ownerApi.CallAsync("state");
        var ownerMe = await Gate.UnlockAsync(ownerApi, st, Env("CIPHERCHAT_DEV_OWNER_PASSPHRASE")!);
        Assert.NotNull(ownerMe.AnchorFp);

        // ---- a new person: invited, enrolled, signed in, identity created
        var user = "win" + Convert.ToHexString(RandomNumberGenerator.GetBytes(3)).ToLowerInvariant();
        var inv = await ownerApi.CallAsync("admin/users/invite", new JsonObject { ["username"] = user, ["role"] = "member" });
        var token = inv.Obj("link").Str("url").Split("#enrol=")[1];
        var flaky = new FlakyTransport(T());
        var userApi = new ChatApi(flaky, "CipherChat/0.1 (Windows; tests)");
        const string pw = "windows engine test password 1";
        var start = await Paced(() => userApi.CallAsync("auth/enrol/start", new JsonObject { ["token"] = token, ["password"] = pw }));
        var secret = start.Str("secret");
        await Paced(() => userApi.CallAsync("auth/enrol/finish", new JsonObject { ["token"] = token, ["code"] = Totp(secret, -1) }));
        await Paced(() => userApi.LoginAsync(user, pw, Totp(secret)));
        var ust = await userApi.CallAsync("state");
        const string pass = "windows engine test chat passphrase";
        var userMe = await Gate.SetupAsync(userApi, ust, pass, reset: false, ask: _ => Task.FromResult<string?>(null));
        Assert.Null(userMe.AnchorFp);

        // ---- the same safety number on both sides, then the user pins and the owner certifies
        var owner = new ChatEngine(ownerApi, ownerMe);
        await owner.RefreshAsync();
        var them = owner.People[user];
        Assert.Equal(TrustLevel.Pending, them.Trust);
        ust = await userApi.CallAsync("state");
        Assert.Equal(owner.SafetyNumber(them), Gate.OwnerSafetyNumber(ust, userMe));
        await Gate.PinOwnerAsync(userApi, ust, userMe, pass, _ => Task.FromResult<string?>(null));
        await owner.CertifyAsync(them);
        Assert.Equal(TrustLevel.Ok, owner.People[user].Trust);

        var alice = new ChatEngine(userApi, userMe);
        await owner.StartAsync();
        await alice.StartAsync();
        Assert.Equal(TrustLevel.Ok, alice.People[ownerUser].Trust);

        // ---- a room, text, a file, a reaction, an edit
        var room = await owner.CreateRoomAsync("win-" + user, "engine test", 1, [user]);
        await owner.OpenRoomAsync(room);
        await owner.SendTextAsync(room, "hello from the Windows engine ✓");
        var pic = new byte[] { 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a }.Concat(RandomNumberGenerator.GetBytes(90000)).ToArray();
        await owner.SendFilesAsync(room, "a picture", [new ChatEngine.OutgoingFile("test.png", pic)]);
        await alice.RefreshAsync();
        var aroom = alice.RoomById(room.Id)!;
        await alice.OpenRoomAsync(aroom);
        await Until(() => aroom.Timeline.Count(e => e.Message is not null) >= 2, "both messages at alice");
        var msgs = aroom.Timeline.Where(e => e.Message is not null).Select(e => e.Message!).ToList();
        Assert.Equal("hello from the Windows engine ✓", msgs[0].Text);
        Assert.Equal("image", msgs[1].Files[0].Kind);
        Assert.Equal(pic, await alice.FetchFileAsync(aroom, msgs[1].Files[0]));

        var changed = 0;
        owner.EntryChanged += (_, _) => Interlocked.Increment(ref changed);
        await alice.ReactAsync(aroom, msgs[0], "👍", true);
        await Until(() => owner.RoomById(room.Id)!.Timeline.FirstOrDefault(e => e.Message?.Text.StartsWith("hello", StringComparison.Ordinal) == true)?.Message?.Reactions.Count > 0, "the reaction at the owner");
        var ownerMsg = owner.RoomById(room.Id)!.Timeline.First(e => e.Message?.Text.StartsWith("hello", StringComparison.Ordinal) == true).Message!;
        Assert.Contains(user, ownerMsg.Reactions[0].Users);
        await owner.EditAsync(room, ownerMsg, "hello, edited");
        await Until(() => msgs[0].Text == "hello, edited", "the edit at alice");

        // ---- a burn message: hidden until revealed, destroyed on the server once read
        await owner.SendTextAsync(room, "this burns", burn: 10);
        await Until(() => aroom.Timeline.Any(e => e.Message?.Burn == 10), "the burn message at alice");
        var burn = aroom.Timeline.First(e => e.Message?.Burn == 10).Message!;
        await alice.RevealBurnAsync(aroom, burn);
        alice.BurnOut(aroom, burn);
        await Until(() => owner.RoomById(room.Id)!.Timeline.All(e => e.Message?.Burn != 10), "the burn message to be destroyed for the owner");

        // ---- bad network: alice's link drops; her messages wait, then arrive once each and in order
        flaky.Down = true;
        await alice.SendTextAsync(aroom, "queued while offline 1");
        await alice.SendTextAsync(aroom, "queued while offline 2");
        await Task.Delay(2500);
        Assert.Equal(2, alice.Outgoing.Count(o => o.State == Outgoing.States.Queued));
        lock (aroom.Timeline) Assert.Equal(2, aroom.Timeline.Count(e => e.Outgoing is not null));
        flaky.Down = false;
        alice.NetworkChanged();
        List<string> OwnerTexts() { var r = owner.RoomById(room.Id)!; lock (r.Timeline) return r.Timeline.Where(e => e.Message is not null).Select(e => e.Message!.Text).ToList(); }
        await Until(() => OwnerTexts().Contains("queued while offline 1") && OwnerTexts().Contains("queued while offline 2"), "both queued messages at the owner", 60);
        Assert.True(OwnerTexts().IndexOf("queued while offline 1") < OwnerTexts().IndexOf("queued while offline 2"));
        await Until(() => { lock (aroom.Timeline) return aroom.Timeline.All(e => e.Outgoing is null); }, "the placeholders to go");
        // the server stores a message but its answer never arrives: the resend is recognised, not duplicated
        flaky.LoseNextSendAnswer = true;
        await alice.SendTextAsync(aroom, "answer lost once");
        await Until(() => OwnerTexts().Contains("answer lost once"), "the lost-answer message at the owner", 60);
        await Until(() => alice.Outgoing.Count == 0, "alice's outbox to empty", 60);
        await Task.Delay(1500);
        Assert.Equal(1, OwnerTexts().Count(t => t == "answer lost once"));
        Assert.Equal(1, flaky.LostAnswers);

        owner.Lock();
        alice.Lock();
        await ownerApi.CallAsync("admin/users/" + user + "/delete", new JsonObject());   // tidy up the demo server
    }

    /// <summary>
    /// Passkeys through ChatApi (the path the Windows app takes with webauthn.dll, here with a software authenticator):
    /// register, sign in with nothing but the passkey, confirm-it's-you with it; and the server refuses an assertion
    /// made for another origin and one whose counter didn't move (a cloned authenticator).
    /// </summary>
    [Fact]
    public async Task PasskeySignInThroughTheRealServer()
    {
        var origin = Env("CIPHERCHAT_DEV_ORIGIN");
        if (string.IsNullOrEmpty(origin)) return;
        var uri = new Uri(origin);
        ITransport T() => uri.Scheme == "https" ? new PqTlsTransport(uri) : new LoopbackDevTransport(uri);

        var ownerApi = new ChatApi(T(), "CipherChat/0.1 (Windows; tests)");
        await Paced(() => ownerApi.LoginAsync(Env("CIPHERCHAT_DEV_OWNER")!, Env("CIPHERCHAT_DEV_OWNER_PASSWORD")!, Totp(Env("CIPHERCHAT_DEV_OWNER_TOTP")!)));
        var user = "pk" + Convert.ToHexString(RandomNumberGenerator.GetBytes(3)).ToLowerInvariant();
        var inv = await ownerApi.CallAsync("admin/users/invite", new JsonObject { ["username"] = user, ["role"] = "member" });
        var token = inv.Obj("link").Str("url").Split("#enrol=")[1];
        var api = new ChatApi(T(), "CipherChat/0.1 (Windows; tests)");
        const string pw = "windows passkey test password 1";
        var secret = (await Paced(() => api.CallAsync("auth/enrol/start", new JsonObject { ["token"] = token, ["password"] = pw }))).Str("secret");
        await Paced(() => api.CallAsync("auth/enrol/finish", new JsonObject { ["token"] = token, ["code"] = Totp(secret, -1) }));
        await Paced(() => api.LoginAsync(user, pw, Totp(secret)));
        try
        {
            // ---- register (a fresh sign-in counts as "confirmed it's you")
            using var pk = new SoftPasskey();
            var begin = await api.CallAsync("passkeys/register/begin", new JsonObject(), _ => Task.FromResult<string?>(Totp(secret)));
            var done = await api.CallAsync("passkeys/register/finish", new JsonObject
            {
                ["flow"] = begin["flow"]!.DeepClone(), ["name"] = "test passkey", ["credential"] = pk.Create(begin.Obj("publicKey"), uri.GetLeftPart(UriPartial.Authority)),
            });
            Assert.Equal(pk.Id, done.Str("id"));

            // ---- sign in with only the passkey, on a client that has never seen a password
            var fresh = new ChatApi(T(), "CipherChat/0.1 (Windows; tests)");
            Assert.Equal(user, await Paced(() => fresh.PasskeyLoginAsync(pk.Sign)));
            Assert.Equal(user, (await fresh.CallAsync("state")).Obj("me").Str("user"));
            Assert.True(await Paced(() => fresh.PasskeyReauthAsync(pk.Sign)));

            // ---- refused: a counter that didn't move since the last use (a clone), and an assertion for another origin (phishing)
            pk.RepeatCounter = true;
            var cloned = new ChatApi(T(), "CipherChat/0.1 (Windows; tests)");
            var e = await Assert.ThrowsAsync<ApiException>(() => Paced(() => cloned.PasskeyLoginAsync(pk.Sign)));
            Assert.Contains("cloned", e.Message, StringComparison.Ordinal);
            pk.RepeatCounter = false;
            var phished = new ChatApi(T(), "CipherChat/0.1 (Windows; tests)");
            var p = await Assert.ThrowsAsync<ApiException>(() => Paced(() => phished.PasskeyLoginAsync((o, _) => pk.Sign(o, "https://cipherchat.example.net"))));
            Assert.Equal(401, p.Status);
            Assert.False(phished.HasSession);
        }
        finally
        {
            await ownerApi.CallAsync("admin/users/" + user + "/delete", new JsonObject());   // tidy up the demo server
        }
    }
}

/// <summary>A network that can go away (every request fails) or lose the answer to the next message send after the server got it.</summary>
internal sealed class FlakyTransport(ITransport inner) : ITransport
{
    public volatile bool Down;
    public volatile bool LoseNextSendAnswer;
    public int LostAnswers;
    public Uri Origin => inner.Origin;

    public async Task<HttpResult> SendAsync(HttpRequest request, CancellationToken ct)
    {
        if (Down) throw new IOException("network down");
        var res = await inner.SendAsync(request, ct).ConfigureAwait(false);
        if (LoseNextSendAnswer && request.PathAndQuery.EndsWith("/send", StringComparison.Ordinal))
        {
            LoseNextSendAnswer = false;
            Interlocked.Increment(ref LostAnswers);
            throw new IOException("connection dropped before the answer");
        }
        return res;
    }
}
