using System.Text.Json.Nodes;
using CipherChat.Api;
using CipherChat.Crypto;
using static CipherChat.Crypto.Bytes;

namespace CipherChat.Engine;

/// <summary>This device's unlocked identity: keys live in memory only, until <see cref="ChatEngine.Lock"/>.</summary>
public sealed class Me
{
    internal Me(Identity id, string fp, string? anchorFp) { Id = id; Fp = fp; AnchorFp = anchorFp; }
    internal Identity Id { get; }
    public string User => Id.User;
    public string Fp { get; }
    public string? AnchorFp { get; internal set; }
}

/// <summary>
/// The steps in front of the chat (gate.js): create an identity, unlock it with the chat passphrase, pin the owner's
/// identity after comparing safety numbers, change the passphrase. The passphrase is only ever a local variable for the
/// moment it's needed; it is never stored or sent.
/// </summary>
public static class Gate
{
    public const int MinPass = 16;

    public static string? PassProblems(string p)
    {
        if (p.Length < MinPass) return "Use at least " + MinPass + " characters (4 or more random words works well).";
        if (p.Distinct().Count() < 8) return "That has too few different characters.";
        return null;
    }

    private static long NowMs() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    /// <summary>First time on any device (or a deliberate reset): make the identity, seal it, publish it.</summary>
    public static async Task<Me> SetupAsync(ChatApi api, JsonObject state, string passphrase, bool reset, AskCode ask, IProgress<string>? progress = null)
    {
        var problem = PassProblems(passphrase);
        if (problem is not null) throw new ArgumentException(problem);
        var me = state.Obj("me");
        var user = me.Str("user");
        var owner = me["owner"]?.GetValue<bool>() == true;
        progress?.Report("Generating ML-KEM-1024, X25519, ML-DSA-87 and Ed25519 keys…");
        var master = Random(32);
        try
        {
            var id = Hybrid.IdentityFromMaster(user, master);
            var pub = Hybrid.PublishIdentity(id, NowMs());
            progress?.Report("Getting the server key share…");
            var pep = await api.CallAsync("pepper").ConfigureAwait(false);
            var anchor = owner ? pub.Fp : null;                   // the owner is the trust anchor; members pin it next
            progress?.Report("Sealing your keys with Argon2id (64 MiB)…");
            var payload = new JsonObject { ["v"] = 1, ["master"] = B64(master), ["anchor_fp"] = anchor, ["created"] = NowMs() };
            var backup = await Task.Run(() => Backup.Seal(user, passphrase, Unb64(pep.Str("pepper"), 32), (int)pep.Long("pepper_ver"), payload)).ConfigureAwait(false);
            progress?.Report("Publishing your public keys…");
            await api.CallAsync("identity", new JsonObject
            {
                ["bundle"] = new JsonObject { ["b"] = pub.B, ["s"] = pub.S }, ["backup"] = backup, ["confirm_reset"] = reset,
            }, ask).ConfigureAwait(false);
            return new Me(id, pub.Fp, anchor);
        }
        finally { Wipe(master); }
    }

    /// <summary>Opens the sealed identity with the chat passphrase and checks the server publishes exactly these keys.</summary>
    public static async Task<Me> UnlockAsync(ChatApi api, JsonObject state, string passphrase, IProgress<string>? progress = null)
    {
        var user = state.Obj("me").Str("user");
        progress?.Report("Fetching your sealed keys…");
        var b = await api.CallAsync("backup/fetch", new JsonObject()).ConfigureAwait(false);
        progress?.Report("Deriving the key (Argon2id, 64 MiB)…");
        JsonObject payload;
        try { payload = await Task.Run(() => Backup.Open(user, passphrase, Unb64(b.Str("pepper"), 32), b.Obj("backup"))).ConfigureAwait(false); }
        catch (CryptoFail e) when (e.Message == "wrong passphrase") { throw new UnauthorizedAccessException("That passphrase isn't right."); }
        var master = Unb64(payload.Str("master"), 32);
        try
        {
            var id = Hybrid.IdentityFromMaster(user, master);
            var bundle = b.Obj("bundle");
            var at = Canon.ParseSigned(bundle.Str("b"), 16384).Obj.Long("at");
            if (Hybrid.PublishIdentity(id, at).Fp != b.Str("fp"))
                throw new CryptoFail("The identity the server shows for you doesn't match your keys. Don't use the chat; tell the owner.");
            return new Me(id, b.Str("fp"), payload.StrOrNull("anchor_fp"));
        }
        finally { Wipe(master); }
    }

    /// <summary>The 60 digits to compare with the owner, or null if the owner has no identity yet.</summary>
    public static string? OwnerSafetyNumber(JsonObject state, Me me)
    {
        var owner = OwnerIdentity(state);
        return owner is null ? null : Hybrid.SafetyNumber(me.Fp, owner.Str("fp"));
    }

    public static JsonObject? OwnerIdentity(JsonObject state)
    {
        var ownerUser = state.Str("owner");
        return state.Arr("directory").OfType<JsonObject>().FirstOrDefault(d => d.StrOrNull("user") == ownerUser)?["identity"] as JsonObject;
    }

    /// <summary>After the person confirmed the safety number matches: pin the owner's fingerprint inside the sealed backup.</summary>
    public static async Task PinOwnerAsync(ChatApi api, JsonObject state, Me me, string passphrase, AskCode ask)
    {
        var owner = OwnerIdentity(state) ?? throw new InvalidOperationException("The owner hasn't set up their chat identity yet.");
        Hybrid.OpenIdentity(owner.Str("b"), owner.Str("s"), state.Str("owner"), owner.Str("fp"));   // must be a valid, self-signed identity
        var user = me.User;
        var b = await api.CallAsync("backup/fetch", new JsonObject()).ConfigureAwait(false);
        var payload = await Task.Run(() => Backup.Open(user, passphrase, Unb64(b.Str("pepper"), 32), b.Obj("backup"))).ConfigureAwait(false);
        payload["anchor_fp"] = owner.Str("fp");
        var pep = await api.CallAsync("pepper").ConfigureAwait(false);
        var backup = await Task.Run(() => Backup.Seal(user, passphrase, Unb64(pep.Str("pepper"), 32), (int)pep.Long("pepper_ver"), payload)).ConfigureAwait(false);
        await api.CallAsync("backup", new JsonObject { ["fp"] = me.Fp, ["backup"] = backup }, ask).ConfigureAwait(false);
        me.AnchorFp = owner.Str("fp");
    }

    public static async Task ChangePassphraseAsync(ChatApi api, Me me, string current, string next, AskCode ask)
    {
        var problem = PassProblems(next);
        if (problem is not null) throw new ArgumentException(problem);
        var b = await api.CallAsync("backup/fetch", new JsonObject()).ConfigureAwait(false);
        JsonObject payload;
        try { payload = await Task.Run(() => Backup.Open(me.User, current, Unb64(b.Str("pepper"), 32), b.Obj("backup"))).ConfigureAwait(false); }
        catch (CryptoFail e) when (e.Message == "wrong passphrase") { throw new UnauthorizedAccessException("The current passphrase isn't right."); }
        var pep = await api.CallAsync("pepper").ConfigureAwait(false);
        var backup = await Task.Run(() => Backup.Seal(me.User, next, Unb64(pep.Str("pepper"), 32), (int)pep.Long("pepper_ver"), payload)).ConfigureAwait(false);
        await api.CallAsync("backup", new JsonObject { ["fp"] = me.Fp, ["backup"] = backup }, ask).ConfigureAwait(false);
    }
}
