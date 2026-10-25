using System.Text.Json.Nodes;
using CipherChat.Api;
using CipherChat.Crypto;
using static CipherChat.Crypto.Bytes;

namespace CipherChat.Engine;

/// <summary>
/// An add-on's identity (docs/ADDONS.md): the same hybrid post-quantum keys as a person's, made from a 32-byte master
/// secret that the add-on keeps on its own machine (CipherChat.Addons seals it with DPAPI); the server gets only the
/// public half, once. The owner's fingerprint comes from the connector code the owner's own client showed, so the
/// add-on pins the trust anchor without trusting the server for it.
/// </summary>
public static class AddonIdentity
{
    public const string Prefix = "addon.";

    public static bool IsAddon(string user) => user.StartsWith(Prefix, StringComparison.Ordinal);

    /// <summary>A new master secret (the caller seals it, then wipes it).</summary>
    public static byte[] NewMaster() => Random(32);

    /// <summary>
    /// Opens the add-on's identity: publishes it the first time, otherwise checks the server shows exactly these keys,
    /// and checks the owner the server names is the one the connector code pinned.
    /// </summary>
    public static async Task<Me> OpenAsync(ChatApi api, JsonObject state, byte[] master, string ownerFp, CancellationToken ct = default)
    {
        var user = state.Obj("me").Str("user");
        if (!IsAddon(user)) throw new InvalidOperationException("This isn't an add-on account.");
        var owner = Gate.OwnerIdentity(state) ?? throw new InvalidOperationException("The owner hasn't set up their chat identity yet.");
        if (!string.Equals(owner.Str("fp"), ownerFp, StringComparison.Ordinal))
            throw new CryptoFail("The server's owner identity isn't the one in the connector code. Don't use this server; tell the owner.");
        Hybrid.OpenIdentity(owner.Str("b"), owner.Str("s"), state.Str("owner"), ownerFp);
        var id = Hybrid.IdentityFromMaster(user, master);
        var mine = state.Arr("directory").OfType<JsonObject>().FirstOrDefault(d => d.StrOrNull("user") == user)?["identity"] as JsonObject;
        if (mine is null)
        {
            var pub = Hybrid.PublishIdentity(id, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            await api.CallAsync("identity", new JsonObject { ["bundle"] = new JsonObject { ["b"] = pub.B, ["s"] = pub.S } }, ct: ct).ConfigureAwait(false);
            return new Me(id, pub.Fp, ownerFp);
        }
        var at = Canon.ParseSigned(mine.Str("b"), 16384).Obj.Long("at");
        if (Hybrid.PublishIdentity(id, at).Fp != mine.Str("fp"))
            throw new CryptoFail("The identity the server shows for this add-on doesn't match its keys. Stop it and tell the owner.");
        return new Me(id, mine.Str("fp"), ownerFp);
    }
}
