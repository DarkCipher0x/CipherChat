using System.Text.Json.Nodes;
using CipherChat.Crypto;

namespace CipherChat.Engine;

public enum TrustLevel { Ok, Pending, None, Bad }

/// <summary>One person as this device sees them. <see cref="Pub"/> is set only when <see cref="Trust"/> is Ok.</summary>
public sealed record Person(string User, string DisplayName, bool Owner, string? Fp, PublicIdentity? Pub, TrustLevel Trust, string Why);

/// <summary>
/// Who to trust (trust.js). The only root of trust is the owner's identity fingerprint that YOU compared (safety number)
/// and pinned in your sealed backup. Everyone else is trusted only through a certificate signed by that identity. The
/// server's word counts for nothing here: it can hand out any keys it likes and this refuses them.
/// </summary>
public sealed class Trust
{
    private readonly Dictionary<string, PublicIdentity> _opened = new();
    private readonly Dictionary<string, bool> _certs = new();

    public sealed record Result(IReadOnlyDictionary<string, Person> People, PublicIdentity? OwnerPub, string OwnerProblem);

    public Result Evaluate(JsonArray directory, string ownerUser, string? anchorFp)
    {
        var people = new Dictionary<string, Person>();
        var entries = directory.OfType<JsonObject>().ToList();
        var ownerEntry = entries.FirstOrDefault(d => d.StrOrNull("user") == ownerUser);
        PublicIdentity? ownerPub = null;
        var ownerProblem = "";
        if (anchorFp is null) ownerProblem = "you haven't verified the owner's identity yet";
        else if (ownerEntry?["identity"] is not JsonObject oid) ownerProblem = "the owner has no chat identity on the server";
        else if (oid.StrOrNull("fp") != anchorFp) ownerProblem = "THE OWNER'S KEY ON THE SERVER IS NOT THE ONE YOU VERIFIED";
        else
        {
            try { ownerPub = Open(ownerUser, oid); }
            catch (CryptoFail e) { ownerProblem = "the owner's identity doesn't verify: " + e.Message; }
        }
        foreach (var d in entries)
        {
            var user = d.StrOrNull("user");
            if (user is null) continue;
            var name = d.StrOrNull("display_name") ?? "";
            var owner = d["owner"] is JsonValue ov && ov.GetValueKind() == System.Text.Json.JsonValueKind.True;
            var ident = d["identity"] as JsonObject;
            var fp = ident?.StrOrNull("fp");
            Person P(TrustLevel t, string why, PublicIdentity? pub = null) => new(user, name, owner, fp, pub, t, why);
            if (ident is null) { people[user] = P(TrustLevel.None, "hasn't set up the chat yet"); continue; }
            if (user == ownerUser)
            {
                people[user] = ownerPub is not null ? P(TrustLevel.Ok, "the owner (you verified this key)", ownerPub) : P(TrustLevel.Bad, ownerProblem);
                continue;
            }
            if (ownerPub is null) { people[user] = P(TrustLevel.Bad, "can't check: " + ownerProblem); continue; }
            PublicIdentity pub;
            try { pub = Open(user, ident); }
            catch (CryptoFail e) { people[user] = P(TrustLevel.Bad, "identity doesn't verify: " + e.Message); continue; }
            if (d["cert"] is not JsonObject cert) { people[user] = P(TrustLevel.Pending, "waiting for the owner to verify and certify"); continue; }
            var s = cert.StrOrNull("s") ?? "";
            var key = user + "|" + fp + "|" + s[..Math.Min(64, s.Length)] + "|" + ownerPub.Fp;
            if (!_certs.TryGetValue(key, out var ok))
            {
                ok = Hybrid.VerifyCert(new Signed64(cert.StrOrNull("b") ?? "", s), ownerPub, user, fp!);
                _certs[key] = ok;
            }
            people[user] = ok ? P(TrustLevel.Ok, "certified by the owner", pub) : P(TrustLevel.Bad, "the certificate doesn't verify");
        }
        return new Result(people, ownerPub, ownerProblem);
    }

    private PublicIdentity Open(string user, JsonObject ident)
    {
        var k = user + "|" + ident.StrOrNull("fp");
        if (!_opened.TryGetValue(k, out var pub))
        {
            pub = Hybrid.OpenIdentity(ident.Str("b"), ident.Str("s"), user);
            if (pub.Fp != ident.StrOrNull("fp")) throw new CryptoFail("fingerprint mismatch");
            _opened[k] = pub;
        }
        return pub;
    }
}
