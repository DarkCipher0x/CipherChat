using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace CipherChat.Addons;

/// <summary>
/// The code the owner's client shows once when it creates an add-on: "ccaddon1." + base64url JSON {o: server origin,
/// u: add-on, k: 256-bit request key, a: the owner's identity fingerprint (added by the owner's own client)}.
/// </summary>
public sealed partial class ConnectorCode
{
    public const string Prefix = "ccaddon1.";

    public Uri Server { get; }
    public string User { get; }
    public byte[] Key { get; }
    public string OwnerFp { get; }

    private ConnectorCode(Uri server, string user, byte[] key, string ownerFp) { Server = server; User = user; Key = key; OwnerFp = ownerFp; }

    [GeneratedRegex("^addon\\.[a-z0-9](?:[a-z0-9-]{0,24}[a-z0-9])?$")]
    private static partial Regex UserRe();

    [GeneratedRegex("^[0-9a-f]{64}$")]
    private static partial Regex FpRe();

    public static ConnectorCode Parse(string text, bool allowHttp = false)
    {
        text = text.Trim();
        if (!text.StartsWith(Prefix, StringComparison.Ordinal) || text.Length > 2048) throw new FormatException("That isn't a CipherChat connector code.");
        JsonObject j;
        try { j = JsonNode.Parse(Encoding.UTF8.GetString(Unb64Url(text[Prefix.Length..]))) as JsonObject ?? throw new FormatException(); }
        catch (Exception e) when (e is FormatException or System.Text.Json.JsonException) { throw new FormatException("That connector code is damaged."); }
        var origin = j["o"]?.GetValue<string>() ?? "";
        var user = j["u"]?.GetValue<string>() ?? "";
        var key = Unb64Url(j["k"]?.GetValue<string>() ?? "");
        var owner = j["a"]?.GetValue<string>() ?? "";
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri) || uri.AbsolutePath != "/" || !string.IsNullOrEmpty(uri.Query)
            || !(uri.Scheme == Uri.UriSchemeHttps || (allowHttp && uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback)))
            throw new FormatException("The connector code's server must be an https:// address.");
        if (!UserRe().IsMatch(user) || key.Length != 32) throw new FormatException("That connector code is damaged.");
        if (!FpRe().IsMatch(owner))
            throw new FormatException("This connector code has no owner fingerprint. Copy it from the owner's CipherChat (/addons), which adds it.");
        return new ConnectorCode(uri, user, key, owner);
    }

    internal static byte[] Unb64Url(string s)
    {
        var t = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(t + new string('=', (4 - t.Length % 4) % 4));
    }

    internal static string B64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
