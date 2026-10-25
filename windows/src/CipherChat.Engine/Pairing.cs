namespace CipherChat.Engine;

/// <summary>
/// Pairing codes: "cipherchat:pair/v1?server=&lt;origin&gt;&amp;token=&lt;one-time device token&gt;" (older web chats wrote
/// "dcxchat:pair/v1?..."; both are accepted). The token is the credential for a chat-only device session, so codes are
/// shown once and never logged.
/// </summary>
public static class Pairing
{
    public static string Format(Uri origin, string token) =>
        "cipherchat:pair/v1?server=" + Uri.EscapeDataString(origin.GetLeftPart(UriPartial.Authority)) + "&token=" + Uri.EscapeDataString(token);

    public sealed record Code(Uri Server, string Token);

    /// <summary>The server and token from a pasted code, or null if it isn't one.</summary>
    public static Code? Parse(string text)
    {
        text = (text ?? "").Trim();
        var q = text.StartsWith("cipherchat:pair/v1?", StringComparison.Ordinal) ? text[19..]
              : text.StartsWith("dcxchat:pair/v1?", StringComparison.Ordinal) ? text[16..] : null;
        if (q is null) return null;
        string? server = null, token = null;
        foreach (var part in q.Split('&'))
        {
            var i = part.IndexOf('=', StringComparison.Ordinal);
            if (i <= 0) continue;
            var v = Uri.UnescapeDataString(part[(i + 1)..]);
            if (part[..i] == "server") server = v; else if (part[..i] == "token") token = v;
        }
        if (server is null || token is null || token.Length is < 30 or > 100 || !token.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_')) return null;
        if (!Uri.TryCreate(server, UriKind.Absolute, out var uri) || !(uri.Scheme == Uri.UriSchemeHttps || (uri.Scheme == Uri.UriSchemeHttp && (uri.IsLoopback || uri.Host == "localhost"))))
            return null;
        if (uri.AbsolutePath != "/" || uri.Query.Length > 0 || uri.UserInfo.Length > 0) return null;
        return new Code(uri, token);
    }
}
