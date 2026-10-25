using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace CipherChat.Crypto;

/// <summary>
/// Message payload kinds (inside the encrypted, signed message), checked exactly like the web chat's checkPayload():
///   text {text, re?}   me {text}   file {text (caption), files: [...], re?}
///   react {text: "", target: &lt;msg id&gt;, emoji, on}   edit {text, target}
///   text/me/file may carry burn: seconds visible once opened (10-300)
/// Unknown kinds or malformed fields are refused, so no client ever shows half a message.
/// </summary>
public static partial class Payload
{
    [GeneratedRegex("^[A-Za-z0-9_-]{22}$")] private static partial Regex IdRe();
    [GeneratedRegex("^[0-9a-f]{24}$")] private static partial Regex BlobRe();
    [GeneratedRegex("^[0-9a-f]{64}$")] private static partial Regex Sha3Re();
    [GeneratedRegex("^[A-Za-z0-9+/]{43}=$")] private static partial Regex KeyRe();

    private static CryptoFail Bad() => new("malformed message");

    private static bool IsId(JsonNode? n) => n is JsonValue v && v.GetValueKind() == JsonValueKind.String && IdRe().IsMatch(v.GetValue<string>());
    private static long? Int(JsonNode? n) =>
        n is JsonValue v && v.GetValueKind() == JsonValueKind.Number && long.TryParse(v.ToJsonString(), out var x) && Math.Abs(x) <= 9007199254740991L ? x : null;
    private static string? Str(JsonNode? n) => n is JsonValue v && v.GetValueKind() == JsonValueKind.String ? v.GetValue<string>() : null;

    public static JsonObject Check(JsonObject p)
    {
        var kind = Str(p["k"]) ?? (p.ContainsKey("k") ? throw Bad() : "text");
        if (p.ContainsKey("re") && !IsId(p["re"])) throw Bad();
        if (p.ContainsKey("burn"))
        {
            var b = Int(p["burn"]);
            if (b is null or < 10 or > 300 || kind is not ("text" or "me" or "file")) throw Bad();
        }
        switch (kind)
        {
            case "text": case "me": return p;
            case "react":
                var emoji = Str(p["emoji"]);
                if (!IsId(p["target"]) || emoji is null || emoji.Length is < 1 or > 16 || p["on"] is not JsonValue on ||
                    (on.GetValueKind() != JsonValueKind.True && on.GetValueKind() != JsonValueKind.False)) throw Bad();
                return p;
            case "edit":
                if (!IsId(p["target"])) throw Bad();
                return p;
            case "file":
                if (p["files"] is not JsonArray files || files.Count is 0 or > 10) throw Bad();
                foreach (var f in files) CheckFile(f as JsonObject ?? throw Bad());
                return p;
            default: throw Bad();
        }
    }

    private static bool Ref(JsonObject? r) =>
        r is not null && Str(r["blob"]) is { } blob && BlobRe().IsMatch(blob) && Str(r["sha3"]) is { } h && Sha3Re().IsMatch(h) &&
        Str(r["key"]) is { } k && KeyRe().IsMatch(k) && Int(r["size"]) is { } s && s >= 0 && s <= Files.Max;

    private static void CheckFile(JsonObject f)
    {
        if (!Ref(f) || Str(f["name"]) is not { Length: <= 200 } || Str(f["mime"]) is not { Length: <= 100 } ||
            Str(f["kind"]) is not ("image" or "video" or "audio" or "file")) throw Bad();
        if (f.ContainsKey("thumb") && !Ref(f["thumb"] as JsonObject)) throw Bad();
        foreach (var k in new[] { "w", "h", "dur" })
            if (f.ContainsKey(k) && Int(f[k]) is not (>= 0 and < 10_000_000)) throw Bad();
    }
}
