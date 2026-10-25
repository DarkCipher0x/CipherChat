using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace CipherChat.Crypto;

/// <summary>
/// Canonical JSON, byte-identical to the web chat's canon() (crypto.js) and the Android app's Canon: keys sorted at every
/// level by UTF-16 code units, no spaces, strings escaped exactly like JavaScript's JSON.stringify, and only whole numbers
/// within JavaScript's safe-integer range. Everything signed is canonical bytes sent as base64, so the bytes that were
/// signed are the bytes that get verified.
/// </summary>
public static class Canon
{
    private const long MaxSafe = 9007199254740991L;

    public static string Encode(JsonNode? v)
    {
        var sb = new StringBuilder();
        Write(sb, v);
        return sb.ToString();
    }

    public static byte[] Bytes(JsonNode? v) => Crypto.Bytes.Utf8(Encode(v));

    private static void Write(StringBuilder sb, JsonNode? v)
    {
        switch (v)
        {
            case null: sb.Append("null"); break;
            case JsonObject o:
                sb.Append('{');
                var first = true;
                foreach (var k in o.Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal))   // UTF-16 code units, like JS sort()
                {
                    if (!first) sb.Append(',');
                    first = false;
                    Str(sb, k);
                    sb.Append(':');
                    Write(sb, o[k]);
                }
                sb.Append('}');
                break;
            case JsonArray a:
                sb.Append('[');
                for (var i = 0; i < a.Count; i++) { if (i > 0) sb.Append(','); Write(sb, a[i]); }
                sb.Append(']');
                break;
            case JsonValue val:
                switch (val.GetValueKind())
                {
                    case JsonValueKind.String: Str(sb, val.GetValue<string>()); break;
                    case JsonValueKind.True: sb.Append("true"); break;
                    case JsonValueKind.False: sb.Append("false"); break;
                    case JsonValueKind.Null: sb.Append("null"); break;
                    case JsonValueKind.Number:
                        var text = val.ToJsonString();
                        if (!long.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var n) ||
                            n > MaxSafe || n < -MaxSafe || text != n.ToString(CultureInfo.InvariantCulture))
                            throw new CryptoFail("only whole numbers are signed");
                        sb.Append(n.ToString(CultureInfo.InvariantCulture));
                        break;
                    default: throw new CryptoFail("unsupported JSON value");
                }
                break;
            default: throw new CryptoFail("unsupported JSON value");
        }
    }

    /// <summary>JSON.stringify's string escaping (ES2019 well-formed): \" \\ \b \f \n \r \t, other controls and lone surrogates as \u00xx.</summary>
    private static void Str(StringBuilder sb, string s)
    {
        sb.Append('"');
        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < ' ') sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else if (char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { sb.Append(c).Append(s[i + 1]); i++; }
                    else if (char.IsSurrogate(c)) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>
    /// Strict parse. JsonObject reads its properties lazily, so a duplicate key would otherwise only throw (an
    /// ArgumentException, not a refusal) on first access: the whole tree is walked here, inside the guard.
    /// </summary>
    public static JsonNode? Parse(string text)
    {
        try
        {
            var node = JsonNode.Parse(text, documentOptions: new JsonDocumentOptions { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow });
            Walk(node);
            return node;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException) { throw new CryptoFail("malformed JSON"); }
    }

    private static void Walk(JsonNode? n)
    {
        if (n is JsonObject o) foreach (var p in o) Walk(p.Value);
        else if (n is JsonArray a) foreach (var x in a) Walk(x);
    }

    /// <summary>A signed header: base64 of canonical JSON, version 1. Refuses anything that isn't exactly canonical.</summary>
    public static Signed ParseSigned(string b64, int maxLen)
    {
        var raw = Crypto.Bytes.Unb64(b64);
        if (raw.Length > maxLen) throw new CryptoFail("too large");
        string text;
        try { text = StrictUtf8.GetString(raw); } catch (DecoderFallbackException) { throw new CryptoFail("malformed header"); }
        JsonNode? node;
        try { node = Parse(text); } catch (CryptoFail) { throw new CryptoFail("malformed header"); }
        if (node is not JsonObject obj || obj.LongOrNull("v") != 1) throw new CryptoFail("unsupported version");
        if (Encode(obj) != text) throw new CryptoFail("header is not canonical");
        return new Signed(raw, obj);
    }

    public sealed record Signed(byte[] Raw, JsonObject Obj);
}

/// <summary>Small typed getters for signed headers: a missing or wrong-typed field is a protocol refusal, never a crash.</summary>
public static class JsonGet
{
    public static string Str(this JsonObject o, string k) => o.StrOrNull(k) ?? throw new CryptoFail("missing " + k);

    public static string? StrOrNull(this JsonObject o, string k) =>
        o[k] is JsonValue v && v.GetValueKind() == JsonValueKind.String ? v.GetValue<string>() : null;

    public static long Long(this JsonObject o, string k) => o.LongOrNull(k) ?? throw new CryptoFail("missing " + k);

    public static long? LongOrNull(this JsonObject o, string k) =>
        o[k] is JsonValue v && v.GetValueKind() == JsonValueKind.Number &&
        long.TryParse(v.ToJsonString(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var n) ? n : null;

    public static JsonArray Arr(this JsonObject o, string k) => o[k] as JsonArray ?? throw new CryptoFail("missing " + k);

    public static JsonObject Obj(this JsonObject o, string k) => o[k] as JsonObject ?? throw new CryptoFail("missing " + k);
}
