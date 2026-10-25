using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace CipherChat.Crypto;

/// <summary>Any refusal by the protocol: bad signature, wrong key, tampered data, malformed input. Never leaks key material.</summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1710", Justification = "Same name as the Android core's CryptoFail")]
public sealed class CryptoFail : Exception
{
    public CryptoFail(string message) : base(message) { }
}

public static partial class Bytes
{
    public static byte[] Random(int n) => RandomNumberGenerator.GetBytes(n);

    public static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    public static byte[] Concat(params byte[][] parts)
    {
        var out_ = new byte[parts.Sum(p => p.Length)];
        var o = 0;
        foreach (var p in parts) { p.CopyTo(out_, o); o += p.Length; }
        return out_;
    }

    public static string B64(byte[] bytes) => Convert.ToBase64String(bytes);

    [GeneratedRegex("^[A-Za-z0-9+/]*={0,2}$")]
    private static partial Regex B64Re();

    /// <summary>Strict standard base64 with padding, exactly like the web chat's unb64(); <paramref name="size"/> checks the decoded length.</summary>
    public static byte[] Unb64(string s, int? size = null)
    {
        if (s.Length % 4 != 0 || !B64Re().IsMatch(s)) throw new CryptoFail("malformed base64");
        byte[] out_;
        try { out_ = Convert.FromBase64String(s); } catch (FormatException) { throw new CryptoFail("malformed base64"); }
        if (size is not null && out_.Length != size) throw new CryptoFail("wrong length");
        return out_;
    }

    public static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    public static byte[] FromHex(string h) => Convert.FromHexString(h);

    internal static byte[] U32be(int n) => [(byte)(n >>> 24), (byte)(n >>> 16), (byte)(n >>> 8), (byte)n];

    public static void Wipe(params byte[]?[] arrays)
    {
        foreach (var a in arrays) if (a is not null) CryptographicOperations.ZeroMemory(a);
    }

    /// <summary>Constant-time comparison.</summary>
    public static bool Same(byte[] a, byte[] b) => CryptographicOperations.FixedTimeEquals(a, b);

    /// <summary>URL-safe base64 without padding (message ids).</summary>
    internal static string B64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
