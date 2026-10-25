using System.Security.Cryptography;
using System.Text;
using CipherChat.Crypto;

namespace CipherChat.Addons;

/// <summary>
/// Signs each request for server/cipherchat/addons.py: HMAC-SHA3-256 (keyed with the add-on's 256-bit key) over
/// "CIPHERCHAT-ADDON-V1", the server origin, method, target (path + query), add-on, time, a fresh 192-bit nonce and the
/// SHA3-256 of the body. Symmetric 256-bit keys and SHA-3 keep their strength against quantum computers.
/// </summary>
public sealed class RequestSigner(ConnectorCode code)
{
    private const int Sha3_256Block = 136;
    private readonly byte[] _key = (byte[])code.Key.Clone();
    private readonly string _origin = code.Server.GetLeftPart(UriPartial.Authority);

    /// <summary>Server clock minus ours, learned from a refusal that carried server_time.</summary>
    public long ClockOffset { get; set; }

    public IReadOnlyDictionary<string, string> Sign(string method, string target, byte[] body)
    {
        var ts = (DateTimeOffset.UtcNow.ToUnixTimeSeconds() + ClockOffset).ToString(System.Globalization.CultureInfo.InvariantCulture);
        var nonce = ConnectorCode.B64Url(RandomNumberGenerator.GetBytes(24));
        var bodyHash = Bytes.Hex(Hybrid.Sha3_256(body));
        var msg = Encoding.UTF8.GetBytes(string.Join('\n', "CIPHERCHAT-ADDON-V1", _origin, method, target, code.User, ts, nonce, bodyHash));
        return new Dictionary<string, string>
        {
            ["X-CipherChat-Addon"] = code.User, ["X-CipherChat-Time"] = ts, ["X-CipherChat-Nonce"] = nonce,
            ["X-CipherChat-Content-SHA3"] = bodyHash, ["X-CipherChat-Signature"] = Bytes.Hex(HmacSha3(_key, msg)),
        };
    }

    /// <summary>HMAC (RFC 2104) over SHA3-256 (block 136 bytes), on the SHA-3 the rest of CipherChat uses.</summary>
    public static byte[] HmacSha3(byte[] key, byte[] msg)
    {
        var k = key.Length > Sha3_256Block ? Hybrid.Sha3_256(key) : key;
        var ipad = new byte[Sha3_256Block];
        var opad = new byte[Sha3_256Block];
        for (var i = 0; i < Sha3_256Block; i++)
        {
            var b = i < k.Length ? k[i] : (byte)0;
            ipad[i] = (byte)(b ^ 0x36);
            opad[i] = (byte)(b ^ 0x5c);
        }
        try { return Hybrid.Sha3_256(opad, Hybrid.Sha3_256(ipad, msg)); }
        finally { CryptographicOperations.ZeroMemory(ipad); CryptographicOperations.ZeroMemory(opad); }
    }

    public void Wipe() => CryptographicOperations.ZeroMemory(_key);
}
