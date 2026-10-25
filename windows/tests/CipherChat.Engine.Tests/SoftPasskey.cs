using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace CipherChat.Engine.Tests;

/// <summary>
/// A software ES256 passkey for tests: registers like a platform authenticator (attestation "none", user present and
/// verified) and signs assertions exactly as webauthn.dll returns them, so ChatApi's passkey path can be checked
/// against a real server without a person at Windows Hello.
/// </summary>
internal sealed class SoftPasskey : IDisposable
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly byte[] _id = RandomNumberGenerator.GetBytes(32);
    private byte[] _userHandle = [];
    private uint _counter;

    public string Id => B64u(_id);
    /// <summary>Set to make the next assertion reuse the last counter (what a cloned authenticator would do).</summary>
    public bool RepeatCounter { get; set; }

    public static string B64u(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Unb64u(string s)
    {
        var t = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(t.PadRight(t.Length + (4 - t.Length % 4) % 4, '='));
    }

    private static byte[] ClientData(string type, string challenge, string origin) =>
        Encoding.UTF8.GetBytes("{\"type\":\"" + type + "\",\"challenge\":\"" + challenge + "\",\"origin\":\"" + origin + "\",\"crossOrigin\":false}");

    private byte[] AuthData(string rpId, bool attested)
    {
        var ad = new List<byte>(SHA256.HashData(Encoding.UTF8.GetBytes(rpId))) { (byte)(attested ? 0x45 : 0x05) };   // UP | UV (| AT)
        if (!RepeatCounter) _counter++;
        ad.AddRange([(byte)(_counter >> 24), (byte)(_counter >> 16), (byte)(_counter >> 8), (byte)_counter]);
        if (!attested) return [.. ad];
        ad.AddRange(new byte[16]);                                                // AAGUID: none
        ad.AddRange([(byte)(_id.Length >> 8), (byte)_id.Length]);
        ad.AddRange(_id);
        var p = _key.ExportParameters(false);
        // COSE_Key {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}
        ad.AddRange([0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]); ad.AddRange(p.Q.X!);
        ad.AddRange([0x22, 0x58, 0x20]); ad.AddRange(p.Q.Y!);
        return [.. ad];
    }

    private static byte[] CborBytes(byte[] b) =>
        b.Length < 256 ? [0x58, (byte)b.Length, .. b] : [0x59, (byte)(b.Length >> 8), (byte)b.Length, .. b];

    /// <summary>navigator.credentials.create() for the server's creation options.</summary>
    public JsonObject Create(JsonObject publicKey, string origin)
    {
        var rpId = publicKey["rp"]!["id"]!.GetValue<string>();
        _userHandle = Unb64u(publicKey["user"]!["id"]!.GetValue<string>());
        var ad = AuthData(rpId, attested: true);
        // {"fmt": "none", "attStmt": {}, "authData": <bytes>}
        byte[] att = [0xA3, 0x63, .. "fmt"u8, 0x64, .. "none"u8, 0x67, .. "attStmt"u8, 0xA0, 0x68, .. "authData"u8, .. CborBytes(ad)];
        return new JsonObject
        {
            ["id"] = Id, ["rawId"] = Id, ["type"] = "public-key",
            ["response"] = new JsonObject
            {
                ["clientDataJSON"] = B64u(ClientData("webauthn.create", publicKey["challenge"]!.GetValue<string>(), origin)),
                ["attestationObject"] = B64u(att),
            },
        };
    }

    /// <summary>navigator.credentials.get(): the same shape CipherChat.Passkeys returns from webauthn.dll.</summary>
    public Task<JsonObject?> Sign(JsonObject publicKey, string origin)
    {
        var rpId = publicKey["rpId"]!.GetValue<string>();
        var cd = ClientData("webauthn.get", publicKey["challenge"]!.GetValue<string>(), origin);
        var ad = AuthData(rpId, attested: false);
        var sig = _key.SignData([.. ad, .. SHA256.HashData(cd)], HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        return Task.FromResult<JsonObject?>(new JsonObject
        {
            ["id"] = Id, ["rawId"] = Id, ["type"] = "public-key",
            ["response"] = new JsonObject
            {
                ["clientDataJSON"] = B64u(cd), ["authenticatorData"] = B64u(ad), ["signature"] = B64u(sig), ["userHandle"] = B64u(_userHandle),
            },
        });
    }

    public void Dispose() => _key.Dispose();
}
