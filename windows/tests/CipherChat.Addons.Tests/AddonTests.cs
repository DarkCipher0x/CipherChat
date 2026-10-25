using System.Text;
using System.Text.Json.Nodes;
using CipherChat.Addons;
using CipherChat.Crypto;

namespace CipherChat.Addons.Tests;

/// <summary>The add-on SDK, offline: request signing and add-on codes.</summary>
public class AddonTests
{
    [Fact]
    public void Hmac_sha3_matches_python_and_the_signature_covers_everything()
    {
        // Python: hmac.new(bytes(range(32)), b"CipherChat add-on HMAC test vector", hashlib.sha3_256).hexdigest()
        var key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        Assert.Equal("610326970f8db6cd8246ca818387158d3efe71d4dc3890624da726a7bb62372c",
                     Bytes.Hex(RequestSigner.HmacSha3(key, Encoding.UTF8.GetBytes("CipherChat add-on HMAC test vector"))));
        var json = "{\"o\":\"https://chat.example\",\"u\":\"addon.cc\",\"k\":\"" + ConnectorCode.B64Url(key) + "\",\"a\":\"" + new string('a', 64) + "\"}";
        var code = ConnectorCode.Parse(ConnectorCode.Prefix + ConnectorCode.B64Url(Encoding.UTF8.GetBytes(json)));
        var s = new RequestSigner(code);
        var h1 = s.Sign("GET", "/chat/api/state", []);
        var h2 = s.Sign("GET", "/chat/api/state", []);
        Assert.NotEqual(h1["X-CipherChat-Nonce"], h2["X-CipherChat-Nonce"]);
        Assert.NotEqual(h1["X-CipherChat-Signature"], h2["X-CipherChat-Signature"]);
        Assert.Equal(Bytes.Hex(Hybrid.Sha3_256([])), h1["X-CipherChat-Content-SHA3"]);
        var canon = string.Join('\n', "CIPHERCHAT-ADDON-V1", "https://chat.example", "GET", "/chat/api/state", "addon.cc",
                                h1["X-CipherChat-Time"], h1["X-CipherChat-Nonce"], h1["X-CipherChat-Content-SHA3"]);
        Assert.Equal(Bytes.Hex(RequestSigner.HmacSha3(key, Encoding.UTF8.GetBytes(canon))), h1["X-CipherChat-Signature"]);
    }

    [Fact]
    public void Add_on_codes_are_checked()
    {
        string Make(string o, string u, int keyLen, string? a) =>
            ConnectorCode.Prefix + ConnectorCode.B64Url(Encoding.UTF8.GetBytes(new JsonObject
            { ["o"] = o, ["u"] = u, ["k"] = ConnectorCode.B64Url(new byte[keyLen]), ["a"] = a }.ToJsonString()));
        var fp = new string('b', 64);
        Assert.Equal("addon.cc", ConnectorCode.Parse(Make("https://chat.example", "addon.cc", 32, fp)).User);
        Assert.Throws<FormatException>(() => ConnectorCode.Parse(Make("http://chat.example", "addon.cc", 32, fp)));      // https only
        Assert.Throws<FormatException>(() => ConnectorCode.Parse(Make("http://127.0.0.1:1", "addon.cc", 32, fp)));       // unless dev
        Assert.Equal("addon.cc", ConnectorCode.Parse(Make("http://127.0.0.1:1", "addon.cc", 32, fp), allowHttp: true).User);
        Assert.Throws<FormatException>(() => ConnectorCode.Parse(Make("https://chat.example", "kim", 32, fp)));           // add-ons only
        Assert.Throws<FormatException>(() => ConnectorCode.Parse(Make("https://chat.example", "addon.cc", 16, fp)));      // 256-bit keys
        Assert.Throws<FormatException>(() => ConnectorCode.Parse(Make("https://chat.example", "addon.cc", 32, null)));    // owner pinned
        Assert.Throws<FormatException>(() => ConnectorCode.Parse(Make("https://chat.example/x", "addon.cc", 32, fp)));
        Assert.Throws<FormatException>(() => ConnectorCode.Parse("cipherchat:pair/v1?server=x"));
    }
}
