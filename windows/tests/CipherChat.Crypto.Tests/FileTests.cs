using System.Text.Json.Nodes;
using CipherChat.Crypto;
using static CipherChat.Crypto.Bytes;

namespace CipherChat.Crypto.Tests;

/// <summary>Attachments: round trips, every tamper case, and byte compatibility with the browser (both directions).</summary>
public class FileTests
{
    private static byte[] Pattern(int n) { var b = new byte[n]; for (var i = 0; i < n; i++) b[i] = (byte)((i * 7 + 3) % 256); return b; }

    private static void Refuses(Action a) => Assert.Throws<CryptoFail>(a);

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(65536)] [InlineData(65537)] [InlineData(200000)]
    public void RoundTripsAndPadsToWholeChunks(int n)
    {
        var s = Files.Seal(Pattern(n));
        Assert.Equal(0, s.Data.Length % Files.SealedChunk);
        Assert.Equal(Math.Max(1, (n + Files.Chunk - 1) / Files.Chunk) * Files.SealedChunk, s.Data.Length);
        Assert.Equal(Pattern(n), Files.Open(s.Data, s.Key, s.Size, s.Sha3));
    }

    [Fact]
    public void RefusesTampering()
    {
        var s = Files.Seal(Pattern(150000));
        var flipped = (byte[])s.Data.Clone(); flipped[70000] ^= 1;
        Refuses(() => Files.Open(flipped, s.Key, s.Size, Hex(Hybrid.Sha3_256(flipped))));        // GCM catches it even with a matching hash
        Refuses(() => Files.Open(flipped, s.Key, s.Size, s.Sha3));                                 // and the signed hash catches it first
        var cut = s.Data[..Files.SealedChunk];
        Refuses(() => Files.Open(cut, s.Key, 1000, Hex(Hybrid.Sha3_256(cut))));                   // a dropped last chunk: "last" flag wrong
        var swapped = s.Data[Files.SealedChunk..(2 * Files.SealedChunk)].Concat(s.Data[..Files.SealedChunk]).Concat(s.Data[(2 * Files.SealedChunk)..]).ToArray();
        Refuses(() => Files.Open(swapped, s.Key, s.Size, Hex(Hybrid.Sha3_256(swapped))));         // reordered chunks
        Refuses(() => Files.Open(s.Data, B64(Random(32)), s.Size, s.Sha3));                         // wrong key
        Refuses(() => Files.Open(s.Data, s.Key, 1, s.Sha3));                                        // a size that implies an extra chunk
    }

    [Fact]
    public void SniffsRealContentNotNames()
    {
        Assert.Equal("image/png", Files.Sniff([0x89, 0x50, 0x4e, 0x47, 0, 0]));
        Assert.Equal("image/gif", Files.Sniff("GIF89a"u8.ToArray()));
        Assert.Equal("video/mp4", Files.Sniff([0, 0, 0, 0x18, 0x66, 0x74, 0x79, 0x70, (byte)'i', (byte)'s', (byte)'o', (byte)'m']));
        Assert.Equal("application/octet-stream", Files.Sniff("<svg"u8.ToArray()));
        Assert.Equal("application/octet-stream", Files.Sniff([]));
    }

    [Fact]
    public void WindowsOpensWhatTheBrowserSealed()
    {
        var f = (JsonObject)Canon.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "interop", "browser-files.json")))!;
        var files = f.Arr("files");
        Assert.Equal(5, files.Count);
        foreach (var n in files)
        {
            var x = (JsonObject)n!;
            var plain = Files.Open(Unb64(x.Str("sealed")), x.Str("key"), x.Long("size"), x.Str("sha3"));
            Assert.Equal(x.Str("plain_sha3"), Hex(Hybrid.Sha3_256(plain)));
            Assert.Equal(Pattern((int)x.Long("size")), plain);
        }
    }

    [Fact]
    public void WindowsSealsFilesForTheBrowser()
    {
        var arr = new JsonArray();
        foreach (var n in new[] { 0, 1, 65536, 65537, 200000 })
        {
            var s = Files.Seal(Pattern(n));
            arr.Add(new JsonObject { ["size"] = s.Size, ["key"] = s.Key, ["sha3"] = s.Sha3, ["sealed"] = B64(s.Data), ["plain_sha3"] = Hex(Hybrid.Sha3_256(Pattern(n))) });
        }
        var dir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "interop"));
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "windows-files.json"), new JsonObject { ["made_by"] = "CipherChat for Windows", ["pattern"] = "(i*7+3)%256", ["files"] = arr }.ToJsonString());
    }

    [Fact]
    public void PayloadsAreCheckedLikeTheBrowser()
    {
        JsonObject P(string json) => (JsonObject)Canon.Parse(json)!;
        Payload.Check(P("{\"k\":\"text\",\"text\":\"hi\"}"));
        Payload.Check(P("{\"text\":\"hi\",\"burn\":30}"));
        Payload.Check(P("{\"k\":\"react\",\"text\":\"\",\"target\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"emoji\":\"\\ud83d\\udc4d\",\"on\":true}"));
        Assert.Throws<CryptoFail>(() => Payload.Check(P("{\"k\":\"react\",\"text\":\"\",\"target\":\"short\",\"emoji\":\"x\",\"on\":true}")));
        Assert.Throws<CryptoFail>(() => Payload.Check(P("{\"k\":\"text\",\"text\":\"x\",\"burn\":5}")));
        Assert.Throws<CryptoFail>(() => Payload.Check(P("{\"k\":\"edit\",\"text\":\"x\",\"target\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"burn\":30}")));
        Assert.Throws<CryptoFail>(() => Payload.Check(P("{\"k\":\"bogus\",\"text\":\"x\"}")));
        Assert.Throws<CryptoFail>(() => Payload.Check(P("{\"k\":\"file\",\"text\":\"\",\"files\":[]}")));
    }
}
