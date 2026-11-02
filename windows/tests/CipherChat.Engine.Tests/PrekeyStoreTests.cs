using CipherChat.Crypto;
using CipherChat.Engine;

namespace CipherChat.Engine.Tests;

/// <summary>Prekey seeds in the key store (PROTOCOL.md §11): sealed like room keys, kept apart from them, gone once dropped.</summary>
public class PrekeyStoreTests
{
    private sealed class PlainGuard : IStoreGuard
    {
        public byte[] Protect(byte[] plain) => (byte[])plain.Clone();
        public byte[] Unprotect(byte[] sealed_) => (byte[])sealed_.Clone();
    }

    [Fact]
    public void PrekeysAreSealedKeptApartAndErased()
    {
        var dir = Path.Combine(Path.GetTempPath(), "cc-prekey-" + Bytes.Hex(Bytes.Random(6)));
        var path = Path.Combine(dir, "store.bin");
        var sk = Devices.StoreKey(Bytes.Random(32), "alice");
        try
        {
            var s = KeyStore.Open(path, new PlainGuard(), "alice", sk, "Test PC");
            var seed = Devices.NewSeed();
            s.PutPrekey("00000000000000aa", seed, 5000);
            s.Put("0123456789abcdef", 1, Bytes.Random(32), 1);
            Assert.Single(s.List());                                    // room keys only
            Assert.DoesNotContain(Bytes.B64(seed), File.ReadAllText(path)); // sealed, never plain
            s.Close();

            var again = KeyStore.Open(path, new PlainGuard(), "alice", sk);
            Assert.Equal([("00000000000000aa", 5000L)], again.ListPrekeys());
            Assert.Equal(seed, again.GetPrekey("00000000000000aa"));
            Assert.Null(again.GetPrekey("00000000000000bb"));
            again.DropPrekeys(["00000000000000aa"]);
            Assert.Empty(again.ListPrekeys());
            again.Close();
            Assert.Empty(KeyStore.Open(path, new PlainGuard(), "alice", sk).ListPrekeys());
        }
        finally { try { Directory.Delete(dir, true); } catch (IOException) { } }
    }
}
