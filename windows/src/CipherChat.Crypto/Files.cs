using System.Security.Cryptography;
using System.Text;
using static CipherChat.Crypto.Bytes;

namespace CipherChat.Crypto;

/// <summary>
/// Attachments (files, pictures, videos, GIFs), byte-compatible with the web chat's sealFile/openFile: a fresh random
/// AES-256 key per file (sent inside the signed, encrypted message), the plaintext zero-padded to whole 64 KiB chunks (the
/// server sees only the size in 64 KiB steps), each chunk AES-256-GCM with nonce = chunk index and "index|last" as
/// associated data, so chunks can't be reordered, dropped or swapped between files. The SHA3-256 of the whole ciphertext
/// also goes in the signed message.
/// </summary>
public static class Files
{
    public const int Chunk = 65536;
    public const int SealedChunk = Chunk + 16;
    public const long Max = 1600L * Chunk;                    // 100 MiB, the server's limit

    public sealed record Sealed(string Key, byte[] Data, string Sha3, long Size);

    // 12-byte nonce, chunk index big-endian in bytes 4..7 (the web chat: DataView.setUint32(4, i))
    private static byte[] Nonce(int i) { var n = new byte[12]; n[4] = (byte)(i >>> 24); n[5] = (byte)(i >>> 16); n[6] = (byte)(i >>> 8); n[7] = (byte)i; return n; }
    private static byte[] Aad(int i, bool last) => Utf8("dcx-chat/v1/file|" + i + "|" + (last ? 1 : 0));

    public static Sealed Seal(byte[] bytes)
    {
        if (bytes.LongLength > Max) throw new CryptoFail("file too large");
        var key = Random(32);
        var chunks = Math.Max(1, (int)((bytes.LongLength + Chunk - 1) / Chunk));
        var out_ = new byte[(long)chunks * SealedChunk];
        using var gcm = new AesGcm(key, 16);
        var plain = new byte[Chunk];
        for (var i = 0; i < chunks; i++)
        {
            Array.Clear(plain);
            var start = (long)i * Chunk;
            var n = (int)Math.Min(Chunk, Math.Max(0, bytes.LongLength - start));
            if (n > 0) Array.Copy(bytes, start, plain, 0, n);
            var at = (long)i * SealedChunk;
            gcm.Encrypt(Nonce(i), plain, out_.AsSpan((int)at, Chunk), out_.AsSpan((int)at + Chunk, 16), Aad(i, i == chunks - 1));
        }
        Wipe(plain);
        try { return new Sealed(B64(key), out_, Hex(Hybrid.Sha3_256(out_)), bytes.LongLength); }
        finally { Wipe(key); }
    }

    public static byte[] Open(byte[] sealed_, string keyB64, long size, string sha3Hex)
    {
        if (sealed_.Length == 0 || sealed_.Length % SealedChunk != 0) throw new CryptoFail("not an encrypted attachment");
        if (Hex(Hybrid.Sha3_256(sealed_)) != sha3Hex) throw new CryptoFail("the attachment doesn't match its signed hash");
        var chunks = sealed_.Length / SealedChunk;
        // the padding never adds a whole extra chunk: only the last chunk is partly zeros (a 0-byte file is one chunk)
        if (size < 0 || size > (long)chunks * Chunk || (chunks > 1 && size <= (long)(chunks - 1) * Chunk)) throw new CryptoFail("attachment size doesn't match");
        var key = Unb64(keyB64, 32);
        var out_ = new byte[(long)chunks * Chunk];
        try
        {
            using var gcm = new AesGcm(key, 16);
            for (var i = 0; i < chunks; i++)
            {
                var at = i * SealedChunk;
                try { gcm.Decrypt(Nonce(i), sealed_.AsSpan(at, Chunk), sealed_.AsSpan(at + Chunk, 16), out_.AsSpan(i * Chunk, Chunk), Aad(i, i == chunks - 1)); }
                catch (CryptographicException) { throw new CryptoFail("attachment decryption failed (it was changed)"); }
            }
            return out_[..(int)size];
        }
        finally { Wipe(key); }
    }

    /// <summary>What a picture or video really is, from its first bytes (never from the name or the sender's label).</summary>
    public static string Sniff(byte[] b)
    {
        bool At(int o, params byte[] v) => b.Length >= o + v.Length && v.Select((x, i) => b[o + i] == x).All(t => t);
        if (At(0, 0x89, 0x50, 0x4e, 0x47)) return "image/png";
        if (At(0, 0xff, 0xd8, 0xff)) return "image/jpeg";
        if (At(0, 0x47, 0x49, 0x46, 0x38)) return "image/gif";
        if (At(0, 0x52, 0x49, 0x46, 0x46) && At(8, 0x57, 0x45, 0x42, 0x50)) return "image/webp";
        if (At(4, 0x66, 0x74, 0x79, 0x70) && b.Length >= 12)
        {
            var brand = Encoding.ASCII.GetString(b, 8, 4);
            if (brand is "avif" or "avis") return "image/avif";
            if (brand is "isom" or "iso2" or "mp41" or "mp42" or "avc1" or "M4V " or "dash") return "video/mp4";
            if (brand == "qt  ") return "video/quicktime";
        }
        if (At(0, 0x1a, 0x45, 0xdf, 0xa3)) return "video/webm";
        return "application/octet-stream";
    }
}
