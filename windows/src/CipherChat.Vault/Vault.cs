using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Windows.Security.Credentials;

namespace CipherChat.Vault;

/// <summary>A server this PC is paired with. The device token signs this PC in (chat only) without a password.</summary>
public sealed record SavedServer(string Origin, string User, string DeviceId, string DeviceToken, string Name);

/// <summary>
/// %LOCALAPPDATA%\CipherChat\vault.bin: "CCV1" | mode | salt(32) | DPAPI( [AES-256-GCM(hello key, json)] or json ).
///   mode 0: DPAPI (this Windows account on this PC).
///   mode 1: DPAPI + Windows Hello: the inner key is HKDF-SHA256 of a Windows Hello signature over the salt (an RSA key
///           kept by Windows Hello, usable only after a face, fingerprint or PIN check; RSA PKCS#1 v1.5 signatures are
///           deterministic, so the same check gives the same key). Another program running as you can't open it silently.
/// The file is written atomically (temp file + replace) and never holds the chat passphrase or any chat key.
/// </summary>
public sealed class VaultStore(string? path = null)
{
    private const string HelloKeyName = "CipherChat vault";
    private static readonly byte[] Magic = "CCV1"u8.ToArray();
    private static readonly byte[] Entropy = "CipherChat vault v1"u8.ToArray();

    public string Path { get; } = path ?? System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CipherChat", "vault.bin");

    public sealed class Contents
    {
        public List<SavedServer> Servers { get; set; } = [];
        public int AutoLockMinutes { get; set; } = 15;
    }

    public bool Exists => File.Exists(Path);

    /// <summary>True if the file needs Windows Hello to open.</summary>
    public bool UsesHello => Exists && File.ReadAllBytes(Path) is { Length: > 5 } b && b[4] == 1;

    public static async Task<bool> HelloAvailableAsync()
    {
        try { return await KeyCredentialManager.IsSupportedAsync(); }
        catch (COMException) { return false; }
    }

    public async Task<Contents> LoadAsync()
    {
        if (!Exists) return new Contents();
        var data = await File.ReadAllBytesAsync(Path).ConfigureAwait(false);
        if (data.Length < 4 + 1 + 32 || !data.AsSpan(0, 4).SequenceEqual(Magic)) throw new InvalidDataException("The saved settings aren't a CipherChat vault.");
        var mode = data[4];
        var salt = data[5..37];
        byte[] inner;
        try { inner = ProtectedData.Unprotect(data[37..], Entropy, DataProtectionScope.CurrentUser); }
        catch (CryptographicException) { throw new InvalidDataException("The saved settings were made by another Windows account or PC."); }
        try
        {
            var json = mode == 1 ? await OpenWithHelloAsync(inner, salt).ConfigureAwait(false) : inner;
            try { return JsonSerializer.Deserialize<Contents>(json) ?? new Contents(); }
            finally { CryptographicOperations.ZeroMemory(json); }
        }
        finally { CryptographicOperations.ZeroMemory(inner); }
    }

    public async Task SaveAsync(Contents contents, bool useHello)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(contents);
        var salt = RandomNumberGenerator.GetBytes(32);
        try
        {
            var inner = useHello ? await SealWithHelloAsync(json, salt).ConfigureAwait(false) : (byte[])json.Clone();
            var outer = ProtectedData.Protect(inner, Entropy, DataProtectionScope.CurrentUser);
            CryptographicOperations.ZeroMemory(inner);
            var file = new byte[4 + 1 + 32 + outer.Length];
            Magic.CopyTo(file, 0);
            file[4] = (byte)(useHello ? 1 : 0);
            salt.CopyTo(file, 5);
            outer.CopyTo(file, 37);
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
            var tmp = Path + ".tmp";
            await File.WriteAllBytesAsync(tmp, file).ConfigureAwait(false);
            File.Move(tmp, Path, overwrite: true);
        }
        finally { CryptographicOperations.ZeroMemory(json); }
    }

    /// <summary>Forget everything this PC remembered (and the Windows Hello key).</summary>
    public async Task ForgetAsync()
    {
        if (Exists) File.Delete(Path);
        try { await KeyCredentialManager.DeleteAsync(HelloKeyName); } catch (Exception e) when (e is COMException or FileNotFoundException) { }
    }

    // ------------------------------------------------------------------ Windows Hello
    private static async Task<byte[]> HelloKeyAsync(byte[] salt, bool create)
    {
        KeyCredentialRetrievalResult cred;
        if (create)
        {
            cred = await KeyCredentialManager.RequestCreateAsync(HelloKeyName, KeyCredentialCreationOption.ReplaceExisting);
        }
        else
        {
            cred = await KeyCredentialManager.OpenAsync(HelloKeyName);
        }
        if (cred.Status != KeyCredentialStatus.Success) throw new UnauthorizedAccessException(cred.Status == KeyCredentialStatus.UserCanceled
            ? "Windows Hello was cancelled." : "Windows Hello isn't available (" + cred.Status + ").");
        var challenge = Encoding.UTF8.GetBytes("cipherchat-vault-key/v1|").Concat(salt).ToArray().AsBuffer();
        var sig = await cred.Credential.RequestSignAsync(challenge);
        if (sig.Status != KeyCredentialStatus.Success) throw new UnauthorizedAccessException("Windows Hello didn't confirm it's you.");
        var s = sig.Result.ToArray();
        try { return HKDF.DeriveKey(HashAlgorithmName.SHA256, s, 32, salt, "cipherchat-vault-aes/v1"u8.ToArray()); }
        finally { CryptographicOperations.ZeroMemory(s); }
    }

    private static async Task<byte[]> SealWithHelloAsync(byte[] plain, byte[] salt)
    {
        var key = await HelloKeyAsync(salt, create: true).ConfigureAwait(false);
        try
        {
            var nonce = RandomNumberGenerator.GetBytes(12);
            var ct = new byte[plain.Length];
            var tag = new byte[16];
            using (var g = new AesGcm(key, 16)) g.Encrypt(nonce, plain, ct, tag, salt);
            return [.. nonce, .. ct, .. tag];
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private static async Task<byte[]> OpenWithHelloAsync(byte[] sealed_, byte[] salt)
    {
        var key = await HelloKeyAsync(salt, create: false).ConfigureAwait(false);
        try
        {
            var plain = new byte[sealed_.Length - 28];
            using var g = new AesGcm(key, 16);
            g.Decrypt(sealed_.AsSpan(0, 12), sealed_.AsSpan(12, plain.Length), sealed_.AsSpan(sealed_.Length - 16), plain, salt);
            return plain;
        }
        catch (CryptographicException) { throw new UnauthorizedAccessException("Windows Hello gave a different key: the saved settings can't be opened. Pair this PC again."); }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
}
