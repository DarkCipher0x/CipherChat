using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace CipherChat.Addons;

/// <summary>
/// An add-on's secrets on its own machine: the connector code (its request key) and the master secret its chat keys come
/// from, sealed together with DPAPI for the Windows account that runs it, in
/// %LOCALAPPDATA%\DarkCipher Systems\CipherChat Connector\&lt;name&gt;.key. Another account, or a copy of the file on
/// another PC, can't open it. Nothing is ever written in the clear.
/// </summary>
public static class KeyStore
{
    public static string Folder => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                                                "DarkCipher Systems", "CipherChat Connector");

    public static string PathFor(string name)
    {
        if (name.Length is 0 or > 40 || name.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_')))
            throw new ArgumentException("Connector names are 1-40 of a-z, 0-9, - and _.");
        return Path.Combine(Folder, name + ".key");
    }

    private static byte[] Entropy(string name) => Encoding.UTF8.GetBytes("CipherChat connector key store v1|" + name);

    public static bool Exists(string name) => File.Exists(PathFor(name));

    public static void Save(string name, string code, byte[] master)
    {
        var json = Encoding.UTF8.GetBytes(new JsonObject { ["v"] = 1, ["code"] = code, ["master"] = Convert.ToBase64String(master) }.ToJsonString());
        try
        {
            var sealed_ = ProtectedData.Protect(json, Entropy(name), DataProtectionScope.CurrentUser);
            Directory.CreateDirectory(Folder);
            var path = PathFor(name);
            var tmp = path + ".tmp";
            File.WriteAllBytes(tmp, sealed_);
            File.Move(tmp, path, overwrite: true);
        }
        finally { CryptographicOperations.ZeroMemory(json); }
    }

    /// <summary>(connector code, master secret). The caller wipes the master when done.</summary>
    public static (string Code, byte[] Master) Load(string name)
    {
        var path = PathFor(name);
        if (!File.Exists(path)) throw new FileNotFoundException("This connector isn't set up yet (run setup first).");
        byte[] json;
        try { json = ProtectedData.Unprotect(File.ReadAllBytes(path), Entropy(name), DataProtectionScope.CurrentUser); }
        catch (CryptographicException) { throw new UnauthorizedAccessException("The connector's key file can't be opened by this Windows account."); }
        try
        {
            var j = JsonNode.Parse(json) as JsonObject ?? throw new InvalidDataException("The connector's key file is damaged.");
            return (j["code"]!.GetValue<string>(), Convert.FromBase64String(j["master"]!.GetValue<string>()));
        }
        finally { CryptographicOperations.ZeroMemory(json); }
    }

    public static void Delete(string name)
    {
        var path = PathFor(name);
        if (File.Exists(path)) File.Delete(path);
    }
}
