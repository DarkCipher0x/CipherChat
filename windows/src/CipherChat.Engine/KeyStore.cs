using System.Text;
using System.Text.Json.Nodes;
using CipherChat.Crypto;
using static CipherChat.Crypto.Bytes;

namespace CipherChat.Engine;

/// <summary>Seals the key store file to this PC (the app uses DPAPI for this Windows account; tests pass a stand-in).</summary>
public interface IStoreGuard
{
    byte[] Protect(byte[] plain);
    byte[] Unprotect(byte[] sealed_);
}

/// <summary>
/// This PC's key store (PROTOCOL.md §10): room keys this installation has opened, kept so the server can delete its
/// wrapped copies. Each key is sealed twice, by this installation's device key and by a key derived from the person's
/// master secret, and the whole file is sealed again by <see cref="IStoreGuard"/> (DPAPI), so neither a copy of the
/// file nor the passphrase alone opens anything. Never uploaded or backed up; removing this PC from the device list
/// wipes it. One file per server and person: %LOCALAPPDATA%\CipherChat\keys\&lt;hash&gt;.bin.
/// </summary>
public sealed class KeyStore
{
    private sealed record Row(long At, byte[] Sealed);

    private readonly object _gate = new();
    private readonly string _path;
    private readonly IStoreGuard _guard;
    private readonly byte[] _storeKey;
    private readonly byte[] _deviceKey;
    private readonly byte[] _sealedSeed;
    private readonly Dictionary<(string Room, long Epoch), Row> _keys;
    private readonly Dictionary<string, Row> _prekeys;           // prekey id -> (expiry, sealed 96-byte seed), PROTOCOL.md §11

    public string User { get; }
    public string Dev { get; }
    public string Name { get; }
    public long Added { get; }
    public long ListedSeq { get; private set; }
    public bool IsNew { get; private set; }
    /// <summary>user -> (seq, device ids) of device lists already shown.</summary>
    public Dictionary<string, (long Seq, List<string> Ids)> Seen { get; }
    public Device Device { get; }

    private KeyStore(string path, IStoreGuard guard, string user, byte[] storeKey, byte[] deviceKey, byte[] sealedSeed, Device device,
                     string dev, string name, long added, long listedSeq, bool isNew,
                     Dictionary<string, (long, List<string>)> seen, Dictionary<(string, long), Row> keys, Dictionary<string, Row> prekeys)
    {
        _path = path; _guard = guard; User = user; _storeKey = storeKey; _deviceKey = deviceKey; _sealedSeed = sealedSeed; Device = device;
        Dev = dev; Name = name; Added = added; ListedSeq = listedSeq; IsNew = isNew; Seen = seen; _keys = keys; _prekeys = prekeys;
    }

    public static string DefaultDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CipherChat", "keys");

    public static string PathFor(string dir, string origin, string user) =>
        Path.Combine(dir, Hex(Hybrid.Sha3_256(Utf8("cipherchat-keystore|" + origin + "|" + user)))[..32] + ".bin");

    /// <summary>A short, recognisable name on the device list (no PC name: other people see device names).</summary>
    public static string DefaultName() => "CipherChat for Windows, " + DateTime.Now.ToString("d MMM", System.Globalization.CultureInfo.GetCultureInfo("en-GB"));

    /// <summary>
    /// Opens (or makes) the store for this person on this server. <paramref name="storeKey"/> comes from the unlocked
    /// master (<see cref="Devices.StoreKey"/>). A store sealed under an earlier identity, or damaged, is wiped and made again.
    /// </summary>
    public static KeyStore Open(string path, IStoreGuard guard, string user, byte[] storeKey, string? name = null)
    {
        if (File.Exists(path))
        {
            try { return Load(path, guard, user, storeKey); }
            catch (Exception e) when (e is CryptoFail or System.Security.Cryptography.CryptographicException or FormatException or InvalidDataException
                                      or KeyNotFoundException or InvalidOperationException or System.Text.Json.JsonException)
            {
                Erase(path);
            }
        }
        var deviceKey = Random(32);
        var seed = Devices.NewSeed();
        try
        {
            var s = new KeyStore(path, guard, user, (byte[])storeKey.Clone(), deviceKey, Devices.SealSeed(deviceKey, storeKey, user, seed), Device.FromSeed(seed),
                                 Devices.NewId(), name ?? DefaultName(), DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), 0, true, new(), new(), new());
            s.Save();
            return s;
        }
        finally { Bytes.Wipe(seed); }
    }

    private static KeyStore Load(string path, IStoreGuard guard, string user, byte[] storeKey)
    {
        var plain = guard.Unprotect(File.ReadAllBytes(path));
        JsonObject o;
        try { o = Canon.Parse(new UTF8Encoding(false, true).GetString(plain)) as JsonObject ?? throw new InvalidDataException(); }
        finally { Bytes.Wipe(plain); }
        if (o.LongOrNull("v") != 1 || o.StrOrNull("user") != user) throw new InvalidDataException("not this person's key store");
        var deviceKey = Unb64(o.Str("device_key"), 32);
        var sealedSeed = Unb64(o.Str("seed"));
        var seed = Devices.OpenSeed(deviceKey, storeKey, user, sealedSeed);       // throws under another identity's master
        Device device;
        try { device = Device.FromSeed(seed); } finally { Bytes.Wipe(seed); }
        var seen = new Dictionary<string, (long, List<string>)>();
        if (o["seen"] is JsonObject so)
            foreach (var (u, v) in so)
                if (v is JsonObject e) seen[u] = (e.Long("seq"), e.Arr("ids").Select(x => x!.GetValue<string>()).ToList());
        var keys = new Dictionary<(string, long), Row>();
        foreach (var k in o.Arr("keys").OfType<JsonObject>()) keys[(k.Str("room"), k.Long("epoch"))] = new Row(k.Long("at"), Unb64(k.Str("s")));
        var prekeys = new Dictionary<string, Row>();
        if (o["prekeys"] is JsonArray pa) foreach (var k in pa.OfType<JsonObject>()) prekeys[k.Str("id")] = new Row(k.Long("exp"), Unb64(k.Str("s")));
        return new KeyStore(path, guard, user, (byte[])storeKey.Clone(), deviceKey, sealedSeed, device, o.Str("dev"), o.Str("name"), o.Long("added"),
                            o.LongOrNull("listed_seq") ?? 0, o["is_new"]?.GetValue<bool>() == true, seen, keys, prekeys);
    }

    public DeviceEntry Entry() => Devices.Entry(Dev, Name, Device, Added);
    public string Code() => Devices.Code(Device.KemPqPk, Device.KemEcPk);

    public byte[]? Get(string room, long epoch)
    {
        Row? row;
        lock (_gate) row = _keys.GetValueOrDefault((room, epoch));
        if (row is null) return null;
        try { return Devices.OpenStored(_deviceKey, _storeKey, User, room, epoch, row.Sealed); }
        catch (CryptoFail) { return null; }
    }

    public void Put(string room, long epoch, byte[] key, long at)
    {
        var sealed_ = Devices.SealStored(_deviceKey, _storeKey, User, room, epoch, key);
        lock (_gate) _keys[(room, epoch)] = new Row(at, sealed_);
        Save();
    }

    public void PutMany(IEnumerable<(string Room, long Epoch, byte[] Key, long At)> items)
    {
        lock (_gate) foreach (var x in items) _keys[(x.Room, x.Epoch)] = new Row(x.At, Devices.SealStored(_deviceKey, _storeKey, User, x.Room, x.Epoch, x.Key));
        Save();
    }

    public List<(string Room, long Epoch, long At)> List() { lock (_gate) return _keys.Select(p => (p.Key.Room, p.Key.Epoch, p.Value.At)).ToList(); }

    public bool Has(string room, long epoch) { lock (_gate) return _keys.ContainsKey((room, epoch)); }

    public void Drop(IEnumerable<(string Room, long Epoch)> items)
    {
        var n = 0;
        lock (_gate) foreach (var x in items) if (_keys.Remove(x)) n++;
        if (n > 0) Save();
    }

    // ------------------------------------------------------------------------------------------- prekeys (PROTOCOL.md §11)
    private static string PrekeyRoom(string id) => "prekey:" + id;

    public void PutPrekey(string id, byte[] seed, long exp)
    {
        var sealed_ = Devices.SealStored(_deviceKey, _storeKey, User, PrekeyRoom(id), 0, seed);
        lock (_gate) _prekeys[id] = new Row(exp, sealed_);
        Save();
    }

    /// <summary>The prekey's 96-byte seed (the caller wipes it), or null once it's erased.</summary>
    public byte[]? GetPrekey(string id)
    {
        Row? row;
        lock (_gate) row = _prekeys.GetValueOrDefault(id);
        if (row is null) return null;
        try { return Devices.OpenStored(_deviceKey, _storeKey, User, PrekeyRoom(id), 0, row.Sealed, 96); }
        catch (CryptoFail) { return null; }
    }

    public List<(string Id, long Exp)> ListPrekeys() { lock (_gate) return _prekeys.Select(p => (p.Key, p.Value.At)).ToList(); }

    public void DropPrekeys(IEnumerable<string> ids)
    {
        var n = 0;
        lock (_gate) foreach (var id in ids) if (_prekeys.Remove(id)) n++;
        if (n > 0) Save();
    }

    public void Listed(long seq) { ListedSeq = seq; Save(); }
    public void NotNew() { IsNew = false; Save(); }
    public void SaveSeen() => Save();

    /// <summary>This PC stops being a device for this person: every key it held goes.</summary>
    public void Wipe()
    {
        lock (_gate) { _keys.Clear(); _prekeys.Clear(); }
        Erase(_path);
        Close();
    }

    /// <summary>Forgets the keys in memory (the chat locked); the file stays.</summary>
    public void Close() { Bytes.Wipe(_storeKey, _deviceKey); }

    private static void Erase(string path)
    {
        try
        {
            if (!File.Exists(path)) return;
            var len = new FileInfo(path).Length;
            File.WriteAllBytes(path, new byte[len]);          // overwrite before delete (no plaintext ever, but leave nothing)
            File.Delete(path);
        }
        catch (IOException) { }
    }

    private void Save()
    {
        byte[] plain;
        lock (_gate)
        {
            var keys = new JsonArray();
            foreach (var (k, v) in _keys.OrderBy(p => p.Key.Room, StringComparer.Ordinal).ThenBy(p => p.Key.Epoch))
                keys.Add(new JsonObject { ["room"] = k.Room, ["epoch"] = k.Epoch, ["at"] = v.At, ["s"] = B64(v.Sealed) });
            var prekeys = new JsonArray();
            foreach (var (id, v) in _prekeys.OrderBy(p => p.Key, StringComparer.Ordinal))
                prekeys.Add(new JsonObject { ["id"] = id, ["exp"] = v.At, ["s"] = B64(v.Sealed) });
            var seen = new JsonObject();
            foreach (var (u, (seq, ids)) in Seen) seen[u] = new JsonObject { ["seq"] = seq, ["ids"] = new JsonArray(ids.Select(x => (JsonNode)x).ToArray()) };
            plain = Canon.Bytes(new JsonObject
            {
                ["v"] = 1, ["user"] = User, ["dev"] = Dev, ["name"] = Name, ["added"] = Added, ["listed_seq"] = ListedSeq, ["is_new"] = IsNew,
                ["device_key"] = B64(_deviceKey), ["seed"] = B64(_sealedSeed), ["seen"] = seen, ["keys"] = keys, ["prekeys"] = prekeys,
            });
            try
            {
                var file = _guard.Protect(plain);
                Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
                var tmp = _path + ".tmp";
                File.WriteAllBytes(tmp, file);
                File.Move(tmp, _path, overwrite: true);
            }
            finally { Bytes.Wipe(plain); }
        }
    }
}
