using System.Text.Json;
using System.Text.Json.Nodes;
using CipherChat.Crypto;

namespace CipherChat.Engine;

/// <summary>An encrypted attachment reference, exactly as it travels inside a signed message.</summary>
public sealed record FileRef(string Blob, string Key, string Sha3, long Size, string Name, string Mime, string Kind, FileRef? Thumb, int? W, int? H, int? Dur)
{
    public static FileRef From(JsonObject f) => new(f.Str("blob"), f.Str("key"), f.Str("sha3"), f.Long("size"),
        f.StrOrNull("name") ?? "attachment", f.StrOrNull("mime") ?? "application/octet-stream", f.StrOrNull("kind") ?? "file",
        f["thumb"] is JsonObject t ? From(t) : null, (int?)f.LongOrNull("w"), (int?)f.LongOrNull("h"), (int?)f.LongOrNull("dur"));

    public JsonObject ToJson()
    {
        var o = new JsonObject { ["blob"] = Blob, ["key"] = Key, ["sha3"] = Sha3, ["size"] = Size };
        if (Name.Length > 0) { o["name"] = Name; o["mime"] = Mime; o["kind"] = Kind; }
        if (Thumb is not null) o["thumb"] = Thumb.ToJson();
        if (W is not null) o["w"] = W;
        if (H is not null) o["h"] = H;
        if (Dur is not null) o["dur"] = Dur;
        return o;
    }

    /// <summary>A name safe to show and to save under (no path separators or control characters).</summary>
    public string SafeName
    {
        get
        {
            var s = new string(Name.Select(c => c < 32 || c == 127 || "/\\:*?\"<>|".Contains(c) ? '_' : c).ToArray());
            return s.Length == 0 ? "attachment" : s[..Math.Min(120, s.Length)];
        }
    }
}

/// <summary>A verified message as every device shows it (reactions and edits applied, newest by server order wins).</summary>
public sealed class ChatMessage
{
    public required string Id { get; init; }
    public required long Seq { get; init; }
    public required string From { get; init; }
    public required long At { get; init; }                 // server time, seconds
    public required bool Mine { get; init; }
    public required string Kind { get; init; }             // text | me | file
    public string Text { get; set; } = "";
    public string? ReplyTo { get; init; }
    public IReadOnlyList<FileRef> Files { get; init; } = [];
    public int Burn { get; init; }                         // seconds visible once opened; 0 = not a burn message
    public long EditedSeq { get; set; }
    public bool Revealed { get; set; }
    public bool Burned { get; set; }
    internal readonly Dictionary<string, (long Seq, bool On, string From, string Emoji)> Ops = new();

    /// <summary>emoji -> who reacted with it (only current "on" reactions).</summary>
    public IReadOnlyList<(string Emoji, IReadOnlyList<string> Users)> Reactions =>
        Ops.Values.Where(o => o.On).GroupBy(o => o.Emoji).Select(g => (g.Key, (IReadOnlyList<string>)g.Select(o => o.From).ToList())).ToList();

    public bool MyReaction(string me, string emoji) => Ops.TryGetValue(me + "|" + emoji, out var o) && o.On;
}

public enum LineKind { Sys, Ok, Warn, Err, Server }

/// <summary>One row of a room's log: a message, or a line (key changes, server notices, warnings).</summary>
public sealed class Entry
{
    public long Seq { get; init; }                         // 0 for local lines (shown after everything with a seq)
    public long At { get; init; }
    public ChatMessage? Message { get; init; }
    public LineKind Kind { get; init; }
    public string Who { get; init; } = "--";
    public string Text { get; init; } = "";
    /// <summary>A message of yours still on its way to the server (shown until the real one arrives).</summary>
    public Outgoing? Outgoing { get; init; }
}

/// <summary>Everything this device knows about one room or direct message.</summary>
public sealed class Room
{
    internal Room(string id, JsonObject info) { Id = id; Info = info; }

    public string Id { get; }
    public JsonObject Info { get; internal set; }
    public string Kind => Info.StrOrNull("kind") ?? "room";
    public string Name => Info.StrOrNull("name") ?? "";
    public string Topic => Info.StrOrNull("topic") ?? "";
    public long Epoch => Info.LongOrNull("epoch") ?? 0;
    public long EpochAt => Info.LongOrNull("epoch_at") ?? 0;
    public bool NeedsRotation => Info["needs_rotation"] is JsonValue v && v.GetValueKind() == JsonValueKind.True;
    public string MyRole => Info.StrOrNull("my_role") ?? "member";
    public IReadOnlyList<string> Eligible => Info["eligible"] is JsonArray a ? a.Select(x => x!.GetValue<string>()).ToList() : [];
    public IReadOnlyList<string> EpochRecipients => Info["epoch_recipients"] is JsonArray a ? a.Select(x => x!.GetValue<string>()).ToList() : [];
    public IReadOnlyList<(string User, string Role)> Members =>
        Info["members"] is JsonArray a ? a.OfType<JsonObject>().Select(m => (m.Str("user"), m.StrOrNull("role") ?? "member")).ToList() : [];
    public long RetentionDays => Info.LongOrNull("retention_days") ?? 0;

    public int Unread { get; internal set; }
    public bool Loaded { get; internal set; }
    public bool MoreHistory { get; internal set; }
    public List<Entry> Timeline { get; } = [];

    internal readonly Dictionary<long, byte[]> Keys = new();
    internal readonly Dictionary<long, string> Hashes = new();
    internal readonly Dictionary<long, JsonObject> Headers = new();
    internal readonly HashSet<long> Untrusted = new();
    internal readonly HashSet<long> Seqs = new();
    internal readonly HashSet<string> MsgIds = new();
    internal readonly HashSet<long> EpochTried = new();
    internal readonly Dictionary<string, ChatMessage> Msgs = new();
    internal readonly Dictionary<string, List<(string Kind, string From, long Seq, JsonObject Payload)>> Pending = new();
    internal long Oldest = long.MaxValue;
    internal readonly SemaphoreSlim Lock = new(1, 1);
    internal Task? Loading;
    internal readonly List<JsonObject> Queue = [];

    /// <summary>"#name" for rooms, "@other" for direct messages.</summary>
    public string Label(string me) => Kind == "dm" ? "@" + (Members.Select(m => m.User).FirstOrDefault(u => u != me) ?? "(left)") : "#" + Name;

    internal void Wipe()
    {
        foreach (var k in Keys.Values) Bytes.Wipe(k);
        Keys.Clear();
    }
}
