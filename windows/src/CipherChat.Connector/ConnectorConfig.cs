using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace CipherChat.Connector;

/// <summary>One chat command: "!cc node pc-01" → MCP tool node_details {node: "pc-01"}.</summary>
public sealed record CommandSpec(string Name, string Tool, IReadOnlyList<ArgSpec> Args, JsonObject Fixed, bool Action, string Help);

/// <summary>
/// An argument filled from the chat words: "node" (one word), "node?" (optional), "limit:int" / "limit:int?",
/// "targets..." (the remaining words, a list, at least one), "message*" (the remaining words as one text).
/// </summary>
public sealed record ArgSpec(string Name, bool Optional, bool Int, bool List, bool Rest);

/// <summary>
/// A connector's configuration (connectors/*.json). Read once at start; refused as a whole if anything is off, so a
/// typo never widens what the chat can do.
/// </summary>
public sealed partial class ConnectorConfig
{
    /// <summary>Arguments that are never filled from a chat message, whatever a configuration says.</summary>
    public static readonly HashSet<string> NeverFromChat = new(StringComparer.OrdinalIgnoreCase) { "content", "path", "script", "command", "code" };

    public required string Name { get; init; }
    public required string Prefix { get; init; }
    public required string McpCommand { get; init; }
    public required IReadOnlyList<string> McpArgs { get; init; }
    public TimeSpan McpTimeout { get; init; } = TimeSpan.FromSeconds(200);
    public IReadOnlyList<string> Rooms { get; init; } = [];
    public IReadOnlyList<string> Readers { get; init; } = ["*"];
    public IReadOnlyList<string> Operators { get; init; } = [];
    public int RatePerMinute { get; init; } = 10;
    public int MaxReplyChars { get; init; } = 3500;
    public required IReadOnlyDictionary<string, CommandSpec> Commands { get; init; }

    [GeneratedRegex("^[a-z][a-z0-9-]{0,23}$")]
    private static partial Regex WordRe();

    [GeneratedRegex("^[a-z_][a-z0-9_]{0,40}(:int)?(\\?|\\.\\.\\.|\\*)?$")]
    private static partial Regex ArgRe();

    public static ConnectorConfig Load(string path)
    {
        var j = JsonNode.Parse(File.ReadAllText(path), documentOptions: new System.Text.Json.JsonDocumentOptions { CommentHandling = System.Text.Json.JsonCommentHandling.Skip, AllowTrailingCommas = true })
                as JsonObject ?? throw new InvalidDataException("The configuration isn't a JSON object.");
        string S(string k) => j[k]?.GetValue<string>() ?? throw new InvalidDataException("Missing \"" + k + "\".");
        List<string> L(JsonNode? n) => (n as JsonArray ?? []).Select(x => x?.GetValue<string>() ?? "").ToList();
        var name = S("name");
        if (!WordRe().IsMatch(name)) throw new InvalidDataException("\"name\": 1-24 of a-z, 0-9 and -.");
        var prefix = S("prefix");
        if (prefix.Length is < 2 or > 12 || prefix.Any(char.IsWhiteSpace)) throw new InvalidDataException("\"prefix\": 2-12 characters, no spaces (like !cc).");
        var mcp = j["mcp"] as JsonObject ?? throw new InvalidDataException("Missing \"mcp\".");
        var cmd = mcp["command"]?.GetValue<string>() ?? throw new InvalidDataException("Missing \"mcp.command\".");
        if (!Path.IsPathFullyQualified(cmd)) throw new InvalidDataException("\"mcp.command\" must be a full path (no PATH lookups).");
        var operators = L(j["operators"]);
        if (operators.Contains("*")) throw new InvalidDataException("\"operators\" must name people; \"*\" isn't allowed for actions.");
        var commands = new Dictionary<string, CommandSpec>(StringComparer.Ordinal);
        foreach (var (cname, node) in j["commands"] as JsonObject ?? throw new InvalidDataException("Missing \"commands\"."))
        {
            if (!WordRe().IsMatch(cname) || cname == "help") throw new InvalidDataException("Command \"" + cname + "\": a-z words only, and not \"help\".");
            var c = node as JsonObject ?? throw new InvalidDataException("Command \"" + cname + "\" isn't an object.");
            var args = new List<ArgSpec>();
            foreach (var a in L(c["args"]))
            {
                if (!ArgRe().IsMatch(a)) throw new InvalidDataException("Command \"" + cname + "\": bad argument \"" + a + "\".");
                var list = a.EndsWith("...", StringComparison.Ordinal);
                var rest = a.EndsWith('*');
                var opt = a.EndsWith('?');
                var core = a.TrimEnd('.', '*', '?');
                var isInt = core.EndsWith(":int", StringComparison.Ordinal);
                var argName = isInt ? core[..^4] : core;
                if (NeverFromChat.Contains(argName)) throw new InvalidDataException("Command \"" + cname + "\": \"" + argName + "\" can never come from a chat message.");
                if (args.Any(x => x.List || x.Rest)) throw new InvalidDataException("Command \"" + cname + "\": a list or rest argument must be last.");
                args.Add(new ArgSpec(argName, opt, isInt, list, rest));
            }
            var fixedArgs = c["fixed"] as JsonObject ?? [];
            if (fixedArgs.Any(kv => NeverFromChat.Contains(kv.Key))) throw new InvalidDataException("Command \"" + cname + "\": scripts and file paths can't be wired to chat commands.");
            commands[cname] = new CommandSpec(cname, c["tool"]?.GetValue<string>() ?? throw new InvalidDataException("Command \"" + cname + "\" has no tool."),
                args, (JsonObject)fixedArgs.DeepClone(), c["action"]?.GetValue<bool>() == true, c["help"]?.GetValue<string>() ?? "");
        }
        return new ConnectorConfig
        {
            Name = name, Prefix = prefix, McpCommand = cmd, McpArgs = L(mcp["args"]),
            McpTimeout = TimeSpan.FromSeconds(Math.Clamp(mcp["timeout_seconds"]?.GetValue<int>() ?? 200, 10, 900)),
            Rooms = L(j["rooms"]), Readers = j["readers"] is null ? ["*"] : L(j["readers"]), Operators = operators,
            RatePerMinute = Math.Clamp(j["rate_per_minute"]?.GetValue<int>() ?? 10, 1, 120),
            MaxReplyChars = Math.Clamp(j["max_reply_chars"]?.GetValue<int>() ?? 3500, 200, 12000),
            Commands = commands,
        };
    }
}
