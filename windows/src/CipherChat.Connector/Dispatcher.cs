using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;
using CipherChat.Addons;

namespace CipherChat.Connector;

/// <summary>
/// Turns a verified chat message into at most one MCP tool call, under the connector's rules: the right room, the right
/// person (readers for look-ups, named operators for actions), a per-person rate limit, arguments only where the
/// configuration puts them. Every decision is written to the local log (who, room, command, outcome; never the output).
/// </summary>
public sealed class Dispatcher(ConnectorConfig cfg, Func<string, JsonObject, CancellationToken, Task<(string Text, bool IsError)>> callTool, Action<string> log)
{
    private readonly ConcurrentDictionary<string, Queue<DateTime>> _rates = new();

    public async Task<string?> HandleAsync(AddonMessage m, string roomName, CancellationToken ct = default)
    {
        var text = m.Text.Trim();
        if (!(text == cfg.Prefix || text.StartsWith(cfg.Prefix + " ", StringComparison.Ordinal))) return null;
        if (cfg.Rooms.Count > 0 && !cfg.Rooms.Contains(roomName) && !cfg.Rooms.Contains(m.Room.Id)) return null;
        if (text.Length > 500) return "That's too long for a command.";
        var words = text[cfg.Prefix.Length..].Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (words.Length > 40) return "Too many words for a command.";
        var reader = cfg.Readers.Contains("*") || cfg.Readers.Contains(m.From);
        var op = cfg.Operators.Contains(m.From);
        if (!reader && !op) { Audit(m, roomName, words.FirstOrDefault() ?? "", "refused: not a reader"); return null; }
        if (!RateOk(m.From)) { Audit(m, roomName, words.FirstOrDefault() ?? "", "refused: rate"); return "Slow down: up to " + cfg.RatePerMinute + " commands a minute."; }
        if (words.Length == 0 || words[0] == "help") return Help(op);
        if (!cfg.Commands.TryGetValue(words[0].ToLowerInvariant(), out var c)) return "No command \"" + words[0] + "\". Try " + cfg.Prefix + " help.";
        if (c.Action && !op)
        {
            Audit(m, roomName, c.Name, "refused: not an operator");
            return c.Name + " changes things, and only this connector's operators may use it.";
        }
        JsonObject args;
        try { args = Bind(c, words[1..]); }
        catch (ArgumentException e) { return e.Message + " Usage: " + Usage(c); }
        var sw = Stopwatch.StartNew();
        try
        {
            var (output, isError) = await callTool(c.Tool, args, ct).ConfigureAwait(false);
            Audit(m, roomName, c.Name, (isError ? "tool error" : "ok") + " in " + sw.ElapsedMilliseconds + " ms");
            return Format(c, output, isError);
        }
        catch (Exception e) when (e is IOException or TimeoutException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            Audit(m, roomName, c.Name, "failed: " + e.GetType().Name);
            return c.Name + " didn't work: " + e.Message;
        }
    }

    private static JsonObject Bind(CommandSpec c, string[] words)
    {
        var args = (JsonObject)c.Fixed.DeepClone();
        var i = 0;
        foreach (var a in c.Args)
        {
            if (a.List || a.Rest)
            {
                if (i >= words.Length) { if (a.Optional) break; throw new ArgumentException("Missing " + a.Name + "."); }
                if (a.List) args[a.Name] = new JsonArray(words[i..].Select(w => (JsonNode)Clean(w)).ToArray());
                else args[a.Name] = string.Join(' ', words[i..].Select(Clean));
                i = words.Length;
                break;
            }
            if (i >= words.Length) { if (a.Optional) continue; throw new ArgumentException("Missing " + a.Name + "."); }
            var w = Clean(words[i++]);
            if (a.Int)
            {
                if (!int.TryParse(w, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var n) || n > 100000)
                    throw new ArgumentException(a.Name + " must be a number.");
                args[a.Name] = n;
            }
            else args[a.Name] = w;
        }
        if (i < words.Length) throw new ArgumentException("Too many words.");
        return args;
    }

    // no control characters, bounded length: chat text becomes a JSON string argument, never a command line
    private static string Clean(string w)
    {
        var s = new string(w.Where(ch => !char.IsControl(ch)).ToArray());
        return s.Length > 200 ? s[..200] : s;
    }

    private string Format(CommandSpec c, string output, bool isError)
    {
        var body = output.Replace("```", "'''", StringComparison.Ordinal).Trim();
        if (body.Length == 0) body = isError ? "(the tool reported an error)" : "(no output)";
        if (body.Length > cfg.MaxReplyChars) body = body[..cfg.MaxReplyChars] + "\n… (cut at " + cfg.MaxReplyChars + " characters)";
        return (isError ? c.Name + " failed:\n" : "") + "```\n" + body + "\n```";
    }

    private string Help(bool op)
    {
        var sb = new StringBuilder("Commands (" + cfg.Prefix + " <command>):\n");
        foreach (var c in cfg.Commands.Values.Where(c => !c.Action || op))
            sb.Append("• ").Append(Usage(c)).Append(c.Help.Length > 0 ? " — " + c.Help : "").Append(c.Action ? " [action]" : "").Append('\n');
        if (!op && cfg.Commands.Values.Any(c => c.Action)) sb.Append("(Actions are for this connector's operators.)");
        return sb.ToString().TrimEnd();
    }

    private string Usage(CommandSpec c) =>
        cfg.Prefix + " " + c.Name + string.Concat(c.Args.Select(a => " " + (a.Optional ? "[" : "<") + a.Name + (a.List || a.Rest ? "…" : "") + (a.Optional ? "]" : ">")));

    private bool RateOk(string user)
    {
        var q = _rates.GetOrAdd(user, _ => new Queue<DateTime>());
        lock (q)
        {
            var now = DateTime.UtcNow;
            while (q.Count > 0 && q.Peek() < now.AddMinutes(-1)) q.Dequeue();
            if (q.Count >= cfg.RatePerMinute) return false;
            q.Enqueue(now);
            return true;
        }
    }

    private void Audit(AddonMessage m, string room, string command, string outcome) =>
        log(DateTime.UtcNow.ToString("u") + " " + m.From + " in " + room + ": " + command + " -> " + outcome);
}
