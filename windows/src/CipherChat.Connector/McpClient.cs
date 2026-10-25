using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace CipherChat.Connector;

/// <summary>
/// A Model Context Protocol client over stdio (newline-delimited JSON-RPC 2.0): starts the project's MCP server (for
/// CommandCentre, DcxMcp.exe) as a hidden child process, initialises it and calls its tools. The server process keeps
/// its own rules: CommandCentre still asks its owner to approve anything disruptive.
/// </summary>
public sealed class McpClient(string command, IReadOnlyList<string> args, TimeSpan timeout) : IDisposable
{
    private readonly ConcurrentDictionary<long, TaskCompletionSource<JsonObject>> _pending = new();
    private readonly SemaphoreSlim _start = new(1, 1);
    private Process? _proc;
    private long _nextId;

    public IReadOnlyList<JsonObject> Tools { get; private set; } = [];

    private bool Running => _proc is { HasExited: false };

    private async Task EnsureAsync(CancellationToken ct)
    {
        if (Running) return;
        await _start.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (Running) return;
            _proc?.Dispose();
            var psi = new ProcessStartInfo(command)
            {
                UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8, StandardInputEncoding = new System.Text.UTF8Encoding(false),
            };
            foreach (var a in args) psi.ArgumentList.Add(a);
            var p = Process.Start(psi) ?? throw new InvalidOperationException("Couldn't start " + Path.GetFileName(command) + ".");
            _proc = p;
            _ = Task.Run(() => ReadLoop(p), CancellationToken.None);          // lives as long as the process
            _ = Task.Run(async () => { try { while (await p.StandardError.ReadLineAsync().ConfigureAwait(false) is not null) { } } catch (IOException) { } }, CancellationToken.None);
            var init = await RequestAsync("initialize", new JsonObject
            {
                ["protocolVersion"] = "2025-06-18", ["capabilities"] = new JsonObject(),
                ["clientInfo"] = new JsonObject { ["name"] = "CipherChat Connector", ["version"] = "0.1.1" },
            }, ct, started: true).ConfigureAwait(false);
            await SendAsync(new JsonObject { ["jsonrpc"] = "2.0", ["method"] = "notifications/initialized" }).ConfigureAwait(false);
            var list = await RequestAsync("tools/list", new JsonObject(), ct, started: true).ConfigureAwait(false);
            Tools = (list["tools"] as JsonArray ?? []).OfType<JsonObject>().ToList();
            _ = init;
        }
        finally { _start.Release(); }
    }

    private async Task ReadLoop(Process p)
    {
        try
        {
            while (await p.StandardOutput.ReadLineAsync().ConfigureAwait(false) is { } line)
            {
                if (line.Length == 0 || line.Length > 8 * 1024 * 1024) continue;
                JsonObject? msg;
                try { msg = JsonNode.Parse(line) as JsonObject; } catch (JsonException) { continue; }
                if (msg?["id"] is JsonValue idv && idv.TryGetValue<long>(out var id) && _pending.TryRemove(id, out var tcs)) tcs.TrySetResult(msg);
            }
        }
        catch (IOException) { }
        foreach (var k in _pending.Keys)
            if (_pending.TryRemove(k, out var t)) t.TrySetException(new IOException("The MCP server stopped."));
    }

    private async Task SendAsync(JsonObject msg)
    {
        var p = _proc ?? throw new IOException("The MCP server isn't running.");
        await p.StandardInput.WriteLineAsync(msg.ToJsonString()).ConfigureAwait(false);
        await p.StandardInput.FlushAsync().ConfigureAwait(false);
    }

    private async Task<JsonObject> RequestAsync(string method, JsonObject @params, CancellationToken ct, bool started = false)
    {
        if (!started) await EnsureAsync(ct).ConfigureAwait(false);
        var id = Interlocked.Increment(ref _nextId);
        var tcs = new TaskCompletionSource<JsonObject>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[id] = tcs;
        await SendAsync(new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id, ["method"] = method, ["params"] = @params }).ConfigureAwait(false);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            var reply = await tcs.Task.WaitAsync(cts.Token).ConfigureAwait(false);
            if (reply["error"] is JsonObject err) throw new InvalidOperationException(err["message"]?.GetValue<string>() ?? "The MCP server refused that.");
            return reply["result"] as JsonObject ?? [];
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException("No answer within " + (int)timeout.TotalSeconds + " s.");
        }
        finally { _pending.TryRemove(id, out _); }
    }

    public async Task<IReadOnlyList<JsonObject>> ListToolsAsync(CancellationToken ct = default)
    {
        await EnsureAsync(ct).ConfigureAwait(false);
        return Tools;
    }

    /// <summary>Calls a tool; returns its text output and whether the tool reported an error.</summary>
    public async Task<(string Text, bool IsError)> CallAsync(string tool, JsonObject arguments, CancellationToken ct = default)
    {
        var r = await RequestAsync("tools/call", new JsonObject { ["name"] = tool, ["arguments"] = arguments }, ct).ConfigureAwait(false);
        var text = string.Join("\n", (r["content"] as JsonArray ?? []).OfType<JsonObject>()
            .Where(c => c["type"]?.GetValue<string>() == "text").Select(c => c["text"]?.GetValue<string>() ?? ""));
        return (text, r["isError"]?.GetValue<bool>() == true);
    }

    public void Dispose()
    {
        try { if (Running) _proc!.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
        _proc?.Dispose();
        _start.Dispose();
    }
}
