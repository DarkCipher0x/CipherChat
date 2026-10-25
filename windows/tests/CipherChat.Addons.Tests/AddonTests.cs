using System.Text;
using System.Text.Json.Nodes;
using CipherChat.Addons;
using CipherChat.Connector;
using CipherChat.Crypto;
using CipherChat.Engine;
using Room = CipherChat.Engine.Room;

namespace CipherChat.Addons.Tests;

/// <summary>The add-on SDK and the connector's rules, offline (the live round trip is in docs/ADDONS.md, "Verified").</summary>
public class AddonTests
{
    private static string Cfg(string extra = "", string commands = "") => """
        { "name": "t", "prefix": "!cc", "mcp": { "command": "C:\\x\\mcp.exe" },
          "operators": ["olivia"], "rate_per_minute": 3, "max_reply_chars": 200 EXTRA,
          "commands": { "status": { "tool": "fleet_status" }, "node": { "tool": "node_details", "args": ["node"] },
                        "runs": { "tool": "recent_runs", "args": ["limit:int?"] },
                        "lock": { "tool": "lock", "args": ["targets..."], "action": true } COMMANDS } }
        """.Replace("EXTRA", extra).Replace("COMMANDS", commands);

    private static ConnectorConfig Load(string json)
    {
        var path = Path.GetTempFileName();
        try { File.WriteAllText(path, json); return ConnectorConfig.Load(path); }
        finally { File.Delete(path); }
    }

    private static AddonMessage Msg(string from, string text, string room = "ops") =>
        new(new Room("r1", new JsonObject { ["id"] = "r1", ["kind"] = "room", ["name"] = room }),
            new ChatMessage { Id = Guid.NewGuid().ToString("N"), Seq = 1, From = from, At = 1, Mine = false, Kind = "text", Text = text });

    private sealed class Calls
    {
        public readonly List<(string Tool, string Args)> Made = [];
        public string Reply = "ok";
        public Task<(string, bool)> Call(string tool, JsonObject args, CancellationToken ct)
        {
            Made.Add((tool, args.ToJsonString()));
            return Task.FromResult((Reply, false));
        }
    }

    private static (Dispatcher D, Calls C, List<string> Log) Make(string extra = "")
    {
        var calls = new Calls();
        var log = new List<string>();
        return (new Dispatcher(Load(Cfg(extra)), calls.Call, log.Add), calls, log);
    }

    [Fact]
    public async Task Look_ups_for_readers_actions_only_for_named_operators()
    {
        var (d, c, log) = Make();
        Assert.Contains("ok", await d.HandleAsync(Msg("kim", "!cc status"), "#ops"));
        Assert.Contains("only this connector's operators", await d.HandleAsync(Msg("kim", "!cc lock all"), "#ops"));
        Assert.Contains("ok", await d.HandleAsync(Msg("olivia", "!cc lock pc-01 pc-02"), "#ops"));
        Assert.Equal([("fleet_status", "{}"), ("lock", "{\"targets\":[\"pc-01\",\"pc-02\"]}")], c.Made);
        Assert.Contains(log, l => l.Contains("kim") && l.Contains("refused: not an operator"));
        Assert.Null(await d.HandleAsync(Msg("kim", "hello !cc status"), "#ops"));          // only at the start
        Assert.Null(await d.HandleAsync(Msg("kim", "!ccstatus"), "#ops"));
    }

    [Fact]
    public async Task Arguments_are_bound_strictly()
    {
        var (d, c, _) = Make();                                          // 3 commands a minute each: kim, max, ann
        await d.HandleAsync(Msg("kim", "!cc runs 7"), "#ops");
        Assert.Equal(("recent_runs", "{\"limit\":7}"), c.Made.Single());
        Assert.Contains("Missing node", await d.HandleAsync(Msg("kim", "!cc node"), "#ops"));
        Assert.Contains("Too many words", await d.HandleAsync(Msg("kim", "!cc node a b"), "#ops"));
        Assert.Contains("must be a number", await d.HandleAsync(Msg("max", "!cc runs -5"), "#ops"));
        Assert.Contains("No command", await d.HandleAsync(Msg("max", "!cc rm -rf"), "#ops"));
        Assert.Contains("Too many words", await d.HandleAsync(Msg("max", "!cc status now"), "#ops"));
        Assert.Contains("Missing targets", await d.HandleAsync(Msg("olivia", "!cc lock"), "#ops"));
        Assert.Single(c.Made);
    }

    [Fact]
    public async Task Rooms_readers_and_rate_limit()
    {
        var (d, _, _) = Make(", \"rooms\": [\"ops\"], \"readers\": [\"kim\"]");
        Assert.Null(await d.HandleAsync(Msg("kim", "!cc status", "general"), "#general"));          // other rooms: silent
        Assert.Null(await d.HandleAsync(Msg("max", "!cc status"), "ops"));                          // not a reader: silent
        for (var i = 0; i < 3; i++) Assert.Contains("ok", await d.HandleAsync(Msg("kim", "!cc status"), "ops"));
        Assert.Contains("Slow down", await d.HandleAsync(Msg("kim", "!cc status"), "ops"));
    }

    [Fact]
    public async Task Output_is_fenced_escaped_and_cut()
    {
        var (d, c, _) = Make();
        c.Reply = "```evil```" + new string('x', 500);
        var r = await d.HandleAsync(Msg("kim", "!cc status"), "#ops");
        Assert.StartsWith("```\n'''evil'''", r);
        Assert.Contains("cut at 200", r);
        Assert.EndsWith("\n```", r);
        Assert.Equal(2, r!.Split("```").Length - 1);
    }

    [Fact]
    public void Configurations_that_would_widen_the_chat_are_refused()
    {
        Assert.Throws<InvalidDataException>(() => Load(Cfg(commands: ", \"x\": { \"tool\": \"run_script\", \"args\": [\"content*\"] }")));
        Assert.Throws<InvalidDataException>(() => Load(Cfg(commands: ", \"x\": { \"tool\": \"send_file\", \"args\": [\"to\"], \"fixed\": { \"path\": \"C:\\\\x\" } }")));
        Assert.Throws<InvalidDataException>(() => Load(Cfg().Replace("\"operators\": [\"olivia\"]", "\"operators\": [\"*\"]")));
        Assert.Throws<InvalidDataException>(() => Load(Cfg().Replace("C:\\\\x\\\\mcp.exe", "mcp.exe")));        // no PATH lookups
        Assert.Throws<InvalidDataException>(() => Load(Cfg(commands: ", \"y\": { \"tool\": \"t\", \"args\": [\"a...\", \"b\"] }")));
        Assert.Throws<InvalidDataException>(() => Load(Cfg(commands: ", \"help\": { \"tool\": \"t\" }")));
    }

    [Fact]
    public void The_commandcentre_preset_loads_read_only_by_default()
    {
        var cfg = ConnectorConfig.Load(Path.Combine(AppContext.BaseDirectory, "connectors", "commandcentre.json"));
        Assert.Empty(cfg.Operators);
        Assert.All(cfg.Commands.Values.Where(c => c.Tool is "lock" or "wake" or "service" or "power" or "run_workflow"), c => Assert.True(c.Action));
        Assert.DoesNotContain(cfg.Commands.Values, c => c.Tool is "run_script" or "install_app" or "send_file" or "notify" or "open_tool");
    }

    [Fact]
    public void Hmac_sha3_matches_python_and_the_signature_covers_everything()
    {
        // Python: hmac.new(bytes(range(32)), b"CipherChat add-on HMAC test vector", hashlib.sha3_256).hexdigest()
        var key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        Assert.Equal("610326970f8db6cd8246ca818387158d3efe71d4dc3890624da726a7bb62372c",
                     Bytes.Hex(RequestSigner.HmacSha3(key, Encoding.UTF8.GetBytes("CipherChat add-on HMAC test vector"))));
        var json = "{\"o\":\"https://chat.example\",\"u\":\"addon.cc\",\"k\":\"" + ConnectorCode.B64Url(key) + "\",\"a\":\"" + new string('a', 64) + "\"}";
        var code = ConnectorCode.Parse(ConnectorCode.Prefix + ConnectorCode.B64Url(Encoding.UTF8.GetBytes(json)));
        var s = new RequestSigner(code);
        var h1 = s.Sign("GET", "/chat/api/state", []);
        var h2 = s.Sign("GET", "/chat/api/state", []);
        Assert.NotEqual(h1["X-CipherChat-Nonce"], h2["X-CipherChat-Nonce"]);
        Assert.NotEqual(h1["X-CipherChat-Signature"], h2["X-CipherChat-Signature"]);
        Assert.Equal(Bytes.Hex(Hybrid.Sha3_256([])), h1["X-CipherChat-Content-SHA3"]);
        var canon = string.Join('\n', "CIPHERCHAT-ADDON-V1", "https://chat.example", "GET", "/chat/api/state", "addon.cc",
                                h1["X-CipherChat-Time"], h1["X-CipherChat-Nonce"], h1["X-CipherChat-Content-SHA3"]);
        Assert.Equal(Bytes.Hex(RequestSigner.HmacSha3(key, Encoding.UTF8.GetBytes(canon))), h1["X-CipherChat-Signature"]);
    }

    [Fact]
    public void Connector_codes_are_checked()
    {
        string Make(string o, string u, int keyLen, string? a) =>
            ConnectorCode.Prefix + ConnectorCode.B64Url(Encoding.UTF8.GetBytes(new JsonObject
            { ["o"] = o, ["u"] = u, ["k"] = ConnectorCode.B64Url(new byte[keyLen]), ["a"] = a }.ToJsonString()));
        var fp = new string('b', 64);
        Assert.Equal("addon.cc", ConnectorCode.Parse(Make("https://chat.example", "addon.cc", 32, fp)).User);
        Assert.Throws<FormatException>(() => ConnectorCode.Parse(Make("http://chat.example", "addon.cc", 32, fp)));      // https only
        Assert.Throws<FormatException>(() => ConnectorCode.Parse(Make("http://127.0.0.1:1", "addon.cc", 32, fp)));       // unless dev
        Assert.Equal("addon.cc", ConnectorCode.Parse(Make("http://127.0.0.1:1", "addon.cc", 32, fp), allowHttp: true).User);
        Assert.Throws<FormatException>(() => ConnectorCode.Parse(Make("https://chat.example", "kim", 32, fp)));           // add-ons only
        Assert.Throws<FormatException>(() => ConnectorCode.Parse(Make("https://chat.example", "addon.cc", 16, fp)));      // 256-bit keys
        Assert.Throws<FormatException>(() => ConnectorCode.Parse(Make("https://chat.example", "addon.cc", 32, null)));    // owner pinned
        Assert.Throws<FormatException>(() => ConnectorCode.Parse(Make("https://chat.example/x", "addon.cc", 32, fp)));
        Assert.Throws<FormatException>(() => ConnectorCode.Parse("cipherchat:pair/v1?server=x"));
    }
}
