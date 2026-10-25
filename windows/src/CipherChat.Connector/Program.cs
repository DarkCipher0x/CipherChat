using System.Text;
using CipherChat.Addons;
using CipherChat.Engine;
using CipherChat.Transport;

namespace CipherChat.Connector;

/// <summary>
/// CipherChat Connector by DarkCipher Systems: brings another system into the chat as an add-on (docs/ADDONS.md). It
/// speaks MCP to the system (CommandCentre's DcxMcp.exe, or any MCP server) and post-quantum end-to-end CipherChat to
/// the people. Nothing here opens a window, a port or a listener.
///
///   CipherChatConnector setup &lt;config.json&gt;   paste the connector code (from /addons); makes and seals the add-on's keys
///   CipherChatConnector run &lt;config.json&gt;     connect and answer commands (Ctrl+C to stop)
///   CipherChatConnector check &lt;config.json&gt;   the MCP server's tools, and whether every command maps to one
///   CipherChatConnector forget &lt;config.json&gt;  delete this PC's sealed keys for the connector
/// </summary>
internal static class Program
{
    private static int Main(string[] argv)
    {
        Console.OutputEncoding = Encoding.UTF8;
        if (argv.Length < 2 || argv[0] is not ("setup" or "run" or "check" or "forget"))
        {
            Console.Error.WriteLine("usage: CipherChatConnector setup|run|check|forget <config.json> [--dev]");
            return 2;
        }
        var dev = argv.Contains("--dev");
        ConnectorConfig cfg;
        try { cfg = ConnectorConfig.Load(argv[1]); }
        catch (Exception e) when (e is IOException or InvalidDataException or System.Text.Json.JsonException or InvalidOperationException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine("Configuration refused: " + e.Message);
            return 2;
        }
        try
        {
            return argv[0] switch
            {
                "setup" => Setup(cfg, dev).GetAwaiter().GetResult(),
                "run" => Run(cfg, dev).GetAwaiter().GetResult(),
                "check" => Check(cfg).GetAwaiter().GetResult(),
                _ => Forget(cfg),
            };
        }
        catch (Exception e) when (e is FormatException or UnauthorizedAccessException or FileNotFoundException or Api.ApiException
                                     or Crypto.CryptoFail or InvalidOperationException or ArgumentException or IOException)
        {
            Console.Error.WriteLine(e.Message);
            return 1;
        }
    }

    private static ITransport TransportFor(ConnectorCode code, bool dev) =>
        dev && code.Server.Scheme == Uri.UriSchemeHttp ? new LoopbackDevTransport(code.Server) : new PqTlsTransport(code.Server);

    private static string ReadSecretLine()
    {
        if (Console.IsInputRedirected) return Console.ReadLine() ?? "";
        var sb = new StringBuilder();
        for (ConsoleKeyInfo k; (k = Console.ReadKey(intercept: true)).Key != ConsoleKey.Enter;)
        {
            if (k.Key == ConsoleKey.Backspace) { if (sb.Length > 0) sb.Length--; }
            else if (!char.IsControl(k.KeyChar)) sb.Append(k.KeyChar);
        }
        Console.WriteLine();
        return sb.ToString();
    }

    private static async Task<int> Setup(ConnectorConfig cfg, bool dev)
    {
        if (KeyStore.Exists(cfg.Name)) throw new InvalidOperationException("\"" + cfg.Name + "\" is already set up on this PC. Use forget first to start again.");
        Console.WriteLine("Paste the connector code for " + cfg.Name + " (from /addons in the owner's CipherChat; it isn't shown):");
        var codeText = ReadSecretLine().Trim();
        var code = ConnectorCode.Parse(codeText, allowHttp: dev);
        var master = AddonIdentity.NewMaster();
        KeyStore.Save(cfg.Name, codeText, master);
        Console.WriteLine("Sealed for this Windows account in " + KeyStore.PathFor(cfg.Name));
        var host = new AddonHost(code, TransportFor(code, dev));
        host.Log += Console.WriteLine;
        try
        {
            await host.StartAsync(master).ConfigureAwait(false);
            Console.WriteLine();
            Console.WriteLine(code.User + " has its post-quantum identity (ML-DSA-87 + Ed25519, ML-KEM-1024 + X25519).");
            Console.WriteLine("Owner: in CipherChat type /verify " + code.User + " and check this safety number, then certify it:");
            Console.WriteLine("    " + host.SafetyNumber);
            Console.WriteLine("Then add it to the rooms it should serve: /invite " + code.User);
        }
        catch
        {
            KeyStore.Delete(cfg.Name);                      // nothing half set up is left behind
            throw;
        }
        finally { host.Stop(); }
        return 0;
    }

    private static async Task<int> Run(ConnectorConfig cfg, bool dev)
    {
        var (codeText, master) = KeyStore.Load(cfg.Name);
        var code = ConnectorCode.Parse(codeText, allowHttp: dev);
        var logPath = Path.Combine(KeyStore.Folder, cfg.Name + ".log");
        var logLock = new object();
        void Log(string line)
        {
            Console.WriteLine(line);
            lock (logLock) File.AppendAllText(logPath, line + Environment.NewLine);
        }
        using var mcp = new McpClient(cfg.McpCommand, cfg.McpArgs, cfg.McpTimeout);
        var tools = await mcp.ListToolsAsync().ConfigureAwait(false);
        var missing = cfg.Commands.Values.Where(c => tools.All(t => t["name"]?.GetValue<string>() != c.Tool)).Select(c => c.Name + " (" + c.Tool + ")").ToList();
        if (missing.Count > 0) Log("These commands' tools aren't offered by the MCP server and won't work: " + string.Join(", ", missing));
        var dispatcher = new Dispatcher(cfg, mcp.CallAsync, Log);
        var host = new AddonHost(code, TransportFor(code, dev));
        host.Log += Log;
        host.MessageReceived += async m =>
        {
            var reply = await dispatcher.HandleAsync(m, m.Room.Kind == "dm" ? "@" + m.From : "#" + m.Room.Name).ConfigureAwait(false);
            if (reply is not null) await host.ReplyAsync(m, reply).ConfigureAwait(false);
        };
        await host.StartAsync(master).ConfigureAwait(false);
        Log(code.User + " is running (" + cfg.Commands.Count + " commands, prefix " + cfg.Prefix + "). Safety number " + host.SafetyNumber);
        var done = new TaskCompletionSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; done.TrySetResult(); };
        await done.Task.ConfigureAwait(false);
        host.Stop();
        Log(code.User + " stopped.");
        return 0;
    }

    private static async Task<int> Check(ConnectorConfig cfg)
    {
        using var mcp = new McpClient(cfg.McpCommand, cfg.McpArgs, cfg.McpTimeout);
        var tools = await mcp.ListToolsAsync().ConfigureAwait(false);
        Console.WriteLine(Path.GetFileName(cfg.McpCommand) + " offers " + tools.Count + " tools.");
        var bad = 0;
        foreach (var c in cfg.Commands.Values)
        {
            var ok = tools.Any(t => t["name"]?.GetValue<string>() == c.Tool);
            if (!ok) bad++;
            Console.WriteLine((ok ? "  ok   " : "  MISSING ") + cfg.Prefix + " " + c.Name + " -> " + c.Tool + (c.Action ? "  [action: operators only]" : ""));
        }
        return bad == 0 ? 0 : 1;
    }

    private static int Forget(ConnectorConfig cfg)
    {
        KeyStore.Delete(cfg.Name);
        Console.WriteLine("Deleted this PC's keys for " + cfg.Name + ". Remove the add-on in CipherChat too (/addons).");
        return 0;
    }
}
