using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows;
using CipherChat.Crypto;
using CipherChat.Engine;
using CipherChat.Ui;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;
using Room = CipherChat.Engine.Room;

namespace CipherChat.App.Shell;

/// <summary>
/// A voice or video call (docs/CALLS.md): a window whose WebView2 runs the portal's call code from this app's own
/// folder (CallHost/), mapped to a private host name. The page can't fetch anything (its CSP) and can ask this window
/// only for the operations in <see cref="Dispatch"/>; signing, verifying and key wrapping happen in Calls.cs with the
/// identity, and signals travel over the app's PQ-only TLS. The camera and microphone are allowed for that page only.
/// </summary>
public sealed class CallWindow : Window
{
    private const string Host = "cipherchat-call.example";
    private static readonly string Origin = "https://" + Host;
    private static CallWindow? _open;

    private readonly MainWindow _main;
    private readonly ChatEngine _e;
    private readonly WebView2 _web = new();
    private readonly Func<CallWindow, Task> _first;
    private bool _ended;

    /// <summary>The window of the current call, if there is one.</summary>
    public static CallWindow? Current => _open;

    private CallWindow(MainWindow main, string title, Func<CallWindow, Task> first)
    {
        _main = main;
        _e = main.Session.Engine!;
        _first = first;
        Title = title;
        Width = 1180; Height = 760; MinWidth = 520; MinHeight = 380;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        SetResourceReference(BackgroundProperty, "Bg");
        WindowFrame.Frame(this, _web, null, "", closeTip: "Hang up and close");
        _e.Calls.Signals += OnSignals;
        Loaded += async (_, _) => await InitAsync();
        Closed += (_, _) =>
        {
            _e.Calls.Signals -= OnSignals;
            _e.Calls.Closed();
            _open = null;
            _web.Dispose();
        };
    }

    /// <summary>Starts a call with the members of a room.</summary>
    public static void Start(MainWindow main, Room room, string media)
    {
        if (!Available(main)) return;
        var people = room.Members.Select(m => m.User).Where(u => u != main.Session.Engine!.MyUser).ToList();
        Show(main, (media == "video" ? "Video call" : "Voice call") + " · " + room.Label(main.Session.Engine!.MyUser), w =>
            w.PostAsync("start", new JsonObject { ["room"] = room.Id, ["media"] = media, ["people"] = new JsonArray(people.Select(p => (JsonNode)p).ToArray()) }));
    }

    /// <summary>Answers a ringing call: the window gets every signal kept for it, then accepts.</summary>
    public static void Answer(MainWindow main, IncomingCall inc)
    {
        if (!Available(main)) { main.Session.Engine!.Calls.Decline(inc); return; }
        Show(main, (inc.Media == "video" ? "Video call" : "Voice call") + " with " + inc.From, w =>
            w.PostAsync("answer", new JsonObject { ["call"] = inc.Call, ["items"] = w._e.Calls.Open(inc.Call) }));
    }

    private static bool Available(MainWindow main)
    {
        if (_open is not null) { _open.Activate(); Dialogs.Info(main, "Already in a call", "Hang up the current call first."); return false; }
        try { CoreWebView2Environment.GetAvailableBrowserVersionString(); }
        catch (WebView2RuntimeNotFoundException)
        {
            Dialogs.Error(main, "Calls need the WebView2 runtime", "Windows' Edge WebView2 runtime isn't installed on this PC. The CipherChat installer adds it; or get it from Microsoft (\"WebView2 Runtime\").");
            return false;
        }
        return true;
    }

    private static void Show(MainWindow main, string title, Func<CallWindow, Task> first)
    {
        _open = new CallWindow(main, title, first) { Owner = main };
        _open.Show();
    }

    // ------------------------------------------------------------------------------------------- WebView2
    private async Task InitAsync()
    {
        var data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CipherChat", "WebView2");
        var args = "--disable-features=msSmartScreenProtection";
        // Development only (a --dev-server build, and asked for): Chromium's test camera and tone instead of real devices
        if (_main.Session.DevServer is not null && Environment.GetEnvironmentVariable("CIPHERCHAT_FAKE_MEDIA") == "1")
            args += " --use-fake-device-for-media-stream --use-fake-ui-for-media-stream --disable-features=CalculateNativeWinOcclusion";
        var env = await CoreWebView2Environment.CreateAsync(null, data, new CoreWebView2EnvironmentOptions(args));
        await _web.EnsureCoreWebView2Async(env);
        var core = _web.CoreWebView2;
        var s = core.Settings;
        s.AreDevToolsEnabled = System.Diagnostics.Debugger.IsAttached;
        s.AreDefaultContextMenusEnabled = false;
        s.AreDefaultScriptDialogsEnabled = false;
        s.AreHostObjectsAllowed = false;
        s.IsStatusBarEnabled = false;
        s.IsZoomControlEnabled = false;
        s.IsPasswordAutosaveEnabled = false;
        s.IsGeneralAutofillEnabled = false;
        s.AreBrowserAcceleratorKeysEnabled = false;
        s.IsWebMessageEnabled = true;
        core.SetVirtualHostNameToFolderMapping(Host, Path.Combine(AppContext.BaseDirectory, "CallHost"), CoreWebView2HostResourceAccessKind.Deny);
        core.NavigationStarting += (_, e) => { if (!e.Uri.StartsWith(Origin + "/", StringComparison.Ordinal)) e.Cancel = true; };
        core.NewWindowRequested += (_, e) => e.Handled = true;
        core.PermissionRequested += (_, e) =>
        {
            var ours = e.Uri.StartsWith(Origin + "/", StringComparison.Ordinal);
            e.State = ours && e.PermissionKind is CoreWebView2PermissionKind.Camera or CoreWebView2PermissionKind.Microphone
                ? CoreWebView2PermissionState.Allow : CoreWebView2PermissionState.Deny;
            e.Handled = true;
        };
        core.WebMessageReceived += OnMessage;
        core.Navigate(Origin + "/call.html");
    }

    private Task PostAsync(string ev, JsonObject detail)
    {
        _web.CoreWebView2?.PostWebMessageAsJson(new JsonObject { ["event"] = ev, ["detail"] = detail }.ToJsonString());
        return Task.CompletedTask;
    }

    private void OnSignals(JsonArray items) => Dispatcher.BeginInvoke(() => PostAsync("signals", new JsonObject { ["items"] = items }));

    private async void OnMessage(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        if (!e.Source.StartsWith(Origin + "/", StringComparison.Ordinal)) return;   // only our own page
        JsonObject m;
        try { m = JsonNode.Parse(e.WebMessageAsJson) as JsonObject ?? []; } catch (JsonException) { return; }
        if (m["event"] is not null) { await OnEventAsync(m.StrOrNull("event") ?? "", m["detail"] as JsonObject ?? []); return; }
        var id = m.LongOrNull("id");
        if (id is null) return;
        JsonObject reply;
        try { reply = new JsonObject { ["reply"] = id, ["ok"] = true, ["value"] = await Dispatch(m.StrOrNull("op") ?? "", m["args"]) }; }
        catch (Exception ex) when (ex is CryptoFail or Api.ApiException or InvalidOperationException or ArgumentException or FormatException or KeyNotFoundException)
        {
            reply = new JsonObject { ["reply"] = id, ["ok"] = false, ["error"] = ex.Message };
        }
        _web.CoreWebView2?.PostWebMessageAsJson(reply.ToJsonString());
    }

    /// <summary>Everything the call page may ask of the app. Anything else is refused.</summary>
    private async Task<JsonNode?> Dispatch(string op, JsonNode? args)
    {
        var c = _e.Calls;
        switch (op)
        {
            case "seal":
            {
                var fields = Obj(args);
                c.Started(fields.Str("call"));                     // a call this window started: its signals come here from now on
                return c.Seal(fields);
            }
            case "open": return c.OpenSignal(Obj(args));
            case "wrapKey":
            {
                var a = Obj(args);
                var key = Bytes.Unb64(a.Str("key"), 32);
                try { return c.WrapKey(key, a.Str("call"), a.Long("epoch"), Users(a)); }
                finally { Bytes.Wipe(key); }
            }
            case "unwrapKey":
            {
                var key = c.UnwrapKey(Obj(args));
                try { return Bytes.B64(key); } finally { Bytes.Wipe(key); }
            }
            case "words": { var a = Obj(args); return new JsonArray(c.Words(a.Str("call"), Users(a)).Select(w => (JsonNode)w).ToArray()); }
            case "api":
            {
                var a = Obj(args);
                return a.StrOrNull("path") switch
                {
                    "calls/signal" => await c.SignalAsync(a.Obj("body")).ConfigureAwait(true),
                    "calls/turn" => await c.TurnAsync().ConfigureAwait(true),
                    _ => throw new InvalidOperationException("the call page may only send call signals"),
                };
            }
            default: throw new InvalidOperationException("unknown request");
        }
    }

    private static JsonObject Obj(JsonNode? n) => n as JsonObject ?? throw new ArgumentException("malformed request");

    private static List<string> Users(JsonObject a) =>
        (a["users"] as JsonArray ?? throw new ArgumentException("malformed request")).Select(x => x?.GetValue<string>() ?? throw new ArgumentException("malformed request")).ToList();

    private async Task OnEventAsync(string ev, JsonObject d)
    {
        switch (ev)
        {
            case "ready":
                var labels = new JsonObject();
                foreach (var r in _e.Rooms) labels[r.Id] = r.Label(_e.MyUser);
                await PostAsync("init", new JsonObject
                {
                    ["user"] = _e.MyUser, ["dev"] = _e.Calls.Device, ["labels"] = labels,
                    ["trusted"] = new JsonArray(_e.Calls.TrustedUsers.Select(u => (JsonNode)u).ToArray()),
                    ["diag"] = _main.Session.DevServer is not null,
                    ["fakeMedia"] = _main.Session.DevServer is not null && Environment.GetEnvironmentVariable("CIPHERCHAT_FAKE_MEDIA") == "1",
                }).ConfigureAwait(true);
                await _first(this).ConfigureAwait(true);
                break;
            case "words":
                Title = Title.Split("  ·  ")[0] + "  ·  " + string.Join(" ", (d["words"] as JsonArray ?? []).Select(x => x?.GetValue<string>()));
                break;
            case "diag" when _main.Session.DevServer is not null:      // development builds only
                File.AppendAllText(Path.Combine(Path.GetTempPath(), "cipherchat-call-diag.log"), DateTime.Now.ToString("HH:mm:ss ") + d.ToJsonString() + Environment.NewLine);
                break;
            case "notice":
                _main.ShowNotice(d.StrOrNull("kind") ?? "sys", d.StrOrNull("text") ?? "");
                break;
            case "ended":
                if (_ended) return;
                _ended = true;
                _main.ShowNotice("sys", "Call ended (" + (d.StrOrNull("why") ?? "") + ").");
                await Task.Delay(600).ConfigureAwait(true);
                Close();
                break;
        }
    }

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        if (!_ended && _web.CoreWebView2 is not null)
        {
            e.Cancel = true;                                        // hang up properly first; "ended" closes the window
            _ = PostAsync("hangup", []);
            _ = Task.Delay(3000).ContinueWith(_ => Dispatcher.BeginInvoke(() => { _ended = true; Close(); }), TaskScheduler.Default);
            return;
        }
        base.OnClosing(e);
    }
}
