using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows.Threading;
using WixToolset.BootstrapperApplicationApi;

namespace DarkCipher.Setup;

/// <summary>WiX 5 runs the setup program as its own process (out of the Burn engine); this is its entry point.</summary>
internal static class Program
{
    // No [STAThread]: WiX's native runner sets this thread's COM mode itself (an STA here fails with RPC_E_CHANGED_MODE).
    // The window gets its own STA thread in SetupApplication.Run.
    private static int Main(string[] args)
    {
        // Build check (no window, no engine): read an app's setup-app.json and report each option's detection.
        // build.ps1 runs it so a broken config fails the build, not a user's install.
        if (args.Length == 2 && args[0] == "--check") return Check(args[1]);
        // Design check (never shown on screen): draw every page of the window into PNGs, with the engine absent.
        if (args.Length == 3 && args[0] == "--preview") return Preview(args[1], args[2]);
        var ba = new SetupApplication();
        try
        {
            ManagedBootstrapperApplication.Run(ba);
            return ba.ExitCode;
        }
        catch (Exception ex)
        {
            // Burn shows only "failed to start the bootstrapper application": keep the reason (types and codes, no data).
            try { File.WriteAllText(Path.Combine(Path.GetTempPath(), "DarkCipher.Setup-error.txt"), $"{DateTime.Now:O}\r\nHRESULT 0x{ex.HResult:X8}\r\n{ex}"); } catch { }
            return ex.HResult;
        }
    }

    private static int Preview(string folder, string outDir)
    {
        int result = 1;
        var t = new Thread(() =>
        {
            try
            {
                var ba = new SetupApplication { PreviewFolder = folder };
                ba.Config = SetupConfig.Load(folder);
                Directory.CreateDirectory(outDir);
                new SetupWindow(ba).RenderPages(outDir);
                result = 0;
            }
            catch (Exception ex) { Console.Error.WriteLine(ex); }
        });
        t.SetApartmentState(ApartmentState.STA);
        t.Start();
        t.Join();
        return result;
    }

    private static int Check(string folder)
    {
        try
        {
            var c = SetupConfig.Load(folder);
            if (c.Title.Length == 0) throw new InvalidDataException("setup-app.json has no title");
            if (c.Options.Count == 0) throw new InvalidDataException("setup-app.json has no options");
            foreach (var o in c.Options)
            {
                if (o.Title.Length == 0) throw new InvalidDataException(o.Property + " has no title");
                if (o.Package.Length > 0 && (!o.Package.All(char.IsLetterOrDigit) || o.Detect.Count == 0)) throw new InvalidDataException($"{o.Property}: \"package\" must be a letters-and-digits package Id, with a detect entry");
                foreach (var d in o.Detect)
                    if (d.Kind is not ("appPath" or "uninstall32" or "hklm64" or "hkcu" or "file")) throw new InvalidDataException($"{o.Property}: unknown detect kind \"{d.Kind}\"");
                Console.WriteLine($"{o.Property}: {(o.IsInstalled() ? "installed" : "not installed")} (default {(o.Default ? "on" : "off")})");
            }
            Console.WriteLine($"ok: {c.Title}, {c.Options.Count} option(s)");
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine("setup-app.json: " + ex.Message); return 1; }
    }
}

/// <summary>
/// The setup program's engine side. It detects what is installed, then either shows the themed window (a normal
/// double-click) or, for /quiet and /passive, plans and applies the requested action with no window at all — so the
/// bundle deploys silently like the MSI does. The window only sets bundle variables (the MSI properties) and asks for
/// Install, Repair or Uninstall; Burn and the MSI do the work.
/// </summary>
public sealed class SetupApplication : BootstrapperApplication
{
    private IBootstrapperCommand _command = null!;
    internal IEngine Engine { get; private set; } = null!;
    internal Dispatcher? UiDispatcher { get; private set; }
    internal SetupConfig Config { get; set; } = new();
    /// <summary>Where the payloads are (setup-app.json, logo.png, LICENSE.txt); the app's installer folder in preview.</summary>
    internal string Folder => PreviewFolder ?? Path.GetDirectoryName(typeof(SetupApplication).Assembly.Location) ?? ".";
    internal string? PreviewFolder { get; set; }

    /// <summary>What detection found: the app's MSI is installed (same or other version).</summary>
    internal bool AppInstalled { get; set; }
    internal bool Quiet => _command.Display is Display.None or Display.Embedded or Display.Passive;
    internal LaunchAction RequestedAction => PreviewFolder != null ? LaunchAction.Install : _command.Action;   // no command line in a preview
    internal int ExitCode { get; set; }

    /// <summary>Burn hands over the engine and the command line (/quiet, /uninstall…) before <see cref="Run"/>.</summary>
    protected override void OnCreate(CreateEventArgs args)
    {
        base.OnCreate(args);
        Engine = args.Engine;
        _command = args.Command;
    }

    protected override void Run()
    {
        try { Config = SetupConfig.Load(Folder); }
        catch (Exception ex) { Engine.Log(LogLevel.Error, "setup-app.json: " + ex.Message); }

        DetectPackageComplete += (_, e) => { if (e.PackageId == "App") AppInstalled = e.State == PackageState.Present; };
        // Extra packages (an option's "package"): found or not before detection; run only when the window says so.
        foreach (var o in Config.Options)
            if (o.Package.Length > 0) { Set(PackageVar(o, "Found"), o.IsInstalled() ? "1" : "0"); Set(PackageVar(o, "Run"), "0"); }

        if (Quiet)
        {
            // No visible window: detect, plan the command-line action, apply, quit with Burn's result. WiX 5 refuses
            // Apply without a window handle, so an invisible one (never shown) supplies it; every step that fails ends
            // the run with its error instead of waiting forever.
            using var done = new ManualResetEventSlim(false);
            _finished = done;
            IntPtr handle = IntPtr.Zero;
            var host = new Thread(() =>
            {
                UiDispatcher = Dispatcher.CurrentDispatcher;
                using var hidden = new System.Windows.Interop.HwndSource(0, 0, 0, 0, 0, "DarkCipher Setup", IntPtr.Zero);
                handle = hidden.Handle;
                Dispatcher.Run();
            }) { Name = "setup-quiet", IsBackground = true };
            host.SetApartmentState(ApartmentState.STA);
            host.Start();
            while (handle == IntPtr.Zero && host.IsAlive) Thread.Sleep(10);
            void Step(Action a) { try { a(); } catch (Exception ex) { Engine.Log(LogLevel.Error, "setup: " + ex.Message); Finish(ex.HResult != 0 ? ex.HResult : unchecked((int)0x80004005)); } }
            DetectComplete += (_, e) => Step(() => { if (Succeeded(e.Status)) Engine.Plan(QuietAction()); else Finish(e.Status); });
            PlanComplete += (_, e) => Step(() => { if (Succeeded(e.Status)) Engine.Apply(handle); else Finish(e.Status); });
            ApplyComplete += (_, e) => Finish(e.Status);
            Step(() => Engine.Detect());
            done.Wait();
            UiDispatcher?.InvokeShutdown();
        }
        else
        {
            // WPF needs a single-threaded apartment of its own; the engine's callbacks are marshalled to it by the window.
            var ui = new Thread(() =>
            {
                UiDispatcher = Dispatcher.CurrentDispatcher;
                var window = new SetupWindow(this);
                window.Closed += (_, _) => UiDispatcher.InvokeShutdown();
                window.Show();
                Engine.Detect();
                Dispatcher.Run();
            }) { Name = "setup-ui", IsBackground = false };
            ui.SetApartmentState(ApartmentState.STA);
            ui.Start();
            ui.Join();
        }
        Engine.Quit(ExitCode);
    }

    private ManualResetEventSlim? _finished;

    private LaunchAction QuietAction() => _command.Action switch
    {
        LaunchAction.Uninstall => LaunchAction.Uninstall,
        LaunchAction.Repair => LaunchAction.Repair,
        LaunchAction.Layout => LaunchAction.Layout,
        _ => LaunchAction.Install,
    };

    private void Finish(int status)
    {
        ExitCode = status;
        _finished?.Set();
    }

    internal static bool Succeeded(int hresult) => hresult >= 0;

    /// <summary>A bundle variable, passed to the MSI as the property of the same name (setup-app.properties.wxi).</summary>
    internal static string PackageVar(SetupOption o, string what) => "Pkg_" + o.Package + "_" + what;
    internal void Set(string name, string value) { if (PreviewFolder == null) Engine.SetVariableString(name, value, false); }
    internal string Format(string text) => PreviewFolder != null ? (text == "[WixBundleVersion]" ? "0.0.0 (preview)" : text) : Engine.FormatString(text);
    internal string Get(string name) => PreviewFolder != null ? "" : Engine.ContainsVariable(name) ? Engine.GetVariableString(name) : "";
}
