using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using Microsoft.Win32;

namespace DarkCipher.Setup;

/// <summary>An app's setup texts and options (installer\setup-app.json, a payload beside this assembly). The template
/// code never names an app: everything it shows comes from here.</summary>
[DataContract]
public sealed class SetupConfig
{
    [DataMember(Name = "brand")] public string Brand { get; set; } = "DARKCIPHER SYSTEMS";
    [DataMember(Name = "title")] public string Title { get; set; } = "";
    [DataMember(Name = "tagline")] public string Tagline { get; set; } = "";
    [DataMember(Name = "website")] public string Website { get; set; } = "";
    [DataMember(Name = "dataNote")] public string DataNote { get; set; } = "";
    [DataMember(Name = "options")] public List<SetupOption> Options { get; set; } = new();
    [DataMember(Name = "removeData")] public RemoveOption? RemoveData { get; set; }
    // The wizard's branding and welcome page (0.6.14): all optional.
    /// <summary>The end of the title drawn in the accent colour ("Management" → Server<b>Management</b>).</summary>
    [DataMember(Name = "titleAccent")] public string TitleAccent { get; set; } = "";
    /// <summary>The terminal prompt under the title in the rail ("darkcipher0x@servers:~$").</summary>
    [DataMember(Name = "prompt")] public string Prompt { get; set; } = "";
    /// <summary>The paragraph under the welcome heading.</summary>
    [DataMember(Name = "intro")] public string Intro { get; set; } = "";
    /// <summary>Up to four cards on the welcome page.</summary>
    [DataMember(Name = "highlights")] public List<Highlight> Highlights { get; set; } = new();
    /// <summary>The badge at the bottom of the rail ("Post-quantum protected"); empty = none.</summary>
    [DataMember(Name = "badge")] public string Badge { get; set; } = "";
    [DataMember(Name = "builtBy")] public string BuiltBy { get; set; } = "Built by DarkCipher0x at DarkCipher Systems";
    /// <summary>Disk space the app needs, for the checks page (MB).</summary>
    [DataMember(Name = "diskMb")] public int DiskMb { get; set; } = 400;
    /// <summary>The oldest Windows build the app supports (17763 = Windows 10 1809).</summary>
    [DataMember(Name = "minBuild")] public int MinBuild { get; set; } = 17763;
    /// <summary>The line under "… is installed" on the last page.</summary>
    [DataMember(Name = "doneNote")] public string DoneNote { get; set; } = "";

    public static SetupConfig Load(string folder)
    {
        var path = Path.Combine(folder, "setup-app.json");
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(File.ReadAllText(path)));
        var c = (SetupConfig?)new DataContractJsonSerializer(typeof(SetupConfig)).ReadObject(stream) ?? new SetupConfig();
        // The JSON reader skips constructors and initialisers: anything missing from the file arrives null.
        c.Brand ??= "DARKCIPHER SYSTEMS"; c.Title ??= ""; c.Tagline ??= ""; c.Website ??= ""; c.DataNote ??= "";
        c.Options ??= new();
        c.TitleAccent ??= ""; c.Prompt ??= ""; c.Intro ??= ""; c.Badge ??= ""; c.DoneNote ??= "";
        c.BuiltBy ??= "Built by DarkCipher0x at DarkCipher Systems";
        c.Highlights ??= new();
        foreach (var h in c.Highlights) { h.Title ??= ""; h.Detail ??= ""; }
        c.Highlights.RemoveAll(h => h.Title.Length == 0);
        if (c.DiskMb <= 0) c.DiskMb = 400;
        if (c.MinBuild <= 0) c.MinBuild = 17763;
        foreach (var o in c.Options) { o.Property ??= ""; o.Title ??= ""; o.Detail ??= ""; o.Package ??= ""; o.Detect ??= new(); foreach (var d in o.Detect) { d.Kind ??= ""; d.Key ??= ""; d.Value ??= ""; } }
        if (c.RemoveData is { } r) { r.Title ??= ""; r.Detail ??= ""; r.Properties ??= new(); }
        c.Options.RemoveAll(o => o.Property.Length == 0);
        return c;
    }
}

/// <summary>One switch: the MSI property it sets ("1" / "0"), whether it starts on, and how to tell it is already
/// installed (then it shows "Installed", starts off and leaves the property empty for the MSI to decide).</summary>
[DataContract]
public sealed class SetupOption
{
    [DataMember(Name = "property")] public string Property { get; set; } = "";
    [DataMember(Name = "title")] public string Title { get; set; } = "";
    [DataMember(Name = "detail")] public string Detail { get; set; } = "";
    [DataMember(Name = "default")] public bool Default { get; set; }
    [DataMember(Name = "detect")] public List<Detect> Detect { get; set; } = new();
    /// <summary>Optional: the Id of an ExePackage in the app's bundle chain (setup-app.packages.wxi) that installs this
    /// one when the MSI can't, e.g. an installer that must show its own wizard. The setup app sets the bundle variables
    /// Pkg_&lt;Id&gt;_Found (before detection) and Pkg_&lt;Id&gt;_Run ("1" = switched on and not installed; never in a quiet
    /// install) for the package's DetectCondition and InstallCondition.</summary>
    [DataMember(Name = "package")] public string Package { get; set; } = "";

    public bool IsInstalled() => Detect != null && Detect.Any(d => d.Found());
}

/// <summary>A welcome-page card.</summary>
[DataContract]
public sealed class Highlight
{
    [DataMember(Name = "title")] public string Title { get; set; } = "";
    [DataMember(Name = "detail")] public string Detail { get; set; } = "";
}

[DataContract]
public sealed class RemoveOption
{
    [DataMember(Name = "title")] public string Title { get; set; } = "";
    [DataMember(Name = "detail")] public string Detail { get; set; } = "";
    [DataMember(Name = "properties")] public List<string> Properties { get; set; } = new();
}

/// <summary>One way to find something installed: "appPath" (a packaged app's command under the user's App Paths),
/// "uninstall32" (a 32-bit uninstall entry), "hklm64" / "hkcu" (a key with a value), "file" (a path, %VARS% expanded).</summary>
[DataContract]
public sealed class Detect
{
    [DataMember(Name = "kind")] public string Kind { get; set; } = "";
    [DataMember(Name = "key")] public string Key { get; set; } = "";
    [DataMember(Name = "value")] public string Value { get; set; } = "";

    public bool Found()
    {
        try
        {
            switch (Kind)
            {
                case "appPath":
                    return HasValue(RegistryHive.CurrentUser, RegistryView.Default, @"Software\Microsoft\Windows\CurrentVersion\App Paths\" + Key, "")
                        || HasValue(RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\" + Key, "");
                case "uninstall32":
                    return HasValue(RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + Key, "DisplayVersion");
                case "hklm64":
                    return HasValue(RegistryHive.LocalMachine, RegistryView.Registry64, Key, Value);
                case "hkcu":
                    return HasValue(RegistryHive.CurrentUser, RegistryView.Default, Key, Value);
                case "file":
                    return File.Exists(Environment.ExpandEnvironmentVariables(Key));
                default:
                    return false;
            }
        }
        catch { return false; }
    }

    private static bool HasValue(RegistryHive hive, RegistryView view, string key, string value)
    {
        using var root = RegistryKey.OpenBaseKey(hive, view);
        using var k = root.OpenSubKey(key);
        var v = k?.GetValue(value) as string;
        return !string.IsNullOrWhiteSpace(v) && v != "0.0.0.0";
    }
}
