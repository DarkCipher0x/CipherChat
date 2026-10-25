using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows;

namespace CipherChat.App.Shell;

/// <summary>
/// The text size setting for this PC (Settings, or Ctrl+= / Ctrl+- / Ctrl+0): scales the chat's text sizes (the theme's
/// Fs* sizes for the log, input, sidebar and captions) from their theme values; window chrome keeps its size. Kept in
/// %LOCALAPPDATA%\CipherChat\display.json - one number, nothing secret - so it applies before sign-in too.
/// </summary>
public static class TextSize
{
    public static readonly int[] Steps = [90, 100, 110, 125, 140, 160, 180, 200];
    private static readonly string[] Keys = ["FsMicro", "FsCaption", "FsSmall", "FsMeta", "FsBody", "FsControl", "FsInput", "FsConsole", "FsCode"];
    private static readonly Dictionary<string, double> Base = new();
    private static string File => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CipherChat", "display.json");

    public static int Percent { get; private set; } = 100;
    public static double Factor => Percent / 100.0;
    public static event Action? Changed;

    public static void Load()
    {
        var p = 100;
        try
        {
            if (System.IO.File.Exists(File) && JsonNode.Parse(System.IO.File.ReadAllText(File))?["textSize"] is JsonValue v && v.TryGetValue<int>(out var n)) p = n;
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException) { /* default size */ }
        Apply(Steps.Contains(p) ? p : 100);
    }

    public static void Set(int percent)
    {
        if (!Steps.Contains(percent) || percent == Percent) return;
        Apply(percent);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(File)!);
            System.IO.File.WriteAllText(File, new JsonObject { ["textSize"] = percent }.ToJsonString());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* applies for this run only */ }
        Changed?.Invoke();
    }

    /// <summary>One step bigger (+1) or smaller (-1); 0 resets to 100%.</summary>
    public static void Step(int dir)
    {
        if (dir == 0) { Set(100); return; }
        var i = Array.IndexOf(Steps, Percent) + dir;
        if (i >= 0 && i < Steps.Length) Set(Steps[i]);
    }

    private static void Apply(int percent)
    {
        var res = Application.Current.Resources;
        foreach (var k in Keys)
        {
            if (!Base.ContainsKey(k) && res[k] is double d) Base[k] = d;       // the theme's own value, before any override
            if (Base.TryGetValue(k, out var b)) res[k] = Math.Round(b * percent / 100.0, 1);
        }
        Percent = percent;
    }
}
