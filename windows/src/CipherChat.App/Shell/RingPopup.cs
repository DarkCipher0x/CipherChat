using System.IO;
using System.Media;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using CipherChat.Engine;

namespace CipherChat.App.Shell;

/// <summary>
/// An incoming call, shown natively (no browser engine runs until it's answered): a small window in the corner of the
/// screen in the DarkCipher Systems theme, a ringtone made in memory, and a flashing taskbar button.
/// </summary>
public static class RingPopup
{
    private static Window? _win;
    private static string? _call;
    private static SoundPlayer? _tone;
    private static MemoryStream? _wav;

    public static void Show(MainWindow main, IncomingCall inc)
    {
        Stop(null);
        var room = main.Session.Engine?.RoomById(inc.Room);
        var w = new Window
        {
            WindowStyle = WindowStyle.None, ResizeMode = ResizeMode.NoResize, Topmost = true, ShowInTaskbar = false,
            Width = 360, SizeToContent = SizeToContent.Height, ShowActivated = true, Title = "Incoming call",
        };
        w.SetResourceReference(Control.BackgroundProperty, "Surface2");
        w.SetResourceReference(Control.BorderBrushProperty, "Accent");
        w.BorderThickness = new Thickness(1);
        var panel = new StackPanel { Margin = new Thickness(16) };
        TextBlock Line(string text, string brush, double size, bool bold = false)
        {
            var t = new TextBlock { Text = text, FontSize = size, TextWrapping = TextWrapping.Wrap, FontWeight = bold ? FontWeights.SemiBold : FontWeights.Normal };
            t.SetResourceReference(TextBlock.ForegroundProperty, brush);
            t.SetResourceReference(TextBlock.FontFamilyProperty, "MonoFont");
            panel.Children.Add(t);
            return t;
        }
        Line(inc.From, "FgStrong", 18, bold: true);
        Line((inc.Media == "video" ? "video call" : "voice call") + " · " + (room?.Label(main.Session.Engine!.MyUser) ?? "a room") +
             (inc.People.Count > 2 ? " · " + inc.People.Count + " people" : ""), "Muted", 12).Margin = new Thickness(0, 4, 0, 2);
        Line("ML-KEM-1024 + X25519 · end-to-end encrypted", "Accent", 11).Margin = new Thickness(0, 0, 0, 12);
        var row = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var decline = new Button { Content = "Decline", Margin = new Thickness(0, 0, 8, 0) };
        decline.SetResourceReference(FrameworkElement.StyleProperty, "DangerButton");
        decline.Click += (_, _) => { main.Session.Engine?.Calls.Decline(inc); Stop(null); };
        var answer = new Button { Content = "Answer", IsDefault = true };
        answer.SetResourceReference(FrameworkElement.StyleProperty, "PrimaryButton");
        answer.Click += (_, _) => { Stop(null); CallWindow.Answer(main, inc); };
        row.Children.Add(decline);
        row.Children.Add(answer);
        panel.Children.Add(row);
        w.Content = panel;
        var area = SystemParameters.WorkArea;
        w.Loaded += (_, _) => { w.Left = area.Right - w.ActualWidth - 20; w.Top = area.Bottom - w.ActualHeight - 20; };
        w.Show();
        _win = w; _call = inc.Call;
        Flash(main);
        try
        {
            _wav = Ringtone();
            _tone = new SoundPlayer(_wav);
            _tone.PlayLooping();
        }
        catch (InvalidOperationException) { _tone = null; }
    }

    public static void Stop(string? call)
    {
        if (call is not null && call != _call) return;
        _tone?.Stop(); _tone?.Dispose(); _tone = null;
        _wav?.Dispose(); _wav = null;
        _win?.Close(); _win = null; _call = null;
    }

    /// <summary>Two soft rising tones (660 then 880 Hz) and a pause: 2 seconds, 16-bit mono PCM.</summary>
    private static MemoryStream Ringtone()
    {
        const int rate = 22050;
        var samples = new short[rate * 2];
        void Tone(double at, double hz)
        {
            var start = (int)(at * rate);
            var len = (int)(0.2 * rate);
            for (var i = 0; i < len; i++)
            {
                var env = Math.Min(1, i / (0.03 * rate)) * Math.Exp(-4.0 * i / len);
                samples[start + i] = (short)(Math.Sin(2 * Math.PI * hz * i / rate) * env * 0.25 * short.MaxValue);
            }
        }
        Tone(0, 660);
        Tone(0.22, 880);
        var ms = new MemoryStream();
        using (var bw = new BinaryWriter(ms, System.Text.Encoding.ASCII, leaveOpen: true))
        {
            bw.Write("RIFF"u8.ToArray()); bw.Write(36 + samples.Length * 2); bw.Write("WAVE"u8.ToArray());
            bw.Write("fmt "u8.ToArray()); bw.Write(16); bw.Write((short)1); bw.Write((short)1); bw.Write(rate); bw.Write(rate * 2); bw.Write((short)2); bw.Write((short)16);
            bw.Write("data"u8.ToArray()); bw.Write(samples.Length * 2);
            foreach (var s in samples) bw.Write(s);
        }
        ms.Position = 0;
        return ms;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FlashInfo { public uint cbSize; public IntPtr hwnd; public uint dwFlags; public uint uCount; public uint dwTimeout; }

    [DllImport("user32.dll")]
    private static extern bool FlashWindowEx(ref FlashInfo info);

    private static void Flash(Window w)
    {
        var info = new FlashInfo { hwnd = new WindowInteropHelper(w).Handle, dwFlags = 3 | 12, uCount = 0, dwTimeout = 0 };   // all, until foreground
        info.cbSize = (uint)Marshal.SizeOf(info);
        FlashWindowEx(ref info);
    }
}
