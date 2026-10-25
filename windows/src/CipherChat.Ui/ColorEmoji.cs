using System.Globalization;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace CipherChat.Ui;

/// <summary>
/// Colour emoji for WPF. WPF draws every font in one colour, so Windows' own emoji font (Segoe UI Emoji) comes out as
/// flat black-and-white outlines. DirectWrite and Direct2D (both part of Windows) draw its real colour glyphs: each emoji
/// is drawn once into a small bitmap, cached, and shown inline as a picture. Nothing is fetched or bundled - it is the
/// same Windows emoji font every other Windows app shows, drawn in colour. If Direct2D isn't available the text is shown
/// as it always was. UI thread only (single-threaded Direct2D factory, plain dictionary cache).
/// </summary>
public static class ColorEmoji
{
    private const int Px = 64;                                   // bitmap size; shown smaller, so it stays sharp at 200% scaling
    private static readonly Dictionary<string, BitmapSource?> Cache = new(StringComparer.Ordinal);
    private static IntPtr _d2d, _dwrite, _wic, _format;
    private static bool _broken;

    /// <summary>Splits text into plain runs and single emoji (whole grapheme clusters: ZWJ families, flags, skin tones).</summary>
    public static IEnumerable<(string Text, bool IsEmoji)> Split(string s)
    {
        var plain = new System.Text.StringBuilder();
        var e = StringInfo.GetTextElementEnumerator(s);
        while (e.MoveNext())
        {
            var el = e.GetTextElement();
            if (IsEmoji(el))
            {
                if (plain.Length > 0) { yield return (plain.ToString(), false); plain.Clear(); }
                yield return (el, true);
            }
            else plain.Append(el);
        }
        if (plain.Length > 0) yield return (plain.ToString(), false);
    }

    public static bool HasEmoji(string s) => Split(s).Any(p => p.IsEmoji);

    /// <summary>True when the text is only emoji (1-3) and spaces: chat shows those larger.</summary>
    public static bool IsJumbo(string s)
    {
        var n = 0;
        foreach (var (t, isEmoji) in Split(s)) { if (isEmoji) n++; else if (t.Trim().Length > 0) return false; }
        return n is >= 1 and <= 3;
    }

    /// <summary>A grapheme cluster that shows as an emoji: emoji-presentation characters, anything with VS16 (U+FE0F),
    /// keycaps and flags. Text-style symbols (arrows, ©, the terminal's own ☺ ↩ ✎ glyphs) stay text.</summary>
    public static bool IsEmoji(string el)
    {
        if (el.Length == 0) return false;
        if (el.Contains('️') || el.Contains('⃣')) return el.Length > 1;
        var cp = char.IsSurrogatePair(el, 0) || !char.IsSurrogate(el[0]) ? char.ConvertToUtf32(el, 0) : 0;
        if (cp >= 0x1F1E6 && cp <= 0x1F1FF) return true;                  // regional indicators (flags)
        if (cp >= 0x1F300 && cp <= 0x1FAFF) return true;                  // pictographs, emoticons, transport, supplemental
        if (cp is 0x1F004 or 0x1F0CF or 0x1F18E or (>= 0x1F191 and <= 0x1F19A) or 0x1F201 or 0x1F21A or 0x1F22F
            or (>= 0x1F232 and <= 0x1F236) or (>= 0x1F238 and <= 0x1F23A) or 0x1F250 or 0x1F251) return true;
        return BmpEmoji.Contains(cp);
    }

    // BMP characters whose default presentation is emoji (Unicode Emoji_Presentation=Yes below U+10000)
    private static readonly HashSet<int> BmpEmoji = new()
    {
        0x231A, 0x231B, 0x23E9, 0x23EA, 0x23EB, 0x23EC, 0x23F0, 0x23F3, 0x25FD, 0x25FE, 0x2614, 0x2615,
        0x2648, 0x2649, 0x264A, 0x264B, 0x264C, 0x264D, 0x264E, 0x264F, 0x2650, 0x2651, 0x2652, 0x2653, 0x267F, 0x2693,
        0x26A1, 0x26AA, 0x26AB, 0x26BD, 0x26BE, 0x26C4, 0x26C5, 0x26CE, 0x26D4, 0x26EA, 0x26F2, 0x26F3, 0x26F5, 0x26FA,
        0x26FD, 0x2705, 0x270A, 0x270B, 0x2728, 0x274C, 0x274E, 0x2753, 0x2754, 0x2755, 0x2757, 0x2795, 0x2796, 0x2797,
        0x27B0, 0x27BF, 0x2B1B, 0x2B1C, 0x2B50, 0x2B55,
    };

    /// <summary>The emoji as a colour picture, or null (then show it as text).</summary>
    public static BitmapSource? Bitmap(string emoji)
    {
        if (Cache.TryGetValue(emoji, out var b)) return b;
        b = _broken ? null : Render(emoji);
        if (Cache.Count < 4000) Cache[emoji] = b;
        return b;
    }

    /// <summary>An inline picture of the emoji, <paramref name="scale"/> times the surrounding text's size (it follows
    /// the text size setting live); its Tag holds the emoji text (for copying).</summary>
    public static FrameworkElement Element(string emoji, double scale = 1.3)
    {
        var bmp = Bitmap(emoji);
        FrameworkElement e = bmp is null
            ? new TextBlock { Text = emoji, FontFamily = new FontFamily("Segoe UI Emoji") }
            : new Image { Source = bmp, Stretch = Stretch.Uniform };
        e.Tag = emoji;
        if (e is Image)
        {
            RenderOptions.SetBitmapScalingMode(e, BitmapScalingMode.HighQuality);
            e.SetBinding(FrameworkElement.WidthProperty, SizeBinding(scale));
            e.SetBinding(FrameworkElement.HeightProperty, SizeBinding(scale));
        }
        System.Windows.Automation.AutomationProperties.SetName(e, emoji);
        return e;
    }

    private static Binding SizeBinding(double scale) =>
        new() { RelativeSource = RelativeSource.Self, Path = new PropertyPath(TextElement.FontSizeProperty), Converter = Times.Instance, ConverterParameter = scale };

    private sealed class Times : IValueConverter
    {
        public static readonly Times Instance = new();
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => Math.Round((double)value * (double)parameter);
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
    }

    /// <summary>Inlines for a TextBlock or Paragraph: plain runs as text, emoji as colour pictures sitting on the baseline.</summary>
    public static IEnumerable<Inline> Inlines(string text, double scale = 1.3)
    {
        foreach (var (t, isEmoji) in Split(text))
        {
            if (!isEmoji)
            {
                var lines = t.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
                for (var i = 0; i < lines.Length; i++)
                {
                    if (i > 0) yield return new LineBreak();
                    if (lines[i].Length > 0) yield return new Run(lines[i]);
                }
                continue;
            }
            yield return new InlineUIContainer(Element(t, scale)) { BaselineAlignment = BaselineAlignment.Center };
        }
    }

    /// <summary>Sets a TextBlock's text, with any emoji in colour.</summary>
    public static void SetText(TextBlock t, string? text, double scale = 1.3)
    {
        text ??= "";
        if (!HasEmoji(text)) { t.Text = text; return; }
        t.Inlines.Clear();
        t.Inlines.AddRange(Inlines(text, scale).ToList());
    }

    /// <summary>Content for a button, menu item or label that may hold emoji (picker cells, reaction chips).</summary>
    public static object Content(string text, double scale = 1.3)
    {
        if (!HasEmoji(text)) return text;
        var tb = new TextBlock { VerticalAlignment = VerticalAlignment.Center };
        tb.Inlines.AddRange(Inlines(text, scale).ToList());
        return tb;
    }

    // ------------------------------------------------------------------------------------------- Direct2D / DirectWrite
    private static BitmapSource? Render(string emoji)
    {
        IntPtr bmp = IntPtr.Zero, rt = IntPtr.Zero, brush = IntPtr.Zero;
        try
        {
            if (_d2d == IntPtr.Zero && !Init()) return null;
            var fmt = WicPbgra;
            Check(Fn<WicCreateBitmap>(_wic, 17)(_wic, Px, Px, ref fmt, 2 /* WICBitmapCacheOnLoad */, out bmp));
            var props = new RtProps { Type = 1 /* software */, Format = 87 /* B8G8R8A8 */, Alpha = 1 /* premultiplied */ };
            Check(Fn<D2dCreateWicRt>(_d2d, 13)(_d2d, bmp, ref props, out rt));
            var black = new ColorF { A = 1 };
            Check(Fn<CreateBrush>(rt, 8)(rt, ref black, IntPtr.Zero, out brush));
            Fn<SetMode>(rt, 34)(rt, 2);                                                   // grayscale text antialiasing
            Fn<Begin>(rt, 48)(rt);
            var clear = new ColorF();
            Fn<ClearFn>(rt, 47)(rt, ref clear);
            var rect = new RectF { R = Px, B = Px };
            Fn<DrawTextFn>(rt, 27)(rt, emoji, (uint)emoji.Length, _format, ref rect, brush, 4 /* ENABLE_COLOR_FONT */, 0);
            Check(Fn<End>(rt, 49)(rt, out _, out _));
            var px = new byte[Px * Px * 4];
            Check(Fn<CopyPixelsFn>(bmp, 7)(bmp, IntPtr.Zero, Px * 4, (uint)px.Length, px));
            if (!px.Where((v, i) => i % 4 == 3).Any(a => a != 0)) return null;           // nothing drawn: not in the font
            var src = BitmapSource.Create(Px, Px, 96, 96, PixelFormats.Pbgra32, null, px, Px * 4);
            src.Freeze();
            return src;
        }
        catch (Exception ex) when (ex is COMException or EntryPointNotFoundException or DllNotFoundException or MarshalDirectiveException)
        {
            _broken = true;
            return null;
        }
        finally { Release(brush); Release(rt); Release(bmp); }
    }

    private static bool Init()
    {
        try
        {
            var iidD2d = new Guid("06152247-6f50-465a-9245-118bfd3b6007");
            Check(D2D1CreateFactory(0, ref iidD2d, IntPtr.Zero, out _d2d));
            var iidDw = new Guid("b859ee5a-d838-4b5b-a2e8-1adc7d93db48");
            Check(DWriteCreateFactory(0, ref iidDw, out _dwrite));
            var clsid = new Guid("cacaf262-9370-4615-a13b-9f5539da4c0a");
            var iidWic = new Guid("ec5ec8a9-c395-4314-9c77-54d7a935ff70");
            Check(CoCreateInstance(ref clsid, IntPtr.Zero, 1, ref iidWic, out _wic));
            Check(Fn<CreateTextFormat>(_dwrite, 15)(_dwrite, "Segoe UI Emoji", IntPtr.Zero, 400, 0, 5, Px * 0.74f, "en-us", out _format));
            Check(Fn<SetAlign>(_format, 3)(_format, 2));                                // text alignment: centre
            Check(Fn<SetAlign>(_format, 4)(_format, 2));                                // paragraph alignment: centre
            return true;
        }
        catch (Exception ex) when (ex is COMException or EntryPointNotFoundException or DllNotFoundException)
        {
            _broken = true;
            return false;
        }
    }

    private static Guid WicPbgra => new("6fddc324-4e03-4bfe-b185-3d77768dc910");

    private static void Check(int hr) { if (hr < 0) throw new COMException("Direct2D", hr); }

    private static void Release(IntPtr p) { if (p != IntPtr.Zero) Marshal.Release(p); }

    private static T Fn<T>(IntPtr obj, int slot) where T : Delegate =>
        Marshal.GetDelegateForFunctionPointer<T>(Marshal.ReadIntPtr(Marshal.ReadIntPtr(obj), slot * IntPtr.Size));

    [StructLayout(LayoutKind.Sequential)] private struct ColorF { public float R, G, B, A; }
    [StructLayout(LayoutKind.Sequential)] private struct RectF { public float L, T, R, B; }
    [StructLayout(LayoutKind.Sequential)] private struct RtProps { public int Type, Format, Alpha; public float DpiX, DpiY; public int Usage, MinLevel; }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int WicCreateBitmap(IntPtr self, uint w, uint h, ref Guid format, int option, out IntPtr bitmap);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int D2dCreateWicRt(IntPtr self, IntPtr bitmap, ref RtProps props, out IntPtr target);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int CreateBrush(IntPtr self, ref ColorF color, IntPtr props, out IntPtr brush);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate void SetMode(IntPtr self, int mode);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate void Begin(IntPtr self);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate void ClearFn(IntPtr self, ref ColorF color);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int End(IntPtr self, out ulong tag1, out ulong tag2);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    private delegate void DrawTextFn(IntPtr self, [MarshalAs(UnmanagedType.LPWStr)] string text, uint length, IntPtr format, ref RectF rect, IntPtr brush, int options, int measuring);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int CopyPixelsFn(IntPtr self, IntPtr rect, uint stride, uint size, [Out] byte[] buffer);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    private delegate int CreateTextFormat(IntPtr self, [MarshalAs(UnmanagedType.LPWStr)] string family, IntPtr collection, int weight, int style, int stretch, float size, [MarshalAs(UnmanagedType.LPWStr)] string locale, out IntPtr format);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int SetAlign(IntPtr self, int alignment);

    [DllImport("d2d1.dll", ExactSpelling = true)] private static extern int D2D1CreateFactory(int type, ref Guid riid, IntPtr options, out IntPtr factory);
    [DllImport("dwrite.dll", ExactSpelling = true)] private static extern int DWriteCreateFactory(int type, ref Guid iid, out IntPtr factory);
    [DllImport("ole32.dll", ExactSpelling = true)] private static extern int CoCreateInstance(ref Guid clsid, IntPtr outer, uint context, ref Guid iid, out IntPtr obj);
}
