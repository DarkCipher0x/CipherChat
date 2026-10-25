using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Shell;

namespace CipherChat.Ui;

/// <summary>
/// The DarkCipher Systems window frame: no Windows title bar, a 40 px top bar of the app's own
/// (brand, status, actions) with Fluent caption buttons, Windows 11 rounded corners and a dark border, snap layouts on
/// the maximise button, and a maximised window kept on screen. Windows draw their bar with <see cref="Bar"/> (or in
/// XAML with the ChromeButton styles) and call <see cref="Apply"/>.
/// </summary>
public static class WindowFrame
{
    public const double BarHeight = 40;

    private const string GlyphMin = "", GlyphMax = "", GlyphRestore = "", GlyphClose = "";

    /// <summary>
    /// Takes over the window's frame. root = the element holding everything (its margin keeps a maximised window on the
    /// screen); captions = where the caption buttons go (the right end of the bar).
    /// </summary>
    public static void Apply(Window w, FrameworkElement root, Panel captions, string closeTip = "Close")
    {
        var resizable = w.ResizeMode is ResizeMode.CanResize or ResizeMode.CanResizeWithGrip;
        WindowChrome.SetWindowChrome(w, new WindowChrome
        {
            CaptionHeight = BarHeight, ResizeBorderThickness = resizable ? new Thickness(6) : new Thickness(0),
            GlassFrameThickness = new Thickness(0), CornerRadius = new CornerRadius(0), UseAeroCaptionButtons = false,
        });
        Button? max = null;
        captions.Children.Clear();
        if (w.ResizeMode != ResizeMode.NoResize)
            captions.Children.Add(Caption(GlyphMin, "Minimise", "ChromeButton", () => w.WindowState = WindowState.Minimized));
        if (resizable)
        {
            max = Caption(GlyphMax, "Maximise", "ChromeButton", () => Toggle(w));
            captions.Children.Add(max);
        }
        captions.Children.Add(Caption(GlyphClose, closeTip, "ChromeCloseButton", w.Close));
        WindowChrome.SetIsHitTestVisibleInChrome(captions, true);

        void Fit()
        {
            var maxed = w.WindowState == WindowState.Maximized;
            root.Margin = maxed ? MaximisedInset(w) : new Thickness(0);
            if (max is not null) { max.Content = maxed ? GlyphRestore : GlyphMax; max.ToolTip = maxed ? "Restore down" : "Maximise"; }
        }
        w.StateChanged += (_, _) => Fit();
        w.SourceInitialized += (_, _) =>
        {
            var hwnd = new WindowInteropHelper(w).Handle;
            Dwm(hwnd, w);
            if (max is not null) HwndSource.FromHwnd(hwnd)?.AddHook(new SnapHook(max, () => Toggle(w)).Proc);
            Fit();
        };
        w.DpiChanged += (_, _) => Fit();
    }

    /// <summary>
    /// A ready-made bar: the brand mark, "lead" in the brand colour then "tail" (e.g. "CipherChat" + " by DarkCipher
    /// Systems", or a dialog's title), optional status/actions on the right, then the caption buttons.
    /// </summary>
    public static Border Bar(string? lead, string tail, out StackPanel captions, UIElement? right = null, bool mark = true, Window? titleOf = null)
    {
        var dock = new DockPanel { LastChildFill = false };
        var left = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(14, 0, 0, 0) };
        if (mark)
        {
            var m = new ContentControl { Width = 18, Height = 18, Margin = new Thickness(0, 0, 10, 0), IsTabStop = false, Focusable = false };
            m.SetResourceReference(Control.TemplateProperty, "BrandMark");
            left.Children.Add(m);
        }
        var l = new TextBlock { Text = lead ?? "", FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis };
        if (titleOf is not null) l.SetBinding(TextBlock.TextProperty, new System.Windows.Data.Binding(nameof(Window.Title)) { Source = titleOf });   // follows the window's title
        l.SetResourceReference(TextBlock.ForegroundProperty, mark ? "Brand" : "HeaderFg");
        l.SetResourceReference(TextBlock.FontSizeProperty, "FsBase");
        left.Children.Add(l);
        if (tail.Length > 0)
        {
            var t = new TextBlock { Text = tail, VerticalAlignment = VerticalAlignment.Center };
            t.SetResourceReference(TextBlock.ForegroundProperty, "HeaderMuted");
            t.SetResourceReference(TextBlock.FontSizeProperty, "FsBase");
            left.Children.Add(t);
        }
        DockPanel.SetDock(left, Dock.Left);
        dock.Children.Add(left);
        captions = new StackPanel { Orientation = Orientation.Horizontal };
        DockPanel.SetDock(captions, Dock.Right);
        dock.Children.Add(captions);
        if (right is not null)
        {
            DockPanel.SetDock(right, Dock.Right);
            dock.Children.Add(right);
        }
        var bar = new Border { Height = BarHeight, BorderThickness = new Thickness(0, 0, 0, 1), Child = dock };
        bar.SetResourceReference(Border.BackgroundProperty, "HeaderBg");
        bar.SetResourceReference(Border.BorderBrushProperty, "Line");
        return bar;
    }

    /// <summary>Puts content under a <see cref="Bar"/> and applies the frame: the usual way for windows built in code.</summary>
    /// <remarks>A null lead shows the window's title (and follows it when it changes).</remarks>
    public static void Frame(Window w, UIElement content, string? lead, string tail, UIElement? right = null, bool mark = true, string closeTip = "Close")
    {
        var root = new DockPanel();
        var bar = Bar(lead, tail, out var captions, right, mark, lead is null ? w : null);
        DockPanel.SetDock(bar, Dock.Top);
        root.Children.Add(bar);
        root.Children.Add(content);
        w.Content = root;
        Apply(w, root, captions, closeTip);
    }

    private static Button Caption(string glyph, string tip, string style, Action click)
    {
        var b = new Button { Content = glyph, ToolTip = tip };
        b.SetResourceReference(FrameworkElement.StyleProperty, style);
        AutomationName(b, tip);
        b.Click += (_, _) => click();
        return b;
    }

    private static void AutomationName(DependencyObject d, string name) => System.Windows.Automation.AutomationProperties.SetName(d, name);

    private static void Toggle(Window w) => w.WindowState = w.WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    // A maximised frameless window reaches past the screen by the resize frame; this inset brings its content back.
    private static Thickness MaximisedInset(Window w)
    {
        var dpi = VisualTreeHelper.GetDpi(w);
        double px = GetSystemMetrics(SM_CXSIZEFRAME) + GetSystemMetrics(SM_CXPADDEDBORDER);
        double py = GetSystemMetrics(SM_CYSIZEFRAME) + GetSystemMetrics(SM_CXPADDEDBORDER);
        if (px <= 0) px = 8;
        if (py <= 0) py = 8;
        return new Thickness(px / dpi.DpiScaleX, py / dpi.DpiScaleY, px / dpi.DpiScaleX, py / dpi.DpiScaleY);
    }

    // Windows 11: rounded corners, a dark title area for the system menu and a border in the theme's line colour.
    // Older Windows ignores the attributes it doesn't know.
    private static void Dwm(IntPtr hwnd, Window w)
    {
        int on = 1, round = 2;
        _ = DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref on, sizeof(int));
        _ = DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, ref round, sizeof(int));
        if (w.TryFindResource("LineStrong") is SolidColorBrush line)
        {
            var c = line.Color;
            int colorref = c.R | (c.G << 8) | (c.B << 16);
            _ = DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, ref colorref, sizeof(int));
        }
    }

    // Snap layouts: Windows shows its layout flyout only when the maximise button answers WM_NCHITTEST as
    // HTMAXBUTTON, so the hook does that, draws the hover itself (WPF no longer sees the mouse there) and turns the
    // non-client click into the toggle.
    private sealed class SnapHook(Button max, Action toggle)
    {
        private bool _down;

        public IntPtr Proc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
        {
            switch (msg)
            {
                case WM_NCHITTEST:
                    if (Over(lParam)) { Hot(true); handled = true; return HTMAXBUTTON; }
                    Hot(false);
                    break;
                case WM_NCMOUSELEAVE:
                    Hot(false); _down = false;
                    break;
                case WM_NCLBUTTONDOWN:
                    if (wParam == HTMAXBUTTON) { _down = true; handled = true; }
                    break;
                case WM_NCLBUTTONUP:
                    if (wParam == HTMAXBUTTON) { handled = true; if (_down) { _down = false; Hot(false); toggle(); } }
                    break;
            }
            return IntPtr.Zero;
        }

        private void Hot(bool on)
        {
            var v = on ? "hot" : null;
            if (!Equals(max.Tag, v)) max.Tag = v;
        }

        private bool Over(IntPtr lParam)
        {
            if (!max.IsVisible || PresentationSource.FromVisual(max) is null) return false;
            var l = lParam.ToInt64();
            var x = (short)(l & 0xFFFF);
            var y = (short)((l >> 16) & 0xFFFF);
            var tl = max.PointToScreen(new Point(0, 0));
            var br = max.PointToScreen(new Point(max.ActualWidth, max.ActualHeight));
            return x >= tl.X && x < br.X && y >= tl.Y && y < br.Y;
        }
    }

    private const int WM_NCHITTEST = 0x0084, WM_NCLBUTTONDOWN = 0x00A1, WM_NCLBUTTONUP = 0x00A2, WM_NCMOUSELEAVE = 0x02A2;
    private const int HTMAXBUTTON = 9;
    private const int SM_CXSIZEFRAME = 32, SM_CYSIZEFRAME = 33, SM_CXPADDEDBORDER = 92;
    private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20, DWMWA_WINDOW_CORNER_PREFERENCE = 33, DWMWA_BORDER_COLOR = 34;

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int index);

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
}
