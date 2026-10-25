using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using Microsoft.Win32;
using WixToolset.BootstrapperApplicationApi;
using Path = System.Windows.Shapes.Path;

namespace DarkCipher.Setup;

/// <summary>
/// The setup wizard (DarkCipher design system; 0.6.14 redesign, DarkCipher0x: "something fancy like the ParallelPath
/// installer, but with the DarkCipher0x branding"). Left: the brand rail (logo, the two-tone title, the darkcipher0x
/// prompt, the steps with their progress, the badge, the version and who built it). Right: one page at a time with its
/// heading, and Cancel / Back / Next along the bottom.
/// Install: Welcome, Licence, Options, Checks, Install, Done. Update (an older version is installed): Welcome, Options,
/// Checks, Update, Done. Maintenance (this version is installed): Choose (repair or uninstall), Confirm, Working, Done.
/// Everything app-specific comes from <see cref="SetupConfig"/>; Burn and the MSI do the installing.
/// </summary>
internal sealed class SetupWindow : Window
{
    private readonly SetupApplication _ba;
    private readonly SetupConfig _c;

    // Layout parts
    private readonly StackPanel _stepList = new() { Margin = new Thickness(0, 34, 0, 0) };
    private readonly TextBlock _heading = new() { TextWrapping = TextWrapping.Wrap };
    private readonly TextBlock _sub = new() { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 0) };
    private readonly ContentControl _host = new() { Focusable = false };
    private readonly DockPanel _footer = new() { LastChildFill = false };

    // Controls kept across pages
    private readonly TextBox _folder = new() { MinWidth = 300, VerticalContentAlignment = VerticalAlignment.Center };
    private readonly ProgressBar _bar = new() { Minimum = 0, Maximum = 100, Height = 8 };
    private readonly TextBlock _percent = new() { FontSize = 40, FontWeight = FontWeights.SemiBold };
    private readonly TextBlock _progressText = new() { TextWrapping = TextWrapping.Wrap };
    private readonly CheckBox _launch = new() { IsChecked = true };
    private readonly CheckBox _removeData = new();
    private readonly CheckBox _accept = new();
    private readonly RadioButton _repair = new() { GroupName = "maint", IsChecked = true };
    private readonly RadioButton _uninstall = new() { GroupName = "maint" };
    private readonly Dictionary<SetupOption, CheckBox> _switches = new();

    private bool _detected, _busy, _cancel, _upgrading, _animate = true;
    private LaunchAction _action = LaunchAction.Install;
    private string _error = "";
    private string[] _steps = Array.Empty<string>();
    private Button? _licenceNext;   // the licence page's Next: enabled while "I accept" is ticked

    public SetupWindow(SetupApplication ba)
    {
        _ba = ba;
        _c = ba.Config;
        _ = System.IO.Packaging.PackUriHelper.UriSchemePack;   // registers pack:// before the theme loads (no Application object here)
        Resources.MergedDictionaries.Add((ResourceDictionary)Application.LoadComponent(new Uri("/DarkCipher.Setup;component/Theme.xaml", UriKind.Relative)));
        Title = (_c.Title.Length > 0 ? _c.Title : "Setup") + " Setup";
        Width = 940; Height = 620;
        WindowStyle = WindowStyle.None; ResizeMode = ResizeMode.CanMinimize;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        Background = R("Bg");
        BorderBrush = R("Line"); BorderThickness = new Thickness(1);
        UseLayoutRounding = true; SnapsToDevicePixels = true;
        FontFamily = (FontFamily)Resources["UiFont"]; FontSize = 14;
        TextOptions.SetTextFormattingMode(this, TextFormattingMode.Display);
        try { Icon = BitmapFrame.Create(new Uri(System.IO.Path.Combine(_ba.Folder, "logo.png"))); } catch { }
        SourceInitialized += (_, _) => RoundCorners();
        Closing += OnClosing;
        Content = Build();
        _heading.Foreground = R("FgStrong"); _heading.FontFamily = (FontFamily)Resources["DisplayFont"]; _heading.FontSize = 27; _heading.FontWeight = FontWeights.SemiBold;
        _sub.Foreground = R("FgDim"); _sub.FontSize = 14;
        _progressText.Foreground = R("FgDim");
        _percent.Foreground = R("FgStrong"); _percent.FontFamily = (FontFamily)Resources["DisplayFont"];
        _accept.Checked += (_, _) => { if (_licenceNext != null) _licenceNext.IsEnabled = true; };
        _accept.Unchecked += (_, _) => { if (_licenceNext != null) _licenceNext.IsEnabled = false; };
        ShowDetecting();
        Wire();
    }

    private Brush R(string key) => (Brush)Resources[key];

    // ---- layout -----------------------------------------------------------------------------------------------------

    private UIElement Build()
    {
        var root = new Grid { Background = R("Bg") };
        root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(264) });
        root.ColumnDefinitions.Add(new ColumnDefinition());
        root.Children.Add(BuildRail());

        var right = new Grid();
        right.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        right.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        right.RowDefinitions.Add(new RowDefinition());
        right.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        // Window buttons (the window is borderless, like the app's own)
        var chrome = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 8, 10, 0) };
        chrome.Children.Add(ChromeButton("—", "Minimise", () => WindowState = WindowState.Minimized));
        chrome.Children.Add(ChromeButton("✕", "Close", Close));
        right.Children.Add(chrome);
        var head = new StackPanel { Margin = new Thickness(44, 2, 44, 0) };
        head.Children.Add(_heading);
        head.Children.Add(_sub);
        Grid.SetRow(head, 1); right.Children.Add(head);
        _host.Margin = new Thickness(44, 22, 44, 14);
        Grid.SetRow(_host, 2); right.Children.Add(_host);
        var foot = new Border { BorderBrush = R("Line"), BorderThickness = new Thickness(0, 1, 0, 0), Padding = new Thickness(44, 16, 44, 18), Child = _footer };
        Grid.SetRow(foot, 3); right.Children.Add(foot);
        Grid.SetColumn(right, 1);
        root.Children.Add(right);
        // Drag the borderless window by its background (never from a button, box or text).
        root.MouseLeftButtonDown += (_, e) => { if (e.ButtonState == MouseButtonState.Pressed && !OnControl(e.OriginalSource as DependencyObject)) try { DragMove(); } catch { } };
        return root;
    }

    private Border BuildRail()
    {
        var rail = new Border { Background = R("Rail"), BorderBrush = R("Line"), BorderThickness = new Thickness(0, 0, 1, 0) };
        var dock = new DockPanel { Margin = new Thickness(28, 30, 22, 24) };

        var top = new StackPanel();
        var logo = new Image { Width = 58, Height = 58, HorizontalAlignment = HorizontalAlignment.Left };
        RenderOptions.SetBitmapScalingMode(logo, BitmapScalingMode.HighQuality);
        try { logo.Source = new BitmapImage(new Uri(System.IO.Path.Combine(_ba.Folder, "logo.png"))); } catch { }
        top.Children.Add(logo);
        top.Children.Add(new TextBlock { Text = _c.Brand, Foreground = R("Accent"), FontWeight = FontWeights.Bold, FontSize = 10.5, Margin = new Thickness(0, 18, 0, 2) });
        // The two-tone title (Server + Management in the accent), shrunk to fit rather than broken mid-word.
        var title = new TextBlock { FontFamily = (FontFamily)Resources["DisplayFont"], FontSize = 25, FontWeight = FontWeights.SemiBold };
        var accent = _c.TitleAccent.Length > 0 && _c.Title.EndsWith(_c.TitleAccent, StringComparison.Ordinal) ? _c.TitleAccent : "";
        title.Inlines.Add(new System.Windows.Documents.Run(_c.Title.Substring(0, _c.Title.Length - accent.Length)) { Foreground = R("FgStrong") });
        if (accent.Length > 0) title.Inlines.Add(new System.Windows.Documents.Run(accent) { Foreground = R("Accent") });
        top.Children.Add(new Viewbox { Stretch = Stretch.Uniform, StretchDirection = StretchDirection.DownOnly, HorizontalAlignment = HorizontalAlignment.Left, Child = title });
        if (_c.Prompt.Length > 0)
        {
            // The darkcipher0x prompt, with the app header's blinking block cursor.
            var prompt = new TextBlock { FontFamily = (FontFamily)Resources["MonoFont"], FontSize = 11.5, Foreground = R("Accent"), Margin = new Thickness(0, 4, 0, 0) };
            prompt.Inlines.Add(new System.Windows.Documents.Run(_c.Prompt + " setup "));
            var cursor = new System.Windows.Documents.Run("█") { Foreground = R("Accent") };
            prompt.Inlines.Add(cursor);
            var blink = new DoubleAnimationUsingKeyFrames { RepeatBehavior = RepeatBehavior.Forever, Duration = TimeSpan.FromSeconds(1.1) };
            blink.KeyFrames.Add(new DiscreteDoubleKeyFrame(1, KeyTime.FromTimeSpan(TimeSpan.Zero)));
            blink.KeyFrames.Add(new DiscreteDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(0.55))));
            var brush = new SolidColorBrush(((SolidColorBrush)R("Accent")).Color);
            cursor.Foreground = brush;
            if (SystemParameters.ClientAreaAnimation) brush.BeginAnimation(Brush.OpacityProperty, blink);
            top.Children.Add(prompt);
        }
        DockPanel.SetDock(top, Dock.Top);
        dock.Children.Add(top);

        var bottom = new StackPanel();
        if (_c.Badge.Length > 0)
        {
            var badge = new StackPanel { Orientation = Orientation.Horizontal };
            badge.Children.Add(new Path { Width = 11, Height = 13, Stretch = Stretch.Uniform, Fill = R("Accent"), VerticalAlignment = VerticalAlignment.Center,
                Data = Geometry.Parse("M 6,0 L 12,2.4 L 12,7 C 12,10.6 9.4,13.4 6,14.4 C 2.6,13.4 0,10.6 0,7 L 0,2.4 Z") });
            badge.Children.Add(new TextBlock { Text = _c.Badge, Foreground = R("Accent"), FontSize = 12, FontWeight = FontWeights.SemiBold, Margin = new Thickness(7, 0, 0, 0) });
            bottom.Children.Add(new Border { HorizontalAlignment = HorizontalAlignment.Left, BorderBrush = R("Accent"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(12), Padding = new Thickness(9, 3, 11, 3), Background = R("AccentSoft"), Child = badge });
        }
        bottom.Children.Add(new TextBlock { Text = "Version " + _ba.Format("[WixBundleVersion]"), Foreground = R("Muted"), FontSize = 12.5, Margin = new Thickness(0, 12, 0, 0) });
        if (_c.BuiltBy.Length > 0) bottom.Children.Add(new TextBlock { Text = _c.BuiltBy, Foreground = R("Muted"), FontSize = 12.5, TextWrapping = TextWrapping.Wrap });
        var links = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 0) };
        if (_c.Website.Length > 0) links.Children.Add(Link(_c.Website.Replace("https://", "").TrimEnd('/'), () => Open(_c.Website)));
        links.Children.Add(Link("Licence", () => Open(System.IO.Path.Combine(_ba.Folder, "LICENSE.txt")), left: links.Children.Count > 0 ? 14 : 0));
        bottom.Children.Add(links);
        DockPanel.SetDock(bottom, Dock.Bottom);
        dock.Children.Add(bottom);

        dock.Children.Add(_stepList);
        rail.Child = dock;
        return rail;
    }

    private Button ChromeButton(string glyph, string tip, Action click)
    {
        var b = new Button { Content = glyph, Style = (Style)Resources["Quiet"], ToolTip = tip, FontSize = 12, Padding = new Thickness(12, 6, 12, 6) };
        b.Click += (_, _) => click();
        return b;
    }

    private static bool OnControl(DependencyObject? d)
    {
        for (; d != null; d = d is Visual ? VisualTreeHelper.GetParent(d) : LogicalTreeHelper.GetParent(d))
            if (d is System.Windows.Controls.Primitives.ButtonBase or TextBox or System.Windows.Controls.Primitives.ScrollBar) return true;
        return false;
    }

    /// <summary>The step list: done ones ticked, the current one ringed with a dot, the rest dim.</summary>
    private void ShowSteps(int current)
    {
        _stepList.Children.Clear();
        for (int i = 0; i < _steps.Length; i++)
        {
            bool done = i < current, now = i == current;
            var row = new Grid { Height = 36 };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(32) });
            row.ColumnDefinitions.Add(new ColumnDefinition());
            var mark = new Grid { Width = 20, Height = 20, HorizontalAlignment = HorizontalAlignment.Left };
            mark.Children.Add(new Ellipse { Stroke = done || now ? R("Accent") : R("Line2"), StrokeThickness = 1.5, Fill = done ? R("Accent") : Brushes.Transparent });
            if (now) mark.Children.Add(new Ellipse { Width = 8, Height = 8, Fill = R("Accent") });
            if (done) mark.Children.Add(new Path { Data = Geometry.Parse("M 5.5,10.2 L 8.8,13.4 L 14.6,7"), Stroke = R("AccentFg"), StrokeThickness = 2, StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round, StrokeLineJoin = PenLineJoin.Round });
            row.Children.Add(mark);
            var label = new TextBlock { Text = _steps[i], VerticalAlignment = VerticalAlignment.Center, FontSize = 14,
                Foreground = now ? R("FgStrong") : done ? R("FgDim") : R("Muted"), FontWeight = now ? FontWeights.SemiBold : FontWeights.Normal };
            Grid.SetColumn(label, 1);
            row.Children.Add(label);
            _stepList.Children.Add(row);
        }
    }

    private TextBlock Body(string text, bool dim = true, double bottom = 12) =>
        new() { Text = text, TextWrapping = TextWrapping.Wrap, Foreground = dim ? R("FgDim") : R("Fg"), Margin = new Thickness(0, 0, 0, bottom), LineHeight = 21 };

    private TextBlock Small(string text) => new() { Text = text, TextWrapping = TextWrapping.Wrap, Foreground = R("Muted"), FontSize = 12.5, LineHeight = 18 };

    private Button Btn(string text, string style, Action click, bool isDefault = false, bool enabled = true)
    {
        var b = new Button { Content = text, Style = (Style)Resources[style], IsDefault = isDefault, IsEnabled = enabled };
        b.Click += (_, _) => click();
        return b;
    }

    private TextBlock Link(string text, Action click, double left = 0)
    {
        var l = new TextBlock { Text = text, Foreground = R("Accent"), Cursor = Cursors.Hand, FontSize = 12.5, Margin = new Thickness(left, 0, 0, 0) };
        l.MouseLeftButtonUp += (_, _) => click();
        return l;
    }

    /// <summary>A rounded card with a title and a line under it.</summary>
    private Border Card(string title, string detail, UIElement? extra = null)
    {
        var p = new StackPanel();
        p.Children.Add(new TextBlock { Text = title, Foreground = R("FgStrong"), FontSize = 15, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
        if (detail.Length > 0) p.Children.Add(new TextBlock { Text = detail, Foreground = R("Muted"), FontSize = 13, TextWrapping = TextWrapping.Wrap, LineHeight = 19, Margin = new Thickness(0, 5, 0, 0) });
        if (extra != null) p.Children.Add(extra);
        return new Border { Background = R("Card"), BorderBrush = R("Line"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(12), Padding = new Thickness(18, 15, 18, 16), Child = p };
    }

    /// <summary>A message with a coloured stripe: "ok", "warn", "bad" or information.</summary>
    private Border Banner(string text, string tone)
    {
        var (line, soft) = tone switch { "ok" => ("Good", "GoodSoft"), "warn" => ("Warn", "WarnSoft"), "bad" => ("Bad", "BadSoft"), _ => ("Accent", "AccentSoft") };
        var dock = new DockPanel();
        var stripe = new Border { Width = 3, CornerRadius = new CornerRadius(2), Background = R(line), Margin = new Thickness(0, 0, 12, 0) };
        DockPanel.SetDock(stripe, Dock.Left);
        dock.Children.Add(stripe);
        dock.Children.Add(new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap, Foreground = R("Fg"), LineHeight = 20 });
        var c = ((SolidColorBrush)R(line)).Color;
        return new Border { CornerRadius = new CornerRadius(10), Padding = new Thickness(14, 12, 14, 12), BorderThickness = new Thickness(1), Background = R(soft), BorderBrush = new SolidColorBrush(Color.FromArgb(0x70, c.R, c.G, c.B)), Child = dock };
    }

    /// <summary>One page: its step, heading, content and the footer buttons (Cancel on the left; Back and Next on the right).</summary>
    private void SetPage(int step, string heading, string sub, UIElement content, Button? cancel, Button? back, Button? next)
    {
        if (step >= 0) ShowSteps(step);
        _heading.Text = heading;
        _sub.Text = sub;
        _sub.Visibility = sub.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
        _host.Content = content;
        _footer.Children.Clear();
        if (cancel != null) { DockPanel.SetDock(cancel, Dock.Left); _footer.Children.Add(cancel); }
        if (next != null) { DockPanel.SetDock(next, Dock.Right); _footer.Children.Add(next); }
        if (back != null) { back.Margin = new Thickness(0, 0, 10, 0); DockPanel.SetDock(back, Dock.Right); _footer.Children.Add(back); }
        if (_animate && SystemParameters.ClientAreaAnimation)
        {
            // A short fade and rise as each page arrives.
            var shift = new TranslateTransform(0, 10);
            _host.RenderTransform = shift;
            var ease = new CubicEase { EasingMode = EasingMode.EaseOut };
            _host.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(200)) { EasingFunction = ease });
            shift.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(10, 0, TimeSpan.FromMilliseconds(240)) { EasingFunction = ease });
        }
        var focus = next ?? back ?? cancel;
        if (focus != null) Dispatcher.BeginInvoke(new Action(() => focus.Focus()));
    }

    private Button CancelButton() => Btn("Cancel", "Quiet", Close);
    private string Verb => _upgrading ? "Update" : "Install";

    // ---- install / update pages -------------------------------------------------------------------------------------

    private void ShowDetecting()
    {
        _steps = new[] { "Welcome" };
        SetPage(0, "Getting ready…", "Checking what is already installed on this PC.", new StackPanel(), CancelButton(), null, null);
    }

    private void UseInstallSteps() => _steps = _upgrading
        ? new[] { "Welcome", "Options", "Checks", "Update", "Done" }
        : new[] { "Welcome", "Licence", "Options", "Checks", "Install", "Done" };
    private int StepOf(string name) => Array.IndexOf(_steps, name);

    private void ShowWelcome()
    {
        if (_ba.AppInstalled && !_upgrading) { ShowMaintenance(); return; }
        UseInstallSteps();
        var p = new StackPanel();
        if (_upgrading) p.Children.Add(Body("A newer version is ready to install. Your hosts, credentials, keys, notes and settings are kept, and it opens just where you left off.", dim: false, bottom: 18));
        else if (_c.Intro.Length > 0) p.Children.Add(Body(_c.Intro, dim: false, bottom: 18));
        if (_c.Highlights.Count > 0)
        {
            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition());
            grid.ColumnDefinitions.Add(new ColumnDefinition());
            int n = Math.Min(4, _c.Highlights.Count);
            for (int i = 0; i < (n + 1) / 2; i++) grid.RowDefinitions.Add(new RowDefinition());
            for (int i = 0; i < n; i++)
            {
                var card = Card(_c.Highlights[i].Title, _c.Highlights[i].Detail);
                card.Margin = new Thickness(i % 2 == 0 ? 0 : 6, 0, i % 2 == 0 ? 6 : 0, 12);
                Grid.SetRow(card, i / 2); Grid.SetColumn(card, i % 2);
                grid.Children.Add(card);
            }
            p.Children.Add(grid);
        }
        if (_c.DataNote.Length > 0 && !_upgrading) p.Children.Add(Small(_c.DataNote));
        p.Children.Add(Small($"Setup version {_ba.Format("[WixBundleVersion]")} · {(_ba.PreviewFolder != null ? "WORKSTATION-01" : Environment.MachineName)}"));   // a preview may be published: never this PC's name
        SetPage(StepOf("Welcome"), (_upgrading ? "Update " : "Welcome to ") + _c.Title, _c.Tagline,
            new ScrollViewer { Content = p, VerticalScrollBarVisibility = ScrollBarVisibility.Auto },
            CancelButton(), null, Btn("Next", "Primary", () => { if (_upgrading) ShowOptions(); else ShowLicence(); }, true));
    }

    private void ShowLicence()
    {
        string text;
        // Licence files are hard-wrapped at 80 columns: join each paragraph's lines so the box wraps them evenly.
        try { text = System.Text.RegularExpressions.Regex.Replace(File.ReadAllText(System.IO.Path.Combine(_ba.Folder, "LICENSE.txt")).Replace("\r\n", "\n").Trim(), @"(?<=\S)\n(?=\S)", " "); }
        catch { text = "The licence file is missing from this setup program."; }
        var head = $"{_c.Title} is free and open-source software" + (_c.BuiltBy.Length > 0 ? ", " + char.ToLowerInvariant(_c.BuiltBy[0]) + _c.BuiltBy.Substring(1) : "") + ".\n\n";
        var box = new TextBox
        {
            Text = head + text, IsReadOnly = true, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            FontFamily = (FontFamily)Resources["MonoFont"], FontSize = 12.5, Padding = new Thickness(18, 14, 18, 14), BorderThickness = new Thickness(0),
            Background = Brushes.Transparent, Foreground = R("FgDim"),
        };
        var card = new Border { Background = R("Card"), BorderBrush = R("Line"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(12), Child = box, Height = 286 };
        _accept.Style = (Style)Resources["TickBox"];
        _accept.Content = new TextBlock { Text = "I accept the licence" };
        if (_accept.Parent is Panel old) old.Children.Remove(_accept);
        _accept.Margin = new Thickness(0, 14, 0, 0);
        var p = new StackPanel();
        p.Children.Add(card);
        p.Children.Add(_accept);
        var next = Btn("Next", "Primary", ShowOptions, true, _accept.IsChecked == true);
        _licenceNext = next;
        SetPage(StepOf("Licence"), "Licence", "Please read and accept the licence to continue.", p, CancelButton(), Btn("Back", "Secondary", ShowWelcome), next);
    }

    private void ShowOptions()
    {
        var p = new StackPanel();
        if (!_upgrading)
        {
            p.Children.Add(new TextBlock { Text = "INSTALL FOLDER", Foreground = R("Muted"), FontSize = 11, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 6) });
            var row = new DockPanel { Margin = new Thickness(0, 0, 0, 18) };
            var browse = Btn("Browse…", "Secondary", Browse);
            browse.Margin = new Thickness(10, 0, 0, 0);
            DockPanel.SetDock(browse, Dock.Right); row.Children.Add(browse);
            _folder.Padding = new Thickness(12, 9, 12, 9);
            if (_folder.Parent is Panel old) old.Children.Remove(_folder);
            row.Children.Add(_folder);
            p.Children.Add(row);
        }
        foreach (var o in _c.Options)
        {
            if (!_switches.TryGetValue(o, out var sw))
            {
                bool installed = o.IsInstalled();
                sw = new CheckBox { Style = (Style)Resources["CardCheck"], IsChecked = !installed && o.Default, IsEnabled = !installed };
                var text = new StackPanel();
                var line = new StackPanel { Orientation = Orientation.Horizontal };
                line.Children.Add(new TextBlock { Text = o.Title, FontWeight = FontWeights.SemiBold, FontSize = 15, Foreground = R("FgStrong") });
                if (installed) line.Children.Add(new Border { Background = R("AccentSoft"), BorderBrush = R("AccentLine"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(8), Padding = new Thickness(8, 1, 8, 1), Margin = new Thickness(10, 1, 0, 0), VerticalAlignment = VerticalAlignment.Center,
                    Child = new TextBlock { Text = "Already installed", FontSize = 11, Foreground = R("Accent") } });
                text.Children.Add(line);
                if (o.Detail.Length > 0) text.Children.Add(new TextBlock { Text = o.Detail, Foreground = R("Muted"), FontSize = 13, TextWrapping = TextWrapping.Wrap, LineHeight = 19, Margin = new Thickness(0, 4, 0, 0) });
                sw.Content = text;
                _switches[o] = sw;
            }
            if (sw.Parent is Panel old) old.Children.Remove(sw);
            p.Children.Add(sw);
        }
        SetPage(StepOf("Options"), "Choose what to set up", "Recommended items are on. Untick anything you don't want; what's already on this PC is left as it is.",
            new ScrollViewer { Content = p, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Padding = new Thickness(0, 0, 8, 0) },
            CancelButton(), Btn("Back", "Secondary", () => { if (_upgrading) ShowWelcome(); else ShowLicence(); }), Btn("Next", "Primary", ShowChecks, true));
    }

    /// <summary>What this PC has: Windows, 64-bit, the disk, and what will come along. A hard problem stops Next.</summary>
    private void ShowChecks()
    {
        var rows = new List<(string Title, string Detail, string Tone)>();
        var (build, name) = WindowsBuild();
        rows.Add(("Windows", name, build >= _c.MinBuild || build == 0 ? "ok" : "bad"));
        rows.Add(("64-bit", Environment.Is64BitOperatingSystem ? "yes" : "no: this app needs 64-bit Windows", Environment.Is64BitOperatingSystem ? "ok" : "bad"));
        string disk = "unknown"; string diskTone = "warn";
        try
        {
            var root = System.IO.Path.GetPathRoot(_upgrading || _folder.Text.Trim().Length == 0 ? Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) : _folder.Text.Trim());
            if (!string.IsNullOrEmpty(root))
            {
                var free = new DriveInfo(root).AvailableFreeSpace / (1024.0 * 1024 * 1024);
                disk = $"{free:N0} GB free on {root.TrimEnd('\\')} (about {_c.DiskMb / 1024.0:0.0} GB needed)";
                diskTone = free * 1024 >= _c.DiskMb ? "ok" : "bad";
            }
        }
        catch { }
        rows.Add(("Disk space", disk, diskTone));
        var extra = _c.Options.Where(o => _switches.TryGetValue(o, out var s) ? s.IsChecked == true : !o.IsInstalled() && o.Default).Select(o => o.Title).ToList();
        rows.Add(("Also set up", extra.Count > 0 ? string.Join(", ", extra) : "nothing extra", "ok"));
        rows.Add(("Administrator approval", "Windows asks once, when installing starts.", "info"));

        var p = new StackPanel();
        foreach (var (t, d, tone) in rows) p.Children.Add(CheckRow(t, d, tone));
        bool blocked = rows.Any(r => r.Tone == "bad");
        var banner = Banner(blocked ? "This PC can't run " + _c.Title + ": see the item marked above." : "This PC is ready.", blocked ? "bad" : "ok");
        banner.Margin = new Thickness(0, 10, 0, 0);
        p.Children.Add(banner);
        SetPage(StepOf("Checks"), "Checking this PC", _c.Title + " brings its own runtime; the items you chose are fetched from their publishers.", p,
            CancelButton(), Btn("Back", "Secondary", ShowOptions), Btn(Verb, "Primary", () => Start(LaunchAction.Install), true, !blocked));
    }

    private UIElement CheckRow(string title, string detail, string tone)
    {
        var g = new Grid { Margin = new Thickness(0, 0, 0, 14) };
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(34) });
        g.ColumnDefinitions.Add(new ColumnDefinition());
        var color = tone switch { "bad" => R("Bad"), "warn" => R("Warn"), "info" => R("Line2"), _ => R("Accent") };
        var mark = new Grid { Width = 22, Height = 22, VerticalAlignment = VerticalAlignment.Top, HorizontalAlignment = HorizontalAlignment.Left };
        mark.Children.Add(new Ellipse { Fill = tone == "info" ? Brushes.Transparent : color, Stroke = color, StrokeThickness = 1.5 });
        var glyph = tone switch
        {
            "bad" => "M 7.5,7.5 L 14.5,14.5 M 14.5,7.5 L 7.5,14.5",
            "warn" => "M 11,6 L 11,12.5 M 11,15.6 L 11,15.8",
            "info" => "M 11,10 L 11,15.5 M 11,6.6 L 11,6.8",
            _ => "M 6.2,11.3 L 9.6,14.6 L 15.8,7.8",
        };
        mark.Children.Add(new Path { Data = Geometry.Parse(glyph), Stroke = tone == "info" ? R("FgDim") : R("AccentFg"), StrokeThickness = 2, StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round, StrokeLineJoin = PenLineJoin.Round });
        g.Children.Add(mark);
        var text = new StackPanel();
        text.Children.Add(new TextBlock { Text = title, Foreground = R("FgStrong"), FontSize = 14.5 });
        text.Children.Add(new TextBlock { Text = detail, Foreground = R("Muted"), FontSize = 13, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 2, 0, 0) });
        Grid.SetColumn(text, 1);
        g.Children.Add(text);
        return g;
    }

    /// <summary>Windows' build and name from the registry (Environment.OSVersion is capped for unmanifested .NET Framework apps).</summary>
    private static (int Build, string Name) WindowsBuild()
    {
        try
        {
            using var k = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            int.TryParse(k?.GetValue("CurrentBuildNumber") as string, out var build);
            var display = k?.GetValue("DisplayVersion") as string ?? "";
            var product = build >= 22000 ? "Windows 11" : "Windows 10";
            return (build, $"{product}{(display.Length > 0 ? " " + display : "")} (build {build})");
        }
        catch { return (0, "Windows"); }
    }

    private void ShowProgress()
    {
        if (_action != LaunchAction.Install) _steps = new[] { "Choose", "Confirm", "Working", "Done" };   // repair / uninstall
        int step = _action == LaunchAction.Install ? StepOf(_upgrading ? "Update" : "Install") : 2;
        var card = new Border { Background = R("Card"), BorderBrush = R("Line"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(12), Padding = new Thickness(24, 20, 24, 22) };
        var p = new StackPanel();
        p.Children.Add(_percent);
        if (_bar.Parent is Panel b) b.Children.Remove(_bar);
        _bar.Margin = new Thickness(0, 10, 0, 14);
        p.Children.Add(_bar);
        if (_progressText.Parent is Panel t) t.Children.Remove(_progressText);
        p.Children.Add(_progressText);
        card.Child = p;
        var outer = new StackPanel();
        outer.Children.Add(card);
        var hint = Small("Windows asks for administrator approval once. Cancel rolls everything back; nothing is left half-installed.");
        hint.Margin = new Thickness(0, 14, 0, 0);
        outer.Children.Add(hint);
        ShowPercent(_bar.Value);
        SetPage(step, _action switch { LaunchAction.Uninstall => "Uninstalling " + _c.Title, LaunchAction.Repair => "Repairing " + _c.Title, _ => (_upgrading ? "Updating " : "Installing ") + _c.Title },
            "This takes a minute or two.", outer,
            Btn("Cancel", "Quiet", () => { _cancel = true; _progressText.Text = "Cancelling…"; }), null, null);
    }

    private void ShowPercent(double v) => _percent.Text = $"{Math.Round(v)} %";

    private void ShowDone(int status)
    {
        _busy = false;
        bool ok = SetupApplication.Succeeded(status);
        int last = _steps.Length - 1;
        if (!ok)
        {
            var p = new StackPanel();
            p.Children.Add(Banner(_error.Length > 0 ? _error : $"Error 0x{status:X8}. Nothing was left half-installed: this PC is as it was before.", _cancel ? "warn" : "bad"));
            var log = _ba.Get("WixBundleLog");
            var help = Small("The setup log has the details" + (_c.Website.Length > 0 ? "; you can report a problem at " + _c.Website.Replace("https://", "").TrimEnd('/') + "." : "."));
            help.Margin = new Thickness(0, 14, 0, 0);
            p.Children.Add(help);
            var openLog = log.Length > 0 && File.Exists(log) ? Btn("Open the log", "Secondary", () => Open(log)) : null;
            // The rail stays on the step that failed (Install / Working), never ticks it.
            SetPage(Math.Max(0, last - 1), _cancel ? "Setup was cancelled" : "Setup didn't finish", "", p, null, openLog, Btn("Close", "Primary", Close, true));
            return;
        }
        string what = _action switch { LaunchAction.Uninstall => "uninstalled", LaunchAction.Repair => "repaired", _ => _upgrading ? "updated" : "installed" };
        var page = new StackPanel();
        if (_action == LaunchAction.Uninstall)
        {
            page.Children.Add(Body(_removeData.IsChecked == true ? "Its data and settings for this Windows user were removed too." : "Your data and settings were kept, so a reinstall picks up where you left off.", dim: false, bottom: 18));
        }
        else
        {
            if (_c.DoneNote.Length > 0 && _action == LaunchAction.Install && !_upgrading) page.Children.Add(Body(_c.DoneNote, dim: false, bottom: 18));
            _launch.Style = (Style)Resources["CardCheck"];
            _launch.Content = new TextBlock { Text = "Open " + _c.Title + " now", FontWeight = FontWeights.SemiBold, FontSize = 15, Foreground = R("FgStrong") };
            if (_launch.Parent is Panel old) old.Children.Remove(_launch);
            page.Children.Add(_launch);
            page.Children.Add(Small("To remove it later: Settings › Apps › " + _c.Title + "."));
        }
        SetPage(last, _c.Title + " is " + what, "", page, null, null,
            Btn("Finish", "Primary", () => { if (_launch.IsChecked == true && _action != LaunchAction.Uninstall) Launch(); Close(); }, true));
    }

    // ---- maintenance (this version installed) ------------------------------------------------------------------------

    private void ShowMaintenance()
    {
        _steps = new[] { "Choose", "Confirm", "Working", "Done" };
        _repair.Style = _uninstall.Style = (Style)Resources["CardRadio"];
        _repair.Content = OptionText("Repair", "Puts back any missing or damaged files and shortcuts. Your data and settings aren't touched.");
        _uninstall.Content = OptionText("Uninstall", "Removes the app from this PC. Your data stays unless you choose otherwise on the next page.");
        var p = new StackPanel();
        foreach (var r in new[] { _repair, _uninstall }) { if (r.Parent is Panel old) old.Children.Remove(r); p.Children.Add(r); }
        SetPage(0, _c.Title + " is installed", "Version " + _ba.Format("[WixBundleVersion]") + " is already on this PC. What would you like to do?", p,
            CancelButton(), null, Btn("Next", "Primary", () => { if (_uninstall.IsChecked == true) ShowUninstall(); else Start(LaunchAction.Repair); }, true));
    }

    private UIElement OptionText(string title, string detail)
    {
        var s = new StackPanel();
        s.Children.Add(new TextBlock { Text = title, FontWeight = FontWeights.SemiBold, FontSize = 15, Foreground = R("FgStrong") });
        s.Children.Add(new TextBlock { Text = detail, Foreground = R("Muted"), FontSize = 13, TextWrapping = TextWrapping.Wrap, LineHeight = 19, Margin = new Thickness(0, 4, 0, 0) });
        return s;
    }

    private void ShowUninstall()
    {
        _steps = new[] { "Choose", "Confirm", "Working", "Done" };
        var p = new StackPanel();
        if (_c.RemoveData is { } r)
        {
            _removeData.Style = (Style)Resources["CardCheck"];
            _removeData.Content = OptionText(r.Title, r.Detail);
            if (_removeData.Parent is Panel old) old.Children.Remove(_removeData);
            p.Children.Add(_removeData);
        }
        var back = _ba.RequestedAction == LaunchAction.Uninstall ? null : Btn("Back", "Secondary", ShowMaintenance);
        SetPage(1, "Uninstall " + _c.Title + "?", "The app is removed from this PC. Shared libraries and anything on your servers aren't affected.", p,
            CancelButton(), back, Btn("Uninstall", "Primary", () => Start(LaunchAction.Uninstall), true));
    }

    // ---- engine -----------------------------------------------------------------------------------------------------

    private void Wire()
    {
        _ba.DetectRelatedMsiPackage += (_, e) => { if (e.Operation == RelatedOperation.MajorUpgrade) _upgrading = true; };
        _ba.DetectComplete += (_, e) => Ui(() =>
        {
            _detected = true;
            _folder.Text = _ba.Format("[InstallFolder]");
            if (_ba.RequestedAction == LaunchAction.Uninstall && _ba.AppInstalled) ShowUninstall();
            else ShowWelcome();
        });
        _ba.PlanComplete += (_, e) => Ui(() =>
        {
            if (SetupApplication.Succeeded(e.Status)) _ba.Engine.Apply(new WindowInteropHelper(this).Handle);
            else ShowDone(e.Status);
        });
        _ba.ExecutePackageBegin += (_, e) => Ui(() => _progressText.Text = e.PackageId == "App" ? (_action == LaunchAction.Uninstall ? "Removing " : "Installing ") + _c.Title + "…"
            : _c.Options.FirstOrDefault(o => o.Package == e.PackageId) is { } x ? "Installing " + x.Title + " (finish its own setup window)…" : e.PackageId);
        _ba.Progress += (_, e) => { Ui(() => { _bar.Value = e.OverallPercentage; ShowPercent(e.OverallPercentage); }); if (_cancel) e.Cancel = true; };
        _ba.ExecuteProgress += (_, e) => { if (_cancel) e.Cancel = true; };
        _ba.Error += (_, e) => { if (!string.IsNullOrWhiteSpace(e.ErrorMessage)) _error = e.ErrorMessage.Trim(); };
        _ba.ApplyComplete += (_, e) => Ui(() => { _ba.ExitCode = e.Status; ShowDone(e.Status); });
    }

    private void Start(LaunchAction action)
    {
        if (!_detected || _busy) return;
        _busy = true; _cancel = false; _error = ""; _action = action;
        _bar.Value = 0;
        _progressText.Text = "Preparing…";
        if (action == LaunchAction.Install)
        {
            if (!_upgrading && _folder.Text.Trim().Length > 0) _ba.Set("InstallFolder", _folder.Text.Trim());
            foreach (var o in _c.Options)
            {
                // A switch shown "Already installed" leaves the property empty: the MSI's own detection decides, as it does alone.
                bool installed = o.IsInstalled();
                bool on = _switches.TryGetValue(o, out var sw) ? sw.IsChecked == true : !installed && o.Default;
                _ba.Set(o.Property, installed ? "" : on ? "1" : "0");
                if (o.Package.Length > 0) _ba.Set(SetupApplication.PackageVar(o, "Run"), !installed && on ? "1" : "0");
            }
        }
        if (action == LaunchAction.Uninstall && _c.RemoveData is { } r)
            foreach (var prop in r.Properties) _ba.Set(prop, _removeData.IsChecked == true ? "1" : "");
        ShowProgress();
        _ba.Engine.Plan(action);
    }

    private void OnClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (!_busy) return;
        e.Cancel = true;   // never close mid-install: cancel instead, Burn rolls back
        _cancel = true;
        _progressText.Text = "Cancelling…";
    }

    private void Browse()
    {
        using var dlg = new System.Windows.Forms.FolderBrowserDialog { SelectedPath = _folder.Text, Description = "Install folder", ShowNewFolderButton = true };
        if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK) _folder.Text = dlg.SelectedPath;
    }

    private void Launch()
    {
        var target = _ba.Format("[LaunchTarget]");
        if (File.Exists(target)) Open(target);
    }

    private static void Open(string target)
    {
        try { Process.Start(new ProcessStartInfo(target) { UseShellExecute = true }); } catch { }
    }

    private void Ui(Action a) => Dispatcher.BeginInvoke(a);

    /// <summary>Design check (setup program --preview): draws each page into a PNG without ever showing the window.</summary>
    internal void RenderPages(string outDir)
    {
        _animate = false;
        void Save(string name)
        {
            var root = (FrameworkElement)Content;
            root.Measure(new Size(Width, Height));
            root.Arrange(new Rect(0, 0, Width, Height));
            root.UpdateLayout();
            var bmp = new RenderTargetBitmap((int)Width, (int)Height, 96, 96, PixelFormats.Pbgra32);
            bmp.Render(root);
            var enc = new PngBitmapEncoder();
            enc.Frames.Add(BitmapFrame.Create(bmp));
            using var f = File.Create(System.IO.Path.Combine(outDir, name + ".png"));
            enc.Save(f);
        }
        _detected = true;
        _folder.Text = @"C:\Program Files\DarkCipher Systems\" + _c.Title;
        ShowWelcome(); Save("01-welcome");
        ShowLicence(); _accept.IsChecked = true; Save("02-licence");
        ShowOptions(); Save("03-options");
        ShowChecks(); Save("04-checks");
        _action = LaunchAction.Install; ShowProgress(); _bar.Value = 46; ShowPercent(46); _progressText.Text = "Installing " + _c.Title + "…"; Save("05-install");
        ShowDone(0); Save("06-done");
        _error = "Another installation is in progress. Finish it, then run setup again."; ShowDone(unchecked((int)0x80070652)); Save("07-failed");
        _error = "";
        _upgrading = true; ShowWelcome(); Save("08-update");
        _upgrading = false; _ba.AppInstalled = true; ShowMaintenance(); Save("09-maintenance");
        ShowUninstall(); Save("10-uninstall");
        _action = LaunchAction.Uninstall; ShowDone(0); Save("11-uninstalled");
    }

    // Windows 11 rounded corners for this borderless window (ignored on Windows 10).
    private void RoundCorners()
    {
        try { int round = 2; DwmSetWindowAttribute(new WindowInteropHelper(this).Handle, 33, ref round, sizeof(int)); } catch { }
    }

    [DllImport("dwmapi.dll")] private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
}
