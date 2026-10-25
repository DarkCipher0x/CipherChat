using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using CipherChat.App.Shell;
using CipherChat.Crypto;
using CipherChat.Engine;
using CipherChat.Ui;
using Microsoft.Win32;
using Room = CipherChat.Engine.Room;

namespace CipherChat.App.Views;

/// <summary>
/// The chat screen: renders what <see cref="ChatEngine"/> raises and sends what the person types. Decrypted pictures are
/// decoded in memory only (never written to disk unless the person saves them), and files are only ever saved, never
/// opened or run by this app.
/// </summary>
public partial class ChatView : UserControl
{
    private static readonly int[] BurnSteps = [0, 10, 30, 60, 300];
    private static readonly HashSet<string> InlineImages = ["image/png", "image/jpeg", "image/gif"];
    private const long GifInlineMax = 16L * 1048576;          // bigger GIFs show their still preview; Open shows the picture

    private readonly MainWindow _w;
    private readonly ChatEngine _e;
    private readonly Dictionary<Entry, FrameworkElement> _rows = new();
    private readonly List<ChatEngine.OutgoingFile> _files = [];
    private Room? _cur;
    private ChatMessage? _reply, _edit;
    private int _burn;
    private Action<string>? _emojiPick;

    public ChatView(MainWindow w)
    {
        _w = w;
        _e = w.Session.Engine!;
        InitializeComponent();
        BurnButton.Content = ColorEmoji.Content("🔥");
        _e.RoomsChanged += () => Ui(() => { RenderSide(); RenderHeader(); RenderStatus(); });
        _e.OnlineChanged += _ => Ui(RenderStatus);
        _e.EntryAdded += (r, en) => Ui(() => Added(r, en));
        _e.EntryChanged += (r, en) => Ui(() => Changed(r, en));
        _e.EntryRemoved += (r, en) => Ui(() => Removed(r, en));
        _e.Notice += (r, k, t) => Ui(() => LocalLine(k, t));
        _e.Calls.Ringing += inc => Ui(() => RingPopup.Show(_w, inc));
        _e.Calls.RingStopped += (call, why) => Ui(() =>
        {
            RingPopup.Stop(call);
            if (why == "missed") LocalLine(LineKind.Warn, "Missed call.");
        });
        Drop += OnDrop;
        // A TextBox turns Paste off when the clipboard holds no text, so files and pictures are caught at the command
        CommandManager.AddPreviewCanExecuteHandler(Input, OnCanPaste);
        CommandManager.AddPreviewExecutedHandler(Input, OnPaste);
        Loaded += (_, _) => { _w.Activated += OnWindowActive; _w.Deactivated += OnWindowInactive; TextSize.Changed += Rescale; _w.Run(StartAsync); };
        Unloaded += (_, _) => { _w.Activated -= OnWindowActive; _w.Deactivated -= OnWindowInactive; TextSize.Changed -= Rescale; };
    }

    // Messages arriving in the room on screen aren't unread while the window is in front
    private void OnWindowActive(object? sender, EventArgs e)
    {
        _e.Viewing = _cur;
        if (_cur is not null) _e.MarkRead(_cur);
    }

    private void OnWindowInactive(object? sender, EventArgs e) => _e.Viewing = null;

    /// <summary>A line in the log from outside the chat (the call window).</summary>
    public void Notice(LineKind kind, string text) => LocalLine(kind, text);

    private void OnVoice(object sender, RoutedEventArgs e) { if (_cur is not null) CallWindow.Start(_w, _cur, "audio"); }

    private void OnVideo(object sender, RoutedEventArgs e) { if (_cur is not null) CallWindow.Start(_w, _cur, "video"); }

    private void Ui(Action a) => Dispatcher.BeginInvoke(a);

    private async Task StartAsync()
    {
        await _e.StartAsync();
        _w.Session.RestoreParkedOutbox();                          // messages still waiting when the chat last locked
        RenderSide();
        RenderStatus();
        var first = _e.Rooms.OrderBy(r => r.Kind == "room" ? 0 : 1).ThenBy(r => r.Label(_e.MyUser), StringComparer.Ordinal).FirstOrDefault();
        if (first is not null) await OpenRoom(first);
        else LocalLine(LineKind.Sys, "No rooms yet. Create one with the + next to ROOMS.");
        Input.Focus();
    }

    // ------------------------------------------------------------------------------------------- sidebar
    private void RenderSide()
    {
        NewRoomButton.Visibility = _e.CanCreateRooms ? Visibility.Visible : Visibility.Collapsed;
        RoomList.Children.Clear(); DmList.Children.Clear(); PeopleList.Children.Clear();
        foreach (var r in _e.Rooms.OrderBy(r => r.Label(_e.MyUser), StringComparer.Ordinal))
        {
            var label = r.Label(_e.MyUser);
            var b = SideButton(label + (r.Unread > 0 ? "  (" + r.Unread + ")" : ""), r == _cur ? "Accent" : "Fg");
            b.Click += (_, _) => _w.Run(() => OpenRoom(r));
            (r.Kind == "dm" ? DmList : RoomList).Children.Add(b);
        }
        foreach (var p in _e.People.Values.OrderBy(p => p.User, StringComparer.Ordinal))
        {
            var (tag, brush) = p.Trust switch { TrustLevel.Ok => ("verified", "Good"), TrustLevel.Pending => ("pending", "Warn"), TrustLevel.None => ("no keys", "Muted"), _ => ("untrusted", "Bad") };
            var b = SideButton(null, "Fg");
            var dock = new DockPanel();
            var t = new TextBlock { Text = tag, FontSize = 11 };
            t.SetResourceReference(TextBlock.ForegroundProperty, brush);
            DockPanel.SetDock(t, Dock.Right);
            dock.Children.Add(t);
            dock.Children.Add(new TextBlock { Text = p.User + (p.Owner ? " *" : "") + (AddonIdentity.IsAddon(p.User) ? "  · add-on" : "") + (p.User == _e.MyUser ? " (you)" : "") });
            b.Content = dock;
            b.ToolTip = p.Why;
            b.Click += (_, _) => PersonDialog(p);
            PeopleList.Children.Add(b);
        }
        var total = _e.Rooms.Sum(r => r.Unread);
        _w.Title = (total > 0 ? "(" + total + ") " : "") + "CipherChat";
    }

    private Button SideButton(string? text, string brush)
    {
        var b = new Button { Content = text is null ? null : ColorEmoji.Content(text) };
        b.SetResourceReference(StyleProperty, "SideItem");
        b.SetResourceReference(ForegroundProperty, brush);
        return b;
    }

    private void RenderHeader()
    {
        if (_cur is null) return;
        ColorEmoji.SetText(RoomTitle, _cur.Label(_e.MyUser));
        ColorEmoji.SetText(RoomTopic, _cur.Topic);
        KeyInfo.Text = _cur.Epoch > 0
            ? "key #" + _cur.Epoch + " · " + _cur.EpochRecipients.Count + "/" + _cur.Members.Count + " hold it" + (_cur.NeedsRotation ? " · renewal due" : "")
            : "no key yet";
        ColorEmoji.SetText(Prompt, _e.MyUser + "@cipherchat:" + _cur.Label(_e.MyUser) + "$");
        MembersButton.Visibility = VoiceButton.Visibility = VideoButton.Visibility = Visibility.Visible;
        RoomSettingsButton.Visibility = _cur.Kind == "room" && (_cur.MyRole == "admin" || _e.IAmOwner) ? Visibility.Visible : Visibility.Collapsed;
        OlderButton.Visibility = _cur.MoreHistory ? Visibility.Visible : Visibility.Collapsed;
    }

    private void RenderStatus()
    {
        var me = _e.People.GetValueOrDefault(_e.MyUser);
        StatusLine.Text = (_e.Online ? "● online" : "○ connecting") + "   ML-KEM-1024+X25519 · ML-DSA-87+Ed25519 · AES-256-GCM · TLS X25519MLKEM768   id " +
                          _e.Me.Fp[..16] + " " + (me?.Trust == TrustLevel.Ok ? "verified" : "awaiting certification");
    }

    private async Task OpenRoom(Room r)
    {
        _cur = r;
        _e.Viewing = _w.IsActive ? r : null;
        _files.Clear(); _reply = null; _edit = null; RenderBar();
        Log.Children.Clear();
        _rows.Clear();
        List<Entry> snapshot;
        lock (r.Timeline) snapshot = r.Timeline.ToList();
        foreach (var en in snapshot) Insert(en, -1);
        RenderSide(); RenderHeader();
        await _e.OpenRoomAsync(r);
        RenderHeader();
        await _e.MaybeAutoRotateAsync(r);
        ScrollEnd(force: true);
    }

    // ------------------------------------------------------------------------------------------- the log
    private void Added(Room r, Entry en)
    {
        if (r != _cur)
        {
            if (en.Message is { Mine: false }) Notify();
            return;
        }
        int index;
        lock (r.Timeline) index = r.Timeline.IndexOf(en);
        Insert(en, index);
        if (en.Message is { Mine: false }) Notify();
        ScrollEnd(force: en.Message?.Mine == true);
    }

    private void Changed(Room r, Entry en)
    {
        if (r != _cur || !_rows.TryGetValue(en, out var old)) return;
        var i = Log.Children.IndexOf(old);
        var row = Build(en);
        _rows[en] = row;
        Log.Children.RemoveAt(i);
        Log.Children.Insert(i, row);
    }

    // The text size changed: rows are rebuilt so the time and name columns fit the new size.
    private void Rescale()
    {
        if (_cur is null) return;
        foreach (var en in _rows.Keys.ToList()) Changed(_cur, en);
    }

    private void Removed(Room r, Entry en)
    {
        if (r != _cur || !_rows.Remove(en, out var row)) return;
        Log.Children.Remove(row);
    }

    private void Insert(Entry en, int index)
    {
        var row = Build(en);
        _rows[en] = row;
        if (index < 0 || index >= Log.Children.Count) Log.Children.Add(row); else Log.Children.Insert(index, row);
    }

    private void LocalLine(LineKind k, string text)
    {
        var en = new Entry { At = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), Kind = k, Who = k == LineKind.Err ? "!!" : "--", Text = text };
        Log.Children.Add(Build(en));
        ScrollEnd(force: true);
    }

    private void ScrollEnd(bool force)
    {
        if (force || LogScroll.ScrollableHeight - LogScroll.VerticalOffset < 120) Dispatcher.BeginInvoke(LogScroll.ScrollToEnd, DispatcherPriority.Background);
    }

    private static TextBlock Small(string text, string brush, double size = 11)
    {
        var t = new TextBlock { Margin = new Thickness(0, 0, 8, 0) };
        ColorEmoji.SetText(t, text);
        t.SetResourceReference(TextBlock.FontSizeProperty, size >= 12 ? "FsMeta" : "FsCaption");     // follows the text size setting
        t.SetResourceReference(TextBlock.ForegroundProperty, brush);
        t.SetResourceReference(TextBlock.FontFamilyProperty, "MonoFont");
        return t;
    }

    private FrameworkElement Build(Entry en)
    {
        var grid = new Grid { Margin = new Thickness(0, 2, 0, 2) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(Math.Round(48 * TextSize.Factor)) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(Math.Round(110 * TextSize.Factor)) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        var time = Small(DateTimeOffset.FromUnixTimeSeconds(en.At).ToLocalTime().ToString("HH:mm", System.Globalization.CultureInfo.InvariantCulture), "Muted");
        grid.Children.Add(time);
        var m = en.Message;
        var nick = Small(m is null ? en.Who : m.Kind == "me" ? "*" : m.From, m is null && en.Outgoing is null ? "Muted" : m?.Mine != false ? "Accent" : "FgStrong", 12);
        nick.TextTrimming = TextTrimming.CharacterEllipsis;
        Grid.SetColumn(nick, 1);
        grid.Children.Add(nick);
        FrameworkElement body = en.Outgoing is { } og ? PendingBody(og) : m is null ? LineBody(en) : m.Burn > 0 ? BurnBody(m) : MessageBody(m);
        Grid.SetColumn(body, 2);
        grid.Children.Add(body);
        if (m is not null && m.Burn == 0) grid.ContextMenu = Menu(m);
        return grid;
    }

    /// <summary>A message of yours still on its way: waiting for the network, sending, or refused (Retry / Discard).</summary>
    private FrameworkElement PendingBody(Outgoing o)
    {
        var panel = new StackPanel { Opacity = o.State == Outgoing.States.Failed ? 1 : 0.7 };
        panel.Children.Add(TextView(o.Preview));
        var status = o.State switch
        {
            Outgoing.States.Queued => "⏳ queued · sends when you're back online" + (o.Attempts > 0 && o.Note is { } n ? " (" + n + ")" : ""),
            Outgoing.States.Sending => "↑ sending" + (o.Note is { } s ? " · " + s : "") + "…",
            Outgoing.States.Sent => "✓ sent",
            _ => "✕ not sent: " + (o.Note ?? "refused"),
        };
        var line = new StackPanel { Orientation = Orientation.Horizontal };
        line.Children.Add(Small(status, o.State == Outgoing.States.Failed ? "Bad" : "Muted"));
        if (o.State is Outgoing.States.Failed or Outgoing.States.Queued)
        {
            if (o.State == Outgoing.States.Failed) line.Children.Add(LinkButton("retry", () => _e.Retry(o)));
            line.Children.Add(LinkButton("discard", () => _e.Discard(o)));
        }
        panel.Children.Add(line);
        return panel;
    }

    private static Button LinkButton(string text, Action click)
    {
        var b = new Button { Content = text, Margin = new Thickness(0, 0, 8, 0), Padding = new Thickness(6, 0, 6, 0), Cursor = System.Windows.Input.Cursors.Hand };
        b.SetResourceReference(StyleProperty, "LinkButton");
        b.Click += (_, _) => click();
        return b;
    }

    private static FrameworkElement LineBody(Entry en)
    {
        var t = (Control)TextView(en.Text);
        t.SetResourceReference(ForegroundProperty, en.Kind switch { LineKind.Err => "Bad", LineKind.Warn => "Warn", LineKind.Ok => "Good", LineKind.Server => "Muted", _ => "ConsoleMuted" });
        if (en.Kind == LineKind.Server) t.FontStyle = FontStyles.Italic;
        return t;
    }

    private FrameworkElement MessageBody(ChatMessage m)
    {
        var panel = new StackPanel();
        if (m.ReplyTo is not null)
        {
            var q = _cur is null ? null : _e.MessageById(_cur, m.ReplyTo);
            panel.Children.Add(Small("↳ " + (q is null ? "an earlier message" : q.From + ": " + FirstLine(q.Text.Length > 0 ? q.Text : "[attachment]", 80)), "Muted"));
        }
        if (m.Text.Length > 0 || m.Kind == "me")
        {
            panel.Children.Add(TextView((m.Kind == "me" ? m.From + " " : "") + m.Text + (m.EditedSeq > 0 ? "  (edited)" : ""), jumbo: m.Kind != "me" && m.EditedSeq == 0 && ColorEmoji.IsJumbo(m.Text)));
        }
        foreach (var f in m.Files) panel.Children.Add(FileView(f, keepGif: m.Burn == 0));
        if (m.Reactions.Count > 0)
        {
            var chips = new WrapPanel();
            foreach (var (emoji, users) in m.Reactions)
            {
                var mine = users.Contains(_e.MyUser);
                var c = new Button { Content = ColorEmoji.Content(emoji + " " + users.Count), ToolTip = string.Join(", ", users) };
                c.SetResourceReference(StyleProperty, "Chip");
                if (mine) c.SetResourceReference(BorderBrushProperty, "Accent");
                c.Click += (_, _) => _w.Run(() => _e.ReactAsync(_cur!, m, emoji, !mine));
                chips.Children.Add(c);
            }
            panel.Children.Add(chips);
        }
        return panel;
    }

    /// <summary>Message text: selectable, read-only. With emoji in it, a RichTextBox shows them in colour (ColorEmoji;
    /// WPF alone draws them as flat outlines), and copying gives the emoji back as text. Emoji-only messages show larger.</summary>
    private static FrameworkElement TextView(string text, bool jumbo = false)
    {
        if (!ColorEmoji.HasEmoji(text))
        {
            var t = new TextBox { Text = text };
            t.SetResourceReference(StyleProperty, "LogText");
            return t;
        }
        var p = new Paragraph { Margin = new Thickness(0) };
        p.Inlines.AddRange(ColorEmoji.Inlines(text, jumbo ? 2.8 : 1.3).ToList());
        var box = new RichTextBox { Document = new FlowDocument(p) { PagePadding = new Thickness(0) } };
        box.SetResourceReference(StyleProperty, "LogRich");
        box.CommandBindings.Add(new CommandBinding(ApplicationCommands.Copy, (_, e) => { Clipboard.SetText(SelectedText(box)); e.Handled = true; }));
        return box;
    }

    private static string SelectedText(RichTextBox box)
    {
        var sb = new System.Text.StringBuilder();
        var end = box.Selection.End;
        for (var p = box.Selection.Start; p is not null && p.CompareTo(end) < 0; p = p.GetNextContextPosition(LogicalDirection.Forward))
        {
            var ctx = p.GetPointerContext(LogicalDirection.Forward);
            if (ctx == TextPointerContext.Text)
            {
                var run = p.GetTextInRun(LogicalDirection.Forward);
                var max = p.GetOffsetToPosition(end);
                sb.Append(run.Length > max ? run[..max] : run);
            }
            else if (ctx == TextPointerContext.EmbeddedElement && p.GetAdjacentElement(LogicalDirection.Forward) is FrameworkElement { Tag: string s }) sb.Append(s);
            else if (ctx == TextPointerContext.ElementStart && p.GetAdjacentElement(LogicalDirection.Forward) is LineBreak) sb.Append('\n');
        }
        return sb.ToString();
    }

    private static string FirstLine(string s, int max) { var l = s.Split('\n')[0]; return l.Length > max ? l[..max] + "…" : l; }

    // Burn messages: hidden until opened; opening tells the server (it destroys the ciphertext once everyone has) and
    // starts the countdown; then the text and any decrypted pictures are dropped from this screen.
    private FrameworkElement BurnBody(ChatMessage m)
    {
        var panel = new StackPanel();
        if (m.Mine || m.Revealed)
        {
            var tag = Small(m.Mine ? "🔥 burns once read (" + m.Burn + "s)" : "🔥 " + m.Burn + "s", "Warn");
            panel.Children.Add(tag);
            panel.Children.Add(MessageBody(m));
            if (!m.Mine) StartCountdown(m, tag);
            return panel;
        }
        var reveal = new Button { Content = ColorEmoji.Content("🔥 burn message: click to reveal (visible for " + m.Burn + "s, then destroyed)"), HorizontalAlignment = HorizontalAlignment.Left };
        reveal.SetResourceReference(StyleProperty, "SmallButton");
        reveal.Click += (_, _) => _w.Run(async () =>
        {
            await _e.RevealBurnAsync(_cur!, m);
            var en = _rows.Keys.FirstOrDefault(x => x.Message == m);
            if (en is not null) Changed(_cur!, en);
        });
        panel.Children.Add(reveal);
        return panel;
    }

    private void StartCountdown(ChatMessage m, TextBlock tag)
    {
        var room = _cur!;
        var left = m.Burn;
        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        timer.Tick += (_, _) =>
        {
            left--;
            ColorEmoji.SetText(tag, "🔥 " + left + "s");
            if (left > 0) return;
            timer.Stop();
            _e.BurnOut(room, m);
        };
        timer.Start();
    }

    private ContextMenu Menu(ChatMessage m)
    {
        var menu = new ContextMenu();
        var react = new MenuItem { Header = "React" };
        foreach (var e in Emoji.Quick) { var mi = new MenuItem { Header = ColorEmoji.Content(e) }; mi.Click += (_, _) => _w.Run(() => _e.ReactAsync(_cur!, m, e, !m.MyReaction(_e.MyUser, e))); react.Items.Add(mi); }
        var more = new MenuItem { Header = "More…" };
        more.Click += (_, _) => OpenEmoji(e => _w.Run(() => _e.ReactAsync(_cur!, m, e, !m.MyReaction(_e.MyUser, e))));
        react.Items.Add(more);
        menu.Items.Add(react);
        var reply = new MenuItem { Header = "Reply" };
        reply.Click += (_, _) => { _edit = null; _reply = m; RenderBar(); Input.Focus(); };
        menu.Items.Add(reply);
        if (m.Mine && m.Kind != "file")
        {
            var edit = new MenuItem { Header = "Edit" };
            edit.Click += (_, _) => { _reply = null; _edit = m; Input.Text = m.Text; RenderBar(); Input.Focus(); };
            menu.Items.Add(edit);
        }
        var copy = new MenuItem { Header = "Copy text" };
        copy.Click += (_, _) => Clipboard.SetText(m.Text);
        menu.Items.Add(copy);
        if (m.Mine || (_cur!.Kind == "room" && _cur.MyRole == "admin"))
        {
            var del = new MenuItem { Header = "Delete for everyone" };
            del.Click += (_, _) => { if (Dialogs.Confirm(_w, "Delete message", "Delete this message for everyone? The server removes the ciphertext.", "Delete", true)) _w.Run(() => _e.RedactAsync(_cur!, m.Seq)); };
            menu.Items.Add(del);
        }
        return menu;
    }

    // ------------------------------------------------------------------------------------------- attachments
    private FrameworkElement FileView(FileRef f, bool keepGif = true)
    {
        var label = f.SafeName + " · " + Human(f.Size);
        var room = _cur!;
        if (f.Kind is "image" or "video" && f.Thumb is not null)
        {
            var img = new Image { MaxWidth = 300, MaxHeight = 220, Stretch = Stretch.Uniform, HorizontalAlignment = HorizontalAlignment.Left, Cursor = Cursors.Hand };
            var box = new StackPanel { Margin = new Thickness(0, 4, 0, 4) };
            box.Children.Add(img);
            var gif = f.Kind == "image" && f.Mime == "image/gif" && f.Size <= GifInlineMax;
            box.Children.Add(Small((f.Kind == "video" ? "▶ " : gif ? "GIF · " : "") + label, "Muted"));
            _ = LoadThumbAsync(room, f.Thumb, img);
            // GIFs play inline (unless Windows' "show animations" is off: then the still preview stays)
            if (gif && SystemParameters.ClientAreaAnimation) _ = PlayGifAsync(room, f, img, keepGif);
            img.MouseLeftButtonUp += (_, _) => _w.Run(() => f.Kind == "image" ? ViewImageAsync(room, f) : SaveAsync(room, f));
            img.ToolTip = f.Kind == "image" ? "Open" : "Save the video";
            return box;
        }
        var what = f.Kind switch { "image" => "picture", "video" => "video", "audio" => "audio", _ => "file" };
        var b = new Button { Content = "⬇ " + what + ": " + label, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 4, 0, 4) };
        b.SetResourceReference(StyleProperty, "SmallButton");
        b.Click += (_, _) => _w.Run(() => f.Kind == "image" ? ViewImageAsync(room, f) : SaveAsync(room, f));
        return b;
    }

    private static string Human(long n) => n < 1024 ? n + " B" : n < 1048576 ? (n / 1024.0).ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) + " KB"
        : (n / 1048576.0).ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) + " MB";

    private async Task PlayGifAsync(Room r, FileRef f, Image img, bool keep)
    {
        try
        {
            var bytes = await _e.FetchFileAsync(r, f);
            if (Files.Sniff(bytes) != "image/gif" || !GifPlayer.Play(img, bytes)) return;
            if (keep) RememberGif(f.SafeName, bytes);
        }
        catch (Exception e) when (e is Api.ApiException or CryptoFail or NotSupportedException or FileFormatException) { /* the still preview stays */ }
    }

    // GIFs of this session (sent, or played in a room), newest first, so sending one again is one click. In memory only:
    // gone when the app locks or closes. A burn message's GIF is never kept.
    private readonly List<(string Name, byte[] Bytes)> _gifs = [];

    private void RememberGif(string name, byte[] bytes)
    {
        _gifs.RemoveAll(g => g.Bytes.Length == bytes.Length && g.Name == name);
        _gifs.Insert(0, (name, bytes));
        while (_gifs.Count > 30 || (_gifs.Count > 1 && _gifs.Sum(g => (long)g.Bytes.Length) > 96L * 1048576)) _gifs.RemoveAt(_gifs.Count - 1);
    }

    private void OnGif(object sender, RoutedEventArgs e)
    {
        GifGrid.Children.Clear();
        GifEmpty.Visibility = _gifs.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        foreach (var (name, bytes) in _gifs)
        {
            var cell = new Button { Width = 104, Height = 104, Padding = new Thickness(2), Margin = new Thickness(0, 0, 4, 4), ToolTip = "Send " + name,
                                    Content = new Image { Source = GifPlayer.Still(bytes, 200), Stretch = Stretch.UniformToFill } };
            cell.SetResourceReference(StyleProperty, "SmallButton");
            cell.Click += (_, _) => { GifPopup.IsOpen = false; AddBytes(name, bytes); Input.Focus(); };
            GifGrid.Children.Add(cell);
        }
        GifPopup.PlacementTarget = GifButton;
        GifPopup.IsOpen = true;
    }

    private void OnChooseGif(object sender, RoutedEventArgs e)
    {
        GifPopup.IsOpen = false;
        var dlg = new OpenFileDialog { Multiselect = true, Title = "Choose a GIF (encrypted on this PC before upload)", Filter = "GIF animations (*.gif)|*.gif" };
        if (dlg.ShowDialog(_w) == true) AddFiles(dlg.FileNames);
    }

    private async Task LoadThumbAsync(Room r, FileRef thumb, Image img)
    {
        try
        {
            var bytes = await _e.FetchFileAsync(r, thumb);
            if (InlineImages.Contains(Files.Sniff(bytes)) && img.HasAnimatedProperties == false) img.Source = Decode(bytes, 300);
        }
        catch (Exception e) when (e is Api.ApiException or CryptoFail or NotSupportedException or FileFormatException) { img.ToolTip = "Preview unavailable: " + e.Message; }
    }

    private static BitmapImage Decode(byte[] bytes, int width)
    {
        var bmp = new BitmapImage();
        bmp.BeginInit();
        bmp.CacheOption = BitmapCacheOption.OnLoad;
        bmp.DecodePixelWidth = width;
        bmp.StreamSource = new MemoryStream(bytes, writable: false);
        bmp.EndInit();
        bmp.Freeze();
        return bmp;
    }

    private async Task ViewImageAsync(Room r, FileRef f)
    {
        var bytes = await _e.FetchFileAsync(r, f);
        if (!InlineImages.Contains(Files.Sniff(bytes))) { await SaveBytesAsync(f, bytes); return; }   // not something shown safely
        var d = Dialogs.New(_w, f.SafeName, 900);
        d.Add(new Image { Source = Decode(bytes, 1600), MaxHeight = 640, Stretch = Stretch.Uniform });
        d.Text(Human(f.Size) + " · end-to-end encrypted", "Caption");
        d.Button("Save…", () => { _ = SaveBytesAsync(f, bytes); return true; });
        d.Button("Close", () => true, "PrimaryButton", isDefault: true);
        d.Show();
    }

    private async Task SaveAsync(Room r, FileRef f) => await SaveBytesAsync(f, await _e.FetchFileAsync(r, f));

    private async Task SaveBytesAsync(FileRef f, byte[] bytes)
    {
        var dlg = new SaveFileDialog { FileName = f.SafeName, Title = "Save the decrypted attachment", AddExtension = false };
        if (dlg.ShowDialog(_w) == true) await File.WriteAllBytesAsync(dlg.FileName, bytes);
    }

    private void AddFiles(IEnumerable<string> paths)
    {
        foreach (var p in paths)
        {
            if (_files.Count >= 10) { Dialogs.Error(_w, "Attachments", "Up to 10 attachments per message."); break; }
            var info = new FileInfo(p);
            if (!info.Exists) continue;
            if (info.Length > Files.Max) { Dialogs.Error(_w, "Attachments", info.Name + " is over the 100 MB limit."); continue; }
            AddBytes(info.Name, File.ReadAllBytes(p));
        }
    }

    private void AddBytes(string name, byte[] bytes)
    {
        byte[]? thumb = null; int? w = null, h = null;
        if (InlineImages.Contains(Files.Sniff(bytes)))
        {
            try
            {
                var src = Decode(bytes, 0);
                w = src.PixelWidth; h = src.PixelHeight;
                var scale = Math.Min(1.0, 360.0 / Math.Max(w.Value, h.Value));
                var small = new TransformedBitmap(src, new ScaleTransform(scale, scale));
                var enc = new JpegBitmapEncoder { QualityLevel = 75 };
                enc.Frames.Add(BitmapFrame.Create(small));
                using var ms = new MemoryStream();
                enc.Save(ms);
                thumb = ms.ToArray();
            }
            catch (Exception e) when (e is NotSupportedException or FileFormatException or ArgumentException) { thumb = null; }
        }
        _files.Add(new ChatEngine.OutgoingFile(name, bytes, null, thumb, w, h));
        if (_burn == 0 && Files.Sniff(bytes) == "image/gif") RememberGif(name, bytes);
        RenderBar();
    }

    private void OnAttach(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Multiselect = true, Title = "Attach (encrypted on this PC before upload)" };
        if (dlg.ShowDialog(_w) == true) AddFiles(dlg.FileNames);
    }

    private void OnDrop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] files) AddFiles(files);
    }

    // Pasted files (copied in Explorer) and pictures (screenshots, copied images) become attachments
    private static bool PastesAttachment => Clipboard.ContainsFileDropList() || (Clipboard.ContainsImage() && !Clipboard.ContainsText());

    private void OnCanPaste(object sender, CanExecuteRoutedEventArgs e)
    {
        if (e.Command != ApplicationCommands.Paste || !PastesAttachment) return;
        e.CanExecute = true;
        e.Handled = true;
    }

    private void OnPaste(object sender, ExecutedRoutedEventArgs e)
    {
        if (e.Command != ApplicationCommands.Paste || !PastesAttachment) return;
        e.Handled = true;
        if (Clipboard.ContainsFileDropList())
        {
            AddFiles(Clipboard.GetFileDropList().Cast<string>().ToArray());
            return;
        }
        var img = Clipboard.GetImage();
        if (img is null) return;
        var enc = new PngBitmapEncoder();
        enc.Frames.Add(BitmapFrame.Create(img));
        using var ms = new MemoryStream();
        enc.Save(ms);
        AddBytes("pasted-" + DateTime.Now.ToString("yyyyMMdd-HHmmss", System.Globalization.CultureInfo.InvariantCulture) + ".png", ms.ToArray());
    }

    // ------------------------------------------------------------------------------------------- composing
    private void RenderBar()
    {
        ComposeBar.Children.Clear();
        void Line(string text, Action cancel, string brush = "Muted")
        {
            var dock = new DockPanel { Margin = new Thickness(0, 0, 0, 4) };
            var b = new Button { Content = "cancel" };
            b.SetResourceReference(StyleProperty, "SmallButton");
            b.Click += (_, _) => { cancel(); RenderBar(); };
            DockPanel.SetDock(b, Dock.Right);
            dock.Children.Add(b);
            dock.Children.Add(Small(text, brush, 12));
            ComposeBar.Children.Add(dock);
        }
        if (_reply is not null) Line("↳ replying to " + _reply.From + ": " + FirstLine(_reply.Text.Length > 0 ? _reply.Text : "attachment", 60), () => _reply = null);
        if (_edit is not null) Line("✎ editing your message (Enter saves, Esc cancels)", () => { _edit = null; Input.Clear(); });
        if (_burn > 0) Line("🔥 burn after reading is on: your next messages are destroyed " + _burn + "s after each recipient opens them", () => { _burn = 0; RenderBurn(); }, "Warn");
        for (var i = 0; i < _files.Count; i++)
        {
            var f = _files[i];
            Line((f.Thumb is not null ? "🖼 " : "📎 ") + f.Name + " (" + Human(f.Bytes.LongLength) + ") · encrypted before upload", () => _files.Remove(f));
        }
        ComposeBar.Visibility = ComposeBar.Children.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void RenderBurn()
    {
        BurnButton.Content = ColorEmoji.Content(_burn == 0 ? "🔥" : "🔥" + (_burn < 60 ? _burn + "s" : _burn / 60 + "m"));
        BurnButton.ToolTip = _burn == 0 ? "Burn after reading (off)" : "Burn after reading: " + _burn + "s once opened (click to change)";
        RenderBar();
    }

    private void OnBurn(object sender, RoutedEventArgs e)
    {
        _burn = BurnSteps[(Array.IndexOf(BurnSteps, _burn) + 1) % BurnSteps.Length];
        RenderBurn();
    }

    private void OnInputKey(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && (Keyboard.Modifiers & ModifierKeys.Shift) == 0) { e.Handled = true; OnSend(sender, e); }
        else if (e.Key == Key.Escape && (_edit is not null || _reply is not null)) { if (_edit is not null) Input.Clear(); _edit = null; _reply = null; RenderBar(); e.Handled = true; }
    }

    private void OnSend(object sender, RoutedEventArgs e)
    {
        var text = Input.Text;
        var room = _cur;
        if (room is null || (text.Trim().Length == 0 && _files.Count == 0)) return;
        var reply = _reply?.Id; var edit = _edit; var files = _files.ToList(); var burn = _burn;
        Input.Clear(); _reply = null; _edit = null; _files.Clear(); RenderBar();
        _w.Run(async () =>
        {
            try
            {
                if (edit is not null) { if (text.Trim().Length > 0 && text != edit.Text) await _e.EditAsync(room, edit, text); }
                else if (files.Count > 0) await _e.SendFilesAsync(room, text, files, reply, burn, new Progress<string>(s => StatusLine.Text = s));
                else if (text.StartsWith("/me ", StringComparison.Ordinal)) await _e.SendTextAsync(room, text[4..], reply, burn, action: true);
                else await _e.SendTextAsync(room, text.StartsWith("//", StringComparison.Ordinal) ? text[1..] : text, reply, burn);
            }
            catch
            {
                if (Input.Text.Length == 0) Input.Text = text;     // nothing typed is lost on a refusal
                throw;
            }
            finally { RenderStatus(); }
        });
    }

    // ------------------------------------------------------------------------------------------- emoji
    private void OnEmoji(object sender, RoutedEventArgs e) => OpenEmoji(s => { Input.InsertAtCaret(s); Input.Focus(); });

    private void OpenEmoji(Action<string> pick)
    {
        _emojiPick = pick;
        EmojiPopup.PlacementTarget = EmojiButton;
        EmojiSearch.Text = "";
        FillEmoji("");
        EmojiPopup.IsOpen = true;
        EmojiSearch.Focus();
    }

    private void OnEmojiSearch(object sender, TextChangedEventArgs e) => FillEmoji(EmojiSearch.Text.Trim().ToLowerInvariant());

    private void FillEmoji(string q)
    {
        EmojiGrid.Children.Clear();
        foreach (var (emoji, name, _) in Emoji.All.Where(x => q.Length == 0 || x.Name.Contains(q, StringComparison.Ordinal)))
        {
            var b = new Button { Content = ColorEmoji.Element(emoji), ToolTip = name, FontSize = 18, Width = 38, Height = 34, Padding = new Thickness(0) };
            b.SetResourceReference(StyleProperty, "SmallButton");
            b.Click += (_, _) => { EmojiPopup.IsOpen = false; _emojiPick?.Invoke(emoji); };
            EmojiGrid.Children.Add(b);
        }
    }

    // ------------------------------------------------------------------------------------------- dialogs
    private void PersonDialog(Person p)
    {
        var mine = p.User == _e.MyUser;
        var d = Dialogs.New(_w, p.User + (p.DisplayName.Length > 0 ? " (" + p.DisplayName + ")" : ""), 520);
        d.Text("Trust: " + p.Trust.ToString().ToLowerInvariant() + " — " + p.Why);
        if (p.Fp is not null) d.Text("Fingerprint " + Hybrid.FpGroups(p.Fp), "Caption");
        if (p.Fp is not null && !mine)
        {
            d.Text("Safety number (compare out of band, never in this chat):", "Label");
            var sn = d.Add(new TextBlock { Text = string.Join("   ", _e.SafetyNumber(p).Split(' ').Chunk(4).Select(g => string.Join(" ", g))), TextWrapping = TextWrapping.Wrap, FontSize = 18, Margin = new Thickness(0, 0, 0, 8) });
            sn.SetResourceReference(TextBlock.FontFamilyProperty, "MonoFont");
            if (_e.IAmOwner && p.Trust == TrustLevel.Pending) d.Text("Certify only after " + p.User + " has read you the same 60 digits on a call, in person or over a channel you already trust.", "Caption");
        }
        d.Cancel("Close");
        if (_e.IAmOwner && !mine && p.Fp is not null && p.Trust != TrustLevel.Ok) d.Button("Certify", () => { _w.Run(() => _e.CertifyAsync(p)); return true; }, "PrimaryButton");
        if (_e.IAmOwner && !mine && p.Trust == TrustLevel.Ok) d.Button("Revoke", () => { _w.Run(() => _e.RevokeAsync(p)); return true; }, "DangerButton");
        if (!mine && p.Fp is not null) d.Button("Message", () => { _w.Run(async () => await OpenRoom(await _e.OpenDmAsync(p.User))); return true; });
        d.Show();
    }

    private List<CheckBox> PickList(Dialogs.Builder d, IEnumerable<string> names, IReadOnlyCollection<string>? ticked = null)
    {
        var boxes = new List<CheckBox>();
        var panel = new StackPanel { Margin = new Thickness(0, 0, 0, 8) };
        foreach (var n in names)
        {
            var p = _e.People.GetValueOrDefault(n);
            var cb = new CheckBox { Content = n + "  (" + (p?.Trust.ToString().ToLowerInvariant() ?? "?") + ")", Tag = n, IsChecked = ticked?.Contains(n) == true, Margin = new Thickness(0, 2, 0, 2) };
            panel.Children.Add(cb);
            boxes.Add(cb);
        }
        d.Add(new ScrollViewer { Content = panel, MaxHeight = 220, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
        return boxes;
    }

    private void OnNewRoom(object sender, RoutedEventArgs e)
    {
        var d = Dialogs.New(_w, "New private room", 480);
        d.Text("Only the people you add can see this room or read it: its key is made for them alone.", "Caption");
        var name = d.Field("NAME", "", 32);
        var topic = d.Field("TOPIC (optional)", "", 200);
        d.Text("HISTORY", "Label");
        var keep = d.Add(new ComboBox { Margin = new Thickness(0, 0, 0, 10), ItemsSource = _e.RetentionChoices.Select(x => x == 0 ? "keep messages until deleted" : "delete messages after " + x + " day" + (x > 1 ? "s" : "")).ToList(), SelectedIndex = 0 });
        d.Text("MEMBERS", "Label");
        var boxes = PickList(d, _e.People.Keys.Where(u => u != _e.MyUser).OrderBy(u => u, StringComparer.Ordinal));
        d.Text("Room names, topics and member lists are visible to the server. Messages aren't.", "Caption");
        d.Cancel();
        d.Button("Create", () => name.Text.Trim().Length > 0 ? true : false, "PrimaryButton", isDefault: true);
        if (d.Show(name) is not true) return;
        var retention = _e.RetentionChoices[Math.Max(0, keep.SelectedIndex)];
        var members = boxes.Where(b => b.IsChecked == true).Select(b => (string)b.Tag).ToList();
        _w.Run(async () => await OpenRoom(await _e.CreateRoomAsync(name.Text.Trim().ToLowerInvariant(), topic.Text, retention, members)));
    }

    private void OnNewDm(object sender, RoutedEventArgs e)
    {
        var d = Dialogs.New(_w, "Direct message", 420);
        var people = _e.People.Keys.Where(u => u != _e.MyUser).OrderBy(u => u, StringComparer.Ordinal).ToList();
        var sel = d.Add(new ComboBox { ItemsSource = people, SelectedIndex = people.Count > 0 ? 0 : -1, Margin = new Thickness(0, 0, 0, 8) });
        d.Cancel();
        d.Button("Open", () => sel.SelectedItem is string ? true : false, "PrimaryButton", isDefault: true);
        if (d.Show(sel) is true) _w.Run(async () => await OpenRoom(await _e.OpenDmAsync((string)sel.SelectedItem)));
    }

    private void OnMembers(object sender, RoutedEventArgs e)
    {
        var r = _cur!;
        var admin = r.Kind == "room" && (r.MyRole == "admin" || _e.IAmOwner);
        var d = Dialogs.New(_w, "Members of " + r.Label(_e.MyUser), 480);
        foreach (var (user, role) in r.Members)
            d.Text(user + (role == "admin" ? " (admin)" : "") + "  ·  " + (r.EpochRecipients.Contains(user) ? "holds the key" : "no key") + "  ·  " +
                   (_e.People.GetValueOrDefault(user)?.Trust.ToString().ToLowerInvariant() ?? "?"));
        List<CheckBox>? add = null, remove = null;
        if (admin)
        {
            d.Text("ADD", "Label");
            add = PickList(d, _e.People.Keys.Where(u => r.Members.All(m => m.User != u)).OrderBy(u => u, StringComparer.Ordinal));
            d.Text("REMOVE", "Label");
            remove = PickList(d, r.Members.Select(m => m.User).Where(u => u != _e.MyUser));
            d.Text("Any change gives the room a new key: removed members can't read anything sent afterwards.", "Caption");
            d.Cancel("Close");
            d.Button("Apply", () => true, "PrimaryButton");
        }
        else d.Button("Close", () => null, "PrimaryButton", isDefault: true);
        if (d.Show() is not true || add is null || remove is null) return;
        var a = add.Where(b => b.IsChecked == true).Select(b => (string)b.Tag).ToList();
        var rm = remove.Where(b => b.IsChecked == true).Select(b => (string)b.Tag).ToList();
        if (a.Count + rm.Count > 0) _w.Run(() => _e.ChangeMembersAsync(r, a, rm));
    }

    private void OnRoomSettings(object sender, RoutedEventArgs e)
    {
        var r = _cur!;
        var d = Dialogs.New(_w, "Settings for " + r.Label(_e.MyUser), 460);
        var name = d.Field("NAME", r.Name, 32);
        var topic = d.Field("TOPIC", r.Topic, 200);
        d.Text("KEEP MESSAGES", "Label");
        var choices = _e.RetentionChoices.ToList();
        var keep = d.Add(new ComboBox { ItemsSource = choices.Select(x => x == 0 ? "until deleted" : x + " days").ToList(), SelectedIndex = Math.Max(0, choices.IndexOf(r.RetentionDays)), Margin = new Thickness(0, 0, 0, 10) });
        d.Button("Delete room", () => "delete", "DangerButton");
        d.Button("New key now", () => "rotate");
        d.Cancel();
        d.Button("Save", () => "save", "PrimaryButton", isDefault: true);
        switch (d.Show(name))
        {
            case "save": _w.Run(() => _e.UpdateRoomAsync(r, name.Text.Trim(), topic.Text, choices[Math.Max(0, keep.SelectedIndex)])); break;
            case "rotate": _w.Run(() => _e.RotateNowAsync(r)); break;
            case "delete":
                if (Dialogs.Confirm(_w, "Delete " + r.Label(_e.MyUser), "Delete the room and every message in it for everyone? This can't be undone.", "Delete", true))
                    _w.Run(async () => { await _e.DeleteRoomAsync(r); _cur = null; Log.Children.Clear(); RoomTitle.Text = "no room selected"; });
                break;
        }
    }

    private void OnOlder(object sender, RoutedEventArgs e) => _w.Run(async () =>
    {
        var r = _cur!;
        await _e.LoadOlderAsync(r);
        RenderHeader();
    });

    // ------------------------------------------------------------------------------------------- notifications
    [DllImport("user32.dll")] private static extern bool FlashWindowEx(ref FlashInfo info);
    [StructLayout(LayoutKind.Sequential)] private struct FlashInfo { public uint Size; public IntPtr Hwnd; public uint Flags; public uint Count; public uint Timeout; }

    private void Notify()
    {
        if (_w.IsActive) return;
        var info = new FlashInfo { Size = (uint)Marshal.SizeOf<FlashInfo>(), Hwnd = new WindowInteropHelper(_w).Handle, Flags = 3 | 12, Count = 0, Timeout = 0 };
        FlashWindowEx(ref info);                         // taskbar flash until the window is focused; no content in it
    }
}
