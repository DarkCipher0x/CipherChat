using System.IO;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using CipherChat.App.Views;
using CipherChat.Crypto;
using CipherChat.Ui;

namespace CipherChat.App.Shell;

/// <summary>Hosts the three screens (connect, unlock, chat) and the idle auto-lock.</summary>
public partial class MainWindow : Window
{
    private readonly DispatcherTimer _idle = new() { Interval = TimeSpan.FromSeconds(15) };
    private DateTime _lastActive = DateTime.UtcNow;

    public Session Session { get; }

    public MainWindow(Session session)
    {
        Session = session;
        InitializeComponent();
        WindowFrame.Apply(this, Root, Captions);
        SourceInitialized += (_, _) =>
        {
            var handle = new System.Windows.Interop.WindowInteropHelper(this).Handle;   // passkey dialogs belong to this window
            session.Owner = () => handle;
        };
        PreviewKeyDown += (_, k) =>
        {
            _lastActive = DateTime.UtcNow;
            if (System.Windows.Input.Keyboard.Modifiers != System.Windows.Input.ModifierKeys.Control) return;
            var dir = k.Key switch
            {
                System.Windows.Input.Key.OemPlus or System.Windows.Input.Key.Add => 1,
                System.Windows.Input.Key.OemMinus or System.Windows.Input.Key.Subtract => -1,
                System.Windows.Input.Key.D0 or System.Windows.Input.Key.NumPad0 => 0,
                _ => (int?)null,
            };
            if (dir is { } d) { TextSize.Step(d); k.Handled = true; }      // text size: Ctrl+= bigger, Ctrl+- smaller, Ctrl+0 reset
        };
        PreviewMouseDown += (_, _) => _lastActive = DateTime.UtcNow;
        PreviewMouseWheel += (_, _) => _lastActive = DateTime.UtcNow;
        _idle.Tick += (_, _) =>
        {
            if (CallWindow.Current is not null) _lastActive = DateTime.UtcNow;     // nobody is idle in a call
            if (Session.Engine is not null && DateTime.UtcNow - _lastActive > TimeSpan.FromMinutes(Math.Max(1, Session.Saved.AutoLockMinutes))) Lock();
        };
        Loaded += async (_, _) => await StartAsync();
    }

    private async Task StartAsync()
    {
        try
        {
            await Task.Run(Session.RunSelfTest);
            PqText.Text = "Post-quantum hybrid · " + Session.SelfTestResults.Count + "/" + Session.SelfTestResults.Count + " self-tests";
            PqDot.SetResourceReference(System.Windows.Shapes.Shape.FillProperty, "Good");
        }
        catch (CryptoFail e)
        {
            PqText.Text = "Self-test failed";
            PqDot.SetResourceReference(System.Windows.Shapes.Shape.FillProperty, "Bad");
            PqText.SetResourceReference(System.Windows.Controls.TextBlock.ForegroundProperty, "Bad");
            Dialogs.Error(this, "Crypto self-test failed", e.Message + "\n\nCipherChat won't start on this PC until the self-test passes.");
            return;
        }
        try { await Session.LoadSavedAsync(); }
        catch (Exception e) when (e is InvalidDataException or UnauthorizedAccessException)
        {
            Dialogs.Error(this, "Saved settings", e.Message + " You can pair this PC again.");
        }
        ShowConnect();
    }

    public void ShowConnect()
    {
        WhoText.Text = "";
        SettingsButton.Visibility = LockButton.Visibility = Visibility.Collapsed;
        Host.Content = new ConnectView(this);
    }

    public void ShowGate()
    {
        WhoText.Text = Session.State?["me"]?["user"]?.GetValue<string>() ?? "";
        Host.Content = new GateView(this);
    }

    public void ShowChat()
    {
        SettingsButton.Visibility = LockButton.Visibility = Visibility.Visible;
        _lastActive = DateTime.UtcNow;
        _idle.Start();
        Host.Content = new ChatView(this);
    }

    /// <summary>Wipes the keys from memory and goes back to the unlock screen (the PC stays signed in / paired).</summary>
    public void Lock()
    {
        CallWindow.Current?.Close();                       // hangs up first
        _idle.Stop();
        Session.Lock();
        SettingsButton.Visibility = LockButton.Visibility = Visibility.Collapsed;
        if (Session.Api is null) ShowConnect(); else ShowGate();
    }

    private void OnLock(object sender, RoutedEventArgs e) => Lock();

    /// <summary>A line in the chat log from elsewhere (the call window).</summary>
    public void ShowNotice(string kind, string text)
    {
        if (Host.Content is ChatView chat) chat.Notice(kind switch { "err" => Engine.LineKind.Err, "warn" => Engine.LineKind.Warn, _ => Engine.LineKind.Sys }, text);
    }

    private void OnSettings(object sender, RoutedEventArgs e) => SettingsDialog.Show(this);

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        var unsent = Session.Unsent;
        if (unsent > 0 && !Dialogs.Confirm(this, "Messages not sent yet",
                "Some of your messages haven't reached the server yet (the connection is down). They'll be lost if you close CipherChat now. Close anyway?",
                "Close", true))
            e.Cancel = true;
        base.OnClosing(e);
    }

    protected override void OnClosed(EventArgs e)
    {
        Session.Lock();
        base.OnClosed(e);
    }

    /// <summary>Runs an async UI action and shows any refusal instead of crashing.</summary>
    public async void Run(Func<Task> action)
    {
        try { Mouse.OverrideCursor = Cursors.AppStarting; await action(); }
        catch (OperationCanceledException) { }
        catch (Exception e) when (e is Api.ApiException or CryptoFail or InvalidOperationException or ArgumentException or UnauthorizedAccessException or IOException or Passkeys.PasskeyException)
        {
            Dialogs.Error(this, "CipherChat", e.Message);
        }
        finally { Mouse.OverrideCursor = null; }
    }
}
