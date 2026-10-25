using System.Windows;
using System.Windows.Controls;
using CipherChat.App.Shell;
using CipherChat.Passkeys;
using CipherChat.Ui;
using CipherChat.Vault;

namespace CipherChat.App.Views;

public partial class ConnectView : UserControl
{
    private readonly MainWindow _w;

    public ConnectView(MainWindow w)
    {
        _w = w;
        InitializeComponent();
        if (w.Session.DevServer is not null) ServerBox.Text = w.Session.DevServer.ToString().TrimEnd('/');
        Loaded += async (_, _) => HelloSwitch.IsEnabled = await VaultStore.HelloAvailableAsync();
        PasskeyButton.Visibility = WindowsPasskey.Available ? Visibility.Visible : Visibility.Collapsed;
        foreach (var s in w.Session.Saved.Servers) SavedList.Items.Add(Row(s));
        SavedCard.Visibility = w.Session.Saved.Servers.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private UIElement Row(SavedServer s)
    {
        var dock = new DockPanel { Margin = new Thickness(0, 0, 0, 8) };
        var forget = new Button { Content = "Forget", Margin = new Thickness(6, 0, 0, 0) };
        forget.SetResourceReference(StyleProperty, "SmallButton");
        forget.Click += (_, _) => _w.Run(async () =>
        {
            if (!Dialogs.Confirm(_w, "Forget " + s.Name, "This PC forgets the pairing. Remove it on the server too (web chat: /devices) so the code stops working.", "Forget", danger: true)) return;
            _w.Session.Saved.Servers.Remove(s);
            if (_w.Session.Saved.Servers.Count == 0) await _w.Session.Vault.ForgetAsync(); else await _w.Session.Vault.SaveAsync(_w.Session.Saved, _w.Session.HelloOn);
            _w.ShowConnect();
        });
        var open = new Button { Content = "Connect", Margin = new Thickness(6, 0, 0, 0) };
        open.SetResourceReference(StyleProperty, "PrimaryButton");
        open.Click += (_, _) => _w.Run(async () => { await _w.Session.ResumeAsync(s); _w.ShowGate(); });
        DockPanel.SetDock(forget, Dock.Right); DockPanel.SetDock(open, Dock.Right);
        dock.Children.Add(forget); dock.Children.Add(open);
        var t = new TextBlock { Text = s.User + "  @  " + s.Origin, VerticalAlignment = VerticalAlignment.Center };
        t.SetResourceReference(TextBlock.FontFamilyProperty, "MonoFont");
        dock.Children.Add(t);
        return dock;
    }

    private void OnPair(object sender, RoutedEventArgs e) => _w.Run(async () =>
    {
        await _w.Session.PairAsync(CodeBox.Text, HelloSwitch.IsChecked == true);
        CodeBox.Clear();
        _w.ShowGate();
    });

    private Uri ServerOrigin() => Uri.TryCreate(ServerBox.Text.Trim(), UriKind.Absolute, out var origin)
        ? new Uri(origin.GetLeftPart(UriPartial.Authority))
        : throw new ArgumentException("Enter the server's address, like https://chat.example.com");

    private void OnPasskey(object sender, RoutedEventArgs e) => _w.Run(async () =>
    {
        PasskeyButton.IsEnabled = false;
        try { await _w.Session.PasskeySignInAsync(ServerOrigin()); }
        finally { PasskeyButton.IsEnabled = true; }
        _w.ShowGate();
    });

    private void OnSignIn(object sender, RoutedEventArgs e) => _w.Run(async () =>
    {
        await _w.Session.SignInAsync(ServerOrigin(), UserBox.Text.Trim().ToLowerInvariant(), PassBox.Password, TotpBox.Text.Trim());
        PassBox.Clear(); TotpBox.Clear();
        _w.ShowGate();
    });
}
