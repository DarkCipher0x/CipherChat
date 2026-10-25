using System.Text;
using System.Windows;
using System.Windows.Controls;
using CipherChat.App.Shell;
using CipherChat.Crypto;
using CipherChat.Engine;
using CipherChat.Ui;

namespace CipherChat.App.Views;

/// <summary>
/// In front of the chat (gate.js): the self-test, then set up or unlock the identity, then pin the owner. The passphrase
/// is read from the PasswordBox only at the moment it's needed and kept only until the owner is pinned.
/// </summary>
public partial class GateView : UserControl
{
    private readonly MainWindow _w;
    private Me? _me;
    private string? _pass;

    public GateView(MainWindow w)
    {
        _w = w;
        InitializeComponent();
        var sb = new StringBuilder("cipherchat 1 // end-to-end encrypted, post-quantum\nsuite  " + Hybrid.Suite + "\ntls    1.3, X25519MLKEM768 only\n\n");
        foreach (var c in w.Session.SelfTestResults) sb.Append("[  OK  ] ").Append(c.Name).Append('\n');
        sb.Append('\n').Append(w.Session.SelfTestResults.Count).Append('/').Append(w.Session.SelfTestResults.Count).Append(" checks passed\n");
        Boot.Text = sb.ToString();
        var me = w.Session.State!["me"]!.AsObject();
        var user = me["user"]!.GetValue<string>();
        if (me["identity_fp"] is null || me["identity_fp"]!.GetValueKind() == System.Text.Json.JsonValueKind.Null) { SetupCard.Visibility = Visibility.Visible; Loaded += (_, _) => NewPass.Focus(); }
        else { UnlockTitle.Text = "Unlock " + user + "@cipherchat"; UnlockCard.Visibility = Visibility.Visible; Loaded += (_, _) => Pass.Focus(); }
        // Development only: automated end-to-end runs against a --dev-server (an http loopback server, never a real one)
        // can't type into a PasswordBox on a locked desktop, so they may hand the passphrase over in the environment.
        var devPass = w.Session.DevServer is not null ? Environment.GetEnvironmentVariable("CIPHERCHAT_DEV_PASSPHRASE") : null;
        if (!string.IsNullOrEmpty(devPass) && UnlockCard.Visibility == Visibility.Visible)
            Loaded += (_, _) => { Pass.Password = devPass; OnUnlock(this, new RoutedEventArgs()); };
    }

    private IProgress<string> Prog => new Progress<string>(t => Progress.Text = t);
    private Task<string?> Ask(string? err) => Dialogs.AskCode(_w, err);

    private void OnSetup(object sender, RoutedEventArgs e) => _w.Run(async () =>
    {
        if (NewPass.Password != NewPass2.Password) throw new ArgumentException("The two passphrases don't match.");
        var problem = Gate.PassProblems(NewPass.Password);
        if (problem is not null) throw new ArgumentException(problem);
        SetupGo.IsEnabled = false;
        try
        {
            _pass = NewPass.Password;
            _me = await Gate.SetupAsync(_w.Session.Api!, _w.Session.State!, _pass, reset: false, Ask, Prog);
            NewPass.Clear(); NewPass2.Clear();
            await AfterUnlockAsync();
        }
        finally { SetupGo.IsEnabled = true; Progress.Text = ""; }
    });

    private void OnUnlock(object sender, RoutedEventArgs e) => _w.Run(async () =>
    {
        UnlockGo.IsEnabled = false;
        try
        {
            _pass = Pass.Password;
            _me = await Gate.UnlockAsync(_w.Session.Api!, _w.Session.State!, _pass, Prog);
            Pass.Clear();
            await AfterUnlockAsync();
        }
        catch (UnauthorizedAccessException) { Pass.SelectAll(); throw; }
        finally { UnlockGo.IsEnabled = true; Progress.Text = ""; }
    });

    private async Task AfterUnlockAsync()
    {
        var st = _w.Session.State!;
        var owner = st["me"]?["owner"]?.GetValue<bool>() == true;
        if (_me!.AnchorFp is null && !owner)
        {
            await _w.Session.RefreshStateAsync();
            var sn = Gate.OwnerSafetyNumber(_w.Session.State!, _me);
            SetupCard.Visibility = UnlockCard.Visibility = Visibility.Collapsed;
            VerifyCard.Visibility = Visibility.Visible;
            var ownerUser = _w.Session.State!["owner"]!.GetValue<string>();
            if (sn is null)
            {
                VerifyText.Text = "The owner (" + ownerUser + ") hasn't set up their chat identity yet, so there's nobody to verify against. You can use the chat once they have.";
                PinGo.IsEnabled = false;
                return;
            }
            VerifyText.Text = "Read this number to " + ownerUser + " (or have them read theirs to you) in person, on a call or through a channel you already trust. Not in the chat, and not by email.";
            Safety.Text = string.Join("\n", sn.Split(' ').Chunk(4).Select(g => string.Join(" ", g)));
            Fps.Text = "Your fingerprint   " + Hybrid.FpGroups(_me.Fp) + "\nOwner fingerprint  " + Hybrid.FpGroups(Gate.OwnerIdentity(_w.Session.State!)!["fp"]!.GetValue<string>());
            return;
        }
        Enter();
    }

    private void OnPin(object sender, RoutedEventArgs e) => _w.Run(async () =>
    {
        if (SameDigits.IsChecked != true) throw new ArgumentException("Compare the number first, then tick the box.");
        PinGo.IsEnabled = false;
        try { await Gate.PinOwnerAsync(_w.Session.Api!, _w.Session.State!, _me!, _pass!, Ask); }
        finally { PinGo.IsEnabled = true; }
        Enter();
    });

    private void OnLater(object sender, RoutedEventArgs e) => Enter();

    private void Enter()
    {
        _pass = null;                                        // the passphrase isn't needed any more
        _w.Session.Start(_me!, Ask);
        _w.ShowChat();
    }

    private void OnSignOut(object sender, RoutedEventArgs e) => _w.Run(async () =>
    {
        await _w.Session.SignOutAsync(forgetPc: false);
        _w.ShowConnect();
    });
}
