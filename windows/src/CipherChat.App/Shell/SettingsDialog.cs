using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using CipherChat.Crypto;
using CipherChat.Engine;
using CipherChat.Ui;
using CipherChat.Vault;

namespace CipherChat.App.Shell;

/// <summary>Settings: this PC (Windows Hello, auto-lock, forget), your chat passphrase, paired devices, about.</summary>
public static class SettingsDialog
{
    public static void Show(MainWindow w)
    {
        var s = w.Session;
        var e = s.Engine!;
        var d = Dialogs.New(w, "Settings", 560);

        d.Text("THIS PC", "Label");
        var hello = d.Add(new CheckBox { Content = "Protect this PC's pairing with Windows Hello", IsChecked = s.HelloOn, Margin = new Thickness(0, 0, 0, 4) });
        hello.SetResourceReference(FrameworkElement.StyleProperty, "Switch");
        hello.IsEnabled = s.Server is not null;
        d.Text("When on, CipherChat asks for your face, fingerprint or PIN before it can sign this PC in.", "Caption");
        d.Text("AUTO-LOCK", "Label");
        var mins = new[] { 5, 15, 30, 60 };
        var lockBox = d.Add(new ComboBox { ItemsSource = mins.Select(m => "after " + m + " minutes without activity").ToList(), SelectedIndex = Math.Max(0, Array.IndexOf(mins, s.Saved.AutoLockMinutes)), Margin = new Thickness(0, 0, 0, 10), Width = 340, HorizontalAlignment = HorizontalAlignment.Left });

        d.Text("TEXT SIZE", "Label");
        var sizeBox = d.Add(new ComboBox { ItemsSource = TextSize.Steps.Select(p => p + "%" + (p == 100 ? " (default)" : "")).ToList(), SelectedIndex = Math.Max(0, Array.IndexOf(TextSize.Steps, TextSize.Percent)), Margin = new Thickness(0, 0, 0, 4), Width = 340, HorizontalAlignment = HorizontalAlignment.Left });
        sizeBox.SelectionChanged += (_, _) => TextSize.Set(TextSize.Steps[Math.Max(0, sizeBox.SelectedIndex)]);     // live preview
        d.Text("The chat's text and emoji. Also Ctrl+= bigger, Ctrl+- smaller, Ctrl+0 back to 100%.", "Caption");

        d.Text("YOUR CHAT IDENTITY", "Label");
        d.Text("Fingerprint " + Hybrid.FpGroups(e.Me.Fp), "Caption");
        var row = d.Add(new WrapPanel { Margin = new Thickness(0, 4, 0, 10) });
        Button Btn(string text, Action click, string style = "SmallButton")
        {
            var b = new Button { Content = text, Margin = new Thickness(0, 0, 6, 6) };
            b.SetResourceReference(FrameworkElement.StyleProperty, style);
            b.Click += (_, _) => click();
            row.Children.Add(b);
            return b;
        }
        Btn("Change chat passphrase…", () => ChangePassphrase(w));
        Btn("Paired devices…", () => Devices(w));
        Btn("Devices holding your keys…", () => KeyDevices(w));
        Btn("Sign out", () => w.Run(async () => { d.Win.Close(); await s.SignOutAsync(forgetPc: false); w.ShowConnect(); }));
        Btn("Forget this PC…", () =>
        {
            if (!Dialogs.Confirm(w, "Forget this PC", "Sign out and delete this PC's pairing (and its Windows Hello key). Remove the pairing on the server too (/devices) so the code stops working.", "Forget", true)) return;
            w.Run(async () => { d.Win.Close(); await s.SignOutAsync(forgetPc: true); w.ShowConnect(); });
        }, "DangerButton");

        d.Text("ABOUT", "Label");
        d.Text("CipherChat 0.2.0 for Windows, by DarkCipher Systems. " + Hybrid.Suite + "; TLS 1.3 with X25519MLKEM768 only. Self-test: " +
               s.SelfTestResults.Count + "/" + s.SelfTestResults.Count + " checks passed (OpenSSL known answers).", "Caption");

        d.Cancel("Close");
        d.Button("Save", () => true, "PrimaryButton", isDefault: true);
        if (d.Show() is not true) return;
        w.Run(async () =>
        {
            if (s.Server is not null && hello.IsChecked == true != s.HelloOn)
            {
                if (hello.IsChecked == true && !await VaultStore.HelloAvailableAsync()) throw new InvalidOperationException("Windows Hello isn't set up on this PC.");
                await s.SetHelloAsync(hello.IsChecked == true);
            }
            await s.SetAutoLockAsync(mins[Math.Max(0, lockBox.SelectedIndex)]);
        });
    }

    private static void ChangePassphrase(MainWindow w)
    {
        var d = Dialogs.New(w, "Change chat passphrase", 440);
        var cur = d.Secret("CURRENT PASSPHRASE");
        var n1 = d.Secret("NEW PASSPHRASE");
        var n2 = d.Secret("NEW PASSPHRASE AGAIN");
        d.Text("Your keys are re-sealed with the new passphrase (Argon2id). Nobody can reset it for you.", "Caption");
        d.Cancel();
        d.Button("Change", () => n1.Password == n2.Password ? true : false, "PrimaryButton", isDefault: true);
        if (d.Show(cur) is not true) return;
        var (c, n) = (cur.Password, n1.Password);
        w.Run(async () =>
        {
            await Gate.ChangePassphraseAsync(w.Session.Api!, w.Session.Engine!.Me, c, n, err => Dialogs.AskCode(w, err));
            Dialogs.Info(w, "Passphrase changed", "Your keys are sealed with the new passphrase.");
        });
    }

    private static void Devices(MainWindow w) => w.Run(async () =>
    {
        var e = w.Session.Engine!;
        var list = (await e.DevicesAsync())["devices"] as JsonArray ?? [];
        var d = Dialogs.New(w, "Paired devices", 520);
        if (list.Count == 0) d.Text("No devices paired.");
        foreach (var dev in list.OfType<JsonObject>())
        {
            var id = dev["id"]!.GetValue<string>();
            var name = dev["name"]?.GetValue<string>() ?? "device";
            var dock = d.Add(new DockPanel { Margin = new Thickness(0, 0, 0, 6) });
            var rm = new Button { Content = "Remove" };
            rm.SetResourceReference(FrameworkElement.StyleProperty, "DangerButton");
            rm.Click += (_, _) =>
            {
                if (!Dialogs.Confirm(w, "Remove " + name, "The device is signed out at once and its pairing stops working.", "Remove", true)) return;
                w.Run(async () => { await e.RevokeDeviceAsync(id); d.Win.Close(); });
            };
            DockPanel.SetDock(rm, Dock.Right);
            dock.Children.Add(rm);
            dock.Children.Add(new TextBlock { Text = name + (dev["this"]?.GetValue<bool>() == true ? " (this PC)" : ""), VerticalAlignment = VerticalAlignment.Center });
        }
        d.Text("Pairing another device needs a sign-in with your password and code (not a paired device), so it's done from the web chat (/pair).", "Caption");
        d.Button("Close", () => true, "PrimaryButton", isDefault: true);
        d.Show();
    });

    // The devices on your signed device list hold your room keys. Removing one stops new history going to it and lets the
    // server delete wraps it never collected; a removed device wipes its own store the next time it's unlocked.
    private static void KeyDevices(MainWindow w)
    {
        var e = w.Session.Engine!;
        DeviceList? list;
        try { list = e.KeyDevices(); } catch (CryptoFail) { return; }
        var seen = e.DeviceSeen;
        var d = Dialogs.New(w, "Devices holding your room keys", 540);
        d.Text(e.Store is { } st ? "This PC keeps keys (device code " + st.Code() + "). They're sealed to this PC and your passphrase, and never leave it except to a device you approve."
                                 : "This session keeps no keys on this PC.", "Caption");
        if (list is null) d.Text("No devices yet: the server still holds every wrapped room key for you (compatibility mode).");
        foreach (var dev in list?.Devices ?? [])
        {
            var mine = e.Store is { } s && dev.Id == s.Dev;
            var dock = d.Add(new DockPanel { Margin = new Thickness(0, 0, 0, 6) });
            var rm = new Button { Content = "Remove" };
            rm.SetResourceReference(FrameworkElement.StyleProperty, "DangerButton");
            rm.Click += (_, _) =>
            {
                if (!Dialogs.Confirm(w, "Remove " + dev.Name, mine
                        ? "Remove this PC from your devices? The room keys it holds are wiped now, and older messages can only be read here again if another device sends them."
                        : "Remove " + dev.Name + " from your devices? It gets no more history, and wipes the keys it holds the next time it's unlocked. If it was lost or stolen, also reset your identity.",
                        "Remove", true)) return;
                w.Run(async () => { d.Win.Close(); await e.RemoveKeyDeviceAsync(list!, dev); });
            };
            DockPanel.SetDock(rm, Dock.Right);
            dock.Children.Add(rm);
            var when = seen.TryGetValue(dev.Id, out var at) ? "active " + DateTimeOffset.FromUnixTimeSeconds(at).ToLocalTime().ToString("d MMM yyyy", System.Globalization.CultureInfo.CurrentCulture) : "not seen yet";
            dock.Children.Add(new TextBlock { Text = dev.Name + (mine ? " (this PC)" : "") + "   " + when, VerticalAlignment = VerticalAlignment.Center });
        }
        if (e.Store is not null && list is { Devices.Count: > 1 }) d.Button("Ask for history again", () => "ask");
        d.Button("Close", () => true, "PrimaryButton", isDefault: true);
        if (d.Show() is "ask") w.Run(e.AskHistoryAgainAsync);
    }

    /// <summary>Another of my devices asks for this PC's room keys. True sends, false declines, null = not now.</summary>
    public static bool? ConfirmSync(MainWindow w, string name, DateTimeOffset added, string code)
    {
        var d = Dialogs.New(w, "Send history to a new device?", 480);
        d.Text("\"" + name + "\" (added " + added.ToString("g", System.Globalization.CultureInfo.CurrentCulture) + ") is asking for the room keys this PC holds, so it can read older messages.");
        d.Text("Approve only if it's your own device and it shows this code:", "Caption");
        d.Text(code, "Label");
        d.Text("Rooms whose admins turned history sync off aren't included, and nothing older than each room's history window.", "Caption");
        d.Button("Decline", () => "no", "DangerButton");
        d.Cancel("Not now");
        d.Button("Approve", () => "yes", "PrimaryButton");
        return d.Show() switch { "yes" => true, "no" => false, _ => null };
    }
}
