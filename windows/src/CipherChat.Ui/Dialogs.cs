using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace CipherChat.Ui;

/// <summary>
/// The app's dialogs, built from the theme's styles so they look like the rest of the DarkCipher Systems apps. Every
/// dialog is modal to its window, closes on Esc, and puts text in with Text properties (never parsed as markup).
/// </summary>
public static class Dialogs
{
    public sealed class Builder
    {
        /// <summary>The dialog window itself (to close it from a button inside it).</summary>
        public Window Win { get; }
        internal readonly StackPanel Body = new();
        internal readonly StackPanel Buttons = new() { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 16, 0, 0) };
        internal object? Result;

        internal Builder(Window? owner, string title, double width)
        {
            Win = new Window
            {
                Title = title, Owner = owner, Width = width, SizeToContent = SizeToContent.Height, ResizeMode = ResizeMode.NoResize,
                WindowStartupLocation = owner is null ? WindowStartupLocation.CenterScreen : WindowStartupLocation.CenterOwner, ShowInTaskbar = false,
            };
            Win.SetResourceReference(Control.BackgroundProperty, "Surface");
            Win.SetResourceReference(Control.ForegroundProperty, "Fg");
            Win.PreviewKeyDown += (_, e) => { if (e.Key == Key.Escape) Win.Close(); };
            var root = new StackPanel { Margin = new Thickness(20, 16, 20, 18) };
            root.Children.Add(Body);
            root.Children.Add(Buttons);
            WindowFrame.Frame(Win, root, title, "");               // the title lives in the top bar
        }

        public TextBlock Text(string text, string style = "Body")
        {
            var t = new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8) };
            t.SetResourceReference(FrameworkElement.StyleProperty, style);
            Body.Children.Add(t);
            return t;
        }

        public T Add<T>(T element) where T : UIElement { Body.Children.Add(element); return element; }

        public TextBox Field(string label, string initial = "", int max = 200)
        {
            Text(label, "Label");
            var box = new TextBox { Text = initial, MaxLength = max, Margin = new Thickness(0, 0, 0, 10) };
            Body.Children.Add(box);
            return box;
        }

        public PasswordBox Secret(string label)
        {
            Text(label, "Label");
            var box = new PasswordBox { MaxLength = 1024, Margin = new Thickness(0, 0, 0, 10) };
            Body.Children.Add(box);
            return box;
        }

        public Button Button(string label, Func<object?> value, string? style = null, bool isDefault = false)
        {
            var b = new Button { Content = label, Margin = new Thickness(8, 0, 0, 0), IsDefault = isDefault, MinWidth = 84 };
            if (style is not null) b.SetResourceReference(FrameworkElement.StyleProperty, style);
            b.Click += (_, _) =>
            {
                var v = value();
                if (v is false) return;                          // validation failed: keep the dialog open
                Result = v;
                Win.Close();
            };
            Buttons.Children.Add(b);
            return b;
        }

        public void Cancel(string label = "Cancel") => Button(label, () => null);

        public object? Show(UIElement? focus = null)
        {
            if (focus is not null) Win.Loaded += (_, _) => focus.Focus();
            Win.ShowDialog();
            return Result;
        }
    }

    public static Builder New(Window? owner, string title, double width = 460) => new(owner, title, width);

    public static void Error(Window? owner, string title, string text)
    {
        var d = New(owner, title);
        d.Text(text).SetResourceReference(TextBlock.ForegroundProperty, "Bad");
        d.Button("OK", () => true, "PrimaryButton", isDefault: true);
        d.Show();
    }

    public static void Info(Window? owner, string title, string text)
    {
        var d = New(owner, title);
        d.Text(text);
        d.Button("OK", () => true, "PrimaryButton", isDefault: true);
        d.Show();
    }

    public static bool Confirm(Window? owner, string title, string text, string ok, bool danger = false)
    {
        var d = New(owner, title);
        d.Text(text);
        d.Cancel();
        d.Button(ok, () => true, danger ? "DangerButton" : "PrimaryButton", isDefault: !danger);
        return d.Show() is true;
    }

    public static string? Prompt(Window? owner, string title, string text, string label, string initial = "", int max = 200)
    {
        var d = New(owner, title);
        if (text.Length > 0) d.Text(text);
        var box = d.Field(label, initial, max);
        d.Cancel();
        d.Button("OK", () => box.Text.Trim().Length > 0 ? box.Text.Trim() : false, "PrimaryButton", isDefault: true);
        return d.Show(box) as string;
    }

    /// <summary>"Confirm it's you": the current authenticator code, or null if cancelled. Runs on the UI thread.</summary>
    public static Task<string?> AskCode(Window owner, string? error) => owner.Dispatcher.InvokeAsync(() =>
    {
        var d = New(owner, "Confirm it's you", 400);
        d.Text("This is a sensitive step (your keys, a certificate or a paired device). Enter the current 6-digit code from your authenticator app.");
        var box = d.Field("Authenticator code", "", 6);
        box.FontFamily = (FontFamily)owner.FindResource("MonoFont");
        box.FontSize = 18;
        if (error is not null) d.Text(error).SetResourceReference(TextBlock.ForegroundProperty, "Bad");
        d.Cancel();
        d.Button("Confirm", () => box.Text.Trim().Length == 6 && box.Text.Trim().All(char.IsAsciiDigit) ? box.Text.Trim() : false, "PrimaryButton", isDefault: true);
        return d.Show(box) as string;
    }).Task;

    /// <summary>Shows a one-time secret (a pairing code) with a copy button.</summary>
    public static void ShowSecret(Window owner, string title, string text, string secret, string note)
    {
        var d = New(owner, title, 560);
        d.Text(text);
        var box = d.Add(new TextBox { Text = secret, IsReadOnly = true, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8) });
        box.SetResourceReference(Control.FontFamilyProperty, "MonoFont");
        d.Text(note, "Caption");
        d.Button("Copy", () => { Clipboard.SetText(secret); return false; });
        d.Button("Done", () => true, "PrimaryButton", isDefault: true);
        d.Show();
    }
}
