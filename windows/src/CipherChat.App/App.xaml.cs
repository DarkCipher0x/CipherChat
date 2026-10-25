using System.Windows;
using System.Windows.Threading;
using CipherChat.App.Shell;
using CipherChat.Ui;

namespace CipherChat.App;

/// <summary>
/// Start-up. Command line:
///   --dev-server http://localhost:8094   use a development server on THIS machine over plain HTTP (loopback only)
/// Every other server is HTTPS with post-quantum-only TLS.
/// </summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnUnhandled;
        TaskScheduler.UnobservedTaskException += (_, a) => a.SetObserved();
        TextSize.Load();
        Uri? dev = null;
        for (var i = 0; i < e.Args.Length - 1; i++)
            if (e.Args[i] == "--dev-server" && Uri.TryCreate(e.Args[i + 1], UriKind.Absolute, out var u)) dev = u;
        var window = new MainWindow(new Session(dev));
        MainWindow = window;
        window.Show();
    }

    // Nothing fails silently or crashes the window: the message goes on screen, the app keeps running.
    private void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        e.Handled = true;
        Dialogs.Error(Current?.MainWindow, "Unexpected error", e.Exception.GetBaseException().Message);
    }
}
