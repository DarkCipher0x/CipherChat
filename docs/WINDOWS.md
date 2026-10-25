# CipherChat on Windows

The CipherChat app for Windows (chat and calls) has a self-contained, 64-bit installer: no .NET to install. The server
runs on Linux ([LINUX-SERVER.md](LINUX-SERVER.md)).

> The installers aren't Authenticode-signed yet. Check the download against `SHA256SUMS`
> (`Get-FileHash .\CipherChat-0.1.2-Setup.exe`). SmartScreen shows a warning ("More info" → "Run anyway"); on PCs with
> **Smart App Control** turned on, unsigned programs are blocked outright until signed builds are published.

## The app — `CipherChat-0.1.2-Setup.exe`

Windows 10 version 2004 or later, or Windows 11. The setup offers a desktop shortcut and Microsoft Edge WebView2 (needed
for calls; built into Windows 11). Administrators can deploy `CipherChat-0.1.2-x64.msi` instead:

```
msiexec /i CipherChat-0.1.2-x64.msi /qn [INSTALLDESKTOPSHORTCUT=0] [INSTALLWEBVIEW2=0]
msiexec /x CipherChat-0.1.2-x64.msi /qn [REMOVE_DATA=1]
```

First start:

1. **Connect** — paste a pairing code (in the web chat type `/pair`, or in the Android app signed in with your
   password: Settings → Pair another device; a paired device can't pair others), sign in with your password and
   authenticator code, or use a **passkey** (Windows Hello, your phone, a security key, or a password manager such as
   Bitwarden).
2. **Unlock** — your chat passphrase opens your keys (they never leave memory, and are wiped when you lock, close the
   app or stay idle). First time ever: choose the passphrase and the app creates your keys.
3. **Verify the owner** — compare the 60-digit safety number with the server's owner in person or on a call, then tick
   "the numbers are the same". Until then nobody can be trusted.

Pairing remembers this PC (the server address and a revocable device token, sealed with DPAPI and optionally Windows
Hello in Settings); signing in with a password doesn't. Calls open in their own window; the PC rings with its own
pop-up and taskbar flash. Data lives in `%LOCALAPPDATA%\CipherChat`.

## Building from source

```powershell
cd windows
dotnet test                                                     # unit tests (live ones need CIPHERCHAT_DEV_*)
powershell -File tools\build-installers.ps1                     # dist\<version>\ MSI + Setup.exe + Connector + SHA256SUMS
```

Signing: set `DCX_SIGN_THUMBPRINT` to a code-signing certificate's thumbprint (Windows SDK signtool) and the script
signs the programs, the MSI and the setup bundle (engine and bundle).
