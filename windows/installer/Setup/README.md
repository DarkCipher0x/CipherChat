# DarkCipher Setup: the themed setup program (template)

`Setup.exe` is the modern, DarkCipher-themed way to install an app by double-clicking a download. It is a WiX Burn
bundle with its own setup program (this folder) around the app's MSI. The MSI is still the engine and still deploys on
its own (`msiexec`, Group Policy, Intune): administrators keep using the MSI; people downloading get `Setup.exe`.

What it shows (everything from the app's `setup-app.json`; this folder names no app):

A wizard (since ServerManagement 0.6.14, the ParallelPath layout in DarkCipher branding): the **rail** on the left has the
logo, DARKCIPHER SYSTEMS, the two-tone title (`titleAccent`), the darkcipher0x prompt with a blinking cursor (`prompt`),
the steps with their progress (done ✓, current ●), the badge (`badge`), the version, who built it (`builtBy`) and the
website and licence links. The page is on the right, with Cancel / Back / Next along the bottom.

| Page | What it does |
|------|--------------|
| Welcome | The tagline, the intro (`intro`) and up to four cards (`highlights`), the data note. **Update** wording when an older version is installed (the licence page is skipped then) |
| Licence | LICENSE.txt (paragraphs reflowed) in a card; Next only once "I accept the licence" is ticked |
| Options | Install folder; one card per option (an MSI property). Something already on the PC shows **Already installed**, starts off and leaves the property to the MSI |
| Checks | Windows build (`minBuild`), 64-bit, free disk space on the install drive (`diskMb`), what else will be set up, the one administrator approval. A hard problem stops Install |
| Install | The percentage, one progress bar, the current package; Cancel rolls back |
| Done | installed / updated / repaired / uninstalled (`doneNote`); "Open <app> now"; a failure shows the error and "Open the log" |
| Maintenance | When the same version is installed: **Repair** or **Uninstall** as cards, then the uninstall page with the app's "remove my data" card |

`--preview <folder> <out>` renders every page (11 PNGs) without showing a window; the PC's name is replaced by a
fictional one so the renders can be published.

Silent use works like any Burn bundle: `Setup.exe /quiet` (install), `/quiet /uninstall`, `/passive`, `/log <file>`.
With no window, the setup program detects, plans and applies the command-line action and exits with its result.

## Files

| File | Per app? | Purpose |
|------|----------|---------|
| `installer\Setup\Bundle.wxs` | no (template) | The bundle: the setup program's payloads, the MSI in the chain, the variables passed to the MSI |
| `installer\Setup\DarkCipher.Setup.csproj`, `*.cs`, `Theme.xaml` | no (template) | The setup program: its own small exe (WiX 5 runs it beside the Burn engine), on the .NET Framework 4.8 that every supported Windows has |
| `installer\setup-app.wxi` | **yes** | Name, manufacturer, **BundleUpgradeCode** (the setup's permanent identity: never change it), icon, logo, licence, the MSI's install-folder property and default, the exe to open at the end |
| `installer\setup-app.properties.wxi` | **yes** | The MSI properties passed through (one line each) |
| `installer\setup-app.json` | **yes** | The texts and switches the setup program shows, and how to tell each option is already installed |

## Using it in another app

1. Copy `installer\Setup\` into the app's `installer\` folder unchanged.
2. Write the app's three `installer\setup-app.*` files (copy ServerManagement's and change them). Give it a new
   `BundleUpgradeCode` (`[guid]::NewGuid()`), and keep it forever.
3. Build: `dotnet build installer\Setup\DarkCipher.Setup.csproj -c Release`, then
   `wix build installer\Setup\Bundle.wxs -d Version=<ver> -d MsiPath=<the app's msi>
   -d SetupBin=installer\Setup\bin\Release\net48\win-x64 -d AppInclude=installer\setup-app.wxi -o dist\<ver>\<App>-<ver>-Setup.exe`
   (ServerManagement's `build.ps1` step 3b does exactly this).
4. Hand-test once: install, update over the previous version, repair, uninstall (keep and remove data), and
   `Setup.exe /quiet` on a VM.

Detection kinds for an option (`detect` in `setup-app.json`): `appPath` (a packaged app's command under App Paths, e.g.
winget.exe), `uninstall32` (a 32-bit uninstall entry), `hklm64` / `hkcu` (a registry key and value), `file` (a path with
%VARIABLES%).

The setup is not code-signed yet (no certificate), so SmartScreen warns as it does for the MSI. Sign `Setup.exe` with
the same certificate as the MSI when there is one (`wix burn detach` / `reattach` for the engine, then sign the bundle).
