# Release step "verify": the pre-publish checks on dist\<ver>\. It only reads, so it is always safe to run again.
#   - every expected file is there (installers, APK, Linux release, source zip, notes, checksums, test report);
#   - SHA256SUMS verifies, and lists every file in the folder;
#   - the version agrees everywhere: windows\Directory.Build.props, the MSI, the server, the Android app, the notes,
#     the Linux release's folder name, and the source zip's copies of them;
#   - the APK's own .sha256 and signing certificate file are there and consistent;
#   - the build passed: every test in tests-<ver>.txt passed.
param([Parameter(Mandatory)][string]$Version, [switch]$DryRun)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReleaseLib.ps1')
$dist = Get-DistDir $Version
if (-not (Test-Path $dist)) { throw "dist\$Version does not exist: build it first" }
$need = Get-ReleaseFiles $Version | ForEach-Object { $_.File }
$missing = @($need | Where-Object { -not (Test-Path (Join-Path $dist $_)) })
if ($missing.Count) { throw "missing from dist\${Version}: $($missing -join ', ')" }

# Checksums: every line verifies, and every file is listed (only this pipeline's own record and manifest may be unlisted).
$listed = @{}
foreach ($line in [IO.File]::ReadAllLines((Join-Path $dist 'SHA256SUMS'))) {
    if (-not $line.Trim()) { continue }
    if ($line -notmatch '^([0-9a-f]{64})  (.+)$') { throw "SHA256SUMS: unreadable line '$line'" }
    $want = $Matches[1]; $file = $Matches[2]
    $path = Join-Path $dist $file.Replace('/', '\')
    if (-not (Test-Path $path)) { throw "SHA256SUMS lists $file, which is missing" }
    if ((Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $want) { throw "checksum mismatch: $file" }
    $listed[$file] = $true
}
$unlisted = @(Get-ChildItem $dist -Recurse -File | ForEach-Object { $_.FullName.Substring($dist.Length + 1).Replace('\', '/') } |
    Where-Object { $_ -notin 'SHA256SUMS', 'release-state.json', 'release-manifest.json' -and -not $listed.ContainsKey($_) })
if ($unlisted.Count) { throw "files in dist\$Version that SHA256SUMS does not cover: $($unlisted -join ', ')" }
$apkSha = (Get-FileHash (Join-Path $dist "CipherChat-$Version.apk") -Algorithm SHA256).Hash.ToLowerInvariant()
if ([IO.File]::ReadAllText((Join-Path $dist "CipherChat-$Version.apk.sha256")) -notmatch $apkSha) { throw "CipherChat-$Version.apk.sha256 doesn't match the APK" }
if ([IO.File]::ReadAllText((Join-Path $dist 'android-signing-certificate.sha256')) -notmatch '[0-9a-fA-F:]{64,}') { throw 'android-signing-certificate.sha256 holds no certificate fingerprint' }

# The version, everywhere it is written.
function MsiVersion([string]$path) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @([string]$path, [int]0))
    $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @("SELECT Value FROM Property WHERE Property='ProductVersion'"))
    [void]$view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
    $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
    $v = $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, @(1))
    [void]$view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null)
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view); [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($db)
    $v
}
foreach ($msi in @("CipherChat-$Version-x64.msi")) {
    $v = MsiVersion (Join-Path $dist $msi)
    if ($v -ne $Version -and $v -ne "$Version.0") { throw "$msi says $v, not $Version" }
}
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$name = Get-SourceName $Version
$zip = [IO.Compression.ZipFile]::OpenRead((Join-Path $dist "$name.zip"))
try {
    function Read-Entry([string]$path) {
        $e = $zip.GetEntry("$name/$path")
        if (-not $e) { throw "the source zip has no $path (expected under $name/)" }
        $r = New-Object IO.StreamReader($e.Open()); try { $r.ReadToEnd() } finally { $r.Dispose() }
    }
    if ((Read-Entry 'windows/Directory.Build.props') -notmatch "<Version>$([regex]::Escape($Version))</Version>") { throw "the source's windows\Directory.Build.props is not $Version" }
    if ((Read-Entry 'server/cipherchat/server.py') -notmatch "(?m)^VERSION = `"$([regex]::Escape($Version))`"") { throw "the source's server.py VERSION is not $Version" }
    if ((Read-Entry 'android/app/build.gradle.kts') -notmatch "versionName = `"$([regex]::Escape($Version))`"") { throw "the source's Android versionName is not $Version" }
    if ((Read-Entry "docs/release-notes/$Version.md") -notmatch "^# CipherChat $([regex]::Escape($Version)) ") { throw "docs/release-notes/$Version.md does not start with '# CipherChat $Version'" }
    if ($zip.Entries | Where-Object { $_.FullName -notlike "$name/*" }) { throw "the source zip has files outside $name/" }
}
finally { $zip.Dispose() }
$tar = & tar -tzf (Join-Path $dist "cipherchat-server-$Version-linux.tar.gz") 2>$null | Select-Object -First 1
if ($tar -notlike "cipherchat-server-$Version/*") { throw "the Linux release isn't cipherchat-server-$Version/ ($tar)" }

# The build passed its own tests.
$tests = [IO.File]::ReadAllText((Join-Path $dist "tests-$Version.txt"))
if ($tests -notmatch 'Total tests: (\d+)') { throw "tests-$Version.txt has no total" }
$total = [int]$Matches[1]
if ($tests -notmatch '(?m)^Passed: (\d+)' -or [int]$Matches[1] -ne $total -or $tests -notmatch '(?m)^Failed: 0') { throw "tests-$Version.txt: not every one of the $total tests passed" }

New-StepResult 'done' "$($listed.Count) files match SHA256SUMS; MSI, server, Android, notes and Linux release all say $Version; $total/$total tests passed"
