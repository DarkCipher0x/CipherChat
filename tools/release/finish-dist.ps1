# Completes dist\<ver>\ after the installers, the APK and the Linux release are built (windows\tools\build-installers.ps1,
# android\tools\release.ps1, tools\build-linux-release.sh). Adds:
#   RELEASE-NOTES-<ver>.md   docs\release-notes\<ver>.md
#   CipherChat-<ver>-source.zip   every file on tools\public-allowlist.txt, under one top folder CipherChat-<ver>-source/
#                            (a file on neither list stops it: classify it first)
#   tests-<ver>.txt          a fresh run of the server, pentest, WebAuthn and Windows suites, plus the Android unit-test
#                            results of the last Android build
#   SHA256SUMS               rewritten over every file
# Usage: powershell -ExecutionPolicy Bypass -File tools\release\finish-dist.ps1 [-Version 0.1.2] [-SkipTests]
param([string]$Version, [switch]$SkipTests)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReleaseLib.ps1')
if (-not $Version) { $Version = Get-PropsVersion }
$dist = Get-DistDir $Version
if (-not (Test-Path $dist)) { throw "dist\$Version does not exist: build the installers first" }
$root = $script:ProjectRoot

# 1. Release notes
$notes = Join-Path $root "docs\release-notes\$Version.md"
if (-not (Test-Path $notes)) { throw "docs\release-notes\$Version.md is missing" }
Copy-Item $notes (Join-Path $dist "RELEASE-NOTES-$Version.md") -Force

# 2. The source zip: only allowlisted files, nothing unclassified
$files = @(Get-TreeFiles $root)
$split = Split-ByAllowlist $files
if ($split.Unclassified.Count) {
    $split.Unclassified | Select-Object -First 40 | ForEach-Object { Write-Host "  unclassified: $_" -ForegroundColor Red }
    throw "$($split.Unclassified.Count) file(s) are on neither tools\public-allowlist.txt nor tools\private-list.txt (above): classify them first"
}
$name = Get-SourceName $Version
$zipPath = Join-Path $dist "$name.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath }
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$z = [IO.Compression.ZipFile]::Open($zipPath, [IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($f in $split.Public) {
        $e = $z.CreateEntry("$name/$f", [IO.Compression.CompressionLevel]::Optimal)
        $e.LastWriteTime = [DateTimeOffset]'2026-01-01T00:00:00Z'          # reproducible: no build-time timestamps
        $src = [IO.File]::OpenRead((Join-Path $root $f.Replace('/', '\')))
        $dst = $e.Open()
        try { $src.CopyTo($dst) } finally { $dst.Dispose(); $src.Dispose() }
    }
}
finally { $z.Dispose() }
Write-Host ("source zip: {0} files ({1} kept private)" -f $split.Public.Count, $split.Private.Count)

# 3. The test report
$report = Join-Path $dist "tests-$Version.txt"
if (-not $SkipTests) {
    $py = Join-Path $root 'windows\build\python\python.exe'
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("CipherChat $Version test report ($((Get-Date).ToString('yyyy-MM-dd HH:mm')))")
    $total = 0; $passed = 0
    foreach ($t in 'test_server.py', 'pentest_server.py', 'test_webauthn.py') {
        $out = cmd /c "`"$py`" -I `"$(Join-Path $root "server\tests\$t")`" 2>&1" | Out-String     # via cmd: stderr is captured, never thrown (PS 5.1)
        $n = if ($out -match 'Ran (\d+) tests?') { [int]$Matches[1] } else { 0 }
        $ok = $out -match '(?m)^OK'
        $total += $n; if ($ok) { $passed += $n }
        $lines.Add(("server/tests/{0}: {1} tests, {2}" -f $t, $n, $(if ($ok) { 'all passed' } else { 'FAILED' })))
    }
    $out = cmd /c "dotnet test `"$(Join-Path $root 'windows\CipherChat.sln')`" -c Release --nologo -v q 2>&1" | Out-String
    foreach ($m in [regex]::Matches($out, 'Passed!\s+-\s+Failed:\s+(\d+), Passed:\s+(\d+), Skipped:\s+(\d+), Total:\s+(\d+)[^\n]*- (\S+\.dll)')) {
        $total += [int]$m.Groups[4].Value; $passed += [int]$m.Groups[2].Value
        $lines.Add(("windows {0}: {1} tests, {2} failed" -f $m.Groups[5].Value, $m.Groups[4].Value, $m.Groups[1].Value))
    }
    if ($out -match 'Failed!') { $lines.Add('windows: FAILED'); $total += 1 }
    $xml = Get-ChildItem (Join-Path $root 'android') -Recurse -Filter 'TEST-*.xml' -ErrorAction SilentlyContinue | Where-Object FullName -match '\\test-results\\'
    $at = 0; $af = 0
    foreach ($x in $xml) { $s = ([xml][IO.File]::ReadAllText($x.FullName)).testsuite; $at += [int]$s.tests; $af += [int]$s.failures + [int]$s.errors }
    $total += $at; $passed += ($at - $af)
    $lines.Add(("android (unit tests of the last android\tools\release.ps1 build): {0} tests, {1} failed" -f $at, $af))
    $lines.Add('')
    $lines.Add("Total tests: $total")
    $lines.Add("Passed: $passed")
    $lines.Add("Failed: $($total - $passed)")
    [IO.File]::WriteAllText($report, (($lines -join "`n") + "`n"), (New-Object Text.UTF8Encoding $false))
    $lines | ForEach-Object { Write-Host "  $_" }
    if ($total -ne $passed) { throw "not every test passed (tests-$Version.txt)" }
}
elseif (-not (Test-Path $report)) { throw "no tests-$Version.txt yet: run without -SkipTests once" }

# 4. Checksums over everything (the pipeline's own record and manifest excluded)
$sums = Get-ChildItem $dist -File | Where-Object { $_.Name -notin 'SHA256SUMS', 'release-state.json', 'release-manifest.json' } | Sort-Object Name |
    ForEach-Object { (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $_.Name }
[IO.File]::WriteAllText((Join-Path $dist 'SHA256SUMS'), (($sums -join "`n") + "`n"), (New-Object Text.UTF8Encoding $false))
Write-Host "dist\$Version complete: $(@($sums).Count) files in SHA256SUMS"
