# Release step "release": the GitHub Release "CipherChat <ver>" on tag v<ver> (pushed by the mirror step).
#   Notes   docs/release-notes/<ver>.md from the staged public copy (the same text as the repository), plus the downloads
#   Files   every file in Get-ReleaseFiles (installers, APK, Linux release, connector, source zip, checksums, notes,
#           test report), all from dist\<ver>\ (checked by the verify step)
# GitHub reports its own SHA-256 of every upload; it must equal ours. A release that exists is completed, never changed:
# missing files are uploaded, present files must match, and a mismatch stops the step (fix: a new version).
# Sign-in: the GitHub token Git Credential Manager already holds, in memory only.
param([Parameter(Mandatory)][string]$Version, [switch]$DryRun)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReleaseLib.ps1')
$cfg = Get-ReleaseConfig
$api = $cfg.publicRepoApi
$dist = Get-DistDir $Version
$tag = "v$Version"
$top = Join-Path (Get-StagingDir $Version) (Get-SourceName $Version)
if (-not (Test-Path $top)) { throw "no public copy staged for ${Version}: run the sanitise step first" }

# 1. The files, each checked before it goes anywhere.
$assets = Get-ReleaseFiles $Version | ForEach-Object { Join-Path $dist $_.File }
foreach ($a in $assets) { if (-not (Test-Path $a)) { throw "missing $a" } }

# 2. The notes: the release notes from the public copy, then what to download.
$notes = [IO.File]::ReadAllText((Join-Path $top "docs\release-notes\$Version.md"))
$notes = ($notes -replace '^# [^\n]*\n', '').Trim()
$body = @"
$notes

## Download

| File | What it is |
|---|---|
| ``CipherChat-$Version-Setup.exe`` | The Windows app (Windows 10 2004+ / 11). ``CipherChat-$Version-x64.msi`` is the same for administrators (msiexec, GPO, Intune). |
| ``CipherChat-$Version.apk`` | The Android app (Android 12+), signed. Its signing certificate is in ``android-signing-certificate.sha256``. |
| ``cipherchat-server-$Version-linux.tar.gz`` | The server for Linux: ``tar xzf``, then ``sudo sh cipherchat-server-$Version/install.sh`` (docs/LINUX-SERVER.md). |
| ``CipherChat-Connector-$Version-win-x64.zip`` | Add-ons: brings DarkCipher CommandCentre, or any MCP system, into the chat (docs/ADDONS.md). |
| ``CipherChat-$Version-source.zip`` | The source this release was built from (the same files as this repository at ``$tag``). |
| ``SHA256SUMS`` | SHA-256 of every file. ``tests-$Version.txt`` is the test report of this build. |

The Windows installers aren't code-signed yet, so SmartScreen will warn. Check a download against ``SHA256SUMS`` first:
``Get-FileHash .\CipherChat-$Version-Setup.exe -Algorithm SHA256``
"@

# 3. GitHub: the tag must be there (the mirror step pushes it), then create or complete the release.
if ($DryRun) {
    try { $h = Get-GitHubHeaders } catch { return New-StepResult 'would-do' "would create release $tag with $($assets.Count) files (no GitHub sign-in to check further)" }
}
else { $h = Get-GitHubHeaders }
$tagRef = Get-GitHubOrNull "$api/git/ref/tags/$tag" $h
if (-not $tagRef) {
    if ($DryRun) { return New-StepResult 'would-do' "would create release $tag (after the mirror step pushes the tag) with $($assets.Count) files" }
    throw "tag $tag is not on GitHub: run the mirror step first"
}
$rel = Get-GitHubOrNull "$api/releases/tags/$tag" $h
if (-not $rel) {
    if ($DryRun) { return New-StepResult 'would-do' "would create release $tag with $($assets.Count) files" }
    $json = @{ tag_name = $tag; name = "CipherChat $Version"; body = $body; draft = $false; prerelease = $false; make_latest = 'true' } | ConvertTo-Json
    $rel = Invoke-RestMethod "$api/releases" -Method Post -Headers $h -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($json))
    Write-Host "  created release $tag"
}
$present = @{}
foreach ($x in @($rel.assets)) { if ($x) { $present[$x.name] = $x } }
$uploaded = 0; $matched = 0; $todo = @()
foreach ($a in $assets) {
    $n = Split-Path $a -Leaf
    $local = 'sha256:' + (Get-FileHash $a -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($present.ContainsKey($n)) {
        if ($present[$n].digest -and $present[$n].digest -ne $local) { throw "GitHub already has $n with a different SHA-256 ($($present[$n].digest)). A published file is never replaced: release a new version." }
        $matched++; continue
    }
    if ($DryRun) { $todo += $n; continue }
    $up = ($rel.upload_url -replace '\{.*\}$', '') + '?name=' + [uri]::EscapeDataString($n)
    $ct = if ($n -like '*.txt' -or $n -like '*.sha256' -or $n -like '*.md' -or $n -eq 'SHA256SUMS') { 'text/plain' } elseif ($n -like '*.zip') { 'application/zip' } elseif ($n -like '*.apk') { 'application/vnd.android.package-archive' } else { 'application/octet-stream' }
    $r = Invoke-RestMethod $up -Method Post -Headers $h -ContentType $ct -InFile $a -TimeoutSec 1800
    if ($r.digest -and $r.digest -ne $local) { throw "GitHub stored $n with a different SHA-256 ($($r.digest))" }
    Write-Host ("  uploaded {0} ({1:N1} MB), SHA-256 confirmed" -f $n, ($r.size / 1MB))
    $uploaded++
}
if ($DryRun -and $todo.Count) { return New-StepResult 'would-do' "release $tag exists; would upload $($todo.Count) missing file(s): $($todo -join ', ')" }
if (-not $DryRun) { & (Join-Path $PSScriptRoot 'write-manifest.ps1') -Version $Version | Out-Host }
if ($uploaded -eq 0) { return New-StepResult 'skipped' "release $tag already has all $matched files, every SHA-256 matching" }
New-StepResult 'done' "release $tag ($($rel.html_url)): $uploaded uploaded, $matched already there, every SHA-256 matching"
