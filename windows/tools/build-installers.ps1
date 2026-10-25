# CipherChat by DarkCipher Systems: builds the Windows installers into dist\<version>\
#   CipherChat-<ver>-x64.msi, CipherChat-<ver>-Setup.exe    (the app)
# The server is Linux only (tools\build-linux-release.sh).
# Self-contained .NET (no runtime to install), WiX 5 (pinned in .config\dotnet-tools.json), the DarkCipher Setup
# template (installer\Setup) around the MSI. Signs with Authenticode when DCX_SIGN_THUMBPRINT is set.
#   powershell -NoProfile -ExecutionPolicy Bypass -File windows\tools\build-installers.ps1 [-Version <x.y.z>] [-SkipTests]
#Requires -Version 5.1
param([string]$Version, [switch]$SkipTests)
$ErrorActionPreference = 'Stop'
$win = Split-Path -Parent $PSScriptRoot
if (-not $Version) { $Version = ([xml](Get-Content (Join-Path $win 'Directory.Build.props') -Raw)).Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1 }   # one source of truth
$repo = Split-Path -Parent $win
$out = Join-Path $repo "dist\$Version"
$stage = Join-Path $win 'build\stage'
Set-Location $win

function Step($t) { Write-Host "`n== $t" -ForegroundColor Cyan }
function Check($what) { if ($LASTEXITCODE) { throw "$what failed (exit $LASTEXITCODE)" } }

$thumb = $env:DCX_SIGN_THUMBPRINT
$signtool = if ($thumb) { Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue | Where-Object FullName -match '\\x64\\' | Sort-Object FullName -Descending | Select-Object -First 1 }
function Sign($file) {
    if (-not $thumb) { return }
    if (-not $signtool) { throw 'DCX_SIGN_THUMBPRINT is set but signtool.exe (Windows SDK) was not found' }
    & $signtool.FullName sign /sha1 $thumb /fd SHA256 /tr 'http://timestamp.digicert.com' /td SHA256 /q $file; Check "signing $file"
}

if (-not $SkipTests) {
    Step 'Unit tests (the live ones run only with CIPHERCHAT_DEV_* set)'
    dotnet test CipherChat.sln -c Release --nologo -v q; Check 'dotnet test'
}

Step 'Publish (self-contained, win-x64)'
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
$client = Join-Path $stage 'client'
dotnet publish src\CipherChat.App\CipherChat.App.csproj -c Release -r win-x64 --self-contained true -o $client -nologo -v q; Check 'publish app'
Get-ChildItem $client -Recurse -Include *.pdb | Remove-Item -Force   # no debug symbols or build paths in a release

foreach ($f in Get-ChildItem $client -Recurse -Include CipherChat*.exe, CipherChat*.dll) { Sign $f.FullName }

Step 'MSIs (WiX 5)'
New-Item -ItemType Directory $out -Force | Out-Null
dotnet tool restore | Out-Null; Check 'dotnet tool restore'
foreach ($e in 'WixToolset.UI.wixext', 'WixToolset.Util.wixext') { dotnet tool run wix extension add -g "$e/5.0.2" | Out-Null; Check "wix extension $e" }
$numeric = ($Version -split '-')[0]
$clientMsi = Join-Path $out "CipherChat-$Version-x64.msi"
dotnet tool run wix build installer\client\CipherChat.wxs -arch x64 -ext WixToolset.UI.wixext `
    -d Version=$numeric -d PublishDir="$client" -d Root="$win" -d Repo="$repo" -wx -o $clientMsi; Check 'wix build (app)'
Sign $clientMsi

Step 'Setup.exe (the DarkCipher Setup template around the MSI)'
dotnet build installer\Setup\DarkCipher.Setup.csproj -c Release -nologo -v q | Out-Null; Check 'setup program build'
$setupBin = Join-Path $win 'installer\Setup\bin\Release\net48\win-x64'
foreach ($p in @(@{ Dir = 'client'; Msi = $clientMsi; Exe = "CipherChat-$Version-Setup.exe" })) {
    $check = & "$setupBin\DarkCipher.Setup.exe" --check (Join-Path $win "installer\$($p.Dir)")
    if ($LASTEXITCODE) { throw "setup-app.json check failed ($($p.Dir)): $check" }
    $exe = Join-Path $out $p.Exe
    dotnet tool run wix build installer\Setup\Bundle.wxs -d Version=$numeric -d AppRoot="$win" -d MsiPath="$($p.Msi)" `
        -d SetupBin="$setupBin" -d AppInclude="$win\installer\$($p.Dir)\setup-app.wxi" -wx -o $exe; Check "setup bundle ($($p.Dir))"
    if ($thumb) {
        $engine = Join-Path $out 'setup-engine.exe'
        dotnet tool run wix burn detach $exe -engine $engine; Check 'wix burn detach'
        Sign $engine
        dotnet tool run wix burn reattach $exe -engine $engine -o $exe; Check 'wix burn reattach'
        Remove-Item $engine
    }
    Sign $exe
}
Remove-Item (Join-Path $out '*.wixpdb') -ErrorAction SilentlyContinue

Step 'Checksums'
$sums = Get-ChildItem $out -File | Where-Object Name -ne 'SHA256SUMS' | Sort-Object Name | ForEach-Object { (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower() + '  ' + $_.Name }
[IO.File]::WriteAllText((Join-Path $out 'SHA256SUMS'), (($sums -join "`n") + "`n"), (New-Object Text.UTF8Encoding $false))
Get-ChildItem $out -File | Select-Object Name, @{ n = 'MB'; e = { [math]::Round($_.Length / 1MB, 1) } } | Format-Table -AutoSize
if (-not $thumb) { Write-Host 'Not Authenticode-signed (no DCX_SIGN_THUMBPRINT): SmartScreen will warn on downloaded copies.' -ForegroundColor Yellow }
