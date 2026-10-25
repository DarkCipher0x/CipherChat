# Builds CipherChat's Android release: host tests, then the R8-minified APK signed with the key from new-release-key.ps1.
# Output: dist\<version>\CipherChat-<version>.apk (+ .sha256) and the signing certificate's SHA-256, which is also
# what a server puts in CIPHERCHAT_ANDROID_APPS to allow this app's passkeys.
#   powershell -NoProfile -ExecutionPolicy Bypass -File android\tools\release.ps1 [-SkipTests] [-ShowKeyPassword]
param([switch]$SkipTests, [switch]$ShowKeyPassword)
. "$PSScriptRoot\env.ps1"
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$android = Split-Path $PSScriptRoot -Parent
$repo = Split-Path $android -Parent

$dir = Join-Path $env:LOCALAPPDATA 'CipherChat-signing'
$store = Join-Path $dir 'cipherchat-release.p12'
$pass = Join-Path $dir 'cipherchat-release.pass.dpapi'
if (-not (Test-Path $store)) { throw 'No release key. Run android\tools\new-release-key.ps1 first (once, ever).' }
$secret = [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($pass), $null, 'CurrentUser'))
if ($ShowKeyPassword) { Write-Host "Keystore password (store it in your password manager): $secret"; return }

$gradle = [IO.File]::ReadAllText((Join-Path $android 'app\build.gradle.kts'))
$version = [regex]::Match($gradle, 'versionName = "([^"]+)"').Groups[1].Value
$out = Join-Path $repo "dist\$version"
$apk = Join-Path $out "CipherChat-$version.apk"
if (Test-Path $apk) { throw "$apk exists already. Bump versionName and versionCode first." }

$env:CIPHERCHAT_KEYSTORE = $store; $env:CIPHERCHAT_KEYSTORE_PASS = $secret
$env:CIPHERCHAT_KEY_ALIAS = 'cipherchat'; $env:CIPHERCHAT_KEY_PASS = $secret
Push-Location $android
try {
    $tasks = @(':app:assembleRelease')
    if (-not $SkipTests) { $tasks = @(':core:crypto:test', ':core:client:test', ':app:lintRelease') + $tasks }
    & .\gradlew.bat @tasks --console=plain
    if ($LASTEXITCODE -ne 0) { throw 'Gradle build failed' }
} finally {
    Pop-Location
    'CIPHERCHAT_KEYSTORE', 'CIPHERCHAT_KEYSTORE_PASS', 'CIPHERCHAT_KEY_ALIAS', 'CIPHERCHAT_KEY_PASS' | ForEach-Object { Remove-Item "Env:$_" -ErrorAction SilentlyContinue }
}

$tools = Get-ChildItem (Join-Path $env:ANDROID_HOME 'build-tools') -Directory | Sort-Object { [version]$_.Name } | Select-Object -Last 1
$apksigner = Join-Path $tools.FullName 'apksigner.bat'
$src = Join-Path $android 'app\build\outputs\apk\release\app-release.apk'
$check = & cmd /c "`"$apksigner`" verify --print-certs `"$src`" 2>nul"
if ($LASTEXITCODE -ne 0) { throw 'Signature check failed' }
$cert = ($check | Select-String 'SHA-256 digest: (\w+)' | Select-Object -First 1).Matches[0].Groups[1].Value
New-Item -ItemType Directory -Force $out | Out-Null
Copy-Item $src $apk
$hash = (Get-FileHash $apk -Algorithm SHA256).Hash.ToLower()
[IO.File]::WriteAllText("$apk.sha256", "$hash  $(Split-Path $apk -Leaf)`n")
$colon = (($cert.ToUpper() -split '(..)' | Where-Object { $_ }) -join ':')
[IO.File]::WriteAllText((Join-Path $out 'android-signing-certificate.sha256'),
    "$cert  CipherChat Android release signing certificate`nCIPHERCHAT_ANDROID_APPS=systems.darkcipher.cipherchat=$colon`n")
Write-Host "Built $apk  SHA-256 $hash" -ForegroundColor Green
Write-Host "Signing certificate SHA-256 $cert"
