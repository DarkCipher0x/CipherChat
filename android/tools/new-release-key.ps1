# Creates CipherChat's Android release signing key ONCE: %LOCALAPPDATA%\CipherChat-signing\cipherchat-release.p12
# (RSA 4096, 30 years), its random password sealed for this Windows user with DPAPI. Android only installs updates
# signed by the same key, so this key must never be replaced: the script refuses if one exists. Back up the .p12 and
# the password (release.ps1 -ShowKeyPassword) to the password manager, offline.
#   powershell -NoProfile -ExecutionPolicy Bypass -File android\tools\new-release-key.ps1
. "$PSScriptRoot\env.ps1"
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$dir = Join-Path $env:LOCALAPPDATA 'CipherChat-signing'
$store = Join-Path $dir 'cipherchat-release.p12'
$pass = Join-Path $dir 'cipherchat-release.pass.dpapi'
if ((Test-Path $store) -or (Test-Path $pass)) { throw "A release key already exists in $dir. It must never be replaced." }
New-Item -ItemType Directory -Force $dir | Out-Null
$bytes = New-Object byte[] 24
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$secret = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
[IO.File]::WriteAllBytes($pass, [Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($secret), $null, 'CurrentUser'))
& (Join-Path $env:JAVA_HOME 'bin\keytool.exe') -genkeypair -alias cipherchat -keyalg RSA -keysize 4096 -validity 10950 `
    -dname 'CN=CipherChat, O=DarkCipher Systems' -keystore $store -storetype PKCS12 -storepass $secret -keypass $secret
if ($LASTEXITCODE -ne 0) { Remove-Item $store, $pass -ErrorAction SilentlyContinue; throw 'keytool failed' }
& (Join-Path $env:JAVA_HOME 'bin\keytool.exe') -list -v -keystore $store -storepass $secret | Select-String 'SHA256:'
Write-Host "Created $store. Back it up with its password (release.ps1 -ShowKeyPassword) in your password manager." -ForegroundColor Green
