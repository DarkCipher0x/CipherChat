# Dot-source this (". .\tools\env.ps1") to put the project's portable toolchain on PATH for this shell only.
# Nothing here needs admin; everything lives under %LOCALAPPDATA%.
$tc = Join-Path $env:LOCALAPPDATA 'DcxToolchain'
$env:GOROOT       = Join-Path $tc 'go'
$env:GOPATH       = Join-Path $tc 'gopath'
$env:JAVA_HOME    = Join-Path $tc 'jdk21'
$env:ANDROID_HOME = Join-Path $env:LOCALAPPDATA 'Android\Sdk'
$env:ANDROID_SDK_ROOT = $env:ANDROID_HOME
$ndk = Get-ChildItem (Join-Path $env:ANDROID_HOME 'ndk') -Directory -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
if ($ndk) { $env:ANDROID_NDK_HOME = $ndk.FullName }
$env:GOFLAGS = '-trimpath'          # no local paths in binaries (privacy gate: no paths in shipped artifacts)
$env:GOTOOLCHAIN = 'local'          # never auto-download another Go
$env:Path = @(
    (Join-Path $env:GOROOT 'bin'), (Join-Path $env:GOPATH 'bin'), (Join-Path $env:JAVA_HOME 'bin'),
    (Join-Path $env:ANDROID_HOME 'platform-tools'), (Join-Path $env:ANDROID_HOME 'cmdline-tools\latest\bin'), $env:Path
) -join ';'
