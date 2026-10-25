# Dot-source this (". .\tools\env.ps1") to put the portable toolchain (shared with the other DarkCipher Android apps)
# on PATH for this shell only. Nothing here needs admin; everything lives under %LOCALAPPDATA%.
$tc = Join-Path $env:LOCALAPPDATA 'DcxToolchain'
$env:JAVA_HOME    = Join-Path $tc 'jdk21'
$env:ANDROID_HOME = Join-Path $env:LOCALAPPDATA 'Android\Sdk'
$env:ANDROID_SDK_ROOT = $env:ANDROID_HOME
$env:Path = @(
    (Join-Path $env:JAVA_HOME 'bin'), (Join-Path $env:ANDROID_HOME 'platform-tools'), (Join-Path $env:ANDROID_HOME 'emulator'),
    (Join-Path $env:ANDROID_HOME 'cmdline-tools\latest\bin'), $env:Path
) -join ';'
