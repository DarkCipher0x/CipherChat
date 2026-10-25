# The official embeddable Python from python.org, used to run the server's test suites on Windows (finish-dist.ps1;
# no installation, nothing added to PATH). This fetches it once into windows\build\python, checked against
# the SHA-256 python.org publishes for that file; a mismatch stops the build.
#   powershell -NoProfile -File windows\tools\fetch-python.ps1
#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
$Version = '3.14.4'
$Sha256 = 'cda80a9b1e75c0f1b4f9872ca1b417f0d19bce32facc811aea9180e70fad5fb9'   # python.org release page, "Windows embeddable package (64-bit)"
$Url = "https://www.python.org/ftp/python/$Version/python-$Version-embed-amd64.zip"

$root = Split-Path -Parent $PSScriptRoot
$build = Join-Path $root 'build'
$zip = Join-Path $build "python-$Version-embed-amd64.zip"
$dest = Join-Path $build 'python'
[IO.Directory]::CreateDirectory($build) | Out-Null

if (-not (Test-Path $zip)) {
    Write-Host "downloading $Url"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    Invoke-WebRequest -Uri $Url -OutFile "$zip.part" -UseBasicParsing
    Move-Item "$zip.part" $zip
}
$got = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
if ($got -ne $Sha256) {
    Remove-Item $zip
    throw "python-$Version-embed-amd64.zip has the wrong SHA-256 ($got, expected $Sha256): deleted, not used"
}
if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
Expand-Archive -Path $zip -DestinationPath $dest
# isolated: only the standard library zip and the folder itself on sys.path, no site-packages
$pth = Get-ChildItem $dest -Filter 'python*._pth' | Select-Object -First 1
[IO.File]::WriteAllText($pth.FullName, "python$($Version.Split('.')[0])$($Version.Split('.')[1]).zip`n.`n", (New-Object Text.UTF8Encoding $false))
Write-Host "Python $Version (SHA-256 verified) in $dest"
