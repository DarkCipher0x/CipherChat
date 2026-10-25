# First release only: creates the two GitHub repositories the pipeline publishes to, then clones the public one beside
# this project (release-config.json: publicClone). Without -Create it only reports what exists and what it would do.
#   DarkCipher0x/CipherChat           public, the sanitised mirror (release.ps1's mirror and release steps)
#   DarkCipher0x/CipherChat-private   private, this project's full working tree (origin)
# Both get Dependabot alerts, secret scanning with push protection, and private vulnerability reporting where GitHub
# offers them. Sign-in: the GitHub token Git Credential Manager already holds, in memory only.
# Usage: powershell -ExecutionPolicy Bypass -File tools\release\create-repos.ps1 [-Create]
param([switch]$Create)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReleaseLib.ps1')
if ($Create -and (Test-PublishOff)) { throw 'Held by the kill switch (DCX_PUBLISH_OFF): nothing created' }
$cfg = Get-ReleaseConfig
$h = Get-GitHubHeaders
$me = (Invoke-RestMethod 'https://api.github.com/user' -Headers $h).login
$repos = @(
    @{ Name = 'CipherChat'; Private = $false; Description = 'Post-quantum end-to-end encrypted chat and calls on your own server: web, Windows and Android.' },
    @{ Name = 'CipherChat-private'; Private = $true; Description = 'CipherChat working tree (private).' }
)
foreach ($r in $repos) {
    $api = "https://api.github.com/repos/$me/$($r.Name)"
    $have = Get-GitHubOrNull $api $h
    if ($have) {
        if ([bool]$have.private -ne $r.Private) { throw "$me/$($r.Name) exists but is $(if ($have.private) { 'private' } else { 'public' }): visibility is never changed here" }
        Write-Host "  $me/$($r.Name): exists ($(if ($have.private) { 'private' } else { 'public' }))"
        continue
    }
    if (-not $Create) { Write-Host "  $me/$($r.Name): would create ($(if ($r.Private) { 'private' } else { 'public' }))"; continue }
    $body = @{ name = $r.Name; description = $r.Description; private = $r.Private; has_wiki = $false; has_projects = $false; auto_init = $false } | ConvertTo-Json
    Invoke-RestMethod 'https://api.github.com/user/repos' -Method Post -Headers $h -ContentType 'application/json' -Body $body | Out-Null
    Write-Host "  $me/$($r.Name): created"
    foreach ($try in @(
        @{ Uri = "$api/vulnerability-alerts"; Method = 'Put'; Body = $null },
        @{ Uri = "$api/private-vulnerability-reporting"; Method = 'Put'; Body = $null },
        @{ Uri = $api; Method = 'Patch'; Body = (@{ security_and_analysis = @{ secret_scanning = @{ status = 'enabled' }; secret_scanning_push_protection = @{ status = 'enabled' } } } | ConvertTo-Json -Depth 4) })) {
        try { Invoke-RestMethod $try.Uri -Method $try.Method -Headers $h -ContentType 'application/json' -Body $try.Body | Out-Null }
        catch { Write-Host "    (not available for this repository: $($try.Uri -replace '^.*/', ''))" -ForegroundColor DarkGray }
    }
}
$clone = [IO.Path]::GetFullPath((Join-Path $script:ProjectRoot $cfg.publicClone))
if (Test-Path (Join-Path $clone '.git')) { Write-Host "  public clone: $clone (exists)" }
elseif (-not $Create) { Write-Host "  public clone: would clone $($cfg.publicRemote) into $clone" }
else { & git clone $cfg.publicRemote $clone; if ($LASTEXITCODE) { throw 'git clone failed' }; Write-Host "  public clone: $clone" }
if (-not $Create) { Write-Host 'Nothing was changed. Run with -Create to create them.' -ForegroundColor Cyan }
