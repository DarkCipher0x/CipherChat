# Regenerates windows\src\CipherChat.App\Shell\Emoji.cs and the Android app's EmojiSets.kt from web\app\emoji.js, so
# every client's emoji picker offers exactly the web chat's curated set. Run after editing emoji.js (ASCII only: Windows PowerShell 5.1 reads scripts as ANSI;
# the files themselves are read and written as UTF-8).
# Usage: powershell -ExecutionPolicy Bypass -File tools\gen-emoji.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$utf8 = New-Object Text.UTF8Encoding $false
$js = [IO.File]::ReadAllText((Join-Path $root 'web\app\emoji.js'), $utf8)

if ($js -notmatch '(?m)^export const QUICK = (\[[^\]]+\]);') { throw 'emoji.js: no QUICK list' }
$quick = $Matches[1]
$sets = [regex]::Matches($js, '(?m)^\s+\["([^"]+)", "([^"]+)"\],?\s*$')
if ($sets.Count -lt 3) { throw 'emoji.js: no SETS found' }

$lines = New-Object Collections.Generic.List[string]
$lines.Add('// GENERATED from web/app/emoji.js by tools/gen-emoji.ps1 (the same curated set as the web chat, so every client')
$lines.Add('// offers the same emoji). Nothing is fetched: the system emoji font draws them. Regenerate rather than edit by hand.')
$lines.Add('namespace CipherChat.App.Shell;')
$lines.Add('')
$lines.Add('public static class Emoji')
$lines.Add('{')
$lines.Add("    public static readonly string[] Quick = $quick;")
$lines.Add('    public static readonly (string Category, string Items)[] Sets =')
$lines.Add('    [')
foreach ($m in $sets) { $lines.Add(('        ("{0}", "{1}"),' -f $m.Groups[1].Value, $m.Groups[2].Value)) }
$lines.Add('    ];')
$lines.Add('')
$lines.Add('    public static IEnumerable<(string Emoji, string Name, string Category)> All =>')
$lines.Add('        Sets.SelectMany(s => s.Items.Split(''|'').Select(x => { var i = x.IndexOf('' '', StringComparison.Ordinal); return (x[..i], x[(i + 1)..], s.Category); }));')
$lines.Add('}')
$out = Join-Path $root 'windows\src\CipherChat.App\Shell\Emoji.cs'
[IO.File]::WriteAllText($out, (($lines -join "`n") + "`n"), $utf8)
Write-Host "wrote Emoji.cs: $($sets.Count) categories"

# The Android app's copy (feature/chat EmojiSets.kt)
$kt = New-Object Collections.Generic.List[string]
$kt.Add('// GENERATED from web/app/emoji.js by tools/gen-emoji.ps1 (the same curated set as the web chat and the Windows app).')
$kt.Add('// Nothing is fetched: the system emoji font draws them. Regenerate rather than edit by hand.')
$kt.Add('package systems.darkcipher.cipherchat.chat')
$kt.Add('')
$kt.Add('internal object EmojiSets {')
$kt.Add("    val quick = listOf($($quick.Trim('[', ']')))")
$kt.Add('    val sets = listOf(')
foreach ($m in $sets) { $kt.Add(('        "{0}" to "{1}",' -f $m.Groups[1].Value, $m.Groups[2].Value)) }
$kt.Add('    )')
$kt.Add('')
$kt.Add('    /** (emoji, name, category) for every entry, in picker order. */')
$kt.Add('    val all: List<Triple<String, String, String>> by lazy {')
$kt.Add('        sets.flatMap { (cat, items) -> items.split(''|'').map { x -> val i = x.indexOf('' ''); Triple(x.substring(0, i), x.substring(i + 1), cat) } }')
$kt.Add('    }')
$kt.Add('}')
$ktOut = Join-Path $root 'android\feature\chat\src\main\kotlin\systems\darkcipher\cipherchat\chat\EmojiSets.kt'
[IO.File]::WriteAllText($ktOut, (($kt -join "`n") + "`n"), $utf8)
Write-Host "wrote EmojiSets.kt: $($sets.Count) categories"
