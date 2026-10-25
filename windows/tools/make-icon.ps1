# Renders the CipherChat mark (the same vector drawing as web/public/cipherchat.svg and Themes/Chat.xaml) at every
# Windows icon size and packs them into src/CipherChat.App/Assets/cipherchat.ico (PNG-compressed entries).
# Run from anywhere:  powershell -NoProfile -STA -File windows\tools\make-icon.ps1
#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root 'src\CipherChat.App\Assets\cipherchat.ico'
[IO.Directory]::CreateDirectory((Split-Path -Parent $out)) | Out-Null

$xaml = @'
<Canvas xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Width="64" Height="64">
  <Canvas.Resources>
    <LinearGradientBrush x:Key="Teal" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" StartPoint="0,0" EndPoint="1,1">
      <GradientStop Offset="0" Color="#5FF2EA"/>
      <GradientStop Offset="1" Color="#1FA9A3"/>
    </LinearGradientBrush>
  </Canvas.Resources>
  <Rectangle Canvas.Left="3" Canvas.Top="3" Width="58" Height="58" RadiusX="14" RadiusY="14" Fill="#081313" Stroke="{StaticResource Teal}" StrokeThickness="3"/>
  <Path Data="M15,17 H49 A4,4 0 0 1 53,21 V38 A4,4 0 0 1 49,42 H29 L20,49 V42 H15 A4,4 0 0 1 11,38 V21 A4,4 0 0 1 15,17 Z" Stroke="{StaticResource Teal}" StrokeThickness="3.5" StrokeLineJoin="Round"/>
  <Path Data="M20,25 L26,30 L20,35" Stroke="{StaticResource Teal}" StrokeThickness="3.5" StrokeStartLineCap="Round" StrokeEndLineCap="Round" StrokeLineJoin="Round"/>
  <Rectangle Canvas.Left="30" Canvas.Top="33" Width="14" Height="3.5" RadiusX="1.75" RadiusY="1.75" Fill="#3DD6D0"/>
</Canvas>
'@

$sizes = 16, 20, 24, 32, 40, 48, 64, 128, 256
$pngs = foreach ($s in $sizes) {
    $canvas = [Windows.Markup.XamlReader]::Parse($xaml)
    $box = New-Object Windows.Controls.Viewbox -Property @{ Width = $s; Height = $s; Child = $canvas }
    $box.Measure((New-Object Windows.Size $s, $s)); $box.Arrange((New-Object Windows.Rect 0, 0, $s, $s)); $box.UpdateLayout()
    $bmp = New-Object Windows.Media.Imaging.RenderTargetBitmap $s, $s, 96, 96, ([Windows.Media.PixelFormats]::Pbgra32)
    $bmp.Render($box)
    $enc = New-Object Windows.Media.Imaging.PngBitmapEncoder
    $enc.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bmp))
    $ms = New-Object IO.MemoryStream; $enc.Save($ms)
    , $ms.ToArray()
}

# ICONDIR, then one ICONDIRENTRY per size, then the PNG images
$ms = New-Object IO.MemoryStream; $w = New-Object IO.BinaryWriter $ms
$w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $s = $sizes[$i]; $dim = if ($s -ge 256) { 0 } else { $s }
    $w.Write([byte]$dim); $w.Write([byte]$dim); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([uint16]1); $w.Write([uint16]32); $w.Write([uint32]$pngs[$i].Length); $w.Write([uint32]$offset)
    $offset += $pngs[$i].Length
}
foreach ($p in $pngs) { $w.Write($p) }
$w.Flush(); [IO.File]::WriteAllBytes($out, $ms.ToArray())
# a 256 px PNG too, for README and store listings
[IO.File]::WriteAllBytes((Join-Path (Split-Path -Parent $out) 'cipherchat-256.png'), $pngs[-1])
Write-Host "wrote $out ($($sizes -join ', ') px)"
