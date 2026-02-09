Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pyScript = Join-Path $scriptDir "get_youtube_subtitle.py"

$url = Read-Host "Paste YouTube URL (press Enter to download)"
if ([string]::IsNullOrWhiteSpace($url)) {
  Write-Error "Missing URL"
}

$lang = Read-Host "Optional: subtitle language code (e.g. zh-CN). Press Enter to auto-pick"
$outDir = Join-Path $scriptDir "dl"

$args = @($pyScript, $url, "--out", $outDir)
if (-not [string]::IsNullOrWhiteSpace($lang)) {
  $args += @("--lang", $lang)
}

python @args

