param(
  [ValidateSet('chrome','edge','brave','opera','firefox')]
  [string]$Browser = 'chrome'
)

$ErrorActionPreference = 'Stop'
$base = 'https://frenzynets.com/frenzynet-updates'
$targetRoot = Join-Path $env:USERPROFILE 'Downloads\\FlickFuse-Extension'
New-Item -ItemType Directory -Path $targetRoot -Force | Out-Null

$zipName = if ($Browser -eq 'firefox') { 'flickfuse-extension-firefox-latest.zip' } else { 'flickfuse-extension-chromium-latest.zip' }
$zipPath = Join-Path $targetRoot $zipName
$extractPath = Join-Path $targetRoot ($zipName -replace '\\.zip$','')

Write-Host "Downloading $zipName ..."
Invoke-WebRequest -Uri "$base/$zipName" -OutFile $zipPath

if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

Write-Host "Extension extracted to: $extractPath"
Start-Process explorer.exe $extractPath

switch ($Browser) {
  'chrome' {
    Start-Process 'chrome.exe' 'chrome://extensions/'
    Write-Host 'Chrome opened. Enable Developer mode, click Load unpacked, select the extracted folder.'
  }
  'edge' {
    Start-Process 'msedge.exe' 'edge://extensions/'
    Write-Host 'Edge opened. Enable Developer mode, click Load unpacked, select the extracted folder.'
  }
  'brave' {
    Start-Process 'brave.exe' 'brave://extensions/'
    Write-Host 'Brave opened. Enable Developer mode, click Load unpacked, select the extracted folder.'
  }
  'opera' {
    Start-Process 'opera.exe' 'opera://extensions/'
    Write-Host 'Opera opened. Enable Developer mode, click Load unpacked, select the extracted folder.'
  }
  'firefox' {
    Start-Process 'firefox.exe' 'https://addons.mozilla.org/en-US/firefox/search/?q=flickfuse'
    Write-Host 'Firefox opened to Add-ons search. Install the official listing when available.'
  }
}

Write-Host 'Done.'
