# FrenzyNet runtime diagnostics (safe, targeted checks only)
$ErrorActionPreference = "SilentlyContinue"

Write-Host "=== FrenzyNet Runtime Diagnostics ==="
Write-Host ("Timestamp: " + (Get-Date).ToString("u"))

$osArch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
$procArch = $env:PROCESSOR_ARCHITECTURE
Write-Host ("OS Architecture: " + $osArch)
Write-Host ("Process Architecture: " + $procArch)

$dotnetCmd = Get-Command dotnet -ErrorAction SilentlyContinue
if (-not $dotnetCmd) {
  Write-Host "dotnet command: NOT FOUND"
  Write-Host "Install .NET 8 Windows Desktop Runtime for your architecture."
  exit 1
}

Write-Host ("dotnet path: " + $dotnetCmd.Source)
Write-Host ""
Write-Host "Installed runtimes:"
$runtimes = & dotnet --list-runtimes
$runtimes | ForEach-Object { Write-Host ("  " + $_) }

$hasDesktop8 = $false
$hasCore8 = $false
foreach ($line in $runtimes) {
  if ($line -match "^Microsoft\.WindowsDesktop\.App 8\.0\.") { $hasDesktop8 = $true }
  if ($line -match "^Microsoft\.NETCore\.App 8\.0\.") { $hasCore8 = $true }
}

Write-Host ""
if ($hasDesktop8 -and $hasCore8) {
  Write-Host "Result: PASS"
  Write-Host "Required .NET 8 desktop/runtime components were detected."
  exit 0
}

Write-Host "Result: FAIL"
if (-not $hasDesktop8) { Write-Host "Missing: Microsoft.WindowsDesktop.App 8.0.x" }
if (-not $hasCore8) { Write-Host "Missing: Microsoft.NETCore.App 8.0.x" }
Write-Host "Install the correct .NET 8 Windows Desktop Runtime matching your app architecture."
exit 2

