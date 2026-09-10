# SPDX-License-Identifier: GPL-3.0-or-later
# Dot-source this file from the Windows build/test entry points.

$ErrorActionPreference = 'Stop'
$hasCrtHeaders = $false
foreach ($includeDirectory in ($env:INCLUDE -split ';')) {
  if ($includeDirectory -and (Test-Path -LiteralPath (Join-Path $includeDirectory 'errno.h'))) {
    $hasCrtHeaders = $true
    break
  }
}
if ($hasCrtHeaders -and (Get-Command link.exe -ErrorAction SilentlyContinue)) {
  return
}

$visualStudioLocator = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $visualStudioLocator -PathType Leaf)) {
  throw 'Visual Studio Build Tools with the x64 C++ tools and Windows SDK are required. Install them, then retry make from an x64 Developer PowerShell.'
}
$visualStudioRoot = & $visualStudioLocator -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or -not $visualStudioRoot) {
  throw 'No Visual Studio installation with x64 C++ tools was found. Install that workload and the Windows SDK, then retry make.'
}
$developerShell = Join-Path $visualStudioRoot 'Common7\Tools\Launch-VsDevShell.ps1'
if (-not (Test-Path -LiteralPath $developerShell -PathType Leaf)) {
  throw 'The Visual Studio developer-shell helper is missing. Repair the Build Tools installation or configure an x64 Developer PowerShell explicitly.'
}
& $developerShell -Arch amd64 -HostArch amd64 -SkipAutomaticLocation
