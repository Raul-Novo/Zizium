# SPDX-License-Identifier: GPL-3.0-or-later

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$buildRoot = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot 'build'))

if (-not $buildRoot.StartsWith($repositoryRoot + [System.IO.Path]::DirectorySeparatorChar,
    [StringComparison]::OrdinalIgnoreCase)) {
  throw "Refusing to clean an unexpected path: '$buildRoot'."
}

if (Test-Path -LiteralPath $buildRoot) {
  Remove-Item -LiteralPath $buildRoot -Recurse -Force
  Write-Host "Removed '$buildRoot'."
} else {
  Write-Host "Nothing to clean."
}
