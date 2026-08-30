# SPDX-License-Identifier: GPL-3.0-or-later

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $repositoryRoot 'external/dependencies.json'
$dependencyRoot = Join-Path $repositoryRoot 'external/deps'
$downloadRoot = Join-Path $dependencyRoot 'downloads'

function Test-DependencyHash {
  param(
    [Parameter(Mandatory)] [string] $Path,
    [Parameter(Mandatory)] [string] $ExpectedHash
  )

  $actualHash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actualHash -ne $ExpectedHash.ToLowerInvariant()) {
    throw "Checksum mismatch for '$Path': expected $ExpectedHash, received $actualHash."
  }
}

function Get-VerifiedDependency {
  param(
    [Parameter(Mandatory)] [pscustomobject] $Dependency,
    [Parameter(Mandatory)] [string] $Destination
  )

  if (Test-Path -LiteralPath $Destination) {
    Test-DependencyHash -Path $Destination -ExpectedHash $Dependency.sha256
    Write-Host "Using verified $($Dependency.name) $($Dependency.version)."
    return
  }

  Write-Host "Downloading $($Dependency.name) $($Dependency.version) from $($Dependency.url)"
  Invoke-WebRequest -UseBasicParsing -Uri $Dependency.url -OutFile $Destination
  Test-DependencyHash -Path $Destination -ExpectedHash $Dependency.sha256
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
New-Item -ItemType Directory -Path $downloadRoot -Force | Out-Null

foreach ($dependency in $manifest.dependencies) {
  $extension = [System.IO.Path]::GetExtension([uri]$dependency.url).TrimStart('.')
  if ($dependency.url.EndsWith('.tar.gz', [StringComparison]::OrdinalIgnoreCase)) {
    $extension = 'tar.gz'
  }

  $archiveName = "$($dependency.name)-$($dependency.version).$extension"
  $archivePath = Join-Path $downloadRoot $archiveName
  Get-VerifiedDependency -Dependency $dependency -Destination $archivePath

  $targetPath = Join-Path $dependencyRoot $dependency.name
  if ($dependency.name -eq 'limine-protocol') {
    New-Item -ItemType Directory -Path $targetPath -Force | Out-Null
    Copy-Item -LiteralPath $archivePath -Destination (Join-Path $targetPath 'limine.h') -Force
    continue
  }

  if (Test-Path -LiteralPath $targetPath) {
    continue
  }

  New-Item -ItemType Directory -Path $targetPath -Force | Out-Null
  if ($extension -eq 'zip') {
    Expand-Archive -LiteralPath $archivePath -DestinationPath $targetPath -Force
  } elseif ($extension -eq 'tar.gz') {
    & tar -xzf $archivePath -C $targetPath
    if ($LASTEXITCODE -ne 0) {
      throw "tar failed while extracting '$archivePath'."
    }
  } else {
    throw "Unsupported dependency archive '$archivePath'."
  }
}

Write-Host "Dependencies are available under '$dependencyRoot'."
