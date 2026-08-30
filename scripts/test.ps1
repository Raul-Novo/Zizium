# SPDX-License-Identifier: GPL-3.0-or-later

[CmdletBinding()]
param(
  [ValidateSet('debug', 'release', 'sanitised')] [string] $Configuration = 'debug',
  [switch] $Boot,
  [switch] $Fault,
  [switch] $Storage,
  [switch] $ZiFs
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$driverPath = Join-Path $PSScriptRoot 'build_driver.py'
$selectedModes = 0
if ($Boot) { ++$selectedModes }
if ($Fault) { ++$selectedModes }
if ($Storage) { ++$selectedModes }
if ($ZiFs) { ++$selectedModes }
if ($selectedModes -gt 1) {
  throw 'Choose only one of -Boot, -Fault, -Storage, or -ZiFs.'
}
$target = if ($Boot) {
  'boot-test'
} elseif ($Fault) {
  'fault-test'
} elseif ($Storage) {
  'storage-test'
} elseif ($ZiFs) {
  'zifs-test'
} else {
  'test'
}

& python $driverPath --root $repositoryRoot --configuration $Configuration --target $target
if ($LASTEXITCODE -ne 0) {
  throw "Zizium tests failed with exit code $LASTEXITCODE."
}
