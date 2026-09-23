# SPDX-License-Identifier: GPL-3.0-or-later

[CmdletBinding()]
param(
  [ValidateSet('debug', 'release', 'sanitised')] [string] $Configuration = 'debug',
  [switch] $Boot,
  [switch] $Fault,
  [switch] $Storage,
  [switch] $ZiFs,
  [switch] $Identity
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$driverPath = Join-Path $PSScriptRoot 'build_driver.py'
. (Join-Path $PSScriptRoot 'enter_toolchain.ps1')
$selectedModes = 0
if ($Boot) { ++$selectedModes }
if ($Fault) { ++$selectedModes }
if ($Storage) { ++$selectedModes }
if ($ZiFs) { ++$selectedModes }
if ($Identity) { ++$selectedModes }
if ($selectedModes -gt 1) {
  throw 'Choose only one of -Boot, -Fault, -Storage, -ZiFs, or -Identity.'
}
$target = if ($Boot) {
  'boot-test'
} elseif ($Fault) {
  'fault-test'
} elseif ($Storage) {
  'storage-test'
} elseif ($ZiFs) {
  'zifs-test'
} elseif ($Identity) {
  'identity-test'
} else {
  'test'
}

& python $driverPath --root $repositoryRoot --configuration $Configuration --target $target
if ($LASTEXITCODE -ne 0) {
  throw "Zizium tests failed with exit code $LASTEXITCODE."
}
