# SPDX-License-Identifier: GPL-3.0-or-later

[CmdletBinding()]
param(
  [ValidateSet('debug', 'release')] [string] $Configuration = 'debug',
  [ValidateSet('all', 'host', 'kernel', 'image', 'analyse', 'intel', 'run', 'boot-test', 'fault-test', 'storage-test', 'zifs-test')]
  [string] $Target = 'all'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$driverPath = Join-Path $PSScriptRoot 'build_driver.py'

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
  throw 'Python 3 is required. Install Python and ensure python.exe is on PATH.'
}

& python $driverPath --root $repositoryRoot --configuration $Configuration --target $Target
if ($LASTEXITCODE -ne 0) {
  throw "The Zizium build failed with exit code $LASTEXITCODE."
}
