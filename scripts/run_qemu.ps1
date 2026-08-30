# SPDX-License-Identifier: GPL-3.0-or-later

[CmdletBinding()]
param(
  [ValidateSet('debug', 'release')] [string] $Configuration = 'debug'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$driverPath = Join-Path $PSScriptRoot 'build_driver.py'

& python $driverPath --root $repositoryRoot --configuration $Configuration --target run
if ($LASTEXITCODE -ne 0) {
  throw "QEMU exited with code $LASTEXITCODE."
}
