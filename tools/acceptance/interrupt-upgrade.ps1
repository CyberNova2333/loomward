# SPDX-License-Identifier: AGPL-3.0-only
param([string]$StateDir,[string]$Workspace,[string]$Image,[string]$Context)
$ErrorActionPreference='Stop'
$target=Join-Path $StateDir 'installation.json'
$reader=[IO.File]::Open($target,'Open','Read','Read')
try {
  try {
    & (Join-Path $PSScriptRoot '..\..\scripts\Install-Hardened.ps1') -StateDir $StateDir -Workspace $Workspace -Image $Image -Context $Context
  } catch {
    $cause=$_.Exception.GetBaseException()
    if($cause -is [IO.IOException] -and ($cause.HResult -band 0xffff) -eq 32){return}
    throw
  }
  throw 'Expected the sharing violation to interrupt publication.'
} finally {$reader.Dispose()}
