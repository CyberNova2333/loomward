# SPDX-License-Identifier: AGPL-3.0-only
param([Parameter(Mandatory)][string]$StateDir,
  [Parameter(Mandatory)][ValidateSet('Start','Stop','Status','Password','Approve')][string]$Action)
$ErrorActionPreference='Stop'
. ([IO.Path]::Combine($PSScriptRoot,'State-Safety.ps1'))
$state=Assert-PrivateState $StateDir
$configPath=Join-Path $state 'config.json'
Assert-WriteProtectedPath $configPath
$config=Get-Content -Raw -LiteralPath $configPath | ConvertFrom-Json
if(-not $config.requireLocalApproval -or -not $config.sandbox.enabled){throw 'No protected release is active.'}
$release=Assert-PlainLocalPath $config.sourceRoot
if([IO.Path]::GetDirectoryName($release) -ine $state -or [IO.Path]::GetFileName($release) -cnotmatch '^runtime-\d{8}-\d{6}-[a-f0-9]{8}$'){throw 'Invalid protected release.'}
$entry=if($Action -eq 'Approve'){'scripts\Approve.ps1'}else{'scripts\Manage.ps1'}
$script=Join-Path $release $entry
Assert-WriteProtectedPath $script
if($Action -eq 'Approve'){& $script -StateDir $state}else{& $script -StateDir $state -Action $Action}
