# SPDX-License-Identifier: AGPL-3.0-only
# This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
param(
  [string]$StateDir=([IO.Path]::Combine([Environment]::GetFolderPath('UserProfile'), '.agentdock-bridge')),
  [string]$Workspace='D:\Projects',
  [string]$Image='agentdock-dev:2026-10-28',
  [string]$Context='desktop-linux',
  [switch]$AllowOutbound=$true,
  [string]$Proxy
)
$ErrorActionPreference='Stop'
. ([IO.Path]::Combine($PSScriptRoot, 'State-Safety.ps1'))
$source=Split-Path -Parent $PSScriptRoot
$workspacePath=(Resolve-Path -LiteralPath $Workspace).Path.TrimEnd('\')
$statePath=Assert-PrivateState $StateDir
if($statePath -ieq $workspacePath -or $statePath.StartsWith($workspacePath+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Private runtime must not be inside the mounted workspace.'}
Assert-ConnectorStopped $statePath
if(-not(Test-Path -LiteralPath (Join-Path $statePath 'secrets.dpapi'))){throw 'Set up protected credentials before installing the runtime.'}
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$unexpected=@((Get-Acl -LiteralPath $statePath).Access | Where-Object {$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @($sid,'S-1-5-18')})
if($unexpected.Count){throw 'Private state ACL contains other principals; installation stopped.'}
if($Context -notmatch '^[a-zA-Z0-9_-]{1,64}$'){throw 'Invalid Docker context name.'}
$docker=(Get-Command docker.exe -ErrorAction Stop).Source
$docker=Assert-TrustedBinary $docker $workspacePath
$nodeRuntime=& (Join-Path $PSScriptRoot 'Install-NodeRuntime.ps1') -StateDir $statePath -Workspace $workspacePath -Proxy $Proxy
$node=$nodeRuntime.nodePath
$npm=$nodeRuntime.npmCli
$pnpm=Join-Path $source 'node_modules\pnpm\bin\pnpm.mjs'
if(-not(Test-Path -LiteralPath $pnpm)){throw 'Run pnpm install in the reviewed checkout before installing the runtime.'}
Clear-NodeOverrides
$inspectedJson=(& $docker --context $Context context inspect $Context | Out-String)
if($LASTEXITCODE -ne 0){throw 'Cannot inspect Docker context.'}
$endpoint=(($inspectedJson | ConvertFrom-Json)[0].Endpoints.docker.Host)
if(-not($endpoint -like 'npipe://*' -or $endpoint -like 'unix:///*')){throw 'Only a local Docker engine is permitted.'}
$imageId=(& $docker --context $Context image inspect $Image --format '{{.Id}}').Trim()
if($LASTEXITCODE -ne 0 -or $imageId -notmatch '^sha256:[a-f0-9]{64}$'){throw 'Build and verify the development image first.'}
$release='runtime-'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8)
$destination=Join-Path $statePath $release
New-Item -ItemType Directory -Path $destination | Out-Null
function Copy-FilteredTree([string]$src,[string]$dst){
  New-Item -ItemType Directory -Path $dst -Force | Out-Null
  foreach($item in Get-ChildItem -LiteralPath $src -Force){
    if($item.Name.StartsWith('.')){continue}
    if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Runtime source must not contain symbolic links or junctions.'}
    $target=Join-Path $dst $item.Name
    if($item.PSIsContainer){Copy-FilteredTree $item.FullName $target}
    else{Copy-Item -LiteralPath $item.FullName -Destination $target}
  }
}
foreach($folder in @('local','scripts')){Copy-FilteredTree (Join-Path $source $folder) (Join-Path $destination $folder)}
foreach($file in @('package.json','pnpm-lock.yaml')){
  $item=Get-Item -LiteralPath (Join-Path $source $file) -Force
  if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Runtime manifest must not be a link.'}
  Copy-Item -LiteralPath $item.FullName -Destination $destination
}
Push-Location $destination
try {
  & $node $pnpm install --frozen-lockfile --prod --ignore-scripts
  if($LASTEXITCODE -ne 0){throw 'Protected runtime dependency installation failed.'}
} finally {Pop-Location}
$configFile=Join-Path $statePath 'config.json'
$old=Get-Content -LiteralPath $configFile -Raw | ConvertFrom-Json
Assert-ConnectorStopped $statePath
Copy-Item -LiteralPath $configFile -Destination (Join-Path $statePath ('config-before-'+$release+'.json'))
$config=@{
  origin=$old.origin;roots=@($workspacePath);defaultCwd=$workspacePath;allowExec=$true
  sourceRoot=$destination;nodePath=$node;nodeRoot=$nodeRuntime.nodeRoot;nodeSha256=$nodeRuntime.nodeSha256;requireLocalApproval=$true
  sandbox=@{enabled=$true;image=$imageId;dockerPath=$docker;context=$Context;allowOutbound=[bool]$AllowOutbound}
}
$temporary=Join-Path $statePath ('config-'+[Guid]::NewGuid().ToString('N')+'.tmp')
try {
  [IO.File]::WriteAllText($temporary,($config|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
  Move-Item -LiteralPath $temporary -Destination $configFile -Force
} finally { if(Test-Path -LiteralPath $temporary){Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue} }
$powershell=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
foreach($action in @('Start','Stop','Status','Password')) {
  $content='@echo off'+"`r`n"+'setlocal DisableDelayedExpansion'+"`r`n"+'chcp 65001 >nul'+"`r`n"+'"'+$powershell+'" -NoProfile -ExecutionPolicy RemoteSigned -File "'+(Join-Path $destination 'scripts\Manage.ps1').Replace('%','%%')+'" -Action '+$action+' -StateDir "'+$statePath.Replace('%','%%')+'"'+"`r`n"
  [IO.File]::WriteAllText((Join-Path $statePath ($action+'.cmd')),$content,[Text.UTF8Encoding]::new($false))
}
if(Test-Path -LiteralPath (Join-Path $destination 'scripts\Approve.ps1')) {
  $approve='@echo off'+"`r`n"+'setlocal DisableDelayedExpansion'+"`r`n"+'chcp 65001 >nul'+"`r`n"+'"'+$powershell+'" -NoProfile -ExecutionPolicy RemoteSigned -File "'+(Join-Path $destination 'scripts\Approve.ps1').Replace('%','%%')+'" -StateDir "'+$statePath.Replace('%','%%')+'"'+"`r`n"
  [IO.File]::WriteAllText((Join-Path $statePath 'Approve.cmd'),$approve,[Text.UTF8Encoding]::new($false))
}
$manifest=@{installedAt=[DateTime]::UtcNow.ToString('o');runtime=$destination;workspace=$workspacePath;image=$imageId;sha256=@{}}
Get-ChildItem -LiteralPath $destination -File -Recurse | Where-Object {$_.FullName -notlike '*\node_modules\*'} | ForEach-Object {$manifest.sha256[$_.FullName.Substring($destination.Length+1)]=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
$tmpManifest=Join-Path $statePath ('installation-'+[Guid]::NewGuid().ToString('N')+'.tmp')
try {
  [IO.File]::WriteAllText($tmpManifest,($manifest|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
  Move-Item -LiteralPath $tmpManifest -Destination (Join-Path $statePath 'installation.json') -Force
} finally { if(Test-Path -LiteralPath $tmpManifest){Remove-Item -LiteralPath $tmpManifest -Force -ErrorAction SilentlyContinue} }
[pscustomobject]@{runtime=$destination;workspace=$workspacePath;image=$imageId;context=$Context;allowOutbound=[bool]$AllowOutbound;started=$false}|ConvertTo-Json
