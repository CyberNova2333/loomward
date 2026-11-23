# SPDX-License-Identifier: AGPL-3.0-only
# This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
param(
  [string]$StateDir=([IO.Path]::Combine([Environment]::GetFolderPath('UserProfile'), '.agentdock-bridge')),
  [string]$Workspace='D:\Projects',
  [string]$Proxy
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
. ([IO.Path]::Combine($PSScriptRoot, 'State-Safety.ps1'))
$statePath=Assert-PrivateState $StateDir
# Fixed official distribution, independently pinned from nodejs.org SHASUMS256.txt.
$version='24.22.1'
$archiveHash='d2046d28c2c3dcd211ac5145c0bf30e2047ef9dfb306693c8c6e2eccd8b95fa5'
if(-not [Environment]::Is64BitOperatingSystem){throw 'This pinned Node distribution requires Windows x64.'}
$toolchains=Join-Path ([Environment]::GetFolderPath('UserProfile')) '.agentdock-toolchains'
if(-not(Test-Path -LiteralPath $toolchains)) {
  Assert-WriteProtectedPath (Split-Path -Parent $toolchains)
  $null=New-Item -ItemType Directory -Path $toolchains
  $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
  $acl=[Security.AccessControl.DirectorySecurity]::new()
  $acl.SetAccessRuleProtection($true,$false); $acl.SetOwner($sid)
  foreach($principal in @($sid,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
  }
  [IO.Directory]::SetAccessControl($toolchains,$acl)
}
$toolchains=Assert-PrivateState $toolchains
Assert-WriteProtectedPath $toolchains
$folder=Join-Path $toolchains "node-v$version-win-x64"
$manifestFile=Join-Path $toolchains "node-v$version-win-x64.verified.json"
if(-not(Test-Path -LiteralPath $folder)) {
  $archive=Join-Path $toolchains ('node-download-'+[Guid]::NewGuid().ToString('N')+'.zip')
  $staging=Join-Path $toolchains ('.node-staging-'+[Guid]::NewGuid().ToString('N'))
  $tmpManifest=Join-Path $toolchains ('.manifest-'+[Guid]::NewGuid().ToString('N')+'.tmp')
  try {
    $parameters=@{Uri="https://nodejs.org/dist/v$version/node-v$version-win-x64.zip";OutFile=$archive;UseBasicParsing=$true;TimeoutSec=300;MaximumRedirection=0}
    if($Proxy){$parameters.Proxy=$Proxy}
    [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
    try {Invoke-WebRequest @parameters | Out-Null} catch {throw 'Official Node download failed; no runtime was installed.'}
    if((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ine $archiveHash){throw 'Official Node archive digest mismatch; installation stopped.'}
    $null=New-Item -ItemType Directory -Path $staging
    # Extract into a private staging directory; publish the final folder only after verification.
    Import-Module -Name "$PSHOME\Modules\Microsoft.PowerShell.Archive\Microsoft.PowerShell.Archive.psd1" -ErrorAction Stop
    Expand-Archive -LiteralPath $archive -DestinationPath $staging
    $stagedFolder=Join-Path $staging "node-v$version-win-x64"
    $node=Join-Path $stagedFolder 'node.exe'
    $npm=Join-Path $stagedFolder 'node_modules\npm\bin\npm-cli.js'
    $signature=Get-AuthenticodeSignature -LiteralPath $node
    if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(^|,\s*)O=OpenJS Foundation(,|$)'){throw 'Official Node signature verification failed.'}
    $manifest=@{version=$version;archiveSha256=$archiveHash;nodeSha256=(Get-FileHash -LiteralPath $node -Algorithm SHA256).Hash.ToLowerInvariant();npmCliSha256=(Get-FileHash -LiteralPath $npm -Algorithm SHA256).Hash.ToLowerInvariant()}
    [IO.File]::WriteAllText($tmpManifest,($manifest|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $tmpManifest -Destination $manifestFile -Force
    Move-Item -LiteralPath $stagedFolder -Destination $folder
  } finally {
    if(Test-Path -LiteralPath $archive){Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue}
    if(Test-Path -LiteralPath $tmpManifest){Remove-Item -LiteralPath $tmpManifest -Force -ErrorAction SilentlyContinue}
    if(Test-Path -LiteralPath $staging){Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue}
  }
}
if(-not(Test-Path -LiteralPath $manifestFile)){throw 'Private Node installation is incomplete; inspect it before retrying.'}
$manifest=Get-Content -LiteralPath $manifestFile -Raw|ConvertFrom-Json
if($manifest.version -cne $version -or $manifest.archiveSha256 -cne $archiveHash){throw 'Private Node installation manifest mismatch.'}
$node=Join-Path $folder 'node.exe'
$npm=Join-Path $folder 'node_modules\npm\bin\npm-cli.js'
$nodeConfig=@{nodePath=$node;nodeRoot=$toolchains;nodeSha256=$manifest.nodeSha256;roots=@($Workspace)}
$null=Assert-PinnedNode $nodeConfig $statePath
$null=Assert-TrustedBinary $npm $Workspace
if((Get-FileHash -LiteralPath $npm -Algorithm SHA256).Hash -ine $manifest.npmCliSha256){throw 'Private npm integrity verification failed.'}
[pscustomobject]@{nodePath=$node;nodeRoot=$toolchains;nodeSha256=$manifest.nodeSha256;npmCli=$npm;version=$version;archiveSha256=$archiveHash}
