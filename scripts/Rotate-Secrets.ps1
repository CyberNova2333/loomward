# SPDX-License-Identifier: AGPL-3.0-only
# This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
param(
  [string]$StateDir=([IO.Path]::Combine([Environment]::GetFolderPath('UserProfile'), '.agentdock-bridge')),
  [string]$Wrangler=([IO.Path]::Combine([IO.Path]::GetDirectoryName($PSScriptRoot), 'node_modules\.bin\wrangler.cmd')),
  [string]$WranglerConfig=([IO.Path]::Combine([IO.Path]::GetDirectoryName($PSScriptRoot), 'wrangler.jsonc'))
)
$ErrorActionPreference='Stop'
. ([IO.Path]::Combine($PSScriptRoot, 'State-Safety.ps1'))
$statePath=Assert-PrivateState $StateDir
Assert-ConnectorStopped $statePath
$wranglerBin=Assert-PlainLocalPath $Wrangler
Assert-WriteProtectedPath $wranglerBin
$configPath=Assert-PlainLocalPath $WranglerConfig
Clear-NodeOverrides
Add-Type -AssemblyName System.Security
$entropy=[Text.Encoding]::UTF8.GetBytes('cbnv.agentdock-bridge.secrets.v1')
$pending=Join-Path $statePath 'secrets.next.dpapi'
$current=Join-Path $statePath 'secrets.dpapi'
if(-not(Test-Path -LiteralPath $current)){throw 'Current protected credentials are missing.'}
$currentPlain=[Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String([IO.File]::ReadAllText($current)),$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)
try {
  $currentData=[Text.Encoding]::UTF8.GetString($currentPlain)|ConvertFrom-Json
  $currentToken=$currentData.bridgeToken
  $currentHash=$currentData.ownerPasswordHash
} finally {[Array]::Clear($currentPlain,0,$currentPlain.Length);$currentData=$null}
function RandomUrl([int]$count){
  $bytes=New-Object byte[] $count
  $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
  try{$rng.GetBytes($bytes)}finally{$rng.Dispose()}
  return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}
$needGenerate=$true
if(Test-Path -LiteralPath $pending){
  try {
    $checkPlain=[Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String([IO.File]::ReadAllText($pending)),$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    try {
      $checkData=[Text.Encoding]::UTF8.GetString($checkPlain)|ConvertFrom-Json
      if($checkData.bridgeToken -and $checkData.bridgeToken -cne $currentToken -and $checkData.ownerPasswordHash -cne $currentHash){$needGenerate=$false}
    } finally {[Array]::Clear($checkPlain,0,$checkPlain.Length);$checkData=$null}
  } catch {}
}
if($needGenerate){
  $password=RandomUrl 24
  $saltString=RandomUrl 16
  $padded=$saltString.Replace('-','+').Replace('_','/')+'=='
  $salt=[Convert]::FromBase64String($padded)
  $derive=[Security.Cryptography.Rfc2898DeriveBytes]::new($password,$salt,100000,[Security.Cryptography.HashAlgorithmName]::SHA256)
  try{$hash='pbkdf2-sha256$100000$'+$saltString+'$'+[Convert]::ToBase64String($derive.GetBytes(32)).TrimEnd('=').Replace('+','-').Replace('/','_')}finally{$derive.Dispose()}
  $data=@{bridgeToken=(RandomUrl 32);ownerPassword=$password;ownerPasswordHash=$hash}
  $plain=[Text.Encoding]::UTF8.GetBytes(($data|ConvertTo-Json -Compress))
  $tmpPending=Join-Path $statePath ('.secret-next-'+[Guid]::NewGuid().ToString('N')+'.tmp')
  try{
    $cipher=[Security.Cryptography.ProtectedData]::Protect($plain,$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    [IO.File]::WriteAllText($tmpPending,[Convert]::ToBase64String($cipher),[Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $tmpPending -Destination $pending -Force
  }finally{[Array]::Clear($plain,0,$plain.Length);$data=$null;$password=$null;if(Test-Path -LiteralPath $tmpPending){Remove-Item -LiteralPath $tmpPending -Force -ErrorAction SilentlyContinue}}
}
$plain=[Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String([IO.File]::ReadAllText($pending)),$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)
try{
  $data=[Text.Encoding]::UTF8.GetString($plain)|ConvertFrom-Json
  $upload=@{BRIDGE_TOKEN=$data.bridgeToken;OWNER_PASSWORD_HASH=$data.ownerPasswordHash}|ConvertTo-Json -Compress
  $upload | & $wranglerBin secret bulk --config $configPath
  if($LASTEXITCODE -ne 0){throw 'Cloud secret update did not complete. Connector must remain stopped; retry this script using the protected pending credentials.'}
  $stamp=[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8)
  Copy-Item -LiteralPath $current -Destination (Join-Path $statePath ('secrets-retired-'+$stamp+'.dpapi'))
  Move-Item -LiteralPath $pending -Destination $current -Force
}finally{[Array]::Clear($plain,0,$plain.Length);$data=$null;$upload=$null}
'Project connection credentials rotated. Reconnect MCP clients with the new locally displayed password.'
