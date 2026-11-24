# SPDX-License-Identifier: AGPL-3.0-only
# This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
param(
  [ValidateSet('Start','Stop','Status','Run','Password')][string]$Action='Status',
  [string]$StateDir=([IO.Path]::Combine([Environment]::GetFolderPath('UserProfile'), '.agentdock-bridge'))
)
$ErrorActionPreference='Stop'
. ([IO.Path]::Combine($PSScriptRoot, 'State-Safety.ps1'))
$statePath=Assert-PrivateState $StateDir
$root=Split-Path -Parent $PSScriptRoot
$connector=Join-Path $root 'local\connector.mjs'
$self=$PSCommandPath
$processFile=Join-Path $statePath 'supervisor.json'
$childFile=Join-Path $statePath 'connector-process.json'
$stopFile=Join-Path $statePath 'stop.request'
function Resolve-RuntimePaths {
  $supSource=$self
  $connSource=$connector
  $cfgFile=Join-Path $statePath 'config.json'
  if(Test-Path -LiteralPath $cfgFile){
    try {
      $cfg=Get-Content -LiteralPath $cfgFile -Raw|ConvertFrom-Json
      if($cfg.sourceRoot -and ($cfg.sourceRoot -match '^[A-Za-z]:[\\/]')){
        $resolvedRoot=Assert-PlainLocalPath $cfg.sourceRoot
        if($resolvedRoot -ine $root){
          $supSource=Join-Path $resolvedRoot 'scripts\Manage.ps1'
        }
        $connSource=Join-Path $resolvedRoot 'local\connector.mjs'
      }
    } catch {}
  }
  return @{SupervisorSource=$supSource;ConnectorSource=$connSource}
}
function SaveProcess($file,$process,$marker){
  # The protected record is written atomically via temp file + move.
  $tmp=Join-Path $statePath ('.proc-'+[Guid]::NewGuid().ToString('N')+'.tmp')
  try {
    [IO.File]::WriteAllText($tmp,(@{pid=$process.Id;startTime=$process.StartTime.ToUniversalTime().Ticks.ToString();executable=$process.Path;source=$marker}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $tmp -Destination $file -Force
  } finally { if(Test-Path -LiteralPath $tmp){Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue} }
}
function OwnedProcess($file,$marker){
  if(-not(Test-Path -LiteralPath $file)){return $null}
  try {
    $record=Get-Content -LiteralPath $file -Raw|ConvertFrom-Json
    $process=Get-Process -Id $record.pid -ErrorAction Stop
    # PID plus the exact creation time prevents a stale file from matching a
    # recycled PID. Check our recorded source and actual executable as well.
    # Avoid WMI queries here: they can stall for tens of seconds on this host.
    if($record.source -ieq $marker -and $process.Path -ieq $record.executable -and $process.StartTime.ToUniversalTime().Ticks.ToString() -ceq $record.startTime){return $process}
  } catch {}
  return $null
}
function ProbePublicHealth([string]$Origin){
  if(-not $Origin -or -not $Origin.StartsWith('https://',[StringComparison]::OrdinalIgnoreCase)){
    return [pscustomobject]@{error='Invalid gateway origin scheme.'}
  }
  [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
  $uri=$Origin.TrimEnd('/')+'/healthz'
  $req=[System.Net.HttpWebRequest]::Create($uri)
  $req.Method='GET'
  $req.Timeout=15000
  $req.AllowAutoRedirect=$false
  $readBounded={
    param($stream)
    $reader=[IO.StreamReader]::new($stream,[Text.Encoding]::UTF8)
    try {
      $buf=New-Object char[] 65537
      $total=0
      while($total -lt $buf.Length){
        $n=$reader.Read($buf,$total,$buf.Length-$total)
        if($n -le 0){break}
        $total+=$n
      }
      if($total -gt 65536){throw 'Health response exceeded limit.'}
      return [string]::new($buf,0,$total)
    } finally { $reader.Dispose() }
  }
  try {
    $resp=$req.GetResponse()
    try {
      $text=& $readBounded $resp.GetResponseStream()
      return [pscustomobject]@{status=[int]$resp.StatusCode;body=($text|ConvertFrom-Json)}
    } finally { $resp.Close() }
  } catch [System.Net.WebException] {
    $resp=$_.Exception.Response
    if($resp -is [System.Net.HttpWebResponse]){
      try {
        $text=& $readBounded $resp.GetResponseStream()
        try { return [pscustomobject]@{status=[int]$resp.StatusCode;body=($text|ConvertFrom-Json)} }
        catch { return [pscustomobject]@{status=[int]$resp.StatusCode;error='Invalid health response.'} }
      } finally { $resp.Close() }
    }
    return [pscustomobject]@{error='Public health request failed.'}
  } catch {
    return [pscustomobject]@{error='Public health request failed.'}
  }
}
if($Action -eq 'Password') {& (Join-Path $PSScriptRoot 'Secrets.ps1') -Action ShowPassword -StateDir $statePath;exit}
if($Action -eq 'Status') {
  $runtimePaths=Resolve-RuntimePaths
  $supervisor=OwnedProcess $processFile $runtimePaths.SupervisorSource
  $child=OwnedProcess $childFile $runtimePaths.ConnectorSource
  $status=Join-Path $statePath 'connector-status.json'
  $connectorStatus=$null
  if(Test-Path -LiteralPath $status){
    try { $connectorStatus=Get-Content -LiteralPath $status -Raw|ConvertFrom-Json }
    catch { $connectorStatus=[pscustomobject]@{corrupt=$true} }
  }
  $configFile=Join-Path $statePath 'config.json'
  $publicHealth=$null
  if(Test-Path -LiteralPath $configFile){
    try {
      $origin=(Get-Content -LiteralPath $configFile -Raw|ConvertFrom-Json).origin
      $publicHealth=ProbePublicHealth $origin
    } catch { $publicHealth=[pscustomobject]@{error='Invalid configuration.'} }
  }
  [pscustomobject]@{
    supervisorAlive=[bool]$supervisor
    connectorAlive=[bool]$child
    stateDirectory=$statePath
    connectorStatus=$connectorStatus
    publicHealth=$publicHealth
  }|ConvertTo-Json -Depth 8
  exit
}
if($Action -eq 'Stop') {
  $runtimePaths=Resolve-RuntimePaths
  [IO.File]::WriteAllText($stopFile,'stop')
  $process=OwnedProcess $processFile $runtimePaths.SupervisorSource
  if($process){$null=$process.WaitForExit(20000)}
  if(OwnedProcess $processFile $runtimePaths.SupervisorSource){throw 'Supervisor is still running. Inspect its status.'}
  $child=OwnedProcess $childFile $runtimePaths.ConnectorSource
  if($child){throw 'Connector is still stopping. Inspect its status before forcing termination.'}
  if(Test-Path -LiteralPath $stopFile){Remove-Item -LiteralPath $stopFile -Force -ErrorAction SilentlyContinue}
  'Stopped this connector and its supervisor.'
  exit
}
if($Action -eq 'Start') {
  $config=Get-Content -LiteralPath (Join-Path $statePath 'config.json') -Raw | ConvertFrom-Json
  if(-not $config.sandbox.enabled -or -not $config.requireLocalApproval){throw 'Install the hardened runtime and local approval policy first.'}
  if($config.sourceRoot -ine $root){throw 'Start using the protected Start.cmd in the private AgentDockBridge directory.'}
  $null=Assert-PinnedNode $config $statePath
  Clear-NodeOverrides
  if(OwnedProcess $processFile $self){'Already running.';exit}
  if(Test-Path -LiteralPath $stopFile){Remove-Item -LiteralPath $stopFile}
  $powershell=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $arguments='-NoProfile -ExecutionPolicy RemoteSigned -File "'+$self+'" -Action Run -StateDir "'+$statePath+'"'
  Start-Process -FilePath $powershell -ArgumentList $arguments -WorkingDirectory $root -WindowStyle Hidden | Out-Null
  'Start requested. Use Status.cmd to verify the public connection.'
  exit
}
$digest=[Security.Cryptography.SHA256]::Create()
try{$identifier=([BitConverter]::ToString($digest.ComputeHash([Text.Encoding]::UTF8.GetBytes($statePath.ToLowerInvariant())))).Replace('-','')}finally{$digest.Dispose()}
$mutex=[Threading.Mutex]::new($false,'Local\CbnvComputerBridge-'+$identifier)
$owns=$false
try{$owns=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$owns=$true}
if(-not $owns){$mutex.Dispose();exit}
try {
  SaveProcess $processFile (Get-Process -Id $PID) $self
  $config=Get-Content -LiteralPath (Join-Path $statePath 'config.json') -Raw | ConvertFrom-Json
  if(-not $config.sandbox.enabled -or -not $config.requireLocalApproval -or $config.sourceRoot -ine $root){throw 'Untrusted or incomplete runtime configuration.'}
  $node=$config.nodePath
  if(-not [IO.Path]::IsPathRooted($node) -or -not(Test-Path -LiteralPath $node -PathType Leaf)){throw 'Pinned Node executable is missing.'}
  $null=Assert-PinnedNode $config $statePath
  Clear-NodeOverrides
  $quickFailures=0
  $lastSpawnAt=[DateTime]::MinValue
  $nextRestartAt=[DateTime]::MinValue
  while(-not(Test-Path -LiteralPath $stopFile)) {
    $child=OwnedProcess $childFile $connector
    if(-not $child -and [DateTime]::UtcNow -ge $nextRestartAt) {
      if($lastSpawnAt -ne [DateTime]::MinValue) {
        $elapsed=([DateTime]::UtcNow - $lastSpawnAt).TotalSeconds
        if($elapsed -lt 10){
          $quickFailures=[Math]::Min($quickFailures+1, 5)
          $backoff=[Math]::Min(30, [int][Math]::Pow(2, $quickFailures))
          $nextRestartAt=[DateTime]::UtcNow.AddSeconds($backoff)
          Start-Sleep -Seconds 1
          continue
        }
        $quickFailures=0
      }
      $null=Assert-PinnedNode $config $statePath
      $arguments='"'+$connector+'" "'+$statePath+'"'
      $lastSpawnAt=[DateTime]::UtcNow
      $child=Start-Process -FilePath $node -ArgumentList $arguments -WorkingDirectory $root -WindowStyle Hidden -PassThru
      SaveProcess $childFile $child $connector
    }
    Start-Sleep -Seconds 2
  }
  $child=OwnedProcess $childFile $connector
  if($child){
    if(-not $child.WaitForExit(12000)){
      try{ $child.Kill(); $null=$child.WaitForExit(3000) }catch{}
    }
  }
} finally {
  if(-not (OwnedProcess $childFile $connector) -and (Test-Path -LiteralPath $childFile)){Remove-Item -LiteralPath $childFile -Force -ErrorAction SilentlyContinue}
  if(Test-Path -LiteralPath $stopFile){Remove-Item -LiteralPath $stopFile -Force -ErrorAction SilentlyContinue}
  if(Test-Path -LiteralPath $processFile){Remove-Item -LiteralPath $processFile -Force -ErrorAction SilentlyContinue}
  $mutex.ReleaseMutex()
  $mutex.Dispose()
}
