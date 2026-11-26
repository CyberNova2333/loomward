# SPDX-License-Identifier: AGPL-3.0-only
"""Verify the same working-tree snapshot in the two prepared desktop guests."""
import argparse
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tarfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
SCOPE = ['local', 'scripts', 'packages', 'plugins', 'package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml',
         'tools/acceptance/guest.mjs', 'tools/acceptance/interrupt-upgrade.ps1',
         'tools/acceptance/keyboard.mjs', 'tools/acceptance/native-browser.mjs']
REQUIRED = {'dependencies', 'nativeCredentials', 'install', 'protectedLifecycle', 'readonlyMount', 'zeroContainers',
            'upgradeInterruption', 'previousReleaseLifecycle', 'upgradeRetry', 'privatePluginState'}


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)


def bundle():
    names = git('ls-files', '-co', '--exclude-standard', '-z', '--', *SCOPE).decode().split('\0')
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode='wb', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w|') as tar:
            for name in sorted(set(filter(None, names))):
                p = ROOT / name
                if 'test' in p.relative_to(ROOT).parts or (not p.exists() and not p.is_symlink()):
                    continue
                if p.resolve() != p or not p.is_file() or any(i.startswith('.') for i in p.relative_to(ROOT).parts):
                    raise ValueError('Invalid path in acceptance source')
                if p.suffix.lower() not in {'.mjs', '.js', '.json', '.css', '.ps1', '.py', '.md', '.yaml'}:
                    raise ValueError('Review new source type before transferring it')
                data = p.read_bytes()
                item = tarfile.TarInfo(name)
                item.size = len(data)
                item.mode = 0o600
                tar.addfile(item, io.BytesIO(data))
    return output.getvalue()


def macos(options, archive, commit, digest):
    # SSH configuration supplies the dedicated account, private key and pinned host key.
    cmd = """
set -eu
umask 077
work=$(mktemp -d "$HOME/.lw-accept.XXXXXXXX")
domain=gui/$(id -u)
label=org.loomward.acceptance.$(basename "$work" | tr -dc 'a-zA-Z0-9')
trap 'launchctl bootout "$domain/$label" >/dev/null 2>&1 || :; rm -rf "$work"' EXIT
cd "$work"
cat > source.tar.gz
echo 'DIGEST  source.tar.gz' | /usr/bin/shasum -a 256 -c - >/dev/null
/usr/bin/tar -xzf source.tar.gz
node=$(/usr/bin/plutil -extract node raw -o - "$HOME/.loomward-acceptance.json")
"$node" -e 'const [Label,node,work,commit,image,suite]=process.argv.slice(1);require("fs").writeFileSync("job.plist",JSON.stringify({Label,RunAtLoad:true,ProgramArguments:[node,work+"/tools/acceptance/guest.mjs",commit,image,suite],WorkingDirectory:work}));' "$label" "$node" "$work" COMMIT IMAGE SUITE
/usr/bin/plutil -convert xml1 job.plist
launchctl bootstrap "$domain" "$work/job.plist"
n=0
while [ ! -f acceptance-result.json ]; do
  n=$((n+1))
  [ "$n" -lt 800 ] || exit 1
  if launchctl print "$domain/$label" | grep -q 'last exit code = [0-9]'; then [ -f acceptance-result.json ] || exit 1; fi
  sleep 1
done
cat acceptance-result.json
""".replace('DIGEST', digest).replace('COMMIT', commit).replace('IMAGE', shlex.quote(options.image or '-')).replace('SUITE', options.suite)
    args = ['ssh', '-oBatchMode=yes', '-oStrictHostKeyChecking=yes', '-oConnectTimeout=10']
    if options.ssh_config:
        args += ['-F', options.ssh_config]
    args.extend(['--', options.mac_ssh, '/bin/sh -c ' + shlex.quote(cmd)])
    result = subprocess.run(args, input=archive, capture_output=True, timeout=900, check=True)
    return json.loads(result.stdout)


class GuestAgent:
    def __init__(self, domain):
        import libvirt
        import libvirt_qemu
        self.conn = libvirt.open('qemu:///system')
        self.domain = self.conn.lookupByName(domain)
        self.command = libvirt_qemu.qemuAgentCommand

    def call(self, name, **args):
        reply = json.loads(self.command(self.domain, json.dumps({'execute': name, 'arguments': args}), 12, 0))
        if 'return' not in reply:
            raise RuntimeError('Guest agent command failed')
        return reply['return']

    def powershell(self, code, timeout=45):
        prelude = "$ErrorActionPreference='Stop'\n[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n"
        encoded = base64.b64encode((prelude + code).encode('utf-16le')).decode()
        pid = self.call('guest-exec', path=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                        arg=['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], **{'capture-output': True})['pid']
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            status = self.call('guest-exec-status', pid=pid)
            if status['exited']:
                if status.get('exitcode') != 0:
                    raise RuntimeError('Guest PowerShell operation failed')
                return base64.b64decode(status.get('out-data', '')).decode('utf-8-sig').strip()
            time.sleep(.4)
        raise TimeoutError('Guest PowerShell timed out')

    def write(self, target, data):
        handle = self.call('guest-file-open', path=target, mode='wb')
        try:
            for i in range(0, len(data), 32768):
                part = data[i:i + 32768]
                result = self.call('guest-file-write', handle=handle, **{'buf-b64': base64.b64encode(part).decode()})
                if result['count'] != len(part):
                    raise IOError('Incomplete guest transfer')
        finally:
            self.call('guest-file-close', handle=handle)


def windows(options, archive, commit, digest):
    agent = GuestAgent(options.windows_domain)
    job = 'LoomWardAccept-' + uuid.uuid4().hex
    drop = 'C:\\Windows\\Temp\\' + job
    result = drop + '\\out\\report.json'
    user = options.windows_user
    try:
        # Only the logged-in account can execute the test. The agent stages the
        # archive in a private directory and schedules a non-elevated task.
        agent.powershell(r"""
$user=$env:COMPUTERNAME+'\USER'
if((Get-CimInstance Win32_ComputerSystem).UserName -ine $user){throw 'Test desktop not logged in'}
$dir=New-Item -ItemType Directory -Path 'DROP'
$acl=Get-Acl $dir.FullName
$acl.SetAccessRuleProtection($true,$false)
foreach($id in @('S-1-5-18','S-1-5-32-544')){
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($id),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
}
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
Set-Acl -LiteralPath $dir.FullName -AclObject $acl
$out=New-Item -ItemType Directory -Path 'DROP\out'
$oa=Get-Acl $out.FullName
$oa.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user,'Modify','ContainerInherit,ObjectInherit','None','Allow'))
Set-Acl -LiteralPath $out.FullName -AclObject $oa
""".replace('DROP', drop).replace('\\USER\'', '\\' + user + "'"))
        agent.write(drop + '\\source.tgz', archive)
        script = r"""
$ErrorActionPreference='Stop'
$work=Join-Path $env:USERPROFILE 'JOB'
New-Item -ItemType Directory -Path $work | Out-Null
try {
  Set-Location $work
  if((Get-FileHash 'DROP\source.tgz').Hash -ine 'DIGEST'){throw 'Source digest mismatch'}
  & "$env:WINDIR\System32\tar.exe" -xzf 'DROP\source.tgz'
  if($LASTEXITCODE){throw 'Cannot extract acceptance source'}
  $cfg=Get-Content -Raw -LiteralPath (Join-Path $env:USERPROFILE '.loomward-acceptance.json')|ConvertFrom-Json
  $ErrorActionPreference='Continue'
  & $cfg.node 'tools\acceptance\guest.mjs' 'COMMIT' 'IMAGE' 'SUITE' *> $null
  $ErrorActionPreference='Stop'
  $report=[IO.File]::ReadAllText((Join-Path $work 'acceptance-result.json'))
} finally {
  Set-Location $env:USERPROFILE
  if($cfg.node){& $cfg.node -e 'require(process.argv[1]).rmSync(process.argv[2],{recursive:true,force:true,maxRetries:3})' node:fs $work}
}
[IO.File]::WriteAllText('DROP\out\report.tmp',$report)
[IO.File]::Move('DROP\out\report.tmp','DROP\out\report.json')
""".replace('DROP', drop).replace('JOB', job).replace('DIGEST', digest).replace('COMMIT', commit).replace('IMAGE', options.image or '-').replace('SUITE', options.suite)
        agent.write(drop + '\\run.ps1', script.encode())
        agent.powershell(r"""
$p=New-ScheduledTaskPrincipal -UserId ($env:COMPUTERNAME+'\USER') -LogonType Interactive -RunLevel Limited
$a=New-ScheduledTaskAction -Execute "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument '-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "DROP\run.ps1"'
Register-ScheduledTask -TaskName 'JOB' -Action $a -Principal $p | Out-Null
Start-ScheduledTask -TaskName 'JOB'
""".replace('JOB', job).replace('DROP', drop).replace('\\USER\'', '\\' + user + "'"))
        end = time.monotonic() + 900
        while time.monotonic() < end:
            raw = agent.powershell("if(Test-Path -LiteralPath 'REPORT'){[IO.File]::ReadAllText('REPORT')}elseif((Get-ScheduledTask -TaskName 'JOB').State -eq 'Ready'){throw 'Guest task ended without report'}".replace('REPORT', result).replace('JOB', job))
            if raw:
                return json.loads(raw)
            time.sleep(3)
        raise TimeoutError('Windows acceptance timed out')
    finally:
        try:
            agent.powershell(r"""
Unregister-ScheduledTask -TaskName 'JOB' -Confirm:$false -ErrorAction SilentlyContinue
if([IO.Directory]::Exists('DROP')){
  $out='DROP\out'
  if([IO.Directory]::Exists($out)){
    if(([IO.File]::GetAttributes($out) -band [IO.FileAttributes]::ReparsePoint) -eq 0){
      foreach($name in @('report.json','report.tmp')){[IO.File]::Delete([IO.Path]::Combine($out,$name))}
    }
    [IO.Directory]::Delete($out)
  }
  foreach($name in @('source.tgz','run.ps1')){[IO.File]::Delete([IO.Path]::Combine('DROP',$name))}
  [IO.Directory]::Delete('DROP')
}
""".replace('JOB', job).replace('DROP', drop))
        finally:
            agent.conn.close()


# Every viewport must exercise each interaction; a partially completed result cannot pass.
KEYBOARD_STEPS = {
    'menuEntry', 'drawerOpens', 'drawerClose', 'drawerReverseWrap', 'drawerForwardWrap', 'drawerEscape',
    'drawerApprovals', 'drawerAudit', 'drawerNavigation', 'mapInitiallyClosed', 'mapSpace', 'mapToggleRefresh',
    'mapFirstNode', 'mapNodeRefresh', 'mapCollapse', 'mapApprovalsNode', 'mapOpensQueue', 'queueReviewEntry',
    'reviewOpens', 'reviewContents', 'reviewText', 'reviewReverseWrap', 'reviewForwardWrap', 'reviewCancel',
    'reviewConfirm', 'reviewConfirmRefresh', 'reviewEscape', 'reviewEntryRefresh', 'reviewDefaultCancel',
}


def keyboard_summary(keyboard, platform, assets):
    browser = keyboard.get('browser', '')
    browser_pattern = r'Edg/[0-9.]+' if platform == 'win32' else r'Safari [0-9.]+'
    summary = {'viewports': []}
    if re.fullmatch(browser_pattern, browser):
        summary['browser'] = browser
    phase = keyboard.get('phase')
    if phase in ('setup', 'browser', 'console', 'keyboard', 'approval', 'complete'):
        summary['phase'] = phase
    if keyboard.get('assets') == assets:
        summary['assets'] = assets
    rows = keyboard.get('viewports', [])
    valid = [r.get('requestedWidth') for r in rows] == [650, 390, 320]
    for row in rows:
        requested, actual = row['requestedWidth'], row.get('width')
        passed = set(row.get('passed', [])) & KEYBOARD_STEPS
        width_ok = isinstance(actual, int) and (390 < actual <= 720 if requested == 650 else actual == requested)
        info = {'requestedWidth': requested, 'width': actual, 'passedChecks': len(passed)}
        if passed != KEYBOARD_STEPS:
            info['missing'] = sorted(KEYBOARD_STEPS - passed)
        if row.get('failedStep') in KEYBOARD_STEPS:
            info['failedStep'] = row['failedStep']
        summary['viewports'].append(info)
        valid = valid and width_ok and passed == KEYBOARD_STEPS and not row.get('failedStep')
    approval = keyboard.get('approval', {})
    summary['approval'] = {key: approval.get(key) is True for key in ('digestMatched', 'queueFocusRestored')}
    return summary, (valid and 'browser' in summary and 'assets' in summary and phase == 'complete'
                     and all(summary['approval'].values()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', choices=['host', 'keyboard', 'all'], default='host', help='Guest checks to run (default: host)')
    parser.add_argument('--image', help='Expected Docker image ID (required for host and all)')
    parser.add_argument('--mac-ssh', default='loomward-test-mac')
    parser.add_argument('--ssh-config')
    parser.add_argument('--windows-domain', default='loomward-test-windows')
    parser.add_argument('--windows-user', default='loomward-test')
    parser.add_argument('--only', choices=['darwin', 'win32'], help='Diagnostic run on just one guest')
    args = parser.parse_args()
    if args.suite != 'keyboard' and not args.image:
        parser.error('--image is required for host and all')
    if args.image is not None and not re.fullmatch('sha256:[0-9a-f]{64}', args.image):
        parser.error('Invalid Docker image ID')
    if not re.fullmatch('[A-Za-z0-9_.-]{1,64}', args.windows_user):
        parser.error('Invalid Windows account')
    data = bundle()
    digest = hashlib.sha256(data).hexdigest()
    commit = git('rev-parse', 'HEAD').decode().strip()
    dirty = bool(git('status', '--porcelain', '--', *SCOPE))
    assets = {}
    if args.suite != 'host':
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            for name in ('console.css', 'console.js'):
                asset = archive.extractfile('packages/console/dist/' + name)
                assets[name] = hashlib.sha256(asset.read()).hexdigest()
    results = {}
    for platform, run in [('darwin', macos), ('win32', windows)]:
        if args.only and args.only != platform:
            continue
        try:
            result = run(args, data, commit, digest)
            required = {'dependencies'} if args.suite == 'keyboard' else REQUIRED
            if args.suite != 'host':
                required = required | {'keyboard'}
            checks = result['checks']
            passed = (result.get('passed') is True and result.get('platform') == platform and
                      result.get('commit') == commit and result.get('image') == args.image and result.get('suite') == args.suite and
                      required <= checks.keys() and all(v == 'passed' for v in checks.values()))
            results[platform] = {'passed': passed, 'checks': {k: checks.get(k, 'missing') for k in sorted(required)}}
            if args.suite != 'host':
                summary, complete = keyboard_summary(result.get('keyboard', {}), platform, assets)
                results[platform]['keyboard'] = summary
                passed = passed and complete
                results[platform]['passed'] = passed
            if not passed:
                for key in ('dependencyError', 'errorType'):
                    value = result.get(key)
                    if isinstance(value, str) and re.fullmatch('[A-Z0-9_]{1,80}', value):
                        results[platform][key] = value
                if isinstance(result.get('childExit'), int):
                    results[platform]['childExit'] = result['childExit']
        except Exception as error:
            results[platform] = {'passed': False, 'error': type(error).__name__}
    accepted = set(results) == {'win32', 'darwin'} and all(row['passed'] for row in results.values())
    print(json.dumps({'commit': commit, 'dirty': dirty, 'sourceSha256': digest, 'image': args.image,
                      'suite': args.suite, 'accepted': accepted, 'guests': results}, indent=2))
    return int(not all(row['passed'] for row in results.values())) if args.only else int(not accepted)


if __name__ == '__main__':
    sys.exit(main())
