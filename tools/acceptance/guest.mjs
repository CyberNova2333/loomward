// SPDX-License-Identifier: AGPL-3.0-only
// Run from the disposable checkout under the dedicated, logged-in test account.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const root = path.resolve(import.meta.dirname, '../..');
const win = process.platform === 'win32';
const report = { platform: process.platform, commit: process.argv[2], image: process.argv[3], checks: {} };
const profile = JSON.parse(fs.readFileSync(path.join(os.homedir(), '.loomward-acceptance.json'), 'utf8'));
const run = (bin, args, options = {}) => execFileSync(bin, args, {
  cwd: root, stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8', timeout: 240000, windowsHide: true, ...options,
}).trim();
const read = file => JSON.parse(fs.readFileSync(file, 'utf8'));
function requireThat(condition) { if (!condition) throw new Error('Acceptance assertion failed'); }
const check = async (name, fn) => {
  report.checks[name] = 'failed';
  await fn();
  report.checks[name] = 'passed';
};

async function verify() {
  requireThat((win || process.platform === 'darwin') && /^[a-f0-9]{40}$/.test(report.commit) && /^sha256:[a-f0-9]{64}$/.test(report.image));
  for (const key of ['node', 'docker', 'pnpm']) requireThat(path.isAbsolute(profile[key]));
  requireThat(/^[a-zA-Z0-9_-]{1,64}$/.test(profile.context));
  process.env.PATH = [path.dirname(profile.node), path.dirname(profile.docker), process.env.PATH].join(path.delimiter);
  await check('dependencies', () => {
    requireThat('pnpm@' + run(profile.pnpm, ['--version']) === read(path.join(root, 'package.json')).packageManager);
    try { run(profile.pnpm, ['install', '--frozen-lockfile', '--ignore-scripts']); }
    catch (error) {
      const code = (String(error.stdout) + String(error.stderr)).match(/\b(?:ERR_PNPM_[A-Z0-9_]+|EACCES|EPERM|ENAMETOOLONG|ENOENT|ETIMEDOUT)\b/)?.[0];
      report.dependencyError = code || 'INSTALL_FAILED';
      throw error;
    }
  });
  const cli = await import('../../scripts/host-cli.mjs');
  const { loadSecrets } = await import('../../local/connector.mjs');
  const { writeCapabilitiesSync } = await import('../../local/capabilities.mjs');
  const base = fs.mkdtempSync(path.join(os.homedir(), '.loomward-check-'));
  const state = path.join(base, 'state'), workspace = path.join(base, 'workspace');
  const configPath = path.join(state, 'config.json');
  fs.mkdirSync(workspace, { mode: 0o700 });
  const docker = (...args) => run(profile.docker, ['--context', profile.context, ...args]);
  const powershell = win && path.join(process.env.SystemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe');
  const ps = (script, args) => run(powershell, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-File', path.join(root, 'scripts', script), ...args]);
  const wrapper = action => win
    ? run(powershell, ['-NoProfile', '-NonInteractive', '-Command', '& $env:LW_CHECK_WRAPPER; exit $LASTEXITCODE'],
      { env: { ...process.env, LW_CHECK_WRAPPER: path.join(state, action + '.cmd') } })
    : run(path.join(state, action), []);
  const install = async () => {
    if (win) return ps('Install-Hardened.ps1', ['-StateDir', state, '-Workspace', workspace, '-Image', report.image, '-Context', profile.context]);
    return cli.installHardened({ stateDir: state, workspace, image: report.image, docker: profile.docker, context: profile.context, allowOutbound: false });
  };
  let launched = false, keychain = false, gateway;
  const origin = 'http://127.0.0.1:1';
  try {
    await check('nativeCredentials', () => {
      if (win) ps('Setup.ps1', ['-StateDir', state, '-Roots', workspace, '-Origin', origin]);
      else {
        cli.setupHost({ stateDir: state, roots: [workspace], origin, secretBackend: 'macos-keychain' });
        keychain = true;
        requireThat(read(path.join(state, 'secrets.meta.json')).backend === 'macos-keychain');
      }
      const token = () => loadSecrets(state, { fields: ['bridgeToken'] }).bridgeToken;
      const one = token();
      requireThat(typeof one === 'string' && one.length >= 32 && token() === one);
    });
    await check('install', async () => {
      requireThat(docker('image', 'inspect', '--format', '{{.Id}}', report.image) === report.image);
      await install();
      const cfg = read(configPath);
      requireThat(cfg.sandbox.image === report.image && cfg.requireLocalApproval && path.dirname(cfg.sourceRoot) === state);
    });
    const lifecycle = async () => {
      launched = true;
      wrapper('start');
      const end = Date.now() + 60000;
      while (true) {
        const s = JSON.parse(wrapper('status'));
        if (s.supervisorAlive && s.connectorAlive) break;
        requireThat(Date.now() < end);
        await delay(750);
      }
      wrapper('stop');
      const stopped = JSON.parse(wrapper('status'));
      requireThat(stopped.supervisorAlive === false && stopped.connectorAlive === false);
      launched = false;
    };
    const active = read(configPath);
    active.webuiPort = 19001;
    active.sandbox.allowOutbound = false;
    fs.writeFileSync(configPath, JSON.stringify(active));
    const previous = active.sourceRoot;
    const token = loadSecrets(state, { fields: ['bridgeToken'] }).bridgeToken;
    const { enrollPasskeySync } = await import('../../local/webui-auth.mjs');
    const { LocalApprovals } = await import('../../local/approvals.mjs');
    const { publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const credential = { credentialId: crypto.randomUUID(), alg: -7, signCount: 1, publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }) };
    enrollPasskeySync(state, { credential, workspaceRoots: [workspace], passkeyDetector: () => ({ supported: false }) });
    const queue = new LocalApprovals(state, origin);
    const pending = await queue.authorize({ method: 'tools/call', params: { name: 'read_file', arguments: { path: '/workspace/note' } } },
      { userId: 'owner', clientId: 'acceptance', scope: ['computer:read'] });
    requireThat(!pending.approved && pending.id);
    writeCapabilitiesSync(state, { fileRead: true, fileWrite: false }, { workspaceRoots: [workspace] });
    const files = ['webui-auth.json', 'capabilities.json', path.join('approvals', pending.id + '.request.json')];
    const before = files.map(name => fs.readFileSync(path.join(state, name)));
    const statePreserved = () => read(configPath).webuiPort === 19001 && read(configPath).sandbox.allowOutbound === false &&
      files.every((name, i) => fs.readFileSync(path.join(state, name)).equals(before[i])) &&
      loadSecrets(state, { fields: ['bridgeToken'] }).bridgeToken === token;
    await check('upgradeInterruption', async () => {
      if (win) {
        run(powershell, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-File',
          path.join(import.meta.dirname, 'interrupt-upgrade.ps1'), state, workspace, report.image, profile.context]);
      } else {
        const target = path.join(state, 'installation.json');
        run('/usr/bin/chflags', ['uchg', target]);
        try {
          let interrupted = false;
          try { await install(); }
          catch (error) {
            if (error.dest !== target || error.code !== 'EPERM') throw error;
            interrupted = true;
          }
          requireThat(interrupted);
        } finally { run('/usr/bin/chflags', ['nouchg', target]); }
      }
      requireThat(read(configPath).sourceRoot === previous && statePreserved());
    });
    await check('previousReleaseLifecycle', lifecycle);
    await check('upgradeRetry', async () => {
      await install();
      requireThat(read(configPath).sourceRoot !== previous && statePreserved());
    });
    await check('protectedLifecycle', lifecycle);
    const cfg = read(configPath);
    await check('readonlyMount', async () => {
      fs.writeFileSync(path.join(workspace, 'note'), 'read-ok');
      const { createSandboxRuntime } = await import(pathToFileURL(path.join(cfg.sourceRoot, 'local/sandbox.mjs')).href);
      gateway = await createSandboxRuntime({ ...cfg, stateDir: state });
      const rpc = await gateway.handleRpc({ jsonrpc: '2.0', id: 1, method: 'tools/call',
        params: { name: 'exec_command', arguments: { cmd: 'cat /workspace/note && touch /workspace/readonly-check', timeout_ms: 30000 } } });
      const result = rpc.result?.structuredContent;
      requireThat(result?.stdout === 'read-ok' && Number.isInteger(result.exit_code) && result.exit_code !== 0 &&
        /read-only file system/i.test(result.stderr) && !fs.existsSync(path.join(workspace, 'readonly-check')));
      await gateway.close();
      gateway = undefined;
    });
    await check('zeroContainers', () => {
      const label = crypto.createHash('sha256').update(fs.realpathSync(state).toLowerCase()).digest('hex').slice(0, 24);
      requireThat(docker('ps', '-aq', '--filter', 'label=cbnv.agentdock.install=' + label) === '');
    });
  } finally {
    await gateway?.close();
    if (launched) wrapper('stop');
    if (keychain) {
      const service = 'cbnv.agentdock-bridge.' + crypto.createHash('sha256').update(fs.realpathSync(state)).digest('hex').slice(0, 16);
      run('/usr/bin/security', ['delete-generic-password', '-s', service, '-a', 'current']);
    }
    fs.rmSync(base, { recursive: true, force: true, maxRetries: 3 });
  }
}
try { await verify(); report.passed = true; }
catch (err) {
  // Child-process errors may carry captured streams, credentials and command arguments.
  report.passed = false;
  report.errorType = err.code && /^[A-Z0-9_]+$/.test(String(err.code)) ? String(err.code) : 'CHECK_FAILED';
  if (Number.isInteger(err.status)) report.childExit = err.status;
  process.exitCode = 1;
}
fs.writeFileSync(path.join(root, "acceptance-result.json"), JSON.stringify(report), { flag: "wx", mode: 0o600 });
