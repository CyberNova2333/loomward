// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import crypto from 'node:crypto';
import readline from 'node:readline/promises';
import { execFileSync, spawn } from 'node:child_process';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { beneath } from '../local/file-safety.mjs';
import { defaultDockerContext } from '../local/sandbox.mjs';
import { proxyCandidates } from '../local/connector.mjs';
import {
  assertConfigOutsideWorkspace,
  capabilityFilePath,
  loadWorkspaceRootsFromStateConfig,
  writeCapabilitiesSync,
} from '../local/capabilities.mjs';
import { mcpServersFilePath } from '../local/mcp-registry.mjs';
import {
  issueSetupTicketSync,
  publicWebUiAuthSummary,
  readWebUiAuthSync,
  resetWebUiAuthSync,
  setStrongPasswordSync,
  validateStrongPassword,
  webuiAuthFilePath,
} from '../local/webui-auth.mjs';
import { isLoopbackHost, startWebUiServer } from '../local/webui.mjs';
import {
  assertPlainLocalPath,
  assertPrivateFile,
  assertPrivateState,
  assertPinnedNode,
  assertTrustedBinary,
  assertConnectorStopped,
  clearNodeOverrides,
  findOwnedProcess,
  getProcessIdentity,
  sanitizedToolEnv,
  sha256FileSync,
} from '../local/host-safety.mjs';
import { ensurePinnedNodeRuntime } from '../local/node-toolchains.mjs';
import {
  SECRET_META_FILE,
  createSecrets,
  exportSecretsSync,
  rotateSecretsSync,
  uploadSecretsSync,
} from '../local/host-secrets.mjs';

export function defaultStateDirectory() {
  return path.join(os.homedir(), '.agentdock-bridge');
}

function parseCliArgs(argv) {
  const [command, ...rest] = argv;
  const flags = {};
  const positionals = [];
  for (let i = 0; i < rest.length; i++) {
    const token = rest[i];
    if (!token.startsWith('--')) {
      positionals.push(token);
      continue;
    }
    const eq = token.indexOf('=');
    if (eq > 2) {
      flags[token.slice(2, eq)] = token.slice(eq + 1);
    } else {
      const key = token.slice(2);
      const next = rest[i + 1];
      if (['state-dir', 'roots', 'origin', 'secret-backend', 'workspace', 'image', 'context', 'docker', 'proxy', 'wrangler', 'wrangler-config', 'allow-outbound', 'host', 'port'].includes(key)) {
        if (next === undefined || next.startsWith('--')) throw new Error(`Missing value for --${key}`);
        flags[key] = next;
        i++;
      } else if (next !== undefined && !next.startsWith('--')) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = 'true';
      }
    }
  }
  return { command, flags, positionals };
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}

function writePrivateJsonSync(filePath, data) {
  const dir = path.dirname(filePath);
  const temp = path.join(dir, `.tmp-${crypto.randomUUID()}.json`);
  const fd = fs.openSync(temp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o600);
  try {
    fs.writeFileSync(fd, JSON.stringify(data, null, 2), 'utf8');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    fs.chmodSync(temp, 0o600);
    fs.renameSync(temp, filePath);
  } catch (error) {
    fs.rmSync(temp, { force: true });
    throw error;
  }
}

function writeExecutableWrapperSync(filePath, content) {
  const dir = path.dirname(filePath);
  const temp = path.join(dir, `.tmp-${crypto.randomUUID()}.sh`);
  const fd = fs.openSync(temp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o700);
  try {
    fs.writeFileSync(fd, content, 'utf8');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    fs.chmodSync(temp, 0o700);
    fs.renameSync(temp, filePath);
  } catch (error) {
    fs.rmSync(temp, { force: true });
    throw error;
  }
}

export function findDockerExecutable(explicitPath) {
  const candidates = [];
  if (explicitPath) candidates.push(explicitPath);
  for (const dir of (process.env.PATH || '').split(path.delimiter).filter(Boolean)) {
    candidates.push(path.join(dir, 'docker'));
  }
  candidates.push(
    '/usr/bin/docker',
    '/usr/local/bin/docker',
    '/opt/homebrew/bin/docker',
    '/Applications/Docker.app/Contents/Resources/bin/docker',
  );
  for (const candidate of candidates) {
    try {
      const resolved = fs.realpathSync(candidate);
      const stat = fs.statSync(resolved);
      if (stat.isFile() && (stat.mode & 0o111) !== 0) return resolved;
    } catch { /* Try next candidate. */ }
  }
  throw new Error('Cannot locate a usable Docker CLI executable.');
}

function resolveDockerContext(dockerPath, explicitContext) {
  if (explicitContext) return explicitContext;
  try {
    const active = execFileSync(dockerPath, ['context', 'show'], {
      encoding: 'utf8',
      timeout: 10000,
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    if (active) return active;
  } catch { /* Fall back to platform default context. */ }
  return defaultDockerContext();
}

function inspectDockerInstallation(dockerPath, context, image) {
  const contextJson = execFileSync(dockerPath, ['--context', context, 'context', 'inspect', context], {
    encoding: 'utf8',
    timeout: 15000,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const inspected = JSON.parse(contextJson)[0];
  const endpoint = inspected?.Endpoints?.docker?.Host || '';
  if (!endpoint.startsWith('unix:///')) {
    throw new Error(`Docker context '${context}' must use a local unix:/// socket (got '${endpoint || 'empty'}').`);
  }
  const imageId = execFileSync(dockerPath, ['--context', context, 'image', 'inspect', image, '--format', '{{.Id}}'], {
    encoding: 'utf8',
    timeout: 15000,
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
  if (!/^sha256:[a-f0-9]{64}$/.test(imageId)) {
    throw new Error('Build and verify the development image first.');
  }
  return { endpoint, imageId };
}

function copyTreeFilteredSync(sourceDir, targetDir, { skipDirs = new Set() } = {}) {
  fs.mkdirSync(targetDir, { recursive: true, mode: 0o700 });
  for (const entry of fs.readdirSync(sourceDir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === '__pycache__' || entry.name.startsWith('.')) continue;
    if (entry.isDirectory() && skipDirs.has(entry.name)) continue;
    if (entry.isFile() && entry.name.endsWith('.pyc')) continue;
    const src = path.join(sourceDir, entry.name);
    const dst = path.join(targetDir, entry.name);
    if (entry.isSymbolicLink()) throw new Error(`Refusing symbolic link in runtime source tree: ${src}`);
    if (entry.isDirectory()) {
      copyTreeFilteredSync(src, dst, { skipDirs });
    } else if (entry.isFile()) {
      fs.copyFileSync(src, dst);
      fs.chmodSync(dst, 0o600);
    }
  }
}

async function generateWorkspaceRpmForRelease(sourceRoot, destination) {
  const { buildReleaseRpm } = await import('./generate-rpm.mjs');
  return buildReleaseRpm({ sourceRoot, destinationRoot: destination });
}

function collectReleaseHashes(releaseDir) {
  const hashes = {};
  const walk = dir => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'node_modules') continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) {
        const rel = path.relative(releaseDir, full).split(path.sep).join('/');
        hashes[rel] = sha256FileSync(full);
      }
    }
  };
  walk(releaseDir);
  return hashes;
}

export function setupHost({
  stateDir = defaultStateDirectory(),
  roots,
  origin = 'https://bridge.example.test',
  secretBackend = 'auto',
} = {}) {
  if (process.platform === 'win32') throw new Error('Use Setup.ps1 on Windows hosts.');
  const resolvedState = path.resolve(stateDir);
  const configFile = path.join(resolvedState, 'config.json');
  if (fs.existsSync(configFile)) {
    throw new Error('Existing local configuration found; inspect it before changing it.');
  }
  const candidateRoots = Array.isArray(roots) && roots.length
    ? roots
    : typeof roots === 'string' && roots
      ? roots.split(',').map(v => v.trim()).filter(Boolean)
      : [path.join(os.homedir(), 'Projects')];
  if (!candidateRoots.length) throw new Error('At least one workspace root directory is required.');

  const allowedRoots = candidateRoots.map(candidate => {
    const resolved = fs.realpathSync(candidate);
    if (!fs.statSync(resolved).isDirectory()) throw new Error('Each allowed root must be a directory.');
    return resolved;
  });

  const { backend, stateDir: realState } = createSecrets(resolvedState, { backend: secretBackend });
  if (backend === 'posix-file') {
    console.error('Notice: Using 0600 file-based credential storage (posix-file) because no OS keyring session was selected.');
  }
  const sourceRoot = path.resolve(import.meta.dirname, '..');
  const config = {
    origin,
    roots: allowedRoots,
    defaultCwd: allowedRoots[0],
    allowExec: false,
    requireLocalApproval: true,
    sourceRoot,
    sandbox: { enabled: false },
  };
  writePrivateJsonSync(path.join(realState, 'config.json'), config);
  return {
    stateDir: realState,
    origin,
    roots: allowedRoots,
    secretBackend: backend,
    next: 'Build container/Dockerfile and run host-cli.mjs install before starting.',
  };
}

export async function installHardened({
  stateDir = defaultStateDirectory(),
  workspace,
  image = 'agentdock-dev:2026-10-28',
  context,
  docker,
  proxy,
  allowOutbound = true,
  nodeRuntimeProvider = ensurePinnedNodeRuntime,
  dockerInspector = inspectDockerInstallation,
  skipDependencyInstall = false,
} = {}) {
  if (process.platform === 'win32') throw new Error('Use Install-Hardened.ps1 on Windows hosts.');
  if (!workspace) throw new Error('An explicit --workspace directory is required.');

  const sourceRoot = path.resolve(import.meta.dirname, '..');
  const workspacePath = fs.realpathSync(workspace);
  if (!fs.statSync(workspacePath).isDirectory()) throw new Error('Workspace must be an existing directory.');
  const statePath = assertPrivateState(stateDir);
  if (beneath(statePath, workspacePath) || beneath(workspacePath, statePath)) {
    throw new Error('Private runtime must not overlap the mounted workspace.');
  }
  assertConnectorStopped(statePath);
  assertPrivateFile(path.join(statePath, SECRET_META_FILE));

  const dockerPath = findDockerExecutable(docker);
  assertTrustedBinary(dockerPath, workspacePath);
  const chosenContext = resolveDockerContext(dockerPath, context);
  const { imageId } = dockerInspector(dockerPath, chosenContext, image);

  clearNodeOverrides();
  const nodeRuntime = await nodeRuntimeProvider({ stateDir: statePath, workspace: workspacePath, proxy });

  const pnpmCli = path.join(sourceRoot, 'node_modules', 'pnpm', 'bin', 'pnpm.mjs');
  if (!skipDependencyInstall && !fs.existsSync(pnpmCli)) {
    throw new Error('Run pnpm install in the reviewed checkout before installing the runtime.');
  }

  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+$/, '').replace('T', '-');
  const release = `runtime-${stamp}-${crypto.randomUUID().replaceAll('-', '').slice(0, 8)}`;
  const destination = path.join(statePath, release);
  fs.mkdirSync(destination, { mode: 0o700 });
  for (const folder of ['local', 'scripts']) {
    copyTreeFilteredSync(path.join(sourceRoot, folder), path.join(destination, folder));
  }
  for (const folder of ['packages', 'plugins']) {
    const srcFolder = path.join(sourceRoot, folder);
    if (fs.existsSync(srcFolder)) {
      copyTreeFilteredSync(srcFolder, path.join(destination, folder), { skipDirs: new Set(['test']) });
    }
  }
  for (const file of ['package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml']) {
    const src = path.join(sourceRoot, file);
    if (!fs.existsSync(src)) continue;
    const dst = path.join(destination, file);
    fs.copyFileSync(src, dst);
    fs.chmodSync(dst, 0o600);
  }
  let rpmManifestHash = null;
  if (fs.existsSync(path.join(destination, 'packages', 'shared', 'src', 'index.mjs'))) {
    const frozenRpm = await generateWorkspaceRpmForRelease(sourceRoot, destination);
    writePrivateJsonSync(path.join(destination, 'rpm.json'), frozenRpm);
    rpmManifestHash = frozenRpm.manifestHash;
  }

  if (!skipDependencyInstall) {
    const installEnv = sanitizedToolEnv();
    installEnv.PATH = `${path.dirname(nodeRuntime.nodePath)}${path.delimiter}${installEnv.PATH || ''}`;
    execFileSync(nodeRuntime.nodePath, [pnpmCli, 'install', '--frozen-lockfile', '--prod', '--ignore-scripts'], {
      cwd: destination,
      env: installEnv,
      timeout: 180000,
      stdio: 'inherit',
    });
  }

  const configFile = assertPrivateFile(path.join(statePath, 'config.json'));
  const oldConfig = JSON.parse(fs.readFileSync(configFile, 'utf8'));
  assertConnectorStopped(statePath);
  fs.copyFileSync(configFile, path.join(statePath, `config-before-${release}.json`));
  fs.chmodSync(path.join(statePath, `config-before-${release}.json`), 0o600);

  const nextConfig = {
    origin: oldConfig.origin,
    roots: [workspacePath],
    defaultCwd: workspacePath,
    allowExec: true,
    sourceRoot: destination,
    nodePath: nodeRuntime.nodePath,
    nodeRoot: nodeRuntime.nodeRoot,
    nodeSha256: nodeRuntime.nodeSha256,
    requireLocalApproval: true,
    sandbox: {
      enabled: true,
      image: imageId,
      dockerPath,
      context: chosenContext,
      allowOutbound: Boolean(allowOutbound),
    },
  };
  writePrivateJsonSync(configFile, nextConfig);
  assertConfigOutsideWorkspace(capabilityFilePath(statePath), [workspacePath]);
  assertConfigOutsideWorkspace(webuiAuthFilePath(statePath), [workspacePath]);
  assertConfigOutsideWorkspace(mcpServersFilePath(statePath), [workspacePath]);
  if (!fs.existsSync(capabilityFilePath(statePath))) {
    writeCapabilitiesSync(
      statePath,
      { fileRead: true, fileWrite: true, allowExec: true },
      { configAllowExec: true, requirePrivateState: true, workspaceRoots: [workspacePath] },
    );
  }

  const cliEntry = path.join(destination, 'scripts', 'host-cli.mjs');
  for (const [wrapperName, action] of [
    ['start', 'start'],
    ['stop', 'stop'],
    ['status', 'status'],
    ['approve', 'approve'],
    ['password', 'password'],
    ['run-service', 'run'],
    ['webui', 'webui'],
    ['webui-auth', 'webui-auth'],
    ['service', 'service'],
  ]) {
    const script = [
      '#!/bin/sh',
      'set -eu',
      'unset NODE_OPTIONS NODE_PATH NODE_TLS_REJECT_UNAUTHORIZED NODE_EXTRA_CA_CERTS LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH',
      `exec ${shellQuote(nodeRuntime.nodePath)} ${shellQuote(cliEntry)} ${action} --state-dir ${shellQuote(statePath)} "$@"`,
      '',
    ].join('\n');
    writeExecutableWrapperSync(path.join(statePath, wrapperName), script);
  }

  const manifest = {
    installedAt: new Date().toISOString(),
    runtime: destination,
    workspace: workspacePath,
    image: imageId,
    ...(rpmManifestHash ? { rpmManifestHash } : {}),
    sha256: collectReleaseHashes(destination),
  };
  writePrivateJsonSync(path.join(statePath, 'installation.json'), manifest);
  return { runtime: destination, workspace: workspacePath, image: imageId, context: chosenContext, started: false };
}

function readTrustedConfig(stateDir, runtimeRoot) {
  const realState = assertPrivateState(stateDir);
  const configFile = assertPrivateFile(path.join(realState, 'config.json'));
  const config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
  if (!config?.sandbox?.enabled || !config.requireLocalApproval) {
    throw new Error('Install the hardened runtime and local approval policy first.');
  }
  if (path.resolve(config.sourceRoot || '') !== path.resolve(runtimeRoot)) {
    throw new Error('Start using the protected launcher inside ~/.agentdock-bridge.');
  }
  assertPinnedNode(config, realState);
  return { realState, config };
}

function saveProcessRecordSync(filePath, pid, source) {
  const identity = getProcessIdentity(pid);
  if (!identity) throw new Error(`Cannot capture process identity for PID ${pid}.`);
  writePrivateJsonSync(filePath, {
    pid: identity.pid,
    startTime: identity.startTime,
    executable: identity.executable,
    source,
  });
}

async function probeSocketActive(sockPath) {
  return new Promise(resolve => {
    const client = net.createConnection(sockPath);
    const done = value => {
      client.destroy();
      resolve(value);
    };
    client.setTimeout(500, () => done(false));
    client.once('connect', () => done(true));
    client.once('error', () => done(false));
  });
}

function acquireFileLockSync(lockPath) {
  for (let attempt = 0; attempt < 20; attempt++) {
    try {
      const fd = fs.openSync(lockPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o600);
      try { fs.writeFileSync(fd, JSON.stringify({ pid: process.pid, time: Date.now() }), 'utf8'); } finally { fs.closeSync(fd); }
      return () => { fs.rmSync(lockPath, { force: true }); };
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      let stale = false;
      try {
        const info = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
        let alive = false;
        if (Number.isSafeInteger(info?.pid) && info.pid > 0) {
          try { process.kill(info.pid, 0); alive = true; } catch (killErr) { alive = killErr.code === 'EPERM'; }
        }
        if (!alive || Date.now() - Number(info?.time || 0) > 15000) stale = true;
      } catch {
        const st = fs.lstatSync(lockPath, { throwIfNoEntry: false });
        if (!st || Date.now() - st.mtimeMs > 15000) stale = true;
      }
      if (stale) {
        fs.rmSync(lockPath, { force: true });
        continue;
      }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
    }
  }
  return null;
}

async function acquireSupervisorSocket(sockPath, supervisorFile, selfPath, lockPath) {
  const releaseLock = acquireFileLockSync(lockPath);
  if (!releaseLock) return null;
  const server = net.createServer();
  const tryListen = () => new Promise((resolve, reject) => {
    const onError = err => {
      if (err?.code === 'ENAMETOOLONG' || err?.code === 'EINVAL') {
        reject(new Error(`Supervisor socket path is too long for this OS (${sockPath.length} bytes). Pass a shorter --state-dir path.`));
      } else {
        reject(err);
      }
    };
    server.once('error', onError);
    try {
      server.listen(sockPath, () => {
        server.removeListener('error', onError);
        resolve();
      });
    } catch (err) {
      server.removeListener('error', onError);
      onError(err);
    }
  });
  try {
    try {
      await tryListen();
    } catch (error) {
      if (error.code !== 'EADDRINUSE') throw error;
      const active = await probeSocketActive(sockPath);
      if (active || findOwnedProcess(supervisorFile, selfPath)) {
        server.close();
        return null;
      }
      fs.rmSync(sockPath, { force: true });
      await tryListen();
    }
    fs.chmodSync(sockPath, 0o600);
    return server;
  } finally {
    releaseLock();
  }
}

export async function runSupervisor({ stateDir = defaultStateDirectory() } = {}) {
  const runtimeRoot = path.resolve(import.meta.dirname, '..');
  const selfPath = path.resolve(import.meta.filename);
  const { realState, config } = readTrustedConfig(stateDir, runtimeRoot);
  clearNodeOverrides();

  const supervisorFile = path.join(realState, 'supervisor.json');
  const childFile = path.join(realState, 'connector-process.json');
  const stopFile = path.join(realState, 'stop.request');
  const sockPath = path.join(realState, 'supervisor.sock');
  const lockPath = path.join(realState, 'supervisor.lock');
  const connectorLog = path.join(realState, 'connector.log');
  const connectorScript = path.join(runtimeRoot, 'local', 'connector.mjs');

  const recordSupervisorLog = (event, fields = {}) => {
    try {
      fs.appendFileSync(connectorLog, JSON.stringify({ time: new Date().toISOString(), event, ...fields }) + '\n', { mode: 0o600 });
    } catch {}
  };

  const lockServer = await acquireSupervisorSocket(sockPath, supervisorFile, selfPath, lockPath);
  if (!lockServer) return { started: false, reason: 'already_running' };

  let stopping = false;
  let activeChild = null;
  let quickFailures = 0;
  let lastSpawnAt = 0;
  let nextRestartAt = 0;
  const requestStop = () => {
    stopping = true;
    try { fs.writeFileSync(stopFile, 'stop', { mode: 0o600 }); } catch {}
  };
  process.on('SIGINT', requestStop);
  process.on('SIGTERM', requestStop);

  saveProcessRecordSync(supervisorFile, process.pid, selfPath);
  try {
    while (!stopping && !fs.existsSync(stopFile)) {
      if (!activeChild && !findOwnedProcess(childFile, connectorScript) && Date.now() >= nextRestartAt) {
        const latest = readTrustedConfig(realState, runtimeRoot).config;
        lastSpawnAt = Date.now();
        const child = spawn(latest.nodePath, [connectorScript, realState], {
          cwd: runtimeRoot,
          env: sanitizedToolEnv(),
          stdio: 'ignore',
        });
        activeChild = child;
        child.once('spawn', () => {
          if (child.pid) {
            try { saveProcessRecordSync(childFile, child.pid, connectorScript); } catch {}
          }
        });
        child.once('error', err => {
          if (activeChild === child) activeChild = null;
          quickFailures += 1;
          nextRestartAt = Date.now() + Math.min(30000, 1000 * 2 ** Math.min(quickFailures - 1, 5));
          recordSupervisorLog('connector_spawn_failed', { code: /^[A-Z0-9_]+$/.test(err?.code || '') ? err.code : 'SPAWN_ERROR' });
        });
        child.once('exit', (code, signal) => {
          if (activeChild === child) activeChild = null;
          const ranMs = Date.now() - lastSpawnAt;
          if (!stopping && !fs.existsSync(stopFile) && (ranMs < 10000 || (code !== 0 && code !== null))) {
            quickFailures = ranMs < 10000 ? quickFailures + 1 : 0;
            nextRestartAt = Date.now() + Math.min(30000, 1000 * 2 ** Math.min(quickFailures, 5));
            recordSupervisorLog('connector_exited', { code, signal: signal || null });
          } else {
            quickFailures = 0;
          }
        });
      }
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    const deadline = Date.now() + 12000;
    while (Date.now() < deadline && (activeChild || findOwnedProcess(childFile, connectorScript))) {
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    if (activeChild && activeChild.exitCode === null && activeChild.signalCode === null) {
      const waitExit = (child, ms) => new Promise(resolve => {
        if (child.exitCode !== null || child.signalCode !== null) return resolve(true);
        const timer = setTimeout(() => { child.removeListener('exit', onExit); resolve(false); }, ms);
        const onExit = () => { clearTimeout(timer); resolve(true); };
        child.once('exit', onExit);
      });
      try { activeChild.kill('SIGTERM'); } catch {}
      const exited = await waitExit(activeChild, 3000);
      if (!exited && activeChild.exitCode === null) {
        try { activeChild.kill('SIGKILL'); } catch {}
        await waitExit(activeChild, 1500);
      }
    }
  } finally {
    fs.rmSync(childFile, { force: true });
    await new Promise(resolve => lockServer.close(resolve));
    fs.rmSync(sockPath, { force: true });
    fs.rmSync(stopFile, { force: true });
    fs.rmSync(supervisorFile, { force: true });
  }
  return { stopped: true };
}

export function startConnector({ stateDir = defaultStateDirectory() } = {}) {
  const runtimeRoot = path.resolve(import.meta.dirname, '..');
  const selfPath = path.resolve(import.meta.filename);
  const { realState, config } = readTrustedConfig(stateDir, runtimeRoot);
  clearNodeOverrides();
  const supervisorFile = path.join(realState, 'supervisor.json');
  if (findOwnedProcess(supervisorFile, selfPath)) {
    return { alreadyRunning: true, message: 'Already running.' };
  }
  const stopFile = path.join(realState, 'stop.request');
  if (fs.existsSync(stopFile)) fs.rmSync(stopFile, { force: true });
  const child = spawn(config.nodePath, [selfPath, 'run', '--state-dir', realState], {
    cwd: runtimeRoot,
    env: sanitizedToolEnv(),
    detached: true,
    stdio: 'ignore',
  });
  child.unref();
  const settleDeadline = Date.now() + 1500;
  while (Date.now() < settleDeadline && !findOwnedProcess(supervisorFile, selfPath)) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
  }
  return { alreadyRunning: false, pid: child.pid, message: 'Start requested. Run status to verify the public connection.' };
}

function expectedRuntimePaths(realState, fallbackRoot, fallbackSelf) {
  const configFile = path.join(realState, 'config.json');
  let root = fallbackRoot;
  if (fs.existsSync(configFile)) {
    try {
      assertPrivateFile(configFile);
      const config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
      if (config?.sourceRoot && path.isAbsolute(config.sourceRoot)) {
        root = path.resolve(config.sourceRoot);
      }
    } catch { /* Fall back to current runtime root. */ }
  }
  return {
    supervisorSource: root === fallbackRoot ? fallbackSelf : path.join(root, 'scripts', 'host-cli.mjs'),
    connectorSource: path.join(root, 'local', 'connector.mjs'),
  };
}

export async function stopConnector({ stateDir = defaultStateDirectory() } = {}) {
  const runtimeRoot = path.resolve(import.meta.dirname, '..');
  const selfPath = path.resolve(import.meta.filename);
  const realState = assertPrivateState(stateDir);
  const { supervisorSource, connectorSource } = expectedRuntimePaths(realState, runtimeRoot, selfPath);
  const supervisorFile = path.join(realState, 'supervisor.json');
  const childFile = path.join(realState, 'connector-process.json');
  const stopFile = path.join(realState, 'stop.request');

  fs.writeFileSync(stopFile, 'stop', { mode: 0o600 });
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    const sup = findOwnedProcess(supervisorFile, supervisorSource);
    const child = findOwnedProcess(childFile, connectorSource);
    if (!sup && !child) {
      fs.rmSync(stopFile, { force: true });
      return { stopped: true, message: 'Stopped this connector and its supervisor.' };
    }
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  if (findOwnedProcess(supervisorFile, supervisorSource)) {
    throw new Error('Supervisor is still running. Inspect its status.');
  }
  if (findOwnedProcess(childFile, connectorSource)) {
    throw new Error('Connector is still stopping. Inspect its status before forcing termination.');
  }
  fs.rmSync(stopFile, { force: true });
  return { stopped: true, message: 'Stopped this connector and its supervisor.' };
}

function probeHealthOnce(url, proxy) {
  return new Promise(resolve => {
    let agent;
    if (proxy) {
      try { agent = new HttpsProxyAgent(proxy); } catch { return resolve({ error: 'Invalid proxy configuration.' }); }
    }
    let settled = false;
    const done = outcome => {
      if (settled) return;
      settled = true;
      resolve(outcome);
    };
    const req = https.get(url, { agent, minVersion: 'TLSv1.2', timeout: 15000 }, res => {
      const chunks = [];
      let bytes = 0;
      res.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > 65536) {
          req.destroy(new Error('Health response exceeded limit.'));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => {
        try {
          done({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) });
        } catch {
          done({ status: res.statusCode, error: 'Invalid health response.' });
        }
      });
      res.on('close', () => done({ error: 'Public health request failed.' }));
      res.on('error', () => done({ error: 'Public health request failed.' }));
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', () => done({ error: 'Public health request failed.' }));
  });
}

async function fetchHealth(origin) {
  const url = `${origin.replace(/\/+$/, '')}/healthz`;
  const candidates = proxyCandidates(origin);
  let lastResult = { error: 'Public health request failed.' };
  for (const proxy of candidates) {
    const outcome = await probeHealthOnce(url, proxy);
    if (typeof outcome.status === 'number') return outcome;
    lastResult = outcome;
  }
  return lastResult;
}

export async function statusConnector({ stateDir = defaultStateDirectory(), probeHealth = true } = {}) {
  const runtimeRoot = path.resolve(import.meta.dirname, '..');
  const selfPath = path.resolve(import.meta.filename);
  const realState = assertPrivateState(stateDir);
  const { supervisorSource, connectorSource } = expectedRuntimePaths(realState, runtimeRoot, selfPath);
  const supervisorAlive = Boolean(findOwnedProcess(path.join(realState, 'supervisor.json'), supervisorSource));
  const connectorAlive = Boolean(findOwnedProcess(path.join(realState, 'connector-process.json'), connectorSource));
  const statusFile = path.join(realState, 'connector-status.json');
  let connectorStatus = null;
  if (fs.existsSync(statusFile)) {
    try { connectorStatus = JSON.parse(fs.readFileSync(statusFile, 'utf8')); } catch { connectorStatus = { corrupt: true }; }
  }
  const configFile = path.join(realState, 'config.json');
  let publicHealth = null;
  if (probeHealth && fs.existsSync(configFile)) {
    try {
      const config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
      if (config.origin?.startsWith('https://')) publicHealth = await fetchHealth(config.origin);
    } catch { publicHealth = { error: 'Invalid configuration.' }; }
  }
  return { supervisorAlive, connectorAlive, stateDirectory: realState, connectorStatus, publicHealth };
}

export function approveCommand({ stateDir = defaultStateDirectory() } = {}) {
  const runtimeRoot = path.resolve(import.meta.dirname, '..');
  const { realState, config } = readTrustedConfig(stateDir, runtimeRoot);
  clearNodeOverrides();
  execFileSync(config.nodePath, [path.join(runtimeRoot, 'local', 'approval-cli.mjs'), realState], {
    env: sanitizedToolEnv(),
    stdio: 'inherit',
  });
}

export async function showPassword({ stateDir = defaultStateDirectory() } = {}) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error('Password display requires an interactive local terminal.');
  }
  const runtimeRoot = path.resolve(import.meta.dirname, '..');
  const realState = assertPrivateState(stateDir);
  const configFile = path.join(realState, 'config.json');
  let site = 'your bridge origin';
  if (fs.existsSync(configFile)) {
    const config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
    if (config.sourceRoot && path.resolve(config.sourceRoot) !== path.resolve(runtimeRoot)) {
      throw new Error('Open password from the protected ~/.agentdock-bridge directory.');
    }
    site = config.origin || site;
  }
  const secrets = exportSecretsSync(realState);
  const prompt = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    console.log(`${site} - login password (do not share):`);
    console.log(secrets.ownerPassword);
    await prompt.question('Press Enter to clear this password from the terminal...');
    process.stdout.write('\x1b[2A\x1b[0J');
  } finally {
    secrets.ownerPassword = undefined;
    secrets.ownerPasswordHash = undefined;
    secrets.bridgeToken = undefined;
    prompt.close();
  }
}

function escapeSystemdExecArg(value) {
  return `"${String(value).replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
}

export function renderSystemdUnits({ stateDir = defaultStateDirectory(), host = '127.0.0.1', port = 18797 } = {}) {
  const resolvedState = path.resolve(stateDir);
  if (!isLoopbackHost(host)) throw new Error('WebUI host must be a loopback address.');
  const portNum = Number(port);
  if (!Number.isInteger(portNum) || portNum < 1024 || portNum > 65535) {
    throw new Error('WebUI port must be an integer between 1024 and 65535.');
  }
  const runWrapper = path.join(resolvedState, 'run-service');
  const webuiWrapper = path.join(resolvedState, 'webui');
  const wrapWithDockerGroupFallback = cmd =>
    `if [ -x /usr/bin/sg ] && ! { case " $(id -Gn) " in *" docker "*) true;; *) false;; esac; } && getent group docker 2>/dev/null | grep -qE "[:,]$(id -un)(,|$)"; then exec /usr/bin/sg docker -c ${shellQuote(`exec ${cmd}`)}; else exec ${cmd}; fi`;
  const bridgeExecScript = wrapWithDockerGroupFallback(shellQuote(runWrapper));
  const webuiCmd = `${shellQuote(webuiWrapper)} --host ${shellQuote(host)} --port ${portNum}`;
  const webuiExecScript = wrapWithDockerGroupFallback(webuiCmd);

  const bridgeUnit = [
    '[Unit]',
    'Description=AgentDock Bridge Local Connector',
    'After=network-online.target gnome-keyring-daemon.service dbus.service',
    'Wants=network-online.target',
    'StartLimitIntervalSec=0',
    '',
    '[Service]',
    'Type=simple',
    'Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=%t/bus',
    `ExecStart=/bin/sh -c ${escapeSystemdExecArg(bridgeExecScript)}`,
    'Restart=on-failure',
    'RestartSec=10',
    'TimeoutStopSec=25',
    '',
    '[Install]',
    'WantedBy=default.target',
    '',
  ].join('\n');

  const webuiUnit = [
    '[Unit]',
    'Description=AgentDock Bridge Local Monitoring WebUI',
    'After=network-online.target',
    'Wants=network-online.target',
    'StartLimitIntervalSec=0',
    '',
    '[Service]',
    'Type=simple',
    'Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=%t/bus',
    `ExecStart=/bin/sh -c ${escapeSystemdExecArg(webuiExecScript)}`,
    'Restart=on-failure',
    'RestartSec=5',
    'TimeoutStopSec=10',
    '',
    '[Install]',
    'WantedBy=default.target',
    '',
  ].join('\n');

  return { bridgeUnit, webuiUnit };
}

async function promptHiddenInput(label) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error('Interactive local terminal (TTY) is required for WebUI credential setup.');
  }
  process.stdout.write(label);
  const wasRaw = Boolean(process.stdin.isRaw);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  return new Promise((resolve, reject) => {
    const chars = [];
    const cleanup = () => {
      process.stdin.removeListener('data', onData);
      try { process.stdin.setRawMode(wasRaw); } catch {}
      process.stdin.pause();
      process.stdout.write('\n');
    };
    const onData = chunk => {
      const text = chunk.toString('utf8');
      for (const ch of text) {
        if (ch === '\r' || ch === '\n') {
          cleanup();
          resolve(chars.join(''));
          return;
        }
        if (ch === '\u0003') {
          cleanup();
          reject(new Error('Cancelled.'));
          return;
        }
        if (ch === '\u007f' || ch === '\b') {
          chars.pop();
          continue;
        }
        if (ch >= ' ' && ch !== '\u007f') {
          chars.push(ch);
        }
      }
    };
    process.stdin.on('data', onData);
  });
}

export async function manageWebUiAuth({
  action = 'status',
  stateDir = defaultStateDirectory(),
  port = 18797,
} = {}) {
  const runtimeRoot = path.resolve(import.meta.dirname, '..');
  const { realState, config } = readTrustedConfig(stateDir, runtimeRoot);
  const roots = Array.isArray(config.roots) && config.roots.length
    ? config.roots
    : loadWorkspaceRootsFromStateConfig(realState);
  assertConfigOutsideWorkspace(capabilityFilePath(realState), roots);
  assertConfigOutsideWorkspace(webuiAuthFilePath(realState), roots);

  if (action === 'status') {
    const auth = readWebUiAuthSync(realState, { workspaceRoots: roots });
    return {
      ...publicWebUiAuthSummary(auth),
      authFile: webuiAuthFilePath(realState),
      capabilitiesFile: capabilityFilePath(realState),
      outsideWorkspace: true,
    };
  }

  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error('Modifying WebUI credentials requires an interactive local terminal (TTY).');
  }

  if (action === 'init') {
    const ticket = issueSetupTicketSync(realState, { workspaceRoots: roots, requirePrivateState: true });
    const auth = readWebUiAuthSync(realState, { workspaceRoots: roots });
    console.log(`Open http://localhost:${port}/ in your browser.`);
    console.log(`Requirement: ${auth.hostPasskeySupported || auth.requirePasskey ? 'PassKey mandatory' : 'Strong password (or PassKey if browser supports it)'}`);
    console.log(`Single-use setup code (expires ${ticket.expiresAt}):`);
    console.log(ticket.setupToken);
    return { initializedTicket: true, expiresAt: ticket.expiresAt };
  }

  if (action === 'set-password') {
    const auth = readWebUiAuthSync(realState, { workspaceRoots: roots });
    if (auth.hostPasskeySupported || auth.requirePasskey || auth.passkeys.length > 0) {
      throw new Error('This machine enforces PassKey authentication; run webui-auth init to enroll a PassKey instead.');
    }
    const first = await promptHiddenInput('New strong WebUI password (>=14 chars, upper+lower+digit+symbol): ');
    const strength = validateStrongPassword(first, { forbiddenTerms: [os.userInfo().username, os.hostname()] });
    if (!strength.valid) throw new Error(strength.reason);
    const second = await promptHiddenInput('Confirm WebUI password: ');
    if (first !== second) throw new Error('Passwords do not match.');
    const updated = setStrongPasswordSync(realState, {
      password: first,
      allowBypassTicket: true,
      workspaceRoots: roots,
      requirePrivateState: true,
    });
    return { configured: true, ...publicWebUiAuthSummary(updated) };
  }

  if (action === 'reset') {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    let answer = '';
    try {
      answer = (await rl.question('Type RESET to clear enrolled WebUI credentials and issue a fresh setup code: ')).trim();
    } finally {
      rl.close();
    }
    if (answer !== 'RESET') throw new Error('Reset cancelled.');
    const result = resetWebUiAuthSync(realState, { workspaceRoots: roots, requirePrivateState: true, issueTicket: true });
    console.log(`Open http://localhost:${port}/ in your browser.`);
    if (result.setupToken) {
      console.log(`Single-use setup code (expires ${result.expiresAt}):`);
      console.log(result.setupToken);
    }
    return { reset: true, hostPasskeySupported: result.hostPasskeySupported, expiresAt: result.expiresAt };
  }

  throw new Error('Usage: webui-auth <status|init|set-password|reset>');
}

export async function runWebUi({
  stateDir = defaultStateDirectory(),
  host = '127.0.0.1',
  port = 18797,
} = {}) {
  const runtimeRoot = path.resolve(import.meta.dirname, '..');
  const { realState } = readTrustedConfig(stateDir, runtimeRoot);
  clearNodeOverrides();
  const parsedPort = Number(port);
  if (!Number.isInteger(parsedPort) || parsedPort < 0 || parsedPort > 65535) {
    throw new Error('Invalid --port value.');
  }
  const server = await startWebUiServer({
    stateDir: realState,
    runtimeRoot,
    host,
    port: parsedPort,
    requirePrivateState: true,
  });
  const displayHost = host === '127.0.0.1' ? 'localhost' : host;
  console.log(`AgentDock WebUI listening on http://${displayHost}:${server.port} (${server.url})`);
  await new Promise(resolve => {
    const shutdown = () => {
      void server.close().finally(resolve);
    };
    process.once('SIGINT', shutdown);
    process.once('SIGTERM', shutdown);
  });
}

export function manageSystemdUserServices({
  action = 'status',
  stateDir = defaultStateDirectory(),
  host = '127.0.0.1',
  port = 18797,
} = {}) {
  if (process.platform !== 'linux') {
    throw new Error('systemd user service management is only supported on Linux.');
  }
  const runtimeRoot = path.resolve(import.meta.dirname, '..');
  const { realState } = readTrustedConfig(stateDir, runtimeRoot);
  const runWrapper = path.join(realState, 'run-service');
  const webuiWrapper = path.join(realState, 'webui');
  assertTrustedBinary(runWrapper);
  assertTrustedBinary(webuiWrapper);

  const unitDir = path.join(os.homedir(), '.config', 'systemd', 'user');
  const bridgeUnitPath = path.join(unitDir, 'agentdock-bridge.service');
  const webuiUnitPath = path.join(unitDir, 'agentdock-webui.service');

  if (action === 'install' || action === 'enable') {
    fs.mkdirSync(unitDir, { recursive: true, mode: 0o755 });
    const { bridgeUnit, webuiUnit } = renderSystemdUnits({ stateDir: realState, host, port });
    fs.writeFileSync(bridgeUnitPath, bridgeUnit, { mode: 0o644 });
    fs.writeFileSync(webuiUnitPath, webuiUnit, { mode: 0o644 });
    execFileSync('systemctl', ['--user', 'daemon-reload'], { stdio: 'inherit', timeout: 15000 });
    execFileSync('systemctl', ['--user', 'enable', '--now', 'agentdock-webui.service', 'agentdock-bridge.service'], {
      stdio: 'inherit',
      timeout: 30000,
    });
    return {
      installed: true,
      units: [bridgeUnitPath, webuiUnitPath],
      webuiUrl: `http://${host === '127.0.0.1' ? 'localhost' : host}:${port}`,
    };
  }

  if (['start', 'stop', 'restart', 'disable'].includes(action)) {
    const args = action === 'disable'
      ? ['--user', 'disable', '--now', 'agentdock-webui.service', 'agentdock-bridge.service']
      : ['--user', action, 'agentdock-webui.service', 'agentdock-bridge.service'];
    execFileSync('systemctl', args, { stdio: 'inherit', timeout: 30000 });
    return { action, ok: true };
  }

  if (action === 'status') {
    const query = unit => {
      const read = verb => {
        try {
          return execFileSync('systemctl', ['--user', verb, unit], { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
        } catch (err) {
          return String(err?.stdout || '').trim() || 'inactive';
        }
      };
      return { enabled: read('is-enabled'), active: read('is-active') };
    };
    return {
      bridge: query('agentdock-bridge.service'),
      webui: query('agentdock-webui.service'),
    };
  }

  throw new Error('Usage: service <install|enable|disable|start|stop|restart|status>');
}

async function main() {
  if (process.platform === 'win32') {
    throw new Error('Use the PowerShell scripts in scripts/*.ps1 on Windows hosts.');
  }
  const { command, flags, positionals } = parseCliArgs(process.argv.slice(2));
  const stateDir = path.resolve(flags['state-dir'] || defaultStateDirectory());
  switch (command) {
    case 'setup': {
      const result = setupHost({
        stateDir,
        roots: flags.roots,
        origin: flags.origin,
        secretBackend: flags['secret-backend'] || 'auto',
      });
      console.log(JSON.stringify(result, null, 2));
      break;
    }
    case 'install': {
      const result = await installHardened({
        stateDir,
        workspace: flags.workspace,
        image: flags.image || 'agentdock-dev:2026-10-28',
        context: flags.context,
        docker: flags.docker,
        proxy: flags.proxy,
        allowOutbound: flags['allow-outbound'] !== 'false',
      });
      console.log(JSON.stringify(result, null, 2));
      break;
    }
    case 'start': {
      console.log(startConnector({ stateDir }).message);
      break;
    }
    case 'stop': {
      console.log((await stopConnector({ stateDir })).message);
      break;
    }
    case 'status': {
      console.log(JSON.stringify(await statusConnector({ stateDir }), null, 2));
      break;
    }
    case 'run': {
      await runSupervisor({ stateDir });
      break;
    }
    case 'webui': {
      await runWebUi({
        stateDir,
        host: flags.host || '127.0.0.1',
        port: flags.port ? Number(flags.port) : 18797,
      });
      break;
    }
    case 'webui-auth': {
      const action = positionals[0] || 'status';
      const outcome = await manageWebUiAuth({
        action,
        stateDir,
        port: flags.port ? Number(flags.port) : 18797,
      });
      if (action === 'status' || action === 'set-password') {
        console.log(JSON.stringify(outcome, null, 2));
      }
      break;
    }
    case 'service': {
      const action = positionals[0] || 'status';
      const outcome = manageSystemdUserServices({
        action,
        stateDir,
        host: flags.host || '127.0.0.1',
        port: flags.port ? Number(flags.port) : 18797,
      });
      console.log(JSON.stringify(outcome, null, 2));
      break;
    }
    case 'approve': {
      approveCommand({ stateDir });
      break;
    }
    case 'password': {
      await showPassword({ stateDir });
      break;
    }
    case 'upload-secrets': {
      const realState = assertPrivateState(stateDir);
      uploadSecretsSync(realState, { wranglerPath: flags.wrangler, wranglerConfig: flags['wrangler-config'] });
      console.log('Secrets uploaded to Cloudflare Worker.');
      break;
    }
    case 'rotate-secrets': {
      const realState = assertPrivateState(stateDir);
      const outcome = rotateSecretsSync(realState, { wranglerPath: flags.wrangler, wranglerConfig: flags['wrangler-config'] });
      console.log(JSON.stringify(outcome));
      break;
    }
    default: {
      console.error('Usage: node scripts/host-cli.mjs <setup|install|start|stop|status|webui|webui-auth|service|approve|password|upload-secrets|rotate-secrets> [options]');
      process.exitCode = 1;
    }
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename)) {
  main().catch(error => {
    console.error(error?.message || 'Host command failed.');
    process.exitCode = 1;
  });
}
