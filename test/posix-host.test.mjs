// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { promisify } from 'node:util';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import {
  assertPlainLocalPath,
  assertWriteProtectedPath,
  assertPrivateState,
  assertPrivateFile,
  assertTrustedBinary,
  assertPinnedNode,
  assertConnectorStopped,
  clearNodeOverrides,
  getProcessIdentity,
  findOwnedProcess,
  sha256FileSync,
} from '../local/host-safety.mjs';
import {
  SECRET_META_FILE,
  SECRET_DATA_FILE,
  SECRET_NEXT_FILE,
  createSecrets,
  exportSecretsSync,
  rotateSecretsSync,
  resolveSecretBackend,
} from '../local/host-secrets.mjs';
import { NODE_DISTRIBUTIONS, getDistribution } from '../local/node-toolchains.mjs';
import { loadSecrets, proxyCandidates } from '../local/connector.mjs';
import { defaultDockerContext, hostContainerIds, isCaseInsensitiveHost } from '../local/sandbox.mjs';
import { parseChildId } from '../container/runner.mjs';
import { setupHost, installHardened, startConnector, stopConnector, statusConnector } from '../scripts/host-cli.mjs';

const posix = process.platform !== 'win32';

async function homeFixture(t) {
  const base = await fs.mkdtemp(path.join(os.homedir(), '.ad-posix-'));
  await fs.chmod(base, 0o700);
  t.after(async () => {
    assert.equal(path.dirname(base), os.homedir());
    assert.ok(path.basename(base).startsWith('.ad-posix-'));
    await fs.rm(base, { recursive: true, force: true });
  });
  return base;
}

test('POSIX host safety enforces 0700 state, rejects symlinks, hardlinks, group/world write and checksum tampering', { skip: !posix }, async t => {
  const base = await homeFixture(t);
  const workspace = path.join(base, 'workspace');
  const state = path.join(base, 'state');
  const toolchain = path.join(base, 'toolchains');
  await Promise.all([workspace, state, toolchain].map(dir => fs.mkdir(dir, { mode: 0o700 })));

  const nodeExe = path.join(toolchain, 'node');
  await fs.copyFile(process.execPath, nodeExe);
  await fs.chmod(nodeExe, 0o755);
  const nodeSha = sha256FileSync(nodeExe);

  assert.equal(assertPrivateState(state), path.resolve(state));
  assert.equal(assertTrustedBinary(nodeExe, workspace), path.resolve(nodeExe));
  assert.equal(assertPinnedNode({ nodePath: nodeExe, nodeRoot: toolchain, nodeSha256: nodeSha, roots: [workspace] }, state), path.resolve(nodeExe));

  // World-writable / group-readable state must be rejected.
  await fs.chmod(state, 0o755);
  assert.throws(() => assertPrivateState(state), /0700/);
  await fs.chmod(state, 0o700);

  // Untrusted group-writable parent must be rejected.
  const nestedParent = path.join(base, 'shared-parent');
  const nestedChild = path.join(nestedParent, 'binary');
  await fs.mkdir(nestedParent);
  await fs.chmod(nestedParent, 0o775);
  await fs.writeFile(nestedChild, '#!/bin/sh\n', { mode: 0o755 });
  assert.throws(() => assertWriteProtectedPath(nestedChild), /writable by an untrusted/);
  await fs.chmod(nestedParent, 0o700);
  assert.equal(assertTrustedBinary(nestedChild, workspace), path.resolve(nestedChild));

  // Symlinked state path must be rejected.
  const symlinkState = path.join(base, 'state-link');
  await fs.symlink(state, symlinkState);
  assert.throws(() => assertPlainLocalPath(symlinkState), /symbolic links/);
  await fs.unlink(symlinkState);

  // Hard-linked executable must be rejected.
  const alias = path.join(workspace, 'node-alias');
  await fs.link(nodeExe, alias);
  assert.throws(() => assertTrustedBinary(nodeExe, workspace), /hard-link/);
  await fs.unlink(alias);

  // Checksum mismatch or outside toolchain root must be rejected.
  assert.throws(() => assertPinnedNode({ nodePath: nodeExe, nodeRoot: toolchain, nodeSha256: '0'.repeat(64), roots: [workspace] }, state), /integrity/);
  assert.throws(() => assertPinnedNode({ nodePath: nestedChild, nodeRoot: toolchain, nodeSha256: sha256FileSync(nestedChild), roots: [workspace] }, state), /inside its private/);
});

test('POSIX clearNodeOverrides strips Node and dynamic linker injection variables', { skip: !posix }, () => {
  const env = {
    PATH: '/usr/bin',
    NODE_OPTIONS: '--require /tmp/evil.js',
    NODE_PATH: '/tmp/evil',
    NODE_TLS_REJECT_UNAUTHORIZED: '0',
    NODE_EXTRA_CA_CERTS: '/tmp/ca.pem',
    LD_PRELOAD: '/tmp/evil.so',
    LD_LIBRARY_PATH: '/tmp/lib',
    DYLD_INSERT_LIBRARIES: '/tmp/evil.dylib',
    DYLD_LIBRARY_PATH: '/tmp/dylib',
    DYLD_FRAMEWORK_PATH: '/tmp/fw',
  };
  clearNodeOverrides(env);
  assert.deepEqual(env, { PATH: '/usr/bin' });
});

test('POSIX process identity detects live processes and rejects mismatched sources or recycled records', { skip: !posix }, async t => {
  const base = await homeFixture(t);
  const recordFile = path.join(base, 'proc.json');
  const me = getProcessIdentity(process.pid);
  assert.ok(me);
  assert.equal(me.pid, process.pid);
  assert.ok(me.startTime.length > 0);
  await fs.writeFile(recordFile, JSON.stringify({ ...me, source: 'unit-test-marker' }), { mode: 0o600 });
  assert.ok(findOwnedProcess(recordFile, 'unit-test-marker'));
  assert.equal(findOwnedProcess(recordFile, 'wrong-marker'), null);
  await fs.writeFile(recordFile, JSON.stringify({ ...me, startTime: '0', source: 'unit-test-marker' }), { mode: 0o600 });
  assert.equal(findOwnedProcess(recordFile, 'unit-test-marker'), null);

  await fs.writeFile(path.join(base, 'supervisor.json'), JSON.stringify({ ...me, source: 'unit-test-marker' }), { mode: 0o600 });
  assert.throws(() => assertConnectorStopped(base), /Stop the current connector/);
});

test('POSIX posix-file secrets create, load via connector.loadSecrets, and two-phase rotate safely', { skip: !posix }, async t => {
  const base = await homeFixture(t);
  const state = path.join(base, 'state');

  const created = createSecrets(state, { backend: 'file' });
  assert.equal(created.backend, 'posix-file');
  assert.equal((await fs.stat(state)).mode & 0o777, 0o700);
  assert.equal((await fs.stat(path.join(state, SECRET_DATA_FILE))).mode & 0o777, 0o600);
  assert.equal((await fs.stat(path.join(state, SECRET_META_FILE))).mode & 0o777, 0o600);

  const loaded = loadSecrets(state);
  assert.ok(loaded.bridgeToken.length >= 32);
  assert.ok(loaded.ownerPassword.length > 0);
  assert.match(loaded.ownerPasswordHash, /^pbkdf2-sha256\$100000\$/);

  // Relaxing permissions on secret file or state dir must fail closed without leaking secrets.
  await fs.chmod(path.join(state, SECRET_DATA_FILE), 0o644);
  assert.throws(() => loadSecrets(state), error => {
    assert.equal(error.message, 'Protected credential loading failed. Check the trusted local installation.');
    assert.equal(error.message.includes(loaded.bridgeToken), false);
    return true;
  });
  await fs.chmod(path.join(state, SECRET_DATA_FILE), 0o600);
  assert.deepEqual(exportSecretsSync(state), loaded);

  // Failed upload during rotation must preserve current credentials and keep secrets.next.json.
  assert.throws(() => rotateSecretsSync(state, {
    uploader: () => { throw new Error('Simulated cloud upload outage'); },
  }), /outage/);
  assert.deepEqual(loadSecrets(state), loaded);
  assert.ok(fsSync.existsSync(path.join(state, SECRET_NEXT_FILE)));

  // Subsequent retry promotes the staged next secret and archives the retired one.
  const stagedNext = JSON.parse(await fs.readFile(path.join(state, SECRET_NEXT_FILE), 'utf8'));
  let uploadedPayload;
  const rotated = rotateSecretsSync(state, {
    uploader: next => { uploadedPayload = next; },
  });
  assert.equal(rotated.rotated, true);
  assert.deepEqual(uploadedPayload, stagedNext);
  assert.deepEqual(loadSecrets(state), stagedNext);
  assert.equal(fsSync.existsSync(path.join(state, SECRET_NEXT_FILE)), false);
  const files = await fs.readdir(state);
  assert.ok(files.some(name => name.startsWith('secrets-retired-') && name.endsWith('.json')));

  // Selective field export only returns bridgeToken without owner password hashes.
  const tokenOnly = exportSecretsSync(state, { fields: ['bridgeToken'] });
  assert.deepEqual(tokenOnly, { bridgeToken: stagedNext.bridgeToken });

  // Stale next matching current must not produce a no-op rotation.
  await fs.writeFile(path.join(state, SECRET_NEXT_FILE), JSON.stringify(stagedNext), { mode: 0o600 });
  const freshRotated = rotateSecretsSync(state, {
    uploader: next => { uploadedPayload = next; },
  });
  assert.equal(freshRotated.rotated, true);
  assert.notEqual(uploadedPayload.bridgeToken, stagedNext.bridgeToken);
  assert.deepEqual(loadSecrets(state), uploadedPayload);
});

test('Linux and macOS toolchain distributions and secret backend selection follow platform rules', () => {
  for (const [platform, arch] of [['linux', 'x64'], ['linux', 'arm64'], ['darwin', 'x64'], ['darwin', 'arm64'], ['win32', 'x64']]) {
    const dist = getDistribution(platform, arch);
    assert.match(dist.sha256, /^[a-f0-9]{64}$/);
    assert.ok(NODE_DISTRIBUTIONS[`${platform}-${arch}`]);
  }
  if (process.platform === 'linux') {
    assert.throws(() => resolveSecretBackend('keychain'), /requires macOS/);
    assert.equal(resolveSecretBackend('file'), 'posix-file');
  } else if (process.platform === 'darwin') {
    assert.throws(() => resolveSecretBackend('secret-service'), /requires Linux/);
    assert.equal(resolveSecretBackend('file'), 'posix-file');
  }
});

test('proxyCandidates honors lowercase and uppercase proxy environment variables on POSIX', { skip: !posix }, () => {
  const saved = {
    HTTPS_PROXY: process.env.HTTPS_PROXY,
    https_proxy: process.env.https_proxy,
    HTTP_PROXY: process.env.HTTP_PROXY,
    http_proxy: process.env.http_proxy,
  };
  try {
    delete process.env.HTTPS_PROXY;
    delete process.env.HTTP_PROXY;
    process.env.https_proxy = 'http://127.0.0.1:8888';
    process.env.http_proxy = 'http://127.0.0.1:8889';
    const candidates = proxyCandidates();
    assert.ok(candidates.includes('http://127.0.0.1:8888'));
    assert.ok(candidates.includes('http://127.0.0.1:8889'));
    assert.equal(candidates.at(-1), null);
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
});

test('sandbox defaults and container runner ID parsing handle Linux UIDs and macOS case sensitivity safely', async t => {
  assert.equal(defaultDockerContext('linux'), 'default');
  assert.equal(defaultDockerContext('darwin'), 'desktop-linux');
  assert.equal(defaultDockerContext('win32'), 'desktop-linux');
  assert.equal(isCaseInsensitiveHost('darwin'), true);
  assert.equal(isCaseInsensitiveHost('win32'), true);
  assert.equal(isCaseInsensitiveHost('linux'), false);

  assert.deepEqual(hostContainerIds('linux', () => 1005, () => 1006), { uid: 1005, gid: 1006 });
  assert.deepEqual(hostContainerIds('linux', () => 0, () => 0), { uid: 1000, gid: 1000 });
  assert.deepEqual(hostContainerIds('darwin', () => 501, () => 20), { uid: 1000, gid: 1000 });

  assert.equal(parseChildId(undefined), 1000);
  assert.equal(parseChildId('0'), 1000);
  assert.equal(parseChildId('-5'), 1000);
  assert.equal(parseChildId('70000'), 1000);
  assert.equal(parseChildId('abc'), 1000);
  assert.equal(parseChildId('1005'), 1005);

  if (!posix) return;
  const base = await homeFixture(t);
  const workspace = path.join(base, 'workspace');
  const stateDir = path.join(base, 'state');
  await fs.mkdir(workspace, { mode: 0o700 });
  await fs.mkdir(stateDir, { mode: 0o700 });
  const dockerPath = await fs.realpath(process.execPath);

  const seenCreateFlags = [];
  const originalExecFile = childProcess.execFile;
  const originalSpawn = childProcess.spawn;
  const fakeImage = `sha256:${'b'.repeat(64)}`;
  const execMock = () => { throw new Error('expected custom promisify'); };
  execMock[promisify.custom] = async (_file, args) => {
    const sub = args.slice(2);
    if (sub[0] === 'context') return { stdout: JSON.stringify([{ Endpoints: { docker: { Host: 'unix:///synthetic.sock' } } }]) };
    if (sub[0] === 'image' || sub[0] === 'ps') return { stdout: '' };
    if (sub[0] === 'create') {
      seenCreateFlags.push(sub);
      return { stdout: sub[sub.indexOf('--name') + 1] };
    }
    if (sub[0] === 'rm') return { stdout: '' };
    throw new Error(`Unexpected command: ${sub[0]}`);
  };
  const spawnMock = () => {
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.stdin = new Writable({ write(_chunk, _enc, done) { done(); } });
    child.kill = () => true;
    queueMicrotask(() => {
      child.stdout.write(JSON.stringify({ result: { content: [{ type: 'text', text: '{}' }] } }));
      child.stdout.end();
      child.stderr.end();
      child.emit('close', 0, null);
    });
    return child;
  };

  childProcess.execFile = execMock;
  childProcess.spawn = spawnMock;
  syncBuiltinESMExports();
  let runtime;
  try {
    const { createSandboxRuntime } = await import(`../local/sandbox.mjs?test=${Date.now()}`);
    runtime = await createSandboxRuntime({
      roots: [workspace],
      stateDir,
      allowExec: true,
      sandbox: { enabled: true, image: fakeImage, dockerPath },
    });
    await runtime.handleRpc({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'list_directory', arguments: {} } });
    assert.equal(seenCreateFlags.length, 1);
    const expectedIds = hostContainerIds();
    assert.ok(seenCreateFlags[0].includes(`/home/developer:rw,nosuid,nodev,size=512m,uid=${expectedIds.uid},gid=${expectedIds.gid},mode=700`));

    // Simulate non-1000 Linux UID/GID to verify dynamic ID propagation flags.
    if (process.platform === 'linux') {
      seenCreateFlags.length = 0;
      const origGetUid = process.getuid;
      const origGetGid = process.getgid;
      process.getuid = () => 1005;
      process.getgid = () => 1006;
      try {
        const nonDefaultRuntime = await createSandboxRuntime({
          roots: [workspace],
          stateDir,
          allowExec: true,
          sandbox: { enabled: true, image: fakeImage, dockerPath },
        });
        await nonDefaultRuntime.handleRpc({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'list_directory', arguments: {} } });
        await nonDefaultRuntime.close();
      } finally {
        process.getuid = origGetUid;
        process.getgid = origGetGid;
      }
      assert.equal(seenCreateFlags.length, 1);
      assert.ok(seenCreateFlags[0].includes('/home/developer:rw,nosuid,nodev,size=512m,uid=1005,gid=1006,mode=700'));
      assert.ok(seenCreateFlags[0].includes('AGENTDOCK_CHILD_UID=1005'));
      assert.ok(seenCreateFlags[0].includes('AGENTDOCK_CHILD_GID=1006'));
    }
  } finally {
    await runtime?.close();
    childProcess.execFile = originalExecFile;
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
  }
});

test('POSIX host-cli setup and hardened install produce 0700 wrappers and reject untrusted workspace runs', { skip: !posix }, async t => {
  const base = await homeFixture(t);
  const workspace = path.join(base, 'workspace');
  const stateDir = path.join(base, 'state');
  const toolchain = path.join(base, 'toolchains');
  await fs.mkdir(workspace, { mode: 0o700 });
  await fs.mkdir(toolchain, { mode: 0o700 });

  const fakeDocker = path.join(base, 'fake-docker');
  await fs.writeFile(fakeDocker, '#!/bin/sh\necho ok\n', { mode: 0o755 });
  const fakeNode = path.join(toolchain, 'node');
  await fs.copyFile(process.execPath, fakeNode);
  await fs.chmod(fakeNode, 0o755);
  const fakeNodeSha = sha256FileSync(fakeNode);
  const fakeImage = `sha256:${'c'.repeat(64)}`;

  const setup = setupHost({
    stateDir,
    roots: [workspace],
    origin: 'https://bridge.example.test',
    secretBackend: 'file',
  });
  assert.equal(setup.secretBackend, 'posix-file');

  const installed = await installHardened({
    stateDir,
    workspace,
    docker: fakeDocker,
    context: 'default',
    image: 'agentdock-dev:test',
    skipDependencyInstall: true,
    nodeRuntimeProvider: async () => ({
      nodePath: fakeNode,
      nodeRoot: toolchain,
      nodeSha256: fakeNodeSha,
      version: '24.22.1',
    }),
    dockerInspector: () => ({ endpoint: 'unix:///var/run/docker.sock', imageId: fakeImage }),
  });

  assert.ok(installed.runtime.startsWith(stateDir + path.sep));
  assert.equal(installed.image, fakeImage);

  const config = JSON.parse(await fs.readFile(path.join(stateDir, 'config.json'), 'utf8'));
  assert.equal(config.sourceRoot, installed.runtime);
  assert.equal(config.allowExec, true);
  assert.equal(config.sandbox.dockerPath, await fs.realpath(fakeDocker));
  assert.equal(config.sandbox.context, 'default');

  // Monorepo workspace files and frozen rpm.json must be installed and hashed in installation.json.
  assert.equal(fsSync.existsSync(path.join(installed.runtime, 'pnpm-workspace.yaml')), true);
  assert.equal(fsSync.existsSync(path.join(installed.runtime, 'packages', 'kernel', 'src', 'boot.mjs')), true);
  assert.equal(fsSync.existsSync(path.join(installed.runtime, 'plugins', 'mcp-hub', 'src', 'index.mjs')), true);
  assert.equal(fsSync.existsSync(path.join(installed.runtime, 'packages', 'kernel', 'test')), false);
  const rpmPath = path.join(installed.runtime, 'rpm.json');
  const rpmDoc = JSON.parse(await fs.readFile(rpmPath, 'utf8'));
  assert.equal(rpmDoc.format, 1);
  assert.deepEqual(rpmDoc.rootPlugins.map(p => p.id).sort(), ['cloud-relay', 'console', 'host', 'sandbox']);
  const installationDoc = JSON.parse(await fs.readFile(path.join(stateDir, 'installation.json'), 'utf8'));
  assert.equal(installationDoc.rpmManifestHash, rpmDoc.manifestHash);
  assert.equal(installationDoc.sha256['rpm.json'], sha256FileSync(rpmPath));
  assert.equal(installationDoc.sha256['pnpm-workspace.yaml'], sha256FileSync(path.join(installed.runtime, 'pnpm-workspace.yaml')));

  for (const name of ['start', 'stop', 'status', 'approve', 'password']) {
    const wrapper = path.join(stateDir, name);
    const stat = await fs.stat(wrapper);
    assert.equal(stat.mode & 0o777, 0o700);
    const text = await fs.readFile(wrapper, 'utf8');
    assert.match(text, /unset NODE_OPTIONS/);
    assert.match(text, /LD_PRELOAD/);
    assert.match(text, /DYLD_INSERT_LIBRARIES/);
  }

  // Attempting to start/status from the git repo source copy instead of installed runtime must be rejected.
  assert.throws(() => startConnector({ stateDir }), /protected launcher/);
  const status = await statusConnector({ stateDir, probeHealth: false });
  assert.equal(status.supervisorAlive, false);
  assert.equal(status.connectorAlive, false);

  // Run stopConnector when stopped returns clean confirmation.
  const stopped = await stopConnector({ stateDir });
  assert.equal(stopped.stopped, true);
});

test('POSIX supervisor start, status, single-instance lock, and graceful stop work via generated launchers', { skip: !posix, timeout: 30000 }, async t => {
  const execFile = promisify(childProcess.execFile);
  const base = await homeFixture(t);
  const workspace = path.join(base, 'workspace');
  const stateDir = path.join(base, 'st');
  const toolchain = path.join(base, 'tc');
  await fs.mkdir(workspace, { mode: 0o700 });
  await fs.mkdir(toolchain, { mode: 0o700 });

  const fakeNode = path.join(toolchain, 'node');
  await fs.copyFile(process.execPath, fakeNode);
  await fs.chmod(fakeNode, 0o755);
  const fakeNodeSha = sha256FileSync(fakeNode);

  // Create a mock docker executable that passes context/image/ps probes cleanly.
  const fakeDocker = path.join(base, 'docker');
  await fs.writeFile(fakeDocker, `#!/bin/sh
case "$3" in
  context) echo '[{"Endpoints":{"docker":{"Host":"unix:///var/run/docker.sock"}}}]' ;;
  image) echo "sha256:${'d'.repeat(64)}" ;;
  ps) echo "" ;;
  *) exit 0 ;;
esac
`, { mode: 0o755 });

  setupHost({ stateDir, roots: [workspace], origin: 'http://127.0.0.1:1', secretBackend: 'file' });
  const installed = await installHardened({
    stateDir,
    workspace,
    docker: fakeDocker,
    context: 'default',
    image: 'agentdock-dev:test',
    skipDependencyInstall: true,
    nodeRuntimeProvider: async () => ({
      nodePath: fakeNode,
      nodeRoot: toolchain,
      nodeSha256: fakeNodeSha,
      version: '24.22.1',
    }),
    dockerInspector: () => ({ endpoint: 'unix:///var/run/docker.sock', imageId: `sha256:${'d'.repeat(64)}` }),
  });

  // Provide minimal prod stubs in the isolated test release so connector.mjs boots offline.
  const wsDir = path.join(installed.runtime, 'node_modules', 'ws');
  const proxyDir = path.join(installed.runtime, 'node_modules', 'https-proxy-agent');
  await fs.mkdir(wsDir, { recursive: true });
  await fs.mkdir(proxyDir, { recursive: true });
  await fs.writeFile(path.join(wsDir, 'package.json'), '{"name":"ws","type":"module","main":"index.mjs"}');
  await fs.writeFile(path.join(wsDir, 'index.mjs'), 'import { EventEmitter } from "node:events"; export default class WebSocket extends EventEmitter { static OPEN=1; static CONNECTING=0; static CLOSED=3; readyState=3; close(){} terminate(){} }');
  await fs.writeFile(path.join(proxyDir, 'package.json'), '{"name":"https-proxy-agent","type":"module","main":"index.mjs"}');
  await fs.writeFile(path.join(proxyDir, 'index.mjs'), 'export class HttpsProxyAgent {}');

  t.after(async () => {
    await stopConnector({ stateDir }).catch(() => {});
  });

  const startOut = await execFile(path.join(stateDir, 'start'), [], { timeout: 10000 });
  assert.match(startOut.stdout, /Start requested/);

  // Wait until both supervisor and connector process records appear and are verified alive.
  const deadline = Date.now() + 10000;
  let live;
  while (Date.now() < deadline) {
    live = await statusConnector({ stateDir, probeHealth: false });
    if (live.supervisorAlive && live.connectorAlive) break;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.equal(live.supervisorAlive, true);
  assert.equal(live.connectorAlive, true);

  // Second start invocation must recognize the active instance without spawning another.
  const secondStart = await execFile(path.join(stateDir, 'start'), [], { timeout: 10000 });
  assert.match(secondStart.stdout, /Already running/);

  // Verify the generated status launcher also reports both processes live.
  const statusCmdOut = await execFile(path.join(stateDir, 'status'), [], { timeout: 10000 });
  const statusParsed = JSON.parse(statusCmdOut.stdout);
  assert.equal(statusParsed.supervisorAlive, true);
  assert.equal(statusParsed.connectorAlive, true);

  const stopOut = await execFile(path.join(stateDir, 'stop'), [], { timeout: 25000 });
  assert.match(stopOut.stdout, /Stopped this connector/);

  const afterStop = await statusConnector({ stateDir, probeHealth: false });
  assert.equal(afterStop.supervisorAlive, false);
  assert.equal(afterStop.connectorAlive, false);
  assert.equal(fsSync.existsSync(path.join(stateDir, 'supervisor.sock')), false);
});
