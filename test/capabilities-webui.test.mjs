// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import crypto, { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { WebSocketServer } from 'ws';
import {
  assertConfigOutsideWorkspace,
  capabilityFilePath,
  readCapabilitiesSync,
  writeCapabilitiesSync,
  isToolEnabled,
  filterToolsByCapabilities,
} from '../local/capabilities.mjs';
import { BridgeConnector } from '../local/connector.mjs';
import { mcpServersFilePath, readMcpServersSync } from '../local/mcp-registry.mjs';
import { digest as policyDigest } from '../local/request-policy.mjs';
import { resolveTestSandbox } from './docker-fixture.mjs';
import { createSandboxRuntime } from '../local/sandbox.mjs';
import { TOOL_DEFINITIONS } from '../local/tools.mjs';
import { toBase64Url } from '../local/webauthn.mjs';
import {
  deletePasskeySync,
  issueSetupTicketSync,
  readWebUiAuthSync,
  setStrongPasswordSync,
  switchToStrongPasswordSync,
  validateStrongPassword,
  webuiAuthFilePath,
} from '../local/webui-auth.mjs';
import { startWebUiServer } from '../local/webui.mjs';
import { renderSystemdUnits } from '../scripts/host-cli.mjs';

async function makeTempState(t) {
  const dir = await fs.mkdtemp(path.join(os.homedir(), '.ad-cap-test-'));
  await fs.chmod(dir, 0o700);
  t.after(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });
  return dir;
}

function httpCall(baseUrl, pathname, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const target = new URL(baseUrl);
    const req = http.request({
      hostname: target.hostname,
      port: target.port,
      path: pathname,
      method,
      headers,
      timeout: 5000,
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({
          status: res.statusCode,
          headers: res.headers,
          text,
          json: () => JSON.parse(text),
        });
      });
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

function mergeCookieHeader(existingCookie, setCookieHeaders = []) {
  const map = new Map();
  for (const part of String(existingCookie || '').split(';')) {
    const eq = part.indexOf('=');
    if (eq > 0) map.set(part.slice(0, eq).trim(), part.slice(eq + 1).trim());
  }
  for (const header of setCookieHeaders) {
    const pair = header.split(';')[0];
    const eq = pair.indexOf('=');
    if (eq > 0) map.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
  }
  return [...map.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
}

function encodeCbor(value) {
  const header = (major, len) => {
    if (len < 24) return Buffer.from([(major << 5) | len]);
    if (len < 256) return Buffer.from([(major << 5) | 24, len]);
    if (len < 65536) {
      const b = Buffer.allocUnsafe(3);
      b[0] = (major << 5) | 25;
      b.writeUInt16BE(len, 1);
      return b;
    }
    const b = Buffer.allocUnsafe(5);
    b[0] = (major << 5) | 26;
    b.writeUInt32BE(len, 1);
    return b;
  };
  if (typeof value === 'boolean') return Buffer.from([value ? 0xf5 : 0xf4]);
  if (typeof value === 'number') {
    return value >= 0 ? header(0, value) : header(1, -1 - value);
  }
  if (Buffer.isBuffer(value)) return Buffer.concat([header(2, value.length), value]);
  if (typeof value === 'string') {
    const buf = Buffer.from(value, 'utf8');
    return Buffer.concat([header(3, buf.length), buf]);
  }
  if (value instanceof Map) {
    const chunks = [header(5, value.size)];
    for (const [k, v] of value.entries()) {
      chunks.push(encodeCbor(k), encodeCbor(v));
    }
    return Buffer.concat(chunks);
  }
  throw new Error('Unsupported test CBOR type.');
}

function createVirtualEs256Passkey({ origin, rpId = 'localhost' }) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const credId = crypto.randomBytes(32);
  let signCount = 0;

  return {
    credentialId: toBase64Url(credId),
    register(challenge) {
      signCount += 1;
      const coseMap = new Map([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, Buffer.from(jwk.x, 'base64url')],
        [-3, Buffer.from(jwk.y, 'base64url')],
      ]);
      const coseBytes = encodeCbor(coseMap);
      const rpHash = crypto.createHash('sha256').update(rpId).digest();
      const flags = Buffer.from([0x45]); // UP | UV | AT
      const counter = Buffer.alloc(4);
      counter.writeUInt32BE(signCount, 0);
      const aaguid = Buffer.alloc(16, 0);
      const credIdLen = Buffer.alloc(2);
      credIdLen.writeUInt16BE(credId.length, 0);
      const authData = Buffer.concat([rpHash, flags, counter, aaguid, credIdLen, credId, coseBytes]);
      const attestationObject = encodeCbor(new Map([
        ['fmt', 'none'],
        ['attStmt', new Map()],
        ['authData', authData],
      ]));
      const clientData = Buffer.from(JSON.stringify({
        type: 'webauthn.create',
        challenge,
        origin,
      }), 'utf8');
      return {
        id: toBase64Url(credId),
        type: 'public-key',
        response: {
          clientDataJSON: toBase64Url(clientData),
          attestationObject: toBase64Url(attestationObject),
          transports: ['internal'],
        },
      };
    },
    assert(challenge, { overrideSignCount, overrideRpId, tamperSig = false } = {}) {
      if (overrideSignCount === undefined) signCount += 1;
      const sc = overrideSignCount ?? signCount;
      const rpHash = crypto.createHash('sha256').update(overrideRpId || rpId).digest();
      const flags = Buffer.from([0x05]); // UP | UV
      const counter = Buffer.alloc(4);
      counter.writeUInt32BE(sc, 0);
      const authData = Buffer.concat([rpHash, flags, counter]);
      const clientData = Buffer.from(JSON.stringify({
        type: 'webauthn.get',
        challenge,
        origin,
      }), 'utf8');
      const clientHash = crypto.createHash('sha256').update(clientData).digest();
      const sig = crypto.sign('sha256', Buffer.concat([authData, clientHash]), privateKey);
      if (tamperSig) sig[sig.length - 1] ^= 0xff;
      return {
        id: toBase64Url(credId),
        type: 'public-key',
        response: {
          clientDataJSON: toBase64Url(clientData),
          authenticatorData: toBase64Url(authData),
          signature: toBase64Url(sig),
        },
      };
    },
  };
}

test('capabilities policy enforces 0600, fail-closed tampering guards, and tool filtering', async t => {
  const stateDir = await makeTempState(t);

  const initial = readCapabilitiesSync(stateDir, { configAllowExec: true });
  assert.equal(initial.exists, false);
  assert.equal(initial.fileRead, true);
  assert.equal(initial.fileWrite, true);
  assert.equal(initial.allowExec, true);

  const written = writeCapabilitiesSync(stateDir, { fileRead: true, fileWrite: false }, { configAllowExec: true });
  assert.equal(written.fileRead, true);
  assert.equal(written.fileWrite, false);
  assert.equal((await fs.stat(capabilityFilePath(stateDir))).mode & 0o777, 0o600);

  const readOnlyNames = filterToolsByCapabilities(TOOL_DEFINITIONS, written, { configAllowExec: true }).map(tool => tool.name);
  assert.ok(readOnlyNames.includes('read_file'));
  assert.ok(readOnlyNames.includes('list_directory'));
  assert.ok(readOnlyNames.includes('exec_command'));
  assert.equal(readOnlyNames.includes('write_file'), false);
  assert.equal(readOnlyNames.includes('edit_file'), false);
  assert.equal(readOnlyNames.includes('delete_file'), false);

  const noRead = writeCapabilitiesSync(stateDir, { fileRead: false, fileWrite: true }, { configAllowExec: true });
  assert.equal(isToolEnabled('read_file', noRead).enabled, false);
  assert.equal(isToolEnabled('exec_command', noRead).enabled, false);
  assert.equal(isToolEnabled('write_file', noRead).enabled, true);
  assert.equal(isToolEnabled('computer_context', noRead).enabled, true);
  assert.equal(isToolEnabled('stop_command', noRead).enabled, true);

  assert.throws(() => writeCapabilitiesSync(stateDir, { allowExec: true }, { configAllowExec: false }), /config\.allowExec is false/);
  assert.throws(() => writeCapabilitiesSync(stateDir, { fileRead: 'yes' }, { configAllowExec: true }), /booleans/);

  // Loose permissions or corrupted JSON must fail closed.
  await fs.chmod(capabilityFilePath(stateDir), 0o644);
  const badPerm = readCapabilitiesSync(stateDir, { configAllowExec: true });
  assert.ok(badPerm.error);
  assert.equal(badPerm.fileRead, false);
  assert.equal(badPerm.fileWrite, false);
  assert.equal(isToolEnabled('read_file', badPerm).enabled, false);
  assert.equal(isToolEnabled('write_file', badPerm).enabled, false);
  assert.equal(isToolEnabled('computer_context', badPerm).enabled, true);

  await fs.chmod(capabilityFilePath(stateDir), 0o600);
  await fs.writeFile(capabilityFilePath(stateDir), '{corrupt', { mode: 0o600 });
  const corrupt = readCapabilitiesSync(stateDir, { configAllowExec: true });
  assert.ok(corrupt.error);
  assert.equal(isToolEnabled('write_file', corrupt).enabled, false);

  // Recovering from corrupted policy must default untouched capabilities to false (fail-safe).
  const recovered = writeCapabilitiesSync(stateDir, { fileRead: true }, { configAllowExec: true });
  assert.equal(recovered.fileRead, true);
  assert.equal(recovered.fileWrite, false);
  assert.equal(recovered.allowExec, false);
});

test('security and capability configs strictly reject storage inside or symlinked into mounted workspace', async t => {
  const base = await makeTempState(t);
  const workspace = path.join(base, 'workspace');
  const insideState = path.join(workspace, '.agentdock-inside');
  const outsideState = path.join(base, 'outside-state');
  await fs.mkdir(workspace, { mode: 0o700 });
  await fs.mkdir(insideState, { mode: 0o700 });
  await fs.mkdir(outsideState, { mode: 0o700 });

  assert.throws(() => assertConfigOutsideWorkspace(capabilityFilePath(insideState), [workspace]), /outside the mounted workspace/);
  assert.throws(() => assertConfigOutsideWorkspace(webuiAuthFilePath(insideState), [workspace]), /outside the mounted workspace/);
  assert.throws(() => writeCapabilitiesSync(insideState, { fileWrite: false }, { workspaceRoots: [workspace] }), /outside the mounted workspace/);
  assert.throws(() => issueSetupTicketSync(insideState, { workspaceRoots: [workspace], passkeyDetector: () => ({ supported: false, reason: 'none' }) }), /outside the mounted workspace/);

  // Symlink inside outsideState pointing into workspace must also be rejected and fail closed.
  const targetInsideWorkspace = path.join(workspace, 'escape-cap.json');
  await fs.writeFile(targetInsideWorkspace, JSON.stringify({ fileRead: true, fileWrite: true }), { mode: 0o600 });
  await fs.symlink(targetInsideWorkspace, capabilityFilePath(outsideState));
  const capViaLink = readCapabilitiesSync(outsideState, { workspaceRoots: [workspace] });
  assert.ok(capViaLink.error);
  assert.equal(capViaLink.fileRead, false);
  assert.equal(capViaLink.fileWrite, false);

  await fs.symlink(targetInsideWorkspace, webuiAuthFilePath(outsideState));
  const authViaLink = readWebUiAuthSync(outsideState, {
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
  });
  assert.ok(authViaLink.error);
  assert.equal(authViaLink.requirePasskey, true);

  // Starting WebUI with auth file symlinked into workspace must fail closed.
  await fs.writeFile(path.join(outsideState, 'config.json'), JSON.stringify({
    origin: 'http://127.0.0.1:8797',
    roots: [workspace],
    defaultCwd: workspace,
    allowExec: true,
    requireLocalApproval: true,
  }), { mode: 0o600 });
  await assert.rejects(() => startWebUiServer({
    stateDir: outsideState,
    runtimeRoot: path.resolve(import.meta.dirname, '..'),
    host: '127.0.0.1',
    port: 0,
  }), /symbolic links|outside/i);
});

test('BridgeConnector enforces live capability changes before creating approval requests', async t => {
  const stateDir = await makeTempState(t);
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await once(wss, 'listening');

  const sockets = [];
  const replies = new Map();
  wss.on('connection', socket => {
    sockets.push(socket);
    socket.on('message', data => {
      const msg = JSON.parse(data);
      if (msg.type === 'ping') socket.send('{"type":"pong"}');
      else if (msg.type === 'response') replies.set(msg.id, msg.body);
    });
  });

  let rpcCalls = 0;
  const connector = new BridgeConnector({
    origin: `http://127.0.0.1:${wss.address().port}`,
    bridgeToken: 'test-bridge-token-value-with-32-chars',
    stateDir,
    proxyProvider: () => [null],
    runtime: {
      handleRpc: async body => ({ jsonrpc: '2.0', id: body.id, result: { ok: ++rpcCalls } }),
      close: async () => {},
    },
  });
  await connector.start();
  while (!sockets.length) await new Promise(r => setTimeout(r, 10));
  t.after(async () => {
    await connector.stop();
    for (const s of wss.clients) s.terminate();
    await new Promise(resolve => wss.close(resolve));
  });

  const sendTool = async (name, args) => {
    const id = randomUUID();
    sockets[0].send(JSON.stringify({
      type: 'request',
      id,
      issuedAt: Date.now(),
      deadline: Date.now() + 90000,
      authorization: { userId: 'owner', clientId: 'test-client', scope: ['computer:read', 'computer:write', 'computer:execute'] },
      body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } },
    }));
    while (!replies.has(id)) await new Promise(r => setTimeout(r, 10));
    return replies.get(id);
  };

  writeCapabilitiesSync(stateDir, { fileRead: true, fileWrite: false }, { configAllowExec: true });
  const writeBlocked = await sendTool('write_file', { path: '/workspace/a.txt', content: 'hi' });
  assert.equal(writeBlocked.error?.data?.code, 'CAPABILITY_DISABLED');
  assert.equal((await fs.readdir(path.join(stateDir, 'approvals'))).length, 0);

  const readRequiresApproval = await sendTool('read_file', { path: '/workspace/a.txt' });
  assert.equal(readRequiresApproval.error?.data?.code, 'LOCAL_APPROVAL_REQUIRED');

  writeCapabilitiesSync(stateDir, { fileRead: false, fileWrite: false }, { configAllowExec: true });
  const execBlocked = await sendTool('exec_command', { cmd: 'echo synthetic-log-marker' });
  assert.equal(execBlocked.error?.data?.code, 'CAPABILITY_DISABLED');
  assert.equal(rpcCalls, 0);
  await connector.logQueue;
  const log = await fs.readFile(path.join(stateDir, 'connector.log'), 'utf8');
  assert.match(log, /capability_blocked/);
  assert.doesNotMatch(log, /synthetic-log-marker|workspace\/a\.txt/);
});

test('WebUI blocks unauthenticated access, enforces strong passwords + lockout + CSRF/Host isolation, and toggles capabilities', async t => {
  const stateDir = await makeTempState(t);
  const outsideWorkspace = await fs.mkdtemp(path.join(os.homedir(), '.ad-cap-ws-'));
  t.after(() => fs.rm(outsideWorkspace, { recursive: true, force: true }));

  await fs.writeFile(path.join(stateDir, 'config.json'), JSON.stringify({
    origin: 'http://127.0.0.1:8797',
    roots: [outsideWorkspace],
    defaultCwd: outsideWorkspace,
    allowExec: true,
    requireLocalApproval: true,
    sandbox: { enabled: true, image: `sha256:${'a'.repeat(64)}`, context: 'default', allowOutbound: true },
  }), { mode: 0o600 });
  await fs.writeFile(path.join(stateDir, 'secrets.meta.json'), JSON.stringify({ backend: 'posix-file' }), { mode: 0o600 });
  await fs.writeFile(path.join(stateDir, 'secrets.json'), JSON.stringify({
    bridgeToken: 'CANARY-NEVER-EXPOSE-BRIDGE-TOKEN-123456',
    ownerPassword: 'CANARY-NEVER-EXPOSE-PASSWORD',
    ownerPasswordHash: 'pbkdf2-sha256$100000$salt$hash',
  }), { mode: 0o600 });
  await fs.mkdir(path.join(stateDir, 'approvals'), { mode: 0o700 });
  await fs.writeFile(path.join(stateDir, 'approvals', '12345678-aaaa-4aaa-8aaa-aaaaaaaaaaaa.request.json'), JSON.stringify({
    id: '12345678-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    tool: 'evil-injected-tool-name',
    expiresAt: Date.now() + 60000,
    body: { params: { arguments: { path: '/workspace/SECRET_BODY_CANARY' } } },
  }), { mode: 0o600 });

  for (const weak of ['short1!', 'alllowercase1234!', 'ALLUPPERCASE1234!', 'NoDigitsHere!Abc', 'NoSymbolsHere123A', 'AgentDock!123456', 'AAAA1234!bcdefg']) {
    assert.equal(validateStrongPassword(weak).valid, false, `Expected weak password rejected: ${weak}`);
  }
  const strongPassword = 'Kx9!mP4#vR2@qL8$zW';
  assert.equal(validateStrongPassword(strongPassword).valid, true);

  await assert.rejects(() => startWebUiServer({
    stateDir,
    runtimeRoot: path.resolve(import.meta.dirname, '..'),
    host: '0.0.0.0',
    port: 0,
  }), /loopback/i);

  const webui = await startWebUiServer({
    stateDir,
    runtimeRoot: path.resolve(import.meta.dirname, '..'),
    host: '127.0.0.1',
    port: 0,
    pollIntervalMs: 100,
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
    gatewayProbe: async () => ({ reachable: false, status: null, latencyMs: null }),
    dockerProbe: async () => ({ dockerOk: true, runningContainers: [] }),
    systemdProbe: async () => ({ supported: true, installed: true, enabled: true, active: false, bridgeEnabled: true, bridgeActive: false, webuiEnabled: true, linger: false }),
    serviceController: async () => {},
  });
  t.after(() => webui.close());

  // Untrusted Host header (DNS rebinding attempt) must be rejected.
  const badHost = await httpCall(webui.url, '/api/status', { headers: { host: 'evil.example:18797' } });
  assert.equal(badHost.status, 403);

  const doubleSlash = await httpCall(webui.url, '//evil.example/api/status');
  assert.equal(doubleSlash.status, 400);

  // Unauthenticated access to status, SSE, capabilities, and service must ALL return 401.
  assert.equal((await httpCall(webui.url, '/api/status')).status, 401);
  assert.equal((await httpCall(webui.url, '/api/events')).status, 401);

  const home = await httpCall(webui.url, '/');
  assert.equal(home.status, 200);
  let csrf = home.text.match(/<meta name="agentdock-csrf" content="([^"]+)"/)?.[1];
  assert.ok(csrf);
  let cookie = mergeCookieHeader('', home.headers['set-cookie']);
  assert.ok(cookie.includes('agentdock_ui_pre='));
  assert.equal(cookie.includes('agentdock_ui_sid='), false);

  // Remote Agent cannot initialize password over HTTP without CLI setup ticket.
  const noTicketSetup = await httpCall(webui.url, '/api/auth/setup/password', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ password: strongPassword }),
  });
  assert.equal(noTicketSetup.status, 401);

  // Unauthenticated POST /api/capabilities returns 401 even with pre-auth CSRF.
  assert.equal((await httpCall(webui.url, '/api/capabilities', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ fileWrite: false }),
  })).status, 401);

  // CLI issues setup ticket -> strong password setup succeeds & rejects weak passwords.
  const ticket = issueSetupTicketSync(stateDir, {
    workspaceRoots: [outsideWorkspace],
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
  });
  const weakAttempt = await httpCall(webui.url, '/api/auth/setup/password', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ setupToken: ticket.setupToken, password: 'weak' }),
  });
  assert.equal(weakAttempt.status, 400);

  const setupRes = await httpCall(webui.url, '/api/auth/setup/password', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ setupToken: ticket.setupToken, password: strongPassword }),
  });
  assert.equal(setupRes.status, 200);
  const setupJson = setupRes.json();
  csrf = setupJson.csrfToken;
  let tabToken = setupJson.tabToken;
  assert.ok(tabToken);
  assert.equal(setupJson.authState.sessionPersistence, 'tab');
  cookie = mergeCookieHeader(cookie, setupRes.headers['set-cookie']);

  // Default per-tab persistence: Cookie alone without X-AgentDock-Tab-Auth must be rejected (401), without destroying the owning tab's session.
  assert.equal((await httpCall(webui.url, '/api/status', { headers: { cookie } })).status, 401);
  assert.equal((await httpCall(webui.url, '/api/status', { headers: { cookie, 'x-agentdock-tab-auth': tabToken } })).status, 200);

  // Verify CSRF / Sec-Fetch-Site / Content-Type rejections even when authenticated.
  const crossSite = await httpCall(webui.url, '/api/capabilities', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'x-agentdock-tab-auth': tabToken,
      'sec-fetch-site': 'cross-site',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ fileWrite: false }),
  });
  assert.equal(crossSite.status, 403);

  const badContentType = await httpCall(webui.url, '/api/capabilities', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'x-agentdock-tab-auth': tabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'text/plain',
    },
    body: '{"fileWrite":false}',
  });
  assert.equal(badContentType.status, 415);

  // Authenticated SSE stream and capability update.
  const sseChunks = [];
  const sseReq = http.get({
    hostname: '127.0.0.1',
    port: webui.port,
    path: '/api/events',
    headers: { cookie, 'x-agentdock-tab-auth': tabToken },
  }, res => {
    assert.equal(res.statusCode, 200);
    res.on('data', chunk => sseChunks.push(chunk.toString('utf8')));
  });
  t.after(() => sseReq.destroy());
  await new Promise(r => setTimeout(r, 80));

  const updateRes = await httpCall(webui.url, '/api/capabilities', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'x-agentdock-tab-auth': tabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ fileRead: true, fileWrite: false }),
  });
  assert.equal(updateRes.status, 200);
  const updatedJson = updateRes.json();
  assert.equal(updatedJson.capabilities.fileWrite, false);
  assert.equal(updatedJson.snapshot.capabilities.mountMode, 'readonly');
  assert.equal(updatedJson.snapshot.approvals.pendingCount, 1);
  assert.equal(updatedJson.snapshot.approvals.items[0].tool, 'unknown');

  const statusRes = await httpCall(webui.url, '/api/status', { headers: { cookie, 'x-agentdock-tab-auth': tabToken } });
  assert.equal(statusRes.status, 200);
  assert.equal(statusRes.text.includes('CANARY-NEVER-EXPOSE'), false);
  assert.equal(statusRes.text.includes('SECRET_BODY_CANARY'), false);
  assert.equal(statusRes.text.includes('passwordHash'), false);

  await new Promise(r => setTimeout(r, 80));
  assert.match(sseChunks.join(''), /event: status/);
  assert.match(sseChunks.join(''), /"mountMode":"readonly"/);

  // Toggling sessionPersistence to 'browser' permits cookie-only requests; switching back to 'tab' rotates tabToken and re-locks.
  const switchBrowser = await httpCall(webui.url, '/api/auth/settings', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'x-agentdock-tab-auth': tabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ sessionPersistence: 'browser' }),
  });
  assert.equal(switchBrowser.status, 200);
  assert.equal(switchBrowser.json().authState.sessionPersistence, 'browser');
  assert.equal((await httpCall(webui.url, '/api/status', { headers: { cookie } })).status, 200);

  const switchTab = await httpCall(webui.url, '/api/auth/settings', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ sessionPersistence: 'tab' }),
  });
  assert.equal(switchTab.status, 200);
  const rotatedTabToken = switchTab.json().tabToken;
  assert.ok(rotatedTabToken && rotatedTabToken !== tabToken);
  tabToken = rotatedTabToken;
  assert.equal((await httpCall(webui.url, '/api/status', { headers: { cookie } })).status, 401);
  assert.equal((await httpCall(webui.url, '/api/status', { headers: { cookie, 'x-agentdock-tab-auth': tabToken } })).status, 200);

  // Logout must invalidate session immediately, return fresh pre-auth CSRF, and 5 failed logins must trigger 429 lockout.
  const stream = http.get(webui.url + '/api/events', { headers: { cookie, 'x-agentdock-tab-auth': tabToken } });
  t.after(() => stream.destroy());
  const [response] = await once(stream, 'response');
  response.resume();
  const streamEnded = once(response, 'end', { signal: AbortSignal.timeout(5000) });
  const logoutRes = await httpCall(webui.url, '/api/auth/logout', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: '{}',
  });
  assert.equal(logoutRes.status, 200);
  await streamEnded;
  csrf = logoutRes.json().csrfToken;
  cookie = mergeCookieHeader(cookie, logoutRes.headers['set-cookie']);
  assert.equal((await httpCall(webui.url, '/api/status', { headers: { cookie } })).status, 401);

  for (let i = 0; i < 5; i++) {
    const failRes = await httpCall(webui.url, '/api/auth/login/password', {
      method: 'POST',
      headers: {
        origin: webui.url,
        cookie,
        'x-agentdock-csrf': csrf,
        'sec-fetch-site': 'same-origin',
        'content-type': 'application/json',
      },
      body: JSON.stringify({ password: 'WrongPassword1!@#4' }),
    });
    assert.equal(failRes.status, 401);
  }
  const lockedRes = await httpCall(webui.url, '/api/auth/login/password', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ password: strongPassword }),
  });
  assert.equal(lockedRes.status, 429);
});

test('WebUI mandates PassKey on PassKey-capable hosts, verifies WebAuthn ECDSA CBOR assertions, and blocks password downgrade', async t => {
  const stateDir = await makeTempState(t);
  const workspace = await fs.mkdtemp(path.join(os.homedir(), '.ad-pk-ws-'));
  t.after(() => fs.rm(workspace, { recursive: true, force: true }));

  await fs.writeFile(path.join(stateDir, 'config.json'), JSON.stringify({
    origin: 'http://127.0.0.1:8797',
    roots: [workspace],
    defaultCwd: workspace,
    allowExec: true,
    requireLocalApproval: true,
  }), { mode: 0o600 });

  // Host with PassKey support must forbid password setup in CLI as well.
  assert.throws(() => setStrongPasswordSync(stateDir, {
    password: 'Kx9!mP4#vR2@qL8$zW',
    allowBypassTicket: true,
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: true, reason: 'windows-hello' }),
  }), /PassKey authentication/i);

  const webui = await startWebUiServer({
    stateDir,
    runtimeRoot: path.resolve(import.meta.dirname, '..'),
    host: '127.0.0.1',
    port: 0,
    passkeyDetector: () => ({ supported: true, reason: 'linux-fido2-hid' }),
    gatewayProbe: async () => ({ reachable: false, status: null, latencyMs: null }),
    dockerProbe: async () => ({ dockerOk: true, runningContainers: [] }),
    systemdProbe: async () => ({ supported: false, installed: false, enabled: false, active: false, linger: false }),
    serviceController: async () => {},
  });
  t.after(() => webui.close());

  const localhostOrigin = `http://localhost:${webui.port}`;
  const home = await httpCall(localhostOrigin, '/', { headers: { host: `localhost:${webui.port}` } });
  let csrf = home.text.match(/<meta name="agentdock-csrf" content="([^"]+)"/)?.[1];
  let cookie = mergeCookieHeader('', home.headers['set-cookie']);

  const ticket = issueSetupTicketSync(stateDir, {
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: true, reason: 'linux-fido2-hid' }),
  });

  // Attempting password setup via HTTP must fail 403 when host supports PassKey.
  const pwSetup = await httpCall(localhostOrigin, '/api/auth/setup/password', {
    method: 'POST',
    headers: {
      host: `localhost:${webui.port}`,
      origin: localhostOrigin,
      cookie,
      'x-agentdock-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ setupToken: ticket.setupToken, password: 'Kx9!mP4#vR2@qL8$zW' }),
  });
  assert.equal(pwSetup.status, 403);

  // Enroll simulated W3C WebAuthn ES256 PassKey.
  const regOptRes = await httpCall(localhostOrigin, '/api/auth/setup/passkey/options', {
    method: 'POST',
    headers: {
      host: `localhost:${webui.port}`,
      origin: localhostOrigin,
      cookie,
      'x-agentdock-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ setupToken: ticket.setupToken }),
  });
  assert.equal(regOptRes.status, 200);
  const regOpt = regOptRes.json();

  const authenticator = createVirtualEs256Passkey({ origin: localhostOrigin, rpId: 'localhost' });
  const regCredential = authenticator.register(regOpt.publicKey.challenge);

  const regVerify = await httpCall(localhostOrigin, '/api/auth/setup/passkey/verify', {
    method: 'POST',
    headers: {
      host: `localhost:${webui.port}`,
      origin: localhostOrigin,
      cookie,
      'x-agentdock-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      challengeId: regOpt.challengeId,
      setupToken: ticket.setupToken,
      label: 'Simulated Key',
      credential: regCredential,
    }),
  });
  assert.equal(regVerify.status, 200);
  const regJson = regVerify.json();
  csrf = regJson.csrfToken;
  const regTabToken = regJson.tabToken;
  assert.ok(regTabToken);
  cookie = mergeCookieHeader(cookie, regVerify.headers['set-cookie']);

  // Verify authenticated capability toggle works only with matching per-tab token, then log out and verify PassKey login + replay guards.
  assert.equal((await httpCall(localhostOrigin, '/api/status', {
    headers: { host: `localhost:${webui.port}`, cookie },
  })).status, 401);
  assert.equal((await httpCall(localhostOrigin, '/api/status', {
    headers: { host: `localhost:${webui.port}`, cookie, 'x-agentdock-tab-auth': regTabToken },
  })).status, 200);

  const logoutPasskey = await httpCall(localhostOrigin, '/api/auth/logout', {
    method: 'POST',
    headers: {
      host: `localhost:${webui.port}`,
      origin: localhostOrigin,
      cookie,
      'x-agentdock-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: '{}',
  });
  assert.equal(logoutPasskey.status, 200);
  csrf = logoutPasskey.json().csrfToken;
  cookie = mergeCookieHeader(cookie, logoutPasskey.headers['set-cookie']);

  // Password login must remain 403 blocked.
  const pwLogin = await httpCall(localhostOrigin, '/api/auth/login/password', {
    method: 'POST',
    headers: {
      host: `localhost:${webui.port}`,
      origin: localhostOrigin,
      cookie,
      'x-agentdock-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ password: 'Kx9!mP4#vR2@qL8$zW' }),
  });
  assert.equal(pwLogin.status, 403);

  const getLoginChallenge = async () => (await httpCall(localhostOrigin, '/api/auth/passkey/login/options', {
    method: 'POST',
    headers: {
      host: `localhost:${webui.port}`,
      origin: localhostOrigin,
      cookie,
      'x-agentdock-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: '{}',
  })).json();

  // Reject tampered signature, wrong RP ID, and replayed signCount.
  const chBadSig = await getLoginChallenge();
  assert.equal((await httpCall(localhostOrigin, '/api/auth/passkey/login/verify', {
    method: 'POST',
    headers: {
      host: `localhost:${webui.port}`,
      origin: localhostOrigin,
      cookie,
      'x-agentdock-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      challengeId: chBadSig.challengeId,
      credential: authenticator.assert(chBadSig.publicKey.challenge, { tamperSig: true }),
    }),
  })).status, 401);

  const chValid = await getLoginChallenge();
  const validLogin = await httpCall(localhostOrigin, '/api/auth/passkey/login/verify', {
    method: 'POST',
    headers: {
      host: `localhost:${webui.port}`,
      origin: localhostOrigin,
      cookie,
      'x-agentdock-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      challengeId: chValid.challengeId,
      credential: authenticator.assert(chValid.publicKey.challenge),
    }),
  });
  assert.equal(validLogin.status, 200);
  const validJson = validLogin.json();
  csrf = validJson.csrfToken;
  cookie = mergeCookieHeader(cookie, validLogin.headers['set-cookie']);
  assert.equal(validJson.authState.authMethod, 'passkey');

  const chReplay = await getLoginChallenge();
  assert.equal((await httpCall(localhostOrigin, '/api/auth/passkey/login/verify', {
    method: 'POST',
    headers: {
      host: `localhost:${webui.port}`,
      origin: localhostOrigin,
      cookie,
      'x-agentdock-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      challengeId: chReplay.challengeId,
      credential: authenticator.assert(chReplay.publicKey.challenge, { overrideSignCount: 1 }),
    }),
  })).status, 401);
});

test('renderSystemdUnits builds hardened user service templates with loopback guard', () => {
  assert.throws(() => renderSystemdUnits({ stateDir: '/home/user/.agentdock-bridge', host: '0.0.0.0' }), /loopback/);
  const { bridgeUnit, webuiUnit } = renderSystemdUnits({
    stateDir: '/home/user/.agentdock-bridge',
    host: '127.0.0.1',
    port: 18797,
  });
  assert.match(bridgeUnit, /WantedBy=default\.target/);
  assert.match(bridgeUnit, /StartLimitIntervalSec=0/);
  assert.match(bridgeUnit, /run-service/);
  assert.match(webuiUnit, /--host/);
  assert.match(webuiUnit, /127\.0\.0\.1/);
  assert.match(webuiUnit, /18797/);

  assert.throws(() => renderSystemdUnits({ stateDir: '/home/user/\nExecStartPre=/bin/id\n.state' }), /newline/i);
  const { bridgeUnit: escapedBridge } = renderSystemdUnits({
    stateDir: '/home/user/100%safe${HOME}',
    host: '127.0.0.1',
    port: 18797,
  });
  assert.match(escapedBridge, /100%%safe\$\$\{HOME\}/);
});

test('Docker sandbox dynamically hides disabled tools and mounts /workspace readonly when write is off', {
  timeout: 120000,
  skip: process.env.AGENTDOCK_DOCKER_TEST !== '1',
}, async t => {
  const sandbox = await resolveTestSandbox();
  // macOS may return /var/folders through the /var symlink.
  const tempRoot = await fs.realpath(os.tmpdir());
  const base = await fs.mkdtemp(path.join(tempRoot, 'agentdock-cap-docker-'));
  const workspace = path.join(base, 'workspace');
  const state = path.join(base, 'state');
  await fs.mkdir(workspace, { mode: 0o755 });
  await fs.mkdir(state, { mode: 0o700 });
  await fs.writeFile(path.join(workspace, 'ro-target.txt'), 'original-ro-content');

  const gateway = await createSandboxRuntime({
    roots: [workspace],
    stateDir: state,
    auditFile: path.join(state, 'audit.jsonl'),
    allowExec: true,
    sandbox: { ...sandbox, enabled: true, allowOutbound: false },
  });
  t.after(async () => {
    await gateway.close();
    await fs.rm(base, { recursive: true, force: true });
  });

  writeCapabilitiesSync(state, { fileRead: true, fileWrite: false }, { configAllowExec: true, requirePrivateState: false });
  const listedRo = await gateway.handleRpc({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
  const roTools = listedRo.result.tools.map(item => item.name);
  assert.ok(roTools.includes('read_file'));
  assert.ok(roTools.includes('exec_command'));
  assert.equal(roTools.includes('write_file'), false);

  const deniedWrite = await gateway.handleRpc({
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/call',
    params: { name: 'write_file', arguments: { path: '/workspace/new.txt', content: 'x' } },
  });
  assert.equal(deniedWrite.result.isError, true);

  const roExec = await gateway.handleRpc({
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: { name: 'exec_command', arguments: { cmd: 'cat /workspace/ro-target.txt && touch /workspace/should-fail.txt' } },
  });
  assert.notEqual(roExec.result.structuredContent.exit_code, 0);
  assert.match(roExec.result.structuredContent.stdout, /original-ro-content/);
  assert.equal(await fs.access(path.join(workspace, 'should-fail.txt')).then(() => true, () => false), false);

  const audit = await fs.readFile(path.join(state, 'audit.jsonl'), 'utf8');
  assert.ok(audit.trim().split('\n').map(line => JSON.parse(line)).some(entry => entry.tool === 'exec_command' && entry.stdoutBytes > 0));
  assert.doesNotMatch(audit, /ro-target|should-fail|original-ro-content|"args"|"result"/);
  writeCapabilitiesSync(state, { tools: { exec_command: false } }, { configAllowExec: true, requirePrivateState: false });
  const context = await gateway.handleRpc({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'computer_context' } });
  assert.equal(context.result.structuredContent.command_execution, false);
  assert.equal(context.result.structuredContent.capabilities.command_execution, false);
  writeCapabilitiesSync(state, { fileRead: false, fileWrite: false }, { configAllowExec: true, requirePrivateState: false });
  const listedLocked = await gateway.handleRpc({ jsonrpc: '2.0', id: 4, method: 'tools/list' });
  const lockedTools = listedLocked.result.tools.map(item => item.name);
  assert.deepEqual(lockedTools.sort(), ['command_status', 'computer_context', 'stop_command']);
});

test('WebUI serves docs-inspired inspector assets and shows execution metadata and omits payloads from older audit logs', async t => {
  const stateDir = await makeTempState(t);
  const workspace = await fs.mkdtemp(path.join(os.homedir(), '.ad-inspector-ws-'));
  t.after(() => fs.rm(workspace, { recursive: true, force: true }));

  await fs.writeFile(path.join(stateDir, 'config.json'), JSON.stringify({
    origin: 'http://127.0.0.1:8797',
    roots: [workspace],
    defaultCwd: workspace,
    allowExec: true,
    requireLocalApproval: true,
    sandbox: { enabled: true, allowOutbound: false, image: `sha256:${'a'.repeat(64)}`, context: 'default' },
  }), { mode: 0o600 });

  await fs.writeFile(path.join(stateDir, 'audit.jsonl'), [
    JSON.stringify({
      time: '2026-11-21T02:00:01.000Z',
      tool: 'read_file',
      success: true,
      reason: 'ok',
      durationMs: 18,
      mountMode: 'readwrite',
      args: { path: '/workspace/app.mjs', offset: 0, max_bytes: 65536 },
      result: { path: '/workspace/app.mjs', bytesRead: 12, content: 'export const x = 1;', sha256: 'deadbeef' },
    }),
    JSON.stringify({
      time: '2026-11-21T02:00:05.000Z',
      tool: 'exec_command',
      success: false,
      reason: 'tool_error',
      durationMs: 245,
      mountMode: 'readonly',
      mode: 'sync',
      network: 'none',
      exitCode: 2,
      timedOut: false,
      cancelled: false,
      args: { cmd: 'cat /workspace/app.mjs && false', cwd: '/workspace', mode: 'sync' },
      result: { exitCode: 2, stderr: 'Permission denied or non-zero exit', stdout: 'export const x = 1;' },
    }),
  ].join('\n') + '\n', { mode: 0o600 });

  await fs.writeFile(path.join(stateDir, 'connector.log'), [
    JSON.stringify({ time: '2026-11-21T02:00:03.000Z', event: 'capability_blocked', tool: 'write_file', capability: 'fileWrite', target: '/workspace/app.mjs' }),
    JSON.stringify({ time: '2026-11-21T02:00:04.000Z', event: 'approval_required', tool: 'exec_command', approvalIdShort: 'abc12345', target: 'npm test' }),
  ].join('\n') + '\n', { mode: 0o600 });

  setStrongPasswordSync(stateDir, {
    password: 'Inspect!Strong#2026Aa',
    allowBypassTicket: true,
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
  });

  const webui = await startWebUiServer({
    stateDir,
    runtimeRoot: path.resolve(import.meta.dirname, '..'),
    host: '127.0.0.1',
    port: 0,
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
    gatewayProbe: async () => ({ reachable: false, status: null, latencyMs: null }),
    dockerProbe: async () => ({ dockerOk: true, runningContainers: [] }),
    systemdProbe: async () => ({ supported: false, installed: false, enabled: false, active: false, linger: false }),
    serviceController: async () => {},
  });
  t.after(() => webui.close());

  const home = await httpCall(webui.url, '/');
  assert.equal(home.status, 200);
  assert.ok(home.headers['content-security-policy']?.includes("style-src 'self'"));
  assert.match(home.text, /id="tool-search"/);
  assert.match(home.text, /id="btn-theme"/);
  assert.match(home.text, /id="btn-tools-expand"/);
  assert.match(home.text, /id="kpi-tools-ratio"/);
  assert.match(home.text, /id="toggle-tab-auth"/);
  assert.match(home.text, /id="tab-btn-overview"/);
  assert.match(home.text, /id="tab-btn-audit"/);
  assert.match(home.text, /id="tab-btn-tools"/);
  assert.match(home.text, /id="view-overview"/);
  assert.match(home.text, /id="view-audit"/);
  assert.match(home.text, /id="view-tools"/);
  assert.match(home.text, /id="tool-detail-pane"/);

  const cssRes = await httpCall(webui.url, '/styles.css');
  assert.equal(cssRes.status, 200);
  assert.match(cssRes.text, /:root\.dark/);
  assert.match(cssRes.text, /\[hidden\]\s*\{\s*display:\s*none\s*!important;/);

  const jsRes = await httpCall(webui.url, '/app.js');
  assert.equal(jsRes.status, 200);
  assert.doesNotThrow(() => new Function(jsRes.text));

  let csrf = home.text.match(/<meta name="agentdock-csrf" content="([^"]+)"/)?.[1];
  let cookie = mergeCookieHeader('', home.headers['set-cookie']);

  const loginRes = await httpCall(webui.url, '/api/auth/login/password', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ password: 'Inspect!Strong#2026Aa' }),
  });
  assert.equal(loginRes.status, 200);
  const loginJson = loginRes.json();
  const tabToken = loginJson.tabToken;
  assert.ok(tabToken);
  cookie = mergeCookieHeader(cookie, loginRes.headers['set-cookie']);

  const statusRes = await httpCall(webui.url, '/api/status', { headers: { cookie, 'x-agentdock-tab-auth': tabToken } });
  assert.equal(statusRes.status, 200);
  const snap = statusRes.json();

  assert.equal(snap.security.sessionPersistence, 'tab');
  assert.equal(statusRes.text.includes('passwordHash') || JSON.stringify(snap).includes('passwordHash'), false);

  assert.equal(snap.capabilities.effectiveTools.length, TOOL_DEFINITIONS.length);
  const readTool = snap.capabilities.effectiveTools.find(t => t.name === 'read_file');
  assert.equal(readTool.kind, 'READ');
  assert.equal(readTool.requiresApproval, true);
  assert.deepEqual(readTool.scopes, ['computer:read']);
  assert.equal(readTool.stats.totalCalls, 1);
  assert.equal(readTool.stats.successCount, 1);
  assert.equal(readTool.stats.lastDurationMs, 18);
  assert.equal(readTool.parameters.find(p => p.name === 'max_bytes')?.maximum, 262144);

  const readEvent = snap.events.find(e => e.source === 'audit' && e.name === 'read_file');
  assert.equal(readEvent.meta.durationMs, 18);
  assert.equal(readEvent.meta.bytesRead, 12);
  assert.doesNotMatch(statusRes.text, /export const x|app\.mjs|Permission denied or non-zero exit/);

  const execTool = snap.capabilities.effectiveTools.find(t => t.name === 'exec_command');
  assert.equal(execTool.kind, 'EXEC');
  assert.equal(execTool.stats.totalCalls, 1);
  assert.equal(execTool.stats.failureCount, 1);
  assert.deepEqual(execTool.parameters.find(p => p.name === 'network')?.enumValues, ['none']);

  const writeTool = snap.capabilities.effectiveTools.find(t => t.name === 'write_file');
  assert.equal(writeTool.stats.blockedCount, 1);

  assert.equal(snap.telemetry.totalAuditCalls, 2);
  assert.equal(snap.telemetry.totalAuditSuccess, 1);
  assert.equal(snap.telemetry.totalAuditFailed, 1);
  assert.equal(snap.telemetry.totalBlocked, 1);

  const execEvent = snap.events.find(e => e.source === 'audit' && e.name === 'exec_command');
  assert.equal(execEvent.meta.exitCode, 2);
  assert.equal(execEvent.meta.mountMode, 'readonly');
  assert.equal(execEvent.meta.durationMs, 245);
  assert.equal(execEvent.auditArgs, undefined);
  assert.equal(execEvent.auditResult, undefined);

  const approvalEvent = snap.events.find(e => e.source === 'connector' && e.name === 'approval_required');
  assert.equal(approvalEvent.meta.approvalIdShort, 'abc12345');
  assert.equal(approvalEvent.meta.target, undefined);
});

test('per-tool capability overrides fail closed on invalid entries and toggle individually via WebUI', async t => {
  const stateDir = await makeTempState(t);
  const workspace = await fs.mkdtemp(path.join(os.homedir(), '.ad-pertool-ws-'));
  t.after(() => fs.rm(workspace, { recursive: true, force: true }));

  await fs.writeFile(path.join(stateDir, 'config.json'), JSON.stringify({
    origin: 'http://127.0.0.1:8797',
    roots: [workspace],
    defaultCwd: workspace,
    allowExec: true,
    requireLocalApproval: true,
    sandbox: { enabled: true, allowOutbound: false, image: `sha256:${'a'.repeat(64)}`, context: 'default' },
  }), { mode: 0o600 });

  assert.throws(
    () => writeCapabilitiesSync(stateDir, { tools: { unknown_tool: false } }, { configAllowExec: true }),
    /Unknown MCP tool/,
  );
  assert.throws(
    () => writeCapabilitiesSync(stateDir, { tools: { delete_file: 'false' } }, { configAllowExec: true }),
    /boolean/,
  );

  const singleOff = writeCapabilitiesSync(stateDir, { tools: { delete_file: false } }, { configAllowExec: true });
  assert.equal(singleOff.tools.delete_file, false);
  assert.equal(isToolEnabled('delete_file', singleOff, { configAllowExec: true }).enabled, false);
  assert.equal(isToolEnabled('write_file', singleOff, { configAllowExec: true }).enabled, true);
  assert.equal(filterToolsByCapabilities(TOOL_DEFINITIONS, singleOff, { configAllowExec: true }).some(t => t.name === 'delete_file'), false);

  await fs.writeFile(capabilityFilePath(stateDir), JSON.stringify({
    fileRead: true,
    fileWrite: true,
    allowExec: true,
    tools: { delete_file: 'tampered' },
  }), { mode: 0o600 });
  const tampered = readCapabilitiesSync(stateDir, { configAllowExec: true });
  assert.ok(tampered.error);
  assert.equal(tampered.fileRead, false);
  assert.equal(tampered.fileWrite, false);
  assert.equal(tampered.allowExec, false);

  // Restore clean default and exercise via WebUI
  writeCapabilitiesSync(stateDir, { fileRead: true, fileWrite: true, allowExec: true, tools: { delete_file: true } }, { configAllowExec: true });
  setStrongPasswordSync(stateDir, {
    password: 'PerTool!Strong#2026Aa',
    allowBypassTicket: true,
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
  });

  const webui = await startWebUiServer({
    stateDir,
    runtimeRoot: path.resolve(import.meta.dirname, '..'),
    host: '127.0.0.1',
    port: 0,
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
    gatewayProbe: async () => ({ reachable: false, status: null, latencyMs: null }),
    dockerProbe: async () => ({ dockerOk: true, runningContainers: [] }),
    systemdProbe: async () => ({ supported: false, installed: false, enabled: false, active: false, linger: false }),
    serviceController: async () => {},
  });
  t.after(() => webui.close());

  const home = await httpCall(webui.url, '/');
  let csrf = home.text.match(/<meta name="agentdock-csrf" content="([^"]+)"/)?.[1];
  let cookie = mergeCookieHeader('', home.headers['set-cookie']);

  const loginRes = await httpCall(webui.url, '/api/auth/login/password', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ password: 'PerTool!Strong#2026Aa' }),
  });
  assert.equal(loginRes.status, 200);
  const loginJson = loginRes.json();
  csrf = loginJson.csrfToken;
  const tabToken = loginJson.tabToken;
  cookie = mergeCookieHeader(cookie, loginRes.headers['set-cookie']);

  const badCap = await httpCall(webui.url, '/api/capabilities', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'x-agentdock-tab-auth': tabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ tools: { non_existent: false } }),
  });
  assert.equal(badCap.status, 400);

  const disableOne = await httpCall(webui.url, '/api/capabilities', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'x-agentdock-tab-auth': tabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ tools: { delete_file: false } }),
  });
  assert.equal(disableOne.status, 200);
  const delTool = disableOne.json().snapshot.capabilities.effectiveTools.find(item => item.name === 'delete_file');
  const writeTool = disableOne.json().snapshot.capabilities.effectiveTools.find(item => item.name === 'write_file');
  assert.equal(delTool.individuallyDisabled, true);
  assert.equal(delTool.enabled, false);
  assert.equal(writeTool.enabled, true);

  const reenableOne = await httpCall(webui.url, '/api/capabilities', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'x-agentdock-tab-auth': tabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ tools: { delete_file: true } }),
  });
  assert.equal(reenableOne.status, 200);
  assert.equal(reenableOne.json().snapshot.capabilities.effectiveTools.find(item => item.name === 'delete_file').enabled, true);
});

test('PassKey management supports multiple keys, blocks deleting final key, and honors hardware downgrade guard', async t => {
  const stateDir = await makeTempState(t);
  const workspace = await fs.mkdtemp(path.join(os.homedir(), '.ad-pkmgmt-ws-'));
  t.after(() => fs.rm(workspace, { recursive: true, force: true }));

  await fs.writeFile(path.join(stateDir, 'config.json'), JSON.stringify({
    origin: 'http://127.0.0.1:8797',
    roots: [workspace],
    defaultCwd: workspace,
    allowExec: false,
    requireLocalApproval: true,
    sandbox: { enabled: true, allowOutbound: false, image: `sha256:${'a'.repeat(64)}`, context: 'default' },
  }), { mode: 0o600 });

  const ticket = issueSetupTicketSync(stateDir, {
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
  });

  const webui = await startWebUiServer({
    stateDir,
    runtimeRoot: path.resolve(import.meta.dirname, '..'),
    host: '127.0.0.1',
    port: 0,
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
    gatewayProbe: async () => ({ reachable: false, status: null, latencyMs: null }),
    dockerProbe: async () => ({ dockerOk: true, runningContainers: [] }),
    systemdProbe: async () => ({ supported: false, installed: false, enabled: false, active: false, linger: false }),
    serviceController: async () => {},
  });
  t.after(() => webui.close());

  const localhostOrigin = `http://localhost:${webui.port}`;
  const home = await httpCall(localhostOrigin, '/', { headers: { host: `localhost:${webui.port}` } });
  let csrf = home.text.match(/<meta name="agentdock-csrf" content="([^"]+)"/)?.[1];
  let cookie = mergeCookieHeader('', home.headers['set-cookie']);

  const enrollKey = async (auth, { setupToken, label, tabToken }) => {
    const optRes = await httpCall(localhostOrigin, '/api/auth/setup/passkey/options', {
      method: 'POST',
      headers: {
        host: `localhost:${webui.port}`,
        origin: localhostOrigin,
        cookie,
        'x-agentdock-csrf': csrf,
        ...(tabToken ? { 'x-agentdock-tab-auth': tabToken } : {}),
        'sec-fetch-site': 'same-origin',
        'content-type': 'application/json',
      },
      body: JSON.stringify(setupToken ? { setupToken } : {}),
    });
    assert.equal(optRes.status, 200);
    const opt = optRes.json();
    const verRes = await httpCall(localhostOrigin, '/api/auth/setup/passkey/verify', {
      method: 'POST',
      headers: {
        host: `localhost:${webui.port}`,
        origin: localhostOrigin,
        cookie,
        'x-agentdock-csrf': csrf,
        ...(tabToken ? { 'x-agentdock-tab-auth': tabToken } : {}),
        'sec-fetch-site': 'same-origin',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        challengeId: opt.challengeId,
        ...(setupToken ? { setupToken } : {}),
        label,
        credential: auth.register(opt.publicKey.challenge),
      }),
    });
    assert.equal(verRes.status, 200);
    const json = verRes.json();
    csrf = json.csrfToken;
    cookie = mergeCookieHeader(cookie, verRes.headers['set-cookie']);
    return json.tabToken;
  };

  const key1 = createVirtualEs256Passkey({ origin: localhostOrigin, rpId: 'localhost' });
  const key2 = createVirtualEs256Passkey({ origin: localhostOrigin, rpId: 'localhost' });

  let tabToken = await enrollKey(key1, { setupToken: ticket.setupToken, label: 'Primary Key' });
  // Enroll a second PassKey via active authenticated session (no setup ticket required)
  tabToken = await enrollKey(key2, { label: 'Backup YubiKey', tabToken });

  const statusTwo = await httpCall(localhostOrigin, '/api/status', {
    headers: { host: `localhost:${webui.port}`, cookie, 'x-agentdock-tab-auth': tabToken },
  });
  assert.equal(statusTwo.status, 200);
  const twoSec = statusTwo.json().security;
  assert.equal(twoSec.passkeyCount, 2);
  assert.deepEqual(twoSec.passkeys.map(p => p.label), ['Primary Key', 'Backup YubiKey']);
  assert.equal(JSON.stringify(twoSec).includes('publicKeyPem'), false);

  // Delete Primary Key
  const del1 = await httpCall(localhostOrigin, '/api/auth/passkey/delete', {
    method: 'POST',
    headers: {
      host: `localhost:${webui.port}`,
      origin: localhostOrigin,
      cookie,
      'x-agentdock-csrf': csrf,
      'x-agentdock-tab-auth': tabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ credentialId: key1.credentialId }),
  });
  assert.equal(del1.status, 200);
  assert.equal(del1.json().authState.passkeyCount, 1);
  assert.equal(del1.json().authState.passkeys[0].label, 'Backup YubiKey');

  // Cannot delete the final remaining PassKey
  const delLast = await httpCall(localhostOrigin, '/api/auth/passkey/delete', {
    method: 'POST',
    headers: {
      host: `localhost:${webui.port}`,
      origin: localhostOrigin,
      cookie,
      'x-agentdock-csrf': csrf,
      'x-agentdock-tab-auth': tabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ credentialId: key2.credentialId }),
  });
  assert.equal(delLast.status, 400);

  // Unit check: hardware-mandated host rejects switchToStrongPasswordSync
  assert.throws(
    () => switchToStrongPasswordSync(stateDir, {
      password: 'Switch!Strong#2026Cc',
      workspaceRoots: [workspace],
      requirePrivateState: false,
      passkeyDetector: () => ({ supported: true, reason: 'fido-hid' }),
    }),
    /enforces PassKey/,
  );

  // Also test deletePasskeySync final-key protection directly
  assert.throws(
    () => deletePasskeySync(stateDir, {
      credentialId: key2.credentialId,
      workspaceRoots: [workspace],
      requirePrivateState: false,
      passkeyDetector: () => ({ supported: false, reason: 'none' }),
    }),
    /final PassKey/,
  );

  // On non-hardware-mandated host, authenticated PassKey session may switch to strong password
  const switched = await httpCall(localhostOrigin, '/api/auth/passkey/switch-password', {
    method: 'POST',
    headers: {
      host: `localhost:${webui.port}`,
      origin: localhostOrigin,
      cookie,
      'x-agentdock-csrf': csrf,
      'x-agentdock-tab-auth': tabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ password: 'Switch!Strong#2026Cc' }),
  });
  assert.equal(switched.status, 200);
  const swJson = switched.json();
  assert.equal(swJson.authState.mode, 'password');
  assert.equal(swJson.authState.passkeyCount, 0);
});

test('WebUI supports password reset with currentPassword check, autostart toggle actions, and real-time pending approval/rejection', async t => {
  const stateDir = await makeTempState(t);
  const workspace = await fs.mkdtemp(path.join(os.homedir(), '.ad-ops-ws-'));
  t.after(() => fs.rm(workspace, { recursive: true, force: true }));

  await fs.writeFile(path.join(stateDir, 'config.json'), JSON.stringify({
    origin: 'http://127.0.0.1:8797',
    roots: [workspace],
    defaultCwd: workspace,
    allowExec: true,
    requireLocalApproval: true,
    sandbox: { enabled: true, allowOutbound: false, image: `sha256:${'a'.repeat(64)}`, context: 'default' },
  }), { mode: 0o600 });

  const approvalsDir = path.join(stateDir, 'approvals');
  await fs.mkdir(approvalsDir, { mode: 0o700 });
  const now = Date.now();
  const makePendingRecord = (id, cmd) => {
    const request = {
      method: 'tools/call',
      params: { name: 'exec_command', arguments: { cmd, cwd: '/workspace', mode: 'sync' } },
      authorization: { clientId: 'client-webui-test' },
    };
    return {
      id,
      version: 1,
      createdAt: now - 1000,
      expiresAt: now + 299000,
      hash: policyDigest(request),
      request,
    };
  };
  const reqApproveId = '11111111-1111-4111-8111-111111111111';
  const reqRejectId = '22222222-2222-4222-8222-222222222222';
  const recApprove = makePendingRecord(reqApproveId, 'x'.repeat(5000) + '\u202eREVIEW_TAIL');
  const recReject = makePendingRecord(reqRejectId, 'rm -rf /workspace/tmp');
  await fs.writeFile(path.join(approvalsDir, `${reqApproveId}.request.json`), JSON.stringify(recApprove), { mode: 0o600 });
  await fs.writeFile(path.join(approvalsDir, `${reqRejectId}.request.json`), JSON.stringify(recReject), { mode: 0o600 });

  setStrongPasswordSync(stateDir, {
    password: 'InitPw!Strong#2026Aa',
    allowBypassTicket: true,
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
  });

  let systemdEnabled = false;
  const serviceActions = [];
  const webui = await startWebUiServer({
    stateDir,
    runtimeRoot: path.resolve(import.meta.dirname, '..'),
    host: '127.0.0.1',
    port: 0,
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
    gatewayProbe: async () => ({ reachable: true, status: 200, latencyMs: 3 }),
    dockerProbe: async () => ({ dockerOk: true, runningContainers: [] }),
    systemdProbe: async () => ({
      supported: true,
      installed: true,
      enabled: systemdEnabled,
      active: true,
      bridgeEnabled: systemdEnabled,
      bridgeActive: true,
      webuiEnabled: systemdEnabled,
      linger: true,
    }),
    serviceController: async action => {
      serviceActions.push(action);
      if (action === 'enable-autostart') systemdEnabled = true;
      if (action === 'disable-autostart') systemdEnabled = false;
    },
  });
  t.after(() => webui.close());

  const home = await httpCall(webui.url, '/');
  let csrf = home.text.match(/<meta name="agentdock-csrf" content="([^"]+)"/)?.[1];
  let cookie = mergeCookieHeader('', home.headers['set-cookie']);

  const login1 = await httpCall(webui.url, '/api/auth/login/password', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ password: 'InitPw!Strong#2026Aa' }),
  });
  assert.equal(login1.status, 200);
  csrf = login1.json().csrfToken;
  let tabToken = login1.json().tabToken;
  cookie = mergeCookieHeader(cookie, login1.headers['set-cookie']);

  // Reset password requires accurate currentPassword when already password-authenticated
  const badReset = await httpCall(webui.url, '/api/auth/setup/password', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'x-agentdock-tab-auth': tabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ currentPassword: 'Wrong!Password#2026Zz', password: 'NextPw!Strong#2026Bb' }),
  });
  assert.equal(badReset.status, 401);

  const okReset = await httpCall(webui.url, '/api/auth/setup/password', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'x-agentdock-tab-auth': tabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ currentPassword: 'InitPw!Strong#2026Aa', password: 'NextPw!Strong#2026Bb' }),
  });
  assert.equal(okReset.status, 200);
  const oldTabToken = tabToken;
  csrf = okReset.json().csrfToken;
  tabToken = okReset.json().tabToken;
  assert.notEqual(tabToken, oldTabToken);
  assert.equal((await httpCall(webui.url, '/api/status', { headers: { cookie, 'x-agentdock-tab-auth': oldTabToken } })).status, 401);
  cookie = mergeCookieHeader(cookie, okReset.headers['set-cookie']);

  // Autostart toggle via /api/service
  const autoOn = await httpCall(webui.url, '/api/service', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'x-agentdock-tab-auth': tabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ action: 'enable-autostart' }),
  });
  assert.equal(autoOn.status, 200);
  assert.equal(autoOn.json().snapshot.systemd.enabled, true);

  const autoOff = await httpCall(webui.url, '/api/service', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'x-agentdock-tab-auth': tabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ action: 'disable-autostart' }),
  });
  assert.equal(autoOff.status, 200);
  assert.equal(autoOff.json().snapshot.systemd.enabled, false);
  assert.deepEqual(serviceActions, ['enable-autostart', 'disable-autostart']);

  // The status stream carries queue metadata. Only an authenticated review returns the exact subject.
  const snapBefore = (await httpCall(webui.url, '/api/status', { headers: { cookie, 'x-agentdock-tab-auth': tabToken } })).json();
  assert.equal(snapBefore.approvals.pendingCount, 2);
  const itemA = snapBefore.approvals.items.find(i => i.id === reqApproveId);
  assert.equal(itemA.arguments, undefined);
  assert.equal(itemA.digest, undefined);
  assert.doesNotMatch(JSON.stringify(snapBefore), /REVIEW_TAIL/);
  const reviewOptions = {
    method: 'POST',
    headers: { origin: webui.url, cookie, 'x-agentdock-csrf': csrf, 'x-agentdock-tab-auth': tabToken, 'content-type': 'application/json' },
    body: JSON.stringify({ id: itemA.id }),
  };
  const unauthed = await httpCall(webui.url, '/api/approvals/review', { ...reviewOptions, headers: {} });
  assert.equal(unauthed.status, 401);
  const review = await httpCall(webui.url, '/api/approvals/review', reviewOptions);
  assert.equal(review.status, 200);
  const reviewed = review.json();
  assert.deepEqual(JSON.parse(reviewed.requestText), recApprove.request);
  assert.ok(reviewed.requestText.includes('\\u202eREVIEW_TAIL'));
  assert.equal(reviewed.digest, policyDigest(recApprove));
  assert.equal(itemA.approvable, true);

  // Replace the request with a different, internally consistent record after review.
  recApprove.request.params.arguments.cmd = 'echo updated-after-review';
  recApprove.hash = policyDigest(recApprove.request);
  await fs.writeFile(path.join(approvalsDir, reqApproveId + '.request.json'), JSON.stringify(recApprove));
  const wrongDigest = await httpCall(webui.url, '/api/approvals/approve', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'x-agentdock-tab-auth': tabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ id: reqApproveId, digest: reviewed.digest }),
  });
  assert.equal(wrongDigest.status, 409);
  await assert.rejects(fs.access(path.join(approvalsDir, reqApproveId + '.approved.json')), { code: 'ENOENT' });
  const freshReview = await httpCall(webui.url, '/api/approvals/review', reviewOptions);
  assert.equal(freshReview.status, 200);
  assert.notEqual(freshReview.json().digest, reviewed.digest);

  const approveOk = await httpCall(webui.url, '/api/approvals/approve', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'x-agentdock-tab-auth': tabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ id: itemA.id, digest: freshReview.json().digest }),
  });
  assert.equal(approveOk.status, 200);
  const approvedMarker = JSON.parse(await fs.readFile(path.join(approvalsDir, `${reqApproveId}.approved.json`), 'utf8'));
  assert.equal(approvedMarker.hash, recApprove.hash);
  assert.equal(approvedMarker.expiresAt, recApprove.expiresAt);
  assert.equal(approveOk.json().snapshot.approvals.items.find(i => i.id === reqApproveId).alreadyApproved, true);

  // Verify reset password invalidated old credentials and accepts the new password
  const oldPwTry = await httpCall(webui.url, '/api/auth/login/password', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ password: 'InitPw!Strong#2026Aa' }),
  });
  assert.equal(oldPwTry.status, 401);

  const newPwTry = await httpCall(webui.url, '/api/auth/login/password', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ password: 'NextPw!Strong#2026Bb' }),
  });
  assert.equal(newPwTry.status, 200);

  // A refusal can also revoke a marker awaiting consumption.
  await fs.writeFile(path.join(approvalsDir, reqRejectId + '.approved.json'), JSON.stringify({ hash: recReject.hash, expiresAt: recReject.expiresAt }), { mode: 0o600 });
  const rejectOk = await httpCall(webui.url, '/api/approvals/reject', {
    method: 'POST',
    headers: {
      origin: webui.url,
      cookie,
      'x-agentdock-csrf': csrf,
      'x-agentdock-tab-auth': tabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ id: reqRejectId }),
  });
  assert.equal(rejectOk.status, 200);
  await assert.rejects(fs.access(path.join(approvalsDir, reqRejectId + '.approved.json')), { code: 'ENOENT' });
  assert.equal(rejectOk.json().snapshot.approvals.pendingCount, 1);
  assert.equal(await fs.access(path.join(approvalsDir, `${reqRejectId}.request.json`)).then(() => true, () => false), false);
});

test('WebUI auth & API review fixes: H1 switch-password guard, M1 WebAuthn ED/crossOrigin, M2 CSRF/ticket lockout, M5 hardware latch, M6 corrupt reject & bidi clientId, L1/L3/L4', async t => {
  const stateDir = await makeTempState(t);
  const workspace = await fs.mkdtemp(path.join(os.homedir(), '.ad-review-ws-'));
  t.after(() => fs.rm(workspace, { recursive: true, force: true }));

  // L3: prototype property name on isToolEnabled safely resolves to unknown
  const defaultCaps = readCapabilitiesSync(stateDir, { workspaceRoots: [workspace] });
  assert.equal(isToolEnabled('toString', defaultCaps).enabled, false);
  assert.equal(isToolEnabled('toString', defaultCaps).capability, 'unknown');

  // L1: ancestor symlink is caught by assertConfigOutsideWorkspace
  const realOuter = path.join(stateDir, 'real-outer');
  const symOuter = path.join(stateDir, 'sym-outer');
  await fs.mkdir(realOuter, { mode: 0o700 });
  await fs.symlink(realOuter, symOuter);
  assert.throws(() => assertConfigOutsideWorkspace(path.join(symOuter, 'sub', 'cap.json'), [workspace]), /symbolic links/);

  // M1: WebAuthn registration accepts trailing ED (0x80) extension CBOR map and rejects crossOrigin: true
  const { verifyRegistrationResponse } = await import('../local/webauthn.mjs');
  const { publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const credId = crypto.randomBytes(32);
  const coseBytes = encodeCbor(new Map([
    [1, 2], [3, -7], [-1, 1],
    [-2, Buffer.from(jwk.x, 'base64url')],
    [-3, Buffer.from(jwk.y, 'base64url')],
  ]));
  const extBytes = encodeCbor(new Map([['credProps', new Map([['rk', true]])]]));
  const rpHash = crypto.createHash('sha256').update('localhost').digest();
  const flagsEd = Buffer.from([0xc5]); // UP | UV | AT | ED
  const counter = Buffer.alloc(4);
  const aaguid = Buffer.alloc(16, 0);
  const credIdLen = Buffer.alloc(2);
  credIdLen.writeUInt16BE(credId.length, 0);
  const authDataWithExt = Buffer.concat([rpHash, flagsEd, counter, aaguid, credIdLen, credId, coseBytes, extBytes]);
  const attObjWithExt = encodeCbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authDataWithExt]]));
  const challenge = toBase64Url(crypto.randomBytes(32));
  const okClientData = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin: 'http://localhost:18797', crossOrigin: false }));
  const regOk = verifyRegistrationResponse({
    credential: {
      id: toBase64Url(credId),
      type: 'public-key',
      response: { clientDataJSON: toBase64Url(okClientData), attestationObject: toBase64Url(attObjWithExt) },
    },
    expectedChallenge: challenge,
    expectedRpId: 'localhost',
    allowedOrigins: new Set(['http://localhost:18797']),
  });
  assert.equal(regOk.credentialId, toBase64Url(credId));

  const crossOriginData = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin: 'http://localhost:18797', crossOrigin: true }));
  assert.throws(() => verifyRegistrationResponse({
    credential: {
      id: toBase64Url(credId),
      type: 'public-key',
      response: { clientDataJSON: toBase64Url(crossOriginData), attestationObject: toBase64Url(attObjWithExt) },
    },
    expectedChallenge: challenge,
    expectedRpId: 'localhost',
    allowedOrigins: new Set(['http://localhost:18797']),
  }), /Cross-origin/);

  // M5: hardwarePasskeyEnforced latches across USB unplug (detector later returns false)
  const latchDir = await makeTempState(t);
  const { enrollPasskeySync } = await import('../local/webui-auth.mjs');
  enrollPasskeySync(latchDir, {
    credential: regOk,
    label: 'YubiKey',
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: true, reason: 'linux-fido2-hid' }),
  });
  assert.throws(() => switchToStrongPasswordSync(latchDir, {
    password: 'Latch!Strong#2026Aa',
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: false, reason: 'unplugged' }),
  }), /enforces PassKey/);

  // Configure password-mode WebUI to test H1, M2, M6, L4
  await fs.writeFile(path.join(stateDir, 'config.json'), JSON.stringify({
    origin: 'http://127.0.0.1:8797',
    roots: [workspace],
    defaultCwd: workspace,
    allowExec: true,
    requireLocalApproval: true,
    sandbox: { enabled: true, allowOutbound: false, image: `sha256:${'a'.repeat(64)}`, context: 'default' },
  }), { mode: 0o600 });

  const approvalsDir = path.join(stateDir, 'approvals');
  await fs.mkdir(approvalsDir, { mode: 0o700 });
  const bidiId = '33333333-3333-4333-8333-333333333333';
  const corruptId = '44444444-4444-4444-8444-444444444444';
  const now = Date.now();
  const bidiReq = {
    method: 'tools/call',
    params: { name: 'read_file', arguments: { path: '/workspace/a.txt' } },
    authorization: { clientId: 'client-\u202eEVIL' },
  };
  await fs.writeFile(path.join(approvalsDir, `${bidiId}.request.json`), JSON.stringify({
    id: bidiId,
    version: 1,
    createdAt: now - 1000,
    expiresAt: now + 299000,
    hash: policyDigest(bidiReq),
    request: bidiReq,
  }), { mode: 0o600 });
  await fs.writeFile(path.join(approvalsDir, `${corruptId}.request.json`), '{corrupted-json', { mode: 0o600 });

  setStrongPasswordSync(stateDir, {
    password: 'Review!Strong#2026Aa',
    allowBypassTicket: true,
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
  });

  const webui = await startWebUiServer({
    stateDir,
    runtimeRoot: path.resolve(import.meta.dirname, '..'),
    host: '127.0.0.1',
    port: 0,
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
    gatewayProbe: async () => ({ reachable: false, status: null, latencyMs: null }),
    dockerProbe: async () => ({ dockerOk: true, runningContainers: [] }),
    systemdProbe: async () => ({ supported: false, installed: false, enabled: false, active: false, linger: false }),
    serviceController: async () => {},
  });
  t.after(() => webui.close());

  const home = await httpCall(webui.url, '/');
  const preCsrf = home.text.match(/<meta name="agentdock-csrf" content="([^"]+)"/)?.[1];
  const preCookie = mergeCookieHeader('', home.headers['set-cookie']);

  // L4: unauthenticated /api/auth/state omits private metadata (passkeys, hasActiveSetupTicket)
  const unauthState = await httpCall(webui.url, '/api/auth/state', { headers: { 'sec-fetch-site': 'same-origin' } });
  assert.equal(unauthState.status, 200);
  assert.equal(unauthState.json().passkeys, undefined);
  assert.equal(unauthState.json().hasActiveSetupTicket, undefined);

  // M2: invalid setupToken triggers lockout rate limiting (5 fails -> 429)
  for (let i = 0; i < 5; i++) {
    const badTicket = await httpCall(webui.url, '/api/auth/setup/password', {
      method: 'POST',
      headers: { origin: webui.url, cookie: preCookie, 'x-agentdock-csrf': preCsrf, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
      body: JSON.stringify({ setupToken: 'AD-wrong-token', password: 'Review!Strong#2026Bb' }),
    });
    assert.equal(badTicket.status, 401);
  }
  const rateLimitedTicket = await httpCall(webui.url, '/api/auth/setup/password', {
    method: 'POST',
    headers: { origin: webui.url, cookie: preCookie, 'x-agentdock-csrf': preCsrf, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ setupToken: 'AD-wrong-token', password: 'Review!Strong#2026Bb' }),
  });
  assert.equal(rateLimitedTicket.status, 429);

  // Spin a fresh server instance (clean rate-limit bucket) for authenticated H1/M2/M6 checks
  const webui2 = await startWebUiServer({
    stateDir,
    runtimeRoot: path.resolve(import.meta.dirname, '..'),
    host: '127.0.0.1',
    port: 0,
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
    gatewayProbe: async () => ({ reachable: false, status: null, latencyMs: null }),
    dockerProbe: async () => ({ dockerOk: true, runningContainers: [] }),
    systemdProbe: async () => ({ supported: false, installed: false, enabled: false, active: false, linger: false }),
    serviceController: async () => {},
  });
  t.after(() => webui2.close());

  const home2 = await httpCall(webui2.url, '/');
  const preCsrf2 = home2.text.match(/<meta name="agentdock-csrf" content="([^"]+)"/)?.[1];
  const preCookie2 = mergeCookieHeader('', home2.headers['set-cookie']);
  const login2 = await httpCall(webui2.url, '/api/auth/login/password', {
    method: 'POST',
    headers: { origin: webui2.url, cookie: preCookie2, 'x-agentdock-csrf': preCsrf2, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ password: 'Review!Strong#2026Aa' }),
  });
  assert.equal(login2.status, 200);
  const csrf2 = login2.json().csrfToken;
  const tabToken2 = login2.json().tabToken;
  const cookie2 = mergeCookieHeader(preCookie2, login2.headers['set-cookie']);

  // H1: password-authenticated user MUST NOT bypass currentPassword via /api/auth/passkey/switch-password
  const bypassAttempt = await httpCall(webui2.url, '/api/auth/passkey/switch-password', {
    method: 'POST',
    headers: { origin: webui2.url, cookie: cookie2, 'x-agentdock-csrf': csrf2, 'x-agentdock-tab-auth': tabToken2, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ password: 'Hijacked!Strong#2026Zz' }),
  });
  assert.equal(bypassAttempt.status, 403);

  // M2: pre-auth CSRF token must NOT be accepted for authenticated session on /api/auth/setup/password or /api/auth/logout
  const stalePreSetup = await httpCall(webui2.url, '/api/auth/setup/password', {
    method: 'POST',
    headers: { origin: webui2.url, cookie: `${cookie2}; ${preCookie2}`, 'x-agentdock-csrf': preCsrf2, 'x-agentdock-tab-auth': tabToken2, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ currentPassword: 'Review!Strong#2026Aa', password: 'New!Strong#2026Cc' }),
  });
  assert.equal(stalePreSetup.status, 403);
  const stalePreLogout = await httpCall(webui2.url, '/api/auth/logout', {
    method: 'POST',
    headers: { origin: webui2.url, cookie: `${cookie2}; ${preCookie2}`, 'x-agentdock-csrf': preCsrf2, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: '{}',
  });
  assert.equal(stalePreLogout.status, 403);

  // M6: clientId bidi characters escaped in /api/status; corrupted .request.json removable via /api/approvals/reject
  const stRes = await httpCall(webui2.url, '/api/status', { headers: { cookie: cookie2, 'x-agentdock-tab-auth': tabToken2, 'sec-fetch-site': 'same-origin' } });
  assert.equal(stRes.status, 200);
  const bidiItem = stRes.json().approvals.items.find(i => i.id === bidiId);
  assert.ok(bidiItem.clientId.includes('\\u202e'));
  assert.equal(bidiItem.clientId.includes('\u202e'), false);

  const rejectCorrupt = await httpCall(webui2.url, '/api/approvals/reject', {
    method: 'POST',
    headers: { origin: webui2.url, cookie: cookie2, 'x-agentdock-csrf': csrf2, 'x-agentdock-tab-auth': tabToken2, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ id: corruptId }),
  });
  assert.equal(rejectCorrupt.status, 200);
  await assert.rejects(fs.access(path.join(approvalsDir, `${corruptId}.request.json`)), { code: 'ENOENT' });
});

test('WebUI Round 2 regressions: H1 CSRF re-mint, H2 concurrent burst lockout, H3 client-abort probe, M1 post-body logout, M4 save conflict, L2 CORP & L4 WebAuthn hardening', async t => {
  const { verifyRegistrationResponse, verifyAuthenticationResponse } = await import('../local/webauthn.mjs');

  // L4: WebAuthn duplicate CBOR map key, topOrigin, AT bit on assertion, and mismatched EC curve
  {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' });
    const credId = crypto.randomBytes(32);
    const rpHash = crypto.createHash('sha256').update('localhost').digest();
    const challenge = toBase64Url(crypto.randomBytes(32));
    const coseBytes = encodeCbor(new Map([
      [1, 2], [3, -7], [-1, 1],
      [-2, Buffer.from(jwk.x, 'base64url')],
      [-3, Buffer.from(jwk.y, 'base64url')],
    ]));
    const credIdLen = Buffer.alloc(2);
    credIdLen.writeUInt16BE(credId.length, 0);
    const authData = Buffer.concat([rpHash, Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), credIdLen, credId, coseBytes]);

    // Raw CBOR map with duplicate key "fmt" (major 5 count 2: "fmt"->"none", "fmt"->"packed")
    const dupAttObj = Buffer.concat([
      Buffer.from([0xa2]),
      encodeCbor('fmt'), encodeCbor('none'),
      encodeCbor('fmt'), encodeCbor('packed'),
    ]);
    const okClientData = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin: 'http://localhost:18797' }));
    assert.throws(() => verifyRegistrationResponse({
      credential: {
        id: toBase64Url(credId),
        type: 'public-key',
        response: { clientDataJSON: toBase64Url(okClientData), attestationObject: toBase64Url(dupAttObj) },
      },
      expectedChallenge: challenge,
      expectedRpId: 'localhost',
      allowedOrigins: new Set(['http://localhost:18797']),
    }), /Duplicate key in CBOR map/);

    // topOrigin present in clientDataJSON
    const attObj = encodeCbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
    const topOriginData = Buffer.from(JSON.stringify({
      type: 'webauthn.create',
      challenge,
      origin: 'http://localhost:18797',
      topOrigin: 'https://evil.example',
    }));
    assert.throws(() => verifyRegistrationResponse({
      credential: {
        id: toBase64Url(credId),
        type: 'public-key',
        response: { clientDataJSON: toBase64Url(topOriginData), attestationObject: toBase64Url(attObj) },
      },
      expectedChallenge: challenge,
      expectedRpId: 'localhost',
      allowedOrigins: new Set(['http://localhost:18797']),
    }), /Cross-origin/);

    // Assertion with AT bit (0x40) set must be rejected
    const getClientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'http://localhost:18797' }));
    const clientHash = crypto.createHash('sha256').update(getClientData).digest();
    const badAssertAuthData = Buffer.concat([rpHash, Buffer.from([0x45]), Buffer.from([0, 0, 0, 1]), Buffer.alloc(16), credIdLen, credId, coseBytes]);
    const sig = crypto.sign('sha256', Buffer.concat([badAssertAuthData, clientHash]), privateKey);
    const storedP256 = {
      id: toBase64Url(credId),
      alg: -7,
      signCount: 0,
      publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    };
    assert.throws(() => verifyAuthenticationResponse({
      credential: {
        id: toBase64Url(credId),
        type: 'public-key',
        response: {
          clientDataJSON: toBase64Url(getClientData),
          authenticatorData: toBase64Url(badAssertAuthData),
          signature: toBase64Url(sig),
        },
      },
      storedPasskey: storedP256,
      expectedChallenge: challenge,
      expectedRpId: 'localhost',
      allowedOrigins: new Set(['http://localhost:18797']),
    }), /Attested credential data is not permitted/);

    // Mismatched EC curve (P-384 key claimed as alg -7 / P-256)
    const p384 = crypto.generateKeyPairSync('ec', { namedCurve: 'P-384' });
    const cleanAssertAuthData = Buffer.concat([rpHash, Buffer.from([0x05]), Buffer.from([0, 0, 0, 2])]);
    const p384Sig = crypto.sign('sha256', Buffer.concat([cleanAssertAuthData, clientHash]), p384.privateKey);
    assert.throws(() => verifyAuthenticationResponse({
      credential: {
        id: toBase64Url(credId),
        type: 'public-key',
        response: {
          clientDataJSON: toBase64Url(getClientData),
          authenticatorData: toBase64Url(cleanAssertAuthData),
          signature: toBase64Url(p384Sig),
        },
      },
      storedPasskey: {
        id: toBase64Url(credId),
        alg: -7,
        signCount: 0,
        publicKeyPem: p384.publicKey.export({ type: 'spki', format: 'pem' }),
      },
      expectedChallenge: challenge,
      expectedRpId: 'localhost',
      allowedOrigins: new Set(['http://localhost:18797']),
    }), /elliptic curve does not match/);
  }

  const stateDir = await makeTempState(t);
  const workspace = await fs.mkdtemp(path.join(os.homedir(), '.ad-r2-ws-'));
  t.after(() => fs.rm(workspace, { recursive: true, force: true }));

  await fs.writeFile(path.join(stateDir, 'config.json'), JSON.stringify({
    origin: 'http://127.0.0.1:8797',
    roots: [workspace],
    defaultCwd: workspace,
    allowExec: true,
    requireLocalApproval: true,
    sandbox: { enabled: true, allowOutbound: false, image: `sha256:${'a'.repeat(64)}`, context: 'default' },
  }), { mode: 0o600 });

  setStrongPasswordSync(stateDir, {
    password: 'Round2!Strong#2026Aa',
    allowBypassTicket: true,
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
  });

  let probeSignalAborted = false;
  let probeStartedResolve;
  let probeReleaseResolve;
  const resetProbeHooks = () => {
    probeSignalAborted = false;
    const started = new Promise(r => { probeStartedResolve = r; });
    const waitRelease = new Promise(r => { probeReleaseResolve = r; });
    return { started, waitRelease };
  };
  let probeHooks = resetProbeHooks();

  const webui = await startWebUiServer({
    stateDir,
    runtimeRoot: path.resolve(import.meta.dirname, '..'),
    host: '127.0.0.1',
    port: 0,
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
    gatewayProbe: async () => ({ reachable: false, status: null, latencyMs: null }),
    dockerProbe: async () => ({ dockerOk: true, runningContainers: [] }),
    systemdProbe: async () => ({ supported: false, installed: false, enabled: false, active: false, linger: false }),
    serviceController: async () => {},
    mcpProber: async (_srv, { signal }) => {
      probeStartedResolve(signal);
      await new Promise(resolve => {
        if (signal.aborted) {
          probeSignalAborted = true;
          return resolve();
        }
        signal.addEventListener('abort', () => {
          probeSignalAborted = true;
          resolve();
        }, { once: true });
        probeHooks.waitRelease.then(resolve);
      });
      return { ok: false, latencyMs: 10, error: probeSignalAborted ? 'aborted' : 'done' };
    },
  });
  t.after(() => webui.close());

  // L2: CORP header & Sec-Fetch-Site rejection on static assets
  const cssOk = await httpCall(webui.url, '/styles.css', { headers: { 'sec-fetch-site': 'same-origin' } });
  assert.equal(cssOk.status, 200);
  assert.equal(cssOk.headers['cross-origin-resource-policy'], 'same-origin');
  const jsCross = await httpCall(webui.url, '/app.js', { headers: { 'sec-fetch-site': 'cross-site' } });
  assert.equal(jsCross.status, 403);

  // H1: Without calling GET /, GET /api/auth/state mints PRE_AUTH_COOKIE + csrfToken for re-login!
  const authState = await httpCall(webui.url, '/api/auth/state', { headers: { 'sec-fetch-site': 'same-origin' } });
  assert.equal(authState.status, 200);
  const authStateJson = authState.json();
  assert.equal(authStateJson.authenticated, false);
  assert.ok(authStateJson.csrfToken, 'Unauthenticated /api/auth/state must issue pre-auth csrfToken');
  let cookie = mergeCookieHeader('', authState.headers['set-cookie']);
  let csrf = authStateJson.csrfToken;

  const loginOk = await httpCall(webui.url, '/api/auth/login/password', {
    method: 'POST',
    headers: { origin: webui.url, cookie, 'x-agentdock-csrf': csrf, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ password: 'Round2!Strong#2026Aa' }),
  });
  assert.equal(loginOk.status, 200);
  csrf = loginOk.json().csrfToken;
  const tabToken = loginOk.json().tabToken;
  cookie = mergeCookieHeader(cookie, loginOk.headers['set-cookie']);
  const authedHeaders = {
    origin: webui.url,
    cookie,
    'x-agentdock-csrf': csrf,
    'x-agentdock-tab-auth': tabToken,
    'sec-fetch-site': 'same-origin',
    'content-type': 'application/json',
  };

  // Seed MCP server for H3 & M4 tests
  const seedMcp = await httpCall(webui.url, '/api/mcp-servers/save', {
    method: 'POST',
    headers: authedHeaders,
    body: JSON.stringify({ id: 'slow_r2', name: 'Slow R2', transport: 'stdio', command: process.execPath, args: ['-v'] }),
  });
  assert.equal(seedMcp.status, 200);

  // H3: Client disconnecting during POST /api/mcp-servers/probe aborts probe signal via res.on('close')
  const parsedUrl = new URL(webui.url);
  await new Promise((resolve, reject) => {
    const req = http.request({
      hostname: parsedUrl.hostname,
      port: parsedUrl.port,
      path: '/api/mcp-servers/probe',
      method: 'POST',
      headers: authedHeaders,
    });
    req.on('error', () => {});
    req.end(JSON.stringify({ id: 'slow_r2' }));
    probeHooks.started.then(async signal => {
      const aborted = once(signal, 'abort', { signal: AbortSignal.timeout(5000) });
      req.destroy();
      await aborted;
    }).then(resolve, reject);
  });
  assert.equal(probeSignalAborted, true, 'Destroying client socket after POST body must abort in-flight probe');

  // M4: Concurrent /save with probe:true while probe already in progress returns 200 with ok:true and probe failure (not 409)
  probeHooks = resetProbeHooks();
  const inFlightProbe = httpCall(webui.url, '/api/mcp-servers/probe', {
    method: 'POST',
    headers: authedHeaders,
    body: JSON.stringify({ id: 'slow_r2' }),
  });
  await probeHooks.started;
  const saveDuringProbe = await httpCall(webui.url, '/api/mcp-servers/save', {
    method: 'POST',
    headers: authedHeaders,
    body: JSON.stringify({ id: 'slow_r2', name: 'Slow R2 Edited', transport: 'stdio', command: process.execPath, args: ['-v'], probe: true }),
  });
  assert.equal(saveDuringProbe.status, 200);
  assert.equal(saveDuringProbe.json().ok, true);
  assert.equal(saveDuringProbe.json().server.name, 'Slow R2 Edited');
  assert.equal(saveDuringProbe.json().probe.ok, false);
  assert.match(saveDuringProbe.json().probe.error, /already in progress/);
  probeReleaseResolve();
  await inFlightProbe;

  // M1: Parked authenticated POST resumed after /api/auth/logout MUST return 401 and NOT write capabilities
  const parkedResult = await new Promise((resolve, reject) => {
    const req = http.request({
      hostname: parsedUrl.hostname,
      port: parsedUrl.port,
      path: '/api/capabilities',
      method: 'POST',
      headers: authedHeaders,
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.write('{"fileWrite":');
    setTimeout(async () => {
      try {
        const out = await httpCall(webui.url, '/api/auth/logout', {
          method: 'POST',
          headers: authedHeaders,
          body: '{}',
        });
        assert.equal(out.status, 200);
        req.end('false}');
      } catch (err) {
        reject(err);
      }
    }, 60);
  });
  assert.equal(parkedResult.status, 401);
  assert.equal(readCapabilitiesSync(stateDir, { workspaceRoots: [workspace] }).fileWrite, true);

  // H2: Concurrent slow-body burst against /api/auth/login/password enforces 5-failure lockout (post-body check -> 429)
  const freshPre = await httpCall(webui.url, '/api/auth/state', { headers: { 'sec-fetch-site': 'same-origin' } });
  const preCookie = mergeCookieHeader('', freshPre.headers['set-cookie']);
  const preCsrf = freshPre.json().csrfToken;
  const burstPromises = Array.from({ length: 8 }, (_, idx) => new Promise((resolve, reject) => {
    const req = http.request({
      hostname: parsedUrl.hostname,
      port: parsedUrl.port,
      path: '/api/auth/login/password',
      method: 'POST',
      headers: {
        origin: webui.url,
        cookie: preCookie,
        'x-agentdock-csrf': preCsrf,
        'sec-fetch-site': 'same-origin',
        'content-type': 'application/json',
      },
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject);
    req.write('{"password":');
    setTimeout(() => req.end(`"WrongBurst!${idx}Aa#99"}`), 25 + idx * 15);
  }));
  const statuses = await Promise.all(burstPromises);
  assert.equal(statuses.filter(s => s === 401).length, 5, `Expected 5 failures before lockout, got ${JSON.stringify(statuses)}`);
  assert.equal(statuses.filter(s => s === 429).length, 3, `Expected 3 rate-limited responses, got ${JSON.stringify(statuses)}`);
});

test('WebUI /api/mcp-servers/save and /import redact thrown probe errors, persist failures, preserve 409 state, and propagate persistence errors', async t => {
  const stateDir = await makeTempState(t);
  const workspace = await fs.mkdtemp(path.join(os.homedir(), '.ad-mcp-probe-ws-'));
  t.after(() => fs.rm(workspace, { recursive: true, force: true }));

  await fs.writeFile(path.join(stateDir, 'config.json'), JSON.stringify({
    origin: 'http://127.0.0.1:8797',
    roots: [workspace],
    defaultCwd: workspace,
    allowExec: true,
    requireLocalApproval: true,
    sandbox: { enabled: true, allowOutbound: false, image: `sha256:${'a'.repeat(64)}`, context: 'default' },
  }), { mode: 0o600 });

  setStrongPasswordSync(stateDir, {
    password: 'WebUiProbe!Strong#2026Aa',
    allowBypassTicket: true,
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
  });

  let proberMode = 'ok';
  let holdStartedResolve;
  let holdReleaseResolve;
  const resetHold = () => {
    const started = new Promise(resolve => { holdStartedResolve = resolve; });
    const release = new Promise(resolve => { holdReleaseResolve = resolve; });
    return { started, release };
  };
  let hold = resetHold();
  let multiHoldCount = 0;
  let multiHoldAllStartedResolve;
  let multiHoldAllStarted = new Promise(resolve => { multiHoldAllStartedResolve = resolve; });
  let multiHoldReleaseResolve;
  let multiHoldRelease = new Promise(resolve => { multiHoldReleaseResolve = resolve; });
  let savedBackupForCorrupt = null;

  const webui = await startWebUiServer({
    stateDir,
    runtimeRoot: path.resolve(import.meta.dirname, '..'),
    host: '127.0.0.1',
    port: 0,
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
    gatewayProbe: async () => ({ reachable: false, status: null, latencyMs: null }),
    dockerProbe: async () => ({ dockerOk: true, runningContainers: [] }),
    systemdProbe: async () => ({ supported: false, installed: false, enabled: false, active: false, linger: false }),
    serviceController: async () => {},
    mcpProber: async srv => {
      if (proberMode === 'hold_all_3' && srv.id.startsWith('wb_hold_')) {
        multiHoldCount += 1;
        if (multiHoldCount === 3) multiHoldAllStartedResolve();
        await multiHoldRelease;
        return { ok: true, latencyMs: 5, tools: [] };
      }
      if (proberMode === 'hold_on_busy' && srv.id === 'wb_busy') {
        holdStartedResolve();
        await hold.release;
        return { ok: true, latencyMs: 5, tools: [{ name: 'busy_tool', inputSchema: { type: 'object', properties: {} } }] };
      }
      if (proberMode === 'corrupt_registry') {
        const file = mcpServersFilePath(stateDir);
        savedBackupForCorrupt = await fs.readFile(file, 'utf8');
        await fs.writeFile(file, '{corrupted-before-saveProbeResult', { mode: 0o600 });
        return { ok: true, latencyMs: 3, tools: [] };
      }
      if (srv.id === 'wb_save_throw' || srv.id === 'wb_imp_throw') {
        const secret = srv.env?.API_TOKEN || srv.headers?.Authorization || 'Bearer WEBUI_FALLBACK_SECRET_99';
        throw new Error(`External MCP connection failed with ${secret}`);
      }
      return {
        ok: true,
        latencyMs: 6,
        tools: [{ name: `${srv.id}_tool`, inputSchema: { type: 'object', properties: {} } }],
      };
    },
  });
  t.after(() => webui.close());

  const authState = await httpCall(webui.url, '/api/auth/state', { headers: { 'sec-fetch-site': 'same-origin' } });
  let cookie = mergeCookieHeader('', authState.headers['set-cookie']);
  let csrf = authState.json().csrfToken;
  const loginRes = await httpCall(webui.url, '/api/auth/login/password', {
    method: 'POST',
    headers: { origin: webui.url, cookie, 'x-agentdock-csrf': csrf, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ password: 'WebUiProbe!Strong#2026Aa' }),
  });
  assert.equal(loginRes.status, 200);
  csrf = loginRes.json().csrfToken;
  const tabToken = loginRes.json().tabToken;
  cookie = mergeCookieHeader(cookie, loginRes.headers['set-cookie']);

  const authedHeaders = {
    origin: webui.url,
    cookie,
    'x-agentdock-csrf': csrf,
    'x-agentdock-tab-auth': tabToken,
    'sec-fetch-site': 'same-origin',
    'content-type': 'application/json',
  };

  // 1. /save (probe: true) when mcpProber throws: redacts secret AND persists lastProbeOk: false on disk
  const saveThrowRes = await httpCall(webui.url, '/api/mcp-servers/save', {
    method: 'POST',
    headers: authedHeaders,
    body: JSON.stringify({
      id: 'wb_save_throw',
      name: 'WebUI Save Throw',
      transport: 'stdio',
      command: process.execPath,
      args: ['-v'],
      env: { API_TOKEN: 'WEBUI_SAVE_SECRET_1357' },
      probe: true,
    }),
  });
  assert.equal(saveThrowRes.status, 200);
  assert.equal(saveThrowRes.text.includes('WEBUI_SAVE_SECRET_1357'), false);
  assert.equal(saveThrowRes.json().probe.ok, false);
  assert.match(saveThrowRes.json().probe.error, /\[REDACTED\]/);
  assert.equal(saveThrowRes.json().server.lastProbeOk, false);
  const diskSaveThrow = readMcpServersSync(stateDir, { workspaceRoots: [workspace] }).servers.find(s => s.id === 'wb_save_throw');
  assert.equal(diskSaveThrow.lastProbeOk, false);
  assert.match(diskSaveThrow.lastProbeError, /\[REDACTED\]/);
  assert.equal(diskSaveThrow.lastProbeError.includes('WEBUI_SAVE_SECRET_1357'), false);

  // 2. Seed wb_busy to lastProbeOk: true, then verify 409 conflict in /save and /import does NOT overwrite lastProbeOk
  const seedBusy = await httpCall(webui.url, '/api/mcp-servers/save', {
    method: 'POST',
    headers: authedHeaders,
    body: JSON.stringify({
      id: 'wb_busy',
      name: 'WebUI Busy',
      transport: 'stdio',
      command: process.execPath,
      args: ['-v'],
      probe: true,
    }),
  });
  assert.equal(seedBusy.status, 200);
  assert.equal(seedBusy.json().server.lastProbeOk, true);

  hold = resetHold();
  proberMode = 'hold_on_busy';
  const inFlightProbe = httpCall(webui.url, '/api/mcp-servers/probe', {
    method: 'POST',
    headers: authedHeaders,
    body: JSON.stringify({ id: 'wb_busy' }),
  });
  await hold.started;

  // 2a. Concurrent /save preserves 200 + M4 UX while skipping saveMcpProbeResultSync
  const saveDuringConflict = await httpCall(webui.url, '/api/mcp-servers/save', {
    method: 'POST',
    headers: authedHeaders,
    body: JSON.stringify({
      id: 'wb_busy',
      name: 'WebUI Busy Renamed',
      transport: 'stdio',
      command: process.execPath,
      args: ['-v'],
      probe: true,
    }),
  });
  assert.equal(saveDuringConflict.status, 200);
  assert.equal(saveDuringConflict.json().ok, true);
  assert.equal(saveDuringConflict.json().server.name, 'WebUI Busy Renamed');
  assert.equal(saveDuringConflict.json().probe.ok, false);
  assert.match(saveDuringConflict.json().probe.error, /already in progress/);
  assert.equal(readMcpServersSync(stateDir, { workspaceRoots: [workspace] }).servers.find(s => s.id === 'wb_busy').lastProbeOk, true);

  // 2b. Concurrent /import with wb_busy (409), wb_imp_throw (secret redaction + persist), and wb_imp_ok (success)
  const importRes = await httpCall(webui.url, '/api/mcp-servers/import', {
    method: 'POST',
    headers: authedHeaders,
    body: JSON.stringify({
      probe: true,
      json: JSON.stringify({
        mcpServers: {
          wb_busy: { name: 'WebUI Busy Renamed', command: process.execPath, args: ['-v'] },
          wb_imp_throw: { command: process.execPath, args: ['-v'], env: { API_TOKEN: 'WEBUI_IMP_SECRET_2468' } },
          wb_imp_ok: { command: process.execPath, args: ['-v'] },
        },
      }),
    }),
  });
  assert.equal(importRes.status, 200);
  assert.equal(importRes.text.includes('WEBUI_IMP_SECRET_2468'), false);
  const importJson = importRes.json();
  assert.equal(importJson.probes.wb_busy.ok, false);
  assert.equal(importJson.probes.wb_busy.status, 409);
  assert.match(importJson.probes.wb_busy.error, /already in progress/);
  assert.equal(importJson.probes.wb_imp_throw.ok, false);
  assert.match(importJson.probes.wb_imp_throw.error, /\[REDACTED\]/);
  assert.equal(importJson.probes.wb_imp_ok.ok, true);
  assert.equal(importJson.probes.wb_imp_ok.toolCount, 1);

  const diskAfterImport = readMcpServersSync(stateDir, { workspaceRoots: [workspace] }).servers;
  assert.equal(diskAfterImport.find(s => s.id === 'wb_busy').lastProbeOk, true);
  assert.equal(diskAfterImport.find(s => s.id === 'wb_imp_throw').lastProbeOk, false);
  assert.match(diskAfterImport.find(s => s.id === 'wb_imp_throw').lastProbeError, /\[REDACTED\]/);
  assert.equal(diskAfterImport.find(s => s.id === 'wb_imp_ok').lastProbeOk, true);

  holdReleaseResolve();
  await inFlightProbe;
  proberMode = 'ok';

  // 2c. 429 concurrency limit (>= 3 active probes) on /save preserves 200 + M4 UX and does NOT overwrite lastProbeOk: true
  for (const id of ['wb_hold_1', 'wb_hold_2', 'wb_hold_3']) {
    const seeded = await httpCall(webui.url, '/api/mcp-servers/save', {
      method: 'POST',
      headers: authedHeaders,
      body: JSON.stringify({ id, name: id, transport: 'stdio', command: process.execPath, args: ['-v'] }),
    });
    assert.equal(seeded.status, 200);
  }
  proberMode = 'hold_all_3';
  const threeProbes = ['wb_hold_1', 'wb_hold_2', 'wb_hold_3'].map(id => httpCall(webui.url, '/api/mcp-servers/probe', {
    method: 'POST',
    headers: authedHeaders,
    body: JSON.stringify({ id }),
  }));
  await multiHoldAllStarted;
  const saveOn429 = await httpCall(webui.url, '/api/mcp-servers/save', {
    method: 'POST',
    headers: authedHeaders,
    body: JSON.stringify({
      id: 'wb_imp_ok',
      name: 'WebUI Imp Ok 429',
      transport: 'stdio',
      command: process.execPath,
      args: ['-v'],
      probe: true,
    }),
  });
  assert.equal(saveOn429.status, 200);
  assert.equal(saveOn429.json().ok, true);
  assert.equal(saveOn429.json().probe.ok, false);
  assert.match(saveOn429.json().probe.error, /Too many concurrent/);
  assert.equal(readMcpServersSync(stateDir, { workspaceRoots: [workspace] }).servers.find(s => s.id === 'wb_imp_ok').lastProbeOk, true);
  multiHoldReleaseResolve();
  await Promise.all(threeProbes);
  proberMode = 'ok';

  // 3. Non-NOT_FOUND persistence errors from saveMcpProbeResultSync propagate as HTTP 500 on both /save and /import
  proberMode = 'corrupt_registry';
  const saveWriteErr = await httpCall(webui.url, '/api/mcp-servers/save', {
    method: 'POST',
    headers: authedHeaders,
    body: JSON.stringify({
      id: 'wb_imp_ok',
      name: 'WebUI Imp Ok',
      transport: 'stdio',
      command: process.execPath,
      args: ['-v'],
      probe: true,
    }),
  });
  assert.equal(saveWriteErr.status, 500);
  await fs.writeFile(mcpServersFilePath(stateDir), savedBackupForCorrupt, { mode: 0o600 });

  const importWriteErr = await httpCall(webui.url, '/api/mcp-servers/import', {
    method: 'POST',
    headers: authedHeaders,
    body: JSON.stringify({
      probe: true,
      json: JSON.stringify({
        mcpServers: {
          wb_imp_ok: { command: process.execPath, args: ['-v'] },
        },
      }),
    }),
  });
  assert.equal(importWriteErr.status, 500);
  await fs.writeFile(mcpServersFilePath(stateDir), savedBackupForCorrupt, { mode: 0o600 });
});
