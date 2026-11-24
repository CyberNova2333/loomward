// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import {
  ToolBlockedError,
  applyOutputRedaction,
  buildContentInspectRequest,
  validateConsolePanelDecl,
  validateContentInspectVerdict,
} from '@loomward/shared';
import { startDualOriginConsole, connectControlSocket } from '../src/index.mjs';
import { startLoomWardDaemon } from '../../host/src/daemon.mjs';
import { issueSetupTicketSync } from '../../../local/webui-auth.mjs';
import { toBase64Url } from '../../../local/webauthn.mjs';
import { digest as policyDigest } from '../../../local/request-policy.mjs';

const REPO_ROOT = path.resolve(import.meta.dirname, '../../..');

async function makeTempState(t) {
  const base = await fs.mkdtemp(path.join(os.homedir(), '.lw-c2-'));
  await fs.chmod(base, 0o700);
  const stateDir = path.join(base, 'st');
  const workspace = path.join(base, 'ws');
  await fs.mkdir(stateDir, { mode: 0o700 });
  await fs.mkdir(workspace, { mode: 0o700 });
  await fs.writeFile(path.join(stateDir, 'config.json'), JSON.stringify({
    origin: 'https://bridge.example.test',
    roots: [workspace],
    defaultCwd: workspace,
    allowExec: true,
    requireLocalApproval: true,
    sandbox: { enabled: true, image: `sha256:${'a'.repeat(64)}`, context: 'default', allowOutbound: false },
  }), { mode: 0o600 });
  await fs.writeFile(path.join(stateDir, 'secrets.meta.json'), JSON.stringify({ backend: 'posix-file' }), { mode: 0o600 });
  await fs.writeFile(path.join(stateDir, 'secrets.json'), JSON.stringify({
    bridgeToken: 'CANARY-NEVER-EXPOSE-BRIDGE-TOKEN-9876543210',
    ownerPassword: 'CANARY-NEVER-EXPOSE-PASSWORD-987654',
    ownerPasswordHash: 'pbkdf2-sha256$100000$salt$hash',
  }), { mode: 0o600 });
  t.after(async () => {
    assert.equal(path.dirname(base), os.homedir());
    assert.ok(path.basename(base).startsWith('.lw-c2-'));
    await fs.rm(base, { recursive: true, force: true });
  });
  return { base, stateDir, workspace };
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
    const b = Buffer.allocUnsafe(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(len, 1);
    return b;
  };
  if (typeof value === 'boolean') return Buffer.from([value ? 0xf5 : 0xf4]);
  if (typeof value === 'number') return value >= 0 ? header(0, value) : header(1, -1 - value);
  if (Buffer.isBuffer(value)) return Buffer.concat([header(2, value.length), value]);
  if (typeof value === 'string') {
    const buf = Buffer.from(value, 'utf8');
    return Buffer.concat([header(3, buf.length), buf]);
  }
  if (value instanceof Map) {
    const chunks = [header(5, value.size)];
    for (const [k, v] of value.entries()) chunks.push(encodeCbor(k), encodeCbor(v));
    return Buffer.concat(chunks);
  }
  throw new Error('Unsupported CBOR type');
}

function createVirtualEs256Passkey({ origin, rpId = 'localhost' }) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const credId = crypto.randomBytes(32);
  let signCount = 0;
  return {
    register(challenge) {
      signCount += 1;
      const coseBytes = encodeCbor(new Map([
        [1, 2], [3, -7], [-1, 1],
        [-2, Buffer.from(jwk.x, 'base64url')],
        [-3, Buffer.from(jwk.y, 'base64url')],
      ]));
      const rpHash = crypto.createHash('sha256').update(rpId).digest();
      const flags = Buffer.from([0x45]);
      const counter = Buffer.alloc(4);
      counter.writeUInt32BE(signCount, 0);
      const aaguid = Buffer.alloc(16, 0);
      const credIdLen = Buffer.alloc(2);
      credIdLen.writeUInt16BE(credId.length, 0);
      const authData = Buffer.concat([rpHash, flags, counter, aaguid, credIdLen, credId, coseBytes]);
      const attestationObject = encodeCbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
      const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin }), 'utf8');
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
    assert(challenge) {
      signCount += 1;
      const rpHash = crypto.createHash('sha256').update(rpId).digest();
      const flags = Buffer.from([0x05]);
      const counter = Buffer.alloc(4);
      counter.writeUInt32BE(signCount, 0);
      const authData = Buffer.concat([rpHash, flags, counter]);
      const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin }), 'utf8');
      const clientHash = crypto.createHash('sha256').update(clientData).digest();
      const sig = crypto.sign('sha256', Buffer.concat([authData, clientHash]), privateKey);
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

test('Dual-Origin Console enforces physical isolation, single-use handoff, linked logout revocation, and control.sock SSE push', async t => {
  const { stateDir, workspace } = await makeTempState(t);

  // Reject non-loopback host or colliding ports.
  await assert.rejects(() => startDualOriginConsole({
    stateDir,
    runtimeRoot: REPO_ROOT,
    host: '0.0.0.0',
    consolePort: 0,
    trustPort: 0,
  }), /loopback/i);
  await assert.rejects(() => startDualOriginConsole({
    stateDir,
    runtimeRoot: REPO_ROOT,
    host: '127.0.0.1',
    consolePort: 19999,
    trustPort: 19999,
  }), /distinct ports/i);

  const dual = await startDualOriginConsole({
    stateDir,
    runtimeRoot: REPO_ROOT,
    host: '127.0.0.1',
    consolePort: 0,
    trustPort: 0,
    pollIntervalMs: 0,
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
    gatewayProbe: async () => ({ reachable: false, status: null, latencyMs: null }),
    dockerProbe: async () => ({ dockerOk: true, runningContainers: [] }),
    systemdProbe: async () => ({ supported: false, installed: false, enabled: false, active: false, linger: false }),
    serviceController: async () => {},
  });
  t.after(() => dual.close());

  assert.notEqual(dual.trust.port, dual.console.port);

  // Built zero-CDN assets are served with strict CSP & CORP on their respective origins.
  const trustHome = await httpCall(dual.trust.url, '/');
  assert.equal(trustHome.status, 200);
  // Top-level cross-port/cross-host loopback navigation (e.g. window.open from Trust Origin to Console Origin) is permitted on GET /
  const navConsoleHome = await httpCall(dual.console.url, '/', {
    headers: { 'sec-fetch-site': 'same-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' },
  });
  assert.equal(navConsoleHome.status, 200);
  // But subresource or API requests with Sec-Fetch-Site: same-site are strictly rejected with 403.
  const crossSiteScript = await httpCall(dual.console.url, '/console.js', {
    headers: { 'sec-fetch-site': 'same-site', 'sec-fetch-mode': 'no-cors', 'sec-fetch-dest': 'script' },
  });
  assert.equal(crossSiteScript.status, 403);
  assert.equal(trustHome.headers['cross-origin-resource-policy'], 'same-origin');
  assert.match(trustHome.headers['content-security-policy'], /script-src 'self'/);
  let trustCsrf = trustHome.text.match(/<meta name="loomward-csrf" content="([^"]+)"/)?.[1];
  let trustCookie = mergeCookieHeader('', trustHome.headers['set-cookie']);
  assert.ok(trustCsrf && trustCookie.includes('loomward_trust_pre='));
  assert.equal((await httpCall(dual.trust.url, '/trust.js', { headers: { 'sec-fetch-site': 'same-origin' } })).status, 200);
  assert.equal((await httpCall(dual.console.url, '/console.js', { headers: { 'sec-fetch-site': 'same-origin' } })).status, 200);

  // Trust Origin strictly forbids /api/panels (extension panels never run on Ring 2).
  const trustPanels = await httpCall(dual.trust.url, '/api/panels');
  assert.equal(trustPanels.status, 403);
  assert.equal(trustPanels.json().code, 'CONSOLE_ORIGIN_ONLY');

  // Setup strong password on Trust Origin using CLI ticket.
  const ticket = issueSetupTicketSync(stateDir, {
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
  });
  const strongPassword = 'Kx9!mP4#vR2@qL8$zW';
  const setupRes = await httpCall(dual.trust.url, '/api/auth/setup/password', {
    method: 'POST',
    headers: {
      origin: dual.trust.url,
      cookie: trustCookie,
      'x-loomward-csrf': trustCsrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ setupToken: ticket.setupToken, password: strongPassword }),
  });
  assert.equal(setupRes.status, 200);
  const setupJson = setupRes.json();
  trustCsrf = setupJson.csrfToken;
  const trustTabToken = setupJson.tabToken;
  trustCookie = mergeCookieHeader(trustCookie, setupRes.headers['set-cookie']);

  // Trust Origin rejects cross-origin mutation pretending to come from Console Origin.
  const crossOriginMut = await httpCall(dual.trust.url, '/api/capabilities', {
    method: 'POST',
    headers: {
      origin: dual.console.url,
      cookie: trustCookie,
      'x-loomward-csrf': trustCsrf,
      'x-loomward-tab-auth': trustTabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ fileWrite: false }),
  });
  assert.equal(crossOriginMut.status, 403);

  // Console Origin rejects Trust cookie directly.
  assert.equal((await httpCall(dual.console.url, '/api/status', {
    headers: { cookie: trustCookie, 'x-loomward-tab-auth': trustTabToken },
  })).status, 401);

  // Trust Origin issues a single-use read-only handoff ticket for Console Origin.
  const handoffRes = await httpCall(dual.trust.url, '/api/trust/issue-console-ticket', {
    method: 'POST',
    headers: {
      origin: dual.trust.url,
      cookie: trustCookie,
      'x-loomward-csrf': trustCsrf,
      'x-loomward-tab-auth': trustTabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: '{}',
  });
  assert.equal(handoffRes.status, 200);
  const handoffTicket = handoffRes.json().ticket;
  assert.ok(handoffTicket);

  // Console Origin exchanges the single-use ticket into its own read-only session + tabToken.
  const consoleHome = await httpCall(dual.console.url, '/');
  let consoleCsrf = consoleHome.text.match(/<meta name="loomward-csrf" content="([^"]+)"/)?.[1];
  let consoleCookie = mergeCookieHeader('', consoleHome.headers['set-cookie']);

  const exchangeRes = await httpCall(dual.console.url, '/api/console/session/exchange', {
    method: 'POST',
    headers: {
      origin: dual.console.url,
      cookie: consoleCookie,
      'x-loomward-csrf': consoleCsrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ ticket: handoffTicket }),
  });
  assert.equal(exchangeRes.status, 200);
  const exJson = exchangeRes.json();
  consoleCsrf = exJson.csrfToken;
  const consoleTabToken = exJson.tabToken;
  consoleCookie = mergeCookieHeader(consoleCookie, exchangeRes.headers['set-cookie']);

  // Reusing the same handoff ticket must fail 401.
  const reuseRes = await httpCall(dual.console.url, '/api/console/session/exchange', {
    method: 'POST',
    headers: {
      origin: dual.console.url,
      cookie: consoleCookie,
      'x-loomward-csrf': consoleCsrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ ticket: handoffTicket }),
  });
  assert.equal(reuseRes.status, 401);

  // Per-tab isolation on Console Origin: cookie alone returns 401; with tabToken returns 200 and leaks zero secrets.
  assert.equal((await httpCall(dual.console.url, '/api/status', { headers: { cookie: consoleCookie } })).status, 401);
  const consoleStatus = await httpCall(dual.console.url, '/api/status', {
    headers: { cookie: consoleCookie, 'x-loomward-tab-auth': consoleTabToken },
  });
  assert.equal(consoleStatus.status, 200);
  assert.equal(consoleStatus.json().readOnly, true);
  assert.equal(consoleStatus.text.includes('CANARY-NEVER-EXPOSE'), false);

  // Console Origin MUST reject every privileged mutation even with valid Console session + CSRF + tabToken.
  for (const [pathname, payload] of [
    ['/api/capabilities', { fileWrite: false }],
    ['/api/approvals/review', { id: '12345678-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }],
    ['/api/approvals/approve', { id: '12345678-aaaa-4aaa-8aaa-aaaaaaaaaaaa', digest: 'a'.repeat(64) }],
    ['/api/approvals/reject', { id: '12345678-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }],
    ['/api/service', { action: 'restart' }],
    ['/api/mcp-servers/save', { id: 'evil', name: 'Evil', transport: 'stdio', command: 'echo' }],
    ['/api/auth/login/password', { password: strongPassword }],
    ['/api/trust/decide', { decisionId: 'd1', approved: true }],
  ]) {
    const blocked = await httpCall(dual.console.url, pathname, {
      method: 'POST',
      headers: {
        origin: dual.console.url,
        cookie: consoleCookie,
        'x-loomward-csrf': consoleCsrf,
        'x-loomward-tab-auth': consoleTabToken,
        'sec-fetch-site': 'same-origin',
        'content-type': 'application/json',
      },
      body: JSON.stringify(payload),
    });
    assert.equal(blocked.status, 403, `Expected 403 on Console Origin for ${pathname}`);
    assert.equal(blocked.json().code, 'TRUST_ORIGIN_REQUIRED');
  }

  // Open Console Origin SSE stream and verify real-time push via control.sock AND Trust Origin mutation.
  const sseChunks = [];
  const sseReq = http.get(dual.console.url + '/api/events', {
    headers: { cookie: consoleCookie, 'x-loomward-tab-auth': consoleTabToken },
  });
  t.after(() => sseReq.destroy());
  const [sseRes] = await once(sseReq, 'response');
  assert.equal(sseRes.statusCode, 200);
  sseRes.on('data', chunk => sseChunks.push(chunk.toString('utf8')));
  const sseEnded = once(sseRes, 'end', { signal: AbortSignal.timeout(5000) });

  if (dual.controlSocketPath) {
    const sockClient = connectControlSocket(dual.controlSocketPath);
    t.after(() => sockClient.close());
    await once(sockClient.socket, 'connect');
    sockClient.publish({ type: 'moderation.alert', ruleId: 'MOD-42', bridgeToken: 'CANARY-STRIP-ME' });
  } else {
    dual.controlChannel.publish({ type: 'moderation.alert', ruleId: 'MOD-42', bridgeToken: 'CANARY-STRIP-ME' });
  }

  // Also toggle fileWrite on Trust Origin and confirm Console SSE receives readonly update without polling.
  const capMut = await httpCall(dual.trust.url, '/api/capabilities', {
    method: 'POST',
    headers: {
      origin: dual.trust.url,
      cookie: trustCookie,
      'x-loomward-csrf': trustCsrf,
      'x-loomward-tab-auth': trustTabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ fileWrite: false }),
  });
  assert.equal(capMut.status, 200);
  await new Promise(r => setTimeout(r, 120));
  const combinedSse = sseChunks.join('');
  assert.match(combinedSse, /event: kernel/);
  assert.match(combinedSse, /moderation\.alert/);
  assert.equal(combinedSse.includes('CANARY-STRIP-ME'), false);
  assert.match(combinedSse, /"mountMode":"readonly"/);

  // Logging out on Trust Origin IMMEDIATELY revokes linked Console session and closes its SSE stream.
  const logoutRes = await httpCall(dual.trust.url, '/api/auth/logout', {
    method: 'POST',
    headers: {
      origin: dual.trust.url,
      cookie: trustCookie,
      'x-loomward-csrf': trustCsrf,
      'x-loomward-tab-auth': trustTabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: '{}',
  });
  assert.equal(logoutRes.status, 200);
  await sseEnded;
  assert.equal((await httpCall(dual.console.url, '/api/status', {
    headers: { cookie: consoleCookie, 'x-loomward-tab-auth': consoleTabToken },
  })).status, 401);
});

test('Trust Origin enforces WebAuthn PassKey ES256 and exact two-step approval review/approve', async t => {
  const { stateDir, workspace } = await makeTempState(t);

  const dual = await startDualOriginConsole({
    stateDir,
    runtimeRoot: REPO_ROOT,
    host: '127.0.0.1',
    consolePort: 0,
    trustPort: 0,
    pollIntervalMs: 0,
    passkeyDetector: () => ({ supported: true, reason: 'linux-fido2-hid' }),
    gatewayProbe: async () => ({ reachable: false, status: null, latencyMs: null }),
    dockerProbe: async () => ({ dockerOk: true, runningContainers: [] }),
    systemdProbe: async () => ({ supported: false, installed: false, enabled: false, active: false, linger: false }),
    serviceController: async () => {},
  });
  t.after(() => dual.close());

  const trustLocalhost = `http://localhost:${dual.trust.port}`;
  const home = await httpCall(trustLocalhost, '/', { headers: { host: `localhost:${dual.trust.port}` } });
  let csrf = home.text.match(/<meta name="loomward-csrf" content="([^"]+)"/)?.[1];
  let cookie = mergeCookieHeader('', home.headers['set-cookie']);

  const ticket = issueSetupTicketSync(stateDir, {
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: true, reason: 'linux-fido2-hid' }),
  });

  // Enroll virtual ES256 PassKey on Trust Origin.
  const optRes = await httpCall(trustLocalhost, '/api/auth/setup/passkey/options', {
    method: 'POST',
    headers: {
      host: `localhost:${dual.trust.port}`,
      origin: trustLocalhost,
      cookie,
      'x-loomward-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ setupToken: ticket.setupToken }),
  });
  assert.equal(optRes.status, 200);
  const optJson = optRes.json();
  const key = createVirtualEs256Passkey({ origin: trustLocalhost, rpId: 'localhost' });
  const verifyRes = await httpCall(trustLocalhost, '/api/auth/setup/passkey/verify', {
    method: 'POST',
    headers: {
      host: `localhost:${dual.trust.port}`,
      origin: trustLocalhost,
      cookie,
      'x-loomward-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      challengeId: optJson.challengeId,
      setupToken: ticket.setupToken,
      label: 'Trust Key',
      credential: key.register(optJson.publicKey.challenge),
    }),
  });
  assert.equal(verifyRes.status, 200);
  const verified = verifyRes.json();
  csrf = verified.csrfToken;
  const tabToken = verified.tabToken;
  cookie = mergeCookieHeader(cookie, verifyRes.headers['set-cookie']);

  // Place a valid pending approval request and execute exact 2-step review -> approve on Trust Origin.
  const reqId = '11111111-2222-4333-8444-555555555555';
  const createdAt = Date.now();
  const requestObj = {
    origin: 'https://bridge.example.test',
    authorization: { userId: 'owner', clientId: 'client-1', scope: ['computer:read'] },
    method: 'tools/call',
    params: { name: 'read_file', arguments: { path: '/workspace/README.md' } },
  };
  const pending = {
    id: reqId,
    hash: policyDigest(requestObj),
    createdAt,
    expiresAt: createdAt + 5 * 60 * 1000,
    request: requestObj,
  };
  await fs.mkdir(path.join(stateDir, 'approvals'), { mode: 0o700, recursive: true });
  await fs.writeFile(path.join(stateDir, 'approvals', `${reqId}.request.json`), JSON.stringify(pending), { mode: 0o600 });

  const reviewRes = await httpCall(trustLocalhost, '/api/approvals/review', {
    method: 'POST',
    headers: {
      host: `localhost:${dual.trust.port}`,
      origin: trustLocalhost,
      cookie,
      'x-loomward-csrf': csrf,
      'x-loomward-tab-auth': tabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ id: reqId }),
  });
  assert.equal(reviewRes.status, 200);
  const { digest } = reviewRes.json();
  assert.match(reviewRes.json().requestText, /README\.md/);

  const approveRes = await httpCall(trustLocalhost, '/api/approvals/approve', {
    method: 'POST',
    headers: {
      host: `localhost:${dual.trust.port}`,
      origin: trustLocalhost,
      cookie,
      'x-loomward-csrf': csrf,
      'x-loomward-tab-auth': tabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ id: reqId, digest }),
  });
  assert.equal(approveRes.status, 200);
  const approvedFile = JSON.parse(await fs.readFile(path.join(stateDir, 'approvals', `${reqId}.approved.json`), 'utf8'));
  assert.equal(approvedFile.hash, pending.hash);
});

test('Cordis kernel + Dual-Origin Console host an isolated standalone-style LLM Content Moderation plugin via declarative console:panel@1 and input/output hooks', async t => {
  const { stateDir, workspace } = await makeTempState(t);
  let inspectedCount = 0;
  let blockedCount = 0;

  const sandboxRuntime = {
    async handleRpc(body) {
      if (body.method === 'tools/list') return { jsonrpc: '2.0', id: body.id ?? null, result: { tools: [] } };
      if (body.method === 'tools/call') {
        if (body.params.name === 'computer_context') {
          return { jsonrpc: '2.0', id: body.id ?? null, result: { content: [{ type: 'text', text: 'raw output with PII_CANARY_123' }] } };
        }
      }
      return { jsonrpc: '2.0', id: body.id ?? null, result: {} };
    },
    async close() {},
  };

  const daemon = await startLoomWardDaemon({
    rootDir: REPO_ROOT,
    stateDir,
    origin: 'https://bridge.example.test',
    workspaceRoots: [workspace],
    sandboxRuntime,
    enableMcpHub: false,
    consoleConfig: {
      enabled: true,
      host: '127.0.0.1',
      consolePort: 0,
      trustPort: 0,
      pollIntervalMs: 0,
      passkeyDetector: () => ({ supported: false, reason: 'none' }),
      gatewayProbe: async () => ({ reachable: false, status: null, latencyMs: null }),
      dockerProbe: async () => ({ dockerOk: true, runningContainers: [] }),
      systemdProbe: async () => ({ supported: false, installed: false, enabled: false, active: false, linger: false }),
      serviceController: async () => {},
    },
  });
  t.after(() => daemon.stop());

  // Mount a loosely coupled out-of-process LLM content moderation plugin using only public contracts!
  await daemon.control.mountExtensionUnit({
    contract: {
      schemaVersion: 1,
      id: 'llm-moderation',
      kind: 'extension-plugin',
      version: '1.0.0',
      executionBoundary: 'out-of-process',
      provides: ['moderation:llm'],
      consumes: ['tool:invoke@1', 'console:panel@1'],
      registers: [{ slot: 'console:panel@1', name: 'llm-moderation' }],
      writes: {
        hooks: [
          { slot: 'tool:invoke@1', phase: 'before' },
          { slot: 'tool:invoke@1', phase: 'after' },
        ],
        intercepts: [],
        isolateProvides: [],
      },
    },
    trust: { autoApproveTrusted: true },
    load: () => ({
      name: 'llm-moderation',
      apply(ctx) {
        ctx.get('console:panel@1').register('llm-moderation', validateConsolePanelDecl({
          id: 'llm-moderation',
          title: 'LLM 内容审核引擎',
          subtitle: '零耦合可独立交付的输入/输出内容风控插件',
          category: 'moderation',
          order: 10,
          executionBoundary: 'out-of-process',
          getSnapshot: () => ({
            status: blockedCount > 0 ? 'warn' : 'ok',
            summary: [
              { label: '已审核', value: String(inspectedCount), tone: 'info' },
              { label: '已阻断', value: String(blockedCount), tone: blockedCount > 0 ? 'err' : 'ok' },
            ],
            table: { columns: ['阶段', '策略'], rows: [['input', 'block / escalate'], ['output', 'redact']] },
            links: [
              { label: '审核说明', href: 'https://example.test/moderation' },
              { label: 'BadLink', href: 'javascript:alert(1)' },
            ],
          }),
        }));

        const invokeSlot = ctx.get('tool:invoke@1');
        invokeSlot.hook('before', input => {
          inspectedCount += 1;
          const req = buildContentInspectRequest({
            stage: 'input',
            requestId: input.requestId,
            toolName: input.toolName,
            payload: input.body?.params?.arguments,
          });
          const raw = JSON.stringify(req.payload || {});
          if (raw.includes('PROHIBITED_CONTENT')) {
            blockedCount += 1;
            const v = validateContentInspectVerdict({
              protocolVersion: 1,
              decision: 'block',
              categories: ['safety.prohibited'],
              score: 0.99,
              ruleId: 'LLM-MOD-1',
              reason: 'Blocked by standalone LLM content moderation engine.',
            }, { stage: 'input' });
            throw new ToolBlockedError(v.reason, { code: 'MODERATION_BLOCKED', rule: v.ruleId });
          }
          if (raw.includes('ESCALATE_ME')) {
            const v = validateContentInspectVerdict({
              protocolVersion: 1,
              decision: 'escalate',
              categories: ['safety.review'],
              score: 0.65,
              ruleId: 'LLM-MOD-2',
            }, { stage: 'input' });
            if (v.decision === 'escalate') return { ...input, forceApproval: true };
          }
          return input;
        });

        invokeSlot.hook('after', output => {
          const text = output?.result?.content?.[0]?.text;
          if (typeof text === 'string' && text.includes('PII_CANARY_123')) {
            const v = validateContentInspectVerdict({
              protocolVersion: 1,
              decision: 'redact',
              categories: ['privacy.pii'],
              redactedPayload: text.replace('PII_CANARY_123', '[REDACTED_PII]'),
            }, { stage: 'output' });
            return applyOutputRedaction(output, v);
          }
          return output;
        });
      },
    }),
  });

  // 1. Input block stops execution before approval queue.
  const blockedRes = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file', arguments: { path: 'PROHIBITED_CONTENT.txt' } } },
    { requestId: 'mod_req_1' },
  );
  assert.equal(blockedRes.error.data.code, 'MODERATION_BLOCKED');

  // 2. Input escalate forces human approval EVEN on normally exempt computer_context!
  const escalatedRes = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'computer_context', arguments: { note: 'ESCALATE_ME' } } },
    { requestId: 'mod_req_2' },
  );
  assert.equal(escalatedRes.error.data.code, 'LOCAL_APPROVAL_REQUIRED');

  // 3. Output redaction sanitizes response cleanly before returning to caller.
  const safeRes = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'computer_context', arguments: {} } },
    { requestId: 'mod_req_3' },
  );
  assert.equal(safeRes.result.content[0].text, 'raw output with [REDACTED_PII]');

  // 4. Console Origin dynamically discovers & renders the declarative llm-moderation panel with safe link filtering!
  const trustSvc = daemon.control.getService('console:trust-origin');
  const consoleSvc = daemon.control.getService('console:loopback');
  assert.ok(trustSvc.url && consoleSvc.url);

  const ticket = issueSetupTicketSync(stateDir, {
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
  });
  const tHome = await httpCall(trustSvc.url, '/');
  let tCsrf = tHome.text.match(/<meta name="loomward-csrf" content="([^"]+)"/)?.[1];
  let tCookie = mergeCookieHeader('', tHome.headers['set-cookie']);
  const tSetup = await httpCall(trustSvc.url, '/api/auth/setup/password', {
    method: 'POST',
    headers: { origin: trustSvc.url, cookie: tCookie, 'x-loomward-csrf': tCsrf, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ setupToken: ticket.setupToken, password: 'Kx9!mP4#vR2@qL8$zW' }),
  });
  tCsrf = tSetup.json().csrfToken;
  const tTab = tSetup.json().tabToken;
  tCookie = mergeCookieHeader(tCookie, tSetup.headers['set-cookie']);

  const handoff = await httpCall(trustSvc.url, '/api/trust/issue-console-ticket', {
    method: 'POST',
    headers: { origin: trustSvc.url, cookie: tCookie, 'x-loomward-csrf': tCsrf, 'x-loomward-tab-auth': tTab, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: '{}',
  });
  const cHome = await httpCall(consoleSvc.url, '/');
  const cCsrf = cHome.text.match(/<meta name="loomward-csrf" content="([^"]+)"/)?.[1];
  let cCookie = mergeCookieHeader('', cHome.headers['set-cookie']);
  const cEx = await httpCall(consoleSvc.url, '/api/console/session/exchange', {
    method: 'POST',
    headers: { origin: consoleSvc.url, cookie: cCookie, 'x-loomward-csrf': cCsrf, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ ticket: handoff.json().ticket }),
  });
  const cTab = cEx.json().tabToken;
  cCookie = mergeCookieHeader(cCookie, cEx.headers['set-cookie']);

  const panelsRes = await httpCall(consoleSvc.url, '/api/panels', {
    headers: { cookie: cCookie, 'x-loomward-tab-auth': cTab },
  });
  assert.equal(panelsRes.status, 200);
  const panels = panelsRes.json().panels;
  assert.equal(panels.length, 1);
  assert.equal(panels[0].id, 'llm-moderation');
  assert.equal(panels[0].status, 'warn');
  assert.equal(panels[0].links.length, 1);
  assert.equal(panels[0].links[0].href, 'https://example.test/moderation');
  assert.deepEqual(panels[0].summary, [
    { label: '已审核', value: '3', tone: 'info' },
    { label: '已阻断', value: '1', tone: 'err' },
  ]);
});

test('control-channel refuses to overwrite an existing regular file at socketPath', { skip: process.platform === 'win32' }, async t => {
  const { createControlChannel } = await import('../src/control-channel.mjs');
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'lw-sock-'));
  await fs.chmod(tmpDir, 0o700);
  t.after(() => fs.rm(tmpDir, { recursive: true, force: true }));

  const sentinel = path.join(tmpDir, 'control.sock');
  await fs.writeFile(sentinel, 'do-not-delete', { mode: 0o600 });

  const channel = createControlChannel({ socketPath: sentinel });
  t.after(() => channel.close());

  await assert.rejects(() => channel.startSocketServer(), /non-socket/i);
  assert.equal(await fs.readFile(sentinel, 'utf8'), 'do-not-delete');
});

test('R6-H2/R6-H4: built console assets enforce allowlist, safe URL filtering, and never echo handoff tickets into Trust DOM', async () => {
  const { loadBuiltAsset } = await import('../src/html.mjs');
  const { isSafeNavigationUrl } = await import('../web/shared/client.mjs');

  assert.throws(() => loadBuiltAsset('../package.json'), /Unknown console asset/);
  const trustJs = loadBuiltAsset('trust.js');
  assert.equal(trustJs.includes('请手动访问：${issued.handoffUrl}'), false);
  assert.match(trustJs, /noopener,noreferrer/);

  assert.equal(isSafeNavigationUrl('https://example.test/ok'), true);
  assert.equal(isSafeNavigationUrl('http://localhost:18797/#ticket=abc'), true);
  assert.equal(isSafeNavigationUrl('javascript:alert(1)'), false);
  assert.equal(isSafeNavigationUrl('data:text/html,<script>alert(1)</script>'), false);
  assert.equal(isSafeNavigationUrl('//evil.example/path', { allowRelative: true }), false);
  assert.equal(isSafeNavigationUrl('/\\evil.example/path', { allowRelative: true }), false);
  assert.equal(isSafeNavigationUrl('/panels/overview', { allowRelative: true }), true);
});

test('Round 7 console hardening: tab settings preserves snapshot race, startDualOriginConsole cleans up control socket on bind failure, and Console mirrors requirePasskey', async t => {
  const { startDualOriginConsole } = await import('../src/server.mjs');
  const { stateDir, workspace } = await makeTempState(t);
  const sockPath = path.join(stateDir, 'bind-fail-control.sock');
  const blocker = http.createServer();
  await new Promise(resolve => blocker.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => blocker.close(resolve)));
  const occupiedPort = blocker.address().port;

  await assert.rejects(
    () => startDualOriginConsole({
      stateDir,
      workspaceRoots: [workspace],
      trustPort: occupiedPort,
      consolePort: 0,
      requirePrivateState: true,
      enableControlSocket: true,
      controlSocketPath: sockPath,
    }),
    /EADDRINUSE|listen/i,
  );
  await assert.rejects(() => fs.access(sockPath), { code: 'ENOENT' });

  const dual = await startDualOriginConsole({
    stateDir,
    workspaceRoots: [workspace],
    trustPort: 0,
    consolePort: 0,
    requirePrivateState: true,
    enableControlSocket: false,
    passkeyDetector: () => ({ supported: true, reason: 'linux-fido2-hid' }),
    statusLoader: async () => ({
      security: {
        initialized: true,
        mode: 'passkey',
        passkeyRequired: true,
        passkeyCount: 1,
        sessionPersistence: 'browser',
      },
      approvals: { pendingCount: 0, items: [] },
    }),
    dockerProbe: async () => ({ dockerOk: true, runningContainers: [] }),
    systemdProbe: async () => ({ supported: false, installed: false, enabled: false, active: false, linger: false }),
    serviceController: async () => {},
  });
  t.after(() => dual.close());

  const trustLocalhost = `http://localhost:${dual.trust.port}`;
  const home = await httpCall(trustLocalhost, '/', { headers: { host: `localhost:${dual.trust.port}` } });
  let csrf = home.text.match(/<meta name="loomward-csrf" content="([^"]+)"/)?.[1];
  let cookie = mergeCookieHeader('', home.headers['set-cookie']);
  const ticket = issueSetupTicketSync(stateDir, {
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: true, reason: 'linux-fido2-hid' }),
  });
  const optRes = await httpCall(trustLocalhost, '/api/auth/setup/passkey/options', {
    method: 'POST',
    headers: { host: `localhost:${dual.trust.port}`, origin: trustLocalhost, cookie, 'x-loomward-csrf': csrf, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ setupToken: ticket.setupToken }),
  });
  const optJson = optRes.json();
  const key = createVirtualEs256Passkey({ origin: trustLocalhost, rpId: 'localhost' });
  const verifyRes = await httpCall(trustLocalhost, '/api/auth/setup/passkey/verify', {
    method: 'POST',
    headers: { host: `localhost:${dual.trust.port}`, origin: trustLocalhost, cookie, 'x-loomward-csrf': csrf, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ challengeId: optJson.challengeId, setupToken: ticket.setupToken, label: 'K', credential: key.register(optJson.publicKey.challenge) }),
  });
  const verified = verifyRes.json();
  csrf = verified.csrfToken;
  let tTab = verified.tabToken;
  cookie = mergeCookieHeader(cookie, verifyRes.headers['set-cookie']);

  // Verify browser -> tab settings rotates tabToken reliably and still authorizes handoff + Console requirePasskey=true.
  const toBrowser = await httpCall(trustLocalhost, '/api/auth/settings', {
    method: 'POST',
    headers: { host: `localhost:${dual.trust.port}`, origin: trustLocalhost, cookie, 'x-loomward-csrf': csrf, 'x-loomward-tab-auth': tTab, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ sessionPersistence: 'browser' }),
  });
  assert.equal(toBrowser.status, 200);
  const toTab = await httpCall(trustLocalhost, '/api/auth/settings', {
    method: 'POST',
    headers: { host: `localhost:${dual.trust.port}`, origin: trustLocalhost, cookie, 'x-loomward-csrf': csrf, 'x-loomward-tab-auth': tTab, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ sessionPersistence: 'tab' }),
  });
  assert.equal(toTab.status, 200);
  const rotatedTab = toTab.json().tabToken;
  assert.ok(rotatedTab && rotatedTab !== tTab);

  const handoff = await httpCall(trustLocalhost, '/api/trust/issue-console-ticket', {
    method: 'POST',
    headers: { host: `localhost:${dual.trust.port}`, origin: trustLocalhost, cookie, 'x-loomward-csrf': csrf, 'x-loomward-tab-auth': rotatedTab, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: '{}',
  });
  assert.equal(handoff.status, 200);

  const cHome = await httpCall(dual.console.url, '/');
  const cCsrf = cHome.text.match(/<meta name="loomward-csrf" content="([^"]+)"/)?.[1];
  let cCookie = mergeCookieHeader('', cHome.headers['set-cookie']);
  const cEx = await httpCall(dual.console.url, '/api/console/session/exchange', {
    method: 'POST',
    headers: { origin: dual.console.url, cookie: cCookie, 'x-loomward-csrf': cCsrf, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ ticket: handoff.json().ticket }),
  });
  cCookie = mergeCookieHeader(cCookie, cEx.headers['set-cookie']);
  const cStatus = await httpCall(dual.console.url, '/api/status', {
    headers: { cookie: cCookie, 'x-loomward-tab-auth': cEx.json().tabToken },
  });
  assert.equal(cStatus.status, 200);
  assert.equal(cStatus.json().security.requirePasskey, true);
});
