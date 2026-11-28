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
import { startUnifiedConsole, connectControlSocket } from '../src/index.mjs';
import { startLoomWardDaemon } from '../../host/src/daemon.mjs';
import { issueSetupTicketSync } from '../../../local/webui-auth.mjs';
import { toBase64Url } from '../../../local/webauthn.mjs';
import { digest as policyDigest } from '../../../local/request-policy.mjs';
import {
  DEFAULT_OLLAMA_ORIGIN,
  OLLAMA_RECOMMENDED_MODELS,
  assertValidOllamaModelTag,
  sanitizedOllamaEnv,
  normalizeOllamaEndpoint,
  ollamaStreamPull,
  startOllamaDaemon,
  createOllamaController,
} from '../../../local/ollama.mjs';

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

test('Unified Console enforces loopback security, tab isolation, logout revocation, and control.sock SSE push', async t => {
  const { stateDir, workspace } = await makeTempState(t);

  await assert.rejects(() => startUnifiedConsole({
    stateDir,
    runtimeRoot: REPO_ROOT,
    host: '0.0.0.0',
    consolePort: 0,
  }), /loopback/i);

  const consoleSrv = await startUnifiedConsole({
    stateDir,
    runtimeRoot: REPO_ROOT,
    host: '127.0.0.1',
    consolePort: 0,
    pollIntervalMs: 0,
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
    gatewayProbe: async () => ({ reachable: false, status: null, latencyMs: null }),
    dockerProbe: async () => ({ dockerOk: true, runningContainers: [] }),
    systemdProbe: async () => ({ supported: false, installed: false, enabled: false, active: false, linger: false }),
    serviceController: async () => {},
  });
  t.after(() => consoleSrv.close());

  const home = await httpCall(consoleSrv.url, '/');
  assert.equal(home.status, 200);
  const navHome = await httpCall(consoleSrv.url, '/', {
    headers: { 'sec-fetch-site': 'same-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' },
  });
  assert.equal(navHome.status, 200);
  const crossSiteScript = await httpCall(consoleSrv.url, '/console.js', {
    headers: { 'sec-fetch-site': 'same-site', 'sec-fetch-mode': 'no-cors', 'sec-fetch-dest': 'script' },
  });
  assert.equal(crossSiteScript.status, 403);
  assert.equal(home.headers['cross-origin-resource-policy'], 'same-origin');
  assert.match(home.headers['content-security-policy'], /script-src 'self'/);
  let csrf = home.text.match(/<meta name="loomward-csrf" content="([^"]+)"/)?.[1];
  let cookie = mergeCookieHeader('', home.headers['set-cookie']);
  assert.ok(csrf && cookie.includes('loomward_console_pre='));
  assert.equal((await httpCall(consoleSrv.url, '/console.js', { headers: { 'sec-fetch-site': 'same-origin' } })).status, 200);
  assert.equal((await httpCall(consoleSrv.url, '/trust.js', { headers: { 'sec-fetch-site': 'same-origin' } })).status, 401);

  const ticket = issueSetupTicketSync(stateDir, {
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
  });
  const strongPassword = 'Kx9!mP4#vR2@qL8$zW';
  const setupRes = await httpCall(consoleSrv.url, '/api/auth/setup/password', {
    method: 'POST',
    headers: {
      origin: consoleSrv.url,
      cookie,
      'x-loomward-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ setupToken: ticket.setupToken, password: strongPassword }),
  });
  assert.equal(setupRes.status, 200);
  const setupJson = setupRes.json();
  csrf = setupJson.csrfToken;
  const tabToken = setupJson.tabToken;
  cookie = mergeCookieHeader(cookie, setupRes.headers['set-cookie']);

  // Reject cross-origin mutation pretending to come from another port.
  const crossOriginMut = await httpCall(consoleSrv.url, '/api/capabilities', {
    method: 'POST',
    headers: {
      origin: 'http://127.0.0.1:65500',
      cookie,
      'x-loomward-csrf': csrf,
      'x-loomward-tab-auth': tabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ fileWrite: false }),
  });
  assert.equal(crossOriginMut.status, 403);

  // Per-tab isolation: cookie alone returns 401; with tabToken returns 200 and leaks zero secrets.
  assert.equal((await httpCall(consoleSrv.url, '/api/status', { headers: { cookie } })).status, 401);
  const statusRes = await httpCall(consoleSrv.url, '/api/status', {
    headers: { cookie, 'x-loomward-tab-auth': tabToken },
  });
  assert.equal(statusRes.status, 200);
  assert.equal(statusRes.json().originRole, 'unified');
  assert.equal(statusRes.text.includes('CANARY-NEVER-EXPOSE'), false);

  // Open unified SSE stream and verify real-time push via control.sock AND capability mutation.
  const sseChunks = [];
  const sseReq = http.get(consoleSrv.url + '/api/events', {
    headers: { cookie, 'x-loomward-tab-auth': tabToken },
  });
  t.after(() => sseReq.destroy());
  const [sseRes] = await once(sseReq, 'response');
  assert.equal(sseRes.statusCode, 200);
  sseRes.on('data', chunk => sseChunks.push(chunk.toString('utf8')));
  const sseEnded = once(sseRes, 'end', { signal: AbortSignal.timeout(5000) });

  if (consoleSrv.controlSocketPath) {
    const sockClient = connectControlSocket(consoleSrv.controlSocketPath);
    t.after(() => sockClient.close());
    await once(sockClient.socket, 'connect');
    sockClient.publish({ type: 'moderation.alert', ruleId: 'MOD-42', bridgeToken: 'CANARY-STRIP-ME' });
  } else {
    consoleSrv.controlChannel.publish({ type: 'moderation.alert', ruleId: 'MOD-42', bridgeToken: 'CANARY-STRIP-ME' });
  }

  const capMut = await httpCall(consoleSrv.url, '/api/capabilities', {
    method: 'POST',
    headers: {
      origin: consoleSrv.url,
      cookie,
      'x-loomward-csrf': csrf,
      'x-loomward-tab-auth': tabToken,
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

  // Logging out IMMEDIATELY closes active SSE stream and revokes session.
  const logoutRes = await httpCall(consoleSrv.url, '/api/auth/logout', {
    method: 'POST',
    headers: {
      origin: consoleSrv.url,
      cookie,
      'x-loomward-csrf': csrf,
      'x-loomward-tab-auth': tabToken,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: '{}',
  });
  assert.equal(logoutRes.status, 200);
  await sseEnded;
  assert.equal((await httpCall(consoleSrv.url, '/api/status', {
    headers: { cookie, 'x-loomward-tab-auth': tabToken },
  })).status, 401);
});

test('Unified Console enforces WebAuthn PassKey ES256 and exact two-step approval review/approve', async t => {
  const { stateDir, workspace } = await makeTempState(t);

  const consoleSrv = await startUnifiedConsole({
    stateDir,
    runtimeRoot: REPO_ROOT,
    host: '127.0.0.1',
    consolePort: 0,
    pollIntervalMs: 0,
    passkeyDetector: () => ({ supported: true, reason: 'linux-fido2-hid' }),
    gatewayProbe: async () => ({ reachable: false, status: null, latencyMs: null }),
    dockerProbe: async () => ({ dockerOk: true, runningContainers: [] }),
    systemdProbe: async () => ({ supported: false, installed: false, enabled: false, active: false, linger: false }),
    serviceController: async () => {},
  });
  t.after(() => consoleSrv.close());

  const consoleLocalhost = `http://localhost:${consoleSrv.port}`;
  const home = await httpCall(consoleLocalhost, '/', { headers: { host: `localhost:${consoleSrv.port}` } });
  let csrf = home.text.match(/<meta name="loomward-csrf" content="([^"]+)"/)?.[1];
  let cookie = mergeCookieHeader('', home.headers['set-cookie']);

  const ticket = issueSetupTicketSync(stateDir, {
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: true, reason: 'linux-fido2-hid' }),
  });

  const optRes = await httpCall(consoleLocalhost, '/api/auth/setup/passkey/options', {
    method: 'POST',
    headers: {
      host: `localhost:${consoleSrv.port}`,
      origin: consoleLocalhost,
      cookie,
      'x-loomward-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ setupToken: ticket.setupToken }),
  });
  assert.equal(optRes.status, 200);
  const optJson = optRes.json();
  const key = createVirtualEs256Passkey({ origin: consoleLocalhost, rpId: 'localhost' });
  const verifyRes = await httpCall(consoleLocalhost, '/api/auth/setup/passkey/verify', {
    method: 'POST',
    headers: {
      host: `localhost:${consoleSrv.port}`,
      origin: consoleLocalhost,
      cookie,
      'x-loomward-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      challengeId: optJson.challengeId,
      setupToken: ticket.setupToken,
      label: 'Console Key',
      credential: key.register(optJson.publicKey.challenge),
    }),
  });
  assert.equal(verifyRes.status, 200);
  const verified = verifyRes.json();
  csrf = verified.csrfToken;
  const tabToken = verified.tabToken;
  cookie = mergeCookieHeader(cookie, verifyRes.headers['set-cookie']);

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

  const reviewRes = await httpCall(consoleLocalhost, '/api/approvals/review', {
    method: 'POST',
    headers: {
      host: `localhost:${consoleSrv.port}`,
      origin: consoleLocalhost,
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

  const approveRes = await httpCall(consoleLocalhost, '/api/approvals/approve', {
    method: 'POST',
    headers: {
      host: `localhost:${consoleSrv.port}`,
      origin: consoleLocalhost,
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

test('Cordis kernel + Unified Console host an isolated standalone-style LLM Content Moderation plugin via declarative console:panel@1 and input/output hooks', async t => {
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
      pollIntervalMs: 0,
      passkeyDetector: () => ({ supported: false, reason: 'none' }),
      gatewayProbe: async () => ({ reachable: false, status: null, latencyMs: null }),
      dockerProbe: async () => ({ dockerOk: true, runningContainers: [] }),
      systemdProbe: async () => ({ supported: false, installed: false, enabled: false, active: false, linger: false }),
      serviceController: async () => {},
    },
  });
  t.after(() => daemon.stop());

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

  const blockedRes = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file', arguments: { path: 'PROHIBITED_CONTENT.txt' } } },
    { requestId: 'mod_req_1' },
  );
  assert.equal(blockedRes.error.data.code, 'MODERATION_BLOCKED');

  const escalatedRes = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'computer_context', arguments: { note: 'ESCALATE_ME' } } },
    { requestId: 'mod_req_2' },
  );
  assert.equal(escalatedRes.error.data.code, 'LOCAL_APPROVAL_REQUIRED');

  const safeRes = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'computer_context', arguments: {} } },
    { requestId: 'mod_req_3' },
  );
  assert.equal(safeRes.result.content[0].text, 'raw output with [REDACTED_PII]');

  const consoleSvc = daemon.control.getService('console:loopback');
  assert.ok(consoleSvc?.url);
  assert.equal(daemon.control.getService('console:trust-origin'), undefined);

  const ticket = issueSetupTicketSync(stateDir, {
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
  });
  const home = await httpCall(consoleSvc.url, '/');
  let csrf = home.text.match(/<meta name="loomward-csrf" content="([^"]+)"/)?.[1];
  let cookie = mergeCookieHeader('', home.headers['set-cookie']);
  const setup = await httpCall(consoleSvc.url, '/api/auth/setup/password', {
    method: 'POST',
    headers: { origin: consoleSvc.url, cookie, 'x-loomward-csrf': csrf, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ setupToken: ticket.setupToken, password: 'Kx9!mP4#vR2@qL8$zW' }),
  });
  csrf = setup.json().csrfToken;
  const tab = setup.json().tabToken;
  cookie = mergeCookieHeader(cookie, setup.headers['set-cookie']);

  const panelsRes = await httpCall(consoleSvc.url, '/api/panels', {
    headers: { cookie, 'x-loomward-tab-auth': tab },
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

test('built console assets enforce allowlist, safe URL filtering, and zero legacy handoff tickets in bundle', async () => {
  const { loadBuiltAsset } = await import('../src/html.mjs');
  const { isSafeNavigationUrl } = await import('../web/shared/client.mjs');

  assert.throws(() => loadBuiltAsset('../package.json'), /Unknown console asset/);
  assert.throws(() => loadBuiltAsset('trust.js'), /Unknown console asset/);
  const consoleJs = loadBuiltAsset('console.js');
  const consoleCss = loadBuiltAsset('console.css');
  assert.equal(consoleJs.includes('issue-console-ticket'), false);
  assert.match(consoleJs, /noopener noreferrer/);
  assert.match(consoleJs, /lw-svg-diagram/);
  assert.match(consoleJs, /lw-radio-item/);
  assert.match(consoleJs, /lw-switch-pill/);
  assert.match(consoleJs, /lw-metric-ledger/);
  assert.match(consoleJs, /lw-meta-chips/);
  assert.match(consoleCss, /lw-svg-pulse/);
  assert.match(consoleCss, /lw-select-box/);
  assert.match(consoleCss, /lw-approval-row/);

  assert.equal(isSafeNavigationUrl('https://example.test/ok'), true);
  assert.equal(isSafeNavigationUrl('http://localhost:18797/#overview'), true);
  assert.equal(isSafeNavigationUrl('javascript:alert(1)'), false);
  assert.equal(isSafeNavigationUrl('data:text/html,<script>alert(1)</script>'), false);
  assert.equal(isSafeNavigationUrl('//evil.example/path', { allowRelative: true }), false);
  assert.equal(isSafeNavigationUrl('/\\evil.example/path', { allowRelative: true }), false);
  assert.equal(isSafeNavigationUrl('/panels/overview', { allowRelative: true }), true);
});

test('unified console hardening: tab settings preserves snapshot race, cleans up control socket on bind failure, and mirrors requirePasskey', async t => {
  const { startUnifiedConsole: startConsole } = await import('../src/server.mjs');
  const { stateDir, workspace } = await makeTempState(t);
  const sockPath = path.join(stateDir, 'bind-fail-control.sock');
  const blocker = http.createServer();
  await new Promise(resolve => blocker.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => blocker.close(resolve)));
  const occupiedPort = blocker.address().port;

  await assert.rejects(
    () => startConsole({
      stateDir,
      workspaceRoots: [workspace],
      consolePort: occupiedPort,
      requirePrivateState: true,
      enableControlSocket: true,
      controlSocketPath: sockPath,
    }),
    /EADDRINUSE|listen/i,
  );
  await assert.rejects(() => fs.access(sockPath), { code: 'ENOENT' });

  const consoleSrv = await startConsole({
    stateDir,
    workspaceRoots: [workspace],
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
  t.after(() => consoleSrv.close());

  const consoleLocalhost = `http://localhost:${consoleSrv.port}`;
  const home = await httpCall(consoleLocalhost, '/', { headers: { host: `localhost:${consoleSrv.port}` } });
  let csrf = home.text.match(/<meta name="loomward-csrf" content="([^"]+)"/)?.[1];
  let cookie = mergeCookieHeader('', home.headers['set-cookie']);
  const ticket = issueSetupTicketSync(stateDir, {
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: true, reason: 'linux-fido2-hid' }),
  });
  const optRes = await httpCall(consoleLocalhost, '/api/auth/setup/passkey/options', {
    method: 'POST',
    headers: { host: `localhost:${consoleSrv.port}`, origin: consoleLocalhost, cookie, 'x-loomward-csrf': csrf, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ setupToken: ticket.setupToken }),
  });
  const optJson = optRes.json();
  const key = createVirtualEs256Passkey({ origin: consoleLocalhost, rpId: 'localhost' });
  const verifyRes = await httpCall(consoleLocalhost, '/api/auth/setup/passkey/verify', {
    method: 'POST',
    headers: { host: `localhost:${consoleSrv.port}`, origin: consoleLocalhost, cookie, 'x-loomward-csrf': csrf, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ challengeId: optJson.challengeId, setupToken: ticket.setupToken, label: 'K', credential: key.register(optJson.publicKey.challenge) }),
  });
  const verified = verifyRes.json();
  csrf = verified.csrfToken;
  const tabToken = verified.tabToken;
  cookie = mergeCookieHeader(cookie, verifyRes.headers['set-cookie']);

  const toBrowser = await httpCall(consoleLocalhost, '/api/auth/settings', {
    method: 'POST',
    headers: { host: `localhost:${consoleSrv.port}`, origin: consoleLocalhost, cookie, 'x-loomward-csrf': csrf, 'x-loomward-tab-auth': tabToken, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ sessionPersistence: 'browser' }),
  });
  assert.equal(toBrowser.status, 200);
  const toTab = await httpCall(consoleLocalhost, '/api/auth/settings', {
    method: 'POST',
    headers: { host: `localhost:${consoleSrv.port}`, origin: consoleLocalhost, cookie, 'x-loomward-csrf': csrf, 'x-loomward-tab-auth': tabToken, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ sessionPersistence: 'tab' }),
  });
  assert.equal(toTab.status, 200);
  const rotatedTab = toTab.json().tabToken;
  assert.ok(rotatedTab && rotatedTab !== tabToken);

  const statusRes = await httpCall(consoleLocalhost, '/api/status', {
    headers: { host: `localhost:${consoleSrv.port}`, cookie, 'x-loomward-tab-auth': rotatedTab },
  });
  assert.equal(statusRes.status, 200);
  assert.equal(statusRes.json().security.requirePasskey, true);

  const { upsertMcpServerSync } = await import('../../../local/mcp-registry.mjs');
  upsertMcpServerSync(stateDir, {
    id: 'r8_slow_probe',
    name: 'Slow Probe',
    transport: 'stdio',
    command: process.execPath,
    args: ['-e', 'setTimeout(() => process.exit(1), 400)'],
    timeoutMs: 3000,
  }, { workspaceRoots: [workspace] });

  const probeHeaders = {
    host: `localhost:${consoleSrv.port}`,
    origin: consoleLocalhost,
    cookie,
    'x-loomward-csrf': csrf,
    'x-loomward-tab-auth': rotatedTab,
    'sec-fetch-site': 'same-origin',
    'content-type': 'application/json',
  };
  const pSlow1 = httpCall(consoleLocalhost, '/api/mcp-servers/probe', {
    method: 'POST',
    headers: probeHeaders,
    body: JSON.stringify({ id: 'r8_slow_probe' }),
  });
  await new Promise(resolve => setTimeout(resolve, 40));
  const pSlow2 = await httpCall(consoleLocalhost, '/api/mcp-servers/probe', {
    method: 'POST',
    headers: probeHeaders,
    body: JSON.stringify({ id: 'r8_slow_probe' }),
  });
  assert.equal(pSlow2.status, 409);
  const probe1Res = await pSlow1;
  assert.equal(probe1Res.status, 200);
  const probe1Json = probe1Res.json();
  assert.equal(probe1Json.probe?.ok ?? probe1Json.server?.lastProbe?.ok, false);
});

test('Unified Console /api/mcp-servers/save and /import enforce bounded probing, secret redaction, 409 preservation, and persistence error propagation', async t => {
  const { stateDir, workspace } = await makeTempState(t);
  const { mcpServersFilePath, readMcpServersSync } = await import('../../../local/mcp-registry.mjs');

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
  const multiHoldAllStarted = new Promise(resolve => { multiHoldAllStartedResolve = resolve; });
  let multiHoldReleaseResolve;
  const multiHoldRelease = new Promise(resolve => { multiHoldReleaseResolve = resolve; });
  let savedBackupForCorrupt = null;

  const consoleSrv = await startUnifiedConsole({
    stateDir,
    runtimeRoot: REPO_ROOT,
    host: '127.0.0.1',
    consolePort: 0,
    pollIntervalMs: 0,
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
    gatewayProbe: async () => ({ reachable: false, status: null, latencyMs: null }),
    dockerProbe: async () => ({ dockerOk: true, runningContainers: [] }),
    systemdProbe: async () => ({ supported: false, installed: false, enabled: false, active: false, linger: false }),
    serviceController: async () => {},
    mcpProber: async srv => {
      if (proberMode === 'hold_all_3' && srv.id.startsWith('hold_')) {
        multiHoldCount += 1;
        if (multiHoldCount === 3) multiHoldAllStartedResolve();
        await multiHoldRelease;
        return { ok: true, latencyMs: 5, tools: [] };
      }
      if (proberMode === 'hold_on_busy' && srv.id === 'imp_busy') {
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
      if (srv.id === 'save_throw' || srv.id === 'imp_throw') {
        const secret = srv.env?.API_TOKEN || srv.headers?.Authorization || 'Bearer CONSOLE_FALLBACK_SECRET_99';
        throw new Error(`Upstream handshake failed with ${secret}`);
      }
      return {
        ok: true,
        latencyMs: 7,
        tools: [{ name: `${srv.id}_tool`, inputSchema: { type: 'object', properties: {} } }],
      };
    },
  });
  t.after(() => consoleSrv.close());

  const home = await httpCall(consoleSrv.url, '/');
  let csrf = home.text.match(/<meta name="loomward-csrf" content="([^"]+)"/)?.[1];
  let cookie = mergeCookieHeader('', home.headers['set-cookie']);
  const ticket = issueSetupTicketSync(stateDir, {
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
  });
  const setupRes = await httpCall(consoleSrv.url, '/api/auth/setup/password', {
    method: 'POST',
    headers: {
      origin: consoleSrv.url,
      cookie,
      'x-loomward-csrf': csrf,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ setupToken: ticket.setupToken, password: 'Console!Strong#2026Aa' }),
  });
  assert.equal(setupRes.status, 200);
  csrf = setupRes.json().csrfToken;
  const tabToken = setupRes.json().tabToken;
  cookie = mergeCookieHeader(cookie, setupRes.headers['set-cookie']);

  const authHeaders = {
    origin: consoleSrv.url,
    cookie,
    'x-loomward-csrf': csrf,
    'x-loomward-tab-auth': tabToken,
    'sec-fetch-site': 'same-origin',
    'content-type': 'application/json',
  };

  const saveThrowRes = await httpCall(consoleSrv.url, '/api/mcp-servers/save', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      id: 'save_throw',
      name: 'Save Throw',
      transport: 'stdio',
      command: process.execPath,
      args: ['-v'],
      env: { API_TOKEN: 'CONSOLE_SAVE_CANARY_4242' },
      probe: true,
    }),
  });
  assert.equal(saveThrowRes.status, 200);
  assert.equal(saveThrowRes.text.includes('CONSOLE_SAVE_CANARY_4242'), false);
  const saveThrowJson = saveThrowRes.json();
  assert.equal(saveThrowJson.ok, true);
  assert.equal(saveThrowJson.probe.ok, false);
  assert.match(saveThrowJson.probe.error, /\[REDACTED\]/);
  assert.equal(saveThrowJson.server.lastProbeOk, false);
  const diskAfterSaveThrow = readMcpServersSync(stateDir, { workspaceRoots: [workspace] }).servers.find(s => s.id === 'save_throw');
  assert.equal(diskAfterSaveThrow.lastProbeOk, false);
  assert.match(diskAfterSaveThrow.lastProbeError, /\[REDACTED\]/);
  assert.equal(diskAfterSaveThrow.lastProbeError.includes('CONSOLE_SAVE_CANARY_4242'), false);

  const seedBusy = await httpCall(consoleSrv.url, '/api/mcp-servers/save', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      id: 'imp_busy',
      name: 'Busy Server',
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
  const inFlightProbe = httpCall(consoleSrv.url, '/api/mcp-servers/probe', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ id: 'imp_busy' }),
  });
  await hold.started;

  const saveDuringConflict = await httpCall(consoleSrv.url, '/api/mcp-servers/save', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      id: 'imp_busy',
      name: 'Busy Server Renamed',
      transport: 'stdio',
      command: process.execPath,
      args: ['-v'],
      probe: true,
    }),
  });
  assert.equal(saveDuringConflict.status, 200);
  assert.equal(saveDuringConflict.json().ok, true);
  assert.equal(saveDuringConflict.json().server.name, 'Busy Server Renamed');
  assert.equal(saveDuringConflict.json().probe.ok, false);
  assert.match(saveDuringConflict.json().probe.error, /already in progress/);
  assert.equal(readMcpServersSync(stateDir, { workspaceRoots: [workspace] }).servers.find(s => s.id === 'imp_busy').lastProbeOk, true);

  const importRes = await httpCall(consoleSrv.url, '/api/mcp-servers/import', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      probe: true,
      json: JSON.stringify({
        mcpServers: {
          imp_busy: { name: 'Busy Server Renamed', command: process.execPath, args: ['-v'] },
          imp_throw: { command: process.execPath, args: ['-v'], env: { API_TOKEN: 'CONSOLE_IMP_CANARY_8888' } },
          imp_ok: { command: process.execPath, args: ['-v'] },
        },
      }),
    }),
  });
  assert.equal(importRes.status, 200);
  assert.equal(importRes.text.includes('CONSOLE_IMP_CANARY_8888'), false);
  const importJson = importRes.json();
  assert.deepEqual(importJson.importedIds.sort(), ['imp_busy', 'imp_ok', 'imp_throw']);
  assert.equal(importJson.probes.imp_busy.ok, false);
  assert.equal(importJson.probes.imp_busy.status, 409);
  assert.match(importJson.probes.imp_busy.error, /already in progress/);
  assert.equal(importJson.probes.imp_throw.ok, false);
  assert.match(importJson.probes.imp_throw.error, /\[REDACTED\]/);
  assert.equal(importJson.probes.imp_ok.ok, true);
  assert.equal(importJson.probes.imp_ok.toolCount, 1);

  const diskAfterImport = readMcpServersSync(stateDir, { workspaceRoots: [workspace] }).servers;
  assert.equal(diskAfterImport.find(s => s.id === 'imp_busy').lastProbeOk, true);
  assert.equal(diskAfterImport.find(s => s.id === 'imp_throw').lastProbeOk, false);
  assert.match(diskAfterImport.find(s => s.id === 'imp_throw').lastProbeError, /\[REDACTED\]/);
  assert.equal(diskAfterImport.find(s => s.id === 'imp_ok').lastProbeOk, true);

  holdReleaseResolve();
  await inFlightProbe;
  proberMode = 'ok';

  for (const id of ['hold_1', 'hold_2', 'hold_3']) {
    const seeded = await httpCall(consoleSrv.url, '/api/mcp-servers/save', {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ id, name: id, transport: 'stdio', command: process.execPath, args: ['-v'] }),
    });
    assert.equal(seeded.status, 200);
  }
  proberMode = 'hold_all_3';
  const threeProbes = ['hold_1', 'hold_2', 'hold_3'].map(id => httpCall(consoleSrv.url, '/api/mcp-servers/probe', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ id }),
  }));
  await multiHoldAllStarted;
  const saveOn429 = await httpCall(consoleSrv.url, '/api/mcp-servers/save', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      id: 'imp_ok',
      name: 'Imp Ok 429',
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
  assert.equal(readMcpServersSync(stateDir, { workspaceRoots: [workspace] }).servers.find(s => s.id === 'imp_ok').lastProbeOk, true);
  multiHoldReleaseResolve();
  await Promise.all(threeProbes);
  proberMode = 'ok';

  proberMode = 'corrupt_registry';
  const saveWriteErr = await httpCall(consoleSrv.url, '/api/mcp-servers/save', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      id: 'imp_ok',
      name: 'Imp Ok',
      transport: 'stdio',
      command: process.execPath,
      args: ['-v'],
      probe: true,
    }),
  });
  assert.equal(saveWriteErr.status, 500);
  await fs.writeFile(mcpServersFilePath(stateDir), savedBackupForCorrupt, { mode: 0o600 });

  const importWriteErr = await httpCall(consoleSrv.url, '/api/mcp-servers/import', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      probe: true,
      json: JSON.stringify({
        mcpServers: {
          imp_ok: { command: process.execPath, args: ['-v'] },
        },
      }),
    }),
  });
  assert.equal(importWriteErr.status, 500);
  await fs.writeFile(mcpServersFilePath(stateDir), savedBackupForCorrupt, { mode: 0o600 });
});

test('Unified Console manages write-only plugin secrets and moderation policy config without exposing plaintext secrets', async t => {
  const { createPluginSecretsStore } = await import('../../host/src/plugin-secrets.mjs');
  let consoleSrv;
  t.after(async () => { await consoleSrv?.close(); });
  const { stateDir, workspace } = await makeTempState(t);
  const ticket = issueSetupTicketSync(stateDir, {
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
  });
  const secretsStore = createPluginSecretsStore({ stateDir, workspaceRoots: [workspace] });
  const events = [];
  consoleSrv = await startUnifiedConsole({
    stateDir,
    host: '127.0.0.1',
    consolePort: 0,
    enableControlSocket: false,
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
    getPluginSecretsAdmin: () => secretsStore.adminView,
  });
  consoleSrv.controlChannel.subscribe(ev => events.push(ev));

  const home = await httpCall(consoleSrv.url, '/');
  let csrf = home.text.match(/<meta name="loomward-csrf" content="([^"]+)"/)?.[1];
  let cookie = mergeCookieHeader('', home.headers['set-cookie']);
  const setup = await httpCall(consoleSrv.url, '/api/auth/setup/password', {
    method: 'POST',
    headers: { origin: consoleSrv.url, cookie, 'x-loomward-csrf': csrf, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ setupToken: ticket.setupToken, password: 'Kx9!mP4#vR2@qL8$zW' }),
  });
  csrf = setup.json().csrfToken;
  const tab = setup.json().tabToken;
  cookie = mergeCookieHeader(cookie, setup.headers['set-cookie']);
  const authHeaders = { origin: consoleSrv.url, cookie, 'x-loomward-csrf': csrf, 'x-loomward-tab-auth': tab, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' };

  const saveSec = await httpCall(consoleSrv.url, '/api/plugin-secrets/save', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ unitId: 'llm-moderation', secrets: { OPENAI_API_KEY: 'sk-canary-never-echo-99999999' } }),
  });
  assert.equal(saveSec.status, 200);
  assert.equal(saveSec.text.includes('sk-canary-never-echo'), false);
  assert.deepEqual(saveSec.json().meta.keys, ['OPENAI_API_KEY']);

  const listMeta = await httpCall(consoleSrv.url, '/api/plugin-secrets/meta', {
    headers: { cookie, 'x-loomward-tab-auth': tab },
  });
  assert.equal(listMeta.status, 200);
  assert.equal(listMeta.text.includes('sk-canary-never-echo'), false);
  assert.equal(listMeta.json().units[0].unitId, 'llm-moderation');

  const badModCfg = await httpCall(consoleSrv.url, '/api/moderation/config', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ policyProfile: 'strict', fallback: { onAllFailedOutput: 'warn-experimental' } }),
  });
  assert.equal(badModCfg.status, 400);

  const invalidAlerts = await httpCall(consoleSrv.url, '/api/moderation/config', {
    method: 'POST', headers: authHeaders, body: JSON.stringify({ injectionAlerts: { globalThreshold: -1 } }),
  });
  assert.equal(invalidAlerts.status, 400);

  const goodModCfg = await httpCall(consoleSrv.url, '/api/moderation/config', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      mode: 'guard-plus-canary',
      policyProfile: 'balanced',
      cloudOptIn: true,
      cloudProvider: 'baidu-aip',
      injectionAlerts: { clientThreshold: 1, globalThreshold: 6 },
      localGuard: { endpoint: 'http://127.0.0.1:11434', model: 'qwen3-guard' },
      canary: { enabled: true, endpoint: 'http://127.0.0.1:11434', model: 'qwen2.5-0.5b' },
    }),
  });
  assert.equal(goodModCfg.status, 200);
  assert.equal(goodModCfg.json().config.mode, 'guard-plus-canary');
  assert.equal(goodModCfg.json().config.cloudProvider, 'baidu-aip');
  assert.ok(events.some(e => e.type === 'plugin.secrets_updated' && e.meta?.unitId === 'llm-moderation'));
  assert.ok(events.some(e => e.type === 'moderation.config_updated' && e.meta?.mode === 'guard-plus-canary'));

  const limits = goodModCfg.json().config.injectionAlerts;
  assert.deepEqual(limits, { clientThreshold: 1, globalThreshold: 6 });
  const { createInjectionAlertStore } = await import('../../../local/injection-alerts.mjs');
  const writer = createInjectionAlertStore({ stateDir, workspaceRoots: [workspace] });
  try {
    writer.record({ clientRef: 'a'.repeat(64), requestId: 'private-test-request', toolName: 'read_file',
      stage: 'input', source: 'input', rule: 'prompt.injection', action: 'block' }, limits);
  } finally { writer.close(); }
  const unauthStatus = await httpCall(consoleSrv.url, '/api/status');
  assert.equal(unauthStatus.status, 401);
  assert.equal(unauthStatus.json().injectionAlerts, undefined);
  const statusAfter = await httpCall(consoleSrv.url, '/api/status', {
    headers: { cookie, 'x-loomward-tab-auth': tab },
  });
  assert.equal(statusAfter.status, 200);
  const alerts = statusAfter.json().injectionAlerts;
  assert.equal(alerts.activeCount, 1);
  assert.equal(alerts.items[0].samples[0].tool, 'read_file');
  assert.doesNotMatch(JSON.stringify(alerts), /private-test-request/);
  const auditEvents = statusAfter.json().events || [];
  const secEv = auditEvents.find(ev => ev.name === 'plugin_secret_saved');
  const modEv = auditEvents.find(ev => ev.name === 'moderation_config_saved');
  assert.equal(secEv?.tone, 'ok');
  assert.equal(secEv?.label, '写入插件密钥');
  assert.equal(modEv?.tone, 'ok');
  assert.equal(modEv?.label, '更新审查策略');

  // Unauthenticated access to secrets or moderation routes must remain denied.
  const unauthSec = await httpCall(consoleSrv.url, '/api/plugin-secrets/meta');
  assert.equal(unauthSec.status, 401);
  const unauthMod = await httpCall(consoleSrv.url, '/api/moderation/config', { method: 'POST', body: '{}' });
  assert.equal(unauthMod.status, 401);
});

async function startMockOllamaServer(t) {
  const recordedChats = [];
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const bodyText = Buffer.concat(chunks).toString('utf8');
    if (req.url === '/api/version') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ version: '0.40.16-test' }));
      return;
    }
    if (req.url === '/api/tags') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        models: [
          {
            name: 'qwen3.5:9b',
            size: 6_600_000_000,
            details: { parameter_size: '9.7B', quantization_level: 'Q4_K_M', family: 'qwen35' },
            capabilities: ['completion', 'vision', 'thinking'],
          },
        ],
      }));
      return;
    }
    if (req.url === '/api/ps') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ models: [{ name: 'qwen3.5:9b', size_vram: 6_600_000_000 }] }));
      return;
    }
    if (req.url === '/api/pull') {
      const parsed = JSON.parse(bodyText || '{}');
      res.writeHead(200, { 'content-type': 'application/x-ndjson' });
      res.write(`${JSON.stringify({ status: 'pulling manifest' })}\n`);
      res.write(`${JSON.stringify({ status: `downloading ${parsed.model}`, total: 1000, completed: 500 })}\n`);
      res.write(`${JSON.stringify({ status: 'success', total: 1000, completed: 1000 })}\n`);
      res.end();
      return;
    }
    if (req.url === '/api/chat') {
      const parsed = JSON.parse(bodyText || '{}');
      recordedChats.push(parsed);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ message: { role: 'assistant', content: 'SAFE' } }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { await new Promise(resolve => server.close(resolve)); });
  const addr = server.address();
  return { url: `http://127.0.0.1:${addr.port}`, recordedChats };
}

test('local/ollama.mjs enforces SSRF boundaries, sanitizes env, streams pull NDJSON and tests chat against mock runtime', async t => {
  const prevSecret = process.env.LOOMWARD_TEST_SECRET;
  process.env.LOOMWARD_TEST_SECRET = 'never-inherit-me';
  t.after(() => {
    if (prevSecret === undefined) delete process.env.LOOMWARD_TEST_SECRET;
    else process.env.LOOMWARD_TEST_SECRET = prevSecret;
  });
  const env = sanitizedOllamaEnv();
  assert.equal(env.LOOMWARD_TEST_SECRET, undefined);
  assert.equal(typeof env.PATH, 'string');

  assert.throws(() => assertValidOllamaModelTag('../evil:latest'));
  assert.throws(() => assertValidOllamaModelTag('llama;rm -rf /'));
  assert.equal(assertValidOllamaModelTag('llama-guard3:1b'), 'llama-guard3:1b');

  assert.equal(DEFAULT_OLLAMA_ORIGIN, 'http://127.0.0.1:11434');
  assert.ok(OLLAMA_RECOMMENDED_MODELS.some(m => m.id === 'llama-guard3:1b'));
  assert.throws(() => normalizeOllamaEndpoint('http://192.168.10.20:11434', { allowPrivateNetwork: false }));
  assert.equal(normalizeOllamaEndpoint('http://192.168.10.20:11434/api', { allowPrivateNetwork: true }), 'http://192.168.10.20:11434');
  assert.throws(() => normalizeOllamaEndpoint('http://169.254.169.254/latest', { allowPrivateNetwork: true }));
  assert.throws(() => normalizeOllamaEndpoint('http://8.8.8.8:11434', { allowPrivateNetwork: true }));

  await assert.rejects(() => startOllamaDaemon({ endpoint: 'http://192.168.10.20:11434' }), /private network IP/i);
  await assert.rejects(() => startOllamaDaemon({ endpoint: 'https://gpu.example.test:11434' }), /loopback/i);

  const mock = await startMockOllamaServer(t);
  const progressEvents = [];
  const pullRes = await ollamaStreamPull(mock.url, 'llama-guard3:1b', {
    onProgress: ev => progressEvents.push(ev),
  });
  assert.equal(pullRes.ok, true);
  assert.ok(progressEvents.some(ev => ev.percent === 50));

  const ctrl = createOllamaController({
    prober: undefined,
    installer: async () => ({ ok: true, alreadyInstalled: false, installed: true, binaryPath: '/mock/ollama', version: '0.40.16-test' }),
    starter: async () => ({ ok: true, alreadyRunning: true, running: true, endpoint: mock.url, version: '0.40.16-test' }),
  });
  t.after(() => ctrl.close());

  const status = await ctrl.status({ endpoint: mock.url });
  assert.equal(status.running, true);
  assert.equal(status.version, '0.40.16-test');
  assert.equal(status.models[0].name, 'qwen3.5:9b');
  assert.equal(status.loadedModels.length, 1);

  const jobRes = await ctrl.pull({ endpoint: mock.url, model: 'qwen3:0.6b' });
  assert.equal(jobRes.ok, true);
  assert.equal(jobRes.job.status, 'completed');
  assert.equal(jobRes.job.percent, 100);

  const testRes = await ctrl.testModel({ endpoint: mock.url, model: 'qwen3.5:9b', think: false });
  assert.equal(testRes.ok, true);
  assert.equal(testRes.replyPreview, 'SAFE');
  assert.equal(mock.recordedChats.at(-1).think, false);
});

test('Unified Console exposes authenticated /api/moderation/ollama/* lifecycle routes with confirmInstall safety gate', async t => {
  const mock = await startMockOllamaServer(t);
  const { stateDir, workspace } = await makeTempState(t);
  const ticket = issueSetupTicketSync(stateDir, {
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
  });
  let installCalls = 0;
  let startCalls = 0;
  const consoleSrv = await startUnifiedConsole({
    stateDir,
    host: '127.0.0.1',
    consolePort: 0,
    enableControlSocket: false,
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
    ollamaHooks: {
      installer: async () => {
        installCalls += 1;
        return { ok: true, alreadyInstalled: false, installed: true, binaryPath: '/mock/ollama', version: '0.40.16-test' };
      },
      starter: async ({ endpoint }) => {
        startCalls += 1;
        return { ok: true, alreadyRunning: false, running: true, pid: 4242, endpoint: endpoint || mock.url, version: '0.40.16-test' };
      },
    },
  });
  t.after(async () => { await consoleSrv.close(); });

  const unauth = await httpCall(consoleSrv.url, '/api/moderation/ollama/status');
  assert.equal(unauth.status, 401);

  const home = await httpCall(consoleSrv.url, '/');
  let csrf = home.text.match(/<meta name="loomward-csrf" content="([^"]+)"/)?.[1];
  let cookie = mergeCookieHeader('', home.headers['set-cookie']);
  const setup = await httpCall(consoleSrv.url, '/api/auth/setup/password', {
    method: 'POST',
    headers: { origin: consoleSrv.url, cookie, 'x-loomward-csrf': csrf, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ setupToken: ticket.setupToken, password: 'Kx9!mP4#vR2@qL8$zW' }),
  });
  csrf = setup.json().csrfToken;
  const tab = setup.json().tabToken;
  cookie = mergeCookieHeader(cookie, setup.headers['set-cookie']);
  const authHeaders = { origin: consoleSrv.url, cookie, 'x-loomward-csrf': csrf, 'x-loomward-tab-auth': tab, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' };

  const statusRes = await httpCall(consoleSrv.url, `/api/moderation/ollama/status?endpoint=${encodeURIComponent(mock.url)}`, {
    headers: { cookie, 'x-loomward-tab-auth': tab },
  });
  assert.equal(statusRes.status, 200);
  assert.equal(statusRes.json().running, true);
  assert.equal(statusRes.json().models[0].name, 'qwen3.5:9b');

  const blockedMeta = await httpCall(consoleSrv.url, `/api/moderation/ollama/status?endpoint=${encodeURIComponent('http://169.254.169.254/latest')}&allowPrivateNetwork=1`, {
    headers: { cookie, 'x-loomward-tab-auth': tab },
  });
  assert.equal(blockedMeta.status, 400);

  const unconfirmedInstall = await httpCall(consoleSrv.url, '/api/moderation/ollama/install', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({}),
  });
  assert.equal(unconfirmedInstall.status, 400);
  assert.equal(installCalls, 0);

  const confirmedInstall = await httpCall(consoleSrv.url, '/api/moderation/ollama/install', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ confirmInstall: true }),
  });
  assert.equal(confirmedInstall.status, 200);
  assert.equal(confirmedInstall.json().installed, true);
  assert.equal(installCalls, 1);

  const startedRes = await httpCall(consoleSrv.url, '/api/moderation/ollama/start', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ endpoint: mock.url }),
  });
  assert.equal(startedRes.status, 200);
  assert.equal(startedRes.json().pid, 4242);
  assert.equal(startCalls, 1);

  const pullRes = await httpCall(consoleSrv.url, '/api/moderation/ollama/pull', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ endpoint: mock.url, model: 'llama-guard3:1b' }),
  });
  assert.ok(pullRes.status === 200 || pullRes.status === 202);
  assert.equal(pullRes.json().job.status, 'completed');

  const testRes = await httpCall(consoleSrv.url, '/api/moderation/ollama/test', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ endpoint: mock.url, model: 'qwen3.5:9b', think: false }),
  });
  assert.equal(testRes.status, 200);
  assert.equal(testRes.json().replyPreview, 'SAFE');
  assert.equal(mock.recordedChats.at(-1).think, false);
});

test('Unified Console /api/fencing/* manages R1-R7 policy safely without leaking private repo cache entries', async t => {
  const { stateDir, workspace } = await makeTempState(t);
  const ticket = issueSetupTicketSync(stateDir, {
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: false, reason: 'test' }),
  });
  const consoleSrv = await startUnifiedConsole({
    stateDir,
    host: '127.0.0.1',
    consolePort: 0,
    enableControlSocket: false,
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
  });
  t.after(() => consoleSrv.close());

  const home = await httpCall(consoleSrv.url, '/');
  let csrf = home.text.match(/<meta name="loomward-csrf" content="([^"]+)"/)?.[1];
  let cookie = mergeCookieHeader('', home.headers['set-cookie']);
  const setup = await httpCall(consoleSrv.url, '/api/auth/setup/password', {
    method: 'POST',
    headers: { origin: consoleSrv.url, cookie, 'x-loomward-csrf': csrf, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ setupToken: ticket.setupToken, password: 'Kx9!mP4#vR2@qL8$zW' }),
  });
  csrf = setup.json().csrfToken;
  const tab = setup.json().tabToken;
  cookie = mergeCookieHeader(cookie, setup.headers['set-cookie']);
  const authHeaders = { origin: consoleSrv.url, cookie, 'x-loomward-csrf': csrf, 'x-loomward-tab-auth': tab, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' };

  // Write a synthetic private-repos.json containing sensitive repo/pattern strings to ensure they NEVER leak via HTTP responses
  const antileakDir = path.join(stateDir, 'antileak');
  await fs.mkdir(antileakDir, { recursive: true, mode: 0o700 });
  const canaryRepo = 'acme/canary-topsecret-private-repo-42';
  const canaryPattern = 'CANARY_R4_SECRET_TERM_99';
  const nowSec = Math.floor(Date.now() / 1000);
  await fs.writeFile(path.join(antileakDir, 'private-repos.json'), JSON.stringify({
    generated_at: nowSec,
    expires_at: nowSec + 28800,
    status: 'fresh',
    sources: ['seed'],
    owners: ['acme'],
    private: [canaryRepo],
    patterns: [canaryPattern],
  }), { mode: 0o600 });

  const initialGet = await httpCall(consoleSrv.url, '/api/fencing/config', {
    headers: { cookie, 'x-loomward-tab-auth': tab },
  });
  assert.equal(initialGet.status, 200);
  assert.equal(initialGet.text.includes(canaryRepo), false);
  assert.equal(initialGet.text.includes(canaryPattern), false);
  assert.equal(initialGet.json().cache.status, 'fresh');
  assert.equal(initialGet.json().cache.privateCount, 1);
  assert.equal(initialGet.json().cache.patternCount, 1);
  assert.equal(initialGet.json().rules.length, 7);

  // Reject unauthenticated and malformed regex updates
  const noAuthPost = await httpCall(consoleSrv.url, '/api/fencing/config', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ config: { resolveBudget: 12 } }),
  });
  assert.ok(noAuthPost.status === 401 || noAuthPost.status === 403);

  const badRegexRes = await httpCall(consoleSrv.url, '/api/fencing/config', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ config: { forbiddenPatterns: ['[unclosed-regex'] } }),
  });
  assert.equal(badRegexRes.status, 400);

  // Save valid customized policy
  const saveRes = await httpCall(consoleSrv.url, '/api/fencing/config', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      config: {
        forbiddenPatterns: ['CANARY_BLOCKED_TERM'],
        secretRegexes: ['sk-test-[A-Za-z0-9]{12,}'],
        agentBranchPrefixes: ['claude/', 'codex/', 'feature-bot/'],
        expectedOwners: ['acme'],
        privateCacheTtl: 14400,
        resolveBudget: 15,
        resignExempt: true,
        exemptTools: ['computer_context'],
      },
    }),
  });
  assert.equal(saveRes.status, 200);
  assert.deepEqual(saveRes.json().config.forbiddenPatterns, ['CANARY_BLOCKED_TERM']);
  assert.equal(saveRes.json().config.privateCacheTtl, 14400);
  const policyStat = await fs.stat(path.join(antileakDir, 'policy.json'));
  assert.equal(policyStat.mode & 0o777, 0o600);

  // Dry-run inspection: safe vs rule R7/R2 violation vs cache private repo violation (all fail-closed safe)
  const passDry = await httpCall(consoleSrv.url, '/api/fencing/test', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ text: 'Clean documentation note without secrets.' }),
  });
  assert.equal(passDry.status, 200);
  assert.equal(passDry.json().result.decision, 'pass');

  const secretLeakDry = await httpCall(consoleSrv.url, '/api/fencing/test', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ text: 'leaky token sk-test-AbCdEf1234567890 here' }),
  });
  assert.equal(secretLeakDry.status, 200);
  assert.equal(secretLeakDry.json().result.decision, 'violation');
  assert.equal(secretLeakDry.text.includes('sk-test-AbCdEf1234567890'), false);

  const doctorRes = await httpCall(consoleSrv.url, '/api/fencing/doctor', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({}),
  });
  assert.equal(doctorRes.status, 200);
  assert.ok(Array.isArray(doctorRes.json().result.checks));
  assert.equal(doctorRes.text.includes(canaryRepo), false);

  // Verify per-tool individual toggle for both built-in tools (/api/capabilities) and 3rd-party MCP tools (/api/mcp-servers/toggle using id)
  const capToolOff = await httpCall(consoleSrv.url, '/api/capabilities', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ tools: { read_file: false } }),
  });
  assert.equal(capToolOff.status, 200);
  assert.equal(capToolOff.json().snapshot.capabilities.effectiveTools.find(x => x.name === 'read_file').individuallyDisabled, true);

  const mockMcpPath = path.join(stateDir, 'mock-toggle-mcp.mjs');
  await fs.writeFile(mockMcpPath, [
    "let b='';process.stdin.setEncoding('utf8');process.stdin.on('data',c=>{b+=c;const ls=b.split('\\n');b=ls.pop();for(const l of ls){if(!l.trim())continue;const m=JSON.parse(l);if(m.method==='initialize')process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:m.id,result:{protocolVersion:'2025-11-25',capabilities:{tools:{}},serverInfo:{name:'t',version:'1'}}})+'\\n');else if(m.method==='tools/list')process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:m.id,result:{tools:[{name:'ping_tool',description:'ping',inputSchema:{type:'object',properties:{}}}]}})+'\\n');}});",
  ].join('\n'), { mode: 0o700 });
  const mcpSave = await httpCall(consoleSrv.url, '/api/mcp-servers/save', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      id: 'toggle_srv',
      name: 'Toggle Test',
      transport: 'stdio',
      command: process.execPath,
      args: [mockMcpPath],
      probe: true,
    }),
  });
  assert.equal(mcpSave.status, 200);
  assert.equal(mcpSave.json().probe.ok, true);

  const mcpToolOff = await httpCall(consoleSrv.url, '/api/mcp-servers/toggle', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ id: 'toggle_srv', toolName: 'ping_tool', enabled: false }),
  });
  assert.equal(mcpToolOff.status, 200);
  assert.equal(mcpToolOff.json().server.tools[0].individuallyDisabled, true);
  assert.equal(mcpToolOff.json().server.tools[0].enabled, false);

  const mcpToolOn = await httpCall(consoleSrv.url, '/api/mcp-servers/toggle', {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ id: 'toggle_srv', toolName: 'ping_tool', enabled: true }),
  });
  assert.equal(mcpToolOn.status, 200);
  assert.equal(mcpToolOn.json().server.tools[0].individuallyDisabled, false);
  assert.equal(mcpToolOn.json().server.tools[0].enabled, true);
});

test('Unified Console supports zero-init loopback previewAutoSession without relaxing CSRF or production auth', async t => {
  const { stateDir, workspace } = await makeTempState(t);

  // Non-loopback host must reject console startup even when previewAutoSession is requested
  await assert.rejects(() => startUnifiedConsole({
    stateDir,
    host: '0.0.0.0',
    consolePort: 0,
    enableControlSocket: false,
    previewAutoSession: true,
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
  }), /loopback/i);

  // Default server (previewAutoSession: false) refuses /api/auth/preview
  const normalSrv = await startUnifiedConsole({
    stateDir,
    host: '127.0.0.1',
    consolePort: 0,
    enableControlSocket: false,
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
  });
  t.after(() => normalSrv.close());
  const normalHome = await httpCall(normalSrv.url, '/');
  const normalCsrf = normalHome.text.match(/<meta name="loomward-csrf" content="([^"]+)"/)?.[1];
  const normalCookie = mergeCookieHeader('', normalHome.headers['set-cookie']);
  const deniedPreview = await httpCall(normalSrv.url, '/api/auth/preview', {
    method: 'POST',
    headers: { origin: normalSrv.url, cookie: normalCookie, 'x-loomward-csrf': normalCsrf, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: '{}',
  });
  assert.equal(deniedPreview.status, 403);
  await normalSrv.close();

  // Preview server auto-mints scoped loopback session on /api/auth/state while still enforcing CSRF and Origin
  const previewSrv = await startUnifiedConsole({
    stateDir,
    host: '127.0.0.1',
    consolePort: 0,
    enableControlSocket: false,
    previewAutoSession: true,
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
  });
  t.after(() => previewSrv.close());

  // Direct call to protected endpoints without session/tab token still fails 401
  const unauthStatus = await httpCall(previewSrv.url, '/api/status');
  assert.equal(unauthStatus.status, 401);

  const authState = await httpCall(previewSrv.url, '/api/auth/state');
  assert.equal(authState.status, 200);
  const authBody = authState.json();
  assert.equal(authBody.authenticated, true);
  assert.equal(authBody.authMethod, 'preview');
  assert.equal(authBody.previewMode, true);
  assert.ok(typeof authBody.csrfToken === 'string' && authBody.csrfToken.length >= 16);
  assert.ok(typeof authBody.tabToken === 'string' && authBody.tabToken.length >= 16);

  const previewCookie = mergeCookieHeader('', authState.headers['set-cookie']);
  const okStatus = await httpCall(previewSrv.url, '/api/status', {
    headers: { cookie: previewCookie, 'x-loomward-tab-auth': authBody.tabToken },
  });
  assert.equal(okStatus.status, 200);

  // Mutation without CSRF still blocked (403), valid CSRF succeeds (200)
  const missingCsrfCap = await httpCall(previewSrv.url, '/api/capabilities', {
    method: 'POST',
    headers: { origin: previewSrv.url, cookie: previewCookie, 'x-loomward-tab-auth': authBody.tabToken, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ fileWrite: false }),
  });
  assert.equal(missingCsrfCap.status, 403);

  const okCap = await httpCall(previewSrv.url, '/api/capabilities', {
    method: 'POST',
    headers: { origin: previewSrv.url, cookie: previewCookie, 'x-loomward-csrf': authBody.csrfToken, 'x-loomward-tab-auth': authBody.tabToken, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ fileWrite: false }),
  });
  assert.equal(okCap.status, 200);

  // Explicit logout locks preview until manual POST /api/auth/preview
  const logoutRes = await httpCall(previewSrv.url, '/api/auth/logout', {
    method: 'POST',
    headers: { origin: previewSrv.url, cookie: previewCookie, 'x-loomward-csrf': authBody.csrfToken, 'x-loomward-tab-auth': authBody.tabToken, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: '{}',
  });
  assert.equal(logoutRes.status, 200);
  const lockedCookie = mergeCookieHeader(previewCookie, logoutRes.headers['set-cookie']);
  const lockedState = await httpCall(previewSrv.url, '/api/auth/state', { headers: { cookie: lockedCookie } });
  assert.equal(lockedState.status, 200);
  assert.equal(lockedState.json().authenticated, false);
  assert.equal(lockedState.json().previewAvailable, true);

  // Manual re-entry via POST /api/auth/preview restores preview session cleanly
  const reenterRes = await httpCall(previewSrv.url, '/api/auth/preview', {
    method: 'POST',
    headers: { origin: previewSrv.url, cookie: lockedCookie, 'x-loomward-csrf': logoutRes.json().csrfToken, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: '{}',
  });
  assert.equal(reenterRes.status, 200);
  assert.equal(reenterRes.json().authState.authenticated, true);
  assert.equal(reenterRes.json().authState.authMethod, 'preview');

  // Initializing real console credentials revokes preview sessions and disables preview mode
  const ticket = issueSetupTicketSync(stateDir, {
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
  });
  const realSetup = await httpCall(previewSrv.url, '/api/auth/setup/password', {
    method: 'POST',
    headers: { origin: previewSrv.url, cookie: mergeCookieHeader('', reenterRes.headers['set-cookie']), 'x-loomward-csrf': reenterRes.json().csrfToken, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ setupToken: ticket.setupToken, password: 'Kx9!mP4#vR2@qL8$zW' }),
  });
  assert.equal(realSetup.status, 200);

  const postRealPreviewCookie = mergeCookieHeader('', reenterRes.headers['set-cookie']);
  const revokedRes = await httpCall(previewSrv.url, '/api/status', {
    headers: { cookie: postRealPreviewCookie, 'x-loomward-tab-auth': reenterRes.json().tabToken },
  });
  assert.equal(revokedRes.status, 401);
});
