// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { pathToFileURL } from 'node:url';
import { SlotError, VAULT_SLOT } from '@loomward/shared';
import { startLoomWardDaemon } from '../../../packages/host/src/daemon.mjs';
import * as adaptersPlugin from '../src/index.mjs';

const REPO_ROOT = path.resolve(import.meta.dirname, '../../..');

const {
  MODELBRIDGE_MAX_TIMEOUT_MS,
  assertSafeIntegrationOrigin,
  classifyCloudForgeToolRisk,
  createCloudForgeClient,
  createModelBridgeClient,
  generatePkcePair,
} = adaptersPlugin;

function listenServer(handler) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(handler);
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({
        server,
        origin: `http://127.0.0.1:${addr.port}`,
        close: () => new Promise(done => {
          server.closeAllConnections?.();
          server.close(() => done());
        }),
      });
    });
  });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function makeTempPrivateDir(prefix) {
  const dir = fs.mkdtempSync(path.join(os.homedir(), prefix));
  if (process.platform !== 'win32') fs.chmodSync(dir, 0o700);
  return dir;
}

test('network boundary guard blocks non-HTTPS remote URLs, metadata IPs, embedded credentials, and redirects', async t => {
  assert.equal(assertSafeIntegrationOrigin('https://forge.example.test'), 'https://forge.example.test');
  assert.equal(
    assertSafeIntegrationOrigin('http://127.0.0.1:8788', { allowLoopbackHttp: true }),
    'http://127.0.0.1:8788',
  );
  assert.throws(() => assertSafeIntegrationOrigin('http://forge.example.test'), /https:\/\//i);
  assert.throws(() => assertSafeIntegrationOrigin('http://127.0.0.1:8788'), /loopback|https:\/\//i);
  assert.throws(() => assertSafeIntegrationOrigin('https://127.0.0.1:8443'), /loopback/i);
  assert.throws(() => assertSafeIntegrationOrigin('https://localhost.:8443'), /loopback/i);
  assert.throws(() => assertSafeIntegrationOrigin('https://169.254.169.254'), /blocked/i);
  assert.throws(() => assertSafeIntegrationOrigin('https://[::ffff:169.254.169.254]'), /blocked|private|loopback/i);
  assert.throws(() => assertSafeIntegrationOrigin('https://[64:ff9b::169.254.169.254]'), /blocked|private|loopback/i);
  assert.throws(() => assertSafeIntegrationOrigin('https://[fe80::1]'), /blocked|private|loopback/i);
  assert.throws(() => assertSafeIntegrationOrigin('https://10.0.0.5'), /private network/i);
  assert.throws(() => assertSafeIntegrationOrigin('https://user:pass@forge.example.test'), /credentials/i);
  assert.throws(() => assertSafeIntegrationOrigin('https://forge.example.test/api'), /path suffix/i);

  const redirectSrv = await listenServer((_req, res) => {
    res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' });
    res.end();
  });
  t.after(() => redirectSrv.close());

  const client = createCloudForgeClient({
    origin: redirectSrv.origin,
    allowLoopbackHttp: true,
    getAccessToken: () => 'cf-secret-token-never-follow',
  });
  const probe = await client.probeWellKnown();
  assert.equal(probe.reachable, false);
  await assert.rejects(() => client.listTools(), /Upstream request failed/);
});

test('CloudForge adapter supports RFC 9728/8414 OAuth 2.1 + PKCE discovery, metadata probe, JSON & SSE Streamable HTTP /mcp', async t => {
  const secretToken = 'cf-live-access-token-secret-xyz';
  let expectedChallenge = null;
  let lastToolCall = null;

  const mockForge = await listenServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const origin = `http://${req.headers.host}`;

    if (req.method === 'GET' && url.pathname === '/.well-known/cloudforge') {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({
        installationId: 'cf-inst-42',
        version: '2.4.1',
        schemaDigest: 'sha256:abc',
        accessRuntime: {
          protocol: 1,
          ready: true,
          minimumProtocol: 1,
          schemaMode: 'runtime-bridge-v1',
          rolePublishingEnabled: true,
          revision: 9,
          reason: null,
        },
      }));
      return;
    }

    if (req.method === 'GET' && url.pathname === '/.well-known/oauth-protected-resource/mcp') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        resource: `${origin}/mcp`,
        authorization_servers: [`${origin}/api/auth`],
      }));
      return;
    }

    if (req.method === 'GET' && url.pathname === '/.well-known/oauth-authorization-server/api/auth') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        issuer: `${origin}/api/auth`,
        authorization_endpoint: `${origin}/api/auth/oauth2/authorize`,
        token_endpoint: `${origin}/api/auth/oauth2/token`,
        registration_endpoint: `${origin}/api/auth/oauth2/register`,
        code_challenge_methods_supported: ['S256'],
      }));
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/auth/oauth2/token') {
      const form = new URLSearchParams(await readBody(req));
      if (form.get('grant_type') === 'authorization_code') {
        const computed = crypto.createHash('sha256').update(form.get('code_verifier') || '', 'utf8').digest('base64url');
        assert.equal(computed, expectedChallenge);
        assert.equal(form.get('resource'), `${origin}/mcp`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ access_token: secretToken, refresh_token: 'cf-refresh-1', token_type: 'Bearer' }));
        return;
      }
      if (form.get('grant_type') === 'refresh_token') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ access_token: 'cf-refreshed-token', token_type: 'Bearer' }));
        return;
      }
    }

    if (req.method === 'POST' && url.pathname === '/mcp') {
      if (req.headers.authorization !== `Bearer ${secretToken}`) {
        res.writeHead(401, {
          'WWW-Authenticate': `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"`,
        });
        res.end('Unauthorized');
        return;
      }
      const rpc = JSON.parse(await readBody(req));
      if (rpc.method === 'tools/list') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          jsonrpc: '2.0',
          id: rpc.id,
          result: {
            tools: [
              { name: 'list_repos', description: 'List CloudForge repositories', inputSchema: { type: 'object' } },
              { name: 'merge_pull_request', description: 'Merge pull request', inputSchema: { type: 'object' } },
            ],
          },
        }));
        return;
      }
      if (rpc.method === 'tools/call') {
        lastToolCall = rpc.params;
        // Return Streamable HTTP SSE format to verify SSE frame parsing.
        res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8' });
        res.end(
          `event: message\ndata: ${JSON.stringify({
            jsonrpc: '2.0',
            id: rpc.id,
            result: {
              content: [{ type: 'text', text: `merged:${rpc.params.arguments.repo}#${rpc.params.arguments.pr}` }],
            },
          })}\n\n`,
        );
        return;
      }
    }

    res.writeHead(404);
    res.end('Not found');
  });
  t.after(() => mockForge.close());

  let activeToken = null;
  const cf = createCloudForgeClient({
    origin: mockForge.origin,
    allowLoopbackHttp: true,
    getAccessToken: () => activeToken,
  });

  // 1. Metadata probe works anonymously
  const probe = await cf.probeWellKnown();
  assert.equal(probe.reachable, true);
  assert.equal(probe.installationId, 'cf-inst-42');
  assert.equal(probe.accessRuntime.ready, true);

  // 2. Unauthenticated /mcp surfaces structured 401 Bearer challenge
  await assert.rejects(
    () => cf.listTools(),
    err => err.code === 'CLOUDFORGE_UNAUTHORIZED' && err.wwwAuthenticate.includes('oauth-protected-resource/mcp'),
  );

  // 3. RFC 9728 + RFC 8414 discovery + PKCE S256 token flow
  const oauth = await cf.discoverOAuth();
  assert.equal(oauth.tokenEndpoint, `${mockForge.origin}/api/auth/oauth2/token`);
  const pkce = generatePkcePair();
  expectedChallenge = pkce.challenge;
  const authReq = cf.buildAuthorizationUrl({
    authorizationEndpoint: oauth.authorizationEndpoint,
    clientId: 'loomward-cli',
    redirectUri: 'http://127.0.0.1:33418/callback',
    state: 'st-123',
    pkce,
  });
  assert.match(authReq.url, /code_challenge_method=S256/);
  assert.match(authReq.url, /resource=http/);

  const tokens = await cf.exchangeCode({
    tokenEndpoint: oauth.tokenEndpoint,
    clientId: 'loomward-cli',
    code: 'code-xyz',
    redirectUri: 'http://127.0.0.1:33418/callback',
    codeVerifier: pkce.verifier,
  });
  assert.equal(tokens.access_token, secretToken);
  activeToken = tokens.access_token;

  const refreshed = await cf.refreshToken({
    tokenEndpoint: oauth.tokenEndpoint,
    clientId: 'loomward-cli',
    refreshToken: tokens.refresh_token,
  });
  assert.equal(refreshed.access_token, 'cf-refreshed-token');

  // 4. Tool discovery + risk classification + SSE call
  const tools = await cf.listTools();
  assert.equal(tools.length, 2);
  assert.equal(tools[0].name, 'mcp__cloudforge__list_repos');
  assert.equal(tools[0].annotations.risk, 'read');
  assert.equal(tools[1].name, 'mcp__cloudforge__merge_pull_request');
  assert.equal(tools[1].annotations.risk, 'write');
  assert.equal(classifyCloudForgeToolRisk('moderate_issue'), 'write');
  assert.equal(classifyCloudForgeToolRisk('fork_repo'), 'write');
  assert.equal(classifyCloudForgeToolRisk('star_repo'), 'write');
  assert.equal(classifyCloudForgeToolRisk('search_issues'), 'read');

  const res = await cf.callTool('mcp__cloudforge__merge_pull_request', { repo: 'loomward', pr: 7 });
  assert.equal(res.isError, undefined);
  assert.equal(res.content[0].text, 'merged:loomward#7');
  assert.deepEqual(lastToolCall, { name: 'merge_pull_request', arguments: { repo: 'loomward', pr: 7 } });
});

test('ModelBridge adapter enforces 12s timeout cap, sanitizes secrets, and degrades gracefully on timeout', async t => {
  assert.throws(
    () => createModelBridgeClient({ origin: 'https://mb.example.test', timeoutMs: MODELBRIDGE_MAX_TIMEOUT_MS + 1 }),
    RangeError,
  );

  const apiKey = 'mb-user-key-super-secret-999';
  let delayMs = 0;
  const mockMb = await listenServer((req, res) => {
    const finish = () => {
      if (req.url === '/api/auth/status') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ isSetup: true }));
        return;
      }
      if (req.url === '/api/usage/summary') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          totalRequests: 42,
          activeAccounts: 3,
          apiToken: 'SHOULD_BE_STRIPPED',
          nested: { secretKey: 'NEVER_LEAK', healthy: true },
        }));
        return;
      }
      if (req.url === '/v1/models') {
        if (req.headers.authorization !== `Bearer ${apiKey}`) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: { code: 'invalid_api_key' } }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          data: [
            { id: 'gpt-4.1-mini', owned_by: 'openai' },
            { id: 'claude-sonnet-4-5', owned_by: 'anthropic' },
          ],
        }));
        return;
      }
      res.writeHead(404);
      res.end();
    };
    if (delayMs > 0) setTimeout(finish, delayMs);
    else finish();
  });
  t.after(() => mockMb.close());

  const mb = createModelBridgeClient({
    origin: mockMb.origin,
    allowLoopbackHttp: true,
    timeoutMs: 250,
    getApiKey: () => apiKey,
  });

  const snap = await mb.getSnapshot();
  assert.equal(snap.status.reachable, true);
  assert.equal(snap.status.isSetup, true);
  assert.equal(snap.usage.ok, true);
  assert.equal(snap.usage.summary.totalRequests, 42);
  assert.equal('apiToken' in snap.usage.summary, false);
  assert.equal('secretKey' in snap.usage.summary.nested, false);
  assert.equal(snap.catalog.ok, true);
  assert.equal(snap.catalog.count, 2);
  assert.equal(JSON.stringify(snap).includes(apiKey), false);

  // Trigger timeout boundary
  delayMs = 400;
  const timedOut = await mb.probeStatus();
  assert.equal(timedOut.reachable, false);
  assert.match(timedOut.error, /timed out/i);
});

test('adapters plugin integrates with LoomWard daemon approval pipeline, dual-origin console panels, and vault isolation', async t => {
  const stateDir = makeTempPrivateDir('.lw-adapters-state-');
  const workspaceDir = makeTempPrivateDir('.lw-adapters-ws-');
  t.after(() => {
    fs.rmSync(stateDir, { recursive: true, force: true });
    fs.rmSync(workspaceDir, { recursive: true, force: true });
  });

  const cfToken = 'cf-e2e-bearer-secret-never-echo';
  const mbKey = 'mb-e2e-api-key-never-echo';
  let mergeExecutions = 0;

  const mockForge = await listenServer(async (req, res) => {
    if (req.url === '/.well-known/cloudforge') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        installationId: 'cf-e2e',
        version: '2.5.0',
        schemaDigest: null,
        accessRuntime: { protocol: 1, ready: true, schemaMode: 'runtime-bridge-v1' },
      }));
      return;
    }
    if (req.url === '/mcp' && req.headers.authorization === `Bearer ${cfToken}`) {
      const rpc = JSON.parse(await readBody(req));
      if (rpc.method === 'tools/list') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          jsonrpc: '2.0',
          id: rpc.id,
          result: {
            tools: [
              { name: 'merge_pull_request', description: 'Merge PR in CloudForge', inputSchema: { type: 'object' } },
            ],
          },
        }));
        return;
      }
      if (rpc.method === 'tools/call') {
        mergeExecutions += 1;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          jsonrpc: '2.0',
          id: rpc.id,
          result: { content: [{ type: 'text', text: `merged-ok-${mergeExecutions}` }] },
        }));
        return;
      }
    }
    res.writeHead(404);
    res.end();
  });
  t.after(() => mockForge.close());

  const mockMb = await listenServer((req, res) => {
    if (req.url === '/api/auth/status') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ isSetup: true }));
      return;
    }
    if (req.url === '/api/usage/summary') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ totalRequests: 11, healthyProviders: 2 }));
      return;
    }
    if (req.url === '/v1/models' && req.headers.authorization === `Bearer ${mbKey}`) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ data: [{ id: 'gpt-oss-120b', owned_by: 'meta' }] }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  t.after(() => mockMb.close());

  const daemon = await startLoomWardDaemon({
    rootDir: REPO_ROOT,
    stateDir,
    origin: 'https://bridge.example.test',
    workspaceRoots: [workspaceDir],
    enableMcpHub: false,
    sandboxRuntime: {
      async handleRpc(body) {
        if (body.method === 'tools/list') return { jsonrpc: '2.0', id: body.id ?? null, result: { tools: [] } };
        return { jsonrpc: '2.0', id: body.id ?? null, result: { content: [{ type: 'text', text: 'ok' }] } };
      },
      async close() {},
    },
  });
  t.after(() => daemon.stop());

  let pluginCtx;
  await daemon.control.mountExtensionUnit({
    contract: adaptersPlugin.contract,
    load: async () => {
      const mod = await import(pathToFileURL(path.join(REPO_ROOT, 'plugins/adapters/src/index.mjs')).href);
      return {
        name: mod.name,
        apply(ctx, cfg) {
          pluginCtx = ctx;
          return mod.apply(ctx, cfg);
        },
      };
    },
    config: {
      cloudforge: {
        origin: mockForge.origin,
        allowLoopbackHttp: true,
        getAccessToken: () => cfToken,
      },
      modelbridge: {
        origin: mockMb.origin,
        allowLoopbackHttp: true,
        getApiKey: () => mbKey,
      },
    },
    trust: { autoApproveTrusted: true, trustLevel: 'official', signed: true },
  });

  // Out-of-process boundary: external adapters cannot access closed vault:backend@1.
  assert.throws(() => pluginCtx.get(VAULT_SLOT), SlotError);

  // Verify tool discovery via daemon local ingress
  const listed = await daemon.localIngress.dispatchRpc({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
  assert.ok(listed.result.tools.some(item => item.name === 'mcp__cloudforge__merge_pull_request'));

  // Calling write tool without approval returns LOCAL_APPROVAL_REQUIRED without touching CloudForge.
  const firstCall = await daemon.localIngress.dispatchRpc(
    {
      jsonrpc: '2.0',
      id: 'cf-1',
      method: 'tools/call',
      params: { name: 'mcp__cloudforge__merge_pull_request', arguments: { repo: 'loomward', pr: 9 } },
    },
    { requestId: 'cf_merge_req_1' },
  );
  assert.equal(firstCall.error?.data?.code, 'LOCAL_APPROVAL_REQUIRED');
  assert.equal(mergeExecutions, 0);

  // Approve exact pending request on disk, then re-dispatch.
  const approvalId = firstCall.error.data.approval_id;
  const reqFile = path.join(stateDir, 'approvals', `${approvalId}.request.json`);
  const pending = JSON.parse(fs.readFileSync(reqFile, 'utf8'));
  fs.writeFileSync(
    path.join(stateDir, 'approvals', `${approvalId}.approved.json`),
    JSON.stringify({ id: pending.id, hash: pending.hash, expiresAt: pending.expiresAt, approvedAt: Date.now() }),
    { mode: 0o600 },
  );

  const approvedRpc = {
    jsonrpc: '2.0',
    id: 'cf-2',
    method: 'tools/call',
    params: { name: 'mcp__cloudforge__merge_pull_request', arguments: { repo: 'loomward', pr: 9 } },
  };
  const executed = await daemon.localIngress.dispatchRpc(approvedRpc, { requestId: 'cf_merge_req_2' });
  assert.equal(executed.result?.content?.[0]?.text, 'merged-ok-1');
  assert.equal(mergeExecutions, 1);

  // Replay exact same requestId must be blocked by 24h RequestReceipts without re-executing!
  const replayed = await daemon.localIngress.dispatchRpc(approvedRpc, { requestId: 'cf_merge_req_2' });
  assert.ok(
    ['already_attempted', 'request_id_conflict'].includes(replayed.error?.data?.reason),
    `Expected replay rejection reason, got: ${JSON.stringify(replayed)}`,
  );
  assert.equal(mergeExecutions, 1);

  // Declarative console:panel@1 exposes BOTH cloudforge and modelbridge snapshots with zero secrets.
  const consoleSvc = daemon.control.getService('console:loopback');
  const allPanels = await consoleSvc.panelCollector.collectAll();
  const cfPanel = allPanels.find(p => p.id === 'cloudforge');
  const mbPanel = allPanels.find(p => p.id === 'modelbridge');
  assert.ok(cfPanel && cfPanel.status === 'ok');
  assert.ok(mbPanel && mbPanel.status === 'ok');
  assert.ok(cfPanel.table && Array.isArray(cfPanel.tables));
  assert.ok(mbPanel.table && Array.isArray(mbPanel.tables));
  assert.ok(mbPanel.summary.some(s => s.label === '可见模型数' && s.value === '1'));

  const serialized = JSON.stringify(allPanels);
  assert.equal(serialized.includes(cfToken), false);
  assert.equal(serialized.includes(mbKey), false);
});
