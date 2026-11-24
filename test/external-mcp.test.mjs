// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { WebSocketServer } from 'ws';
import {
  assertSafeMcpHttpUrl,
  formatExternalToolName,
  isBlockedIpAddress,
  isForbiddenEnvKey,
  mcpServersFilePath,
  normalizeCachedTool,
  parseExternalToolName,
  parseStandardMcpJson,
  publicMcpServerSummary,
  readMcpServersSync,
  redactSecretsFromText,
  redactUrlForDisplay,
  saveMcpProbeResultSync,
  upsertMcpServerSync,
  toggleMcpServerSync,
  deleteMcpServerSync,
} from '../local/mcp-registry.mjs';
import { createExternalMcpHub, probeMcpServer } from '../local/mcp-client.mjs';
import { BridgeConnector } from '../local/connector.mjs';
import { setStrongPasswordSync } from '../local/webui-auth.mjs';
import { startWebUiServer } from '../local/webui.mjs';

async function makeTempState(t) {
  const dir = await fs.mkdtemp(path.join(os.homedir(), '.ad-mcp-test-'));
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
      timeout: 10000,
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({
          status: res.statusCode,
          headers: res.headers,
          text,
          json() { return JSON.parse(text); },
        });
      });
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

function mergeCookieHeader(existing, setCookies) {
  const map = new Map();
  for (const part of String(existing || '').split(';')) {
    const eq = part.indexOf('=');
    if (eq > 0) map.set(part.slice(0, eq).trim(), part.slice(eq + 1).trim());
  }
  const list = Array.isArray(setCookies) ? setCookies : (setCookies ? [setCookies] : []);
  for (const raw of list) {
    const pair = String(raw).split(';')[0];
    const eq = pair.indexOf('=');
    if (eq <= 0) continue;
    const key = pair.slice(0, eq).trim();
    const val = pair.slice(eq + 1).trim();
    if (!val) map.delete(key);
    else map.set(key, val);
  }
  return [...map.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
}

async function createMockStdioMcpScript(dir) {
  const scriptPath = path.join(dir, 'mock-stdio-mcp.mjs');
  await fs.writeFile(scriptPath, `
import readline from 'node:readline';
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on('line', line => {
  if (!line.trim()) return;
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  if (msg.method === 'initialize') {
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0',
      id: msg.id,
      result: {
        protocolVersion: '2025-11-25',
        capabilities: { tools: {} },
        serverInfo: { name: 'mock-stdio-server', version: '1.2.3' },
      },
    }) + '\\n');
    return;
  }
  if (msg.method === 'tools/list') {
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0',
      id: msg.id,
      result: {
        tools: [
          {
            name: 'echo_upper',
            description: 'Return uppercased input text and report env status',
            inputSchema: {
              type: 'object',
              properties: { text: { type: 'string', description: 'Input text' } },
              required: ['text'],
            },
          },
          {
            name: 'secondary_tool',
            description: 'Second tool used for per-tool toggle testing',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      },
    }) + '\\n');
    return;
  }
  if (msg.method === 'tools/call') {
    const name = msg.params?.name;
    if (name === 'echo_upper') {
      const text = String(msg.params?.arguments?.text || '').toUpperCase();
      const hasCustom = process.env.DEMO_API_TOKEN === 'SECRET_ENV_CANARY_42';
      const leakedBridge = Boolean(process.env.AGENTDOCK_BRIDGE_TOKEN);
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        result: {
          content: [{ type: 'text', text: JSON.stringify({ text, hasCustom, leakedBridge }) }],
        },
      }) + '\\n');
      return;
    }
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0',
      id: msg.id,
      result: { content: [{ type: 'text', text: 'secondary-ok' }] },
    }) + '\\n');
  }
});
`, { mode: 0o700 });
  return scriptPath;
}

async function createMockHttpMcpServer(t, { expectedAuth = 'Bearer SECRET_HEADER_CANARY_99' } = {}) {
  let callCount = 0;
  const server = http.createServer(async (req, res) => {
    if (req.method === 'DELETE') {
      res.writeHead(204);
      res.end();
      return;
    }
    if (req.headers.authorization !== expectedAuth) {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const msg = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (msg.method === 'notifications/initialized') {
      res.writeHead(202);
      res.end();
      return;
    }
    if (msg.method === 'initialize') {
      res.writeHead(200, {
        'content-type': 'application/json',
        'mcp-session-id': 'mock-http-session-1',
      });
      res.end(JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        result: {
          protocolVersion: '2025-11-25',
          capabilities: { tools: {} },
          serverInfo: { name: 'mock-http-server', version: '2.0.0' },
        },
      }));
      return;
    }
    if (msg.method === 'tools/list') {
      // Reply via Streamable HTTP SSE format to exercise SSE parser too.
      res.writeHead(200, {
        'content-type': 'text/event-stream',
        'mcp-session-id': 'mock-http-session-1',
      });
      res.end(`event: message\ndata: ${JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        result: {
          tools: [
            {
              name: 'add_nums',
              description: 'Add two numbers remotely',
              inputSchema: {
                type: 'object',
                properties: {
                  a: { type: 'integer' },
                  b: { type: 'integer' },
                },
                required: ['a', 'b'],
              },
            },
          ],
        },
      })}\n\n`);
      return;
    }
    if (msg.method === 'tools/call' && msg.params?.name === 'add_nums') {
      callCount += 1;
      const sum = Number(msg.params?.arguments?.a || 0) + Number(msg.params?.arguments?.b || 0);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        result: { content: [{ type: 'text', text: String(sum) }] },
      }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  t.after(() => new Promise(resolve => {
    server.closeAllConnections?.();
    server.close(resolve);
  }));
  return {
    url: `http://127.0.0.1:${addr.port}/mcp`,
    getCallCount: () => callCount,
  };
}

test('mcp-registry enforces outside-workspace isolation, 0600 fail-closed guards, URL/env safety, and write-only secrets', async t => {
  const stateDir = await makeTempState(t);
  const workspace = await fs.mkdtemp(path.join(os.homedir(), '.ad-mcp-ws-'));
  t.after(() => fs.rm(workspace, { recursive: true, force: true }));

  // Reject unsafe URLs and self-SSRF targets
  assert.throws(() => assertSafeMcpHttpUrl('http://example.com/mcp'), /https/);
  assert.throws(() => assertSafeMcpHttpUrl('https://user:pass@example.com/mcp'), /credentials/);
  assert.throws(
    () => assertSafeMcpHttpUrl('http://localhost:18797/api/capabilities', { blockedOrigins: ['http://127.0.0.1:18797'] }),
    /cannot target AgentDock/,
  );

  // Reject dangerous loader env overrides & stateDir cwd
  assert.throws(() => upsertMcpServerSync(stateDir, {
    id: 'bad-env',
    name: 'Bad Env',
    transport: 'stdio',
    command: 'node',
    env: { LD_PRELOAD: '/tmp/evil.so' },
  }, { workspaceRoots: [workspace] }), /blocked for host safety/);

  assert.throws(() => upsertMcpServerSync(stateDir, {
    id: 'bad-cwd',
    name: 'Bad Cwd',
    transport: 'stdio',
    command: 'node',
    cwd: stateDir,
  }, { workspaceRoots: [workspace] }), /protected AgentDock state directory/);

  // Save valid server with secret env, verify write-only summary and secret preservation on partial edit
  const saved = upsertMcpServerSync(stateDir, {
    id: 'github',
    name: 'GitHub',
    transport: 'stdio',
    command: 'npx',
    args: ['-y', '@modelcontextprotocol/server-github'],
    env: { GITHUB_TOKEN: 'SECRET_TOKEN_CANARY' },
  }, { workspaceRoots: [workspace] });

  const summary = publicMcpServerSummary(saved);
  assert.deepEqual(summary.envKeys, ['GITHUB_TOKEN']);
  assert.equal(JSON.stringify(summary).includes('SECRET_TOKEN_CANARY'), false);

  const edited = upsertMcpServerSync(stateDir, {
    id: 'github',
    name: 'GitHub Renamed',
    transport: 'stdio',
    command: 'npx',
    args: ['-y', '@modelcontextprotocol/server-github'],
    timeoutMs: 45000,
  }, { workspaceRoots: [workspace] });
  assert.equal(edited.env.GITHUB_TOKEN, 'SECRET_TOKEN_CANARY');

  const removedSecret = upsertMcpServerSync(stateDir, {
    id: 'github',
    name: 'GitHub Renamed',
    transport: 'stdio',
    command: 'npx',
    args: ['-y', '@modelcontextprotocol/server-github'],
    removeEnvKeys: ['GITHUB_TOKEN'],
  }, { workspaceRoots: [workspace] });
  assert.deepEqual(removedSecret.env, {});

  // Standard JSON import (Claude/Cursor mcpServers format)
  const imported = parseStandardMcpJson(JSON.stringify({
    mcpServers: {
      'My Memory Server': { command: 'npx', args: ['-y', '@modelcontextprotocol/server-memory'] },
      remoteDocs: { url: 'https://docs.example.test/mcp', headers: { Authorization: 'Bearer tok' } },
    },
  }));
  assert.equal(imported.length, 2);
  assert.equal(imported[0].id, 'my-memory-server');
  assert.equal(imported[0].transport, 'stdio');
  assert.equal(imported[1].id, 'remotedocs');
  assert.equal(imported[1].transport, 'http');

  // Fail-closed if file permissions are loosened on POSIX
  if (process.platform !== 'win32') {
    await fs.chmod(mcpServersFilePath(stateDir), 0o644);
    const badPerm = readMcpServersSync(stateDir, { workspaceRoots: [workspace] });
    assert.ok(badPerm.error);
    assert.deepEqual(badPerm.servers, []);
    await fs.chmod(mcpServersFilePath(stateDir), 0o600);
  }

  // Reject storage inside mounted workspace
  const inside = readMcpServersSync(workspace, { workspaceRoots: [workspace] });
  assert.ok(inside.error);
  assert.deepEqual(inside.servers, []);

  // Delete cleanly
  const del = deleteMcpServerSync(stateDir, 'github', { workspaceRoots: [workspace] });
  assert.equal(del.deleted, 'github');
});

test('WebUI manages stdio & Streamable HTTP third-party MCP servers and BridgeConnector enforces local exact approval', async t => {
  const stateDir = await makeTempState(t);
  const workspace = await fs.mkdtemp(path.join(os.homedir(), '.ad-mcp-e2e-ws-'));
  const scriptDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ad-mock-mcp-'));
  t.after(async () => {
    await fs.rm(workspace, { recursive: true, force: true });
    await fs.rm(scriptDir, { recursive: true, force: true });
  });

  const stdioScript = await createMockStdioMcpScript(scriptDir);
  const httpMcp = await createMockHttpMcpServer(t);

  // Start mock bridge WebSocket relay
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await once(wss, 'listening');
  const relayPort = wss.address().port;
  const relayOrigin = `http://127.0.0.1:${relayPort}`;
  t.after(() => new Promise(resolve => {
    for (const client of wss.clients) client.terminate();
    wss.close(resolve);
  }));

  await fs.writeFile(path.join(stateDir, 'config.json'), JSON.stringify({
    origin: relayOrigin,
    roots: [workspace],
    defaultCwd: workspace,
    allowExec: true,
    requireLocalApproval: true,
    sandbox: { enabled: true, allowOutbound: false, image: `sha256:${'a'.repeat(64)}`, context: 'default' },
  }), { mode: 0o600 });

  setStrongPasswordSync(stateDir, {
    password: 'McpUi!Strong#2026Aa',
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
    gatewayProbe: async () => ({ reachable: true, status: 200, latencyMs: 2 }),
    dockerProbe: async () => ({ dockerOk: true, runningContainers: [] }),
    systemdProbe: async () => ({ supported: false, installed: false, enabled: false, active: false, linger: false }),
    serviceController: async () => {},
  });
  t.after(() => webui.close());

  // Verify HTML/JS expose the new third-party MCP tab and valid JS syntax
  const home = await httpCall(webui.url, '/');
  assert.equal(home.status, 200);
  assert.match(home.text, /id="tab-btn-mcp"/);
  assert.match(home.text, /id="view-mcp"/);
  assert.match(home.text, /id="mcp-server-form"/);
  assert.match(home.text, /id="mcp-import-form"/);

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
    body: JSON.stringify({ password: 'McpUi!Strong#2026Aa' }),
  });
  assert.equal(loginRes.status, 200);
  csrf = loginRes.json().csrfToken;
  const tabToken = loginRes.json().tabToken;
  cookie = mergeCookieHeader(cookie, loginRes.headers['set-cookie']);
  const postHeaders = {
    origin: webui.url,
    cookie,
    'x-agentdock-csrf': csrf,
    'x-agentdock-tab-auth': tabToken,
    'sec-fetch-site': 'same-origin',
    'content-type': 'application/json',
  };

  // Reject self-SSRF attempting to register AgentDock WebUI itself as HTTP MCP
  const ssrfRes = await httpCall(webui.url, '/api/mcp-servers/save', {
    method: 'POST',
    headers: postHeaders,
    body: JSON.stringify({
      id: 'self-loop',
      name: 'Self Loop',
      transport: 'http',
      url: `${webui.url}/api/status`,
    }),
  });
  assert.equal(ssrfRes.status, 400);

  // Add real stdio MCP server + probe
  const saveStdio = await httpCall(webui.url, '/api/mcp-servers/save', {
    method: 'POST',
    headers: postHeaders,
    body: JSON.stringify({
      id: 'demo_stdio',
      name: 'Demo Stdio',
      transport: 'stdio',
      command: process.execPath,
      args: [stdioScript],
      env: { DEMO_API_TOKEN: 'SECRET_ENV_CANARY_42' },
      probe: true,
    }),
  });
  assert.equal(saveStdio.status, 200);
  const stdioJson = saveStdio.json();
  assert.equal(stdioJson.probe.ok, true);
  assert.equal(stdioJson.probe.tools.length, 2);
  assert.equal(saveStdio.text.includes('SECRET_ENV_CANARY_42'), false);

  // Import real Streamable HTTP (SSE tools/list) MCP server via standard Claude/Cursor JSON + probe
  const importHttp = await httpCall(webui.url, '/api/mcp-servers/import', {
    method: 'POST',
    headers: postHeaders,
    body: JSON.stringify({
      probe: true,
      json: JSON.stringify({
        mcpServers: {
          demo_http: {
            url: httpMcp.url,
            headers: { Authorization: 'Bearer SECRET_HEADER_CANARY_99' },
          },
        },
      }),
    }),
  });
  assert.equal(importHttp.status, 200);
  const httpJson = importHttp.json();
  assert.deepEqual(httpJson.importedIds, ['demo_http']);
  assert.equal(httpJson.probes.demo_http.ok, true);
  assert.equal(httpJson.probes.demo_http.toolCount, 1);
  assert.equal(importHttp.text.includes('SECRET_HEADER_CANARY_99'), false);

  // Disable secondary_tool individually via WebUI API
  const toggleOne = await httpCall(webui.url, '/api/mcp-servers/toggle', {
    method: 'POST',
    headers: postHeaders,
    body: JSON.stringify({ id: 'demo_stdio', toolName: 'secondary_tool', enabled: false }),
  });
  assert.equal(toggleOne.status, 200);
  const snapAfterToggle = toggleOne.json().snapshot;
  assert.equal(snapAfterToggle.mcpServers.serverCount, 2);
  assert.equal(snapAfterToggle.mcpServers.enabledToolCount, 2);
  assert.equal(JSON.stringify(snapAfterToggle).includes('SECRET_ENV_CANARY_42'), false);
  assert.equal(JSON.stringify(snapAfterToggle).includes('SECRET_HEADER_CANARY_99'), false);

  // Connect real BridgeConnector and exercise tools/list + approval + execution + live disable
  const builtInStubRuntime = {
    async handleRpc(body) {
      if (body.method === 'tools/list') {
        return { jsonrpc: '2.0', id: body.id, result: { tools: [{ name: 'computer_context', inputSchema: { type: 'object', properties: {} } }] } };
      }
      return { jsonrpc: '2.0', id: body.id, result: { content: [{ type: 'text', text: 'builtin' }] } };
    },
    async close() {},
  };

  let relaySocket;
  const connectedPromise = new Promise(resolve => {
    wss.once('connection', ws => {
      relaySocket = ws;
      resolve(ws);
    });
  });

  process.env.AGENTDOCK_BRIDGE_TOKEN = 'SHOULD_NEVER_LEAK_TO_STDIO_MCP';
  t.after(() => { delete process.env.AGENTDOCK_BRIDGE_TOKEN; });

  const connector = new BridgeConnector({
    origin: relayOrigin,
    bridgeToken: 'test-bridge-token-0123456789abcdef',
    runtime: builtInStubRuntime,
    stateDir,
    allowExec: true,
    workspaceRoots: [workspace],
  });
  await connector.start();
  t.after(() => connector.stop());
  await connectedPromise;

  const sendRelayRpc = (body, scope = ['computer:read', 'computer:write', 'computer:execute'], reqId = randomUUID()) =>
    new Promise((resolve, reject) => {
      const onMsg = raw => {
        const parsed = JSON.parse(raw.toString('utf8'));
        if (parsed.type === 'ping') {
          relaySocket.send(JSON.stringify({ type: 'pong' }));
          return;
        }
        if (parsed.type === 'response' && parsed.id === reqId) {
          relaySocket.off('message', onMsg);
          resolve(parsed.body);
        }
      };
      relaySocket.on('message', onMsg);
      const now = Date.now();
      relaySocket.send(JSON.stringify({
        type: 'request',
        id: reqId,
        issuedAt: now,
        deadline: now + 30000,
        authorization: { userId: 'owner', clientId: 'test-agent-client', scope },
        body,
      }));
      setTimeout(() => { relaySocket.off('message', onMsg); reject(new Error('Relay RPC timeout')); }, 8000).unref();
    });

  // 1. tools/list aggregates built-in + enabled third-party MCP tools (omits disabled secondary_tool)
  const listed = await sendRelayRpc({ jsonrpc: '2.0', id: 1, method: 'tools/list' }, ['computer:read']);
  const toolNames = listed.result.tools.map(item => item.name);
  assert.ok(toolNames.includes('computer_context'));
  assert.ok(toolNames.includes(formatExternalToolName('demo_stdio', 'echo_upper')));
  assert.ok(toolNames.includes(formatExternalToolName('demo_http', 'add_nums')));
  assert.equal(toolNames.includes(formatExternalToolName('demo_stdio', 'secondary_tool')), false);

  // 2. Read-only OAuth scope is rejected for third-party MCP tools
  const scopeDenied = await sendRelayRpc(
    { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'mcp__demo_stdio__echo_upper', arguments: { text: 'hello' } } },
    ['computer:read'],
  );
  assert.ok(scopeDenied.error);
  assert.match(scopeDenied.error.message, /not permitted/);

  // 3. Full scope triggers mandatory LOCAL_APPROVAL_REQUIRED before invoking stdio MCP
  const needApproval = await sendRelayRpc({
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: { name: 'mcp__demo_stdio__echo_upper', arguments: { text: 'hello agentdock' } },
  });
  assert.equal(needApproval.error?.data?.code, 'LOCAL_APPROVAL_REQUIRED');
  const approvalId = needApproval.error.data.approval_id;
  assert.ok(approvalId);

  // Review & approve via WebUI API
  const reviewRes = await httpCall(webui.url, '/api/approvals/review', {
    method: 'POST',
    headers: postHeaders,
    body: JSON.stringify({ id: approvalId }),
  });
  assert.equal(reviewRes.status, 200);
  assert.match(reviewRes.json().requestText, /mcp__demo_stdio__echo_upper/);

  const approveRes = await httpCall(webui.url, '/api/approvals/approve', {
    method: 'POST',
    headers: postHeaders,
    body: JSON.stringify({ id: approvalId, digest: reviewRes.json().digest }),
  });
  assert.equal(approveRes.status, 200);

  // Retry with same arguments -> executes via real stdio MCP server!
  const replayId = randomUUID();
  const stdioResult = await sendRelayRpc({
    jsonrpc: '2.0',
    id: 4,
    method: 'tools/call',
    params: { name: 'mcp__demo_stdio__echo_upper', arguments: { text: 'hello agentdock' } },
  }, ['computer:read', 'computer:write', 'computer:execute'], replayId);
  const parsedStdio = JSON.parse(stdioResult.result.content[0].text);
  assert.equal(parsedStdio.text, 'HELLO AGENTDOCK');
  assert.equal(parsedStdio.hasCustom, true);
  assert.equal(parsedStdio.leakedBridge, false);

  // Replaying same bridge request ID must be rejected by RequestReceipts
  const replayDenied = await sendRelayRpc({
    jsonrpc: '2.0',
    id: 5,
    method: 'tools/call',
    params: { name: 'mcp__demo_stdio__echo_upper', arguments: { text: 'hello agentdock' } },
  }, ['computer:read', 'computer:write', 'computer:execute'], replayId);
  assert.ok(replayDenied.error);
  assert.match(replayDenied.error.message, /already attempted/);

  // Also test Streamable HTTP MCP tool approval + execution
  const httpNeedApproval = await sendRelayRpc({
    jsonrpc: '2.0',
    id: 6,
    method: 'tools/call',
    params: { name: 'mcp__demo_http__add_nums', arguments: { a: 19, b: 23 } },
  });
  assert.equal(httpNeedApproval.error?.data?.code, 'LOCAL_APPROVAL_REQUIRED');
  assert.equal(httpMcp.getCallCount(), 0);
  const httpReview = (await httpCall(webui.url, '/api/approvals/review', {
    method: 'POST',
    headers: postHeaders,
    body: JSON.stringify({ id: httpNeedApproval.error.data.approval_id }),
  })).json();
  await httpCall(webui.url, '/api/approvals/approve', {
    method: 'POST',
    headers: postHeaders,
    body: JSON.stringify({ id: httpNeedApproval.error.data.approval_id, digest: httpReview.digest }),
  });
  const httpOut = await sendRelayRpc({
    jsonrpc: '2.0',
    id: 7,
    method: 'tools/call',
    params: { name: 'mcp__demo_http__add_nums', arguments: { a: 19, b: 23 } },
  });
  assert.equal(httpOut.result.content[0].text, '42');
  assert.equal(httpMcp.getCallCount(), 1);

  // Audit log records telemetry only (no raw secrets or tool arguments/outputs)
  const auditText = await fs.readFile(path.join(stateDir, 'audit.jsonl'), 'utf8');
  assert.match(auditText, /mcp__demo_stdio__echo_upper/);
  assert.match(auditText, /mcp__demo_http__add_nums/);
  assert.equal(auditText.includes('HELLO AGENTDOCK'), false);
  assert.equal(auditText.includes('SECRET_ENV_CANARY_42'), false);

  // Disabling demo_stdio live blocks calls immediately without restarting BridgeConnector
  toggleMcpServerSync(stateDir, { id: 'demo_stdio', enabled: false }, { workspaceRoots: [workspace] });
  const liveBlocked = await sendRelayRpc({
    jsonrpc: '2.0',
    id: 8,
    method: 'tools/call',
    params: { name: 'mcp__demo_stdio__echo_upper', arguments: { text: 'after disable' } },
  });
  assert.equal(liveBlocked.error?.data?.code, 'CAPABILITY_DISABLED');

  // Probe helper directly handles unreachable error cleanly
  const badProbe = await probeMcpServer({
    id: 'bad',
    name: 'Bad',
    transport: 'http',
    url: 'http://127.0.0.1:1/mcp',
    headers: {},
    timeoutMs: 3000,
  });
  assert.equal(badProbe.ok, false);
  await connector.stop();
});

test('external MCP security hardening: C1 env/cwd isolation, H2 secret rotation & redaction, H3 schema/mass-assignment, H4 ID disambiguation, H5-H9 & M1/M6/L2', async t => {
  const stateDir = await makeTempState(t);
  const workspace = await fs.mkdtemp(path.join(os.homedir(), '.ad-mcp-hard-ws-'));
  const scriptDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ad-mcp-hard-scripts-'));
  t.after(async () => {
    await fs.rm(workspace, { recursive: true, force: true });
    await fs.rm(scriptDir, { recursive: true, force: true });
  });

  // H4: double-underscore tool name parses unambiguously; server IDs with "__" or trailing "_" are rejected
  assert.deepEqual(parseExternalToolName('mcp__github__repo__list_issues'), {
    serverId: 'github',
    toolName: 'repo__list_issues',
  });
  assert.equal(parseExternalToolName('mcp__a__b__c')?.serverId, 'a');
  assert.throws(() => formatExternalToolName('a__b', 'tool'), /Invalid external MCP/);
  assert.throws(() => formatExternalToolName('trail_', 'tool'), /Invalid external MCP/);

  // H7: trailing-dot origin, cloud metadata, IPv4-mapped IPv6, and non-127.0.0.1 loopback blocked
  assert.throws(
    () => assertSafeMcpHttpUrl('https://bridge.example.test./mcp', { blockedOrigins: ['https://bridge.example.test'] }),
    /cannot target AgentDock/,
  );
  assert.throws(() => assertSafeMcpHttpUrl('https://169.254.169.254/latest/meta-data'), /blocked or reserved/);
  assert.throws(() => assertSafeMcpHttpUrl('http://127.0.0.2:8080/mcp'), /https/);
  assert.throws(() => assertSafeMcpHttpUrl('https://127.0.0.2/mcp'), /blocked or reserved/);
  assert.throws(() => assertSafeMcpHttpUrl('https://[::ffff:127.0.0.1]/mcp'), /blocked or reserved/);

  // C1: symlinked cwd rejected; default cwd is isolated empty temp dir (not workspace/stateDir/cwd); host secrets not inherited
  const realDir = path.join(scriptDir, 'real-cwd');
  const linkCwd = path.join(scriptDir, 'link-cwd');
  await fs.mkdir(realDir, { mode: 0o700 });
  await fs.symlink(realDir, linkCwd);
  assert.throws(() => upsertMcpServerSync(stateDir, {
    id: 'symcwd',
    name: 'Symlink Cwd',
    transport: 'stdio',
    command: process.execPath,
    cwd: linkCwd,
  }, { workspaceRoots: [workspace] }), /symbolic links/);

  const inspectScript = path.join(scriptDir, 'inspect-mcp.mjs');
  const spawnMarker = path.join(scriptDir, 'spawn-count.txt');
  await fs.writeFile(inspectScript, `
import fs from 'node:fs';
import readline from 'node:readline';
fs.appendFileSync(${JSON.stringify(spawnMarker)}, '1\\n');
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on('line', line => {
  if (!line.trim()) return;
  let msg; try { msg = JSON.parse(line); } catch { return; }
  if (msg.method === 'initialize') {
    setTimeout(() => {
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        result: { protocolVersion: '2025-11-25', capabilities: { tools: {} }, serverInfo: { name: 'inspect', version: '1' } },
      }) + '\\n');
    }, 60);
    return;
  }
  if (msg.method === 'tools/list') {
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0',
      id: msg.id,
      result: {
        tools: [{
          name: 'repo__env_check',
          description: 'Check env/cwd isolation and server-initiated ping collision',
          inputSchema: { type: 'object', properties: { ok: { type: 'boolean' } } },
        }],
      },
    }) + '\\n');
    return;
  }
  if (msg.method === 'tools/call') {
    // H8: send a server-initiated request with the SAME id before replying to tools/call
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, method: 'ping', params: {} }) + '\\n');
    setTimeout(() => {
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        result: {
          content: [{
            type: 'text',
            text: JSON.stringify({
              cwd: process.cwd(),
              hasAws: Boolean(process.env.AWS_SECRET_ACCESS_KEY),
              hasDbus: Boolean(process.env.DBUS_SESSION_BUS_ADDRESS),
              hasCustom: process.env.SAFE_APP_KEY === 'SUPER_SECRET_KEY_777',
            }),
          }],
        },
      }) + '\\n');
    }, 20);
  }
});
`, { mode: 0o700 });

  const prevAws = process.env.AWS_SECRET_ACCESS_KEY;
  const prevDbus = process.env.DBUS_SESSION_BUS_ADDRESS;
  process.env.AWS_SECRET_ACCESS_KEY = 'HOST_AWS_CANARY';
  process.env.DBUS_SESSION_BUS_ADDRESS = 'unix:path=/tmp/fake-dbus';
  t.after(() => {
    if (prevAws === undefined) delete process.env.AWS_SECRET_ACCESS_KEY;
    else process.env.AWS_SECRET_ACCESS_KEY = prevAws;
    if (prevDbus === undefined) delete process.env.DBUS_SESSION_BUS_ADDRESS;
    else process.env.DBUS_SESSION_BUS_ADDRESS = prevDbus;
  });

  // Save & probe inspect server
  const savedInspect = upsertMcpServerSync(stateDir, {
    id: 'inspect_srv',
    name: 'Inspect Server',
    transport: 'stdio',
    command: process.execPath,
    args: [inspectScript],
    env: { SAFE_APP_KEY: 'SUPER_SECRET_KEY_777' },
  }, { workspaceRoots: [workspace] });
  const probedInspect = await probeMcpServer(savedInspect, { stateDir });
  assert.equal(probedInspect.ok, true);
  assert.equal(probedInspect.tools[0].name, 'repo__env_check');
  // M5: external tool annotations forced conservative
  assert.equal(probedInspect.tools[0].annotations.readOnlyHint, false);
  assert.equal(probedInspect.tools[0].annotations.destructiveHint, true);

  // H2: changing command/args while secrets exist must fail without replaceSecrets: true
  assert.throws(() => upsertMcpServerSync(stateDir, {
    id: 'inspect_srv',
    name: 'Inspect Server',
    transport: 'stdio',
    command: process.execPath,
    args: ['-e', 'console.log(process.env)'],
  }, { workspaceRoots: [workspace] }), /replaceSecrets/);

  // Store cachedTools via probe result, then verify H5 (single-flight ensureSession) + C1 (cwd/env) + H8 (server ping id collision)
  await fs.rm(spawnMarker, { force: true });
  const hub = createExternalMcpHub({ stateDir, workspaceRoots: [workspace], auditFile: path.join(stateDir, 'audit.jsonl') });
  t.after(() => hub.close());
  // Manually populate cachedTools using saveMcpProbeResultSync? Let's call via WebUI or import saveMcpProbeResultSync
  const { saveMcpProbeResultSync } = await import('../local/mcp-registry.mjs');
  saveMcpProbeResultSync(stateDir, 'inspect_srv', probedInspect, { workspaceRoots: [workspace] });

  const [r1, r2] = await Promise.all([
    hub.callTool('mcp__inspect_srv__repo__env_check', { ok: true }),
    hub.callTool('mcp__inspect_srv__repo__env_check', { ok: true }),
  ]);
  assert.notEqual(r1.isError, true);
  assert.notEqual(r2.isError, true);
  const envOut = JSON.parse(r1.content[0].text);
  assert.equal(envOut.hasAws, false);
  assert.equal(envOut.hasDbus, false);
  assert.equal(envOut.hasCustom, true);
  assert.notEqual(envOut.cwd, workspace);
  assert.notEqual(envOut.cwd, stateDir);
  assert.notEqual(envOut.cwd, process.cwd());
  const spawns = (await fs.readFile(spawnMarker, 'utf8')).trim().split('\n').filter(Boolean);
  assert.equal(spawns.length, 1, 'Concurrent calls must share one single-flight stdio spawn');

  // H6 + H2: immediate-exiting stdio child with secret in stderr must NOT crash on EPIPE and MUST redact secret
  const crashScript = path.join(scriptDir, 'crash-stderr.mjs');
  await fs.writeFile(crashScript, `
process.stderr.write('fatal token leak: SUPER_SECRET_KEY_777 Bearer SECRET_TOK_999\\n');
process.exit(2);
`, { mode: 0o700 });
  const crashProbe = await probeMcpServer({
    id: 'crash_srv',
    name: 'Crash',
    transport: 'stdio',
    command: process.execPath,
    args: [crashScript],
    env: { SAFE_APP_KEY: 'SUPER_SECRET_KEY_777' },
    timeoutMs: 3000,
  }, { stateDir });
  assert.equal(crashProbe.ok, false);
  assert.equal(JSON.stringify(crashProbe).includes('SUPER_SECRET_KEY_777'), false);
  assert.equal(JSON.stringify(crashProbe).includes('SECRET_TOK_999'), false);

  // M1 + M6: HTTP MCP persistent SSE stream (never closes EOF) returns immediately, and HTTP 404 session expiry recovers on next call
  let initCount = 0;
  let forceExpireOnce = true;
  const openSseResponses = new Set();
  const sseHttpServer = http.createServer(async (req, res) => {
    if (req.method === 'DELETE') { res.writeHead(204); res.end(); return; }
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const msg = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (msg.method === 'notifications/initialized') { res.writeHead(202); res.end(); return; }
    if (msg.method === 'initialize') {
      initCount += 1;
      res.writeHead(200, { 'content-type': 'application/json', 'mcp-session-id': `sess-${initCount}` });
      res.end(JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        result: { protocolVersion: '2025-11-25', capabilities: { tools: {} }, serverInfo: { name: 'sse-srv', version: '1' } },
      }));
      return;
    }
    if (msg.method === 'tools/list') {
      // Persistent SSE stream: write event then NEVER call res.end()!
      res.writeHead(200, { 'content-type': 'text/event-stream', 'mcp-session-id': `sess-${initCount}` });
      openSseResponses.add(res);
      res.on('close', () => openSseResponses.delete(res));
      res.write(': keepalive\n\n');
      res.write(`data: ${JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        result: { tools: [{ name: 'ping_sse', description: 'SSE tool', inputSchema: { type: 'object', properties: {} } }] },
      })}\n\n`);
      return;
    }
    if (msg.method === 'tools/call') {
      if (forceExpireOnce) {
        forceExpireOnce = false;
        res.writeHead(404, { 'content-type': 'text/plain' });
        res.end('Session expired Bearer SECRET_HDR_CANARY_88');
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        result: { content: [{ type: 'text', text: `recovered-init-${initCount}` }] },
      }));
    }
  });
  await new Promise(resolve => sseHttpServer.listen(0, '127.0.0.1', resolve));
  const sseUrl = `http://127.0.0.1:${sseHttpServer.address().port}/mcp`;
  t.after(() => new Promise(resolve => {
    for (const r of openSseResponses) r.destroy();
    sseHttpServer.closeAllConnections?.();
    sseHttpServer.close(resolve);
  }));

  const savedSse = upsertMcpServerSync(stateDir, {
    id: 'sse_srv',
    name: 'SSE Server',
    transport: 'http',
    url: sseUrl,
    headers: { Authorization: 'Bearer SECRET_HDR_CANARY_88' },
  }, { workspaceRoots: [workspace] });
  const probedSse = await probeMcpServer(savedSse, { stateDir });
  assert.equal(probedSse.ok, true, 'Persistent SSE stream must resolve without waiting for EOF');
  saveMcpProbeResultSync(stateDir, 'sse_srv', probedSse, { workspaceRoots: [workspace] });

  // First call hits 404 session expiry -> error must NOT leak secret header; session marks closed
  const expiredCall = await hub.callTool('mcp__sse_srv__ping_sse', {});
  assert.equal(expiredCall.isError, true);
  assert.equal(expiredCall.content[0].text.includes('SECRET_HDR_CANARY_88'), false);
  // Next call transparently re-initializes and succeeds!
  const recoveredCall = await hub.callTool('mcp__sse_srv__ping_sse', {});
  assert.notEqual(recoveredCall.isError, true);
  assert.equal(recoveredCall.content[0].text, 'recovered-init-3');

  // H3 + H9 + L2 via WebUI HTTP API:
  await fs.writeFile(path.join(stateDir, 'config.json'), JSON.stringify({
    origin: 'http://127.0.0.1:8797',
    roots: [workspace],
    defaultCwd: workspace,
    allowExec: true,
    requireLocalApproval: true,
    sandbox: { enabled: true, allowOutbound: false, image: `sha256:${'a'.repeat(64)}`, context: 'default' },
  }), { mode: 0o600 });
  setStrongPasswordSync(stateDir, {
    password: 'HardMcp!Strong#2026Aa',
    allowBypassTicket: true,
    workspaceRoots: [workspace],
    passkeyDetector: () => ({ supported: false, reason: 'none' }),
  });

  let releaseSlowProbe;
  let slowProbeStarted;
  const slowProbeStartedPromise = new Promise(resolve => { slowProbeStarted = resolve; });
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
      if (srv.id === 'slow_del') {
        slowProbeStarted();
        await new Promise(resolve => { releaseSlowProbe = resolve; });
        return { ok: true, latencyMs: 10, tools: [] };
      }
      return { ok: true, latencyMs: 5, tools: [] };
    },
  });
  t.after(() => webui.close());

  const home = await httpCall(webui.url, '/');
  let csrf = home.text.match(/<meta name="agentdock-csrf" content="([^"]+)"/)?.[1];
  let cookie = mergeCookieHeader('', home.headers['set-cookie']);
  const login = await httpCall(webui.url, '/api/auth/login/password', {
    method: 'POST',
    headers: { origin: webui.url, cookie, 'x-agentdock-csrf': csrf, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: JSON.stringify({ password: 'HardMcp!Strong#2026Aa' }),
  });
  csrf = login.json().csrfToken;
  const tabToken = login.json().tabToken;
  cookie = mergeCookieHeader(cookie, login.headers['set-cookie']);
  const headers = {
    origin: webui.url,
    cookie,
    'x-agentdock-csrf': csrf,
    'x-agentdock-tab-auth': tabToken,
    'sec-fetch-site': 'same-origin',
    'content-type': 'application/json',
  };

  // H3: mass assignment of cachedTools / lastProbeOk via /save must be stripped
  const massRes = await httpCall(webui.url, '/api/mcp-servers/save', {
    method: 'POST',
    headers,
    body: JSON.stringify({
      id: 'mass_test',
      name: 'Mass Test',
      transport: 'stdio',
      command: process.execPath,
      args: ['-v'],
      lastProbeOk: true,
      cachedTools: [{ name: 'injected_tool', inputSchema: { type: 'object', properties: { bad: null } } }],
    }),
  });
  assert.equal(massRes.status, 200);
  assert.equal(massRes.json().server.toolCount, 0);
  assert.equal(massRes.json().server.lastProbeOk, null);

  // H3: malformed properties in mcp-servers.json must NOT crash /api/status
  const rawMcpFile = JSON.parse(await fs.readFile(mcpServersFilePath(stateDir), 'utf8'));
  rawMcpFile.servers.find(s => s.id === 'mass_test').cachedTools = [
    { name: 'weird_tool', description: 'ok', inputSchema: { type: 'object', properties: { bad: null, good: { type: 'string' } } } },
  ];
  await fs.writeFile(mcpServersFilePath(stateDir), JSON.stringify(rawMcpFile, null, 2), { mode: 0o600 });
  const statusOk = await httpCall(webui.url, '/api/status', { headers: { cookie, 'x-agentdock-tab-auth': tabToken } });
  assert.equal(statusOk.status, 200);

  // L2: duplicate slugified IDs rejected; atomic import rolls back on invalid later entry
  assert.throws(() => parseStandardMcpJson({
    mcpServers: {
      'My Server': { command: 'node' },
      'my-server': { command: 'node' },
    },
  }), /Duplicate MCP server ID/);

  const badBatch = await httpCall(webui.url, '/api/mcp-servers/import', {
    method: 'POST',
    headers,
    body: JSON.stringify({
      json: JSON.stringify({
        mcpServers: {
          good_one: { command: 'node', args: ['-v'] },
          bad_one: { url: 'http://evil.example.com/mcp' },
        },
      }),
    }),
  });
  assert.equal(badBatch.status, 400);
  const regAfterBad = readMcpServersSync(stateDir, { workspaceRoots: [workspace] });
  assert.equal(regAfterBad.servers.some(s => s.id === 'good_one'), false, 'Failed batch import must not partially persist');

  // H9: deleting a server mid-probe must NOT cause a 500 error
  await httpCall(webui.url, '/api/mcp-servers/save', {
    method: 'POST',
    headers,
    body: JSON.stringify({ id: 'slow_del', name: 'Slow Del', transport: 'stdio', command: process.execPath, args: ['-v'] }),
  });
  const probeReq = httpCall(webui.url, '/api/mcp-servers/probe', {
    method: 'POST',
    headers,
    body: JSON.stringify({ id: 'slow_del' }),
  });
  await slowProbeStartedPromise;
  const delDuringProbe = await httpCall(webui.url, '/api/mcp-servers/delete', {
    method: 'POST',
    headers,
    body: JSON.stringify({ id: 'slow_del' }),
  });
  assert.equal(delDuringProbe.status, 200);
  releaseSlowProbe();
  const probeDone = await probeReq;
  assert.equal(probeDone.status, 200);
  assert.equal(probeDone.json().server, null);
});

test('external MCP Round 2 regressions: H4 URL preservation, H8 cwd guard, H9 caller-isolated single-flight & close, H10 IPv6/RFC1918/redirect, H11 pre-truncation redaction, M9 schema', async t => {
  const stateDir = await makeTempState(t);
  const workspace = await fs.mkdtemp(path.join(os.homedir(), '.ad-mcp-r2-ws-'));
  const scriptDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ad-mcp-r2-scripts-'));
  const cwdA = path.join(scriptDir, 'cwd-a');
  const cwdB = path.join(scriptDir, 'cwd-b');
  await fs.mkdir(cwdA, { mode: 0o700 });
  await fs.mkdir(cwdB, { mode: 0o700 });
  t.after(async () => {
    await fs.rm(workspace, { recursive: true, force: true });
    await fs.rm(scriptDir, { recursive: true, force: true });
  });

  // H8: expanded env blocklist, cwd preservation on partial edit, and replaceSecrets required when cwd changes
  for (const forbidden of ['LD_ANY_CUSTOM', 'DYLD_CUSTOM', 'JAVA_TOOL_OPTIONS', 'PYTHONHOME', 'GLIBC_TUNABLES', 'AGENTDOCK_EXTRA']) {
    assert.equal(isForbiddenEnvKey(forbidden), true, `${forbidden} must be blocked`);
  }
  const withCwd = upsertMcpServerSync(stateDir, {
    id: 'cwd_guard',
    name: 'Cwd Guard',
    transport: 'stdio',
    command: process.execPath,
    args: ['-v'],
    cwd: cwdA,
    env: { MY_SECRET: 'CWD_SECRET_12345' },
  }, { workspaceRoots: [workspace] });
  assert.equal(withCwd.cwd, await fs.realpath(cwdA));

  // Omitting cwd preserves existing cwd
  const partialEdit = upsertMcpServerSync(stateDir, {
    id: 'cwd_guard',
    name: 'Cwd Guard Renamed',
    transport: 'stdio',
    command: process.execPath,
    args: ['-v'],
  }, { workspaceRoots: [workspace] });
  assert.equal(partialEdit.cwd, withCwd.cwd);
  assert.equal(partialEdit.env.MY_SECRET, 'CWD_SECRET_12345');

  // Changing cwd while secrets exist MUST require replaceSecrets: true
  assert.throws(() => upsertMcpServerSync(stateDir, {
    id: 'cwd_guard',
    name: 'Cwd Guard Moved',
    transport: 'stdio',
    command: process.execPath,
    args: ['-v'],
    cwd: cwdB,
  }, { workspaceRoots: [workspace] }), /replaceSecrets/);

  // H4: URL hash & query redaction + urlRedacted flag + omitting url preserves stored URL
  const httpSaved = upsertMcpServerSync(stateDir, {
    id: 'url_keep',
    name: 'URL Keep',
    transport: 'http',
    url: 'https://mcp.example.test/api?token=QUERY_CANARY_99#HASH_CANARY_77',
    headers: { Authorization: 'Bearer HDR_CANARY_55' },
  }, { workspaceRoots: [workspace] });
  const httpSummary = publicMcpServerSummary(httpSaved);
  assert.equal(httpSummary.urlRedacted, true);
  assert.equal(httpSummary.url.includes('QUERY_CANARY_99'), false);
  assert.equal(httpSummary.url.includes('HASH_CANARY_77'), false);
  assert.match(redactUrlForDisplay(httpSaved.url), /#\[REDACTED\]$/);
  const httpEdited = upsertMcpServerSync(stateDir, {
    id: 'url_keep',
    name: 'URL Keep Edited',
    transport: 'http',
  }, { workspaceRoots: [workspace] });
  assert.equal(httpEdited.url, httpSaved.url);
  assert.equal(httpEdited.headers.Authorization, 'Bearer HDR_CANARY_55');

  // H10 & M6: full IPv4/IPv6 blocked IP parser + https://localhost & http://localhost. rejections
  for (const blocked of [
    '0:0:0:0:0:0:0:1',
    '0:0:0:0:0:0:0:0',
    '::127.0.0.1',
    '::ffff:0:127.0.0.1',
    '::ffff:10.0.0.1',
    '64:ff9b::169.254.169.254',
    '64:ff9b:1::1',
    '2002:0a00:0001::1',
    'ff02::1',
    'fec0::1',
    '100::1',
    '10.0.0.1',
    '100.100.100.200',
    '172.16.0.1',
    '192.168.1.1',
    '198.18.0.1',
    '224.0.0.1',
    '240.0.0.1',
  ]) {
    assert.equal(isBlockedIpAddress(blocked, { allowLoopback127: false }), true, `${blocked} must be blocked`);
  }
  assert.equal(isBlockedIpAddress('0:0:0:0:0:0:0:1', { allowLoopback127: true }), false);
  assert.equal(isBlockedIpAddress('93.184.216.34', { allowLoopback127: false }), false);
  assert.equal(isBlockedIpAddress('2606:2800:220:1:248:1893:25c8:1946', { allowLoopback127: false }), false);
  assert.throws(() => assertSafeMcpHttpUrl('https://localhost/mcp'), /blocked or reserved/);
  assert.throws(() => assertSafeMcpHttpUrl('http://localhost./mcp'), /trailing dots/);

  // H10: HTTP 3xx redirects must be rejected without following
  const redirectSrv = http.createServer((_req, res) => {
    res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' });
    res.end();
  });
  await new Promise(resolve => redirectSrv.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { redirectSrv.closeAllConnections?.(); redirectSrv.close(resolve); }));
  const redirProbe = await probeMcpServer({
    id: 'redir_srv',
    name: 'Redir',
    transport: 'http',
    url: `http://127.0.0.1:${redirectSrv.address().port}/mcp`,
    headers: {},
    timeoutMs: 3000,
  }, { stateDir });
  assert.equal(redirProbe.ok, false);
  assert.match(redirProbe.error, /redirect/i);

  // H11: Pre-truncation secret redaction (straddling truncation boundary, bare auth sub-token, URL query & hash)
  const straddleText = `${'A'.repeat(190)}BARE_SUBTOK_998877${'B'.repeat(50)}QUERY_TOK_665544 HASH_TOK_332211`;
  const redacted = redactSecretsFromText(straddleText, {
    url: 'https://mcp.example.test/x?k=QUERY_TOK_665544#HASH_TOK_332211',
    headers: { Authorization: 'Bearer BARE_SUBTOK_998877' },
    env: {},
  }, 200);
  assert.equal(redacted.includes('BARE_SUBTOK'), false);
  assert.equal(redacted.includes('QUERY_TOK'), false);
  assert.equal(redacted.includes('HASH_TOK'), false);

  const leakErrSrv = http.createServer((_req, res) => {
    res.writeHead(500, { 'content-type': 'text/plain' });
    res.end(`${'X'.repeat(192)}BARE_ERR_SECRET_4242 trailing QUERY_ERR_9988`);
  });
  await new Promise(resolve => leakErrSrv.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { leakErrSrv.closeAllConnections?.(); leakErrSrv.close(resolve); }));
  const leakProbe = await probeMcpServer({
    id: 'leak_srv',
    name: 'Leak',
    transport: 'http',
    url: `http://127.0.0.1:${leakErrSrv.address().port}/mcp?key=QUERY_ERR_9988`,
    headers: { Authorization: 'Bearer BARE_ERR_SECRET_4242' },
    timeoutMs: 3000,
  }, { stateDir });
  assert.equal(leakProbe.ok, false);
  assert.equal(leakProbe.error.includes('BARE_ERR_SECRET'), false);
  assert.equal(leakProbe.error.includes('QUERY_ERR'), false);

  // M9: sanitizeInputSchema drops BiDi propName, strips control chars from enum, omits empty enum, preserves array items
  const normTool = normalizeCachedTool({
    name: 'schema_tool',
    description: 'ok',
    inputSchema: {
      type: 'object',
      properties: {
        'bad\u202ename': { type: 'string' },
        tags: { type: 'array', items: { type: 'integer', description: 'tag\u202eid' } },
        mode: { type: 'string', enum: ['fast\u202e', 'fast', 'safe'] },
        badEnum: { type: 'string', enum: [{ obj: 1 }] },
      },
      required: ['bad\u202ename', 'tags'],
    },
  });
  assert.equal(Object.hasOwn(normTool.inputSchema.properties, 'bad\u202ename'), false);
  assert.deepEqual(normTool.inputSchema.required, ['tags']);
  assert.deepEqual(normTool.inputSchema.properties.tags.items, { type: 'integer', description: 'tagid' });
  assert.deepEqual(normTool.inputSchema.properties.mode.enum, ['fast', 'safe']);
  assert.equal('enum' in normTool.inputSchema.properties.badEnum, false);

  // H9: Caller 1 aborting during single-flight handshake MUST NOT kill caller 2; hub.close() cleans tempCwd
  const slowInitScript = path.join(scriptDir, 'slow-init-mcp.mjs');
  await fs.writeFile(slowInitScript, `
import readline from 'node:readline';
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on('line', line => {
  if (!line.trim()) return;
  let msg; try { msg = JSON.parse(line); } catch { return; }
  if (msg.method === 'initialize') {
    setTimeout(() => {
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        result: { protocolVersion: '2025-11-25', capabilities: { tools: {} }, serverInfo: { name: 'slow-init', version: '1' } },
      }) + '\\n');
    }, 250);
  } else if (msg.method === 'tools/list') {
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0',
      id: msg.id,
      result: { tools: [{ name: 'slow_echo', description: 'echo', inputSchema: { type: 'object', properties: {} } }] },
    }) + '\\n');
  } else if (msg.method === 'tools/call') {
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0',
      id: msg.id,
      result: { content: [{ type: 'text', text: process.cwd() }] },
    }) + '\\n');
  }
});
`, { mode: 0o700 });

  const slowSrv = upsertMcpServerSync(stateDir, {
    id: 'slow_sf',
    name: 'Slow SingleFlight',
    transport: 'stdio',
    command: process.execPath,
    args: [slowInitScript],
    timeoutMs: 10000,
  }, { workspaceRoots: [workspace] });
  const slowProbe = await probeMcpServer(slowSrv, { stateDir });
  assert.equal(slowProbe.ok, true);
  saveMcpProbeResultSync(stateDir, 'slow_sf', slowProbe, { workspaceRoots: [workspace] });

  const hub = createExternalMcpHub({ stateDir, workspaceRoots: [workspace], auditFile: path.join(stateDir, 'audit.jsonl') });
  const c1 = new AbortController();
  const c2 = new AbortController();
  const p1 = hub.callTool('mcp__slow_sf__slow_echo', {}, { signal: c1.signal });
  const p2 = hub.callTool('mcp__slow_sf__slow_echo', {}, { signal: c2.signal });
  setTimeout(() => c1.abort(new Error('caller1 cancelled')), 50);
  const [r1, r2] = await Promise.allSettled([p1, p2]);
  assert.equal(r1.status, 'rejected', 'Aborted caller 1 must reject with cancellation error');
  assert.match(r1.reason?.message || '', /cancelled/i);
  assert.equal(r2.status, 'fulfilled', 'Caller 2 must succeed despite caller 1 aborting single-flight connect');
  const out2 = r2.value;
  assert.notEqual(out2.isError, true);
  const tempCwdUsed = out2.content[0].text;
  assert.ok(tempCwdUsed && tempCwdUsed.includes('agentdock-mcp-'));
  await hub.close();
  await assert.rejects(fs.access(tempCwdUsed), { code: 'ENOENT' });

  // R7-C1/C5: Percent-encoded query secrets & bare query tokens never leak; saveMcpProbeResultSync invalidates liveToolsByServer.
  const pctSecretUrl = 'https://func.example.test/api/mcp?code=abc%2Fdef%2B123%3D%3D';
  const pctRedacted = redactSecretsFromText(`HTTP 401 ${pctSecretUrl}`, { url: pctSecretUrl });
  assert.equal(pctRedacted.includes('abc%2Fdef'), false);
  const bareSecretUrl = 'https://mcp.example.test/sse?sk_live_supersecret999';
  const bareDisplay = redactUrlForDisplay(bareSecretUrl);
  assert.equal(bareDisplay.includes('sk_live_supersecret999'), false);
  assert.equal(redactSecretsFromText(`Err ${bareSecretUrl}`, { url: bareSecretUrl }).includes('sk_live_supersecret999'), false);

  saveMcpProbeResultSync(stateDir, 'slow_sf', {
    ok: true,
    latencyMs: 5,
    tools: [{ name: 'slow_echo', description: 'echo', inputSchema: { type: 'object', properties: {} } }],
  }, { workspaceRoots: [workspace] });
  const refreshHub = createExternalMcpHub({ stateDir, workspaceRoots: [workspace], auditFile: path.join(stateDir, 'audit.jsonl') });
  const liveRes = await refreshHub.callTool('mcp__slow_sf__slow_echo', {});
  assert.notEqual(liveRes.isError, true);
  assert.equal(refreshHub.getConfiguredToolScopes().has('mcp__slow_sf__slow_echo_v2'), false);
  saveMcpProbeResultSync(stateDir, 'slow_sf', {
    ok: true,
    latencyMs: 4,
    tools: [
      { name: 'slow_echo', description: 'echo', inputSchema: { type: 'object', properties: {} } },
      { name: 'slow_echo_v2', description: 'echo v2', inputSchema: { type: 'object', properties: {} } },
    ],
  }, { workspaceRoots: [workspace] });
  assert.equal(refreshHub.getConfiguredToolScopes().has('mcp__slow_sf__slow_echo_v2'), true);
  await refreshHub.close();
});
