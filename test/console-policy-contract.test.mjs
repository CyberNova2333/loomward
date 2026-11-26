// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { once } from 'node:events';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { WebSocketServer } from 'ws';
import { BridgeConnector } from '../local/connector.mjs';
import { digest } from '../local/request-policy.mjs';
import { issueSetupTicketSync } from '../local/webui-auth.mjs';
import { startWebUiServer } from '../local/webui.mjs';
import { startUnifiedConsole } from '../packages/console/src/index.mjs';

for (const [prefix, start] of [['agentdock', startWebUiServer], ['loomward', startUnifiedConsole]]) {
  test(`${prefix} console binds reviews, enforces read-only changes and revokes open streams`, { timeout: 30000 }, async t => {
    const base = await fs.mkdtemp(path.join(os.homedir(), '.lw-contract-'));
    const cleanup = [];
    t.after(async () => {
      try { for (const close of cleanup.reverse()) await close(); }
      finally { await fs.rm(base, { recursive: true, force: true }); }
    });
    const stateDir = path.join(base, 'state');
    const workspace = path.join(base, 'workspace');
    const approvals = path.join(stateDir, 'approvals');
    await fs.mkdir(approvals, { recursive: true, mode: 0o700 });
    await fs.mkdir(workspace, { mode: 0o700 });
    const relay = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await once(relay, 'listening');
    cleanup.push(() => new Promise(resolve => relay.close(resolve)));
    const origin = `http://127.0.0.1:${relay.address().port}`;
    await fs.writeFile(path.join(stateDir, 'config.json'), JSON.stringify({
      origin, roots: [workspace], allowExec: true, requireLocalApproval: true,
    }), { mode: 0o600 });
    const passkeyDetector = () => ({ supported: false, reason: 'fixture' });
    const server = await start({ stateDir, runtimeRoot: path.resolve(import.meta.dirname, '..'), host: '127.0.0.1',
      port: 0, consolePort: 0, pollIntervalMs: 0, passkeyDetector,
      gatewayProbe: async () => ({}), dockerProbe: async () => ({ runningContainers: [] }),
      systemdProbe: async () => ({ supported: false }),
    });
    cleanup.push(() => server.close());
    const home = await fetch(server.url);
    const csrf = (await home.text()).match(new RegExp(`name="${prefix}-csrf" content="([^"]+)"`))[1];
    const cookie = r => r.headers.getSetCookie().map(v => v.split(';')[0]).join('; ');
    const headers = { origin: server.url, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json',
      cookie: cookie(home), [`x-${prefix}-csrf`]: csrf };
    const post = (route, data) => fetch(server.url + '/api/' + route, { method: 'POST', headers, body: JSON.stringify(data) });
    const { setupToken } = issueSetupTicketSync(stateDir, { workspaceRoots: [workspace], passkeyDetector });
    const login = await post('auth/setup/password', { setupToken, password: crypto.randomBytes(18).toString('hex') + 'Z!8q' });
    assert.equal(login.status, 200);
    const session = await login.json();
    Object.assign(headers, { cookie: cookie(login), [`x-${prefix}-csrf`]: session.csrfToken, [`x-${prefix}-tab-auth`]: session.tabToken });

    const id = crypto.randomUUID();
    const authorization = { userId: 'owner', clientId: 'contract', scope: ['computer:read', 'computer:write'] };
    const request = { origin, authorization, method: 'tools/call', params: { name: 'write_file', arguments: { path: '/workspace/note.txt', content: 'first' } } };
    const createdAt = Date.now();
    const save = () => fs.writeFile(path.join(approvals, id + '.request.json'), JSON.stringify({
      id, request, hash: digest(request), createdAt, expiresAt: createdAt + 300000,
    }), { mode: 0o600 });
    await save();
    const review = async () => {
      const res = await post('approvals/review', { id });
      assert.equal(res.status, 200);
      return (await res.json()).digest;
    };
    const original = await review();
    request.params.arguments.content = 'second';
    await save();
    assert.equal((await post('approvals/approve', { id, digest: original })).status, 409);
    await assert.rejects(fs.access(path.join(approvals, id + '.approved.json')), { code: 'ENOENT' });
    const current = await review();
    assert.notEqual(current, original);
    assert.equal((await post('approvals/approve', { id, digest: current })).status, 200);
    assert.equal((await post('capabilities', { fileWrite: false })).status, 200);

    let executions = 0;
    const connector = new BridgeConnector({ origin, stateDir, workspaceRoots: [workspace], bridgeToken: 'contract',
      proxyProvider: () => [null], runtime: { handleRpc: async () => { executions++; }, close: async () => {} } });
    const connected = once(relay, 'connection');
    await connector.start();
    const [socket] = await connected;
    cleanup.push(async () => { await connector.stop(); socket.terminate(); await connector.logQueue; });
    const reply = new Promise(resolve => socket.on('message', raw => {
      const frame = JSON.parse(raw);
      if (frame.type === 'ping') socket.send('{"type":"pong"}');
      if (frame.id === id && frame.type === 'response') resolve(frame.body);
    }));
    socket.send(JSON.stringify({ type: 'request', id, issuedAt: createdAt, deadline: createdAt + 90000, authorization,
      body: { jsonrpc: '2.0', id: 1, method: request.method, params: request.params } }));
    assert.equal((await reply).error?.data?.code, 'CAPABILITY_DISABLED');
    assert.equal(executions, 0);
    await assert.rejects(fs.access(path.join(workspace, 'note.txt')), { code: 'ENOENT' });

    const stream = http.get(server.url + '/api/events', { headers });
    cleanup.push(() => stream.destroy());
    const [response] = await once(stream, 'response');
    assert.equal(response.statusCode, 200);
    response.resume();
    const ended = once(response, 'end', { signal: AbortSignal.timeout(5000) });
    assert.equal((await post('auth/logout', {})).status, 200);
    await ended;
    assert.equal((await fetch(server.url + '/api/status', { headers })).status, 401);
  });
}
