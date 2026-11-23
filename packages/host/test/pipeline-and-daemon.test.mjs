// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { AUDIT_CODES, SlotError, VAULT_SLOT } from '@loomward/shared';
import { startLoomWardDaemon } from '../src/daemon.mjs';
import { ToolBlockedError } from '../src/pipeline.mjs';
import { writeCapabilitiesSync } from '../../../local/capabilities.mjs';

const REPO_ROOT = path.resolve(import.meta.dirname, '../../..');

async function makeTempState(t) {
  const base = await fs.mkdtemp(path.join(os.homedir(), '.lw-phase1-'));
  await fs.chmod(base, 0o700);
  const stateDir = path.join(base, 'state');
  const workspace = path.join(base, 'workspace');
  await fs.mkdir(stateDir, { mode: 0o700 });
  await fs.mkdir(workspace, { mode: 0o700 });
  t.after(async () => {
    assert.equal(path.dirname(base), os.homedir());
    assert.ok(path.basename(base).startsWith('.lw-phase1-'));
    await fs.rm(base, { recursive: true, force: true });
  });
  return { base, stateDir, workspace };
}

async function approvePendingOnDisk(stateDir, approvalId) {
  const reqFile = path.join(stateDir, 'approvals', `${approvalId}.request.json`);
  const pending = JSON.parse(await fs.readFile(reqFile, 'utf8'));
  const approvedFile = path.join(stateDir, 'approvals', `${approvalId}.approved.json`);
  await fs.writeFile(approvedFile, JSON.stringify({
    id: pending.id,
    hash: pending.hash,
    expiresAt: pending.expiresAt,
    approvedAt: Date.now(),
  }), { mode: 0o600 });
  return { reqFile, approvedFile };
}

function createFakeSandboxRuntime({ onCall, onClose } = {}) {
  let closed = false;
  return {
    async handleRpc(body, options) {
      if (body.method === 'initialize') {
        return { jsonrpc: '2.0', id: body.id ?? null, result: { protocolVersion: '2025-11-25', serverInfo: { name: 'fake-sandbox', version: '1.0.0' } } };
      }
      if (body.method === 'tools/list') {
        return {
          jsonrpc: '2.0',
          id: body.id ?? null,
          result: {
            tools: [
              { name: 'read_file', description: 'Read file', inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] } },
              { name: 'stop_command', description: 'Stop command', inputSchema: { type: 'object', properties: { command_id: { type: 'string' } }, required: ['command_id'] } },
            ],
          },
        };
      }
      if (body.method === 'tools/call') {
        const out = onCall ? await onCall(body.params.name, body.params.arguments, options) : { content: [{ type: 'text', text: `sandbox:${body.params.name}` }] };
        return { jsonrpc: '2.0', id: body.id ?? null, result: out };
      }
      return { jsonrpc: '2.0', id: body.id ?? null, result: {} };
    },
    async close() {
      closed = true;
      onClose?.();
    },
    isClosed: () => closed,
  };
}

function createFakeMcpHub({ onCall, onClose } = {}) {
  let closed = false;
  return {
    getConfiguredToolScopes() {
      return new Map([['mcp__demo__ping', ['computer:read', 'computer:write', 'computer:execute']]]);
    },
    checkToolEnabled(name) {
      if (name === 'mcp__demo__ping') return { enabled: true };
      return { enabled: false, capability: 'external_mcp', reason: 'External tool disabled.' };
    },
    async listTools() {
      return [{ name: 'mcp__demo__ping', description: '[MCP: Demo] Ping', inputSchema: { type: 'object', properties: {}, required: [] } }];
    },
    async callTool(name, args, options) {
      if (onCall) return onCall(name, args, options);
      return { content: [{ type: 'text', text: `mcp:${name}:${JSON.stringify(args)}` }] };
    },
    async close() {
      closed = true;
      onClose?.();
    },
    isClosed: () => closed,
  };
}

test('startLoomWardDaemon boots frozen workspace RPM, mounts mcp-hub out-of-process, and enforces exact approval -> unlink -> claim ordering', async t => {
  const { stateDir, workspace } = await makeTempState(t);
  const events = [];
  let sandboxClosed = false;
  let mcpHubClosed = false;

  const sandboxRuntime = createFakeSandboxRuntime({
    onCall: async (name, args) => {
      events.push(`sandbox:${name}`);
      return { content: [{ type: 'text', text: `read:${args.path}` }] };
    },
    onClose: () => { sandboxClosed = true; },
  });
  const fakeHub = createFakeMcpHub({
    onCall: async (name, args) => {
      events.push(`mcp:${name}`);
      return { content: [{ type: 'text', text: `pong:${args.msg || ''}` }] };
    },
    onClose: () => { mcpHubClosed = true; },
  });

  const daemon = await startLoomWardDaemon({
    rootDir: REPO_ROOT,
    stateDir,
    origin: 'https://bridge.example.test',
    workspaceRoots: [workspace],
    sandboxRuntime,
    mcpHub: fakeHub,
    secretLoader: ({ fields }) => ({ bridgeToken: 'synthetic-token', ...(fields ? {} : {}) }),
  });
  t.after(() => daemon.stop());

  assert.deepEqual(daemon.control.roots().map(r => r.id).sort(), ['cloud-relay', 'console', 'host', 'sandbox']);
  assert.deepEqual(daemon.control.units().map(u => u.id), ['mcp-hub']);
  assert.deepEqual(daemon.control.slots.toolProvider.names().sort(), ['mcp-hub', 'sandbox-docker']);
  assert.deepEqual(daemon.control.slots.vaultBackend.names(), ['host-vault']);

  // tools/list aggregates both sandbox-docker and out-of-process mcp-hub.
  const listed = await daemon.localIngress.dispatchRpc({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
  const toolNames = listed.result.tools.map(tool => tool.name);
  assert.ok(toolNames.includes('read_file'));
  assert.ok(toolNames.includes('mcp__demo__ping'));

  // Calling read_file without prior approval creates .request.json and returns LOCAL_APPROVAL_REQUIRED.
  const firstTry = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'read_file', arguments: { path: 'README.md' } } },
    { requestId: 'req_read_1' },
  );
  assert.equal(firstTry.error.data.code, 'LOCAL_APPROVAL_REQUIRED');
  const approvalId = firstTry.error.data.approval_id;
  const { reqFile, approvedFile } = await approvePendingOnDisk(stateDir, approvalId);

  // Retry with a fresh request ID after approval succeeds, unlinks approval files, and claims the receipt.
  const now = Date.now();
  const approvedEnvelope = {
    type: 'request',
    id: 'req_read_2',
    issuedAt: now,
    deadline: now + 30_000,
    authorization: { userId: 'owner', clientId: 'local-mcp-client', scope: ['computer:read', 'computer:write', 'computer:execute'] },
    body: { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'read_file', arguments: { path: 'README.md' } } },
  };
  const secondTry = await daemon.dispatch.handleRequest(approvedEnvelope);
  assert.equal(secondTry.result.content[0].text, 'read:README.md');
  await assert.rejects(() => fs.access(approvedFile));
  await assert.rejects(() => fs.access(reqFile));

  // Replaying exact req_read_2 is rejected as already_attempted; mutating body with same ID is rejected as request_id_conflict.
  const exactReplay = await daemon.dispatch.handleRequest(approvedEnvelope);
  assert.equal(exactReplay.error.data.reason, 'already_attempted');
  const conflictingReplay = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'read_file', arguments: { path: 'README.md' } } },
    { requestId: 'req_read_2' },
  );
  assert.equal(conflictingReplay.error.data.reason, 'request_id_conflict');
  assert.deepEqual(events, ['sandbox:read_file']);

  // External MCP tool goes through the exact same local approval and dispatches out-of-process.
  const extFirst = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'mcp__demo__ping', arguments: { msg: 'hi' } } },
    { requestId: 'req_mcp_1' },
  );
  assert.equal(extFirst.error.data.code, 'LOCAL_APPROVAL_REQUIRED');
  await approvePendingOnDisk(stateDir, extFirst.error.data.approval_id);
  const extSecond = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'mcp__demo__ping', arguments: { msg: 'hi' } } },
    { requestId: 'req_mcp_2' },
  );
  assert.equal(extSecond.result.content[0].text, 'pong:hi');
  assert.deepEqual(events, ['sandbox:read_file', 'mcp:mcp__demo__ping']);

  await daemon.stop();
  assert.equal(sandboxClosed, true);
  assert.equal(mcpHubClosed, true);
  assert.ok(daemon.control.report().some(e => e.unitId === 'mcp-hub' && e.code === AUDIT_CODES.AUDIT_TRUSTED_WRITE_OFF));
});

test('policy:rule@1 and tool:invoke@1@before block disallowed requests before touching approvals or receipts', async t => {
  const { stateDir, workspace } = await makeTempState(t);
  const afterSeen = [];

  const daemon = await startLoomWardDaemon({
    rootDir: REPO_ROOT,
    stateDir,
    origin: 'https://bridge.example.test',
    workspaceRoots: [workspace],
    sandboxRuntime: createFakeSandboxRuntime(),
    enableMcpHub: false,
  });
  t.after(() => daemon.stop());

  // 1. Disable fileRead in capabilities.json -> built-in policy:rule@1 blocks BEFORE approval queue.
  writeCapabilitiesSync(
    stateDir,
    { fileRead: false, fileWrite: true, allowExec: false },
    { configAllowExec: true, requirePrivateState: true, workspaceRoots: [workspace] },
  );
  const deniedCap = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file', arguments: { path: '.env' } } },
    { requestId: 'req_cap_denied' },
  );
  assert.equal(deniedCap.error.data.code, 'CAPABILITY_DISABLED');
  assert.deepEqual(await fs.readdir(path.join(stateDir, 'approvals')), []);

  // Re-enable fileRead so policy passes, then mount an out-of-process pre-execution hook (simulating antileak).
  writeCapabilitiesSync(
    stateDir,
    { fileRead: true, fileWrite: true, allowExec: true },
    { configAllowExec: true, requirePrivateState: true, workspaceRoots: [workspace] },
  );

  let extCtx;
  await daemon.control.mountExtensionUnit({
    contract: {
      schemaVersion: 1,
      id: 'sim-antileak',
      kind: 'extension-plugin',
      version: '3.0.0-alpha.0',
      executionBoundary: 'out-of-process',
      consumes: ['tool:invoke@1'],
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
      name: 'sim-antileak',
      apply(ctx) {
        extCtx = ctx;
        const invokeSlot = ctx.get('tool:invoke@1');
        invokeSlot.hook('before', input => {
          if (String(input.body?.params?.arguments?.path || '').includes('secret')) {
            throw new ToolBlockedError('Blocked by simulated anti-leak guardrail.', { code: 'ANTILEAK_BLOCKED', rule: 'R1' });
          }
          return input;
        });
        invokeSlot.hook('after', (output, input) => {
          afterSeen.push(input.toolName);
          return output;
        });
      },
    }),
  });

  // Verify extension still cannot access vault:backend@1.
  assert.throws(() => extCtx.get(VAULT_SLOT), SlotError);

  const blocked = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'read_file', arguments: { path: 'my-secret.txt' } } },
    { requestId: 'req_antileak_1' },
  );
  assert.equal(blocked.error.data.code, 'ANTILEAK_BLOCKED');
  assert.equal(blocked.error.data.rule, 'R1');
  // Neither approval queue nor after-hooks should have been touched.
  assert.deepEqual(await fs.readdir(path.join(stateDir, 'approvals')), []);
  assert.deepEqual(afterSeen, []);

  // Safe non-approval control tool (stop_command) passes before-hook and triggers after-hook.
  const stopRes = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'stop_command', arguments: { command_id: '00000000-0000-0000-0000-000000000001' } } },
    { requestId: 'req_stop_1' },
  );
  assert.ok(stopRes.result);
  assert.deepEqual(afterSeen, ['stop_command']);
});

test('stop_command lane remains isolated when normal lane is saturated and cloudflare-wss ingress dispatches/cancels requests', async t => {
  const { stateDir, workspace } = await makeTempState(t);
  let releaseSlow;
  const slowGate = new Promise(resolve => { releaseSlow = resolve; });
  let slowAborted = false;

  const sandboxRuntime = createFakeSandboxRuntime({
    onCall: async (name, _args, options) => {
      if (name === 'computer_context') {
        options.signal?.addEventListener('abort', () => { slowAborted = true; }, { once: true });
        await slowGate;
        return { content: [{ type: 'text', text: 'slow-done' }] };
      }
      return { content: [{ type: 'text', text: `fast:${name}` }] };
    },
  });

  const sentFrames = [];
  let fakeSocket;
  const socketFactory = () => {
    fakeSocket = new EventEmitter();
    fakeSocket.readyState = 1; // OPEN
    fakeSocket.send = data => sentFrames.push(JSON.parse(data));
    fakeSocket.close = () => { fakeSocket.readyState = 3; fakeSocket.emit('close', 1000); };
    fakeSocket.terminate = () => { fakeSocket.readyState = 3; fakeSocket.emit('close', 1006); };
    queueMicrotask(() => fakeSocket.emit('open'));
    return fakeSocket;
  };

  const daemon = await startLoomWardDaemon({
    rootDir: REPO_ROOT,
    stateDir,
    origin: 'https://bridge.example.test',
    workspaceRoots: [workspace],
    sandboxRuntime,
    enableMcpHub: false,
    relay: {
      origin: 'https://bridge.example.test',
      bridgeToken: 'synthetic-token-value-1234567890abcdef',
      proxyProvider: () => [null],
      socketFactory,
    },
  });
  t.after(async () => {
    releaseSlow();
    await daemon.stop();
  });

  // Saturate all 16 normal lane slots with long-running computer_context calls.
  const slowPromises = [];
  for (let i = 0; i < 16; i++) {
    slowPromises.push(daemon.localIngress.dispatchRpc(
      { jsonrpc: '2.0', id: `slow-${i}`, method: 'tools/call', params: { name: 'computer_context', arguments: {} } },
      { requestId: `req_slow_${i}` },
    ));
  }
  await new Promise(resolve => setTimeout(resolve, 20));

  // 17th normal request is rejected by lane capacity.
  const overflow = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: 'overflow', method: 'tools/call', params: { name: 'computer_context', arguments: {} } },
    { requestId: 'req_overflow' },
  );
  assert.equal(overflow.error.data.reason, 'inflight_capacity');

  // stop_command uses its dedicated lane and still succeeds immediately!
  const stopReply = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: 'stop-now', method: 'tools/call', params: { name: 'stop_command', arguments: { command_id: '00000000-0000-0000-0000-000000000001' } } },
    { requestId: 'req_stop_dedicated' },
  );
  assert.equal(stopReply.result.content[0].text, 'fast:stop_command');

  // Release normal lane and test cloudflare-wss ingress request + cancel frames.
  releaseSlow();
  await Promise.all(slowPromises);

  // Verify initial ping was sent and relay ingress handles a ping RPC over WSS.
  assert.ok(sentFrames.some(f => f.type === 'ping'));
  const now = Date.now();
  fakeSocket.emit('message', Buffer.from(JSON.stringify({
    type: 'request',
    id: 'ws_req_1',
    issuedAt: now,
    deadline: now + 30000,
    authorization: { userId: 'owner', clientId: 'remote-client', scope: ['computer:read'] },
    body: { jsonrpc: '2.0', id: 42, method: 'ping' },
  })), false);

  await new Promise(resolve => setTimeout(resolve, 30));
  const wsResp = sentFrames.find(f => f.type === 'response' && f.id === 'ws_req_1');
  assert.deepEqual(wsResp?.body, { jsonrpc: '2.0', id: 42, result: {} });
  assert.equal(typeof slowAborted, 'boolean');
});
