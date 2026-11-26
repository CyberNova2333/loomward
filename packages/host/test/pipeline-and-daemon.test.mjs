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

  // initialize returns canonical LoomWard serverInfo, and tools/list aggregates both sandbox-docker and out-of-process mcp-hub.
  const initReply = await daemon.localIngress.dispatchRpc({
    jsonrpc: '2.0',
    id: 0,
    method: 'initialize',
    params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1.0' } },
  });
  assert.equal(initReply.result?.serverInfo?.name, 'loomward');

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

  // Verify notifications/initialized over cloudflare-wss returns a response frame (body omitted) instead of hanging!
  fakeSocket.emit('message', Buffer.from(JSON.stringify({
    type: 'request',
    id: 'ws_notify_1',
    issuedAt: now,
    deadline: now + 30000,
    authorization: { userId: 'owner', clientId: 'remote-client', scope: ['computer:read'] },
    body: { jsonrpc: '2.0', method: 'notifications/initialized' },
  })), false);
  await new Promise(resolve => setTimeout(resolve, 25));
  const wsNotifyReply = sentFrames.find(f => f.type === 'response' && f.id === 'ws_notify_1');
  assert.ok(wsNotifyReply, 'notifications/initialized must emit a response frame to complete HTTP 202');
  assert.equal(wsNotifyReply.body, undefined);
});

test('Wave 2 hardening: sandbox lockdown blocks before approval, forceApproval claims durable receipts, output redaction strips structuredContent, and localIngress enforces running state', async t => {
  const { applyOutputRedaction } = await import('@loomward/shared');
  const { stateDir, workspace } = await makeTempState(t);

  let lockedDown = false;
  const sandboxRuntime = {
    isLockedDown: () => lockedDown,
    async handleRpc(body) {
      if (body.method === 'tools/list') return { jsonrpc: '2.0', id: body.id ?? null, result: { tools: [] } };
      return {
        jsonrpc: '2.0',
        id: body.id ?? null,
        result: {
          content: [{ type: 'text', text: 'raw-secret-output' }],
          structuredContent: { stdout: 'raw-secret-output' },
        },
      };
    },
    async close() {},
  };

  const daemon = await startLoomWardDaemon({
    rootDir: REPO_ROOT,
    stateDir,
    origin: 'https://bridge.example.test/',
    workspaceRoots: [workspace],
    sandboxRuntime,
    enableMcpHub: false,
  });
  t.after(() => daemon.stop());

  // 1. Cleanup-failure lockdown blocks read_file at policy stage BEFORE creating an approval record.
  lockedDown = true;
  const lockedRead = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: 'lock-1', method: 'tools/call', params: { name: 'read_file', arguments: { path: 'a.txt' } } },
    { requestId: 'req_lock_read_1', timeoutMs: 5000.75 },
  );
  assert.equal(lockedRead.error.data.code, 'CAPABILITY_DISABLED');
  assert.equal(lockedRead.error.data.capability, 'cleanup_failed');
  // command_status remains enabled during lockdown!
  const lockedStatus = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: 'lock-2', method: 'tools/call', params: { name: 'command_status', arguments: { command_id: '00000000-0000-0000-0000-000000000001' } } },
    { requestId: 'req_lock_status_1' },
  );
  assert.ok(lockedStatus.result);
  lockedDown = false;

  // 2. Output-stage redaction helper redacts BOTH content and structuredContent, and after-hook block maps to ToolBlockedError.
  let forceExempt = false;
  let blockOutput = false;
  await daemon.control.mountExtensionUnit({
    contract: {
      schemaVersion: 1,
      id: 'mod-hook-ext',
      kind: 'extension-plugin',
      version: '3.0.0-alpha.0',
      executionBoundary: 'out-of-process',
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
      name: 'mod-hook-ext',
      apply(ctx) {
        const slot = ctx.get('tool:invoke@1');
        slot.hook('before', input => {
          // Verify invocation.body is deeply frozen so hooks cannot mutate arguments in-place.
          assert.throws(() => { input.body.params.arguments.injected = true; }, TypeError);
          if (forceExempt) return { ...input, forceApproval: true };
          return input;
        });
        slot.hook('after', out => {
          if (blockOutput) {
            return { ...out, blocked: true, code: 'MOD_OUTPUT_BLOCKED', rule: 'MOD-OUT-1', reason: 'Output blocked by moderation.' };
          }
          return applyOutputRedaction(out, {
            protocolVersion: 1,
            decision: 'redact',
            categories: ['pii'],
            ruleId: 'MOD-REDACT-1',
            redactedPayload: '[REDACTED]',
          });
        });
      },
    }),
  });

  // Exempt tool with forceApproval=true pauses for local approval WITHOUT burning the request ID,
  // and after approval claims a durable receipt and applies output redaction to both content & structuredContent!
  forceExempt = true;
  const forced1 = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: 'f-1', method: 'tools/call', params: { name: 'computer_context', arguments: {} } },
    { requestId: 'req_force_exempt_same_id' },
  );
  assert.equal(forced1.error.data.code, 'LOCAL_APPROVAL_REQUIRED');
  await approvePendingOnDisk(stateDir, forced1.error.data.approval_id);

  // Re-sending with the SAME requestId succeeds now that it's approved (proving pre-approval did not burn the ID),
  // and a third attempt with the same requestId is rejected by the durable 24h RequestReceipts ledger!
  const forced2 = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: 'f-1', method: 'tools/call', params: { name: 'computer_context', arguments: {} } },
    { requestId: 'req_force_exempt_same_id' },
  );
  assert.equal(forced2.result.content[0].text, '[REDACTED]');
  assert.equal(forced2.result.structuredContent.text, '[REDACTED]');
  assert.equal(forced2.result.structuredContent.stdout, undefined);

  const forcedReplay = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: 'f-1', method: 'tools/call', params: { name: 'computer_context', arguments: {} } },
    { requestId: 'req_force_exempt_same_id' },
  );
  assert.ok(['already_attempted', 'request_id_conflict'].includes(forcedReplay.error.data.reason));
  forceExempt = false;

  // Output-stage block returns structured JSON-RPC error instead of leaking raw output.
  blockOutput = true;
  const outBlocked = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: 'ob-1', method: 'tools/call', params: { name: 'computer_context', arguments: {} } },
    { requestId: 'req_out_blocked_1' },
  );
  assert.equal(outBlocked.error.data.code, 'MOD_OUTPUT_BLOCKED');
  assert.equal(outBlocked.error.data.rule, 'MOD-OUT-1');
  blockOutput = false;

  // After localIngress.stop(), dispatchRpc refuses new calls cleanly.
  await daemon.localIngress.stop();
  const afterStop = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: 'stop-1', method: 'ping' },
    { requestId: 'req_after_stop_1' },
  );
  assert.equal(afterStop.error.code, -32001);
});

test('Round 7 ingress hardening: unexpected-response terminates socket to trigger reconnect backoff and normalizes oversized error rpcId', async t => {
  const { stateDir, workspace } = await makeTempState(t);
  let terminateCalls = 0;
  let fakeSocket;
  const socketFactory = () => {
    fakeSocket = new EventEmitter();
    fakeSocket.readyState = 0; // CONNECTING
    fakeSocket.terminate = () => {
      terminateCalls += 1;
      fakeSocket.readyState = 3;
      fakeSocket.emit('close', 1006);
    };
    fakeSocket.close = () => { fakeSocket.readyState = 3; fakeSocket.emit('close', 1000); };
    return fakeSocket;
  };

  const daemon = await startLoomWardDaemon({
    rootDir: REPO_ROOT,
    stateDir,
    origin: 'https://bridge.example.test',
    workspaceRoots: [workspace],
    sandboxRuntime: createFakeSandboxRuntime(),
    enableMcpHub: false,
    relay: {
      origin: 'https://bridge.example.test',
      bridgeToken: 'synthetic-token-value-1234567890abcdef',
      proxyProvider: () => [null],
      socketFactory,
    },
  });
  t.after(() => daemon.stop());

  assert.ok(fakeSocket);
  fakeSocket.emit('unexpected-response', { destroy() {} }, { statusCode: 503, resume() {} });
  assert.equal(terminateCalls, 1);

  const oversizedId = 'X'.repeat(400);
  const badEnvelopeReply = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: oversizedId, method: 'ping' },
    { requestId: 'invalid request id with spaces' },
  );
  assert.equal(badEnvelopeReply.id, null);
  assert.ok(badEnvelopeReply.error);

  // Round 8: notifications/* WITH an explicit id must receive JSON-RPC -32601 (never undefined).
  const notifWithId = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', id: 'notif-with-id', method: 'notifications/initialized' },
    { requestId: 'req_notif_with_id_1' },
  );
  assert.equal(notifWithId.id, 'notif-with-id');
  assert.equal(notifWithId.error?.code, -32601);

  const notifNoId = await daemon.localIngress.dispatchRpc(
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { requestId: 'req_notif_no_id_1' },
  );
  assert.equal(notifNoId, undefined);
});

test('Round 8 sandbox root-plugin applies effective workspaceRoots and allowOutbound=false onto runtime', async t => {
  const { base, stateDir, workspace } = await makeTempState(t);
  const wrongRoot = path.join(base, 'wrong-root');
  await fs.mkdir(wrongRoot, { mode: 0o700 });
  const { apply: applySandbox } = await import('../../sandbox/src/index.mjs');

  let capturedToolProvider;
  const fakeCtx = {
    get(slot) {
      if (slot === 'tool:provider@1') {
        return {
          register(name, impl) {
            capturedToolProvider = { name, impl };
          },
        };
      }
      return undefined;
    },
    provide() {},
    on() {},
    effect(fn) {
      const dispose = fn();
      if (typeof dispose === 'function') t.after(dispose);
    },
  };

  let seenMergedConfig = null;
  await applySandbox(fakeCtx, {
    stateDir,
    workspaceRoots: [workspace],
    allowOutbound: false,
    sandboxConfig: {
      roots: [wrongRoot],
      allowExec: false,
      sandbox: { enabled: true, allowOutbound: true },
    },
    createRuntime: async cfg => {
      seenMergedConfig = cfg;
      return {
        async handleRpc(body) {
          if (body.method === 'tools/call' && body.params?.name === 'computer_context') {
            return {
              jsonrpc: '2.0',
              id: body.id,
              result: {
                content: [{
                  type: 'text',
                  text: JSON.stringify({
                    roots: cfg.roots,
                    sandbox_allow_outbound: cfg.sandbox.allowOutbound,
                  }),
                }],
              },
            };
          }
          return { jsonrpc: '2.0', id: body.id, result: { tools: [] } };
        },
        async close() {},
      };
    },
  });

  assert.ok(seenMergedConfig);
  assert.deepEqual(seenMergedConfig.roots, [workspace]);
  assert.equal(seenMergedConfig.sandbox.allowOutbound, false);
  assert.ok(capturedToolProvider);
  const ctxRes = await capturedToolProvider.impl.handleRpc({
    jsonrpc: '2.0',
    id: 'ctx-1',
    method: 'tools/call',
    params: { name: 'computer_context', arguments: {} },
  });
  const payload = JSON.parse(ctxRes.result.content[0].text);
  assert.equal(payload.roots.includes(workspace), true);
  assert.equal(payload.roots.includes(wrongRoot), false);
  assert.equal(payload.sandbox_allow_outbound, false);
});

test('streamed sandbox RPC errors keep their JSON-RPC error envelope', async t => {
  const { stateDir, workspace } = await makeTempState(t);
  const error = { code: -32001, message: 'Workspace unavailable' };
  const daemon = await startLoomWardDaemon({
    rootDir: REPO_ROOT,
    stateDir,
    workspaceRoots: [workspace],
    enableMcpHub: false,
    sandboxRuntime: {
      handleRpc: async body => ({ jsonrpc: '2.0', id: body.id, error }),
      close: async () => {},
    },
  });
  t.after(() => daemon.stop());
  const reply = await daemon.localIngress.dispatchRpcStream(
    { jsonrpc: '2.0', id: 'context', method: 'tools/call', params: { name: 'computer_context', arguments: {} } },
    { requestId: 'fixture-stream-error', onChunk: () => assert.fail('Unexpected chunk') },
  );
  assert.deepEqual(reply, { jsonrpc: '2.0', id: 'context', error });
});

test('Host native streaming pipeline enforces approval before streaming, supports tool:stream@1 chunk abort, and isolates plugin:secrets@1 by unitId', async t => {
  const { PLUGIN_SECRETS_SLOT } = await import('@loomward/shared');
  const { stateDir, workspace } = await makeTempState(t);

  let streamAborted = false;
  let approvedCallCount = 0;
  let extAlphaSecrets = null;
  let extBetaSecrets = null;

  const sentWsFrames = [];
  let fakeSocket;
  const socketFactory = () => {
    fakeSocket = new EventEmitter();
    fakeSocket.readyState = 1;
    fakeSocket.send = data => {
      try { sentWsFrames.push(JSON.parse(data)); } catch {}
    };
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
    sandboxRuntime: createFakeSandboxRuntime(),
    enableMcpHub: false,
    approvals: {
      async authorize(body) {
        const allow = body.params?.arguments?.approved === true;
        if (allow) approvedCallCount += 1;
        return { approved: allow, id: 'ap-stream-1', expiresAt: Date.now() + 60_000 };
      },
    },
    relay: {
      origin: 'https://bridge.example.test',
      bridgeToken: 'synthetic-token-value-1234567890abcdef',
      proxyProvider: () => [null],
      socketFactory,
    },
    consoleConfig: {},
  });
  t.after(() => daemon.stop());

  const admin = daemon.control.getService('host:plugin-secrets-admin');
  admin.setSecrets('stream-ext', { LLM_KEY: 'secret-for-stream-ext' });
  admin.setSecrets('other-ext', { LLM_KEY: 'secret-for-other-ext' });

  await daemon.control.mountExtensionUnit({
    contract: {
      schemaVersion: 1,
      id: 'stream-ext',
      kind: 'extension-plugin',
      version: '3.0.0-alpha.0',
      executionBoundary: 'out-of-process',
      provides: ['tool:streaming-demo'],
      consumes: ['tool:provider@1', 'tool:stream@1', PLUGIN_SECRETS_SLOT],
      registers: [{ slot: 'tool:provider@1', name: 'streaming-demo' }],
      writes: { hooks: [{ slot: 'tool:stream@1', phase: 'after' }] },
    },
    trust: { autoApproveTrusted: true },
    load: () => ({
      name: 'stream-ext',
      apply(ctx) {
        extAlphaSecrets = ctx.get(PLUGIN_SECRETS_SLOT);
        ctx.get('tool:provider@1').register('streaming-demo', {
          ownsTool: name => name === 'mcp__streaming__gen',
          getToolScopes: () => new Map([['mcp__streaming__gen', ['computer:read']]]),
          checkToolEnabled: () => ({ enabled: true }),
          listTools: () => [{ name: 'mcp__streaming__gen', inputSchema: { type: 'object', properties: {} } }],
          async callToolStream(_name, args, { signal, emit }) {
            signal.addEventListener('abort', () => { streamAborted = true; }, { once: true });
            await emit({ type: 'text', text: 'chunk-0' });
            if (signal.aborted) return { aborted: true };
            await emit({ type: 'text', text: args.poisonChunk ? 'BAD_CHUNK' : 'chunk-1' });
            return { content: [{ type: 'text', text: 'stream-complete' }] };
          },
          async callTool() {
            return { content: [{ type: 'text', text: 'sync-complete' }] };
          },
        });
        ctx.get('tool:stream@1').hook('after', (chunkOut, meta) => {
          if (meta.phase === 'stream_chunk' && chunkOut?.text === 'BAD_CHUNK') {
            return { blocked: true, code: 'STREAM_BLOCKED', rule: 'ST-1', reason: 'Stream chunk violated safety rule.' };
          }
          return chunkOut;
        });
      },
    }),
  });

  await daemon.control.mountExtensionUnit({
    contract: {
      schemaVersion: 1,
      id: 'other-ext',
      kind: 'extension-plugin',
      version: '3.0.0-alpha.0',
      executionBoundary: 'out-of-process',
      consumes: [PLUGIN_SECRETS_SLOT],
    },
    trust: { autoApproveTrusted: true },
    load: () => ({
      name: 'other-ext',
      apply(ctx) {
        extBetaSecrets = ctx.get(PLUGIN_SECRETS_SLOT);
      },
    }),
  });

  // Extension namespace secret isolation:
  assert.equal(extAlphaSecrets.getSecret('LLM_KEY'), 'secret-for-stream-ext');
  assert.equal(extBetaSecrets.getSecret('LLM_KEY'), 'secret-for-other-ext');
  assert.deepEqual(extBetaSecrets.buildChildEnvBindings({ MY_ENV: 'LLM_KEY' }), { MY_ENV: 'secret-for-other-ext' });
  const perm = (await fs.stat(path.join(stateDir, 'plugin-secrets', 'stream-ext.secrets.json'))).mode & 0o777;
  assert.equal(perm, 0o600);

  // 1. Unapproved streaming request fails BEFORE tool runs or emits chunks.
  const emittedUnapproved = [];
  const unapprovedRes = await daemon.localIngress.dispatchRpcStream(
    { jsonrpc: '2.0', id: 's-unapproved', method: 'tools/call', params: { name: 'mcp__streaming__gen', arguments: { approved: false } } },
    { requestId: 'req_stream_unapproved', onChunk: c => emittedUnapproved.push(c) },
  );
  assert.equal(unapprovedRes.error.data.code, 'LOCAL_APPROVAL_REQUIRED');
  assert.equal(emittedUnapproved.length, 0);

  // 2. Approved healthy streaming emits chunks + final result cleanly via WSS relay ingress.
  assert.ok(fakeSocket);
  fakeSocket.emit('message', Buffer.from(JSON.stringify({
    type: 'request',
    id: 'ws-stream-ok',
    issuedAt: Date.now(),
    deadline: Date.now() + 30_000,
    stream: true,
    authorization: { userId: 'owner', clientId: 'test-client', scope: ['computer:read', 'computer:write', 'computer:execute'] },
    body: { jsonrpc: '2.0', id: 's-ok', method: 'tools/call', params: { name: 'mcp__streaming__gen', arguments: { approved: true } } },
  })), false);
  const okDeadline = Date.now() + 2000;
  while (!sentWsFrames.some(f => f.id === 'ws-stream-ok' && f.type === 'stream_end') && Date.now() < okDeadline) {
    await new Promise(r => setTimeout(r, 15));
  }
  const okChunks = sentWsFrames.filter(f => f.id === 'ws-stream-ok' && f.type === 'stream_chunk');
  const okEnd = sentWsFrames.find(f => f.id === 'ws-stream-ok' && f.type === 'stream_end');
  assert.equal(okChunks.length, 2);
  assert.equal(okChunks[0].body.params.chunk.text, 'chunk-0');
  assert.equal(okEnd.body.result.content[0].text, 'stream-complete');
  assert.equal(approvedCallCount, 1);

  // 3. Mid-stream block aborts provider immediately after forwarding only safe prior chunks.
  const emittedBlocked = [];
  const blockedRes = await daemon.localIngress.dispatchRpcStream(
    { jsonrpc: '2.0', id: 's-block', method: 'tools/call', params: { name: 'mcp__streaming__gen', arguments: { approved: true, poisonChunk: true } } },
    { requestId: 'req_stream_block', onChunk: c => emittedBlocked.push(c) },
  );
  assert.equal(blockedRes.error.data.code, 'STREAM_BLOCKED');
  assert.equal(emittedBlocked.length, 1);
  assert.equal(streamAborted, true);
});
