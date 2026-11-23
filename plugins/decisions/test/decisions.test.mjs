// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { SlotError, VAULT_SLOT } from '@loomward/shared';
import { contract, createDecisionsServiceClient } from '../src/index.mjs';
import { startLoomWardDaemon } from '../../../packages/host/src/daemon.mjs';

const REPO_ROOT = path.resolve(import.meta.dirname, '../../..');

async function makeTempFixture(t) {
  const base = await fs.mkdtemp(path.join(os.homedir(), '.lw-dec-'));
  await fs.chmod(base, 0o700);
  const stateDir = path.join(base, 'state');
  const workspace = path.join(base, 'workspace');
  const ledgerRoot = path.join(base, 'ledger');
  await fs.mkdir(stateDir, { mode: 0o700 });
  await fs.mkdir(workspace, { mode: 0o700 });
  await fs.mkdir(path.join(ledgerRoot, 'decisions'), { recursive: true, mode: 0o700 });

  const configPath = path.join(ledgerRoot, 'dashboard.config.json');
  await fs.writeFile(configPath, JSON.stringify({
    project_name: 'LoomWard Test Ledger',
    project_subtitle: 'Phase 3 Out-of-Process SQLite Verification',
    host: '127.0.0.1',
    port: 0,
    decisions_dir: 'decisions',
    database_path: 'decisions.db',
    metadata_json_path: 'decisions/metadata.json',
    doc_data_json_path: 'doc_data.json',
    git_commit: { enabled: false },
  }, null, 2), { mode: 0o600 });

  t.after(async () => {
    assert.equal(path.dirname(base), os.homedir());
    assert.ok(path.basename(base).startsWith('.lw-dec-'));
    await fs.rm(base, { recursive: true, force: true });
  });
  return { stateDir, workspace, configPath };
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
}

test('decisions service client enforces strict loopback binding', () => {
  assert.throws(
    () => createDecisionsServiceClient({ baseUrl: 'http://192.168.1.50:8765' }),
    /loopback/i,
  );
  assert.throws(
    () => createDecisionsServiceClient({ baseUrl: 'https://example.com:8765' }),
    /loopback http/i,
  );
});

test('decisions plugin runs out-of-process Python SQLite ledger, enforces local approval, CAS conflict 409, idempotency, and declarative console:panel@1', async t => {
  const { stateDir, workspace, configPath } = await makeTempFixture(t);

  const sandboxRuntime = {
    async handleRpc(body) {
      if (body.method === 'tools/list') return { jsonrpc: '2.0', id: body.id ?? null, result: { tools: [] } };
      return { jsonrpc: '2.0', id: body.id ?? null, result: { content: [{ type: 'text', text: 'ok' }] } };
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
  });
  t.after(() => daemon.stop());

  let pluginCtx;
  await daemon.control.mountExtensionUnit({
    contract,
    load: async () => {
      const mod = await import(pathToFileURL(path.join(REPO_ROOT, 'plugins/decisions/src/index.mjs')).href);
      return {
        name: mod.name,
        apply(ctx, cfg) {
          pluginCtx = ctx;
          return mod.apply(ctx, cfg);
        },
      };
    },
    config: {
      spawnService: true,
      eagerStart: true,
      configPath,
      host: '127.0.0.1',
      port: 0,
    },
    trust: { autoApproveTrusted: true, trustLevel: 'official', signed: true },
  });

  // Out-of-process boundary: decisions plugin cannot touch closed vault:backend@1.
  assert.throws(() => pluginCtx.get(VAULT_SLOT), SlotError);

  // tools/list includes all 3 namespaced decisions tools.
  const listed = await daemon.localIngress.dispatchRpc({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
  const names = listed.result.tools.map(item => item.name);
  assert.ok(names.includes('mcp__decisions__export_context'));
  assert.ok(names.includes('mcp__decisions__check_consistency'));
  assert.ok(names.includes('mcp__decisions__record'));

  // Helper to invoke a tool with exact local approval flow.
  const callApproved = async (toolName, args, prefix) => {
    const first = await daemon.localIngress.dispatchRpc(
      { jsonrpc: '2.0', id: `${prefix}-1`, method: 'tools/call', params: { name: toolName, arguments: args } },
      { requestId: `${prefix}_1` },
    );
    assert.equal(first.error?.data?.code, 'LOCAL_APPROVAL_REQUIRED');
    await approvePendingOnDisk(stateDir, first.error.data.approval_id);
    return daemon.localIngress.dispatchRpc(
      { jsonrpc: '2.0', id: `${prefix}-2`, method: 'tools/call', params: { name: toolName, arguments: args } },
      { requestId: `${prefix}_2` },
    );
  };

  // 1. Create a decision topic via real SQLite service with stable request_id.
  const createArgs = {
    action: 'create',
    request_id: 'idem-create-adr-001',
    payload: {
      id: 'adr-001',
      title: 'Adopt Cordis 4 Microkernel & Out-of-Process Extensions',
      workflow_state: 'decided',
      decision_outcome: 'accepted',
      implementation_state: 'in_progress',
      new_user_opinion: 'Keep extensions strictly out-of-process with declarative panels.',
      new_agent_reply: 'Implemented Cordis 4 KernelGuard + ContentInspect v1 + console:panel@1.',
    },
  };
  const created = await callApproved('mcp__decisions__record', createArgs, 'dec_create');
  assert.equal(created.result.isError, undefined);
  assert.equal(created.result.structuredContent.httpStatus, 200);
  assert.equal(created.result.structuredContent.status, 'success');

  // 2. Idempotent replay with same request_id succeeds cleanly without duplicating topic.
  const replayed = await callApproved('mcp__decisions__record', createArgs, 'dec_idem');
  assert.equal(replayed.result.structuredContent.httpStatus, 200);
  assert.equal(replayed.result.structuredContent.status, 'success');

  // 3. Stale expected_version triggers CAS optimistic locking conflict (409 version_conflict).
  const staleSave = await callApproved('mcp__decisions__record', {
    action: 'save',
    topic_id: 'adr-001',
    expected_version: 99,
    request_id: 'idem-stale-save',
    payload: {
      title: 'Conflicting Edit',
      new_user_opinion: 'Stale write must be rejected.',
    },
  }, 'dec_cas_conflict');
  assert.equal(staleSave.result.isError, true);
  assert.equal(staleSave.result.structuredContent.httpStatus, 409);
  assert.equal(staleSave.result.structuredContent.error, 'version_conflict');

  // 4. Consistency check & context export read live SQLite records, while path-traversal topic_id is rejected.
  const dotTraversal = await callApproved('mcp__decisions__export_context', { topic_id: '..' }, 'dec_dot');
  assert.equal(dotTraversal.result.isError, true);
  assert.match(dotTraversal.result.content[0].text, /invalid topic_id/i);

  const consistency = await callApproved('mcp__decisions__check_consistency', {}, 'dec_check');
  assert.equal(consistency.result.structuredContent.consistent, true);

  const exported = await callApproved('mcp__decisions__export_context', { topic_id: 'adr-001' }, 'dec_ctx');
  assert.ok(JSON.stringify(exported.result.structuredContent).includes('adr-001'));

  // 5. Declarative console:panel@1 reflects live SQLite topic inventory, workflow_state, & loopback link!
  const consoleSvc = daemon.control.getService('console:loopback');
  const panel = await consoleSvc.panelCollector.collectById('decisions');
  assert.equal(panel.id, 'decisions');
  assert.equal(panel.status, 'ok');
  assert.ok(panel.summary.some(s => s.label === '决策议题' && s.value === '1'));
  assert.equal(panel.table.rows[0][2], 'decided');
  assert.equal(panel.links.length, 1);
  assert.match(panel.links[0].href, /^http:\/\/127\.0\.0\.1:\d+$/);

  // 6. R4-H1: any other local process POSTing directly to the managed loopback ledger without the
  // per-process service token is rejected (writes cannot bypass LoomWard's exact local approval).
  const directStatus = await new Promise((resolve, reject) => {
    const target = new URL('/api/topic/create', panel.links[0].href);
    const payload = JSON.stringify({ id: 'rogue-topic', title: 'Bypass approval' });
    const req = http.request({
      hostname: target.hostname,
      port: target.port,
      path: target.pathname,
      method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) },
    }, res => {
      res.resume();
      res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject);
    req.end(payload);
  });
  assert.equal(directStatus, 401);
});
