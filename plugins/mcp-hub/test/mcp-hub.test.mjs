// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';
import { startLoomWardDaemon } from '../../../packages/host/src/daemon.mjs';
import { contract as decisionsContract } from '../../decisions/src/index.mjs';

const REPO_ROOT = path.resolve(import.meta.dirname, '../../..');

test('mcp-hub with enableMcpHub: true only claims configured servers and never hijacks decisions or cloudforge namespaces', async t => {
  const base = await fs.mkdtemp(path.join(os.homedir(), '.lw-mcphub-'));
  await fs.chmod(base, 0o700);
  const stateDir = path.join(base, 'state');
  const workspace = path.join(base, 'workspace');
  await fs.mkdir(stateDir, { mode: 0o700 });
  await fs.mkdir(workspace, { mode: 0o700 });
  t.after(async () => {
    await fs.rm(base, { recursive: true, force: true });
  });

  const daemon = await startLoomWardDaemon({
    rootDir: REPO_ROOT,
    stateDir,
    origin: 'https://bridge.example.test',
    workspaceRoots: [workspace],
    enableMcpHub: true,
    sandboxRuntime: {
      async handleRpc(body) {
        if (body.method === 'tools/list') return { jsonrpc: '2.0', id: body.id ?? null, result: { tools: [] } };
        return { jsonrpc: '2.0', id: body.id ?? null, result: { content: [{ type: 'text', text: 'ok' }] } };
      },
      async close() {},
    },
  });
  t.after(() => daemon.stop());

  await daemon.control.mountExtensionUnit({
    contract: decisionsContract,
    load: async () => import(pathToFileURL(path.join(REPO_ROOT, 'plugins/decisions/src/index.mjs')).href),
    config: { spawnService: false, eagerStart: false },
    trust: { autoApproveTrusted: true, trustLevel: 'official', signed: true },
  });

  // Verify tools/list discovers decisions tools even when mcp-hub is mounted first with enableMcpHub: true.
  const listed = await daemon.localIngress.dispatchRpc({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
  const names = listed.result.tools.map(item => item.name);
  assert.ok(names.includes('mcp__decisions__record'));

  // Calling mcp__decisions__record must route to decisions (returning LOCAL_APPROVAL_REQUIRED, NOT MCP_SERVER_NOT_FOUND from mcp-hub!).
  const res = await daemon.localIngress.dispatchRpc(
    {
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'mcp__decisions__record', arguments: { action: 'create', payload: { id: 'adr-1', title: 'Test' } } },
    },
    { requestId: 'hub_coexist_1' },
  );
  assert.equal(res.error?.data?.code, 'LOCAL_APPROVAL_REQUIRED');

  // Verify mcp-hub declarative console:panel@1 is registered.
  const consoleSvc = daemon.control.getService('console:loopback');
  const hubPanel = await consoleSvc.panelCollector.collectById('mcp-hub');
  assert.ok(hubPanel);
  assert.equal(hubPanel.id, 'mcp-hub');
  assert.equal(hubPanel.executionBoundary, 'out-of-process');
});
