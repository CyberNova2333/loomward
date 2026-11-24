// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { SlotError, VAULT_SLOT } from '@loomward/shared';
import { createAntileakEngineRunner, contract } from '../src/index.mjs';
import { startLoomWardDaemon } from '../../../packages/host/src/daemon.mjs';

const REPO_ROOT = path.resolve(import.meta.dirname, '../../..');

async function makeTempState(t) {
  const base = await fs.mkdtemp(path.join(os.homedir(), '.lw-al-'));
  await fs.chmod(base, 0o700);
  const stateDir = path.join(base, 'state');
  const workspace = path.join(base, 'workspace');
  const antileakDir = path.join(stateDir, 'antileak');
  await fs.mkdir(stateDir, { mode: 0o700 });
  await fs.mkdir(workspace, { mode: 0o700 });
  await fs.mkdir(antileakDir, { mode: 0o700 });
  t.after(async () => {
    assert.equal(path.dirname(base), os.homedir());
    assert.ok(path.basename(base).startsWith('.lw-al-'));
    await fs.rm(base, { recursive: true, force: true });
  });
  return { stateDir, workspace, cachePath: path.join(antileakDir, 'private-repos.json') };
}

async function writePrivateCache(cachePath, { expiresOffsetSec = 3600 } = {}) {
  const nowSec = Math.floor(Date.now() / 1000);
  await fs.writeFile(cachePath, JSON.stringify({
    status: 'ok',
    generated_at: nowSec,
    expires_at: nowSec + expiresOffsetSec,
    sources: ['seed'],
    private: ['OrgAlpha/secret-internal-repo', 'secret-internal-repo'],
    patterns: ['internal\\.corp\\.example'],
  }), { mode: 0o600 });
}

test('antileak offline Python engine enforces R1-R7 rules, redacts secrets, and fails closed on stale/missing cache', async t => {
  const { cachePath } = await makeTempState(t);
  const runner = createAntileakEngineRunner({ cachePath });

  // 1. Missing cache -> fail-closed block.
  assert.equal(runner.inspectCacheHealth().status, 'missing');
  const missingVerdict = await runner.inspectText('normal clean hello world');
  assert.equal(missingVerdict.decision, 'block');
  assert.ok(missingVerdict.categories.includes('antileak.fail_closed'));

  // 2. Fresh cache -> clean content passes, private repo / R4 / secret patterns are blocked!
  await writePrivateCache(cachePath, { expiresOffsetSec: 3600 });
  assert.equal(runner.inspectCacheHealth().status, 'fresh');

  const okVerdict = await runner.inspectText('Refactor kernel slot registration cleanly.');
  assert.equal(okVerdict.decision, 'allow');

  const r1Hit = await runner.inspectText('See notes from secret-internal-repo for details.');
  assert.equal(r1Hit.decision, 'block');
  assert.ok(r1Hit.categories.includes('antileak.violation'));
  assert.equal(r1Hit.reason.includes('secret-internal-repo'), false);
  assert.equal(r1Hit.ruleId, 'ANTILEAK-R1');

  const r4Hit = await runner.inspectText('Endpoint https://api.internal.corp.example/v1');
  assert.equal(r4Hit.decision, 'block');
  assert.ok(r4Hit.categories.includes('antileak.violation'));
  assert.equal(r4Hit.ruleId, 'ANTILEAK-R4');

  // Dynamically construct synthetic credential so repository secret scanners never see a literal.
  const syntheticSecret = ['ghp', '_'].join('') + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4';
  const r7Hit = await runner.inspectText(`token=${syntheticSecret}`);
  assert.equal(r7Hit.decision, 'block');
  assert.equal(r7Hit.reason.includes(syntheticSecret), false);
  assert.equal(r7Hit.ruleId, 'ANTILEAK-R7');

  // Pre-aborted signal must fail closed without ReferenceError TDZ.
  const preAborted = new AbortController();
  preAborted.abort();
  const abortedVerdict = await runner.inspectText('hello', { signal: preAborted.signal });
  assert.equal(abortedVerdict.decision, 'block');
  assert.equal(abortedVerdict.ruleId, 'ANTILEAK-CANCELLED');

  // 3. Expired cache -> fail-closed block even on harmless content!
  await writePrivateCache(cachePath, { expiresOffsetSec: -600 });
  assert.equal(runner.inspectCacheHealth().status, 'stale');
  const staleVerdict = await runner.inspectText('completely harmless text');
  assert.equal(staleVerdict.decision, 'block');
  assert.ok(staleVerdict.categories.includes('antileak.fail_closed'));
  assert.equal(staleVerdict.ruleId, 'ANTILEAK-CACHE-STALE');
});

test('antileak mounts out-of-process on Cordis kernel, blocks leaked arguments before approval queue, and exposes declarative console:panel@1', async t => {
  const { stateDir, workspace, cachePath } = await makeTempState(t);
  await writePrivateCache(cachePath, { expiresOffsetSec: 3600 });

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
      const mod = await import(pathToFileURL(path.join(REPO_ROOT, 'plugins/antileak/src/index.mjs')).href);
      return {
        name: mod.name,
        apply(ctx, cfg) {
          pluginCtx = ctx;
          return mod.apply(ctx, cfg);
        },
      };
    },
    config: { stateDir, cachePath },
    trust: { autoApproveTrusted: true, trustLevel: 'official', signed: true },
  });

  // Strict out-of-process isolation: antileak cannot read vault:backend@1.
  assert.throws(() => pluginCtx.get(VAULT_SLOT), SlotError);

  // Leaked private repo name in write_file is blocked BEFORE entering approval queue!
  const blocked = await daemon.localIngress.dispatchRpc(
    {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'write_file', arguments: { path: 'README.md', content: 'ref secret-internal-repo' } },
    },
    { requestId: 'al_req_1' },
  );
  assert.equal(blocked.error.data.code, 'ANTILEAK_BLOCKED');
  assert.equal(JSON.stringify(blocked).includes('secret-internal-repo'), false);
  assert.deepEqual(await fs.readdir(path.join(stateDir, 'approvals')), []);

  // Leaked secret inside an object key is also detected and blocked!
  const keyBlocked = await daemon.localIngress.dispatchRpc(
    {
      jsonrpc: '2.0',
      id: '1b',
      method: 'tools/call',
      params: { name: 'write_file', arguments: { path: 'README.md', secret_map: { 'secret-internal-repo': '1' } } },
    },
    { requestId: 'al_req_1b' },
  );
  assert.equal(keyBlocked.error.data.code, 'ANTILEAK_BLOCKED');

  // > 1 MiB padding attack fails closed with ANTILEAK-INPUT-TOO-LARGE instead of truncating!
  const hugePadding = 'a'.repeat(1024 * 1024 + 64) + ' secret-internal-repo';
  const overflowBlocked = await daemon.localIngress.dispatchRpc(
    {
      jsonrpc: '2.0',
      id: '1c',
      method: 'tools/call',
      params: { name: 'write_file', arguments: { path: 'README.md', content: hugePadding } },
    },
    { requestId: 'al_req_1c' },
  );
  assert.equal(overflowBlocked.error.data.code, 'ANTILEAK_FAIL_CLOSED');
  assert.equal(overflowBlocked.error.data.rule, 'ANTILEAK-INPUT-TOO-LARGE');

  // Expire cache -> read_file fails closed BEFORE entering approval queue!
  await writePrivateCache(cachePath, { expiresOffsetSec: -120 });
  const failClosed = await daemon.localIngress.dispatchRpc(
    {
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'read_file', arguments: { path: 'README.md' } },
    },
    { requestId: 'al_req_2' },
  );
  assert.equal(failClosed.error.data.code, 'ANTILEAK_FAIL_CLOSED');
  assert.deepEqual(await fs.readdir(path.join(stateDir, 'approvals')), []);

  // Declarative console:panel@1 reports live counts & stale cache health without secrets.
  const consoleSvc = daemon.control.getService('console:loopback');
  const panel = await consoleSvc.panelCollector.collectById('antileak');
  assert.equal(panel.id, 'antileak');
  assert.equal(panel.status, 'error');
  assert.ok(panel.summary.some(s => s.label === '规则阻断' && s.value === '2'));
  assert.ok(panel.summary.some(s => s.label === '故障闭锁' && s.value === '2'));
});

test('Round 7 antileak hardening: closes R2 base64 URL/path bypasses, fails non-zero on missing policy, and scans # lines in commit mode', async t => {
  const { execFileSync, spawnSync } = await import('node:child_process');
  const { cachePath } = await makeTempState(t);
  await writePrivateCache(cachePath, { expiresOffsetSec: 3600 });
  const runner = createAntileakEngineRunner({ cachePath });

  // R2 bypass payloads (previously incorrectly exempted by in_b64_run):
  for (const payload of [
    'https://claude.ai/chat/A1b2C3d4E5f6G7h8',
    'src/agents/ClaudeSonnet45Handler.ts',
    'Generated by Claude Opus 4.6/v1/abcdef',
  ]) {
    const v = await runner.inspectText(payload);
    assert.equal(v.decision, 'block', `Expected block for ${payload}`);
    assert.equal(v.ruleId, 'ANTILEAK-R1-R7');
  }

  // Policy load failure must exit non-zero (fail-closed for CLI/git hooks).
  const checkPy = path.join(REPO_ROOT, 'plugins/antileak/engine/check.py');
  const missingPolicyRes = spawnSync('python3', [checkPy, 'content'], {
    input: 'hello',
    encoding: 'utf8',
    env: { ...process.env, LOOMWARD_ANTILEAK_POLICY: '/nonexistent/missing-policy.json' },
  });
  assert.notEqual(missingPolicyRes.status, 0);

  // '#' lines in non-interactive `git commit -m` / `-F` stay in the commit message and must be scanned!
  const repoDir = await fs.mkdtemp(path.join(os.homedir(), '.lw-al-git-'));
  await fs.chmod(repoDir, 0o700);
  t.after(() => fs.rm(repoDir, { recursive: true, force: true }));
  execFileSync('git', ['init'], { cwd: repoDir });
  const commitRes = spawnSync('python3', [checkPy, 'commit'], {
    cwd: repoDir,
    input: 'chore: ok title\n\n# secret-internal-repo\n\nCo-authored-by: Dev\n',
    encoding: 'utf8',
    env: { ...process.env, LOOMWARD_ANTILEAK_CACHE: cachePath },
  });
  assert.notEqual(commitRes.status, 0);
  assert.match(commitRes.stdout, /violation/);
});
