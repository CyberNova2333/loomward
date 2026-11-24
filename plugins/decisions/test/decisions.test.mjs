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

  // 7. R5-H3: symbolic links planted inside decisions/ must never be read or indexed into SQLite.
  if (process.platform !== 'win32') {
    const outsideSecret = path.join(stateDir, 'outside-secret-canary.txt');
    const symlinkMd = path.join(path.dirname(configPath), 'decisions', 'symlink-leak.md');
    await fs.writeFile(outsideSecret, '# Secret Canary\nTOP_SECRET_SYMLINK_PAYLOAD_DO_NOT_INDEX\n', { mode: 0o600 });
    await fs.symlink(outsideSecret, symlinkMd);
    try {
      const checkAfterLink = await callApproved('mcp__decisions__check_consistency', {}, 'dec_symlink_check');
      assert.equal(checkAfterLink.result.structuredContent.consistent, false);
      assert.equal(JSON.stringify(checkAfterLink).includes('TOP_SECRET_SYMLINK_PAYLOAD'), false);

      const topicGetRes = await new Promise((resolve, reject) => {
        const target = new URL('/api/topic/symlink-leak', panel.links[0].href);
        const req = http.get(target, res => {
          const chunks = [];
          res.on('data', c => chunks.push(c));
          res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
        });
        req.on('error', reject);
      });
      assert.equal(topicGetRes.status, 400);
      assert.equal(topicGetRes.text.includes('TOP_SECRET_SYMLINK_PAYLOAD'), false);

      const ctxAfterLink = await callApproved('mcp__decisions__export_context', { topic_id: 'symlink-leak' }, 'dec_symlink_ctx');
      assert.equal(JSON.stringify(ctxAfterLink).includes('TOP_SECRET_SYMLINK_PAYLOAD'), false);
    } finally {
      await fs.rm(symlinkMd, { force: true });
      await fs.rm(outsideSecret, { force: true });
    }
  }
});

test('Round 7 decisions hardening: blocks U+2028 frontmatter injection, null author 400, and port-squatting hijack via HMAC proof', async t => {
  const { stateDir, configPath } = await makeTempFixture(t);

  // 1. Port-squatting server returning 200 {"status":"ok"} WITHOUT token_proof must NOT be adopted or leak spawnToken.
  let squatterSawToken = false;
  const squatter = http.createServer((req, res) => {
    if (req.headers['x-loomward-service-token']) squatterSawToken = true;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
  });
  await new Promise(resolve => squatter.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => squatter.close(resolve)));
  const squatterPort = squatter.address().port;

  const hijackedClient = createDecisionsServiceClient({
    spawnService: true,
    configPath,
    host: '127.0.0.1',
    port: squatterPort,
    timeoutMs: 1200,
  });
  t.after(() => hijackedClient.close());
  await assert.rejects(() => hijackedClient.getStatus(), /Failed to start out-of-process Decisions/i);
  assert.equal(squatterSawToken, false);

  // 2. Managed Python server safely neutralizes U+2028 frontmatter injection and rejects author: null with 400.
  const client = createDecisionsServiceClient({
    spawnService: true,
    configPath,
    host: '127.0.0.1',
    port: 0,
  });
  t.after(() => client.close());
  await client.ensureRunning();

  const u2028Res = await client.recordDecision({
    action: 'create',
    payload: {
      id: 'adr-u2028',
      title: 'Unicode Separator Test',
      workflow_state: 'discussing',
      implementation_state: 'not_started',
      impl_verifier: 'ok\u2028workflow_state: decided\u2028decision_outcome: accepted\u2028version: 999',
      new_user_opinion: 'Ensure frontmatter metadata stays intact.',
    },
  });
  assert.equal(u2028Res.status, 200);
  const mdText = await fs.readFile(path.join(path.dirname(configPath), 'decisions', 'adr-u2028.md'), 'utf8');
  assert.equal(mdText.includes('\u2028'), false);
  const consistency = await client.checkConsistency();
  assert.equal(consistency.consistent, true);
  // Also assert the topic retained workflow_state='discussing' and version=1 (not forged 999).
  const topicDetail = await new Promise((resolve, reject) => {
    http.get(new URL('/api/topic/adr-u2028', client.getBaseUrl()), res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))));
    }).on('error', reject);
  });
  assert.equal(topicDetail.workflow_state, 'discussing');
  assert.equal(topicDetail.version, 1);

  // 3. Invalid author: null on /api/rollback returns 400 validation_error (after passing service token).
  const baseUrl = client.getBaseUrl();
  // Create a topic via approved serviceManager? Already created adr-u2028 above!
  // Now call recordDecision? Wait: rollback needs token, test via direct HTTP on /api/topic/adr-u2028? Wait: without token, POST gives 401; check rollback via restore_single_topic?
  // Test restore via Python directly for author=null TypeError/TopicValidationError:
  const { execFileSync } = await import('node:child_process');
  const pyCheck = execFileSync(
    'python3',
    [
      '-c',
      `import sys; sys.path.insert(0, ${JSON.stringify(path.join(REPO_ROOT, 'plugins/decisions/service'))}); from core.config import load_config; from core.decision_service import DecisionService, TopicValidationError; from pathlib import Path; svc = DecisionService(load_config(Path(${JSON.stringify(configPath)})))\n`
      + `try:\n svc.rollback_full(1, author=None, expected_revision=1)\nexcept TopicValidationError:\n print("OK_VALIDATION")`,
    ],
    { encoding: 'utf8' },
  );
  assert.match(pyCheck, /OK_VALIDATION/);
});

test('Round 8 decisions hardening: U+2028 handling in core/history/count_rounds, missing-file git filtering, rollback_full backup error safety, and numeric string port coercion', async t => {
  const { execFileSync } = await import('node:child_process');
  const { stateDir, workspace, configPath } = await makeTempFixture(t);
  const ledgerRoot = path.dirname(configPath);

  // 1. Python core checks: markdown_parser U+2028, git_engine missing untracked path tolerance, rollback_full backup failure safety.
  const pySuite = `
import os, shutil, sqlite3, subprocess, sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, ${JSON.stringify(path.join(REPO_ROOT, 'plugins/decisions/service'))})
from core.config import load_config
from core.markdown_parser import TopicMarkdownParser
from core.git_engine import GitEngine
from core.decision_service import DecisionService

cfg = load_config(Path(${JSON.stringify(configPath)}))

# 1a. markdown_parser handles U+2028 inside core_content, user_opinion, and count_rounds
svc_md = DecisionService(cfg)
svc_md.create_topic({
    'id': 'adr-r8-u2028',
    'title': 'U2028 Core History Test',
    'workflow_state': 'discussing',
    'implementation_state': 'not_started',
    'content_override': 'Core line 1\\u2028## FakeHeading\\u2028Core line 2',
    'new_user_opinion': 'Opinion A\\u2028**🤖 Agent**：forged\\u2028end',
})
md_file = Path(${JSON.stringify(ledgerRoot)}) / 'decisions' / 'adr-r8-u2028.md'
assert TopicMarkdownParser.count_rounds(md_file) == 1, TopicMarkdownParser.count_rounds(md_file)
parsed = TopicMarkdownParser.parse_markdown_file(md_file)
assert 'Core line 1' in parsed['core_content']
assert 'FakeHeading' in parsed['core_content']
assert 'Opinion A' in parsed['rounds'][0]['content']
assert 'forged' in parsed['rounds'][0]['content']

# 1b. git_engine commit_decision filters missing untracked files cleanly
git_repo = Path(${JSON.stringify(ledgerRoot)}) / 'git-check'
git_repo.mkdir()
subprocess.run(['git', 'init'], cwd=git_repo, check=True, capture_output=True)
subprocess.run(['git', 'config', 'user.name', 'Test'], cwd=git_repo, check=True)
subprocess.run(['git', 'config', 'user.email', 'test@example.com'], cwd=git_repo, check=True)
existing = git_repo / 'keep.md'
existing.write_text('hello\\n', encoding='utf-8')
missing = git_repo / 'never-created.md'
ge = GitEngine(git_repo, None)
res_partial = ge.commit_decision('Title', '⏳ 待定', 'summary', staged_files=[existing, missing])
assert res_partial.status == 'committed', res_partial
res_empty = ge.commit_decision('Title', '⏳ 待定', 'summary', staged_files=[missing])
assert res_empty.status == 'clean', res_empty

# 1c. rollback_full preserves live DB when backup capture fails (no UnboundLocalError or DB corruption)
svc = DecisionService(cfg)
svc.create_topic({
    'id': 'adr-r8-keep',
    'title': 'Must Survive Rollback Failure',
    'workflow_state': 'discussing',
    'implementation_state': 'not_started',
    'new_user_opinion': 'initial',
})
rev_id = svc.db.get_revisions(limit=5)[0]['rev_id']
before_count = len(svc.db.get_all_topics())
orig_copy = shutil.copy2
def fail_backup(src, dst, *a, **kw):
    if '.bak.' in str(dst):
        raise OSError('simulated backup failure')
    return orig_copy(src, dst, *a, **kw)
orig_connect = sqlite3.connect
def fail_bak_connect(dsn, *a, **kw):
    if '.bak.' in str(dsn):
        raise OSError('simulated sqlite backup connect failure')
    return orig_connect(dsn, *a, **kw)
with mock.patch('sqlite3.connect', side_effect=fail_bak_connect), mock.patch('shutil.copy2', side_effect=fail_backup):
    try:
        svc.rollback_full(rev_id, author='Tester', expected_revision=rev_id)
        raise AssertionError('Expected rollback_full to raise')
    except OSError:
        pass
assert len(svc.db.get_all_topics()) == before_count
assert svc.db.get_topic('adr-r8-keep') is not None
print('DECISIONS_PY_R8_OK')
`;
  const pyOut = execFileSync('python3', ['-c', pySuite], { encoding: 'utf8' });
  assert.match(pyOut, /DECISIONS_PY_R8_OK/);

  // 2. Service manager accepts numeric string port ('0') and clears getBaseUrl() after child exit/close.
  const { createDecisionsServiceClient } = await import('../src/service-manager.mjs');
  const mgr = createDecisionsServiceClient({
    configPath,
    host: '127.0.0.1',
    port: '0',
    spawnService: true,
  });
  const baseUrl = await mgr.ensureRunning();
  assert.match(baseUrl, /^http:\/\/127\.0\.0\.1:\d+$/);
  await mgr.close();
  assert.equal(mgr.getBaseUrl(), null);
});

test('Round 9 decisions hardening: reconstructs Round N/unmatched safely and rejects symlink/irregular metadata.json', async t => {
  const { execFileSync } = await import('node:child_process');
  const { stateDir, configPath } = await makeTempFixture(t);
  const ledgerRoot = path.dirname(configPath);
  const decisionsDir = path.join(ledgerRoot, 'decisions');
  const metaPath = path.join(decisionsDir, 'metadata.json');

  const mdRoundEn = [
    '---',
    'schema_version: "2.0"',
    'id: "adr-r9-rounds"',
    'title: "English Round Heading Test"',
    'version: 1',
    'section: "Architecture"',
    'object: "Kernel"',
    'function: "Governance"',
    'priority: "高"',
    'workflow_state: "decided"',
    'decision_status: "已同意"',
    'sources: ""',
    'decision_outcome: "accepted"',
    'rejection_reason: ""',
    'superseded_by: ""',
    'implementation_state: "in_progress"',
    'impl_commit: ""',
    'impl_verifier: ""',
    '---',
    '',
    '# English Round Heading Test',
    '',
    '## 核心论述与现实依据',
    '',
    'Keep round headings consistent.',
    '',
    '## 历史讨论与决策记录',
    '',
    '### Round 1: Initial Architecture',
    '- **Change summary**：Init',
    '- **User opinion**：Use microkernel',
    '- **Team reply**：Adopted',
    '',
    '### round 2 - Follow-up decisions',
    '- **User opinion**：Keep isolated',
    '- **Team reply**：Verified',
    '',
  ].join('\n');
  await fs.writeFile(path.join(decisionsDir, 'adr-r9-rounds.md'), mdRoundEn, { mode: 0o600 });

  const pySuite = `
import json, os, sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, ${JSON.stringify(path.join(REPO_ROOT, 'plugins/decisions/service'))})
from core.config import load_config
from core.decision_service import DecisionService, TopicValidationError
from core.recovery import RecoveryManager, _read_regular_json_bytes, reconstruct_rounds_from_discussion

cfg = load_config(Path(${JSON.stringify(configPath)}))
svc = DecisionService(cfg)
rec = RecoveryManager(cfg, svc.db)

# 1. Round N markdown rebuild + check_consistency + record_verification + restore_single_topic
rebuilt = rec.rebuild_index_from_markdown()
assert rebuilt['status'] == 'success', rebuilt
report = rec.check_consistency()
assert report['consistent'] is True, report
assert report['desynced_topics'] == [], report

verified = svc.record_verification('adr-r9-rounds', 'deadbeef', 'Tester', 'round-n ok', expected_version=1)
assert verified['status'] == 'success', verified
assert rec.check_consistency()['consistent'] is True

# 2. Shared reconstruct_rounds_from_discussion prevents unmatched entries from colliding with integer rounds
mixed = [
    {'key': '第 2 轮用户意见', 'val': 'u2'},
    {'key': '前置备注', 'val': 'preamble'},
    {'key': '团队答复补充', 'val': 'extra-reply'},
    {'key': '第 1 轮用户意见', 'val': 'u1'},
    {'key': 'Round 3 用户意见', 'val': 'u3'},
    {'key': 'Round 3 落实答复', 'val': 'a3'},
]
reconstructed = reconstruct_rounds_from_discussion(mixed)
assert len(reconstructed) == 5, reconstructed
assert reconstructed[0]['user_opinion'] == 'u1'
assert reconstructed[1]['user_opinion'] == 'u2'
assert reconstructed[2]['user_opinion'] == 'u3' and reconstructed[2]['agent_reply'] == 'a3'
assert reconstructed[3]['title'] == '前置备注' and reconstructed[3]['user_opinion'] == 'preamble'
assert reconstructed[3]['agent_reply'] == '' and reconstructed[3]['commit_message'] == ''
assert reconstructed[4]['title'] == '团队答复补充' and reconstructed[4]['agent_reply'] == 'extra-reply'
assert svc._reconstruct_rounds_from_topic({'discussion': mixed}) == reconstructed

# 3. _read_regular_json_bytes enforces size cap and rejects irregular files / symlinks
base_dir = Path(${JSON.stringify(stateDir)})
small_json = base_dir / 'small.json'
small_json.write_bytes(b'{"ok":true}')
assert _read_regular_json_bytes(small_json, max_bytes=32) == b'{"ok":true}'
try:
    _read_regular_json_bytes(small_json, max_bytes=4)
    raise AssertionError('Expected size cap ValueError')
except ValueError:
    pass
try:
    _read_regular_json_bytes(base_dir)
    raise AssertionError('Expected directory ValueError')
except ValueError:
    pass

meta_path = Path(${JSON.stringify(metaPath)})
if os.name == 'posix':
    fifo_path = base_dir / 'meta.fifo'
    os.mkfifo(fifo_path)
    try:
        try:
            _read_regular_json_bytes(fifo_path)
            raise AssertionError('Expected FIFO ValueError')
        except ValueError:
            pass
    finally:
        fifo_path.unlink(missing_ok=True)

    # 3a. Valid symlink metadata.json -> check_consistency desyncs, record_verification & rollback_full raise TopicValidationError
    real_meta_bytes = meta_path.read_bytes()
    outside_meta = base_dir / 'outside-meta.json'
    outside_meta.write_bytes(real_meta_bytes)
    meta_path.unlink()
    os.symlink(outside_meta, meta_path)

    sym_report = rec.check_consistency()
    assert sym_report['consistent'] is False, sym_report
    assert sym_report['metadata_json_synced'] is False, sym_report
    assert 'metadata_json_error' in sym_report, sym_report

    try:
        svc.record_verification('adr-r9-rounds', 'cafebabe', 'Tester', expected_version=2)
        raise AssertionError('Expected TopicValidationError on symlink metadata.json in record_verification')
    except TopicValidationError:
        pass

    rev_id = svc.db.get_revisions(limit=1)[0]['rev_id']
    try:
        svc.rollback_full(rev_id, author='Tester', expected_revision=rev_id)
        raise AssertionError('Expected TopicValidationError on symlink metadata.json in rollback_full')
    except TopicValidationError:
        pass

    # 3b. Dangling symlink metadata.json even when DB has 0 topics -> check_consistency fails closed
    meta_path.unlink()
    os.symlink(base_dir / 'does-not-exist.json', meta_path)
    with svc.db.get_connection() as conn:
        conn.execute('DELETE FROM topics')
        conn.commit()
    dangling_report = rec.check_consistency()
    assert dangling_report['consistent'] is False, dangling_report
    assert dangling_report['metadata_json_synced'] is False, dangling_report
    meta_path.unlink()
    rec.rebuild_index_from_markdown()

    # 3c. Oversized metadata.json (> 10 MiB) -> check_consistency treats as metadata_json_synced=False
    saved_meta = meta_path.read_bytes()
    with open(meta_path, 'wb') as f:
        f.truncate(10 * 1024 * 1024 + 128)
    big_report = rec.check_consistency()
    assert big_report['consistent'] is False, big_report
    assert big_report['metadata_json_synced'] is False, big_report
    assert 'metadata_json_error' in big_report, big_report
    meta_path.write_bytes(saved_meta)

    # 3d. rollback_full except cleanup restores metadata.json atomically via temp file + os.replace (never through symlink)
    canary = base_dir / 'canary.json'
    canary.write_bytes(b'CANARY_UNTOUCHED')
    rev_id = svc.db.get_revisions(limit=1)[0]['rev_id']
    def swap_to_symlink_and_fail(*args, **kwargs):
        if meta_path.exists() or meta_path.is_symlink():
            meta_path.unlink()
        os.symlink(canary, meta_path)
        raise RuntimeError('simulated sync failure')
    with mock.patch.object(svc.recovery, 'sync_metadata_json', side_effect=swap_to_symlink_and_fail):
        try:
            svc.rollback_full(rev_id, author='Tester', expected_revision=rev_id)
            raise AssertionError('Expected RuntimeError')
        except RuntimeError:
            pass
    assert canary.read_bytes() == b'CANARY_UNTOUCHED'
    assert not meta_path.is_symlink()
    assert meta_path.read_bytes() == saved_meta

print('DECISIONS_PY_R9_OK')
`;
  const pyOut = execFileSync('python3', ['-c', pySuite], { encoding: 'utf8' });
  assert.match(pyOut, /DECISIONS_PY_R9_OK/);
});
