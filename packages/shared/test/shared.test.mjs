// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AUDIT_CODES,
  BOOT_DEADLINE_MS,
  BootDeadlineError,
  CLOSED_SLOTS,
  ImplSlot,
  MechanismSlot,
  REJECT_CODES,
  SlotError,
  VAULT_SLOT,
  buildContentInspectRequest,
  buildPermissionSubject,
  canonicalJson,
  computeManifestHash,
  createFrozenRpm,
  formatActionNode,
  isRpmShape,
  isSafeUnicodeString,
  mechanismActionKind,
  sanitizeAuditMetadata,
  sanitizeConsolePanelSnapshot,
  serviceInvokeActionKind,
  sha256Tagged,
  validateConsolePanelDecl,
  validateContentInspectVerdict,
  validateContractDecl,
  withDeadline,
} from '../src/index.mjs';

test('canonicalJson sorts keys deterministically and RPM verifies shape and hash', async () => {
  assert.equal(canonicalJson({ b: 1, a: [2, { d: 4, c: 3 }] }), '{"a":[2,{"c":3,"d":4}],"b":1}');
  const hash = await sha256Tagged('entry-bytes');
  const rpm = await createFrozenRpm({
    target: 'runtime',
    rootPlugins: [
      { id: 'sandbox', version: '3.0.0-alpha.0', entryHash: hash, provides: ['sandbox:docker'] },
      { id: 'host', version: '3.0.0-alpha.0', entryHash: hash, provides: ['host:platform'] },
    ],
  });
  assert.equal(isRpmShape(rpm), true);
  assert.equal(await computeManifestHash(rpm), rpm.manifestHash);
  assert.equal(isRpmShape({ ...rpm, extraField: true }), false);
});

test('validateContractDecl enforces executionBoundary and registers/writes declarations', () => {
  const valid = validateContractDecl({
    schemaVersion: 1,
    id: 'antileak',
    kind: 'extension-plugin',
    version: '3.0.0-alpha.0',
    executionBoundary: 'out-of-process',
    provides: ['policy:antileak'],
    consumes: ['tool:invoke@1'],
    registers: [{ slot: 'policy:rule@1', name: 'antileak-rule' }],
    writes: {
      hooks: [{ slot: 'tool:invoke@1', phase: 'before' }],
      intercepts: [],
      isolateProvides: [],
    },
  });
  assert.equal(valid.executionBoundary, 'out-of-process');
  assert.equal(valid.registers.length, 1);
  assert.equal(valid.writes.hooks[0].phase, 'before');

  assert.throws(() => validateContractDecl({
    schemaVersion: 1,
    id: 'bad-ext',
    kind: 'extension-plugin',
    version: '3.0.0-alpha.0',
    executionBoundary: 'in-process-root',
  }), /cannot declare executionBoundary/);

  assert.throws(() => validateContractDecl({
    schemaVersion: 1,
    id: 'bad-hook',
    kind: 'extension-plugin',
    version: '3.0.0-alpha.0',
    executionBoundary: 'out-of-process',
    writes: { hooks: [{ slot: 'tool:invoke@1', phase: 'invalid' }] },
  }), /Invalid hook write phase/);
});

test('guard-types helpers format action nodes, build subjects, and strip forbidden secret audit fields', () => {
  assert.equal(VAULT_SLOT, 'vault:backend@1');
  assert.ok(CLOSED_SLOTS.includes(VAULT_SLOT));
  assert.ok(AUDIT_CODES.AUDIT_VAULT_ACCESS_DENIED);
  assert.ok(REJECT_CODES.GUARD_POLICY_CLOSED);
  assert.equal(BOOT_DEADLINE_MS, 60_000);

  assert.equal(mechanismActionKind('before'), 'mechanism.hook.before');
  assert.equal(serviceInvokeActionKind('write'), 'service.invoke.write');
  assert.equal(
    formatActionNode({ kind: 'service.invoke.write', target: 'host:dispatch', method: 'exec' }),
    'service.invoke.write:host:dispatch#exec',
  );
  assert.equal(
    formatActionNode({ kind: 'impl.register', target: 'tool:provider@1' }),
    'impl.register:tool:provider@1',
  );

  const contract = validateContractDecl({
    schemaVersion: 1,
    id: 'mcp-hub',
    kind: 'extension-plugin',
    version: '3.0.0-alpha.0',
    executionBoundary: 'out-of-process',
  });
  const subject = buildPermissionSubject(contract, { signed: true, trustLevel: 'official', isolated: true });
  assert.deepEqual(subject, {
    unitId: 'mcp-hub',
    kind: 'extension-plugin',
    executionBoundary: 'out-of-process',
    signed: true,
    trustLevel: 'official',
    isolated: true,
  });

  assert.equal(isSafeUnicodeString('hello-世界'), true);
  assert.equal(isSafeUnicodeString('bad\0null'), false);
  assert.equal(isSafeUnicodeString('\uD800'), false);

  const clean = sanitizeAuditMetadata({
    unitId: 'mcp-hub',
    code: AUDIT_CODES.AUDIT_UNIT_MOUNTED,
    bridgeToken: 'secret-token-value',
    stdout: 'raw command output',
    content: 'private file contents',
    count: 2,
  });
  assert.deepEqual(clean, { unitId: 'mcp-hub', code: 'AUDIT_UNIT_MOUNTED', count: 2 });
});

test('withDeadline runs LIFO rollback on error and immediately undoes late registrations after timeout', async () => {
  const log = [];
  await assert.rejects(
    () => withDeadline(500, async run => {
      run.add(() => log.push('a'));
      run.add(() => log.push('b'));
      throw new Error('boom');
    }),
    /boom/,
  );
  assert.deepEqual(log, ['b', 'a']);

  const lateLog = [];
  let releaseGate;
  const gate = new Promise(resolve => { releaseGate = resolve; });
  await assert.rejects(
    () => withDeadline(30, async run => {
      run.add(() => lateLog.push('early'));
      await gate;
      run.add(() => lateLog.push('late'));
      run.live();
    }),
    BootDeadlineError,
  );
  releaseGate();
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.deepEqual(lateLog, ['early', 'late']);
});

test('ImplSlot and MechanismSlot enforce authorization, report release, and track replace state', async () => {
  const events = [];
  const authorizer = {
    authorize(_caller, req) {
      events.push(`auth:${req.kind}:${req.slot}`);
    },
    released(_caller, req) {
      events.push(`rel:${req.kind}:${req.slot}`);
    },
  };
  const slot = new ImplSlot({ name: 'tool:provider@1', cardinality: 'multi', policy: 'trusted' }, () => authorizer);
  slot.registerBuiltin('builtin-default', { kind: 'default' });
  assert.equal(slot.has('builtin-default'), true);
  assert.throws(() => slot.register('untracked', {}), SlotError);

  const trackedCaller = {
    effect(fn) {
      return fn();
    },
  };
  const ORIGINAL = Symbol.for('cordis.original');
  const proxied = Object.create(slot, {
    ctx: { value: trackedCaller },
    [ORIGINAL]: { value: slot },
  });
  const dispose = proxied.register('custom', { kind: 'custom' });
  assert.deepEqual(slot.names(), ['builtin-default', 'custom']);
  dispose();
  assert.deepEqual(slot.names(), ['builtin-default']);
  assert.ok(events.includes('rel:register:tool:provider@1'));

  const mech = new MechanismSlot({ name: 'tool:invoke@1', policy: 'trusted' }, () => authorizer);
  const mechProxy = Object.create(mech, {
    ctx: { value: trackedCaller },
    [ORIGINAL]: { value: mech },
  });
  assert.equal(mech.hasReplace(), false);
  const unhookBefore = mechProxy.hook('before', input => ({ ...input, checked: true }));
  const unhookReplace = mechProxy.hook('replace', (input, base) => base({ ...input, replaced: true }));
  assert.equal(mech.hasReplace(), true);
  const result = await mech.run({ tool: 'read_file' }, x => ({ ok: true, ...x }));
  assert.deepEqual(result, { ok: true, tool: 'read_file', checked: true, replaced: true });
  unhookBefore();
  unhookReplace();
  assert.equal(mech.hasReplace(), false);
  assert.ok(events.includes('rel:hook:tool:invoke@1'));
});

test('panel-schema and content-guard contracts validate declarative panels and input/output moderation verdicts', () => {
  const decl = validateConsolePanelDecl({
    id: 'llm-moderation',
    title: 'LLM 内容审核引擎',
    subtitle: '独立进程外内容风控与合规审核',
    category: 'moderation',
    order: 20,
    executionBoundary: 'out-of-process',
  });
  assert.equal(decl.readOnly, true);
  assert.equal(decl.category, 'moderation');

  const snap = sanitizeConsolePanelSnapshot(decl, {
    status: 'ok',
    summary: [{ label: '已审核', value: '128', tone: 'ok' }],
    table: { columns: ['时间', '裁决'], rows: [['12:00', 'allow']] },
    links: [
      { label: 'Safe Docs', href: 'https://example.test/docs' },
      { label: 'XSS Attempt', href: 'javascript:alert(1)' },
    ],
  });
  assert.equal(snap.links.length, 1);
  assert.equal(snap.links[0].href, 'https://example.test/docs');

  const req = buildContentInspectRequest({
    stage: 'input',
    requestId: 'req-1',
    toolName: 'write_file',
    providerName: 'sandbox-docker',
    payload: { path: 'notes.md', content: 'hello' },
  });
  assert.equal(req.protocolVersion, 1);

  const escalated = validateContentInspectVerdict({
    protocolVersion: 1,
    decision: 'escalate',
    categories: ['policy.review'],
    score: 0.72,
    ruleId: 'MOD-01',
    reason: 'Needs human review',
  }, { stage: 'input' });
  assert.equal(escalated.decision, 'escalate');

  // Input stage forbids silent redaction; output stage allows redaction.
  assert.throws(() => validateContentInspectVerdict({
    protocolVersion: 1,
    decision: 'redact',
    categories: ['pii'],
    redactedPayload: '[redacted]',
  }, { stage: 'input' }), /cannot silently rewrite/);

  const redacted = validateContentInspectVerdict({
    protocolVersion: 1,
    decision: 'redact',
    categories: ['pii'],
    redactedPayload: '[redacted]',
  }, { stage: 'output' });
  assert.equal(redacted.redactedPayload, '[redacted]');
});

test('MechanismSlot enforces monotonic blocked/forceApproval latches and allowReplace=false guard', async () => {
  const trackedCaller = { effect: fn => fn() };
  const ORIGINAL = Symbol.for('cordis.original');
  const mech = new MechanismSlot({ name: 'tool:invoke@1', policy: 'trusted', allowReplace: false });
  const proxy = Object.create(mech, {
    ctx: { value: trackedCaller },
    [ORIGINAL]: { value: mech },
  });

  // Replace hooks are structurally forbidden when allowReplace=false.
  assert.throws(() => proxy.hook('replace', (input, base) => base(input)), SlotError);

  // Downstream before-hook cannot downgrade forceApproval=true back to false.
  const u1 = proxy.hook('before', input => ({ ...input, forceApproval: true }));
  const u2 = proxy.hook('before', input => ({ ...input, forceApproval: false, touched: true }));
  const escalated = await mech.run({ tool: 'command_status' }, x => x);
  assert.equal(escalated.forceApproval, true);
  assert.equal(escalated.touched, true);
  u1();
  u2();

  // Downstream before-hook cannot un-block or observe an already blocked request.
  let downstreamRan = false;
  const b1 = proxy.hook('before', input => ({ ...input, blocked: true, code: 'ANTILEAK_BLOCKED' }));
  const b2 = proxy.hook('before', input => {
    downstreamRan = true;
    return { ...input, blocked: false };
  });
  const blocked = await mech.run({ tool: 'write_file' }, x => x);
  assert.equal(blocked.blocked, true);
  assert.equal(blocked.code, 'ANTILEAK_BLOCKED');
  assert.equal(downstreamRan, false);
  b1();
  b2();

  // Primitive/null return or getter TOCTOU cannot wipe forceApproval or skip downstream before-hooks.
  const n1 = proxy.hook('before', input => ({ ...input, forceApproval: true }), { order: 10 });
  const n2 = proxy.hook('before', () => null, { order: 20 });
  const survivedNull = await mech.run({ tool: 'command_status' }, x => x);
  assert.equal(survivedNull.forceApproval, true);
  n1();
  n2();

  let flip = 0;
  let secondHookSawIt = false;
  const g1 = proxy.hook('before', input => ({
    ...input,
    get blocked() {
      flip += 1;
      return flip === 1;
    },
  }), { order: 10 });
  const g2 = proxy.hook('before', input => {
    secondHookSawIt = true;
    return input;
  }, { order: 20 });
  const getterBlocked = await mech.run({ tool: 'exec_command' }, x => x);
  assert.equal(getterBlocked.blocked, true);
  assert.equal(secondHookSawIt, false);
  g1();
  g2();

  // Deterministic order: order=10 runs before order=100 even when registered second.
  const orderTrace = [];
  const o2 = proxy.hook('before', input => { orderTrace.push('external-llm-100'); return input; }, { order: 100 });
  const o1 = proxy.hook('before', input => { orderTrace.push('offline-antileak-10'); return input; }, { order: 10 });
  await mech.run({ tool: 'read_file' }, x => x);
  assert.deepEqual(orderTrace, ['offline-antileak-10', 'external-llm-100']);
  o1();
  o2();

  // After-hook monotonic blocked latch prevents downstream after-hook from unblocking output.
  let after2Ran = false;
  const a1 = proxy.hook('after', out => ({ ...out, blocked: true, code: 'MOD_OUTPUT_BLOCKED' }), { order: 10 });
  const a2 = proxy.hook('after', out => { after2Ran = true; return { ...out, blocked: false }; }, { order: 20 });
  const afterOut = await mech.run({ tool: 'read_file' }, () => ({ jsonrpc: '2.0', id: 1, result: {} }));
  assert.equal(afterOut.blocked, true);
  assert.equal(after2Ran, false);
  a1();
  a2();
});
