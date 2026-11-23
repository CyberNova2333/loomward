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
  buildPermissionSubject,
  canonicalJson,
  computeManifestHash,
  createFrozenRpm,
  formatActionNode,
  isRpmShape,
  isSafeUnicodeString,
  mechanismActionKind,
  sanitizeAuditMetadata,
  serviceInvokeActionKind,
  sha256Tagged,
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
