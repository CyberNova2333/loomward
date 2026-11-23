// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalJson,
  computeManifestHash,
  createFrozenRpm,
  isRpmShape,
  sha256Tagged,
  validateContractDecl,
  withDeadline,
  BootDeadlineError,
  ImplSlot,
  MechanismSlot,
  SlotError,
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

test('validateContractDecl enforces executionBoundary discipline', () => {
  const valid = validateContractDecl({
    schemaVersion: 1,
    id: 'antileak',
    kind: 'extension-plugin',
    version: '3.0.0-alpha.0',
    executionBoundary: 'out-of-process',
    provides: ['policy:antileak'],
    consumes: ['tool:invoke@1'],
  });
  assert.equal(valid.executionBoundary, 'out-of-process');
  assert.throws(() => validateContractDecl({
    schemaVersion: 1,
    id: 'bad-ext',
    kind: 'extension-plugin',
    version: '3.0.0-alpha.0',
    executionBoundary: 'in-process-root',
  }), /cannot declare executionBoundary/);
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

test('ImplSlot and MechanismSlot enforce authorization and undo registrations on dispose', async () => {
  const events = [];
  const authorizer = {
    authorize(_caller, req) {
      events.push(`auth:${req.kind}:${req.slot}`);
    },
    released(_caller, req) {
      events.push(`rel:${req.kind}:${req.slot}`);
    },
  };
  const slot = new ImplSlot({ name: 'vault:backend@1', cardinality: 'single', policy: 'trusted' }, () => authorizer);
  slot.registerBuiltin('builtin-default', { kind: 'default' });
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

  const mech = new MechanismSlot({ name: 'tool:invoke@1', policy: 'trusted' }, () => authorizer);
  const mechProxy = Object.create(mech, {
    ctx: { value: trackedCaller },
    [ORIGINAL]: { value: mech },
  });
  const unhook = mechProxy.hook('before', input => ({ ...input, checked: true }));
  const result = await mech.run({ tool: 'read_file' }, x => ({ ok: true, ...x }));
  assert.deepEqual(result, { ok: true, tool: 'read_file', checked: true });
  unhook();
  assert.ok(events.includes('rel:hook:tool:invoke@1'));
});
