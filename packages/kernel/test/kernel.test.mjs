// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {
  AUDIT_CODES,
  REJECT_CODES,
  SlotError,
  VAULT_SLOT,
  createFrozenRpm,
  sha256Tagged,
  validateContractDecl,
} from '@loomward/shared';
import {
  PLATFORM_SLOTS,
  StartupRejectedError,
  buildWorkspaceRpm,
  createLoomWardKernel,
  evaluateGuard,
  evaluatePermissionTree,
  verifyWorkspaceRpm,
} from '../src/index.mjs';

const REPO_ROOT = path.resolve(import.meta.dirname, '../../..');

async function bootMinimalKernel(extraApply = () => {}) {
  const sourceBytes = new TextEncoder().encode('root-plugin-demo-v1');
  const entryHash = await sha256Tagged(sourceBytes);
  const contract = validateContractDecl({
    schemaVersion: 1,
    id: 'demo-root',
    kind: 'root-plugin',
    version: '3.0.0-alpha.0',
    executionBoundary: 'in-process-root',
    provides: ['demo:service'],
    consumes: ['tool:provider@1', VAULT_SLOT],
  });
  const rpm = await createFrozenRpm({
    target: 'runtime',
    rootPlugins: [
      { id: contract.id, version: contract.version, entryHash, provides: [...contract.provides] },
    ],
  });
  return createLoomWardKernel({
    rpm,
    roots: [{
      id: contract.id,
      contract,
      bytes: async () => sourceBytes,
      load: async () => ({
        name: 'demo-root',
        apply(ctx) {
          ctx.provide('demo:service', {
            async sensitiveAction(arg) {
              return `done:${arg}`;
            },
            syncDanger() {
              return 'nope';
            },
            readInfo() {
              return 'ok';
            },
          });
          ctx.get(VAULT_SLOT).register('demo-vault', {
            exportSecrets: () => ({ secret: 'top-secret' }),
          });
          extraApply(ctx);
        },
      }),
    }],
  });
}

test('PolicyTree applies specificity precedence and deny > escalate > allow on ties', () => {
  const tree = [
    { node: 'tool.invoke:*', effect: 'allow' },
    { node: 'tool.invoke:fs:*', effect: 'escalate' },
    { node: 'tool.invoke:fs:delete_file', effect: 'deny' },
    { node: 'tool.invoke:fs:delete_file', effect: 'allow' },
  ];
  const subject = { signed: true, trustLevel: 'personal-trusted', executionBoundary: 'out-of-process' };
  assert.equal(evaluatePermissionTree(tree, subject, 'tool.invoke:meta:context').effect, 'allow');
  assert.equal(evaluatePermissionTree(tree, subject, 'tool.invoke:fs:read_file').effect, 'escalate');
  assert.equal(evaluatePermissionTree(tree, subject, 'tool.invoke:fs:delete_file').effect, 'deny');
  assert.equal(evaluatePermissionTree([], subject, 'tool.invoke:any:op').effect, 'deny');
});

test('createLoomWardKernel verifies RPM, exposes all 7 platform slots including closed vault:backend@1, and tears down cleanly', async () => {
  assert.equal(PLATFORM_SLOTS.vaultBackend.name, VAULT_SLOT);
  assert.equal(PLATFORM_SLOTS.vaultBackend.policy, 'closed');

  const { control } = await bootMinimalKernel(ctx => {
    ctx.get('tool:provider@1').register('demo-tools', { list: () => ['ping'] });
  });

  assert.deepEqual(control.roots().map(r => r.id), ['demo-root']);
  assert.ok(control.getService('demo:service'));
  assert.deepEqual(control.slots.toolProvider.names(), ['demo-tools']);
  assert.deepEqual(control.slots.vaultBackend.names(), ['demo-vault']);

  await control.stop();
  assert.deepEqual(control.slots.toolProvider.names(), []);
  assert.deepEqual(control.slots.vaultBackend.names(), []);
});

test('createLoomWardKernel fails closed when RPM hash or root entry bytes are tampered', async () => {
  const goodBytes = new TextEncoder().encode('trusted-root');
  const badBytes = new TextEncoder().encode('tampered-root');
  const entryHash = await sha256Tagged(goodBytes);
  const contract = validateContractDecl({
    schemaVersion: 1,
    id: 'guarded-root',
    kind: 'root-plugin',
    version: '3.0.0-alpha.0',
    executionBoundary: 'in-process-root',
    provides: ['guarded:service'],
  });
  const rpm = await createFrozenRpm({
    target: 'runtime',
    rootPlugins: [
      { id: contract.id, version: contract.version, entryHash, provides: [...contract.provides] },
    ],
  });

  let loaded = false;
  await assert.rejects(
    () => createLoomWardKernel({
      rpm,
      roots: [{
        id: contract.id,
        contract,
        bytes: async () => badBytes,
        load: async () => {
          loaded = true;
          return { name: 'guarded-root', apply() {} };
        },
      }],
    }),
    error => error instanceof StartupRejectedError && error.code === REJECT_CODES.GUARD_ROOT_HASH_MISMATCH,
  );
  assert.equal(loaded, false);
});

test('KernelGuard blocks extension units from reading vault:backend@1, undeclared writes, and non-isolated provide', async () => {
  const { control } = await bootMinimalKernel();

  // 1. Contract attempting to consume closed vault slot is rejected at evaluateGuard time.
  await assert.rejects(
    () => control.mountExtensionUnit({
      contract: {
        schemaVersion: 1,
        id: 'greedy-ext',
        kind: 'extension-plugin',
        version: '3.0.0-alpha.0',
        executionBoundary: 'out-of-process',
        consumes: [VAULT_SLOT],
      },
      load: () => ({ name: 'greedy-ext', apply() {} }),
      trust: { autoApproveTrusted: true },
    }),
    error => error instanceof StartupRejectedError && error.code === REJECT_CODES.GUARD_POLICY_CLOSED,
  );

  // 2. Contract declaring in-process-signed is rejected because Node.js extensions must be out-of-process.
  await assert.rejects(
    () => control.mountExtensionUnit({
      contract: {
        schemaVersion: 1,
        id: 'inproc-ext',
        kind: 'extension-plugin',
        version: '3.0.0-alpha.0',
        executionBoundary: 'in-process-signed',
      },
      load: () => ({ name: 'inproc-ext', apply() {} }),
      trust: { autoApproveTrusted: true },
    }),
    error => error instanceof StartupRejectedError && error.code === REJECT_CODES.GUARD_EXECUTION_BOUNDARY_REQUIRED,
  );

  // 3. Mounted extension unit trying to read vault:backend@1 via ctx.get OR property access,
  // or perform undeclared register/hook/provide/intercept is blocked at runtime with audit trail.
  let capturedCtx;
  await control.mountExtensionUnit({
    contract: {
      schemaVersion: 1,
      id: 'probing-ext',
      kind: 'extension-plugin',
      version: '3.0.0-alpha.0',
      executionBoundary: 'out-of-process',
      consumes: ['tool:provider@1'],
      registers: [{ slot: 'tool:provider@1', name: 'probing-provider' }],
      writes: { hooks: [{ slot: 'tool:invoke@1', phase: 'before' }], intercepts: [], isolateProvides: [] },
    },
    trust: { autoApproveTrusted: true },
    load: () => ({
      name: 'probing-ext',
      apply(ctx) {
        capturedCtx = ctx;
        ctx.get('tool:provider@1').register('probing-provider', { id: 'probing-provider' });
        ctx.get('tool:invoke@1').hook('before', input => input);
      },
    }),
  });

  assert.throws(() => capturedCtx.get(VAULT_SLOT), SlotError);
  assert.throws(() => capturedCtx[VAULT_SLOT], SlotError);
  assert.throws(() => capturedCtx.get('tool:provider@1').register('undeclared-name', {}), SlotError);
  assert.throws(() => capturedCtx.get('tool:provider@1').select('probing-provider'), SlotError);
  assert.throws(() => capturedCtx.get('tool:invoke@1').hook('after', x => x), SlotError);
  assert.throws(() => capturedCtx.intercept('demo:service', {}), SlotError);
  assert.throws(() => capturedCtx.provide('rogue:service', {}), SlotError);

  const beforeUnmount = control.report();
  assert.ok(beforeUnmount.some(e => e.unitId === 'probing-ext' && e.code === AUDIT_CODES.AUDIT_VAULT_ACCESS_DENIED));
  assert.ok(beforeUnmount.some(e => e.unitId === 'probing-ext' && e.code === AUDIT_CODES.AUDIT_TRUSTED_WRITE_ON));

  assert.equal(await control.unmountExtensionUnit('probing-ext'), true);
  assert.equal(control.slots.toolProvider.has('probing-provider'), false);

  const afterUnmount = control.report();
  assert.ok(afterUnmount.some(e => e.unitId === 'probing-ext' && e.code === AUDIT_CODES.AUDIT_TRUSTED_WRITE_OFF));
  assert.ok(afterUnmount.some(e => e.unitId === 'probing-ext' && e.code === AUDIT_CODES.AUDIT_UNIT_UNMOUNTED));

  await control.stop();
});

test('KernelGuard single-flight ask-on-use coalesces concurrent calls and aborts pending escalations on unmount', async () => {
  const { control } = await bootMinimalKernel();

  let escalationCalls = 0;
  let resolveGate;
  let svcProxy;

  await control.mountExtensionUnit({
    contract: {
      schemaVersion: 1,
      id: 'escalating-ext',
      kind: 'extension-plugin',
      version: '3.0.0-alpha.0',
      executionBoundary: 'out-of-process',
      consumes: ['demo:service'],
    },
    trust: { autoApproveTrusted: true },
    serviceMethods: {
      'demo:service': {
        readInfo: { policy: 'public', mode: 'read' },
        syncDanger: { policy: 'ask-on-use', mode: 'write', async: false },
        sensitiveAction: { policy: 'ask-on-use', mode: 'write', async: true },
      },
    },
    escalateRuntime: async () => {
      escalationCalls++;
      return new Promise(resolve => { resolveGate = resolve; });
    },
    load: () => ({
      name: 'escalating-ext',
      apply(ctx) {
        svcProxy = ctx.get('demo:service');
      },
    }),
  });

  // Public sync method works immediately; sync ask-on-use fails closed.
  assert.equal(svcProxy.readInfo(), 'ok');
  assert.throws(() => svcProxy.syncDanger(), SlotError);

  // Two concurrent async ask-on-use calls coalesce into one trust prompt.
  const p1 = svcProxy.sensitiveAction('a');
  const p2 = svcProxy.sensitiveAction('b');
  await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(escalationCalls, 1);
  resolveGate(true);
  assert.deepEqual(await Promise.all([p1, p2]), ['done:a', 'done:b']);
  // Subsequent call uses cached approval without re-prompting.
  assert.equal(await svcProxy.sensitiveAction('c'), 'done:c');
  assert.equal(escalationCalls, 1);

  // Now verify unmount aborts an in-flight escalation on a second unit.
  let secondGate;
  let secondSvc;
  await control.mountExtensionUnit({
    contract: {
      schemaVersion: 1,
      id: 'unmount-abort-ext',
      kind: 'extension-plugin',
      version: '3.0.0-alpha.0',
      executionBoundary: 'out-of-process',
      consumes: ['demo:service'],
    },
    trust: { autoApproveTrusted: true },
    serviceMethods: {
      'demo:service': {
        sensitiveAction: { policy: 'ask-on-use', mode: 'write', async: true },
      },
    },
    escalateRuntime: () => new Promise(resolve => { secondGate = resolve; }),
    load: () => ({
      name: 'unmount-abort-ext',
      apply(ctx) {
        secondSvc = ctx.get('demo:service');
      },
    }),
  });

  const pendingCall = secondSvc.sensitiveAction('aborted');
  await new Promise(resolve => setTimeout(resolve, 10));
  await control.unmountExtensionUnit('unmount-abort-ext');
  secondGate(true);
  await assert.rejects(() => pendingCall, /unmounted/);

  await control.stop();
});

test('evaluateGuard requires explicit approval for trusted slots and fails closed on invalid input', () => {
  assert.equal(evaluateGuard(null).decision, 'deny');
  assert.equal(evaluateGuard(null).code, REJECT_CODES.GUARD_INDETERMINATE);

  const slotRegistry = new Map([
    ['tool:provider@1', { decl: { name: 'tool:provider@1', policy: 'trusted' }, register() {}, has: () => false }],
  ]);
  const res = evaluateGuard({
    contract: {
      schemaVersion: 1,
      id: 'third-party-ext',
      kind: 'extension-plugin',
      version: '1.0.0',
      executionBoundary: 'out-of-process',
      registers: [{ slot: 'tool:provider@1', name: 'third-party' }],
    },
    slotRegistry,
    trust: { approvedActions: [] },
  });
  assert.equal(res.decision, 'escalate');
  assert.equal(res.code, REJECT_CODES.GUARD_TRUSTED_APPROVAL_REQUIRED);
  assert.deepEqual(res.pendingActions, ['impl.register:tool:provider@1']);
});

test('buildWorkspaceRpm and verifyWorkspaceRpm hash real workspace root plugins and detect tampering', async () => {
  const { rpm, entries } = await buildWorkspaceRpm(REPO_ROOT);
  assert.deepEqual(entries.map(e => e.id).sort(), ['cloud-relay', 'console', 'host', 'sandbox']);
  assert.equal(await verifyWorkspaceRpm(REPO_ROOT, rpm), true);

  const tampered = {
    ...rpm,
    rootPlugins: rpm.rootPlugins.map(entry =>
      entry.id === 'host' ? { ...entry, entryHash: `sha256:${'0'.repeat(64)}` } : entry,
    ),
  };
  await assert.rejects(
    () => verifyWorkspaceRpm(REPO_ROOT, tampered),
    error => error instanceof StartupRejectedError && error.code === REJECT_CODES.GUARD_RPM_HASH_MISMATCH,
  );
});

test('evaluateGuard rejects tool:invoke@1@replace to prevent bypassing approval and replay pipeline', () => {
  const slotRegistry = new Map([
    ['tool:invoke@1', { decl: { name: 'tool:invoke@1', policy: 'trusted', allowReplace: false }, hook() {}, hasReplace: () => false }],
  ]);
  const res = evaluateGuard({
    contract: {
      schemaVersion: 1,
      id: 'hostile-replacer',
      kind: 'extension-plugin',
      version: '1.0.0',
      executionBoundary: 'out-of-process',
      writes: {
        hooks: [{ slot: 'tool:invoke@1', phase: 'replace' }],
        intercepts: [],
        isolateProvides: [],
      },
    },
    slotRegistry,
    trust: { autoApproveTrusted: true, signed: true },
  });
  assert.equal(res.decision, 'deny');
  assert.equal(res.code, REJECT_CODES.GUARD_POLICY_CLOSED);
});

test('KernelGuard blocks Cordis context escapes (ctx.root/reflect/registry/events/proto/cordis.original), root-plugin spoofing, and hung-root BootDeadline deadlock', async () => {
  // 1. Hung root plugin during boot with hung dispose does not deadlock withDeadline.
  const hungBytes = new TextEncoder().encode('hung-root');
  const hungHash = await sha256Tagged(hungBytes);
  const hungContract = validateContractDecl({
    schemaVersion: 1,
    id: 'hung-root',
    kind: 'root-plugin',
    version: '3.0.0-alpha.0',
    executionBoundary: 'in-process-root',
  });
  const hungRpm = await createFrozenRpm({
    target: 'runtime',
    rootPlugins: [{ id: 'hung-root', version: '3.0.0-alpha.0', entryHash: hungHash, provides: [] }],
  });
  await assert.rejects(
    () => createLoomWardKernel({
      rpm: hungRpm,
      timeoutMs: 80,
      roots: [{
        id: 'hung-root',
        contract: hungContract,
        bytes: async () => hungBytes,
        load: async () => ({
          name: 'hung-root',
          async apply() {
            await new Promise(() => {});
          },
        }),
      }],
    }),
    err => err.name === 'BootDeadlineError',
  );

  // 2. mountExtensionUnit rejects contract with kind="root-plugin".
  const { control } = await bootMinimalKernel();
  await assert.rejects(
    () => control.mountExtensionUnit({
      contract: {
        schemaVersion: 1,
        id: 'spoofed-root',
        kind: 'root-plugin',
        version: '3.0.0-alpha.0',
        executionBoundary: 'in-process-root',
      },
      load: () => ({ name: 'spoofed-root', apply() {} }),
    }),
    err => err instanceof StartupRejectedError && err.code === REJECT_CODES.GUARD_CONTRACT_MISMATCH,
  );

  // 3. Mounted extension facade hides root/reflect/registry/events, blocks null-proto escape & cordis.original, and blocks after unmount.
  let extCtx;
  let extProviderSlot;
  let extPanelSlot;
  let extService;
  let interceptedCtx;
  let isolatedCtx;
  await control.mountExtensionUnit({
    contract: {
      schemaVersion: 1,
      id: 'escape-probe-ext',
      kind: 'extension-plugin',
      version: '3.0.0-alpha.0',
      executionBoundary: 'out-of-process',
      consumes: ['tool:provider@1', 'console:panel@1', 'demo:service'],
      registers: [{ slot: 'tool:provider@1', name: 'probe-prov' }],
      writes: {
        hooks: [],
        intercepts: ['demo:service'],
        isolateProvides: ['ext:local'],
      },
    },
    trust: { autoApproveTrusted: true },
    serviceMethods: {
      'demo:service': {
        readInfo: { policy: 'public', mode: 'read' },
      },
    },
    load: () => ({
      name: 'escape-probe-ext',
      apply(ctx) {
        extCtx = ctx;
        extProviderSlot = ctx.get('tool:provider@1');
        extPanelSlot = ctx.get('console:panel@1');
        extService = ctx.get('demo:service');
        interceptedCtx = ctx.intercept('demo:service', {});
        isolatedCtx = ctx.isolate(['ext:local']);
        isolatedCtx.provide('ext:local', { ok: true });
      },
    }),
  });

  assert.equal(extCtx.root, undefined);
  assert.equal(extCtx.reflect, undefined);
  assert.equal(extCtx.registry, undefined);
  assert.equal(extCtx.events, undefined);
  assert.equal(Object.getPrototypeOf(extCtx), null);
  assert.deepEqual(Object.getOwnPropertySymbols(extCtx), []);
  // R2-C1: ctx.intercept() and ctx.isolate() return restricted null-prototype facades, NEVER raw Cordis Context!
  assert.ok(interceptedCtx);
  assert.equal(interceptedCtx.root, undefined);
  assert.equal(Object.getPrototypeOf(interceptedCtx), null);
  assert.throws(() => interceptedCtx.get(VAULT_SLOT), SlotError);
  assert.ok(isolatedCtx);
  assert.equal(isolatedCtx.root, undefined);
  assert.equal(Object.getPrototypeOf(isolatedCtx), null);
  assert.throws(() => extCtx.isolate(['undeclared:svc']), SlotError);
  assert.equal(extProviderSlot[Symbol.for('cordis.original')], undefined);
  assert.equal(extProviderSlot.registerBuiltin, undefined);
  assert.equal(extProviderSlot.entries, undefined);
  // R2-H1: public slot console:panel@1 also hides entries/current from extensions so other plugins' closures are isolated.
  assert.equal(extPanelSlot.entries, undefined);
  assert.equal(extPanelSlot.current, undefined);
  assert.equal(extService[Symbol.for('cordis.original')], undefined);
  assert.throws(() => extCtx.on('internal/service', () => {}), SlotError);
  assert.throws(() => extCtx.get('sandbox:docker'), SlotError);
  assert.throws(() => extCtx.get('console:loopback'), SlotError);
  assert.throws(() => extCtx.get('host:vault'), SlotError);
  // Unlisted method on demo:service fails closed.
  assert.throws(() => extService.syncDanger(), SlotError);
  assert.equal(extService.readInfo(), 'ok');

  // R2-H2: serviceMethods referencing a service not in contract.consumes is rejected at evaluateGuard time.
  await assert.rejects(
    () => control.mountExtensionUnit({
      contract: {
        schemaVersion: 1,
        id: 'undeclared-svc-ext',
        kind: 'extension-plugin',
        version: '3.0.0-alpha.0',
        executionBoundary: 'out-of-process',
        consumes: [],
      },
      serviceMethods: {
        'demo:service': {
          readInfo: { policy: 'public', mode: 'read' },
        },
      },
      load: () => ({ name: 'undeclared-svc-ext', apply() {} }),
    }),
    err => err instanceof StartupRejectedError && err.code === REJECT_CODES.GUARD_SLOT_UNDECLARED,
  );

  // After unmount, captured service proxy & context fail closed.
  await control.unmountExtensionUnit('escape-probe-ext');
  assert.throws(() => extService.readInfo(), SlotError);
  assert.throws(() => extCtx.get('demo:service'), SlotError);

  await control.stop();
  await assert.rejects(
    () => control.mountExtensionUnit({
      contract: {
        schemaVersion: 1,
        id: 'post-stop-ext',
        kind: 'extension-plugin',
        version: '3.0.0-alpha.0',
        executionBoundary: 'out-of-process',
      },
      load: () => ({ name: 'post-stop-ext', apply() {} }),
    }),
    StartupRejectedError,
  );
});
