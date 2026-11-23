// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createFrozenRpm, sha256Tagged, validateContractDecl } from '@loomward/shared';
import {
  createLoomWardKernel,
  evaluatePermissionTree,
  StartupRejectedError,
} from '../src/index.mjs';

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

test('createLoomWardKernel verifies RPM, boots Cordis root plugins, registers slots, and tears down cleanly', async () => {
  const sourceBytes = new TextEncoder().encode('root-plugin-demo-v1');
  const entryHash = await sha256Tagged(sourceBytes);
  const contract = validateContractDecl({
    schemaVersion: 1,
    id: 'demo-root',
    kind: 'root-plugin',
    version: '3.0.0-alpha.0',
    executionBoundary: 'in-process-root',
    provides: ['demo:service'],
    consumes: ['tool:provider@1'],
  });
  const rpm = await createFrozenRpm({
    target: 'runtime',
    rootPlugins: [
      { id: contract.id, version: contract.version, entryHash, provides: [...contract.provides] },
    ],
  });

  const { control } = await createLoomWardKernel({
    rpm,
    roots: [{
      id: contract.id,
      contract,
      bytes: async () => sourceBytes,
      load: async () => ({
        name: 'demo-root',
        apply(ctx) {
          ctx.provide('demo:service', { ready: true });
          const providerSlot = ctx.get('tool:provider@1');
          providerSlot.register('demo-tools', { list: () => ['ping'] });
        },
      }),
    }],
  });

  assert.deepEqual(control.roots().map(r => r.id), ['demo-root']);
  assert.deepEqual(control.getService('demo:service'), { ready: true });
  assert.deepEqual(control.slots.toolProvider.names(), ['demo-tools']);

  await control.stop();
  assert.deepEqual(control.slots.toolProvider.names(), []);
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
    error => error instanceof StartupRejectedError && error.code === 'GUARD_ROOT_HASH_MISMATCH',
  );
  assert.equal(loaded, false);
});
