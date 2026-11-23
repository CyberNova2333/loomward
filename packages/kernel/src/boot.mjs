// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import { Context } from 'cordis';
import {
  BOOT_DEADLINE_MS,
  ImplSlot,
  MechanismSlot,
  SlotError,
  computeManifestHash,
  isRpmShape,
  sha256Tagged,
  validateContractDecl,
  withDeadline,
} from '@loomward/shared';

export const PLATFORM_SLOTS = Object.freeze({
  toolProvider: Object.freeze({ name: 'tool:provider@1', cardinality: 'multi', policy: 'trusted' }),
  toolInvoke: Object.freeze({ name: 'tool:invoke@1', policy: 'trusted' }),
  policyRule: Object.freeze({ name: 'policy:rule@1', cardinality: 'multi', policy: 'trusted' }),
  approvalChannel: Object.freeze({ name: 'approval:channel@1', cardinality: 'single', policy: 'trusted' }),
  gatewayIngress: Object.freeze({ name: 'gateway:ingress@1', cardinality: 'multi', policy: 'trusted' }),
  consolePanel: Object.freeze({ name: 'console:panel@1', cardinality: 'multi', policy: 'public' }),
});

export class StartupRejectedError extends Error {
  constructor(code, rootId, detail = '') {
    super(`LoomWard startup rejected [${code}] (${rootId})${detail ? `: ${detail}` : ''}`);
    this.name = 'StartupRejectedError';
    this.code = code;
    this.rootId = rootId;
  }
}

export async function createLoomWardKernel({ rpm, roots = [], timeoutMs = BOOT_DEADLINE_MS } = {}) {
  return withDeadline(timeoutMs, async run => {
    if (!isRpmShape(rpm)) {
      throw new StartupRejectedError('GUARD_RPM_INVALID_SHAPE', 'rpm');
    }
    const expectedHash = await computeManifestHash(rpm);
    if (expectedHash !== rpm.manifestHash) {
      throw new StartupRejectedError('GUARD_RPM_HASH_MISMATCH', 'rpm');
    }

    const given = new Map();
    for (const ref of roots) {
      if (!ref || typeof ref.id !== 'string' || given.has(ref.id)) {
        throw new StartupRejectedError('GUARD_ROOT_ENTRY_MISMATCH', String(ref?.id || 'unknown'));
      }
      given.set(ref.id, ref);
    }

    const expectedIds = new Set(rpm.rootPlugins.map(p => p.id));
    for (const id of given.keys()) {
      if (!expectedIds.has(id)) {
        throw new StartupRejectedError('GUARD_ROOT_ENTRY_MISMATCH', id, 'Unexpected root plugin not in RPM.');
      }
    }

    const rootCtx = new Context();
    const rootFibers = new Set([rootCtx.fiber]);
    const mountedRoots = [];
    const report = [];

    run.add(async () => {
      await rootCtx.fiber.dispose();
    });

    const authorizer = {
      authorize(caller, request) {
        if (caller?.fiber && rootFibers.has(caller.fiber)) return;
        throw new SlotError(`Unauthorized slot write (${request.kind}:${request.slot}) from non-root caller.`);
      },
      released() {},
    };

    const slots = {
      toolProvider: new ImplSlot(PLATFORM_SLOTS.toolProvider, () => authorizer),
      toolInvoke: new MechanismSlot(PLATFORM_SLOTS.toolInvoke, () => authorizer),
      policyRule: new ImplSlot(PLATFORM_SLOTS.policyRule, () => authorizer),
      approvalChannel: new ImplSlot(PLATFORM_SLOTS.approvalChannel, () => authorizer),
      gatewayIngress: new ImplSlot(PLATFORM_SLOTS.gatewayIngress, () => authorizer),
      consolePanel: new ImplSlot(PLATFORM_SLOTS.consolePanel, () => authorizer),
    };

    for (const slot of Object.values(slots)) {
      rootCtx.provide(slot.name, slot);
    }

    run.live();

    for (const entry of rpm.rootPlugins) {
      run.live();
      const ref = given.get(entry.id);
      if (!ref || typeof ref.bytes !== 'function' || typeof ref.load !== 'function') {
        throw new StartupRejectedError('GUARD_INDETERMINATE', entry.id, 'Missing root module loader.');
      }
      const contract = validateContractDecl(ref.contract);
      if (contract.id !== entry.id || contract.kind !== 'root-plugin' || contract.version !== entry.version) {
        throw new StartupRejectedError('GUARD_CONTRACT_MISMATCH', entry.id);
      }
      const actualHash = await sha256Tagged(await ref.bytes());
      if (actualHash !== entry.entryHash) {
        throw new StartupRejectedError('GUARD_ROOT_HASH_MISMATCH', entry.id);
      }
      run.live();
      const mod = await ref.load();
      const fiber = rootCtx.plugin(mod, ref.config);
      rootFibers.add(fiber.ctx.fiber);
      run.add(async () => {
        await fiber.dispose();
        rootFibers.delete(fiber.ctx.fiber);
      });
      await fiber;
      mountedRoots.push({ id: entry.id, version: entry.version, provides: [...entry.provides] });
      report.push({ unitId: entry.id, code: 'AUDIT_ROOT_MOUNTED', at: Date.now() });
    }

    run.live();

    const control = Object.freeze({
      rpm: Object.freeze({ ...rpm }),
      roots: () => mountedRoots.map(item => ({ ...item, provides: [...item.provides] })),
      report: () => report.map(item => ({ ...item })),
      slots: Object.freeze({ ...slots }),
      getService: name => rootCtx.get(name),
      stop: async () => {
        await rootCtx.fiber.dispose();
      },
    });

    return { control };
  });
}
