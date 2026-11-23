// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import { Context } from 'cordis';
import {
  AUDIT_CODES,
  BOOT_DEADLINE_MS,
  ImplSlot,
  MechanismSlot,
  REJECT_CODES,
  VAULT_SLOT,
  computeManifestHash,
  isRpmShape,
  sanitizeAuditMetadata,
  sha256Tagged,
  validateContractDecl,
  withDeadline,
} from '@loomward/shared';
import { KernelGuard, createGuardedUnitState } from './guard.mjs';
import { evaluateGuard } from './rules.mjs';

export const PLATFORM_SLOTS = Object.freeze({
  vaultBackend: Object.freeze({ name: VAULT_SLOT, cardinality: 'single', policy: 'closed' }),
  toolProvider: Object.freeze({ name: 'tool:provider@1', cardinality: 'multi', policy: 'trusted' }),
  toolInvoke: Object.freeze({ name: 'tool:invoke@1', policy: 'trusted', allowReplace: false }),
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
      throw new StartupRejectedError(REJECT_CODES.GUARD_RPM_INVALID_SHAPE, 'rpm');
    }
    const expectedHash = await computeManifestHash(rpm);
    if (expectedHash !== rpm.manifestHash) {
      throw new StartupRejectedError(REJECT_CODES.GUARD_RPM_HASH_MISMATCH, 'rpm');
    }

    const given = new Map();
    for (const ref of roots) {
      if (!ref || typeof ref.id !== 'string' || given.has(ref.id)) {
        throw new StartupRejectedError(REJECT_CODES.GUARD_ROOT_ENTRY_MISMATCH, String(ref?.id || 'unknown'));
      }
      given.set(ref.id, ref);
    }

    const expectedIds = new Set(rpm.rootPlugins.map(p => p.id));
    for (const id of given.keys()) {
      if (!expectedIds.has(id)) {
        throw new StartupRejectedError(REJECT_CODES.GUARD_ROOT_ENTRY_MISMATCH, id, 'Unexpected root plugin not in RPM.');
      }
    }

    const rootCtx = new Context();
    const rootFibers = new Set([rootCtx.fiber]);
    const mountedRoots = [];
    const mountedUnits = new Map();
    const report = [];

    const recordAudit = (unitId, code, target, action) => {
      report.push(sanitizeAuditMetadata({
        unitId,
        code,
        ...(target ? { target } : {}),
        ...(action ? { action } : {}),
        at: Date.now(),
      }));
    };

    const guard = new KernelGuard({
      rootFibers,
      closedSlots: new Set([VAULT_SLOT]),
    });
    const disposeGetHook = guard.installGetHook(rootCtx);

    run.add(async () => {
      disposeGetHook();
      await rootCtx.fiber.dispose();
    });

    const slots = {
      vaultBackend: new ImplSlot(PLATFORM_SLOTS.vaultBackend, () => guard),
      toolProvider: new ImplSlot(PLATFORM_SLOTS.toolProvider, () => guard),
      toolInvoke: new MechanismSlot(PLATFORM_SLOTS.toolInvoke, () => guard),
      policyRule: new ImplSlot(PLATFORM_SLOTS.policyRule, () => guard),
      approvalChannel: new ImplSlot(PLATFORM_SLOTS.approvalChannel, () => guard),
      gatewayIngress: new ImplSlot(PLATFORM_SLOTS.gatewayIngress, () => guard),
      consolePanel: new ImplSlot(PLATFORM_SLOTS.consolePanel, () => guard),
    };

    const slotRegistry = new Map();
    for (const slot of Object.values(slots)) {
      rootCtx.provide(slot.name, slot);
      slotRegistry.set(slot.name, slot);
    }

    run.live();

    for (const entry of rpm.rootPlugins) {
      run.live();
      const ref = given.get(entry.id);
      if (!ref || typeof ref.bytes !== 'function' || typeof ref.load !== 'function') {
        throw new StartupRejectedError(REJECT_CODES.GUARD_INDETERMINATE, entry.id, 'Missing root module loader.');
      }
      const contract = validateContractDecl(ref.contract);
      if (contract.id !== entry.id || contract.kind !== 'root-plugin' || contract.version !== entry.version) {
        throw new StartupRejectedError(REJECT_CODES.GUARD_CONTRACT_MISMATCH, entry.id);
      }
      const actualHash = await sha256Tagged(await ref.bytes());
      if (actualHash !== entry.entryHash) {
        throw new StartupRejectedError(REJECT_CODES.GUARD_ROOT_HASH_MISMATCH, entry.id);
      }
      run.live();
      const mod = await ref.load();
      // Cordis plugin() constructs fiber synchronously and invokes apply(fiber.ctx);
      // pre-register fiber before awaiting so synchronous slot registrations inside apply() are authorized.
      const fiber = rootCtx.plugin({
        name: mod.name || entry.id,
        inject: mod.inject,
        apply(ctx, cfg) {
          rootFibers.add(ctx.fiber);
          return mod.apply(ctx, cfg);
        },
      }, ref.config);
      rootFibers.add(fiber.ctx.fiber);
      run.add(async () => {
        await fiber.dispose();
        rootFibers.delete(fiber.ctx.fiber);
      });
      await fiber;
      mountedRoots.push({ id: entry.id, version: entry.version, provides: [...entry.provides] });
      recordAudit(entry.id, AUDIT_CODES.AUDIT_ROOT_MOUNTED);
    }

    run.live();

    async function mountExtensionUnit({
      contract: rawContract,
      load,
      config,
      trust = {},
      isolated = true,
      escalateRuntime,
      serviceMethods = {},
      extraNodes = [],
      pipeline,
    }) {
      const contract = validateContractDecl(rawContract);
      if (mountedUnits.has(contract.id)) {
        throw new StartupRejectedError(REJECT_CODES.GUARD_UNIT_ALREADY_MOUNTED, contract.id);
      }
      const evaluation = evaluateGuard(
        { contract, slotRegistry, trust, isolated },
        { ...(pipeline ? { pipeline } : {}), extraNodes, serviceMethods },
      );
      if (evaluation.decision !== 'allow') {
        const err = new StartupRejectedError(
          evaluation.code || REJECT_CODES.GUARD_INDETERMINATE,
          contract.id,
          evaluation.decision === 'escalate'
            ? `Trusted actions require explicit approval: ${(evaluation.pendingActions || []).join(', ')}`
            : '',
        );
        err.decision = evaluation.decision;
        if (evaluation.pendingActions) err.pendingActions = [...evaluation.pendingActions];
        throw err;
      }

      const state = createGuardedUnitState({
        contract,
        grant: evaluation.grant,
        subject: evaluation.subject,
        onAudit: (code, target, action) => recordAudit(contract.id, code, target, action),
        escalateRuntime,
      });
      guard.registerUnit(state);
      const unitCtx = guard.createUnitContext(rootCtx, rootCtx, state);
      let fiber;
      try {
        const mod = typeof load === 'function' ? await load() : load;
        fiber = unitCtx.plugin(mod, config);
        await fiber;
      } catch (error) {
        guard.unregisterUnit(contract.id);
        if (fiber) {
          await fiber.dispose().catch(() => {});
        }
        throw error;
      }

      const record = {
        id: contract.id,
        version: contract.version,
        executionBoundary: contract.executionBoundary,
        provides: [...contract.provides],
        fiber,
        state,
      };
      mountedUnits.set(contract.id, record);
      recordAudit(contract.id, AUDIT_CODES.AUDIT_UNIT_MOUNTED);
      return {
        id: contract.id,
        version: contract.version,
        executionBoundary: contract.executionBoundary,
        grant: evaluation.grant,
      };
    }

    async function unmountExtensionUnit(unitId) {
      const record = mountedUnits.get(unitId);
      if (!record) return false;
      mountedUnits.delete(unitId);
      guard.unregisterUnit(unitId);
      await record.fiber.dispose();
      recordAudit(unitId, AUDIT_CODES.AUDIT_UNIT_UNMOUNTED);
      return true;
    }

    const control = Object.freeze({
      rpm: Object.freeze({ ...rpm }),
      roots: () => mountedRoots.map(item => ({ ...item, provides: [...item.provides] })),
      units: () => [...mountedUnits.values()].map(item => ({
        id: item.id,
        version: item.version,
        executionBoundary: item.executionBoundary,
        provides: [...item.provides],
      })),
      report: () => report.map(item => ({ ...item })),
      slots: Object.freeze({ ...slots }),
      getService: name => rootCtx.get(name),
      mountExtensionUnit,
      unmountExtensionUnit,
      stop: async () => {
        for (const unitId of [...mountedUnits.keys()].reverse()) {
          await unmountExtensionUnit(unitId).catch(() => {});
        }
        disposeGetHook();
        await rootCtx.fiber.dispose();
      },
    });

    return { control };
  });
}
