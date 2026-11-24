// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import { Context } from 'cordis';
import {
  AUDIT_CODES,
  BOOT_DEADLINE_MS,
  ImplSlot,
  MechanismSlot,
  REJECT_CODES,
  ROOT_ONLY_SERVICES,
  SlotError,
  VAULT_SLOT,
  computeManifestHash,
  isRpmShape,
  sanitizeAuditMetadata,
  sha256Tagged,
  validateContractDecl,
  withDeadline,
} from '@loomward/shared';
import { KernelGuard, createGuardedUnitState } from './guard.mjs';
import { createGuardPipeline, evaluateGuard } from './rules.mjs';

const MAX_AUDIT_REPORT = 1000;
const DISPOSE_TIMEOUT_MS = 2000;

async function disposeFiberBounded(fiber, timeoutMs = DISPOSE_TIMEOUT_MS) {
  if (!fiber || typeof fiber.dispose !== 'function') return;
  let timer;
  const disposePromise = Promise.resolve().then(() => fiber.dispose()).catch(() => {});
  try {
    await Promise.race([
      disposePromise,
      new Promise(resolve => {
        timer = setTimeout(resolve, timeoutMs);
        timer.unref?.();
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

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

function sameStringSet(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
  const sa = [...a].sort();
  const sb = [...b].sort();
  return sa.every((val, i) => val === sb[i]);
}

function extractInjectNames(inject) {
  if (!inject) return [];
  if (Array.isArray(inject)) return inject.filter(x => typeof x === 'string');
  if (typeof inject === 'object') {
    const out = [];
    for (const [k, v] of Object.entries(inject)) {
      if (k === 'required' || k === 'optional') {
        if (Array.isArray(v)) out.push(...v.filter(x => typeof x === 'string'));
      } else {
        out.push(k);
      }
    }
    return out;
  }
  return [];
}

export async function createLoomWardKernel({ rpm, roots = [], expectedTarget = null, timeoutMs = BOOT_DEADLINE_MS } = {}) {
  return withDeadline(timeoutMs, async run => {
    if (!isRpmShape(rpm)) {
      throw new StartupRejectedError(REJECT_CODES.GUARD_RPM_INVALID_SHAPE, 'rpm');
    }
    if (expectedTarget && rpm.target !== expectedTarget) {
      throw new StartupRejectedError(REJECT_CODES.GUARD_RPM_INVALID_SHAPE, 'rpm', `Expected RPM target ${expectedTarget}, got ${rpm.target}.`);
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
    const kernelCapability = Symbol('loomward.kernel.capability');
    const mountedRoots = [];
    const mountedUnits = new Map();
    const inFlightMounts = new Set();
    const report = [];
    let stopped = false;

    const recordAudit = (unitId, code, target, action) => {
      report.push(sanitizeAuditMetadata({
        unitId,
        code,
        ...(target ? { target } : {}),
        ...(action ? { action } : {}),
        at: Date.now(),
      }));
      if (report.length > MAX_AUDIT_REPORT) {
        report.splice(0, report.length - MAX_AUDIT_REPORT);
      }
    };

    const guard = new KernelGuard({
      rootFibers,
      closedSlots: new Set([VAULT_SLOT]),
      rootOnlyServices: new Set(ROOT_ONLY_SERVICES),
    });
    const disposeGetHook = guard.installGetHook(rootCtx);

    run.add(async () => {
      stopped = true;
      disposeGetHook();
      await rootCtx.fiber.dispose();
      rootFibers.clear();
    });

    const slots = {
      vaultBackend: new ImplSlot(PLATFORM_SLOTS.vaultBackend, () => guard, { capability: kernelCapability }),
      toolProvider: new ImplSlot(PLATFORM_SLOTS.toolProvider, () => guard, { capability: kernelCapability }),
      toolInvoke: new MechanismSlot(PLATFORM_SLOTS.toolInvoke, () => guard),
      policyRule: new ImplSlot(PLATFORM_SLOTS.policyRule, () => guard, { capability: kernelCapability }),
      approvalChannel: new ImplSlot(PLATFORM_SLOTS.approvalChannel, () => guard, { capability: kernelCapability }),
      gatewayIngress: new ImplSlot(PLATFORM_SLOTS.gatewayIngress, () => guard, { capability: kernelCapability }),
      consolePanel: new ImplSlot(PLATFORM_SLOTS.consolePanel, () => guard, { capability: kernelCapability }),
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
      if (
        contract.id !== entry.id
        || contract.kind !== 'root-plugin'
        || contract.version !== entry.version
        || !sameStringSet(contract.provides, entry.provides)
      ) {
        throw new StartupRejectedError(REJECT_CODES.GUARD_CONTRACT_MISMATCH, entry.id);
      }
      const actualHash = await sha256Tagged(await ref.bytes());
      if (actualHash !== entry.entryHash) {
        throw new StartupRejectedError(REJECT_CODES.GUARD_ROOT_HASH_MISMATCH, entry.id);
      }
      run.live();
      const mod = await ref.load();
      const applyFn = typeof mod === 'function'
        ? mod
        : (mod && typeof mod === 'object' && typeof mod.apply === 'function' ? mod.apply : null);
      if (!applyFn) {
        throw new StartupRejectedError(REJECT_CODES.GUARD_INDETERMINATE, entry.id, 'Root plugin missing apply function.');
      }
      const fiber = rootCtx.plugin({
        name: (mod && typeof mod === 'object' && mod.name) || entry.id,
        inject: mod && typeof mod === 'object' ? mod.inject : undefined,
        apply(ctx, cfg) {
          rootFibers.add(ctx.fiber);
          return applyFn(ctx, cfg);
        },
      }, ref.config);
      rootFibers.add(fiber.ctx.fiber);
      run.add(async () => {
        await fiber.dispose();
        rootFibers.delete(fiber.ctx.fiber);
      });
      await fiber;
      if (fiber.state !== 2) {
        throw new StartupRejectedError(REJECT_CODES.GUARD_INDETERMINATE, entry.id, 'Root plugin did not reach ACTIVE state.');
      }
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
      extraRules = [],
    }) {
      if (stopped) {
        throw new StartupRejectedError(REJECT_CODES.GUARD_INDETERMINATE, String(rawContract?.id || 'unknown'), 'Kernel has been stopped.');
      }
      const contract = validateContractDecl(rawContract);
      if (contract.kind !== 'extension-plugin') {
        throw new StartupRejectedError(REJECT_CODES.GUARD_CONTRACT_MISMATCH, contract.id, 'Extension mount requires kind="extension-plugin".');
      }
      if (mountedUnits.has(contract.id) || inFlightMounts.has(contract.id)) {
        throw new StartupRejectedError(REJECT_CODES.GUARD_UNIT_ALREADY_MOUNTED, contract.id);
      }
      const effectivePipeline = createGuardPipeline(Array.isArray(extraRules) ? extraRules : []);
      const evaluation = evaluateGuard(
        { contract, slotRegistry, trust, isolated },
        { pipeline: effectivePipeline, extraNodes, serviceMethods, expectedKind: 'extension-plugin' },
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

      inFlightMounts.add(contract.id);
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
        if (stopped) {
          throw new StartupRejectedError(REJECT_CODES.GUARD_INDETERMINATE, contract.id, 'Kernel stopped during extension mount.');
        }
        const applyFn = typeof mod === 'function'
          ? mod
          : (mod && typeof mod === 'object' && typeof mod.apply === 'function' ? mod.apply : null);
        if (!applyFn) {
          throw new StartupRejectedError(REJECT_CODES.GUARD_INDETERMINATE, contract.id, 'Extension plugin missing apply function.');
        }
        // Reject undeclared or closed services in plugin.inject to prevent implicit Fiber intercept bypass.
        if (mod && typeof mod === 'object' && mod.inject) {
          for (const reqName of extractInjectNames(mod.inject)) {
            if (guard.isClosedSlot(reqName) || guard.isRootOnlyService(reqName) || !contract.consumes.includes(reqName)) {
              throw new SlotError(`Extension unit ${contract.id} inject references undeclared or forbidden service: ${reqName}.`);
            }
          }
        }
        fiber = unitCtx.plugin({
          name: (mod && typeof mod === 'object' && mod.name) || contract.id,
          apply(childCtx, cfg) {
            if (stopped) return;
            const facade = guard.createRestrictedFacade(childCtx, rootCtx, state);
            return applyFn(facade, cfg);
          },
        }, config);
        await fiber;
        if (stopped) {
          throw new StartupRejectedError(REJECT_CODES.GUARD_INDETERMINATE, contract.id, 'Kernel stopped during extension mount.');
        }
        if (fiber.state !== 2) {
          throw new StartupRejectedError(REJECT_CODES.GUARD_INDETERMINATE, contract.id, 'Extension plugin did not reach ACTIVE state.');
        }
      } catch (error) {
        guard.unregisterUnit(contract.id);
        await disposeFiberBounded(fiber);
        throw error;
      } finally {
        inFlightMounts.delete(contract.id);
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
      await disposeFiberBounded(record.fiber);
      recordAudit(unitId, AUDIT_CODES.AUDIT_UNIT_UNMOUNTED);
      return true;
    }

    const frozenRpmView = Object.freeze({
      format: rpm.format,
      target: rpm.target,
      manifestHash: rpm.manifestHash,
      rootPlugins: Object.freeze(rpm.rootPlugins.map(p => Object.freeze({
        id: p.id,
        version: p.version,
        entryHash: p.entryHash,
        provides: Object.freeze([...p.provides]),
      }))),
    });

    const control = Object.freeze({
      rpm: frozenRpmView,
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
        if (stopped) return;
        stopped = true;
        for (const unitId of [...mountedUnits.keys()].reverse()) {
          await unmountExtensionUnit(unitId).catch(() => {});
        }
        disposeGetHook();
        await disposeFiberBounded(rootCtx.fiber);
        rootFibers.clear();
      },
    });

    return { control };
  });
}
