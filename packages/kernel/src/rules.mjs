// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import {
  CLOSED_SLOTS,
  REJECT_CODES,
  ROOT_ONLY_SERVICES,
  buildPermissionSubject,
  formatActionNode,
  mechanismActionKind,
  serviceInvokeActionKind,
  validateContractDecl,
} from '@loomward/shared';
import { compileUnitGrant } from './policy-tree.mjs';

const CLOSED_SLOT_SET = new Set(CLOSED_SLOTS);
const ROOT_ONLY_SET = new Set(ROOT_ONLY_SERVICES);

export const executionBoundaryRule = Object.freeze({
  id: 'guard.execution-boundary',
  order: 10,
  evaluate(ctx) {
    const { contract, expectedKind } = ctx;
    if (expectedKind && contract.kind !== expectedKind) {
      return REJECT_CODES.GUARD_CONTRACT_MISMATCH;
    }
    if (contract.kind === 'extension-plugin' && contract.executionBoundary !== 'out-of-process') {
      return REJECT_CODES.GUARD_EXECUTION_BOUNDARY_REQUIRED;
    }
    if (contract.kind === 'root-plugin' && contract.executionBoundary !== 'in-process-root') {
      return REJECT_CODES.GUARD_EXECUTION_BOUNDARY_REQUIRED;
    }
  },
});

export const closedSlotRule = Object.freeze({
  id: 'guard.closed-slot',
  order: 20,
  evaluate(ctx) {
    const { contract, slotRegistry } = ctx;
    if (contract.kind === 'root-plugin') return;
    const isClosedTarget = target => {
      if (CLOSED_SLOT_SET.has(target) || ROOT_ONLY_SET.has(target)) return true;
      const slot = slotRegistry.get(target);
      return slot?.decl?.policy === 'closed';
    };
    const referenced = [
      ...contract.consumes,
      ...contract.provides,
      ...contract.registers.map(r => r.slot),
      ...contract.writes.hooks.map(h => h.slot),
      ...contract.writes.intercepts,
      ...contract.writes.isolateProvides,
    ];
    for (const target of referenced) {
      if (isClosedTarget(target)) {
        return REJECT_CODES.GUARD_POLICY_CLOSED;
      }
    }
  },
});

export const slotDeclarationRule = Object.freeze({
  id: 'guard.slot-declaration',
  order: 30,
  evaluate(ctx) {
    const { contract, slotRegistry } = ctx;
    const isRoot = contract.kind === 'root-plugin';
    const singleSlotsClaimed = new Set();

    for (const reg of contract.registers) {
      const slot = slotRegistry.get(reg.slot);
      if (!slot || typeof slot.register !== 'function') {
        return REJECT_CODES.GUARD_SLOT_UNDECLARED;
      }
      if (!isRoot && slot.decl?.policy === 'closed') {
        return REJECT_CODES.GUARD_POLICY_CLOSED;
      }
      if (slot.decl?.cardinality === 'single') {
        const existingCount = typeof slot.names === 'function' ? slot.names().length : 0;
        if (existingCount > 0 || singleSlotsClaimed.has(reg.slot)) {
          return REJECT_CODES.GUARD_SLOT_NAME_TAKEN;
        }
        singleSlotsClaimed.add(reg.slot);
      }
      if (typeof slot.has === 'function' && slot.has(reg.name)) {
        return REJECT_CODES.GUARD_SLOT_NAME_TAKEN;
      }
      if (!isRoot && slot.decl?.policy === 'trusted') {
        ctx.trustedActions.push(formatActionNode({ kind: 'impl.register', target: reg.slot }));
      }
    }

    const replaceSlots = new Set();
    for (const hook of contract.writes.hooks) {
      const slot = slotRegistry.get(hook.slot);
      if (!slot || typeof slot.hook !== 'function') {
        return REJECT_CODES.GUARD_SLOT_UNDECLARED;
      }
      if (!isRoot && slot.decl?.policy === 'closed') {
        return REJECT_CODES.GUARD_POLICY_CLOSED;
      }
      if (hook.phase === 'replace') {
        if (slot.decl?.allowReplace === false) {
          return REJECT_CODES.GUARD_POLICY_CLOSED;
        }
        if ((typeof slot.hasReplace === 'function' && slot.hasReplace()) || replaceSlots.has(hook.slot)) {
          return REJECT_CODES.GUARD_SLOT_REPLACE_TAKEN;
        }
        replaceSlots.add(hook.slot);
      }
      if (!isRoot && slot.decl?.policy === 'trusted') {
        ctx.trustedActions.push(formatActionNode({ kind: mechanismActionKind(hook.phase), target: hook.slot }));
      }
    }

    if (!isRoot) {
      for (const svcName of contract.writes.intercepts) {
        ctx.trustedActions.push(formatActionNode({ kind: 'service.intercept', target: svcName }));
      }
      for (const svcName of contract.writes.isolateProvides) {
        ctx.trustedActions.push(formatActionNode({ kind: 'service.isolate-provide', target: svcName }));
      }
      for (const [svcName, rules] of Object.entries(ctx.serviceMethods ?? {})) {
        if (!rules || typeof rules !== 'object') continue;
        for (const [methodName, rule] of Object.entries(rules)) {
          if (rule?.policy === 'trusted') {
            ctx.trustedActions.push(
              formatActionNode({ kind: serviceInvokeActionKind(rule.mode || 'read'), target: svcName, method: methodName }),
            );
          }
        }
      }
    }
  },
});

export const trustedApprovalRule = Object.freeze({
  id: 'guard.trusted-approval',
  order: 40,
  evaluate(ctx) {
    if (ctx.contract.kind === 'root-plugin') return;
    if (ctx.trust.autoApproveTrusted === true) return;
    const approved = new Set(ctx.trust.approvedActions ?? []);
    for (const node of ctx.trustedActions) {
      if (!approved.has(node)) {
        ctx.pendingActions.push(node);
      }
    }
  },
});

export const BUILTIN_GUARD_RULES = Object.freeze([
  executionBoundaryRule,
  closedSlotRule,
  slotDeclarationRule,
  trustedApprovalRule,
]);

export function createGuardPipeline(extraRules = []) {
  return Object.freeze([...BUILTIN_GUARD_RULES, ...extraRules].sort((a, b) => a.order - b.order));
}

export function evaluateGuard(
  input,
  { pipeline = BUILTIN_GUARD_RULES, extraNodes = [], serviceMethods = {}, expectedKind = null } = {},
) {
  try {
    if (!input || typeof input !== 'object' || !(input.slotRegistry instanceof Map)) {
      return { decision: 'deny', code: REJECT_CODES.GUARD_INDETERMINATE };
    }
    const contract = validateContractDecl(input.contract);
    const trust = input.trust ?? {};
    const subject = buildPermissionSubject(contract, {
      signed: trust.signed === true,
      trustLevel: trust.trustLevel ?? 'personal-trusted',
      isolated: input.isolated !== false,
    });
    const evalCtx = {
      input,
      contract,
      expectedKind,
      slotRegistry: input.slotRegistry,
      serviceMethods,
      trust,
      subject,
      trustedActions: [],
      pendingActions: [],
    };
    for (const rule of pipeline) {
      const code = rule.evaluate(evalCtx);
      if (code !== undefined) {
        if (typeof code === 'string' && code.length > 0) {
          return { decision: 'deny', code };
        }
        // Fail closed on async/thenable or non-string guard rule results.
        return { decision: 'deny', code: REJECT_CODES.GUARD_INDETERMINATE };
      }
    }
    if (evalCtx.pendingActions.length > 0) {
      return {
        decision: 'escalate',
        code: REJECT_CODES.GUARD_TRUSTED_APPROVAL_REQUIRED,
        pendingActions: Object.freeze([...new Set(evalCtx.pendingActions)]),
        subject,
      };
    }
    const grant = compileUnitGrant(subject, contract, input.slotRegistry, {
      approvedActions: trust.approvedActions ?? [],
      extraNodes,
      serviceMethods,
      autoApproveTrusted: trust.autoApproveTrusted === true,
    });
    return {
      decision: 'allow',
      subject,
      grant,
    };
  } catch {
    return { decision: 'deny', code: REJECT_CODES.GUARD_INDETERMINATE };
  }
}
