// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Cordis 4 kernel-level AOP proxy guard and single-flight async escalation layer (adapted from Weftale KernelGuard).
import {
  AUDIT_CODES,
  CLOSED_SLOTS,
  SlotError,
  formatActionNode,
  mechanismActionKind,
  serviceInvokeActionKind,
} from '@loomward/shared';
import { evaluatePermissionTree } from './policy-tree.mjs';

const ORIGINAL = Symbol.for('cordis.original');
const ISOLATE = Symbol.for('cordis.isolate');
const GUARD_WRAPPED = Symbol('loomward.guard.wrapped');
export const GUARD_UNIT_STATE = Symbol('loomward.guard.unit-state');

function isolateOf(ctx) {
  return (ctx && typeof ctx === 'object' ? ctx[ISOLATE] : undefined) ?? {};
}

export function resolveUnitState(ctx) {
  if (!ctx || typeof ctx !== 'object') return undefined;
  return ctx[GUARD_UNIT_STATE];
}

export function unwrapCordisOriginal(obj) {
  return (obj && typeof obj === 'object' ? obj[ORIGINAL] : undefined) ?? obj;
}

export function createGuardedUnitState({
  contract,
  grant,
  subject,
  onAudit = () => {},
  escalateRuntime,
}) {
  return {
    unitId: contract.id,
    manifest: contract,
    grant,
    subject,
    runtimeWritten: [],
    approvedActions: new Set(grant.approvedActions ?? []),
    inflightEscalations: new Map(),
    active: true,
    onAudit,
    ...(typeof escalateRuntime === 'function' ? { escalateRuntime } : {}),
  };
}

function resolveMethodRule(methodRules, method) {
  return methodRules[method] ?? methodRules['*'];
}

export class KernelGuard {
  #byUnit = new Map();
  #proxyCache = new WeakMap();
  #rootFibers;
  #closedSlots;

  constructor({ rootFibers = new Set(), closedSlots = new Set(CLOSED_SLOTS) } = {}) {
    this.#rootFibers = rootFibers;
    this.#closedSlots = new Set(closedSlots);
  }

  isClosedSlot(name) {
    return this.#closedSlots.has(name);
  }

  registerUnit(state) {
    this.#byUnit.set(state.unitId, state);
  }

  unregisterUnit(unitId) {
    const state = this.#byUnit.get(unitId);
    if (state) {
      state.active = false;
      this.#byUnit.delete(unitId);
    }
  }

  getUnit(unitId) {
    return this.#byUnit.get(unitId);
  }

  /** Install global Cordis `internal/get` waterfall interceptor on the root Context. */
  installGetHook(rootCtx) {
    return rootCtx.on('internal/get', (callerCtx, prop, _error, next) => {
      if (typeof prop !== 'string') return next();
      const state = resolveUnitState(callerCtx);
      if (!state) return next();
      if (this.#closedSlots.has(prop)) {
        state.onAudit(AUDIT_CODES.AUDIT_VAULT_ACCESS_DENIED, prop, `service.get:${prop}`);
        throw new SlotError(`Unit ${state.unitId} is forbidden from accessing closed slot ${prop}.`);
      }
      const value = next();
      if (value === undefined || value === null) return value;
      return this.wrapService(prop, value, state);
    }, { global: true });
  }

  /** Build a guarded Cordis Context proxy for a single non-root extension unit. */
  createUnitContext(ctx, base, state) {
    const baseIsolates = isolateOf(base);
    const guard = this;

    const unitCtx = ctx.extend({
      get(name, strict) {
        if (typeof name === 'string' && guard.isClosedSlot(name)) {
          state.onAudit(AUDIT_CODES.AUDIT_VAULT_ACCESS_DENIED, name, `service.get:${name}`);
          throw new SlotError(`Unit ${state.unitId} is forbidden from accessing closed slot ${name}.`);
        }
        const original = Reflect.get(Object.getPrototypeOf(unitCtx), 'get', this);
        const value = original.call(this, name, strict);
        if (value === undefined || value === null) return value;
        return guard.wrapService(name, value, state);
      },
      intercept(name, config) {
        guard.assertWriteAction(
          state,
          { kind: 'service.intercept', target: name },
          () => state.manifest.writes.intercepts.includes(name),
          `Unit ${state.unitId} did not declare intercept write edge: ${name}.`,
        );
        const action = formatActionNode({ kind: 'service.intercept', target: name });
        state.runtimeWritten.push({ kind: 'intercept', target: name, action });
        if (state.grant.trustedActionNodes.includes(action)) {
          state.onAudit(AUDIT_CODES.AUDIT_TRUSTED_WRITE_ON, name, action);
        }
        const original = Reflect.get(Object.getPrototypeOf(unitCtx), 'intercept', this);
        return original.call(this, name, config);
      },
      provide(name, value, check) {
        if (isolateOf(this)[name] === baseIsolates[name]) {
          throw new SlotError(`Unit ${state.unitId} cannot call provide outside its own isolate: ${name}.`);
        }
        guard.assertWriteAction(
          state,
          { kind: 'service.isolate-provide', target: name },
          () => state.manifest.writes.isolateProvides.includes(name),
          `Unit ${state.unitId} did not declare isolate-provide write edge: ${name}.`,
        );
        const action = formatActionNode({ kind: 'service.isolate-provide', target: name });
        state.runtimeWritten.push({ kind: 'isolate-provide', target: name, action });
        const audited = state.grant.trustedActionNodes.includes(action);
        if (audited) state.onAudit(AUDIT_CODES.AUDIT_TRUSTED_WRITE_ON, name, action);
        const original = Reflect.get(Object.getPrototypeOf(unitCtx), 'provide', this);
        const dispose = original.call(this, name, value, check);
        if (!audited || typeof dispose !== 'function') return dispose;
        return async () => {
          try {
            return await dispose();
          } finally {
            state.onAudit(AUDIT_CODES.AUDIT_TRUSTED_WRITE_OFF, name, action);
          }
        };
      },
    });

    Object.defineProperty(unitCtx, GUARD_UNIT_STATE, {
      value: state,
      enumerable: false,
      configurable: true,
    });
    return unitCtx;
  }

  /** WriteAuthorizer for ImplSlot and MechanismSlot. */
  authorize(caller, request) {
    if (caller?.fiber && this.#rootFibers.has(caller.fiber)) return;
    const state = resolveUnitState(caller);
    if (!state || !state.active) {
      throw new SlotError(`Unauthorized slot write (${request.kind}:${request.slot}) from untracked or inactive caller.`);
    }

    if (request.kind === 'select') {
      const evalRes = evaluatePermissionTree(
        state.grant.tree,
        state.subject,
        { kind: 'impl.select', target: request.slot },
        { defaultEffect: 'deny' },
      );
      if (evalRes.effect !== 'allow') {
        throw new SlotError(`Unit ${state.unitId} is not allowed to select slot implementation: ${request.slot}.`);
      }
      return;
    }

    if (request.kind === 'register') {
      const actionReq = { kind: 'impl.register', target: request.slot };
      this.assertWriteAction(
        state,
        actionReq,
        () => state.manifest.registers.some(r => r.slot === request.slot && r.name === request.name),
        `Unit ${state.unitId} did not declare register write edge: ${request.slot}#${request.name}.`,
      );
      const node = formatActionNode(actionReq);
      state.runtimeWritten.push({ kind: 'impl', target: request.slot, action: node });
      if (state.grant.trustedActionNodes.includes(node)) {
        state.onAudit(AUDIT_CODES.AUDIT_TRUSTED_WRITE_ON, request.slot, node);
      }
      return;
    }

    if (request.kind === 'hook') {
      const kind = mechanismActionKind(request.phase);
      const actionReq = { kind, target: request.slot, phase: request.phase };
      this.assertWriteAction(
        state,
        actionReq,
        () => state.manifest.writes.hooks.some(h => h.slot === request.slot && h.phase === request.phase),
        `Unit ${state.unitId} did not declare hook write edge: ${request.slot}@${request.phase}.`,
      );
      const node = formatActionNode(actionReq);
      state.runtimeWritten.push({ kind: 'mechanism', target: request.slot, action: node });
      if (state.grant.trustedActionNodes.includes(node)) {
        state.onAudit(AUDIT_CODES.AUDIT_TRUSTED_WRITE_ON, request.slot, node);
      }
      return;
    }

    throw new SlotError(`Unsupported slot write kind: ${String(request.kind)}`);
  }

  released(caller, request) {
    if (caller?.fiber && this.#rootFibers.has(caller.fiber)) return;
    const state = resolveUnitState(caller);
    if (!state) return;
    let action;
    if (request.kind === 'hook') {
      action = formatActionNode({ kind: mechanismActionKind(request.phase), target: request.slot, phase: request.phase });
    } else if (request.kind === 'register') {
      action = formatActionNode({ kind: 'impl.register', target: request.slot });
    } else {
      return;
    }
    if (!state.grant.trustedActionNodes.includes(action)) return;
    state.onAudit(AUDIT_CODES.AUDIT_TRUSTED_WRITE_OFF, request.slot, action);
  }

  assertWriteAction(state, actionReq, manifestDeclared, deniedMessage) {
    if (!manifestDeclared()) throw new SlotError(deniedMessage);
    const evaluated = evaluatePermissionTree(state.grant.tree, state.subject, actionReq, { defaultEffect: 'deny' });
    if (evaluated.effect !== 'allow') throw new SlotError(deniedMessage);
  }

  wrapService(serviceName, value, state) {
    if (value === null || (typeof value !== 'object' && typeof value !== 'function')) return value;
    if (value[GUARD_WRAPPED] === true) return value;
    const methodRules = state.grant.serviceMethods?.[serviceName];
    if (!methodRules) return value;

    let byObj = this.#proxyCache.get(state);
    if (!byObj) {
      byObj = new WeakMap();
      this.#proxyCache.set(state, byObj);
    }
    let byName = byObj.get(value);
    if (!byName) {
      byName = new Map();
      byObj.set(value, byName);
    }
    const cached = byName.get(serviceName);
    if (cached !== undefined) return cached;

    const guard = this;
    let wrapped;
    if (typeof value === 'function') {
      const rule = resolveMethodRule(methodRules, '$');
      wrapped = new Proxy(value, {
        get(target, prop, receiver) {
          if (prop === GUARD_WRAPPED) return true;
          return Reflect.get(target, prop, receiver);
        },
        apply(target, thisArg, args) {
          return guard.#invokeGuardedMethod(state, serviceName, '$', rule, () => Reflect.apply(target, thisArg, args));
        },
      });
    } else {
      wrapped = new Proxy(value, {
        get(target, prop) {
          if (prop === GUARD_WRAPPED) return true;
          if (typeof prop === 'symbol') return Reflect.get(target, prop, target);
          const raw = Reflect.get(target, prop, target);
          if (typeof raw !== 'function') return raw;
          const rule = resolveMethodRule(methodRules, prop);
          if (!rule) return raw.bind(target);
          return function guardedMethod(...args) {
            return guard.#invokeGuardedMethod(
              state,
              serviceName,
              prop,
              rule,
              () => Reflect.apply(raw, target, args),
            );
          };
        },
      });
    }
    byName.set(serviceName, wrapped);
    return wrapped;
  }

  #invokeGuardedMethod(state, serviceName, methodName, rule, exec) {
    if (!rule) return exec();
    const kind = serviceInvokeActionKind(rule.mode || 'read');
    const req = {
      kind,
      target: serviceName,
      method: methodName,
      mode: rule.mode || 'read',
      async: rule.async === true,
    };
    const node = formatActionNode(req);
    const effect = state.approvedActions.has(node)
      ? 'allow'
      : evaluatePermissionTree(state.grant.tree, state.subject, req, { defaultEffect: 'deny' }).effect;

    if (effect === 'allow') return exec();

    if (effect === 'deny') {
      const err = new SlotError(`Unit ${state.unitId} is denied invoking ${serviceName}#${methodName} (policy=${rule.policy}).`);
      if (rule.async === true) return Promise.reject(err);
      throw err;
    }

    // effect === 'escalate': only async methods may suspend for single-flight runtime escalation.
    if (rule.async !== true) {
      throw new SlotError(`Synchronous method cannot escalate on use: ${serviceName}#${methodName}.`);
    }

    return (async () => {
      if (!state.active) {
        throw new SlotError(`Unit ${state.unitId} was unmounted before permission escalation.`);
      }
      if (state.approvedActions.has(node)) return exec();
      if (typeof state.escalateRuntime !== 'function') {
        throw new SlotError(`No runtime trust adjudicator bound for ${serviceName}#${methodName}.`);
      }

      let inflight = state.inflightEscalations.get(node);
      if (!inflight) {
        const detail = { node, kind, target: serviceName, method: methodName, mode: rule.mode || 'read' };
        inflight = Promise.resolve()
          .then(() => state.escalateRuntime(detail))
          .finally(() => {
            state.inflightEscalations.delete(node);
          });
        state.inflightEscalations.set(node, inflight);
      }

      const approved = await inflight;
      if (!state.active) {
        throw new SlotError(`Unit ${state.unitId} was unmounted during permission escalation.`);
      }
      if (!approved) {
        state.onAudit(AUDIT_CODES.AUDIT_ESCALATION_DENIED, serviceName, node);
        throw new SlotError(`User denied unit ${state.unitId} invoking ${serviceName}#${methodName}.`);
      }
      state.approvedActions.add(node);
      state.onAudit(AUDIT_CODES.AUDIT_ESCALATION_APPROVED, serviceName, node);
      state.onAudit(AUDIT_CODES.AUDIT_TRUSTED_WRITE_ON, serviceName, node);
      return exec();
    })();
  }
}
