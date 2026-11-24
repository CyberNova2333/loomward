// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Cordis 4 kernel-level AOP proxy guard and single-flight async escalation layer (adapted from Weftale KernelGuard).
import { Context } from 'cordis';
import {
  AUDIT_CODES,
  CLOSED_SLOTS,
  ImplSlot,
  MechanismSlot,
  ROOT_ONLY_SERVICES,
  SlotError,
  VAULT_SLOT,
  formatActionNode,
  mechanismActionKind,
  serviceInvokeActionKind,
} from '@loomward/shared';
import { evaluatePermissionTree } from './policy-tree.mjs';

const ORIGINAL = Symbol.for('cordis.original');
const CALLER = Symbol.for('cordis.caller');
const SHADOW = Symbol.for('cordis.shadow');
const ISOLATE = Symbol.for('cordis.isolate');
const TRACKER = Symbol.for('cordis.tracker');
const GUARD_WRAPPED = Symbol('loomward.guard.wrapped');
const MAX_RUNTIME_WRITTEN = 256;

const BLOCKED_CONTEXT_PROPS = new Set([
  'root',
  'reflect',
  'registry',
  'events',
  'fiber',
  'parent',
  'scope',
  'extend',
  'plugin',
  'base',
  'lifecycle',
  'symbols',
  'runtime',
  'state',
  'constructor',
  '__proto__',
  'prototype',
]);

const BLOCKED_SYMBOLS = new Set([ORIGINAL, CALLER, SHADOW, ISOLATE, TRACKER]);

function isCordisContextOrFiber(value) {
  if (!value || (typeof value !== 'object' && typeof value !== 'function')) return false;
  if (Context.is(value)) return true;
  try {
    return Boolean(value.ctx && Context.is(value.ctx) && typeof value.dispose === 'function' && 'state' in value);
  } catch {
    return false;
  }
}

function hasCordisTracker(value) {
  if (!value || (typeof value !== 'object' && typeof value !== 'function')) return false;
  try {
    return TRACKER in value;
  } catch {
    return true;
  }
}

function assertSafeServiceReturn(result, serviceName, memberName) {
  if (isCordisContextOrFiber(result)) {
    throw new SlotError(`Blocked unsafe Cordis context return from ${serviceName}#${memberName}.`);
  }
  if (result && typeof result.then === 'function') {
    return Promise.resolve(result).then(resolved => {
      if (isCordisContextOrFiber(resolved)) {
        throw new SlotError(`Blocked unsafe async Cordis context return from ${serviceName}#${memberName}.`);
      }
      return resolved;
    });
  }
  return result;
}

function isolateOf(ctx) {
  return (ctx && typeof ctx === 'object' ? ctx[ISOLATE] : undefined) ?? {};
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
    approvedActions: new Set(),
    inflightEscalations: new Map(),
    active: true,
    onAudit,
    ...(typeof escalateRuntime === 'function' ? { escalateRuntime } : {}),
  };
}

function recordRuntimeWrite(state, entry) {
  state.runtimeWritten.push(entry);
  if (state.runtimeWritten.length > MAX_RUNTIME_WRITTEN) {
    state.runtimeWritten.splice(0, state.runtimeWritten.length - MAX_RUNTIME_WRITTEN);
  }
}

function resolveMethodRule(methodRules, method) {
  if (Object.hasOwn(methodRules, method)) return methodRules[method];
  if (Object.hasOwn(methodRules, '*')) return methodRules['*'];
  return undefined;
}

function isDeclaredTarget(manifest, target) {
  if (manifest.consumes.includes(target)) return true;
  if (manifest.registers.some(r => r.slot === target)) return true;
  if (manifest.writes.hooks.some(h => h.slot === target)) return true;
  if (manifest.writes.intercepts.includes(target)) return true;
  if (manifest.writes.isolateProvides.includes(target)) return true;
  return false;
}

export class KernelGuard {
  #byUnit = new Map();
  #unitStates = new WeakMap();
  #proxyCache = new WeakMap();
  #wrappedProxies = new WeakSet();
  #rootFibers;
  #closedSlots;
  #rootOnlyServices;

  constructor({
    rootFibers = new Set(),
    closedSlots = new Set(CLOSED_SLOTS),
    rootOnlyServices = new Set(ROOT_ONLY_SERVICES),
  } = {}) {
    this.#rootFibers = rootFibers;
    this.#closedSlots = new Set(closedSlots);
    this.#rootOnlyServices = new Set([...closedSlots, ...rootOnlyServices]);
  }

  isClosedSlot(name) {
    return this.#closedSlots.has(name);
  }

  isRootOnlyService(name) {
    return this.#rootOnlyServices.has(name);
  }

  isRootCaller(caller) {
    return Boolean(caller?.fiber && this.#rootFibers.has(caller.fiber) && !this.resolveState(caller));
  }

  bindContext(ctx, state) {
    if (!ctx || typeof ctx !== 'object') return;
    this.#unitStates.set(ctx, state);
    if (ctx.fiber && typeof ctx.fiber === 'object' && !this.#rootFibers.has(ctx.fiber)) {
      this.#unitStates.set(ctx.fiber, state);
    }
  }

  resolveState(ctx) {
    if (!ctx || typeof ctx !== 'object') return undefined;
    const direct = this.#unitStates.get(ctx);
    if (direct) return direct;
    if (ctx.fiber && typeof ctx.fiber === 'object') {
      return this.#unitStates.get(ctx.fiber);
    }
    return undefined;
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

  #assertUnitActive(state, actionLabel = 'operation') {
    if (!state || !state.active) {
      throw new SlotError(`Extension unit ${state?.unitId || 'unknown'} is inactive and cannot perform ${actionLabel}.`);
    }
  }

  #assertServiceReadable(prop, state) {
    this.#assertUnitActive(state, `service.get:${prop}`);
    if (this.#closedSlots.has(prop)) {
      state.onAudit(AUDIT_CODES.AUDIT_VAULT_ACCESS_DENIED, prop, `service.get:${prop}`);
      throw new SlotError(`Unit ${state.unitId} is forbidden from accessing closed slot ${prop}.`);
    }
    if (this.#rootOnlyServices.has(prop)) {
      if (prop === VAULT_SLOT) {
        state.onAudit(AUDIT_CODES.AUDIT_VAULT_ACCESS_DENIED, prop, `service.get:${prop}`);
      }
      throw new SlotError(`Unit ${state.unitId} is forbidden from accessing root-only service ${prop}.`);
    }
    if (!isDeclaredTarget(state.manifest, prop)) {
      throw new SlotError(`Unit ${state.unitId} did not declare access to service/slot ${prop}.`);
    }
  }

  /** Install global Cordis `internal/get` waterfall interceptor on the root Context. */
  installGetHook(rootCtx) {
    return rootCtx.on('internal/get', (callerCtx, prop, _error, next) => {
      if (typeof prop !== 'string') return next();
      const state = this.resolveState(callerCtx);
      if (!state) return next();
      this.#assertServiceReadable(prop, state);
      const value = next();
      if (value === undefined || value === null) return value;
      return this.wrapResolvedValue(prop, value, callerCtx, state);
    }, { global: true });
  }

  /** Wrap an ImplSlot or MechanismSlot into a restricted facade blocking cordis.original & registerBuiltin. */
  wrapSlot(slotValue, rawCtx, state) {
    const rawSlot = unwrapCordisOriginal(slotValue);
    const guard = this;
    if (rawSlot instanceof ImplSlot) {
      const boundSlot = Object.create(rawSlot, {
        ctx: { value: rawCtx, enumerable: false },
        [ORIGINAL]: { value: rawSlot, enumerable: false },
      });
      const facade = Object.create(null);
      facade.name = rawSlot.name;
      facade.decl = rawSlot.decl;
      facade.register = (name, impl) => {
        guard.#assertUnitActive(state, `impl.register:${rawSlot.name}`);
        return boundSlot.register(name, impl);
      };
      facade.select = name => {
        guard.#assertUnitActive(state, `impl.select:${rawSlot.name}`);
        return boundSlot.select(name);
      };
      facade.has = name => {
        guard.#assertUnitActive(state, `impl.has:${rawSlot.name}`);
        return rawSlot.has(name);
      };
      facade.names = () => {
        guard.#assertUnitActive(state, `impl.names:${rawSlot.name}`);
        return rawSlot.names();
      };
      return Object.freeze(facade);
    }

    if (rawSlot instanceof MechanismSlot) {
      const boundSlot = Object.create(rawSlot, {
        ctx: { value: rawCtx, enumerable: false },
        [ORIGINAL]: { value: rawSlot, enumerable: false },
      });
      const facade = Object.create(null);
      facade.name = rawSlot.name;
      facade.decl = rawSlot.decl;
      facade.hook = (phase, handler, opts) => {
        guard.#assertUnitActive(state, `mechanism.hook:${rawSlot.name}`);
        return boundSlot.hook(phase, handler, opts);
      };
      facade.hasReplace = () => {
        guard.#assertUnitActive(state, `mechanism.hasReplace:${rawSlot.name}`);
        return rawSlot.hasReplace();
      };
      return Object.freeze(facade);
    }

    return null;
  }

  wrapResolvedValue(serviceName, value, rawCtx, state) {
    if (this.#wrappedProxies.has(value)) return value;
    const raw = unwrapCordisOriginal(value);
    if (isCordisContextOrFiber(raw)) {
      throw new SlotError(`Unit ${state.unitId} is forbidden from obtaining raw Cordis context on ${serviceName}.`);
    }
    const wrappedSlot = this.wrapSlot(raw, rawCtx, state);
    if (wrappedSlot) return wrappedSlot;
    return this.wrapService(serviceName, raw, state);
  }

  /** Build a guarded internal Cordis Context for attaching the extension's Fiber. */
  createUnitContext(ctx, base, state) {
    const unitCtx = ctx.extend({});
    this.bindContext(unitCtx, state);
    return unitCtx;
  }

  /** Build a restricted null-prototype facade passed to extension `apply(ctx, cfg)`. */
  createRestrictedFacade(rawCtx, base, state) {
    const baseIsolates = isolateOf(base);
    const guard = this;
    this.bindContext(rawCtx, state);

    const methods = Object.create(null);
    methods.get = (name, strict) => {
      if (typeof name !== 'string') {
        throw new SlotError(`Unit ${state.unitId} cannot query non-string service name.`);
      }
      guard.#assertServiceReadable(name, state);
      const value = rawCtx.reflect?._getImpl
        ? rawCtx.reflect._getImpl(name, strict)?.value
        : rawCtx.get(name, strict);
      if (value === undefined || value === null) return value;
      return guard.wrapResolvedValue(name, value, rawCtx, state);
    };

    methods.effect = (fn, label) => {
      guard.#assertUnitActive(state, 'ctx.effect');
      if (typeof fn !== 'function') {
        throw new SlotError(`Unit ${state.unitId} ctx.effect requires a function.`);
      }
      const dispose = rawCtx.effect(() => fn(), label);
      return typeof dispose === 'function' ? () => { dispose(); } : undefined;
    };

    methods.on = (event, listener) => {
      guard.#assertUnitActive(state, `ctx.on:${String(event)}`);
      if (event !== 'dispose') {
        throw new SlotError(`Extension unit ${state.unitId} may only listen to "dispose" lifecycle events.`);
      }
      if (typeof listener !== 'function') {
        throw new SlotError(`Unit ${state.unitId} ctx.on requires a function.`);
      }
      const dispose = rawCtx.on('dispose', () => listener());
      return typeof dispose === 'function' ? () => { dispose(); } : undefined;
    };

    methods.intercept = (name, config) => {
      guard.#assertUnitActive(state, `service.intercept:${name}`);
      guard.assertWriteAction(
        state,
        { kind: 'service.intercept', target: name },
        () => state.manifest.writes.intercepts.includes(name),
        `Unit ${state.unitId} did not declare intercept write edge: ${name}.`,
      );
      const action = formatActionNode({ kind: 'service.intercept', target: name });
      recordRuntimeWrite(state, { kind: 'intercept', target: name, action });
      const audited = state.grant.trustedActionNodes.includes(action);
      if (audited) state.onAudit(AUDIT_CODES.AUDIT_TRUSTED_WRITE_ON, name, action);
      const childOrDispose = rawCtx.intercept(name, config);
      if (audited) {
        let offEmitted = false;
        const emitOff = () => {
          if (offEmitted) return;
          offEmitted = true;
          state.onAudit(AUDIT_CODES.AUDIT_TRUSTED_WRITE_OFF, name, action);
        };
        rawCtx.effect(() => () => emitOff(), `audit:intercept:${name}`);
      }
      if (typeof childOrDispose === 'function') {
        return () => { childOrDispose(); };
      }
      if (childOrDispose && typeof childOrDispose === 'object') {
        return guard.createRestrictedFacade(childOrDispose, base, state);
      }
      return undefined;
    };

    methods.isolate = names => {
      guard.#assertUnitActive(state, 'ctx.isolate');
      const list = Array.isArray(names) ? names : [names];
      if (list.length === 0 || list.some(n => typeof n !== 'string' || !n)) {
        throw new SlotError(`Unit ${state.unitId} ctx.isolate requires a non-empty list of service names.`);
      }
      for (const n of list) {
        if (guard.#closedSlots.has(n) || guard.#rootOnlyServices.has(n) || !state.manifest.writes.isolateProvides.includes(n)) {
          throw new SlotError(`Unit ${state.unitId} is not allowed to isolate service: ${n}.`);
        }
      }
      let isoCtx = rawCtx;
      for (const n of list) {
        isoCtx = isoCtx.isolate(n);
      }
      return guard.createRestrictedFacade(isoCtx, base, state);
    };

    methods.provide = (name, value, check) => {
      guard.#assertUnitActive(state, `service.isolate-provide:${name}`);
      if (check !== undefined) {
        throw new SlotError(`Unit ${state.unitId} cannot register custom provide check callbacks on ${name}.`);
      }
      if (isCordisContextOrFiber(value) || hasCordisTracker(value)) {
        throw new SlotError(`Unit ${state.unitId} cannot provide a Cordis Context, Fiber, or tracker object on ${name}.`);
      }
      if (isolateOf(rawCtx)[name] === baseIsolates[name]) {
        throw new SlotError(`Unit ${state.unitId} cannot call provide outside its own isolate: ${name}.`);
      }
      guard.assertWriteAction(
        state,
        { kind: 'service.isolate-provide', target: name },
        () => state.manifest.writes.isolateProvides.includes(name),
        `Unit ${state.unitId} did not declare isolate-provide write edge: ${name}.`,
      );
      const action = formatActionNode({ kind: 'service.isolate-provide', target: name });
      recordRuntimeWrite(state, { kind: 'isolate-provide', target: name, action });
      const audited = state.grant.trustedActionNodes.includes(action);
      if (audited) state.onAudit(AUDIT_CODES.AUDIT_TRUSTED_WRITE_ON, name, action);
      const dispose = rawCtx.provide(name, value);
      let offEmitted = false;
      const emitOff = () => {
        if (!audited || offEmitted) return;
        offEmitted = true;
        state.onAudit(AUDIT_CODES.AUDIT_TRUSTED_WRITE_OFF, name, action);
      };
      if (audited) {
        rawCtx.effect(() => () => emitOff(), `audit:provide:${name}`);
      }
      if (typeof dispose !== 'function') return dispose;
      return async () => {
        try {
          return await dispose();
        } finally {
          emitOff();
        }
      };
    };

    const backing = Object.create(null);
    return new Proxy(backing, {
      getPrototypeOf() {
        return null;
      },
      setPrototypeOf() {
        return false;
      },
      ownKeys() {
        return ['get', 'effect', 'on', 'intercept', 'isolate', 'provide'];
      },
      get(_target, prop) {
        if (typeof prop === 'symbol') return undefined;
        if (Object.hasOwn(methods, prop)) return methods[prop];
        if (BLOCKED_CONTEXT_PROPS.has(prop)) return undefined;
        // Property-style service access (e.g. `ctx['vault:backend@1']`) goes through the exact same guard.
        return methods.get(prop);
      },
      set() {
        return false;
      },
      deleteProperty() {
        return false;
      },
    });
  }

  /** WriteAuthorizer for ImplSlot and MechanismSlot. */
  authorize(caller, request) {
    if (this.isRootCaller(caller)) return;
    const state = this.resolveState(caller);
    if (!state || !state.active) {
      throw new SlotError(`Unauthorized slot access (${request.kind}:${request.slot}) from untracked or inactive caller.`);
    }

    if (request.kind === 'read') {
      throw new SlotError(`Unit ${state.unitId} is forbidden from reading raw registrations on ${request.slot}.`);
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
      recordRuntimeWrite(state, { kind: 'impl', target: request.slot, action: node });
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
      recordRuntimeWrite(state, { kind: 'mechanism', target: request.slot, action: node });
      if (state.grant.trustedActionNodes.includes(node)) {
        state.onAudit(AUDIT_CODES.AUDIT_TRUSTED_WRITE_ON, request.slot, node);
      }
      return;
    }

    throw new SlotError(`Unsupported slot write kind: ${String(request.kind)}`);
  }

  released(caller, request) {
    if (this.isRootCaller(caller)) return;
    const state = this.resolveState(caller);
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
    if (this.#wrappedProxies.has(value)) return value;
    const rawTarget = unwrapCordisOriginal(value);
    if (this.#wrappedProxies.has(rawTarget)) return rawTarget;
    if (isCordisContextOrFiber(rawTarget)) {
      throw new SlotError(`Unit ${state.unitId} cannot wrap raw Cordis context on ${serviceName}.`);
    }
    const methodRules = state.grant.serviceMethods?.[serviceName] ?? null;

    let byObj = this.#proxyCache.get(state);
    if (!byObj) {
      byObj = new WeakMap();
      this.#proxyCache.set(state, byObj);
    }
    let byName = byObj.get(rawTarget);
    if (!byName) {
      byName = new Map();
      byObj.set(rawTarget, byName);
    }
    const cached = byName.get(serviceName);
    if (cached !== undefined) return cached;

    const guard = this;
    const isCallable = typeof rawTarget === 'function';
    const shadowTarget = isCallable ? () => {} : Object.create(null);
    if (isCallable) {
      try {
        delete shadowTarget.length;
        delete shadowTarget.name;
      } catch {}
    }

    let wrapped;
    const invokeCallable = (thisArg, args) => {
      const boundThis = thisArg === wrapped ? rawTarget : thisArg;
      if (!methodRules) {
        guard.#assertUnitActive(state, `service.invoke:${serviceName}#$`);
        return assertSafeServiceReturn(Reflect.apply(rawTarget, boundThis, args), serviceName, '$');
      }
      const callRule = resolveMethodRule(methodRules, '$');
      return guard.#invokeGuardedMethod(
        state,
        serviceName,
        '$',
        callRule,
        () => assertSafeServiceReturn(Reflect.apply(rawTarget, boundThis, args), serviceName, '$'),
      );
    };

    const readGuardedProp = prop => {
      if (prop === GUARD_WRAPPED) return true;
      if (typeof prop === 'symbol') {
        if (BLOCKED_SYMBOLS.has(prop)) return undefined;
        guard.#assertUnitActive(state, `service.get:${serviceName}#${String(prop)}`);
        const symVal = Reflect.get(rawTarget, prop, rawTarget);
        return isCordisContextOrFiber(symVal) ? undefined : symVal;
      }
      if (prop === 'constructor' || prop === '__proto__' || prop === 'prototype') {
        return undefined;
      }
      guard.#assertUnitActive(state, `service.get:${serviceName}#${String(prop)}`);
      if (isCallable) {
        if (prop === 'call') return (thisArg, ...args) => invokeCallable(thisArg, args);
        if (prop === 'apply') return (thisArg, args = []) => invokeCallable(thisArg, args);
        if (prop === 'bind') return (thisArg, ...boundArgs) => (...moreArgs) => invokeCallable(thisArg, [...boundArgs, ...moreArgs]);
      }
      const raw = Reflect.get(rawTarget, prop, rawTarget);
      if (isCordisContextOrFiber(raw)) return undefined;
      if (typeof raw !== 'function') return raw;
      if (!methodRules) {
        return function activeCheckedMethod(...args) {
          guard.#assertUnitActive(state, `service.invoke:${serviceName}#${String(prop)}`);
          return assertSafeServiceReturn(Reflect.apply(raw, rawTarget, args), serviceName, String(prop));
        };
      }
      const rule = resolveMethodRule(methodRules, prop);
      return function guardedMethod(...args) {
        return guard.#invokeGuardedMethod(
          state,
          serviceName,
          prop,
          rule,
          () => assertSafeServiceReturn(Reflect.apply(raw, rawTarget, args), serviceName, String(prop)),
        );
      };
    };

    const traps = {
      get: (_shadow, prop) => readGuardedProp(prop),
      has: (_shadow, prop) => {
        if (typeof prop === 'symbol' && BLOCKED_SYMBOLS.has(prop)) return false;
        if (prop === 'constructor' || prop === '__proto__' || prop === 'prototype') return false;
        guard.#assertUnitActive(state, `service.has:${serviceName}`);
        return Reflect.has(rawTarget, prop);
      },
      ownKeys: () => {
        guard.#assertUnitActive(state, `service.ownKeys:${serviceName}`);
        return Reflect.ownKeys(rawTarget).filter(k => {
          if (typeof k === 'symbol' && BLOCKED_SYMBOLS.has(k)) return false;
          if (k === 'constructor' || k === '__proto__' || k === 'prototype') return false;
          return true;
        });
      },
      getOwnPropertyDescriptor: (_shadow, prop) => {
        if (typeof prop === 'symbol' && BLOCKED_SYMBOLS.has(prop)) return undefined;
        if (prop === 'constructor' || prop === '__proto__' || prop === 'prototype') return undefined;
        guard.#assertUnitActive(state, `service.desc:${serviceName}`);
        if (!Object.prototype.hasOwnProperty.call(rawTarget, prop)) return undefined;
        return {
          configurable: true,
          enumerable: true,
          writable: false,
          value: readGuardedProp(prop),
        };
      },
      getPrototypeOf: () => null,
      set: () => false,
      deleteProperty: () => false,
      defineProperty: () => false,
      setPrototypeOf: () => false,
    };
    if (isCallable) {
      traps.apply = (_shadow, thisArg, args) => invokeCallable(thisArg, args);
      traps.construct = () => {
        throw new SlotError(`Unit ${state.unitId} cannot construct guarded service ${serviceName}.`);
      };
    }

    wrapped = new Proxy(shadowTarget, traps);
    this.#wrappedProxies.add(wrapped);
    byName.set(serviceName, wrapped);
    return wrapped;
  }

  #invokeGuardedMethod(state, serviceName, methodName, rule, exec) {
    if (!state.active) {
      const err = new SlotError(`Unit ${state.unitId} was unmounted and can no longer invoke ${serviceName}#${methodName}.`);
      if (rule?.async === true) return Promise.reject(err);
      throw err;
    }
    if (!rule) {
      // Fail closed on methods unlisted in methodRules (unless wildcard '*' was explicitly configured).
      throw new SlotError(`Unit ${state.unitId} is denied invoking undeclared method ${serviceName}#${methodName}.`);
    }
    const kind = serviceInvokeActionKind(rule.mode || 'read');
    const req = {
      kind,
      target: serviceName,
      method: methodName,
      mode: rule.mode || 'read',
      async: rule.async === true,
    };
    const node = formatActionNode(req);
    // Always evaluate PolicyTree first so approvedActions can NEVER override closed or explicit deny rules.
    const effect = evaluatePermissionTree(state.grant.tree, state.subject, req, { defaultEffect: 'deny' }).effect;

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

    if (state.approvedActions.has(node)) return exec();

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
          .then(
            decision => {
              const granted = decision === true;
              if (!state.active) {
                return { granted: false, unmounted: true };
              }
              if (granted) {
                state.approvedActions.add(node);
                state.onAudit(AUDIT_CODES.AUDIT_ESCALATION_APPROVED, serviceName, node);
                if ((rule.mode || 'read') !== 'read') {
                  state.onAudit(AUDIT_CODES.AUDIT_TRUSTED_WRITE_ON, serviceName, node);
                }
              } else {
                state.onAudit(AUDIT_CODES.AUDIT_ESCALATION_DENIED, serviceName, node);
              }
              return { granted, unmounted: false };
            },
            () => {
              if (state.active) {
                state.onAudit(AUDIT_CODES.AUDIT_ESCALATION_DENIED, serviceName, node);
              }
              return { granted: false, unmounted: !state.active };
            },
          )
          .finally(() => {
            state.inflightEscalations.delete(node);
          });
        state.inflightEscalations.set(node, inflight);
      }

      const outcome = await inflight;
      if (!state.active || outcome.unmounted) {
        throw new SlotError(`Unit ${state.unitId} was unmounted during permission escalation.`);
      }
      if (!outcome.granted) {
        throw new SlotError(`User denied unit ${state.unitId} invoking ${serviceName}#${methodName}.`);
      }
      return exec();
    })();
  }
}
