// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).

const TRACKER = Symbol.for('cordis.tracker');
const ORIGINAL = Symbol.for('cordis.original');

function own(target) {
  return target?.[ORIGINAL] ?? target;
}

export class SlotError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SlotError';
  }
}

let seqCounter = 0;

export class ImplSlot {
  [TRACKER] = { property: 'ctx' };
  #entries = new Map();
  #decl;
  #authorizer;
  #capability;
  #userPick;

  constructor(decl, authorizer = () => undefined, { capability = null } = {}) {
    if (!decl?.name) throw new SlotError('ImplSlot requires a declaration with a name.');
    this.#decl = Object.freeze({ ...decl });
    this.#authorizer = authorizer;
    this.#capability = capability;
  }

  get decl() {
    return own(this).#decl;
  }

  get name() {
    return own(this).#decl.name;
  }

  registerBuiltin(name, impl, token) {
    const self = own(this);
    if (this.ctx) throw new SlotError('Builtin implementations cannot be registered via tracked proxy.');
    if (self.#capability !== null && token !== self.#capability) {
      throw new SlotError(`Builtin registration on ${self.#decl.name} requires kernel capability token.`);
    }
    if (self.#decl.cardinality === 'single' && self.#entries.size > 0) {
      throw new SlotError(`ImplSlot ${self.#decl.name} has cardinality="single" and already has an implementation.`);
    }
    if (self.#entries.has(name)) throw new SlotError(`ImplSlot ${self.#decl.name} already has ${name}.`);
    self.#entries.set(name, { impl, builtin: true, rootOwned: true, seq: seqCounter++ });
  }

  register(name, impl) {
    const caller = this.ctx;
    const self = own(this);
    if (!caller || typeof caller.effect !== 'function') {
      throw new SlotError('ImplSlot.register requires a tracked Cordis caller context.');
    }
    if (self.#decl.cardinality === 'single' && self.#entries.size > 0) {
      throw new SlotError(`ImplSlot ${self.#decl.name} has cardinality="single" and already has an implementation.`);
    }
    if (self.#entries.has(name)) {
      throw new SlotError(`ImplSlot ${self.#decl.name} already has ${name}.`);
    }
    const req = { kind: 'register', slot: self.#decl.name, name };
    const auth = self.#authorizer();
    auth?.authorize(caller, req);
    const rootOwned = Boolean(auth?.isRootCaller?.(caller));
    const entry = { impl, builtin: false, rootOwned, seq: seqCounter++ };
    const dispose = caller.effect(() => {
      self.#entries.set(name, entry);
      return () => {
        if (self.#entries.get(name) !== entry) return;
        self.#entries.delete(name);
        if (self.#userPick === name) self.#userPick = undefined;
        self.#authorizer()?.released?.(caller, req);
      };
    }, `slot:${self.#decl.name}#${name}`);
    return () => {
      if (typeof dispose === 'function') dispose();
    };
  }

  select(name, token) {
    const caller = this.ctx;
    const self = own(this);
    const hasKernelCap = self.#capability !== null && token === self.#capability;
    if (!hasKernelCap) {
      const auth = self.#authorizer();
      if (auth) {
        if (!caller) throw new SlotError(`ImplSlot.select on ${self.#decl.name} requires an authorized caller.`);
        auth.authorize(caller, { kind: 'select', slot: self.#decl.name });
      }
    }
    if (name !== undefined && !self.#entries.has(name)) {
      throw new SlotError(`Unknown implementation "${name}" in slot ${self.#decl.name}.`);
    }
    self.#userPick = name;
  }

  #assertReadAllowed(caller) {
    if (!caller) return;
    this.#authorizer()?.authorize(caller, { kind: 'read', slot: this.#decl.name });
  }

  current() {
    const self = own(this);
    self.#assertReadAllowed(this.ctx);
    if (self.#userPick && self.#entries.has(self.#userPick)) {
      return { name: self.#userPick, impl: self.#entries.get(self.#userPick).impl };
    }
    const first = self.#entries.entries().next();
    return first.done ? undefined : { name: first.value[0], impl: first.value[1].impl };
  }

  entries() {
    const self = own(this);
    self.#assertReadAllowed(this.ctx);
    return [...self.#entries.entries()].map(([name, entry]) => ({
      name,
      impl: entry.impl,
      builtin: entry.builtin,
      rootOwned: entry.rootOwned,
    }));
  }

  names() {
    return [...own(this).#entries.keys()];
  }

  has(name) {
    return own(this).#entries.has(name);
  }
}

export class MechanismSlot {
  [TRACKER] = { property: 'ctx' };
  #hooks = { before: [], after: [], replace: [] };
  #decl;
  #authorizer;

  constructor(decl, authorizer = () => undefined) {
    if (!decl?.name) throw new SlotError('MechanismSlot requires a declaration with a name.');
    this.#decl = Object.freeze({ ...decl });
    this.#authorizer = authorizer;
  }

  get decl() {
    return own(this).#decl;
  }

  get name() {
    return own(this).#decl.name;
  }

  hasReplace() {
    return own(this).#hooks.replace.length > 0;
  }

  hook(phase, handler, { order = 100 } = {}) {
    if (!['before', 'after', 'replace'].includes(phase)) {
      throw new SlotError(`Invalid mechanism phase: ${String(phase)}`);
    }
    if (typeof handler !== 'function') throw new SlotError('Hook handler must be a function.');
    const caller = this.ctx;
    const self = own(this);
    if (phase === 'replace' && self.#decl.allowReplace === false) {
      throw new SlotError(`MechanismSlot ${self.#decl.name} forbids replace hooks to protect core invariants.`);
    }
    if (phase === 'replace' && self.#hooks.replace.length > 0) {
      throw new SlotError(`MechanismSlot ${self.#decl.name} already has a replace hook.`);
    }
    if (!caller || typeof caller.effect !== 'function') {
      throw new SlotError('MechanismSlot.hook requires a tracked Cordis caller context.');
    }
    const normalizedOrder = Number.isFinite(order) ? Math.trunc(order) : 100;
    const req = { kind: 'hook', slot: self.#decl.name, phase };
    self.#authorizer()?.authorize(caller, req);
    const entry = { handler, order: normalizedOrder, seq: seqCounter++ };
    const dispose = caller.effect(() => {
      self.#hooks[phase].push(entry);
      self.#hooks[phase].sort((a, b) => (a.order - b.order) || (a.seq - b.seq));
      return () => {
        const list = self.#hooks[phase];
        const idx = list.indexOf(entry);
        if (idx >= 0) list.splice(idx, 1);
        self.#authorizer()?.released?.(caller, req);
      };
    }, `mechanism:${self.#decl.name}@${phase}`);
    return () => {
      if (typeof dispose === 'function') dispose();
    };
  }

  async run(input, baseAction) {
    const self = own(this);
    const isObjectInput = Boolean(input && typeof input === 'object' && !Array.isArray(input));
    let currentInput = isObjectInput ? { ...input } : input;
    let forcedApproval = Boolean(isObjectInput && currentInput.forceApproval === true);
    let alreadyBlocked = Boolean(isObjectInput && currentInput.blocked === true);

    if (!alreadyBlocked) {
      for (const item of [...self.#hooks.before]) {
        const next = await item.handler(currentInput);
        if (next === undefined) continue;
        if (!next || typeof next !== 'object' || Array.isArray(next)) {
          // Non-object return cannot erase monotonic safety latches or structured invocation input.
          if (isObjectInput && forcedApproval) {
            currentInput = { ...currentInput, forceApproval: true };
          }
          continue;
        }
        // Read getter-sensitive security flags ONCE into plain booleans to prevent getter TOCTOU.
        const nextBlocked = next.blocked === true;
        const nextForceApproval = next.forceApproval === true;
        if (nextForceApproval) forcedApproval = true;
        const materialized = {
          ...next,
          ...(forcedApproval ? { forceApproval: true } : {}),
          ...(nextBlocked ? { blocked: true } : {}),
        };
        currentInput = materialized;
        // Monotonic deny latch: once any before-hook blocks, later hooks cannot inspect or un-block it.
        if (nextBlocked) {
          alreadyBlocked = true;
          break;
        }
      }
    }

    let output;
    if (self.#decl.allowReplace !== false && self.#hooks.replace.length > 0) {
      const replacer = self.#hooks.replace[self.#hooks.replace.length - 1];
      output = await replacer.handler(currentInput, baseAction);
    } else {
      output = await baseAction(currentInput);
    }

    for (const item of [...self.#hooks.after]) {
      const next = await item.handler(output, currentInput);
      if (next === undefined) continue;
      if (next && typeof next === 'object' && !Array.isArray(next)) {
        const nextBlocked = next.blocked === true;
        if (nextBlocked) {
          output = {
            ...next,
            blocked: true,
          };
          // Monotonic output deny latch: later after-hooks cannot un-block or observe blocked output.
          break;
        }
      }
      output = next;
    }
    return output;
  }
}
