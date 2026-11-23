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
  #userPick;

  constructor(decl, authorizer = () => undefined) {
    if (!decl?.name) throw new SlotError('ImplSlot requires a declaration with a name.');
    this.#decl = Object.freeze({ ...decl });
    this.#authorizer = authorizer;
  }

  get decl() {
    return own(this).#decl;
  }

  get name() {
    return own(this).#decl.name;
  }

  registerBuiltin(name, impl) {
    if (this.ctx) throw new SlotError('Builtin implementations cannot be registered via tracked proxy.');
    const self = own(this);
    if (self.#entries.has(name)) throw new SlotError(`ImplSlot ${self.#decl.name} already has ${name}.`);
    self.#entries.set(name, { impl, builtin: true, seq: seqCounter++ });
  }

  register(name, impl) {
    const caller = this.ctx;
    const self = own(this);
    if (!caller || typeof caller.effect !== 'function') {
      throw new SlotError('ImplSlot.register requires a tracked Cordis caller context.');
    }
    const req = { kind: 'register', slot: self.#decl.name, name };
    self.#authorizer()?.authorize(caller, req);
    if (self.#entries.has(name)) {
      throw new SlotError(`ImplSlot ${self.#decl.name} already has ${name}.`);
    }
    const entry = { impl, builtin: false, seq: seqCounter++ };
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

  select(name) {
    const caller = this.ctx;
    const self = own(this);
    if (caller) self.#authorizer()?.authorize(caller, { kind: 'select', slot: self.#decl.name });
    if (name !== undefined && !self.#entries.has(name)) {
      throw new SlotError(`Unknown implementation "${name}" in slot ${self.#decl.name}.`);
    }
    self.#userPick = name;
  }

  current() {
    const self = own(this);
    if (self.#userPick && self.#entries.has(self.#userPick)) {
      return { name: self.#userPick, impl: self.#entries.get(self.#userPick).impl };
    }
    const first = self.#entries.entries().next();
    return first.done ? undefined : { name: first.value[0], impl: first.value[1].impl };
  }

  entries() {
    const self = own(this);
    return [...self.#entries.entries()].map(([name, entry]) => ({
      name,
      impl: entry.impl,
      builtin: entry.builtin,
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

  hook(phase, handler) {
    if (!['before', 'after', 'replace'].includes(phase)) {
      throw new SlotError(`Invalid mechanism phase: ${String(phase)}`);
    }
    if (typeof handler !== 'function') throw new SlotError('Hook handler must be a function.');
    const caller = this.ctx;
    const self = own(this);
    if (phase === 'replace' && self.#decl.allowReplace === false) {
      throw new SlotError(`MechanismSlot ${self.#decl.name} forbids replace hooks to protect core invariants.`);
    }
    if (!caller || typeof caller.effect !== 'function') {
      throw new SlotError('MechanismSlot.hook requires a tracked Cordis caller context.');
    }
    const req = { kind: 'hook', slot: self.#decl.name, phase };
    self.#authorizer()?.authorize(caller, req);
    const entry = { handler, seq: seqCounter++ };
    const dispose = caller.effect(() => {
      self.#hooks[phase].push(entry);
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
    let currentInput = input;
    let forcedApproval = Boolean(input && typeof input === 'object' && input.forceApproval === true);
    for (const item of [...self.#hooks.before]) {
      const next = await item.handler(currentInput);
      if (next !== undefined) {
        if (next && typeof next === 'object') {
          if (next.forceApproval === true) forcedApproval = true;
          currentInput = forcedApproval && next.forceApproval !== true
            ? { ...next, forceApproval: true }
            : next;
          // Monotonic deny latch: once any before-hook blocks, later hooks cannot inspect or un-block it.
          if (currentInput.blocked === true) break;
        } else {
          currentInput = next;
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
      if (next !== undefined) output = next;
    }
    return output;
  }
}
