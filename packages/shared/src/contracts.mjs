// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).

export const CONTRACT_SCHEMA_VERSION = 1;
export const CONTRACT_KINDS = Object.freeze(['root-plugin', 'extension-plugin']);
export const EXECUTION_BOUNDARIES = Object.freeze([
  'in-process-root',
  'in-process-signed',
  'out-of-process',
]);
export const SLOT_POLICIES = Object.freeze(['public', 'trusted', 'closed']);
export const SLOT_CARDINALITIES = Object.freeze(['single', 'multi']);

const ID_RE = /^[a-z][a-z0-9-]{1,47}$/;
const SERVICE_OR_SLOT_RE = /^[a-z][a-z0-9-]*(?::[a-z0-9-]+)+(?:@\d+)?$/;
const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

function assertStringArray(list, label, pattern) {
  if (!Array.isArray(list)) throw new Error(`${label} must be an array.`);
  const normalized = [];
  const seen = new Set();
  for (const item of list) {
    if (typeof item !== 'string' || !pattern.test(item)) {
      throw new Error(`Invalid entry in ${label}: ${String(item)}`);
    }
    if (seen.has(item)) throw new Error(`Duplicate entry in ${label}: ${item}`);
    seen.add(item);
    normalized.push(item);
  }
  return normalized;
}

export function validateContractDecl(decl) {
  if (!decl || typeof decl !== 'object' || Array.isArray(decl)) {
    throw new Error('Contract declaration must be an object.');
  }
  const schemaVersion = decl.schemaVersion;
  const id = decl.id;
  const kind = decl.kind;
  const version = decl.version;
  const executionBoundary = decl.executionBoundary;
  const archiveSource = decl.archiveSource;

  if (schemaVersion !== CONTRACT_SCHEMA_VERSION) {
    throw new Error(`Unsupported contract schemaVersion: ${String(schemaVersion)}`);
  }
  if (typeof id !== 'string' || !ID_RE.test(id)) {
    throw new Error(`Invalid contract id: ${String(id)}`);
  }
  if (!CONTRACT_KINDS.includes(kind)) {
    throw new Error(`Invalid contract kind for ${id}: ${String(kind)}`);
  }
  if (typeof version !== 'string' || !SEMVER_RE.test(version)) {
    throw new Error(`Invalid contract version for ${id}: ${String(version)}`);
  }
  if (!EXECUTION_BOUNDARIES.includes(executionBoundary)) {
    throw new Error(`Invalid executionBoundary for ${id}: ${String(executionBoundary)}`);
  }
  if (kind === 'root-plugin' && executionBoundary !== 'in-process-root') {
    throw new Error(`Root plugin ${id} must declare executionBoundary="in-process-root".`);
  }
  if (kind === 'extension-plugin' && executionBoundary === 'in-process-root') {
    throw new Error(`Extension plugin ${id} cannot declare executionBoundary="in-process-root".`);
  }

  const provides = assertStringArray(decl.provides ?? [], `${id}.provides`, SERVICE_OR_SLOT_RE);
  const consumes = assertStringArray(decl.consumes ?? [], `${id}.consumes`, SERVICE_OR_SLOT_RE);

  const rawImplSlots = decl.implSlots ?? [];
  if (!Array.isArray(rawImplSlots)) throw new Error(`${id}.implSlots must be an array.`);
  const seenSlots = new Set();
  const implSlots = [];
  for (const rawSlot of rawImplSlots) {
    if (!rawSlot || typeof rawSlot !== 'object' || Array.isArray(rawSlot)) {
      throw new Error(`Invalid implSlot entry in ${id}.`);
    }
    const name = rawSlot.name;
    const cardinality = rawSlot.cardinality;
    const policy = rawSlot.policy;
    if (typeof name !== 'string' || !SERVICE_OR_SLOT_RE.test(name)) {
      throw new Error(`Invalid implSlot name in ${id}: ${String(name)}`);
    }
    if (!SLOT_CARDINALITIES.includes(cardinality)) {
      throw new Error(`Invalid implSlot cardinality in ${id}: ${String(cardinality)}`);
    }
    if (!SLOT_POLICIES.includes(policy)) {
      throw new Error(`Invalid implSlot policy in ${id}: ${String(policy)}`);
    }
    if (seenSlots.has(name)) throw new Error(`Duplicate slot in ${id}: ${name}`);
    seenSlots.add(name);
    implSlots.push(Object.freeze({ name, cardinality, policy }));
  }

  const rawMechanismSlots = decl.mechanismSlots ?? [];
  if (!Array.isArray(rawMechanismSlots)) throw new Error(`${id}.mechanismSlots must be an array.`);
  const mechanismSlots = [];
  for (const rawSlot of rawMechanismSlots) {
    if (!rawSlot || typeof rawSlot !== 'object' || Array.isArray(rawSlot)) {
      throw new Error(`Invalid mechanismSlot entry in ${id}.`);
    }
    const name = rawSlot.name;
    const policy = rawSlot.policy;
    const allowReplace = rawSlot.allowReplace;
    if (typeof name !== 'string' || !SERVICE_OR_SLOT_RE.test(name)) {
      throw new Error(`Invalid mechanismSlot name in ${id}: ${String(name)}`);
    }
    if (!SLOT_POLICIES.includes(policy)) {
      throw new Error(`Invalid mechanismSlot policy in ${id}: ${String(policy)}`);
    }
    if (allowReplace !== undefined && typeof allowReplace !== 'boolean') {
      throw new Error(`Invalid mechanismSlot allowReplace in ${id}: must be boolean.`);
    }
    if (seenSlots.has(name)) throw new Error(`Duplicate slot in ${id}: ${name}`);
    seenSlots.add(name);
    mechanismSlots.push(Object.freeze({
      name,
      policy,
      ...(typeof allowReplace === 'boolean' ? { allowReplace } : {}),
    }));
  }

  const rawRegisters = decl.registers ?? [];
  if (!Array.isArray(rawRegisters)) throw new Error(`${id}.registers must be an array.`);
  const seenRegisters = new Set();
  const registers = [];
  for (const rawReg of rawRegisters) {
    if (!rawReg || typeof rawReg !== 'object' || Array.isArray(rawReg)) {
      throw new Error(`Invalid register entry in ${id}.`);
    }
    const slot = rawReg.slot;
    const name = rawReg.name;
    if (typeof slot !== 'string' || !SERVICE_OR_SLOT_RE.test(slot)) {
      throw new Error(`Invalid register slot in ${id}: ${String(slot)}`);
    }
    if (typeof name !== 'string' || !ID_RE.test(name)) {
      throw new Error(`Invalid register name in ${id}: ${String(name)}`);
    }
    const key = `${slot}#${name}`;
    if (seenRegisters.has(key)) throw new Error(`Duplicate register in ${id}: ${key}`);
    seenRegisters.add(key);
    registers.push(Object.freeze({ slot, name }));
  }

  const rawWrites = decl.writes ?? {};
  if (!rawWrites || typeof rawWrites !== 'object' || Array.isArray(rawWrites)) {
    throw new Error(`${id}.writes must be an object.`);
  }
  const rawHooks = rawWrites.hooks ?? [];
  if (!Array.isArray(rawHooks)) throw new Error(`${id}.writes.hooks must be an array.`);
  const seenHooks = new Set();
  const hooks = [];
  for (const rawHook of rawHooks) {
    if (!rawHook || typeof rawHook !== 'object' || Array.isArray(rawHook)) {
      throw new Error(`Invalid hook write entry in ${id}.`);
    }
    const slot = rawHook.slot;
    const phase = rawHook.phase;
    if (typeof slot !== 'string' || !SERVICE_OR_SLOT_RE.test(slot)) {
      throw new Error(`Invalid hook write slot in ${id}: ${String(slot)}`);
    }
    if (!['before', 'after', 'replace'].includes(phase)) {
      throw new Error(`Invalid hook write phase in ${id}: ${String(phase)}`);
    }
    const key = `${slot}@${phase}`;
    if (seenHooks.has(key)) throw new Error(`Duplicate hook write in ${id}: ${key}`);
    seenHooks.add(key);
    hooks.push(Object.freeze({ slot, phase }));
  }
  const intercepts = assertStringArray(rawWrites.intercepts ?? [], `${id}.writes.intercepts`, SERVICE_OR_SLOT_RE);
  const isolateProvides = assertStringArray(rawWrites.isolateProvides ?? [], `${id}.writes.isolateProvides`, SERVICE_OR_SLOT_RE);

  return Object.freeze({
    schemaVersion,
    id,
    kind,
    version,
    executionBoundary,
    provides: Object.freeze(provides),
    consumes: Object.freeze(consumes),
    implSlots: Object.freeze(implSlots),
    mechanismSlots: Object.freeze(mechanismSlots),
    registers: Object.freeze(registers),
    writes: Object.freeze({
      hooks: Object.freeze(hooks),
      intercepts: Object.freeze(intercepts),
      isolateProvides: Object.freeze(isolateProvides),
    }),
    ...(typeof archiveSource === 'string' ? { archiveSource } : {}),
  });
}
