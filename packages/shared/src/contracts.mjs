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
  const seen = new Set();
  for (const item of list) {
    if (typeof item !== 'string' || !pattern.test(item)) {
      throw new Error(`Invalid entry in ${label}: ${String(item)}`);
    }
    if (seen.has(item)) throw new Error(`Duplicate entry in ${label}: ${item}`);
    seen.add(item);
  }
}

export function validateContractDecl(decl) {
  if (!decl || typeof decl !== 'object' || Array.isArray(decl)) {
    throw new Error('Contract declaration must be an object.');
  }
  if (decl.schemaVersion !== CONTRACT_SCHEMA_VERSION) {
    throw new Error(`Unsupported contract schemaVersion: ${String(decl.schemaVersion)}`);
  }
  if (typeof decl.id !== 'string' || !ID_RE.test(decl.id)) {
    throw new Error(`Invalid contract id: ${String(decl.id)}`);
  }
  if (!CONTRACT_KINDS.includes(decl.kind)) {
    throw new Error(`Invalid contract kind for ${decl.id}: ${String(decl.kind)}`);
  }
  if (typeof decl.version !== 'string' || !SEMVER_RE.test(decl.version)) {
    throw new Error(`Invalid contract version for ${decl.id}: ${String(decl.version)}`);
  }
  if (!EXECUTION_BOUNDARIES.includes(decl.executionBoundary)) {
    throw new Error(`Invalid executionBoundary for ${decl.id}: ${String(decl.executionBoundary)}`);
  }
  if (decl.kind === 'root-plugin' && decl.executionBoundary !== 'in-process-root') {
    throw new Error(`Root plugin ${decl.id} must declare executionBoundary="in-process-root".`);
  }
  if (decl.kind === 'extension-plugin' && decl.executionBoundary === 'in-process-root') {
    throw new Error(`Extension plugin ${decl.id} cannot declare executionBoundary="in-process-root".`);
  }

  assertStringArray(decl.provides ?? [], `${decl.id}.provides`, SERVICE_OR_SLOT_RE);
  assertStringArray(decl.consumes ?? [], `${decl.id}.consumes`, SERVICE_OR_SLOT_RE);

  const implSlots = decl.implSlots ?? [];
  if (!Array.isArray(implSlots)) throw new Error(`${decl.id}.implSlots must be an array.`);
  const seenSlots = new Set();
  for (const slot of implSlots) {
    if (!slot || typeof slot !== 'object' || Array.isArray(slot)) {
      throw new Error(`Invalid implSlot entry in ${decl.id}.`);
    }
    if (typeof slot.name !== 'string' || !SERVICE_OR_SLOT_RE.test(slot.name)) {
      throw new Error(`Invalid implSlot name in ${decl.id}: ${String(slot.name)}`);
    }
    if (!SLOT_CARDINALITIES.includes(slot.cardinality)) {
      throw new Error(`Invalid implSlot cardinality in ${decl.id}: ${String(slot.cardinality)}`);
    }
    if (!SLOT_POLICIES.includes(slot.policy)) {
      throw new Error(`Invalid implSlot policy in ${decl.id}: ${String(slot.policy)}`);
    }
    if (seenSlots.has(slot.name)) throw new Error(`Duplicate slot in ${decl.id}: ${slot.name}`);
    seenSlots.add(slot.name);
  }

  const mechanismSlots = decl.mechanismSlots ?? [];
  if (!Array.isArray(mechanismSlots)) throw new Error(`${decl.id}.mechanismSlots must be an array.`);
  for (const slot of mechanismSlots) {
    if (!slot || typeof slot !== 'object' || Array.isArray(slot)) {
      throw new Error(`Invalid mechanismSlot entry in ${decl.id}.`);
    }
    if (typeof slot.name !== 'string' || !SERVICE_OR_SLOT_RE.test(slot.name)) {
      throw new Error(`Invalid mechanismSlot name in ${decl.id}: ${String(slot.name)}`);
    }
    if (!SLOT_POLICIES.includes(slot.policy)) {
      throw new Error(`Invalid mechanismSlot policy in ${decl.id}: ${String(slot.policy)}`);
    }
    if (seenSlots.has(slot.name)) throw new Error(`Duplicate slot in ${decl.id}: ${slot.name}`);
    seenSlots.add(slot.name);
  }

  return Object.freeze({
    schemaVersion: decl.schemaVersion,
    id: decl.id,
    kind: decl.kind,
    version: decl.version,
    executionBoundary: decl.executionBoundary,
    provides: Object.freeze([...(decl.provides ?? [])]),
    consumes: Object.freeze([...(decl.consumes ?? [])]),
    implSlots: Object.freeze(implSlots.map(s => Object.freeze({ ...s }))),
    mechanismSlots: Object.freeze(mechanismSlots.map(s => Object.freeze({ ...s }))),
    ...(typeof decl.archiveSource === 'string' ? { archiveSource: decl.archiveSource } : {}),
  });
}
