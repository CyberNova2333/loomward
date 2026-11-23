// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).

export const VAULT_SLOT = 'vault:backend@1';
export const CLOSED_SLOTS = Object.freeze([VAULT_SLOT]);

export const AUDIT_CODES = Object.freeze({
  AUDIT_ROOT_MOUNTED: 'AUDIT_ROOT_MOUNTED',
  AUDIT_UNIT_MOUNTED: 'AUDIT_UNIT_MOUNTED',
  AUDIT_UNIT_UNMOUNTED: 'AUDIT_UNIT_UNMOUNTED',
  AUDIT_TRUSTED_WRITE_ON: 'AUDIT_TRUSTED_WRITE_ON',
  AUDIT_TRUSTED_WRITE_OFF: 'AUDIT_TRUSTED_WRITE_OFF',
  AUDIT_VAULT_ACCESS_DENIED: 'AUDIT_VAULT_ACCESS_DENIED',
  AUDIT_ESCALATION_APPROVED: 'AUDIT_ESCALATION_APPROVED',
  AUDIT_ESCALATION_DENIED: 'AUDIT_ESCALATION_DENIED',
});

export const REJECT_CODES = Object.freeze({
  GUARD_RPM_INVALID_SHAPE: 'GUARD_RPM_INVALID_SHAPE',
  GUARD_RPM_HASH_MISMATCH: 'GUARD_RPM_HASH_MISMATCH',
  GUARD_ROOT_ENTRY_MISMATCH: 'GUARD_ROOT_ENTRY_MISMATCH',
  GUARD_ROOT_HASH_MISMATCH: 'GUARD_ROOT_HASH_MISMATCH',
  GUARD_CONTRACT_MISMATCH: 'GUARD_CONTRACT_MISMATCH',
  GUARD_POLICY_CLOSED: 'GUARD_POLICY_CLOSED',
  GUARD_SLOT_UNDECLARED: 'GUARD_SLOT_UNDECLARED',
  GUARD_SLOT_NAME_TAKEN: 'GUARD_SLOT_NAME_TAKEN',
  GUARD_SLOT_REPLACE_TAKEN: 'GUARD_SLOT_REPLACE_TAKEN',
  GUARD_EXECUTION_BOUNDARY_REQUIRED: 'GUARD_EXECUTION_BOUNDARY_REQUIRED',
  GUARD_TRUSTED_APPROVAL_REQUIRED: 'GUARD_TRUSTED_APPROVAL_REQUIRED',
  GUARD_UNIT_ALREADY_MOUNTED: 'GUARD_UNIT_ALREADY_MOUNTED',
  GUARD_INDETERMINATE: 'GUARD_INDETERMINATE',
});

export const FORBIDDEN_AUDIT_KEYS = Object.freeze([
  'bridgeToken',
  'ownerPassword',
  'ownerPasswordHash',
  'password',
  'secret',
  'token',
  'authorization',
  'cookie',
  'stdout',
  'stderr',
  'content',
  'fileContent',
  'rawBody',
]);

const FORBIDDEN_AUDIT_KEY_SET = new Set(FORBIDDEN_AUDIT_KEYS.map(k => k.toLowerCase()));

export function mechanismActionKind(phase) {
  if (phase === 'before') return 'mechanism.hook.before';
  if (phase === 'after') return 'mechanism.hook.after';
  if (phase === 'replace') return 'mechanism.hook.replace';
  throw new TypeError(`Invalid mechanism phase: ${String(phase)}`);
}

export function serviceInvokeActionKind(mode) {
  if (mode === 'read') return 'service.invoke.read';
  if (mode === 'write') return 'service.invoke.write';
  if (mode === 'admin') return 'service.invoke.admin';
  throw new TypeError(`Invalid service access mode: ${String(mode)}`);
}

export function formatActionNode(req) {
  if (typeof req === 'string') return req;
  if (!req || typeof req !== 'object' || typeof req.kind !== 'string' || typeof req.target !== 'string') {
    throw new TypeError('Permission action request requires string kind and target.');
  }
  if (typeof req.method === 'string' && req.method.length > 0) {
    return `${req.kind}:${req.target}#${req.method}`;
  }
  return `${req.kind}:${req.target}`;
}

export function buildPermissionSubject(
  contract,
  { signed = false, trustLevel = 'personal-trusted', isolated = true } = {},
) {
  if (!contract || typeof contract !== 'object' || typeof contract.id !== 'string') {
    throw new TypeError('buildPermissionSubject requires a validated contract declaration.');
  }
  return Object.freeze({
    unitId: contract.id,
    kind: contract.kind,
    executionBoundary: contract.executionBoundary,
    signed: Boolean(signed),
    trustLevel,
    isolated: Boolean(isolated),
  });
}

export function isSafeUnicodeString(value, { allowNullByte = false } = {}) {
  if (typeof value !== 'string') return false;
  if (!value.isWellFormed()) return false;
  if (!allowNullByte && value.includes('\0')) return false;
  return true;
}

export function sanitizeAuditMetadata(entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    return {};
  }
  const clean = {};
  for (const [key, value] of Object.entries(entry)) {
    if (FORBIDDEN_AUDIT_KEY_SET.has(key.toLowerCase())) continue;
    if (value === undefined) continue;
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean' || value === null) {
      clean[key] = value;
    } else if (Array.isArray(value) && value.every(v => typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean')) {
      clean[key] = [...value];
    }
  }
  return clean;
}
