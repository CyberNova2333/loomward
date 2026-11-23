// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).

export const VAULT_SLOT = 'vault:backend@1';
export const CLOSED_SLOTS = Object.freeze([VAULT_SLOT]);
export const ROOT_ONLY_SERVICES = Object.freeze([
  VAULT_SLOT,
  'sandbox:docker',
  'host:dispatch',
  'host:platform',
  'host:vault',
  'host:approval-ledger',
  'console:trust-origin',
  'console:loopback',
]);

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
const FORBIDDEN_AUDIT_KEY_RE =
  /(token|secret|password|passphrase|api[_-]?key|private[_-]?key|authorization|cookie|credential|stdout|stderr|content|rawbody|prompt|payload|arguments)/i;
const PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const ACTION_KIND_RE = /^[a-z][a-z0-9._-]{0,63}$/;
const ACTION_TARGET_RE = /^[a-zA-Z0-9._:@/-]{1,128}$/;
const ACTION_METHOD_RE = /^(?:\*|[A-Za-z0-9_$.-]{1,64})$/;
const MAX_AUDIT_KEYS = 32;
const MAX_AUDIT_STRING = 256;
const MAX_AUDIT_ARRAY = 16;

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
  if (!ACTION_KIND_RE.test(req.kind)) {
    throw new TypeError(`Invalid permission action kind: ${req.kind}`);
  }
  if (!ACTION_TARGET_RE.test(req.target)) {
    throw new TypeError(`Invalid permission action target: ${req.target}`);
  }
  if (req.method !== undefined && req.method !== null && req.method !== '') {
    if (typeof req.method !== 'string' || !ACTION_METHOD_RE.test(req.method)) {
      throw new TypeError(`Invalid permission action method: ${String(req.method)}`);
    }
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

function clampAuditScalar(value) {
  if (typeof value === 'string') {
    const cleaned = value.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/g, '');
    return cleaned.length > MAX_AUDIT_STRING ? `${cleaned.slice(0, MAX_AUDIT_STRING - 1)}…` : cleaned;
  }
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : undefined;
  }
  if (typeof value === 'boolean' || value === null) return value;
  return undefined;
}

export function sanitizeAuditMetadata(entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    return {};
  }
  const clean = {};
  let count = 0;
  for (const [key, value] of Object.entries(entry)) {
    if (count >= MAX_AUDIT_KEYS) break;
    if (PROTO_KEYS.has(key)) continue;
    const lower = key.toLowerCase();
    if (FORBIDDEN_AUDIT_KEY_SET.has(lower) || FORBIDDEN_AUDIT_KEY_RE.test(key)) continue;
    if (value === undefined) continue;
    const scalar = clampAuditScalar(value);
    if (scalar !== undefined) {
      clean[key] = scalar;
      count += 1;
      continue;
    }
    if (Array.isArray(value)) {
      const sanitizedArr = [];
      for (const item of value.slice(0, MAX_AUDIT_ARRAY)) {
        const s = clampAuditScalar(item);
        if (s !== undefined && s !== null) sanitizedArr.push(s);
      }
      if (sanitizedArr.length === value.slice(0, MAX_AUDIT_ARRAY).length) {
        clean[key] = sanitizedArr;
        count += 1;
      }
    }
  }
  return clean;
}
