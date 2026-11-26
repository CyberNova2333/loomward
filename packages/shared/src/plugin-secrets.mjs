// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Zero-dependency namespaced extension secret contract constants and validators.

export const PLUGIN_SECRETS_SLOT = 'plugin:secrets@1';
export const PLUGIN_SECRETS_ADMIN_SERVICE = 'host:plugin-secrets-admin';
export const PLUGIN_SECRET_BINDER = Symbol.for('loomward.plugin.secrets.binder');

export const PLUGIN_UNIT_ID_RE = /^[a-z][a-z0-9-]{1,47}$/;
export const SECRET_KEY_RE = /^[A-Z][A-Z0-9_]{1,63}$/;
export const MAX_PLUGIN_SECRET_KEYS = 32;
export const MAX_PLUGIN_SECRET_VALUE_BYTES = 16 * 1024;

export function assertValidPluginNamespace(unitId) {
  if (typeof unitId !== 'string' || !PLUGIN_UNIT_ID_RE.test(unitId)) {
    throw new TypeError(`Invalid extension secret namespace id: ${String(unitId)}`);
  }
  return unitId;
}

export function assertValidPluginSecretKey(key) {
  if (typeof key !== 'string' || !SECRET_KEY_RE.test(key)) {
    throw new TypeError(`Invalid extension secret key (must match /^[A-Z][A-Z0-9_]{1,63}$/): ${String(key)}`);
  }
  return key;
}

export function assertValidPluginSecretValue(value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError('Plugin secret value must be a non-empty string.');
  }
  if (!value.isWellFormed() || value.includes('\0')) {
    throw new TypeError('Plugin secret value must be well-formed Unicode without null bytes.');
  }
  const encoder = new TextEncoder();
  if (encoder.encode(value).byteLength > MAX_PLUGIN_SECRET_VALUE_BYTES) {
    throw new RangeError(`Plugin secret value exceeds ${MAX_PLUGIN_SECRET_VALUE_BYTES} byte limit.`);
  }
  return value;
}
