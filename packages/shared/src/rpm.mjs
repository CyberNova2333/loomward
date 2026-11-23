// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).

export const RPM_FORMAT_VERSION = 1;
const SHA256_TAGGED_RE = /^sha256:[a-f0-9]{64}$/;
const ROOT_ID_RE = /^[a-z][a-z0-9-]{1,47}$/;
const TARGETS = new Set(['runtime', 'dev']);
const RPM_KEYS = new Set(['format', 'target', 'rootPlugins', 'manifestHash']);
const ROOT_ENTRY_KEYS = new Set(['id', 'version', 'entryHash', 'provides']);

export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('Non-finite numbers are not allowed in canonical JSON.');
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(item => canonicalJson(item)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value).filter(k => value[k] !== undefined).sort();
    return `{${keys.map(k => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  }
  throw new TypeError(`Unsupported value type in canonical JSON: ${typeof value}`);
}

export async function sha256Tagged(input) {
  const bytes = typeof input === 'string'
    ? new TextEncoder().encode(input)
    : input instanceof Uint8Array
      ? input
      : new Uint8Array(input);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  const hex = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
  return `sha256:${hex}`;
}

export function hashedRpmFields(rpm) {
  return {
    format: rpm.format,
    target: rpm.target,
    rootPlugins: rpm.rootPlugins,
  };
}

export async function computeManifestHash(rpmBody) {
  return sha256Tagged(canonicalJson(hashedRpmFields(rpmBody)));
}

export function isRpmShape(rpm) {
  if (!rpm || typeof rpm !== 'object' || Array.isArray(rpm)) return false;
  const keys = Object.keys(rpm);
  if (keys.length !== RPM_KEYS.size || keys.some(k => !RPM_KEYS.has(k))) return false;
  if (rpm.format !== RPM_FORMAT_VERSION) return false;
  if (typeof rpm.target !== 'string' || !TARGETS.has(rpm.target)) return false;
  if (typeof rpm.manifestHash !== 'string' || !SHA256_TAGGED_RE.test(rpm.manifestHash)) return false;
  if (!Array.isArray(rpm.rootPlugins) || rpm.rootPlugins.length === 0) return false;

  const seen = new Set();
  for (const entry of rpm.rootPlugins) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return false;
    const entryKeys = Object.keys(entry);
    if (entryKeys.length !== ROOT_ENTRY_KEYS.size || entryKeys.some(k => !ROOT_ENTRY_KEYS.has(k))) return false;
    if (typeof entry.id !== 'string' || !ROOT_ID_RE.test(entry.id) || seen.has(entry.id)) return false;
    seen.add(entry.id);
    if (typeof entry.version !== 'string' || !entry.version.length) return false;
    if (typeof entry.entryHash !== 'string' || !SHA256_TAGGED_RE.test(entry.entryHash)) return false;
    if (!Array.isArray(entry.provides) || entry.provides.some(p => typeof p !== 'string' || !p.length)) return false;
  }
  return true;
}

export async function createFrozenRpm({ target = 'runtime', rootPlugins }) {
  const sorted = [...rootPlugins].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const body = { format: RPM_FORMAT_VERSION, target, rootPlugins: sorted };
  const manifestHash = await computeManifestHash(body);
  const rpm = { ...body, manifestHash };
  if (!isRpmShape(rpm)) throw new Error('Generated RPM failed shape validation.');
  return Object.freeze(rpm);
}
