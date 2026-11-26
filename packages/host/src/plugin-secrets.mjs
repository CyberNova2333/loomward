// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Namespaced extension secret store isolating each extension's API keys outside workspaces and strictly separate from host owner credentials.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  MAX_PLUGIN_SECRET_KEYS,
  PLUGIN_SECRET_BINDER,
  PLUGIN_UNIT_ID_RE,
  assertValidPluginNamespace,
  assertValidPluginSecretKey,
  assertValidPluginSecretValue,
} from '@loomward/shared';
import { assertConfigOutsideWorkspace } from '../../../local/capabilities.mjs';
import { assertPrivateFile, assertPrivateState } from '../../../local/host-safety.mjs';

const MAX_PLUGIN_SECRET_FILE_BYTES = 256 * 1024;
const PLUGIN_SECRETS_DIR = 'plugin-secrets';

function readBoundedPrivateJsonSync(filePath, { requirePrivateState = true } = {}) {
  const dir = path.dirname(filePath);
  if (fs.existsSync(dir)) {
    assertPrivateState(dir);
  }
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0);
  let fd;
  try {
    fd = fs.openSync(filePath, flags);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > MAX_PLUGIN_SECRET_FILE_BYTES) {
      throw new Error('Plugin secrets file must be a regular single-link file within size limit.');
    }
    assertPrivateFile(filePath);
    const raw = fs.readFileSync(fd, 'utf8');
    if (!raw.trim()) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Corrupt plugin secrets file format.');
    }
    return parsed;
  } finally {
    try { fs.closeSync(fd); } catch {}
  }
}

function atomicWritePrivateJsonSync(targetPath, data, { workspaceRoots = [], requirePrivateState = true } = {}) {
  assertConfigOutsideWorkspace(targetPath, workspaceRoots);
  const dir = path.dirname(targetPath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  assertPrivateState(dir);
  if (process.platform !== 'win32') {
    fs.chmodSync(dir, 0o700);
  }
  const tmpPath = path.join(dir, `.tmp-plugin-secret-${crypto.randomUUID()}.json`);
  const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0);
  let fd;
  try {
    fd = fs.openSync(tmpPath, flags, 0o600);
    fs.writeFileSync(fd, JSON.stringify(data, null, 2), 'utf8');
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    if (process.platform !== 'win32') fs.chmodSync(tmpPath, 0o600);
    fs.renameSync(tmpPath, targetPath);
  } catch (error) {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch {}
    }
    try { fs.rmSync(tmpPath, { force: true }); } catch {}
    throw error;
  }
}

export function createPluginSecretsStore({
  stateDir = null,
  workspaceRoots = [],
  requirePrivateState = true,
  onSecretsChanged = () => {},
} = {}) {
  const memoryStore = new Map();
  const scopedCache = new Map();
  const resolvedState = stateDir ? path.resolve(stateDir) : null;
  const secretsRoot = resolvedState ? path.join(resolvedState, PLUGIN_SECRETS_DIR) : null;

  function filePathForUnit(unitId) {
    assertValidPluginNamespace(unitId);
    if (!secretsRoot) return null;
    const p = path.join(secretsRoot, `${unitId}.secrets.json`);
    assertConfigOutsideWorkspace(p, workspaceRoots);
    return p;
  }

  function loadUnitRecord(unitId) {
    assertValidPluginNamespace(unitId);
    const filePath = filePathForUnit(unitId);
    if (!filePath) {
      return memoryStore.get(unitId) ?? { version: 1, unitId, updatedAt: null, secrets: {} };
    }
    const existing = readBoundedPrivateJsonSync(filePath, { requirePrivateState });
    if (!existing) {
      return { version: 1, unitId, updatedAt: null, secrets: {} };
    }
    const safeSecrets = {};
    for (const [k, v] of Object.entries(existing.secrets || {})) {
      try {
        assertValidPluginSecretKey(k);
        assertValidPluginSecretValue(v);
        safeSecrets[k] = v;
      } catch {}
    }
    return {
      version: 1,
      unitId,
      updatedAt: typeof existing.updatedAt === 'string' ? existing.updatedAt : null,
      secrets: safeSecrets,
    };
  }

  function saveUnitRecord(unitId, record) {
    const filePath = filePathForUnit(unitId);
    if (!filePath) {
      memoryStore.set(unitId, record);
      return;
    }
    atomicWritePrivateJsonSync(filePath, record, { workspaceRoots, requirePrivateState });
  }

  function metaForRecord(record) {
    return Object.freeze({
      unitId: record.unitId,
      keys: Object.freeze(Object.keys(record.secrets).sort()),
      updatedAt: record.updatedAt,
    });
  }

  function notifyChanged(unitId) {
    try {
      onSecretsChanged(unitId);
    } catch {}
  }

  const adminView = Object.freeze({
    listUnitsMeta() {
      const units = [];
      if (!secretsRoot) {
        for (const [unitId, rec] of memoryStore.entries()) {
          if (PLUGIN_UNIT_ID_RE.test(unitId)) units.push(metaForRecord(rec));
        }
        return Object.freeze(units.sort((a, b) => a.unitId.localeCompare(b.unitId)));
      }
      if (!fs.existsSync(secretsRoot)) return Object.freeze([]);
      assertPrivateState(secretsRoot);
      for (const entry of fs.readdirSync(secretsRoot, { withFileTypes: true })) {
        if (!entry.isFile() || !entry.name.endsWith('.secrets.json')) continue;
        const unitId = entry.name.slice(0, -'.secrets.json'.length);
        if (!PLUGIN_UNIT_ID_RE.test(unitId)) continue;
        try {
          units.push(metaForRecord(loadUnitRecord(unitId)));
        } catch {}
      }
      return Object.freeze(units.sort((a, b) => a.unitId.localeCompare(b.unitId)));
    },

    getUnitSecretMeta(unitId) {
      return metaForRecord(loadUnitRecord(unitId));
    },

    setSecrets(unitId, entries, { replace = false } = {}) {
      assertValidPluginNamespace(unitId);
      if (!entries || typeof entries !== 'object' || Array.isArray(entries)) {
        throw new TypeError('Secret entries must be a plain key-value object.');
      }
      const rec = loadUnitRecord(unitId);
      const nextSecrets = replace ? {} : { ...rec.secrets };
      for (const [rawKey, rawVal] of Object.entries(entries)) {
        const key = assertValidPluginSecretKey(rawKey);
        if (rawVal === null || rawVal === '') {
          delete nextSecrets[key];
          continue;
        }
        nextSecrets[key] = assertValidPluginSecretValue(rawVal);
      }
      if (Object.keys(nextSecrets).length > MAX_PLUGIN_SECRET_KEYS) {
        throw new RangeError(`Extension unit ${unitId} cannot store more than ${MAX_PLUGIN_SECRET_KEYS} secret keys.`);
      }
      const nextRecord = {
        version: 1,
        unitId,
        updatedAt: new Date().toISOString(),
        secrets: nextSecrets,
      };
      saveUnitRecord(unitId, nextRecord);
      notifyChanged(unitId);
      return metaForRecord(nextRecord);
    },

    deleteSecret(unitId, key) {
      assertValidPluginNamespace(unitId);
      const cleanKey = assertValidPluginSecretKey(key);
      const rec = loadUnitRecord(unitId);
      const nextSecrets = { ...rec.secrets };
      const existed = Object.hasOwn(nextSecrets, cleanKey);
      delete nextSecrets[cleanKey];
      const nextRecord = {
        version: 1,
        unitId,
        updatedAt: new Date().toISOString(),
        secrets: nextSecrets,
      };
      saveUnitRecord(unitId, nextRecord);
      notifyChanged(unitId);
      return Object.freeze({
        deleted: existed,
        meta: metaForRecord(nextRecord),
      });
    },
  });

  function bindUnit(unitId) {
    const cleanUnit = assertValidPluginNamespace(unitId);
    if (scopedCache.has(cleanUnit)) return scopedCache.get(cleanUnit);
    const facade = Object.freeze({
      describeKeys() {
        return metaForRecord(loadUnitRecord(cleanUnit)).keys;
      },
      hasSecret(key) {
        const cleanKey = assertValidPluginSecretKey(key);
        const rec = loadUnitRecord(cleanUnit);
        return Object.hasOwn(rec.secrets, cleanKey);
      },
      getSecret(key) {
        const cleanKey = assertValidPluginSecretKey(key);
        const rec = loadUnitRecord(cleanUnit);
        return Object.hasOwn(rec.secrets, cleanKey) ? rec.secrets[cleanKey] : null;
      },
      buildChildEnvBindings(mapping) {
        if (!mapping || typeof mapping !== 'object' || Array.isArray(mapping)) {
          throw new TypeError('buildChildEnvBindings expects an { ENV_VAR: SECRET_KEY } map.');
        }
        const rec = loadUnitRecord(cleanUnit);
        const env = Object.create(null);
        for (const [envName, secretKey] of Object.entries(mapping)) {
          if (typeof envName !== 'string' || !SECRET_KEY_RE_COMPAT.test(envName)) {
            throw new TypeError(`Invalid target env variable name: ${String(envName)}`);
          }
          const cleanKey = assertValidPluginSecretKey(secretKey);
          if (Object.hasOwn(rec.secrets, cleanKey)) {
            env[envName] = rec.secrets[cleanKey];
          }
        }
        return { ...env };
      },
    });
    scopedCache.set(cleanUnit, facade);
    return facade;
  }

  const binderService = Object.freeze({
    [PLUGIN_SECRET_BINDER]: bindUnit,
  });

  return Object.freeze({
    adminView,
    binderService,
  });
}

const SECRET_KEY_RE_COMPAT = /^[A-Z][A-Z0-9_]{1,63}$/;
