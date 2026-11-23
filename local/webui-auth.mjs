// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { assertPrivateState } from './host-safety.mjs';
import {
  assertConfigOutsideWorkspace,
  loadWorkspaceRootsFromStateConfig,
} from './capabilities.mjs';

export const WEBUI_AUTH_FILE = 'webui-auth.json';
export const SESSION_PERSISTENCE_MODES = new Set(['tab', 'browser']);
const FIDO_HID_USAGE_PREFIX = Buffer.from([0x06, 0xd0, 0xf1]);
const MIN_PASSWORD_LENGTH = 14;
const MAX_PASSWORD_LENGTH = 256;
const MAX_PASSKEYS = 16;

export function webuiAuthFilePath(stateDir) {
  return path.join(path.resolve(stateDir), WEBUI_AUTH_FILE);
}

function assertWritableStateDir(stateDir, requirePrivateState) {
  const resolved = path.resolve(stateDir);
  if (!requirePrivateState) return resolved;
  if (process.platform !== 'win32') return assertPrivateState(resolved);
  const stat = fs.lstatSync(resolved);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error('Private state must be an ordinary non-linked directory.');
  }
  return resolved;
}

function writePrivateAuthJsonSync(targetPath, data) {
  const dir = path.dirname(targetPath);
  const temp = path.join(dir, `.webui-auth-${crypto.randomUUID()}.tmp`);
  const fd = fs.openSync(
    temp,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0),
    0o600,
  );
  try {
    fs.writeFileSync(fd, JSON.stringify(data, null, 2) + '\n', 'utf8');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    if (process.platform !== 'win32') fs.chmodSync(temp, 0o600);
    fs.renameSync(temp, targetPath);
  } catch (error) {
    fs.rmSync(temp, { force: true });
    throw error;
  }
}

let fprintdCache = { expiresAt: 0, supported: false };
let hostPasskeyCache = { key: '', expiresAt: 0, value: null };
const HOST_PASSKEY_CACHE_TTL_MS = 60000;

function safeUsername() {
  try { return os.userInfo().username || ''; } catch { return ''; }
}

export function detectHostPasskeySupport({ platform = process.platform, linuxProbe, bypassCache = false } = {}) {
  const canCache = !bypassCache && typeof linuxProbe !== 'function';
  if (platform !== 'linux' && canCache && hostPasskeyCache.key === platform && hostPasskeyCache.expiresAt > Date.now() && hostPasskeyCache.value) {
    return hostPasskeyCache.value;
  }
  const cacheAndReturn = val => {
    if (canCache && platform !== 'linux') {
      hostPasskeyCache = { key: platform, expiresAt: Date.now() + HOST_PASSKEY_CACHE_TTL_MS, value: val };
    }
    return val;
  };

  if (platform === 'win32') {
    const dll = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'webauthn.dll');
    if (fs.existsSync(dll)) {
      return cacheAndReturn({ supported: true, reason: 'windows-hello' });
    }
    return cacheAndReturn({ supported: false, reason: 'no-windows-webauthn' });
  }

  if (platform === 'darwin') {
    const major = Number(os.release().split('.')[0] || 0);
    if (fs.existsSync('/usr/bin/bioutil') || major >= 21) {
      return cacheAndReturn({ supported: true, reason: 'macos-platform-passkey' });
    }
    return cacheAndReturn({ supported: false, reason: 'unsupported-macos-release' });
  }

  if (platform === 'linux') {
    if (typeof linuxProbe === 'function') return linuxProbe();
    // Always scan hidraw live (sub-ms sysfs read) so newly hot-plugged FIDO2 keys immediately latch.
    try {
      for (const entry of fs.readdirSync('/sys/class/hidraw')) {
        const descPath = path.join('/sys/class/hidraw', entry, 'device', 'report_descriptor');
        try {
          const desc = fs.readFileSync(descPath);
          if (desc.includes(FIDO_HID_USAGE_PREFIX)) {
            return { supported: true, reason: 'linux-fido2-hid' };
          }
        } catch {}
      }
    } catch {}

    if (canCache && fprintdCache.expiresAt > Date.now()) {
      return fprintdCache.supported
        ? { supported: true, reason: 'linux-fprintd' }
        : { supported: false, reason: 'no-host-passkey-authenticator' };
    }

    let hasFprint = false;
    if (fs.existsSync('/usr/bin/fprintd-list')) {
      try {
        const user = safeUsername();
        if (user) {
          const out = execFileSync('/usr/bin/fprintd-list', [user], {
            encoding: 'utf8',
            timeout: 1500,
            stdio: ['ignore', 'pipe', 'pipe'],
          });
          if (out && !/No devices available|has no fingers enrolled/i.test(out) && /Fingerprints for user/i.test(out)) {
            hasFprint = true;
          }
        }
      } catch {}
    }
    if (canCache) fprintdCache = { expiresAt: Date.now() + HOST_PASSKEY_CACHE_TTL_MS, supported: hasFprint };
    return hasFprint
      ? { supported: true, reason: 'linux-fprintd' }
      : { supported: false, reason: 'no-host-passkey-authenticator' };
  }

  return cacheAndReturn({ supported: false, reason: 'unsupported-platform' });
}

export function validateStrongPassword(password, { forbiddenTerms = [] } = {}) {
  if (typeof password !== 'string' || !password.isWellFormed()) {
    return { valid: false, reason: 'Password must be a valid UTF-8 string.' };
  }
  if (/[\x00-\x1f\x7f]/.test(password)) {
    return { valid: false, reason: 'Password must not contain control characters.' };
  }
  if (password.length < MIN_PASSWORD_LENGTH) {
    return { valid: false, reason: `Strong password must be at least ${MIN_PASSWORD_LENGTH} characters.` };
  }
  if (password.length > MAX_PASSWORD_LENGTH) {
    return { valid: false, reason: `Password must not exceed ${MAX_PASSWORD_LENGTH} characters.` };
  }
  if (/^\s|\s$/.test(password)) {
    return { valid: false, reason: 'Password must not start or end with whitespace.' };
  }
  if (!/[A-Z]/.test(password)) {
    return { valid: false, reason: 'Strong password must include at least one uppercase letter (A-Z).' };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, reason: 'Strong password must include at least one lowercase letter (a-z).' };
  }
  if (!/[0-9]/.test(password)) {
    return { valid: false, reason: 'Strong password must include at least one digit (0-9).' };
  }
  if (!/[^A-Za-z0-9\s]/.test(password)) {
    return { valid: false, reason: 'Strong password must include at least one symbol character.' };
  }
  if (/(.)\1\1\1/.test(password)) {
    return { valid: false, reason: 'Password must not repeat the same character 4 or more times in a row.' };
  }

  const lower = password.toLowerCase();
  const defaults = ['agentdock', 'password', 'passw0rd', 'qwerty', '123456', 'admin'];
  for (const term of [...defaults, ...forbiddenTerms]) {
    if (typeof term === 'string' && term.trim().length >= 3 && lower.includes(term.trim().toLowerCase())) {
      return { valid: false, reason: 'Password must not contain common words or host/user identifiers.' };
    }
  }
  return { valid: true };
}

export function hashStrongPassword(password) {
  const salt = crypto.randomBytes(16);
  const N = 16384;
  const r = 8;
  const p = 1;
  const derived = crypto.scryptSync(password, salt, 64, { N, r, p });
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64url')}$${derived.toString('base64url')}`;
}

export function verifyStrongPassword(password, storedHash) {
  if (typeof password !== 'string' || password.length > MAX_PASSWORD_LENGTH || typeof storedHash !== 'string') {
    return false;
  }
  const parts = storedHash.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  if (N !== 16384 || r !== 8 || p !== 1) return false;
  let salt, expected;
  try {
    salt = Buffer.from(parts[4], 'base64url');
    expected = Buffer.from(parts[5], 'base64url');
  } catch {
    return false;
  }
  if (salt.length < 16 || expected.length !== 64) return false;
  const actual = crypto.scryptSync(password, salt, 64, { N, r, p });
  return crypto.timingSafeEqual(actual, expected);
}

function normalizeSessionPersistence(value) {
  return value === 'browser' ? 'browser' : 'tab';
}

function defaultAuthRecord(hostSupport) {
  return {
    version: 1,
    initialized: false,
    requirePasskey: hostSupport.supported,
    hardwarePasskeyEnforced: Boolean(hostSupport.supported),
    passkeys: [],
    passwordHash: null,
    setupTicket: null,
    sessionPersistence: 'tab',
    authVersion: 1,
    updatedAt: null,
    error: null,
  };
}

export function readWebUiAuthSync(stateDir, { workspaceRoots, passkeyDetector = detectHostPasskeySupport, bypassCache = false } = {}) {
  const hostSupport = passkeyDetector === detectHostPasskeySupport
    ? detectHostPasskeySupport({ bypassCache })
    : passkeyDetector();
  if (!stateDir || typeof stateDir !== 'string') {
    return { ...defaultAuthRecord(hostSupport), hostPasskeySupported: hostSupport.supported, hostPasskeyReason: hostSupport.reason };
  }
  const filePath = webuiAuthFilePath(stateDir);
  try {
    const roots = workspaceRoots ?? loadWorkspaceRootsFromStateConfig(stateDir);
    assertConfigOutsideWorkspace(filePath, roots);
  } catch (error) {
    return {
      ...defaultAuthRecord(hostSupport),
      requirePasskey: true,
      hostPasskeySupported: hostSupport.supported,
      hostPasskeyReason: hostSupport.reason,
      error: error.message,
    };
  }

  let fd;
  try {
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return {
        ...defaultAuthRecord(hostSupport),
        hardwarePasskeyEnforced: Boolean(hostSupport.supported),
        hostPasskeySupported: hostSupport.supported,
        hostPasskeyReason: hostSupport.reason,
      };
    }
    return {
      ...defaultAuthRecord(hostSupport),
      requirePasskey: true,
      hardwarePasskeyEnforced: Boolean(hostSupport.supported),
      hostPasskeySupported: hostSupport.supported,
      hostPasskeyReason: hostSupport.reason,
      error: error?.code === 'ELOOP' ? 'WebUI auth file must not be a symbolic link.' : 'Cannot inspect WebUI auth configuration.',
    };
  }

  let rawText;
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1) {
      return {
        ...defaultAuthRecord(hostSupport),
        requirePasskey: true,
        hardwarePasskeyEnforced: Boolean(hostSupport.supported),
        hostPasskeySupported: hostSupport.supported,
        hostPasskeyReason: hostSupport.reason,
        error: 'WebUI auth file must be a regular single-link file.',
      };
    }
    if (stat.size > 131072) {
      return {
        ...defaultAuthRecord(hostSupport),
        requirePasskey: true,
        hardwarePasskeyEnforced: Boolean(hostSupport.supported),
        hostPasskeySupported: hostSupport.supported,
        hostPasskeyReason: hostSupport.reason,
        error: 'WebUI auth configuration exceeds maximum allowed size.',
      };
    }
    if (process.platform !== 'win32') {
      if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
        return {
          ...defaultAuthRecord(hostSupport),
          requirePasskey: true,
          hardwarePasskeyEnforced: Boolean(hostSupport.supported),
          hostPasskeySupported: hostSupport.supported,
          hostPasskeyReason: hostSupport.reason,
          error: 'WebUI auth file has an untrusted owner.',
        };
      }
      if ((stat.mode & 0o077) !== 0) {
        return {
          ...defaultAuthRecord(hostSupport),
          requirePasskey: true,
          hardwarePasskeyEnforced: Boolean(hostSupport.supported),
          hostPasskeySupported: hostSupport.supported,
          hostPasskeyReason: hostSupport.reason,
          error: 'WebUI auth file permissions must restrict access to owner (0600).',
        };
      }
    }
    rawText = fs.readFileSync(fd, 'utf8');
  } finally {
    fs.closeSync(fd);
  }

  try {
    const parsed = JSON.parse(rawText);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Invalid JSON structure.');
    }
    const rawPasskeys = Array.isArray(parsed.passkeys) ? parsed.passkeys : [];
    const passkeys = [];
    for (const pk of rawPasskeys) {
      if (
        !pk ||
        typeof pk.id !== 'string' ||
        !pk.id ||
        typeof pk.publicKeyPem !== 'string' ||
        !Number.isInteger(pk.alg) ||
        !Number.isSafeInteger(pk.signCount) ||
        pk.signCount < 0
      ) {
        throw new Error('Corrupted PassKey entry.');
      }
      passkeys.push(pk);
    }
    const passwordHash = typeof parsed.passwordHash === 'string' ? parsed.passwordHash : null;
    const hardwarePasskeyEnforced = Boolean(parsed.hardwarePasskeyEnforced || hostSupport.supported);
    const requirePasskey = Boolean(parsed.requirePasskey || hardwarePasskeyEnforced || passkeys.length > 0);
    const initialized = passkeys.length > 0 || Boolean(passwordHash && !requirePasskey);
    const setupTicket = parsed.setupTicket
      && typeof parsed.setupTicket.hash === 'string'
      && Number.isFinite(parsed.setupTicket.expiresAt)
      ? parsed.setupTicket
      : null;

    return {
      version: 1,
      initialized,
      requirePasskey,
      hardwarePasskeyEnforced,
      passkeys,
      passwordHash: requirePasskey ? null : passwordHash,
      setupTicket,
      sessionPersistence: normalizeSessionPersistence(parsed.sessionPersistence),
      authVersion: Number.isSafeInteger(parsed.authVersion) && parsed.authVersion > 0 ? parsed.authVersion : 1,
      updatedAt: typeof parsed.updatedAt === 'string' ? parsed.updatedAt : null,
      hostPasskeySupported: hostSupport.supported,
      hostPasskeyReason: hostSupport.reason,
      error: null,
    };
  } catch {
    return {
      ...defaultAuthRecord(hostSupport),
      requirePasskey: true,
      hardwarePasskeyEnforced: Boolean(hostSupport.supported),
      hostPasskeySupported: hostSupport.supported,
      hostPasskeyReason: hostSupport.reason,
      error: 'WebUI auth configuration is corrupted.',
    };
  }
}

export function publicWebUiAuthSummary(record, { includePrivateMeta = true } = {}) {
  const mode = record.error
    ? 'error'
    : !record.initialized
      ? 'uninitialized'
      : (record.requirePasskey || record.passkeys.length > 0)
        ? 'passkey'
        : 'password';
  return {
    initialized: record.initialized,
    mode,
    passkeyRequired: Boolean(record.requirePasskey || record.passkeys.length > 0 || record.hostPasskeySupported),
    hardwarePasskeyEnforced: Boolean(record.hardwarePasskeyEnforced || record.hostPasskeySupported),
    passkeyCount: record.passkeys.length,
    ...(includePrivateMeta
      ? {
          passkeys: record.passkeys.map(pk => ({
            id: pk.id,
            idShort: pk.id.slice(0, 12),
            alg: pk.alg,
            label: pk.label || 'PassKey',
            createdAt: pk.createdAt || null,
            lastUsedAt: pk.lastUsedAt || null,
            transports: Array.isArray(pk.transports) ? pk.transports : [],
          })),
          hasActiveSetupTicket: Boolean(record.setupTicket && record.setupTicket.expiresAt > Date.now()),
        }
      : {}),
    hasPassword: Boolean(record.passwordHash),
    hostPasskeySupported: record.hostPasskeySupported,
    hostPasskeyReason: record.hostPasskeyReason,
    sessionPersistence: normalizeSessionPersistence(record.sessionPersistence),
    updatedAt: includePrivateMeta ? record.updatedAt : null,
    error: record.error,
  };
}

function saveAuthState(stateDir, next, { workspaceRoots, requirePrivateState }) {
  const resolvedState = assertWritableStateDir(stateDir, requirePrivateState);
  const filePath = webuiAuthFilePath(resolvedState);
  const roots = workspaceRoots ?? loadWorkspaceRootsFromStateConfig(resolvedState);
  assertConfigOutsideWorkspace(filePath, roots);
  writePrivateAuthJsonSync(filePath, {
    version: 1,
    requirePasskey: Boolean(next.requirePasskey),
    hardwarePasskeyEnforced: Boolean(next.hardwarePasskeyEnforced),
    passkeys: next.passkeys,
    passwordHash: next.passwordHash,
    setupTicket: next.setupTicket,
    sessionPersistence: normalizeSessionPersistence(next.sessionPersistence),
    authVersion: next.authVersion,
    updatedAt: new Date().toISOString(),
  });
  return filePath;
}

export function verifySetupTicketMatch(record, providedTicket) {
  if (!record?.setupTicket || typeof providedTicket !== 'string' || !providedTicket.trim()) return false;
  if (record.setupTicket.expiresAt <= Date.now()) return false;
  const expected = Buffer.from(record.setupTicket.hash, 'hex');
  const actual = crypto.createHash('sha256').update(providedTicket.trim()).digest();
  return expected.length === 32 && crypto.timingSafeEqual(actual, expected);
}

export function issueSetupTicketSync(
  stateDir,
  { workspaceRoots, requirePrivateState = true, ttlMs = 300000, passkeyDetector = detectHostPasskeySupport } = {},
) {
  const current = readWebUiAuthSync(stateDir, { workspaceRoots, passkeyDetector });
  if (current.error) throw new Error(current.error);
  const token = `AD-${crypto.randomBytes(12).toString('base64url')}`;
  const expiresAt = Date.now() + ttlMs;
  saveAuthState(stateDir, {
    requirePasskey: current.requirePasskey || current.hostPasskeySupported || current.passkeys.length > 0,
    hardwarePasskeyEnforced: current.hardwarePasskeyEnforced || current.hostPasskeySupported,
    passkeys: current.passkeys,
    passwordHash: current.passwordHash,
    setupTicket: {
      hash: crypto.createHash('sha256').update(token).digest('hex'),
      expiresAt,
    },
    sessionPersistence: current.sessionPersistence,
    authVersion: current.authVersion,
  }, { workspaceRoots, requirePrivateState });
  return { setupToken: token, expiresAt: new Date(expiresAt).toISOString() };
}

export function setStrongPasswordSync(
  stateDir,
  { password, setupToken, allowBypassTicket = false, workspaceRoots, requirePrivateState = true, passkeyDetector = detectHostPasskeySupport } = {},
) {
  const current = readWebUiAuthSync(stateDir, { workspaceRoots, passkeyDetector, bypassCache: true });
  if (current.error) throw new Error(current.error);
  if (current.hostPasskeySupported || current.hardwarePasskeyEnforced || current.requirePasskey || current.passkeys.length > 0) {
    throw new Error('This machine enforces PassKey authentication; password authentication cannot be used.');
  }
  if (!allowBypassTicket && !verifySetupTicketMatch(current, setupToken)) {
    throw new Error('Valid single-use setup code from ~/.agentdock-bridge/webui-auth init is required.');
  }
  const strength = validateStrongPassword(password, {
    forbiddenTerms: [safeUsername(), os.hostname()],
  });
  if (!strength.valid) throw new Error(strength.reason);

  saveAuthState(stateDir, {
    requirePasskey: false,
    hardwarePasskeyEnforced: false,
    passkeys: [],
    passwordHash: hashStrongPassword(password),
    setupTicket: null,
    sessionPersistence: current.sessionPersistence,
    authVersion: current.authVersion + 1,
  }, { workspaceRoots, requirePrivateState });

  return readWebUiAuthSync(stateDir, { workspaceRoots, passkeyDetector });
}

export function enrollPasskeySync(
  stateDir,
  { credential, label = 'Primary PassKey', workspaceRoots, requirePrivateState = true, passkeyDetector = detectHostPasskeySupport } = {},
) {
  const current = readWebUiAuthSync(stateDir, { workspaceRoots, passkeyDetector, bypassCache: true });
  if (current.error) throw new Error(current.error);
  if (current.passkeys.some(pk => pk.id === credential.credentialId)) {
    throw new Error('This PassKey is already enrolled.');
  }
  if (current.passkeys.length >= MAX_PASSKEYS) {
    throw new Error('Maximum number of enrolled PassKeys reached.');
  }
  const passkeys = [
    ...current.passkeys,
    {
      id: credential.credentialId,
      alg: credential.alg,
      publicKeyPem: credential.publicKeyPem,
      signCount: credential.signCount,
      transports: credential.transports || [],
      label: String(label || 'PassKey').slice(0, 48),
      createdAt: new Date().toISOString(),
    },
  ];
  saveAuthState(stateDir, {
    requirePasskey: true,
    hardwarePasskeyEnforced: current.hardwarePasskeyEnforced || current.hostPasskeySupported,
    passkeys,
    passwordHash: null,
    setupTicket: null,
    sessionPersistence: current.sessionPersistence,
    authVersion: current.authVersion + 1,
  }, { workspaceRoots, requirePrivateState });

  return readWebUiAuthSync(stateDir, { workspaceRoots, passkeyDetector });
}

export function updatePasskeySignCountSync(
  stateDir,
  { credentialId, newSignCount, workspaceRoots, requirePrivateState = true, passkeyDetector = detectHostPasskeySupport } = {},
) {
  const current = readWebUiAuthSync(stateDir, { workspaceRoots, passkeyDetector });
  if (current.error) throw new Error(current.error);
  const existing = current.passkeys.find(pk => pk.id === credentialId);
  if (!existing) throw new Error('PassKey credential is no longer enrolled.');
  if (!Number.isSafeInteger(newSignCount) || newSignCount < 0 || ((existing.signCount > 0 || newSignCount > 0) && newSignCount <= existing.signCount)) {
    throw new Error('Authenticator signature counter did not advance.');
  }
  const passkeys = current.passkeys.map(pk =>
    pk.id === credentialId ? { ...pk, signCount: newSignCount, lastUsedAt: new Date().toISOString() } : pk,
  );
  saveAuthState(stateDir, {
    requirePasskey: true,
    hardwarePasskeyEnforced: current.hardwarePasskeyEnforced || current.hostPasskeySupported,
    passkeys,
    passwordHash: null,
    setupTicket: current.setupTicket,
    sessionPersistence: current.sessionPersistence,
    authVersion: current.authVersion,
  }, { workspaceRoots, requirePrivateState });
}

export function markPasskeyRequiredSync(
  stateDir,
  { workspaceRoots, requirePrivateState = true, passkeyDetector = detectHostPasskeySupport } = {},
) {
  const current = readWebUiAuthSync(stateDir, { workspaceRoots, passkeyDetector });
  if (current.error) throw new Error(current.error);
  if (!current.requirePasskey || !current.hardwarePasskeyEnforced) {
    saveAuthState(stateDir, {
      requirePasskey: true,
      hardwarePasskeyEnforced: true,
      passkeys: current.passkeys,
      passwordHash: null,
      setupTicket: current.setupTicket,
      sessionPersistence: current.sessionPersistence,
      authVersion: current.authVersion + (current.requirePasskey ? 0 : 1),
    }, { workspaceRoots, requirePrivateState });
  }
  return readWebUiAuthSync(stateDir, { workspaceRoots, passkeyDetector });
}

export function setSessionPersistenceSync(
  stateDir,
  { sessionPersistence, workspaceRoots, requirePrivateState = true, passkeyDetector = detectHostPasskeySupport } = {},
) {
  if (!SESSION_PERSISTENCE_MODES.has(sessionPersistence)) {
    throw new Error('sessionPersistence must be "tab" or "browser".');
  }
  const current = readWebUiAuthSync(stateDir, { workspaceRoots, passkeyDetector });
  if (current.error) throw new Error(current.error);
  saveAuthState(stateDir, {
    requirePasskey: current.requirePasskey,
    hardwarePasskeyEnforced: current.hardwarePasskeyEnforced || current.hostPasskeySupported,
    passkeys: current.passkeys,
    passwordHash: current.passwordHash,
    setupTicket: current.setupTicket,
    sessionPersistence,
    authVersion: current.authVersion + (sessionPersistence === 'tab' ? 1 : 0),
  }, { workspaceRoots, requirePrivateState });
  return readWebUiAuthSync(stateDir, { workspaceRoots, passkeyDetector });
}

export function deletePasskeySync(
  stateDir,
  { credentialId, workspaceRoots, requirePrivateState = true, passkeyDetector = detectHostPasskeySupport } = {},
) {
  if (typeof credentialId !== 'string' || !credentialId) {
    throw new Error('PassKey credentialId is required.');
  }
  const current = readWebUiAuthSync(stateDir, { workspaceRoots, passkeyDetector });
  if (current.error) throw new Error(current.error);
  if (!current.passkeys.some(pk => pk.id === credentialId)) {
    throw new Error('PassKey credential not found.');
  }
  if (current.passkeys.length <= 1) {
    throw new Error('Cannot remove the final PassKey. Enroll a backup PassKey first, or switch to a strong password on supported hosts.');
  }
  const passkeys = current.passkeys.filter(pk => pk.id !== credentialId);
  saveAuthState(stateDir, {
    requirePasskey: true,
    hardwarePasskeyEnforced: current.hardwarePasskeyEnforced || current.hostPasskeySupported,
    passkeys,
    passwordHash: null,
    setupTicket: current.setupTicket,
    sessionPersistence: current.sessionPersistence,
    authVersion: current.authVersion + 1,
  }, { workspaceRoots, requirePrivateState });
  return readWebUiAuthSync(stateDir, { workspaceRoots, passkeyDetector });
}

export function switchToStrongPasswordSync(
  stateDir,
  { password, workspaceRoots, requirePrivateState = true, passkeyDetector = detectHostPasskeySupport } = {},
) {
  const current = readWebUiAuthSync(stateDir, { workspaceRoots, passkeyDetector, bypassCache: true });
  if (current.error) throw new Error(current.error);
  if (!current.requirePasskey && current.passkeys.length === 0) {
    throw new Error('WebUI is already using strong password authentication; use password reset instead.');
  }
  if (current.hostPasskeySupported || current.hardwarePasskeyEnforced) {
    throw new Error('This host enforces PassKey authentication and cannot switch back to password mode.');
  }
  const strength = validateStrongPassword(password, {
    forbiddenTerms: [safeUsername(), os.hostname()],
  });
  if (!strength.valid) throw new Error(strength.reason);
  saveAuthState(stateDir, {
    requirePasskey: false,
    hardwarePasskeyEnforced: false,
    passkeys: [],
    passwordHash: hashStrongPassword(password),
    setupTicket: null,
    sessionPersistence: current.sessionPersistence,
    authVersion: current.authVersion + 1,
  }, { workspaceRoots, requirePrivateState });
  return readWebUiAuthSync(stateDir, { workspaceRoots, passkeyDetector });
}

export function resetWebUiAuthSync(
  stateDir,
  { workspaceRoots, requirePrivateState = true, issueTicket = true, passkeyDetector = detectHostPasskeySupport } = {},
) {
  const hostSupport = passkeyDetector === detectHostPasskeySupport
    ? detectHostPasskeySupport({ bypassCache: true })
    : passkeyDetector();
  const token = issueTicket ? `AD-${crypto.randomBytes(12).toString('base64url')}` : null;
  const expiresAt = Date.now() + 300000;
  const existing = readWebUiAuthSync(stateDir, { workspaceRoots, passkeyDetector });
  const nextVersion = (existing.authVersion || 1) + 1;

  saveAuthState(stateDir, {
    requirePasskey: hostSupport.supported,
    hardwarePasskeyEnforced: hostSupport.supported,
    passkeys: [],
    passwordHash: null,
    setupTicket: token ? { hash: crypto.createHash('sha256').update(token).digest('hex'), expiresAt } : null,
    sessionPersistence: 'tab',
    authVersion: nextVersion,
  }, { workspaceRoots, requirePrivateState });

  return {
    reset: true,
    hostPasskeySupported: hostSupport.supported,
    ...(token ? { setupToken: token, expiresAt: new Date(expiresAt).toISOString() } : {}),
  };
}
