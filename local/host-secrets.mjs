// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  assertPlainLocalPath,
  assertWriteProtectedPath,
  assertPrivateState,
  assertPrivateFile,
  assertConnectorStopped,
  sanitizedToolEnv,
} from './host-safety.mjs';

export const SECRET_META_FILE = 'secrets.meta.json';
export const SECRET_DATA_FILE = 'secrets.json';
export const SECRET_NEXT_FILE = 'secrets.next.json';
const BACKEND_TYPES = new Set(['macos-keychain', 'linux-secret-service', 'posix-file']);
const KEYRING_ID = /^[A-Za-z0-9._-]{1,128}$/;

function base64url(buffer) {
  return buffer.toString('base64url');
}

export function generateCredentials() {
  const ownerPassword = base64url(crypto.randomBytes(24));
  const salt = crypto.randomBytes(16);
  const derived = crypto.pbkdf2Sync(ownerPassword, salt, 100000, 32, 'sha256');
  const ownerPasswordHash = `pbkdf2-sha256$100000$${base64url(salt)}$${base64url(derived)}`;
  const bridgeToken = base64url(crypto.randomBytes(32));
  return { bridgeToken, ownerPassword, ownerPasswordHash };
}

function validateSecretsShape(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Invalid credential format.');
  if (typeof data.bridgeToken !== 'string' || data.bridgeToken.length < 32) throw new Error('Invalid bridgeToken.');
  if (typeof data.ownerPassword !== 'string' || !data.ownerPassword.length) throw new Error('Invalid ownerPassword.');
  if (typeof data.ownerPasswordHash !== 'string' || !data.ownerPasswordHash.startsWith('pbkdf2-sha256$100000$')) {
    throw new Error('Invalid ownerPasswordHash.');
  }
  return data;
}

function serviceNameForState(realStateDir) {
  const hash = crypto.createHash('sha256').update(realStateDir).digest('hex').slice(0, 16);
  return `cbnv.agentdock-bridge.${hash}`;
}

function atomicWritePrivateFileSync(targetPath, content) {
  const dir = path.dirname(targetPath);
  const temp = path.join(dir, `.secret-${crypto.randomUUID()}.tmp`);
  const fd = fs.openSync(temp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o600);
  try {
    fs.writeFileSync(fd, content, { encoding: 'utf8' });
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    fs.chmodSync(temp, 0o600);
    fs.renameSync(temp, targetPath);
  } catch (error) {
    fs.rmSync(temp, { force: true });
    throw error;
  }
}

function keychainExecutable() {
  return '/usr/bin/security';
}

function secretToolExecutable() {
  for (const candidate of ['/usr/bin/secret-tool', '/bin/secret-tool']) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

function canUseMacosKeychain() {
  if (process.platform !== 'darwin' || !fs.existsSync(keychainExecutable())) return false;
  try {
    execFileSync(keychainExecutable(), ['default-keychain'], { timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] });
    return true;
  } catch {
    return false;
  }
}

function canUseLinuxSecretService() {
  if (process.platform !== 'linux') return false;
  const bin = secretToolExecutable();
  if (!bin || !process.env.DBUS_SESSION_BUS_ADDRESS) return false;
  try {
    // A harmless search query proves D-Bus secret service is reachable and unlocked.
    execFileSync(bin, ['search', 'service', 'cbnv.agentdock-bridge.probe'], {
      timeout: 5000,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return true;
  } catch (error) {
    // secret-tool exits 0 or 1 with empty stderr when no item matches,
    // whereas D-Bus or locked keyring failures write diagnostics to stderr or exit > 1.
    return error?.status === 0 || (error?.status === 1 && !String(error?.stderr || '').trim());
  }
}

export function resolveSecretBackend(requested = 'auto') {
  if (process.platform === 'win32') throw new Error('Windows uses DPAPI via Secrets.ps1.');
  const normalized = requested === 'keychain' ? 'macos-keychain'
    : requested === 'secret-service' ? 'linux-secret-service'
    : requested === 'file' ? 'posix-file'
    : requested;
  if (normalized === 'auto') {
    if (process.platform === 'darwin') {
      if (canUseMacosKeychain()) return 'macos-keychain';
      throw new Error('macOS login Keychain is unavailable or locked. Unlock it or pass --secret-backend file.');
    }
    if (process.platform === 'linux') {
      return canUseLinuxSecretService() ? 'linux-secret-service' : 'posix-file';
    }
    return 'posix-file';
  }
  if (!BACKEND_TYPES.has(normalized)) throw new Error(`Unsupported secret backend: ${requested}`);
  if (normalized === 'macos-keychain' && process.platform !== 'darwin') throw new Error('macos-keychain requires macOS.');
  if (normalized === 'linux-secret-service' && process.platform !== 'linux') throw new Error('linux-secret-service requires Linux.');
  return normalized;
}

function assertKeyringIdentifier(service, account) {
  if (!KEYRING_ID.test(service || '') || !KEYRING_ID.test(account || '')) {
    throw new Error('Invalid credential identifier.');
  }
}

function writeBackendPayloadSync({ backend, stateDir, service, account, payload }) {
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  if (backend === 'posix-file') {
    const fileName = account === 'current' ? SECRET_DATA_FILE : account === 'next' ? SECRET_NEXT_FILE : `secrets-${account}.json`;
    atomicWritePrivateFileSync(path.join(stateDir, fileName), JSON.stringify(payload));
    return;
  }
  if (backend === 'macos-keychain') {
    assertKeyringIdentifier(service, account);
    // Pass base64 payload over stdin (-i) so credentials never appear in argv/ps.
    const cmd = `add-generic-password -U -s "${service}" -a "${account}" -w "${encoded}"\n`;
    execFileSync(keychainExecutable(), ['-i'], {
      input: cmd,
      encoding: 'utf8',
      timeout: 15000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const roundTrip = readBackendPayloadSync({ backend, stateDir, service, account });
    if (roundTrip.bridgeToken !== payload.bridgeToken) throw new Error('Keychain verification failed.');
    return;
  }
  if (backend === 'linux-secret-service') {
    assertKeyringIdentifier(service, account);
    const bin = secretToolExecutable();
    if (!bin) throw new Error('secret-tool is not installed.');
    execFileSync(bin, ['store', `--label=AgentDock Bridge (${account})`, 'service', service, 'account', account], {
      input: encoded,
      encoding: 'utf8',
      timeout: 15000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const roundTrip = readBackendPayloadSync({ backend, stateDir, service, account });
    if (roundTrip.bridgeToken !== payload.bridgeToken) throw new Error('Secret service verification failed.');
    return;
  }
  throw new Error('Unknown secret backend.');
}

function readBackendPayloadSync({ backend, stateDir, service, account }) {
  if (backend === 'posix-file') {
    const fileName = account === 'current' ? SECRET_DATA_FILE : account === 'next' ? SECRET_NEXT_FILE : `secrets-${account}.json`;
    const filePath = assertPrivateFile(path.join(stateDir, fileName));
    return validateSecretsShape(JSON.parse(fs.readFileSync(filePath, 'utf8')));
  }
  if (backend === 'macos-keychain') {
    assertKeyringIdentifier(service, account);
    const raw = execFileSync(keychainExecutable(), ['find-generic-password', '-s', service, '-a', account, '-w'], {
      encoding: 'utf8',
      timeout: 15000,
      maxBuffer: 65536,
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
    return validateSecretsShape(JSON.parse(Buffer.from(raw, 'base64').toString('utf8')));
  }
  if (backend === 'linux-secret-service') {
    assertKeyringIdentifier(service, account);
    const bin = secretToolExecutable();
    if (!bin) throw new Error('secret-tool is not installed.');
    const raw = execFileSync(bin, ['lookup', 'service', service, 'account', account], {
      encoding: 'utf8',
      timeout: 15000,
      maxBuffer: 65536,
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
    return validateSecretsShape(JSON.parse(Buffer.from(raw, 'base64').toString('utf8')));
  }
  throw new Error('Unknown secret backend.');
}

function deleteBackendPayloadSync({ backend, stateDir, service, account }) {
  if (backend === 'posix-file') {
    const fileName = account === 'current' ? SECRET_DATA_FILE : account === 'next' ? SECRET_NEXT_FILE : `secrets-${account}.json`;
    fs.rmSync(path.join(stateDir, fileName), { force: true });
    return;
  }
  if (backend === 'macos-keychain') {
    assertKeyringIdentifier(service, account);
    try {
      execFileSync(keychainExecutable(), ['-i'], {
        input: `delete-generic-password -s "${service}" -a "${account}"\n`,
        encoding: 'utf8',
        timeout: 15000,
        stdio: ['pipe', 'ignore', 'ignore'],
      });
    } catch { /* Missing pending entries are harmless during cleanup. */ }
    return;
  }
  if (backend === 'linux-secret-service') {
    assertKeyringIdentifier(service, account);
    const bin = secretToolExecutable();
    if (!bin) return;
    try {
      execFileSync(bin, ['clear', 'service', service, 'account', account], {
        timeout: 15000,
        stdio: ['ignore', 'ignore', 'ignore'],
      });
    } catch { /* Missing pending entries are harmless during cleanup. */ }
  }
}

function readSecretMetaSync(stateDir) {
  const realState = assertPrivateState(stateDir);
  const metaPath = assertPrivateFile(path.join(realState, SECRET_META_FILE));
  const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
  if (!meta || !BACKEND_TYPES.has(meta.backend)) throw new Error('Invalid secret metadata.');
  if (meta.backend !== 'posix-file') {
    assertKeyringIdentifier(meta.service, meta.account || 'current');
  }
  return { realState, meta };
}

export function createSecrets(stateDir, { backend = 'auto' } = {}) {
  const chosenBackend = resolveSecretBackend(backend);
  const parent = assertPlainLocalPath(path.dirname(path.resolve(stateDir)));
  assertWriteProtectedPath(parent);
  if (fs.existsSync(stateDir)) {
    assertWriteProtectedPath(stateDir);
    if (fs.readdirSync(stateDir).length > 0) {
      throw new Error('Credential directory is not empty; inspect it before setup.');
    }
  } else {
    fs.mkdirSync(stateDir, { mode: 0o700 });
  }
  fs.chmodSync(stateDir, 0o700);
  const realState = assertPrivateState(stateDir);
  const metaFile = path.join(realState, SECRET_META_FILE);
  if (fs.existsSync(metaFile) || fs.existsSync(path.join(realState, SECRET_DATA_FILE))) {
    throw new Error('Secrets already exist; preserve them.');
  }
  const credentials = generateCredentials();
  const service = serviceNameForState(realState);
  writeBackendPayloadSync({ backend: chosenBackend, stateDir: realState, service, account: 'current', payload: credentials });
  atomicWritePrivateFileSync(metaFile, JSON.stringify({
    version: 1,
    backend: chosenBackend,
    ...(chosenBackend === 'posix-file' ? {} : { service, account: 'current' }),
  }, null, 2));
  return { backend: chosenBackend, stateDir: realState };
}

export function exportSecretsSync(stateDir, { fields } = {}) {
  try {
    const { realState, meta } = readSecretMetaSync(stateDir);
    const service = meta.service || serviceNameForState(realState);
    const account = meta.account || 'current';
    const data = readBackendPayloadSync({ backend: meta.backend, stateDir: realState, service, account });
    if (Array.isArray(fields) && fields.length) {
      const subset = {};
      for (const field of fields) subset[field] = data[field];
      return subset;
    }
    return data;
  } catch {
    // Never attach raw shell diagnostics or credential fragments to thrown errors.
    throw new Error('Protected credential loading failed. Check the trusted local installation.');
  }
}

export function uploadSecretsSync(stateDir, { wranglerPath, wranglerConfig, secrets } = {}) {
  const realState = assertPrivateState(stateDir);
  assertConnectorStopped(realState);
  const data = secrets || exportSecretsSync(realState);
  const root = path.resolve(import.meta.dirname, '..');
  const rawBin = wranglerPath || path.join(root, 'node_modules', '.bin', 'wrangler');
  const bin = assertPlainLocalPath(rawBin);
  assertWriteProtectedPath(bin);
  const binStat = fs.statSync(bin);
  if (!binStat.isFile() || binStat.nlink !== 1) throw new Error('Untrusted wrangler executable.');
  const config = assertPlainLocalPath(wranglerConfig || path.join(root, 'wrangler.jsonc'));
  const payload = JSON.stringify({ BRIDGE_TOKEN: data.bridgeToken, OWNER_PASSWORD_HASH: data.ownerPasswordHash });
  execFileSync(bin, ['secret', 'bulk', '--config', config], {
    input: payload,
    encoding: 'utf8',
    env: sanitizedToolEnv(),
    timeout: 60000,
    stdio: ['pipe', 'inherit', 'inherit'],
  });
}

export function rotateSecretsSync(stateDir, { wranglerPath, wranglerConfig, uploader } = {}) {
  const { realState, meta } = readSecretMetaSync(stateDir);
  assertConnectorStopped(realState);
  const service = meta.service || serviceNameForState(realState);
  const currentAccount = meta.account || 'current';
  const current = readBackendPayloadSync({ backend: meta.backend, stateDir: realState, service, account: currentAccount });
  let next = null;
  try {
    const staged = readBackendPayloadSync({ backend: meta.backend, stateDir: realState, service, account: 'next' });
    if (staged.bridgeToken !== current.bridgeToken && staged.ownerPasswordHash !== current.ownerPasswordHash) {
      next = staged;
    }
  } catch { /* No reusable next credentials staged yet. */ }
  if (!next) {
    next = generateCredentials();
    writeBackendPayloadSync({ backend: meta.backend, stateDir: realState, service, account: 'next', payload: next });
  }

  if (uploader) uploader(next);
  else uploadSecretsSync(realState, { wranglerPath, wranglerConfig, secrets: next });

  const stamp = `${new Date().toISOString().replace(/[:.]/g, '-')}-${crypto.randomUUID().slice(0, 8)}`;
  writeBackendPayloadSync({ backend: meta.backend, stateDir: realState, service, account: `retired-${stamp}`, payload: current });
  if (meta.backend === 'posix-file') {
    const nextFile = assertPrivateFile(path.join(realState, SECRET_NEXT_FILE));
    fs.renameSync(nextFile, path.join(realState, SECRET_DATA_FILE));
  } else {
    writeBackendPayloadSync({ backend: meta.backend, stateDir: realState, service, account: currentAccount, payload: next });
    deleteBackendPayloadSync({ backend: meta.backend, stateDir: realState, service, account: 'next' });
  }
  return { backend: meta.backend, rotated: true };
}
