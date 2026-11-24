// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { beneath } from './file-safety.mjs';

export const NODE_OVERRIDE_VARS = Object.freeze([
  'NODE_OPTIONS',
  'NODE_PATH',
  'NODE_TLS_REJECT_UNAUTHORIZED',
  'NODE_EXTRA_CA_CERTS',
  'LD_PRELOAD',
  'LD_LIBRARY_PATH',
  'DYLD_INSERT_LIBRARIES',
  'DYLD_LIBRARY_PATH',
  'DYLD_FRAMEWORK_PATH',
]);

export function clearNodeOverrides(env = process.env) {
  for (const name of NODE_OVERRIDE_VARS) delete env[name];
  return env;
}

export function sanitizedToolEnv(base = process.env) {
  const env = { ...base };
  return clearNodeOverrides(env);
}

export function sha256FileSync(filePath) {
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) throw new Error('Expected a regular file for integrity hashing.');
    const hash = crypto.createHash('sha256');
    const buffer = Buffer.allocUnsafe(65536);
    while (true) {
      const bytesRead = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (!bytesRead) break;
      hash.update(buffer.subarray(0, bytesRead));
    }
    return hash.digest('hex');
  } finally {
    fs.closeSync(fd);
  }
}

function currentPosixUid() {
  if (typeof process.getuid !== 'function') throw new Error('POSIX UID checks are unavailable on this platform.');
  return process.getuid();
}

function assertPosixSupported() {
  if (process.platform === 'win32') throw new Error('Use State-Safety.ps1 on Windows hosts.');
}

function isTrustedAncestorGroupWrite(stat) {
  // Mirror Windows trusting Administrators (S-1-5-32-544) on system ancestors
  // such as macOS /Applications (root:admin 0775) while keeping user paths strict.
  if ((stat.mode & 0o020) === 0) return true;
  if (stat.gid === 0) return true;
  return process.platform === 'darwin' && stat.gid === 80;
}

export function assertPlainLocalPath(targetPath) {
  assertPosixSupported();
  if (typeof targetPath !== 'string' || !path.isAbsolute(targetPath) || targetPath.includes('\0')) {
    throw new Error('A local absolute path is required.');
  }
  const resolved = path.resolve(targetPath);
  let cursor = resolved;
  while (true) {
    const stat = fs.lstatSync(cursor);
    if (stat.isSymbolicLink()) {
      throw new Error('Control paths must not contain symbolic links.');
    }
    const parent = path.dirname(cursor);
    if (!parent || parent === cursor) break;
    cursor = parent;
  }
  return resolved;
}

export function assertWriteProtectedPath(targetPath) {
  const uid = currentPosixUid();
  let cursor = assertPlainLocalPath(targetPath);
  while (true) {
    const stat = fs.lstatSync(cursor);
    if (stat.uid !== uid && stat.uid !== 0) {
      throw new Error('A control path has an untrusted owner.');
    }
    if ((stat.mode & 0o002) !== 0 || !isTrustedAncestorGroupWrite(stat)) {
      throw new Error('A control executable or parent directory is writable by an untrusted principal.');
    }
    const parent = path.dirname(cursor);
    if (!parent || parent === cursor) break;
    cursor = parent;
  }
  return path.resolve(targetPath);
}

export function assertPrivateState(stateDir) {
  const uid = currentPosixUid();
  const resolved = assertPlainLocalPath(stateDir);
  const stat = fs.lstatSync(resolved);
  if (!stat.isDirectory()) throw new Error('Private state must be a directory.');
  assertWriteProtectedPath(resolved);
  if (stat.uid !== uid || (stat.mode & 0o077) !== 0) {
    throw new Error('Private state directory permissions must restrict access to the owner (0700).');
  }
  return resolved;
}

export function assertPrivateFile(filePath) {
  const uid = currentPosixUid();
  const resolved = assertPlainLocalPath(filePath);
  const stat = fs.lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
    throw new Error('Private file must be a regular file without hard-link aliases.');
  }
  assertWriteProtectedPath(resolved);
  if (stat.uid !== uid || (stat.mode & 0o077) !== 0) {
    throw new Error('Private file permissions must restrict access to the owner (0600).');
  }
  return resolved;
}

export function assertTrustedBinary(binaryPath, workspacePath) {
  const resolved = assertPlainLocalPath(binaryPath);
  if (workspacePath) {
    const work = path.resolve(workspacePath);
    if (beneath(resolved, work)) {
      throw new Error('Control executables must be outside the mounted workspace.');
    }
  }
  const stat = fs.lstatSync(resolved);
  if (!stat.isFile() || stat.nlink !== 1) {
    throw new Error('Control executables must not have hard-link aliases.');
  }
  if ((stat.mode & 0o111) === 0) {
    throw new Error('Control file must be executable.');
  }
  assertWriteProtectedPath(resolved);
  return resolved;
}

export function assertPinnedNode(config, stateDir) {
  let privateRoot = assertPrivateState(stateDir);
  if (config.nodeRoot) privateRoot = assertPrivateState(config.nodeRoot);
  if (!config.nodePath || !path.isAbsolute(config.nodePath)) {
    throw new Error('Pinned Node executable is missing.');
  }
  const workspace = Array.isArray(config.roots) && config.roots[0] ? config.roots[0] : undefined;
  const node = assertTrustedBinary(config.nodePath, workspace);
  if (!beneath(node, privateRoot) || node === privateRoot) {
    throw new Error('Node must be installed inside its private runtime directory.');
  }
  if (!/^[a-f0-9]{64}$/i.test(config.nodeSha256 || '') || sha256FileSync(node) !== config.nodeSha256.toLowerCase()) {
    throw new Error('Pinned Node integrity check failed.');
  }
  return node;
}

export function getProcessIdentity(pid) {
  assertPosixSupported();
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  try {
    process.kill(pid, 0);
  } catch {
    return null;
  }
  if (process.platform === 'linux') {
    try {
      const statText = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
      const rparen = statText.lastIndexOf(')');
      if (rparen < 0) return null;
      const fields = statText.slice(rparen + 2).trim().split(/\s+/);
      // Field 22 in /proc/<pid>/stat corresponds to index 19 after ') <state>'.
      const startTime = fields[19];
      const executable = fs.realpathSync(`/proc/${pid}/exe`);
      if (!startTime || !executable) return null;
      return { pid, startTime, executable };
    } catch {
      return null;
    }
  }
  if (process.platform === 'darwin') {
    try {
      const psEnv = { ...process.env, LC_ALL: 'C' };
      const raw = execFileSync('/bin/ps', ['-ww', '-p', String(pid), '-o', 'lstart=,comm='], {
        encoding: 'utf8',
        env: psEnv,
        timeout: 5000,
        stdio: ['ignore', 'pipe', 'ignore'],
      }).trim();
      if (!raw) return null;
      // ps -o lstart=,comm= under LC_ALL=C begins with 5 whitespace-separated date tokens:
      // e.g. "Fri Nov 20 21:30:00 2026 /path/to/node"
      const match = /^(\S+\s+\S+\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.+)$/.exec(raw);
      if (!match) return null;
      let rawExe = match[2].trim();
      if (!path.isAbsolute(rawExe) && fs.existsSync('/usr/sbin/lsof')) {
        try {
          const lsofOut = execFileSync('/usr/sbin/lsof', ['-Fn', '-a', '-d', 'txt', '-p', String(pid)], {
            encoding: 'utf8',
            env: psEnv,
            timeout: 5000,
            stdio: ['ignore', 'pipe', 'ignore'],
          });
          const exeLine = lsofOut.split('\n').find(line => line.startsWith('n/'));
          if (exeLine) rawExe = exeLine.slice(1).trim();
        } catch { /* Fall back to ps args inspection below if lsof is unavailable. */ }
      }
      if (!path.isAbsolute(rawExe)) {
        const argsRaw = execFileSync('/bin/ps', ['-ww', '-p', String(pid), '-o', 'args='], {
          encoding: 'utf8',
          env: psEnv,
          timeout: 5000,
          stdio: ['ignore', 'pipe', 'ignore'],
        }).trim();
        const exeMatch = /^(\/[^\0]*?\/node)(?:\s|$)/.exec(argsRaw);
        const firstToken = exeMatch ? exeMatch[1] : argsRaw.split(/\s+/)[0];
        if (firstToken && path.isAbsolute(firstToken) && fs.existsSync(firstToken)) rawExe = firstToken;
      }
      const executable = path.isAbsolute(rawExe) ? fs.realpathSync(rawExe) : rawExe;
      return { pid, startTime: match[1].replace(/\s+/g, ' '), executable };
    } catch {
      return null;
    }
  }
  return null;
}

export function findOwnedProcess(recordFile, expectedSource) {
  if (!fs.existsSync(recordFile)) return null;
  try {
    const record = JSON.parse(fs.readFileSync(recordFile, 'utf8'));
    if (!record || record.source !== expectedSource) return null;
    const identity = getProcessIdentity(record.pid);
    if (!identity) return null;
    const expectedExe = fs.realpathSync(record.executable);
    if (identity.executable !== expectedExe || identity.startTime !== String(record.startTime)) return null;
    return identity;
  } catch {
    return null;
  }
}

export function assertConnectorStopped(stateDir) {
  const root = assertPlainLocalPath(stateDir);
  for (const [file, markerField] of [['supervisor.json', 'source'], ['connector-process.json', 'source']]) {
    const recordFile = path.join(root, file);
    if (!fs.existsSync(recordFile)) continue;
    try {
      const record = JSON.parse(fs.readFileSync(recordFile, 'utf8'));
      if (record && record[markerField] && findOwnedProcess(recordFile, record[markerField])) {
        throw new Error('Stop the current connector before installing or rotating credentials.');
      }
    } catch (error) {
      if (error.message.includes('Stop the current connector')) throw error;
    }
  }
}
