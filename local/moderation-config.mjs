// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Bounded 0600 out-of-workspace storage helper for LLM moderation strategy configuration.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DEFAULT_MODERATION_CONFIG, validateModerationConfig } from '../packages/shared/src/moderation-config.mjs';
import { assertConfigOutsideWorkspace } from './capabilities.mjs';
import { assertPrivateFile, assertPrivateState } from './host-safety.mjs';

const MAX_MODERATION_CONFIG_BYTES = 128 * 1024;

export function moderationConfigFilePath(stateDir) {
  return path.join(path.resolve(stateDir), 'moderation', 'config.json');
}

export function readModerationConfigSync(
  stateDir,
  { workspaceRoots = [], blockedOrigins = [], fallback = DEFAULT_MODERATION_CONFIG } = {},
) {
  if (!stateDir) return fallback;
  const filePath = moderationConfigFilePath(stateDir);
  assertConfigOutsideWorkspace(filePath, workspaceRoots);
  const dir = path.dirname(filePath);
  if (fs.existsSync(dir)) {
    assertPrivateState(dir);
  }
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0);
  let fd;
  try {
    fd = fs.openSync(filePath, flags);
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return fallback;
    }
    throw error;
  }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > MAX_MODERATION_CONFIG_BYTES) {
      throw new Error('Moderation config file must be a regular single-link file within size limit.');
    }
    assertPrivateFile(filePath);
    const text = fs.readFileSync(fd, 'utf8');
    const parsed = text.trim() ? JSON.parse(text) : {};
    return validateModerationConfig(parsed, { blockedOrigins });
  } finally {
    try { fs.closeSync(fd); } catch {}
  }
}

export function writeModerationConfigSync(
  stateDir,
  rawConfig,
  { workspaceRoots = [], blockedOrigins = [] } = {},
) {
  const filePath = moderationConfigFilePath(stateDir);
  assertConfigOutsideWorkspace(filePath, workspaceRoots);
  const validated = validateModerationConfig(rawConfig, { blockedOrigins });
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  assertPrivateState(dir);
  if (process.platform !== 'win32') fs.chmodSync(dir, 0o700);
  const tmpPath = path.join(dir, `.tmp-mod-cfg-${crypto.randomUUID()}.json`);
  const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0);
  let fd;
  try {
    fd = fs.openSync(tmpPath, flags, 0o600);
    fs.writeFileSync(fd, JSON.stringify(validated, null, 2), 'utf8');
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    if (process.platform !== 'win32') fs.chmodSync(tmpPath, 0o600);
    fs.renameSync(tmpPath, filePath);
  } catch (error) {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch {}
    }
    try { fs.rmSync(tmpPath, { force: true }); } catch {}
    throw error;
  }
  return validated;
}
