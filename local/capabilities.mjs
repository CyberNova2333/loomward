// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { assertPrivateState } from './host-safety.mjs';
import { beneath } from './file-safety.mjs';

export const CAPABILITIES_FILE = 'capabilities.json';

export const TOOL_CAPABILITY_GROUPS = Object.freeze({
  computer_context: 'context',
  list_directory: 'fileRead',
  read_file: 'fileRead',
  search_files: 'fileRead',
  write_file: 'fileWrite',
  edit_file: 'fileWrite',
  delete_file: 'fileWrite',
  exec_command: 'exec',
  command_status: 'execControl',
  stop_command: 'execControl',
});

export function defaultCapabilities(configAllowExec = true) {
  return {
    exists: false,
    version: 1,
    fileRead: true,
    fileWrite: true,
    allowExec: configAllowExec === true,
    tools: {},
    updatedAt: null,
    error: null,
  };
}

function failClosedCapabilities(reason) {
  return {
    exists: true,
    version: 1,
    fileRead: false,
    fileWrite: false,
    allowExec: false,
    tools: {},
    updatedAt: null,
    error: reason,
  };
}

function normalizeToolOverrides(rawTools) {
  if (rawTools === undefined) return {};
  if (!rawTools || typeof rawTools !== 'object' || Array.isArray(rawTools)) {
    throw new Error('Invalid capability policy tools map.');
  }
  const out = {};
  for (const [name, enabled] of Object.entries(rawTools)) {
    if (!Object.hasOwn(TOOL_CAPABILITY_GROUPS, name)) {
      throw new Error(`Unknown tool in capability policy: ${name}`);
    }
    if (typeof enabled !== 'boolean') {
      throw new Error(`Tool toggle for ${name} must be a boolean.`);
    }
    if (enabled === false) out[name] = false;
  }
  return out;
}

export function capabilityFilePath(stateDir) {
  return path.join(path.resolve(stateDir), CAPABILITIES_FILE);
}

export function resolveRealPathAllowMissingLeaf(targetPath) {
  const resolved = path.resolve(targetPath);
  try {
    return fs.realpathSync(resolved);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
    const parent = path.dirname(resolved);
    if (parent === resolved) return resolved;
    return path.join(resolveRealPathAllowMissingLeaf(parent), path.basename(resolved));
  }
}

export function hasSymlinkComponent(targetPath) {
  let current = path.resolve(targetPath);
  const seen = new Set();
  while (!seen.has(current)) {
    seen.add(current);
    try {
      const st = fs.lstatSync(current);
      if (st.isSymbolicLink()) return true;
    } catch (error) {
      if (error?.code !== 'ENOENT') return true;
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return false;
}

export function loadWorkspaceRootsFromStateConfig(stateDir) {
  const cfgPath = path.join(path.resolve(stateDir), 'config.json');
  if (hasSymlinkComponent(cfgPath)) {
    throw new Error('Protected state config.json must not traverse symbolic links.');
  }
  let fd;
  try {
    fd = fs.openSync(cfgPath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw new Error('Cannot open protected state config.json to verify workspace isolation.');
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > 1024 * 1024) {
      throw new Error('Protected state config.json is invalid or oversized.');
    }
    const raw = JSON.parse(fs.readFileSync(fd, 'utf8'));
    const roots = [];
    if (Array.isArray(raw?.roots)) {
      for (const entry of raw.roots) if (typeof entry === 'string' && path.isAbsolute(entry)) roots.push(entry);
    }
    if (typeof raw?.defaultCwd === 'string' && path.isAbsolute(raw.defaultCwd)) roots.push(raw.defaultCwd);
    return roots;
  } catch (error) {
    throw new Error(error?.message || 'Protected state config.json is corrupted.');
  } finally {
    fs.closeSync(fd);
  }
}

export function assertConfigOutsideWorkspace(targetPath, workspaceRoots = []) {
  const roots = (Array.isArray(workspaceRoots) ? workspaceRoots : [workspaceRoots]).filter(Boolean);
  if (hasSymlinkComponent(targetPath)) {
    throw new Error('Configuration paths must not traverse symbolic links.');
  }
  const realTarget = resolveRealPathAllowMissingLeaf(targetPath);
  const targetDir = resolveRealPathAllowMissingLeaf(path.dirname(path.resolve(targetPath)));
  for (const root of roots) {
    const realRoot = resolveRealPathAllowMissingLeaf(root);
    if (
      beneath(realTarget, realRoot) ||
      beneath(realRoot, realTarget) ||
      beneath(targetDir, realRoot) ||
      beneath(realRoot, targetDir)
    ) {
      throw new Error('Configuration and security files must be stored strictly outside the mounted workspace.');
    }
  }
  return realTarget;
}

export function readCapabilitiesSync(stateDir, { configAllowExec = true, workspaceRoots } = {}) {
  const execCeiling = configAllowExec === true;
  if (!stateDir || typeof stateDir !== 'string') {
    return defaultCapabilities(execCeiling);
  }
  const filePath = capabilityFilePath(stateDir);
  let roots;
  try {
    roots = workspaceRoots ?? loadWorkspaceRootsFromStateConfig(stateDir);
    assertConfigOutsideWorkspace(filePath, roots);
  } catch (error) {
    return failClosedCapabilities(error.message);
  }
  let fd;
  try {
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  } catch (error) {
    if (error?.code === 'ENOENT') return defaultCapabilities(execCeiling);
    if (error?.code === 'ELOOP') return failClosedCapabilities('Capability policy file must not be a symbolic link.');
    return failClosedCapabilities('Cannot inspect capability policy.');
  }
  let rawText;
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1) {
      return failClosedCapabilities('Capability policy file must be an ordinary single-link regular file.');
    }
    if (stat.size > 65536) {
      return failClosedCapabilities('Capability policy file exceeds maximum allowed size.');
    }
    if (process.platform !== 'win32') {
      if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
        return failClosedCapabilities('Capability policy file has an untrusted owner.');
      }
      if ((stat.mode & 0o077) !== 0) {
        return failClosedCapabilities('Capability policy permissions must be restricted to the owner (0600).');
      }
    }
    rawText = fs.readFileSync(fd, 'utf8');
  } finally {
    fs.closeSync(fd);
  }

  try {
    const parsed = JSON.parse(rawText);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return failClosedCapabilities('Invalid capability policy payload.');
    }
    if (typeof parsed.fileRead !== 'boolean' || typeof parsed.fileWrite !== 'boolean') {
      return failClosedCapabilities('Capability policy boolean fields are invalid.');
    }
    if (parsed.allowExec !== undefined && typeof parsed.allowExec !== 'boolean') {
      return failClosedCapabilities('Capability policy allowExec flag is invalid.');
    }
    let tools;
    try {
      tools = normalizeToolOverrides(parsed.tools);
    } catch (err) {
      return failClosedCapabilities(err.message || 'Capability policy tools map is invalid.');
    }
    return {
      exists: true,
      version: 1,
      fileRead: parsed.fileRead,
      fileWrite: parsed.fileWrite,
      allowExec: execCeiling && parsed.allowExec !== false,
      tools,
      updatedAt: typeof parsed.updatedAt === 'string' ? parsed.updatedAt : null,
      error: null,
    };
  } catch {
    return failClosedCapabilities('Capability policy JSON is unreadable or corrupted.');
  }
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

export function writeCapabilitiesSync(
  stateDir,
  patch,
  { configAllowExec = true, requirePrivateState = true, workspaceRoots } = {},
) {
  const resolvedState = assertWritableStateDir(stateDir, requirePrivateState);
  const roots = workspaceRoots ?? loadWorkspaceRootsFromStateConfig(resolvedState);
  const target = capabilityFilePath(resolvedState);
  assertConfigOutsideWorkspace(target, roots);
  const current = readCapabilitiesSync(resolvedState, { configAllowExec, workspaceRoots: roots });
  const execCeiling = configAllowExec === true;
  const base = current.error
    ? { fileRead: false, fileWrite: false, allowExec: false, tools: {} }
    : current;

  const nextFileRead = patch.fileRead !== undefined ? patch.fileRead : base.fileRead;
  const nextFileWrite = patch.fileWrite !== undefined ? patch.fileWrite : base.fileWrite;
  const requestedExec = patch.allowExec !== undefined ? patch.allowExec : base.allowExec;
  if (typeof nextFileRead !== 'boolean' || typeof nextFileWrite !== 'boolean' || typeof requestedExec !== 'boolean') {
    throw new Error('Capability toggles must be booleans.');
  }
  if (!execCeiling && patch.allowExec === true) {
    throw new Error('Command execution cannot be enabled when config.allowExec is false.');
  }

  let nextTools = { ...(base.tools || {}) };
  if (patch.tools !== undefined) {
    if (!patch.tools || typeof patch.tools !== 'object' || Array.isArray(patch.tools)) {
      throw new Error('Capability tools patch must be an object.');
    }
    for (const [name, enabled] of Object.entries(patch.tools)) {
      if (!Object.hasOwn(TOOL_CAPABILITY_GROUPS, name)) {
        throw new Error(`Unknown MCP tool: ${name}`);
      }
      if (typeof enabled !== 'boolean') {
        throw new Error(`Tool toggle for ${name} must be a boolean.`);
      }
      if (enabled === false) nextTools[name] = false;
      else delete nextTools[name];
    }
  }

  const next = {
    version: 1,
    fileRead: nextFileRead,
    fileWrite: nextFileWrite,
    allowExec: execCeiling && requestedExec,
    ...(Object.keys(nextTools).length ? { tools: nextTools } : {}),
    updatedAt: new Date().toISOString(),
  };

  const temp = path.join(resolvedState, `.capabilities-${crypto.randomUUID()}.tmp`);
  const fd = fs.openSync(
    temp,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0),
    0o600,
  );
  try {
    fs.writeFileSync(fd, JSON.stringify(next, null, 2) + '\n', 'utf8');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    if (process.platform !== 'win32') fs.chmodSync(temp, 0o600);
    fs.renameSync(temp, target);
  } catch (error) {
    fs.rmSync(temp, { force: true });
    throw error;
  }

  return {
    exists: true,
    ...next,
    tools: nextTools,
    error: null,
  };
}

export function isToolEnabled(toolName, policy, { configAllowExec = true } = {}) {
  const effectivePolicy = policy || defaultCapabilities(configAllowExec);
  if (effectivePolicy.error) {
    if (toolName === 'computer_context' || toolName === 'command_status' || toolName === 'stop_command') {
      if (toolName !== 'computer_context' && configAllowExec !== true) {
        return { enabled: false, capability: 'execControl', reason: 'Command execution is disabled by configuration.' };
      }
      return { enabled: true, capability: TOOL_CAPABILITY_GROUPS[toolName] };
    }
    return { enabled: false, capability: 'policyError', reason: 'Local capability policy is invalid; file and command tools are locked.' };
  }

  if (typeof toolName !== 'string' || !Object.hasOwn(TOOL_CAPABILITY_GROUPS, toolName)) {
    return { enabled: false, capability: 'unknown', reason: 'Unknown tool.' };
  }
  const group = TOOL_CAPABILITY_GROUPS[toolName];
  const checkIndividual = () => (effectivePolicy.tools?.[toolName] === false
    ? { enabled: false, capability: `tool:${toolName}`, reason: `Tool "${toolName}" is individually disabled in local AgentDock settings.` }
    : { enabled: true, capability: group });

  if (group === 'context') return checkIndividual();
  if (group === 'fileRead') {
    return effectivePolicy.fileRead
      ? checkIndividual()
      : { enabled: false, capability: 'fileRead', reason: 'File reading is disabled by local AgentDock capability settings.' };
  }
  if (group === 'fileWrite') {
    return effectivePolicy.fileWrite
      ? checkIndividual()
      : { enabled: false, capability: 'fileWrite', reason: 'File writing is disabled by local AgentDock capability settings.' };
  }
  if (group === 'execControl') {
    return configAllowExec === true
      ? checkIndividual()
      : { enabled: false, capability: group, reason: 'Command execution is disabled by configuration.' };
  }
  if (group === 'exec') {
    if (configAllowExec !== true || !effectivePolicy.allowExec) {
      return { enabled: false, capability: 'exec', reason: 'Command execution is disabled by local AgentDock capability settings.' };
    }
    if (!effectivePolicy.fileRead) {
      return { enabled: false, capability: 'fileRead', reason: 'File reading is disabled; container command access to /workspace is blocked.' };
    }
    return checkIndividual();
  }
  return { enabled: false, capability: group, reason: 'Tool is disabled.' };
}

export function filterToolsByCapabilities(tools, policy, { configAllowExec = true } = {}) {
  return tools.filter(tool => isToolEnabled(tool.name, policy, { configAllowExec }).enabled);
}
