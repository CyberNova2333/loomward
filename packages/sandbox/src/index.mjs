// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import path from 'node:path';
import {
  SANDBOX_TOOLS,
  buildSandboxTools,
  createSandboxRuntime,
  defaultDockerContext,
  hostContainerIds,
  isCaseInsensitiveHost,
} from '../../../local/sandbox.mjs';
import {
  TOOL_CAPABILITY_GROUPS,
  defaultCapabilities,
  filterToolsByCapabilities,
  isToolEnabled,
  readCapabilitiesSync,
} from '../../../local/capabilities.mjs';
import { getToolScopes } from '../../../local/request-policy.mjs';

export { contract } from './contract.mjs';
export {
  SANDBOX_TOOLS,
  buildSandboxTools,
  createSandboxRuntime,
  defaultDockerContext,
  hostContainerIds,
  isCaseInsensitiveHost,
};

export const BUILTIN_SANDBOX_TOOLS = Object.freeze(Object.keys(TOOL_CAPABILITY_GROUPS));
const BUILTIN_SANDBOX_TOOL_SET = new Set(BUILTIN_SANDBOX_TOOLS);
const LOCKDOWN_EXEMPT_TOOLS = new Set(['command_status', 'stop_command']);

export function createSandboxToolProvider({
  runtime = null,
  stateDir = null,
  allowExec = true,
  allowOutbound = false,
  workspaceRoots,
} = {}) {
  let closed = false;
  const effectiveAllowExec = allowExec !== false;
  const staticTools = buildSandboxTools(allowOutbound === true);

  function isRuntimeLockedDown() {
    return typeof runtime?.isLockedDown === 'function' && runtime.isLockedDown() === true;
  }

  function readLivePolicy() {
    if (!stateDir) return defaultCapabilities(effectiveAllowExec);
    return readCapabilitiesSync(stateDir, {
      configAllowExec: effectiveAllowExec,
      workspaceRoots,
    });
  }

  return Object.freeze({
    id: 'sandbox-docker',
    executionBoundary: 'in-process-root',
    ownsTool(toolName) {
      return typeof toolName === 'string' && BUILTIN_SANDBOX_TOOL_SET.has(toolName);
    },
    getToolScopes() {
      const map = new Map();
      for (const toolName of BUILTIN_SANDBOX_TOOLS) {
        map.set(toolName, getToolScopes(toolName));
      }
      return map;
    },
    checkToolEnabled(toolName) {
      if (closed) {
        return { enabled: false, capability: 'closed', reason: 'Sandbox tool provider is closed.' };
      }
      if (!BUILTIN_SANDBOX_TOOL_SET.has(toolName)) {
        return { enabled: false, capability: 'unknown', reason: 'Unknown sandbox tool.' };
      }
      if (isRuntimeLockedDown() && !LOCKDOWN_EXEMPT_TOOLS.has(toolName)) {
        return {
          enabled: false,
          capability: 'cleanup_failed',
          reason: 'Container cleanup could not be confirmed; new file and command operations are locked down.',
        };
      }
      return isToolEnabled(toolName, readLivePolicy(), { configAllowExec: effectiveAllowExec });
    },
    async listTools(options = {}) {
      if (closed) return [];
      if (runtime && typeof runtime.handleRpc === 'function') {
        const res = await runtime.handleRpc({ jsonrpc: '2.0', id: 'list', method: 'tools/list' }, options);
        if (Array.isArray(res?.result?.tools)) return res.result.tools;
      }
      return filterToolsByCapabilities(staticTools, readLivePolicy(), { configAllowExec: effectiveAllowExec });
    },
    async callTool(toolName, args = {}, options = {}) {
      if (closed) {
        throw new Error('Sandbox Docker runtime is closed.');
      }
      if (!runtime || typeof runtime.handleRpc !== 'function') {
        throw new Error('Sandbox Docker runtime is not initialized.');
      }
      const res = await runtime.handleRpc(
        { jsonrpc: '2.0', id: options?.rpcId ?? null, method: 'tools/call', params: { name: toolName, arguments: args ?? {} } },
        options,
      );
      if (res?.error) {
        const err = new Error(res.error.message || 'Sandbox tool invocation failed.');
        err.rpcCode = res.error.code;
        throw err;
      }
      return res?.result;
    },
    async handleRpc(body, options = {}) {
      if (closed) {
        throw new Error('Sandbox Docker runtime is closed.');
      }
      if (!runtime || typeof runtime.handleRpc !== 'function') {
        throw new Error('Sandbox Docker runtime is not initialized.');
      }
      return runtime.handleRpc(body, options);
    },
    health() {
      const locked = isRuntimeLockedDown();
      return {
        status: closed ? 'closed' : locked ? 'locked' : runtime ? 'ready' : 'standby',
        lockedDown: locked,
        allowExec: effectiveAllowExec,
        allowOutbound: allowOutbound === true,
      };
    },
    async close() {
      if (closed) return;
      closed = true;
      if (runtime && typeof runtime.close === 'function') {
        await runtime.close();
      }
    },
  });
}

export const name = 'sandbox';

export async function apply(ctx, config = {}) {
  const effectiveStateDir = config.stateDir ?? config.sandboxConfig?.stateDir ?? null;
  const effectiveAllowExec = config.allowExec ?? config.sandboxConfig?.allowExec ?? true;
  const effectiveAllowOutbound = config.allowOutbound ?? config.sandboxConfig?.sandbox?.allowOutbound ?? false;
  const effectiveRoots = config.workspaceRoots ?? config.sandboxConfig?.roots;

  let runtime = config.runtime ?? null;
  if (!runtime && config.sandboxConfig?.sandbox?.enabled === true) {
    const mergedConfig = {
      ...config.sandboxConfig,
      ...(effectiveStateDir ? { stateDir: effectiveStateDir } : {}),
      allowExec: effectiveAllowExec,
      ...(effectiveStateDir && !config.sandboxConfig.auditFile
        ? { auditFile: path.join(effectiveStateDir, 'audit.jsonl') }
        : {}),
    };
    runtime = await createSandboxRuntime(mergedConfig);
  }
  const provider = createSandboxToolProvider({
    runtime,
    stateDir: effectiveStateDir,
    allowExec: effectiveAllowExec,
    allowOutbound: effectiveAllowOutbound,
    workspaceRoots: effectiveRoots,
  });

  const providerSlot = ctx.get('tool:provider@1');
  if (providerSlot) {
    providerSlot.register('sandbox-docker', provider);
  }

  ctx.effect(() => async () => {
    await provider.close();
  }, 'sandbox:close');

  ctx.provide('sandbox:docker', Object.freeze({
    status: runtime ? 'ready' : 'standby',
    legacyEntry: 'local/sandbox.mjs',
    health: () => provider.health(),
  }));
}
