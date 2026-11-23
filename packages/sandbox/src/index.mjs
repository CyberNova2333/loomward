// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
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
      if (!BUILTIN_SANDBOX_TOOL_SET.has(toolName)) {
        return { enabled: false, capability: 'unknown', reason: 'Unknown sandbox tool.' };
      }
      return isToolEnabled(toolName, readLivePolicy(), { configAllowExec: effectiveAllowExec });
    },
    async listTools(options = {}) {
      if (runtime && typeof runtime.handleRpc === 'function') {
        const res = await runtime.handleRpc({ jsonrpc: '2.0', id: 'list', method: 'tools/list' }, options);
        if (Array.isArray(res?.result?.tools)) return res.result.tools;
      }
      return filterToolsByCapabilities(staticTools, readLivePolicy(), { configAllowExec: effectiveAllowExec });
    },
    async callTool(toolName, args = {}, options = {}) {
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
      if (!runtime || typeof runtime.handleRpc !== 'function') {
        throw new Error('Sandbox Docker runtime is not initialized.');
      }
      return runtime.handleRpc(body, options);
    },
    health() {
      return {
        status: closed ? 'closed' : runtime ? 'ready' : 'standby',
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
  let runtime = config.runtime ?? null;
  if (!runtime && config.sandboxConfig?.sandbox?.enabled === true) {
    runtime = await createSandboxRuntime(config.sandboxConfig);
  }
  const provider = createSandboxToolProvider({
    runtime,
    stateDir: config.stateDir ?? config.sandboxConfig?.stateDir ?? null,
    allowExec: config.allowExec ?? config.sandboxConfig?.allowExec ?? true,
    allowOutbound: config.allowOutbound ?? config.sandboxConfig?.sandbox?.allowOutbound ?? false,
    workspaceRoots: config.workspaceRoots ?? config.sandboxConfig?.roots,
  });

  const providerSlot = ctx.get('tool:provider@1');
  if (providerSlot) {
    providerSlot.register('sandbox-docker', provider);
  }

  ctx.effect(() => () => {
    void provider.close();
  }, 'sandbox:close');

  ctx.provide('sandbox:docker', Object.freeze({
    status: runtime ? 'ready' : 'standby',
    legacyEntry: 'local/sandbox.mjs',
    provider,
    runtime,
    close: () => provider.close(),
  }));
}
