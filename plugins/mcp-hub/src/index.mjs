// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import path from 'node:path';
import { createExternalMcpHub, probeMcpServer } from '../../../local/mcp-client.mjs';
import { isValidExternalToolName } from '../../../local/request-policy.mjs';

export { contract } from './contract.mjs';
export { createExternalMcpHub, probeMcpServer };

export const name = 'plugin-mcp-hub';

export function createMcpHubDescriptor() {
  return Object.freeze({
    id: 'mcp-hub',
    boundary: 'out-of-process',
    transports: ['stdio', 'streamable-http'],
    legacyEntries: ['local/mcp-registry.mjs', 'local/mcp-client.mjs'],
  });
}

export function createMcpHubToolProvider({
  hub = null,
  stateDir = null,
  workspaceRoots,
  auditFile,
  blockedOrigins = [],
} = {}) {
  const effectiveHub = hub ?? (
    stateDir
      ? createExternalMcpHub({
          stateDir,
          workspaceRoots,
          auditFile: auditFile || path.join(stateDir, 'audit.jsonl'),
          blockedOrigins,
        })
      : null
  );
  let closed = false;

  return Object.freeze({
    id: 'mcp-hub',
    executionBoundary: 'out-of-process',
    ownsTool(toolName) {
      return isValidExternalToolName(toolName);
    },
    getToolScopes() {
      if (!effectiveHub || closed) return new Map();
      return effectiveHub.getConfiguredToolScopes();
    },
    checkToolEnabled(toolName) {
      if (!effectiveHub || closed) {
        return { enabled: false, capability: 'external_mcp', reason: 'External MCP support is unavailable.' };
      }
      return effectiveHub.checkToolEnabled(toolName);
    },
    async listTools(options = {}) {
      if (!effectiveHub || closed) return [];
      return effectiveHub.listTools(options);
    },
    async callTool(toolName, args = {}, options = {}) {
      if (!effectiveHub || closed) {
        return { content: [{ type: 'text', text: 'External MCP support is unavailable.' }], isError: true };
      }
      return effectiveHub.callTool(toolName, args, options);
    },
    health() {
      return {
        status: closed ? 'closed' : effectiveHub ? 'ready' : 'standby',
        executionBoundary: 'out-of-process',
      };
    },
    async close() {
      if (closed) return;
      closed = true;
      if (effectiveHub && typeof effectiveHub.close === 'function') {
        await effectiveHub.close();
      }
    },
  });
}

export function apply(ctx, config = {}) {
  const provider = createMcpHubToolProvider(config);
  const providerSlot = ctx.get('tool:provider@1');
  if (providerSlot) {
    providerSlot.register('mcp-hub', provider);
  }
  ctx.effect(() => () => {
    void provider.close();
  }, 'mcp-hub:close');
}
