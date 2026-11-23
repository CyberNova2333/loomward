// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import path from 'node:path';
import { validateConsolePanelDecl } from '@loomward/shared';
import { createExternalMcpHub, probeMcpServer } from '../../../local/mcp-client.mjs';
import { parseExternalToolName } from '../../../local/mcp-registry.mjs';
import { isValidExternalToolName } from '../../../local/request-policy.mjs';

export { contract } from './contract.mjs';
export { createExternalMcpHub, probeMcpServer };

export const name = 'plugin-mcp-hub';

// First-party extension tool namespaces must never be shadowed or hijacked by external mcp-hub servers.
const RESERVED_FIRST_PARTY_SERVERS = new Set(['decisions', 'cloudforge']);

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
      if (!effectiveHub || closed || !isValidExternalToolName(toolName)) return false;
      const parsed = parseExternalToolName(toolName);
      if (!parsed || RESERVED_FIRST_PARTY_SERVERS.has(parsed.serverId)) return false;
      if (typeof effectiveHub.ownsTool === 'function') {
        return Boolean(effectiveHub.ownsTool(toolName));
      }
      if (typeof effectiveHub.getConfiguredToolScopes === 'function') {
        const scopes = effectiveHub.getConfiguredToolScopes();
        if (scopes instanceof Map && scopes.has(toolName)) return true;
      }
      if (typeof effectiveHub.checkToolEnabled === 'function') {
        const check = effectiveHub.checkToolEnabled(toolName);
        if (check?.enabled) return true;
        if (typeof check?.reason === 'string' && /is not configured\.$/i.test(check.reason)) {
          return false;
        }
        return Boolean(check?.reason);
      }
      return false;
    },
    getToolScopes() {
      if (!effectiveHub || closed) return new Map();
      const raw = effectiveHub.getConfiguredToolScopes();
      if (!(raw instanceof Map)) return new Map();
      const filtered = new Map();
      for (const [toolName, scopes] of raw.entries()) {
        const parsed = parseExternalToolName(toolName);
        if (!parsed || RESERVED_FIRST_PARTY_SERVERS.has(parsed.serverId)) continue;
        filtered.set(toolName, scopes);
      }
      return filtered;
    },
    checkToolEnabled(toolName) {
      if (!effectiveHub || closed) {
        return { enabled: false, capability: 'external_mcp', reason: 'External MCP support is unavailable.' };
      }
      const parsed = parseExternalToolName(toolName);
      if (!parsed || RESERVED_FIRST_PARTY_SERVERS.has(parsed.serverId)) {
        return { enabled: false, capability: 'external_mcp', reason: 'Tool belongs to a reserved platform plugin namespace.' };
      }
      return effectiveHub.checkToolEnabled(toolName);
    },
    async listTools(options = {}) {
      if (!effectiveHub || closed) return [];
      const listed = await effectiveHub.listTools(options);
      if (!Array.isArray(listed)) return [];
      return listed.filter(tool => {
        const parsed = parseExternalToolName(tool?.name);
        return Boolean(parsed && !RESERVED_FIRST_PARTY_SERVERS.has(parsed.serverId));
      });
    },
    async callTool(toolName, args = {}, options = {}) {
      if (!effectiveHub || closed) {
        return { content: [{ type: 'text', text: 'External MCP support is unavailable.' }], isError: true };
      }
      const parsed = parseExternalToolName(toolName);
      if (!parsed || RESERVED_FIRST_PARTY_SERVERS.has(parsed.serverId)) {
        return { content: [{ type: 'text', text: 'Tool belongs to a reserved platform plugin namespace.' }], isError: true };
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
  const panelSlot = ctx.get('console:panel@1');
  if (panelSlot) {
    panelSlot.register('mcp-hub', validateConsolePanelDecl({
      id: 'mcp-hub',
      title: '第三方 MCP 聚合中心',
      subtitle: '进程外 stdio / Streamable HTTP 外部 MCP 工具聚合与命名空间隔离',
      category: 'tools',
      order: 30,
      executionBoundary: 'out-of-process',
      getSnapshot() {
        const h = provider.health();
        const toolCount = provider.getToolScopes().size;
        return {
          status: h.status === 'ready' ? 'ok' : 'idle',
          summary: [
            { label: '运行状态', value: h.status, tone: h.status === 'ready' ? 'ok' : 'neutral' },
            { label: '已登记工具', value: String(toolCount), tone: 'info' },
            { label: '隔离边界', value: 'out-of-process', tone: 'ok' },
          ],
          notices: [
            { tone: 'info', text: '第三方 MCP 服务器配置与启停仅允许在 Ring 2 Trust Origin 中修改。' },
          ],
        };
      },
    }));
  }
  ctx.effect(() => async () => {
    await provider.close();
  }, 'mcp-hub:close');
}
