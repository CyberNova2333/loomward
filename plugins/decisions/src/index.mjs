// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import { validateConsolePanelDecl } from '@loomward/shared';
import { createDecisionsServiceClient } from './service-manager.mjs';

export { contract } from './contract.mjs';
export { createDecisionsServiceClient } from './service-manager.mjs';

export const name = 'plugin-decisions';

export const DECISIONS_TOOLS = Object.freeze([
  Object.freeze({
    name: 'mcp__decisions__export_context',
    description: '[Decisions Ledger] Export structured human-agent governance decisions and constraints context (read-only).',
    scopes: Object.freeze(['computer:read']),
    inputSchema: {
      type: 'object',
      properties: {
        module: { type: 'string', description: 'Optional module filter.' },
        topic_id: { type: 'string', description: 'Optional specific topic ID.' },
        path: { type: 'string', description: 'Optional file path keyword filter.' },
      },
      required: [],
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }),
  Object.freeze({
    name: 'mcp__decisions__check_consistency',
    description: '[Decisions Ledger] Verify SQLite index, Markdown files, and metadata.json consistency (read-only).',
    scopes: Object.freeze(['computer:read']),
    inputSchema: { type: 'object', properties: {}, required: [] },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }),
  Object.freeze({
    name: 'mcp__decisions__record',
    description: '[Decisions Ledger] Create or update a decision topic with CAS expected_version optimistic locking and request_id idempotency (requires exact local human approval).',
    scopes: Object.freeze(['computer:read', 'computer:write']),
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['create', 'save'], description: 'Create a new topic or update an existing topic with CAS expected_version.' },
        topic_id: { type: 'string', description: 'Topic identifier (required for save, optional for create).' },
        expected_version: { type: 'integer', description: 'Expected topic version for CAS optimistic locking on save.' },
        request_id: { type: 'string', description: 'Stable idempotency request_id for safe retries.' },
        payload: {
          type: 'object',
          description: 'Topic data fields: title, workflow_state (discussing|pending|decided|deferred|superseded), decision_outcome (""|accepted|partially_accepted|rejected), implementation_state (not_started|in_progress|implemented|verified), new_user_opinion, new_agent_reply.',
        },
      },
      required: ['action', 'payload'],
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  }),
]);

const TOOL_MAP = new Map(DECISIONS_TOOLS.map(tool => [tool.name, tool]));

export function createDecisionsAdapterDescriptor() {
  return Object.freeze({
    id: 'decisions',
    boundary: 'out-of-process',
    axes: ['workflow_state', 'decision_outcome', 'implementation_state'],
    tools: DECISIONS_TOOLS.map(t => t.name),
    archiveBranch: 'archive/agent-decisions-dashboard',
  });
}

export function createDecisionsToolProvider({ client } = {}) {
  return Object.freeze({
    id: 'decisions',
    executionBoundary: 'out-of-process',
    ownsTool(toolName) {
      return TOOL_MAP.has(toolName);
    },
    getToolScopes() {
      const map = new Map();
      for (const tool of DECISIONS_TOOLS) {
        map.set(tool.name, [...tool.scopes]);
      }
      return map;
    },
    checkToolEnabled(toolName) {
      if (!TOOL_MAP.has(toolName)) {
        return { enabled: false, capability: 'decisions', reason: 'Unknown decisions ledger tool.' };
      }
      if (!client || client.isClosed()) {
        return { enabled: false, capability: 'decisions', reason: 'Decisions ledger service is unavailable.' };
      }
      return { enabled: true, capability: 'decisions' };
    },
    async listTools() {
      if (!client || client.isClosed()) return [];
      return DECISIONS_TOOLS.map(({ scopes: _scopes, ...def }) => structuredClone(def));
    },
    async callTool(toolName, args = {}, { signal } = {}) {
      if (!client || client.isClosed()) {
        return { content: [{ type: 'text', text: 'Decisions ledger service is closed.' }], isError: true };
      }
      try {
        if (toolName === 'mcp__decisions__export_context') {
          const data = await client.exportContext({
            module: args.module,
            topicId: args.topic_id,
            pathKeyword: args.path,
          }, { signal });
          return { content: [{ type: 'text', text: JSON.stringify(data) }], structuredContent: data };
        }
        if (toolName === 'mcp__decisions__check_consistency') {
          const data = await client.checkConsistency({ signal });
          return { content: [{ type: 'text', text: JSON.stringify(data) }], structuredContent: data };
        }
        if (toolName === 'mcp__decisions__record') {
          const res = await client.recordDecision({
            action: args.action || 'create',
            topicId: args.topic_id,
            expectedVersion: args.expected_version,
            requestId: args.request_id,
            payload: args.payload || {},
          }, { signal });
          const isError = res.status < 200 || res.status >= 300;
          return {
            content: [{ type: 'text', text: JSON.stringify(res.data ?? { status: res.status }) }],
            structuredContent: { httpStatus: res.status, ...(res.data && typeof res.data === 'object' ? res.data : {}) },
            ...(isError ? { isError: true } : {}),
          };
        }
        return { content: [{ type: 'text', text: `Unknown tool: ${toolName}` }], isError: true };
      } catch (err) {
        return { content: [{ type: 'text', text: err?.message || 'Decisions ledger invocation failed.' }], isError: true };
      }
    },
    health() {
      return { status: client && !client.isClosed() ? 'ready' : 'closed', executionBoundary: 'out-of-process' };
    },
    close: () => (client ? client.close() : Promise.resolve()),
  });
}

export async function apply(ctx, config = {}) {
  const client = config.client ?? createDecisionsServiceClient({
    baseUrl: config.baseUrl,
    pythonPath: config.pythonPath,
    configPath: config.configPath,
    host: config.host,
    port: config.port,
    spawnService: config.spawnService === true,
    timeoutMs: config.timeoutMs,
  });

  if (config.eagerStart === true) {
    await client.ensureRunning();
  }

  const provider = createDecisionsToolProvider({ client });
  const providerSlot = ctx.get('tool:provider@1');
  if (providerSlot) {
    providerSlot.register('decisions', provider);
  }

  const panelSlot = ctx.get('console:panel@1');
  if (panelSlot) {
    panelSlot.register('decisions', validateConsolePanelDecl({
      id: 'decisions',
      title: '人机决策台账',
      subtitle: '独立 Python + SQLite 回环台账（三轴状态治理 · CAS 乐观锁 · 幂等回执）',
      category: 'integrations',
      order: 25,
      executionBoundary: 'out-of-process',
      async getSnapshot() {
        try {
          const [statusData, topicsData] = await Promise.all([
            client.getStatus(),
            client.listTopics(),
          ]);
          const topics = Array.isArray(topicsData?.topics)
            ? topicsData.topics
            : Array.isArray(topicsData) ? topicsData : [];
          const consistent = statusData?.consistency?.consistent === true;
          const url = client.getBaseUrl();
          return {
            status: consistent ? 'ok' : 'warn',
            summary: [
              { label: '一致性', value: consistent ? '一致' : '待核查', tone: consistent ? 'ok' : 'warn' },
              { label: '决策议题', value: String(topics.length), tone: 'info' },
              { label: '隔离模式', value: 'out-of-process', tone: 'ok' },
            ],
            table: {
              columns: ['议题 ID', '标题', '流程状态', '版本'],
              rows: topics.slice(0, 10).map(item => [
                String(item.id || ''),
                String(item.title || ''),
                String(item.lifecycle_state || item.status || ''),
                `v${item.version ?? 1}`,
              ]),
            },
            ...(url ? { links: [{ label: '打开独立决策台账', href: url }] } : {}),
          };
        } catch {
          return {
            status: 'idle',
            summary: [{ label: '服务状态', value: '未连接或待启动', tone: 'warn' }],
            notices: [{ tone: 'info', text: '配置 decisions 回环服务后即可自动同步只读台账状态。' }],
          };
        }
      },
    }));
  }

  ctx.effect(() => () => {
    void client.close();
  }, 'decisions:close');
}
