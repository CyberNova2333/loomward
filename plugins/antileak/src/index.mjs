// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import path from 'node:path';
import {
  buildContentInspectRequest,
  validateConsolePanelDecl,
} from '@loomward/shared';
import { createAntileakEngineRunner } from './runner.mjs';

export { contract } from './contract.mjs';
export { createAntileakEngineRunner } from './runner.mjs';

export const name = 'plugin-antileak';

const DEFAULT_EXEMPT_TOOLS = new Set(['computer_context', 'command_status', 'stop_command']);
const MAX_RECENT_BLOCKS = 20;

export function createAntileakAdapterDescriptor() {
  return Object.freeze({
    id: 'antileak',
    boundary: 'out-of-process',
    rules: ['R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7'],
    archiveBranch: 'archive/claude-code-antileak-hooks',
    engineScript: 'plugins/antileak/engine/check.py',
  });
}

export function extractInspectableText(toolName, args) {
  if (!args || typeof args !== 'object') return '';
  const parts = [];
  const collect = value => {
    if (typeof value === 'string') {
      if (value.trim()) parts.push(value);
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value) collect(item);
      return;
    }
    if (value && typeof value === 'object') {
      for (const v of Object.values(value)) collect(v);
    }
  };
  collect(args);
  return parts.join('\n');
}

export function apply(ctx, config = {}) {
  const cachePath = config.cachePath
    || (config.stateDir ? path.join(config.stateDir, 'antileak', 'private-repos.json') : null);
  const runner = config.runner ?? createAntileakEngineRunner({
    pythonPath: config.pythonPath,
    policyPath: config.policyPath,
    cachePath,
    timeoutMs: config.timeoutMs ?? 5000,
  });

  const stats = {
    inspected: 0,
    passed: 0,
    blocked: 0,
    failClosed: 0,
    recentBlocks: [],
  };

  const invokeSlot = ctx.get('tool:invoke@1');
  if (invokeSlot) {
    invokeSlot.hook('before', async input => {
      if (!config.inspectControlTools && DEFAULT_EXEMPT_TOOLS.has(input.toolName)) {
        return input;
      }
      const req = buildContentInspectRequest({
        stage: 'input',
        requestId: input.requestId,
        toolName: input.toolName,
        providerName: input.providerName,
        payload: input.body?.params?.arguments ?? {},
      });
      const text = extractInspectableText(req.toolName, req.payload);
      stats.inspected += 1;
      const verdict = await runner.inspectText(text, { signal: input.signal });
      if (verdict.decision === 'allow') {
        stats.passed += 1;
        return input;
      }
      const isFailClosed = verdict.categories.includes('antileak.fail_closed');
      if (isFailClosed) stats.failClosed += 1;
      else stats.blocked += 1;
      stats.recentBlocks.unshift({
        time: new Date().toISOString(),
        tool: req.toolName,
        ruleId: verdict.ruleId || 'ANTILEAK',
        category: isFailClosed ? 'fail-closed' : 'violation',
      });
      if (stats.recentBlocks.length > MAX_RECENT_BLOCKS) {
        stats.recentBlocks.length = MAX_RECENT_BLOCKS;
      }
      return {
        ...input,
        blocked: true,
        code: isFailClosed ? 'ANTILEAK_FAIL_CLOSED' : 'ANTILEAK_BLOCKED',
        rule: verdict.ruleId || 'ANTILEAK',
        reason: verdict.reason || 'Blocked by offline anti-leak guardrail.',
      };
    });
  }

  const panelSlot = ctx.get('console:panel@1');
  if (panelSlot) {
    panelSlot.register('antileak', validateConsolePanelDecl({
      id: 'antileak',
      title: 'R1–R7 防泄漏护栏',
      subtitle: '离线子进程参数预检与私有名单缓存健康监控（fail-closed）',
      category: 'security',
      order: 15,
      executionBoundary: 'out-of-process',
      getSnapshot() {
        const cache = runner.inspectCacheHealth();
        const status = cache.status === 'fresh'
          ? (stats.blocked > 0 ? 'warn' : 'ok')
          : 'error';
        const notices = [];
        if (cache.status !== 'fresh') {
          notices.push({
            tone: 'err',
            text: `私有仓动态缓存状态为 ${cache.status}：离线护栏当前处于 fail-closed 阻断态，请在本机刷新私有缓存。`,
          });
        }
        return {
          status,
          summary: [
            { label: '缓存状态', value: cache.status, tone: cache.status === 'fresh' ? 'ok' : 'err' },
            { label: '已预检', value: String(stats.inspected), tone: 'info' },
            { label: '规则阻断', value: String(stats.blocked), tone: stats.blocked > 0 ? 'warn' : 'ok' },
            { label: '故障闭锁', value: String(stats.failClosed), tone: stats.failClosed > 0 ? 'err' : 'ok' },
          ],
          table: {
            columns: ['时间', '工具', '规则码', '类型'],
            rows: stats.recentBlocks.slice(0, 10).map(item => [item.time, item.tool, item.ruleId, item.category]),
          },
          notices,
        };
      },
    }));
  }
}
