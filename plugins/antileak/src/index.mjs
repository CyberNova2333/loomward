// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import path from 'node:path';
import {
  buildContentInspectRequest,
  validateConsolePanelDecl,
} from '@loomward/shared';
import { MAX_INPUT_BYTES, createAntileakEngineRunner } from './runner.mjs';

export { contract } from './contract.mjs';
export { createAntileakEngineRunner } from './runner.mjs';

export const name = 'plugin-antileak';

const DEFAULT_EXEMPT_TOOLS = new Set(['computer_context', 'command_status', 'stop_command']);
const MAX_RECENT_BLOCKS = 20;
const MAX_EXTRACT_DEPTH = 32;

export function createAntileakAdapterDescriptor() {
  return Object.freeze({
    id: 'antileak',
    boundary: 'out-of-process',
    rules: ['R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7'],
    archiveBranch: 'archive/claude-code-antileak-hooks',
    engineScript: 'plugins/antileak/engine/check.py',
  });
}

export function extractInspectablePayload(_toolName, args) {
  if (args === null || args === undefined) {
    return { text: '', overflow: false, reason: null };
  }
  const parts = [];
  const seen = new WeakSet();
  let totalBytes = 0;
  let overflow = false;
  let overflowReason = null;

  const pushString = str => {
    if (overflow) return;
    const trimmed = str.trim();
    if (!trimmed) return;
    const bytes = Buffer.byteLength(trimmed, 'utf8');
    if (totalBytes + bytes > MAX_INPUT_BYTES) {
      overflow = true;
      overflowReason = 'ANTILEAK-INPUT-TOO-LARGE';
      return;
    }
    parts.push(trimmed);
    totalBytes += bytes + 1;
  };

  const collect = (value, depth) => {
    if (overflow) return;
    if (depth > MAX_EXTRACT_DEPTH) {
      overflow = true;
      overflowReason = 'ANTILEAK-DEPTH-EXCEEDED';
      return;
    }
    if (typeof value === 'string') {
      pushString(value);
      return;
    }
    if (typeof value === 'number' || typeof value === 'boolean') {
      return;
    }
    if (value instanceof Uint8Array || ArrayBuffer.isView(value)) {
      if (value.byteLength > MAX_INPUT_BYTES) {
        overflow = true;
        overflowReason = 'ANTILEAK-INPUT-TOO-LARGE';
        return;
      }
      pushString(Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString('utf8'));
      return;
    }
    if (!value || typeof value !== 'object') return;
    if (seen.has(value)) return;
    seen.add(value);
    if (Array.isArray(value)) {
      for (const item of value) {
        if (overflow) break;
        collect(item, depth + 1);
      }
      return;
    }
    for (const [k, v] of Object.entries(value)) {
      if (overflow) break;
      pushString(k);
      if (overflow) break;
      collect(v, depth + 1);
    }
  };

  collect(args, 0);
  return {
    text: overflow ? '' : parts.join('\n'),
    overflow,
    reason: overflowReason,
  };
}

export function extractInspectableText(toolName, args) {
  const res = extractInspectablePayload(toolName, args);
  return res.text;
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

  const recordBlock = (toolName, ruleId, isFailClosed) => {
    if (isFailClosed) stats.failClosed += 1;
    else stats.blocked += 1;
    stats.recentBlocks.unshift({
      time: new Date().toISOString(),
      tool: toolName,
      ruleId: ruleId || 'ANTILEAK',
      category: isFailClosed ? 'fail-closed' : 'violation',
    });
    if (stats.recentBlocks.length > MAX_RECENT_BLOCKS) {
      stats.recentBlocks.length = MAX_RECENT_BLOCKS;
    }
  };

  const invokeSlot = ctx.get('tool:invoke@1');
  if (invokeSlot) {
    // Register with order: 10 so offline R1-R7 anti-leak always executes BEFORE any external LLM moderation plugin.
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
      stats.inspected += 1;
      const extracted = extractInspectablePayload(req.toolName, req.payload);
      if (extracted.overflow) {
        const ruleId = extracted.reason || 'ANTILEAK-INPUT-TOO-LARGE';
        recordBlock(req.toolName, ruleId, true);
        return {
          ...input,
          blocked: true,
          code: 'ANTILEAK_FAIL_CLOSED',
          rule: ruleId,
          reason: 'Tool payload exceeds offline anti-leak size or nesting depth limit (fail-closed).',
        };
      }

      const verdict = await runner.inspectText(extracted.text, { signal: input.signal });
      if (verdict.decision === 'allow') {
        stats.passed += 1;
        return input;
      }
      const isFailClosed = verdict.failClosed === true || verdict.categories.includes('antileak.fail_closed');
      recordBlock(req.toolName, verdict.ruleId || 'ANTILEAK', isFailClosed);
      return {
        ...input,
        blocked: true,
        code: isFailClosed ? 'ANTILEAK_FAIL_CLOSED' : 'ANTILEAK_BLOCKED',
        rule: verdict.ruleId || 'ANTILEAK',
        reason: verdict.reason || 'Blocked by offline anti-leak guardrail.',
      };
    }, { order: 10 });
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

  ctx.effect(() => async () => {
    if (typeof runner.close === 'function') {
      await runner.close();
    }
  }, 'antileak:close');
}
