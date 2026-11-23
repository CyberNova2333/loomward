// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Out-of-process read-only telemetry adapter for standalone ModelBridge (respects 4-state secret isolation & 12s timeout budget).
import { validateConsolePanelDecl } from '@loomward/shared';
import {
  DEFAULT_MAX_RESPONSE_BYTES,
  assertSafeIntegrationOrigin,
  fetchBounded,
} from './network.mjs';

export const MODELBRIDGE_MAX_TIMEOUT_MS = 12_000;
const SNAPSHOT_CACHE_TTL_MS = 5_000;
const SECRET_FIELD_HINT =
  /(token|secret|password|passphrase|api[_-]?key|private[_-]?key|access[_-]?key|authorization|cookie|credential|jwt|bearer|session[_-]?id)/i;
const INLINE_SECRET_RE = /\b(Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{8,}/gi;
const INLINE_KEY_PREFIX_RE = /\b(?:sk|rk|pk|mb|ghp|gho|ghs|ghu|ghr|github_pat)_[A-Za-z0-9_-]{12,}\b/g;
const PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function sanitizeTelemetryValue(value, depth = 0) {
  if (depth > 3 || value === null || value === undefined) return null;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    return value
      .replace(INLINE_SECRET_RE, '$1 [REDACTED]')
      .replace(INLINE_KEY_PREFIX_RE, '[REDACTED_KEY]')
      .slice(0, 120);
  }
  if (Array.isArray(value)) {
    return value.slice(0, 16).map(item => sanitizeTelemetryValue(item, depth + 1));
  }
  if (typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      if (PROTO_KEYS.has(key) || SECRET_FIELD_HINT.test(key)) continue;
      out[key] = sanitizeTelemetryValue(item, depth + 1);
    }
    return out;
  }
  return null;
}

export function createModelBridgeClient({
  origin,
  getApiKey = null,
  fetchImpl = globalThis.fetch,
  allowLoopbackHttp = false,
  allowPrivateNetwork = false,
  blockedOrigins = [],
  dnsLookup = null,
  timeoutMs = 8_000,
  maxBytes = DEFAULT_MAX_RESPONSE_BYTES,
} = {}) {
  const safeOrigin = assertSafeIntegrationOrigin(origin, {
    allowLoopbackHttp,
    allowPrivateNetwork,
    blockedOrigins,
    label: 'ModelBridge',
  });
  const requestedTimeout = Number(timeoutMs);
  if (!Number.isFinite(requestedTimeout) || requestedTimeout < 50 || requestedTimeout > MODELBRIDGE_MAX_TIMEOUT_MS) {
    throw new RangeError(`ModelBridge timeoutMs must be within 50..${MODELBRIDGE_MAX_TIMEOUT_MS}ms.`);
  }
  const boundedTimeout = Math.floor(requestedTimeout);

  let cachedSnapshot = null;
  let cachedAt = 0;
  let inflightSnapshot = null;

  async function probeStatus({ signal = null, timeoutOverrideMs = null } = {}) {
    const effTimeout = timeoutOverrideMs ? Math.min(boundedTimeout, timeoutOverrideMs) : boundedTimeout;
    try {
      const res = await fetchBounded(`${safeOrigin}/api/auth/status`, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        timeoutMs: effTimeout,
        maxBytes,
        fetchImpl,
        signal,
        allowLoopbackHttp,
        allowPrivateNetwork,
        dnsLookup,
      });
      if (!res.ok) {
        return { reachable: false, isSetup: false, status: res.status, latencyMs: res.latencyMs, error: `HTTP ${res.status}` };
      }
      const parsed = JSON.parse(res.text);
      return {
        reachable: true,
        isSetup: Boolean(parsed?.isSetup),
        status: res.status,
        latencyMs: res.latencyMs,
        error: null,
      };
    } catch (error) {
      return {
        reachable: false,
        isSetup: false,
        status: 0,
        latencyMs: 0,
        error: error.message || 'ModelBridge status probe failed.',
      };
    }
  }

  async function fetchUsageSummary({ signal = null, timeoutOverrideMs = null } = {}) {
    const effTimeout = timeoutOverrideMs ? Math.min(boundedTimeout, timeoutOverrideMs) : boundedTimeout;
    try {
      const res = await fetchBounded(`${safeOrigin}/api/usage/summary`, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        timeoutMs: effTimeout,
        maxBytes,
        fetchImpl,
        signal,
        allowLoopbackHttp,
        allowPrivateNetwork,
        dnsLookup,
      });
      if (!res.ok) {
        return { ok: false, status: res.status, latencyMs: res.latencyMs, summary: null, error: `HTTP ${res.status}` };
      }
      const parsed = JSON.parse(res.text);
      return {
        ok: true,
        status: res.status,
        latencyMs: res.latencyMs,
        summary: sanitizeTelemetryValue(parsed),
        error: null,
      };
    } catch (error) {
      return {
        ok: false,
        status: 0,
        latencyMs: 0,
        summary: null,
        error: error.message || 'ModelBridge usage summary unavailable.',
      };
    }
  }

  async function listModels({ signal = null, timeoutOverrideMs = null } = {}) {
    if (typeof getApiKey !== 'function') {
      return { queried: false, ok: false, count: 0, models: [], error: null };
    }
    const effTimeout = timeoutOverrideMs ? Math.min(boundedTimeout, timeoutOverrideMs) : boundedTimeout;
    try {
      const key = await getApiKey();
      if (typeof key !== 'string' || !key.trim()) {
        return { queried: false, ok: false, count: 0, models: [], error: null };
      }
      const res = await fetchBounded(`${safeOrigin}/v1/models`, {
        method: 'GET',
        headers: {
          Accept: 'application/json',
          Authorization: `Bearer ${key.trim()}`,
        },
        timeoutMs: effTimeout,
        maxBytes,
        fetchImpl,
        signal,
        allowLoopbackHttp,
        allowPrivateNetwork,
        dnsLookup,
      });
      if (!res.ok) {
        return { queried: true, ok: false, count: 0, models: [], status: res.status, error: `HTTP ${res.status}` };
      }
      const parsed = JSON.parse(res.text);
      const list = Array.isArray(parsed?.data) ? parsed.data : [];
      const models = list
        .filter(item => item && typeof item.id === 'string')
        .slice(0, 64)
        .map(item => ({
          id: item.id.slice(0, 100),
          ownedBy: typeof item.owned_by === 'string' ? item.owned_by.slice(0, 40) : 'unknown',
        }));
      return { queried: true, ok: true, count: list.length, models, status: res.status, error: null };
    } catch {
      return {
        queried: true,
        ok: false,
        count: 0,
        models: [],
        error: 'ModelBridge model catalog query failed.',
      };
    }
  }

  async function getSnapshot({ refresh = false, signal = null, timeoutOverrideMs = null } = {}) {
    if (!refresh && cachedSnapshot && Date.now() - cachedAt < SNAPSHOT_CACHE_TTL_MS) {
      return cachedSnapshot;
    }
    if (!refresh && inflightSnapshot) {
      return inflightSnapshot;
    }
    const run = (async () => {
      try {
        const opts = { signal, timeoutOverrideMs };
        const [status, usage, catalog] = await Promise.all([
          probeStatus(opts),
          fetchUsageSummary(opts),
          listModels(opts),
        ]);
        const snap = Object.freeze({
          origin: safeOrigin,
          timeoutMs: boundedTimeout,
          status,
          usage,
          catalog,
        });
        cachedSnapshot = snap;
        cachedAt = Date.now();
        return snap;
      } finally {
        inflightSnapshot = null;
      }
    })();
    inflightSnapshot = run;
    return run;
  }

  return Object.freeze({
    origin: safeOrigin,
    timeoutMs: boundedTimeout,
    probeStatus,
    fetchUsageSummary,
    listModels,
    getSnapshot,
  });
}

export function createModelBridgePanel(client, { origin = null } = {}) {
  return validateConsolePanelDecl({
    id: 'modelbridge',
    title: 'ModelBridge · 模型网关状态',
    subtitle: '独立维护的多协议边缘模型网关（只读观测，保留四态密钥隔离与 12s 超时边界）',
    order: 45,
    async getSnapshot(context = {}) {
      if (!client) {
        return {
          status: 'idle',
          summary: [
            { label: '网关状态', value: '未配置', tone: 'neutral' },
            { label: '超时上限', value: `${MODELBRIDGE_MAX_TIMEOUT_MS}ms`, tone: 'neutral' },
          ],
          notices: [
            { tone: 'info', text: '未配置 ModelBridge 网关地址；本体保持独立仓库维护，管理员密钥不进入 LoomWard。' },
          ],
        };
      }
      const snap = await client.getSnapshot({
        signal: context?.signal || null,
        timeoutOverrideMs: 1500,
      });
      const online = snap.status.reachable;
      const summary = [
        { label: '网关连通', value: online ? (snap.status.isSetup ? '在线已初始化' : '在线未初始化') : '不可达', tone: online ? 'ok' : 'err' },
        { label: '探测延迟', value: online ? `${snap.status.latencyMs}ms` : '—', tone: 'neutral' },
        { label: '用量摘要', value: snap.usage.ok ? '已同步' : '不可用', tone: snap.usage.ok ? 'ok' : 'warn' },
        { label: '可见模型数', value: snap.catalog.queried ? String(snap.catalog.count) : '未查询', tone: 'neutral' },
      ];
      const rows = [
        ['网关地址', snap.origin],
        ['超时预算', `${snap.timeoutMs}ms (上限 ${MODELBRIDGE_MAX_TIMEOUT_MS}ms)`],
        ['管理面隔离', '仅只读公开状态与受限模型目录，不接触 ADMIN_PASSWORD'],
      ];
      if (snap.usage.ok && snap.usage.summary && typeof snap.usage.summary === 'object') {
        const keys = Object.keys(snap.usage.summary).slice(0, 6);
        for (const key of keys) {
          const val = snap.usage.summary[key];
          if (typeof val === 'number' || typeof val === 'string' || typeof val === 'boolean') {
            rows.push([`usage.${key}`, String(val)]);
          }
        }
      }
      const mainTable = { title: 'ModelBridge 运行观测', columns: ['指标', '值'], rows };
      const tables = [mainTable];
      if (snap.catalog.ok && snap.catalog.models.length > 0) {
        tables.push({
          title: '模型目录样本',
          columns: ['模型 ID', '提供方'],
          rows: snap.catalog.models.slice(0, 12).map(m => [m.id, m.ownedBy]),
        });
      }
      const notices = [];
      if (!online && snap.status.error) {
        notices.push({ tone: 'warn', text: `状态探针异常：${snap.status.error}` });
      }
      if (snap.catalog.queried && !snap.catalog.ok && snap.catalog.error) {
        notices.push({ tone: 'warn', text: `模型目录查询失败：${snap.catalog.error}` });
      }
      return {
        status: !online ? 'error' : snap.usage.ok ? 'ok' : 'warn',
        summary,
        table: mainTable,
        tables,
        notices,
        links: origin || snap.origin ? [{ label: '打开 ModelBridge 网关', href: origin || snap.origin }] : [],
      };
    },
  });
}
