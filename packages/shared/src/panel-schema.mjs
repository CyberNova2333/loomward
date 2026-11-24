// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).

export const CONSOLE_PANEL_SCHEMA_VERSION = 1;
export const PANEL_CATEGORIES = Object.freeze(['security', 'moderation', 'tools', 'telemetry', 'integrations']);
export const PANEL_STATUSES = Object.freeze(['ok', 'warn', 'error', 'idle']);
export const PANEL_TONES = Object.freeze(['neutral', 'ok', 'info', 'warn', 'err']);

const PANEL_ID_RE = /^[a-z][a-z0-9-]{1,47}$/;
const MAX_SUMMARY_ITEMS = 12;
const MAX_TABLES = 4;
const MAX_TABLE_COLUMNS = 8;
const MAX_TABLE_ROWS = 50;
const MAX_NOTICES = 12;
const MAX_LINKS = 8;
const UNSAFE_TEXT_RE = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u200e\u200f\u061c\u202a-\u202e\u2066-\u2069]/g;

function clampText(value, maxLen = 240) {
  if (typeof value !== 'string') return '';
  const cleaned = value.replace(UNSAFE_TEXT_RE, '').trim();
  const points = Array.from(cleaned);
  return points.length > maxLen ? `${points.slice(0, maxLen - 1).join('')}…` : cleaned;
}

function safeScalarText(value, maxLen = 160) {
  if (typeof value === 'string') return clampText(value, maxLen);
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : '';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  return '';
}

function isSafePanelHref(href) {
  if (typeof href !== 'string') return false;
  if (/[\x00-\x1f\x7f\\]/.test(href)) return false;
  const trimmed = href.trim();
  if (!trimmed || trimmed.length > 512) return false;
  if (/^\/(?![/\\])/.test(trimmed)) {
    try {
      const resolved = new URL(trimmed, 'http://loomward.local');
      return resolved.origin === 'http://loomward.local';
    } catch {
      return false;
    }
  }
  try {
    const parsed = new URL(trimmed);
    if (parsed.username || parsed.password) return false;
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function sanitizeTable(rawTable) {
  if (!rawTable || typeof rawTable !== 'object' || Array.isArray(rawTable)) return null;
  const rawColumns = rawTable.columns;
  const rawRows = rawTable.rows;
  const rawTitle = rawTable.title;
  const columns = Array.isArray(rawColumns)
    ? rawColumns
        .filter(c => typeof c === 'string')
        .slice(0, MAX_TABLE_COLUMNS)
        .map(c => clampText(c, 40))
    : [];
  if (columns.length === 0) return null;
  const rows = Array.isArray(rawRows)
    ? rawRows
        .filter(row => Array.isArray(row))
        .slice(0, MAX_TABLE_ROWS)
        .map(row => row.slice(0, columns.length).map(cell => safeScalarText(cell, 160)))
    : [];
  const title = typeof rawTitle === 'string' ? clampText(rawTitle, 80) : '';
  return {
    ...(title ? { title } : {}),
    columns,
    rows,
  };
}

export function validateConsolePanelDecl(decl) {
  if (!decl || typeof decl !== 'object' || Array.isArray(decl)) {
    throw new Error('Console panel declaration must be an object.');
  }
  const schemaVersion = decl.schemaVersion;
  const id = decl.id;
  const rawTitle = decl.title;
  const rawCategory = decl.category;
  const getSnapshot = decl.getSnapshot;
  const rawOrder = decl.order;
  const rawSubtitle = decl.subtitle;
  const rawBoundary = decl.executionBoundary;
  const rawTrustReq = decl.trustOriginRequiredForMutations;

  if (schemaVersion !== undefined && schemaVersion !== CONSOLE_PANEL_SCHEMA_VERSION) {
    throw new Error(`Unsupported console panel schemaVersion: ${String(schemaVersion)}`);
  }
  if (typeof id !== 'string' || !PANEL_ID_RE.test(id)) {
    throw new Error(`Invalid console panel id: ${String(id)}`);
  }
  const title = clampText(rawTitle, 80);
  if (!title) throw new Error(`Console panel ${id} requires a non-empty title.`);
  const category = rawCategory ?? 'integrations';
  if (!PANEL_CATEGORIES.includes(category)) {
    throw new Error(`Invalid console panel category for ${id}: ${String(category)}`);
  }
  if (getSnapshot !== undefined && typeof getSnapshot !== 'function') {
    throw new Error(`Console panel ${id}.getSnapshot must be a function.`);
  }
  const order = Number.isFinite(rawOrder) ? Math.trunc(rawOrder) : 100;
  return Object.freeze({
    schemaVersion: CONSOLE_PANEL_SCHEMA_VERSION,
    id,
    title,
    subtitle: clampText(rawSubtitle ?? '', 160),
    category,
    order,
    executionBoundary: rawBoundary === 'in-process-root' ? 'in-process-root' : 'out-of-process',
    readOnly: true,
    trustOriginRequiredForMutations: rawTrustReq !== false,
    ...(typeof getSnapshot === 'function' ? { getSnapshot } : {}),
  });
}

export function sanitizeConsolePanelSnapshot(panelDecl, rawSnapshot, { executionBoundary } = {}) {
  const snapObj = rawSnapshot && typeof rawSnapshot === 'object' ? rawSnapshot : null;
  const snapStatus = snapObj?.status;
  const rawStatus = snapStatus === 'degraded' ? 'warn' : snapStatus;
  const safeStatus = PANEL_STATUSES.includes(rawStatus) ? rawStatus : 'idle';
  const rawSummary = snapObj?.summary;
  const summary = Array.isArray(rawSummary)
    ? rawSummary
        .filter(item => item && typeof item === 'object' && !Array.isArray(item))
        .slice(0, MAX_SUMMARY_ITEMS)
        .map(item => {
          const itemLabel = item.label;
          const itemValue = item.value;
          const itemTone = item.tone;
          return {
            label: clampText(itemLabel, 48) || '指标',
            value: safeScalarText(itemValue, 96),
            tone: PANEL_TONES.includes(itemTone) ? itemTone : 'neutral',
          };
        })
    : [];

  const tables = [];
  const rawTables = snapObj?.tables;
  if (Array.isArray(rawTables)) {
    for (const rawTable of rawTables) {
      if (tables.length >= MAX_TABLES) break;
      const sanitized = sanitizeTable(rawTable);
      if (sanitized) tables.push(sanitized);
    }
  }
  const rawSingleTable = tables.length === 0 ? snapObj?.table : null;
  if (tables.length === 0 && rawSingleTable) {
    const sanitized = sanitizeTable(rawSingleTable);
    if (sanitized) tables.push(sanitized);
  }
  const table = tables[0] ?? null;

  const rawNotices = snapObj?.notices;
  const notices = Array.isArray(rawNotices)
    ? rawNotices
        .filter(n => n && typeof n === 'object' && !Array.isArray(n))
        .slice(0, MAX_NOTICES)
        .map(n => {
          const nTone = n.tone;
          const nText = n.text;
          return {
            tone: PANEL_TONES.includes(nTone) ? nTone : 'info',
            text: clampText(nText, 240),
          };
        })
        .filter(n => n.text.length > 0)
    : [];

  const rawLinks = snapObj?.links;
  const links = [];
  if (Array.isArray(rawLinks)) {
    for (const l of rawLinks) {
      if (links.length >= MAX_LINKS) break;
      if (!l || typeof l !== 'object' || Array.isArray(l)) continue;
      const href = l.href;
      if (!isSafePanelHref(href)) continue;
      const label = l.label;
      links.push({
        label: clampText(label, 48) || '打开链接',
        href: href.trim(),
      });
    }
  }

  const rawUpdatedAt = snapObj?.updatedAt;
  const effectiveBoundary = executionBoundary === 'in-process-root' || executionBoundary === 'out-of-process'
    ? executionBoundary
    : panelDecl.executionBoundary;

  return {
    schemaVersion: CONSOLE_PANEL_SCHEMA_VERSION,
    id: panelDecl.id,
    title: panelDecl.title,
    subtitle: panelDecl.subtitle,
    category: panelDecl.category,
    order: panelDecl.order,
    executionBoundary: effectiveBoundary,
    readOnly: true,
    status: safeStatus,
    updatedAt: typeof rawUpdatedAt === 'string' ? clampText(rawUpdatedAt, 64) : new Date().toISOString(),
    summary,
    table,
    tables,
    notices,
    links,
  };
}
