// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).

export const CONSOLE_PANEL_SCHEMA_VERSION = 1;
export const PANEL_CATEGORIES = Object.freeze(['security', 'moderation', 'tools', 'telemetry', 'integrations']);
export const PANEL_STATUSES = Object.freeze(['ok', 'warn', 'error', 'idle']);
export const PANEL_TONES = Object.freeze(['neutral', 'ok', 'info', 'warn', 'err']);

const PANEL_ID_RE = /^[a-z][a-z0-9-]{1,47}$/;
const MAX_SUMMARY_ITEMS = 12;
const MAX_TABLE_COLUMNS = 8;
const MAX_TABLE_ROWS = 50;
const MAX_NOTICES = 12;
const MAX_LINKS = 8;

function clampText(value, maxLen = 240) {
  if (typeof value !== 'string') return '';
  const cleaned = value.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '').trim();
  return cleaned.length > maxLen ? `${cleaned.slice(0, maxLen - 1)}…` : cleaned;
}

function isSafePanelHref(href) {
  if (typeof href !== 'string') return false;
  const trimmed = href.trim();
  if (!trimmed || trimmed.length > 512) return false;
  if (trimmed.startsWith('/') && !trimmed.startsWith('//')) return true;
  try {
    const parsed = new URL(trimmed);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

export function validateConsolePanelDecl(decl) {
  if (!decl || typeof decl !== 'object' || Array.isArray(decl)) {
    throw new Error('Console panel declaration must be an object.');
  }
  if (decl.schemaVersion !== undefined && decl.schemaVersion !== CONSOLE_PANEL_SCHEMA_VERSION) {
    throw new Error(`Unsupported console panel schemaVersion: ${String(decl.schemaVersion)}`);
  }
  if (typeof decl.id !== 'string' || !PANEL_ID_RE.test(decl.id)) {
    throw new Error(`Invalid console panel id: ${String(decl.id)}`);
  }
  const title = clampText(decl.title, 80);
  if (!title) throw new Error(`Console panel ${decl.id} requires a non-empty title.`);
  const category = decl.category ?? 'integrations';
  if (!PANEL_CATEGORIES.includes(category)) {
    throw new Error(`Invalid console panel category for ${decl.id}: ${String(category)}`);
  }
  if (decl.getSnapshot !== undefined && typeof decl.getSnapshot !== 'function') {
    throw new Error(`Console panel ${decl.id}.getSnapshot must be a function.`);
  }
  const order = Number.isFinite(decl.order) ? Math.trunc(decl.order) : 100;
  return Object.freeze({
    schemaVersion: CONSOLE_PANEL_SCHEMA_VERSION,
    id: decl.id,
    title,
    subtitle: clampText(decl.subtitle ?? '', 160),
    category,
    order,
    executionBoundary: decl.executionBoundary === 'in-process-root' ? 'in-process-root' : 'out-of-process',
    readOnly: true,
    trustOriginRequiredForMutations: decl.trustOriginRequiredForMutations !== false,
    ...(typeof decl.getSnapshot === 'function' ? { getSnapshot: decl.getSnapshot } : {}),
  });
}

export function sanitizeConsolePanelSnapshot(panelDecl, rawSnapshot) {
  const safeStatus = PANEL_STATUSES.includes(rawSnapshot?.status) ? rawSnapshot.status : 'idle';
  const summary = Array.isArray(rawSnapshot?.summary)
    ? rawSnapshot.summary
        .filter(item => item && typeof item === 'object' && !Array.isArray(item))
        .slice(0, MAX_SUMMARY_ITEMS)
        .map(item => ({
          label: clampText(item.label, 48) || '指标',
          value: clampText(String(item.value ?? ''), 96),
          tone: PANEL_TONES.includes(item.tone) ? item.tone : 'neutral',
        }))
    : [];

  let table = null;
  if (rawSnapshot?.table && typeof rawSnapshot.table === 'object' && !Array.isArray(rawSnapshot.table)) {
    const columns = Array.isArray(rawSnapshot.table.columns)
      ? rawSnapshot.table.columns
          .filter(c => typeof c === 'string')
          .slice(0, MAX_TABLE_COLUMNS)
          .map(c => clampText(c, 40))
      : [];
    const rows = Array.isArray(rawSnapshot.table.rows)
      ? rawSnapshot.table.rows
          .filter(row => Array.isArray(row))
          .slice(0, MAX_TABLE_ROWS)
          .map(row => row.slice(0, columns.length || MAX_TABLE_COLUMNS).map(cell => clampText(String(cell ?? ''), 160)))
      : [];
    if (columns.length > 0) {
      table = { columns, rows };
    }
  }

  const notices = Array.isArray(rawSnapshot?.notices)
    ? rawSnapshot.notices
        .filter(n => n && typeof n === 'object' && !Array.isArray(n))
        .slice(0, MAX_NOTICES)
        .map(n => ({
          tone: PANEL_TONES.includes(n.tone) ? n.tone : 'info',
          text: clampText(n.text, 240),
        }))
        .filter(n => n.text.length > 0)
    : [];

  const links = Array.isArray(rawSnapshot?.links)
    ? rawSnapshot.links
        .filter(l => l && typeof l === 'object' && !Array.isArray(l) && isSafePanelHref(l.href))
        .slice(0, MAX_LINKS)
        .map(l => ({
          label: clampText(l.label, 48) || '打开链接',
          href: l.href.trim(),
        }))
    : [];

  return {
    schemaVersion: CONSOLE_PANEL_SCHEMA_VERSION,
    id: panelDecl.id,
    title: panelDecl.title,
    subtitle: panelDecl.subtitle,
    category: panelDecl.category,
    order: panelDecl.order,
    executionBoundary: panelDecl.executionBoundary,
    readOnly: true,
    status: safeStatus,
    updatedAt: typeof rawSnapshot?.updatedAt === 'string' ? clampText(rawSnapshot.updatedAt, 64) : new Date().toISOString(),
    summary,
    table,
    notices,
    links,
  };
}
