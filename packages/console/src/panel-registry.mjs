// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Zero-coupling declarative console:panel@1 snapshot collector (strictly read-only, schema-validated, fail-safe per panel).
import { sanitizeConsolePanelSnapshot, validateConsolePanelDecl } from '@loomward/shared';

const PANEL_TIMEOUT_MS = 2000;

async function withTimeout(promise, ms, onTimeout) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          try { onTimeout?.(); } catch {}
          reject(new Error('Panel snapshot timed out.'));
        }, ms);
        timer.unref?.();
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

export function createConsolePanelCollector({ panelSlot = null, staticPanels = [] } = {}) {
  function listRawEntries() {
    const out = [];
    const seen = new Set();
    if (panelSlot && typeof panelSlot.entries === 'function') {
      for (const entry of panelSlot.entries()) {
        try {
          const decl = validateConsolePanelDecl(entry.impl);
          if (seen.has(decl.id)) continue;
          seen.add(decl.id);
          out.push({ decl, rootOwned: Boolean(entry.rootOwned) });
        } catch {
          // Malformed third-party panel declarations are silently ignored without affecting other panels.
        }
      }
    }
    for (const raw of staticPanels) {
      try {
        const decl = validateConsolePanelDecl(raw);
        if (seen.has(decl.id)) continue;
        seen.add(decl.id);
        out.push({ decl, rootOwned: false });
      } catch {}
    }
    out.sort((a, b) => (a.decl.order - b.decl.order) || (a.decl.id < b.decl.id ? -1 : a.decl.id > b.decl.id ? 1 : 0));
    return out;
  }

  async function resolvePanel(item, context) {
    const { decl, rootOwned } = item;
    const boundaryOpts = { executionBoundary: rootOwned ? decl.executionBoundary : 'out-of-process' };
    if (typeof decl.getSnapshot !== 'function') {
      return sanitizeConsolePanelSnapshot(decl, { status: 'idle', summary: [] }, boundaryOpts);
    }
    const controller = new AbortController();
    try {
      const panelContext = { ...(context && typeof context === 'object' ? context : {}), signal: controller.signal };
      const raw = await withTimeout(
        Promise.resolve().then(() => decl.getSnapshot(panelContext)),
        PANEL_TIMEOUT_MS,
        () => controller.abort(new Error('Panel snapshot timed out.')),
      );
      return sanitizeConsolePanelSnapshot(decl, raw, boundaryOpts);
    } catch {
      return sanitizeConsolePanelSnapshot(decl, {
        status: 'error',
        summary: [{ label: '状态', value: '面板快照读取失败', tone: 'err' }],
        notices: [{ tone: 'warn', text: '扩展面板暂时不可用；核心安全控制面不受影响。' }],
      }, boundaryOpts);
    }
  }

  async function collectAll(context = {}) {
    const entries = listRawEntries();
    return Promise.all(entries.map(item => resolvePanel(item, context)));
  }

  async function collectById(id, context = {}) {
    const item = listRawEntries().find(entry => entry.decl.id === id);
    if (!item) return null;
    return resolvePanel(item, context);
  }

  return Object.freeze({
    listDeclarations: () => listRawEntries().map(({ decl: { getSnapshot: _drop, ...meta }, rootOwned }) => ({
      ...meta,
      executionBoundary: rootOwned ? meta.executionBoundary : 'out-of-process',
    })),
    collectAll,
    collectById,
  });
}
