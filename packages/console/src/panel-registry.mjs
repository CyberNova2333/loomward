// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Zero-coupling declarative console:panel@1 snapshot collector (strictly read-only, schema-validated, fail-safe per panel).
import { sanitizeConsolePanelSnapshot, validateConsolePanelDecl } from '@loomward/shared';

const PANEL_TIMEOUT_MS = 2000;

async function withTimeout(promise, ms) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('Panel snapshot timed out.')), ms);
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
          out.push(decl);
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
        out.push(decl);
      } catch {}
    }
    out.sort((a, b) => (a.order - b.order) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    return out;
  }

  async function resolvePanel(decl, context) {
    if (typeof decl.getSnapshot !== 'function') {
      return sanitizeConsolePanelSnapshot(decl, { status: 'idle', summary: [] });
    }
    try {
      const raw = await withTimeout(Promise.resolve().then(() => decl.getSnapshot(context)), PANEL_TIMEOUT_MS);
      return sanitizeConsolePanelSnapshot(decl, raw);
    } catch {
      return sanitizeConsolePanelSnapshot(decl, {
        status: 'error',
        summary: [{ label: '状态', value: '面板快照读取失败', tone: 'err' }],
        notices: [{ tone: 'warn', text: '扩展面板暂时不可用；核心安全控制面不受影响。' }],
      });
    }
  }

  async function collectAll(context = {}) {
    const entries = listRawEntries();
    return Promise.all(entries.map(decl => resolvePanel(decl, context)));
  }

  async function collectById(id, context = {}) {
    const decl = listRawEntries().find(item => item.id === id);
    if (!decl) return null;
    return resolvePanel(decl, context);
  }

  return Object.freeze({
    listDeclarations: () => listRawEntries().map(({ getSnapshot: _drop, ...meta }) => meta),
    collectAll,
    collectById,
  });
}
