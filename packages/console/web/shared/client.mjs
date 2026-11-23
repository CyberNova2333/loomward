// SPDX-License-Identifier: AGPL-3.0-only
// Safe zero-dependency browser primitives shared by Trust Origin and Console Origin.

export function readMeta(name) {
  return document.querySelector(`meta[name="${name}"]`)?.getAttribute('content') || '';
}

export function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = String(v);
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2).toLowerCase(), v);
    else if (v === true) node.setAttribute(k, '');
    else node.setAttribute(k, String(v));
  }
  const list = Array.isArray(children) ? children : [children];
  for (const child of list) {
    if (child === null || child === undefined || child === false) continue;
    node.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

export function clearNode(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

export function initThemeToggle() {
  const saved = window.localStorage.getItem('loomward-theme');
  const initial = saved === 'dark' || saved === 'light'
    ? saved
    : (window.matchMedia?.('(prefers-color-scheme: dark)')?.matches ? 'dark' : 'light');
  document.documentElement.dataset.theme = initial;
  return {
    current: () => document.documentElement.dataset.theme || 'light',
    toggle() {
      const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
      document.documentElement.dataset.theme = next;
      try { window.localStorage.setItem('loomward-theme', next); } catch {}
      return next;
    },
  };
}

export function b64urlToBytes(str) {
  const pad = '='.repeat((4 - (str.length % 4)) % 4);
  const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64url(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function createOriginClient({ storageKey }) {
  let csrfToken = readMeta('loomward-csrf');
  let tabToken = '';
  try {
    tabToken = window.sessionStorage.getItem(storageKey) || '';
  } catch {}

  function setTokens({ csrf, tab } = {}) {
    if (typeof csrf === 'string' && csrf) csrfToken = csrf;
    if (tab !== undefined) {
      tabToken = typeof tab === 'string' ? tab : '';
      try {
        if (tabToken) window.sessionStorage.setItem(storageKey, tabToken);
        else window.sessionStorage.removeItem(storageKey);
      } catch {}
    }
  }

  function clearTabToken() {
    setTokens({ tab: '' });
  }

  function authHeaders(isMutation = false) {
    const headers = {};
    if (tabToken) headers['X-LoomWard-Tab-Auth'] = tabToken;
    if (isMutation) {
      headers['Content-Type'] = 'application/json';
      if (csrfToken) headers['X-LoomWard-CSRF'] = csrfToken;
    }
    return headers;
  }

  async function api(pathname, { method = 'GET', body } = {}) {
    const isMutation = method !== 'GET' && method !== 'HEAD';
    const res = await fetch(pathname, {
      method,
      credentials: 'same-origin',
      headers: authHeaders(isMutation),
      ...(isMutation ? { body: JSON.stringify(body ?? {}) } : {}),
    });
    const text = await res.text();
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch {}
    if (typeof data?.csrfToken === 'string' && data.csrfToken) {
      csrfToken = data.csrfToken;
    }
    if (typeof data?.tabToken === 'string' && data.tabToken) {
      setTokens({ tab: data.tabToken });
    }
    if (!res.ok) {
      const err = new Error(data?.error || `HTTP ${res.status}`);
      err.status = res.status;
      err.code = data?.code || null;
      err.data = data;
      throw err;
    }
    return data;
  }

  function connectSse(pathname, { onEvent, onStatus }) {
    let closed = false;
    let activeController = null;
    let retryTimer = null;

    async function run() {
      if (closed) return;
      activeController = new AbortController();
      try {
        onStatus?.('connecting');
        const res = await fetch(pathname, {
          method: 'GET',
          credentials: 'same-origin',
          headers: {
            Accept: 'text/event-stream',
            ...(tabToken ? { 'X-LoomWard-Tab-Auth': tabToken } : {}),
          },
          signal: activeController.signal,
        });
        if (!res.ok || !res.body) {
          if (res.status === 401 || res.status === 403) {
            onStatus?.('unauthorized');
            return;
          }
          onStatus?.('disconnected');
        } else {
          onStatus?.('connected');
          const reader = res.body.getReader();
          const decoder = new TextDecoder();
          let buffer = '';
          while (!closed) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            let idx;
            while ((idx = buffer.indexOf('\n\n')) !== -1) {
              const block = buffer.slice(0, idx);
              buffer = buffer.slice(idx + 2);
              let eventName = 'message';
              const dataLines = [];
              for (const line of block.split('\n')) {
                if (line.startsWith('event:')) eventName = line.slice(6).trim();
                else if (line.startsWith('data:')) dataLines.push(line.slice(5).trim());
              }
              if (dataLines.length) {
                try { onEvent?.(eventName, JSON.parse(dataLines.join('\n'))); } catch {}
              }
            }
          }
        }
      } catch {
        if (!closed) onStatus?.('disconnected');
      }
      if (!closed) {
        retryTimer = setTimeout(run, 2500);
      }
    }

    void run();
    return () => {
      closed = true;
      clearTimeout(retryTimer);
      activeController?.abort();
    };
  }

  return {
    getCsrf: () => csrfToken,
    getTabToken: () => tabToken,
    setTokens,
    clearTabToken,
    api,
    connectSse,
  };
}
