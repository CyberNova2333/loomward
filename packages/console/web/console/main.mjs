// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Single-Origin Unified Console UI controller with grouped workspace navigation.
import {
  b64urlToBytes,
  bytesToB64url,
  clearNode,
  createOriginClient,
  el,
  initThemeToggle,
  isSafeNavigationUrl,
  svgEl,
} from '../shared/client.mjs';

const client = createOriginClient({ storageKey: 'loomward_console_tab_token' });
const theme = initThemeToggle();
const root = document.getElementById('app');

const DEFAULT_MOD_CONFIG = {
  enabled: true,
  mode: 'local-only',
  policyProfile: 'experimental-resilient',
  defaultScope: 'combined',
  cloudOptIn: false,
  cloudProvider: 'openai-compat',
  cloudRegion: '',
  cloudEndpoint: '',
  localGuard: {
    kind: 'ollama',
    endpoint: 'http://127.0.0.1:11434',
    model: 'llama-guard3:1b',
    think: false,
    allowPrivateNetwork: false,
  },
  canary: {
    enabled: false,
    kind: 'ollama',
    endpoint: 'http://127.0.0.1:11434',
    model: 'qwen2.5:0.5b',
    think: false,
    allowPrivateNetwork: false,
    shadowMode: true,
  },
};

const state = {
  auth: null,
  snapshot: null,
  moderationConfig: null,
  draftMod: null,
  ollama: null,
  ollamaLoading: false,
  ollamaError: '',
  ollamaEndpointInput: '',
  ollamaAllowPrivate: false,
  ollamaPullTag: '',
  ollamaInstallConfirm: false,
  ollamaTestResult: null,
  ollamaPollTimer: null,
  draftAuth: { setupToken: '', password: '', passkeyLabel: '' },
  draftSecret: { unitId: 'llm-moderation', key: '', value: '' },
  draftCloudCreds: {},
  pluginSecretUnits: null,
  page: 'overview',
  modTab: 'routing',
  mobileNavOpen: false,
  overviewTopologyOpen: false,
  toolFilter: 'all',
  toolSearch: '',
  toolCatalogMode: 'mcp',
  selectedToolName: '',
  selectedHttpId: 'status',
  toolArgsDraft: {},
  toolHttpTryResult: null,
  copiedTarget: '',
  fencingTab: 'antileak',
  fencingData: null,
  fencingDraft: null,
  fencingLoading: false,
  fencingDryText: '',
  fencingDryResult: null,
  fencingDoctorResult: null,
  fencingRefreshResult: null,
  mcpDraft: {
    editingId: '',
    id: '',
    name: '',
    description: '',
    transport: 'stdio',
    command: '',
    argsText: '',
    cwd: '',
    url: '',
    timeoutMs: '30000',
    envText: '',
    removeEnvKeysText: '',
    headersText: '',
    removeHeaderKeysText: '',
    replaceSecrets: false,
    enabled: true,
    probe: true,
  },
  mcpImportJson: '',
  mcpImportProbe: true,
  mcpExpandedTools: {},
  mcpDeleteConfirmId: '',
  auditFilter: 'all',
  expandedAuditKeys: {},
  expandedKernelKeys: {},
  sseStatus: 'idle',
  liveKernelEvents: [],
  error: '',
  notice: '',
  busy: false,
  reviewModal: null,
  stopSse: null,
  countdownTimer: null,
};

function setNotice(msg) {
  state.notice = msg || '';
  if (msg) state.error = '';
  render();
}

function setError(msg) {
  state.error = msg || '';
  if (msg) state.notice = '';
  render();
}

function navigate(pageId, opts = {}) {
  state.page = pageId;
  state.mobileNavOpen = false;
  if (opts.fencingTab) state.fencingTab = opts.fencingTab;
  if (opts.selectedToolName) {
    state.selectedToolName = opts.selectedToolName;
    state.toolCatalogMode = 'mcp';
  }
  if (pageId === 'moderation' && state.auth?.authenticated && !state.ollama && !state.ollamaLoading) {
    void loadOllamaStatus({ silent: true });
  }
  if (pageId === 'fencing' && state.auth?.authenticated && !state.fencingData && !state.fencingLoading) {
    void loadFencingConfig({ silent: true });
  }
  render();
  (root.querySelector('.lw-page-head h1') || root.querySelector('#lw-main'))?.focus({ preventScroll: true });
  window.scrollTo(0, 0);
}

function stopOllamaPolling() {
  if (state.ollamaPollTimer) {
    clearTimeout(state.ollamaPollTimer);
    state.ollamaPollTimer = null;
  }
}

function stopLiveResources() {
  stopOllamaPolling();
  if (state.stopSse) {
    state.stopSse();
    state.stopSse = null;
  }
  if (state.countdownTimer) {
    clearInterval(state.countdownTimer);
    state.countdownTimer = null;
  }
}

function updateLiveCountdowns() {
  const nodes = root.querySelectorAll('[data-countdown-expires]');
  for (const node of nodes) {
    const exp = Date.parse(node.getAttribute('data-countdown-expires') || '');
    if (!Number.isFinite(exp)) continue;
    const leftSec = Math.max(0, Math.ceil((exp - Date.now()) / 1000));
    const threshold = Number(node.getAttribute('data-warn-threshold') || '30');
    node.textContent = `剩余 ${leftSec}s`;
    node.className = `lw-pill ${leftSec <= threshold ? 'lw-pill-err' : 'lw-pill-warn'}`;
  }
  const btns = root.querySelectorAll('[data-countdown-disable-expires]');
  for (const btn of btns) {
    const exp = Date.parse(btn.getAttribute('data-countdown-disable-expires') || '');
    if (!Number.isFinite(exp)) continue;
    const leftSec = Math.max(0, Math.ceil((exp - Date.now()) / 1000));
    if (leftSec <= 0) btn.disabled = true;
  }
}

function startLiveStream() {
  stopLiveResources();
  state.stopSse = client.connectSse('/api/events', {
    onStatus(status) {
      state.sseStatus = status;
      if (status === 'unauthorized') {
        stopLiveResources();
        client.clearTabToken();
        state.snapshot = null;
        state.liveKernelEvents = [];
        state.reviewModal = null;
        void refreshAuthState().catch(() => {});
      } else {
        render();
      }
    },
    onEvent(name, payload) {
      if (name === 'status') {
        state.snapshot = payload;
        render();
      } else if (name === 'kernel') {
        state.liveKernelEvents.unshift(payload);
        if (state.liveKernelEvents.length > 40) state.liveKernelEvents.length = 40;
        render();
      }
    },
  });
  state.countdownTimer = setInterval(() => {
    if (state.snapshot?.approvals?.pendingCount > 0 || state.reviewModal) {
      updateLiveCountdowns();
    }
  }, 1000);
}

async function runMutation(fn) {
  if (state.busy) return;
  state.busy = true;
  state.error = '';
  render();
  try {
    await fn();
  } catch (err) {
    state.error = err?.message || '操作失败';
    if (err?.status === 401) {
      stopLiveResources();
      client.clearTabToken();
      state.snapshot = null;
      state.liveKernelEvents = [];
      state.reviewModal = null;
      await refreshAuthState().catch(() => {});
    }
  } finally {
    state.busy = false;
    render();
  }
}

function scheduleOllamaPolling(jobs) {
  stopOllamaPolling();
  if (!state.auth?.authenticated) return;
  if (Array.isArray(jobs) && jobs.some(j => j.status === 'pulling')) {
    state.ollamaPollTimer = setTimeout(() => {
      void loadOllamaStatus({ silent: true });
    }, 1500);
  }
}

async function loadOllamaStatus({ endpoint, allowPrivateNetwork, silent = false } = {}) {
  if (!state.auth?.authenticated) return null;
  const fallbackEp = (state.draftMod?.localGuard?.endpoint || state.moderationConfig?.localGuard?.endpoint || 'http://127.0.0.1:11434').trim();
  const targetEp = String(endpoint ?? (state.ollamaEndpointInput || fallbackEp)).trim();
  const allowPriv = Boolean(allowPrivateNetwork ?? state.ollamaAllowPrivate);
  const qs = new URLSearchParams();
  if (targetEp) qs.set('endpoint', targetEp);
  if (allowPriv) qs.set('allowPrivateNetwork', '1');
  if (!silent) state.ollamaLoading = true;
  state.ollamaError = '';
  if (!silent) render();
  try {
    const res = await client.api(`/api/moderation/ollama/status?${qs.toString()}`);
    state.ollama = res;
    if (!state.ollamaEndpointInput && res?.endpoint) state.ollamaEndpointInput = res.endpoint;
    scheduleOllamaPolling(res?.pullJobs);
    return res;
  } catch (err) {
    state.ollamaError = err?.message || 'Ollama 运行时探测失败';
    if (!silent) setError(state.ollamaError);
    return null;
  } finally {
    state.ollamaLoading = false;
    render();
  }
}

async function loadFencingConfig({ silent = false } = {}) {
  if (!state.auth?.authenticated) return null;
  if (!silent) state.fencingLoading = true;
  if (!silent) render();
  try {
    const res = await client.api('/api/fencing/config');
    state.fencingData = res;
    if (res?.config && !state.fencingDraft) {
      state.fencingDraft = structuredClone(res.config);
    }
    return res;
  } catch (err) {
    if (!silent) setError(err?.message || '读取 Agent 防泄漏围栏配置失败');
    return null;
  } finally {
    state.fencingLoading = false;
    render();
  }
}

async function refreshAuthState() {
  const auth = await client.api('/api/auth/state');
  state.auth = auth;
  if (auth.authenticated) {
    const [snap, modRes, secRes, fenceRes] = await Promise.all([
      client.api('/api/status'),
      client.api('/api/moderation/config').catch(() => null),
      client.api('/api/plugin-secrets/meta').catch(() => null),
      client.api('/api/fencing/config').catch(() => null),
    ]);
    state.snapshot = snap;
    state.liveKernelEvents = Array.isArray(snap?.channelEvents) ? [...snap.channelEvents].reverse() : [];
    if (modRes?.config) {
      state.moderationConfig = modRes.config;
      if (!state.draftMod) state.draftMod = structuredClone(modRes.config);
      if (!state.ollamaEndpointInput && modRes.config.localGuard?.endpoint) {
        state.ollamaEndpointInput = modRes.config.localGuard.endpoint;
      }
      if (modRes.config.localGuard?.allowPrivateNetwork !== undefined) {
        state.ollamaAllowPrivate = Boolean(modRes.config.localGuard.allowPrivateNetwork);
      }
    }
    if (Array.isArray(secRes?.units)) state.pluginSecretUnits = secRes.units;
    if (fenceRes?.config) {
      state.fencingData = fenceRes;
      if (!state.fencingDraft) state.fencingDraft = structuredClone(fenceRes.config);
    }
    startLiveStream();
    void loadOllamaStatus({ silent: true });
  } else {
    stopLiveResources();
    state.snapshot = null;
    state.moderationConfig = null;
    state.draftMod = null;
    state.fencingData = null;
    state.fencingDraft = null;
    state.fencingDryResult = null;
    state.fencingDoctorResult = null;
    state.fencingRefreshResult = null;
    state.ollama = null;
    state.ollamaError = '';
    state.ollamaTestResult = null;
    state.ollamaInstallConfirm = false;
    state.draftCloudCreds = {};
    state.pluginSecretUnits = null;
    state.liveKernelEvents = [];
    state.mobileNavOpen = false;
  }
  render();
}

function ensureWebAuthnLocalhostOrigin() {
  if (window.location.hostname === '127.0.0.1' || window.location.hostname === '[::1]' || window.location.hostname === '::1') {
    const target = `http://localhost:${window.location.port}${window.location.pathname}${window.location.search}`;
    window.location.replace(target);
    throw new Error(`WebAuthn PassKey 需通过 localhost 域名访问，正在跳转至 ${target}`);
  }
}

async function handlePasskeyLogin() {
  await runMutation(async () => {
    ensureWebAuthnLocalhostOrigin();
    const opt = await client.api('/api/auth/passkey/login/options', { method: 'POST', body: {} });
    const pubKey = {
      ...opt.publicKey,
      challenge: b64urlToBytes(opt.publicKey.challenge),
      allowCredentials: (opt.publicKey.allowCredentials || []).map(c => ({ ...c, id: b64urlToBytes(c.id) })),
    };
    const cred = await navigator.credentials.get({ publicKey: pubKey });
    if (!cred) throw new Error('PassKey 验证已取消。');
    await client.api('/api/auth/passkey/login/verify', {
      method: 'POST',
      body: {
        challengeId: opt.challengeId,
        credential: {
          id: cred.id,
          type: cred.type,
          response: {
            clientDataJSON: bytesToB64url(cred.response.clientDataJSON),
            authenticatorData: bytesToB64url(cred.response.authenticatorData),
            signature: bytesToB64url(cred.response.signature),
          },
        },
      },
    });
    await refreshAuthState();
  });
}

async function handlePasskeyEnroll(setupToken, label) {
  await runMutation(async () => {
    ensureWebAuthnLocalhostOrigin();
    const opt = await client.api('/api/auth/setup/passkey/options', {
      method: 'POST',
      body: { ...(setupToken ? { setupToken } : {}) },
    });
    const pubKey = {
      ...opt.publicKey,
      challenge: b64urlToBytes(opt.publicKey.challenge),
      user: { ...opt.publicKey.user, id: b64urlToBytes(opt.publicKey.user.id) },
      excludeCredentials: (opt.publicKey.excludeCredentials || []).map(c => ({ ...c, id: b64urlToBytes(c.id) })),
    };
    const cred = await navigator.credentials.create({ publicKey: pubKey });
    if (!cred) throw new Error('PassKey 注册已取消。');
    await client.api('/api/auth/setup/passkey/verify', {
      method: 'POST',
      body: {
        challengeId: opt.challengeId,
        ...(setupToken ? { setupToken } : {}),
        label: label || 'Local PassKey',
        credential: {
          id: cred.id,
          type: cred.type,
          response: {
            clientDataJSON: bytesToB64url(cred.response.clientDataJSON),
            attestationObject: bytesToB64url(cred.response.attestationObject),
            transports: cred.response.getTransports?.() || ['internal'],
          },
        },
      },
    });
    state.draftAuth = { setupToken: '', password: '', passkeyLabel: '' };
    setNotice('PassKey 注册并登录成功。');
    await refreshAuthState();
  });
}

async function handleLogout() {
  await runMutation(async () => {
    stopLiveResources();
    await client.api('/api/auth/logout', { method: 'POST', body: {} });
    client.clearTabToken();
    state.snapshot = null;
    state.liveKernelEvents = [];
    state.reviewModal = null;
    setNotice('已锁定并清理当前会话。');
    await refreshAuthState();
  });
}

const ICON_SHAPES = {
  menu: [['path', { d: 'M3 6h18M3 12h18M3 18h18' }]],
  close: [['path', { d: 'm6 6 12 12M18 6 6 18' }]],
  moon: [['path', { d: 'M20.6 13A8.8 8.8 0 0 1 11 3.4 9 9 0 1 0 20.6 13Z' }]],
  sun: [['circle', { cx: 12, cy: 12, r: 4 }], ['path', { d: 'M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5' }]],
  shield: [['path', { d: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' }]],
  shieldCheck: [
    ['path', { d: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' }],
    ['path', { d: 'M9 12l2 2 4-4' }],
  ],
  radar: [
    ['circle', { cx: '12', cy: '12', r: '9' }],
    ['circle', { cx: '12', cy: '12', r: '4' }],
    ['path', { d: 'M12 12l6.5-6.5' }],
  ],
  cloud: [['path', { d: 'M17.5 19H9a5 5 0 1 1 .9-9.9 6 6 0 0 1 11.1 2.4A4 4 0 0 1 17.5 19z' }]],
  layers: [
    ['polygon', { points: '12 2 2 7 12 12 22 7 12 2' }],
    ['polyline', { points: '2 12 12 17 22 12' }],
    ['polyline', { points: '2 17 12 22 22 17' }],
  ],
  lock: [
    ['rect', { x: '4', y: '11', width: '16', height: '10', rx: '2' }],
    ['path', { d: 'M8 11V7a4 4 0 0 1 8 0v4' }],
  ],
  cpu: [
    ['rect', { x: '6', y: '6', width: '12', height: '12', rx: '2' }],
    ['rect', { x: '9.5', y: '9.5', width: '5', height: '5' }],
    ['path', { d: 'M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4' }],
  ],
  server: [
    ['rect', { x: '3', y: '4', width: '18', height: '7', rx: '2' }],
    ['rect', { x: '3', y: '13', width: '18', height: '7', rx: '2' }],
    ['circle', { cx: '7', cy: '7.5', r: '1' }],
    ['circle', { cx: '7', cy: '16.5', r: '1' }],
  ],
  terminal: [
    ['rect', { x: '3', y: '4', width: '18', height: '16', rx: '2' }],
    ['path', { d: 'M7 15l4-3-4-3' }],
    ['path', { d: 'M13 15h4' }],
  ],
  bolt: [['polygon', { points: '13 2 4 14 11 14 10 22 20 10 13 10 13 2' }]],
  play: [['polygon', { points: '6 4 20 12 6 20 6 4' }]],
  refresh: [
    ['path', { d: 'M21 12a9 9 0 1 1-2.64-6.36' }],
    ['polyline', { points: '21 3 21 9 15 9' }],
  ],
  download: [
    ['path', { d: 'M12 3v12' }],
    ['polyline', { points: '7 10 12 15 17 10' }],
    ['path', { d: 'M4 19h16' }],
  ],
  check: [['polyline', { points: '20 6 9 17 4 12' }]],
  chevronDown: [['polyline', { points: '6 9 12 15 18 9' }]],
  arrowRight: [
    ['line', { x1: '4', y1: '12', x2: '20', y2: '12' }],
    ['polyline', { points: '14 6 20 12 14 18' }],
  ],
  rotateCcw: [
    ['polyline', { points: '3 4 3 10 9 10' }],
    ['path', { d: 'M3.51 15a9 9 0 1 0 2.13-9.36L3 10' }],
  ],
  eye: [
    ['path', { d: 'M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z' }],
    ['circle', { cx: '12', cy: '12', r: '3' }],
  ],
  globe: [
    ['circle', { cx: '12', cy: '12', r: '9' }],
    ['path', { d: 'M3 12h18' }],
    ['path', { d: 'M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18z' }],
  ],
  alert: [
    ['path', { d: 'M12 3L2 20h20L12 3z' }],
    ['line', { x1: '12', y1: '10', x2: '12', y2: '14' }],
    ['circle', { cx: '12', cy: '17', r: '0.8' }],
  ],
  stop: [['rect', { x: '6', y: '6', width: '12', height: '12', rx: '2' }]],
  key: [
    ['circle', { cx: '7.5', cy: '15.5', r: '4.5' }],
    ['path', { d: 'M11 12l9-9' }],
    ['path', { d: 'M17 6l3 3' }],
    ['path', { d: 'M15 8l2 2' }],
  ],
  home: [
    ['path', { d: 'M3 10.5L12 3l9 7.5' }],
    ['path', { d: 'M5 9.5V20h14V9.5' }],
  ],
  clipboardCheck: [
    ['rect', { x: '5', y: '4', width: '14', height: '17', rx: '2' }],
    ['path', { d: 'M9 4V2h6v2' }],
    ['path', { d: 'M9 13l2 2 4-4' }],
  ],
  sliders: [
    ['line', { x1: '4', y1: '7', x2: '20', y2: '7' }],
    ['circle', { cx: '9', cy: '7', r: '2' }],
    ['line', { x1: '4', y1: '17', x2: '20', y2: '17' }],
    ['circle', { cx: '15', cy: '17', r: '2' }],
  ],
  layoutPanel: [
    ['rect', { x: '3', y: '4', width: '18', height: '16', rx: '2' }],
    ['line', { x1: '3', y1: '9', x2: '21', y2: '9' }],
    ['line', { x1: '10', y1: '9', x2: '10', y2: '20' }],
  ],
  activity: [['polyline', { points: '3 12 7 12 10 5 14 19 17 12 21 12' }]],
  wrench: [['path', { d: 'M14.7 6.3a4 4 0 0 0-5.4 5.4L4 17l3 3 5.3-5.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2.5-2.5 2-2.5z' }]],
  file: [
    ['path', { d: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z' }],
    ['polyline', { points: '14 2 14 8 20 8' }],
  ],
  search: [
    ['circle', { cx: '11', cy: '11', r: '7' }],
    ['line', { x1: '16.5', y1: '16.5', x2: '21', y2: '21' }],
  ],
  clock: [
    ['circle', { cx: '12', cy: '12', r: '9' }],
    ['polyline', { points: '12 7 12 12 15.5 14' }],
  ],
  copy: [
    ['rect', { x: '9', y: '9', width: '13', height: '13', rx: '2' }],
    ['path', { d: 'M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1' }],
  ],
  code: [
    ['polyline', { points: '16 18 22 12 16 6' }],
    ['polyline', { points: '8 6 2 12 8 18' }],
  ],
  plus: [
    ['line', { x1: '12', y1: '5', x2: '12', y2: '19' }],
    ['line', { x1: '5', y1: '12', x2: '19', y2: '12' }],
  ],
  trash: [
    ['polyline', { points: '3 6 5 6 21 6' }],
    ['path', { d: 'M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6' }],
    ['path', { d: 'M10 11v6M14 11v6M9 6V4h6v2' }],
  ],
  plug: [
    ['path', { d: 'M12 22v-5' }],
    ['path', { d: 'M9 8V2M15 8V2' }],
    ['path', { d: 'M18 8H6v4a6 6 0 0 0 12 0V8z' }],
  ],
  chevronRight: [['polyline', { points: '9 18 15 12 9 6' }]],
};

function isToolParentEnabled(snap, tool) {
  if (!tool) return false;
  if (tool.external) return tool.serverEnabled !== false;
  const caps = snap?.capabilities || {};
  const allowExecConfig = snap?.sandbox?.configAllowExec === true;
  if (caps.error) {
    if (tool.group === 'context') return true;
    if (tool.group === 'execControl') return allowExecConfig;
    return false;
  }
  if (tool.group === 'context') return true;
  if (tool.group === 'fileRead') return Boolean(caps.fileRead);
  if (tool.group === 'fileWrite') return Boolean(caps.fileWrite);
  if (tool.group === 'execControl') return allowExecConfig;
  if (tool.group === 'exec') return Boolean(caps.fileRead && caps.allowExec && allowExecConfig);
  return true;
}

function getSingleToolStatusLabel(snap, tool) {
  if (!tool) return '未知';
  if (tool.individuallyDisabled) return '单工具已关';
  if (!isToolParentEnabled(snap, tool)) return tool.external ? '服务已停用' : '总开关限制';
  return tool.enabled ? '已启用' : '已停用';
}

function toggleSingleTool(tool, nextEnabled) {
  return runMutation(async () => {
    if (tool.external) {
      const res = await client.api('/api/mcp-servers/toggle', {
        method: 'POST',
        body: { id: tool.serverId, toolName: tool.rawToolName, enabled: nextEnabled },
      });
      if (res.snapshot) state.snapshot = res.snapshot;
    } else {
      const res = await client.api('/api/capabilities', {
        method: 'POST',
        body: { tools: { [tool.name]: nextEnabled } },
      });
      if (res.snapshot) state.snapshot = res.snapshot;
    }
    setNotice(`工具 ${tool.name} 已${nextEnabled ? '启用' : '单独停用'}。`);
  });
}

function makeStatStrip(cells) {
  return el('div', { class: 'lw-stat-strip' }, cells.map(c => el('div', { class: 'lw-stat-cell' }, [
    el('span', { class: 'lw-stat-k' }, [
      c.icon ? makeIcon(c.icon) : null,
      el('span', { text: c.label }),
    ]),
    el('span', { class: `lw-stat-v ${c.tone ? `is-${c.tone}` : ''}`, text: c.value }),
  ])));
}

function svgNodeBox({ x, y, w, h, title, sub, badge, stateCls = '', badgeCls = '', isDelta = false }) {
  const kids = [];
  if (isDelta) {
    kids.push(svgEl('rect', { x: x - 4, y: y - 4, width: w + 8, height: h + 8, rx: 10, class: 'lw-svg-halo' }));
  }
  kids.push(svgEl('rect', { x, y, width: w, height: h, rx: 7, class: `lw-svg-node-bg ${stateCls}` }));
  const tNode = svgEl('text', { x: x + 10, y: y + (sub || badge ? 19 : Math.round(h / 2) + 4), class: 'lw-svg-title' });
  tNode.textContent = title;
  kids.push(tNode);
  if (sub) {
    const sNode = svgEl('text', { x: x + 10, y: y + 35, class: 'lw-svg-sub' });
    sNode.textContent = sub;
    kids.push(sNode);
  }
  if (badge) {
    const bNode = svgEl('text', { x: x + 10, y: y + (h >= 62 ? 51 : 49), class: `lw-svg-badge ${badgeCls}` });
    bNode.textContent = badge;
    kids.push(bNode);
  }
  return svgEl('g', {}, kids);
}

function formatMetaChips(meta) {
  if (!meta || typeof meta !== 'object') return [el('span', { class: 'lw-muted', text: '-' })];
  const entries = Object.entries(meta).filter(([, v]) => v !== undefined && v !== null && v !== '');
  if (!entries.length) return [el('span', { class: 'lw-muted', text: '无附加字段' })];
  return entries.slice(0, 6).map(([k, v]) => {
    const valStr = typeof v === 'object' ? JSON.stringify(v) : String(v);
    return el('span', { class: 'lw-meta-chip' }, [
      el('span', { class: 'lw-meta-chip-k', text: k }),
      el('span', { class: 'lw-meta-chip-v', text: clipText(valStr, 36) }),
    ]);
  });
}

function classifyToolBoundary(toolName, isExternal = false) {
  const name = String(toolName || '');
  if (isExternal || name.startsWith('mcp__')) {
    return { icon: 'globe', label: '进程外 MCP（非容器）', tone: 'warn', desc: '经插件或第三方 MCP 服务运行于容器外，受权限与内容审查约束' };
  }
  if (/exec|command|bash|shell/i.test(name)) {
    return { icon: 'terminal', label: 'Docker 命令沙箱', tone: 'warn', desc: '仅限无入站网络的一次性受限 Linux 容器内执行命令' };
  }
  if (/write|edit|replace|delete|remove|patch|create/i.test(name)) {
    return { icon: 'lock', label: '工作区写入工具', tone: 'warn', desc: '需 fileWrite=true 与容器 :rw 挂载，否则物理拒绝写入' };
  }
  return { icon: 'file', label: 'Docker 只读沙箱', tone: 'ok', desc: '默认工作区 :ro 只读挂载与路径/Unicode 安全校验' };
}

function makeIcon(name, className = '') {
  const specs = ICON_SHAPES[name] || ICON_SHAPES.shield;
  return svgEl('svg', {
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    'stroke-width': '1.9',
    'stroke-linecap': 'round',
    'stroke-linejoin': 'round',
    'aria-hidden': 'true',
    ...(className ? { class: className } : {}),
  }, specs.map(([tag, attrs]) => svgEl(tag, attrs)));
}

function makeIconButton({ text, iconName, className = 'lw-btn', disabled = false, onClick, attrs = {} }) {
  return el('button', {
    type: 'button',
    class: className,
    disabled,
    ...attrs,
    ...(onClick ? { onClick } : {}),
  }, [
    iconName ? makeIcon(iconName) : null,
    el('span', { text }),
  ]);
}

function makeField(labelContent, controlNode, { fullWidth = false } = {}) {
  const labelNode = typeof labelContent === 'string'
    ? el('label', { class: 'lw-field-label', text: labelContent })
    : el('label', { class: 'lw-field-label lw-field-label-rich' }, [labelContent]);
  return el('div', { class: `lw-field ${fullWidth ? 'lw-field-full' : ''}` }, [
    labelNode,
    controlNode,
  ]);
}

function makeSelect(options, current, onChange, { iconName = null, isDelta = false } = {}) {
  const sel = el('select', { class: 'lw-select', ...(onChange ? { onChange } : {}) });
  for (const [val, label] of options) {
    const opt = el('option', { value: val, text: label });
    if (val === current) opt.selected = true;
    sel.append(opt);
  }
  return el('div', { class: `lw-select-box ${iconName ? 'has-lead' : ''} ${isDelta ? 'is-delta' : ''}` }, [
    iconName ? makeIcon(iconName, 'lw-select-lead') : null,
    sel,
    makeIcon('chevronDown', 'lw-select-caret'),
  ]);
}

function makeSwitchCard({
  checked,
  onChange,
  title,
  subtitle = '',
  pillText = '',
  pillTone = 'info',
  iconName = null,
  isDelta = false,
  disabled = false,
}) {
  const input = el('input', {
    type: 'checkbox',
    class: 'lw-switch-input',
    disabled,
    onChange: e => onChange?.(e.target.checked),
  });
  input.checked = Boolean(checked);
  const stateClass = pillTone === 'warn' ? 'is-warn' : (checked ? 'is-on' : '');
  return el('label', { class: `lw-setting-row ${isDelta ? 'is-delta' : ''}` }, [
    el('span', { class: 'lw-switch-main' }, [
      iconName ? makeIcon(iconName) : null,
      el('span', { class: 'lw-switch-copy' }, [
        el('span', { class: 'lw-row' }, [
          el('span', { class: 'lw-switch-label', text: title }),
          isDelta ? el('span', { class: 'lw-delta-tag', text: '将变更' }) : null,
        ]),
        subtitle ? el('span', { class: 'lw-switch-sub', text: subtitle }) : null,
      ]),
    ]),
    el('span', { class: 'lw-switch-ctrl' }, [
      pillText ? el('span', { class: `lw-switch-state ${stateClass}`, text: pillText }) : null,
      el('span', { class: 'lw-switch-pill' }, [
        input,
        el('span', { class: 'lw-switch-track', 'aria-hidden': 'true' }),
      ]),
    ]),
  ]);
}

function makeOptionCards({ options, value, savedValue, onSelect }) {
  return el('div', {
    class: 'lw-radio-list',
    role: 'radiogroup',
  }, options.map(opt => {
    const selected = value === opt.value;
    const isDelta = selected && savedValue !== undefined && savedValue !== value;
    return el('button', {
      type: 'button',
      role: 'radio',
      'aria-checked': String(selected),
      class: `lw-radio-item ${selected ? 'is-selected' : ''} ${isDelta ? 'is-delta' : ''}`,
      onClick: () => onSelect?.(opt.value),
    }, [
      el('div', { class: 'lw-radio-left' }, [
        makeIcon(opt.icon),
        el('div', {}, [
          el('div', { class: 'lw-radio-title', text: opt.title }),
          el('div', { class: 'lw-radio-desc', text: opt.desc }),
        ]),
      ]),
      el('div', { class: 'lw-radio-right' }, [
        isDelta
          ? el('span', { class: 'lw-delta-tag', text: '将变更' })
          : (opt.badge ? el('span', { class: `lw-pill ${opt.badgeTone ? `lw-pill-${opt.badgeTone}` : ''}`, text: opt.badge }) : null),
      ]),
    ]);
  }));
}

function makeSegmentedChoice({ options, value, savedValue, disabled = false, onSelect }) {
  return el('div', { class: 'lw-seg', role: 'radiogroup' }, options.map(opt => {
    const selected = value === opt.value;
    const isDelta = selected && savedValue !== undefined && savedValue !== value;
    return el('button', {
      type: 'button',
      role: 'radio',
      'aria-checked': String(selected),
      disabled: disabled || opt.disabled,
      class: `lw-seg-btn ${selected ? 'is-selected' : ''} ${isDelta ? 'is-delta' : ''}`,
      onClick: () => onSelect?.(opt.value),
    }, [
      opt.icon ? makeIcon(opt.icon) : null,
      el('span', { text: opt.label }),
    ]);
  }));
}

function makePageHeader(title, desc) {
  return el('div', { class: 'lw-page-head' }, [
    el('h1', { text: title, tabindex: '-1' }),
    desc ? el('p', { class: 'lw-page-desc', text: desc }) : null,
  ]);
}

const NAV_GROUPS = [
  { title: '工作台', pages: [
    { id: 'overview', label: '系统概览', icon: 'home' },
    { id: 'approvals', label: '审批队列', icon: 'clipboardCheck' },
    { id: 'audit', label: '实时审计', icon: 'activity' },
  ] },
  { title: '策略与权限', pages: [
    { id: 'capabilities', label: '能力与服务', icon: 'sliders' },
    { id: 'fencing', label: '安全围栏', icon: 'shield' },
    { id: 'moderation', label: '内容审查', icon: 'shieldCheck' },
    { id: 'secrets', label: '插件密钥', icon: 'key' },
  ] },
  { title: '工具与扩展', pages: [
    { id: 'tools', label: 'API 工作台', icon: 'code' },
    { id: 'panels', label: '扩展面板', icon: 'layoutPanel' },
  ] },
];
const drawerViewport = window.matchMedia('(max-width: 900px)');

function brand() {
  return el('div', { class: 'lw-brand' }, [
    el('img', { src: '/brand-icon.svg', alt: '', width: '39', height: '39' }),
    el('div', { class: 'lw-brand-copy' }, [
      el('strong', { text: 'LoomWard' }),
      el('span', { text: '织盾控制台' }),
    ]),
  ]);
}

function chromeButton(id, icon, label, action, attrs = {}) {
  return el('button', {
    id, type: 'button', class: 'lw-chrome-button', title: label, 'aria-label': label, onClick: action, ...attrs,
  }, [makeIcon(icon)]);
}

function setDrawer(open) {
  state.mobileNavOpen = open;
  render();
  root.querySelector(open ? '.lw-nav-item.active' : '#lw-menu-open')?.focus();
}

function renderTopbar() {
  const authed = Boolean(state.auth?.authenticated);
  const group = NAV_GROUPS.find(g => g.pages.some(p => p.id === state.page));
  const live = state.sseStatus === 'connected' || state.sseStatus === 'open';
  const streamLabel = live ? '推送在线' : state.sseStatus === 'connecting' ? '正在连接' : '推送未连接';
  const dark = theme.current() === 'dark';
  return el('header', { class: 'lw-topbar' }, [
    el('div', { class: 'lw-topbar-inner' }, [
      authed ? el('div', { class: 'lw-location' }, [
        chromeButton('lw-menu-open', 'menu', '打开导航', () => setDrawer(true), {
          class: 'lw-chrome-button lw-menu-btn', 'aria-controls': 'lw-navigation', 'aria-expanded': String(state.mobileNavOpen),
        }),
        el('span', { class: 'lw-location-root', text: '控制台' }),
        makeIcon('chevronRight'),
        el('strong', { text: group?.title || '工作台' }),
      ]) : brand(),
      el('div', { class: 'lw-topbar-actions' }, [
        authed ? el('span', { class: `lw-stream-state ${live ? 'is-online' : ''}`, text: streamLabel }) : null,
        chromeButton('lw-theme', dark ? 'sun' : 'moon', dark ? '切换到浅色' : '切换到深色', () => { theme.toggle(); render(); }),
        authed ? chromeButton('lw-lock', 'lock', '锁定退出', handleLogout, { disabled: state.busy }) : null,
      ]),
    ]),
  ]);
}

function renderSidebar() {
  const pending = state.snapshot?.approvals?.pendingCount;
  const cacheStatus = state.fencingData?.cache?.status;
  const session = state.auth?.previewMode ? '本地预览' : state.auth?.authMethod === 'passkey' ? 'PassKey 会话' : '密码会话';
  return el('aside', {
    id: 'lw-navigation', class: `lw-sidebar ${state.mobileNavOpen ? 'open' : ''}`, 'aria-label': '控制台导航',
  }, [
    el('div', { class: 'lw-sidebar-head' }, [
      brand(),
      chromeButton('lw-menu-close', 'close', '关闭导航', () => setDrawer(false), { class: 'lw-chrome-button lw-menu-btn' }),
    ]),
    el('nav', { class: 'lw-sidebar-nav', 'aria-label': '页面' }, NAV_GROUPS.map(group =>
      el('div', { class: 'lw-nav-group' }, [
        el('div', { class: 'lw-nav-group-title', text: group.title }),
        ...group.pages.map(item => el('button', {
          type: 'button', class: `lw-nav-item ${state.page === item.id ? 'active' : ''}`,
          'data-nav-id': item.id, 'aria-current': state.page === item.id ? 'page' : null,
          onClick: () => navigate(item.id),
        }, [
          makeIcon(item.icon), el('span', { text: item.label }),
          item.id === 'approvals' && pending > 0 ? el('span', { class: 'lw-nav-badge', text: String(pending) }) : null,
          item.id === 'fencing' && cacheStatus && cacheStatus !== 'fresh'
            ? el('span', { class: 'lw-nav-badge', 'aria-label': '围栏缓存需要检查', title: '围栏缓存需要检查', text: '!' }) : null,
        ])),
      ]),
    )),
    el('div', { class: 'lw-sidebar-footer' }, [
      makeIcon('lock'),
      el('div', {}, [
        el('strong', { text: session }),
        el('span', { text: state.auth?.sessionPersistence === 'browser' ? '浏览器会话' : '标签页隔离' }),
      ]),
    ]),
  ]);
}

drawerViewport.addEventListener('change', () => {
  if (state.mobileNavOpen && !drawerViewport.matches) { state.mobileNavOpen = false; render(); }
});
document.addEventListener('keydown', event => {
  if (!state.reviewModal && !state.mobileNavOpen) return;
  if (event.key === 'Escape') {
    event.preventDefault();
    if (state.reviewModal) { state.reviewModal = null; render(); }
    else setDrawer(false);
    return;
  }
  if (event.key !== 'Tab') return;
  const buttons = root.querySelectorAll(state.reviewModal ? '.lw-modal [tabindex="0"], .lw-modal button:not(:disabled)' : '.lw-sidebar button');
  const first = buttons[0], last = buttons[buttons.length - 1];
  if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
  if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
});

function renderAuthGate() {
  const auth = state.auth || {};
  const needPasskey = Boolean(
    auth.passkeyRequired
    || auth.requirePasskey
    || auth.mode === 'passkey'
    || auth.hostPasskeySupported
    || (auth.passkeyCount > 0)
    || (auth.passkeys?.length > 0),
  );
  const pwInput = el('input', {
    type: 'password',
    class: 'lw-input',
    value: state.draftAuth.password,
    placeholder: '输入本机强密码（≥14 位）',
    autocomplete: 'current-password',
    onInput: e => { state.draftAuth.password = e.target.value; },
  });
  const ticketInput = el('input', {
    type: 'text',
    class: 'lw-input lw-mono',
    value: state.draftAuth.setupToken,
    placeholder: '终端 webui-auth init 签发的一次性 setupToken',
    onInput: e => { state.draftAuth.setupToken = e.target.value; },
  });
  const labelInput = el('input', {
    type: 'text',
    class: 'lw-input',
    value: state.draftAuth.passkeyLabel,
    placeholder: 'PassKey 备注名称（如 YubiKey / Touch ID）',
    onInput: e => { state.draftAuth.passkeyLabel = e.target.value; },
  });

  const body = [];
  if (auth.previewAvailable) {
    body.push(el('div', { class: 'lw-doc-callout is-info', text: '当前运行于本地回环预览环境，无需终端初始化引导码即可直接进入控制台，仍保持同源 CSP 与 CSRF 保护。' }));
    body.push(el('div', { class: 'lw-row' }, [
      el('button', {
        type: 'button',
        class: 'lw-btn lw-btn-primary',
        disabled: state.busy,
        text: '一键进入本地预览（免初始化）',
        onClick: () => runMutation(async () => {
          await client.api('/api/auth/preview', { method: 'POST', body: {} });
          await refreshAuthState();
        }),
      }),
    ]));
  }
  if (!auth.initialized) {
    body.push(el('p', { class: 'lw-muted', text: '首次初始化须在本机终端执行 webui-auth init 获取一次性 setupToken，再在此控制台完成凭据绑定。' }));
    body.push(makeField('一次性初始化引导码 (setupToken)', ticketInput));
    if (needPasskey) {
      body.push(makeField('PassKey 备注名称', labelInput));
      body.push(el('div', { class: 'lw-row' }, [
        el('button', {
          type: 'button',
          class: 'lw-btn lw-btn-trust',
          disabled: state.busy,
          text: '使用 PassKey 完成初始化',
          onClick: () => handlePasskeyEnroll(state.draftAuth.setupToken.trim(), state.draftAuth.passkeyLabel.trim()),
        }),
      ]));
    } else {
      body.push(makeField('设置强密码（≥14 位）', pwInput));
      body.push(el('div', { class: 'lw-row' }, [
        el('button', {
          type: 'button',
          class: 'lw-btn lw-btn-trust',
          disabled: state.busy,
          text: '配置强密码并解锁',
          onClick: () => runMutation(async () => {
            await client.api('/api/auth/setup/password', {
              method: 'POST',
              body: { setupToken: state.draftAuth.setupToken.trim(), password: state.draftAuth.password },
            });
            state.draftAuth = { setupToken: '', password: '', passkeyLabel: '' };
            await refreshAuthState();
          }),
        }),
        el('button', {
          type: 'button',
          class: 'lw-btn',
          disabled: state.busy,
          text: '改用 PassKey 初始化',
          onClick: () => handlePasskeyEnroll(state.draftAuth.setupToken.trim(), 'Local PassKey'),
        }),
      ]));
    }
  } else if (needPasskey) {
    body.push(el('p', { class: 'lw-muted', text: '本机已启用强制 PassKey（WebAuthn）验证，请通过绑定硬件密钥或系统通行密钥解锁。' }));
    body.push(el('div', { class: 'lw-row' }, [
      el('button', {
        type: 'button',
        class: 'lw-btn lw-btn-trust',
        disabled: state.busy,
        text: '使用 PassKey 解锁控制台',
        onClick: handlePasskeyLogin,
      }),
    ]));
  } else {
    body.push(makeField('本机管理密码', pwInput));
    body.push(el('div', { class: 'lw-row' }, [
      el('button', {
        type: 'button',
        class: 'lw-btn lw-btn-trust',
        disabled: state.busy,
        text: '验证强密码解锁',
        onClick: () => runMutation(async () => {
          await client.api('/api/auth/login/password', {
            method: 'POST',
            body: { password: state.draftAuth.password },
          });
          state.draftAuth.password = '';
          await refreshAuthState();
        }),
      }),
    ]));
  }

  return el('section', { class: 'lw-card lw-auth-shell' }, [
    el('div', { class: 'lw-card-head' }, [
      el('div', {}, [
        el('h2', { text: '控制台身份验证' }),
        el('p', { class: 'lw-muted', text: '仅监听本机回环地址，融合 PassKey / 强密码鉴权、标签页令牌隔离与严格同源 CSP。' }),
      ]),
      el('span', { class: 'lw-pill lw-pill-warn', text: auth.initialized ? '已锁定' : '待初始化' }),
    ]),
    el('div', { class: 'lw-auth-form' }, body),
  ]);
}

function renderOverviewPage() {
  const heading = makePageHeader('系统概览', '查看待办审批、工作区权限与最近的工具调用。');
  const snap = state.snapshot;
  if (!snap) return el('div', { class: 'lw-stack-md' }, [heading, el('p', { role: 'status', text: '等待运行状态…' })]);

  const { approvals, capabilities: cap, daemon, kernel, events } = snap;
  const pending = approvals?.pendingCount;
  const units = kernel?.units;
  const roots = kernel?.roots;
  const mod = state.moderationConfig;
  const unknown = '未上报';
  const mount = { readonly: '只读', readwrite: '可读写', locked: '已锁定' }[cap?.mountMode] || unknown;
  const relay = daemon?.online === true ? '在线' : daemon?.online === false ? '离线' : unknown;
  const reviewMode = { 'local-only': '仅本地', 'cloud-first': '云端优先', 'hybrid-tiered': '分层审查' }[mod?.mode] || mod?.mode || unknown;

  function statusCard(label, value, hint, icon, tone, pageId) {
    return el('button', { type: 'button', class: 'lw-status-card', onClick: () => navigate(pageId) }, [
      el('span', { class: 'lw-status-label' }, [el('span', { class: 'lw-status-icon ' + tone }, [makeIcon(icon)]), label]),
      el('strong', { text: value }),
      el('span', { class: 'lw-status-foot' }, [hint, makeIcon('arrowRight')]),
    ]);
  }

  function flowNode(title, value, icon, pageId) {
    return el('button', { class: 'lw-flow-node', type: 'button', onClick: () => navigate(pageId) }, [
      makeIcon(icon), el('strong', { text: title }), el('span', { text: value }),
    ]);
  }

  function sectionBar(title, link, pageId) {
    return el('div', { class: 'lw-board-heading' }, [
      el('h2', { text: title }),
      link ? el('button', { class: 'lw-board-link', type: 'button', onClick: () => navigate(pageId) }, [link, makeIcon('chevronRight')]) : null,
    ]);
  }

  function fact(label, value) {
    return el('div', { class: 'lw-board-fact' }, [
      el('dt', { text: label }), el('dd', { text: value }),
    ]);
  }

  function switchValue(value) {
    return value === true ? '已启用' : value === false ? '已禁用' : unknown;
  }

  function unitNames(list) {
    if (!Array.isArray(list)) return unknown;
    return list.map(unit => unit.id || unit).join('、') || '无';
  }

  const auditRows = (events || []).slice(0, 5).map(event => {
    const date = new Date(event.time);
    const time = event.time && Number.isFinite(date.getTime());
    return el('li', { class: 'lw-recent-item' }, [
      el('span', { class: 'lw-event-dot is-' + event.tone, 'aria-hidden': 'true' }),
      el('div', {}, [
        el('strong', { text: event.name || event.source }),
        el('span', { text: event.label || event.source }),
      ]),
      time ? el('time', { datetime: event.time, title: date.toLocaleString(), text: date.toLocaleTimeString('zh-CN', { hour12: false }) }) : null,
    ]);
  });

  const topology = el('section', { class: 'lw-board-panel lw-map-panel' }, [
    el('div', { class: 'lw-board-heading' }, [
      el('h2', { text: '运行拓扑' }),
      el('button', {
        id: 'lw-map-toggle', type: 'button', class: 'lw-board-link', 'aria-controls': 'lw-flow-map',
        'aria-expanded': String(state.overviewTopologyOpen),
        onClick: () => {
          state.overviewTopologyOpen = !state.overviewTopologyOpen;
          render();
          document.getElementById('lw-map-toggle')?.focus({ preventScroll: true });
        },
      }, [state.overviewTopologyOpen ? '收起拓扑' : '展开拓扑', makeIcon('layers')]),
    ]),
    el('div', { id: 'lw-flow-map', class: 'lw-flow-map' + (state.overviewTopologyOpen ? ' is-open' : ''), role: 'group', 'aria-label': '运行拓扑，选择节点查看配置或队列' }, [
      el('div', { class: 'lw-flow-entry' }, [
        flowNode('云端中继', relay, 'cloud', 'capabilities'),
        el('span', { class: 'lw-flow-connector', 'aria-hidden': 'true' }, [makeIcon('arrowRight')]),
        flowNode('本机审批', pending == null ? unknown : pending + ' 项待处理', 'clipboardCheck', 'approvals'),
      ]),
      el('div', { class: 'lw-flow-hub' }, [makeIcon('shield'), el('strong', { text: 'LoomWard 宿主' })]),
      el('div', { class: 'lw-flow-branches' }, [
        flowNode('Docker 沙箱', mount, 'terminal', 'capabilities'),
        flowNode('内容审查', mod?.enabled === false ? '已关闭' : reviewMode, 'shieldCheck', 'moderation'),
        flowNode('进程外扩展', units ? units.length + ' 个单元' : unknown, 'layers', 'panels'),
      ]),
    ]),
  ]);

  return el('div', { class: 'lw-overview' }, [
    heading,
    el('div', { class: 'lw-status-grid' }, [
      statusCard('待审批请求', pending ?? '—', pending > 0 ? '前往处理' : '查看审批队列', 'clipboardCheck', pending > 0 ? 'amber' : 'blue', 'approvals'),
      statusCard('云端中继', relay, '查看宿主服务', 'cloud', daemon?.online ? 'green' : 'slate', 'capabilities'),
      statusCard('工作区挂载', mount, '查看沙箱权限', 'lock', cap?.mountMode === 'readonly' ? 'green' : cap?.mountMode ? 'amber' : 'slate', 'capabilities'),
      statusCard('进程外扩展', units?.length ?? '—', '查看扩展面板', 'layers', 'violet', 'panels'),
    ]),
    el('div', { class: 'lw-board-grid' }, [
      topology,
      el('section', { class: 'lw-board-panel' }, [
        sectionBar('最近审计', '查看全部', 'audit'),
        auditRows.length ? el('ul', { class: 'lw-recent' }, auditRows) : el('p', { class: 'lw-board-empty', text: events ? '暂无审计记录' : unknown }),
        snap.telemetry ? el('div', { class: 'lw-board-totals' }, [
          ['成功', snap.telemetry.totalAuditSuccess], ['失败', snap.telemetry.totalAuditFailed], ['策略拦截', snap.telemetry.totalBlocked],
        ].map(([label, value]) => el('span', {}, [label, el('b', { text: value ?? '—' })]))) : null,
      ]),
    ]),
    el('div', { class: 'lw-board-grid' }, [
      el('section', { class: 'lw-board-panel' }, [
        sectionBar('工作区权限', '管理能力', 'capabilities'),
        el('dl', { class: 'lw-board-facts' }, [
          fact('文件读取', switchValue(cap?.fileRead)),
          fact('文件写入', switchValue(cap?.fileWrite)),
          fact('容器命令执行', switchValue(cap?.allowExec)),
          fact('已启用工具', cap?.effectiveTools?.filter(tool => tool.enabled).length ?? unknown),
        ]),
      ]),
      el('section', { class: 'lw-board-panel' }, [
        sectionBar('扩展与凭据', '管理密钥', 'secrets'),
        el('dl', { class: 'lw-board-facts' }, [
          fact('根插件', unitNames(roots)),
          fact('进程外单元', unitNames(units)),
          fact('声明式面板', snap.panels?.length ?? unknown),
          fact('只写密钥', state.pluginSecretUnits == null ? unknown : state.pluginSecretUnits.reduce((n, unit) => n + (unit.keys?.length || 0), 0)),
        ]),
      ]),
    ]),
  ]);
}

function renderApprovalsPage() {
  const items = state.snapshot?.approvals?.items || [];

  const approvalFlowSvg = svgEl('svg', {
    viewBox: '0 0 356 286',
    class: 'lw-svg-diagram',
    role: 'img',
    'aria-label': '两步人工审批与单次消费防重放状态机',
  }, [
    svgEl('path', { d: 'M 178 54 L 178 78', class: 'lw-svg-wire lw-svg-wire-active' }),
    svgEl('path', { d: 'M 178 138 L 178 162', class: `lw-svg-wire ${items.length > 0 ? 'lw-svg-wire-warn' : 'lw-svg-wire-active'}` }),
    svgEl('path', { d: 'M 178 214 L 178 236', class: 'lw-svg-wire lw-svg-wire-active' }),
    svgNodeBox({
      x: 24, y: 8, w: 308, h: 46,
      title: '1. 冻结请求与 policyDigest 绑定',
      sub: '完整工具名 + 参数 + cwd + 超时绑定摘要',
      stateCls: 'is-active',
    }),
    svgNodeBox({
      x: 24, y: 78, w: 308, h: 60,
      title: '2. 待本机人工逐参复核队列',
      sub: items.length > 0 ? `当前 ${items.length} 条请求等待核对未脱敏参数` : '队列空闲（新请求经 SSE 即时推送）',
      badge: items.length > 0 ? '点击左侧「复核完整参数」' : '5 分钟未处理自动清理',
      stateCls: items.length > 0 ? 'is-warn' : 'is-ok',
      badgeCls: items.length > 0 ? 'is-warn' : 'is-muted',
      isDelta: items.length > 0,
    }),
    svgNodeBox({
      x: 24, y: 162, w: 308, h: 52,
      title: '3. 人工比对一致并签发单次凭证',
      sub: '仅限当前精确 id + digest，不自动扩展权限',
      stateCls: 'is-active',
    }),
    svgNodeBox({
      x: 24, y: 236, w: 308, h: 42,
      title: '4. 沙箱/扩展执行 + 24h 防重放登记',
      sub: '同一凭证严禁二次重放或并发消费',
      stateCls: 'is-ok',
    }),
  ]);

  const queueContent = items.length
    ? el('div', { class: 'lw-setting-list' }, items.map(item => {
        const leftSec = Math.max(0, Math.ceil((Date.parse(item.expiresAt) - Date.now()) / 1000));
        const pct = Math.max(0, Math.min(100, Math.round((leftSec / 300) * 100)));
        const boundary = classifyToolBoundary(item.tool, item.tool?.startsWith('mcp__'));
        return el('div', { class: 'lw-approval-row' }, [
          el('div', { class: 'lw-approval-main' }, [
            el('div', { class: 'lw-row' }, [
              makeIcon(boundary.icon),
              el('strong', { class: 'lw-mono', text: `${item.tool} · #${item.idShort}` }),
              el('span', { class: `lw-pill lw-pill-${boundary.tone}`, text: boundary.label }),
              el('span', {
                class: `lw-pill ${leftSec <= 30 ? 'lw-pill-err' : 'lw-pill-warn'}`,
                'data-countdown-expires': item.expiresAt,
                'data-warn-threshold': '30',
                text: `剩余 ${leftSec}s`,
              }),
            ]),
            el('div', { class: 'lw-muted lw-mono', text: `client=${item.clientId || 'unknown'} · ${item.alreadyApproved ? '已签发单次许可（等待连接器消费）' : '等待点击复核完整未脱敏参数'}` }),
            el('div', { class: 'lw-progress-track', style: 'max-width:320px' }, [
              el('div', { class: 'lw-progress-bar', style: `width:${pct}%` }),
            ]),
          ]),
          el('div', { class: 'lw-btn-group' }, [
            item.approvable
              ? makeIconButton({
                  text: '复核完整参数',
                  iconName: 'eye',
                  className: 'lw-btn lw-btn-trust lw-btn-sm',
                  disabled: state.busy || leftSec <= 0,
                  attrs: { 'data-countdown-disable-expires': item.expiresAt, 'data-review-id': item.id },
                  onClick: () => runMutation(async () => {
                    const review = await client.api('/api/approvals/review', { method: 'POST', body: { id: item.id } });
                    state.reviewModal = { ...review, tool: item.tool, expiresAt: item.expiresAt };
                  }),
                })
              : null,
            item.id
              ? makeIconButton({
                  text: '拒绝并移除',
                  iconName: 'stop',
                  className: 'lw-btn lw-btn-danger lw-btn-sm',
                  disabled: state.busy,
                  onClick: () => runMutation(async () => {
                    const res = await client.api('/api/approvals/reject', { method: 'POST', body: { id: item.id } });
                    if (res.snapshot) state.snapshot = res.snapshot;
                    setNotice(`已拒绝请求 #${item.idShort}。`);
                  }),
                })
              : null,
          ]),
        ]);
      }))
    : el('div', { class: 'lw-doc-callout is-ok' }, [
        el('div', { text: '当前无待人工批准的工具请求。任何需要本机批准的敏感操作触发时，都将经 SSE 实时推送到此队列。' }),
      ]);

  const splitLayout = el('div', { class: 'lw-doc-split' }, [
    el('div', { class: 'lw-doc-main' }, [
      makeStatStrip([
        { icon: 'clipboardCheck', label: '待审请求', value: `${items.length} 条`, tone: items.length > 0 ? 'warn' : 'ok' },
        { icon: 'lock', label: '批准粒度', value: '全参摘要精确绑定' },
        { icon: 'shieldCheck', label: '消费约束', value: '单次 + 24h 防重放' },
        { icon: 'clock', label: '请求超时', value: '5 分钟自动清理' },
      ]),
      el('section', { class: 'lw-section' }, [
        el('div', { class: 'lw-section-head' }, [
          el('div', {}, [
            el('h3', { text: '实时待批请求队列' }),
            el('p', { text: '点击「复核完整参数」查看原始未脱敏请求文本与 policyDigest，再决定是否放行一次。' }),
          ]),
          el('span', { class: `lw-pill ${items.length ? 'lw-pill-warn' : 'lw-pill-ok'}`, text: `${items.length} 条待审` }),
        ]),
        queueContent,
      ]),
    ]),
    el('aside', { class: 'lw-doc-aside' }, [
      el('div', { class: 'lw-section-head' }, [
        el('div', {}, [
          el('h3', { text: '人工审批状态机' }),
          el('p', { text: '禁止以云端身份校验替代本机精确放行' }),
        ]),
        el('span', { class: `lw-pill ${items.length > 0 ? 'lw-pill-warn' : 'lw-pill-ok'}`, text: items.length > 0 ? '等待批复' : '空闲就绪' }),
      ]),
      approvalFlowSvg,
      el('div', { class: 'lw-aside-list' }, [
        el('div', { class: 'lw-aside-row' }, [
          el('span', { class: 'lw-muted', text: '参数可见性' }),
          el('strong', { text: '复核弹窗完整不脱敏' }),
        ]),
        el('div', { class: 'lw-aside-row' }, [
          el('span', { class: 'lw-muted', text: '写操作断连' }),
          el('strong', { text: '超时/取消绝不自动重试' }),
        ]),
        el('div', { class: 'lw-aside-row' }, [
          el('span', { class: 'lw-muted', text: '多标签竞争' }),
          el('strong', { text: '单次原子签发与消费' }),
        ]),
      ]),
    ]),
  ]);

  return el('div', { class: 'lw-stack-md' }, [
    makePageHeader('审批队列', '核对工具与调用参数后，可批准一次执行或拒绝请求。'),
    splitLayout,
  ]);
}

function renderCapabilitiesPage() {
  const cap = state.snapshot?.capabilities || {};
  const persistence = state.auth?.sessionPersistence || 'tab';
  const mountRw = cap.mountMode === 'readwrite' || Boolean(cap.fileWrite);

  const updateCap = (label, field, nextVal) => runMutation(async () => {
    const res = await client.api('/api/capabilities', { method: 'POST', body: { [field]: nextVal } });
    if (res.snapshot) state.snapshot = res.snapshot;
    setNotice(`已更新能力开关：${label} → ${nextVal ? '开启' : '关闭'}。`);
  });

  const serviceBtn = (label, action, iconName, danger = false) => makeIconButton({
    text: label,
    iconName,
    className: `lw-btn lw-btn-sm ${danger ? 'lw-btn-danger' : ''}`,
    disabled: state.busy,
    onClick: () => runMutation(async () => {
      const res = await client.api('/api/service', { method: 'POST', body: { action } });
      if (res.snapshot) state.snapshot = res.snapshot;
      setNotice(`服务操作 ${action} 已完成。`);
    }),
  });

  const daemonOnline = Boolean(state.snapshot?.daemon?.online);
  const boundarySvg = svgEl('svg', {
    viewBox: '0 0 356 254',
    class: 'lw-svg-diagram',
    role: 'img',
    'aria-label': '工作区挂载与 Docker 沙箱及会话隔离边界示意图',
  }, [
    svgEl('path', {
      d: 'M 148 39 L 194 39',
      class: `lw-svg-wire ${mountRw ? 'lw-svg-wire-warn' : 'lw-svg-wire-active'}`,
    }),
    svgEl('path', { d: 'M 272 68 L 272 96', class: 'lw-svg-wire lw-svg-wire-active' }),
    svgEl('path', { d: 'M 178 152 L 178 182', class: 'lw-svg-wire lw-svg-wire-active' }),
    svgNodeBox({
      x: 8, y: 10, w: 140, h: 58,
      title: '宿主工作区',
      sub: 'workspaceRoots',
      badge: mountRw ? ':rw 读写映射' : ':ro 只读映射',
      stateCls: 'is-active',
      badgeCls: mountRw ? 'is-warn' : 'is-ok',
    }),
    svgNodeBox({
      x: 196, y: 10, w: 152, h: 58,
      title: 'Linux Docker 沙箱',
      sub: `读:${cap.fileRead ? 'ON' : 'OFF'} · 命:${cap.allowExec ? 'ON' : 'OFF'}`,
      badge: cap.allowExec ? 'exec 开启 · 默认无外网' : '无入站 / 默认无出站',
      stateCls: mountRw || cap.allowExec ? 'is-warn' : 'is-ok',
      badgeCls: mountRw || cap.allowExec ? 'is-warn' : 'is-ok',
    }),
    svgNodeBox({
      x: 8, y: 96, w: 340, h: 56,
      title: '受保护连接器守护进程',
      sub: daemonOnline ? '已在线接入云端中继' : '本地待命（热响应 capabilities.json）',
      badge: '从受保护安装目录运行 · 不自动覆盖',
      stateCls: 'is-active',
      badgeCls: 'is-muted',
    }),
    svgNodeBox({
      x: 8, y: 182, w: 340, h: 58,
      title: '控制台浏览器会话认证边界',
      sub: persistence === 'tab' ? 'X-LoomWard-Tab-Auth 单标签页隔离' : '浏览器同源共享会话',
      badge: persistence === 'tab' ? '关闭标签页即锁定（推荐）' : '多标签页共享已解锁态',
      stateCls: persistence === 'tab' ? 'is-ok' : 'is-warn',
      badgeCls: persistence === 'tab' ? 'is-ok' : 'is-warn',
    }),
  ]);

  const applyCapPreset = (label, nextBody) => runMutation(async () => {
    const res = await client.api('/api/capabilities', { method: 'POST', body: nextBody });
    if (res.snapshot) state.snapshot = res.snapshot;
    setNotice(`已应用预设姿态：${label}。`);
  });

  const canExecConfig = state.snapshot?.sandbox?.configAllowExec !== false;
  const disabledIndivCount = (cap.effectiveTools || []).filter(t => !t.external && t.individuallyDisabled).length;

  const splitLayout = el('div', { class: 'lw-doc-split' }, [
    el('div', { class: 'lw-doc-main' }, [
      makeStatStrip([
        { icon: 'eye', label: '文件读取', value: cap.fileRead ? '允许读取' : '已熔断拦截', tone: cap.fileRead ? 'ok' : 'err' },
        { icon: 'lock', label: '工作区挂载', value: mountRw ? '读写开放 (rw)' : '只读锁定 (:ro)', tone: mountRw ? 'warn' : 'ok' },
        { icon: 'terminal', label: '容器命令', value: cap.allowExec ? '沙箱执行开放' : '已安全禁用', tone: cap.allowExec ? 'warn' : 'ok' },
        { icon: 'shieldCheck', label: '会话隔离', value: persistence === 'tab' ? '标签页令牌隔离' : '浏览器共享会话' },
      ]),
      el('section', { class: 'lw-section' }, [
        el('div', { class: 'lw-section-head' }, [
          el('div', {}, [
            el('h3', { text: '核心能力熔断开关' }),
            el('p', { text: '切换开关立即原子写入 <stateDir>/capabilities.json 并生效于沙箱容器，无需重启连接器。' }),
          ]),
          el('span', { class: `lw-pill ${mountRw ? 'lw-pill-warn' : 'lw-pill-ok'}`, text: `mount: ${cap.mountMode || 'readonly'}` }),
        ]),
        el('div', { class: 'lw-btn-group' }, [
          makeIconButton({
            text: canExecConfig ? '完整读写（含容器命令）' : '完整读写（无命令权限）',
            iconName: 'bolt',
            className: `lw-btn lw-btn-sm ${cap.fileRead && cap.fileWrite && (!canExecConfig || cap.allowExec) ? 'lw-btn-primary' : ''}`,
            disabled: state.busy,
            onClick: () => applyCapPreset('完整读写', { fileRead: true, fileWrite: true, ...(canExecConfig ? { allowExec: true } : {}) }),
          }),
          makeIconButton({
            text: '仅只读锁定 (:ro)',
            iconName: 'eye',
            className: `lw-btn lw-btn-sm ${cap.fileRead && !cap.fileWrite && !cap.allowExec ? 'lw-btn-primary' : ''}`,
            disabled: state.busy,
            onClick: () => applyCapPreset('仅只读', { fileRead: true, fileWrite: false, allowExec: false }),
          }),
          makeIconButton({
            text: '全量锁定工作区读写',
            iconName: 'lock',
            className: `lw-btn lw-btn-sm lw-btn-danger ${!cap.fileRead && !cap.fileWrite && !cap.allowExec ? 'lw-btn-primary' : ''}`,
            disabled: state.busy,
            onClick: () => applyCapPreset('禁用文件读写', { fileRead: false, fileWrite: false, allowExec: false }),
          }),
          makeIconButton({
            text: disabledIndivCount > 0 ? `API 工作台（已单关 ${disabledIndivCount} 项）` : '在 API 工作台逐个管理工具',
            iconName: 'code',
            className: 'lw-btn lw-btn-sm',
            onClick: () => navigate('tools'),
          }),
        ]),
        el('div', { class: 'lw-setting-list' }, [
          makeSwitchCard({
            checked: Boolean(cap.fileRead),
            onChange: next => updateCap('文件读取 (fileRead)', 'fileRead', next),
            title: '文件读取 (fileRead)',
            subtitle: '控制 read_file / list_directory / search_files 及工作区读取权限',
            pillText: cap.fileRead ? '已启用' : '已关闭',
            pillTone: cap.fileRead ? 'ok' : 'err',
            iconName: 'eye',
            disabled: state.busy,
          }),
          makeSwitchCard({
            checked: Boolean(cap.fileWrite),
            onChange: next => updateCap('文件写入 (fileWrite)', 'fileWrite', next),
            title: '文件写入 (fileWrite)',
            subtitle: '关闭后彻底封锁写入，并将 Linux Docker /workspace 自动降级为只读挂载 (:readonly)',
            pillText: cap.fileWrite ? '读写开放' : '只读保护中',
            pillTone: cap.fileWrite ? 'warn' : 'ok',
            iconName: 'lock',
            disabled: state.busy,
          }),
          makeSwitchCard({
            checked: Boolean(cap.allowExec),
            onChange: next => updateCap('容器命令 (allowExec)', 'allowExec', next),
            title: '容器命令 (allowExec)',
            subtitle: '控制一次性只读 Linux 容器内 exec_command 执行能力（默认无出站网络）',
            pillText: cap.allowExec ? '已启用' : '已禁用',
            pillTone: cap.allowExec ? 'warn' : 'ok',
            iconName: 'terminal',
            disabled: state.busy,
          }),
        ]),
        el('div', { class: 'lw-tool-chip-block' }, [
          el('div', { class: 'lw-tool-chip-head' }, [
            el('div', { class: 'lw-stack-md', style: 'gap:2px' }, [
              el('strong', { text: '单工具独立开关矩阵（内置沙箱 + 第三方 MCP）' }),
              el('span', { class: 'lw-muted', text: '点击左侧工具名直达 API 接口工作台查看契约；右侧拨片可逐项单独停用或恢复单个 MCP 工具。' }),
            ]),
            el('span', {
              class: 'lw-pill lw-pill-info',
              text: `${(cap.effectiveTools || []).filter(t => t.enabled).length} / ${(cap.effectiveTools || []).length} 可用`,
            }),
          ]),
          el('div', { class: 'lw-tool-chip-grid' }, (cap.effectiveTools || []).map(tool => {
            const parentOn = isToolParentEnabled(state.snapshot, tool);
            const switchDisabled = state.busy || (!parentOn && !tool.individuallyDisabled);
            const sw = el('input', {
              type: 'checkbox',
              class: 'lw-switch-input',
              disabled: switchDisabled,
              'aria-label': `独立开关 ${tool.name}`,
              'data-cap-tool-switch': tool.name,
              onChange: e => { void toggleSingleTool(tool, e.target.checked); },
            });
            sw.checked = Boolean(tool.enabled && !tool.individuallyDisabled);
            return el('div', { class: `lw-tool-chip ${tool.enabled ? '' : 'is-off'}` }, [
              el('button', {
                type: 'button',
                class: 'lw-tool-chip-link',
                title: `在 API 接口工作台查看 ${tool.name}（${getSingleToolStatusLabel(state.snapshot, tool)}）`,
                onClick: () => navigate('tools', { selectedToolName: tool.name }),
              }, [
                el('span', { class: `lw-apifox-dot ${tool.enabled ? 'is-ok' : 'is-err'}` }),
                el('span', { class: 'lw-tool-chip-link-text' }, [
                  el('span', { class: 'lw-tool-chip-name', text: tool.name }),
                  el('span', {
                    class: 'lw-tool-chip-sub',
                    text: `${tool.external ? '外部 MCP' : (tool.kind || 'MCP')} · ${getSingleToolStatusLabel(state.snapshot, tool)}`,
                  }),
                ]),
              ]),
              el('label', { class: 'lw-switch-pill' }, [
                sw,
                el('span', { class: 'lw-switch-track', 'aria-hidden': 'true' }),
              ]),
            ]);
          })),
        ]),
      ]),
      el('section', { class: 'lw-section' }, [
        el('div', { class: 'lw-section-head' }, [
          el('div', {}, [
            el('h3', { text: '会话隔离与宿主守护进程控制' }),
            el('p', { text: '默认启用标签页令牌隔离（X-LoomWard-Tab-Auth），关闭标签页自动锁定。' }),
          ]),
          el('span', { class: 'lw-pill lw-pill-info', text: persistence === 'tab' ? '标签页隔离' : '浏览器会话' }),
        ]),
        makeField('会话持久化策略', makeSegmentedChoice({
          value: persistence,
          disabled: state.busy,
          options: [
            { value: 'tab', label: '标签页隔离（推荐）', icon: 'shieldCheck' },
            { value: 'browser', label: '同浏览器复用会话', icon: 'globe' },
          ],
          onSelect: nextMode => runMutation(async () => {
            const res = await client.api('/api/auth/settings', { method: 'POST', body: { sessionPersistence: nextMode } });
            if (res.authState) state.auth = res.authState;
            if (res.snapshot) state.snapshot = res.snapshot;
            if (nextMode === 'tab') startLiveStream();
            setNotice(nextMode === 'tab' ? '已启用标签页隔离认证并轮换令牌。' : '已切换为浏览器会话模式。');
          }),
        })),
        el('div', { class: 'lw-btn-group' }, [
          serviceBtn('启动连接器', 'start', 'play'),
          serviceBtn('重启连接器', 'restart', 'refresh'),
          serviceBtn('停止连接器', 'stop', 'stop', true),
        ]),
      ]),
    ]),
    el('aside', { class: 'lw-doc-aside' }, [
      el('div', { class: 'lw-section-head' }, [
        el('div', {}, [
          el('h3', { text: '实时物理边界态势' }),
          el('p', { text: '能力开关与容器挂载参数联动矩阵' }),
        ]),
        el('span', { class: `lw-pill ${mountRw || cap.allowExec ? 'lw-pill-warn' : 'lw-pill-ok'}`, text: mountRw ? ':rw 模式' : ':ro 只读锁定' }),
      ]),
      boundarySvg,
      el('div', { class: 'lw-aside-list' }, [
        el('div', { class: 'lw-aside-row' }, [
          el('span', { class: 'lw-muted', text: '文件读工具组' }),
          el('strong', { text: cap.fileRead ? 'read / list / search 可用' : '已熔断拒绝' }),
        ]),
        el('div', { class: 'lw-aside-row' }, [
          el('span', { class: 'lw-muted', text: '文件写工具组' }),
          el('strong', { text: cap.fileWrite ? 'write / replace 需审批' : '内核级只读封锁' }),
        ]),
        el('div', { class: 'lw-aside-row' }, [
          el('span', { class: 'lw-muted', text: '命令执行工具' }),
          el('strong', { text: cap.allowExec ? '无入站 Docker exec_command' : '已禁用' }),
        ]),
      ]),
    ]),
  ]);

  return el('div', { class: 'lw-stack-md' }, [
    makePageHeader('能力与服务', '管理工作区读写、命令执行和宿主服务。'),
    splitLayout,
  ]);
}

function getDraftModConfig() {
  if (!state.draftMod) {
    state.draftMod = structuredClone(state.moderationConfig || DEFAULT_MOD_CONFIG);
  }
  return state.draftMod;
}

function applyOllamaModelChoice(role, modelName, endpoint, allowPrivateNetwork) {
  const cfg = getDraftModConfig();
  const normalizedEp = (endpoint || '').trim() || 'http://127.0.0.1:11434';
  if (role === 'canary') {
    cfg.canary = {
      ...(cfg.canary || {}),
      enabled: true,
      kind: 'ollama',
      endpoint: normalizedEp,
      model: modelName,
      allowPrivateNetwork: Boolean(allowPrivateNetwork),
      think: cfg.canary?.think ?? false,
    };
    setNotice(`已将 Canary 探测模型设为 ${modelName}（${normalizedEp}），请点击下方「保存审核策略配置」生效。`);
    return;
  }
  cfg.localGuard = {
    ...(cfg.localGuard || {}),
    kind: 'ollama',
    endpoint: normalizedEp,
    model: modelName,
    allowPrivateNetwork: Boolean(allowPrivateNetwork),
    think: cfg.localGuard?.think ?? false,
  };
  setNotice(`已将本地 Guard 模型设为 ${modelName}（${normalizedEp}），请点击下方「保存审核策略配置」生效。`);
}

function renderOllamaManagerCard() {
  const ol = state.ollama;
  const activeEp = state.ollamaEndpointInput || ol?.endpoint || 'http://127.0.0.1:11434';
  const installedNames = new Set((ol?.models || []).map(m => m.name));
  const loadedNames = new Set(
    (ol?.loadedModels || []).map(x => (typeof x === 'string' ? x : (x?.name || x?.model || ''))).filter(Boolean),
  );

  const probeInput = el('input', {
    type: 'url',
    class: 'lw-input lw-mono',
    value: activeEp,
    placeholder: 'http://127.0.0.1:11434 或受信任局域网 GPU 地址',
    onInput: e => { state.ollamaEndpointInput = e.target.value; },
  });

  const allowPrivChk = el('input', {
    type: 'checkbox',
    onChange: e => { state.ollamaAllowPrivate = e.target.checked; },
  });
  allowPrivChk.checked = Boolean(state.ollamaAllowPrivate);

  const pullInput = el('input', {
    type: 'text',
    class: 'lw-input lw-mono',
    value: state.ollamaPullTag,
    placeholder: '输入模型标签，如 llama-guard3:1b、shieldgemma:2b、qwen3:0.6b',
    onInput: e => { state.ollamaPullTag = e.target.value; },
  });

  const recModels = Array.isArray(ol?.recommendedModels) ? ol.recommendedModels : [];
  const pullJobs = Array.isArray(ol?.pullJobs) ? ol.pullJobs : [];

  const headerActions = [
    makeIconButton({
      text: state.ollamaLoading ? '探测中...' : '刷新探测',
      iconName: 'refresh',
      className: 'lw-btn lw-btn-sm',
      disabled: state.busy || state.ollamaLoading,
      onClick: () => { void loadOllamaStatus(); },
    }),
  ];

  if (ol && ol.installed && !ol.running) {
    headerActions.push(makeIconButton({
      text: '启动本地 Ollama',
      iconName: 'play',
      className: 'lw-btn lw-btn-sm lw-btn-trust',
      disabled: state.busy,
      onClick: () => runMutation(async () => {
        const res = await client.api('/api/moderation/ollama/start', {
          method: 'POST',
          body: { endpoint: activeEp },
        });
        await loadOllamaStatus({ endpoint: res.endpoint || activeEp, silent: true });
        setNotice(res.alreadyRunning ? `Ollama 已运行中（${res.version || ''}）。` : `已启动本地 Ollama（PID ${res.pid || '-'}）。`);
      }),
    }));
  }

  if (!ol || !ol.installed) {
    headerActions.push(makeIconButton({
      text: '一键安装 Ollama',
      iconName: 'download',
      className: 'lw-btn lw-btn-sm lw-btn-trust',
      disabled: state.busy,
      onClick: () => {
        state.ollamaInstallConfirm = !state.ollamaInstallConfirm;
        render();
      },
    }));
  }

  const bodyChildren = [
    el('div', { class: 'lw-stack-md' }, [
      el('div', { class: 'lw-ollama-probe-row' }, [
        probeInput,
        makeIconButton({
          text: '探测端点',
          iconName: 'radar',
          className: 'lw-btn lw-btn-sm',
          disabled: state.busy || state.ollamaLoading,
          onClick: () => { void loadOllamaStatus({ endpoint: state.ollamaEndpointInput, allowPrivateNetwork: state.ollamaAllowPrivate }); },
        }),
      ]),
      makeSwitchCard({
        checked: Boolean(state.ollamaAllowPrivate),
        onChange: next => {
          state.ollamaAllowPrivate = next;
          render();
        },
        title: '探测受信任私有局域网 HTTP Ollama（如 192.168.x.x:11434 GPU 节点）',
        subtitle: '仅在当前面板探针开放内网 IP 访问，对 169.254.169.254 与公网明文 HTTP 持续硬阻断',
        pillText: state.ollamaAllowPrivate ? '已放行局域网探针' : '仅回环 / HTTPS',
        pillTone: state.ollamaAllowPrivate ? 'warn' : 'info',
        iconName: 'server',
      }),
    ]),
  ];

  if (state.ollamaInstallConfirm) {
    bodyChildren.push(el('div', { class: 'lw-ollama-confirm' }, [
      el('div', {
        text: '确认在当前宿主机安装 Ollama 二进制？安装脚本仅继承受限 PATH/HOME 等安全环境变量（已剥离 LoomWard 凭据）。',
      }),
      el('div', { class: 'lw-row lw-end' }, [
        makeIconButton({
          text: '取消',
          iconName: 'rotateCcw',
          className: 'lw-btn lw-btn-sm',
          disabled: state.busy,
          onClick: () => { state.ollamaInstallConfirm = false; render(); },
        }),
        makeIconButton({
          text: '确认执行安装',
          iconName: 'check',
          className: 'lw-btn lw-btn-sm lw-btn-trust',
          disabled: state.busy,
          onClick: () => runMutation(async () => {
            const res = await client.api('/api/moderation/ollama/install', {
              method: 'POST',
              body: { confirmInstall: true },
            });
            state.ollamaInstallConfirm = false;
            await loadOllamaStatus({ endpoint: activeEp, silent: true });
            setNotice(res.alreadyInstalled
              ? `检测到本机已安装 Ollama：${res.binaryPath}`
              : `Ollama 安装完成：${res.binaryPath || '已就绪'}`);
          }),
        }),
      ]),
    ]));
  }

  if (state.ollamaError || ol?.error) {
    bodyChildren.push(el('div', {
      class: 'lw-banner lw-banner-err',
      role: 'alert',
      text: state.ollamaError || ol.error,
    }));
  }

  if (state.ollamaTestResult) {
    const tr = state.ollamaTestResult;
    bodyChildren.push(el('div', {
      class: 'lw-banner lw-banner-ok',
      role: 'status',
      text: `推理测试成功 · ${tr.model} · 耗时 ${tr.latencyMs} ms · 返回预览：${tr.replyPreview || '(empty)'}`,
    }));
  }

  const draftGuardModel = getDraftModConfig()?.localGuard?.model || '';
  const draftCanaryModel = getDraftModConfig()?.canary?.model || '';
  const models = Array.isArray(ol?.models) ? ol.models : [];
  bodyChildren.push(el('section', { class: 'lw-section' }, [
    el('div', { class: 'lw-section-head' }, [
      el('div', {}, [
        el('h3', { text: `已安装模型 (${models.length})` }),
        el('p', { text: '点击指派将直接填入 Guard 或 Canary 路由表单，并可在当前端点实时测速。' }),
      ]),
    ]),
    models.length
      ? el('div', { class: 'lw-table-wrap' }, [
          el('table', { class: 'lw-table' }, [
            el('thead', {}, [el('tr', {}, [
              el('th', { text: '模型标识' }),
              el('th', { text: '参数 / 大小' }),
              el('th', { text: '运行态与特性' }),
              el('th', { text: '指派与测速' }),
            ])]),
            el('tbody', {}, models.map(m => {
              const isLoaded = loadedNames.has(m.name);
              const caps = Array.isArray(m.capabilities) ? m.capabilities : [];
              const isGuardSelected = draftGuardModel === m.name;
              const isCanarySelected = draftCanaryModel === m.name;
              return el('tr', {}, [
                el('td', { class: 'lw-mono', text: m.name }),
                el('td', { class: 'lw-mono', text: [m.parameterSize, m.sizeLabel].filter(Boolean).join(' · ') || '-' }),
                el('td', {}, [
                  el('div', { class: 'lw-row' }, [
                    isLoaded ? el('span', { class: 'lw-pill lw-pill-ok', text: 'VRAM 常驻' }) : null,
                    ...caps.slice(0, 3).map(cap => el('span', {
                      class: `lw-pill ${cap === 'thinking' ? 'lw-pill-warn' : ''}`,
                      text: cap === 'thinking' ? 'thinking (默认关闭)' : cap,
                    })),
                  ]),
                ]),
                el('td', {}, [
                  el('div', { class: 'lw-btn-group' }, [
                    makeIconButton({
                      text: isGuardSelected ? 'Guard 已选' : '设为 Guard',
                      iconName: 'shieldCheck',
                      className: `lw-btn lw-btn-sm ${isGuardSelected ? 'is-active' : ''}`,
                      disabled: state.busy,
                      onClick: () => applyOllamaModelChoice('guard', m.name, activeEp, state.ollamaAllowPrivate),
                    }),
                    makeIconButton({
                      text: isCanarySelected ? 'Canary 已选' : '设为 Canary',
                      iconName: 'radar',
                      className: `lw-btn lw-btn-sm ${isCanarySelected ? 'is-active' : ''}`,
                      disabled: state.busy,
                      onClick: () => applyOllamaModelChoice('canary', m.name, activeEp, state.ollamaAllowPrivate),
                    }),
                    makeIconButton({
                      text: '测速',
                      iconName: 'bolt',
                      className: 'lw-btn lw-btn-sm',
                      disabled: state.busy,
                      onClick: () => runMutation(async () => {
                        const res = await client.api('/api/moderation/ollama/test', {
                          method: 'POST',
                          body: {
                            model: m.name,
                            endpoint: activeEp,
                            allowPrivateNetwork: Boolean(state.ollamaAllowPrivate),
                            think: false,
                          },
                        });
                        state.ollamaTestResult = res;
                        setNotice(`Ollama 测速通过：${res.model} (${res.latencyMs} ms)`);
                      }),
                    }),
                  ]),
                ]),
              ]);
            })),
          ]),
        ])
      : el('div', { class: 'lw-empty-state', text: ol?.running ? '当前 Ollama 尚无已拉取模型，请在下方拉取安全 Guard / Canary 模型。' : 'Ollama 未连接或未启动，可点击右上角启动或一键安装。' }),
  ]));

  if (pullJobs.length > 0) {
    bodyChildren.push(el('section', { class: 'lw-section' }, [
      el('div', { class: 'lw-section-head' }, [el('h3', { text: '模型拉取任务' })]),
      el('div', { class: 'lw-setting-list' }, pullJobs.map(job => {
        const pct = Number.isFinite(job.percent) ? Math.max(0, Math.min(100, job.percent)) : 0;
        return el('div', { class: 'lw-ollama-rec-row' }, [
          el('div', { class: 'lw-ollama-rec-info' }, [
            el('div', { class: 'lw-row lw-between' }, [
              el('span', { class: 'lw-mono', text: job.model }),
              el('span', {
                class: `lw-pill ${job.status === 'completed' ? 'lw-pill-ok' : job.status === 'failed' ? 'lw-pill-err' : 'lw-pill-warn'}`,
                text: `${job.status}${pct > 0 ? ` ${pct}%` : ''}`,
              }),
            ]),
            el('div', { class: 'lw-progress-track' }, [
              el('div', { class: 'lw-progress-bar', style: `width:${job.status === 'completed' ? 100 : pct}%` }),
            ]),
            job.error || job.detail ? el('span', { class: 'lw-muted', text: job.error || job.detail }) : null,
          ]),
        ]);
      })),
    ]));
  }

  bodyChildren.push(el('section', { class: 'lw-section' }, [
    el('div', { class: 'lw-section-head' }, [
      el('div', {}, [
        el('h3', { text: '拉取与一键接入安全模型' }),
        el('p', { text: '支持输入任意 Ollama 模型标签拉取，或一键拉取预设安全分类与 Canary 小模型。' }),
      ]),
    ]),
    el('div', { class: 'lw-ollama-probe-row' }, [
      pullInput,
      makeIconButton({
        text: '拉取自定义模型',
        iconName: 'download',
        className: 'lw-btn lw-btn-sm lw-btn-trust',
        disabled: state.busy,
        onClick: () => runMutation(async () => {
          const tag = (state.ollamaPullTag || '').trim();
          if (!tag) throw new Error('请输入要拉取的 Ollama 模型标签。');
          await client.api('/api/moderation/ollama/pull', {
            method: 'POST',
            body: {
              model: tag,
              endpoint: activeEp,
              allowPrivateNetwork: Boolean(state.ollamaAllowPrivate),
            },
          });
          state.ollamaPullTag = '';
          await loadOllamaStatus({ endpoint: activeEp, silent: true });
          setNotice(`已提交 Ollama 模型拉取任务：${tag}`);
        }),
      }),
    ]),
    recModels.length > 0
      ? el('div', { class: 'lw-setting-list' }, recModels.map(rec => {
        const hasExact = installedNames.has(rec.id) || installedNames.has(`${rec.id}:latest`);
        const targetRole = rec.role === 'canary' ? 'canary' : 'guard';
        return el('div', { class: 'lw-ollama-rec-row' }, [
          el('div', { class: 'lw-ollama-rec-info' }, [
            el('div', { class: 'lw-row' }, [
              el('span', { class: 'lw-mono', text: rec.id }),
              el('span', { class: `lw-pill ${rec.role === 'canary' ? 'lw-pill-info' : 'lw-pill-ok'}`, text: `${rec.role === 'canary' ? 'Canary' : 'Guard'} · ${rec.sizeLabel}` }),
            ]),
            el('span', { class: 'lw-switch-sub', text: rec.desc }),
          ]),
          makeIconButton({
            text: hasExact ? `设为默认 ${targetRole === 'canary' ? 'Canary' : 'Guard'}` : `一键拉取 (${rec.sizeLabel})`,
            iconName: hasExact ? 'check' : 'download',
            className: `lw-btn lw-btn-sm ${hasExact ? '' : 'lw-btn-trust'}`,
            disabled: state.busy,
            onClick: () => {
              if (hasExact) {
                applyOllamaModelChoice(targetRole, installedNames.has(rec.id) ? rec.id : `${rec.id}:latest`, activeEp, state.ollamaAllowPrivate);
                return;
              }
              void runMutation(async () => {
                await client.api('/api/moderation/ollama/pull', {
                  method: 'POST',
                  body: {
                    model: rec.id,
                    endpoint: activeEp,
                    allowPrivateNetwork: Boolean(state.ollamaAllowPrivate),
                  },
                });
                await loadOllamaStatus({ endpoint: activeEp, silent: true });
                setNotice(`开始拉取推荐安全模型：${rec.id}`);
              });
            },
          }),
        ]);
      }))
      : null,
  ]));

  const statusText = ol?.running
    ? `在线 · Ollama ${ol.version || ol.binaryVersion || ''}`.trim()
    : (ol?.installed ? `本机已安装 (${ol.binaryVersion || '待启动'})` : '未检测到本地运行时');

  return el('div', { class: 'lw-stack-md' }, [
    el('section', { class: 'lw-section' }, [
      el('div', { class: 'lw-section-head' }, [
        el('div', {}, [
          el('h3', { text: '本地模型运行时 · Ollama' }),
          el('p', {
            text: ol?.binaryPath
              ? `已发现可执行文件：${ol.binaryPath}（支持 /api/tags 自动发现、原生多模态与 think=false 低延迟审查）`
              : '支持受控安装/启动本机 Ollama、拉取安全模型，或连接受信任局域网 GPU 节点。',
          }),
        ]),
        el('div', { class: 'lw-row' }, [
          el('span', { class: `lw-pill ${ol?.running ? 'lw-pill-ok' : ol?.installed ? 'lw-pill-warn' : 'lw-pill-info'}`, text: statusText }),
          ...headerActions,
        ]),
      ]),
      ...bodyChildren.slice(0, 1),
      ...bodyChildren.slice(1, bodyChildren.length - (pullJobs.length > 0 ? 3 : 2)),
    ]),
    ...bodyChildren.slice(bodyChildren.length - (pullJobs.length > 0 ? 3 : 2)),
  ]);
}

const CLOUD_PROVIDER_META = {
  'openai-compat': {
    shortLabel: 'OpenAI Moderation',
    endpointPlaceholder: 'https://api.openai.com/v1/moderations',
    docSummary: '调用 OpenAI POST /v1/moderations（model=omni-moderation-latest）；支持文本与非 SVG 图片 base64 data URI（官方上限 20 MB），内联纯音频/视频将显式报错回退。',
    regions: [],
    creds: [
      { key: 'OPENAI_API_KEY', label: 'OpenAI API Key', placeholder: 'sk-...（仅写保存，不回显）' },
    ],
  },
  'aliyun-green': {
    shortLabel: '阿里云内容安全 2.0',
    endpointPlaceholder: 'https://green-cip.cn-shanghai.aliyuncs.com/',
    docSummary: '调用 green-cip.{region}.aliyuncs.com（ACS3-HMAC-SHA256 + form-urlencoded TextModerationPlus）；图片/音视频内联二进制需 DescribeUploadToken 预传 OSS，直传裸字节会显式报错回退。',
    regions: [
      ['', '(默认 · cn-shanghai)'],
      ['cn-shanghai', '华东 2（上海 · cn-shanghai）'],
      ['cn-beijing', '华北 2（北京 · cn-beijing）'],
      ['cn-shenzhen', '华南 1（深圳 · cn-shenzhen）'],
      ['cn-hangzhou', '华东 1（杭州 · cn-hangzhou）'],
      ['ap-southeast-1', '新加坡（ap-southeast-1）'],
    ],
    creds: [
      { key: 'ALIYUN_ACCESS_KEY_ID', label: 'AccessKey ID', placeholder: 'LTAI5t...' },
      { key: 'ALIYUN_ACCESS_KEY_SECRET', label: 'AccessKey Secret', placeholder: '仅写保存，不回显' },
    ],
  },
  'tencent-tms': {
    shortLabel: '腾讯云天御 TMS/IMS/AMS',
    endpointPlaceholder: 'https://tms.tencentcloudapi.com/',
    docSummary: '调用 *.tencentcloudapi.com（TC3-HMAC-SHA256 2020-12-29）：TMS 文本 + IMS 图片 FileContent + AMS 同步音频 CreateAudioModerationSyncTask；VMS 视频仅异步 URL，内联视频会显式报错回退。',
    regions: [
      ['', '(默认 · ap-guangzhou)'],
      ['ap-guangzhou', '华南（广州 · ap-guangzhou）'],
      ['ap-shanghai', '华东（上海 · ap-shanghai）'],
      ['ap-beijing', '华北（北京 · ap-beijing）'],
      ['ap-chengdu', '西南（成都 · ap-chengdu）'],
      ['ap-hongkong', '港澳台（中国香港 · ap-hongkong）'],
    ],
    creds: [
      { key: 'TENCENT_SECRET_ID', label: 'SecretId', placeholder: 'AKID...' },
      { key: 'TENCENT_SECRET_KEY', label: 'SecretKey', placeholder: '仅写保存，不回显' },
    ],
  },
  'baidu-aip': {
    shortLabel: '百度智能云内容审核',
    endpointPlaceholder: 'https://aip.baidubce.com',
    docSummary: '经 /oauth/2.0/token 单飞缓存换取 Access Token 后调用 text_censor/v2、img_censor/v2（含 imgType）、voice_censor/v3/user_defined；video_censor 仅支持公网 URL，内联视频会显式报错回退。',
    regions: [],
    creds: [
      { key: 'BAIDU_API_KEY', label: 'API Key (Client ID)', placeholder: '百度应用 API Key' },
      { key: 'BAIDU_SECRET_KEY', label: 'Secret Key (Client Secret)', placeholder: '仅写保存，不回显' },
    ],
  },
  webhook: {
    shortLabel: '自定义 HTTPS Webhook',
    endpointPlaceholder: 'https://moderation.example.com/v1/inspect',
    docSummary: '向自定义 HTTPS 端点 POST JSON 审计载荷并解析 { decision, score, categories, reason }；Token 留空时不附带 Authorization 头。',
    regions: [],
    creds: [
      { key: 'WEBHOOK_API_KEY', label: 'Bearer / Webhook Token（可选）', placeholder: '需要鉴权时填写 Bearer Token', optional: true },
    ],
  },
};

function getCloudProviderMeta(provider) {
  return CLOUD_PROVIDER_META[provider] || CLOUD_PROVIDER_META['openai-compat'];
}

function getSavedSecretKeySet(unitId = 'llm-moderation') {
  const unit = (state.pluginSecretUnits || []).find(u => u && u.unitId === unitId);
  return new Set(Array.isArray(unit?.keys) ? unit.keys : []);
}

function collectPendingCloudCreds(provider) {
  const meta = getCloudProviderMeta(provider);
  const out = {};
  for (const cred of meta.creds) {
    const raw = state.draftCloudCreds?.[cred.key];
    if (typeof raw === 'string' && raw.trim().length > 0) {
      out[cred.key] = raw.trim();
    }
  }
  return out;
}

async function savePluginSecretsAndRefresh(unitId, secrets) {
  const res = await client.api('/api/plugin-secrets/save', {
    method: 'POST',
    body: { unitId, secrets },
  });
  const metaRes = await client.api('/api/plugin-secrets/meta').catch(() => null);
  if (Array.isArray(metaRes?.units)) {
    state.pluginSecretUnits = metaRes.units;
  }
  return res;
}

function fallbackMatrixForProfile(profile) {
  if (profile === 'strict') {
    return { cloudDown: '硬阻断 (Fail-Closed)', inputDown: '硬阻断 (Fail-Closed)', outputDown: '硬阻断 (Fail-Closed)' };
  }
  if (profile === 'balanced') {
    return { cloudDown: '转局部/阻断 (Fail-Closed)', inputDown: '转本机人工复核', outputDown: '强制 Fail-Closed 阻断' };
  }
  return { cloudDown: '平滑降级至 Local Guard', inputDown: '转本机人工复核', outputDown: '告警并放行 (实验弹性)' };
}

function normalizeComparableMod(raw) {
  const src = raw || DEFAULT_MOD_CONFIG;
  const lgKind = src.localGuard?.kind || 'http';
  const cnEnabled = Boolean(src.canary?.enabled || src.mode === 'guard-plus-canary');
  const cnKind = src.canary?.kind || 'http';
  return {
    mode: src.mode || 'local-only',
    policyProfile: src.policyProfile || 'experimental-resilient',
    defaultScope: src.defaultScope || 'combined',
    cloudOptIn: Boolean(src.cloudOptIn),
    cloudProvider: src.cloudProvider || 'openai-compat',
    cloudRegion: (src.cloudRegion || '').trim(),
    cloudEndpoint: (src.cloudEndpoint || '').trim(),
    lgKind,
    lgModel: (src.localGuard?.model || 'llama-guard-3').trim(),
    lgEndpoint: ((src.localGuard?.endpoint || '').trim() || (lgKind === 'ollama' ? 'http://127.0.0.1:11434' : '')).replace(/\/+$/, ''),
    lgThink: Boolean(src.localGuard?.think),
    lgPrivate: Boolean(src.localGuard?.allowPrivateNetwork),
    cnEnabled,
    cnKind,
    cnModel: (src.canary?.model || 'qwen2.5-0.5b').trim(),
    cnEndpoint: ((src.canary?.endpoint || '').trim() || (cnEnabled && cnKind === 'ollama' ? 'http://127.0.0.1:11434' : '')).replace(/\/+$/, ''),
    cnPrivate: Boolean(src.canary?.allowPrivateNetwork),
  };
}

function computeModerationDelta(savedRaw, draftRaw) {
  const saved = normalizeComparableMod(savedRaw);
  const draft = normalizeComparableMod(draftRaw);
  const changed = new Set();
  const diffs = [];
  const specs = [
    ['mode', '审查模式'],
    ['policyProfile', '回退策略'],
    ['defaultScope', '校验范围'],
    ['cloudOptIn', '云端外发许可', v => (v ? '允许外发' : '纯本地闭锁')],
    ['cloudProvider', '云端接口'],
    ['cloudRegion', '云端服务地域', v => v || '(默认地域)'],
    ['cloudEndpoint', '自定义云端端点', v => v || '(默认官方域名)'],
    ['lgKind', 'Guard 引擎'],
    ['lgModel', 'Guard 模型'],
    ['lgEndpoint', 'Guard 端点', v => v || '(内置离线引擎)'],
    ['lgThink', 'Guard 思考链', v => (v ? '思考开启' : 'think=false 极速')],
    ['lgPrivate', 'Guard 局域网放行', v => (v ? '开放局域网 HTTP' : '仅回环/HTTPS')],
    ['cnEnabled', 'Canary 探针', v => (v ? '启用' : '关闭')],
    ['cnKind', 'Canary 引擎'],
    ['cnModel', 'Canary 模型'],
    ['cnEndpoint', 'Canary 端点', v => v || '(未指定)'],
    ['cnPrivate', 'Canary 局域网放行', v => (v ? '开放局域网 HTTP' : '仅回环/HTTPS')],
  ];
  for (const [key, label, fmt] of specs) {
    if (saved[key] !== draft[key]) {
      changed.add(key);
      const formatVal = fmt || (v => String(v));
      diffs.push({ key, label, from: formatVal(saved[key]), to: formatVal(draft[key]) });
    }
  }
  return { saved, draft, changed, diffs };
}

function clipText(str, max = 14) {
  const s = String(str || '');
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function renderModerationImpactPreview(savedRaw, draftRaw) {
  const { saved, draft, changed, diffs } = computeModerationDelta(savedRaw, draftRaw);
  const inputActive = draft.defaultScope === 'combined' || draft.defaultScope === 'input-only';
  const savedInputActive = saved.defaultScope === 'combined' || saved.defaultScope === 'input-only';
  const inputChanged = inputActive !== savedInputActive;
  const outputActive = draft.defaultScope === 'combined' || draft.defaultScope === 'output-only';
  const savedOutputActive = saved.defaultScope === 'combined' || saved.defaultScope === 'output-only';
  const outputChanged = outputActive !== savedOutputActive;

  const guardChanged = ['lgKind', 'lgModel', 'lgEndpoint', 'lgThink', 'lgPrivate'].some(k => changed.has(k));
  const canaryActive = draft.cnEnabled || draft.mode === 'guard-plus-canary';
  const savedCanaryActive = saved.cnEnabled || saved.mode === 'guard-plus-canary';
  const canaryChanged = canaryActive !== savedCanaryActive || ['cnKind', 'cnModel', 'cnEndpoint', 'cnPrivate'].some(k => changed.has(k));

  const cloudRouteRequested = draft.mode === 'cloud-first' || draft.mode === 'hybrid-tiered';
  const cloudLive = draft.cloudOptIn && cloudRouteRequested;
  const savedCloudLive = saved.cloudOptIn && (saved.mode === 'cloud-first' || saved.mode === 'hybrid-tiered');
  const cloudChanged = cloudLive !== savedCloudLive
    || changed.has('cloudOptIn')
    || (cloudLive && (changed.has('cloudProvider') || changed.has('cloudRegion') || changed.has('cloudEndpoint')));
  const providerMeta = getCloudProviderMeta(draft.cloudProvider);
  const savedSecKeys = getSavedSecretKeySet('llm-moderation');
  const cloudCredsMissing = providerMeta.creds.some(c => !c.optional && !savedSecKeys.has(c.key));

  const curMatrix = fallbackMatrixForProfile(draft.policyProfile);
  const oldMatrix = fallbackMatrixForProfile(saved.policyProfile);

  const schematicSvg = svgEl('svg', {
    viewBox: '0 0 356 364',
    class: 'lw-svg-diagram',
    role: 'img',
    'aria-label': 'LLM 安全审查实时数据流拓扑示意图',
  }, [
    svgEl('defs', {}, [
      svgEl('marker', { id: 'lw-arr', viewBox: '0 0 10 10', refX: '8', refY: '5', markerWidth: '6', markerHeight: '6', orient: 'auto-start-reverse' }, [
        svgEl('path', { d: 'M 0 1 L 10 5 L 0 9 z', fill: 'currentColor' }),
      ]),
    ]),
    // Stage 1 -> Stage 2 Spine
    svgEl('path', {
      d: 'M 158 34 L 196 34',
      class: `lw-svg-wire ${inputActive ? 'lw-svg-wire-active' : 'lw-svg-wire-off'}`,
    }),
    // Stage 2 -> Dispatch Hub
    svgEl('path', {
      d: 'M 272 58 C 272 82, 178 76, 178 98',
      class: 'lw-svg-wire lw-svg-wire-active',
    }),
    // Dispatch Hub -> 3 Branch Fan-out
    svgEl('path', {
      d: 'M 178 140 C 178 164, 58 158, 58 186',
      class: 'lw-svg-wire lw-svg-wire-active',
    }),
    svgEl('path', {
      d: 'M 178 140 L 178 186',
      class: `lw-svg-wire ${canaryActive ? 'lw-svg-wire-active' : 'lw-svg-wire-off'}`,
    }),
    svgEl('path', {
      d: 'M 178 140 C 178 164, 298 158, 298 186',
      class: `lw-svg-wire ${cloudLive ? 'lw-svg-wire-warn' : 'lw-svg-wire-off'}`,
    }),
    // 3 Branch Fan-in -> Output Stage
    svgEl('path', {
      d: 'M 58 256 C 58 282, 178 278, 178 304',
      class: `lw-svg-wire ${outputActive ? 'lw-svg-wire-active' : 'lw-svg-wire-off'}`,
    }),
    svgEl('path', {
      d: 'M 178 256 L 178 304',
      class: `lw-svg-wire ${canaryActive && outputActive ? 'lw-svg-wire-active' : 'lw-svg-wire-off'}`,
    }),
    svgEl('path', {
      d: 'M 298 256 C 298 282, 178 278, 178 304',
      class: `lw-svg-wire ${cloudLive && outputActive ? 'lw-svg-wire-warn' : 'lw-svg-wire-off'}`,
    }),
    // Nodes
    svgNodeBox({
      x: 8, y: 10, w: 150, h: 48,
      title: '1. 入参参数预检',
      sub: inputActive ? 'Input 已纳管' : '旁路（仅查输出）',
      stateCls: inputActive ? 'is-ok' : 'is-off',
      isDelta: inputChanged,
    }),
    svgNodeBox({
      x: 198, y: 10, w: 150, h: 48,
      title: '2. 防泄漏护栏',
      sub: 'R1–R7 · order: 10',
      stateCls: 'is-ok',
    }),
    svgNodeBox({
      x: 68, y: 98, w: 220, h: 42,
      title: '3. 多模态审查枢纽 (order: 50)',
      sub: `${draft.mode} · ${draft.policyProfile}`,
      stateCls: changed.has('mode') || changed.has('policyProfile') ? 'is-warn' : 'is-active',
      isDelta: changed.has('mode'),
    }),
    svgNodeBox({
      x: 6, y: 186, w: 106, h: 70,
      title: 'Local Guard',
      sub: clipText(draft.lgModel, 13),
      badge: `${draft.lgThink ? '思考' : 'think=off'}·${draft.lgPrivate ? 'LAN' : 'Local'}`,
      stateCls: 'is-active',
      badgeCls: draft.lgPrivate ? 'is-warn' : 'is-ok',
      isDelta: guardChanged,
    }),
    svgNodeBox({
      x: 125, y: 186, w: 106, h: 70,
      title: 'Canary 探针',
      sub: canaryActive ? clipText(draft.cnModel, 13) : '休眠旁路',
      badge: canaryActive ? 'Zero-Tool' : '未启用',
      stateCls: canaryActive ? 'is-active' : 'is-off',
      badgeCls: canaryActive ? '' : 'is-muted',
      isDelta: canaryChanged,
    }),
    svgNodeBox({
      x: 244, y: 186, w: 106, h: 70,
      title: '云端安全 API',
      sub: cloudLive ? clipText(draft.cloudProvider, 13) : (cloudRouteRequested ? '缺 OptIn' : '离线闭锁'),
      badge: cloudLive ? (cloudCredsMissing ? '待填 API 密钥' : '外部外发开启') : '零出站',
      stateCls: cloudLive ? 'is-warn' : 'is-off',
      badgeCls: cloudLive ? 'is-warn' : 'is-ok',
      isDelta: cloudChanged,
    }),
    svgNodeBox({
      x: 48, y: 304, w: 260, h: 52,
      title: '4. 输出复检与 Holdback 尾部暂留',
      sub: outputActive ? '局部脱敏 / 流式阻断生效' : '旁路（仅入参预检）',
      stateCls: outputActive ? 'is-ok' : 'is-off',
      isDelta: outputChanged,
    }),
  ]);

  return el('div', { class: 'lw-stack-md', 'aria-live': 'polite' }, [
    el('div', { class: 'lw-section-head' }, [
      el('div', {}, [
        el('h3', { text: '系统运行形态推演' }),
        el('p', { text: diffs.length ? `${diffs.length} 项改动将重塑高亮链路与节点` : '与当前已保存线上态一致' }),
      ]),
      diffs.length
        ? el('span', { class: 'lw-delta-tag', text: 'Delta 推演中' })
        : el('span', { class: 'lw-pill lw-pill-ok', text: '已同步' }),
    ]),
    schematicSvg,
    el('div', { class: 'lw-aside-list' }, [
      el('div', { class: `lw-aside-row ${curMatrix.cloudDown !== oldMatrix.cloudDown ? 'is-delta' : ''}` }, [
        el('span', { class: 'lw-muted', text: '云端故障兜底' }),
        el('strong', { text: curMatrix.cloudDown }),
      ]),
      el('div', { class: `lw-aside-row ${curMatrix.inputDown !== oldMatrix.inputDown ? 'is-delta' : ''}` }, [
        el('span', { class: 'lw-muted', text: '入参审查故障' }),
        el('strong', { text: curMatrix.inputDown }),
      ]),
      el('div', { class: `lw-aside-row ${curMatrix.outputDown !== oldMatrix.outputDown ? 'is-delta' : ''}` }, [
        el('span', { class: 'lw-muted', text: '输出审查故障' }),
        el('strong', { text: curMatrix.outputDown }),
      ]),
    ]),
  ]);
}

function renderModSaveBar(savedCfg, diffs, commitSaveConfig) {
  if (diffs.length > 0) {
    return el('div', { class: 'lw-delta-bar' }, [
      el('div', { class: 'lw-stack-sm' }, [
        el('strong', { text: `待应用配置差异 (${diffs.length} 项)` }),
        el('div', { class: 'lw-row' }, diffs.slice(0, 5).map(d => el('span', {
          class: 'lw-pill lw-pill-warn lw-mono',
          text: `${d.label}: ${d.from} → ${d.to}`,
        }))),
      ]),
      el('div', { class: 'lw-row' }, [
        makeIconButton({
          text: '还原',
          iconName: 'rotateCcw',
          className: 'lw-btn lw-btn-sm',
          disabled: state.busy,
          onClick: () => {
            state.draftMod = structuredClone(savedCfg);
            render();
          },
        }),
        makeIconButton({
          text: `保存并热生效 (${diffs.length})`,
          iconName: 'check',
          className: 'lw-btn lw-btn-sm lw-btn-trust',
          disabled: state.busy,
          onClick: commitSaveConfig,
        }),
      ]),
    ]);
  }
  return el('div', { class: 'lw-row lw-end' }, [
    makeIconButton({
      text: '保存审核策略配置',
      iconName: 'check',
      className: 'lw-btn lw-btn-trust',
      disabled: state.busy,
      onClick: commitSaveConfig,
    }),
  ]);
}

function syncModerationLiveRegions(savedCfg, commitSaveConfig) {
  const cfg = getDraftModConfig();
  const { changed, diffs } = computeModerationDelta(savedCfg, cfg);
  const previewHost = root.querySelector('[data-mod-preview-slot]');
  if (previewHost) {
    clearNode(previewHost);
    previewHost.append(renderModerationImpactPreview(savedCfg, cfg));
  }
  const saveHost = root.querySelector('[data-mod-savebar-slot]');
  if (saveHost) {
    clearNode(saveHost);
    saveHost.append(renderModSaveBar(savedCfg, diffs, commitSaveConfig));
  }
  return changed;
}

function renderModerationPage() {
  const cfg = getDraftModConfig();
  const savedCfg = state.moderationConfig || DEFAULT_MOD_CONFIG;
  const { changed, diffs } = computeModerationDelta(savedCfg, cfg);
  const datalistId = 'lw-ollama-models-datalist';
  const modelChoices = new Set();
  for (const m of state.ollama?.models || []) modelChoices.add(m.name);
  for (const rec of state.ollama?.recommendedModels || []) modelChoices.add(rec.id);

  const cloudMeta = getCloudProviderMeta(cfg.cloudProvider);
  const savedSecKeys = getSavedSecretKeySet('llm-moderation');

  const cloudProvSel = makeSelect([
    ['openai-compat', 'OpenAI Moderation Compat (omni-moderation-latest)'],
    ['aliyun-green', '阿里云内容安全 2.0 (Green-CIP)'],
    ['tencent-tms', '腾讯云天御 (TMS / IMS / AMS / VMS)'],
    ['baidu-aip', '百度智能云内容审核 (AIP V2 / V3)'],
    ['webhook', '自定义 HTTPS JSON Webhook'],
  ], cfg.cloudProvider, e => {
    const nextProv = e.target.value;
    cfg.cloudProvider = nextProv;
    const nextMeta = getCloudProviderMeta(nextProv);
    const validRegions = new Set((nextMeta.regions || []).map(([val]) => val));
    if (!validRegions.has(cfg.cloudRegion || '')) {
      cfg.cloudRegion = '';
    }
    render();
  }, { iconName: 'cloud', isDelta: changed.has('cloudProvider') });

  const cloudRegionSel = cloudMeta.regions.length > 0
    ? makeSelect(cloudMeta.regions, cfg.cloudRegion || '', e => {
      cfg.cloudRegion = e.target.value;
      render();
    }, { iconName: 'globe', isDelta: changed.has('cloudRegion') })
    : null;

  const localKind = cfg.localGuard?.kind || 'http';
  const canaryKind = cfg.canary?.kind || 'http';
  const canaryActive = Boolean(cfg.canary?.enabled || cfg.mode === 'guard-plus-canary');

  const commitSaveConfig = () => runMutation(async () => {
    const draft = getDraftModConfig();
    const nextLocalKind = draft.localGuard?.kind || 'http';
    const nextLocalEp = (draft.localGuard?.endpoint || '').trim() || (nextLocalKind === 'ollama' ? 'http://127.0.0.1:11434' : null);
    const nextCanaryKind = draft.canary?.kind || 'http';
    const nextCanaryEnabled = Boolean(draft.canary?.enabled || draft.mode === 'guard-plus-canary');
    const nextCanaryEp = (draft.canary?.endpoint || '').trim() || (nextCanaryEnabled && nextCanaryKind === 'ollama' ? 'http://127.0.0.1:11434' : null);
    const payload = {
      ...draft,
      cloudRegion: (draft.cloudRegion || '').trim() || null,
      cloudEndpoint: (draft.cloudEndpoint || '').trim() || null,
      localGuard: {
        ...(draft.localGuard || {}),
        kind: nextLocalKind,
        endpoint: nextLocalEp,
        model: (draft.localGuard?.model || '').trim() || 'llama-guard-3',
        think: Boolean(draft.localGuard?.think),
        allowPrivateNetwork: Boolean(draft.localGuard?.allowPrivateNetwork),
      },
      canary: {
        ...(draft.canary || {}),
        enabled: nextCanaryEnabled,
        kind: nextCanaryKind,
        endpoint: nextCanaryEp,
        model: (draft.canary?.model || '').trim() || 'qwen2.5-0.5b',
        think: Boolean(draft.canary?.think),
        allowPrivateNetwork: Boolean(draft.canary?.allowPrivateNetwork),
      },
    };
    const pendingCreds = collectPendingCloudCreds(draft.cloudProvider);
    const pendingKeys = Object.keys(pendingCreds);
    for (const k of pendingKeys) state.draftCloudCreds[k] = '';
    const res = await client.api('/api/moderation/config', { method: 'POST', body: { config: payload } });
    if (pendingKeys.length > 0) {
      await savePluginSecretsAndRefresh('llm-moderation', pendingCreds);
    }
    if (res.config) {
      state.moderationConfig = res.config;
      state.draftMod = structuredClone(res.config);
    }
    setNotice(
      pendingKeys.length > 0
        ? `已保存并热生效审核策略（${res.config.mode} / ${res.config.policyProfile}），并只写写入 ${pendingKeys.join('、')}。`
        : `已保存并热生效审核策略（${res.config.mode} / ${res.config.policyProfile}）。`
    );
  });

  const makeLiveInput = ({ type = 'text', list, value, placeholder, changeKey, onAssign }) => el('input', {
    type,
    ...(list ? { list } : {}),
    class: `lw-input lw-mono ${changed.has(changeKey) ? 'is-delta' : ''}`,
    value: value || '',
    placeholder,
    onInput: e => {
      onAssign(e.target.value);
      syncModerationLiveRegions(savedCfg, commitSaveConfig);
    },
  });

  const localModelInput = makeLiveInput({
    list: datalistId,
    value: cfg.localGuard?.model,
    placeholder: 'llama-guard3:1b 或 qwen3.5:9b',
    changeKey: 'lgModel',
    onAssign: v => { cfg.localGuard = { ...(cfg.localGuard || {}), model: v }; },
  });
  const localEpInput = makeLiveInput({
    type: 'url',
    value: cfg.localGuard?.endpoint,
    placeholder: 'http://127.0.0.1:11434 (Ollama 默认回环或受信任局域网)',
    changeKey: 'lgEndpoint',
    onAssign: v => { cfg.localGuard = { ...(cfg.localGuard || {}), endpoint: v }; },
  });
  const canaryModelInput = makeLiveInput({
    list: datalistId,
    value: cfg.canary?.model,
    placeholder: 'qwen2.5:0.5b 或 qwen3:0.6b',
    changeKey: 'cnModel',
    onAssign: v => { cfg.canary = { ...(cfg.canary || {}), model: v }; },
  });
  const canaryEpInput = makeLiveInput({
    type: 'url',
    value: cfg.canary?.endpoint,
    placeholder: 'http://127.0.0.1:11434 (Zero-Tool 金丝雀探针)',
    changeKey: 'cnEndpoint',
    onAssign: v => { cfg.canary = { ...(cfg.canary || {}), endpoint: v }; },
  });
  const cloudEpInput = makeLiveInput({
    type: 'url',
    value: cfg.cloudEndpoint,
    placeholder: cloudMeta.endpointPlaceholder,
    changeKey: 'cloudEndpoint',
    onAssign: v => { cfg.cloudEndpoint = v; },
  });

  const allReqCredsSaved = cloudMeta.creds.every(c => c.optional || savedSecKeys.has(c.key));
  const pendingCredBatch = collectPendingCloudCreds(cfg.cloudProvider);
  const pendingCredCount = Object.keys(pendingCredBatch).length;
  const saveCredBtn = makeIconButton({
    text: pendingCredCount > 0 ? `只写保存 ${pendingCredCount} 项云端密钥` : '只写保存云端 API 密钥',
    iconName: 'key',
    className: `lw-btn lw-btn-sm ${pendingCredCount > 0 ? 'lw-btn-primary' : ''}`,
    disabled: state.busy,
    onClick: () => {
      const batch = collectPendingCloudCreds(cfg.cloudProvider);
      const keys = Object.keys(batch);
      if (keys.length === 0) {
        setError(`请先填写 ${cloudMeta.shortLabel} 的 API 密钥后再点击保存。`);
        return;
      }
      for (const k of keys) state.draftCloudCreds[k] = '';
      void runMutation(async () => {
        await savePluginSecretsAndRefresh('llm-moderation', batch);
        setNotice(`已只写加密保存 ${cloudMeta.shortLabel} 密钥：${keys.join('、')}（后端不回显明文）。`);
      });
    },
  });

  const refreshCredButtonState = () => {
    const cnt = Object.keys(collectPendingCloudCreds(cfg.cloudProvider)).length;
    const span = saveCredBtn.querySelector('span');
    if (span) span.textContent = cnt > 0 ? `只写保存 ${cnt} 项云端密钥` : '只写保存云端 API 密钥';
    saveCredBtn.className = `lw-btn lw-btn-sm ${cnt > 0 ? 'lw-btn-primary' : ''}`;
  };

  const credFields = cloudMeta.creds.map(cred => {
    const isSaved = savedSecKeys.has(cred.key);
    const inputNode = el('input', {
      type: 'password',
      autocomplete: 'new-password',
      class: 'lw-input lw-mono',
      value: state.draftCloudCreds[cred.key] || '',
      placeholder: isSaved ? '已安全写入，输入新值可覆盖更新' : cred.placeholder,
      'data-cloud-cred-key': cred.key,
      onInput: e => {
        state.draftCloudCreds[cred.key] = e.target.value;
        refreshCredButtonState();
      },
    });
    const toggleBtn = el('button', {
      type: 'button',
      class: 'lw-secret-toggle',
      text: '显示',
      onClick: () => {
        const show = inputNode.type === 'password';
        inputNode.type = show ? 'text' : 'password';
        toggleBtn.textContent = show ? '隐藏' : '显示';
      },
    });
    const labelNode = el('span', { class: 'lw-row lw-between', style: 'width:100%' }, [
      el('span', {}, [
        el('span', { text: cred.label }),
        el('span', { text: ' ' }),
        el('code', { class: 'lw-tag-inline', text: cred.key }),
      ]),
      el('span', {
        class: `lw-tag-status ${isSaved ? 'is-ok' : (cred.optional ? '' : 'is-warn')}`,
        text: isSaved ? '已写入（不回显）' : (cred.optional ? '可选' : '未设置'),
      }),
    ]);
    return makeField(labelNode, el('div', { class: 'lw-secret-input-wrap' }, [inputNode, toggleBtn]), {
      fullWidth: cloudMeta.creds.length === 1,
    });
  });

  const ollamaCount = Array.isArray(state.ollama?.models) ? state.ollama.models.length : 0;
  const tabBar = el('div', { class: 'lw-view-tabs', role: 'tablist' }, [
    el('button', {
      type: 'button',
      role: 'tab',
      'aria-selected': String(state.modTab === 'routing'),
      class: `lw-view-tab ${state.modTab === 'routing' ? 'is-active' : ''}`,
      onClick: () => { state.modTab = 'routing'; render(); },
    }, [
      makeIcon('layers'),
      el('span', { text: '策略路由与实时推演' }),
      diffs.length > 0 ? el('span', { class: 'lw-delta-tag', text: String(diffs.length) }) : null,
    ]),
    el('button', {
      type: 'button',
      role: 'tab',
      'aria-selected': String(state.modTab === 'ollama'),
      class: `lw-view-tab ${state.modTab === 'ollama' ? 'is-active' : ''}`,
      onClick: () => {
        state.modTab = 'ollama';
        if (!state.ollama && !state.ollamaLoading) void loadOllamaStatus({ silent: true });
        render();
      },
    }, [
      makeIcon('cpu'),
      el('span', { text: 'Ollama 本地运行时与模型' }),
      el('span', { class: `lw-pill ${state.ollama?.running ? 'lw-pill-ok' : ''}`, text: state.ollama?.running ? `${ollamaCount} 模型` : '待探测' }),
    ]),
  ]);

  const routingSplit = el('div', { class: 'lw-doc-split' }, [
    el('div', { class: 'lw-doc-main' }, [
      el('section', { class: 'lw-section' }, [
        el('div', { class: 'lw-section-head' }, [
          el('div', {}, [
            el('h3', { text: '1. 审查模式与故障回退预设' }),
            el('p', { text: '选择路由模式与异常策略；右侧架构图实时闪烁标注即将变更的节点与连接。' }),
          ]),
        ]),
        makeField('内容审查模式 (mode)', makeOptionCards({
          value: cfg.mode,
          savedValue: savedCfg.mode,
          options: [
            { value: 'local-only', title: '模式 1 · 纯本地 Guard', icon: 'shieldCheck', badge: '零外发', badgeTone: 'ok', desc: '仅由本机 / 局域网 Guard 模型或确定性规则裁决，绝不触发外部网络。' },
            { value: 'guard-plus-canary', title: '模式 2 · Guard + Canary 防诱导', icon: 'radar', badge: '深度探测', badgeTone: 'info', desc: '双模型联动：主 Guard 拦截明显违规，Zero-Tool 探针捕获间接注入诱导。' },
            { value: 'cloud-first', title: '模式 3 · 云端安全 API 优先', icon: 'cloud', badge: '需 OptIn', badgeTone: 'warn', desc: '优先送往云厂商多模态安全接口，故障后回退至本地模型或人工复核。' },
            { value: 'hybrid-tiered', title: '混合分级路由 (Hybrid Tiered)', icon: 'layers', badge: '灰区升级', badgeTone: 'info', desc: '本地极速过滤，仅将灰区样本升级送往云端或人工审核，兼顾性能与隐私。' },
          ],
          onSelect: v => { cfg.mode = v; render(); },
        })),
        makeField('故障回退策略预设 (policyProfile)', makeSegmentedChoice({
          value: cfg.policyProfile,
          savedValue: savedCfg.policyProfile,
          options: [
            { value: 'experimental-resilient', label: '实验弹性 (Resilient)', icon: 'bolt' },
            { value: 'balanced', label: '均衡防线 (Balanced)', icon: 'shield' },
            { value: 'strict', label: '严格闭锁 (Strict)', icon: 'lock' },
          ],
          onSelect: v => { cfg.policyProfile = v; render(); },
        })),
      ]),
      el('section', { class: 'lw-section' }, [
        el('div', { class: 'lw-section-head' }, [
          el('div', {}, [
            el('h3', { text: '2. 校验范围与云端外发授权' }),
            el('p', { text: '控制工具参数/输出的拦截范围，以及是否允许向所选云端接口发送审计载荷。' }),
          ]),
        ]),
        makeField('默认校验范围 (defaultScope)', makeSegmentedChoice({
          value: cfg.defaultScope,
          savedValue: savedCfg.defaultScope,
          options: [
            { value: 'combined', label: '双向关联 (combined)', icon: 'layers' },
            { value: 'input-only', label: '仅入参预检', icon: 'shield' },
            { value: 'output-only', label: '仅输出/流式', icon: 'bolt' },
          ],
          onSelect: v => { cfg.defaultScope = v; render(); },
        })),
        el('div', { class: 'lw-form-grid' }, [
          makeField('云端审核厂商 (cloudProvider)', cloudProvSel),
          ...(cloudRegionSel
            ? [
                makeField('云端服务地域 (cloudRegion)', cloudRegionSel),
                makeField('云端自定义 HTTPS 端点（可选）', cloudEpInput, { fullWidth: true }),
              ]
            : [makeField('云端自定义 HTTPS 端点（可选）', cloudEpInput)]),
        ]),
        el('div', { class: 'lw-doc-callout', text: cloudMeta.docSummary }),
        el('div', { class: 'lw-cred-strip' }, [
          el('div', { class: 'lw-cred-head' }, [
            el('div', {}, [
              el('div', { class: 'lw-cred-title', text: `${cloudMeta.shortLabel} API 凭据（命名空间 llm-moderation）` }),
              el('div', { class: 'lw-switch-sub', text: '仅写加密存入受保护凭据库；可独立点击保存，也可随下方策略保存一并写入。' }),
            ]),
            el('span', {
              class: `lw-pill ${allReqCredsSaved ? 'lw-pill-ok' : 'lw-pill-warn'}`,
              text: allReqCredsSaved ? '凭据已就绪（仅写不回显）' : '待填写 API 密钥',
            }),
          ]),
          el('div', { class: 'lw-form-grid' }, credFields),
          el('div', { class: 'lw-row lw-between' }, [
            el('span', { class: 'lw-switch-sub', text: '提交至 POST /api/plugin-secrets/save，仅由进程外审查引擎鉴权使用。' }),
            saveCredBtn,
          ]),
        ]),
        el('div', { class: 'lw-setting-list' }, [
          makeSwitchCard({
            checked: Boolean(cfg.cloudOptIn),
            onChange: next => { cfg.cloudOptIn = next; render(); },
            title: '全局开启云端内容安全 API 外发许可（cloudOptIn）',
            subtitle: '开启且使用云端/混合模式时，已纳入策略的工具入参及输出将发送至所选云厂商',
            pillText: cfg.cloudOptIn ? '外发已放行' : '仅本地闭环',
            pillTone: cfg.cloudOptIn ? 'warn' : 'info',
            iconName: 'cloud',
            isDelta: changed.has('cloudOptIn'),
          }),
        ]),
      ]),
      el('section', { class: 'lw-section' }, [
        el('div', { class: 'lw-section-head' }, [
          el('div', {}, [
            el('h3', { text: '3. Local Guard & Canary 推理引擎' }),
            el('p', { text: '需安装或拉取模型请切换上方「Ollama 本地运行时与模型」标签页；LAN HTTP 默认隔离元数据与公网明文。' }),
          ]),
          makeIconButton({
            text: `管理 Ollama 模型 (${ollamaCount})`,
            iconName: 'cpu',
            className: 'lw-btn lw-btn-sm',
            onClick: () => {
              state.modTab = 'ollama';
              if (!state.ollama && !state.ollamaLoading) void loadOllamaStatus({ silent: true });
              render();
            },
          }),
        ]),
        makeField('本地 Guard 引擎类型 (localGuard.kind)', makeSegmentedChoice({
          value: localKind,
          savedValue: savedCfg.localGuard?.kind || 'http',
          options: [
            { value: 'ollama', label: 'Ollama 原生 (/api/chat)', icon: 'cpu' },
            { value: 'http', label: 'OpenAI-Compat HTTP', icon: 'server' },
            { value: 'managed-python', label: '托管 Python 规则引擎', icon: 'terminal' },
          ],
          onSelect: nextKind => {
            const prevEp = (cfg.localGuard?.endpoint || '').trim();
            cfg.localGuard = {
              ...(cfg.localGuard || {}),
              kind: nextKind,
              ...(nextKind === 'ollama' && !prevEp ? { endpoint: 'http://127.0.0.1:11434' } : {}),
            };
            render();
          },
        })),
        el('div', { class: 'lw-form-grid' }, [
          makeField('本地 Guard 模型名 (localGuard.model)', localModelInput),
          makeField('本地 Guard 端点 URL (localGuard.endpoint)', localEpInput),
        ]),
        el('div', { class: 'lw-setting-list' }, [
          makeSwitchCard({
            checked: cfg.localGuard?.think !== true,
            onChange: next => { cfg.localGuard = { ...(cfg.localGuard || {}), think: !next }; render(); },
            title: '关闭 Guard 思考链输出（Ollama 发送 think=false）',
            subtitle: '为 Qwen3 / DeepSeek-R1 等推理模型省去数秒冗余思考延时',
            pillText: cfg.localGuard?.think !== true ? 'think=false' : '思考链开启',
            pillTone: cfg.localGuard?.think !== true ? 'info' : 'warn',
            iconName: 'bolt',
            isDelta: changed.has('lgThink'),
          }),
          makeSwitchCard({
            checked: Boolean(cfg.localGuard?.allowPrivateNetwork),
            onChange: next => { cfg.localGuard = { ...(cfg.localGuard || {}), allowPrivateNetwork: next }; render(); },
            title: '允许 Guard 访问受信任私有局域网 HTTP 节点',
            subtitle: '适配内网独立 GPU 服务器；持续阻断 169.254.169.254 云元数据与公网明文 HTTP',
            pillText: cfg.localGuard?.allowPrivateNetwork ? '局域网 HTTP' : '仅回环/HTTPS',
            pillTone: cfg.localGuard?.allowPrivateNetwork ? 'warn' : 'info',
            iconName: 'server',
            isDelta: changed.has('lgPrivate'),
          }),
          makeSwitchCard({
            checked: canaryActive,
            onChange: next => { cfg.canary = { ...(cfg.canary || {}), enabled: next }; render(); },
            title: '启用弱小模型 Canary 防诱导探针 (canary.enabled)',
            subtitle: '向轻量探针模型单独送入无工具试探负载，监测是否被诱导吐出越权调用',
            pillText: canaryActive ? '已就绪' : '休眠',
            pillTone: canaryActive ? 'info' : 'info',
            iconName: 'radar',
            isDelta: changed.has('cnEnabled'),
          }),
        ]),
        makeField('Canary 引擎类型 (canary.kind)', makeSegmentedChoice({
          value: canaryKind,
          savedValue: savedCfg.canary?.kind || 'http',
          options: [
            { value: 'ollama', label: 'Ollama 原生 (/api/chat)', icon: 'cpu' },
            { value: 'http', label: 'OpenAI-Compat HTTP', icon: 'server' },
          ],
          onSelect: nextKind => {
            const prevEp = (cfg.canary?.endpoint || '').trim();
            cfg.canary = {
              ...(cfg.canary || {}),
              kind: nextKind,
              ...(nextKind === 'ollama' && !prevEp ? { endpoint: 'http://127.0.0.1:11434' } : {}),
            };
            render();
          },
        })),
        el('div', { class: 'lw-form-grid' }, [
          makeField('Canary 模型名 (canary.model)', canaryModelInput),
          makeField('Canary 端点 URL (canary.endpoint)', canaryEpInput),
        ]),
        el('div', { class: 'lw-setting-list' }, [
          makeSwitchCard({
            checked: Boolean(cfg.canary?.allowPrivateNetwork),
            onChange: next => { cfg.canary = { ...(cfg.canary || {}), allowPrivateNetwork: next }; render(); },
            title: '允许 Canary 访问受信任私有局域网 HTTP 节点',
            subtitle: '仍强制拦截 169.254.169.254 云元数据与公网明文 HTTP',
            pillText: cfg.canary?.allowPrivateNetwork ? '局域网 HTTP' : '仅回环/HTTPS',
            pillTone: cfg.canary?.allowPrivateNetwork ? 'warn' : 'info',
            iconName: 'server',
            isDelta: changed.has('cnPrivate'),
          }),
        ]),
        el('div', { 'data-mod-savebar-slot': '1' }, [renderModSaveBar(savedCfg, diffs, commitSaveConfig)]),
      ]),
    ]),
    el('aside', { class: 'lw-doc-aside' }, [
      el('div', { 'data-mod-preview-slot': '1' }, [renderModerationImpactPreview(savedCfg, cfg)]),
    ]),
  ]);

  return el('div', { class: 'lw-stack-md' }, [
    makePageHeader('内容审查', '配置本地与云端模型的审查顺序和异常处理方式。'),
    el('datalist', { id: datalistId }, [...modelChoices].map(name => el('option', { value: name }))),
    tabBar,
    state.modTab === 'ollama' ? renderOllamaManagerCard() : routingSplit,
  ]);
}

function renderSecretsPage() {
  const units = state.pluginSecretUnits || [];
  const totalKeys = units.reduce((acc, u) => acc + (Array.isArray(u?.keys) ? u.keys.length : 0), 0);

  const secUnitInput = el('input', {
    type: 'text',
    class: 'lw-input lw-mono',
    value: state.draftSecret.unitId,
    placeholder: 'llm-moderation',
    onInput: e => { state.draftSecret.unitId = e.target.value; },
  });
  const secKeyInput = el('input', {
    type: 'text',
    class: 'lw-input lw-mono',
    value: state.draftSecret.key,
    placeholder: '如 OPENAI_API_KEY',
    onInput: e => { state.draftSecret.key = e.target.value; },
  });
  const secValInput = el('input', {
    type: 'password',
    autocomplete: 'new-password',
    class: 'lw-input lw-mono',
    value: state.draftSecret.value,
    placeholder: '只写保存，绝不回显明文',
    onInput: e => { state.draftSecret.value = e.target.value; },
  });
  const secToggleBtn = el('button', {
    type: 'button',
    class: 'lw-secret-toggle',
    text: '显示',
    onClick: () => {
      const show = secValInput.type === 'password';
      secValInput.type = show ? 'text' : 'password';
      secToggleBtn.textContent = show ? '隐藏' : '显示';
    },
  });

  const presets = [
    ['llm-moderation', 'OPENAI_API_KEY'],
    ['llm-moderation', 'ALIYUN_ACCESS_KEY_ID'],
    ['llm-moderation', 'TENCENT_SECRET_ID'],
    ['llm-moderation', 'BAIDU_API_KEY'],
  ];

  const unitRows = units.map(u => el('div', { class: 'lw-hairline-row' }, [
    el('div', { class: 'lw-switch-main' }, [
      makeIcon('key'),
      el('div', { class: 'lw-switch-copy' }, [
        el('span', { class: 'lw-mono lw-switch-label', text: u.unitId }),
        el('span', { class: 'lw-switch-sub', text: `KernelGuard caller 锁定：仅 ${u.unitId} 进程外工作单元可见` }),
      ]),
    ]),
    el('div', { class: 'lw-row' }, (u.keys && u.keys.length)
      ? u.keys.map(k => el('span', { class: 'lw-pill lw-pill-ok lw-mono', text: k }))
      : [el('span', { class: 'lw-muted', text: '无已配置密钥' })]),
  ]));

  const isolationSvg = svgEl('svg', {
    viewBox: '0 0 356 266',
    class: 'lw-svg-diagram',
    role: 'img',
    'aria-label': 'KernelGuard 扩展插件密钥隔离架构图',
  }, [
    svgEl('path', { d: 'M 178 52 L 178 76', class: 'lw-svg-wire lw-svg-wire-active' }),
    svgEl('path', { d: 'M 178 130 L 178 154', class: 'lw-svg-wire lw-svg-wire-active' }),
    svgEl('path', { d: 'M 178 206 L 178 226', class: 'lw-svg-wire lw-svg-wire-active' }),
    svgNodeBox({
      x: 24, y: 8, w: 308, h: 44,
      title: '1. 控制台只写提交 (不经工具/日志)',
      sub: 'POST /api/plugin-secrets/save · 仅返回键名清单',
      stateCls: 'is-active',
    }),
    svgNodeBox({
      x: 24, y: 76, w: 308, h: 54,
      title: '2. 宿主私有凭据分仓 (0600 落盘)',
      sub: `<stateDir>/plugin-secrets/ · 已存 ${units.length} 单元`,
      stateCls: 'is-ok',
    }),
    svgNodeBox({
      x: 24, y: 154, w: 308, h: 52,
      title: '3. KernelGuard Caller 身份锁定',
      sub: '严禁 isolate/intercept 与跨单元窥探',
      stateCls: 'is-ok',
    }),
    svgNodeBox({
      x: 24, y: 226, w: 308, h: 34,
      title: '4. 仅向同名进程外子进程按需注入 env',
      sub: '',
      stateCls: 'is-active',
    }),
  ]);

  const split = el('div', { class: 'lw-doc-split' }, [
    el('div', { class: 'lw-doc-main' }, [
      makeStatStrip([
        { icon: 'key', label: '已登记命名空间', value: `${units.length} 个`, tone: units.length > 0 ? 'ok' : '' },
        { icon: 'shieldCheck', label: '密钥键总量', value: `${totalKeys} 项` },
        { icon: 'lock', label: '绑定机制', value: 'KernelGuard caller' },
        { icon: 'eye', label: '后端回显策略', value: '仅写绝不回显', tone: 'ok' },
      ]),
      el('section', { class: 'lw-section' }, [
        el('div', { class: 'lw-section-head' }, [
          el('div', {}, [
            el('h3', { text: '写入插件只写密钥' }),
            el('p', { text: '适用于全部进程外扩展单元；如仅配置云端审核密钥，也可直接在「LLM 审查策略」页内分厂商填写。' }),
          ]),
          makeIconButton({
            text: '前往 LLM 策略配云端密钥',
            iconName: 'shieldCheck',
            className: 'lw-btn lw-btn-sm',
            onClick: () => navigate('moderation'),
          }),
        ]),
        el('div', { class: 'lw-row' }, [
          el('span', { class: 'lw-muted', text: '常用模板：' }),
          ...presets.map(([uid, k]) => el('button', {
            type: 'button',
            class: 'lw-btn lw-btn-sm lw-mono',
            text: `${k}`,
            onClick: () => {
              state.draftSecret.unitId = uid;
              state.draftSecret.key = k;
              render();
            },
          })),
        ]),
        el('div', { class: 'lw-form-grid-3' }, [
          makeField('扩展单元 ID', secUnitInput),
          makeField('环境变量 / 密钥键名', secKeyInput),
          makeField('只写密钥值', el('div', { class: 'lw-secret-input-wrap' }, [secValInput, secToggleBtn])),
        ]),
        el('div', { class: 'lw-row lw-between' }, [
          el('span', { class: 'lw-switch-sub', text: '密钥仅在插件进程外鉴权阶段由内核按 caller unitId 注入，不会返回浏览器。' }),
          makeIconButton({
            text: '只写保存扩展密钥',
            iconName: 'key',
            className: 'lw-btn lw-btn-trust lw-btn-sm',
            disabled: state.busy,
            onClick: () => runMutation(async () => {
              const unitId = state.draftSecret.unitId.trim();
              const key = state.draftSecret.key.trim();
              const val = state.draftSecret.value;
              state.draftSecret.value = '';
              const res = await savePluginSecretsAndRefresh(unitId, { [key]: val });
              state.draftSecret.key = '';
              setNotice(`已只写保存 ${res.meta.unitId}#${key}。`);
            }),
          }),
        ]),
      ]),
      el('section', { class: 'lw-section' }, [
        el('div', { class: 'lw-section-head' }, [
          el('div', {}, [
            el('h3', { text: '已登记只写密钥索引（仅展示键名）' }),
            el('p', { text: '每个命名空间互相严格隔离，仅同名扩展单元可凭宿主授权读取。' }),
          ]),
          el('span', { class: 'lw-pill lw-pill-info', text: `${units.length} 个命名空间` }),
        ]),
        unitRows.length
          ? el('div', { class: 'lw-setting-list' }, unitRows)
          : el('div', { class: 'lw-doc-callout', text: '尚未写入任何扩展单元密钥。可使用上方模板快速填入。' }),
      ]),
    ]),
    el('aside', { class: 'lw-doc-aside' }, [
      el('div', { class: 'lw-section-head' }, [
        el('div', {}, [
          el('h3', { text: '进程外凭据隔离流向' }),
          el('p', { text: '保证主控内存与工具输出零凭据泄露' }),
        ]),
        el('span', { class: 'lw-pill lw-pill-ok', text: '0600 隔离' }),
      ]),
      isolationSvg,
      el('div', { class: 'lw-aside-list' }, [
        el('div', { class: 'lw-aside-row' }, [
          el('span', { class: 'lw-muted', text: '跨插件隔离' }),
          el('strong', { text: 'KernelGuard 强制绑定 caller' }),
        ]),
        el('div', { class: 'lw-aside-row' }, [
          el('span', { class: 'lw-muted', text: '明文查询' }),
          el('strong', { text: 'API 永久禁止回传明文' }),
        ]),
      ]),
    ]),
  ]);

  return el('div', { class: 'lw-stack-md' }, [
    makePageHeader('插件密钥', '按插件保存凭据，保存后可查看键名或更新密钥。'),
    split,
  ]);
}

function statusPillTone(status) {
  if (status === 'ok') return 'ok';
  if (status === 'warn') return 'warn';
  if (status === 'error') return 'err';
  return 'info';
}

function renderPanelCard(panel) {
  const statusTone = statusPillTone(panel.status);
  const tables = Array.isArray(panel.tables) && panel.tables.length
    ? panel.tables
    : (panel.table?.columns?.length ? [panel.table] : []);

  const children = [
    el('div', { class: 'lw-section-head' }, [
      el('div', {}, [
        el('h3', { text: panel.title }),
        panel.subtitle ? el('p', { text: panel.subtitle }) : null,
      ]),
      el('div', { class: 'lw-row' }, [
        el('span', { class: 'lw-pill', text: panel.category }),
        el('span', { class: `lw-pill lw-pill-${statusTone}`, text: panel.status }),
      ]),
    ]),
  ];

  if (panel.summary?.length) {
    children.push(el('div', { class: 'lw-metric-ledger' }, panel.summary.map(kpi => {
      const toneCls = kpi.tone === 'ok' || kpi.tone === 'warn' || kpi.tone === 'err' ? `is-${kpi.tone}` : '';
      return el('div', { class: `lw-metric-cell ${toneCls}` }, [
        el('div', { class: 'lw-metric-k', text: kpi.label }),
        el('div', { class: 'lw-metric-v', text: kpi.value }),
      ]);
    })));
  }

  if (panel.notices?.length) {
    for (const notice of panel.notices) {
      const cls = notice.tone === 'err' ? 'is-err' : notice.tone === 'warn' ? 'is-warn' : notice.tone === 'ok' ? 'is-ok' : 'is-info';
      children.push(el('div', { class: `lw-doc-callout ${cls}`, text: notice.text }));
    }
  }

  for (const table of tables) {
    if (!table?.columns?.length) continue;
    if (table.title) {
      children.push(el('h4', { class: 'lw-table-title', text: table.title }));
    }
    children.push(el('div', { class: 'lw-table-wrap' }, [
      el('table', { class: 'lw-table' }, [
        el('thead', {}, [el('tr', {}, table.columns.map(col => el('th', { text: col })))]),
        el('tbody', {}, (table.rows || []).map(row => el('tr', {}, row.map(cell => el('td', { class: 'lw-mono', text: cell }))))),
      ]),
    ]));
  }

  const safeLinks = Array.isArray(panel.links)
    ? panel.links.filter(link => link && isSafeNavigationUrl(link.href, { allowRelative: true }))
    : [];
  if (safeLinks.length) {
    children.push(el('div', { class: 'lw-row' }, safeLinks.map(link => el('a', {
      class: 'lw-btn lw-btn-sm',
      href: link.href,
      target: '_blank',
      rel: 'noopener noreferrer',
      text: link.label,
    }))));
  }

  return el('section', {
    class: 'lw-section',
    'data-panel-id': panel.id,
  }, children);
}

function renderPanelsPage() {
  const panels = state.snapshot?.panels || [];
  return el('div', { class: 'lw-stack-md' }, [
    makePageHeader('扩展面板', '查看已安装插件提供的面板和操作。'),
    makeStatStrip([
      { icon: 'layoutPanel', label: '已挂载扩展面板', value: `${panels.length} 个`, tone: panels.length > 0 ? 'ok' : '' },
      { icon: 'shieldCheck', label: '脚本与 HTML', value: '严格零执行注入' },
      { icon: 'globe', label: '外部链接策略', value: '仅安全协议白名单' },
      { icon: 'cpu', label: '渲染机制', value: '纯 JSON 数据账本' },
    ]),
    panels.length
      ? el('div', { class: 'lw-stack-md' }, panels.map(renderPanelCard))
      : el('div', { class: 'lw-doc-callout', text: '当前未挂载注册扩展面板的插件。任何实现 console:panel@1 契约的进程外插件均会在此自动只读呈现。' }),
  ]);
}

const AUDIT_META_LABELS = [
  ['reason', '结果代码'],
  ['durationMs', '执行耗时'],
  ['mountMode', '挂载姿态'],
  ['mode', '运行模式'],
  ['network', '容器网络'],
  ['exitCode', '退出码'],
  ['bytesRead', '文件读取字节'],
  ['bytesWritten', '文件写入字节'],
  ['stdoutBytes', '标准输出字节'],
  ['stderrBytes', '标准错误字节'],
  ['outputBytes', 'MCP 返回字节'],
  ['serverId', '第三方 MCP 服务'],
  ['timedOut', '是否超时'],
  ['cancelled', '是否取消'],
  ['tool', '涉及工具'],
  ['capability', '触发能力'],
  ['approvalIdShort', '审批短码'],
  ['route', '连接路由'],
  ['status', 'HTTP 状态'],
  ['code', '状态码'],
  ['outcome', '结果标识'],
  ['jobIdPrefix', '容器作业号'],
];

function buildAuditTransportPayload(ev) {
  const meta = ev.meta || {};
  const transportBoundary = ev.source === 'audit'
    ? (meta.serverId ? 'external-mcp-out-of-process' : 'linux-docker-sandbox')
    : 'host-control-plane';
  return {
    key: ev.key || null,
    time: ev.time || null,
    source: ev.source || 'connector',
    transportBoundary,
    logFile: ev.source === 'audit' ? 'audit.jsonl' : 'connector.log',
    toolOrEvent: ev.name || null,
    outcome: ev.tone || 'info',
    label: ev.label || '',
    detailSummary: ev.detail || '',
    transportMeta: meta,
    redactionNotice: '仅包含结构化传输元数据与字节计数，严禁含文件正文或凭据原文',
  };
}

function renderAuditTraceDetail(ev) {
  const meta = ev.meta || {};
  const boundaryLabel = ev.source === 'audit'
    ? (meta.serverId ? '进程外第三方 MCP（非容器）' : 'Linux Docker 只读/受限沙箱')
    : '宿主控制台 / 连接器遥测';
  const kvPairs = [
    ['时间戳', ev.time || '—'],
    ['记录来源', ev.source === 'audit' ? '沙盒审计 audit.jsonl' : '连接器状态 connector.log'],
    ['传输边界', boundaryLabel],
  ];
  for (const [k, label] of AUDIT_META_LABELS) {
    if (meta[k] === undefined || meta[k] === null || meta[k] === '') continue;
    let val = String(meta[k]);
    if (k === 'durationMs') val += ' ms';
    else if (typeof meta[k] === 'boolean') val = meta[k] ? '是' : '否';
    kvPairs.push([label, val]);
  }
  const jsonText = JSON.stringify(buildAuditTransportPayload(ev), null, 2);
  return el('div', { class: 'lw-audit-detail-box' }, [
    el('div', { class: 'lw-trace-grid' }, kvPairs.map(([k, v]) => el('div', { class: 'lw-trace-kv' }, [
      el('span', { class: 'lw-trace-k', text: k }),
      el('span', { class: 'lw-trace-v', text: v }),
    ]))),
    el('div', { class: 'lw-row lw-between' }, [
      el('strong', { style: 'font-size:12px', text: '脱敏 Transport / 审计 JSON 信封' }),
      makeIconButton({
        text: '复制 Transport JSON',
        iconName: 'copy',
        className: 'lw-btn lw-btn-sm',
        onClick: () => void copyTextToClipboard(jsonText, `audit-${ev.key || ev.time}`),
      }),
    ]),
    el('pre', { class: 'lw-pre lw-mono', 'data-audit-transport-json': ev.key || '1', text: jsonText }),
  ]);
}

function renderAuditPage() {
  const events = state.snapshot?.events || [];
  const sseOk = state.sseStatus === 'open' || state.sseStatus === 'connected';
  const filter = state.auditFilter || 'all';
  const visibleAudit = filter === 'kernel'
    ? []
    : events.filter(ev => {
      if (filter === 'flagged') return ev.tone === 'err' || ev.tone === 'warn';
      if (filter === 'ok') return ev.tone === 'ok';
      return true;
    }).slice(0, 60);

  const visibleKernel = (filter === 'all' || filter === 'kernel')
    ? state.liveKernelEvents.slice(0, 25)
    : [];

  const toggleExpandAudit = evKey => {
    if (state.expandedAuditKeys[evKey]) delete state.expandedAuditKeys[evKey];
    else state.expandedAuditKeys[evKey] = true;
    render();
  };

  const toggleExpandKernel = kKey => {
    if (state.expandedKernelKeys[kKey]) delete state.expandedKernelKeys[kKey];
    else state.expandedKernelKeys[kKey] = true;
    render();
  };

  const auditRows = [];
  visibleAudit.forEach((ev, idx) => {
    const tone = ev.tone === 'ok' ? 'ok' : ev.tone === 'err' ? 'err' : ev.tone === 'warn' ? 'warn' : 'info';
    const evKey = ev.key || `${ev.source || 'log'}:${ev.time || ''}:${ev.name || ''}:${idx}`;
    const isOpen = Boolean(state.expandedAuditKeys[evKey]);
    auditRows.push(el('tr', {
      class: `lw-audit-row ${isOpen ? 'is-open' : ''}`,
      'data-audit-row': evKey,
      onClick: () => toggleExpandAudit(evKey),
    }, [
      el('td', { style: 'width:32px;padding-right:4px' }, [
        el('button', {
          type: 'button',
          class: `lw-chevron-btn ${isOpen ? 'is-open' : ''}`,
          'aria-expanded': String(isOpen),
          'aria-label': '展开或收起调用详细 Transport JSON',
          onClick: e => { e.stopPropagation(); toggleExpandAudit(evKey); },
        }, [makeIcon('chevronRight')]),
      ]),
      el('td', { class: 'lw-mono', text: ev.time || '' }),
      el('td', {}, [el('span', { class: `lw-pill lw-pill-${tone}`, text: ev.label || ev.source || 'info' })]),
      el('td', { class: 'lw-mono', text: ev.name || '' }),
      el('td', { class: 'lw-muted lw-mono', text: ev.detail || '-' }),
    ]));
    if (isOpen) {
      auditRows.push(el('tr', { class: 'lw-audit-detail-row' }, [
        el('td', { colSpan: '5' }, [renderAuditTraceDetail(ev)]),
      ]));
    }
  });

  const channelRows = [];
  visibleKernel.forEach((ev, idx) => {
    const kKey = ev.id || `${ev.seq ?? idx}:${ev.time || ''}:${ev.type || ''}`;
    const isOpen = Boolean(state.expandedKernelKeys[kKey]);
    const kernelJsonText = JSON.stringify(ev, null, 2);
    channelRows.push(el('tr', {
      class: `lw-audit-row ${isOpen ? 'is-open' : ''}`,
      'data-kernel-row': String(kKey),
      onClick: () => toggleExpandKernel(String(kKey)),
    }, [
      el('td', { style: 'width:32px;padding-right:4px' }, [
        el('button', {
          type: 'button',
          class: `lw-chevron-btn ${isOpen ? 'is-open' : ''}`,
          'aria-expanded': String(isOpen),
          'aria-label': '展开或收起内核事件 JSON',
          onClick: e => { e.stopPropagation(); toggleExpandKernel(String(kKey)); },
        }, [makeIcon('chevronRight')]),
      ]),
      el('td', { class: 'lw-mono', text: ev.time || '' }),
      el('td', {}, [el('span', { class: 'lw-pill lw-pill-info lw-mono', text: ev.type || '' })]),
      el('td', {}, [el('div', { class: 'lw-meta-chips' }, formatMetaChips(ev.meta))]),
    ]));
    if (isOpen) {
      channelRows.push(el('tr', { class: 'lw-audit-detail-row' }, [
        el('td', { colSpan: '4' }, [
          el('div', { class: 'lw-audit-detail-box' }, [
            el('div', { class: 'lw-row lw-between' }, [
              el('strong', { style: 'font-size:12px', text: 'control.sock 事件原始脱敏 JSON' }),
              makeIconButton({
                text: '复制 JSON',
                iconName: 'copy',
                className: 'lw-btn lw-btn-sm',
                onClick: () => void copyTextToClipboard(kernelJsonText, `kernel-${kKey}`),
              }),
            ]),
            el('pre', { class: 'lw-pre lw-mono', text: kernelJsonText }),
          ]),
        ]),
      ]));
    }
  });

  return el('div', { class: 'lw-stack-md' }, [
    makePageHeader('实时审计', '查看最近的工具调用与内核事件，展开记录可核对详情。'),
    makeStatStrip([
      { icon: 'activity', label: 'SSE 实时通道', value: sseOk ? '在线推送中' : state.sseStatus, tone: sseOk ? 'ok' : 'warn' },
      { icon: 'terminal', label: '内核控制事件', value: `${state.liveKernelEvents.length} 条` },
      { icon: 'clipboardCheck', label: '审计遥测记录', value: `${events.length} 条` },
      { icon: 'lock', label: '遥测脱敏策略', value: '仅元数据 · 零正文', tone: 'ok' },
    ]),
    makeField('视图过滤筛选', makeSegmentedChoice({
      value: filter,
      options: [
        { value: 'all', label: '全部记录', icon: 'layers' },
        { value: 'flagged', label: '拦截与异常', icon: 'alert' },
        { value: 'ok', label: '放行通过', icon: 'check' },
        { value: 'kernel', label: '控制通道事件', icon: 'terminal' },
      ],
      onSelect: v => { state.auditFilter = v; render(); },
    })),
    filter !== 'kernel'
      ? el('section', { class: 'lw-section' }, [
          el('div', { class: 'lw-section-head' }, [
            el('div', {}, [
              el('h3', { text: '审计与连接器遥测流（点击任意行展开 Transport JSON）' }),
              el('p', { text: '展示工具调用、人工审批决定与护栏拦截；展开可见传输边界、字节计数与完整脱敏 JSON 信封。' }),
            ]),
            el('div', { class: 'lw-row' }, [
              el('button', {
                type: 'button',
                class: 'lw-btn lw-btn-sm',
                text: '全部展开',
                disabled: visibleAudit.length === 0,
                onClick: () => {
                  visibleAudit.forEach((ev, idx) => {
                    state.expandedAuditKeys[ev.key || `${ev.source || 'log'}:${ev.time || ''}:${ev.name || ''}:${idx}`] = true;
                  });
                  render();
                },
              }),
              el('button', {
                type: 'button',
                class: 'lw-btn lw-btn-sm',
                text: '全部收起',
                disabled: visibleAudit.length === 0,
                onClick: () => { state.expandedAuditKeys = {}; render(); },
              }),
              el('span', { class: 'lw-pill lw-pill-info', text: `${visibleAudit.length} 条显示` }),
            ]),
          ]),
          visibleAudit.length
            ? el('div', { class: 'lw-table-wrap' }, [
                el('table', { class: 'lw-table' }, [
                  el('thead', {}, [el('tr', {}, [
                    el('th', { style: 'width:32px', 'aria-label': '展开' }),
                    el('th', { text: '时间' }),
                    el('th', { text: '状态' }),
                    el('th', { text: '工具 / 事件' }),
                    el('th', { text: '摘要' }),
                  ])]),
                  el('tbody', {}, auditRows),
                ]),
              ])
            : el('div', { class: 'lw-doc-callout', text: '当前筛选条件下暂无历史审计记录。' }),
        ])
      : null,
    filter === 'all' || filter === 'kernel'
      ? el('section', { class: 'lw-section' }, [
          el('div', { class: 'lw-section-head' }, [
            el('div', {}, [
              el('h3', { text: '实时内核控制通道事件（control.sock 元数据，点击可展开完整 JSON）' }),
              el('p', { text: '自动结构化拆解事件字段并保留原始脱敏 JSON，绝不回传请求原文与凭据。' }),
            ]),
            el('div', { class: 'lw-row' }, [
              el('button', {
                type: 'button',
                class: 'lw-btn lw-btn-sm',
                text: '全部展开',
                disabled: visibleKernel.length === 0,
                onClick: () => {
                  visibleKernel.forEach((ev, idx) => {
                    state.expandedKernelKeys[String(ev.id || `${ev.seq ?? idx}:${ev.time || ''}:${ev.type || ''}`)] = true;
                  });
                  render();
                },
              }),
              el('button', {
                type: 'button',
                class: 'lw-btn lw-btn-sm',
                text: '全部收起',
                disabled: visibleKernel.length === 0,
                onClick: () => { state.expandedKernelKeys = {}; render(); },
              }),
              el('span', { class: 'lw-pill lw-pill-info', text: `${visibleKernel.length} 条显示` }),
            ]),
          ]),
          visibleKernel.length
            ? el('div', { class: 'lw-table-wrap' }, [
                el('table', { class: 'lw-table' }, [
                  el('thead', {}, [el('tr', {}, [
                    el('th', { style: 'width:32px', 'aria-label': '展开' }),
                    el('th', { text: '时间' }),
                    el('th', { text: '事件类型' }),
                    el('th', { text: '结构化元数据字段' }),
                  ])]),
                  el('tbody', {}, channelRows),
                ]),
              ])
            : el('div', { class: 'lw-doc-callout', text: '暂无实时控制通道事件。当发生工具审批、策略变更或流式拦截时将即时出现。' }),
        ])
      : null,
  ]);
}

const CONSOLE_HTTP_CONTRACTS = [
  {
    id: 'status',
    method: 'GET',
    path: '/api/status',
    group: '总览与状态',
    title: '全栈运行快照与聚合工具目录',
    summary: '返回连接器在线态、capabilities.effectiveTools、第三方 MCP 摘要、审批队列、面板清单与近 60 条审计元数据。',
    canTryGet: true,
    params: [],
    bounds: ['严格同源 loopback 鉴权（X-LoomWard-Tab-Auth）', '绝不返回明文密钥、私有仓名或请求正文字段'],
  },
  {
    id: 'capabilities',
    method: 'POST',
    path: '/api/capabilities',
    group: '安全策略',
    title: '原子更新能力开关与单工具启停',
    summary: '写入 0600 <stateDir>/capabilities.json；支持顶层 fileRead / fileWrite / allowExec 与单工具开关映射 tools。',
    canTryGet: false,
    bodyExample: { fileRead: true, fileWrite: false, allowExec: false, tools: { read_file: true } },
    params: [
      { name: 'fileRead', type: 'boolean', required: false, description: '是否允许 read_file / list_directory / search_files' },
      { name: 'fileWrite', type: 'boolean', required: false, description: '关闭时强制容器工作区降级为 :readonly 只读挂载' },
      { name: 'allowExec', type: 'boolean', required: false, description: '是否开放 exec_command（不可突破配置上限）' },
      { name: 'tools', type: 'object', required: false, description: '按工具名单独禁用/恢复的映射（false 为停用）' },
    ],
    bounds: ['需校验 X-LoomWard-CSRF + Origin + Same-Site', '不允许在工作区目录内存储配置文件'],
  },
  {
    id: 'fencing-config-get',
    method: 'GET',
    path: '/api/fencing/config',
    group: 'Agent 围栏',
    title: '读取 R1–R7 防泄漏规则与缓存健康度',
    summary: '返回 <stateDir>/antileak/policy.json 策略配置、R1–R7 规则目录及 private-repos.json 计数/过期时间（脱敏，绝不返私有名）。',
    canTryGet: true,
    params: [],
    bounds: ['只返回 privateCount / patternCount / status，严禁返回私有仓名字或 R4 正则全文'],
  },
  {
    id: 'fencing-config-save',
    method: 'POST',
    path: '/api/fencing/config',
    group: 'Agent 围栏',
    title: '保存 R1–R7 防泄漏围栏策略',
    summary: '经服务端 Python re.compile 语法预检后原子保存 0600 policy.json，并固定 private_cache 路径至受保护目录。',
    canTryGet: false,
    bodyExample: { config: { forbiddenPatterns: ['INTERNAL_CODENAME'], expectedOwners: ['your-org'], privateCacheTtl: 28800, resignExempt: true } },
    params: [
      { name: 'config.forbiddenPatterns', type: 'string[]', required: false, description: 'R2 禁止模式正则列表（Python re 语法）' },
      { name: 'config.secretRegexes', type: 'string[]', required: false, description: 'R7 凭据/私钥正则列表' },
      { name: 'config.expectedOwners', type: 'string[]', required: false, description: 'R1 私有仓归属者白/红名单核对清单' },
      { name: 'config.exemptTools', type: 'string[]', required: false, description: '声明为生命周期控制而不触犯规则的豁免工具名' },
    ],
    bounds: ['锁定 private_cache / refresh_script 路径防 WebUI 篡改', '异常正则立时返回 400 并拒绝落盘'],
  },
  {
    id: 'fencing-test',
    method: 'POST',
    path: '/api/fencing/test',
    group: 'Agent 围栏',
    title: 'R1–R7 离线 Dry-Run 载荷试验',
    summary: '以 strictly offline（永不传 --net）拉起 check.py content 检验合成输入，返回 pass / violation / error 三态及脱敏命中理由。',
    canTryGet: false,
    bodyExample: { text: 'git commit check sample payload' },
    params: [
      { name: 'text', type: 'string', required: true, description: '待检验文本样本（最大 256 KiB）' },
    ],
    bounds: ['缓存缺失或过期时严格返回 failClosed: true (error)', '不回显完整凭据明文'],
  },
  {
    id: 'fencing-refresh',
    method: 'POST',
    path: '/api/fencing/refresh',
    group: 'Agent 围栏',
    title: '触发刷新私有仓缓存 (refresh-private.py)',
    summary: '显式由管理员点击触发 refresh-private.py，更新 private-repos.json 后仅返回状态计数与耗时。',
    canTryGet: false,
    bodyExample: {},
    params: [],
    bounds: ['永不自动执行', '响应体剥除一切仓库名清单与种子模式'],
  },
  {
    id: 'fencing-doctor',
    method: 'POST',
    path: '/api/fencing/doctor',
    group: 'Agent 围栏',
    title: '运行围栏引擎健康自检 (doctor.py)',
    summary: '离线校验策略 JSON、Python 环境、ssh-keygen、缓存新鲜度及规则可用性。',
    canTryGet: false,
    bodyExample: {},
    params: [],
    bounds: ['隔离环境变量白名单运行，不暴露宿主机秘钥'],
  },
  {
    id: 'mcp-servers-list',
    method: 'GET',
    path: '/api/mcp-servers',
    group: '第三方 MCP',
    title: '列出已纳管第三方 MCP 服务（脱敏）',
    summary: '返回 stdio/http 传输配置、已保存密钥键名清单（envKeys/headerKeys，不回显值）及缓存的外部工具元数据。',
    canTryGet: true,
    params: [],
    bounds: ['写后不可读回环境变量值与 HTTP 头密钥值'],
  },
  {
    id: 'mcp-servers-save',
    method: 'POST',
    path: '/api/mcp-servers/save',
    group: '第三方 MCP',
    title: '新增/更新并在有界隔离下探测 MCP 服务',
    summary: '校验传输协议与 SSRF/危险环境变量黑名单，写入 0600 mcp-servers.json，并可选探测 initialize + tools/list。',
    canTryGet: false,
    bodyExample: { id: 'docs_mcp', name: 'Docs MCP', transport: 'stdio', command: 'npx', args: ['-y', '@example/mcp'], probe: true },
    params: [
      { name: 'id', type: 'string', required: true, description: '服务唯一标识（小写字母/数字/-，1–32 字符）' },
      { name: 'transport', type: 'enum', required: true, description: 'stdio 或 http (Streamable HTTP)' },
      { name: 'command / url', type: 'string', required: true, description: 'stdio 启动可执行文件或 HTTPS/loopback 端点' },
      { name: 'probe', type: 'boolean', required: false, description: '保存后是否立即有界握手探测并同步工具目录' },
    ],
    bounds: ['变更命令或 Origin 时如保留旧密需显式传入 replaceSecrets: true', '每服务最多缓存 200 工具，单次探测受 429/409 并发守卫'],
  },
  {
    id: 'mcp-servers-probe',
    method: 'POST',
    path: '/api/mcp-servers/probe',
    group: '第三方 MCP',
    title: '按 ID 强制重探工具列表与握手状态',
    summary: '立即执行受控 MCP initialize + tools/list 并刷新 lastProbeOk 与可用工具目录。',
    canTryGet: false,
    bodyExample: { id: 'docs_mcp' },
    params: [{ name: 'id', type: 'string', required: true, description: '已配置的 MCP 服务 ID' }],
    bounds: ['同 ID 并发探测返回 409', '全盘并发超过上限返回 429'],
  },
  {
    id: 'moderation-config-get',
    method: 'GET',
    path: '/api/moderation/config',
    group: 'LLM 审查',
    title: '获取内容审查路由策略配置',
    summary: '读取模式、回退预设、本地 Ollama Guard、Canary 金丝雀探针与云厂商接入字段。',
    canTryGet: true,
    params: [],
    bounds: ['云端 API 密钥存放在独立 plugin-secrets，不随配置返回'],
  },
  {
    id: 'ollama-status',
    method: 'GET',
    path: '/api/moderation/ollama/status',
    group: 'LLM 审查',
    title: '探测 Ollama 安装状态、运行态与模型列表',
    summary: '按 SSRF 边界校验 endpoint 后拉取 /api/tags、/api/ps 与活跃拉取任务进度。',
    canTryGet: true,
    params: [{ name: 'endpoint', type: 'query', required: false, description: '默认 http://127.0.0.1:11434' }],
    bounds: ['拒绝云元数据 IP (169.254.169.254 等)'],
  },
  {
    id: 'approvals-approve',
    method: 'POST',
    path: '/api/approvals/approve',
    group: '本机审批',
    title: '绑定参数摘要的一次性人工批准',
    summary: '校验审批单号 id 与 policyDigest 完全匹配后签发单次执行令牌并写入 24h 防重放账本。',
    canTryGet: false,
    bodyExample: { id: 'approval-uuid', digest: 'sha256-hex-digest' },
    params: [
      { name: 'id', type: 'string', required: true, description: '待审请求 ID' },
      { name: 'digest', type: 'string', required: true, description: '逐参数规范化摘要，不匹配立即拒绝并作废' },
    ],
    bounds: ['禁止通配符批准或跨请求复用', '每条审批单仅可消费一次'],
  },
];

async function copyTextToClipboard(text, targetKey) {
  if (!text) return;
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const area = document.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', '');
      area.style.position = 'fixed';
      area.style.left = '-9999px';
      document.body.append(area);
      area.select();
      document.execCommand('copy');
      area.remove();
    }
    state.copiedTarget = targetKey;
    setNotice('已复制契约负载到剪贴板。');
    setTimeout(() => {
      if (state.copiedTarget === targetKey) {
        state.copiedTarget = '';
        render();
      }
    }, 1800);
  } catch {
    setError('当前浏览器上下文不允许访问剪贴板。');
  }
}

function getToolDraftArgs(tool) {
  if (!state.toolArgsDraft[tool.name]) {
    const sampleArgs = tool.sampleCall?.params?.arguments || {};
    const draft = {};
    for (const p of (tool.parameters || [])) {
      const val = sampleArgs[p.name];
      draft[p.name] = val === undefined ? '' : (typeof val === 'string' ? val : JSON.stringify(val));
    }
    state.toolArgsDraft[tool.name] = draft;
  }
  return state.toolArgsDraft[tool.name];
}

function parseDraftArgValue(raw, type) {
  if (raw === '' || raw === undefined || raw === null) return undefined;
  if (type === 'boolean') return raw === 'true' || raw === true;
  if (type === 'number' || type === 'integer') {
    const n = Number(raw);
    return Number.isFinite(n) ? n : raw;
  }
  if (type === 'object' || type === 'array') {
    try { return JSON.parse(raw); } catch { return raw; }
  }
  return raw;
}

function methodBadgeClass(kind) {
  const k = String(kind || '').toUpperCase();
  if (k === 'READ' || k === 'GET' || k === 'CTRL') return 'is-read';
  if (k === 'WRITE') return 'is-write';
  if (k === 'EXEC') return 'is-exec';
  if (k === 'MCP') return 'is-mcp';
  return 'is-info';
}

function getFilteredToolsList(allTools) {
  const byGroup = state.toolFilter === 'all'
    ? allTools
    : allTools.filter(t => t.group === state.toolFilter);
  const q = (state.toolSearch || '').trim().toLowerCase();
  if (!q) return byGroup;
  return byGroup.filter(t => (
    String(t.name || '').toLowerCase().includes(q)
    || String(t.title || '').toLowerCase().includes(q)
    || String(t.description || '').toLowerCase().includes(q)
  ));
}

function renderToolsPage() {
  const allTools = state.snapshot?.capabilities?.effectiveTools || [];
  const externalCount = allTools.filter(t => t.external).length;
  const sandboxCount = allTools.length - externalCount;
  const enabledCount = allTools.filter(t => t.enabled).length;
  const mode = state.toolCatalogMode === 'http' ? 'http' : 'mcp';

  const searchInput = el('input', {
    type: 'search',
    class: 'lw-input',
    value: state.toolSearch || '',
    placeholder: mode === 'mcp' ? '检索工具名 / 标题 / 参数...' : '检索 HTTP 路径 / 能力 / 说明...',
    onInput: e => { state.toolSearch = e.target.value; render(); },
  });

  let leftItemsNode;
  let rightDetailNode;
  let groupChipsNode;

  if (mode === 'mcp') {
    const visibleTools = getFilteredToolsList(allTools);
    const activeTool = visibleTools.find(t => t.name === state.selectedToolName)
      || visibleTools[0]
      || allTools.find(t => t.name === state.selectedToolName)
      || allTools[0];
    if (activeTool && state.selectedToolName !== activeTool.name) {
      state.selectedToolName = activeTool.name;
    }

    const chipDefs = [
      ['all', '全部'],
      ['context', '上下文'],
      ['fileRead', '文件读'],
      ['fileWrite', '文件写'],
      ['exec', '命令'],
      ['mcp', '外部 MCP'],
    ];
    groupChipsNode = el('div', { class: 'lw-apifox-chip-row' }, chipDefs.map(([val, label]) => el('button', {
      type: 'button',
      class: `lw-apifox-chip ${state.toolFilter === val ? 'is-active' : ''}`,
      text: label,
      onClick: () => { state.toolFilter = val; render(); },
    })));

    const groupTitles = {
      context: '工作区与运行上下文',
      fileRead: '只读文件系统 (Docker :ro)',
      fileWrite: '工作区写入（需 fileWrite + 批准）',
      exec: '沙箱命令执行（一次性容器）',
      execControl: '后台命令控制',
      mcp: '第三方外部 MCP 进程工具',
    };
    const buckets = new Map();
    for (const tool of visibleTools) {
      const g = tool.group || 'other';
      if (!buckets.has(g)) buckets.set(g, []);
      buckets.get(g).push(tool);
    }

    const catalogRows = [];
    for (const [grp, tools] of buckets.entries()) {
      catalogRows.push(el('div', { class: 'lw-apifox-group-label', text: `${groupTitles[grp] || grp} (${tools.length})` }));
      for (const tool of tools) {
        const isSel = activeTool && activeTool.name === tool.name;
        catalogRows.push(el('button', {
          type: 'button',
          class: `lw-apifox-item ${isSel ? 'is-active' : ''}`,
          'data-apifox-item': tool.name,
          onClick: () => { state.selectedToolName = tool.name; render(); },
        }, [
          el('span', { class: `lw-method-pill ${methodBadgeClass(tool.kind)}`, text: tool.kind || 'MCP' }),
          el('span', { class: 'lw-apifox-item-text' }, [
            el('span', { class: 'lw-apifox-item-name', text: tool.name }),
            el('span', { class: 'lw-apifox-item-sub', text: tool.title || tool.description || '' }),
          ]),
          el('span', { class: `lw-apifox-dot ${tool.enabled ? 'is-ok' : 'is-err'}`, title: tool.enabled ? '已启用' : '已关闭' }),
        ]));
      }
    }
    leftItemsNode = catalogRows.length
      ? catalogRows
      : [el('div', { class: 'lw-muted', style: 'padding:14px', text: '当前筛选条件下无匹配工具接口。' })];

    if (!activeTool) {
      rightDetailNode = el('div', { class: 'lw-doc-callout', text: '暂未发现可用工具契约；请在「能力开关与服务」确认容器就绪，或在「Agent 安全围栏 -> 第三方 MCP」接入新服务。' });
    } else {
      const boundary = classifyToolBoundary(activeTool.name, activeTool.external);
      const argsDraft = getToolDraftArgs(activeTool);
      const builtArgs = {};
      for (const p of (activeTool.parameters || [])) {
        const parsedVal = parseDraftArgValue(argsDraft[p.name], p.type);
        if (parsedVal !== undefined) builtArgs[p.name] = parsedVal;
      }
      const liveRpcPayload = JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: activeTool.name,
          arguments: builtArgs,
        },
      }, null, 2);

      const parentOn = isToolParentEnabled(state.snapshot, activeTool);
      const stats = activeTool.stats || {};
      const totalCalls = stats.totalCalls || 0;
      const blockedCalls = stats.blockedCount || 0;
      const blockPct = totalCalls > 0 ? Math.min(100, Math.round((blockedCalls / totalCalls) * 100)) : 0;

      const paramEditorNodes = (activeTool.parameters || []).length
        ? activeTool.parameters.map(p => {
            const val = argsDraft[p.name] ?? '';
            const labelNode = el('span', { class: 'lw-row lw-between', style: 'width:100%' }, [
              el('span', {}, [
                el('code', { class: 'lw-tag-inline', text: p.name }),
                el('span', { text: ' ' }),
                el('span', { class: 'lw-muted', text: p.type }),
              ]),
              el('span', { class: `lw-pill ${p.required ? 'lw-pill-warn' : ''}`, text: p.required ? '必填' : '可选' }),
            ]);
            const ctrl = p.enumValues?.length
              ? makeSelect(
                  [['', '— 未指定 —'], ...p.enumValues.map(ev => [String(ev), String(ev)])],
                  String(val),
                  e => { argsDraft[p.name] = e.target.value; render(); },
                )
              : el('input', {
                  type: 'text',
                  class: 'lw-input lw-mono',
                  value: String(val),
                  placeholder: p.description || `${p.type} 参数值...`,
                  onInput: e => {
                    argsDraft[p.name] = e.target.value;
                    const codeEl = root.querySelector('[data-apifox-live-json]');
                    if (codeEl) {
                      const nextBuilt = {};
                      for (const item of activeTool.parameters) {
                        const pv = parseDraftArgValue(argsDraft[item.name], item.type);
                        if (pv !== undefined) nextBuilt[item.name] = pv;
                      }
                      codeEl.textContent = JSON.stringify({
                        jsonrpc: '2.0',
                        id: 1,
                        method: 'tools/call',
                        params: { name: activeTool.name, arguments: nextBuilt },
                      }, null, 2);
                    }
                  },
                });
            return makeField(labelNode, ctrl);
          })
        : [el('div', { class: 'lw-muted', text: '该工具无需传入参数（arguments: {}）。' })];

      rightDetailNode = [
        el('div', { class: 'lw-apifox-sigbar' }, [
          el('div', { class: 'lw-row' }, [
            el('span', { class: `lw-method-pill ${methodBadgeClass(activeTool.kind)}`, text: activeTool.kind || 'MCP' }),
            el('code', { class: 'lw-apifox-sigcode', text: `tools/call :: ${activeTool.name}` }),
            el('span', { class: `lw-pill lw-pill-${boundary.tone}`, text: boundary.label }),
            el('span', {
              class: `lw-pill ${activeTool.requiresApproval ? 'lw-pill-info' : 'lw-pill-ok'}`,
              text: activeTool.requiresApproval ? '需本机逐参批准' : '免人工阻塞控制工具',
            }),
          ]),
          el('div', { class: 'lw-row' }, [
            makeIconButton({
              text: state.copiedTarget === activeTool.name ? '已复制契约' : '复制签名',
              iconName: 'copy',
              className: 'lw-btn lw-btn-sm',
              onClick: () => void copyTextToClipboard(activeTool.name, activeTool.name),
            }),
            el('label', { class: 'lw-row', style: 'cursor:pointer' }, [
              el('span', {
                class: `lw-pill ${activeTool.enabled ? 'lw-pill-ok' : 'lw-pill-err'}`,
                text: getSingleToolStatusLabel(state.snapshot, activeTool),
              }),
              el('span', { class: 'lw-switch-pill' }, [
                (() => {
                  const sw = el('input', {
                    type: 'checkbox',
                    class: 'lw-switch-input',
                    'data-tool-hero-switch': activeTool.name,
                    disabled: state.busy || (!parentOn && !activeTool.individuallyDisabled),
                    onChange: e => { void toggleSingleTool(activeTool, e.target.checked); },
                  });
                  sw.checked = Boolean(activeTool.enabled && !activeTool.individuallyDisabled);
                  return sw;
                })(),
                el('span', { class: 'lw-switch-track', 'aria-hidden': 'true' }),
              ]),
            ]),
          ]),
        ]),
        el('div', { class: 'lw-stack-md', style: 'gap:8px' }, [
          el('h3', { text: `${activeTool.title || activeTool.name}` }),
          el('p', { class: 'lw-muted', text: activeTool.description || '无附加描述' }),
          !activeTool.enabled && activeTool.disabledReason
            ? el('div', { class: 'lw-doc-callout is-warn', text: `当前不可用原因：${activeTool.disabledReason}` })
            : null,
          el('div', { class: 'lw-meta-chips' }, [
            ...(activeTool.scopes || []).map(sc => el('span', { class: 'lw-meta-chip' }, [
              el('span', { class: 'lw-meta-chip-k', text: 'scope' }),
              el('span', { class: 'lw-meta-chip-v', text: sc }),
            ])),
            el('span', { class: 'lw-meta-chip' }, [
              el('span', { class: 'lw-meta-chip-k', text: 'readOnlyHint' }),
              el('span', { class: 'lw-meta-chip-v', text: String(Boolean(activeTool.annotations?.readOnlyHint)) }),
            ]),
            el('span', { class: 'lw-meta-chip' }, [
              el('span', { class: 'lw-meta-chip-k', text: 'destructiveHint' }),
              el('span', { class: 'lw-meta-chip-v', text: String(Boolean(activeTool.annotations?.destructiveHint)) }),
            ]),
          ]),
        ]),
        el('section', { class: 'lw-section' }, [
          el('div', { class: 'lw-section-head' }, [
            el('div', {}, [
              el('h3', { text: '在线参数构建与 JSON-RPC 2.0 负载调试' }),
              el('p', { text: '实时修改参数自动组装 tools/call 请求体；所有真实执行须经由 OAuth 中继 → R1–R7/LLM 护栏 → 本机逐参批准。' }),
            ]),
            makeIconButton({
              text: state.copiedTarget === `rpc-${activeTool.name}` ? '已复制 JSON' : '复制 JSON-RPC',
              iconName: 'copy',
              className: 'lw-btn lw-btn-sm lw-btn-primary',
              onClick: () => void copyTextToClipboard(liveRpcPayload, `rpc-${activeTool.name}`),
            }),
          ]),
          el('div', { class: 'lw-form-grid' }, paramEditorNodes),
          el('pre', { class: 'lw-pre lw-mono', 'data-apifox-live-json': '1', text: liveRpcPayload }),
        ]),
        el('section', { class: 'lw-section' }, [
          el('div', { class: 'lw-section-head' }, [
            el('div', {}, [
              el('h3', { text: '输入参数 Schema' }),
              el('p', { text: '由沙箱定义或第三方 MCP tools/list 自动采集的结构化约束。' }),
            ]),
            el('span', { class: 'lw-pill', text: `${(activeTool.parameters || []).length} 个字段` }),
          ]),
          (activeTool.parameters || []).length
            ? el('div', { class: 'lw-table-wrap' }, [
                el('table', { class: 'lw-table' }, [
                  el('thead', {}, [el('tr', {}, [
                    el('th', { text: '字段名' }),
                    el('th', { text: '类型' }),
                    el('th', { text: '必填' }),
                    el('th', { text: '说明与范围限制' }),
                  ])]),
                  el('tbody', {}, activeTool.parameters.map(p => el('tr', {}, [
                    el('td', { class: 'lw-mono', text: p.name }),
                    el('td', { class: 'lw-mono', text: p.type }),
                    el('td', {}, [el('span', { class: `lw-pill ${p.required ? 'lw-pill-warn' : ''}`, text: p.required ? '必填' : '可选' })]),
                    el('td', {
                      class: 'lw-muted',
                      text: [
                        p.description || '-',
                        p.enumValues ? `枚举: ${p.enumValues.join(' | ')}` : '',
                        p.minimum !== null || p.maximum !== null ? `范围: ${p.minimum ?? '-∞'}..${p.maximum ?? '+∞'}` : '',
                      ].filter(Boolean).join(' · '),
                    }),
                  ]))),
                ]),
              ])
            : el('div', { class: 'lw-muted', text: '无入参字段。' }),
        ]),
        el('div', { class: 'lw-apifox-split-grid' }, [
          el('section', { class: 'lw-section' }, [
            el('h3', { text: '能力保证 (canDo)' }),
            (activeTool.canDo || []).length
              ? el('ul', { class: 'lw-bounds-list' }, activeTool.canDo.map(item => el('li', { text: item })))
              : el('div', { class: 'lw-muted', text: '由主机与沙箱定义默认契约。' }),
          ]),
          el('section', { class: 'lw-section' }, [
            el('h3', { text: '硬性安全边界 (limits)' }),
            (activeTool.limits || []).length
              ? el('ul', { class: 'lw-bounds-list' }, activeTool.limits.map(item => el('li', { text: item })))
              : el('div', { class: 'lw-muted', text: '遵循最小权限与 24h 防重放账本。' }),
          ]),
        ]),
        makeStatStrip([
          { icon: 'activity', label: '累计调用', value: `${totalCalls} 次` },
          { icon: 'check', label: '已批准执行', value: `${stats.approvedCount || 0} 次`, tone: 'ok' },
          { icon: 'alert', label: '护栏拦截', value: `${blockedCalls} 次 (${blockPct}%)`, tone: blockedCalls > 0 ? 'warn' : '' },
          { icon: 'clock', label: '待审排队', value: `${stats.pendingApprovalCount || 0} 次` },
        ]),
      ];
    }
  } else {
    const q = (state.toolSearch || '').trim().toLowerCase();
    const groups = ['all', '总览与状态', '安全策略', 'Agent 围栏', '第三方 MCP', 'LLM 审查', '本机审批'];
    groupChipsNode = el('div', { class: 'lw-apifox-chip-row' }, groups.map(g => el('button', {
      type: 'button',
      class: `lw-apifox-chip ${(state.toolFilter === g || (state.toolFilter === 'all' && g === 'all')) ? 'is-active' : ''}`,
      text: g === 'all' ? '全部' : g,
      onClick: () => { state.toolFilter = g; render(); },
    })));
    const visibleHttp = CONSOLE_HTTP_CONTRACTS.filter(ep => {
      if (state.toolFilter !== 'all' && groups.includes(state.toolFilter) && ep.group !== state.toolFilter) return false;
      if (!q) return true;
      return ep.path.toLowerCase().includes(q) || ep.title.toLowerCase().includes(q) || ep.summary.toLowerCase().includes(q);
    });
    const activeEp = visibleHttp.find(ep => ep.id === state.selectedHttpId) || visibleHttp[0] || CONSOLE_HTTP_CONTRACTS[0];
    if (activeEp && state.selectedHttpId !== activeEp.id) state.selectedHttpId = activeEp.id;

    {
      const grouped = new Map();
      for (const ep of visibleHttp) {
        if (!grouped.has(ep.group)) grouped.set(ep.group, []);
        grouped.get(ep.group).push(ep);
      }
      const list = [];
      for (const [grp, eps] of grouped.entries()) {
        list.push(el('div', { class: 'lw-apifox-group-label', text: grp }));
        for (const ep of eps) {
          list.push(el('button', {
            type: 'button',
            class: `lw-apifox-item ${activeEp.id === ep.id ? 'is-active' : ''}`,
            'data-apifox-item': ep.id,
            onClick: () => { state.selectedHttpId = ep.id; state.toolHttpTryResult = null; render(); },
          }, [
            el('span', { class: `lw-method-pill ${methodBadgeClass(ep.method)}`, text: ep.method }),
            el('span', { class: 'lw-apifox-item-text' }, [
              el('span', { class: 'lw-apifox-item-name', text: ep.path }),
              el('span', { class: 'lw-apifox-item-sub', text: ep.title }),
            ]),
          ]));
        }
      }
      leftItemsNode = list.length ? list : [el('div', { class: 'lw-muted', style: 'padding:14px', text: '无匹配控制面端点。' })];
    }

    const originUrl = window.location.origin;
    const sampleBodyStr = activeEp.method === 'POST' ? JSON.stringify(activeEp.bodyExample || {}, null, 2) : '';
    const curlSnippet = activeEp.method === 'GET'
      ? `curl -sS -H "X-LoomWard-Tab-Auth: <tabToken>" "${originUrl}${activeEp.path}"`
      : `curl -sS -X POST -H "Content-Type: application/json" -H "X-LoomWard-CSRF: <csrf>" -H "X-LoomWard-Tab-Auth: <tabToken>" -d '${JSON.stringify(activeEp.bodyExample || {})}' "${originUrl}${activeEp.path}"`;

    rightDetailNode = [
      el('div', { class: 'lw-apifox-sigbar' }, [
        el('div', { class: 'lw-row' }, [
          el('span', { class: `lw-method-pill ${methodBadgeClass(activeEp.method)}`, text: activeEp.method }),
          el('code', { class: 'lw-apifox-sigcode', text: activeEp.path }),
          el('span', { class: 'lw-pill lw-pill-info', text: 'Loopback + Tab Auth' }),
        ]),
        el('div', { class: 'lw-row' }, [
          makeIconButton({
            text: '复制 cURL',
            iconName: 'copy',
            className: 'lw-btn lw-btn-sm',
            onClick: () => void copyTextToClipboard(curlSnippet, `curl-${activeEp.id}`),
          }),
          activeEp.canTryGet
            ? makeIconButton({
                text: '发送实时 GET 探测',
                iconName: 'play',
                className: 'lw-btn lw-btn-sm lw-btn-primary',
                disabled: state.busy,
                onClick: () => runMutation(async () => {
                  const t0 = performance.now();
                  const data = await client.api(activeEp.path);
                  const ms = Math.round(performance.now() - t0);
                  state.toolHttpTryResult = { id: activeEp.id, ms, jsonText: JSON.stringify(data, null, 2) };
                }),
              })
            : null,
        ]),
      ]),
      el('div', { class: 'lw-stack-md', style: 'gap:8px' }, [
        el('h3', { text: activeEp.title }),
        el('p', { class: 'lw-muted', text: activeEp.summary }),
      ]),
      state.toolHttpTryResult && state.toolHttpTryResult.id === activeEp.id
        ? el('section', { class: 'lw-section' }, [
            el('div', { class: 'lw-section-head' }, [
              el('h3', { text: '实时探测响应 (Live 200 OK)' }),
              el('span', { class: 'lw-pill lw-pill-ok', text: `${state.toolHttpTryResult.ms} ms · 已脱敏` }),
            ]),
            el('pre', { class: 'lw-pre lw-mono', text: clipText(state.toolHttpTryResult.jsonText, 2400) }),
          ])
        : null,
      el('section', { class: 'lw-section' }, [
        el('h3', { text: '请求签名与示例载荷' }),
        el('pre', { class: 'lw-pre lw-mono', text: sampleBodyStr ? `${curlSnippet}\n\n# Request Body:\n${sampleBodyStr}` : curlSnippet }),
      ]),
      el('section', { class: 'lw-section' }, [
        el('h3', { text: '参数契约与安全约束' }),
        (activeEp.params || []).length
          ? el('div', { class: 'lw-table-wrap' }, [
              el('table', { class: 'lw-table' }, [
                el('thead', {}, [el('tr', {}, [el('th', { text: '字段名' }), el('th', { text: '类型' }), el('th', { text: '必填' }), el('th', { text: '说明' })])]),
                el('tbody', {}, activeEp.params.map(p => el('tr', {}, [
                  el('td', { class: 'lw-mono', text: p.name }),
                  el('td', { class: 'lw-mono', text: p.type }),
                  el('td', {}, [el('span', { class: `lw-pill ${p.required ? 'lw-pill-warn' : ''}`, text: p.required ? '必填' : '可选' })]),
                  el('td', { class: 'lw-muted', text: p.description }),
                ]))),
              ]),
            ])
          : el('div', { class: 'lw-muted', text: '无附加输入参数。' }),
        el('ul', { class: 'lw-bounds-list', style: 'margin-top:10px' }, (activeEp.bounds || []).map(b => el('li', { text: b }))),
      ]),
    ];
  }

  return el('div', { class: 'lw-stack-md' }, [
    makePageHeader('API 工作台', '检索工具和控制台接口，查看参数、权限与调试结果。'),
    makeStatStrip([
      { icon: 'code', label: 'MCP 工具总计', value: `${allTools.length} 项` },
      { icon: 'lock', label: 'Docker 沙箱接口', value: `${sandboxCount} 项`, tone: 'ok' },
      { icon: 'plug', label: '进程外 MCP 工具', value: `${externalCount} 项`, tone: externalCount > 0 ? 'warn' : '' },
      { icon: 'check', label: '当前开启可用', value: `${enabledCount} 项`, tone: enabledCount > 0 ? 'ok' : 'err' },
    ]),
    el('div', { class: 'lw-apifox-modebar' }, [
      makeSegmentedChoice({
        value: mode,
        options: [
          { value: 'mcp', label: `MCP 工具接口契约 (${allTools.length})`, icon: 'wrench' },
          { value: 'http', label: `控制台 HTTP API (${CONSOLE_HTTP_CONTRACTS.length})`, icon: 'server' },
        ],
        onSelect: nextMode => {
          state.toolCatalogMode = nextMode;
          state.toolFilter = 'all';
          render();
        },
      }),
      makeIconButton({
        text: '管理第三方 MCP 服务围栏 →',
        iconName: 'shield',
        className: 'lw-btn lw-btn-sm',
        onClick: () => navigate('fencing', { fencingTab: 'mcp' }),
      }),
    ]),
    el('div', { class: 'lw-apifox-shell' }, [
      el('div', { class: 'lw-apifox-catalog' }, [
        el('div', { class: 'lw-apifox-catalog-top' }, [
          el('div', { class: 'lw-search-wrap' }, [
            makeIcon('search'),
            searchInput,
          ]),
          groupChipsNode,
        ]),
        el('div', { class: 'lw-apifox-list' }, leftItemsNode),
      ]),
      el('div', { class: 'lw-apifox-detail' }, Array.isArray(rightDetailNode) ? rightDetailNode : [rightDetailNode]),
    ]),
  ]);
}

function splitLinesList(text) {
  return String(text || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean);
}

function splitCommaOrLineList(text) {
  return String(text || '').split(/[\r\n,，]+/).map(s => s.trim()).filter(Boolean);
}

function parseKeyValueEnvLines(text) {
  const out = {};
  for (const rawLine of String(text || '').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) throw new Error(`环境变量格式须为 KEY=VALUE（异常行：${line.slice(0, 40)}）`);
    const k = line.slice(0, eq).trim();
    const v = line.slice(eq + 1);
    out[k] = v;
  }
  return out;
}

function parseKeyValueHeaderLines(text) {
  const out = {};
  for (const rawLine of String(text || '').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const sep = line.includes(':') ? line.indexOf(':') : line.indexOf('=');
    if (sep <= 0) throw new Error(`HTTP Header 格式须为 Header-Name: value（异常行：${line.slice(0, 40)}）`);
    const k = line.slice(0, sep).trim();
    const v = line.slice(sep + 1).trim();
    out[k] = v;
  }
  return out;
}

function renderFencingAntileakTab() {
  const data = state.fencingData || {};
  const saved = data.config || {};
  if (!state.fencingDraft && saved) state.fencingDraft = structuredClone(saved);
  const draft = state.fencingDraft || saved || {};
  const cache = data.cache || { status: 'missing', privateCount: 0, patternCount: 0, ownerCount: 0, expiresInSeconds: 0, sources: [] };
  const rules = Array.isArray(data.rules) ? data.rules : [];

  const listEq = (a, b) => JSON.stringify(a || []) === JSON.stringify(b || []);
  const dirtyFields = new Set();
  if (!listEq(draft.forbiddenPatterns, saved.forbiddenPatterns)) dirtyFields.add('forbiddenPatterns');
  if (!listEq(draft.secretRegexes, saved.secretRegexes)) dirtyFields.add('secretRegexes');
  if (!listEq(draft.agentBranchPrefixes, saved.agentBranchPrefixes)) dirtyFields.add('agentBranchPrefixes');
  if (!listEq(draft.agentProviderEmails, saved.agentProviderEmails)) dirtyFields.add('agentProviderEmails');
  if (!listEq(draft.expectedOwners, saved.expectedOwners)) dirtyFields.add('expectedOwners');
  if (!listEq(draft.resolveIgnore, saved.resolveIgnore)) dirtyFields.add('resolveIgnore');
  if (!listEq(draft.exemptTools, saved.exemptTools)) dirtyFields.add('exemptTools');
  if (String(draft.agentSigningFingerprint || '') !== String(saved.agentSigningFingerprint || '')) dirtyFields.add('agentSigningFingerprint');
  if (String(draft.signingInstructions || '') !== String(saved.signingInstructions || '')) dirtyFields.add('signingInstructions');
  if (Number(draft.privateCacheTtl) !== Number(saved.privateCacheTtl)) dirtyFields.add('privateCacheTtl');
  if (Number(draft.resolveBudget) !== Number(saved.resolveBudget)) dirtyFields.add('resolveBudget');
  if (Boolean(draft.resignExempt) !== Boolean(saved.resignExempt)) dirtyFields.add('resignExempt');
  if (String(draft.cnbApi || '') !== String(saved.cnbApi || '')) dirtyFields.add('cnbApi');

  const cacheStatusLabel = cache.status === 'fresh'
    ? `有效 (余 ${Math.max(1, Math.round((cache.expiresInSeconds || 0) / 60))} 分钟)`
    : cache.status === 'stale' ? '已过期 (fail-closed)' : cache.status === 'corrupt' ? '损坏 (fail-closed)' : '未初始化 (fail-closed)';
  const cacheTone = cache.status === 'fresh' ? 'ok' : cache.status === 'missing' ? 'warn' : 'err';

  const antileakSvg = svgEl('svg', {
    viewBox: '0 0 356 320',
    class: 'lw-svg-diagram',
    role: 'img',
    'aria-label': 'R1-R7 离线防泄漏规则管线与 fail-closed 状态示意图',
  }, [
    svgEl('path', { d: 'M 178 66 L 178 90', class: 'lw-svg-wire lw-svg-wire-active' }),
    svgEl('path', { d: 'M 178 150 L 178 176', class: `lw-svg-wire ${cache.status === 'fresh' ? 'lw-svg-wire-active' : 'lw-svg-wire-warn'}` }),
    svgEl('path', { d: 'M 178 236 L 178 258', class: 'lw-svg-wire lw-svg-wire-active' }),
    svgNodeBox({
      x: 10, y: 10, w: 336, h: 56,
      title: '1. 调用入参 / Git 提交拦截入口',
      sub: `tool:invoke@1 (@before) · 豁免 ${(draft.exemptTools || []).length} 项控制工具`,
      badge: 'order: 10 优先于 LLM 审查',
      stateCls: 'is-active',
      badgeCls: 'is-muted',
      isDelta: dirtyFields.has('exemptTools'),
    }),
    svgNodeBox({
      x: 10, y: 90, w: 336, h: 60,
      title: '2. 静态正则与签名策略 (policy.json)',
      sub: `R2 模式:${(draft.forbiddenPatterns || []).length} · R7 凭据:${(draft.secretRegexes || []).length} · R5 分支:${(draft.agentBranchPrefixes || []).length}`,
      badge: draft.agentSigningFingerprint ? 'R6 独立 SSH 指纹已绑定' : 'R6 独立指纹待填写',
      stateCls: dirtyFields.size > 0 ? 'is-warn' : 'is-active',
      badgeCls: draft.agentSigningFingerprint ? 'is-ok' : 'is-warn',
      isDelta: dirtyFields.has('forbiddenPatterns') || dirtyFields.has('secretRegexes') || dirtyFields.has('agentSigningFingerprint') || dirtyFields.has('agentBranchPrefixes'),
    }),
    svgNodeBox({
      x: 10, y: 176, w: 336, h: 60,
      title: '3. 动态私有仓缓存核对 (private-repos.json)',
      sub: `私有名:${cache.privateCount} · R4 模式:${cache.patternCount} · Owners:${cache.ownerCount}`,
      badge: cache.status === 'fresh' ? '离线核对就绪 · 不联网不漏名' : '缓存缺失/过期 → 强制 ERROR 阻断',
      stateCls: cache.status === 'fresh' ? 'is-ok' : 'is-warn',
      badgeCls: cache.status === 'fresh' ? 'is-ok' : 'is-warn',
      isDelta: dirtyFields.has('expectedOwners') || dirtyFields.has('privateCacheTtl') || dirtyFields.has('resignExempt'),
    }),
    svgNodeBox({
      x: 10, y: 258, w: 336, h: 54,
      title: '4. 三态 fail-closed 裁决输出',
      sub: 'pass (放行) | violation (违规脱敏) | error (硬拦截)',
      badge: '超时或异常永不静默放行',
      stateCls: 'is-ok',
      badgeCls: 'is-ok',
    }),
  ]);

  const rulePreviewValue = ruleId => {
    if (ruleId === 'R1') return `Owners ${draft.expectedOwners?.length || 0} · 私有名 ${cache.privateCount || 0} · 预算 ${draft.resolveBudget ?? 30}`;
    if (ruleId === 'R2') return `${draft.forbiddenPatterns?.length || 0} 条敏感模式正则`;
    if (ruleId === 'R3') return 'Co-authored-by + Commit 规范';
    if (ruleId === 'R4') return `R4 模式 ${cache.patternCount || 0} 条 · 重签豁免 ${draft.resignExempt ? '开启' : '关闭'}`;
    if (ruleId === 'R5') return `${draft.agentBranchPrefixes?.length || 0} 个拦截前缀`;
    if (ruleId === 'R6') return draft.agentSigningFingerprint ? `指纹已绑定 · ${draft.agentProviderEmails?.length || 0} 类代理邮箱` : '未绑定独立指纹';
    if (ruleId === 'R7') return `${draft.secretRegexes?.length || 0} 条私钥与 Token 正则`;
    return '-';
  };

  const split = el('div', { class: 'lw-doc-split' }, [
    el('div', { class: 'lw-doc-main' }, [
      makeStatStrip([
        { icon: 'shield', label: '私有仓缓存姿态', value: cacheStatusLabel, tone: cacheTone },
        { icon: 'lock', label: '受护私有仓数量', value: `${cache.privateCount || 0} 个（只计数不透传）` },
        { icon: 'radar', label: 'R4 动态正则数', value: `${cache.patternCount || 0} 条` },
        { icon: 'sliders', label: '静态 R2 / R7 规则', value: `${(draft.forbiddenPatterns?.length || 0) + (draft.secretRegexes?.length || 0)} 条` },
      ]),
      el('section', { class: 'lw-section' }, [
        el('div', { class: 'lw-section-head' }, [
          el('div', {}, [
            el('h3', { text: '1. 离线 R1–R7 防泄漏规则全矩阵' }),
            el('p', { text: '基于独立 Python 子进程（check.py）执行三态 fail-closed 检查；缓存缺失或脚本超时时绝不静默放行。' }),
          ]),
          el('span', { class: 'lw-pill lw-pill-info', text: 'out-of-process · offline' }),
        ]),
        el('div', { class: 'lw-table-wrap' }, [
          el('table', { class: 'lw-table' }, [
            el('thead', {}, [el('tr', {}, [
              el('th', { text: '规则' }),
              el('th', { text: '拦截时机' }),
              el('th', { text: '当前绑定状态' }),
              el('th', { text: '守卫职责' }),
            ])]),
            el('tbody', {}, rules.map(r => el('tr', {}, [
              el('td', {}, [el('strong', { class: 'lw-mono', text: r.id }), el('div', { class: 'lw-muted', text: r.name })]),
              el('td', {}, [el('span', { class: 'lw-pill', text: r.stage })]),
              el('td', { class: 'lw-mono', text: rulePreviewValue(r.id) }),
              el('td', { class: 'lw-muted', text: r.summary }),
            ]))),
          ]),
        ]),
      ]),
      el('section', { class: 'lw-section' }, [
        el('div', { class: 'lw-section-head' }, [
          el('div', {}, [
            el('h3', { text: '2. 编辑防泄漏围栏策略（<stateDir>/antileak/policy.json）' }),
            el('p', { text: '保存前自动调用 Python re.compile 验证正则语法，并以 0600 权限保存在挂载工作区之外。' }),
          ]),
          dirtyFields.size > 0
            ? el('span', { class: 'lw-delta-tag', text: `${dirtyFields.size} 项未保存更改` })
            : el('span', { class: 'lw-pill lw-pill-ok', text: data.exists ? '已持久化 0600' : '默认模板' }),
        ]),
        el('div', { class: 'lw-form-grid' }, [
          makeField(
            'R2 敏感词与硬件/内部术语正则（forbiddenPatterns，每行 1 条）',
            el('textarea', {
              class: `lw-textarea-mono ${dirtyFields.has('forbiddenPatterns') ? 'is-delta' : ''}`,
              value: (draft.forbiddenPatterns || []).join('\n'),
              placeholder: '例如：\n\\bINTERNAL_PROJ_[A-Z0-9]+\\b',
              onInput: e => { draft.forbiddenPatterns = splitLinesList(e.target.value); render(); },
            }),
          ),
          makeField(
            'R7 凭据与私钥硬拦截正则（secretRegexes，每行 1 条）',
            el('textarea', {
              class: `lw-textarea-mono ${dirtyFields.has('secretRegexes') ? 'is-delta' : ''}`,
              value: (draft.secretRegexes || []).join('\n'),
              placeholder: '-----BEGIN ... PRIVATE KEY-----',
              onInput: e => { draft.secretRegexes = splitLinesList(e.target.value); render(); },
            }),
          ),
          makeField(
            'R5 禁止推送的 Agent 分支前缀（agentBranchPrefixes，每行 1 个）',
            el('textarea', {
              class: `lw-textarea-mono ${dirtyFields.has('agentBranchPrefixes') ? 'is-delta' : ''}`,
              value: (draft.agentBranchPrefixes || []).join('\n'),
              placeholder: 'claude/\ncodex/\nchatgpt/',
              onInput: e => { draft.agentBranchPrefixes = splitLinesList(e.target.value); render(); },
            }),
          ),
          makeField(
            'R6 Agent 提供商邮箱特征（agentProviderEmails）与 R1 归属 Owners',
            el('div', { class: 'lw-stack-md', style: 'gap:8px' }, [
              el('input', {
                type: 'text',
                class: `lw-input lw-mono ${dirtyFields.has('expectedOwners') ? 'is-delta' : ''}`,
                value: (draft.expectedOwners || []).join(', '),
                placeholder: 'expectedOwners 逗号分隔（如 cybernova, your-org）',
                onInput: e => { draft.expectedOwners = splitCommaOrLineList(e.target.value); render(); },
              }),
              el('input', {
                type: 'text',
                class: `lw-input lw-mono ${dirtyFields.has('agentProviderEmails') ? 'is-delta' : ''}`,
                value: (draft.agentProviderEmails || []).join(', '),
                placeholder: 'agentProviderEmails（如 noreply@anthropic.com）',
                onInput: e => { draft.agentProviderEmails = splitCommaOrLineList(e.target.value); render(); },
              }),
            ]),
          ),
          makeField(
            'R6 独立 Agent SSH 签名指纹（agentSigningFingerprint）',
            el('input', {
              type: 'text',
              class: `lw-input lw-mono ${dirtyFields.has('agentSigningFingerprint') ? 'is-delta' : ''}`,
              value: draft.agentSigningFingerprint || '',
              placeholder: 'SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
              onInput: e => { draft.agentSigningFingerprint = e.target.value; render(); },
            }),
          ),
          makeField(
            '控制类工具豁免名单（exemptTools，逗号分隔）',
            el('input', {
              type: 'text',
              class: `lw-input lw-mono ${dirtyFields.has('exemptTools') ? 'is-delta' : ''}`,
              value: (draft.exemptTools || []).join(', '),
              placeholder: 'computer_context, command_status, stop_command',
              onInput: e => { draft.exemptTools = splitCommaOrLineList(e.target.value); render(); },
            }),
          ),
          makeField(
            '私有仓缓存有效期 (秒, 300–86400)',
            el('input', {
              type: 'number',
              min: '300',
              max: '86400',
              class: `lw-input lw-mono ${dirtyFields.has('privateCacheTtl') ? 'is-delta' : ''}`,
              value: String(draft.privateCacheTtl ?? 28800),
              onInput: e => { draft.privateCacheTtl = Number(e.target.value) || 28800; render(); },
            }),
          ),
          makeField(
            'R1 未知短横裸名补查预算 (0–200)',
            el('input', {
              type: 'number',
              min: '0',
              max: '200',
              class: `lw-input lw-mono ${dirtyFields.has('resolveBudget') ? 'is-delta' : ''}`,
              value: String(draft.resolveBudget ?? 30),
              onInput: e => { draft.resolveBudget = Number(e.target.value) || 0; render(); },
            }),
          ),
        ]),
        makeSwitchCard({
          checked: Boolean(draft.resignExempt),
          isDelta: dirtyFields.has('resignExempt'),
          iconName: 'shieldCheck',
          title: '启用 R4 Push 同内容重签 patch-id 豁免（resignExempt）',
          subtitle: '待推提交的 patch-id 若逐字节等于远端已有提交（仅重签/rebase），跳过新增行重扫；消息、作者邮箱与 SSH 签名指纹仍照常检查。',
          pillText: draft.resignExempt ? '已开启豁免' : '全量严格扫描',
          pillTone: draft.resignExempt ? 'ok' : 'info',
          onChange: v => { draft.resignExempt = v; render(); },
        }),
        el('div', { class: 'lw-btn-group', style: 'margin-top:12px' }, [
          makeIconButton({
            text: dirtyFields.size > 0 ? `保存 R1–R7 围栏策略 (${dirtyFields.size} 项)` : '保存 R1–R7 围栏策略',
            iconName: 'check',
            className: `lw-btn ${dirtyFields.size > 0 ? 'lw-btn-primary' : ''}`,
            disabled: state.busy,
            onClick: () => runMutation(async () => {
              const res = await client.api('/api/fencing/config', { method: 'POST', body: { config: draft } });
              state.fencingData = res;
              state.fencingDraft = structuredClone(res.config);
              setNotice('R1–R7 防泄漏围栏策略已原子写入 0600 policy.json。');
            }),
          }),
          makeIconButton({
            text: '还原已保存草稿',
            iconName: 'rotateCcw',
            className: 'lw-btn',
            disabled: state.busy || dirtyFields.size === 0,
            onClick: () => { state.fencingDraft = structuredClone(saved); render(); },
          }),
        ]),
      ]),
      el('section', { class: 'lw-section' }, [
        el('div', { class: 'lw-section-head' }, [
          el('div', {}, [
            el('h3', { text: '3. 离线 Dry-Run 拦截试验与缓存自检工具' }),
            el('p', { text: '粘贴合成样本离线跑一遍 check.py content（不传 --net），或手动刷新私有仓缓存、执行 doctor.py 自检。' }),
          ]),
        ]),
        makeField(
          '离线试验载荷文本（仅传至本机 check.py stdin）',
          el('textarea', {
            class: 'lw-textarea-mono',
            value: state.fencingDryText,
            placeholder: '在此粘贴待测试代码片段、Commit 文本或脱敏正则测试字符串...',
            onInput: e => { state.fencingDryText = e.target.value; },
          }),
          { fullWidth: true },
        ),
        el('div', { class: 'lw-btn-group' }, [
          makeIconButton({
            text: '离线执行规则检测 (check.py)',
            iconName: 'play',
            className: 'lw-btn lw-btn-primary',
            disabled: state.busy,
            onClick: () => runMutation(async () => {
              const res = await client.api('/api/fencing/test', {
                method: 'POST',
                body: { text: state.fencingDryText || '' },
              });
              state.fencingDryResult = res.result;
              if (res.result?.cache && state.fencingData) state.fencingData.cache = res.result.cache;
              setNotice(`离线规则检验完成：${res.result?.decision} (${res.result?.durationMs ?? 0}ms)`);
            }),
          }),
          makeIconButton({
            text: '刷新私有仓缓存 (refresh-private.py)',
            iconName: 'refresh',
            className: 'lw-btn',
            disabled: state.busy,
            onClick: () => runMutation(async () => {
              const res = await client.api('/api/fencing/refresh', { method: 'POST', body: {} });
              state.fencingRefreshResult = res.result;
              if (res.result?.cache && state.fencingData) state.fencingData.cache = res.result.cache;
              setNotice(res.result?.ok ? '私有仓缓存已刷新。' : '私有仓缓存刷新未通过完整性校验（保持原保护姿态）。');
            }),
          }),
          makeIconButton({
            text: '运行引擎自检 (doctor.py)',
            iconName: 'shieldCheck',
            className: 'lw-btn',
            disabled: state.busy,
            onClick: () => runMutation(async () => {
              const res = await client.api('/api/fencing/doctor', { method: 'POST', body: {} });
              state.fencingDoctorResult = res.result;
              setNotice(`围栏自检完成：${res.result?.summaryLine || ''}`);
            }),
          }),
        ]),
        state.fencingDryResult
          ? el('div', {
              class: `lw-doc-callout ${state.fencingDryResult.decision === 'pass' ? 'is-ok' : state.fencingDryResult.decision === 'violation' ? 'is-err' : 'is-warn'}`,
            }, [
              el('strong', {
                text: `裁决：${state.fencingDryResult.decision.toUpperCase()} (${state.fencingDryResult.durationMs} ms · ${state.fencingDryResult.bytesInspected} B)`,
              }),
              state.fencingDryResult.findings?.length
                ? el('div', { class: 'lw-mono', style: 'margin-top:6px', text: state.fencingDryResult.findings.join('\n') })
                : el('div', { class: 'lw-muted', style: 'margin-top:4px', text: '未触发任何 R1/R2/R4/R7 规则告警。' }),
            ])
          : null,
        state.fencingRefreshResult
          ? el('div', {
              class: `lw-doc-callout ${state.fencingRefreshResult.ok ? 'is-ok' : 'is-warn'}`,
              text: `缓存刷新输出 (${state.fencingRefreshResult.durationMs}ms)：${state.fencingRefreshResult.message}`,
            })
          : null,
        state.fencingDoctorResult
          ? el('div', { class: 'lw-aside-list', style: 'margin-top:10px' }, (state.fencingDoctorResult.checks || []).map(chk => el('div', { class: 'lw-doctor-row' }, [
              el('span', { class: `lw-pill ${chk.level === 'pass' ? 'lw-pill-ok' : chk.level === 'fail' ? 'lw-pill-err' : 'lw-pill-warn'}`, text: chk.level.toUpperCase() }),
              el('span', { class: 'lw-mono', style: 'min-width:0;word-break:break-word', text: chk.message }),
            ])))
          : null,
      ]),
    ]),
    el('aside', { class: 'lw-doc-aside' }, [
      el('div', { class: 'lw-section-head' }, [
        el('div', {}, [
          el('h3', { text: '离线 Fail-Closed 拦截管线' }),
          el('p', { text: '实时对照已持久化策略与本机私有缓存' }),
        ]),
        el('span', { class: `lw-pill lw-pill-${cacheTone}`, text: cache.status }),
      ]),
      antileakSvg,
      el('div', { class: 'lw-aside-list' }, [
        el('div', { class: 'lw-aside-row' }, [
          el('span', { class: 'lw-muted', text: '策略文件状态' }),
          el('strong', { text: data.exists ? '<stateDir>/antileak/policy.json (0600)' : '引擎内置默认模板' }),
        ]),
        el('div', { class: 'lw-aside-row' }, [
          el('span', { class: 'lw-muted', text: '缓存来源标签' }),
          el('strong', { text: cache.sources?.length ? cache.sources.join(', ') : '尚无来源（需本机种子或令牌）' }),
        ]),
        el('div', { class: `lw-aside-row ${dirtyFields.size > 0 ? 'is-delta' : ''}` }, [
          el('span', { class: 'lw-muted', text: '待保存草稿差异' }),
          el('strong', { text: dirtyFields.size > 0 ? `${dirtyFields.size} 项将在保存后生效` : '与磁盘一致' }),
        ]),
      ]),
    ]),
  ]);

  return split;
}

function renderFencingMcpTab() {
  const mcp = state.snapshot?.mcpServers || {
    serverCount: 0,
    enabledServerCount: 0,
    totalToolCount: 0,
    enabledToolCount: 0,
    items: [],
  };
  const d = state.mcpDraft;

  const resetMcpForm = () => {
    state.mcpDraft = {
      editingId: '',
      id: '',
      name: '',
      description: '',
      transport: 'stdio',
      command: '',
      argsText: '',
      cwd: '',
      url: '',
      timeoutMs: '30000',
      envText: '',
      removeEnvKeysText: '',
      headersText: '',
      removeHeaderKeysText: '',
      replaceSecrets: false,
      enabled: true,
      probe: true,
    };
    render();
  };

  const mcpSvg = svgEl('svg', {
    viewBox: '0 0 356 262',
    class: 'lw-svg-diagram',
    role: 'img',
    'aria-label': '第三方 MCP 接入安全围栏与人工逐参批准拓扑图',
  }, [
    svgEl('path', { d: 'M 178 66 L 178 92', class: 'lw-svg-wire lw-svg-wire-active' }),
    svgEl('path', { d: 'M 178 152 L 178 180', class: 'lw-svg-wire lw-svg-wire-warn' }),
    svgNodeBox({
      x: 10, y: 10, w: 336, h: 56,
      title: '1. 本机 MCP Registry + 有界探测门控',
      sub: `0600 mcp-servers.json · 已纳管 ${mcp.serverCount} 台 · 工具 ${mcp.totalToolCount}`,
      badge: '自动剥除 LD_PRELOAD / AGENTDOCK_* 等危险 env',
      stateCls: 'is-active',
      badgeCls: 'is-ok',
    }),
    svgNodeBox({
      x: 10, y: 92, w: 336, h: 60,
      title: '2. 逐参审批 + R1–R7/LLM 双重护栏',
      sub: 'tools/call 参数全量进入 policyDigest 复核',
      badge: '不支持免审直调 · 24h 单次防重放',
      stateCls: 'is-active',
      badgeCls: 'is-info',
    }),
    svgNodeBox({
      x: 10, y: 180, w: 336, h: 68,
      title: '3. 进程外第三方 MCP 服务（沙盒外）',
      sub: `${mcp.enabledServerCount} 台启用中 · 支持 stdio 子进程 / Streamable HTTP`,
      badge: '注意：外部端点不受 Linux Docker 容器只读保护',
      stateCls: mcp.enabledServerCount > 0 ? 'is-warn' : 'is-off',
      badgeCls: 'is-warn',
    }),
  ]);

  const handleSaveServer = () => runMutation(async () => {
    const id = d.id.trim();
    const timeoutMs = Number(d.timeoutMs) || 30000;
    const payload = {
      id,
      name: d.name.trim() || id,
      description: d.description.trim(),
      transport: d.transport,
      enabled: Boolean(d.enabled),
      timeoutMs,
      probe: Boolean(d.probe),
      replaceSecrets: Boolean(d.replaceSecrets),
    };
    if (d.transport === 'stdio') {
      payload.command = d.command.trim();
      payload.args = splitLinesList(d.argsText);
      if (d.cwd.trim()) payload.cwd = d.cwd.trim();
      if (d.envText.trim()) payload.env = parseKeyValueEnvLines(d.envText);
      const rmEnv = splitCommaOrLineList(d.removeEnvKeysText);
      if (rmEnv.length) payload.removeEnvKeys = rmEnv;
    } else {
      payload.url = d.url.trim();
      if (d.headersText.trim()) payload.headers = parseKeyValueHeaderLines(d.headersText);
      const rmHeaders = splitCommaOrLineList(d.removeHeaderKeysText);
      if (rmHeaders.length) payload.removeHeaderKeys = rmHeaders;
    }
    const res = await client.api('/api/mcp-servers/save', { method: 'POST', body: payload });
    if (res.snapshot) state.snapshot = res.snapshot;
    resetMcpForm();
    const probedCount = res.probe?.toolCount ?? res.server?.toolCount ?? (Array.isArray(res.probe?.tools) ? res.probe.tools.length : 0);
    const probeMsg = res.probe
      ? (res.probe.ok ? `探测成功，已收录 ${probedCount} 个工具。` : `保存成功，但探测告警：${res.probe.error || '失败'}`)
      : '配置已安全保存（0600）。';
    setNotice(`第三方 MCP「${id}」：${probeMsg}`);
  });

  const handleImportJson = () => runMutation(async () => {
    const raw = (state.mcpImportJson || '').trim();
    if (!raw) throw new Error('请先粘贴标准 mcpServers JSON 配置。');
    const res = await client.api('/api/mcp-servers/import', {
      method: 'POST',
      body: { json: raw, probe: Boolean(state.mcpImportProbe) },
    });
    if (res.snapshot) state.snapshot = res.snapshot;
    state.mcpImportJson = '';
    setNotice(`已导入 ${(res.importedIds || []).length} 个第三方 MCP 服务。`);
  });

  return el('div', { class: 'lw-doc-split' }, [
    el('div', { class: 'lw-doc-main' }, [
      makeStatStrip([
        { icon: 'plug', label: '已纳管 MCP 服务', value: `${mcp.serverCount} 台` },
        { icon: 'check', label: '当前启用服务', value: `${mcp.enabledServerCount} 台`, tone: mcp.enabledServerCount > 0 ? 'ok' : '' },
        { icon: 'code', label: '已发现外部工具', value: `${mcp.totalToolCount} 项` },
        { icon: 'shieldCheck', label: '允许调用工具数', value: `${mcp.enabledToolCount} 项`, tone: mcp.enabledToolCount > 0 ? 'warn' : '' },
      ]),
      el('div', { class: 'lw-doc-callout is-warn', text: '安全边界声明：第三方 MCP 服务在 Docker 沙盒外执行（stdio 子进程或外部 Streamable HTTP）；写入的 env/headers 凭据采用只写模型（保存后永不回显），每次调用仍需本机人工逐参批准。' }),
      el('section', { class: 'lw-section' }, [
        el('div', { class: 'lw-section-head' }, [
          el('div', {}, [
            el('h3', { text: d.editingId ? `1. 编辑第三方 MCP 服务（${d.editingId}）` : '1. 新增第三方 MCP 服务接入' }),
            el('p', { text: '支持本机 stdio 子进程与 Streamable HTTP（HTTPS/loopback）；修改命令或 Origin 时需勾选“清空并重置旧凭据”。' }),
          ]),
          d.editingId
            ? el('button', { type: 'button', class: 'lw-btn lw-btn-sm', text: '取消编辑 / 切回新增', onClick: resetMcpForm })
            : null,
        ]),
        makeField('传输协议 (transport)', makeSegmentedChoice({
          value: d.transport,
          options: [
            { value: 'stdio', label: '本机 stdio 子进程', icon: 'terminal' },
            { value: 'http', label: 'Streamable HTTP 端点', icon: 'globe' },
          ],
          onSelect: v => { d.transport = v; render(); },
        })),
        el('div', { class: 'lw-form-grid' }, [
          makeField('服务唯一 ID（小写字母/数字/-，1–32 字符）', el('input', {
            type: 'text',
            class: 'lw-input lw-mono',
            disabled: Boolean(d.editingId),
            value: d.id,
            placeholder: '例如: github_docs',
            onInput: e => { d.id = e.target.value; },
          })),
          makeField('显示名称', el('input', {
            type: 'text',
            class: 'lw-input',
            value: d.name,
            placeholder: 'GitHub Docs MCP',
            onInput: e => { d.name = e.target.value; },
          })),
          ...(d.transport === 'stdio'
            ? [
                makeField('启动命令 (command)', el('input', {
                  type: 'text',
                  class: 'lw-input lw-mono',
                  value: d.command,
                  placeholder: 'npx 或 /usr/bin/node',
                  onInput: e => { d.command = e.target.value; },
                })),
                makeField('工作目录 cwd（可选，须在工作区/状态目录白名单内）', el('input', {
                  type: 'text',
                  class: 'lw-input lw-mono',
                  value: d.cwd,
                  placeholder: '留空使用连接器默认 cwd',
                  onInput: e => { d.cwd = e.target.value; },
                })),
                makeField('命令参数 args（每行 1 个参数）', el('textarea', {
                  class: 'lw-textarea-mono',
                  value: d.argsText,
                  placeholder: '-y\n@modelcontextprotocol/server-everything',
                  onInput: e => { d.argsText = e.target.value; },
                })),
                makeField('只写环境变量 env（每行 KEY=VALUE，留空保留已存键）', el('textarea', {
                  class: 'lw-textarea-mono',
                  value: d.envText,
                  placeholder: 'API_KEY=输入新值即加密覆盖',
                  onInput: e => { d.envText = e.target.value; },
                })),
              ]
            : [
                makeField('Streamable HTTP 端点 URL（HTTPS 或回环地址）', el('input', {
                  type: 'url',
                  class: 'lw-input lw-mono',
                  value: d.url,
                  placeholder: 'https://mcp.example.com/mcp',
                  onInput: e => { d.url = e.target.value; },
                }), { fullWidth: true }),
                makeField('只写请求头 headers（每行 Name: Value，如 Authorization: Bearer ...）', el('textarea', {
                  class: 'lw-textarea-mono',
                  value: d.headersText,
                  placeholder: 'Authorization: Bearer your-token',
                  onInput: e => { d.headersText = e.target.value; },
                }), { fullWidth: true }),
              ]),
          makeField('超时上限 timeoutMs (3000–100000)', el('input', {
            type: 'number',
            min: '3000',
            max: '100000',
            class: 'lw-input lw-mono',
            value: d.timeoutMs,
            onInput: e => { d.timeoutMs = e.target.value; },
          })),
          makeField(d.transport === 'stdio' ? '删除已存 env 键名（逗号分隔）' : '删除已存 Header 键名（逗号分隔）', el('input', {
            type: 'text',
            class: 'lw-input lw-mono',
            value: d.transport === 'stdio' ? d.removeEnvKeysText : d.removeHeaderKeysText,
            placeholder: 'KEY1, KEY2',
            onInput: e => {
              if (d.transport === 'stdio') d.removeEnvKeysText = e.target.value;
              else d.removeHeaderKeysText = e.target.value;
            },
          })),
        ]),
        el('div', { class: 'lw-setting-list', style: 'margin-top:10px' }, [
          makeSwitchCard({
            checked: Boolean(d.enabled),
            iconName: 'plug',
            title: '启用该第三方 MCP 服务',
            subtitle: '关闭后所有衍生 mcp__<id>__* 工具从模型可见列表中瞬时熔断下线。',
            pillText: d.enabled ? '启用' : '停用',
            pillTone: d.enabled ? 'ok' : 'info',
            onChange: v => { d.enabled = v; render(); },
          }),
          makeSwitchCard({
            checked: Boolean(d.probe),
            iconName: 'radar',
            title: '保存后立即运行有界握手探测并同步工具清单',
            subtitle: '触发 initialize + tools/list（受 409 同 ID 互斥与 429 全局并发守卫）。',
            pillText: d.probe ? '自动探测' : '仅保存',
            pillTone: 'info',
            onChange: v => { d.probe = v; render(); },
          }),
          d.editingId
            ? makeSwitchCard({
                checked: Boolean(d.replaceSecrets),
                iconName: 'key',
                title: '改换命令/端点时显式清空并重设旧凭据 (replaceSecrets)',
                subtitle: '防误变更命令或 HTTP Origin 导致旧密钥泄漏至新目标（security guard）。',
                pillText: d.replaceSecrets ? '允许重置' : '保护保留',
                pillTone: d.replaceSecrets ? 'warn' : 'info',
                onChange: v => { d.replaceSecrets = v; render(); },
              })
            : null,
        ]),
        el('div', { class: 'lw-btn-group', style: 'margin-top:12px' }, [
          makeIconButton({
            text: d.editingId ? '更新 MCP 服务配置' : '保存并接入 MCP 服务',
            iconName: 'check',
            className: 'lw-btn lw-btn-primary',
            disabled: state.busy,
            onClick: handleSaveServer,
          }),
        ]),
      ]),
      el('section', { class: 'lw-section' }, [
        el('div', { class: 'lw-section-head' }, [
          el('div', {}, [
            el('h3', { text: '2. 标准 mcpServers JSON 批量导入' }),
            el('p', { text: '粘贴桌面端/CLI 的 { "mcpServers": { ... } } JSON，一键导入并按并发预算批量探测工具。' }),
          ]),
        ]),
        el('textarea', {
          class: 'lw-textarea-mono',
          value: state.mcpImportJson,
          placeholder: '{\n  "mcpServers": {\n    "filesystem": { "command": "npx", "args": ["-y", "@example/mcp"] }\n  }\n}',
          onInput: e => { state.mcpImportJson = e.target.value; },
        }),
        el('div', { class: 'lw-row lw-between', style: 'margin-top:8px' }, [
          el('label', { class: 'lw-row', style: 'cursor:pointer' }, [
            (() => {
              const cb = el('input', {
                type: 'checkbox',
                onChange: e => { state.mcpImportProbe = e.target.checked; },
              });
              cb.checked = Boolean(state.mcpImportProbe);
              return cb;
            })(),
            el('span', { class: 'lw-muted', text: '导入后自动逐台探测可用工具清单' }),
          ]),
          makeIconButton({
            text: '执行 JSON 批量导入',
            iconName: 'download',
            className: 'lw-btn lw-btn-sm',
            disabled: state.busy,
            onClick: handleImportJson,
          }),
        ]),
      ]),
      el('section', { class: 'lw-section' }, [
        el('div', { class: 'lw-section-head' }, [
          el('div', {}, [
            el('h3', { text: '3. 已纳管第三方 MCP 服务台账' }),
            el('p', { text: '逐服务控制启停、展开独立外部工具开关并直达 APIFox 查看调用契约。' }),
          ]),
          el('span', { class: 'lw-pill', text: `${mcp.items.length} 台` }),
        ]),
        mcp.items.length
          ? el('div', {}, mcp.items.map(srv => {
              const expanded = Boolean(state.mcpExpandedTools[srv.id]);
              const deleting = state.mcpDeleteConfirmId === srv.id;
              return el('div', { class: 'lw-mcp-server-row', 'data-mcp-server-id': srv.id }, [
                el('div', { class: 'lw-mcp-server-top' }, [
                  el('div', { class: 'lw-stack-md', style: 'gap:4px' }, [
                    el('div', { class: 'lw-row' }, [
                      el('span', { class: `lw-method-pill ${srv.transport === 'http' ? 'is-info' : 'is-mcp'}`, text: srv.transport.toUpperCase() }),
                      el('strong', { class: 'lw-mono', text: srv.id }),
                      el('span', { text: `· ${srv.name}` }),
                      el('span', {
                        class: `lw-pill ${srv.lastProbeOk === true ? 'lw-pill-ok' : srv.lastProbeOk === false ? 'lw-pill-err' : ''}`,
                        text: srv.lastProbeOk === true ? `探测正常 (${srv.toolCount} 工具)` : srv.lastProbeOk === false ? '最近探测异常' : '尚未探测',
                      }),
                    ]),
                    el('div', { class: 'lw-muted lw-mono', text: srv.transport === 'stdio' ? `${srv.command} ${(srv.args || []).join(' ')}` : (srv.url || '-') }),
                    srv.lastProbeError
                      ? el('div', { class: 'lw-muted', style: 'color:var(--err)', text: `探测摘要（已脱敏）：${srv.lastProbeError}` })
                      : null,
                    srv.hasSecrets
                      ? el('div', { class: 'lw-meta-chips' }, [
                          ...(srv.envKeys || []).map(k => el('span', { class: 'lw-meta-chip' }, [
                            el('span', { class: 'lw-meta-chip-k', text: 'env' }),
                            el('span', { class: 'lw-meta-chip-v', text: k }),
                          ])),
                          ...(srv.headerKeys || []).map(k => el('span', { class: 'lw-meta-chip' }, [
                            el('span', { class: 'lw-meta-chip-k', text: 'hdr' }),
                            el('span', { class: 'lw-meta-chip-v', text: k }),
                          ])),
                        ])
                      : null,
                  ]),
                  el('div', { class: 'lw-btn-group' }, [
                    makeIconButton({
                      text: '探测工具',
                      iconName: 'radar',
                      className: 'lw-btn lw-btn-sm',
                      disabled: state.busy,
                      onClick: () => runMutation(async () => {
                        const res = await client.api('/api/mcp-servers/probe', { method: 'POST', body: { id: srv.id } });
                        if (res.snapshot) state.snapshot = res.snapshot;
                        setNotice(res.probe?.ok ? `「${srv.id}」探测完成，共 ${res.probe.toolCount ?? 0} 个工具。` : `「${srv.id}」探测异常：${res.probe?.error || '未知错误'}`);
                      }),
                    }),
                    makeIconButton({
                      text: expanded ? `收起工具 (${srv.tools.length})` : `外部工具 (${srv.tools.length})`,
                      iconName: 'wrench',
                      className: 'lw-btn lw-btn-sm',
                      onClick: () => { state.mcpExpandedTools[srv.id] = !expanded; render(); },
                    }),
                    makeIconButton({
                      text: srv.enabled ? '停用' : '启用',
                      iconName: srv.enabled ? 'stop' : 'play',
                      className: 'lw-btn lw-btn-sm',
                      disabled: state.busy,
                      onClick: () => runMutation(async () => {
                        const res = await client.api('/api/mcp-servers/toggle', { method: 'POST', body: { id: srv.id, enabled: !srv.enabled } });
                        if (res.snapshot) state.snapshot = res.snapshot;
                        setNotice(`服务 ${srv.id} 已${srv.enabled ? '停用' : '启用'}。`);
                      }),
                    }),
                    makeIconButton({
                      text: '编辑',
                      iconName: 'sliders',
                      className: 'lw-btn lw-btn-sm',
                      onClick: () => {
                        state.mcpDraft = {
                          editingId: srv.id,
                          id: srv.id,
                          name: srv.name,
                          description: srv.description || '',
                          transport: srv.transport,
                          command: srv.command || '',
                          argsText: (srv.args || []).join('\n'),
                          cwd: srv.cwd || '',
                          url: srv.url || '',
                          timeoutMs: String(srv.timeoutMs || 30000),
                          envText: '',
                          removeEnvKeysText: '',
                          headersText: '',
                          removeHeaderKeysText: '',
                          replaceSecrets: false,
                          enabled: Boolean(srv.enabled),
                          probe: true,
                        };
                        render();
                      },
                    }),
                    deleting
                      ? el('span', { class: 'lw-row' }, [
                          makeIconButton({
                            text: '确认移除',
                            iconName: 'trash',
                            className: 'lw-btn lw-btn-sm lw-btn-danger',
                            disabled: state.busy,
                            onClick: () => runMutation(async () => {
                              const res = await client.api('/api/mcp-servers/delete', { method: 'POST', body: { id: srv.id } });
                              state.mcpDeleteConfirmId = '';
                              if (res.snapshot) state.snapshot = res.snapshot;
                              setNotice(`已安全删除第三方 MCP「${srv.id}」及其密文环境配置。`);
                            }),
                          }),
                          el('button', { type: 'button', class: 'lw-btn lw-btn-sm', text: '取消', onClick: () => { state.mcpDeleteConfirmId = ''; render(); } }),
                        ])
                      : makeIconButton({
                          text: '移除',
                          iconName: 'trash',
                          className: 'lw-btn lw-btn-sm',
                          onClick: () => { state.mcpDeleteConfirmId = srv.id; render(); },
                        }),
                  ]),
                ]),
                expanded
                  ? el('div', { class: 'lw-mcp-tools-drawer' }, srv.tools.length
                      ? srv.tools.map(t => el('div', { class: 'lw-aside-row' }, [
                          el('div', { style: 'min-width:0;flex:1' }, [
                            el('div', { class: 'lw-mono lw-switch-label', text: t.fullName }),
                            el('div', { class: 'lw-switch-sub', text: t.description || t.name }),
                          ]),
                          el('div', { class: 'lw-row' }, [
                            el('button', {
                              type: 'button',
                              class: 'lw-btn lw-btn-sm',
                              text: 'APIFox 契约 →',
                              onClick: () => navigate('tools', { selectedToolName: t.fullName }),
                            }),
                            el('label', { class: 'lw-switch-pill' }, [
                              (() => {
                                const cb = el('input', {
                                  type: 'checkbox',
                                  class: 'lw-switch-input',
                                  disabled: state.busy,
                                  onChange: e => runMutation(async () => {
                                    const res = await client.api('/api/mcp-servers/toggle', {
                                      method: 'POST',
                                      body: { id: srv.id, toolName: t.name, enabled: e.target.checked },
                                    });
                                    if (res.snapshot) state.snapshot = res.snapshot;
                                  }),
                                });
                                cb.checked = !t.individuallyDisabled;
                                return cb;
                              })(),
                              el('span', { class: 'lw-switch-track', 'aria-hidden': 'true' }),
                            ]),
                          ]),
                        ]))
                      : [el('div', { class: 'lw-muted', text: '该服务暂未缓存到任何外部工具；请点击上方“探测工具”执行 initialize + tools/list。' })])
                  : null,
              ]);
            }))
          : el('div', { class: 'lw-doc-callout', text: '当前尚未接入任何第三方 MCP 服务；可通过上方表单或标准 mcpServers JSON 接入。' }),
      ]),
    ]),
    el('aside', { class: 'lw-doc-aside' }, [
      el('div', { class: 'lw-section-head' }, [
        el('div', {}, [
          el('h3', { text: '第三方 MCP 进程外围栏' }),
          el('p', { text: '接入即隔离危险 env、限制探测并发与载荷体积' }),
        ]),
        el('span', { class: 'lw-pill lw-pill-warn', text: '容器外执行' }),
      ]),
      mcpSvg,
      el('div', { class: 'lw-aside-list' }, [
        el('div', { class: 'lw-aside-row' }, [
          el('span', { class: 'lw-muted', text: '环境变量黑名单' }),
          el('strong', { text: '自动拒收 LD_* / NODE_OPTIONS / AGENTDOCK_*' }),
        ]),
        el('div', { class: 'lw-aside-row' }, [
          el('span', { class: 'lw-muted', text: '工具注册上限' }),
          el('strong', { text: '最多 32 台 · 每台最多 200 工具' }),
        ]),
        el('div', { class: 'lw-aside-row' }, [
          el('span', { class: 'lw-muted', text: '执行批准要求' }),
          el('strong', { text: '全部强制绑定逐参审批' }),
        ]),
      ]),
    ]),
  ]);
}

function renderFencingPage() {
  const data = state.fencingData || {};
  const mcpCount = state.snapshot?.mcpServers?.serverCount || 0;
  const cacheStatus = data.cache?.status || 'missing';
  const activeTab = state.fencingTab === 'mcp' ? 'mcp' : 'antileak';

  const tabBar = el('div', { class: 'lw-view-tabs', role: 'tablist' }, [
    el('button', {
      type: 'button',
      role: 'tab',
      'data-fencing-tab': 'antileak',
      'aria-selected': String(activeTab === 'antileak'),
      class: `lw-view-tab ${activeTab === 'antileak' ? 'is-active' : ''}`,
      onClick: () => {
        state.fencingTab = 'antileak';
        if (!state.fencingData && !state.fencingLoading) void loadFencingConfig({ silent: true });
        render();
      },
    }, [
      makeIcon('shield'),
      el('span', { text: 'R1–R7 防泄漏与规则围栏' }),
      el('span', {
        class: `lw-pill ${cacheStatus === 'fresh' ? 'lw-pill-ok' : 'lw-pill-warn'}`,
        text: cacheStatus === 'fresh' ? '缓存就绪' : cacheStatus,
      }),
    ]),
    el('button', {
      type: 'button',
      role: 'tab',
      'data-fencing-tab': 'mcp',
      'aria-selected': String(activeTab === 'mcp'),
      class: `lw-view-tab ${activeTab === 'mcp' ? 'is-active' : ''}`,
      onClick: () => { state.fencingTab = 'mcp'; render(); },
    }, [
      makeIcon('plug'),
      el('span', { text: '第三方 MCP 接入围栏' }),
      el('span', { class: `lw-pill ${mcpCount > 0 ? 'lw-pill-info' : ''}`, text: `${mcpCount} 台服务` }),
    ]),
  ]);

  return el('div', { class: 'lw-stack-md' }, [
    makePageHeader('安全围栏', '管理离线防泄漏规则和第三方 MCP 工具的访问策略。'),
    tabBar,
    activeTab === 'mcp' ? renderFencingMcpTab() : renderFencingAntileakTab(),
  ]);
}

function renderReviewModal() {
  const modal = state.reviewModal;
  if (!modal) return null;
  const leftSec = Math.max(0, Math.ceil((Date.parse(modal.expiresAt) - Date.now()) / 1000));
  const boundary = classifyToolBoundary(modal.tool, modal.tool?.startsWith('mcp__'));
  return el('div', { class: 'lw-modal-backdrop', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'lw-review-title', 'data-request-id': modal.id }, [
    el('div', { class: 'lw-modal' }, [
      el('div', { class: 'lw-row lw-between' }, [
        el('h3', { id: 'lw-review-title', text: `精确参数复核 · ${modal.tool}` }),
        el('span', {
          class: `lw-pill ${leftSec <= 20 ? 'lw-pill-err' : 'lw-pill-warn'}`,
          'data-countdown-expires': modal.expiresAt,
          'data-warn-threshold': '20',
          text: `剩余 ${leftSec}s`,
        }),
      ]),
      makeStatStrip([
        { icon: boundary.icon, label: '执行边界', value: boundary.label, tone: boundary.tone },
        { icon: 'lock', label: '授权额度', value: '仅限本次 1 次调用' },
        { icon: 'shieldCheck', label: '防重放保护', value: '24h 账本不可重用' },
        { icon: 'clock', label: '过期策略', value: '超时自动作废' },
      ]),
      el('div', { class: 'lw-muted lw-mono', text: `policyDigest: ${modal.digest}` }),
      el('pre', { class: 'lw-pre', id: 'lw-review-request', tabindex: '0', 'aria-label': '完整请求参数', text: modal.requestText }),
      el('div', { class: 'lw-row lw-end' }, [
        el('button', {
          type: 'button',
          class: 'lw-btn',
          id: 'lw-review-cancel', text: '取消',
          onClick: () => { state.reviewModal = null; render(); },
        }),
        el('button', {
          type: 'button',
          class: 'lw-btn lw-btn-trust',
          disabled: state.busy || leftSec <= 0,
          'data-countdown-disable-expires': modal.expiresAt,
          id: 'lw-review-confirm', text: '确认批准一次',
          onClick: () => runMutation(async () => {
            const res = await client.api('/api/approvals/approve', {
              method: 'POST',
              body: { id: modal.id, digest: modal.digest },
            });
            state.reviewModal = null;
            if (res.snapshot) state.snapshot = res.snapshot;
            setNotice(`已精确批准一次请求 ${modal.id.slice(0, 8)}。`);
          }),
        }),
      ]),
    ]),
  ]);
}

function renderActivePage() {
  if (state.page === 'approvals') return renderApprovalsPage();
  if (state.page === 'capabilities') return renderCapabilitiesPage();
  if (state.page === 'fencing') return renderFencingPage();
  if (state.page === 'moderation') return renderModerationPage();
  if (state.page === 'secrets') return renderSecretsPage();
  if (state.page === 'panels') return renderPanelsPage();
  if (state.page === 'audit') return renderAuditPage();
  if (state.page === 'tools') return renderToolsPage();
  return renderOverviewPage();
}

function render() {
  const prevRequestId = root.querySelector('.lw-modal-backdrop')?.dataset.requestId;
  const reviewFocus = document.activeElement?.closest('.lw-modal [id]')?.id;
  const prevPre = root.querySelector('.lw-modal .lw-pre');
  const prevScrollTop = prevPre ? prevPre.scrollTop : 0;
  const prevScrollLeft = prevPre ? prevPre.scrollLeft : 0;

  const navFocus = document.activeElement?.closest('.lw-nav-item')?.dataset.navId;
  const chromeFocus = document.activeElement?.closest('.lw-chrome-button')?.id;
  const sidebarScroll = root.querySelector('.lw-sidebar')?.scrollTop;
  clearNode(root);
  const children = [];

  if (!state.auth?.authenticated) {
    children.push(renderTopbar());
    const main = el('main', { class: 'lw-shell' });
    if (state.error) main.append(el('div', { class: 'lw-banner lw-banner-err', role: 'alert', text: state.error }));
    if (state.notice) main.append(el('div', { class: 'lw-banner lw-banner-ok', role: 'status', text: state.notice }));
    main.append(renderAuthGate());
    children.push(main);
  } else {
    const contentInner = el('div', { class: 'lw-content-inner' });
    if (state.error) contentInner.append(el('div', { class: 'lw-banner lw-banner-err', role: 'alert', text: state.error }));
    if (state.notice) contentInner.append(el('div', { class: 'lw-banner lw-banner-ok', role: 'status', text: state.notice }));
    contentInner.append(renderActivePage());

    const backdrop = el('div', {
      class: `lw-sidebar-backdrop ${state.mobileNavOpen ? 'open' : ''}`,
      onClick: () => setDrawer(false),
    });

    children.push(el('div', { class: 'lw-app-frame', inert: Boolean(state.reviewModal) }, [
      renderSidebar(),
      backdrop,
      el('div', { class: 'lw-work-area', inert: state.mobileNavOpen ? '' : null }, [
        renderTopbar(),
        el('main', { id: 'lw-main', class: 'lw-content', tabindex: '-1' }, [contentInner]),
      ]),
    ]));
  }

  const modal = renderReviewModal();
  if (modal) children.push(modal);
  root.append(...children);
  const sidebar = root.querySelector('.lw-sidebar');
  if (sidebar && sidebarScroll) sidebar.scrollTop = sidebarScroll;
  if (navFocus) sidebar?.querySelector(`[data-nav-id="${CSS.escape(navFocus)}"]`)?.focus({ preventScroll: true });
  if (chromeFocus) document.getElementById(chromeFocus)?.focus({ preventScroll: true });

  if (modal) {
    const target = reviewFocus && document.getElementById(reviewFocus);
    (target && !target.disabled ? target : document.getElementById('lw-review-cancel'))?.focus({ preventScroll: true });
  } else if (prevRequestId) {
    const trigger = root.querySelector(`[data-review-id="${CSS.escape(prevRequestId)}"]:not(:disabled)`);
    (trigger || root.querySelector('.lw-page-head h1'))?.focus({ preventScroll: true });
  }

  if (modal && (prevScrollTop > 0 || prevScrollLeft > 0)) {
    const nextPre = root.querySelector('.lw-modal .lw-pre');
    if (nextPre) {
      nextPre.scrollTop = prevScrollTop;
      nextPre.scrollLeft = prevScrollLeft;
    }
  }
}

void refreshAuthState().catch(err => setError(err?.message || '无法连接安全控制台。'));
