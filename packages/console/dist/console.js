(() => {
  // web/shared/client.mjs
  function readMeta(name) {
    return document.querySelector(`meta[name="${name}"]`)?.getAttribute("content") || "";
  }
  function el(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === void 0 || v === null || v === false) continue;
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = String(v);
      else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2).toLowerCase(), v);
      else if (v === true) node.setAttribute(k, "");
      else node.setAttribute(k, String(v));
    }
    const list = Array.isArray(children) ? children : [children];
    for (const child of list) {
      if (child === null || child === void 0 || child === false) continue;
      node.append(typeof child === "string" ? document.createTextNode(child) : child);
    }
    return node;
  }
  var SVG_NS = "http://www.w3.org/2000/svg";
  function svgEl(tag, attrs = {}, children = []) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === void 0 || v === null || v === false) continue;
      if (k === "class") node.setAttribute("class", String(v));
      else node.setAttribute(k, String(v));
    }
    const list = Array.isArray(children) ? children : [children];
    for (const child of list) {
      if (child === null || child === void 0 || child === false) continue;
      node.append(child);
    }
    return node;
  }
  function isSafeNavigationUrl(raw, { allowRelative = false } = {}) {
    if (typeof raw !== "string") return false;
    const trimmed = raw.trim();
    if (!trimmed || /[\x00-\x1f\x7f]/.test(trimmed)) return false;
    if (allowRelative && trimmed.startsWith("/") && !trimmed.startsWith("//") && !trimmed.startsWith("/\\")) {
      return true;
    }
    try {
      const parsed = new URL(trimmed);
      return parsed.protocol === "https:" || parsed.protocol === "http:";
    } catch {
      return false;
    }
  }
  function clearNode(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }
  function initThemeToggle() {
    const saved = window.localStorage.getItem("loomward-theme");
    const initial = saved === "dark" || saved === "light" ? saved : window.matchMedia?.("(prefers-color-scheme: dark)")?.matches ? "dark" : "light";
    document.documentElement.dataset.theme = initial;
    return {
      current: () => document.documentElement.dataset.theme || "light",
      toggle() {
        const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
        document.documentElement.dataset.theme = next;
        try {
          window.localStorage.setItem("loomward-theme", next);
        } catch {
        }
        return next;
      }
    };
  }
  function b64urlToBytes(str) {
    const pad = "=".repeat((4 - str.length % 4) % 4);
    const bin = atob(str.replace(/-/g, "+").replace(/_/g, "/") + pad);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function bytesToB64url(buf) {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function createOriginClient({ storageKey }) {
    let csrfToken = readMeta("loomward-csrf");
    let tabToken = "";
    try {
      tabToken = window.sessionStorage.getItem(storageKey) || "";
    } catch {
    }
    function setTokens({ csrf, tab } = {}) {
      if (typeof csrf === "string" && csrf) csrfToken = csrf;
      if (tab !== void 0) {
        tabToken = typeof tab === "string" ? tab : "";
        try {
          if (tabToken) window.sessionStorage.setItem(storageKey, tabToken);
          else window.sessionStorage.removeItem(storageKey);
        } catch {
        }
      }
    }
    function clearTabToken() {
      setTokens({ tab: "" });
    }
    function authHeaders(isMutation = false) {
      const headers = {};
      if (tabToken) headers["X-LoomWard-Tab-Auth"] = tabToken;
      if (isMutation) {
        headers["Content-Type"] = "application/json";
        if (csrfToken) headers["X-LoomWard-CSRF"] = csrfToken;
      }
      return headers;
    }
    async function api(pathname, { method = "GET", body } = {}) {
      const isMutation = method !== "GET" && method !== "HEAD";
      const res = await fetch(pathname, {
        method,
        credentials: "same-origin",
        headers: authHeaders(isMutation),
        ...isMutation ? { body: JSON.stringify(body ?? {}) } : {}
      });
      const text = await res.text();
      let data = {};
      try {
        data = text ? JSON.parse(text) : {};
      } catch {
      }
      if (typeof data?.csrfToken === "string" && data.csrfToken) {
        csrfToken = data.csrfToken;
      }
      if (typeof data?.tabToken === "string" && data.tabToken) {
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
          onStatus?.("connecting");
          const res = await fetch(pathname, {
            method: "GET",
            credentials: "same-origin",
            headers: {
              Accept: "text/event-stream",
              ...tabToken ? { "X-LoomWard-Tab-Auth": tabToken } : {}
            },
            signal: activeController.signal
          });
          if (!res.ok || !res.body) {
            if (res.status === 401 || res.status === 403) {
              onStatus?.("unauthorized");
              return;
            }
            onStatus?.("disconnected");
          } else {
            onStatus?.("connected");
            const reader = res.body.getReader();
            const decoder = new TextDecoder();
            let buffer = "";
            while (!closed) {
              const { done, value } = await reader.read();
              if (done) break;
              buffer += decoder.decode(value, { stream: true });
              let sep;
              while ((sep = /\r?\n\r?\n/.exec(buffer)) !== null) {
                const block = buffer.slice(0, sep.index);
                buffer = buffer.slice(sep.index + sep[0].length);
                let eventName = "message";
                const dataLines = [];
                for (const line of block.split(/\r?\n/)) {
                  if (line.startsWith("event:")) eventName = line.slice(6).trim();
                  else if (line.startsWith("data:")) {
                    const rest = line.slice(5);
                    dataLines.push(rest.startsWith(" ") ? rest.slice(1) : rest);
                  }
                }
                if (dataLines.length) {
                  try {
                    onEvent?.(eventName, JSON.parse(dataLines.join("\n")));
                  } catch {
                  }
                }
              }
            }
            if (!closed) onStatus?.("disconnected");
          }
        } catch {
          if (!closed) onStatus?.("disconnected");
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
      connectSse
    };
  }

  // web/console/main.mjs
  var client = createOriginClient({ storageKey: "loomward_console_tab_token" });
  var theme = initThemeToggle();
  var root = document.getElementById("app");
  var DEFAULT_MOD_CONFIG = {
    enabled: true,
    mode: "local-only",
    policyProfile: "experimental-resilient",
    defaultScope: "combined",
    cloudOptIn: false,
    cloudProvider: "openai-compat",
    cloudRegion: "",
    cloudEndpoint: "",
    localGuard: {
      kind: "ollama",
      endpoint: "http://127.0.0.1:11434",
      model: "llama-guard3:1b",
      think: false,
      allowPrivateNetwork: false
    },
    canary: {
      enabled: false,
      kind: "ollama",
      endpoint: "http://127.0.0.1:11434",
      model: "qwen2.5:0.5b",
      think: false,
      allowPrivateNetwork: false,
      shadowMode: true
    }
  };
  var state = {
    auth: null,
    snapshot: null,
    moderationConfig: null,
    draftMod: null,
    ollama: null,
    ollamaLoading: false,
    ollamaError: "",
    ollamaEndpointInput: "",
    ollamaAllowPrivate: false,
    ollamaPullTag: "",
    ollamaInstallConfirm: false,
    ollamaTestResult: null,
    ollamaPollTimer: null,
    draftAuth: { setupToken: "", password: "", passkeyLabel: "" },
    draftSecret: { unitId: "llm-moderation", key: "", value: "" },
    draftCloudCreds: {},
    pluginSecretUnits: [],
    page: "overview",
    modTab: "routing",
    mobileNavOpen: false,
    toolFilter: "all",
    toolSearch: "",
    toolCatalogMode: "mcp",
    selectedToolName: "",
    selectedHttpId: "status",
    toolArgsDraft: {},
    toolHttpTryResult: null,
    copiedTarget: "",
    fencingTab: "antileak",
    fencingData: null,
    fencingDraft: null,
    fencingLoading: false,
    fencingDryText: "",
    fencingDryResult: null,
    fencingDoctorResult: null,
    fencingRefreshResult: null,
    mcpDraft: {
      editingId: "",
      id: "",
      name: "",
      description: "",
      transport: "stdio",
      command: "",
      argsText: "",
      cwd: "",
      url: "",
      timeoutMs: "30000",
      envText: "",
      removeEnvKeysText: "",
      headersText: "",
      removeHeaderKeysText: "",
      replaceSecrets: false,
      enabled: true,
      probe: true
    },
    mcpImportJson: "",
    mcpImportProbe: true,
    mcpExpandedTools: {},
    mcpDeleteConfirmId: "",
    auditFilter: "all",
    expandedAuditKeys: {},
    expandedKernelKeys: {},
    sseStatus: "idle",
    liveKernelEvents: [],
    error: "",
    notice: "",
    busy: false,
    reviewModal: null,
    stopSse: null,
    countdownTimer: null
  };
  function setNotice(msg) {
    state.notice = msg || "";
    if (msg) state.error = "";
    render();
  }
  function setError(msg) {
    state.error = msg || "";
    if (msg) state.notice = "";
    render();
  }
  function navigate(pageId, opts = {}) {
    state.page = pageId;
    state.mobileNavOpen = false;
    if (opts.fencingTab) state.fencingTab = opts.fencingTab;
    if (opts.selectedToolName) {
      state.selectedToolName = opts.selectedToolName;
      state.toolCatalogMode = "mcp";
    }
    if (pageId === "moderation" && state.auth?.authenticated && !state.ollama && !state.ollamaLoading) {
      void loadOllamaStatus({ silent: true });
    }
    if (pageId === "fencing" && state.auth?.authenticated && !state.fencingData && !state.fencingLoading) {
      void loadFencingConfig({ silent: true });
    }
    render();
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
    const nodes = root.querySelectorAll("[data-countdown-expires]");
    for (const node of nodes) {
      const exp = Date.parse(node.getAttribute("data-countdown-expires") || "");
      if (!Number.isFinite(exp)) continue;
      const leftSec = Math.max(0, Math.ceil((exp - Date.now()) / 1e3));
      const threshold = Number(node.getAttribute("data-warn-threshold") || "30");
      node.textContent = `\u5269\u4F59 ${leftSec}s`;
      node.className = `lw-pill ${leftSec <= threshold ? "lw-pill-err" : "lw-pill-warn"}`;
    }
    const btns = root.querySelectorAll("[data-countdown-disable-expires]");
    for (const btn of btns) {
      const exp = Date.parse(btn.getAttribute("data-countdown-disable-expires") || "");
      if (!Number.isFinite(exp)) continue;
      const leftSec = Math.max(0, Math.ceil((exp - Date.now()) / 1e3));
      if (leftSec <= 0) btn.disabled = true;
    }
  }
  function startLiveStream() {
    stopLiveResources();
    state.stopSse = client.connectSse("/api/events", {
      onStatus(status) {
        state.sseStatus = status;
        if (status === "unauthorized") {
          stopLiveResources();
          client.clearTabToken();
          state.snapshot = null;
          state.liveKernelEvents = [];
          state.reviewModal = null;
          void refreshAuthState().catch(() => {
          });
        } else {
          render();
        }
      },
      onEvent(name, payload) {
        if (name === "status") {
          state.snapshot = payload;
          render();
        } else if (name === "kernel") {
          state.liveKernelEvents.unshift(payload);
          if (state.liveKernelEvents.length > 40) state.liveKernelEvents.length = 40;
          render();
        }
      }
    });
    state.countdownTimer = setInterval(() => {
      if (state.snapshot?.approvals?.pendingCount > 0 || state.reviewModal) {
        updateLiveCountdowns();
      }
    }, 1e3);
  }
  async function runMutation(fn) {
    if (state.busy) return;
    state.busy = true;
    state.error = "";
    render();
    try {
      await fn();
    } catch (err) {
      state.error = err?.message || "\u64CD\u4F5C\u5931\u8D25";
      if (err?.status === 401) {
        stopLiveResources();
        client.clearTabToken();
        state.snapshot = null;
        state.liveKernelEvents = [];
        state.reviewModal = null;
        await refreshAuthState().catch(() => {
        });
      }
    } finally {
      state.busy = false;
      render();
    }
  }
  function scheduleOllamaPolling(jobs) {
    stopOllamaPolling();
    if (!state.auth?.authenticated) return;
    if (Array.isArray(jobs) && jobs.some((j) => j.status === "pulling")) {
      state.ollamaPollTimer = setTimeout(() => {
        void loadOllamaStatus({ silent: true });
      }, 1500);
    }
  }
  async function loadOllamaStatus({ endpoint, allowPrivateNetwork, silent = false } = {}) {
    if (!state.auth?.authenticated) return null;
    const fallbackEp = (state.draftMod?.localGuard?.endpoint || state.moderationConfig?.localGuard?.endpoint || "http://127.0.0.1:11434").trim();
    const targetEp = String(endpoint ?? (state.ollamaEndpointInput || fallbackEp)).trim();
    const allowPriv = Boolean(allowPrivateNetwork ?? state.ollamaAllowPrivate);
    const qs = new URLSearchParams();
    if (targetEp) qs.set("endpoint", targetEp);
    if (allowPriv) qs.set("allowPrivateNetwork", "1");
    if (!silent) state.ollamaLoading = true;
    state.ollamaError = "";
    if (!silent) render();
    try {
      const res = await client.api(`/api/moderation/ollama/status?${qs.toString()}`);
      state.ollama = res;
      if (!state.ollamaEndpointInput && res?.endpoint) state.ollamaEndpointInput = res.endpoint;
      scheduleOllamaPolling(res?.pullJobs);
      return res;
    } catch (err) {
      state.ollamaError = err?.message || "Ollama \u8FD0\u884C\u65F6\u63A2\u6D4B\u5931\u8D25";
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
      const res = await client.api("/api/fencing/config");
      state.fencingData = res;
      if (res?.config && !state.fencingDraft) {
        state.fencingDraft = structuredClone(res.config);
      }
      return res;
    } catch (err) {
      if (!silent) setError(err?.message || "\u8BFB\u53D6 Agent \u9632\u6CC4\u6F0F\u56F4\u680F\u914D\u7F6E\u5931\u8D25");
      return null;
    } finally {
      state.fencingLoading = false;
      render();
    }
  }
  async function refreshAuthState() {
    const auth = await client.api("/api/auth/state");
    state.auth = auth;
    if (auth.authenticated) {
      const [snap, modRes, secRes, fenceRes] = await Promise.all([
        client.api("/api/status"),
        client.api("/api/moderation/config").catch(() => null),
        client.api("/api/plugin-secrets/meta").catch(() => null),
        client.api("/api/fencing/config").catch(() => null)
      ]);
      state.snapshot = snap;
      state.liveKernelEvents = Array.isArray(snap?.channelEvents) ? [...snap.channelEvents].reverse() : [];
      if (modRes?.config) {
        state.moderationConfig = modRes.config;
        if (!state.draftMod) state.draftMod = structuredClone(modRes.config);
        if (!state.ollamaEndpointInput && modRes.config.localGuard?.endpoint) {
          state.ollamaEndpointInput = modRes.config.localGuard.endpoint;
        }
        if (modRes.config.localGuard?.allowPrivateNetwork !== void 0) {
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
      state.ollamaError = "";
      state.ollamaTestResult = null;
      state.ollamaInstallConfirm = false;
      state.draftCloudCreds = {};
      state.pluginSecretUnits = [];
      state.liveKernelEvents = [];
      state.mobileNavOpen = false;
    }
    render();
  }
  function ensureWebAuthnLocalhostOrigin() {
    if (window.location.hostname === "127.0.0.1" || window.location.hostname === "[::1]" || window.location.hostname === "::1") {
      const target = `http://localhost:${window.location.port}${window.location.pathname}${window.location.search}`;
      window.location.replace(target);
      throw new Error(`WebAuthn PassKey \u9700\u901A\u8FC7 localhost \u57DF\u540D\u8BBF\u95EE\uFF0C\u6B63\u5728\u8DF3\u8F6C\u81F3 ${target}`);
    }
  }
  async function handlePasskeyLogin() {
    await runMutation(async () => {
      ensureWebAuthnLocalhostOrigin();
      const opt = await client.api("/api/auth/passkey/login/options", { method: "POST", body: {} });
      const pubKey = {
        ...opt.publicKey,
        challenge: b64urlToBytes(opt.publicKey.challenge),
        allowCredentials: (opt.publicKey.allowCredentials || []).map((c) => ({ ...c, id: b64urlToBytes(c.id) }))
      };
      const cred = await navigator.credentials.get({ publicKey: pubKey });
      if (!cred) throw new Error("PassKey \u9A8C\u8BC1\u5DF2\u53D6\u6D88\u3002");
      await client.api("/api/auth/passkey/login/verify", {
        method: "POST",
        body: {
          challengeId: opt.challengeId,
          credential: {
            id: cred.id,
            type: cred.type,
            response: {
              clientDataJSON: bytesToB64url(cred.response.clientDataJSON),
              authenticatorData: bytesToB64url(cred.response.authenticatorData),
              signature: bytesToB64url(cred.response.signature)
            }
          }
        }
      });
      await refreshAuthState();
    });
  }
  async function handlePasskeyEnroll(setupToken, label) {
    await runMutation(async () => {
      ensureWebAuthnLocalhostOrigin();
      const opt = await client.api("/api/auth/setup/passkey/options", {
        method: "POST",
        body: { ...setupToken ? { setupToken } : {} }
      });
      const pubKey = {
        ...opt.publicKey,
        challenge: b64urlToBytes(opt.publicKey.challenge),
        user: { ...opt.publicKey.user, id: b64urlToBytes(opt.publicKey.user.id) },
        excludeCredentials: (opt.publicKey.excludeCredentials || []).map((c) => ({ ...c, id: b64urlToBytes(c.id) }))
      };
      const cred = await navigator.credentials.create({ publicKey: pubKey });
      if (!cred) throw new Error("PassKey \u6CE8\u518C\u5DF2\u53D6\u6D88\u3002");
      await client.api("/api/auth/setup/passkey/verify", {
        method: "POST",
        body: {
          challengeId: opt.challengeId,
          ...setupToken ? { setupToken } : {},
          label: label || "Local PassKey",
          credential: {
            id: cred.id,
            type: cred.type,
            response: {
              clientDataJSON: bytesToB64url(cred.response.clientDataJSON),
              attestationObject: bytesToB64url(cred.response.attestationObject),
              transports: cred.response.getTransports?.() || ["internal"]
            }
          }
        }
      });
      state.draftAuth = { setupToken: "", password: "", passkeyLabel: "" };
      setNotice("PassKey \u6CE8\u518C\u5E76\u767B\u5F55\u6210\u529F\u3002");
      await refreshAuthState();
    });
  }
  async function handleLogout() {
    await runMutation(async () => {
      stopLiveResources();
      await client.api("/api/auth/logout", { method: "POST", body: {} });
      client.clearTabToken();
      state.snapshot = null;
      state.liveKernelEvents = [];
      state.reviewModal = null;
      setNotice("\u5DF2\u9501\u5B9A\u5E76\u6E05\u7406\u5F53\u524D\u4F1A\u8BDD\u3002");
      await refreshAuthState();
    });
  }
  var ICON_SHAPES = {
    shield: [["path", { d: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" }]],
    shieldCheck: [
      ["path", { d: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" }],
      ["path", { d: "M9 12l2 2 4-4" }]
    ],
    radar: [
      ["circle", { cx: "12", cy: "12", r: "9" }],
      ["circle", { cx: "12", cy: "12", r: "4" }],
      ["path", { d: "M12 12l6.5-6.5" }]
    ],
    cloud: [["path", { d: "M17.5 19H9a5 5 0 1 1 .9-9.9 6 6 0 0 1 11.1 2.4A4 4 0 0 1 17.5 19z" }]],
    layers: [
      ["polygon", { points: "12 2 2 7 12 12 22 7 12 2" }],
      ["polyline", { points: "2 12 12 17 22 12" }],
      ["polyline", { points: "2 17 12 22 22 17" }]
    ],
    lock: [
      ["rect", { x: "4", y: "11", width: "16", height: "10", rx: "2" }],
      ["path", { d: "M8 11V7a4 4 0 0 1 8 0v4" }]
    ],
    cpu: [
      ["rect", { x: "6", y: "6", width: "12", height: "12", rx: "2" }],
      ["rect", { x: "9.5", y: "9.5", width: "5", height: "5" }],
      ["path", { d: "M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4" }]
    ],
    server: [
      ["rect", { x: "3", y: "4", width: "18", height: "7", rx: "2" }],
      ["rect", { x: "3", y: "13", width: "18", height: "7", rx: "2" }],
      ["circle", { cx: "7", cy: "7.5", r: "1" }],
      ["circle", { cx: "7", cy: "16.5", r: "1" }]
    ],
    terminal: [
      ["rect", { x: "3", y: "4", width: "18", height: "16", rx: "2" }],
      ["path", { d: "M7 15l4-3-4-3" }],
      ["path", { d: "M13 15h4" }]
    ],
    bolt: [["polygon", { points: "13 2 4 14 11 14 10 22 20 10 13 10 13 2" }]],
    play: [["polygon", { points: "6 4 20 12 6 20 6 4" }]],
    refresh: [
      ["path", { d: "M21 12a9 9 0 1 1-2.64-6.36" }],
      ["polyline", { points: "21 3 21 9 15 9" }]
    ],
    download: [
      ["path", { d: "M12 3v12" }],
      ["polyline", { points: "7 10 12 15 17 10" }],
      ["path", { d: "M4 19h16" }]
    ],
    check: [["polyline", { points: "20 6 9 17 4 12" }]],
    chevronDown: [["polyline", { points: "6 9 12 15 18 9" }]],
    arrowRight: [
      ["line", { x1: "4", y1: "12", x2: "20", y2: "12" }],
      ["polyline", { points: "14 6 20 12 14 18" }]
    ],
    rotateCcw: [
      ["polyline", { points: "3 4 3 10 9 10" }],
      ["path", { d: "M3.51 15a9 9 0 1 0 2.13-9.36L3 10" }]
    ],
    eye: [
      ["path", { d: "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z" }],
      ["circle", { cx: "12", cy: "12", r: "3" }]
    ],
    globe: [
      ["circle", { cx: "12", cy: "12", r: "9" }],
      ["path", { d: "M3 12h18" }],
      ["path", { d: "M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18z" }]
    ],
    alert: [
      ["path", { d: "M12 3L2 20h20L12 3z" }],
      ["line", { x1: "12", y1: "10", x2: "12", y2: "14" }],
      ["circle", { cx: "12", cy: "17", r: "0.8" }]
    ],
    stop: [["rect", { x: "6", y: "6", width: "12", height: "12", rx: "2" }]],
    key: [
      ["circle", { cx: "7.5", cy: "15.5", r: "4.5" }],
      ["path", { d: "M11 12l9-9" }],
      ["path", { d: "M17 6l3 3" }],
      ["path", { d: "M15 8l2 2" }]
    ],
    home: [
      ["path", { d: "M3 10.5L12 3l9 7.5" }],
      ["path", { d: "M5 9.5V20h14V9.5" }]
    ],
    clipboardCheck: [
      ["rect", { x: "5", y: "4", width: "14", height: "17", rx: "2" }],
      ["path", { d: "M9 4V2h6v2" }],
      ["path", { d: "M9 13l2 2 4-4" }]
    ],
    sliders: [
      ["line", { x1: "4", y1: "7", x2: "20", y2: "7" }],
      ["circle", { cx: "9", cy: "7", r: "2" }],
      ["line", { x1: "4", y1: "17", x2: "20", y2: "17" }],
      ["circle", { cx: "15", cy: "17", r: "2" }]
    ],
    layoutPanel: [
      ["rect", { x: "3", y: "4", width: "18", height: "16", rx: "2" }],
      ["line", { x1: "3", y1: "9", x2: "21", y2: "9" }],
      ["line", { x1: "10", y1: "9", x2: "10", y2: "20" }]
    ],
    activity: [["polyline", { points: "3 12 7 12 10 5 14 19 17 12 21 12" }]],
    wrench: [["path", { d: "M14.7 6.3a4 4 0 0 0-5.4 5.4L4 17l3 3 5.3-5.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2.5-2.5 2-2.5z" }]],
    file: [
      ["path", { d: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" }],
      ["polyline", { points: "14 2 14 8 20 8" }]
    ],
    search: [
      ["circle", { cx: "11", cy: "11", r: "7" }],
      ["line", { x1: "16.5", y1: "16.5", x2: "21", y2: "21" }]
    ],
    clock: [
      ["circle", { cx: "12", cy: "12", r: "9" }],
      ["polyline", { points: "12 7 12 12 15.5 14" }]
    ],
    copy: [
      ["rect", { x: "9", y: "9", width: "13", height: "13", rx: "2" }],
      ["path", { d: "M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" }]
    ],
    code: [
      ["polyline", { points: "16 18 22 12 16 6" }],
      ["polyline", { points: "8 6 2 12 8 18" }]
    ],
    plus: [
      ["line", { x1: "12", y1: "5", x2: "12", y2: "19" }],
      ["line", { x1: "5", y1: "12", x2: "19", y2: "12" }]
    ],
    trash: [
      ["polyline", { points: "3 6 5 6 21 6" }],
      ["path", { d: "M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" }],
      ["path", { d: "M10 11v6M14 11v6M9 6V4h6v2" }]
    ],
    plug: [
      ["path", { d: "M12 22v-5" }],
      ["path", { d: "M9 8V2M15 8V2" }],
      ["path", { d: "M18 8H6v4a6 6 0 0 0 12 0V8z" }]
    ],
    chevronRight: [["polyline", { points: "9 18 15 12 9 6" }]]
  };
  function isToolParentEnabled(snap, tool) {
    if (!tool) return false;
    if (tool.external) return tool.serverEnabled !== false;
    const caps = snap?.capabilities || {};
    const allowExecConfig = snap?.sandbox?.configAllowExec === true;
    if (caps.error) {
      if (tool.group === "context") return true;
      if (tool.group === "execControl") return allowExecConfig;
      return false;
    }
    if (tool.group === "context") return true;
    if (tool.group === "fileRead") return Boolean(caps.fileRead);
    if (tool.group === "fileWrite") return Boolean(caps.fileWrite);
    if (tool.group === "execControl") return allowExecConfig;
    if (tool.group === "exec") return Boolean(caps.fileRead && caps.allowExec && allowExecConfig);
    return true;
  }
  function getSingleToolStatusLabel(snap, tool) {
    if (!tool) return "\u672A\u77E5";
    if (tool.individuallyDisabled) return "\u5355\u5DE5\u5177\u5DF2\u5173";
    if (!isToolParentEnabled(snap, tool)) return tool.external ? "\u670D\u52A1\u5DF2\u505C\u7528" : "\u603B\u5F00\u5173\u9650\u5236";
    return tool.enabled ? "\u5DF2\u542F\u7528" : "\u5DF2\u505C\u7528";
  }
  function toggleSingleTool(tool, nextEnabled) {
    return runMutation(async () => {
      if (tool.external) {
        const res = await client.api("/api/mcp-servers/toggle", {
          method: "POST",
          body: { id: tool.serverId, toolName: tool.rawToolName, enabled: nextEnabled }
        });
        if (res.snapshot) state.snapshot = res.snapshot;
      } else {
        const res = await client.api("/api/capabilities", {
          method: "POST",
          body: { tools: { [tool.name]: nextEnabled } }
        });
        if (res.snapshot) state.snapshot = res.snapshot;
      }
      setNotice(`\u5DE5\u5177 ${tool.name} \u5DF2${nextEnabled ? "\u542F\u7528" : "\u5355\u72EC\u505C\u7528"}\u3002`);
    });
  }
  function makeStatStrip(cells) {
    return el("div", { class: "lw-stat-strip" }, cells.map((c) => el("div", { class: "lw-stat-cell" }, [
      el("span", { class: "lw-stat-k" }, [
        c.icon ? makeIcon(c.icon) : null,
        el("span", { text: c.label })
      ]),
      el("span", { class: `lw-stat-v ${c.tone ? `is-${c.tone}` : ""}`, text: c.value })
    ])));
  }
  function svgNodeBox({ x, y, w, h, title, sub, badge, stateCls = "", badgeCls = "", isDelta = false }) {
    const kids = [];
    if (isDelta) {
      kids.push(svgEl("rect", { x: x - 4, y: y - 4, width: w + 8, height: h + 8, rx: 10, class: "lw-svg-halo" }));
    }
    kids.push(svgEl("rect", { x, y, width: w, height: h, rx: 7, class: `lw-svg-node-bg ${stateCls}` }));
    const tNode = svgEl("text", { x: x + 10, y: y + (sub || badge ? 19 : Math.round(h / 2) + 4), class: "lw-svg-title" });
    tNode.textContent = title;
    kids.push(tNode);
    if (sub) {
      const sNode = svgEl("text", { x: x + 10, y: y + 35, class: "lw-svg-sub" });
      sNode.textContent = sub;
      kids.push(sNode);
    }
    if (badge) {
      const bNode = svgEl("text", { x: x + 10, y: y + (h >= 62 ? 51 : 49), class: `lw-svg-badge ${badgeCls}` });
      bNode.textContent = badge;
      kids.push(bNode);
    }
    return svgEl("g", {}, kids);
  }
  function formatMetaChips(meta) {
    if (!meta || typeof meta !== "object") return [el("span", { class: "lw-muted", text: "-" })];
    const entries = Object.entries(meta).filter(([, v]) => v !== void 0 && v !== null && v !== "");
    if (!entries.length) return [el("span", { class: "lw-muted", text: "\u65E0\u9644\u52A0\u5B57\u6BB5" })];
    return entries.slice(0, 6).map(([k, v]) => {
      const valStr = typeof v === "object" ? JSON.stringify(v) : String(v);
      return el("span", { class: "lw-meta-chip" }, [
        el("span", { class: "lw-meta-chip-k", text: k }),
        el("span", { class: "lw-meta-chip-v", text: clipText(valStr, 36) })
      ]);
    });
  }
  function classifyToolBoundary(toolName, isExternal = false) {
    const name = String(toolName || "");
    if (isExternal || name.startsWith("mcp__")) {
      return { icon: "globe", label: "\u8FDB\u7A0B\u5916 MCP\uFF08\u975E\u5BB9\u5668\uFF09", tone: "warn", desc: "\u7ECF\u63D2\u4EF6\u6216\u7B2C\u4E09\u65B9 MCP \u670D\u52A1\u8FD0\u884C\u4E8E\u5BB9\u5668\u5916\uFF0C\u53D7\u6743\u9650\u4E0E\u5185\u5BB9\u5BA1\u67E5\u7EA6\u675F" };
    }
    if (/exec|command|bash|shell/i.test(name)) {
      return { icon: "terminal", label: "Docker \u547D\u4EE4\u6C99\u7BB1", tone: "warn", desc: "\u4EC5\u9650\u65E0\u5165\u7AD9\u7F51\u7EDC\u7684\u4E00\u6B21\u6027\u53D7\u9650 Linux \u5BB9\u5668\u5185\u6267\u884C\u547D\u4EE4" };
    }
    if (/write|edit|replace|delete|remove|patch|create/i.test(name)) {
      return { icon: "lock", label: "\u5DE5\u4F5C\u533A\u5199\u5165\u5DE5\u5177", tone: "warn", desc: "\u9700 fileWrite=true \u4E0E\u5BB9\u5668 :rw \u6302\u8F7D\uFF0C\u5426\u5219\u7269\u7406\u62D2\u7EDD\u5199\u5165" };
    }
    return { icon: "file", label: "Docker \u53EA\u8BFB\u6C99\u7BB1", tone: "ok", desc: "\u9ED8\u8BA4\u5DE5\u4F5C\u533A :ro \u53EA\u8BFB\u6302\u8F7D\u4E0E\u8DEF\u5F84/Unicode \u5B89\u5168\u6821\u9A8C" };
  }
  function makeIcon(name, className = "") {
    const specs = ICON_SHAPES[name] || ICON_SHAPES.shield;
    return svgEl("svg", {
      viewBox: "0 0 24 24",
      fill: "none",
      stroke: "currentColor",
      "stroke-width": "1.9",
      "stroke-linecap": "round",
      "stroke-linejoin": "round",
      "aria-hidden": "true",
      ...className ? { class: className } : {}
    }, specs.map(([tag, attrs]) => svgEl(tag, attrs)));
  }
  function makeIconButton({ text, iconName, className = "lw-btn", disabled = false, onClick, attrs = {} }) {
    return el("button", {
      type: "button",
      class: className,
      disabled,
      ...attrs,
      ...onClick ? { onClick } : {}
    }, [
      iconName ? makeIcon(iconName) : null,
      el("span", { text })
    ]);
  }
  function makeField(labelContent, controlNode, { fullWidth = false } = {}) {
    const labelNode = typeof labelContent === "string" ? el("label", { class: "lw-field-label", text: labelContent }) : el("label", { class: "lw-field-label lw-field-label-rich" }, [labelContent]);
    return el("div", { class: `lw-field ${fullWidth ? "lw-field-full" : ""}` }, [
      labelNode,
      controlNode
    ]);
  }
  function makeSelect(options, current, onChange, { iconName = null, isDelta = false } = {}) {
    const sel = el("select", { class: "lw-select", ...onChange ? { onChange } : {} });
    for (const [val, label] of options) {
      const opt = el("option", { value: val, text: label });
      if (val === current) opt.selected = true;
      sel.append(opt);
    }
    return el("div", { class: `lw-select-box ${iconName ? "has-lead" : ""} ${isDelta ? "is-delta" : ""}` }, [
      iconName ? makeIcon(iconName, "lw-select-lead") : null,
      sel,
      makeIcon("chevronDown", "lw-select-caret")
    ]);
  }
  function makeSwitchCard({
    checked,
    onChange,
    title,
    subtitle = "",
    pillText = "",
    pillTone = "info",
    iconName = null,
    isDelta = false,
    disabled = false
  }) {
    const input = el("input", {
      type: "checkbox",
      class: "lw-switch-input",
      disabled,
      onChange: (e) => onChange?.(e.target.checked)
    });
    input.checked = Boolean(checked);
    const stateClass = pillTone === "warn" ? "is-warn" : checked ? "is-on" : "";
    return el("label", { class: `lw-setting-row ${isDelta ? "is-delta" : ""}` }, [
      el("span", { class: "lw-switch-main" }, [
        iconName ? makeIcon(iconName) : null,
        el("span", { class: "lw-switch-copy" }, [
          el("span", { class: "lw-row" }, [
            el("span", { class: "lw-switch-label", text: title }),
            isDelta ? el("span", { class: "lw-delta-tag", text: "\u5C06\u53D8\u66F4" }) : null
          ]),
          subtitle ? el("span", { class: "lw-switch-sub", text: subtitle }) : null
        ])
      ]),
      el("span", { class: "lw-switch-ctrl" }, [
        pillText ? el("span", { class: `lw-switch-state ${stateClass}`, text: pillText }) : null,
        el("span", { class: "lw-switch-pill" }, [
          input,
          el("span", { class: "lw-switch-track", "aria-hidden": "true" })
        ])
      ])
    ]);
  }
  function makeOptionCards({ options, value, savedValue, onSelect }) {
    return el("div", {
      class: "lw-radio-list",
      role: "radiogroup"
    }, options.map((opt) => {
      const selected = value === opt.value;
      const isDelta = selected && savedValue !== void 0 && savedValue !== value;
      return el("button", {
        type: "button",
        role: "radio",
        "aria-checked": String(selected),
        class: `lw-radio-item ${selected ? "is-selected" : ""} ${isDelta ? "is-delta" : ""}`,
        onClick: () => onSelect?.(opt.value)
      }, [
        el("div", { class: "lw-radio-left" }, [
          makeIcon(opt.icon),
          el("div", {}, [
            el("div", { class: "lw-radio-title", text: opt.title }),
            el("div", { class: "lw-radio-desc", text: opt.desc })
          ])
        ]),
        el("div", { class: "lw-radio-right" }, [
          isDelta ? el("span", { class: "lw-delta-tag", text: "\u5C06\u53D8\u66F4" }) : opt.badge ? el("span", { class: `lw-pill ${opt.badgeTone ? `lw-pill-${opt.badgeTone}` : ""}`, text: opt.badge }) : null
        ])
      ]);
    }));
  }
  function makeSegmentedChoice({ options, value, savedValue, disabled = false, onSelect }) {
    return el("div", { class: "lw-seg", role: "radiogroup" }, options.map((opt) => {
      const selected = value === opt.value;
      const isDelta = selected && savedValue !== void 0 && savedValue !== value;
      return el("button", {
        type: "button",
        role: "radio",
        "aria-checked": String(selected),
        disabled: disabled || opt.disabled,
        class: `lw-seg-btn ${selected ? "is-selected" : ""} ${isDelta ? "is-delta" : ""}`,
        onClick: () => onSelect?.(opt.value)
      }, [
        opt.icon ? makeIcon(opt.icon) : null,
        el("span", { text: opt.label })
      ]);
    }));
  }
  function makePageHeader(title, desc) {
    return el("div", { class: "lw-page-head" }, [
      el("h2", { text: title }),
      desc ? el("p", { class: "lw-page-desc", text: desc }) : null
    ]);
  }
  function renderTopbar() {
    const authed = Boolean(state.auth?.authenticated);
    const sseOk = state.sseStatus === "open" || state.sseStatus === "connected";
    return el("header", { class: "lw-topbar" }, [
      el("div", { class: "lw-topbar-inner" }, [
        el("div", { class: "lw-brand" }, [
          authed ? el("button", {
            type: "button",
            class: "lw-btn lw-btn-sm lw-menu-btn",
            "aria-expanded": String(state.mobileNavOpen),
            text: state.mobileNavOpen ? "\u5173\u95ED\u5BFC\u822A" : "\u5BFC\u822A\u83DC\u5355",
            onClick: () => {
              state.mobileNavOpen = !state.mobileNavOpen;
              render();
            }
          }) : null,
          el("img", {
            src: "/brand-icon.svg",
            class: "lw-console-logo",
            alt: "LoomWard \xB7 \u7EC7\u76FE",
            width: "34",
            height: "34"
          }),
          el("div", {}, [
            el("div", { class: "lw-row" }, [
              el("h1", { class: "lw-brand-title", text: "LoomWard \xB7 \u7EC7\u76FE" }),
              el("span", { class: "lw-pill lw-pill-info", text: "\u5B89\u5168\u63A7\u5236\u53F0" })
            ]),
            el("p", { class: "lw-brand-sub", text: "\u672C\u5730\u56DE\u73AF\u7BA1\u63A7\u9762 \xB7 Cordis 4 \u5FAE\u5185\u6838\u4E0E\u591A\u6A21\u6001\u9632\u62A4" })
          ])
        ]),
        el("div", { class: "lw-row" }, [
          authed && state.auth?.authMethod ? el("span", {
            class: `lw-pill ${state.auth.authMethod === "preview" ? "lw-pill-warn" : ""}`,
            text: state.auth.authMethod === "preview" ? "\u672C\u5730\u9884\u89C8\uFF08\u514D\u521D\u59CB\u5316\uFF09" : state.auth.authMethod === "passkey" ? "PassKey \u4F1A\u8BDD" : "\u5F3A\u5BC6\u7801\u4F1A\u8BDD"
          }) : null,
          authed ? el("span", {
            class: `lw-pill ${sseOk ? "lw-pill-ok" : "lw-pill-warn"}`,
            text: sseOk ? "SSE \u5728\u7EBF" : `SSE ${state.sseStatus}`
          }) : el("span", { class: "lw-pill lw-pill-warn", text: "\u672A\u89E3\u9501" }),
          el("button", {
            type: "button",
            class: "lw-btn lw-btn-sm",
            text: theme.current() === "dark" ? "\u6D45\u8272" : "\u6DF1\u8272",
            onClick: () => {
              theme.toggle();
              render();
            }
          }),
          authed ? el("button", {
            type: "button",
            class: "lw-btn lw-btn-sm",
            disabled: state.busy,
            text: "\u9501\u5B9A\u9000\u51FA",
            onClick: handleLogout
          }) : null
        ])
      ])
    ]);
  }
  function renderSidebar() {
    const pendingCount = state.snapshot?.approvals?.pendingCount || 0;
    const panelsCount = state.snapshot?.panels?.length || 0;
    const mcpCount = state.snapshot?.mcpServers?.serverCount || 0;
    const cacheMissing = state.fencingData?.cache?.status && state.fencingData.cache.status !== "fresh";
    const enabledToolsCount = (state.snapshot?.capabilities?.effectiveTools || []).filter((t) => t.enabled).length;
    const persistence = state.auth?.sessionPersistence || "tab";
    const groups = [
      {
        title: "\u8FD0\u884C\u603B\u89C8",
        items: [
          { id: "overview", label: "\u7CFB\u7EDF\u6982\u89C8", icon: "home" }
        ]
      },
      {
        title: "\u5B89\u5168\u4E0E\u6CBB\u7406",
        items: [
          { id: "approvals", label: "\u5F85\u5BA1\u5BA1\u6279\u961F\u5217", icon: "clipboardCheck", badge: pendingCount > 0 ? String(pendingCount) : "", warn: pendingCount > 0 },
          { id: "capabilities", label: "\u80FD\u529B\u5F00\u5173\u4E0E\u670D\u52A1", icon: "sliders" },
          { id: "fencing", label: "Agent \u5B89\u5168\u56F4\u680F", icon: "shield", badge: mcpCount > 0 ? String(mcpCount) : cacheMissing ? "!" : "", warn: Boolean(cacheMissing) },
          { id: "moderation", label: "LLM \u5BA1\u67E5\u7B56\u7565", icon: "shieldCheck" },
          { id: "secrets", label: "\u63D2\u4EF6\u5BC6\u94A5\u5E93", icon: "key" }
        ]
      },
      {
        title: "\u6269\u5C55\u4E0E\u89C2\u6D4B",
        items: [
          { id: "tools", label: "API \u63A5\u53E3\u5DE5\u4F5C\u53F0", icon: "code", badge: enabledToolsCount > 0 ? String(enabledToolsCount) : "" },
          { id: "panels", label: "\u58F0\u660E\u5F0F\u6269\u5C55\u9762\u677F", icon: "layoutPanel", badge: String(panelsCount) },
          { id: "audit", label: "\u5B9E\u65F6\u5BA1\u8BA1\u901A\u9053", icon: "activity" }
        ]
      }
    ];
    return el("aside", {
      class: `lw-sidebar ${state.mobileNavOpen ? "open" : ""}`,
      "aria-label": "\u63A7\u5236\u53F0\u4FA7\u8FB9\u5BFC\u822A"
    }, [
      el("nav", { class: "lw-sidebar-nav" }, groups.map((group) => el("div", { class: "lw-nav-group" }, [
        el("div", { class: "lw-nav-group-title", text: group.title }),
        ...group.items.map((item) => el("button", {
          type: "button",
          class: `lw-nav-item ${state.page === item.id ? "active" : ""}`,
          "data-nav-id": item.id,
          "aria-current": state.page === item.id ? "page" : "false",
          onClick: () => navigate(item.id)
        }, [
          el("span", { class: "lw-nav-left" }, [
            makeIcon(item.icon),
            el("span", { text: item.label })
          ]),
          item.badge ? el("span", { class: `lw-nav-badge ${item.warn ? "lw-nav-badge-warn" : ""}`, text: item.badge }) : null
        ]))
      ]))),
      el("div", { class: "lw-sidebar-footer" }, [
        el("div", { class: "lw-row lw-between" }, [
          el("span", { class: "lw-sidebar-meta", text: "KernelGuard" }),
          el("span", { class: "lw-pill lw-pill-ok", text: "\u5DF2\u9501\u5B9A" })
        ]),
        el("div", { class: "lw-sidebar-meta", text: `\u4F1A\u8BDD\u7B56\u7565\uFF1A${persistence === "tab" ? "\u6807\u7B7E\u9875\u9694\u79BB" : "\u6D4F\u89C8\u5668\u4F1A\u8BDD"}` })
      ])
    ]);
  }
  function renderAuthGate() {
    const auth = state.auth || {};
    const needPasskey = Boolean(
      auth.passkeyRequired || auth.requirePasskey || auth.mode === "passkey" || auth.hostPasskeySupported || auth.passkeyCount > 0 || auth.passkeys?.length > 0
    );
    const pwInput = el("input", {
      type: "password",
      class: "lw-input",
      value: state.draftAuth.password,
      placeholder: "\u8F93\u5165\u672C\u673A\u5F3A\u5BC6\u7801\uFF08\u226514 \u4F4D\uFF09",
      autocomplete: "current-password",
      onInput: (e) => {
        state.draftAuth.password = e.target.value;
      }
    });
    const ticketInput = el("input", {
      type: "text",
      class: "lw-input lw-mono",
      value: state.draftAuth.setupToken,
      placeholder: "\u7EC8\u7AEF webui-auth init \u7B7E\u53D1\u7684\u4E00\u6B21\u6027 setupToken",
      onInput: (e) => {
        state.draftAuth.setupToken = e.target.value;
      }
    });
    const labelInput = el("input", {
      type: "text",
      class: "lw-input",
      value: state.draftAuth.passkeyLabel,
      placeholder: "PassKey \u5907\u6CE8\u540D\u79F0\uFF08\u5982 YubiKey / Touch ID\uFF09",
      onInput: (e) => {
        state.draftAuth.passkeyLabel = e.target.value;
      }
    });
    const body = [];
    if (auth.previewAvailable) {
      body.push(el("div", { class: "lw-doc-callout is-info", text: "\u5F53\u524D\u8FD0\u884C\u4E8E\u672C\u5730\u56DE\u73AF\u9884\u89C8\u73AF\u5883\uFF0C\u65E0\u9700\u7EC8\u7AEF\u521D\u59CB\u5316\u5F15\u5BFC\u7801\u5373\u53EF\u76F4\u63A5\u8FDB\u5165\u63A7\u5236\u53F0\uFF0C\u4ECD\u4FDD\u6301\u540C\u6E90 CSP \u4E0E CSRF \u4FDD\u62A4\u3002" }));
      body.push(el("div", { class: "lw-row" }, [
        el("button", {
          type: "button",
          class: "lw-btn lw-btn-primary",
          disabled: state.busy,
          text: "\u4E00\u952E\u8FDB\u5165\u672C\u5730\u9884\u89C8\uFF08\u514D\u521D\u59CB\u5316\uFF09",
          onClick: () => runMutation(async () => {
            await client.api("/api/auth/preview", { method: "POST", body: {} });
            await refreshAuthState();
          })
        })
      ]));
    }
    if (!auth.initialized) {
      body.push(el("p", { class: "lw-muted", text: "\u9996\u6B21\u521D\u59CB\u5316\u987B\u5728\u672C\u673A\u7EC8\u7AEF\u6267\u884C webui-auth init \u83B7\u53D6\u4E00\u6B21\u6027 setupToken\uFF0C\u518D\u5728\u6B64\u63A7\u5236\u53F0\u5B8C\u6210\u51ED\u636E\u7ED1\u5B9A\u3002" }));
      body.push(makeField("\u4E00\u6B21\u6027\u521D\u59CB\u5316\u5F15\u5BFC\u7801 (setupToken)", ticketInput));
      if (needPasskey) {
        body.push(makeField("PassKey \u5907\u6CE8\u540D\u79F0", labelInput));
        body.push(el("div", { class: "lw-row" }, [
          el("button", {
            type: "button",
            class: "lw-btn lw-btn-trust",
            disabled: state.busy,
            text: "\u4F7F\u7528 PassKey \u5B8C\u6210\u521D\u59CB\u5316",
            onClick: () => handlePasskeyEnroll(state.draftAuth.setupToken.trim(), state.draftAuth.passkeyLabel.trim())
          })
        ]));
      } else {
        body.push(makeField("\u8BBE\u7F6E\u5F3A\u5BC6\u7801\uFF08\u226514 \u4F4D\uFF09", pwInput));
        body.push(el("div", { class: "lw-row" }, [
          el("button", {
            type: "button",
            class: "lw-btn lw-btn-trust",
            disabled: state.busy,
            text: "\u914D\u7F6E\u5F3A\u5BC6\u7801\u5E76\u89E3\u9501",
            onClick: () => runMutation(async () => {
              await client.api("/api/auth/setup/password", {
                method: "POST",
                body: { setupToken: state.draftAuth.setupToken.trim(), password: state.draftAuth.password }
              });
              state.draftAuth = { setupToken: "", password: "", passkeyLabel: "" };
              await refreshAuthState();
            })
          }),
          el("button", {
            type: "button",
            class: "lw-btn",
            disabled: state.busy,
            text: "\u6539\u7528 PassKey \u521D\u59CB\u5316",
            onClick: () => handlePasskeyEnroll(state.draftAuth.setupToken.trim(), "Local PassKey")
          })
        ]));
      }
    } else if (needPasskey) {
      body.push(el("p", { class: "lw-muted", text: "\u672C\u673A\u5DF2\u542F\u7528\u5F3A\u5236 PassKey\uFF08WebAuthn\uFF09\u9A8C\u8BC1\uFF0C\u8BF7\u901A\u8FC7\u7ED1\u5B9A\u786C\u4EF6\u5BC6\u94A5\u6216\u7CFB\u7EDF\u901A\u884C\u5BC6\u94A5\u89E3\u9501\u3002" }));
      body.push(el("div", { class: "lw-row" }, [
        el("button", {
          type: "button",
          class: "lw-btn lw-btn-trust",
          disabled: state.busy,
          text: "\u4F7F\u7528 PassKey \u89E3\u9501\u63A7\u5236\u53F0",
          onClick: handlePasskeyLogin
        })
      ]));
    } else {
      body.push(makeField("\u672C\u673A\u7BA1\u7406\u5BC6\u7801", pwInput));
      body.push(el("div", { class: "lw-row" }, [
        el("button", {
          type: "button",
          class: "lw-btn lw-btn-trust",
          disabled: state.busy,
          text: "\u9A8C\u8BC1\u5F3A\u5BC6\u7801\u89E3\u9501",
          onClick: () => runMutation(async () => {
            await client.api("/api/auth/login/password", {
              method: "POST",
              body: { password: state.draftAuth.password }
            });
            state.draftAuth.password = "";
            await refreshAuthState();
          })
        })
      ]));
    }
    return el("section", { class: "lw-card lw-auth-shell" }, [
      el("div", { class: "lw-card-head" }, [
        el("div", {}, [
          el("h2", { text: "\u63A7\u5236\u53F0\u8EAB\u4EFD\u9A8C\u8BC1" }),
          el("p", { class: "lw-muted", text: "\u4EC5\u76D1\u542C\u672C\u673A\u56DE\u73AF\u5730\u5740\uFF0C\u878D\u5408 PassKey / \u5F3A\u5BC6\u7801\u9274\u6743\u3001\u6807\u7B7E\u9875\u4EE4\u724C\u9694\u79BB\u4E0E\u4E25\u683C\u540C\u6E90 CSP\u3002" })
        ]),
        el("span", { class: "lw-pill lw-pill-warn", text: auth.initialized ? "\u5DF2\u9501\u5B9A" : "\u5F85\u521D\u59CB\u5316" })
      ]),
      el("div", { class: "lw-auth-form" }, body)
    ]);
  }
  function renderOverviewPage() {
    const snap = state.snapshot || {};
    const daemon = snap.daemon || {};
    const cap = snap.capabilities || {};
    const kernel = snap.kernel || { roots: [], units: [] };
    const panels = snap.panels || [];
    const pending = snap.approvals?.pendingCount || 0;
    const modCfg = state.moderationConfig || DEFAULT_MOD_CONFIG;
    const mountRw = cap.mountMode === "readwrite" || Boolean(cap.fileWrite);
    const modCloudLive = Boolean(modCfg.cloudOptIn && (modCfg.mode === "cloud-first" || modCfg.mode === "hybrid-tiered"));
    const totalSecretKeys = (state.pluginSecretUnits || []).reduce((acc, u) => acc + (u?.keys?.length || 0), 0);
    const ollamaModelsCount = Array.isArray(state.ollama?.models) ? state.ollama.models.length : 0;
    const navLinkBtn = (label, pageId, icon = "arrowRight") => makeIconButton({
      text: label,
      iconName: icon,
      className: "lw-btn lw-btn-sm",
      onClick: () => navigate(pageId)
    });
    const topologySvg = svgEl("svg", {
      viewBox: "0 0 356 312",
      class: "lw-svg-diagram",
      role: "img",
      "aria-label": "LoomWard \u7CFB\u7EDF\u5B9E\u65F6\u5B89\u5168\u62D3\u6251\u56FE"
    }, [
      svgEl("path", {
        d: "M 156 34 L 196 34",
        class: `lw-svg-wire ${daemon.online ? "lw-svg-wire-active" : "lw-svg-wire-off"}`
      }),
      svgEl("path", {
        d: "M 273 58 C 273 78, 178 72, 178 92",
        class: "lw-svg-wire lw-svg-wire-active"
      }),
      svgEl("path", {
        d: "M 178 138 C 178 164, 60 158, 60 186",
        class: `lw-svg-wire ${mountRw || cap.allowExec ? "lw-svg-wire-warn" : "lw-svg-wire-active"}`
      }),
      svgEl("path", {
        d: "M 178 138 L 178 186",
        class: `lw-svg-wire ${modCloudLive ? "lw-svg-wire-warn" : "lw-svg-wire-active"}`
      }),
      svgEl("path", {
        d: "M 178 138 C 178 164, 296 158, 296 186",
        class: `lw-svg-wire ${(kernel.units || []).length > 0 ? "lw-svg-wire-active" : "lw-svg-wire-off"}`
      }),
      svgNodeBox({
        x: 8,
        y: 10,
        w: 148,
        h: 48,
        title: "1. \u4E91\u7AEF OAuth \u4E2D\u7EE7",
        sub: daemon.online ? "WSS / SSE \u5DF2\u8FDE\u63A5" : "\u672C\u5730\u9884\u89C8\u5F85\u547D",
        stateCls: daemon.online ? "is-ok" : "is-active"
      }),
      svgNodeBox({
        x: 198,
        y: 10,
        w: 150,
        h: 48,
        title: "2. \u5BBF\u4E3B\u5BA1\u6279\u67A2\u7EBD",
        sub: pending > 0 ? `${pending} \u6761\u5F85\u4EBA\u5DE5\u590D\u6838` : "24h \u9632\u91CD\u653E\u5DF2\u5C31\u7EEA",
        stateCls: pending > 0 ? "is-warn" : "is-ok",
        isDelta: pending > 0
      }),
      svgNodeBox({
        x: 58,
        y: 92,
        w: 240,
        h: 46,
        title: "3. \u62A4\u680F\u5BA1\u67E5\u94FE (antileak \u2192 mod)",
        sub: `\u6A21\u5F0F: ${modCfg.mode} \xB7 ${modCloudLive ? modCfg.cloudProvider : "\u96F6\u5916\u90E8\u5916\u53D1"}`,
        stateCls: modCloudLive ? "is-warn" : "is-active"
      }),
      svgNodeBox({
        x: 6,
        y: 186,
        w: 108,
        h: 70,
        title: "Docker \u6C99\u7BB1",
        sub: `mount:${mountRw ? "rw" : "ro"}`,
        badge: cap.allowExec ? "exec \u5F00\u542F" : "exec \u7981\u7528",
        stateCls: mountRw || cap.allowExec ? "is-warn" : "is-ok",
        badgeCls: mountRw || cap.allowExec ? "is-warn" : "is-ok"
      }),
      svgNodeBox({
        x: 124,
        y: 186,
        w: 108,
        h: 70,
        title: "\u672C\u5730\u5BA1\u67E5\u6A21\u578B",
        sub: clipText(modCfg.localGuard?.model || "rules", 13),
        badge: state.ollama?.running ? `${ollamaModelsCount} Ollama \u6A21\u578B` : modCfg.localGuard?.kind || "ollama",
        stateCls: "is-active",
        badgeCls: state.ollama?.running ? "is-ok" : "is-muted"
      }),
      svgNodeBox({
        x: 242,
        y: 186,
        w: 108,
        h: 70,
        title: "\u8FDB\u7A0B\u5916\u6269\u5C55",
        sub: `${(kernel.units || []).length} \u5DF2\u6302\u8F7D`,
        badge: `${panels.length} \u58F0\u660E\u5F0F\u9762\u677F`,
        stateCls: (kernel.units || []).length > 0 ? "is-active" : "is-off",
        badgeCls: "is-muted"
      }),
      svgEl("path", { d: "M 178 256 L 178 268", class: "lw-svg-wire lw-svg-wire-active" }),
      svgEl("path", { d: "M 296 256 L 296 268", class: "lw-svg-wire lw-svg-wire-active" }),
      svgNodeBox({
        x: 6,
        y: 268,
        w: 344,
        h: 36,
        title: `KernelGuard \u51ED\u636E\u9694\u79BB \xB7 ${totalSecretKeys} \u9879\u53EA\u5199\u5BC6\u94A5`,
        sub: "",
        stateCls: "is-ok"
      })
    ]);
    const overviewSplit = el("div", { class: "lw-doc-split" }, [
      el("div", { class: "lw-doc-main" }, [
        pending > 0 ? el("div", { class: "lw-doc-callout is-warn" }, [
          el("div", { class: "lw-row lw-between" }, [
            el("span", { text: `\u5F53\u524D\u6709 ${pending} \u6761\u654F\u611F\u5DE5\u5177\u8C03\u7528\u7B49\u5F85\u672C\u673A\u4EBA\u5DE5\u667A\u80FD\u53C2\u6570\u590D\u6838\uFF0C\u786E\u8BA4\u4E00\u81F4\u540E\u624D\u4F1A\u7B7E\u53D1\u5355\u6B21\u6267\u884C\u8BB8\u53EF\u3002` }),
            makeIconButton({
              text: "\u524D\u5F80\u5BA1\u6279\u961F\u5217",
              iconName: "clipboardCheck",
              className: "lw-btn lw-btn-trust lw-btn-sm",
              onClick: () => navigate("approvals")
            })
          ])
        ]) : null,
        makeStatStrip([
          { icon: "cloud", label: "\u4E91\u7AEF\u4E2D\u7EE7", value: daemon.online ? "WSS \u5728\u7EBF" : "\u672C\u5730\u5F85\u547D", tone: daemon.online ? "ok" : "" },
          { icon: "lock", label: "\u5DE5\u4F5C\u533A\u6302\u8F7D", value: mountRw ? "\u8BFB\u5199\u5F00\u653E (:rw)" : "\u53EA\u8BFB\u9501\u5B9A (:ro)", tone: mountRw ? "warn" : "ok" },
          { icon: "layers", label: "\u5FAE\u5185\u6838\u88C5\u914D", value: `${kernel.roots?.length || 0} \u6839 / ${kernel.units?.length || 0} \u6269\u5C55` },
          { icon: "shieldCheck", label: "\u5185\u5BB9\u5BA1\u67E5", value: `${modCfg.mode}`, tone: modCloudLive ? "warn" : "ok" }
        ]),
        el("section", { class: "lw-section" }, [
          el("div", { class: "lw-section-head" }, [
            el("div", {}, [
              el("h3", { text: "\u5B9E\u65F6\u5B89\u5168\u9632\u7EBF\u4E0E\u80FD\u529B\u603B\u89C8" }),
              el("p", { text: "\u4EE5\u4E0B\u5F00\u5173\u4E0E\u7B56\u7565\u5B9E\u65F6\u70ED\u751F\u6548\u4E8E\u53D7\u9650 Docker \u5BB9\u5668\u4E0E\u8FDB\u7A0B\u5916\u5BA1\u67E5\u7BA1\u7EBF\u3002" })
            ]),
            navLinkBtn("\u914D\u7F6E\u80FD\u529B\u5F00\u5173", "capabilities", "sliders")
          ]),
          el("div", { class: "lw-setting-list" }, [
            el("div", { class: "lw-hairline-row" }, [
              el("span", { class: "lw-switch-main" }, [
                makeIcon("file"),
                el("span", { class: "lw-switch-copy" }, [
                  el("span", { class: "lw-switch-label", text: "\u6587\u4EF6\u8BFB\u53D6\u4E0E\u68C0\u7D22 (fileRead)" }),
                  el("span", { class: "lw-switch-sub", text: "read_file / list_directory / search_files" })
                ])
              ]),
              el("span", { class: `lw-pill ${cap.fileRead ? "lw-pill-ok" : "lw-pill-err"}`, text: cap.fileRead ? "\u5DF2\u542F\u7528" : "\u5DF2\u7194\u65AD\u62E6\u622A" })
            ]),
            el("div", { class: "lw-hairline-row" }, [
              el("span", { class: "lw-switch-main" }, [
                makeIcon("lock"),
                el("span", { class: "lw-switch-copy" }, [
                  el("span", { class: "lw-switch-label", text: "\u5DE5\u4F5C\u533A\u5199\u5165 (fileWrite)" }),
                  el("span", { class: "lw-switch-sub", text: "\u5173\u95ED\u65F6\u5BB9\u5668\u5F3A\u5236\u964D\u7EA7\u4E3A\u53EA\u8BFB\u6302\u8F7D :ro" })
                ])
              ]),
              el("span", { class: `lw-pill ${cap.fileWrite ? "lw-pill-warn" : "lw-pill-ok"}`, text: cap.fileWrite ? "\u8BFB\u5199\u5F00\u653E (:rw)" : "\u53EA\u8BFB\u4FDD\u62A4\u4E2D (:ro)" })
            ]),
            el("div", { class: "lw-hairline-row" }, [
              el("span", { class: "lw-switch-main" }, [
                makeIcon("terminal"),
                el("span", { class: "lw-switch-copy" }, [
                  el("span", { class: "lw-switch-label", text: "\u5BB9\u5668\u547D\u4EE4\u884C (allowExec)" }),
                  el("span", { class: "lw-switch-sub", text: "\u4E00\u6B21\u6027\u65E0\u5165\u7AD9 Linux \u5BB9\u5668\u6267\u884C\u6743\u9650" })
                ])
              ]),
              el("span", { class: `lw-pill ${cap.allowExec ? "lw-pill-warn" : "lw-pill-ok"}`, text: cap.allowExec ? "\u5DF2\u542F\u7528" : "\u5DF2\u7981\u7528" })
            ]),
            el("div", { class: "lw-hairline-row" }, [
              el("span", { class: "lw-switch-main" }, [
                makeIcon("shieldCheck"),
                el("span", { class: "lw-switch-copy" }, [
                  el("span", { class: "lw-switch-label", text: `\u591A\u6A21\u6001 LLM \u5BA1\u67E5 (${modCfg.mode})` }),
                  el("span", { class: "lw-switch-sub", text: `\u56DE\u9000\u9884\u8BBE: ${modCfg.policyProfile} \xB7 Guard: ${modCfg.localGuard?.model || "rules"}` })
                ])
              ]),
              el("div", { class: "lw-row" }, [
                el("span", { class: `lw-pill ${modCloudLive ? "lw-pill-warn" : "lw-pill-ok"}`, text: modCloudLive ? `\u4E91\u7AEF ${modCfg.cloudProvider}` : "\u4EC5\u672C\u5730\u95ED\u73AF" }),
                navLinkBtn("\u8C03\u6574\u7B56\u7565", "moderation", "shieldCheck")
              ])
            ])
          ])
        ]),
        el("section", { class: "lw-section" }, [
          el("div", { class: "lw-section-head" }, [
            el("div", {}, [
              el("h3", { text: "Cordis \u5FAE\u5185\u6838\u88C5\u914D\u4E0E\u6269\u5C55\u5355\u5143" }),
              el("p", { text: "\u6839\u63D2\u4EF6\u8FD0\u884C\u4E8E\u51BB\u7ED3\u7269\u7406\u76EE\u5F55\uFF08RPM\uFF09\uFF1B\u7B2C\u4E09\u65B9\u4E0E\u591A\u8BED\u8A00\u63D2\u4EF6\u7ECF\u8FDB\u7A0B\u5916\u8FB9\u754C\u63A5\u5165\u3002" })
            ]),
            panels.length ? navLinkBtn(`\u67E5\u770B\u6269\u5C55\u9762\u677F (${panels.length})`, "panels", "layoutPanel") : null
          ]),
          el("div", { class: "lw-setting-list" }, [
            el("div", { class: "lw-hairline-row" }, [
              el("span", { class: "lw-switch-label", text: "\u51BB\u7ED3\u6839\u63D2\u4EF6 (RPM)" }),
              el("div", { class: "lw-row" }, (kernel.roots || []).map((r) => el("span", { class: "lw-pill lw-pill-info lw-mono", text: r.id || r })))
            ]),
            el("div", { class: "lw-hairline-row" }, [
              el("span", { class: "lw-switch-label", text: "\u8FDB\u7A0B\u5916\u6269\u5C55\u5355\u5143 (out-of-process)" }),
              el("div", { class: "lw-row" }, (kernel.units || []).length ? kernel.units.map((u) => el("span", { class: "lw-pill lw-pill-ok lw-mono", text: u.id || u })) : [el("span", { class: "lw-muted", text: "\u65E0\u5DF2\u6302\u8F7D\u6269\u5C55\u5355\u5143" })])
            ]),
            el("div", { class: "lw-hairline-row" }, [
              el("span", { class: "lw-switch-label", text: "\u53EA\u5199\u51ED\u636E\u547D\u540D\u7A7A\u95F4" }),
              el("div", { class: "lw-row" }, [
                el("span", { class: "lw-pill lw-pill-info", text: `${(state.pluginSecretUnits || []).length} \u5355\u5143 / ${totalSecretKeys} \u5BC6\u94A5` }),
                navLinkBtn("\u7BA1\u7406\u5BC6\u94A5", "secrets", "key")
              ])
            ])
          ])
        ])
      ]),
      el("aside", { class: "lw-doc-aside" }, [
        el("div", { class: "lw-section-head" }, [
          el("div", {}, [
            el("h3", { text: "\u7CFB\u7EDF\u8FD0\u884C\u62D3\u6251\u6001" }),
            el("p", { text: "\u5B9E\u65F6\u6C47\u603B\u5F53\u524D\u6743\u9650\u5F00\u5173\u3001\u5BA1\u67E5\u94FE\u4E0E\u6269\u5C55\u8FB9\u754C" })
          ]),
          el("span", { class: `lw-pill ${pending > 0 || mountRw ? "lw-pill-warn" : "lw-pill-ok"}`, text: pending > 0 ? `${pending} \u5F85\u5BA1` : "\u53D7\u63A7\u6001" })
        ]),
        topologySvg,
        el("div", { class: "lw-aside-list" }, [
          el("div", { class: "lw-aside-row" }, [
            el("span", { class: "lw-muted", text: "SSE \u5B9E\u65F6\u901A\u9053" }),
            el("strong", { text: state.sseStatus === "open" || state.sseStatus === "connected" ? "\u5728\u7EBF\u63A8\u6D41\u4E2D" : state.sseStatus })
          ]),
          el("div", { class: "lw-aside-row" }, [
            el("span", { class: "lw-muted", text: "\u4F1A\u8BDD\u9694\u79BB\u673A\u5236" }),
            el("strong", { text: (state.auth?.sessionPersistence || "tab") === "tab" ? "\u6807\u7B7E\u9875\u4EE4\u724C\u9694\u79BB" : "\u6D4F\u89C8\u5668\u4F1A\u8BDD" })
          ]),
          el("div", { class: "lw-aside-row" }, [
            el("span", { class: "lw-muted", text: "\u805A\u5408\u5DE5\u5177\u5165\u53E3" }),
            el("strong", { text: `${(cap.effectiveTools || []).length} \u9879\u5DE5\u5177` })
          ])
        ])
      ])
    ]);
    return el("div", { class: "lw-stack-md" }, [
      makePageHeader("\u7CFB\u7EDF\u6982\u89C8", "\u6C47\u603B\u672C\u5730\u5B88\u62A4\u8FDB\u7A0B\u3001\u5DE5\u4F5C\u533A\u6302\u8F7D\u59FF\u6001\u3001\u5FAE\u5185\u6838\u88C5\u914D\u6E05\u5355\u4E0E\u5185\u5BB9\u5B89\u5168\u7BA1\u7EBF\u72B6\u6001\u3002"),
      overviewSplit
    ]);
  }
  function renderApprovalsPage() {
    const items = state.snapshot?.approvals?.items || [];
    const approvalFlowSvg = svgEl("svg", {
      viewBox: "0 0 356 286",
      class: "lw-svg-diagram",
      role: "img",
      "aria-label": "\u4E24\u6B65\u4EBA\u5DE5\u5BA1\u6279\u4E0E\u5355\u6B21\u6D88\u8D39\u9632\u91CD\u653E\u72B6\u6001\u673A"
    }, [
      svgEl("path", { d: "M 178 54 L 178 78", class: "lw-svg-wire lw-svg-wire-active" }),
      svgEl("path", { d: "M 178 138 L 178 162", class: `lw-svg-wire ${items.length > 0 ? "lw-svg-wire-warn" : "lw-svg-wire-active"}` }),
      svgEl("path", { d: "M 178 214 L 178 236", class: "lw-svg-wire lw-svg-wire-active" }),
      svgNodeBox({
        x: 24,
        y: 8,
        w: 308,
        h: 46,
        title: "1. \u51BB\u7ED3\u8BF7\u6C42\u4E0E policyDigest \u7ED1\u5B9A",
        sub: "\u5B8C\u6574\u5DE5\u5177\u540D + \u53C2\u6570 + cwd + \u8D85\u65F6\u7ED1\u5B9A\u6458\u8981",
        stateCls: "is-active"
      }),
      svgNodeBox({
        x: 24,
        y: 78,
        w: 308,
        h: 60,
        title: "2. \u5F85\u672C\u673A\u4EBA\u5DE5\u9010\u53C2\u590D\u6838\u961F\u5217",
        sub: items.length > 0 ? `\u5F53\u524D ${items.length} \u6761\u8BF7\u6C42\u7B49\u5F85\u6838\u5BF9\u672A\u8131\u654F\u53C2\u6570` : "\u961F\u5217\u7A7A\u95F2\uFF08\u65B0\u8BF7\u6C42\u7ECF SSE \u5373\u65F6\u63A8\u9001\uFF09",
        badge: items.length > 0 ? "\u70B9\u51FB\u5DE6\u4FA7\u300C\u590D\u6838\u5B8C\u6574\u53C2\u6570\u300D" : "5 \u5206\u949F\u672A\u5904\u7406\u81EA\u52A8\u6E05\u7406",
        stateCls: items.length > 0 ? "is-warn" : "is-ok",
        badgeCls: items.length > 0 ? "is-warn" : "is-muted",
        isDelta: items.length > 0
      }),
      svgNodeBox({
        x: 24,
        y: 162,
        w: 308,
        h: 52,
        title: "3. \u4EBA\u5DE5\u6BD4\u5BF9\u4E00\u81F4\u5E76\u7B7E\u53D1\u5355\u6B21\u51ED\u8BC1",
        sub: "\u4EC5\u9650\u5F53\u524D\u7CBE\u786E id + digest\uFF0C\u4E0D\u81EA\u52A8\u6269\u5C55\u6743\u9650",
        stateCls: "is-active"
      }),
      svgNodeBox({
        x: 24,
        y: 236,
        w: 308,
        h: 42,
        title: "4. \u6C99\u7BB1/\u6269\u5C55\u6267\u884C + 24h \u9632\u91CD\u653E\u767B\u8BB0",
        sub: "\u540C\u4E00\u51ED\u8BC1\u4E25\u7981\u4E8C\u6B21\u91CD\u653E\u6216\u5E76\u53D1\u6D88\u8D39",
        stateCls: "is-ok"
      })
    ]);
    const queueContent = items.length ? el("div", { class: "lw-setting-list" }, items.map((item) => {
      const leftSec = Math.max(0, Math.ceil((Date.parse(item.expiresAt) - Date.now()) / 1e3));
      const pct = Math.max(0, Math.min(100, Math.round(leftSec / 300 * 100)));
      const boundary = classifyToolBoundary(item.tool, item.tool?.startsWith("mcp__"));
      return el("div", { class: "lw-approval-row" }, [
        el("div", { class: "lw-approval-main" }, [
          el("div", { class: "lw-row" }, [
            makeIcon(boundary.icon),
            el("strong", { class: "lw-mono", text: `${item.tool} \xB7 #${item.idShort}` }),
            el("span", { class: `lw-pill lw-pill-${boundary.tone}`, text: boundary.label }),
            el("span", {
              class: `lw-pill ${leftSec <= 30 ? "lw-pill-err" : "lw-pill-warn"}`,
              "data-countdown-expires": item.expiresAt,
              "data-warn-threshold": "30",
              text: `\u5269\u4F59 ${leftSec}s`
            })
          ]),
          el("div", { class: "lw-muted lw-mono", text: `client=${item.clientId || "unknown"} \xB7 ${item.alreadyApproved ? "\u5DF2\u7B7E\u53D1\u5355\u6B21\u8BB8\u53EF\uFF08\u7B49\u5F85\u8FDE\u63A5\u5668\u6D88\u8D39\uFF09" : "\u7B49\u5F85\u70B9\u51FB\u590D\u6838\u5B8C\u6574\u672A\u8131\u654F\u53C2\u6570"}` }),
          el("div", { class: "lw-progress-track", style: "max-width:320px" }, [
            el("div", { class: "lw-progress-bar", style: `width:${pct}%` })
          ])
        ]),
        el("div", { class: "lw-btn-group" }, [
          item.approvable ? makeIconButton({
            text: "\u590D\u6838\u5B8C\u6574\u53C2\u6570",
            iconName: "eye",
            className: "lw-btn lw-btn-trust lw-btn-sm",
            disabled: state.busy || leftSec <= 0,
            attrs: { "data-countdown-disable-expires": item.expiresAt },
            onClick: () => runMutation(async () => {
              const review = await client.api("/api/approvals/review", { method: "POST", body: { id: item.id } });
              state.reviewModal = { ...review, tool: item.tool, expiresAt: item.expiresAt };
            })
          }) : null,
          item.id ? makeIconButton({
            text: "\u62D2\u7EDD\u5E76\u79FB\u9664",
            iconName: "stop",
            className: "lw-btn lw-btn-danger lw-btn-sm",
            disabled: state.busy,
            onClick: () => runMutation(async () => {
              const res = await client.api("/api/approvals/reject", { method: "POST", body: { id: item.id } });
              if (res.snapshot) state.snapshot = res.snapshot;
              setNotice(`\u5DF2\u62D2\u7EDD\u8BF7\u6C42 #${item.idShort}\u3002`);
            })
          }) : null
        ])
      ]);
    })) : el("div", { class: "lw-doc-callout is-ok" }, [
      el("div", { text: "\u5F53\u524D\u65E0\u5F85\u4EBA\u5DE5\u6279\u51C6\u7684\u5DE5\u5177\u8BF7\u6C42\u3002\u4EFB\u4F55\u9700\u8981\u672C\u673A\u6279\u51C6\u7684\u654F\u611F\u64CD\u4F5C\u89E6\u53D1\u65F6\uFF0C\u90FD\u5C06\u7ECF SSE \u5B9E\u65F6\u63A8\u9001\u5230\u6B64\u961F\u5217\u3002" })
    ]);
    const splitLayout = el("div", { class: "lw-doc-split" }, [
      el("div", { class: "lw-doc-main" }, [
        makeStatStrip([
          { icon: "clipboardCheck", label: "\u5F85\u5BA1\u8BF7\u6C42", value: `${items.length} \u6761`, tone: items.length > 0 ? "warn" : "ok" },
          { icon: "lock", label: "\u6279\u51C6\u7C92\u5EA6", value: "\u5168\u53C2\u6458\u8981\u7CBE\u786E\u7ED1\u5B9A" },
          { icon: "shieldCheck", label: "\u6D88\u8D39\u7EA6\u675F", value: "\u5355\u6B21 + 24h \u9632\u91CD\u653E" },
          { icon: "clock", label: "\u8BF7\u6C42\u8D85\u65F6", value: "5 \u5206\u949F\u81EA\u52A8\u6E05\u7406" }
        ]),
        el("section", { class: "lw-section" }, [
          el("div", { class: "lw-section-head" }, [
            el("div", {}, [
              el("h3", { text: "\u5B9E\u65F6\u5F85\u6279\u8BF7\u6C42\u961F\u5217" }),
              el("p", { text: "\u70B9\u51FB\u300C\u590D\u6838\u5B8C\u6574\u53C2\u6570\u300D\u67E5\u770B\u539F\u59CB\u672A\u8131\u654F\u8BF7\u6C42\u6587\u672C\u4E0E policyDigest\uFF0C\u518D\u51B3\u5B9A\u662F\u5426\u653E\u884C\u4E00\u6B21\u3002" })
            ]),
            el("span", { class: `lw-pill ${items.length ? "lw-pill-warn" : "lw-pill-ok"}`, text: `${items.length} \u6761\u5F85\u5BA1` })
          ]),
          queueContent
        ])
      ]),
      el("aside", { class: "lw-doc-aside" }, [
        el("div", { class: "lw-section-head" }, [
          el("div", {}, [
            el("h3", { text: "\u4EBA\u5DE5\u5BA1\u6279\u72B6\u6001\u673A" }),
            el("p", { text: "\u7981\u6B62\u4EE5\u4E91\u7AEF\u8EAB\u4EFD\u6821\u9A8C\u66FF\u4EE3\u672C\u673A\u7CBE\u786E\u653E\u884C" })
          ]),
          el("span", { class: `lw-pill ${items.length > 0 ? "lw-pill-warn" : "lw-pill-ok"}`, text: items.length > 0 ? "\u7B49\u5F85\u6279\u590D" : "\u7A7A\u95F2\u5C31\u7EEA" })
        ]),
        approvalFlowSvg,
        el("div", { class: "lw-aside-list" }, [
          el("div", { class: "lw-aside-row" }, [
            el("span", { class: "lw-muted", text: "\u53C2\u6570\u53EF\u89C1\u6027" }),
            el("strong", { text: "\u590D\u6838\u5F39\u7A97\u5B8C\u6574\u4E0D\u8131\u654F" })
          ]),
          el("div", { class: "lw-aside-row" }, [
            el("span", { class: "lw-muted", text: "\u5199\u64CD\u4F5C\u65AD\u8FDE" }),
            el("strong", { text: "\u8D85\u65F6/\u53D6\u6D88\u7EDD\u4E0D\u81EA\u52A8\u91CD\u8BD5" })
          ]),
          el("div", { class: "lw-aside-row" }, [
            el("span", { class: "lw-muted", text: "\u591A\u6807\u7B7E\u7ADE\u4E89" }),
            el("strong", { text: "\u5355\u6B21\u539F\u5B50\u7B7E\u53D1\u4E0E\u6D88\u8D39" })
          ])
        ])
      ])
    ]);
    return el("div", { class: "lw-stack-md" }, [
      makePageHeader("\u5F85\u5BA1\u5BA1\u6279\u961F\u5217", "\u5BF9\u654F\u611F\u5DE5\u5177\u8C03\u7528\u6838\u5BF9\u5B8C\u6574\u672A\u8131\u654F\u53C2\u6570\u4E0E policyDigest\uFF0C\u6279\u51C6\u540E\u4EC5\u5355\u6B21\u6D88\u8D39\u5E76\u767B\u8BB0 24h \u9632\u91CD\u653E\u8D26\u672C\u3002"),
      splitLayout
    ]);
  }
  function renderCapabilitiesPage() {
    const cap = state.snapshot?.capabilities || {};
    const persistence = state.auth?.sessionPersistence || "tab";
    const mountRw = cap.mountMode === "readwrite" || Boolean(cap.fileWrite);
    const updateCap = (label, field, nextVal) => runMutation(async () => {
      const res = await client.api("/api/capabilities", { method: "POST", body: { [field]: nextVal } });
      if (res.snapshot) state.snapshot = res.snapshot;
      setNotice(`\u5DF2\u66F4\u65B0\u80FD\u529B\u5F00\u5173\uFF1A${label} \u2192 ${nextVal ? "\u5F00\u542F" : "\u5173\u95ED"}\u3002`);
    });
    const serviceBtn = (label, action, iconName, danger = false) => makeIconButton({
      text: label,
      iconName,
      className: `lw-btn lw-btn-sm ${danger ? "lw-btn-danger" : ""}`,
      disabled: state.busy,
      onClick: () => runMutation(async () => {
        const res = await client.api("/api/service", { method: "POST", body: { action } });
        if (res.snapshot) state.snapshot = res.snapshot;
        setNotice(`\u670D\u52A1\u64CD\u4F5C ${action} \u5DF2\u5B8C\u6210\u3002`);
      })
    });
    const daemonOnline = Boolean(state.snapshot?.daemon?.online);
    const boundarySvg = svgEl("svg", {
      viewBox: "0 0 356 254",
      class: "lw-svg-diagram",
      role: "img",
      "aria-label": "\u5DE5\u4F5C\u533A\u6302\u8F7D\u4E0E Docker \u6C99\u7BB1\u53CA\u4F1A\u8BDD\u9694\u79BB\u8FB9\u754C\u793A\u610F\u56FE"
    }, [
      svgEl("path", {
        d: "M 148 39 L 194 39",
        class: `lw-svg-wire ${mountRw ? "lw-svg-wire-warn" : "lw-svg-wire-active"}`
      }),
      svgEl("path", { d: "M 272 68 L 272 96", class: "lw-svg-wire lw-svg-wire-active" }),
      svgEl("path", { d: "M 178 152 L 178 182", class: "lw-svg-wire lw-svg-wire-active" }),
      svgNodeBox({
        x: 8,
        y: 10,
        w: 140,
        h: 58,
        title: "\u5BBF\u4E3B\u5DE5\u4F5C\u533A",
        sub: "workspaceRoots",
        badge: mountRw ? ":rw \u8BFB\u5199\u6620\u5C04" : ":ro \u53EA\u8BFB\u6620\u5C04",
        stateCls: "is-active",
        badgeCls: mountRw ? "is-warn" : "is-ok"
      }),
      svgNodeBox({
        x: 196,
        y: 10,
        w: 152,
        h: 58,
        title: "Linux Docker \u6C99\u7BB1",
        sub: `\u8BFB:${cap.fileRead ? "ON" : "OFF"} \xB7 \u547D:${cap.allowExec ? "ON" : "OFF"}`,
        badge: cap.allowExec ? "exec \u5F00\u542F \xB7 \u9ED8\u8BA4\u65E0\u5916\u7F51" : "\u65E0\u5165\u7AD9 / \u9ED8\u8BA4\u65E0\u51FA\u7AD9",
        stateCls: mountRw || cap.allowExec ? "is-warn" : "is-ok",
        badgeCls: mountRw || cap.allowExec ? "is-warn" : "is-ok"
      }),
      svgNodeBox({
        x: 8,
        y: 96,
        w: 340,
        h: 56,
        title: "\u53D7\u4FDD\u62A4\u8FDE\u63A5\u5668\u5B88\u62A4\u8FDB\u7A0B",
        sub: daemonOnline ? "\u5DF2\u5728\u7EBF\u63A5\u5165\u4E91\u7AEF\u4E2D\u7EE7" : "\u672C\u5730\u5F85\u547D\uFF08\u70ED\u54CD\u5E94 capabilities.json\uFF09",
        badge: "\u4ECE\u53D7\u4FDD\u62A4\u5B89\u88C5\u76EE\u5F55\u8FD0\u884C \xB7 \u4E0D\u81EA\u52A8\u8986\u76D6",
        stateCls: "is-active",
        badgeCls: "is-muted"
      }),
      svgNodeBox({
        x: 8,
        y: 182,
        w: 340,
        h: 58,
        title: "\u63A7\u5236\u53F0\u6D4F\u89C8\u5668\u4F1A\u8BDD\u8BA4\u8BC1\u8FB9\u754C",
        sub: persistence === "tab" ? "X-LoomWard-Tab-Auth \u5355\u6807\u7B7E\u9875\u9694\u79BB" : "\u6D4F\u89C8\u5668\u540C\u6E90\u5171\u4EAB\u4F1A\u8BDD",
        badge: persistence === "tab" ? "\u5173\u95ED\u6807\u7B7E\u9875\u5373\u9501\u5B9A\uFF08\u63A8\u8350\uFF09" : "\u591A\u6807\u7B7E\u9875\u5171\u4EAB\u5DF2\u89E3\u9501\u6001",
        stateCls: persistence === "tab" ? "is-ok" : "is-warn",
        badgeCls: persistence === "tab" ? "is-ok" : "is-warn"
      })
    ]);
    const applyCapPreset = (label, nextBody) => runMutation(async () => {
      const res = await client.api("/api/capabilities", { method: "POST", body: nextBody });
      if (res.snapshot) state.snapshot = res.snapshot;
      setNotice(`\u5DF2\u5E94\u7528\u9884\u8BBE\u59FF\u6001\uFF1A${label}\u3002`);
    });
    const canExecConfig = state.snapshot?.sandbox?.configAllowExec !== false;
    const disabledIndivCount = (cap.effectiveTools || []).filter((t) => !t.external && t.individuallyDisabled).length;
    const splitLayout = el("div", { class: "lw-doc-split" }, [
      el("div", { class: "lw-doc-main" }, [
        makeStatStrip([
          { icon: "eye", label: "\u6587\u4EF6\u8BFB\u53D6", value: cap.fileRead ? "\u5141\u8BB8\u8BFB\u53D6" : "\u5DF2\u7194\u65AD\u62E6\u622A", tone: cap.fileRead ? "ok" : "err" },
          { icon: "lock", label: "\u5DE5\u4F5C\u533A\u6302\u8F7D", value: mountRw ? "\u8BFB\u5199\u5F00\u653E (rw)" : "\u53EA\u8BFB\u9501\u5B9A (:ro)", tone: mountRw ? "warn" : "ok" },
          { icon: "terminal", label: "\u5BB9\u5668\u547D\u4EE4", value: cap.allowExec ? "\u6C99\u7BB1\u6267\u884C\u5F00\u653E" : "\u5DF2\u5B89\u5168\u7981\u7528", tone: cap.allowExec ? "warn" : "ok" },
          { icon: "shieldCheck", label: "\u4F1A\u8BDD\u9694\u79BB", value: persistence === "tab" ? "\u6807\u7B7E\u9875\u4EE4\u724C\u9694\u79BB" : "\u6D4F\u89C8\u5668\u5171\u4EAB\u4F1A\u8BDD" }
        ]),
        el("section", { class: "lw-section" }, [
          el("div", { class: "lw-section-head" }, [
            el("div", {}, [
              el("h3", { text: "\u6838\u5FC3\u80FD\u529B\u7194\u65AD\u5F00\u5173" }),
              el("p", { text: "\u5207\u6362\u5F00\u5173\u7ACB\u5373\u539F\u5B50\u5199\u5165 <stateDir>/capabilities.json \u5E76\u751F\u6548\u4E8E\u6C99\u7BB1\u5BB9\u5668\uFF0C\u65E0\u9700\u91CD\u542F\u8FDE\u63A5\u5668\u3002" })
            ]),
            el("span", { class: `lw-pill ${mountRw ? "lw-pill-warn" : "lw-pill-ok"}`, text: `mount: ${cap.mountMode || "readonly"}` })
          ]),
          el("div", { class: "lw-btn-group" }, [
            makeIconButton({
              text: canExecConfig ? "\u5B8C\u6574\u8BFB\u5199\uFF08\u542B\u5BB9\u5668\u547D\u4EE4\uFF09" : "\u5B8C\u6574\u8BFB\u5199\uFF08\u65E0\u547D\u4EE4\u6743\u9650\uFF09",
              iconName: "bolt",
              className: `lw-btn lw-btn-sm ${cap.fileRead && cap.fileWrite && (!canExecConfig || cap.allowExec) ? "lw-btn-primary" : ""}`,
              disabled: state.busy,
              onClick: () => applyCapPreset("\u5B8C\u6574\u8BFB\u5199", { fileRead: true, fileWrite: true, ...canExecConfig ? { allowExec: true } : {} })
            }),
            makeIconButton({
              text: "\u4EC5\u53EA\u8BFB\u9501\u5B9A (:ro)",
              iconName: "eye",
              className: `lw-btn lw-btn-sm ${cap.fileRead && !cap.fileWrite && !cap.allowExec ? "lw-btn-primary" : ""}`,
              disabled: state.busy,
              onClick: () => applyCapPreset("\u4EC5\u53EA\u8BFB", { fileRead: true, fileWrite: false, allowExec: false })
            }),
            makeIconButton({
              text: "\u5168\u91CF\u9501\u5B9A\u5DE5\u4F5C\u533A\u8BFB\u5199",
              iconName: "lock",
              className: `lw-btn lw-btn-sm lw-btn-danger ${!cap.fileRead && !cap.fileWrite && !cap.allowExec ? "lw-btn-primary" : ""}`,
              disabled: state.busy,
              onClick: () => applyCapPreset("\u7981\u7528\u6587\u4EF6\u8BFB\u5199", { fileRead: false, fileWrite: false, allowExec: false })
            }),
            makeIconButton({
              text: disabledIndivCount > 0 ? `API \u5DE5\u4F5C\u53F0\uFF08\u5DF2\u5355\u5173 ${disabledIndivCount} \u9879\uFF09` : "\u5728 API \u5DE5\u4F5C\u53F0\u9010\u4E2A\u7BA1\u7406\u5DE5\u5177",
              iconName: "code",
              className: "lw-btn lw-btn-sm",
              onClick: () => navigate("tools")
            })
          ]),
          el("div", { class: "lw-setting-list" }, [
            makeSwitchCard({
              checked: Boolean(cap.fileRead),
              onChange: (next) => updateCap("\u6587\u4EF6\u8BFB\u53D6 (fileRead)", "fileRead", next),
              title: "\u6587\u4EF6\u8BFB\u53D6 (fileRead)",
              subtitle: "\u63A7\u5236 read_file / list_directory / search_files \u53CA\u5DE5\u4F5C\u533A\u8BFB\u53D6\u6743\u9650",
              pillText: cap.fileRead ? "\u5DF2\u542F\u7528" : "\u5DF2\u5173\u95ED",
              pillTone: cap.fileRead ? "ok" : "err",
              iconName: "eye",
              disabled: state.busy
            }),
            makeSwitchCard({
              checked: Boolean(cap.fileWrite),
              onChange: (next) => updateCap("\u6587\u4EF6\u5199\u5165 (fileWrite)", "fileWrite", next),
              title: "\u6587\u4EF6\u5199\u5165 (fileWrite)",
              subtitle: "\u5173\u95ED\u540E\u5F7B\u5E95\u5C01\u9501\u5199\u5165\uFF0C\u5E76\u5C06 Linux Docker /workspace \u81EA\u52A8\u964D\u7EA7\u4E3A\u53EA\u8BFB\u6302\u8F7D (:readonly)",
              pillText: cap.fileWrite ? "\u8BFB\u5199\u5F00\u653E" : "\u53EA\u8BFB\u4FDD\u62A4\u4E2D",
              pillTone: cap.fileWrite ? "warn" : "ok",
              iconName: "lock",
              disabled: state.busy
            }),
            makeSwitchCard({
              checked: Boolean(cap.allowExec),
              onChange: (next) => updateCap("\u5BB9\u5668\u547D\u4EE4 (allowExec)", "allowExec", next),
              title: "\u5BB9\u5668\u547D\u4EE4 (allowExec)",
              subtitle: "\u63A7\u5236\u4E00\u6B21\u6027\u53EA\u8BFB Linux \u5BB9\u5668\u5185 exec_command \u6267\u884C\u80FD\u529B\uFF08\u9ED8\u8BA4\u65E0\u51FA\u7AD9\u7F51\u7EDC\uFF09",
              pillText: cap.allowExec ? "\u5DF2\u542F\u7528" : "\u5DF2\u7981\u7528",
              pillTone: cap.allowExec ? "warn" : "ok",
              iconName: "terminal",
              disabled: state.busy
            })
          ]),
          el("div", { class: "lw-tool-chip-block" }, [
            el("div", { class: "lw-tool-chip-head" }, [
              el("div", { class: "lw-stack-md", style: "gap:2px" }, [
                el("strong", { text: "\u5355\u5DE5\u5177\u72EC\u7ACB\u5F00\u5173\u77E9\u9635\uFF08\u5185\u7F6E\u6C99\u7BB1 + \u7B2C\u4E09\u65B9 MCP\uFF09" }),
                el("span", { class: "lw-muted", text: "\u70B9\u51FB\u5DE6\u4FA7\u5DE5\u5177\u540D\u76F4\u8FBE API \u63A5\u53E3\u5DE5\u4F5C\u53F0\u67E5\u770B\u5951\u7EA6\uFF1B\u53F3\u4FA7\u62E8\u7247\u53EF\u9010\u9879\u5355\u72EC\u505C\u7528\u6216\u6062\u590D\u5355\u4E2A MCP \u5DE5\u5177\u3002" })
              ]),
              el("span", {
                class: "lw-pill lw-pill-info",
                text: `${(cap.effectiveTools || []).filter((t) => t.enabled).length} / ${(cap.effectiveTools || []).length} \u53EF\u7528`
              })
            ]),
            el("div", { class: "lw-tool-chip-grid" }, (cap.effectiveTools || []).map((tool) => {
              const parentOn = isToolParentEnabled(state.snapshot, tool);
              const switchDisabled = state.busy || !parentOn && !tool.individuallyDisabled;
              const sw = el("input", {
                type: "checkbox",
                class: "lw-switch-input",
                disabled: switchDisabled,
                "aria-label": `\u72EC\u7ACB\u5F00\u5173 ${tool.name}`,
                "data-cap-tool-switch": tool.name,
                onChange: (e) => {
                  void toggleSingleTool(tool, e.target.checked);
                }
              });
              sw.checked = Boolean(tool.enabled && !tool.individuallyDisabled);
              return el("div", { class: `lw-tool-chip ${tool.enabled ? "" : "is-off"}` }, [
                el("button", {
                  type: "button",
                  class: "lw-tool-chip-link",
                  title: `\u5728 API \u63A5\u53E3\u5DE5\u4F5C\u53F0\u67E5\u770B ${tool.name}\uFF08${getSingleToolStatusLabel(state.snapshot, tool)}\uFF09`,
                  onClick: () => navigate("tools", { selectedToolName: tool.name })
                }, [
                  el("span", { class: `lw-apifox-dot ${tool.enabled ? "is-ok" : "is-err"}` }),
                  el("span", { class: "lw-tool-chip-link-text" }, [
                    el("span", { class: "lw-tool-chip-name", text: tool.name }),
                    el("span", {
                      class: "lw-tool-chip-sub",
                      text: `${tool.external ? "\u5916\u90E8 MCP" : tool.kind || "MCP"} \xB7 ${getSingleToolStatusLabel(state.snapshot, tool)}`
                    })
                  ])
                ]),
                el("label", { class: "lw-switch-pill" }, [
                  sw,
                  el("span", { class: "lw-switch-track", "aria-hidden": "true" })
                ])
              ]);
            }))
          ])
        ]),
        el("section", { class: "lw-section" }, [
          el("div", { class: "lw-section-head" }, [
            el("div", {}, [
              el("h3", { text: "\u4F1A\u8BDD\u9694\u79BB\u4E0E\u5BBF\u4E3B\u5B88\u62A4\u8FDB\u7A0B\u63A7\u5236" }),
              el("p", { text: "\u9ED8\u8BA4\u542F\u7528\u6807\u7B7E\u9875\u4EE4\u724C\u9694\u79BB\uFF08X-LoomWard-Tab-Auth\uFF09\uFF0C\u5173\u95ED\u6807\u7B7E\u9875\u81EA\u52A8\u9501\u5B9A\u3002" })
            ]),
            el("span", { class: "lw-pill lw-pill-info", text: persistence === "tab" ? "\u6807\u7B7E\u9875\u9694\u79BB" : "\u6D4F\u89C8\u5668\u4F1A\u8BDD" })
          ]),
          makeField("\u4F1A\u8BDD\u6301\u4E45\u5316\u7B56\u7565", makeSegmentedChoice({
            value: persistence,
            disabled: state.busy,
            options: [
              { value: "tab", label: "\u6807\u7B7E\u9875\u9694\u79BB\uFF08\u63A8\u8350\uFF09", icon: "shieldCheck" },
              { value: "browser", label: "\u540C\u6D4F\u89C8\u5668\u590D\u7528\u4F1A\u8BDD", icon: "globe" }
            ],
            onSelect: (nextMode) => runMutation(async () => {
              const res = await client.api("/api/auth/settings", { method: "POST", body: { sessionPersistence: nextMode } });
              if (res.authState) state.auth = res.authState;
              if (res.snapshot) state.snapshot = res.snapshot;
              if (nextMode === "tab") startLiveStream();
              setNotice(nextMode === "tab" ? "\u5DF2\u542F\u7528\u6807\u7B7E\u9875\u9694\u79BB\u8BA4\u8BC1\u5E76\u8F6E\u6362\u4EE4\u724C\u3002" : "\u5DF2\u5207\u6362\u4E3A\u6D4F\u89C8\u5668\u4F1A\u8BDD\u6A21\u5F0F\u3002");
            })
          })),
          el("div", { class: "lw-btn-group" }, [
            serviceBtn("\u542F\u52A8\u8FDE\u63A5\u5668", "start", "play"),
            serviceBtn("\u91CD\u542F\u8FDE\u63A5\u5668", "restart", "refresh"),
            serviceBtn("\u505C\u6B62\u8FDE\u63A5\u5668", "stop", "stop", true)
          ])
        ])
      ]),
      el("aside", { class: "lw-doc-aside" }, [
        el("div", { class: "lw-section-head" }, [
          el("div", {}, [
            el("h3", { text: "\u5B9E\u65F6\u7269\u7406\u8FB9\u754C\u6001\u52BF" }),
            el("p", { text: "\u80FD\u529B\u5F00\u5173\u4E0E\u5BB9\u5668\u6302\u8F7D\u53C2\u6570\u8054\u52A8\u77E9\u9635" })
          ]),
          el("span", { class: `lw-pill ${mountRw || cap.allowExec ? "lw-pill-warn" : "lw-pill-ok"}`, text: mountRw ? ":rw \u6A21\u5F0F" : ":ro \u53EA\u8BFB\u9501\u5B9A" })
        ]),
        boundarySvg,
        el("div", { class: "lw-aside-list" }, [
          el("div", { class: "lw-aside-row" }, [
            el("span", { class: "lw-muted", text: "\u6587\u4EF6\u8BFB\u5DE5\u5177\u7EC4" }),
            el("strong", { text: cap.fileRead ? "read / list / search \u53EF\u7528" : "\u5DF2\u7194\u65AD\u62D2\u7EDD" })
          ]),
          el("div", { class: "lw-aside-row" }, [
            el("span", { class: "lw-muted", text: "\u6587\u4EF6\u5199\u5DE5\u5177\u7EC4" }),
            el("strong", { text: cap.fileWrite ? "write / replace \u9700\u5BA1\u6279" : "\u5185\u6838\u7EA7\u53EA\u8BFB\u5C01\u9501" })
          ]),
          el("div", { class: "lw-aside-row" }, [
            el("span", { class: "lw-muted", text: "\u547D\u4EE4\u6267\u884C\u5DE5\u5177" }),
            el("strong", { text: cap.allowExec ? "\u65E0\u5165\u7AD9 Docker exec_command" : "\u5DF2\u7981\u7528" })
          ])
        ])
      ])
    ]);
    return el("div", { class: "lw-stack-md" }, [
      makePageHeader("\u80FD\u529B\u5F00\u5173\u4E0E\u5BBF\u4E3B\u670D\u52A1", "\u5B9E\u65F6\u539F\u5B50\u4FEE\u6539\u5DE5\u4F5C\u533A\u5916 0600 \u7B56\u7565\u5F00\u5173\u4E0E\u6D4F\u89C8\u5668\u4F1A\u8BDD\u6301\u4E45\u5316\u59FF\u6001\u3002"),
      splitLayout
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
    const normalizedEp = (endpoint || "").trim() || "http://127.0.0.1:11434";
    if (role === "canary") {
      cfg.canary = {
        ...cfg.canary || {},
        enabled: true,
        kind: "ollama",
        endpoint: normalizedEp,
        model: modelName,
        allowPrivateNetwork: Boolean(allowPrivateNetwork),
        think: cfg.canary?.think ?? false
      };
      setNotice(`\u5DF2\u5C06 Canary \u63A2\u6D4B\u6A21\u578B\u8BBE\u4E3A ${modelName}\uFF08${normalizedEp}\uFF09\uFF0C\u8BF7\u70B9\u51FB\u4E0B\u65B9\u300C\u4FDD\u5B58\u5BA1\u6838\u7B56\u7565\u914D\u7F6E\u300D\u751F\u6548\u3002`);
      return;
    }
    cfg.localGuard = {
      ...cfg.localGuard || {},
      kind: "ollama",
      endpoint: normalizedEp,
      model: modelName,
      allowPrivateNetwork: Boolean(allowPrivateNetwork),
      think: cfg.localGuard?.think ?? false
    };
    setNotice(`\u5DF2\u5C06\u672C\u5730 Guard \u6A21\u578B\u8BBE\u4E3A ${modelName}\uFF08${normalizedEp}\uFF09\uFF0C\u8BF7\u70B9\u51FB\u4E0B\u65B9\u300C\u4FDD\u5B58\u5BA1\u6838\u7B56\u7565\u914D\u7F6E\u300D\u751F\u6548\u3002`);
  }
  function renderOllamaManagerCard() {
    const ol = state.ollama;
    const activeEp = state.ollamaEndpointInput || ol?.endpoint || "http://127.0.0.1:11434";
    const installedNames = new Set((ol?.models || []).map((m) => m.name));
    const loadedNames = new Set(
      (ol?.loadedModels || []).map((x) => typeof x === "string" ? x : x?.name || x?.model || "").filter(Boolean)
    );
    const probeInput = el("input", {
      type: "url",
      class: "lw-input lw-mono",
      value: activeEp,
      placeholder: "http://127.0.0.1:11434 \u6216\u53D7\u4FE1\u4EFB\u5C40\u57DF\u7F51 GPU \u5730\u5740",
      onInput: (e) => {
        state.ollamaEndpointInput = e.target.value;
      }
    });
    const allowPrivChk = el("input", {
      type: "checkbox",
      onChange: (e) => {
        state.ollamaAllowPrivate = e.target.checked;
      }
    });
    allowPrivChk.checked = Boolean(state.ollamaAllowPrivate);
    const pullInput = el("input", {
      type: "text",
      class: "lw-input lw-mono",
      value: state.ollamaPullTag,
      placeholder: "\u8F93\u5165\u6A21\u578B\u6807\u7B7E\uFF0C\u5982 llama-guard3:1b\u3001shieldgemma:2b\u3001qwen3:0.6b",
      onInput: (e) => {
        state.ollamaPullTag = e.target.value;
      }
    });
    const recModels = Array.isArray(ol?.recommendedModels) ? ol.recommendedModels : [];
    const pullJobs = Array.isArray(ol?.pullJobs) ? ol.pullJobs : [];
    const headerActions = [
      makeIconButton({
        text: state.ollamaLoading ? "\u63A2\u6D4B\u4E2D..." : "\u5237\u65B0\u63A2\u6D4B",
        iconName: "refresh",
        className: "lw-btn lw-btn-sm",
        disabled: state.busy || state.ollamaLoading,
        onClick: () => {
          void loadOllamaStatus();
        }
      })
    ];
    if (ol && ol.installed && !ol.running) {
      headerActions.push(makeIconButton({
        text: "\u542F\u52A8\u672C\u5730 Ollama",
        iconName: "play",
        className: "lw-btn lw-btn-sm lw-btn-trust",
        disabled: state.busy,
        onClick: () => runMutation(async () => {
          const res = await client.api("/api/moderation/ollama/start", {
            method: "POST",
            body: { endpoint: activeEp }
          });
          await loadOllamaStatus({ endpoint: res.endpoint || activeEp, silent: true });
          setNotice(res.alreadyRunning ? `Ollama \u5DF2\u8FD0\u884C\u4E2D\uFF08${res.version || ""}\uFF09\u3002` : `\u5DF2\u542F\u52A8\u672C\u5730 Ollama\uFF08PID ${res.pid || "-"}\uFF09\u3002`);
        })
      }));
    }
    if (!ol || !ol.installed) {
      headerActions.push(makeIconButton({
        text: "\u4E00\u952E\u5B89\u88C5 Ollama",
        iconName: "download",
        className: "lw-btn lw-btn-sm lw-btn-trust",
        disabled: state.busy,
        onClick: () => {
          state.ollamaInstallConfirm = !state.ollamaInstallConfirm;
          render();
        }
      }));
    }
    const bodyChildren = [
      el("div", { class: "lw-stack-md" }, [
        el("div", { class: "lw-ollama-probe-row" }, [
          probeInput,
          makeIconButton({
            text: "\u63A2\u6D4B\u7AEF\u70B9",
            iconName: "radar",
            className: "lw-btn lw-btn-sm",
            disabled: state.busy || state.ollamaLoading,
            onClick: () => {
              void loadOllamaStatus({ endpoint: state.ollamaEndpointInput, allowPrivateNetwork: state.ollamaAllowPrivate });
            }
          })
        ]),
        makeSwitchCard({
          checked: Boolean(state.ollamaAllowPrivate),
          onChange: (next) => {
            state.ollamaAllowPrivate = next;
            render();
          },
          title: "\u63A2\u6D4B\u53D7\u4FE1\u4EFB\u79C1\u6709\u5C40\u57DF\u7F51 HTTP Ollama\uFF08\u5982 192.168.x.x:11434 GPU \u8282\u70B9\uFF09",
          subtitle: "\u4EC5\u5728\u5F53\u524D\u9762\u677F\u63A2\u9488\u5F00\u653E\u5185\u7F51 IP \u8BBF\u95EE\uFF0C\u5BF9 169.254.169.254 \u4E0E\u516C\u7F51\u660E\u6587 HTTP \u6301\u7EED\u786C\u963B\u65AD",
          pillText: state.ollamaAllowPrivate ? "\u5DF2\u653E\u884C\u5C40\u57DF\u7F51\u63A2\u9488" : "\u4EC5\u56DE\u73AF / HTTPS",
          pillTone: state.ollamaAllowPrivate ? "warn" : "info",
          iconName: "server"
        })
      ])
    ];
    if (state.ollamaInstallConfirm) {
      bodyChildren.push(el("div", { class: "lw-ollama-confirm" }, [
        el("div", {
          text: "\u786E\u8BA4\u5728\u5F53\u524D\u5BBF\u4E3B\u673A\u5B89\u88C5 Ollama \u4E8C\u8FDB\u5236\uFF1F\u5B89\u88C5\u811A\u672C\u4EC5\u7EE7\u627F\u53D7\u9650 PATH/HOME \u7B49\u5B89\u5168\u73AF\u5883\u53D8\u91CF\uFF08\u5DF2\u5265\u79BB LoomWard \u51ED\u636E\uFF09\u3002"
        }),
        el("div", { class: "lw-row lw-end" }, [
          makeIconButton({
            text: "\u53D6\u6D88",
            iconName: "rotateCcw",
            className: "lw-btn lw-btn-sm",
            disabled: state.busy,
            onClick: () => {
              state.ollamaInstallConfirm = false;
              render();
            }
          }),
          makeIconButton({
            text: "\u786E\u8BA4\u6267\u884C\u5B89\u88C5",
            iconName: "check",
            className: "lw-btn lw-btn-sm lw-btn-trust",
            disabled: state.busy,
            onClick: () => runMutation(async () => {
              const res = await client.api("/api/moderation/ollama/install", {
                method: "POST",
                body: { confirmInstall: true }
              });
              state.ollamaInstallConfirm = false;
              await loadOllamaStatus({ endpoint: activeEp, silent: true });
              setNotice(res.alreadyInstalled ? `\u68C0\u6D4B\u5230\u672C\u673A\u5DF2\u5B89\u88C5 Ollama\uFF1A${res.binaryPath}` : `Ollama \u5B89\u88C5\u5B8C\u6210\uFF1A${res.binaryPath || "\u5DF2\u5C31\u7EEA"}`);
            })
          })
        ])
      ]));
    }
    if (state.ollamaError || ol?.error) {
      bodyChildren.push(el("div", {
        class: "lw-banner lw-banner-err",
        role: "alert",
        text: state.ollamaError || ol.error
      }));
    }
    if (state.ollamaTestResult) {
      const tr = state.ollamaTestResult;
      bodyChildren.push(el("div", {
        class: "lw-banner lw-banner-ok",
        role: "status",
        text: `\u63A8\u7406\u6D4B\u8BD5\u6210\u529F \xB7 ${tr.model} \xB7 \u8017\u65F6 ${tr.latencyMs} ms \xB7 \u8FD4\u56DE\u9884\u89C8\uFF1A${tr.replyPreview || "(empty)"}`
      }));
    }
    const draftGuardModel = getDraftModConfig()?.localGuard?.model || "";
    const draftCanaryModel = getDraftModConfig()?.canary?.model || "";
    const models = Array.isArray(ol?.models) ? ol.models : [];
    bodyChildren.push(el("section", { class: "lw-section" }, [
      el("div", { class: "lw-section-head" }, [
        el("div", {}, [
          el("h3", { text: `\u5DF2\u5B89\u88C5\u6A21\u578B (${models.length})` }),
          el("p", { text: "\u70B9\u51FB\u6307\u6D3E\u5C06\u76F4\u63A5\u586B\u5165 Guard \u6216 Canary \u8DEF\u7531\u8868\u5355\uFF0C\u5E76\u53EF\u5728\u5F53\u524D\u7AEF\u70B9\u5B9E\u65F6\u6D4B\u901F\u3002" })
        ])
      ]),
      models.length ? el("div", { class: "lw-table-wrap" }, [
        el("table", { class: "lw-table" }, [
          el("thead", {}, [el("tr", {}, [
            el("th", { text: "\u6A21\u578B\u6807\u8BC6" }),
            el("th", { text: "\u53C2\u6570 / \u5927\u5C0F" }),
            el("th", { text: "\u8FD0\u884C\u6001\u4E0E\u7279\u6027" }),
            el("th", { text: "\u6307\u6D3E\u4E0E\u6D4B\u901F" })
          ])]),
          el("tbody", {}, models.map((m) => {
            const isLoaded = loadedNames.has(m.name);
            const caps = Array.isArray(m.capabilities) ? m.capabilities : [];
            const isGuardSelected = draftGuardModel === m.name;
            const isCanarySelected = draftCanaryModel === m.name;
            return el("tr", {}, [
              el("td", { class: "lw-mono", text: m.name }),
              el("td", { class: "lw-mono", text: [m.parameterSize, m.sizeLabel].filter(Boolean).join(" \xB7 ") || "-" }),
              el("td", {}, [
                el("div", { class: "lw-row" }, [
                  isLoaded ? el("span", { class: "lw-pill lw-pill-ok", text: "VRAM \u5E38\u9A7B" }) : null,
                  ...caps.slice(0, 3).map((cap) => el("span", {
                    class: `lw-pill ${cap === "thinking" ? "lw-pill-warn" : ""}`,
                    text: cap === "thinking" ? "thinking (\u9ED8\u8BA4\u5173\u95ED)" : cap
                  }))
                ])
              ]),
              el("td", {}, [
                el("div", { class: "lw-btn-group" }, [
                  makeIconButton({
                    text: isGuardSelected ? "Guard \u5DF2\u9009" : "\u8BBE\u4E3A Guard",
                    iconName: "shieldCheck",
                    className: `lw-btn lw-btn-sm ${isGuardSelected ? "is-active" : ""}`,
                    disabled: state.busy,
                    onClick: () => applyOllamaModelChoice("guard", m.name, activeEp, state.ollamaAllowPrivate)
                  }),
                  makeIconButton({
                    text: isCanarySelected ? "Canary \u5DF2\u9009" : "\u8BBE\u4E3A Canary",
                    iconName: "radar",
                    className: `lw-btn lw-btn-sm ${isCanarySelected ? "is-active" : ""}`,
                    disabled: state.busy,
                    onClick: () => applyOllamaModelChoice("canary", m.name, activeEp, state.ollamaAllowPrivate)
                  }),
                  makeIconButton({
                    text: "\u6D4B\u901F",
                    iconName: "bolt",
                    className: "lw-btn lw-btn-sm",
                    disabled: state.busy,
                    onClick: () => runMutation(async () => {
                      const res = await client.api("/api/moderation/ollama/test", {
                        method: "POST",
                        body: {
                          model: m.name,
                          endpoint: activeEp,
                          allowPrivateNetwork: Boolean(state.ollamaAllowPrivate),
                          think: false
                        }
                      });
                      state.ollamaTestResult = res;
                      setNotice(`Ollama \u6D4B\u901F\u901A\u8FC7\uFF1A${res.model} (${res.latencyMs} ms)`);
                    })
                  })
                ])
              ])
            ]);
          }))
        ])
      ]) : el("div", { class: "lw-empty-state", text: ol?.running ? "\u5F53\u524D Ollama \u5C1A\u65E0\u5DF2\u62C9\u53D6\u6A21\u578B\uFF0C\u8BF7\u5728\u4E0B\u65B9\u62C9\u53D6\u5B89\u5168 Guard / Canary \u6A21\u578B\u3002" : "Ollama \u672A\u8FDE\u63A5\u6216\u672A\u542F\u52A8\uFF0C\u53EF\u70B9\u51FB\u53F3\u4E0A\u89D2\u542F\u52A8\u6216\u4E00\u952E\u5B89\u88C5\u3002" })
    ]));
    if (pullJobs.length > 0) {
      bodyChildren.push(el("section", { class: "lw-section" }, [
        el("div", { class: "lw-section-head" }, [el("h3", { text: "\u6A21\u578B\u62C9\u53D6\u4EFB\u52A1" })]),
        el("div", { class: "lw-setting-list" }, pullJobs.map((job) => {
          const pct = Number.isFinite(job.percent) ? Math.max(0, Math.min(100, job.percent)) : 0;
          return el("div", { class: "lw-ollama-rec-row" }, [
            el("div", { class: "lw-ollama-rec-info" }, [
              el("div", { class: "lw-row lw-between" }, [
                el("span", { class: "lw-mono", text: job.model }),
                el("span", {
                  class: `lw-pill ${job.status === "completed" ? "lw-pill-ok" : job.status === "failed" ? "lw-pill-err" : "lw-pill-warn"}`,
                  text: `${job.status}${pct > 0 ? ` ${pct}%` : ""}`
                })
              ]),
              el("div", { class: "lw-progress-track" }, [
                el("div", { class: "lw-progress-bar", style: `width:${job.status === "completed" ? 100 : pct}%` })
              ]),
              job.error || job.detail ? el("span", { class: "lw-muted", text: job.error || job.detail }) : null
            ])
          ]);
        }))
      ]));
    }
    bodyChildren.push(el("section", { class: "lw-section" }, [
      el("div", { class: "lw-section-head" }, [
        el("div", {}, [
          el("h3", { text: "\u62C9\u53D6\u4E0E\u4E00\u952E\u63A5\u5165\u5B89\u5168\u6A21\u578B" }),
          el("p", { text: "\u652F\u6301\u8F93\u5165\u4EFB\u610F Ollama \u6A21\u578B\u6807\u7B7E\u62C9\u53D6\uFF0C\u6216\u4E00\u952E\u62C9\u53D6\u9884\u8BBE\u5B89\u5168\u5206\u7C7B\u4E0E Canary \u5C0F\u6A21\u578B\u3002" })
        ])
      ]),
      el("div", { class: "lw-ollama-probe-row" }, [
        pullInput,
        makeIconButton({
          text: "\u62C9\u53D6\u81EA\u5B9A\u4E49\u6A21\u578B",
          iconName: "download",
          className: "lw-btn lw-btn-sm lw-btn-trust",
          disabled: state.busy,
          onClick: () => runMutation(async () => {
            const tag = (state.ollamaPullTag || "").trim();
            if (!tag) throw new Error("\u8BF7\u8F93\u5165\u8981\u62C9\u53D6\u7684 Ollama \u6A21\u578B\u6807\u7B7E\u3002");
            await client.api("/api/moderation/ollama/pull", {
              method: "POST",
              body: {
                model: tag,
                endpoint: activeEp,
                allowPrivateNetwork: Boolean(state.ollamaAllowPrivate)
              }
            });
            state.ollamaPullTag = "";
            await loadOllamaStatus({ endpoint: activeEp, silent: true });
            setNotice(`\u5DF2\u63D0\u4EA4 Ollama \u6A21\u578B\u62C9\u53D6\u4EFB\u52A1\uFF1A${tag}`);
          })
        })
      ]),
      recModels.length > 0 ? el("div", { class: "lw-setting-list" }, recModels.map((rec) => {
        const hasExact = installedNames.has(rec.id) || installedNames.has(`${rec.id}:latest`);
        const targetRole = rec.role === "canary" ? "canary" : "guard";
        return el("div", { class: "lw-ollama-rec-row" }, [
          el("div", { class: "lw-ollama-rec-info" }, [
            el("div", { class: "lw-row" }, [
              el("span", { class: "lw-mono", text: rec.id }),
              el("span", { class: `lw-pill ${rec.role === "canary" ? "lw-pill-info" : "lw-pill-ok"}`, text: `${rec.role === "canary" ? "Canary" : "Guard"} \xB7 ${rec.sizeLabel}` })
            ]),
            el("span", { class: "lw-switch-sub", text: rec.desc })
          ]),
          makeIconButton({
            text: hasExact ? `\u8BBE\u4E3A\u9ED8\u8BA4 ${targetRole === "canary" ? "Canary" : "Guard"}` : `\u4E00\u952E\u62C9\u53D6 (${rec.sizeLabel})`,
            iconName: hasExact ? "check" : "download",
            className: `lw-btn lw-btn-sm ${hasExact ? "" : "lw-btn-trust"}`,
            disabled: state.busy,
            onClick: () => {
              if (hasExact) {
                applyOllamaModelChoice(targetRole, installedNames.has(rec.id) ? rec.id : `${rec.id}:latest`, activeEp, state.ollamaAllowPrivate);
                return;
              }
              void runMutation(async () => {
                await client.api("/api/moderation/ollama/pull", {
                  method: "POST",
                  body: {
                    model: rec.id,
                    endpoint: activeEp,
                    allowPrivateNetwork: Boolean(state.ollamaAllowPrivate)
                  }
                });
                await loadOllamaStatus({ endpoint: activeEp, silent: true });
                setNotice(`\u5F00\u59CB\u62C9\u53D6\u63A8\u8350\u5B89\u5168\u6A21\u578B\uFF1A${rec.id}`);
              });
            }
          })
        ]);
      })) : null
    ]));
    const statusText = ol?.running ? `\u5728\u7EBF \xB7 Ollama ${ol.version || ol.binaryVersion || ""}`.trim() : ol?.installed ? `\u672C\u673A\u5DF2\u5B89\u88C5 (${ol.binaryVersion || "\u5F85\u542F\u52A8"})` : "\u672A\u68C0\u6D4B\u5230\u672C\u5730\u8FD0\u884C\u65F6";
    return el("div", { class: "lw-stack-md" }, [
      el("section", { class: "lw-section" }, [
        el("div", { class: "lw-section-head" }, [
          el("div", {}, [
            el("h3", { text: "\u672C\u5730\u6A21\u578B\u8FD0\u884C\u65F6 \xB7 Ollama" }),
            el("p", {
              text: ol?.binaryPath ? `\u5DF2\u53D1\u73B0\u53EF\u6267\u884C\u6587\u4EF6\uFF1A${ol.binaryPath}\uFF08\u652F\u6301 /api/tags \u81EA\u52A8\u53D1\u73B0\u3001\u539F\u751F\u591A\u6A21\u6001\u4E0E think=false \u4F4E\u5EF6\u8FDF\u5BA1\u67E5\uFF09` : "\u652F\u6301\u53D7\u63A7\u5B89\u88C5/\u542F\u52A8\u672C\u673A Ollama\u3001\u62C9\u53D6\u5B89\u5168\u6A21\u578B\uFF0C\u6216\u8FDE\u63A5\u53D7\u4FE1\u4EFB\u5C40\u57DF\u7F51 GPU \u8282\u70B9\u3002"
            })
          ]),
          el("div", { class: "lw-row" }, [
            el("span", { class: `lw-pill ${ol?.running ? "lw-pill-ok" : ol?.installed ? "lw-pill-warn" : "lw-pill-info"}`, text: statusText }),
            ...headerActions
          ])
        ]),
        ...bodyChildren.slice(0, 1),
        ...bodyChildren.slice(1, bodyChildren.length - (pullJobs.length > 0 ? 3 : 2))
      ]),
      ...bodyChildren.slice(bodyChildren.length - (pullJobs.length > 0 ? 3 : 2))
    ]);
  }
  var CLOUD_PROVIDER_META = {
    "openai-compat": {
      shortLabel: "OpenAI Moderation",
      endpointPlaceholder: "https://api.openai.com/v1/moderations",
      docSummary: "\u8C03\u7528 OpenAI POST /v1/moderations\uFF08model=omni-moderation-latest\uFF09\uFF1B\u652F\u6301\u6587\u672C\u4E0E\u975E SVG \u56FE\u7247 base64 data URI\uFF08\u5B98\u65B9\u4E0A\u9650 20 MB\uFF09\uFF0C\u5185\u8054\u7EAF\u97F3\u9891/\u89C6\u9891\u5C06\u663E\u5F0F\u62A5\u9519\u56DE\u9000\u3002",
      regions: [],
      creds: [
        { key: "OPENAI_API_KEY", label: "OpenAI API Key", placeholder: "sk-...\uFF08\u4EC5\u5199\u4FDD\u5B58\uFF0C\u4E0D\u56DE\u663E\uFF09" }
      ]
    },
    "aliyun-green": {
      shortLabel: "\u963F\u91CC\u4E91\u5185\u5BB9\u5B89\u5168 2.0",
      endpointPlaceholder: "https://green-cip.cn-shanghai.aliyuncs.com/",
      docSummary: "\u8C03\u7528 green-cip.{region}.aliyuncs.com\uFF08ACS3-HMAC-SHA256 + form-urlencoded TextModerationPlus\uFF09\uFF1B\u56FE\u7247/\u97F3\u89C6\u9891\u5185\u8054\u4E8C\u8FDB\u5236\u9700 DescribeUploadToken \u9884\u4F20 OSS\uFF0C\u76F4\u4F20\u88F8\u5B57\u8282\u4F1A\u663E\u5F0F\u62A5\u9519\u56DE\u9000\u3002",
      regions: [
        ["", "(\u9ED8\u8BA4 \xB7 cn-shanghai)"],
        ["cn-shanghai", "\u534E\u4E1C 2\uFF08\u4E0A\u6D77 \xB7 cn-shanghai\uFF09"],
        ["cn-beijing", "\u534E\u5317 2\uFF08\u5317\u4EAC \xB7 cn-beijing\uFF09"],
        ["cn-shenzhen", "\u534E\u5357 1\uFF08\u6DF1\u5733 \xB7 cn-shenzhen\uFF09"],
        ["cn-hangzhou", "\u534E\u4E1C 1\uFF08\u676D\u5DDE \xB7 cn-hangzhou\uFF09"],
        ["ap-southeast-1", "\u65B0\u52A0\u5761\uFF08ap-southeast-1\uFF09"]
      ],
      creds: [
        { key: "ALIYUN_ACCESS_KEY_ID", label: "AccessKey ID", placeholder: "LTAI5t..." },
        { key: "ALIYUN_ACCESS_KEY_SECRET", label: "AccessKey Secret", placeholder: "\u4EC5\u5199\u4FDD\u5B58\uFF0C\u4E0D\u56DE\u663E" }
      ]
    },
    "tencent-tms": {
      shortLabel: "\u817E\u8BAF\u4E91\u5929\u5FA1 TMS/IMS/AMS",
      endpointPlaceholder: "https://tms.tencentcloudapi.com/",
      docSummary: "\u8C03\u7528 *.tencentcloudapi.com\uFF08TC3-HMAC-SHA256 2020-12-29\uFF09\uFF1ATMS \u6587\u672C + IMS \u56FE\u7247 FileContent + AMS \u540C\u6B65\u97F3\u9891 CreateAudioModerationSyncTask\uFF1BVMS \u89C6\u9891\u4EC5\u5F02\u6B65 URL\uFF0C\u5185\u8054\u89C6\u9891\u4F1A\u663E\u5F0F\u62A5\u9519\u56DE\u9000\u3002",
      regions: [
        ["", "(\u9ED8\u8BA4 \xB7 ap-guangzhou)"],
        ["ap-guangzhou", "\u534E\u5357\uFF08\u5E7F\u5DDE \xB7 ap-guangzhou\uFF09"],
        ["ap-shanghai", "\u534E\u4E1C\uFF08\u4E0A\u6D77 \xB7 ap-shanghai\uFF09"],
        ["ap-beijing", "\u534E\u5317\uFF08\u5317\u4EAC \xB7 ap-beijing\uFF09"],
        ["ap-chengdu", "\u897F\u5357\uFF08\u6210\u90FD \xB7 ap-chengdu\uFF09"],
        ["ap-hongkong", "\u6E2F\u6FB3\u53F0\uFF08\u4E2D\u56FD\u9999\u6E2F \xB7 ap-hongkong\uFF09"]
      ],
      creds: [
        { key: "TENCENT_SECRET_ID", label: "SecretId", placeholder: "AKID..." },
        { key: "TENCENT_SECRET_KEY", label: "SecretKey", placeholder: "\u4EC5\u5199\u4FDD\u5B58\uFF0C\u4E0D\u56DE\u663E" }
      ]
    },
    "baidu-aip": {
      shortLabel: "\u767E\u5EA6\u667A\u80FD\u4E91\u5185\u5BB9\u5BA1\u6838",
      endpointPlaceholder: "https://aip.baidubce.com",
      docSummary: "\u7ECF /oauth/2.0/token \u5355\u98DE\u7F13\u5B58\u6362\u53D6 Access Token \u540E\u8C03\u7528 text_censor/v2\u3001img_censor/v2\uFF08\u542B imgType\uFF09\u3001voice_censor/v3/user_defined\uFF1Bvideo_censor \u4EC5\u652F\u6301\u516C\u7F51 URL\uFF0C\u5185\u8054\u89C6\u9891\u4F1A\u663E\u5F0F\u62A5\u9519\u56DE\u9000\u3002",
      regions: [],
      creds: [
        { key: "BAIDU_API_KEY", label: "API Key (Client ID)", placeholder: "\u767E\u5EA6\u5E94\u7528 API Key" },
        { key: "BAIDU_SECRET_KEY", label: "Secret Key (Client Secret)", placeholder: "\u4EC5\u5199\u4FDD\u5B58\uFF0C\u4E0D\u56DE\u663E" }
      ]
    },
    webhook: {
      shortLabel: "\u81EA\u5B9A\u4E49 HTTPS Webhook",
      endpointPlaceholder: "https://moderation.example.com/v1/inspect",
      docSummary: "\u5411\u81EA\u5B9A\u4E49 HTTPS \u7AEF\u70B9 POST JSON \u5BA1\u8BA1\u8F7D\u8377\u5E76\u89E3\u6790 { decision, score, categories, reason }\uFF1BToken \u7559\u7A7A\u65F6\u4E0D\u9644\u5E26 Authorization \u5934\u3002",
      regions: [],
      creds: [
        { key: "WEBHOOK_API_KEY", label: "Bearer / Webhook Token\uFF08\u53EF\u9009\uFF09", placeholder: "\u9700\u8981\u9274\u6743\u65F6\u586B\u5199 Bearer Token", optional: true }
      ]
    }
  };
  function getCloudProviderMeta(provider) {
    return CLOUD_PROVIDER_META[provider] || CLOUD_PROVIDER_META["openai-compat"];
  }
  function getSavedSecretKeySet(unitId = "llm-moderation") {
    const unit = (state.pluginSecretUnits || []).find((u) => u && u.unitId === unitId);
    return new Set(Array.isArray(unit?.keys) ? unit.keys : []);
  }
  function collectPendingCloudCreds(provider) {
    const meta = getCloudProviderMeta(provider);
    const out = {};
    for (const cred of meta.creds) {
      const raw = state.draftCloudCreds?.[cred.key];
      if (typeof raw === "string" && raw.trim().length > 0) {
        out[cred.key] = raw.trim();
      }
    }
    return out;
  }
  async function savePluginSecretsAndRefresh(unitId, secrets) {
    const res = await client.api("/api/plugin-secrets/save", {
      method: "POST",
      body: { unitId, secrets }
    });
    const metaRes = await client.api("/api/plugin-secrets/meta").catch(() => null);
    if (Array.isArray(metaRes?.units)) {
      state.pluginSecretUnits = metaRes.units;
    }
    return res;
  }
  function fallbackMatrixForProfile(profile) {
    if (profile === "strict") {
      return { cloudDown: "\u786C\u963B\u65AD (Fail-Closed)", inputDown: "\u786C\u963B\u65AD (Fail-Closed)", outputDown: "\u786C\u963B\u65AD (Fail-Closed)" };
    }
    if (profile === "balanced") {
      return { cloudDown: "\u8F6C\u5C40\u90E8/\u963B\u65AD (Fail-Closed)", inputDown: "\u8F6C\u672C\u673A\u4EBA\u5DE5\u590D\u6838", outputDown: "\u5F3A\u5236 Fail-Closed \u963B\u65AD" };
    }
    return { cloudDown: "\u5E73\u6ED1\u964D\u7EA7\u81F3 Local Guard", inputDown: "\u8F6C\u672C\u673A\u4EBA\u5DE5\u590D\u6838", outputDown: "\u544A\u8B66\u5E76\u653E\u884C (\u5B9E\u9A8C\u5F39\u6027)" };
  }
  function normalizeComparableMod(raw) {
    const src = raw || DEFAULT_MOD_CONFIG;
    const lgKind = src.localGuard?.kind || "http";
    const cnEnabled = Boolean(src.canary?.enabled || src.mode === "guard-plus-canary");
    const cnKind = src.canary?.kind || "http";
    return {
      mode: src.mode || "local-only",
      policyProfile: src.policyProfile || "experimental-resilient",
      defaultScope: src.defaultScope || "combined",
      cloudOptIn: Boolean(src.cloudOptIn),
      cloudProvider: src.cloudProvider || "openai-compat",
      cloudRegion: (src.cloudRegion || "").trim(),
      cloudEndpoint: (src.cloudEndpoint || "").trim(),
      lgKind,
      lgModel: (src.localGuard?.model || "llama-guard-3").trim(),
      lgEndpoint: ((src.localGuard?.endpoint || "").trim() || (lgKind === "ollama" ? "http://127.0.0.1:11434" : "")).replace(/\/+$/, ""),
      lgThink: Boolean(src.localGuard?.think),
      lgPrivate: Boolean(src.localGuard?.allowPrivateNetwork),
      cnEnabled,
      cnKind,
      cnModel: (src.canary?.model || "qwen2.5-0.5b").trim(),
      cnEndpoint: ((src.canary?.endpoint || "").trim() || (cnEnabled && cnKind === "ollama" ? "http://127.0.0.1:11434" : "")).replace(/\/+$/, ""),
      cnPrivate: Boolean(src.canary?.allowPrivateNetwork)
    };
  }
  function computeModerationDelta(savedRaw, draftRaw) {
    const saved = normalizeComparableMod(savedRaw);
    const draft = normalizeComparableMod(draftRaw);
    const changed = /* @__PURE__ */ new Set();
    const diffs = [];
    const specs = [
      ["mode", "\u5BA1\u67E5\u6A21\u5F0F"],
      ["policyProfile", "\u56DE\u9000\u7B56\u7565"],
      ["defaultScope", "\u6821\u9A8C\u8303\u56F4"],
      ["cloudOptIn", "\u4E91\u7AEF\u5916\u53D1\u8BB8\u53EF", (v) => v ? "\u5141\u8BB8\u5916\u53D1" : "\u7EAF\u672C\u5730\u95ED\u9501"],
      ["cloudProvider", "\u4E91\u7AEF\u63A5\u53E3"],
      ["cloudRegion", "\u4E91\u7AEF\u670D\u52A1\u5730\u57DF", (v) => v || "(\u9ED8\u8BA4\u5730\u57DF)"],
      ["cloudEndpoint", "\u81EA\u5B9A\u4E49\u4E91\u7AEF\u7AEF\u70B9", (v) => v || "(\u9ED8\u8BA4\u5B98\u65B9\u57DF\u540D)"],
      ["lgKind", "Guard \u5F15\u64CE"],
      ["lgModel", "Guard \u6A21\u578B"],
      ["lgEndpoint", "Guard \u7AEF\u70B9", (v) => v || "(\u5185\u7F6E\u79BB\u7EBF\u5F15\u64CE)"],
      ["lgThink", "Guard \u601D\u8003\u94FE", (v) => v ? "\u601D\u8003\u5F00\u542F" : "think=false \u6781\u901F"],
      ["lgPrivate", "Guard \u5C40\u57DF\u7F51\u653E\u884C", (v) => v ? "\u5F00\u653E\u5C40\u57DF\u7F51 HTTP" : "\u4EC5\u56DE\u73AF/HTTPS"],
      ["cnEnabled", "Canary \u63A2\u9488", (v) => v ? "\u542F\u7528" : "\u5173\u95ED"],
      ["cnKind", "Canary \u5F15\u64CE"],
      ["cnModel", "Canary \u6A21\u578B"],
      ["cnEndpoint", "Canary \u7AEF\u70B9", (v) => v || "(\u672A\u6307\u5B9A)"],
      ["cnPrivate", "Canary \u5C40\u57DF\u7F51\u653E\u884C", (v) => v ? "\u5F00\u653E\u5C40\u57DF\u7F51 HTTP" : "\u4EC5\u56DE\u73AF/HTTPS"]
    ];
    for (const [key, label, fmt] of specs) {
      if (saved[key] !== draft[key]) {
        changed.add(key);
        const formatVal = fmt || ((v) => String(v));
        diffs.push({ key, label, from: formatVal(saved[key]), to: formatVal(draft[key]) });
      }
    }
    return { saved, draft, changed, diffs };
  }
  function clipText(str, max = 14) {
    const s = String(str || "");
    return s.length > max ? `${s.slice(0, max - 1)}\u2026` : s;
  }
  function renderModerationImpactPreview(savedRaw, draftRaw) {
    const { saved, draft, changed, diffs } = computeModerationDelta(savedRaw, draftRaw);
    const inputActive = draft.defaultScope === "combined" || draft.defaultScope === "input-only";
    const savedInputActive = saved.defaultScope === "combined" || saved.defaultScope === "input-only";
    const inputChanged = inputActive !== savedInputActive;
    const outputActive = draft.defaultScope === "combined" || draft.defaultScope === "output-only";
    const savedOutputActive = saved.defaultScope === "combined" || saved.defaultScope === "output-only";
    const outputChanged = outputActive !== savedOutputActive;
    const guardChanged = ["lgKind", "lgModel", "lgEndpoint", "lgThink", "lgPrivate"].some((k) => changed.has(k));
    const canaryActive = draft.cnEnabled || draft.mode === "guard-plus-canary";
    const savedCanaryActive = saved.cnEnabled || saved.mode === "guard-plus-canary";
    const canaryChanged = canaryActive !== savedCanaryActive || ["cnKind", "cnModel", "cnEndpoint", "cnPrivate"].some((k) => changed.has(k));
    const cloudRouteRequested = draft.mode === "cloud-first" || draft.mode === "hybrid-tiered";
    const cloudLive = draft.cloudOptIn && cloudRouteRequested;
    const savedCloudLive = saved.cloudOptIn && (saved.mode === "cloud-first" || saved.mode === "hybrid-tiered");
    const cloudChanged = cloudLive !== savedCloudLive || changed.has("cloudOptIn") || cloudLive && (changed.has("cloudProvider") || changed.has("cloudRegion") || changed.has("cloudEndpoint"));
    const providerMeta = getCloudProviderMeta(draft.cloudProvider);
    const savedSecKeys = getSavedSecretKeySet("llm-moderation");
    const cloudCredsMissing = providerMeta.creds.some((c) => !c.optional && !savedSecKeys.has(c.key));
    const curMatrix = fallbackMatrixForProfile(draft.policyProfile);
    const oldMatrix = fallbackMatrixForProfile(saved.policyProfile);
    const schematicSvg = svgEl("svg", {
      viewBox: "0 0 356 364",
      class: "lw-svg-diagram",
      role: "img",
      "aria-label": "LLM \u5B89\u5168\u5BA1\u67E5\u5B9E\u65F6\u6570\u636E\u6D41\u62D3\u6251\u793A\u610F\u56FE"
    }, [
      svgEl("defs", {}, [
        svgEl("marker", { id: "lw-arr", viewBox: "0 0 10 10", refX: "8", refY: "5", markerWidth: "6", markerHeight: "6", orient: "auto-start-reverse" }, [
          svgEl("path", { d: "M 0 1 L 10 5 L 0 9 z", fill: "currentColor" })
        ])
      ]),
      // Stage 1 -> Stage 2 Spine
      svgEl("path", {
        d: "M 158 34 L 196 34",
        class: `lw-svg-wire ${inputActive ? "lw-svg-wire-active" : "lw-svg-wire-off"}`
      }),
      // Stage 2 -> Dispatch Hub
      svgEl("path", {
        d: "M 272 58 C 272 82, 178 76, 178 98",
        class: "lw-svg-wire lw-svg-wire-active"
      }),
      // Dispatch Hub -> 3 Branch Fan-out
      svgEl("path", {
        d: "M 178 140 C 178 164, 58 158, 58 186",
        class: "lw-svg-wire lw-svg-wire-active"
      }),
      svgEl("path", {
        d: "M 178 140 L 178 186",
        class: `lw-svg-wire ${canaryActive ? "lw-svg-wire-active" : "lw-svg-wire-off"}`
      }),
      svgEl("path", {
        d: "M 178 140 C 178 164, 298 158, 298 186",
        class: `lw-svg-wire ${cloudLive ? "lw-svg-wire-warn" : "lw-svg-wire-off"}`
      }),
      // 3 Branch Fan-in -> Output Stage
      svgEl("path", {
        d: "M 58 256 C 58 282, 178 278, 178 304",
        class: `lw-svg-wire ${outputActive ? "lw-svg-wire-active" : "lw-svg-wire-off"}`
      }),
      svgEl("path", {
        d: "M 178 256 L 178 304",
        class: `lw-svg-wire ${canaryActive && outputActive ? "lw-svg-wire-active" : "lw-svg-wire-off"}`
      }),
      svgEl("path", {
        d: "M 298 256 C 298 282, 178 278, 178 304",
        class: `lw-svg-wire ${cloudLive && outputActive ? "lw-svg-wire-warn" : "lw-svg-wire-off"}`
      }),
      // Nodes
      svgNodeBox({
        x: 8,
        y: 10,
        w: 150,
        h: 48,
        title: "1. \u5165\u53C2\u53C2\u6570\u9884\u68C0",
        sub: inputActive ? "Input \u5DF2\u7EB3\u7BA1" : "\u65C1\u8DEF\uFF08\u4EC5\u67E5\u8F93\u51FA\uFF09",
        stateCls: inputActive ? "is-ok" : "is-off",
        isDelta: inputChanged
      }),
      svgNodeBox({
        x: 198,
        y: 10,
        w: 150,
        h: 48,
        title: "2. \u9632\u6CC4\u6F0F\u62A4\u680F",
        sub: "R1\u2013R7 \xB7 order: 10",
        stateCls: "is-ok"
      }),
      svgNodeBox({
        x: 68,
        y: 98,
        w: 220,
        h: 42,
        title: "3. \u591A\u6A21\u6001\u5BA1\u67E5\u67A2\u7EBD (order: 50)",
        sub: `${draft.mode} \xB7 ${draft.policyProfile}`,
        stateCls: changed.has("mode") || changed.has("policyProfile") ? "is-warn" : "is-active",
        isDelta: changed.has("mode")
      }),
      svgNodeBox({
        x: 6,
        y: 186,
        w: 106,
        h: 70,
        title: "Local Guard",
        sub: clipText(draft.lgModel, 13),
        badge: `${draft.lgThink ? "\u601D\u8003" : "think=off"}\xB7${draft.lgPrivate ? "LAN" : "Local"}`,
        stateCls: "is-active",
        badgeCls: draft.lgPrivate ? "is-warn" : "is-ok",
        isDelta: guardChanged
      }),
      svgNodeBox({
        x: 125,
        y: 186,
        w: 106,
        h: 70,
        title: "Canary \u63A2\u9488",
        sub: canaryActive ? clipText(draft.cnModel, 13) : "\u4F11\u7720\u65C1\u8DEF",
        badge: canaryActive ? "Zero-Tool" : "\u672A\u542F\u7528",
        stateCls: canaryActive ? "is-active" : "is-off",
        badgeCls: canaryActive ? "" : "is-muted",
        isDelta: canaryChanged
      }),
      svgNodeBox({
        x: 244,
        y: 186,
        w: 106,
        h: 70,
        title: "\u4E91\u7AEF\u5B89\u5168 API",
        sub: cloudLive ? clipText(draft.cloudProvider, 13) : cloudRouteRequested ? "\u7F3A OptIn" : "\u79BB\u7EBF\u95ED\u9501",
        badge: cloudLive ? cloudCredsMissing ? "\u5F85\u586B API \u5BC6\u94A5" : "\u5916\u90E8\u5916\u53D1\u5F00\u542F" : "\u96F6\u51FA\u7AD9",
        stateCls: cloudLive ? "is-warn" : "is-off",
        badgeCls: cloudLive ? "is-warn" : "is-ok",
        isDelta: cloudChanged
      }),
      svgNodeBox({
        x: 48,
        y: 304,
        w: 260,
        h: 52,
        title: "4. \u8F93\u51FA\u590D\u68C0\u4E0E Holdback \u5C3E\u90E8\u6682\u7559",
        sub: outputActive ? "\u5C40\u90E8\u8131\u654F / \u6D41\u5F0F\u963B\u65AD\u751F\u6548" : "\u65C1\u8DEF\uFF08\u4EC5\u5165\u53C2\u9884\u68C0\uFF09",
        stateCls: outputActive ? "is-ok" : "is-off",
        isDelta: outputChanged
      })
    ]);
    return el("div", { class: "lw-stack-md", "aria-live": "polite" }, [
      el("div", { class: "lw-section-head" }, [
        el("div", {}, [
          el("h3", { text: "\u7CFB\u7EDF\u8FD0\u884C\u5F62\u6001\u63A8\u6F14" }),
          el("p", { text: diffs.length ? `${diffs.length} \u9879\u6539\u52A8\u5C06\u91CD\u5851\u9AD8\u4EAE\u94FE\u8DEF\u4E0E\u8282\u70B9` : "\u4E0E\u5F53\u524D\u5DF2\u4FDD\u5B58\u7EBF\u4E0A\u6001\u4E00\u81F4" })
        ]),
        diffs.length ? el("span", { class: "lw-delta-tag", text: "Delta \u63A8\u6F14\u4E2D" }) : el("span", { class: "lw-pill lw-pill-ok", text: "\u5DF2\u540C\u6B65" })
      ]),
      schematicSvg,
      el("div", { class: "lw-aside-list" }, [
        el("div", { class: `lw-aside-row ${curMatrix.cloudDown !== oldMatrix.cloudDown ? "is-delta" : ""}` }, [
          el("span", { class: "lw-muted", text: "\u4E91\u7AEF\u6545\u969C\u515C\u5E95" }),
          el("strong", { text: curMatrix.cloudDown })
        ]),
        el("div", { class: `lw-aside-row ${curMatrix.inputDown !== oldMatrix.inputDown ? "is-delta" : ""}` }, [
          el("span", { class: "lw-muted", text: "\u5165\u53C2\u5BA1\u67E5\u6545\u969C" }),
          el("strong", { text: curMatrix.inputDown })
        ]),
        el("div", { class: `lw-aside-row ${curMatrix.outputDown !== oldMatrix.outputDown ? "is-delta" : ""}` }, [
          el("span", { class: "lw-muted", text: "\u8F93\u51FA\u5BA1\u67E5\u6545\u969C" }),
          el("strong", { text: curMatrix.outputDown })
        ])
      ])
    ]);
  }
  function renderModSaveBar(savedCfg, diffs, commitSaveConfig) {
    if (diffs.length > 0) {
      return el("div", { class: "lw-delta-bar" }, [
        el("div", { class: "lw-stack-sm" }, [
          el("strong", { text: `\u5F85\u5E94\u7528\u914D\u7F6E\u5DEE\u5F02 (${diffs.length} \u9879)` }),
          el("div", { class: "lw-row" }, diffs.slice(0, 5).map((d) => el("span", {
            class: "lw-pill lw-pill-warn lw-mono",
            text: `${d.label}: ${d.from} \u2192 ${d.to}`
          })))
        ]),
        el("div", { class: "lw-row" }, [
          makeIconButton({
            text: "\u8FD8\u539F",
            iconName: "rotateCcw",
            className: "lw-btn lw-btn-sm",
            disabled: state.busy,
            onClick: () => {
              state.draftMod = structuredClone(savedCfg);
              render();
            }
          }),
          makeIconButton({
            text: `\u4FDD\u5B58\u5E76\u70ED\u751F\u6548 (${diffs.length})`,
            iconName: "check",
            className: "lw-btn lw-btn-sm lw-btn-trust",
            disabled: state.busy,
            onClick: commitSaveConfig
          })
        ])
      ]);
    }
    return el("div", { class: "lw-row lw-end" }, [
      makeIconButton({
        text: "\u4FDD\u5B58\u5BA1\u6838\u7B56\u7565\u914D\u7F6E",
        iconName: "check",
        className: "lw-btn lw-btn-trust",
        disabled: state.busy,
        onClick: commitSaveConfig
      })
    ]);
  }
  function syncModerationLiveRegions(savedCfg, commitSaveConfig) {
    const cfg = getDraftModConfig();
    const { changed, diffs } = computeModerationDelta(savedCfg, cfg);
    const previewHost = root.querySelector("[data-mod-preview-slot]");
    if (previewHost) {
      clearNode(previewHost);
      previewHost.append(renderModerationImpactPreview(savedCfg, cfg));
    }
    const saveHost = root.querySelector("[data-mod-savebar-slot]");
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
    const datalistId = "lw-ollama-models-datalist";
    const modelChoices = /* @__PURE__ */ new Set();
    for (const m of state.ollama?.models || []) modelChoices.add(m.name);
    for (const rec of state.ollama?.recommendedModels || []) modelChoices.add(rec.id);
    const cloudMeta = getCloudProviderMeta(cfg.cloudProvider);
    const savedSecKeys = getSavedSecretKeySet("llm-moderation");
    const cloudProvSel = makeSelect([
      ["openai-compat", "OpenAI Moderation Compat (omni-moderation-latest)"],
      ["aliyun-green", "\u963F\u91CC\u4E91\u5185\u5BB9\u5B89\u5168 2.0 (Green-CIP)"],
      ["tencent-tms", "\u817E\u8BAF\u4E91\u5929\u5FA1 (TMS / IMS / AMS / VMS)"],
      ["baidu-aip", "\u767E\u5EA6\u667A\u80FD\u4E91\u5185\u5BB9\u5BA1\u6838 (AIP V2 / V3)"],
      ["webhook", "\u81EA\u5B9A\u4E49 HTTPS JSON Webhook"]
    ], cfg.cloudProvider, (e) => {
      const nextProv = e.target.value;
      cfg.cloudProvider = nextProv;
      const nextMeta = getCloudProviderMeta(nextProv);
      const validRegions = new Set((nextMeta.regions || []).map(([val]) => val));
      if (!validRegions.has(cfg.cloudRegion || "")) {
        cfg.cloudRegion = "";
      }
      render();
    }, { iconName: "cloud", isDelta: changed.has("cloudProvider") });
    const cloudRegionSel = cloudMeta.regions.length > 0 ? makeSelect(cloudMeta.regions, cfg.cloudRegion || "", (e) => {
      cfg.cloudRegion = e.target.value;
      render();
    }, { iconName: "globe", isDelta: changed.has("cloudRegion") }) : null;
    const localKind = cfg.localGuard?.kind || "http";
    const canaryKind = cfg.canary?.kind || "http";
    const canaryActive = Boolean(cfg.canary?.enabled || cfg.mode === "guard-plus-canary");
    const commitSaveConfig = () => runMutation(async () => {
      const draft = getDraftModConfig();
      const nextLocalKind = draft.localGuard?.kind || "http";
      const nextLocalEp = (draft.localGuard?.endpoint || "").trim() || (nextLocalKind === "ollama" ? "http://127.0.0.1:11434" : null);
      const nextCanaryKind = draft.canary?.kind || "http";
      const nextCanaryEnabled = Boolean(draft.canary?.enabled || draft.mode === "guard-plus-canary");
      const nextCanaryEp = (draft.canary?.endpoint || "").trim() || (nextCanaryEnabled && nextCanaryKind === "ollama" ? "http://127.0.0.1:11434" : null);
      const payload = {
        ...draft,
        cloudRegion: (draft.cloudRegion || "").trim() || null,
        cloudEndpoint: (draft.cloudEndpoint || "").trim() || null,
        localGuard: {
          ...draft.localGuard || {},
          kind: nextLocalKind,
          endpoint: nextLocalEp,
          model: (draft.localGuard?.model || "").trim() || "llama-guard-3",
          think: Boolean(draft.localGuard?.think),
          allowPrivateNetwork: Boolean(draft.localGuard?.allowPrivateNetwork)
        },
        canary: {
          ...draft.canary || {},
          enabled: nextCanaryEnabled,
          kind: nextCanaryKind,
          endpoint: nextCanaryEp,
          model: (draft.canary?.model || "").trim() || "qwen2.5-0.5b",
          think: Boolean(draft.canary?.think),
          allowPrivateNetwork: Boolean(draft.canary?.allowPrivateNetwork)
        }
      };
      const pendingCreds = collectPendingCloudCreds(draft.cloudProvider);
      const pendingKeys = Object.keys(pendingCreds);
      for (const k of pendingKeys) state.draftCloudCreds[k] = "";
      const res = await client.api("/api/moderation/config", { method: "POST", body: { config: payload } });
      if (pendingKeys.length > 0) {
        await savePluginSecretsAndRefresh("llm-moderation", pendingCreds);
      }
      if (res.config) {
        state.moderationConfig = res.config;
        state.draftMod = structuredClone(res.config);
      }
      setNotice(
        pendingKeys.length > 0 ? `\u5DF2\u4FDD\u5B58\u5E76\u70ED\u751F\u6548\u5BA1\u6838\u7B56\u7565\uFF08${res.config.mode} / ${res.config.policyProfile}\uFF09\uFF0C\u5E76\u53EA\u5199\u5199\u5165 ${pendingKeys.join("\u3001")}\u3002` : `\u5DF2\u4FDD\u5B58\u5E76\u70ED\u751F\u6548\u5BA1\u6838\u7B56\u7565\uFF08${res.config.mode} / ${res.config.policyProfile}\uFF09\u3002`
      );
    });
    const makeLiveInput = ({ type = "text", list, value, placeholder, changeKey, onAssign }) => el("input", {
      type,
      ...list ? { list } : {},
      class: `lw-input lw-mono ${changed.has(changeKey) ? "is-delta" : ""}`,
      value: value || "",
      placeholder,
      onInput: (e) => {
        onAssign(e.target.value);
        syncModerationLiveRegions(savedCfg, commitSaveConfig);
      }
    });
    const localModelInput = makeLiveInput({
      list: datalistId,
      value: cfg.localGuard?.model,
      placeholder: "llama-guard3:1b \u6216 qwen3.5:9b",
      changeKey: "lgModel",
      onAssign: (v) => {
        cfg.localGuard = { ...cfg.localGuard || {}, model: v };
      }
    });
    const localEpInput = makeLiveInput({
      type: "url",
      value: cfg.localGuard?.endpoint,
      placeholder: "http://127.0.0.1:11434 (Ollama \u9ED8\u8BA4\u56DE\u73AF\u6216\u53D7\u4FE1\u4EFB\u5C40\u57DF\u7F51)",
      changeKey: "lgEndpoint",
      onAssign: (v) => {
        cfg.localGuard = { ...cfg.localGuard || {}, endpoint: v };
      }
    });
    const canaryModelInput = makeLiveInput({
      list: datalistId,
      value: cfg.canary?.model,
      placeholder: "qwen2.5:0.5b \u6216 qwen3:0.6b",
      changeKey: "cnModel",
      onAssign: (v) => {
        cfg.canary = { ...cfg.canary || {}, model: v };
      }
    });
    const canaryEpInput = makeLiveInput({
      type: "url",
      value: cfg.canary?.endpoint,
      placeholder: "http://127.0.0.1:11434 (Zero-Tool \u91D1\u4E1D\u96C0\u63A2\u9488)",
      changeKey: "cnEndpoint",
      onAssign: (v) => {
        cfg.canary = { ...cfg.canary || {}, endpoint: v };
      }
    });
    const cloudEpInput = makeLiveInput({
      type: "url",
      value: cfg.cloudEndpoint,
      placeholder: cloudMeta.endpointPlaceholder,
      changeKey: "cloudEndpoint",
      onAssign: (v) => {
        cfg.cloudEndpoint = v;
      }
    });
    const allReqCredsSaved = cloudMeta.creds.every((c) => c.optional || savedSecKeys.has(c.key));
    const pendingCredBatch = collectPendingCloudCreds(cfg.cloudProvider);
    const pendingCredCount = Object.keys(pendingCredBatch).length;
    const saveCredBtn = makeIconButton({
      text: pendingCredCount > 0 ? `\u53EA\u5199\u4FDD\u5B58 ${pendingCredCount} \u9879\u4E91\u7AEF\u5BC6\u94A5` : "\u53EA\u5199\u4FDD\u5B58\u4E91\u7AEF API \u5BC6\u94A5",
      iconName: "key",
      className: `lw-btn lw-btn-sm ${pendingCredCount > 0 ? "lw-btn-primary" : ""}`,
      disabled: state.busy,
      onClick: () => {
        const batch = collectPendingCloudCreds(cfg.cloudProvider);
        const keys = Object.keys(batch);
        if (keys.length === 0) {
          setError(`\u8BF7\u5148\u586B\u5199 ${cloudMeta.shortLabel} \u7684 API \u5BC6\u94A5\u540E\u518D\u70B9\u51FB\u4FDD\u5B58\u3002`);
          return;
        }
        for (const k of keys) state.draftCloudCreds[k] = "";
        void runMutation(async () => {
          await savePluginSecretsAndRefresh("llm-moderation", batch);
          setNotice(`\u5DF2\u53EA\u5199\u52A0\u5BC6\u4FDD\u5B58 ${cloudMeta.shortLabel} \u5BC6\u94A5\uFF1A${keys.join("\u3001")}\uFF08\u540E\u7AEF\u4E0D\u56DE\u663E\u660E\u6587\uFF09\u3002`);
        });
      }
    });
    const refreshCredButtonState = () => {
      const cnt = Object.keys(collectPendingCloudCreds(cfg.cloudProvider)).length;
      const span = saveCredBtn.querySelector("span");
      if (span) span.textContent = cnt > 0 ? `\u53EA\u5199\u4FDD\u5B58 ${cnt} \u9879\u4E91\u7AEF\u5BC6\u94A5` : "\u53EA\u5199\u4FDD\u5B58\u4E91\u7AEF API \u5BC6\u94A5";
      saveCredBtn.className = `lw-btn lw-btn-sm ${cnt > 0 ? "lw-btn-primary" : ""}`;
    };
    const credFields = cloudMeta.creds.map((cred) => {
      const isSaved = savedSecKeys.has(cred.key);
      const inputNode = el("input", {
        type: "password",
        autocomplete: "new-password",
        class: "lw-input lw-mono",
        value: state.draftCloudCreds[cred.key] || "",
        placeholder: isSaved ? "\u5DF2\u5B89\u5168\u5199\u5165\uFF0C\u8F93\u5165\u65B0\u503C\u53EF\u8986\u76D6\u66F4\u65B0" : cred.placeholder,
        "data-cloud-cred-key": cred.key,
        onInput: (e) => {
          state.draftCloudCreds[cred.key] = e.target.value;
          refreshCredButtonState();
        }
      });
      const toggleBtn = el("button", {
        type: "button",
        class: "lw-secret-toggle",
        text: "\u663E\u793A",
        onClick: () => {
          const show = inputNode.type === "password";
          inputNode.type = show ? "text" : "password";
          toggleBtn.textContent = show ? "\u9690\u85CF" : "\u663E\u793A";
        }
      });
      const labelNode = el("span", { class: "lw-row lw-between", style: "width:100%" }, [
        el("span", {}, [
          el("span", { text: cred.label }),
          el("span", { text: " " }),
          el("code", { class: "lw-tag-inline", text: cred.key })
        ]),
        el("span", {
          class: `lw-tag-status ${isSaved ? "is-ok" : cred.optional ? "" : "is-warn"}`,
          text: isSaved ? "\u5DF2\u5199\u5165\uFF08\u4E0D\u56DE\u663E\uFF09" : cred.optional ? "\u53EF\u9009" : "\u672A\u8BBE\u7F6E"
        })
      ]);
      return makeField(labelNode, el("div", { class: "lw-secret-input-wrap" }, [inputNode, toggleBtn]), {
        fullWidth: cloudMeta.creds.length === 1
      });
    });
    const ollamaCount = Array.isArray(state.ollama?.models) ? state.ollama.models.length : 0;
    const tabBar = el("div", { class: "lw-view-tabs", role: "tablist" }, [
      el("button", {
        type: "button",
        role: "tab",
        "aria-selected": String(state.modTab === "routing"),
        class: `lw-view-tab ${state.modTab === "routing" ? "is-active" : ""}`,
        onClick: () => {
          state.modTab = "routing";
          render();
        }
      }, [
        makeIcon("layers"),
        el("span", { text: "\u7B56\u7565\u8DEF\u7531\u4E0E\u5B9E\u65F6\u63A8\u6F14" }),
        diffs.length > 0 ? el("span", { class: "lw-delta-tag", text: String(diffs.length) }) : null
      ]),
      el("button", {
        type: "button",
        role: "tab",
        "aria-selected": String(state.modTab === "ollama"),
        class: `lw-view-tab ${state.modTab === "ollama" ? "is-active" : ""}`,
        onClick: () => {
          state.modTab = "ollama";
          if (!state.ollama && !state.ollamaLoading) void loadOllamaStatus({ silent: true });
          render();
        }
      }, [
        makeIcon("cpu"),
        el("span", { text: "Ollama \u672C\u5730\u8FD0\u884C\u65F6\u4E0E\u6A21\u578B" }),
        el("span", { class: `lw-pill ${state.ollama?.running ? "lw-pill-ok" : ""}`, text: state.ollama?.running ? `${ollamaCount} \u6A21\u578B` : "\u5F85\u63A2\u6D4B" })
      ])
    ]);
    const routingSplit = el("div", { class: "lw-doc-split" }, [
      el("div", { class: "lw-doc-main" }, [
        el("section", { class: "lw-section" }, [
          el("div", { class: "lw-section-head" }, [
            el("div", {}, [
              el("h3", { text: "1. \u5BA1\u67E5\u6A21\u5F0F\u4E0E\u6545\u969C\u56DE\u9000\u9884\u8BBE" }),
              el("p", { text: "\u9009\u62E9\u8DEF\u7531\u6A21\u5F0F\u4E0E\u5F02\u5E38\u7B56\u7565\uFF1B\u53F3\u4FA7\u67B6\u6784\u56FE\u5B9E\u65F6\u95EA\u70C1\u6807\u6CE8\u5373\u5C06\u53D8\u66F4\u7684\u8282\u70B9\u4E0E\u8FDE\u63A5\u3002" })
            ])
          ]),
          makeField("\u5185\u5BB9\u5BA1\u67E5\u6A21\u5F0F (mode)", makeOptionCards({
            value: cfg.mode,
            savedValue: savedCfg.mode,
            options: [
              { value: "local-only", title: "\u6A21\u5F0F 1 \xB7 \u7EAF\u672C\u5730 Guard", icon: "shieldCheck", badge: "\u96F6\u5916\u53D1", badgeTone: "ok", desc: "\u4EC5\u7531\u672C\u673A / \u5C40\u57DF\u7F51 Guard \u6A21\u578B\u6216\u786E\u5B9A\u6027\u89C4\u5219\u88C1\u51B3\uFF0C\u7EDD\u4E0D\u89E6\u53D1\u5916\u90E8\u7F51\u7EDC\u3002" },
              { value: "guard-plus-canary", title: "\u6A21\u5F0F 2 \xB7 Guard + Canary \u9632\u8BF1\u5BFC", icon: "radar", badge: "\u6DF1\u5EA6\u63A2\u6D4B", badgeTone: "info", desc: "\u53CC\u6A21\u578B\u8054\u52A8\uFF1A\u4E3B Guard \u62E6\u622A\u660E\u663E\u8FDD\u89C4\uFF0CZero-Tool \u63A2\u9488\u6355\u83B7\u95F4\u63A5\u6CE8\u5165\u8BF1\u5BFC\u3002" },
              { value: "cloud-first", title: "\u6A21\u5F0F 3 \xB7 \u4E91\u7AEF\u5B89\u5168 API \u4F18\u5148", icon: "cloud", badge: "\u9700 OptIn", badgeTone: "warn", desc: "\u4F18\u5148\u9001\u5F80\u4E91\u5382\u5546\u591A\u6A21\u6001\u5B89\u5168\u63A5\u53E3\uFF0C\u6545\u969C\u540E\u56DE\u9000\u81F3\u672C\u5730\u6A21\u578B\u6216\u4EBA\u5DE5\u590D\u6838\u3002" },
              { value: "hybrid-tiered", title: "\u6DF7\u5408\u5206\u7EA7\u8DEF\u7531 (Hybrid Tiered)", icon: "layers", badge: "\u7070\u533A\u5347\u7EA7", badgeTone: "info", desc: "\u672C\u5730\u6781\u901F\u8FC7\u6EE4\uFF0C\u4EC5\u5C06\u7070\u533A\u6837\u672C\u5347\u7EA7\u9001\u5F80\u4E91\u7AEF\u6216\u4EBA\u5DE5\u5BA1\u6838\uFF0C\u517C\u987E\u6027\u80FD\u4E0E\u9690\u79C1\u3002" }
            ],
            onSelect: (v) => {
              cfg.mode = v;
              render();
            }
          })),
          makeField("\u6545\u969C\u56DE\u9000\u7B56\u7565\u9884\u8BBE (policyProfile)", makeSegmentedChoice({
            value: cfg.policyProfile,
            savedValue: savedCfg.policyProfile,
            options: [
              { value: "experimental-resilient", label: "\u5B9E\u9A8C\u5F39\u6027 (Resilient)", icon: "bolt" },
              { value: "balanced", label: "\u5747\u8861\u9632\u7EBF (Balanced)", icon: "shield" },
              { value: "strict", label: "\u4E25\u683C\u95ED\u9501 (Strict)", icon: "lock" }
            ],
            onSelect: (v) => {
              cfg.policyProfile = v;
              render();
            }
          }))
        ]),
        el("section", { class: "lw-section" }, [
          el("div", { class: "lw-section-head" }, [
            el("div", {}, [
              el("h3", { text: "2. \u6821\u9A8C\u8303\u56F4\u4E0E\u4E91\u7AEF\u5916\u53D1\u6388\u6743" }),
              el("p", { text: "\u63A7\u5236\u5DE5\u5177\u53C2\u6570/\u8F93\u51FA\u7684\u62E6\u622A\u8303\u56F4\uFF0C\u4EE5\u53CA\u662F\u5426\u5141\u8BB8\u5411\u6240\u9009\u4E91\u7AEF\u63A5\u53E3\u53D1\u9001\u5BA1\u8BA1\u8F7D\u8377\u3002" })
            ])
          ]),
          makeField("\u9ED8\u8BA4\u6821\u9A8C\u8303\u56F4 (defaultScope)", makeSegmentedChoice({
            value: cfg.defaultScope,
            savedValue: savedCfg.defaultScope,
            options: [
              { value: "combined", label: "\u53CC\u5411\u5173\u8054 (combined)", icon: "layers" },
              { value: "input-only", label: "\u4EC5\u5165\u53C2\u9884\u68C0", icon: "shield" },
              { value: "output-only", label: "\u4EC5\u8F93\u51FA/\u6D41\u5F0F", icon: "bolt" }
            ],
            onSelect: (v) => {
              cfg.defaultScope = v;
              render();
            }
          })),
          el("div", { class: "lw-form-grid" }, [
            makeField("\u4E91\u7AEF\u5BA1\u6838\u5382\u5546 (cloudProvider)", cloudProvSel),
            ...cloudRegionSel ? [
              makeField("\u4E91\u7AEF\u670D\u52A1\u5730\u57DF (cloudRegion)", cloudRegionSel),
              makeField("\u4E91\u7AEF\u81EA\u5B9A\u4E49 HTTPS \u7AEF\u70B9\uFF08\u53EF\u9009\uFF09", cloudEpInput, { fullWidth: true })
            ] : [makeField("\u4E91\u7AEF\u81EA\u5B9A\u4E49 HTTPS \u7AEF\u70B9\uFF08\u53EF\u9009\uFF09", cloudEpInput)]
          ]),
          el("div", { class: "lw-doc-callout", text: cloudMeta.docSummary }),
          el("div", { class: "lw-cred-strip" }, [
            el("div", { class: "lw-cred-head" }, [
              el("div", {}, [
                el("div", { class: "lw-cred-title", text: `${cloudMeta.shortLabel} API \u51ED\u636E\uFF08\u547D\u540D\u7A7A\u95F4 llm-moderation\uFF09` }),
                el("div", { class: "lw-switch-sub", text: "\u4EC5\u5199\u52A0\u5BC6\u5B58\u5165\u53D7\u4FDD\u62A4\u51ED\u636E\u5E93\uFF1B\u53EF\u72EC\u7ACB\u70B9\u51FB\u4FDD\u5B58\uFF0C\u4E5F\u53EF\u968F\u4E0B\u65B9\u7B56\u7565\u4FDD\u5B58\u4E00\u5E76\u5199\u5165\u3002" })
              ]),
              el("span", {
                class: `lw-pill ${allReqCredsSaved ? "lw-pill-ok" : "lw-pill-warn"}`,
                text: allReqCredsSaved ? "\u51ED\u636E\u5DF2\u5C31\u7EEA\uFF08\u4EC5\u5199\u4E0D\u56DE\u663E\uFF09" : "\u5F85\u586B\u5199 API \u5BC6\u94A5"
              })
            ]),
            el("div", { class: "lw-form-grid" }, credFields),
            el("div", { class: "lw-row lw-between" }, [
              el("span", { class: "lw-switch-sub", text: "\u63D0\u4EA4\u81F3 POST /api/plugin-secrets/save\uFF0C\u4EC5\u7531\u8FDB\u7A0B\u5916\u5BA1\u67E5\u5F15\u64CE\u9274\u6743\u4F7F\u7528\u3002" }),
              saveCredBtn
            ])
          ]),
          el("div", { class: "lw-setting-list" }, [
            makeSwitchCard({
              checked: Boolean(cfg.cloudOptIn),
              onChange: (next) => {
                cfg.cloudOptIn = next;
                render();
              },
              title: "\u5168\u5C40\u5F00\u542F\u4E91\u7AEF\u5185\u5BB9\u5B89\u5168 API \u5916\u53D1\u8BB8\u53EF\uFF08cloudOptIn\uFF09",
              subtitle: "\u5F00\u542F\u4E14\u4F7F\u7528\u4E91\u7AEF/\u6DF7\u5408\u6A21\u5F0F\u65F6\uFF0C\u5DF2\u7EB3\u5165\u7B56\u7565\u7684\u5DE5\u5177\u5165\u53C2\u53CA\u8F93\u51FA\u5C06\u53D1\u9001\u81F3\u6240\u9009\u4E91\u5382\u5546",
              pillText: cfg.cloudOptIn ? "\u5916\u53D1\u5DF2\u653E\u884C" : "\u4EC5\u672C\u5730\u95ED\u73AF",
              pillTone: cfg.cloudOptIn ? "warn" : "info",
              iconName: "cloud",
              isDelta: changed.has("cloudOptIn")
            })
          ])
        ]),
        el("section", { class: "lw-section" }, [
          el("div", { class: "lw-section-head" }, [
            el("div", {}, [
              el("h3", { text: "3. Local Guard & Canary \u63A8\u7406\u5F15\u64CE" }),
              el("p", { text: "\u9700\u5B89\u88C5\u6216\u62C9\u53D6\u6A21\u578B\u8BF7\u5207\u6362\u4E0A\u65B9\u300COllama \u672C\u5730\u8FD0\u884C\u65F6\u4E0E\u6A21\u578B\u300D\u6807\u7B7E\u9875\uFF1BLAN HTTP \u9ED8\u8BA4\u9694\u79BB\u5143\u6570\u636E\u4E0E\u516C\u7F51\u660E\u6587\u3002" })
            ]),
            makeIconButton({
              text: `\u7BA1\u7406 Ollama \u6A21\u578B (${ollamaCount})`,
              iconName: "cpu",
              className: "lw-btn lw-btn-sm",
              onClick: () => {
                state.modTab = "ollama";
                if (!state.ollama && !state.ollamaLoading) void loadOllamaStatus({ silent: true });
                render();
              }
            })
          ]),
          makeField("\u672C\u5730 Guard \u5F15\u64CE\u7C7B\u578B (localGuard.kind)", makeSegmentedChoice({
            value: localKind,
            savedValue: savedCfg.localGuard?.kind || "http",
            options: [
              { value: "ollama", label: "Ollama \u539F\u751F (/api/chat)", icon: "cpu" },
              { value: "http", label: "OpenAI-Compat HTTP", icon: "server" },
              { value: "managed-python", label: "\u6258\u7BA1 Python \u89C4\u5219\u5F15\u64CE", icon: "terminal" }
            ],
            onSelect: (nextKind) => {
              const prevEp = (cfg.localGuard?.endpoint || "").trim();
              cfg.localGuard = {
                ...cfg.localGuard || {},
                kind: nextKind,
                ...nextKind === "ollama" && !prevEp ? { endpoint: "http://127.0.0.1:11434" } : {}
              };
              render();
            }
          })),
          el("div", { class: "lw-form-grid" }, [
            makeField("\u672C\u5730 Guard \u6A21\u578B\u540D (localGuard.model)", localModelInput),
            makeField("\u672C\u5730 Guard \u7AEF\u70B9 URL (localGuard.endpoint)", localEpInput)
          ]),
          el("div", { class: "lw-setting-list" }, [
            makeSwitchCard({
              checked: cfg.localGuard?.think !== true,
              onChange: (next) => {
                cfg.localGuard = { ...cfg.localGuard || {}, think: !next };
                render();
              },
              title: "\u5173\u95ED Guard \u601D\u8003\u94FE\u8F93\u51FA\uFF08Ollama \u53D1\u9001 think=false\uFF09",
              subtitle: "\u4E3A Qwen3 / DeepSeek-R1 \u7B49\u63A8\u7406\u6A21\u578B\u7701\u53BB\u6570\u79D2\u5197\u4F59\u601D\u8003\u5EF6\u65F6",
              pillText: cfg.localGuard?.think !== true ? "think=false" : "\u601D\u8003\u94FE\u5F00\u542F",
              pillTone: cfg.localGuard?.think !== true ? "info" : "warn",
              iconName: "bolt",
              isDelta: changed.has("lgThink")
            }),
            makeSwitchCard({
              checked: Boolean(cfg.localGuard?.allowPrivateNetwork),
              onChange: (next) => {
                cfg.localGuard = { ...cfg.localGuard || {}, allowPrivateNetwork: next };
                render();
              },
              title: "\u5141\u8BB8 Guard \u8BBF\u95EE\u53D7\u4FE1\u4EFB\u79C1\u6709\u5C40\u57DF\u7F51 HTTP \u8282\u70B9",
              subtitle: "\u9002\u914D\u5185\u7F51\u72EC\u7ACB GPU \u670D\u52A1\u5668\uFF1B\u6301\u7EED\u963B\u65AD 169.254.169.254 \u4E91\u5143\u6570\u636E\u4E0E\u516C\u7F51\u660E\u6587 HTTP",
              pillText: cfg.localGuard?.allowPrivateNetwork ? "\u5C40\u57DF\u7F51 HTTP" : "\u4EC5\u56DE\u73AF/HTTPS",
              pillTone: cfg.localGuard?.allowPrivateNetwork ? "warn" : "info",
              iconName: "server",
              isDelta: changed.has("lgPrivate")
            }),
            makeSwitchCard({
              checked: canaryActive,
              onChange: (next) => {
                cfg.canary = { ...cfg.canary || {}, enabled: next };
                render();
              },
              title: "\u542F\u7528\u5F31\u5C0F\u6A21\u578B Canary \u9632\u8BF1\u5BFC\u63A2\u9488 (canary.enabled)",
              subtitle: "\u5411\u8F7B\u91CF\u63A2\u9488\u6A21\u578B\u5355\u72EC\u9001\u5165\u65E0\u5DE5\u5177\u8BD5\u63A2\u8D1F\u8F7D\uFF0C\u76D1\u6D4B\u662F\u5426\u88AB\u8BF1\u5BFC\u5410\u51FA\u8D8A\u6743\u8C03\u7528",
              pillText: canaryActive ? "\u5DF2\u5C31\u7EEA" : "\u4F11\u7720",
              pillTone: canaryActive ? "info" : "info",
              iconName: "radar",
              isDelta: changed.has("cnEnabled")
            })
          ]),
          makeField("Canary \u5F15\u64CE\u7C7B\u578B (canary.kind)", makeSegmentedChoice({
            value: canaryKind,
            savedValue: savedCfg.canary?.kind || "http",
            options: [
              { value: "ollama", label: "Ollama \u539F\u751F (/api/chat)", icon: "cpu" },
              { value: "http", label: "OpenAI-Compat HTTP", icon: "server" }
            ],
            onSelect: (nextKind) => {
              const prevEp = (cfg.canary?.endpoint || "").trim();
              cfg.canary = {
                ...cfg.canary || {},
                kind: nextKind,
                ...nextKind === "ollama" && !prevEp ? { endpoint: "http://127.0.0.1:11434" } : {}
              };
              render();
            }
          })),
          el("div", { class: "lw-form-grid" }, [
            makeField("Canary \u6A21\u578B\u540D (canary.model)", canaryModelInput),
            makeField("Canary \u7AEF\u70B9 URL (canary.endpoint)", canaryEpInput)
          ]),
          el("div", { class: "lw-setting-list" }, [
            makeSwitchCard({
              checked: Boolean(cfg.canary?.allowPrivateNetwork),
              onChange: (next) => {
                cfg.canary = { ...cfg.canary || {}, allowPrivateNetwork: next };
                render();
              },
              title: "\u5141\u8BB8 Canary \u8BBF\u95EE\u53D7\u4FE1\u4EFB\u79C1\u6709\u5C40\u57DF\u7F51 HTTP \u8282\u70B9",
              subtitle: "\u4ECD\u5F3A\u5236\u62E6\u622A 169.254.169.254 \u4E91\u5143\u6570\u636E\u4E0E\u516C\u7F51\u660E\u6587 HTTP",
              pillText: cfg.canary?.allowPrivateNetwork ? "\u5C40\u57DF\u7F51 HTTP" : "\u4EC5\u56DE\u73AF/HTTPS",
              pillTone: cfg.canary?.allowPrivateNetwork ? "warn" : "info",
              iconName: "server",
              isDelta: changed.has("cnPrivate")
            })
          ]),
          el("div", { "data-mod-savebar-slot": "1" }, [renderModSaveBar(savedCfg, diffs, commitSaveConfig)])
        ])
      ]),
      el("aside", { class: "lw-doc-aside" }, [
        el("div", { "data-mod-preview-slot": "1" }, [renderModerationImpactPreview(savedCfg, cfg)])
      ])
    ]);
    return el("div", { class: "lw-stack-md" }, [
      makePageHeader("LLM \u591A\u6A21\u6001\u5185\u5BB9\u5B89\u5168\u5BA1\u67E5\u7B56\u7565", "\u70ED\u66F4\u65B0 <stateDir>/moderation/config.json\uFF080600\uFF09\uFF0C\u4F4D\u4E8E\u79BB\u7EBF antileak \u62A4\u680F\u4E4B\u540E\u6309\u7B56\u7565\u6267\u884C\u3002"),
      el("datalist", { id: datalistId }, [...modelChoices].map((name) => el("option", { value: name }))),
      tabBar,
      state.modTab === "ollama" ? renderOllamaManagerCard() : routingSplit
    ]);
  }
  function renderSecretsPage() {
    const units = state.pluginSecretUnits || [];
    const totalKeys = units.reduce((acc, u) => acc + (Array.isArray(u?.keys) ? u.keys.length : 0), 0);
    const secUnitInput = el("input", {
      type: "text",
      class: "lw-input lw-mono",
      value: state.draftSecret.unitId,
      placeholder: "llm-moderation",
      onInput: (e) => {
        state.draftSecret.unitId = e.target.value;
      }
    });
    const secKeyInput = el("input", {
      type: "text",
      class: "lw-input lw-mono",
      value: state.draftSecret.key,
      placeholder: "\u5982 OPENAI_API_KEY",
      onInput: (e) => {
        state.draftSecret.key = e.target.value;
      }
    });
    const secValInput = el("input", {
      type: "password",
      autocomplete: "new-password",
      class: "lw-input lw-mono",
      value: state.draftSecret.value,
      placeholder: "\u53EA\u5199\u4FDD\u5B58\uFF0C\u7EDD\u4E0D\u56DE\u663E\u660E\u6587",
      onInput: (e) => {
        state.draftSecret.value = e.target.value;
      }
    });
    const secToggleBtn = el("button", {
      type: "button",
      class: "lw-secret-toggle",
      text: "\u663E\u793A",
      onClick: () => {
        const show = secValInput.type === "password";
        secValInput.type = show ? "text" : "password";
        secToggleBtn.textContent = show ? "\u9690\u85CF" : "\u663E\u793A";
      }
    });
    const presets = [
      ["llm-moderation", "OPENAI_API_KEY"],
      ["llm-moderation", "ALIYUN_ACCESS_KEY_ID"],
      ["llm-moderation", "TENCENT_SECRET_ID"],
      ["llm-moderation", "BAIDU_API_KEY"]
    ];
    const unitRows = units.map((u) => el("div", { class: "lw-hairline-row" }, [
      el("div", { class: "lw-switch-main" }, [
        makeIcon("key"),
        el("div", { class: "lw-switch-copy" }, [
          el("span", { class: "lw-mono lw-switch-label", text: u.unitId }),
          el("span", { class: "lw-switch-sub", text: `KernelGuard caller \u9501\u5B9A\uFF1A\u4EC5 ${u.unitId} \u8FDB\u7A0B\u5916\u5DE5\u4F5C\u5355\u5143\u53EF\u89C1` })
        ])
      ]),
      el("div", { class: "lw-row" }, u.keys && u.keys.length ? u.keys.map((k) => el("span", { class: "lw-pill lw-pill-ok lw-mono", text: k })) : [el("span", { class: "lw-muted", text: "\u65E0\u5DF2\u914D\u7F6E\u5BC6\u94A5" })])
    ]));
    const isolationSvg = svgEl("svg", {
      viewBox: "0 0 356 266",
      class: "lw-svg-diagram",
      role: "img",
      "aria-label": "KernelGuard \u6269\u5C55\u63D2\u4EF6\u5BC6\u94A5\u9694\u79BB\u67B6\u6784\u56FE"
    }, [
      svgEl("path", { d: "M 178 52 L 178 76", class: "lw-svg-wire lw-svg-wire-active" }),
      svgEl("path", { d: "M 178 130 L 178 154", class: "lw-svg-wire lw-svg-wire-active" }),
      svgEl("path", { d: "M 178 206 L 178 226", class: "lw-svg-wire lw-svg-wire-active" }),
      svgNodeBox({
        x: 24,
        y: 8,
        w: 308,
        h: 44,
        title: "1. \u63A7\u5236\u53F0\u53EA\u5199\u63D0\u4EA4 (\u4E0D\u7ECF\u5DE5\u5177/\u65E5\u5FD7)",
        sub: "POST /api/plugin-secrets/save \xB7 \u4EC5\u8FD4\u56DE\u952E\u540D\u6E05\u5355",
        stateCls: "is-active"
      }),
      svgNodeBox({
        x: 24,
        y: 76,
        w: 308,
        h: 54,
        title: "2. \u5BBF\u4E3B\u79C1\u6709\u51ED\u636E\u5206\u4ED3 (0600 \u843D\u76D8)",
        sub: `<stateDir>/plugin-secrets/ \xB7 \u5DF2\u5B58 ${units.length} \u5355\u5143`,
        stateCls: "is-ok"
      }),
      svgNodeBox({
        x: 24,
        y: 154,
        w: 308,
        h: 52,
        title: "3. KernelGuard Caller \u8EAB\u4EFD\u9501\u5B9A",
        sub: "\u4E25\u7981 isolate/intercept \u4E0E\u8DE8\u5355\u5143\u7AA5\u63A2",
        stateCls: "is-ok"
      }),
      svgNodeBox({
        x: 24,
        y: 226,
        w: 308,
        h: 34,
        title: "4. \u4EC5\u5411\u540C\u540D\u8FDB\u7A0B\u5916\u5B50\u8FDB\u7A0B\u6309\u9700\u6CE8\u5165 env",
        sub: "",
        stateCls: "is-active"
      })
    ]);
    const split = el("div", { class: "lw-doc-split" }, [
      el("div", { class: "lw-doc-main" }, [
        makeStatStrip([
          { icon: "key", label: "\u5DF2\u767B\u8BB0\u547D\u540D\u7A7A\u95F4", value: `${units.length} \u4E2A`, tone: units.length > 0 ? "ok" : "" },
          { icon: "shieldCheck", label: "\u5BC6\u94A5\u952E\u603B\u91CF", value: `${totalKeys} \u9879` },
          { icon: "lock", label: "\u7ED1\u5B9A\u673A\u5236", value: "KernelGuard caller" },
          { icon: "eye", label: "\u540E\u7AEF\u56DE\u663E\u7B56\u7565", value: "\u4EC5\u5199\u7EDD\u4E0D\u56DE\u663E", tone: "ok" }
        ]),
        el("section", { class: "lw-section" }, [
          el("div", { class: "lw-section-head" }, [
            el("div", {}, [
              el("h3", { text: "\u5199\u5165\u63D2\u4EF6\u53EA\u5199\u5BC6\u94A5" }),
              el("p", { text: "\u9002\u7528\u4E8E\u5168\u90E8\u8FDB\u7A0B\u5916\u6269\u5C55\u5355\u5143\uFF1B\u5982\u4EC5\u914D\u7F6E\u4E91\u7AEF\u5BA1\u6838\u5BC6\u94A5\uFF0C\u4E5F\u53EF\u76F4\u63A5\u5728\u300CLLM \u5BA1\u67E5\u7B56\u7565\u300D\u9875\u5185\u5206\u5382\u5546\u586B\u5199\u3002" })
            ]),
            makeIconButton({
              text: "\u524D\u5F80 LLM \u7B56\u7565\u914D\u4E91\u7AEF\u5BC6\u94A5",
              iconName: "shieldCheck",
              className: "lw-btn lw-btn-sm",
              onClick: () => navigate("moderation")
            })
          ]),
          el("div", { class: "lw-row" }, [
            el("span", { class: "lw-muted", text: "\u5E38\u7528\u6A21\u677F\uFF1A" }),
            ...presets.map(([uid, k]) => el("button", {
              type: "button",
              class: "lw-btn lw-btn-sm lw-mono",
              text: `${k}`,
              onClick: () => {
                state.draftSecret.unitId = uid;
                state.draftSecret.key = k;
                render();
              }
            }))
          ]),
          el("div", { class: "lw-form-grid-3" }, [
            makeField("\u6269\u5C55\u5355\u5143 ID", secUnitInput),
            makeField("\u73AF\u5883\u53D8\u91CF / \u5BC6\u94A5\u952E\u540D", secKeyInput),
            makeField("\u53EA\u5199\u5BC6\u94A5\u503C", el("div", { class: "lw-secret-input-wrap" }, [secValInput, secToggleBtn]))
          ]),
          el("div", { class: "lw-row lw-between" }, [
            el("span", { class: "lw-switch-sub", text: "\u5BC6\u94A5\u4EC5\u5728\u63D2\u4EF6\u8FDB\u7A0B\u5916\u9274\u6743\u9636\u6BB5\u7531\u5185\u6838\u6309 caller unitId \u6CE8\u5165\uFF0C\u4E0D\u4F1A\u8FD4\u56DE\u6D4F\u89C8\u5668\u3002" }),
            makeIconButton({
              text: "\u53EA\u5199\u4FDD\u5B58\u6269\u5C55\u5BC6\u94A5",
              iconName: "key",
              className: "lw-btn lw-btn-trust lw-btn-sm",
              disabled: state.busy,
              onClick: () => runMutation(async () => {
                const unitId = state.draftSecret.unitId.trim();
                const key = state.draftSecret.key.trim();
                const val = state.draftSecret.value;
                state.draftSecret.value = "";
                const res = await savePluginSecretsAndRefresh(unitId, { [key]: val });
                state.draftSecret.key = "";
                setNotice(`\u5DF2\u53EA\u5199\u4FDD\u5B58 ${res.meta.unitId}#${key}\u3002`);
              })
            })
          ])
        ]),
        el("section", { class: "lw-section" }, [
          el("div", { class: "lw-section-head" }, [
            el("div", {}, [
              el("h3", { text: "\u5DF2\u767B\u8BB0\u53EA\u5199\u5BC6\u94A5\u7D22\u5F15\uFF08\u4EC5\u5C55\u793A\u952E\u540D\uFF09" }),
              el("p", { text: "\u6BCF\u4E2A\u547D\u540D\u7A7A\u95F4\u4E92\u76F8\u4E25\u683C\u9694\u79BB\uFF0C\u4EC5\u540C\u540D\u6269\u5C55\u5355\u5143\u53EF\u51ED\u5BBF\u4E3B\u6388\u6743\u8BFB\u53D6\u3002" })
            ]),
            el("span", { class: "lw-pill lw-pill-info", text: `${units.length} \u4E2A\u547D\u540D\u7A7A\u95F4` })
          ]),
          unitRows.length ? el("div", { class: "lw-setting-list" }, unitRows) : el("div", { class: "lw-doc-callout", text: "\u5C1A\u672A\u5199\u5165\u4EFB\u4F55\u6269\u5C55\u5355\u5143\u5BC6\u94A5\u3002\u53EF\u4F7F\u7528\u4E0A\u65B9\u6A21\u677F\u5FEB\u901F\u586B\u5165\u3002" })
        ])
      ]),
      el("aside", { class: "lw-doc-aside" }, [
        el("div", { class: "lw-section-head" }, [
          el("div", {}, [
            el("h3", { text: "\u8FDB\u7A0B\u5916\u51ED\u636E\u9694\u79BB\u6D41\u5411" }),
            el("p", { text: "\u4FDD\u8BC1\u4E3B\u63A7\u5185\u5B58\u4E0E\u5DE5\u5177\u8F93\u51FA\u96F6\u51ED\u636E\u6CC4\u9732" })
          ]),
          el("span", { class: "lw-pill lw-pill-ok", text: "0600 \u9694\u79BB" })
        ]),
        isolationSvg,
        el("div", { class: "lw-aside-list" }, [
          el("div", { class: "lw-aside-row" }, [
            el("span", { class: "lw-muted", text: "\u8DE8\u63D2\u4EF6\u9694\u79BB" }),
            el("strong", { text: "KernelGuard \u5F3A\u5236\u7ED1\u5B9A caller" })
          ]),
          el("div", { class: "lw-aside-row" }, [
            el("span", { class: "lw-muted", text: "\u660E\u6587\u67E5\u8BE2" }),
            el("strong", { text: "API \u6C38\u4E45\u7981\u6B62\u56DE\u4F20\u660E\u6587" })
          ])
        ])
      ])
    ]);
    return el("div", { class: "lw-stack-md" }, [
      makePageHeader("\u6269\u5C55\u63D2\u4EF6\u5BC6\u94A5\u5E93\uFF08\u53EA\u5199\u9694\u79BB\uFF09", "\u6309 KernelGuard \u7ED1\u5B9A unitId \u5206\u4ED3\u52A0\u5BC6\u843D\u76D8\uFF0C\u524D\u7AEF\u4E0E\u5DE5\u5177\u65E5\u5FD7\u6C38\u8FDC\u65E0\u6CD5\u8BFB\u53D6\u660E\u6587\u3002"),
      split
    ]);
  }
  function statusPillTone(status) {
    if (status === "ok") return "ok";
    if (status === "warn") return "warn";
    if (status === "error") return "err";
    return "info";
  }
  function renderPanelCard(panel) {
    const statusTone = statusPillTone(panel.status);
    const tables = Array.isArray(panel.tables) && panel.tables.length ? panel.tables : panel.table?.columns?.length ? [panel.table] : [];
    const children = [
      el("div", { class: "lw-section-head" }, [
        el("div", {}, [
          el("h3", { text: panel.title }),
          panel.subtitle ? el("p", { text: panel.subtitle }) : null
        ]),
        el("div", { class: "lw-row" }, [
          el("span", { class: "lw-pill", text: panel.category }),
          el("span", { class: `lw-pill lw-pill-${statusTone}`, text: panel.status })
        ])
      ])
    ];
    if (panel.summary?.length) {
      children.push(el("div", { class: "lw-metric-ledger" }, panel.summary.map((kpi) => {
        const toneCls = kpi.tone === "ok" || kpi.tone === "warn" || kpi.tone === "err" ? `is-${kpi.tone}` : "";
        return el("div", { class: `lw-metric-cell ${toneCls}` }, [
          el("div", { class: "lw-metric-k", text: kpi.label }),
          el("div", { class: "lw-metric-v", text: kpi.value })
        ]);
      })));
    }
    if (panel.notices?.length) {
      for (const notice of panel.notices) {
        const cls = notice.tone === "err" ? "is-err" : notice.tone === "warn" ? "is-warn" : notice.tone === "ok" ? "is-ok" : "is-info";
        children.push(el("div", { class: `lw-doc-callout ${cls}`, text: notice.text }));
      }
    }
    for (const table of tables) {
      if (!table?.columns?.length) continue;
      if (table.title) {
        children.push(el("h4", { class: "lw-table-title", text: table.title }));
      }
      children.push(el("div", { class: "lw-table-wrap" }, [
        el("table", { class: "lw-table" }, [
          el("thead", {}, [el("tr", {}, table.columns.map((col) => el("th", { text: col })))]),
          el("tbody", {}, (table.rows || []).map((row) => el("tr", {}, row.map((cell) => el("td", { class: "lw-mono", text: cell })))))
        ])
      ]));
    }
    const safeLinks = Array.isArray(panel.links) ? panel.links.filter((link) => link && isSafeNavigationUrl(link.href, { allowRelative: true })) : [];
    if (safeLinks.length) {
      children.push(el("div", { class: "lw-row" }, safeLinks.map((link) => el("a", {
        class: "lw-btn lw-btn-sm",
        href: link.href,
        target: "_blank",
        rel: "noopener noreferrer",
        text: link.label
      }))));
    }
    return el("section", {
      class: "lw-section",
      "data-panel-id": panel.id
    }, children);
  }
  function renderPanelsPage() {
    const panels = state.snapshot?.panels || [];
    return el("div", { class: "lw-stack-md" }, [
      makePageHeader("\u58F0\u660E\u5F0F\u6269\u5C55\u9762\u677F\uFF08console:panel@1\uFF09", "\u7531\u8FDB\u7A0B\u5916\u63D2\u4EF6\u6309\u7EAF JSON Schema \u58F0\u660E\u5E76\u7531\u4E3B\u673A\u8131\u654F\u6E05\u6D17\u6E32\u67D3\uFF0C\u96F6\u53EF\u6267\u884C\u811A\u672C\u6CE8\u5165\u3002"),
      makeStatStrip([
        { icon: "layoutPanel", label: "\u5DF2\u6302\u8F7D\u6269\u5C55\u9762\u677F", value: `${panels.length} \u4E2A`, tone: panels.length > 0 ? "ok" : "" },
        { icon: "shieldCheck", label: "\u811A\u672C\u4E0E HTML", value: "\u4E25\u683C\u96F6\u6267\u884C\u6CE8\u5165" },
        { icon: "globe", label: "\u5916\u90E8\u94FE\u63A5\u7B56\u7565", value: "\u4EC5\u5B89\u5168\u534F\u8BAE\u767D\u540D\u5355" },
        { icon: "cpu", label: "\u6E32\u67D3\u673A\u5236", value: "\u7EAF JSON \u6570\u636E\u8D26\u672C" }
      ]),
      panels.length ? el("div", { class: "lw-stack-md" }, panels.map(renderPanelCard)) : el("div", { class: "lw-doc-callout", text: "\u5F53\u524D\u672A\u6302\u8F7D\u6CE8\u518C\u6269\u5C55\u9762\u677F\u7684\u63D2\u4EF6\u3002\u4EFB\u4F55\u5B9E\u73B0 console:panel@1 \u5951\u7EA6\u7684\u8FDB\u7A0B\u5916\u63D2\u4EF6\u5747\u4F1A\u5728\u6B64\u81EA\u52A8\u53EA\u8BFB\u5448\u73B0\u3002" })
    ]);
  }
  var AUDIT_META_LABELS = [
    ["reason", "\u7ED3\u679C\u4EE3\u7801"],
    ["durationMs", "\u6267\u884C\u8017\u65F6"],
    ["mountMode", "\u6302\u8F7D\u59FF\u6001"],
    ["mode", "\u8FD0\u884C\u6A21\u5F0F"],
    ["network", "\u5BB9\u5668\u7F51\u7EDC"],
    ["exitCode", "\u9000\u51FA\u7801"],
    ["bytesRead", "\u6587\u4EF6\u8BFB\u53D6\u5B57\u8282"],
    ["bytesWritten", "\u6587\u4EF6\u5199\u5165\u5B57\u8282"],
    ["stdoutBytes", "\u6807\u51C6\u8F93\u51FA\u5B57\u8282"],
    ["stderrBytes", "\u6807\u51C6\u9519\u8BEF\u5B57\u8282"],
    ["outputBytes", "MCP \u8FD4\u56DE\u5B57\u8282"],
    ["serverId", "\u7B2C\u4E09\u65B9 MCP \u670D\u52A1"],
    ["timedOut", "\u662F\u5426\u8D85\u65F6"],
    ["cancelled", "\u662F\u5426\u53D6\u6D88"],
    ["tool", "\u6D89\u53CA\u5DE5\u5177"],
    ["capability", "\u89E6\u53D1\u80FD\u529B"],
    ["approvalIdShort", "\u5BA1\u6279\u77ED\u7801"],
    ["route", "\u8FDE\u63A5\u8DEF\u7531"],
    ["status", "HTTP \u72B6\u6001"],
    ["code", "\u72B6\u6001\u7801"],
    ["outcome", "\u7ED3\u679C\u6807\u8BC6"],
    ["jobIdPrefix", "\u5BB9\u5668\u4F5C\u4E1A\u53F7"]
  ];
  function buildAuditTransportPayload(ev) {
    const meta = ev.meta || {};
    const transportBoundary = ev.source === "audit" ? meta.serverId ? "external-mcp-out-of-process" : "linux-docker-sandbox" : "host-control-plane";
    return {
      key: ev.key || null,
      time: ev.time || null,
      source: ev.source || "connector",
      transportBoundary,
      logFile: ev.source === "audit" ? "audit.jsonl" : "connector.log",
      toolOrEvent: ev.name || null,
      outcome: ev.tone || "info",
      label: ev.label || "",
      detailSummary: ev.detail || "",
      transportMeta: meta,
      redactionNotice: "\u4EC5\u5305\u542B\u7ED3\u6784\u5316\u4F20\u8F93\u5143\u6570\u636E\u4E0E\u5B57\u8282\u8BA1\u6570\uFF0C\u4E25\u7981\u542B\u6587\u4EF6\u6B63\u6587\u6216\u51ED\u636E\u539F\u6587"
    };
  }
  function renderAuditTraceDetail(ev) {
    const meta = ev.meta || {};
    const boundaryLabel = ev.source === "audit" ? meta.serverId ? "\u8FDB\u7A0B\u5916\u7B2C\u4E09\u65B9 MCP\uFF08\u975E\u5BB9\u5668\uFF09" : "Linux Docker \u53EA\u8BFB/\u53D7\u9650\u6C99\u7BB1" : "\u5BBF\u4E3B\u63A7\u5236\u53F0 / \u8FDE\u63A5\u5668\u9065\u6D4B";
    const kvPairs = [
      ["\u65F6\u95F4\u6233", ev.time || "\u2014"],
      ["\u8BB0\u5F55\u6765\u6E90", ev.source === "audit" ? "\u6C99\u76D2\u5BA1\u8BA1 audit.jsonl" : "\u8FDE\u63A5\u5668\u72B6\u6001 connector.log"],
      ["\u4F20\u8F93\u8FB9\u754C", boundaryLabel]
    ];
    for (const [k, label] of AUDIT_META_LABELS) {
      if (meta[k] === void 0 || meta[k] === null || meta[k] === "") continue;
      let val = String(meta[k]);
      if (k === "durationMs") val += " ms";
      else if (typeof meta[k] === "boolean") val = meta[k] ? "\u662F" : "\u5426";
      kvPairs.push([label, val]);
    }
    const jsonText = JSON.stringify(buildAuditTransportPayload(ev), null, 2);
    return el("div", { class: "lw-audit-detail-box" }, [
      el("div", { class: "lw-trace-grid" }, kvPairs.map(([k, v]) => el("div", { class: "lw-trace-kv" }, [
        el("span", { class: "lw-trace-k", text: k }),
        el("span", { class: "lw-trace-v", text: v })
      ]))),
      el("div", { class: "lw-row lw-between" }, [
        el("strong", { style: "font-size:12px", text: "\u8131\u654F Transport / \u5BA1\u8BA1 JSON \u4FE1\u5C01" }),
        makeIconButton({
          text: "\u590D\u5236 Transport JSON",
          iconName: "copy",
          className: "lw-btn lw-btn-sm",
          onClick: () => void copyTextToClipboard(jsonText, `audit-${ev.key || ev.time}`)
        })
      ]),
      el("pre", { class: "lw-pre lw-mono", "data-audit-transport-json": ev.key || "1", text: jsonText })
    ]);
  }
  function renderAuditPage() {
    const events = state.snapshot?.events || [];
    const sseOk = state.sseStatus === "open" || state.sseStatus === "connected";
    const filter = state.auditFilter || "all";
    const visibleAudit = filter === "kernel" ? [] : events.filter((ev) => {
      if (filter === "flagged") return ev.tone === "err" || ev.tone === "warn";
      if (filter === "ok") return ev.tone === "ok";
      return true;
    }).slice(0, 60);
    const visibleKernel = filter === "all" || filter === "kernel" ? state.liveKernelEvents.slice(0, 25) : [];
    const toggleExpandAudit = (evKey) => {
      if (state.expandedAuditKeys[evKey]) delete state.expandedAuditKeys[evKey];
      else state.expandedAuditKeys[evKey] = true;
      render();
    };
    const toggleExpandKernel = (kKey) => {
      if (state.expandedKernelKeys[kKey]) delete state.expandedKernelKeys[kKey];
      else state.expandedKernelKeys[kKey] = true;
      render();
    };
    const auditRows = [];
    visibleAudit.forEach((ev, idx) => {
      const tone = ev.tone === "ok" ? "ok" : ev.tone === "err" ? "err" : ev.tone === "warn" ? "warn" : "info";
      const evKey = ev.key || `${ev.source || "log"}:${ev.time || ""}:${ev.name || ""}:${idx}`;
      const isOpen = Boolean(state.expandedAuditKeys[evKey]);
      auditRows.push(el("tr", {
        class: `lw-audit-row ${isOpen ? "is-open" : ""}`,
        "data-audit-row": evKey,
        onClick: () => toggleExpandAudit(evKey)
      }, [
        el("td", { style: "width:32px;padding-right:4px" }, [
          el("button", {
            type: "button",
            class: `lw-chevron-btn ${isOpen ? "is-open" : ""}`,
            "aria-expanded": String(isOpen),
            "aria-label": "\u5C55\u5F00\u6216\u6536\u8D77\u8C03\u7528\u8BE6\u7EC6 Transport JSON",
            onClick: (e) => {
              e.stopPropagation();
              toggleExpandAudit(evKey);
            }
          }, [makeIcon("chevronRight")])
        ]),
        el("td", { class: "lw-mono", text: ev.time || "" }),
        el("td", {}, [el("span", { class: `lw-pill lw-pill-${tone}`, text: ev.label || ev.source || "info" })]),
        el("td", { class: "lw-mono", text: ev.name || "" }),
        el("td", { class: "lw-muted lw-mono", text: ev.detail || "-" })
      ]));
      if (isOpen) {
        auditRows.push(el("tr", { class: "lw-audit-detail-row" }, [
          el("td", { colSpan: "5" }, [renderAuditTraceDetail(ev)])
        ]));
      }
    });
    const channelRows = [];
    visibleKernel.forEach((ev, idx) => {
      const kKey = ev.id || `${ev.seq ?? idx}:${ev.time || ""}:${ev.type || ""}`;
      const isOpen = Boolean(state.expandedKernelKeys[kKey]);
      const kernelJsonText = JSON.stringify(ev, null, 2);
      channelRows.push(el("tr", {
        class: `lw-audit-row ${isOpen ? "is-open" : ""}`,
        "data-kernel-row": String(kKey),
        onClick: () => toggleExpandKernel(String(kKey))
      }, [
        el("td", { style: "width:32px;padding-right:4px" }, [
          el("button", {
            type: "button",
            class: `lw-chevron-btn ${isOpen ? "is-open" : ""}`,
            "aria-expanded": String(isOpen),
            "aria-label": "\u5C55\u5F00\u6216\u6536\u8D77\u5185\u6838\u4E8B\u4EF6 JSON",
            onClick: (e) => {
              e.stopPropagation();
              toggleExpandKernel(String(kKey));
            }
          }, [makeIcon("chevronRight")])
        ]),
        el("td", { class: "lw-mono", text: ev.time || "" }),
        el("td", {}, [el("span", { class: "lw-pill lw-pill-info lw-mono", text: ev.type || "" })]),
        el("td", {}, [el("div", { class: "lw-meta-chips" }, formatMetaChips(ev.meta))])
      ]));
      if (isOpen) {
        channelRows.push(el("tr", { class: "lw-audit-detail-row" }, [
          el("td", { colSpan: "4" }, [
            el("div", { class: "lw-audit-detail-box" }, [
              el("div", { class: "lw-row lw-between" }, [
                el("strong", { style: "font-size:12px", text: "control.sock \u4E8B\u4EF6\u539F\u59CB\u8131\u654F JSON" }),
                makeIconButton({
                  text: "\u590D\u5236 JSON",
                  iconName: "copy",
                  className: "lw-btn lw-btn-sm",
                  onClick: () => void copyTextToClipboard(kernelJsonText, `kernel-${kKey}`)
                })
              ]),
              el("pre", { class: "lw-pre lw-mono", text: kernelJsonText })
            ])
          ])
        ]));
      }
    });
    return el("div", { class: "lw-stack-md" }, [
      makePageHeader("\u5B9E\u65F6\u5BA1\u8BA1\u901A\u9053", "\u7ECF\u7531\u8FDB\u7A0B\u5185\u901A\u9053\u4E0E\u79C1\u6709 0600 control.sock \u63A8\u6D41\u7684\u5143\u6570\u636E\u4E0E\u5DE5\u5177\u62E6\u622A\u5386\u53F2\uFF1B\u70B9\u51FB\u4EFB\u610F\u8BB0\u5F55\u884C\u53EF\u5C55\u5F00\u8BE6\u7EC6 Trace \u4E0E Transport JSON\u3002"),
      makeStatStrip([
        { icon: "activity", label: "SSE \u5B9E\u65F6\u901A\u9053", value: sseOk ? "\u5728\u7EBF\u63A8\u9001\u4E2D" : state.sseStatus, tone: sseOk ? "ok" : "warn" },
        { icon: "terminal", label: "\u5185\u6838\u63A7\u5236\u4E8B\u4EF6", value: `${state.liveKernelEvents.length} \u6761` },
        { icon: "clipboardCheck", label: "\u5BA1\u8BA1\u9065\u6D4B\u8BB0\u5F55", value: `${events.length} \u6761` },
        { icon: "lock", label: "\u9065\u6D4B\u8131\u654F\u7B56\u7565", value: "\u4EC5\u5143\u6570\u636E \xB7 \u96F6\u6B63\u6587", tone: "ok" }
      ]),
      makeField("\u89C6\u56FE\u8FC7\u6EE4\u7B5B\u9009", makeSegmentedChoice({
        value: filter,
        options: [
          { value: "all", label: "\u5168\u90E8\u8BB0\u5F55", icon: "layers" },
          { value: "flagged", label: "\u62E6\u622A\u4E0E\u5F02\u5E38", icon: "alert" },
          { value: "ok", label: "\u653E\u884C\u901A\u8FC7", icon: "check" },
          { value: "kernel", label: "\u63A7\u5236\u901A\u9053\u4E8B\u4EF6", icon: "terminal" }
        ],
        onSelect: (v) => {
          state.auditFilter = v;
          render();
        }
      })),
      filter !== "kernel" ? el("section", { class: "lw-section" }, [
        el("div", { class: "lw-section-head" }, [
          el("div", {}, [
            el("h3", { text: "\u5BA1\u8BA1\u4E0E\u8FDE\u63A5\u5668\u9065\u6D4B\u6D41\uFF08\u70B9\u51FB\u4EFB\u610F\u884C\u5C55\u5F00 Transport JSON\uFF09" }),
            el("p", { text: "\u5C55\u793A\u5DE5\u5177\u8C03\u7528\u3001\u4EBA\u5DE5\u5BA1\u6279\u51B3\u5B9A\u4E0E\u62A4\u680F\u62E6\u622A\uFF1B\u5C55\u5F00\u53EF\u89C1\u4F20\u8F93\u8FB9\u754C\u3001\u5B57\u8282\u8BA1\u6570\u4E0E\u5B8C\u6574\u8131\u654F JSON \u4FE1\u5C01\u3002" })
          ]),
          el("div", { class: "lw-row" }, [
            el("button", {
              type: "button",
              class: "lw-btn lw-btn-sm",
              text: "\u5168\u90E8\u5C55\u5F00",
              disabled: visibleAudit.length === 0,
              onClick: () => {
                visibleAudit.forEach((ev, idx) => {
                  state.expandedAuditKeys[ev.key || `${ev.source || "log"}:${ev.time || ""}:${ev.name || ""}:${idx}`] = true;
                });
                render();
              }
            }),
            el("button", {
              type: "button",
              class: "lw-btn lw-btn-sm",
              text: "\u5168\u90E8\u6536\u8D77",
              disabled: visibleAudit.length === 0,
              onClick: () => {
                state.expandedAuditKeys = {};
                render();
              }
            }),
            el("span", { class: "lw-pill lw-pill-info", text: `${visibleAudit.length} \u6761\u663E\u793A` })
          ])
        ]),
        visibleAudit.length ? el("div", { class: "lw-table-wrap" }, [
          el("table", { class: "lw-table" }, [
            el("thead", {}, [el("tr", {}, [
              el("th", { style: "width:32px", "aria-label": "\u5C55\u5F00" }),
              el("th", { text: "\u65F6\u95F4" }),
              el("th", { text: "\u72B6\u6001" }),
              el("th", { text: "\u5DE5\u5177 / \u4E8B\u4EF6" }),
              el("th", { text: "\u6458\u8981" })
            ])]),
            el("tbody", {}, auditRows)
          ])
        ]) : el("div", { class: "lw-doc-callout", text: "\u5F53\u524D\u7B5B\u9009\u6761\u4EF6\u4E0B\u6682\u65E0\u5386\u53F2\u5BA1\u8BA1\u8BB0\u5F55\u3002" })
      ]) : null,
      filter === "all" || filter === "kernel" ? el("section", { class: "lw-section" }, [
        el("div", { class: "lw-section-head" }, [
          el("div", {}, [
            el("h3", { text: "\u5B9E\u65F6\u5185\u6838\u63A7\u5236\u901A\u9053\u4E8B\u4EF6\uFF08control.sock \u5143\u6570\u636E\uFF0C\u70B9\u51FB\u53EF\u5C55\u5F00\u5B8C\u6574 JSON\uFF09" }),
            el("p", { text: "\u81EA\u52A8\u7ED3\u6784\u5316\u62C6\u89E3\u4E8B\u4EF6\u5B57\u6BB5\u5E76\u4FDD\u7559\u539F\u59CB\u8131\u654F JSON\uFF0C\u7EDD\u4E0D\u56DE\u4F20\u8BF7\u6C42\u539F\u6587\u4E0E\u51ED\u636E\u3002" })
          ]),
          el("div", { class: "lw-row" }, [
            el("button", {
              type: "button",
              class: "lw-btn lw-btn-sm",
              text: "\u5168\u90E8\u5C55\u5F00",
              disabled: visibleKernel.length === 0,
              onClick: () => {
                visibleKernel.forEach((ev, idx) => {
                  state.expandedKernelKeys[String(ev.id || `${ev.seq ?? idx}:${ev.time || ""}:${ev.type || ""}`)] = true;
                });
                render();
              }
            }),
            el("button", {
              type: "button",
              class: "lw-btn lw-btn-sm",
              text: "\u5168\u90E8\u6536\u8D77",
              disabled: visibleKernel.length === 0,
              onClick: () => {
                state.expandedKernelKeys = {};
                render();
              }
            }),
            el("span", { class: "lw-pill lw-pill-info", text: `${visibleKernel.length} \u6761\u663E\u793A` })
          ])
        ]),
        visibleKernel.length ? el("div", { class: "lw-table-wrap" }, [
          el("table", { class: "lw-table" }, [
            el("thead", {}, [el("tr", {}, [
              el("th", { style: "width:32px", "aria-label": "\u5C55\u5F00" }),
              el("th", { text: "\u65F6\u95F4" }),
              el("th", { text: "\u4E8B\u4EF6\u7C7B\u578B" }),
              el("th", { text: "\u7ED3\u6784\u5316\u5143\u6570\u636E\u5B57\u6BB5" })
            ])]),
            el("tbody", {}, channelRows)
          ])
        ]) : el("div", { class: "lw-doc-callout", text: "\u6682\u65E0\u5B9E\u65F6\u63A7\u5236\u901A\u9053\u4E8B\u4EF6\u3002\u5F53\u53D1\u751F\u5DE5\u5177\u5BA1\u6279\u3001\u7B56\u7565\u53D8\u66F4\u6216\u6D41\u5F0F\u62E6\u622A\u65F6\u5C06\u5373\u65F6\u51FA\u73B0\u3002" })
      ]) : null
    ]);
  }
  var CONSOLE_HTTP_CONTRACTS = [
    {
      id: "status",
      method: "GET",
      path: "/api/status",
      group: "\u603B\u89C8\u4E0E\u72B6\u6001",
      title: "\u5168\u6808\u8FD0\u884C\u5FEB\u7167\u4E0E\u805A\u5408\u5DE5\u5177\u76EE\u5F55",
      summary: "\u8FD4\u56DE\u8FDE\u63A5\u5668\u5728\u7EBF\u6001\u3001capabilities.effectiveTools\u3001\u7B2C\u4E09\u65B9 MCP \u6458\u8981\u3001\u5BA1\u6279\u961F\u5217\u3001\u9762\u677F\u6E05\u5355\u4E0E\u8FD1 60 \u6761\u5BA1\u8BA1\u5143\u6570\u636E\u3002",
      canTryGet: true,
      params: [],
      bounds: ["\u4E25\u683C\u540C\u6E90 loopback \u9274\u6743\uFF08X-LoomWard-Tab-Auth\uFF09", "\u7EDD\u4E0D\u8FD4\u56DE\u660E\u6587\u5BC6\u94A5\u3001\u79C1\u6709\u4ED3\u540D\u6216\u8BF7\u6C42\u6B63\u6587\u5B57\u6BB5"]
    },
    {
      id: "capabilities",
      method: "POST",
      path: "/api/capabilities",
      group: "\u5B89\u5168\u7B56\u7565",
      title: "\u539F\u5B50\u66F4\u65B0\u80FD\u529B\u5F00\u5173\u4E0E\u5355\u5DE5\u5177\u542F\u505C",
      summary: "\u5199\u5165 0600 <stateDir>/capabilities.json\uFF1B\u652F\u6301\u9876\u5C42 fileRead / fileWrite / allowExec \u4E0E\u5355\u5DE5\u5177\u5F00\u5173\u6620\u5C04 tools\u3002",
      canTryGet: false,
      bodyExample: { fileRead: true, fileWrite: false, allowExec: false, tools: { read_file: true } },
      params: [
        { name: "fileRead", type: "boolean", required: false, description: "\u662F\u5426\u5141\u8BB8 read_file / list_directory / search_files" },
        { name: "fileWrite", type: "boolean", required: false, description: "\u5173\u95ED\u65F6\u5F3A\u5236\u5BB9\u5668\u5DE5\u4F5C\u533A\u964D\u7EA7\u4E3A :readonly \u53EA\u8BFB\u6302\u8F7D" },
        { name: "allowExec", type: "boolean", required: false, description: "\u662F\u5426\u5F00\u653E exec_command\uFF08\u4E0D\u53EF\u7A81\u7834\u914D\u7F6E\u4E0A\u9650\uFF09" },
        { name: "tools", type: "object", required: false, description: "\u6309\u5DE5\u5177\u540D\u5355\u72EC\u7981\u7528/\u6062\u590D\u7684\u6620\u5C04\uFF08false \u4E3A\u505C\u7528\uFF09" }
      ],
      bounds: ["\u9700\u6821\u9A8C X-LoomWard-CSRF + Origin + Same-Site", "\u4E0D\u5141\u8BB8\u5728\u5DE5\u4F5C\u533A\u76EE\u5F55\u5185\u5B58\u50A8\u914D\u7F6E\u6587\u4EF6"]
    },
    {
      id: "fencing-config-get",
      method: "GET",
      path: "/api/fencing/config",
      group: "Agent \u56F4\u680F",
      title: "\u8BFB\u53D6 R1\u2013R7 \u9632\u6CC4\u6F0F\u89C4\u5219\u4E0E\u7F13\u5B58\u5065\u5EB7\u5EA6",
      summary: "\u8FD4\u56DE <stateDir>/antileak/policy.json \u7B56\u7565\u914D\u7F6E\u3001R1\u2013R7 \u89C4\u5219\u76EE\u5F55\u53CA private-repos.json \u8BA1\u6570/\u8FC7\u671F\u65F6\u95F4\uFF08\u8131\u654F\uFF0C\u7EDD\u4E0D\u8FD4\u79C1\u6709\u540D\uFF09\u3002",
      canTryGet: true,
      params: [],
      bounds: ["\u53EA\u8FD4\u56DE privateCount / patternCount / status\uFF0C\u4E25\u7981\u8FD4\u56DE\u79C1\u6709\u4ED3\u540D\u5B57\u6216 R4 \u6B63\u5219\u5168\u6587"]
    },
    {
      id: "fencing-config-save",
      method: "POST",
      path: "/api/fencing/config",
      group: "Agent \u56F4\u680F",
      title: "\u4FDD\u5B58 R1\u2013R7 \u9632\u6CC4\u6F0F\u56F4\u680F\u7B56\u7565",
      summary: "\u7ECF\u670D\u52A1\u7AEF Python re.compile \u8BED\u6CD5\u9884\u68C0\u540E\u539F\u5B50\u4FDD\u5B58 0600 policy.json\uFF0C\u5E76\u56FA\u5B9A private_cache \u8DEF\u5F84\u81F3\u53D7\u4FDD\u62A4\u76EE\u5F55\u3002",
      canTryGet: false,
      bodyExample: { config: { forbiddenPatterns: ["INTERNAL_CODENAME"], expectedOwners: ["your-org"], privateCacheTtl: 28800, resignExempt: true } },
      params: [
        { name: "config.forbiddenPatterns", type: "string[]", required: false, description: "R2 \u7981\u6B62\u6A21\u5F0F\u6B63\u5219\u5217\u8868\uFF08Python re \u8BED\u6CD5\uFF09" },
        { name: "config.secretRegexes", type: "string[]", required: false, description: "R7 \u51ED\u636E/\u79C1\u94A5\u6B63\u5219\u5217\u8868" },
        { name: "config.expectedOwners", type: "string[]", required: false, description: "R1 \u79C1\u6709\u4ED3\u5F52\u5C5E\u8005\u767D/\u7EA2\u540D\u5355\u6838\u5BF9\u6E05\u5355" },
        { name: "config.exemptTools", type: "string[]", required: false, description: "\u58F0\u660E\u4E3A\u751F\u547D\u5468\u671F\u63A7\u5236\u800C\u4E0D\u89E6\u72AF\u89C4\u5219\u7684\u8C41\u514D\u5DE5\u5177\u540D" }
      ],
      bounds: ["\u9501\u5B9A private_cache / refresh_script \u8DEF\u5F84\u9632 WebUI \u7BE1\u6539", "\u5F02\u5E38\u6B63\u5219\u7ACB\u65F6\u8FD4\u56DE 400 \u5E76\u62D2\u7EDD\u843D\u76D8"]
    },
    {
      id: "fencing-test",
      method: "POST",
      path: "/api/fencing/test",
      group: "Agent \u56F4\u680F",
      title: "R1\u2013R7 \u79BB\u7EBF Dry-Run \u8F7D\u8377\u8BD5\u9A8C",
      summary: "\u4EE5 strictly offline\uFF08\u6C38\u4E0D\u4F20 --net\uFF09\u62C9\u8D77 check.py content \u68C0\u9A8C\u5408\u6210\u8F93\u5165\uFF0C\u8FD4\u56DE pass / violation / error \u4E09\u6001\u53CA\u8131\u654F\u547D\u4E2D\u7406\u7531\u3002",
      canTryGet: false,
      bodyExample: { text: "git commit check sample payload" },
      params: [
        { name: "text", type: "string", required: true, description: "\u5F85\u68C0\u9A8C\u6587\u672C\u6837\u672C\uFF08\u6700\u5927 256 KiB\uFF09" }
      ],
      bounds: ["\u7F13\u5B58\u7F3A\u5931\u6216\u8FC7\u671F\u65F6\u4E25\u683C\u8FD4\u56DE failClosed: true (error)", "\u4E0D\u56DE\u663E\u5B8C\u6574\u51ED\u636E\u660E\u6587"]
    },
    {
      id: "fencing-refresh",
      method: "POST",
      path: "/api/fencing/refresh",
      group: "Agent \u56F4\u680F",
      title: "\u89E6\u53D1\u5237\u65B0\u79C1\u6709\u4ED3\u7F13\u5B58 (refresh-private.py)",
      summary: "\u663E\u5F0F\u7531\u7BA1\u7406\u5458\u70B9\u51FB\u89E6\u53D1 refresh-private.py\uFF0C\u66F4\u65B0 private-repos.json \u540E\u4EC5\u8FD4\u56DE\u72B6\u6001\u8BA1\u6570\u4E0E\u8017\u65F6\u3002",
      canTryGet: false,
      bodyExample: {},
      params: [],
      bounds: ["\u6C38\u4E0D\u81EA\u52A8\u6267\u884C", "\u54CD\u5E94\u4F53\u5265\u9664\u4E00\u5207\u4ED3\u5E93\u540D\u6E05\u5355\u4E0E\u79CD\u5B50\u6A21\u5F0F"]
    },
    {
      id: "fencing-doctor",
      method: "POST",
      path: "/api/fencing/doctor",
      group: "Agent \u56F4\u680F",
      title: "\u8FD0\u884C\u56F4\u680F\u5F15\u64CE\u5065\u5EB7\u81EA\u68C0 (doctor.py)",
      summary: "\u79BB\u7EBF\u6821\u9A8C\u7B56\u7565 JSON\u3001Python \u73AF\u5883\u3001ssh-keygen\u3001\u7F13\u5B58\u65B0\u9C9C\u5EA6\u53CA\u89C4\u5219\u53EF\u7528\u6027\u3002",
      canTryGet: false,
      bodyExample: {},
      params: [],
      bounds: ["\u9694\u79BB\u73AF\u5883\u53D8\u91CF\u767D\u540D\u5355\u8FD0\u884C\uFF0C\u4E0D\u66B4\u9732\u5BBF\u4E3B\u673A\u79D8\u94A5"]
    },
    {
      id: "mcp-servers-list",
      method: "GET",
      path: "/api/mcp-servers",
      group: "\u7B2C\u4E09\u65B9 MCP",
      title: "\u5217\u51FA\u5DF2\u7EB3\u7BA1\u7B2C\u4E09\u65B9 MCP \u670D\u52A1\uFF08\u8131\u654F\uFF09",
      summary: "\u8FD4\u56DE stdio/http \u4F20\u8F93\u914D\u7F6E\u3001\u5DF2\u4FDD\u5B58\u5BC6\u94A5\u952E\u540D\u6E05\u5355\uFF08envKeys/headerKeys\uFF0C\u4E0D\u56DE\u663E\u503C\uFF09\u53CA\u7F13\u5B58\u7684\u5916\u90E8\u5DE5\u5177\u5143\u6570\u636E\u3002",
      canTryGet: true,
      params: [],
      bounds: ["\u5199\u540E\u4E0D\u53EF\u8BFB\u56DE\u73AF\u5883\u53D8\u91CF\u503C\u4E0E HTTP \u5934\u5BC6\u94A5\u503C"]
    },
    {
      id: "mcp-servers-save",
      method: "POST",
      path: "/api/mcp-servers/save",
      group: "\u7B2C\u4E09\u65B9 MCP",
      title: "\u65B0\u589E/\u66F4\u65B0\u5E76\u5728\u6709\u754C\u9694\u79BB\u4E0B\u63A2\u6D4B MCP \u670D\u52A1",
      summary: "\u6821\u9A8C\u4F20\u8F93\u534F\u8BAE\u4E0E SSRF/\u5371\u9669\u73AF\u5883\u53D8\u91CF\u9ED1\u540D\u5355\uFF0C\u5199\u5165 0600 mcp-servers.json\uFF0C\u5E76\u53EF\u9009\u63A2\u6D4B initialize + tools/list\u3002",
      canTryGet: false,
      bodyExample: { id: "docs_mcp", name: "Docs MCP", transport: "stdio", command: "npx", args: ["-y", "@example/mcp"], probe: true },
      params: [
        { name: "id", type: "string", required: true, description: "\u670D\u52A1\u552F\u4E00\u6807\u8BC6\uFF08\u5C0F\u5199\u5B57\u6BCD/\u6570\u5B57/-\uFF0C1\u201332 \u5B57\u7B26\uFF09" },
        { name: "transport", type: "enum", required: true, description: "stdio \u6216 http (Streamable HTTP)" },
        { name: "command / url", type: "string", required: true, description: "stdio \u542F\u52A8\u53EF\u6267\u884C\u6587\u4EF6\u6216 HTTPS/loopback \u7AEF\u70B9" },
        { name: "probe", type: "boolean", required: false, description: "\u4FDD\u5B58\u540E\u662F\u5426\u7ACB\u5373\u6709\u754C\u63E1\u624B\u63A2\u6D4B\u5E76\u540C\u6B65\u5DE5\u5177\u76EE\u5F55" }
      ],
      bounds: ["\u53D8\u66F4\u547D\u4EE4\u6216 Origin \u65F6\u5982\u4FDD\u7559\u65E7\u5BC6\u9700\u663E\u5F0F\u4F20\u5165 replaceSecrets: true", "\u6BCF\u670D\u52A1\u6700\u591A\u7F13\u5B58 200 \u5DE5\u5177\uFF0C\u5355\u6B21\u63A2\u6D4B\u53D7 429/409 \u5E76\u53D1\u5B88\u536B"]
    },
    {
      id: "mcp-servers-probe",
      method: "POST",
      path: "/api/mcp-servers/probe",
      group: "\u7B2C\u4E09\u65B9 MCP",
      title: "\u6309 ID \u5F3A\u5236\u91CD\u63A2\u5DE5\u5177\u5217\u8868\u4E0E\u63E1\u624B\u72B6\u6001",
      summary: "\u7ACB\u5373\u6267\u884C\u53D7\u63A7 MCP initialize + tools/list \u5E76\u5237\u65B0 lastProbeOk \u4E0E\u53EF\u7528\u5DE5\u5177\u76EE\u5F55\u3002",
      canTryGet: false,
      bodyExample: { id: "docs_mcp" },
      params: [{ name: "id", type: "string", required: true, description: "\u5DF2\u914D\u7F6E\u7684 MCP \u670D\u52A1 ID" }],
      bounds: ["\u540C ID \u5E76\u53D1\u63A2\u6D4B\u8FD4\u56DE 409", "\u5168\u76D8\u5E76\u53D1\u8D85\u8FC7\u4E0A\u9650\u8FD4\u56DE 429"]
    },
    {
      id: "moderation-config-get",
      method: "GET",
      path: "/api/moderation/config",
      group: "LLM \u5BA1\u67E5",
      title: "\u83B7\u53D6\u5185\u5BB9\u5BA1\u67E5\u8DEF\u7531\u7B56\u7565\u914D\u7F6E",
      summary: "\u8BFB\u53D6\u6A21\u5F0F\u3001\u56DE\u9000\u9884\u8BBE\u3001\u672C\u5730 Ollama Guard\u3001Canary \u91D1\u4E1D\u96C0\u63A2\u9488\u4E0E\u4E91\u5382\u5546\u63A5\u5165\u5B57\u6BB5\u3002",
      canTryGet: true,
      params: [],
      bounds: ["\u4E91\u7AEF API \u5BC6\u94A5\u5B58\u653E\u5728\u72EC\u7ACB plugin-secrets\uFF0C\u4E0D\u968F\u914D\u7F6E\u8FD4\u56DE"]
    },
    {
      id: "ollama-status",
      method: "GET",
      path: "/api/moderation/ollama/status",
      group: "LLM \u5BA1\u67E5",
      title: "\u63A2\u6D4B Ollama \u5B89\u88C5\u72B6\u6001\u3001\u8FD0\u884C\u6001\u4E0E\u6A21\u578B\u5217\u8868",
      summary: "\u6309 SSRF \u8FB9\u754C\u6821\u9A8C endpoint \u540E\u62C9\u53D6 /api/tags\u3001/api/ps \u4E0E\u6D3B\u8DC3\u62C9\u53D6\u4EFB\u52A1\u8FDB\u5EA6\u3002",
      canTryGet: true,
      params: [{ name: "endpoint", type: "query", required: false, description: "\u9ED8\u8BA4 http://127.0.0.1:11434" }],
      bounds: ["\u62D2\u7EDD\u4E91\u5143\u6570\u636E IP (169.254.169.254 \u7B49)"]
    },
    {
      id: "approvals-approve",
      method: "POST",
      path: "/api/approvals/approve",
      group: "\u672C\u673A\u5BA1\u6279",
      title: "\u7ED1\u5B9A\u53C2\u6570\u6458\u8981\u7684\u4E00\u6B21\u6027\u4EBA\u5DE5\u6279\u51C6",
      summary: "\u6821\u9A8C\u5BA1\u6279\u5355\u53F7 id \u4E0E policyDigest \u5B8C\u5168\u5339\u914D\u540E\u7B7E\u53D1\u5355\u6B21\u6267\u884C\u4EE4\u724C\u5E76\u5199\u5165 24h \u9632\u91CD\u653E\u8D26\u672C\u3002",
      canTryGet: false,
      bodyExample: { id: "approval-uuid", digest: "sha256-hex-digest" },
      params: [
        { name: "id", type: "string", required: true, description: "\u5F85\u5BA1\u8BF7\u6C42 ID" },
        { name: "digest", type: "string", required: true, description: "\u9010\u53C2\u6570\u89C4\u8303\u5316\u6458\u8981\uFF0C\u4E0D\u5339\u914D\u7ACB\u5373\u62D2\u7EDD\u5E76\u4F5C\u5E9F" }
      ],
      bounds: ["\u7981\u6B62\u901A\u914D\u7B26\u6279\u51C6\u6216\u8DE8\u8BF7\u6C42\u590D\u7528", "\u6BCF\u6761\u5BA1\u6279\u5355\u4EC5\u53EF\u6D88\u8D39\u4E00\u6B21"]
    }
  ];
  async function copyTextToClipboard(text, targetKey) {
    if (!text) return;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const area = document.createElement("textarea");
        area.value = text;
        area.setAttribute("readonly", "");
        area.style.position = "fixed";
        area.style.left = "-9999px";
        document.body.append(area);
        area.select();
        document.execCommand("copy");
        area.remove();
      }
      state.copiedTarget = targetKey;
      setNotice("\u5DF2\u590D\u5236\u5951\u7EA6\u8D1F\u8F7D\u5230\u526A\u8D34\u677F\u3002");
      setTimeout(() => {
        if (state.copiedTarget === targetKey) {
          state.copiedTarget = "";
          render();
        }
      }, 1800);
    } catch {
      setError("\u5F53\u524D\u6D4F\u89C8\u5668\u4E0A\u4E0B\u6587\u4E0D\u5141\u8BB8\u8BBF\u95EE\u526A\u8D34\u677F\u3002");
    }
  }
  function getToolDraftArgs(tool) {
    if (!state.toolArgsDraft[tool.name]) {
      const sampleArgs = tool.sampleCall?.params?.arguments || {};
      const draft = {};
      for (const p of tool.parameters || []) {
        const val = sampleArgs[p.name];
        draft[p.name] = val === void 0 ? "" : typeof val === "string" ? val : JSON.stringify(val);
      }
      state.toolArgsDraft[tool.name] = draft;
    }
    return state.toolArgsDraft[tool.name];
  }
  function parseDraftArgValue(raw, type) {
    if (raw === "" || raw === void 0 || raw === null) return void 0;
    if (type === "boolean") return raw === "true" || raw === true;
    if (type === "number" || type === "integer") {
      const n = Number(raw);
      return Number.isFinite(n) ? n : raw;
    }
    if (type === "object" || type === "array") {
      try {
        return JSON.parse(raw);
      } catch {
        return raw;
      }
    }
    return raw;
  }
  function methodBadgeClass(kind) {
    const k = String(kind || "").toUpperCase();
    if (k === "READ" || k === "GET" || k === "CTRL") return "is-read";
    if (k === "WRITE") return "is-write";
    if (k === "EXEC") return "is-exec";
    if (k === "MCP") return "is-mcp";
    return "is-info";
  }
  function getFilteredToolsList(allTools) {
    const byGroup = state.toolFilter === "all" ? allTools : allTools.filter((t) => t.group === state.toolFilter);
    const q = (state.toolSearch || "").trim().toLowerCase();
    if (!q) return byGroup;
    return byGroup.filter((t) => String(t.name || "").toLowerCase().includes(q) || String(t.title || "").toLowerCase().includes(q) || String(t.description || "").toLowerCase().includes(q));
  }
  function renderToolsPage() {
    const allTools = state.snapshot?.capabilities?.effectiveTools || [];
    const externalCount = allTools.filter((t) => t.external).length;
    const sandboxCount = allTools.length - externalCount;
    const enabledCount = allTools.filter((t) => t.enabled).length;
    const mode = state.toolCatalogMode === "http" ? "http" : "mcp";
    const searchInput = el("input", {
      type: "search",
      class: "lw-input",
      value: state.toolSearch || "",
      placeholder: mode === "mcp" ? "\u68C0\u7D22\u5DE5\u5177\u540D / \u6807\u9898 / \u53C2\u6570..." : "\u68C0\u7D22 HTTP \u8DEF\u5F84 / \u80FD\u529B / \u8BF4\u660E...",
      onInput: (e) => {
        state.toolSearch = e.target.value;
        render();
      }
    });
    let leftItemsNode;
    let rightDetailNode;
    let groupChipsNode;
    if (mode === "mcp") {
      const visibleTools = getFilteredToolsList(allTools);
      const activeTool = visibleTools.find((t) => t.name === state.selectedToolName) || visibleTools[0] || allTools.find((t) => t.name === state.selectedToolName) || allTools[0];
      if (activeTool && state.selectedToolName !== activeTool.name) {
        state.selectedToolName = activeTool.name;
      }
      const chipDefs = [
        ["all", "\u5168\u90E8"],
        ["context", "\u4E0A\u4E0B\u6587"],
        ["fileRead", "\u6587\u4EF6\u8BFB"],
        ["fileWrite", "\u6587\u4EF6\u5199"],
        ["exec", "\u547D\u4EE4"],
        ["mcp", "\u5916\u90E8 MCP"]
      ];
      groupChipsNode = el("div", { class: "lw-apifox-chip-row" }, chipDefs.map(([val, label]) => el("button", {
        type: "button",
        class: `lw-apifox-chip ${state.toolFilter === val ? "is-active" : ""}`,
        text: label,
        onClick: () => {
          state.toolFilter = val;
          render();
        }
      })));
      const groupTitles = {
        context: "\u5DE5\u4F5C\u533A\u4E0E\u8FD0\u884C\u4E0A\u4E0B\u6587",
        fileRead: "\u53EA\u8BFB\u6587\u4EF6\u7CFB\u7EDF (Docker :ro)",
        fileWrite: "\u5DE5\u4F5C\u533A\u5199\u5165\uFF08\u9700 fileWrite + \u6279\u51C6\uFF09",
        exec: "\u6C99\u7BB1\u547D\u4EE4\u6267\u884C\uFF08\u4E00\u6B21\u6027\u5BB9\u5668\uFF09",
        execControl: "\u540E\u53F0\u547D\u4EE4\u63A7\u5236",
        mcp: "\u7B2C\u4E09\u65B9\u5916\u90E8 MCP \u8FDB\u7A0B\u5DE5\u5177"
      };
      const buckets = /* @__PURE__ */ new Map();
      for (const tool of visibleTools) {
        const g = tool.group || "other";
        if (!buckets.has(g)) buckets.set(g, []);
        buckets.get(g).push(tool);
      }
      const catalogRows = [];
      for (const [grp, tools] of buckets.entries()) {
        catalogRows.push(el("div", { class: "lw-apifox-group-label", text: `${groupTitles[grp] || grp} (${tools.length})` }));
        for (const tool of tools) {
          const isSel = activeTool && activeTool.name === tool.name;
          catalogRows.push(el("button", {
            type: "button",
            class: `lw-apifox-item ${isSel ? "is-active" : ""}`,
            "data-apifox-item": tool.name,
            onClick: () => {
              state.selectedToolName = tool.name;
              render();
            }
          }, [
            el("span", { class: `lw-method-pill ${methodBadgeClass(tool.kind)}`, text: tool.kind || "MCP" }),
            el("span", { class: "lw-apifox-item-text" }, [
              el("span", { class: "lw-apifox-item-name", text: tool.name }),
              el("span", { class: "lw-apifox-item-sub", text: tool.title || tool.description || "" })
            ]),
            el("span", { class: `lw-apifox-dot ${tool.enabled ? "is-ok" : "is-err"}`, title: tool.enabled ? "\u5DF2\u542F\u7528" : "\u5DF2\u5173\u95ED" })
          ]));
        }
      }
      leftItemsNode = catalogRows.length ? catalogRows : [el("div", { class: "lw-muted", style: "padding:14px", text: "\u5F53\u524D\u7B5B\u9009\u6761\u4EF6\u4E0B\u65E0\u5339\u914D\u5DE5\u5177\u63A5\u53E3\u3002" })];
      if (!activeTool) {
        rightDetailNode = el("div", { class: "lw-doc-callout", text: "\u6682\u672A\u53D1\u73B0\u53EF\u7528\u5DE5\u5177\u5951\u7EA6\uFF1B\u8BF7\u5728\u300C\u80FD\u529B\u5F00\u5173\u4E0E\u670D\u52A1\u300D\u786E\u8BA4\u5BB9\u5668\u5C31\u7EEA\uFF0C\u6216\u5728\u300CAgent \u5B89\u5168\u56F4\u680F -> \u7B2C\u4E09\u65B9 MCP\u300D\u63A5\u5165\u65B0\u670D\u52A1\u3002" });
      } else {
        const boundary = classifyToolBoundary(activeTool.name, activeTool.external);
        const argsDraft = getToolDraftArgs(activeTool);
        const builtArgs = {};
        for (const p of activeTool.parameters || []) {
          const parsedVal = parseDraftArgValue(argsDraft[p.name], p.type);
          if (parsedVal !== void 0) builtArgs[p.name] = parsedVal;
        }
        const liveRpcPayload = JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: activeTool.name,
            arguments: builtArgs
          }
        }, null, 2);
        const parentOn = isToolParentEnabled(state.snapshot, activeTool);
        const stats = activeTool.stats || {};
        const totalCalls = stats.totalCalls || 0;
        const blockedCalls = stats.blockedCount || 0;
        const blockPct = totalCalls > 0 ? Math.min(100, Math.round(blockedCalls / totalCalls * 100)) : 0;
        const paramEditorNodes = (activeTool.parameters || []).length ? activeTool.parameters.map((p) => {
          const val = argsDraft[p.name] ?? "";
          const labelNode = el("span", { class: "lw-row lw-between", style: "width:100%" }, [
            el("span", {}, [
              el("code", { class: "lw-tag-inline", text: p.name }),
              el("span", { text: " " }),
              el("span", { class: "lw-muted", text: p.type })
            ]),
            el("span", { class: `lw-pill ${p.required ? "lw-pill-warn" : ""}`, text: p.required ? "\u5FC5\u586B" : "\u53EF\u9009" })
          ]);
          const ctrl = p.enumValues?.length ? makeSelect(
            [["", "\u2014 \u672A\u6307\u5B9A \u2014"], ...p.enumValues.map((ev) => [String(ev), String(ev)])],
            String(val),
            (e) => {
              argsDraft[p.name] = e.target.value;
              render();
            }
          ) : el("input", {
            type: "text",
            class: "lw-input lw-mono",
            value: String(val),
            placeholder: p.description || `${p.type} \u53C2\u6570\u503C...`,
            onInput: (e) => {
              argsDraft[p.name] = e.target.value;
              const codeEl = root.querySelector("[data-apifox-live-json]");
              if (codeEl) {
                const nextBuilt = {};
                for (const item of activeTool.parameters) {
                  const pv = parseDraftArgValue(argsDraft[item.name], item.type);
                  if (pv !== void 0) nextBuilt[item.name] = pv;
                }
                codeEl.textContent = JSON.stringify({
                  jsonrpc: "2.0",
                  id: 1,
                  method: "tools/call",
                  params: { name: activeTool.name, arguments: nextBuilt }
                }, null, 2);
              }
            }
          });
          return makeField(labelNode, ctrl);
        }) : [el("div", { class: "lw-muted", text: "\u8BE5\u5DE5\u5177\u65E0\u9700\u4F20\u5165\u53C2\u6570\uFF08arguments: {}\uFF09\u3002" })];
        rightDetailNode = [
          el("div", { class: "lw-apifox-sigbar" }, [
            el("div", { class: "lw-row" }, [
              el("span", { class: `lw-method-pill ${methodBadgeClass(activeTool.kind)}`, text: activeTool.kind || "MCP" }),
              el("code", { class: "lw-apifox-sigcode", text: `tools/call :: ${activeTool.name}` }),
              el("span", { class: `lw-pill lw-pill-${boundary.tone}`, text: boundary.label }),
              el("span", {
                class: `lw-pill ${activeTool.requiresApproval ? "lw-pill-info" : "lw-pill-ok"}`,
                text: activeTool.requiresApproval ? "\u9700\u672C\u673A\u9010\u53C2\u6279\u51C6" : "\u514D\u4EBA\u5DE5\u963B\u585E\u63A7\u5236\u5DE5\u5177"
              })
            ]),
            el("div", { class: "lw-row" }, [
              makeIconButton({
                text: state.copiedTarget === activeTool.name ? "\u5DF2\u590D\u5236\u5951\u7EA6" : "\u590D\u5236\u7B7E\u540D",
                iconName: "copy",
                className: "lw-btn lw-btn-sm",
                onClick: () => void copyTextToClipboard(activeTool.name, activeTool.name)
              }),
              el("label", { class: "lw-row", style: "cursor:pointer" }, [
                el("span", {
                  class: `lw-pill ${activeTool.enabled ? "lw-pill-ok" : "lw-pill-err"}`,
                  text: getSingleToolStatusLabel(state.snapshot, activeTool)
                }),
                el("span", { class: "lw-switch-pill" }, [
                  (() => {
                    const sw = el("input", {
                      type: "checkbox",
                      class: "lw-switch-input",
                      "data-tool-hero-switch": activeTool.name,
                      disabled: state.busy || !parentOn && !activeTool.individuallyDisabled,
                      onChange: (e) => {
                        void toggleSingleTool(activeTool, e.target.checked);
                      }
                    });
                    sw.checked = Boolean(activeTool.enabled && !activeTool.individuallyDisabled);
                    return sw;
                  })(),
                  el("span", { class: "lw-switch-track", "aria-hidden": "true" })
                ])
              ])
            ])
          ]),
          el("div", { class: "lw-stack-md", style: "gap:8px" }, [
            el("h3", { text: `${activeTool.title || activeTool.name}` }),
            el("p", { class: "lw-muted", text: activeTool.description || "\u65E0\u9644\u52A0\u63CF\u8FF0" }),
            !activeTool.enabled && activeTool.disabledReason ? el("div", { class: "lw-doc-callout is-warn", text: `\u5F53\u524D\u4E0D\u53EF\u7528\u539F\u56E0\uFF1A${activeTool.disabledReason}` }) : null,
            el("div", { class: "lw-meta-chips" }, [
              ...(activeTool.scopes || []).map((sc) => el("span", { class: "lw-meta-chip" }, [
                el("span", { class: "lw-meta-chip-k", text: "scope" }),
                el("span", { class: "lw-meta-chip-v", text: sc })
              ])),
              el("span", { class: "lw-meta-chip" }, [
                el("span", { class: "lw-meta-chip-k", text: "readOnlyHint" }),
                el("span", { class: "lw-meta-chip-v", text: String(Boolean(activeTool.annotations?.readOnlyHint)) })
              ]),
              el("span", { class: "lw-meta-chip" }, [
                el("span", { class: "lw-meta-chip-k", text: "destructiveHint" }),
                el("span", { class: "lw-meta-chip-v", text: String(Boolean(activeTool.annotations?.destructiveHint)) })
              ])
            ])
          ]),
          el("section", { class: "lw-section" }, [
            el("div", { class: "lw-section-head" }, [
              el("div", {}, [
                el("h3", { text: "\u5728\u7EBF\u53C2\u6570\u6784\u5EFA\u4E0E JSON-RPC 2.0 \u8D1F\u8F7D\u8C03\u8BD5" }),
                el("p", { text: "\u5B9E\u65F6\u4FEE\u6539\u53C2\u6570\u81EA\u52A8\u7EC4\u88C5 tools/call \u8BF7\u6C42\u4F53\uFF1B\u6240\u6709\u771F\u5B9E\u6267\u884C\u987B\u7ECF\u7531 OAuth \u4E2D\u7EE7 \u2192 R1\u2013R7/LLM \u62A4\u680F \u2192 \u672C\u673A\u9010\u53C2\u6279\u51C6\u3002" })
              ]),
              makeIconButton({
                text: state.copiedTarget === `rpc-${activeTool.name}` ? "\u5DF2\u590D\u5236 JSON" : "\u590D\u5236 JSON-RPC",
                iconName: "copy",
                className: "lw-btn lw-btn-sm lw-btn-primary",
                onClick: () => void copyTextToClipboard(liveRpcPayload, `rpc-${activeTool.name}`)
              })
            ]),
            el("div", { class: "lw-form-grid" }, paramEditorNodes),
            el("pre", { class: "lw-pre lw-mono", "data-apifox-live-json": "1", text: liveRpcPayload })
          ]),
          el("section", { class: "lw-section" }, [
            el("div", { class: "lw-section-head" }, [
              el("div", {}, [
                el("h3", { text: "\u8F93\u5165\u53C2\u6570 Schema" }),
                el("p", { text: "\u7531\u6C99\u7BB1\u5B9A\u4E49\u6216\u7B2C\u4E09\u65B9 MCP tools/list \u81EA\u52A8\u91C7\u96C6\u7684\u7ED3\u6784\u5316\u7EA6\u675F\u3002" })
              ]),
              el("span", { class: "lw-pill", text: `${(activeTool.parameters || []).length} \u4E2A\u5B57\u6BB5` })
            ]),
            (activeTool.parameters || []).length ? el("div", { class: "lw-table-wrap" }, [
              el("table", { class: "lw-table" }, [
                el("thead", {}, [el("tr", {}, [
                  el("th", { text: "\u5B57\u6BB5\u540D" }),
                  el("th", { text: "\u7C7B\u578B" }),
                  el("th", { text: "\u5FC5\u586B" }),
                  el("th", { text: "\u8BF4\u660E\u4E0E\u8303\u56F4\u9650\u5236" })
                ])]),
                el("tbody", {}, activeTool.parameters.map((p) => el("tr", {}, [
                  el("td", { class: "lw-mono", text: p.name }),
                  el("td", { class: "lw-mono", text: p.type }),
                  el("td", {}, [el("span", { class: `lw-pill ${p.required ? "lw-pill-warn" : ""}`, text: p.required ? "\u5FC5\u586B" : "\u53EF\u9009" })]),
                  el("td", {
                    class: "lw-muted",
                    text: [
                      p.description || "-",
                      p.enumValues ? `\u679A\u4E3E: ${p.enumValues.join(" | ")}` : "",
                      p.minimum !== null || p.maximum !== null ? `\u8303\u56F4: ${p.minimum ?? "-\u221E"}..${p.maximum ?? "+\u221E"}` : ""
                    ].filter(Boolean).join(" \xB7 ")
                  })
                ])))
              ])
            ]) : el("div", { class: "lw-muted", text: "\u65E0\u5165\u53C2\u5B57\u6BB5\u3002" })
          ]),
          el("div", { class: "lw-apifox-split-grid" }, [
            el("section", { class: "lw-section" }, [
              el("h3", { text: "\u80FD\u529B\u4FDD\u8BC1 (canDo)" }),
              (activeTool.canDo || []).length ? el("ul", { class: "lw-bounds-list" }, activeTool.canDo.map((item) => el("li", { text: item }))) : el("div", { class: "lw-muted", text: "\u7531\u4E3B\u673A\u4E0E\u6C99\u7BB1\u5B9A\u4E49\u9ED8\u8BA4\u5951\u7EA6\u3002" })
            ]),
            el("section", { class: "lw-section" }, [
              el("h3", { text: "\u786C\u6027\u5B89\u5168\u8FB9\u754C (limits)" }),
              (activeTool.limits || []).length ? el("ul", { class: "lw-bounds-list" }, activeTool.limits.map((item) => el("li", { text: item }))) : el("div", { class: "lw-muted", text: "\u9075\u5FAA\u6700\u5C0F\u6743\u9650\u4E0E 24h \u9632\u91CD\u653E\u8D26\u672C\u3002" })
            ])
          ]),
          makeStatStrip([
            { icon: "activity", label: "\u7D2F\u8BA1\u8C03\u7528", value: `${totalCalls} \u6B21` },
            { icon: "check", label: "\u5DF2\u6279\u51C6\u6267\u884C", value: `${stats.approvedCount || 0} \u6B21`, tone: "ok" },
            { icon: "alert", label: "\u62A4\u680F\u62E6\u622A", value: `${blockedCalls} \u6B21 (${blockPct}%)`, tone: blockedCalls > 0 ? "warn" : "" },
            { icon: "clock", label: "\u5F85\u5BA1\u6392\u961F", value: `${stats.pendingApprovalCount || 0} \u6B21` }
          ])
        ];
      }
    } else {
      const q = (state.toolSearch || "").trim().toLowerCase();
      const groups = ["all", "\u603B\u89C8\u4E0E\u72B6\u6001", "\u5B89\u5168\u7B56\u7565", "Agent \u56F4\u680F", "\u7B2C\u4E09\u65B9 MCP", "LLM \u5BA1\u67E5", "\u672C\u673A\u5BA1\u6279"];
      groupChipsNode = el("div", { class: "lw-apifox-chip-row" }, groups.map((g) => el("button", {
        type: "button",
        class: `lw-apifox-chip ${state.toolFilter === g || state.toolFilter === "all" && g === "all" ? "is-active" : ""}`,
        text: g === "all" ? "\u5168\u90E8" : g,
        onClick: () => {
          state.toolFilter = g;
          render();
        }
      })));
      const visibleHttp = CONSOLE_HTTP_CONTRACTS.filter((ep) => {
        if (state.toolFilter !== "all" && groups.includes(state.toolFilter) && ep.group !== state.toolFilter) return false;
        if (!q) return true;
        return ep.path.toLowerCase().includes(q) || ep.title.toLowerCase().includes(q) || ep.summary.toLowerCase().includes(q);
      });
      const activeEp = visibleHttp.find((ep) => ep.id === state.selectedHttpId) || visibleHttp[0] || CONSOLE_HTTP_CONTRACTS[0];
      if (activeEp && state.selectedHttpId !== activeEp.id) state.selectedHttpId = activeEp.id;
      {
        const grouped = /* @__PURE__ */ new Map();
        for (const ep of visibleHttp) {
          if (!grouped.has(ep.group)) grouped.set(ep.group, []);
          grouped.get(ep.group).push(ep);
        }
        const list = [];
        for (const [grp, eps] of grouped.entries()) {
          list.push(el("div", { class: "lw-apifox-group-label", text: grp }));
          for (const ep of eps) {
            list.push(el("button", {
              type: "button",
              class: `lw-apifox-item ${activeEp.id === ep.id ? "is-active" : ""}`,
              "data-apifox-item": ep.id,
              onClick: () => {
                state.selectedHttpId = ep.id;
                state.toolHttpTryResult = null;
                render();
              }
            }, [
              el("span", { class: `lw-method-pill ${methodBadgeClass(ep.method)}`, text: ep.method }),
              el("span", { class: "lw-apifox-item-text" }, [
                el("span", { class: "lw-apifox-item-name", text: ep.path }),
                el("span", { class: "lw-apifox-item-sub", text: ep.title })
              ])
            ]));
          }
        }
        leftItemsNode = list.length ? list : [el("div", { class: "lw-muted", style: "padding:14px", text: "\u65E0\u5339\u914D\u63A7\u5236\u9762\u7AEF\u70B9\u3002" })];
      }
      const originUrl = window.location.origin;
      const sampleBodyStr = activeEp.method === "POST" ? JSON.stringify(activeEp.bodyExample || {}, null, 2) : "";
      const curlSnippet = activeEp.method === "GET" ? `curl -sS -H "X-LoomWard-Tab-Auth: <tabToken>" "${originUrl}${activeEp.path}"` : `curl -sS -X POST -H "Content-Type: application/json" -H "X-LoomWard-CSRF: <csrf>" -H "X-LoomWard-Tab-Auth: <tabToken>" -d '${JSON.stringify(activeEp.bodyExample || {})}' "${originUrl}${activeEp.path}"`;
      rightDetailNode = [
        el("div", { class: "lw-apifox-sigbar" }, [
          el("div", { class: "lw-row" }, [
            el("span", { class: `lw-method-pill ${methodBadgeClass(activeEp.method)}`, text: activeEp.method }),
            el("code", { class: "lw-apifox-sigcode", text: activeEp.path }),
            el("span", { class: "lw-pill lw-pill-info", text: "Loopback + Tab Auth" })
          ]),
          el("div", { class: "lw-row" }, [
            makeIconButton({
              text: "\u590D\u5236 cURL",
              iconName: "copy",
              className: "lw-btn lw-btn-sm",
              onClick: () => void copyTextToClipboard(curlSnippet, `curl-${activeEp.id}`)
            }),
            activeEp.canTryGet ? makeIconButton({
              text: "\u53D1\u9001\u5B9E\u65F6 GET \u63A2\u6D4B",
              iconName: "play",
              className: "lw-btn lw-btn-sm lw-btn-primary",
              disabled: state.busy,
              onClick: () => runMutation(async () => {
                const t0 = performance.now();
                const data = await client.api(activeEp.path);
                const ms = Math.round(performance.now() - t0);
                state.toolHttpTryResult = { id: activeEp.id, ms, jsonText: JSON.stringify(data, null, 2) };
              })
            }) : null
          ])
        ]),
        el("div", { class: "lw-stack-md", style: "gap:8px" }, [
          el("h3", { text: activeEp.title }),
          el("p", { class: "lw-muted", text: activeEp.summary })
        ]),
        state.toolHttpTryResult && state.toolHttpTryResult.id === activeEp.id ? el("section", { class: "lw-section" }, [
          el("div", { class: "lw-section-head" }, [
            el("h3", { text: "\u5B9E\u65F6\u63A2\u6D4B\u54CD\u5E94 (Live 200 OK)" }),
            el("span", { class: "lw-pill lw-pill-ok", text: `${state.toolHttpTryResult.ms} ms \xB7 \u5DF2\u8131\u654F` })
          ]),
          el("pre", { class: "lw-pre lw-mono", text: clipText(state.toolHttpTryResult.jsonText, 2400) })
        ]) : null,
        el("section", { class: "lw-section" }, [
          el("h3", { text: "\u8BF7\u6C42\u7B7E\u540D\u4E0E\u793A\u4F8B\u8F7D\u8377" }),
          el("pre", { class: "lw-pre lw-mono", text: sampleBodyStr ? `${curlSnippet}

# Request Body:
${sampleBodyStr}` : curlSnippet })
        ]),
        el("section", { class: "lw-section" }, [
          el("h3", { text: "\u53C2\u6570\u5951\u7EA6\u4E0E\u5B89\u5168\u7EA6\u675F" }),
          (activeEp.params || []).length ? el("div", { class: "lw-table-wrap" }, [
            el("table", { class: "lw-table" }, [
              el("thead", {}, [el("tr", {}, [el("th", { text: "\u5B57\u6BB5\u540D" }), el("th", { text: "\u7C7B\u578B" }), el("th", { text: "\u5FC5\u586B" }), el("th", { text: "\u8BF4\u660E" })])]),
              el("tbody", {}, activeEp.params.map((p) => el("tr", {}, [
                el("td", { class: "lw-mono", text: p.name }),
                el("td", { class: "lw-mono", text: p.type }),
                el("td", {}, [el("span", { class: `lw-pill ${p.required ? "lw-pill-warn" : ""}`, text: p.required ? "\u5FC5\u586B" : "\u53EF\u9009" })]),
                el("td", { class: "lw-muted", text: p.description })
              ])))
            ])
          ]) : el("div", { class: "lw-muted", text: "\u65E0\u9644\u52A0\u8F93\u5165\u53C2\u6570\u3002" }),
          el("ul", { class: "lw-bounds-list", style: "margin-top:10px" }, (activeEp.bounds || []).map((b) => el("li", { text: b })))
        ])
      ];
    }
    return el("div", { class: "lw-stack-md" }, [
      makePageHeader("API \u63A5\u53E3\u5DE5\u4F5C\u53F0\uFF08APIFox \u53CC\u680F\u5951\u7EA6\u89C6\u56FE\uFF09", "\u5DE6\u8FB9\u68C0\u7D22\u6D4F\u89C8\uFF0C\u53F3\u8FB9\u76F4\u63A5\u8C03\u8BD5\u53C2\u6570\u8D1F\u8F7D\u3001\u5355\u5DE5\u5177\u7194\u65AD\u5F00\u5173\u6216\u63A2\u6D4B\u63A7\u5236\u53F0\u63A5\u53E3\uFF1B\u8986\u76D6\u5185\u7F6E\u6C99\u7BB1\u3001\u7B2C\u4E09\u65B9 MCP \u4E0E\u63A7\u5236\u9762 HTTP API\u3002"),
      makeStatStrip([
        { icon: "code", label: "MCP \u5DE5\u5177\u603B\u8BA1", value: `${allTools.length} \u9879` },
        { icon: "lock", label: "Docker \u6C99\u7BB1\u63A5\u53E3", value: `${sandboxCount} \u9879`, tone: "ok" },
        { icon: "plug", label: "\u8FDB\u7A0B\u5916 MCP \u5DE5\u5177", value: `${externalCount} \u9879`, tone: externalCount > 0 ? "warn" : "" },
        { icon: "check", label: "\u5F53\u524D\u5F00\u542F\u53EF\u7528", value: `${enabledCount} \u9879`, tone: enabledCount > 0 ? "ok" : "err" }
      ]),
      el("div", { class: "lw-apifox-modebar" }, [
        makeSegmentedChoice({
          value: mode,
          options: [
            { value: "mcp", label: `MCP \u5DE5\u5177\u63A5\u53E3\u5951\u7EA6 (${allTools.length})`, icon: "wrench" },
            { value: "http", label: `\u63A7\u5236\u53F0 HTTP API (${CONSOLE_HTTP_CONTRACTS.length})`, icon: "server" }
          ],
          onSelect: (nextMode) => {
            state.toolCatalogMode = nextMode;
            state.toolFilter = "all";
            render();
          }
        }),
        makeIconButton({
          text: "\u7BA1\u7406\u7B2C\u4E09\u65B9 MCP \u670D\u52A1\u56F4\u680F \u2192",
          iconName: "shield",
          className: "lw-btn lw-btn-sm",
          onClick: () => navigate("fencing", { fencingTab: "mcp" })
        })
      ]),
      el("div", { class: "lw-apifox-shell" }, [
        el("div", { class: "lw-apifox-catalog" }, [
          el("div", { class: "lw-apifox-catalog-top" }, [
            el("div", { class: "lw-search-wrap" }, [
              makeIcon("search"),
              searchInput
            ]),
            groupChipsNode
          ]),
          el("div", { class: "lw-apifox-list" }, leftItemsNode)
        ]),
        el("div", { class: "lw-apifox-detail" }, Array.isArray(rightDetailNode) ? rightDetailNode : [rightDetailNode])
      ])
    ]);
  }
  function splitLinesList(text) {
    return String(text || "").split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  }
  function splitCommaOrLineList(text) {
    return String(text || "").split(/[\r\n,，]+/).map((s) => s.trim()).filter(Boolean);
  }
  function parseKeyValueEnvLines(text) {
    const out = {};
    for (const rawLine of String(text || "").split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#")) continue;
      const eq = line.indexOf("=");
      if (eq <= 0) throw new Error(`\u73AF\u5883\u53D8\u91CF\u683C\u5F0F\u987B\u4E3A KEY=VALUE\uFF08\u5F02\u5E38\u884C\uFF1A${line.slice(0, 40)}\uFF09`);
      const k = line.slice(0, eq).trim();
      const v = line.slice(eq + 1);
      out[k] = v;
    }
    return out;
  }
  function parseKeyValueHeaderLines(text) {
    const out = {};
    for (const rawLine of String(text || "").split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#")) continue;
      const sep = line.includes(":") ? line.indexOf(":") : line.indexOf("=");
      if (sep <= 0) throw new Error(`HTTP Header \u683C\u5F0F\u987B\u4E3A Header-Name: value\uFF08\u5F02\u5E38\u884C\uFF1A${line.slice(0, 40)}\uFF09`);
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
    const cache = data.cache || { status: "missing", privateCount: 0, patternCount: 0, ownerCount: 0, expiresInSeconds: 0, sources: [] };
    const rules = Array.isArray(data.rules) ? data.rules : [];
    const listEq = (a, b) => JSON.stringify(a || []) === JSON.stringify(b || []);
    const dirtyFields = /* @__PURE__ */ new Set();
    if (!listEq(draft.forbiddenPatterns, saved.forbiddenPatterns)) dirtyFields.add("forbiddenPatterns");
    if (!listEq(draft.secretRegexes, saved.secretRegexes)) dirtyFields.add("secretRegexes");
    if (!listEq(draft.agentBranchPrefixes, saved.agentBranchPrefixes)) dirtyFields.add("agentBranchPrefixes");
    if (!listEq(draft.agentProviderEmails, saved.agentProviderEmails)) dirtyFields.add("agentProviderEmails");
    if (!listEq(draft.expectedOwners, saved.expectedOwners)) dirtyFields.add("expectedOwners");
    if (!listEq(draft.resolveIgnore, saved.resolveIgnore)) dirtyFields.add("resolveIgnore");
    if (!listEq(draft.exemptTools, saved.exemptTools)) dirtyFields.add("exemptTools");
    if (String(draft.agentSigningFingerprint || "") !== String(saved.agentSigningFingerprint || "")) dirtyFields.add("agentSigningFingerprint");
    if (String(draft.signingInstructions || "") !== String(saved.signingInstructions || "")) dirtyFields.add("signingInstructions");
    if (Number(draft.privateCacheTtl) !== Number(saved.privateCacheTtl)) dirtyFields.add("privateCacheTtl");
    if (Number(draft.resolveBudget) !== Number(saved.resolveBudget)) dirtyFields.add("resolveBudget");
    if (Boolean(draft.resignExempt) !== Boolean(saved.resignExempt)) dirtyFields.add("resignExempt");
    if (String(draft.cnbApi || "") !== String(saved.cnbApi || "")) dirtyFields.add("cnbApi");
    const cacheStatusLabel = cache.status === "fresh" ? `\u6709\u6548 (\u4F59 ${Math.max(1, Math.round((cache.expiresInSeconds || 0) / 60))} \u5206\u949F)` : cache.status === "stale" ? "\u5DF2\u8FC7\u671F (fail-closed)" : cache.status === "corrupt" ? "\u635F\u574F (fail-closed)" : "\u672A\u521D\u59CB\u5316 (fail-closed)";
    const cacheTone = cache.status === "fresh" ? "ok" : cache.status === "missing" ? "warn" : "err";
    const antileakSvg = svgEl("svg", {
      viewBox: "0 0 356 320",
      class: "lw-svg-diagram",
      role: "img",
      "aria-label": "R1-R7 \u79BB\u7EBF\u9632\u6CC4\u6F0F\u89C4\u5219\u7BA1\u7EBF\u4E0E fail-closed \u72B6\u6001\u793A\u610F\u56FE"
    }, [
      svgEl("path", { d: "M 178 66 L 178 90", class: "lw-svg-wire lw-svg-wire-active" }),
      svgEl("path", { d: "M 178 150 L 178 176", class: `lw-svg-wire ${cache.status === "fresh" ? "lw-svg-wire-active" : "lw-svg-wire-warn"}` }),
      svgEl("path", { d: "M 178 236 L 178 258", class: "lw-svg-wire lw-svg-wire-active" }),
      svgNodeBox({
        x: 10,
        y: 10,
        w: 336,
        h: 56,
        title: "1. \u8C03\u7528\u5165\u53C2 / Git \u63D0\u4EA4\u62E6\u622A\u5165\u53E3",
        sub: `tool:invoke@1 (@before) \xB7 \u8C41\u514D ${(draft.exemptTools || []).length} \u9879\u63A7\u5236\u5DE5\u5177`,
        badge: "order: 10 \u4F18\u5148\u4E8E LLM \u5BA1\u67E5",
        stateCls: "is-active",
        badgeCls: "is-muted",
        isDelta: dirtyFields.has("exemptTools")
      }),
      svgNodeBox({
        x: 10,
        y: 90,
        w: 336,
        h: 60,
        title: "2. \u9759\u6001\u6B63\u5219\u4E0E\u7B7E\u540D\u7B56\u7565 (policy.json)",
        sub: `R2 \u6A21\u5F0F:${(draft.forbiddenPatterns || []).length} \xB7 R7 \u51ED\u636E:${(draft.secretRegexes || []).length} \xB7 R5 \u5206\u652F:${(draft.agentBranchPrefixes || []).length}`,
        badge: draft.agentSigningFingerprint ? "R6 \u72EC\u7ACB SSH \u6307\u7EB9\u5DF2\u7ED1\u5B9A" : "R6 \u72EC\u7ACB\u6307\u7EB9\u5F85\u586B\u5199",
        stateCls: dirtyFields.size > 0 ? "is-warn" : "is-active",
        badgeCls: draft.agentSigningFingerprint ? "is-ok" : "is-warn",
        isDelta: dirtyFields.has("forbiddenPatterns") || dirtyFields.has("secretRegexes") || dirtyFields.has("agentSigningFingerprint") || dirtyFields.has("agentBranchPrefixes")
      }),
      svgNodeBox({
        x: 10,
        y: 176,
        w: 336,
        h: 60,
        title: "3. \u52A8\u6001\u79C1\u6709\u4ED3\u7F13\u5B58\u6838\u5BF9 (private-repos.json)",
        sub: `\u79C1\u6709\u540D:${cache.privateCount} \xB7 R4 \u6A21\u5F0F:${cache.patternCount} \xB7 Owners:${cache.ownerCount}`,
        badge: cache.status === "fresh" ? "\u79BB\u7EBF\u6838\u5BF9\u5C31\u7EEA \xB7 \u4E0D\u8054\u7F51\u4E0D\u6F0F\u540D" : "\u7F13\u5B58\u7F3A\u5931/\u8FC7\u671F \u2192 \u5F3A\u5236 ERROR \u963B\u65AD",
        stateCls: cache.status === "fresh" ? "is-ok" : "is-warn",
        badgeCls: cache.status === "fresh" ? "is-ok" : "is-warn",
        isDelta: dirtyFields.has("expectedOwners") || dirtyFields.has("privateCacheTtl") || dirtyFields.has("resignExempt")
      }),
      svgNodeBox({
        x: 10,
        y: 258,
        w: 336,
        h: 54,
        title: "4. \u4E09\u6001 fail-closed \u88C1\u51B3\u8F93\u51FA",
        sub: "pass (\u653E\u884C) | violation (\u8FDD\u89C4\u8131\u654F) | error (\u786C\u62E6\u622A)",
        badge: "\u8D85\u65F6\u6216\u5F02\u5E38\u6C38\u4E0D\u9759\u9ED8\u653E\u884C",
        stateCls: "is-ok",
        badgeCls: "is-ok"
      })
    ]);
    const rulePreviewValue = (ruleId) => {
      if (ruleId === "R1") return `Owners ${draft.expectedOwners?.length || 0} \xB7 \u79C1\u6709\u540D ${cache.privateCount || 0} \xB7 \u9884\u7B97 ${draft.resolveBudget ?? 30}`;
      if (ruleId === "R2") return `${draft.forbiddenPatterns?.length || 0} \u6761\u654F\u611F\u6A21\u5F0F\u6B63\u5219`;
      if (ruleId === "R3") return "Co-authored-by + Commit \u89C4\u8303";
      if (ruleId === "R4") return `R4 \u6A21\u5F0F ${cache.patternCount || 0} \u6761 \xB7 \u91CD\u7B7E\u8C41\u514D ${draft.resignExempt ? "\u5F00\u542F" : "\u5173\u95ED"}`;
      if (ruleId === "R5") return `${draft.agentBranchPrefixes?.length || 0} \u4E2A\u62E6\u622A\u524D\u7F00`;
      if (ruleId === "R6") return draft.agentSigningFingerprint ? `\u6307\u7EB9\u5DF2\u7ED1\u5B9A \xB7 ${draft.agentProviderEmails?.length || 0} \u7C7B\u4EE3\u7406\u90AE\u7BB1` : "\u672A\u7ED1\u5B9A\u72EC\u7ACB\u6307\u7EB9";
      if (ruleId === "R7") return `${draft.secretRegexes?.length || 0} \u6761\u79C1\u94A5\u4E0E Token \u6B63\u5219`;
      return "-";
    };
    const split = el("div", { class: "lw-doc-split" }, [
      el("div", { class: "lw-doc-main" }, [
        makeStatStrip([
          { icon: "shield", label: "\u79C1\u6709\u4ED3\u7F13\u5B58\u59FF\u6001", value: cacheStatusLabel, tone: cacheTone },
          { icon: "lock", label: "\u53D7\u62A4\u79C1\u6709\u4ED3\u6570\u91CF", value: `${cache.privateCount || 0} \u4E2A\uFF08\u53EA\u8BA1\u6570\u4E0D\u900F\u4F20\uFF09` },
          { icon: "radar", label: "R4 \u52A8\u6001\u6B63\u5219\u6570", value: `${cache.patternCount || 0} \u6761` },
          { icon: "sliders", label: "\u9759\u6001 R2 / R7 \u89C4\u5219", value: `${(draft.forbiddenPatterns?.length || 0) + (draft.secretRegexes?.length || 0)} \u6761` }
        ]),
        el("section", { class: "lw-section" }, [
          el("div", { class: "lw-section-head" }, [
            el("div", {}, [
              el("h3", { text: "1. \u79BB\u7EBF R1\u2013R7 \u9632\u6CC4\u6F0F\u89C4\u5219\u5168\u77E9\u9635" }),
              el("p", { text: "\u57FA\u4E8E\u72EC\u7ACB Python \u5B50\u8FDB\u7A0B\uFF08check.py\uFF09\u6267\u884C\u4E09\u6001 fail-closed \u68C0\u67E5\uFF1B\u7F13\u5B58\u7F3A\u5931\u6216\u811A\u672C\u8D85\u65F6\u65F6\u7EDD\u4E0D\u9759\u9ED8\u653E\u884C\u3002" })
            ]),
            el("span", { class: "lw-pill lw-pill-info", text: "out-of-process \xB7 offline" })
          ]),
          el("div", { class: "lw-table-wrap" }, [
            el("table", { class: "lw-table" }, [
              el("thead", {}, [el("tr", {}, [
                el("th", { text: "\u89C4\u5219" }),
                el("th", { text: "\u62E6\u622A\u65F6\u673A" }),
                el("th", { text: "\u5F53\u524D\u7ED1\u5B9A\u72B6\u6001" }),
                el("th", { text: "\u5B88\u536B\u804C\u8D23" })
              ])]),
              el("tbody", {}, rules.map((r) => el("tr", {}, [
                el("td", {}, [el("strong", { class: "lw-mono", text: r.id }), el("div", { class: "lw-muted", text: r.name })]),
                el("td", {}, [el("span", { class: "lw-pill", text: r.stage })]),
                el("td", { class: "lw-mono", text: rulePreviewValue(r.id) }),
                el("td", { class: "lw-muted", text: r.summary })
              ])))
            ])
          ])
        ]),
        el("section", { class: "lw-section" }, [
          el("div", { class: "lw-section-head" }, [
            el("div", {}, [
              el("h3", { text: "2. \u7F16\u8F91\u9632\u6CC4\u6F0F\u56F4\u680F\u7B56\u7565\uFF08<stateDir>/antileak/policy.json\uFF09" }),
              el("p", { text: "\u4FDD\u5B58\u524D\u81EA\u52A8\u8C03\u7528 Python re.compile \u9A8C\u8BC1\u6B63\u5219\u8BED\u6CD5\uFF0C\u5E76\u4EE5 0600 \u6743\u9650\u4FDD\u5B58\u5728\u6302\u8F7D\u5DE5\u4F5C\u533A\u4E4B\u5916\u3002" })
            ]),
            dirtyFields.size > 0 ? el("span", { class: "lw-delta-tag", text: `${dirtyFields.size} \u9879\u672A\u4FDD\u5B58\u66F4\u6539` }) : el("span", { class: "lw-pill lw-pill-ok", text: data.exists ? "\u5DF2\u6301\u4E45\u5316 0600" : "\u9ED8\u8BA4\u6A21\u677F" })
          ]),
          el("div", { class: "lw-form-grid" }, [
            makeField(
              "R2 \u654F\u611F\u8BCD\u4E0E\u786C\u4EF6/\u5185\u90E8\u672F\u8BED\u6B63\u5219\uFF08forbiddenPatterns\uFF0C\u6BCF\u884C 1 \u6761\uFF09",
              el("textarea", {
                class: `lw-textarea-mono ${dirtyFields.has("forbiddenPatterns") ? "is-delta" : ""}`,
                value: (draft.forbiddenPatterns || []).join("\n"),
                placeholder: "\u4F8B\u5982\uFF1A\n\\bINTERNAL_PROJ_[A-Z0-9]+\\b",
                onInput: (e) => {
                  draft.forbiddenPatterns = splitLinesList(e.target.value);
                  render();
                }
              })
            ),
            makeField(
              "R7 \u51ED\u636E\u4E0E\u79C1\u94A5\u786C\u62E6\u622A\u6B63\u5219\uFF08secretRegexes\uFF0C\u6BCF\u884C 1 \u6761\uFF09",
              el("textarea", {
                class: `lw-textarea-mono ${dirtyFields.has("secretRegexes") ? "is-delta" : ""}`,
                value: (draft.secretRegexes || []).join("\n"),
                placeholder: "-----BEGIN ... PRIVATE KEY-----",
                onInput: (e) => {
                  draft.secretRegexes = splitLinesList(e.target.value);
                  render();
                }
              })
            ),
            makeField(
              "R5 \u7981\u6B62\u63A8\u9001\u7684 Agent \u5206\u652F\u524D\u7F00\uFF08agentBranchPrefixes\uFF0C\u6BCF\u884C 1 \u4E2A\uFF09",
              el("textarea", {
                class: `lw-textarea-mono ${dirtyFields.has("agentBranchPrefixes") ? "is-delta" : ""}`,
                value: (draft.agentBranchPrefixes || []).join("\n"),
                placeholder: "claude/\ncodex/\nchatgpt/",
                onInput: (e) => {
                  draft.agentBranchPrefixes = splitLinesList(e.target.value);
                  render();
                }
              })
            ),
            makeField(
              "R6 Agent \u63D0\u4F9B\u5546\u90AE\u7BB1\u7279\u5F81\uFF08agentProviderEmails\uFF09\u4E0E R1 \u5F52\u5C5E Owners",
              el("div", { class: "lw-stack-md", style: "gap:8px" }, [
                el("input", {
                  type: "text",
                  class: `lw-input lw-mono ${dirtyFields.has("expectedOwners") ? "is-delta" : ""}`,
                  value: (draft.expectedOwners || []).join(", "),
                  placeholder: "expectedOwners \u9017\u53F7\u5206\u9694\uFF08\u5982 cybernova, your-org\uFF09",
                  onInput: (e) => {
                    draft.expectedOwners = splitCommaOrLineList(e.target.value);
                    render();
                  }
                }),
                el("input", {
                  type: "text",
                  class: `lw-input lw-mono ${dirtyFields.has("agentProviderEmails") ? "is-delta" : ""}`,
                  value: (draft.agentProviderEmails || []).join(", "),
                  placeholder: "agentProviderEmails\uFF08\u5982 noreply@anthropic.com\uFF09",
                  onInput: (e) => {
                    draft.agentProviderEmails = splitCommaOrLineList(e.target.value);
                    render();
                  }
                })
              ])
            ),
            makeField(
              "R6 \u72EC\u7ACB Agent SSH \u7B7E\u540D\u6307\u7EB9\uFF08agentSigningFingerprint\uFF09",
              el("input", {
                type: "text",
                class: `lw-input lw-mono ${dirtyFields.has("agentSigningFingerprint") ? "is-delta" : ""}`,
                value: draft.agentSigningFingerprint || "",
                placeholder: "SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                onInput: (e) => {
                  draft.agentSigningFingerprint = e.target.value;
                  render();
                }
              })
            ),
            makeField(
              "\u63A7\u5236\u7C7B\u5DE5\u5177\u8C41\u514D\u540D\u5355\uFF08exemptTools\uFF0C\u9017\u53F7\u5206\u9694\uFF09",
              el("input", {
                type: "text",
                class: `lw-input lw-mono ${dirtyFields.has("exemptTools") ? "is-delta" : ""}`,
                value: (draft.exemptTools || []).join(", "),
                placeholder: "computer_context, command_status, stop_command",
                onInput: (e) => {
                  draft.exemptTools = splitCommaOrLineList(e.target.value);
                  render();
                }
              })
            ),
            makeField(
              "\u79C1\u6709\u4ED3\u7F13\u5B58\u6709\u6548\u671F (\u79D2, 300\u201386400)",
              el("input", {
                type: "number",
                min: "300",
                max: "86400",
                class: `lw-input lw-mono ${dirtyFields.has("privateCacheTtl") ? "is-delta" : ""}`,
                value: String(draft.privateCacheTtl ?? 28800),
                onInput: (e) => {
                  draft.privateCacheTtl = Number(e.target.value) || 28800;
                  render();
                }
              })
            ),
            makeField(
              "R1 \u672A\u77E5\u77ED\u6A2A\u88F8\u540D\u8865\u67E5\u9884\u7B97 (0\u2013200)",
              el("input", {
                type: "number",
                min: "0",
                max: "200",
                class: `lw-input lw-mono ${dirtyFields.has("resolveBudget") ? "is-delta" : ""}`,
                value: String(draft.resolveBudget ?? 30),
                onInput: (e) => {
                  draft.resolveBudget = Number(e.target.value) || 0;
                  render();
                }
              })
            )
          ]),
          makeSwitchCard({
            checked: Boolean(draft.resignExempt),
            isDelta: dirtyFields.has("resignExempt"),
            iconName: "shieldCheck",
            title: "\u542F\u7528 R4 Push \u540C\u5185\u5BB9\u91CD\u7B7E patch-id \u8C41\u514D\uFF08resignExempt\uFF09",
            subtitle: "\u5F85\u63A8\u63D0\u4EA4\u7684 patch-id \u82E5\u9010\u5B57\u8282\u7B49\u4E8E\u8FDC\u7AEF\u5DF2\u6709\u63D0\u4EA4\uFF08\u4EC5\u91CD\u7B7E/rebase\uFF09\uFF0C\u8DF3\u8FC7\u65B0\u589E\u884C\u91CD\u626B\uFF1B\u6D88\u606F\u3001\u4F5C\u8005\u90AE\u7BB1\u4E0E SSH \u7B7E\u540D\u6307\u7EB9\u4ECD\u7167\u5E38\u68C0\u67E5\u3002",
            pillText: draft.resignExempt ? "\u5DF2\u5F00\u542F\u8C41\u514D" : "\u5168\u91CF\u4E25\u683C\u626B\u63CF",
            pillTone: draft.resignExempt ? "ok" : "info",
            onChange: (v) => {
              draft.resignExempt = v;
              render();
            }
          }),
          el("div", { class: "lw-btn-group", style: "margin-top:12px" }, [
            makeIconButton({
              text: dirtyFields.size > 0 ? `\u4FDD\u5B58 R1\u2013R7 \u56F4\u680F\u7B56\u7565 (${dirtyFields.size} \u9879)` : "\u4FDD\u5B58 R1\u2013R7 \u56F4\u680F\u7B56\u7565",
              iconName: "check",
              className: `lw-btn ${dirtyFields.size > 0 ? "lw-btn-primary" : ""}`,
              disabled: state.busy,
              onClick: () => runMutation(async () => {
                const res = await client.api("/api/fencing/config", { method: "POST", body: { config: draft } });
                state.fencingData = res;
                state.fencingDraft = structuredClone(res.config);
                setNotice("R1\u2013R7 \u9632\u6CC4\u6F0F\u56F4\u680F\u7B56\u7565\u5DF2\u539F\u5B50\u5199\u5165 0600 policy.json\u3002");
              })
            }),
            makeIconButton({
              text: "\u8FD8\u539F\u5DF2\u4FDD\u5B58\u8349\u7A3F",
              iconName: "rotateCcw",
              className: "lw-btn",
              disabled: state.busy || dirtyFields.size === 0,
              onClick: () => {
                state.fencingDraft = structuredClone(saved);
                render();
              }
            })
          ])
        ]),
        el("section", { class: "lw-section" }, [
          el("div", { class: "lw-section-head" }, [
            el("div", {}, [
              el("h3", { text: "3. \u79BB\u7EBF Dry-Run \u62E6\u622A\u8BD5\u9A8C\u4E0E\u7F13\u5B58\u81EA\u68C0\u5DE5\u5177" }),
              el("p", { text: "\u7C98\u8D34\u5408\u6210\u6837\u672C\u79BB\u7EBF\u8DD1\u4E00\u904D check.py content\uFF08\u4E0D\u4F20 --net\uFF09\uFF0C\u6216\u624B\u52A8\u5237\u65B0\u79C1\u6709\u4ED3\u7F13\u5B58\u3001\u6267\u884C doctor.py \u81EA\u68C0\u3002" })
            ])
          ]),
          makeField(
            "\u79BB\u7EBF\u8BD5\u9A8C\u8F7D\u8377\u6587\u672C\uFF08\u4EC5\u4F20\u81F3\u672C\u673A check.py stdin\uFF09",
            el("textarea", {
              class: "lw-textarea-mono",
              value: state.fencingDryText,
              placeholder: "\u5728\u6B64\u7C98\u8D34\u5F85\u6D4B\u8BD5\u4EE3\u7801\u7247\u6BB5\u3001Commit \u6587\u672C\u6216\u8131\u654F\u6B63\u5219\u6D4B\u8BD5\u5B57\u7B26\u4E32...",
              onInput: (e) => {
                state.fencingDryText = e.target.value;
              }
            }),
            { fullWidth: true }
          ),
          el("div", { class: "lw-btn-group" }, [
            makeIconButton({
              text: "\u79BB\u7EBF\u6267\u884C\u89C4\u5219\u68C0\u6D4B (check.py)",
              iconName: "play",
              className: "lw-btn lw-btn-primary",
              disabled: state.busy,
              onClick: () => runMutation(async () => {
                const res = await client.api("/api/fencing/test", {
                  method: "POST",
                  body: { text: state.fencingDryText || "" }
                });
                state.fencingDryResult = res.result;
                if (res.result?.cache && state.fencingData) state.fencingData.cache = res.result.cache;
                setNotice(`\u79BB\u7EBF\u89C4\u5219\u68C0\u9A8C\u5B8C\u6210\uFF1A${res.result?.decision} (${res.result?.durationMs ?? 0}ms)`);
              })
            }),
            makeIconButton({
              text: "\u5237\u65B0\u79C1\u6709\u4ED3\u7F13\u5B58 (refresh-private.py)",
              iconName: "refresh",
              className: "lw-btn",
              disabled: state.busy,
              onClick: () => runMutation(async () => {
                const res = await client.api("/api/fencing/refresh", { method: "POST", body: {} });
                state.fencingRefreshResult = res.result;
                if (res.result?.cache && state.fencingData) state.fencingData.cache = res.result.cache;
                setNotice(res.result?.ok ? "\u79C1\u6709\u4ED3\u7F13\u5B58\u5DF2\u5237\u65B0\u3002" : "\u79C1\u6709\u4ED3\u7F13\u5B58\u5237\u65B0\u672A\u901A\u8FC7\u5B8C\u6574\u6027\u6821\u9A8C\uFF08\u4FDD\u6301\u539F\u4FDD\u62A4\u59FF\u6001\uFF09\u3002");
              })
            }),
            makeIconButton({
              text: "\u8FD0\u884C\u5F15\u64CE\u81EA\u68C0 (doctor.py)",
              iconName: "shieldCheck",
              className: "lw-btn",
              disabled: state.busy,
              onClick: () => runMutation(async () => {
                const res = await client.api("/api/fencing/doctor", { method: "POST", body: {} });
                state.fencingDoctorResult = res.result;
                setNotice(`\u56F4\u680F\u81EA\u68C0\u5B8C\u6210\uFF1A${res.result?.summaryLine || ""}`);
              })
            })
          ]),
          state.fencingDryResult ? el("div", {
            class: `lw-doc-callout ${state.fencingDryResult.decision === "pass" ? "is-ok" : state.fencingDryResult.decision === "violation" ? "is-err" : "is-warn"}`
          }, [
            el("strong", {
              text: `\u88C1\u51B3\uFF1A${state.fencingDryResult.decision.toUpperCase()} (${state.fencingDryResult.durationMs} ms \xB7 ${state.fencingDryResult.bytesInspected} B)`
            }),
            state.fencingDryResult.findings?.length ? el("div", { class: "lw-mono", style: "margin-top:6px", text: state.fencingDryResult.findings.join("\n") }) : el("div", { class: "lw-muted", style: "margin-top:4px", text: "\u672A\u89E6\u53D1\u4EFB\u4F55 R1/R2/R4/R7 \u89C4\u5219\u544A\u8B66\u3002" })
          ]) : null,
          state.fencingRefreshResult ? el("div", {
            class: `lw-doc-callout ${state.fencingRefreshResult.ok ? "is-ok" : "is-warn"}`,
            text: `\u7F13\u5B58\u5237\u65B0\u8F93\u51FA (${state.fencingRefreshResult.durationMs}ms)\uFF1A${state.fencingRefreshResult.message}`
          }) : null,
          state.fencingDoctorResult ? el("div", { class: "lw-aside-list", style: "margin-top:10px" }, (state.fencingDoctorResult.checks || []).map((chk) => el("div", { class: "lw-doctor-row" }, [
            el("span", { class: `lw-pill ${chk.level === "pass" ? "lw-pill-ok" : chk.level === "fail" ? "lw-pill-err" : "lw-pill-warn"}`, text: chk.level.toUpperCase() }),
            el("span", { class: "lw-mono", style: "min-width:0;word-break:break-word", text: chk.message })
          ]))) : null
        ])
      ]),
      el("aside", { class: "lw-doc-aside" }, [
        el("div", { class: "lw-section-head" }, [
          el("div", {}, [
            el("h3", { text: "\u79BB\u7EBF Fail-Closed \u62E6\u622A\u7BA1\u7EBF" }),
            el("p", { text: "\u5B9E\u65F6\u5BF9\u7167\u5DF2\u6301\u4E45\u5316\u7B56\u7565\u4E0E\u672C\u673A\u79C1\u6709\u7F13\u5B58" })
          ]),
          el("span", { class: `lw-pill lw-pill-${cacheTone}`, text: cache.status })
        ]),
        antileakSvg,
        el("div", { class: "lw-aside-list" }, [
          el("div", { class: "lw-aside-row" }, [
            el("span", { class: "lw-muted", text: "\u7B56\u7565\u6587\u4EF6\u72B6\u6001" }),
            el("strong", { text: data.exists ? "<stateDir>/antileak/policy.json (0600)" : "\u5F15\u64CE\u5185\u7F6E\u9ED8\u8BA4\u6A21\u677F" })
          ]),
          el("div", { class: "lw-aside-row" }, [
            el("span", { class: "lw-muted", text: "\u7F13\u5B58\u6765\u6E90\u6807\u7B7E" }),
            el("strong", { text: cache.sources?.length ? cache.sources.join(", ") : "\u5C1A\u65E0\u6765\u6E90\uFF08\u9700\u672C\u673A\u79CD\u5B50\u6216\u4EE4\u724C\uFF09" })
          ]),
          el("div", { class: `lw-aside-row ${dirtyFields.size > 0 ? "is-delta" : ""}` }, [
            el("span", { class: "lw-muted", text: "\u5F85\u4FDD\u5B58\u8349\u7A3F\u5DEE\u5F02" }),
            el("strong", { text: dirtyFields.size > 0 ? `${dirtyFields.size} \u9879\u5C06\u5728\u4FDD\u5B58\u540E\u751F\u6548` : "\u4E0E\u78C1\u76D8\u4E00\u81F4" })
          ])
        ])
      ])
    ]);
    return split;
  }
  function renderFencingMcpTab() {
    const mcp = state.snapshot?.mcpServers || {
      serverCount: 0,
      enabledServerCount: 0,
      totalToolCount: 0,
      enabledToolCount: 0,
      items: []
    };
    const d = state.mcpDraft;
    const resetMcpForm = () => {
      state.mcpDraft = {
        editingId: "",
        id: "",
        name: "",
        description: "",
        transport: "stdio",
        command: "",
        argsText: "",
        cwd: "",
        url: "",
        timeoutMs: "30000",
        envText: "",
        removeEnvKeysText: "",
        headersText: "",
        removeHeaderKeysText: "",
        replaceSecrets: false,
        enabled: true,
        probe: true
      };
      render();
    };
    const mcpSvg = svgEl("svg", {
      viewBox: "0 0 356 262",
      class: "lw-svg-diagram",
      role: "img",
      "aria-label": "\u7B2C\u4E09\u65B9 MCP \u63A5\u5165\u5B89\u5168\u56F4\u680F\u4E0E\u4EBA\u5DE5\u9010\u53C2\u6279\u51C6\u62D3\u6251\u56FE"
    }, [
      svgEl("path", { d: "M 178 66 L 178 92", class: "lw-svg-wire lw-svg-wire-active" }),
      svgEl("path", { d: "M 178 152 L 178 180", class: "lw-svg-wire lw-svg-wire-warn" }),
      svgNodeBox({
        x: 10,
        y: 10,
        w: 336,
        h: 56,
        title: "1. \u672C\u673A MCP Registry + \u6709\u754C\u63A2\u6D4B\u95E8\u63A7",
        sub: `0600 mcp-servers.json \xB7 \u5DF2\u7EB3\u7BA1 ${mcp.serverCount} \u53F0 \xB7 \u5DE5\u5177 ${mcp.totalToolCount}`,
        badge: "\u81EA\u52A8\u5265\u9664 LD_PRELOAD / AGENTDOCK_* \u7B49\u5371\u9669 env",
        stateCls: "is-active",
        badgeCls: "is-ok"
      }),
      svgNodeBox({
        x: 10,
        y: 92,
        w: 336,
        h: 60,
        title: "2. \u9010\u53C2\u5BA1\u6279 + R1\u2013R7/LLM \u53CC\u91CD\u62A4\u680F",
        sub: "tools/call \u53C2\u6570\u5168\u91CF\u8FDB\u5165 policyDigest \u590D\u6838",
        badge: "\u4E0D\u652F\u6301\u514D\u5BA1\u76F4\u8C03 \xB7 24h \u5355\u6B21\u9632\u91CD\u653E",
        stateCls: "is-active",
        badgeCls: "is-info"
      }),
      svgNodeBox({
        x: 10,
        y: 180,
        w: 336,
        h: 68,
        title: "3. \u8FDB\u7A0B\u5916\u7B2C\u4E09\u65B9 MCP \u670D\u52A1\uFF08\u6C99\u76D2\u5916\uFF09",
        sub: `${mcp.enabledServerCount} \u53F0\u542F\u7528\u4E2D \xB7 \u652F\u6301 stdio \u5B50\u8FDB\u7A0B / Streamable HTTP`,
        badge: "\u6CE8\u610F\uFF1A\u5916\u90E8\u7AEF\u70B9\u4E0D\u53D7 Linux Docker \u5BB9\u5668\u53EA\u8BFB\u4FDD\u62A4",
        stateCls: mcp.enabledServerCount > 0 ? "is-warn" : "is-off",
        badgeCls: "is-warn"
      })
    ]);
    const handleSaveServer = () => runMutation(async () => {
      const id = d.id.trim();
      const timeoutMs = Number(d.timeoutMs) || 3e4;
      const payload = {
        id,
        name: d.name.trim() || id,
        description: d.description.trim(),
        transport: d.transport,
        enabled: Boolean(d.enabled),
        timeoutMs,
        probe: Boolean(d.probe),
        replaceSecrets: Boolean(d.replaceSecrets)
      };
      if (d.transport === "stdio") {
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
      const res = await client.api("/api/mcp-servers/save", { method: "POST", body: payload });
      if (res.snapshot) state.snapshot = res.snapshot;
      resetMcpForm();
      const probedCount = res.probe?.toolCount ?? res.server?.toolCount ?? (Array.isArray(res.probe?.tools) ? res.probe.tools.length : 0);
      const probeMsg = res.probe ? res.probe.ok ? `\u63A2\u6D4B\u6210\u529F\uFF0C\u5DF2\u6536\u5F55 ${probedCount} \u4E2A\u5DE5\u5177\u3002` : `\u4FDD\u5B58\u6210\u529F\uFF0C\u4F46\u63A2\u6D4B\u544A\u8B66\uFF1A${res.probe.error || "\u5931\u8D25"}` : "\u914D\u7F6E\u5DF2\u5B89\u5168\u4FDD\u5B58\uFF080600\uFF09\u3002";
      setNotice(`\u7B2C\u4E09\u65B9 MCP\u300C${id}\u300D\uFF1A${probeMsg}`);
    });
    const handleImportJson = () => runMutation(async () => {
      const raw = (state.mcpImportJson || "").trim();
      if (!raw) throw new Error("\u8BF7\u5148\u7C98\u8D34\u6807\u51C6 mcpServers JSON \u914D\u7F6E\u3002");
      const res = await client.api("/api/mcp-servers/import", {
        method: "POST",
        body: { json: raw, probe: Boolean(state.mcpImportProbe) }
      });
      if (res.snapshot) state.snapshot = res.snapshot;
      state.mcpImportJson = "";
      setNotice(`\u5DF2\u5BFC\u5165 ${(res.importedIds || []).length} \u4E2A\u7B2C\u4E09\u65B9 MCP \u670D\u52A1\u3002`);
    });
    return el("div", { class: "lw-doc-split" }, [
      el("div", { class: "lw-doc-main" }, [
        makeStatStrip([
          { icon: "plug", label: "\u5DF2\u7EB3\u7BA1 MCP \u670D\u52A1", value: `${mcp.serverCount} \u53F0` },
          { icon: "check", label: "\u5F53\u524D\u542F\u7528\u670D\u52A1", value: `${mcp.enabledServerCount} \u53F0`, tone: mcp.enabledServerCount > 0 ? "ok" : "" },
          { icon: "code", label: "\u5DF2\u53D1\u73B0\u5916\u90E8\u5DE5\u5177", value: `${mcp.totalToolCount} \u9879` },
          { icon: "shieldCheck", label: "\u5141\u8BB8\u8C03\u7528\u5DE5\u5177\u6570", value: `${mcp.enabledToolCount} \u9879`, tone: mcp.enabledToolCount > 0 ? "warn" : "" }
        ]),
        el("div", { class: "lw-doc-callout is-warn", text: "\u5B89\u5168\u8FB9\u754C\u58F0\u660E\uFF1A\u7B2C\u4E09\u65B9 MCP \u670D\u52A1\u5728 Docker \u6C99\u76D2\u5916\u6267\u884C\uFF08stdio \u5B50\u8FDB\u7A0B\u6216\u5916\u90E8 Streamable HTTP\uFF09\uFF1B\u5199\u5165\u7684 env/headers \u51ED\u636E\u91C7\u7528\u53EA\u5199\u6A21\u578B\uFF08\u4FDD\u5B58\u540E\u6C38\u4E0D\u56DE\u663E\uFF09\uFF0C\u6BCF\u6B21\u8C03\u7528\u4ECD\u9700\u672C\u673A\u4EBA\u5DE5\u9010\u53C2\u6279\u51C6\u3002" }),
        el("section", { class: "lw-section" }, [
          el("div", { class: "lw-section-head" }, [
            el("div", {}, [
              el("h3", { text: d.editingId ? `1. \u7F16\u8F91\u7B2C\u4E09\u65B9 MCP \u670D\u52A1\uFF08${d.editingId}\uFF09` : "1. \u65B0\u589E\u7B2C\u4E09\u65B9 MCP \u670D\u52A1\u63A5\u5165" }),
              el("p", { text: "\u652F\u6301\u672C\u673A stdio \u5B50\u8FDB\u7A0B\u4E0E Streamable HTTP\uFF08HTTPS/loopback\uFF09\uFF1B\u4FEE\u6539\u547D\u4EE4\u6216 Origin \u65F6\u9700\u52FE\u9009\u201C\u6E05\u7A7A\u5E76\u91CD\u7F6E\u65E7\u51ED\u636E\u201D\u3002" })
            ]),
            d.editingId ? el("button", { type: "button", class: "lw-btn lw-btn-sm", text: "\u53D6\u6D88\u7F16\u8F91 / \u5207\u56DE\u65B0\u589E", onClick: resetMcpForm }) : null
          ]),
          makeField("\u4F20\u8F93\u534F\u8BAE (transport)", makeSegmentedChoice({
            value: d.transport,
            options: [
              { value: "stdio", label: "\u672C\u673A stdio \u5B50\u8FDB\u7A0B", icon: "terminal" },
              { value: "http", label: "Streamable HTTP \u7AEF\u70B9", icon: "globe" }
            ],
            onSelect: (v) => {
              d.transport = v;
              render();
            }
          })),
          el("div", { class: "lw-form-grid" }, [
            makeField("\u670D\u52A1\u552F\u4E00 ID\uFF08\u5C0F\u5199\u5B57\u6BCD/\u6570\u5B57/-\uFF0C1\u201332 \u5B57\u7B26\uFF09", el("input", {
              type: "text",
              class: "lw-input lw-mono",
              disabled: Boolean(d.editingId),
              value: d.id,
              placeholder: "\u4F8B\u5982: github_docs",
              onInput: (e) => {
                d.id = e.target.value;
              }
            })),
            makeField("\u663E\u793A\u540D\u79F0", el("input", {
              type: "text",
              class: "lw-input",
              value: d.name,
              placeholder: "GitHub Docs MCP",
              onInput: (e) => {
                d.name = e.target.value;
              }
            })),
            ...d.transport === "stdio" ? [
              makeField("\u542F\u52A8\u547D\u4EE4 (command)", el("input", {
                type: "text",
                class: "lw-input lw-mono",
                value: d.command,
                placeholder: "npx \u6216 /usr/bin/node",
                onInput: (e) => {
                  d.command = e.target.value;
                }
              })),
              makeField("\u5DE5\u4F5C\u76EE\u5F55 cwd\uFF08\u53EF\u9009\uFF0C\u987B\u5728\u5DE5\u4F5C\u533A/\u72B6\u6001\u76EE\u5F55\u767D\u540D\u5355\u5185\uFF09", el("input", {
                type: "text",
                class: "lw-input lw-mono",
                value: d.cwd,
                placeholder: "\u7559\u7A7A\u4F7F\u7528\u8FDE\u63A5\u5668\u9ED8\u8BA4 cwd",
                onInput: (e) => {
                  d.cwd = e.target.value;
                }
              })),
              makeField("\u547D\u4EE4\u53C2\u6570 args\uFF08\u6BCF\u884C 1 \u4E2A\u53C2\u6570\uFF09", el("textarea", {
                class: "lw-textarea-mono",
                value: d.argsText,
                placeholder: "-y\n@modelcontextprotocol/server-everything",
                onInput: (e) => {
                  d.argsText = e.target.value;
                }
              })),
              makeField("\u53EA\u5199\u73AF\u5883\u53D8\u91CF env\uFF08\u6BCF\u884C KEY=VALUE\uFF0C\u7559\u7A7A\u4FDD\u7559\u5DF2\u5B58\u952E\uFF09", el("textarea", {
                class: "lw-textarea-mono",
                value: d.envText,
                placeholder: "API_KEY=\u8F93\u5165\u65B0\u503C\u5373\u52A0\u5BC6\u8986\u76D6",
                onInput: (e) => {
                  d.envText = e.target.value;
                }
              }))
            ] : [
              makeField("Streamable HTTP \u7AEF\u70B9 URL\uFF08HTTPS \u6216\u56DE\u73AF\u5730\u5740\uFF09", el("input", {
                type: "url",
                class: "lw-input lw-mono",
                value: d.url,
                placeholder: "https://mcp.example.com/mcp",
                onInput: (e) => {
                  d.url = e.target.value;
                }
              }), { fullWidth: true }),
              makeField("\u53EA\u5199\u8BF7\u6C42\u5934 headers\uFF08\u6BCF\u884C Name: Value\uFF0C\u5982 Authorization: Bearer ...\uFF09", el("textarea", {
                class: "lw-textarea-mono",
                value: d.headersText,
                placeholder: "Authorization: Bearer your-token",
                onInput: (e) => {
                  d.headersText = e.target.value;
                }
              }), { fullWidth: true })
            ],
            makeField("\u8D85\u65F6\u4E0A\u9650 timeoutMs (3000\u2013100000)", el("input", {
              type: "number",
              min: "3000",
              max: "100000",
              class: "lw-input lw-mono",
              value: d.timeoutMs,
              onInput: (e) => {
                d.timeoutMs = e.target.value;
              }
            })),
            makeField(d.transport === "stdio" ? "\u5220\u9664\u5DF2\u5B58 env \u952E\u540D\uFF08\u9017\u53F7\u5206\u9694\uFF09" : "\u5220\u9664\u5DF2\u5B58 Header \u952E\u540D\uFF08\u9017\u53F7\u5206\u9694\uFF09", el("input", {
              type: "text",
              class: "lw-input lw-mono",
              value: d.transport === "stdio" ? d.removeEnvKeysText : d.removeHeaderKeysText,
              placeholder: "KEY1, KEY2",
              onInput: (e) => {
                if (d.transport === "stdio") d.removeEnvKeysText = e.target.value;
                else d.removeHeaderKeysText = e.target.value;
              }
            }))
          ]),
          el("div", { class: "lw-setting-list", style: "margin-top:10px" }, [
            makeSwitchCard({
              checked: Boolean(d.enabled),
              iconName: "plug",
              title: "\u542F\u7528\u8BE5\u7B2C\u4E09\u65B9 MCP \u670D\u52A1",
              subtitle: "\u5173\u95ED\u540E\u6240\u6709\u884D\u751F mcp__<id>__* \u5DE5\u5177\u4ECE\u6A21\u578B\u53EF\u89C1\u5217\u8868\u4E2D\u77AC\u65F6\u7194\u65AD\u4E0B\u7EBF\u3002",
              pillText: d.enabled ? "\u542F\u7528" : "\u505C\u7528",
              pillTone: d.enabled ? "ok" : "info",
              onChange: (v) => {
                d.enabled = v;
                render();
              }
            }),
            makeSwitchCard({
              checked: Boolean(d.probe),
              iconName: "radar",
              title: "\u4FDD\u5B58\u540E\u7ACB\u5373\u8FD0\u884C\u6709\u754C\u63E1\u624B\u63A2\u6D4B\u5E76\u540C\u6B65\u5DE5\u5177\u6E05\u5355",
              subtitle: "\u89E6\u53D1 initialize + tools/list\uFF08\u53D7 409 \u540C ID \u4E92\u65A5\u4E0E 429 \u5168\u5C40\u5E76\u53D1\u5B88\u536B\uFF09\u3002",
              pillText: d.probe ? "\u81EA\u52A8\u63A2\u6D4B" : "\u4EC5\u4FDD\u5B58",
              pillTone: "info",
              onChange: (v) => {
                d.probe = v;
                render();
              }
            }),
            d.editingId ? makeSwitchCard({
              checked: Boolean(d.replaceSecrets),
              iconName: "key",
              title: "\u6539\u6362\u547D\u4EE4/\u7AEF\u70B9\u65F6\u663E\u5F0F\u6E05\u7A7A\u5E76\u91CD\u8BBE\u65E7\u51ED\u636E (replaceSecrets)",
              subtitle: "\u9632\u8BEF\u53D8\u66F4\u547D\u4EE4\u6216 HTTP Origin \u5BFC\u81F4\u65E7\u5BC6\u94A5\u6CC4\u6F0F\u81F3\u65B0\u76EE\u6807\uFF08security guard\uFF09\u3002",
              pillText: d.replaceSecrets ? "\u5141\u8BB8\u91CD\u7F6E" : "\u4FDD\u62A4\u4FDD\u7559",
              pillTone: d.replaceSecrets ? "warn" : "info",
              onChange: (v) => {
                d.replaceSecrets = v;
                render();
              }
            }) : null
          ]),
          el("div", { class: "lw-btn-group", style: "margin-top:12px" }, [
            makeIconButton({
              text: d.editingId ? "\u66F4\u65B0 MCP \u670D\u52A1\u914D\u7F6E" : "\u4FDD\u5B58\u5E76\u63A5\u5165 MCP \u670D\u52A1",
              iconName: "check",
              className: "lw-btn lw-btn-primary",
              disabled: state.busy,
              onClick: handleSaveServer
            })
          ])
        ]),
        el("section", { class: "lw-section" }, [
          el("div", { class: "lw-section-head" }, [
            el("div", {}, [
              el("h3", { text: "2. \u6807\u51C6 mcpServers JSON \u6279\u91CF\u5BFC\u5165" }),
              el("p", { text: '\u7C98\u8D34\u684C\u9762\u7AEF/CLI \u7684 { "mcpServers": { ... } } JSON\uFF0C\u4E00\u952E\u5BFC\u5165\u5E76\u6309\u5E76\u53D1\u9884\u7B97\u6279\u91CF\u63A2\u6D4B\u5DE5\u5177\u3002' })
            ])
          ]),
          el("textarea", {
            class: "lw-textarea-mono",
            value: state.mcpImportJson,
            placeholder: '{\n  "mcpServers": {\n    "filesystem": { "command": "npx", "args": ["-y", "@example/mcp"] }\n  }\n}',
            onInput: (e) => {
              state.mcpImportJson = e.target.value;
            }
          }),
          el("div", { class: "lw-row lw-between", style: "margin-top:8px" }, [
            el("label", { class: "lw-row", style: "cursor:pointer" }, [
              (() => {
                const cb = el("input", {
                  type: "checkbox",
                  onChange: (e) => {
                    state.mcpImportProbe = e.target.checked;
                  }
                });
                cb.checked = Boolean(state.mcpImportProbe);
                return cb;
              })(),
              el("span", { class: "lw-muted", text: "\u5BFC\u5165\u540E\u81EA\u52A8\u9010\u53F0\u63A2\u6D4B\u53EF\u7528\u5DE5\u5177\u6E05\u5355" })
            ]),
            makeIconButton({
              text: "\u6267\u884C JSON \u6279\u91CF\u5BFC\u5165",
              iconName: "download",
              className: "lw-btn lw-btn-sm",
              disabled: state.busy,
              onClick: handleImportJson
            })
          ])
        ]),
        el("section", { class: "lw-section" }, [
          el("div", { class: "lw-section-head" }, [
            el("div", {}, [
              el("h3", { text: "3. \u5DF2\u7EB3\u7BA1\u7B2C\u4E09\u65B9 MCP \u670D\u52A1\u53F0\u8D26" }),
              el("p", { text: "\u9010\u670D\u52A1\u63A7\u5236\u542F\u505C\u3001\u5C55\u5F00\u72EC\u7ACB\u5916\u90E8\u5DE5\u5177\u5F00\u5173\u5E76\u76F4\u8FBE APIFox \u67E5\u770B\u8C03\u7528\u5951\u7EA6\u3002" })
            ]),
            el("span", { class: "lw-pill", text: `${mcp.items.length} \u53F0` })
          ]),
          mcp.items.length ? el("div", {}, mcp.items.map((srv) => {
            const expanded = Boolean(state.mcpExpandedTools[srv.id]);
            const deleting = state.mcpDeleteConfirmId === srv.id;
            return el("div", { class: "lw-mcp-server-row", "data-mcp-server-id": srv.id }, [
              el("div", { class: "lw-mcp-server-top" }, [
                el("div", { class: "lw-stack-md", style: "gap:4px" }, [
                  el("div", { class: "lw-row" }, [
                    el("span", { class: `lw-method-pill ${srv.transport === "http" ? "is-info" : "is-mcp"}`, text: srv.transport.toUpperCase() }),
                    el("strong", { class: "lw-mono", text: srv.id }),
                    el("span", { text: `\xB7 ${srv.name}` }),
                    el("span", {
                      class: `lw-pill ${srv.lastProbeOk === true ? "lw-pill-ok" : srv.lastProbeOk === false ? "lw-pill-err" : ""}`,
                      text: srv.lastProbeOk === true ? `\u63A2\u6D4B\u6B63\u5E38 (${srv.toolCount} \u5DE5\u5177)` : srv.lastProbeOk === false ? "\u6700\u8FD1\u63A2\u6D4B\u5F02\u5E38" : "\u5C1A\u672A\u63A2\u6D4B"
                    })
                  ]),
                  el("div", { class: "lw-muted lw-mono", text: srv.transport === "stdio" ? `${srv.command} ${(srv.args || []).join(" ")}` : srv.url || "-" }),
                  srv.lastProbeError ? el("div", { class: "lw-muted", style: "color:var(--err)", text: `\u63A2\u6D4B\u6458\u8981\uFF08\u5DF2\u8131\u654F\uFF09\uFF1A${srv.lastProbeError}` }) : null,
                  srv.hasSecrets ? el("div", { class: "lw-meta-chips" }, [
                    ...(srv.envKeys || []).map((k) => el("span", { class: "lw-meta-chip" }, [
                      el("span", { class: "lw-meta-chip-k", text: "env" }),
                      el("span", { class: "lw-meta-chip-v", text: k })
                    ])),
                    ...(srv.headerKeys || []).map((k) => el("span", { class: "lw-meta-chip" }, [
                      el("span", { class: "lw-meta-chip-k", text: "hdr" }),
                      el("span", { class: "lw-meta-chip-v", text: k })
                    ]))
                  ]) : null
                ]),
                el("div", { class: "lw-btn-group" }, [
                  makeIconButton({
                    text: "\u63A2\u6D4B\u5DE5\u5177",
                    iconName: "radar",
                    className: "lw-btn lw-btn-sm",
                    disabled: state.busy,
                    onClick: () => runMutation(async () => {
                      const res = await client.api("/api/mcp-servers/probe", { method: "POST", body: { id: srv.id } });
                      if (res.snapshot) state.snapshot = res.snapshot;
                      setNotice(res.probe?.ok ? `\u300C${srv.id}\u300D\u63A2\u6D4B\u5B8C\u6210\uFF0C\u5171 ${res.probe.toolCount ?? 0} \u4E2A\u5DE5\u5177\u3002` : `\u300C${srv.id}\u300D\u63A2\u6D4B\u5F02\u5E38\uFF1A${res.probe?.error || "\u672A\u77E5\u9519\u8BEF"}`);
                    })
                  }),
                  makeIconButton({
                    text: expanded ? `\u6536\u8D77\u5DE5\u5177 (${srv.tools.length})` : `\u5916\u90E8\u5DE5\u5177 (${srv.tools.length})`,
                    iconName: "wrench",
                    className: "lw-btn lw-btn-sm",
                    onClick: () => {
                      state.mcpExpandedTools[srv.id] = !expanded;
                      render();
                    }
                  }),
                  makeIconButton({
                    text: srv.enabled ? "\u505C\u7528" : "\u542F\u7528",
                    iconName: srv.enabled ? "stop" : "play",
                    className: "lw-btn lw-btn-sm",
                    disabled: state.busy,
                    onClick: () => runMutation(async () => {
                      const res = await client.api("/api/mcp-servers/toggle", { method: "POST", body: { id: srv.id, enabled: !srv.enabled } });
                      if (res.snapshot) state.snapshot = res.snapshot;
                      setNotice(`\u670D\u52A1 ${srv.id} \u5DF2${srv.enabled ? "\u505C\u7528" : "\u542F\u7528"}\u3002`);
                    })
                  }),
                  makeIconButton({
                    text: "\u7F16\u8F91",
                    iconName: "sliders",
                    className: "lw-btn lw-btn-sm",
                    onClick: () => {
                      state.mcpDraft = {
                        editingId: srv.id,
                        id: srv.id,
                        name: srv.name,
                        description: srv.description || "",
                        transport: srv.transport,
                        command: srv.command || "",
                        argsText: (srv.args || []).join("\n"),
                        cwd: srv.cwd || "",
                        url: srv.url || "",
                        timeoutMs: String(srv.timeoutMs || 3e4),
                        envText: "",
                        removeEnvKeysText: "",
                        headersText: "",
                        removeHeaderKeysText: "",
                        replaceSecrets: false,
                        enabled: Boolean(srv.enabled),
                        probe: true
                      };
                      render();
                    }
                  }),
                  deleting ? el("span", { class: "lw-row" }, [
                    makeIconButton({
                      text: "\u786E\u8BA4\u79FB\u9664",
                      iconName: "trash",
                      className: "lw-btn lw-btn-sm lw-btn-danger",
                      disabled: state.busy,
                      onClick: () => runMutation(async () => {
                        const res = await client.api("/api/mcp-servers/delete", { method: "POST", body: { id: srv.id } });
                        state.mcpDeleteConfirmId = "";
                        if (res.snapshot) state.snapshot = res.snapshot;
                        setNotice(`\u5DF2\u5B89\u5168\u5220\u9664\u7B2C\u4E09\u65B9 MCP\u300C${srv.id}\u300D\u53CA\u5176\u5BC6\u6587\u73AF\u5883\u914D\u7F6E\u3002`);
                      })
                    }),
                    el("button", { type: "button", class: "lw-btn lw-btn-sm", text: "\u53D6\u6D88", onClick: () => {
                      state.mcpDeleteConfirmId = "";
                      render();
                    } })
                  ]) : makeIconButton({
                    text: "\u79FB\u9664",
                    iconName: "trash",
                    className: "lw-btn lw-btn-sm",
                    onClick: () => {
                      state.mcpDeleteConfirmId = srv.id;
                      render();
                    }
                  })
                ])
              ]),
              expanded ? el("div", { class: "lw-mcp-tools-drawer" }, srv.tools.length ? srv.tools.map((t) => el("div", { class: "lw-aside-row" }, [
                el("div", { style: "min-width:0;flex:1" }, [
                  el("div", { class: "lw-mono lw-switch-label", text: t.fullName }),
                  el("div", { class: "lw-switch-sub", text: t.description || t.name })
                ]),
                el("div", { class: "lw-row" }, [
                  el("button", {
                    type: "button",
                    class: "lw-btn lw-btn-sm",
                    text: "APIFox \u5951\u7EA6 \u2192",
                    onClick: () => navigate("tools", { selectedToolName: t.fullName })
                  }),
                  el("label", { class: "lw-switch-pill" }, [
                    (() => {
                      const cb = el("input", {
                        type: "checkbox",
                        class: "lw-switch-input",
                        disabled: state.busy,
                        onChange: (e) => runMutation(async () => {
                          const res = await client.api("/api/mcp-servers/toggle", {
                            method: "POST",
                            body: { id: srv.id, toolName: t.name, enabled: e.target.checked }
                          });
                          if (res.snapshot) state.snapshot = res.snapshot;
                        })
                      });
                      cb.checked = !t.individuallyDisabled;
                      return cb;
                    })(),
                    el("span", { class: "lw-switch-track", "aria-hidden": "true" })
                  ])
                ])
              ])) : [el("div", { class: "lw-muted", text: "\u8BE5\u670D\u52A1\u6682\u672A\u7F13\u5B58\u5230\u4EFB\u4F55\u5916\u90E8\u5DE5\u5177\uFF1B\u8BF7\u70B9\u51FB\u4E0A\u65B9\u201C\u63A2\u6D4B\u5DE5\u5177\u201D\u6267\u884C initialize + tools/list\u3002" })]) : null
            ]);
          })) : el("div", { class: "lw-doc-callout", text: "\u5F53\u524D\u5C1A\u672A\u63A5\u5165\u4EFB\u4F55\u7B2C\u4E09\u65B9 MCP \u670D\u52A1\uFF1B\u53EF\u901A\u8FC7\u4E0A\u65B9\u8868\u5355\u6216\u6807\u51C6 mcpServers JSON \u63A5\u5165\u3002" })
        ])
      ]),
      el("aside", { class: "lw-doc-aside" }, [
        el("div", { class: "lw-section-head" }, [
          el("div", {}, [
            el("h3", { text: "\u7B2C\u4E09\u65B9 MCP \u8FDB\u7A0B\u5916\u56F4\u680F" }),
            el("p", { text: "\u63A5\u5165\u5373\u9694\u79BB\u5371\u9669 env\u3001\u9650\u5236\u63A2\u6D4B\u5E76\u53D1\u4E0E\u8F7D\u8377\u4F53\u79EF" })
          ]),
          el("span", { class: "lw-pill lw-pill-warn", text: "\u5BB9\u5668\u5916\u6267\u884C" })
        ]),
        mcpSvg,
        el("div", { class: "lw-aside-list" }, [
          el("div", { class: "lw-aside-row" }, [
            el("span", { class: "lw-muted", text: "\u73AF\u5883\u53D8\u91CF\u9ED1\u540D\u5355" }),
            el("strong", { text: "\u81EA\u52A8\u62D2\u6536 LD_* / NODE_OPTIONS / AGENTDOCK_*" })
          ]),
          el("div", { class: "lw-aside-row" }, [
            el("span", { class: "lw-muted", text: "\u5DE5\u5177\u6CE8\u518C\u4E0A\u9650" }),
            el("strong", { text: "\u6700\u591A 32 \u53F0 \xB7 \u6BCF\u53F0\u6700\u591A 200 \u5DE5\u5177" })
          ]),
          el("div", { class: "lw-aside-row" }, [
            el("span", { class: "lw-muted", text: "\u6267\u884C\u6279\u51C6\u8981\u6C42" }),
            el("strong", { text: "\u5168\u90E8\u5F3A\u5236\u7ED1\u5B9A\u9010\u53C2\u5BA1\u6279" })
          ])
        ])
      ])
    ]);
  }
  function renderFencingPage() {
    const data = state.fencingData || {};
    const mcpCount = state.snapshot?.mcpServers?.serverCount || 0;
    const cacheStatus = data.cache?.status || "missing";
    const activeTab = state.fencingTab === "mcp" ? "mcp" : "antileak";
    const tabBar = el("div", { class: "lw-view-tabs", role: "tablist" }, [
      el("button", {
        type: "button",
        role: "tab",
        "data-fencing-tab": "antileak",
        "aria-selected": String(activeTab === "antileak"),
        class: `lw-view-tab ${activeTab === "antileak" ? "is-active" : ""}`,
        onClick: () => {
          state.fencingTab = "antileak";
          if (!state.fencingData && !state.fencingLoading) void loadFencingConfig({ silent: true });
          render();
        }
      }, [
        makeIcon("shield"),
        el("span", { text: "R1\u2013R7 \u9632\u6CC4\u6F0F\u4E0E\u89C4\u5219\u56F4\u680F" }),
        el("span", {
          class: `lw-pill ${cacheStatus === "fresh" ? "lw-pill-ok" : "lw-pill-warn"}`,
          text: cacheStatus === "fresh" ? "\u7F13\u5B58\u5C31\u7EEA" : cacheStatus
        })
      ]),
      el("button", {
        type: "button",
        role: "tab",
        "data-fencing-tab": "mcp",
        "aria-selected": String(activeTab === "mcp"),
        class: `lw-view-tab ${activeTab === "mcp" ? "is-active" : ""}`,
        onClick: () => {
          state.fencingTab = "mcp";
          render();
        }
      }, [
        makeIcon("plug"),
        el("span", { text: "\u7B2C\u4E09\u65B9 MCP \u63A5\u5165\u56F4\u680F" }),
        el("span", { class: `lw-pill ${mcpCount > 0 ? "lw-pill-info" : ""}`, text: `${mcpCount} \u53F0\u670D\u52A1` })
      ])
    ]);
    return el("div", { class: "lw-stack-md" }, [
      makePageHeader("Agent \u5B89\u5168\u56F4\u680F", "\u96C6\u4E2D\u6CBB\u7406 R1\u2013R7 \u79BB\u7EBF\u9632\u6CC4\u6F0F\u7B56\u7565\u4E0E\u7B2C\u4E09\u65B9\u8FDB\u7A0B\u5916 MCP \u5DE5\u5177\u56F4\u680F\uFF0C\u4E25\u683C\u4FDD\u6301 fail-closed \u8FB9\u754C\u4E0E\u5199\u540E\u4E0D\u53EF\u8BFB\u56DE\u3002"),
      tabBar,
      activeTab === "mcp" ? renderFencingMcpTab() : renderFencingAntileakTab()
    ]);
  }
  function renderReviewModal() {
    const modal = state.reviewModal;
    if (!modal) return null;
    const leftSec = Math.max(0, Math.ceil((Date.parse(modal.expiresAt) - Date.now()) / 1e3));
    const boundary = classifyToolBoundary(modal.tool, modal.tool?.startsWith("mcp__"));
    return el("div", { class: "lw-modal-backdrop", role: "dialog", "aria-modal": "true" }, [
      el("div", { class: "lw-modal" }, [
        el("div", { class: "lw-row lw-between" }, [
          el("h3", { text: `\u7CBE\u786E\u53C2\u6570\u590D\u6838 \xB7 ${modal.tool}` }),
          el("span", {
            class: `lw-pill ${leftSec <= 20 ? "lw-pill-err" : "lw-pill-warn"}`,
            "data-countdown-expires": modal.expiresAt,
            "data-warn-threshold": "20",
            text: `\u5269\u4F59 ${leftSec}s`
          })
        ]),
        makeStatStrip([
          { icon: boundary.icon, label: "\u6267\u884C\u8FB9\u754C", value: boundary.label, tone: boundary.tone },
          { icon: "lock", label: "\u6388\u6743\u989D\u5EA6", value: "\u4EC5\u9650\u672C\u6B21 1 \u6B21\u8C03\u7528" },
          { icon: "shieldCheck", label: "\u9632\u91CD\u653E\u4FDD\u62A4", value: "24h \u8D26\u672C\u4E0D\u53EF\u91CD\u7528" },
          { icon: "clock", label: "\u8FC7\u671F\u7B56\u7565", value: "\u8D85\u65F6\u81EA\u52A8\u4F5C\u5E9F" }
        ]),
        el("div", { class: "lw-muted lw-mono", text: `policyDigest: ${modal.digest}` }),
        el("pre", { class: "lw-pre", text: modal.requestText }),
        el("div", { class: "lw-row lw-end" }, [
          el("button", {
            type: "button",
            class: "lw-btn",
            text: "\u53D6\u6D88",
            onClick: () => {
              state.reviewModal = null;
              render();
            }
          }),
          el("button", {
            type: "button",
            class: "lw-btn lw-btn-trust",
            disabled: state.busy || leftSec <= 0,
            "data-countdown-disable-expires": modal.expiresAt,
            text: "\u786E\u8BA4\u6279\u51C6\u4E00\u6B21",
            onClick: () => runMutation(async () => {
              const res = await client.api("/api/approvals/approve", {
                method: "POST",
                body: { id: modal.id, digest: modal.digest }
              });
              state.reviewModal = null;
              if (res.snapshot) state.snapshot = res.snapshot;
              setNotice(`\u5DF2\u7CBE\u786E\u6279\u51C6\u4E00\u6B21\u8BF7\u6C42 ${modal.id.slice(0, 8)}\u3002`);
            })
          })
        ])
      ])
    ]);
  }
  function renderActivePage() {
    if (state.page === "approvals") return renderApprovalsPage();
    if (state.page === "capabilities") return renderCapabilitiesPage();
    if (state.page === "fencing") return renderFencingPage();
    if (state.page === "moderation") return renderModerationPage();
    if (state.page === "secrets") return renderSecretsPage();
    if (state.page === "panels") return renderPanelsPage();
    if (state.page === "audit") return renderAuditPage();
    if (state.page === "tools") return renderToolsPage();
    return renderOverviewPage();
  }
  function render() {
    const prevPre = root.querySelector(".lw-modal .lw-pre");
    const prevScrollTop = prevPre ? prevPre.scrollTop : 0;
    const prevScrollLeft = prevPre ? prevPre.scrollLeft : 0;
    clearNode(root);
    const children = [renderTopbar()];
    if (!state.auth?.authenticated) {
      const main = el("main", { class: "lw-shell" });
      if (state.error) main.append(el("div", { class: "lw-banner lw-banner-err", role: "alert", text: state.error }));
      if (state.notice) main.append(el("div", { class: "lw-banner lw-banner-ok", role: "status", text: state.notice }));
      main.append(renderAuthGate());
      children.push(main);
    } else {
      const contentInner = el("div", { class: "lw-content-inner" });
      if (state.error) contentInner.append(el("div", { class: "lw-banner lw-banner-err", role: "alert", text: state.error }));
      if (state.notice) contentInner.append(el("div", { class: "lw-banner lw-banner-ok", role: "status", text: state.notice }));
      contentInner.append(renderActivePage());
      const backdrop = el("div", {
        class: `lw-sidebar-backdrop ${state.mobileNavOpen ? "open" : ""}`,
        onClick: () => {
          state.mobileNavOpen = false;
          render();
        }
      });
      children.push(el("div", { class: "lw-app-frame" }, [
        renderSidebar(),
        backdrop,
        el("main", { class: "lw-content" }, [contentInner])
      ]));
    }
    const modal = renderReviewModal();
    if (modal) children.push(modal);
    root.append(...children);
    if (modal && (prevScrollTop > 0 || prevScrollLeft > 0)) {
      const nextPre = root.querySelector(".lw-modal .lw-pre");
      if (nextPre) {
        nextPre.scrollTop = prevScrollTop;
        nextPre.scrollLeft = prevScrollLeft;
      }
    }
  }
  void refreshAuthState().catch((err) => setError(err?.message || "\u65E0\u6CD5\u8FDE\u63A5\u5B89\u5168\u63A7\u5236\u53F0\u3002"));
})();
