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
            onStatus?.(res.status === 401 ? "unauthorized" : "disconnected");
            return;
          }
          onStatus?.("connected");
          const reader = res.body.getReader();
          const decoder = new TextDecoder();
          let buffer = "";
          while (!closed) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            let idx;
            while ((idx = buffer.indexOf("\n\n")) !== -1) {
              const block = buffer.slice(0, idx);
              buffer = buffer.slice(idx + 2);
              let eventName = "message";
              const dataLines = [];
              for (const line of block.split("\n")) {
                if (line.startsWith("event:")) eventName = line.slice(6).trim();
                else if (line.startsWith("data:")) dataLines.push(line.slice(5).trim());
              }
              if (dataLines.length) {
                try {
                  onEvent?.(eventName, JSON.parse(dataLines.join("\n")));
                } catch {
                }
              }
            }
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

  // web/trust/main.mjs
  var client = createOriginClient({ storageKey: "loomward_trust_tab_token" });
  var theme = initThemeToggle();
  var root = document.getElementById("app");
  var state = {
    auth: null,
    snapshot: null,
    consoleOrigin: readMeta("loomward-console-origin"),
    sseStatus: "idle",
    error: "",
    notice: "",
    busy: false,
    reviewModal: null,
    stopSse: null,
    countdownTimer: null
  };
  function setError(msg) {
    state.error = msg || "";
    if (msg) state.notice = "";
    render();
  }
  function setNotice(msg) {
    state.notice = msg || "";
    if (msg) state.error = "";
    render();
  }
  function stopLiveResources() {
    if (state.stopSse) {
      state.stopSse();
      state.stopSse = null;
    }
    if (state.countdownTimer) {
      clearInterval(state.countdownTimer);
      state.countdownTimer = null;
    }
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
        await refreshAuthState();
      }
    } finally {
      state.busy = false;
      render();
    }
  }
  async function refreshAuthState() {
    const auth = await client.api("/api/auth/state");
    state.auth = auth;
    if (auth.consoleOrigin) state.consoleOrigin = auth.consoleOrigin;
    if (auth.authenticated) {
      const snap = await client.api("/api/status");
      state.snapshot = snap;
      startLiveStream();
    } else {
      stopLiveResources();
      state.snapshot = null;
    }
    render();
  }
  function startLiveStream() {
    stopLiveResources();
    state.stopSse = client.connectSse("/api/events", {
      onStatus(status) {
        state.sseStatus = status;
        if (status === "unauthorized") {
          stopLiveResources();
          state.snapshot = null;
          void refreshAuthState();
        } else {
          render();
        }
      },
      onEvent(name, payload) {
        if (name === "status") {
          state.snapshot = payload;
          render();
        }
      }
    });
    state.countdownTimer = setInterval(() => {
      if (state.snapshot?.approvals?.pendingCount > 0 || state.reviewModal) {
        render();
      }
    }, 1e3);
  }
  async function handlePasskeyLogin() {
    await runMutation(async () => {
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
      setNotice("PassKey \u6CE8\u518C\u5E76\u767B\u5F55\u6210\u529F\u3002");
      await refreshAuthState();
    });
  }
  async function handleOpenConsole() {
    await runMutation(async () => {
      const issued = await client.api("/api/trust/issue-console-ticket", { method: "POST", body: {} });
      if (issued.handoffUrl) {
        window.open(issued.handoffUrl, "_blank", "noopener");
        setNotice("\u5DF2\u7B7E\u53D1\u4E00\u6B21\u6027 60 \u79D2\u53EA\u8BFB\u89C2\u6D4B\u7968\u636E\u5E76\u6253\u5F00 Console Origin\u3002");
      }
    });
  }
  async function handleLogout() {
    await runMutation(async () => {
      stopLiveResources();
      await client.api("/api/auth/logout", { method: "POST", body: {} });
      client.clearTabToken();
      state.snapshot = null;
      state.reviewModal = null;
      setNotice("\u5DF2\u9501\u5B9A\u9000\u51FA\uFF0C\u5E76\u540C\u6B65\u64A4\u9500\u6240\u6709\u5173\u8054\u7684\u53EA\u8BFB\u63A7\u5236\u53F0\u4F1A\u8BDD\u3002");
      await refreshAuthState();
    });
  }
  function renderTopbar() {
    const authed = Boolean(state.auth?.authenticated);
    return el("header", { class: "lw-topbar" }, [
      el("div", { class: "lw-topbar-inner" }, [
        el("div", { class: "lw-brand" }, [
          el("div", { class: "lw-trust-shield", "aria-hidden": "true", text: "\u76FE" }),
          el("div", {}, [
            el("div", { class: "lw-row" }, [
              el("h1", { class: "lw-brand-title", text: "LoomWard \xB7 \u7EC7\u76FE" }),
              el("span", { class: "lw-pill lw-pill-trust", text: "Trust Origin \xB7 Ring 2 \u96F6\u6269\u5C55" })
            ]),
            el("p", { class: "lw-brand-sub", text: "\u72EC\u7ACB\u8BA4\u8BC1\u3001\u7CBE\u786E\u9010\u53C2\u590D\u6838\u5BA1\u6279\u4E0E\u6838\u5FC3\u80FD\u529B\u7194\u65AD\u63A7\u5236\u9762" })
          ])
        ]),
        el("div", { class: "lw-row" }, [
          el("span", {
            class: `lw-pill ${authed ? "lw-pill-ok" : "lw-pill-warn"}`,
            text: authed ? `\u5DF2\u8BA4\u8BC1 (${state.auth.authMethod})` : "\u672A\u89E3\u9501"
          }),
          authed && state.consoleOrigin ? el("button", {
            type: "button",
            class: "lw-btn lw-btn-primary",
            disabled: state.busy,
            text: "\u6253\u5F00\u89C2\u6D4B\u63A7\u5236\u53F0 (Console)",
            onClick: handleOpenConsole
          }) : null,
          el("button", {
            type: "button",
            class: "lw-btn",
            text: theme.current() === "dark" ? "\u6D45\u8272" : "\u6DF1\u8272",
            onClick: () => {
              theme.toggle();
              render();
            }
          }),
          authed ? el("button", {
            type: "button",
            class: "lw-btn",
            disabled: state.busy,
            text: "\u9501\u5B9A\u9000\u51FA",
            onClick: handleLogout
          }) : null
        ])
      ])
    ]);
  }
  function renderAuthGate() {
    const auth = state.auth || {};
    const needPasskey = Boolean(auth.requirePasskey || auth.hostPasskeySupported || auth.passkeys?.length > 0);
    const pwInput = el("input", { type: "password", class: "lw-input", placeholder: "\u8F93\u5165\u672C\u673A\u5F3A\u5BC6\u7801\uFF08\u226514 \u4F4D\uFF09", autocomplete: "current-password" });
    const ticketInput = el("input", { type: "text", class: "lw-input lw-mono", placeholder: "\u7EC8\u7AEF webui-auth init \u7B7E\u53D1\u7684\u4E00\u6B21\u6027 setupToken" });
    const labelInput = el("input", { type: "text", class: "lw-input", placeholder: "PassKey \u5907\u6CE8\u540D\u79F0\uFF08\u5982 YubiKey / Touch ID\uFF09" });
    const body = [];
    if (!auth.initialized) {
      body.push(el("p", { class: "lw-muted", text: "\u9996\u6B21\u521D\u59CB\u5316\u987B\u5728\u672C\u673A\u7EC8\u7AEF\u6267\u884C webui-auth init \u83B7\u53D6\u4E00\u6B21\u6027 setupToken\uFF0C\u518D\u5728\u6B64\u72EC\u7ACB\u4FE1\u4EFB\u9762\u5B8C\u6210\u51ED\u636E\u7ED1\u5B9A\u3002" }));
      body.push(ticketInput);
      if (needPasskey) {
        body.push(labelInput);
        body.push(el("button", {
          type: "button",
          class: "lw-btn lw-btn-trust",
          disabled: state.busy,
          text: "\u4F7F\u7528 PassKey \u5B8C\u6210\u521D\u59CB\u5316",
          onClick: () => handlePasskeyEnroll(ticketInput.value.trim(), labelInput.value.trim())
        }));
      } else {
        body.push(pwInput);
        body.push(el("div", { class: "lw-row" }, [
          el("button", {
            type: "button",
            class: "lw-btn lw-btn-trust",
            disabled: state.busy,
            text: "\u914D\u7F6E\u5F3A\u5BC6\u7801\u5E76\u89E3\u9501",
            onClick: () => runMutation(async () => {
              await client.api("/api/auth/setup/password", {
                method: "POST",
                body: { setupToken: ticketInput.value.trim(), password: pwInput.value }
              });
              pwInput.value = "";
              await refreshAuthState();
            })
          }),
          el("button", {
            type: "button",
            class: "lw-btn",
            disabled: state.busy,
            text: "\u6539\u7528 PassKey \u521D\u59CB\u5316",
            onClick: () => handlePasskeyEnroll(ticketInput.value.trim(), "Local PassKey")
          })
        ]));
      }
    } else if (needPasskey) {
      body.push(el("p", { class: "lw-muted", text: "\u672C\u673A\u5DF2\u542F\u7528\u5F3A\u5236 PassKey\uFF08WebAuthn\uFF09\u9A8C\u8BC1\uFF0C\u4EC5\u5141\u8BB8\u5728\u5F53\u524D\u72EC\u7ACB\u4FE1\u4EFB\u9762\u89E3\u9501\u3002" }));
      body.push(el("button", {
        type: "button",
        class: "lw-btn lw-btn-trust",
        disabled: state.busy,
        text: "\u4F7F\u7528 PassKey \u89E3\u9501\u4FE1\u4EFB\u9762",
        onClick: handlePasskeyLogin
      }));
    } else {
      body.push(pwInput);
      body.push(el("button", {
        type: "button",
        class: "lw-btn lw-btn-trust",
        disabled: state.busy,
        text: "\u9A8C\u8BC1\u5F3A\u5BC6\u7801\u89E3\u9501",
        onClick: () => runMutation(async () => {
          await client.api("/api/auth/login/password", {
            method: "POST",
            body: { password: pwInput.value }
          });
          pwInput.value = "";
          await refreshAuthState();
        })
      }));
    }
    return el("section", { class: "lw-card" }, [
      el("div", { class: "lw-card-head" }, [
        el("div", {}, [
          el("h2", { text: "\u72EC\u7ACB\u4FE1\u4EFB\u9762\u8EAB\u4EFD\u9A8C\u8BC1" }),
          el("p", { class: "lw-muted", text: "Trust Origin \u7269\u7406\u9694\u79BB\u4E8E\u63A7\u5236\u53F0\u4E0E\u5168\u90E8\u6269\u5C55\u63D2\u4EF6\uFF0C\u6240\u6709 PassKey\u3001\u5BA1\u6279\u4E0E\u5F00\u5173\u4EC5\u5728\u6B64\u751F\u6548\u3002" })
        ]),
        el("span", { class: "lw-pill lw-pill-warn", text: auth.initialized ? "\u5DF2\u9501\u5B9A" : "\u5F85\u521D\u59CB\u5316" })
      ]),
      el("div", { style: "display:flex;flex-direction:column;gap:10px;max-width:480px;" }, body)
    ]);
  }
  function renderApprovalsCard() {
    const items = state.snapshot?.approvals?.items || [];
    const list = items.length ? items.map((item) => {
      const leftSec = Math.max(0, Math.ceil((Date.parse(item.expiresAt) - Date.now()) / 1e3));
      return el("div", { class: "lw-approval-item" }, [
        el("div", { class: "lw-row", style: "justify-content:space-between;" }, [
          el("strong", { class: "lw-mono", text: `${item.tool}  #${item.idShort}` }),
          el("span", { class: `lw-pill ${leftSec <= 30 ? "lw-pill-err" : "lw-pill-warn"}`, text: `\u5269\u4F59 ${leftSec}s` })
        ]),
        el("div", { class: "lw-muted lw-mono", text: `client=${item.clientId || "unknown"} \xB7 ${item.alreadyApproved ? "\u5DF2\u7B7E\u53D1\u5F85\u6D88\u8D39" : "\u7B49\u5F85\u4EBA\u5DE5\u590D\u6838"}` }),
        el("div", { class: "lw-row" }, [
          item.approvable ? el("button", {
            type: "button",
            class: "lw-btn lw-btn-trust",
            disabled: state.busy || leftSec <= 0,
            text: "\u590D\u6838\u5B8C\u6574\u53C2\u6570",
            onClick: () => runMutation(async () => {
              const review = await client.api("/api/approvals/review", { method: "POST", body: { id: item.id } });
              state.reviewModal = { ...review, tool: item.tool, expiresAt: item.expiresAt };
            })
          }) : null,
          item.id ? el("button", {
            type: "button",
            class: "lw-btn lw-btn-danger",
            disabled: state.busy,
            text: "\u62D2\u7EDD\u5E76\u79FB\u9664",
            onClick: () => runMutation(async () => {
              const res = await client.api("/api/approvals/reject", { method: "POST", body: { id: item.id } });
              if (res.snapshot) state.snapshot = res.snapshot;
              setNotice(`\u5DF2\u62D2\u7EDD\u8BF7\u6C42 #${item.idShort}\u3002`);
            })
          }) : null
        ])
      ]);
    }) : [el("p", { class: "lw-muted", text: "\u5F53\u524D\u65E0\u5F85\u4EBA\u5DE5\u6279\u51C6\u7684\u5DE5\u5177\u8BF7\u6C42\u3002" })];
    return el("section", { class: "lw-card" }, [
      el("div", { class: "lw-card-head" }, [
        el("div", {}, [
          el("h2", { text: "\u7CBE\u786E\u9010\u53C2\u590D\u6838\u5BA1\u6279\u961F\u5217" }),
          el("p", { class: "lw-muted", text: "\u4EC5\u5728 Trust Origin \u5C55\u793A\u5B8C\u6574\u672A\u8131\u654F\u53C2\u6570\uFF0C\u6279\u51C6\u540E\u5355\u6B21\u6D88\u8D39\u5E76\u767B\u8BB0 24h \u9632\u91CD\u653E\u8D26\u672C\u3002" })
        ]),
        el("span", { class: `lw-pill ${items.length ? "lw-pill-warn" : "lw-pill-ok"}`, text: `${items.length} \u6761\u5F85\u5BA1` })
      ]),
      el("div", { style: "display:flex;flex-direction:column;gap:10px;" }, list)
    ]);
  }
  function renderCapabilitiesCard() {
    const cap = state.snapshot?.capabilities || {};
    const makeToggle = (label, desc, field, value) => el("div", { class: "lw-switch-row" }, [
      el("div", {}, [
        el("strong", { text: label }),
        el("div", { class: "lw-muted", text: desc })
      ]),
      el("button", {
        type: "button",
        class: `lw-btn ${value ? "lw-btn-trust" : ""}`,
        disabled: state.busy,
        text: value ? "\u5DF2\u542F\u7528\uFF08\u70B9\u51FB\u5173\u95ED\uFF09" : "\u5DF2\u5173\u95ED\uFF08\u70B9\u51FB\u542F\u7528\uFF09",
        onClick: () => runMutation(async () => {
          const res = await client.api("/api/capabilities", { method: "POST", body: { [field]: !value } });
          if (res.snapshot) state.snapshot = res.snapshot;
          setNotice(`\u5DF2\u66F4\u65B0\u80FD\u529B\u5F00\u5173\uFF1A${label} -> ${!value ? "\u5F00\u542F" : "\u5173\u95ED"}\u3002`);
        })
      })
    ]);
    return el("section", { class: "lw-card" }, [
      el("div", { class: "lw-card-head" }, [
        el("div", {}, [
          el("h2", { text: "\u6838\u5FC3\u80FD\u529B\u603B\u7194\u65AD\u95F8\u95E8" }),
          el("p", { class: "lw-muted", text: "\u5199\u5165\u5DE5\u4F5C\u533A\u5916 0600 capabilities.json\uFF0C\u5B9E\u65F6\u751F\u6548\u4E14\u65E0\u9700\u91CD\u542F\u8FDE\u63A5\u5668\u3002" })
        ]),
        el("span", { class: `lw-pill ${cap.mountMode === "readwrite" ? "lw-pill-warn" : "lw-pill-ok"}`, text: `\u6302\u8F7D\uFF1A${cap.mountMode || "unknown"}` })
      ]),
      makeToggle("\u6587\u4EF6\u8BFB\u53D6 (fileRead)", "\u63A7\u5236 read_file / list_directory / search_files \u53CA\u5BB9\u5668\u5DE5\u4F5C\u533A\u8BFB\u53D6", "fileRead", Boolean(cap.fileRead)),
      makeToggle("\u6587\u4EF6\u5199\u5165 (fileWrite)", "\u5173\u95ED\u540E\u7981\u6B62\u6587\u4EF6\u5199\u5165\u5E76\u5C06\u5BB9\u5668 /workspace \u81EA\u52A8\u964D\u7EA7\u4E3A :readonly", "fileWrite", Boolean(cap.fileWrite)),
      makeToggle("\u5BB9\u5668\u547D\u4EE4 (allowExec)", "\u63A7\u5236\u4E00\u6B21\u6027\u53EA\u8BFB Linux \u5BB9\u5668\u5185 exec_command \u6267\u884C\u80FD\u529B", "allowExec", Boolean(cap.allowExec))
    ]);
  }
  function renderSessionAndServiceCard() {
    const persistence = state.auth?.sessionPersistence || "tab";
    const serviceBtn = (label, action) => el("button", {
      type: "button",
      class: "lw-btn",
      disabled: state.busy,
      text: label,
      onClick: () => runMutation(async () => {
        const res = await client.api("/api/service", { method: "POST", body: { action } });
        if (res.snapshot) state.snapshot = res.snapshot;
        setNotice(`\u670D\u52A1\u64CD\u4F5C ${action} \u5DF2\u5B8C\u6210\u3002`);
      })
    });
    return el("section", { class: "lw-card" }, [
      el("div", { class: "lw-card-head" }, [
        el("div", {}, [
          el("h2", { text: "\u4F1A\u8BDD\u9694\u79BB\u4E0E\u5BBF\u4E3B\u670D\u52A1\u63A7\u5236" }),
          el("p", { class: "lw-muted", text: "\u9ED8\u8BA4\u91C7\u7528\u6807\u7B7E\u9875\u9694\u79BB\u8BA4\u8BC1\uFF08X-LoomWard-Tab-Auth\uFF09\uFF0C\u5173\u95ED\u6807\u7B7E\u9875\u81EA\u52A8\u91CD\u65B0\u9501\u5B9A\u3002" })
        ]),
        el("span", { class: "lw-pill lw-pill-info", text: persistence === "tab" ? "\u6807\u7B7E\u9875\u9694\u79BB" : "\u6D4F\u89C8\u5668\u4F1A\u8BDD" })
      ]),
      el("div", { class: "lw-row", style: "margin-bottom:12px;" }, [
        el("button", {
          type: "button",
          class: `lw-btn ${persistence === "tab" ? "lw-btn-trust" : ""}`,
          disabled: state.busy || persistence === "tab",
          text: "\u5207\u56DE\u6807\u7B7E\u9875\u9694\u79BB\uFF08\u63A8\u8350\uFF09",
          onClick: () => runMutation(async () => {
            const res = await client.api("/api/auth/settings", { method: "POST", body: { sessionPersistence: "tab" } });
            if (res.authState) state.auth = res.authState;
            if (res.snapshot) state.snapshot = res.snapshot;
            setNotice("\u5DF2\u542F\u7528\u6807\u7B7E\u9875\u9694\u79BB\u8BA4\u8BC1\u5E76\u8F6E\u6362\u4EE4\u724C\u3002");
          })
        }),
        el("button", {
          type: "button",
          class: `lw-btn ${persistence === "browser" ? "lw-btn-trust" : ""}`,
          disabled: state.busy || persistence === "browser",
          text: "\u5141\u8BB8\u540C\u6D4F\u89C8\u5668\u590D\u7528\u4F1A\u8BDD",
          onClick: () => runMutation(async () => {
            const res = await client.api("/api/auth/settings", { method: "POST", body: { sessionPersistence: "browser" } });
            if (res.authState) state.auth = res.authState;
            if (res.snapshot) state.snapshot = res.snapshot;
            setNotice("\u5DF2\u5207\u6362\u4E3A\u6D4F\u89C8\u5668\u4F1A\u8BDD\u6A21\u5F0F\u3002");
          })
        })
      ]),
      el("div", { class: "lw-row" }, [
        serviceBtn("\u542F\u52A8\u8FDE\u63A5\u5668", "start"),
        serviceBtn("\u91CD\u542F\u8FDE\u63A5\u5668", "restart"),
        serviceBtn("\u505C\u6B62\u8FDE\u63A5\u5668", "stop")
      ])
    ]);
  }
  function renderReviewModal() {
    const modal = state.reviewModal;
    if (!modal) return null;
    const leftSec = Math.max(0, Math.ceil((Date.parse(modal.expiresAt) - Date.now()) / 1e3));
    return el("div", { class: "lw-modal-backdrop", role: "dialog", "aria-modal": "true" }, [
      el("div", { class: "lw-modal" }, [
        el("div", { class: "lw-row", style: "justify-content:space-between;" }, [
          el("h3", { text: `\u7CBE\u786E\u53C2\u6570\u590D\u6838 \xB7 ${modal.tool}` }),
          el("span", { class: `lw-pill ${leftSec <= 20 ? "lw-pill-err" : "lw-pill-warn"}`, text: `\u5269\u4F59 ${leftSec}s` })
        ]),
        el("div", { class: "lw-muted lw-mono", text: `policyDigest: ${modal.digest}` }),
        el("pre", { class: "lw-pre", text: modal.requestText }),
        el("div", { class: "lw-row", style: "justify-content:flex-end;" }, [
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
  function render() {
    clearNode(root);
    const children = [renderTopbar()];
    const main = el("main", { class: "lw-shell" });
    if (state.error) main.append(el("div", { class: "lw-banner lw-banner-err", role: "alert", text: state.error }));
    if (state.notice) main.append(el("div", { class: "lw-banner lw-banner-ok", role: "status", text: state.notice }));
    if (!state.auth?.authenticated) {
      main.append(renderAuthGate());
    } else {
      main.append(renderApprovalsCard());
      main.append(renderCapabilitiesCard());
      main.append(renderSessionAndServiceCard());
    }
    children.push(main);
    const modal = renderReviewModal();
    if (modal) children.push(modal);
    root.append(...children);
  }
  void refreshAuthState().catch((err) => setError(err?.message || "\u65E0\u6CD5\u8FDE\u63A5 Trust Origin\u3002"));
})();
