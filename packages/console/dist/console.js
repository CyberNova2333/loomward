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
  var state = {
    session: null,
    snapshot: null,
    trustOrigin: readMeta("loomward-trust-origin"),
    tab: "overview",
    toolFilter: "all",
    sseStatus: "idle",
    liveKernelEvents: [],
    error: "",
    stopSse: null
  };
  function extractAndScrubTicketFromHash() {
    const rawHash = window.location.hash || "";
    const match = rawHash.match(/ticket=([A-Za-z0-9_-]{32,80})/);
    if (!match) return null;
    try {
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
    } catch {
    }
    return match[1];
  }
  function stopStream() {
    if (state.stopSse) {
      state.stopSse();
      state.stopSse = null;
    }
  }
  function startStream() {
    stopStream();
    state.stopSse = client.connectSse("/api/events", {
      onStatus(status) {
        state.sseStatus = status;
        if (status === "unauthorized") {
          stopStream();
          client.clearTabToken();
          state.snapshot = null;
          state.liveKernelEvents = [];
          if (state.session) state.session.authenticated = false;
        }
        render();
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
  }
  async function boot() {
    const handoffTicket = extractAndScrubTicketFromHash();
    try {
      const sess = await client.api("/api/console/session");
      state.session = sess;
      if (sess.trustOrigin) state.trustOrigin = sess.trustOrigin;
      if (handoffTicket) {
        try {
          const exchanged = await client.api("/api/console/session/exchange", {
            method: "POST",
            body: { ticket: handoffTicket }
          });
          state.session = {
            authenticated: true,
            role: exchanged.role,
            sessionPersistence: exchanged.sessionPersistence,
            trustOrigin: exchanged.trustOrigin || state.trustOrigin
          };
        } catch (err) {
          state.error = err?.message || "\u79FB\u4EA4\u7968\u636E\u5DF2\u5931\u6548\u6216\u4E0D\u53EF\u7528\u3002";
        }
      }
      if (state.session?.authenticated) {
        state.snapshot = await client.api("/api/status");
        state.liveKernelEvents = Array.isArray(state.snapshot?.channelEvents) ? [...state.snapshot.channelEvents].reverse() : [];
        startStream();
      }
    } catch (err) {
      state.error = err?.message || "Console \u521D\u59CB\u5316\u5931\u8D25\u3002";
    }
    render();
  }
  async function handleLogout() {
    try {
      stopStream();
      await client.api("/api/console/logout", { method: "POST", body: {} });
    } catch {
    }
    client.clearTabToken();
    state.snapshot = null;
    state.liveKernelEvents = [];
    if (state.session) state.session.authenticated = false;
    render();
  }
  function renderTopbar() {
    const authed = Boolean(state.session?.authenticated);
    const panelsCount = state.snapshot?.panels?.length || 0;
    const pendingCount = state.snapshot?.approvals?.pendingCount || 0;
    return el("header", { class: "lw-topbar" }, [
      el("div", { class: "lw-topbar-inner" }, [
        el("div", { class: "lw-brand" }, [
          el("div", { class: "lw-console-mark", "aria-hidden": "true", text: "\u7EC7" }),
          el("div", {}, [
            el("div", { class: "lw-row" }, [
              el("h1", { class: "lw-brand-title", text: "LoomWard \xB7 Console" }),
              el("span", { class: "lw-pill lw-pill-info", text: "Ring 3 \u53EA\u8BFB\u89C2\u6D4B\u9762" })
            ]),
            el("p", { class: "lw-brand-sub", text: "\u5B9E\u65F6\u5BA1\u8BA1\u3001\u5DE5\u5177\u76EE\u5F55\u4E0E\u58F0\u660E\u5F0F\u6269\u5C55\u9762\u677F\uFF08\u4FEE\u6539\u80FD\u529B\u4E0E\u6279\u51C6\u987B\u8DF3\u8F6C Trust Origin\uFF09" })
          ])
        ]),
        authed ? el("nav", { class: "lw-tabs", role: "tablist" }, [
          ["overview", "\u8FD0\u884C\u6982\u89C8"],
          ["audit", `\u5B9E\u65F6\u5BA1\u8BA1${pendingCount ? ` (${pendingCount})` : ""}`],
          ["tools", "\u5DE5\u5177\u76EE\u5F55"],
          ["panels", `\u6269\u5C55\u9762\u677F (${panelsCount})`]
        ].map(([id, label]) => el("button", {
          type: "button",
          class: `lw-tab ${state.tab === id ? "active" : ""}`,
          role: "tab",
          "aria-selected": String(state.tab === id),
          text: label,
          onClick: () => {
            state.tab = id;
            render();
          }
        }))) : null,
        el("div", { class: "lw-row" }, [
          authed ? el("span", {
            class: `lw-pill ${state.sseStatus === "connected" ? "lw-pill-ok" : "lw-pill-warn"}`,
            text: state.sseStatus === "connected" ? "\u5B9E\u65F6\u901A\u9053\u5728\u7EBF" : "\u8FDE\u63A5\u4E2D"
          }) : null,
          isSafeNavigationUrl(state.trustOrigin) ? el("a", {
            class: "lw-btn lw-btn-trust",
            href: state.trustOrigin,
            target: "_blank",
            rel: "noopener noreferrer",
            text: "\u6253\u5F00 Trust Origin"
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
          authed ? el("button", { type: "button", class: "lw-btn", text: "\u9501\u5B9A\u53EA\u8BFB\u4F1A\u8BDD", onClick: handleLogout }) : null
        ])
      ])
    ]);
  }
  function renderLockedGate() {
    return el("section", { class: "lw-card" }, [
      el("div", { class: "lw-card-head" }, [
        el("div", {}, [
          el("h2", { text: "Console Origin \u53EA\u8BFB\u4F1A\u8BDD\u672A\u89E3\u9501" }),
          el("p", { class: "lw-muted", text: "\u51FA\u4E8E\u53CC\u6E90\u7269\u7406\u9694\u79BB\u539F\u5219\uFF0CConsole Origin \u4E0D\u63A5\u6536 PassKey \u6216\u5F3A\u5BC6\u7801\u3002\u8BF7\u5148\u5728 Trust Origin \u5B8C\u6210\u9A8C\u8BC1\u5E76\u70B9\u51FB\u300C\u6253\u5F00\u89C2\u6D4B\u63A7\u5236\u53F0\u300D\u3002" })
        ]),
        el("span", { class: "lw-pill lw-pill-warn", text: "\u53CC\u6E90\u9694\u79BB\u4FDD\u62A4" })
      ]),
      isSafeNavigationUrl(state.trustOrigin) ? el("a", {
        class: "lw-btn lw-btn-trust",
        href: state.trustOrigin,
        rel: "noopener noreferrer",
        text: `\u524D\u5F80 Trust Origin (${state.trustOrigin}) \u89E3\u9501`
      }) : el("p", { class: "lw-muted", text: "\u672A\u914D\u7F6E Trust Origin \u5730\u5740\u3002" })
    ]);
  }
  function renderOverview() {
    const snap = state.snapshot || {};
    const daemon = snap.daemon || {};
    const cap = snap.capabilities || {};
    const kernel = snap.kernel || { roots: [], units: [] };
    const pending = snap.approvals?.pendingCount || 0;
    return el("div", { class: "lw-stack-md" }, [
      pending > 0 ? el("div", { class: "lw-banner lw-banner-warn lw-row lw-between" }, [
        el("span", { text: `\u5F53\u524D\u6709 ${pending} \u6761\u5F85\u4EBA\u5DE5\u590D\u6838\u5BA1\u6279\u7684\u5DE5\u5177\u8BF7\u6C42\uFF0C\u8BF7\u524D\u5F80\u72EC\u7ACB Trust Origin \u590D\u6838\u53C2\u6570\u3002` }),
        isSafeNavigationUrl(state.trustOrigin) ? el("a", { class: "lw-btn lw-btn-trust", href: state.trustOrigin, target: "_blank", rel: "noopener noreferrer", text: "\u53BB Trust Origin \u5BA1\u6279" }) : null
      ]) : null,
      el("div", { class: "lw-grid" }, [
        el("div", { class: "lw-kpi" }, [
          el("div", { class: "lw-kpi-label", text: "\u4E91\u7AEF\u8FDE\u63A5\u72B6\u6001" }),
          el("div", { class: "lw-kpi-value", text: daemon.online ? "\u5728\u7EBF" : "\u79BB\u7EBF" })
        ]),
        el("div", { class: "lw-kpi" }, [
          el("div", { class: "lw-kpi-label", text: "\u5DE5\u4F5C\u533A\u6302\u8F7D\u59FF\u6001" }),
          el("div", { class: "lw-kpi-value", text: cap.mountMode || "unknown" })
        ]),
        el("div", { class: "lw-kpi" }, [
          el("div", { class: "lw-kpi-label", text: "\u5185\u6838\u6839\u63D2\u4EF6 / \u8FDB\u7A0B\u5916\u6269\u5C55" }),
          el("div", { class: "lw-kpi-value", text: `${kernel.roots?.length || 0} / ${kernel.units?.length || 0}` })
        ]),
        el("div", { class: "lw-kpi" }, [
          el("div", { class: "lw-kpi-label", text: "\u58F0\u660E\u5F0F\u6269\u5C55\u9762\u677F" }),
          el("div", { class: "lw-kpi-value", text: String(snap.panels?.length || 0) })
        ])
      ]),
      el("section", { class: "lw-card" }, [
        el("div", { class: "lw-card-head" }, [
          el("div", {}, [
            el("h2", { text: "\u53EA\u8BFB\u80FD\u529B\u7B56\u7565\u6458\u8981" }),
            el("p", { class: "lw-muted", text: "Console Origin \u4EC5\u5141\u8BB8\u89C2\u6D4B\u5F53\u524D\u59FF\u6001\uFF1B\u5982\u9700\u5207\u6362\u5F00\u5173\uFF0C\u8BF7\u524D\u5F80 Trust Origin\u3002" })
          ]),
          el("span", { class: "lw-pill lw-pill-info", text: "\u53EA\u8BFB\u89C6\u56FE" })
        ]),
        el("div", { class: "lw-row" }, [
          el("span", { class: `lw-pill ${cap.fileRead ? "lw-pill-ok" : "lw-pill-err"}`, text: `\u6587\u4EF6\u8BFB\u53D6\uFF1A${cap.fileRead ? "\u5F00" : "\u5173"}` }),
          el("span", { class: `lw-pill ${cap.fileWrite ? "lw-pill-warn" : "lw-pill-ok"}`, text: `\u6587\u4EF6\u5199\u5165\uFF1A${cap.fileWrite ? "\u5F00" : "\u5173\uFF08\u53EA\u8BFB\u5BB9\u5668\uFF09"}` }),
          el("span", { class: `lw-pill ${cap.allowExec ? "lw-pill-warn" : "lw-pill-ok"}`, text: `\u5BB9\u5668\u547D\u4EE4\uFF1A${cap.allowExec ? "\u5F00" : "\u5173"}` })
        ])
      ])
    ]);
  }
  function renderAudit() {
    const events = state.snapshot?.events || [];
    const rows = events.slice(0, 40).map((ev) => el("tr", {}, [
      el("td", { class: "lw-mono", text: ev.time || "" }),
      el("td", {}, [el("span", { class: `lw-pill lw-pill-${ev.tone === "ok" ? "ok" : ev.tone === "err" ? "err" : "info"}`, text: ev.label || ev.source })]),
      el("td", { class: "lw-mono", text: ev.name || "" }),
      el("td", { class: "lw-muted lw-mono", text: ev.detail || "" })
    ]));
    const channelRows = state.liveKernelEvents.slice(0, 15).map((ev) => el("tr", {}, [
      el("td", { class: "lw-mono", text: ev.time || "" }),
      el("td", { class: "lw-mono", text: ev.type || "" }),
      el("td", { class: "lw-muted lw-mono", text: JSON.stringify(ev.meta || {}) })
    ]));
    return el("div", { class: "lw-stack-md" }, [
      el("section", { class: "lw-card" }, [
        el("div", { class: "lw-card-head" }, [
          el("div", {}, [
            el("h2", { text: "\u5B9E\u65F6\u5185\u6838\u63A7\u5236\u901A\u9053\u4E8B\u4EF6\uFF08\u4EC5\u5143\u6570\u636E\uFF09" }),
            el("p", { class: "lw-muted", text: "\u7ECF\u8FDB\u7A0B\u5185\u603B\u7EBF\u6216\u79C1\u6709 0600 control.sock \u63A8\u9001\uFF0C\u96F6\u6B63\u6587\u4E0E\u51ED\u636E\u66B4\u9732\u3002" })
          ]),
          el("span", { class: "lw-pill lw-pill-info", text: `${state.liveKernelEvents.length} \u6761` })
        ]),
        channelRows.length ? el("div", { class: "lw-table-wrap" }, [
          el("table", { class: "lw-table" }, [
            el("thead", {}, [el("tr", {}, [el("th", { text: "\u65F6\u95F4" }), el("th", { text: "\u4E8B\u4EF6\u7C7B\u578B" }), el("th", { text: "\u5143\u6570\u636E" })])]),
            el("tbody", {}, channelRows)
          ])
        ]) : el("p", { class: "lw-muted", text: "\u6682\u65E0\u5B9E\u65F6\u63A7\u5236\u901A\u9053\u4E8B\u4EF6\u3002" })
      ]),
      el("section", { class: "lw-card" }, [
        el("h2", { text: "\u5BA1\u8BA1\u4E0E\u8FDE\u63A5\u5668\u9065\u6D4B\u6D41" }),
        rows.length ? el("div", { class: "lw-table-wrap" }, [
          el("table", { class: "lw-table" }, [
            el("thead", {}, [el("tr", {}, [el("th", { text: "\u65F6\u95F4" }), el("th", { text: "\u72B6\u6001" }), el("th", { text: "\u5DE5\u5177 / \u4E8B\u4EF6" }), el("th", { text: "\u6458\u8981" })])]),
            el("tbody", {}, rows)
          ])
        ]) : el("p", { class: "lw-muted", text: "\u6682\u65E0\u5386\u53F2\u5BA1\u8BA1\u8BB0\u5F55\u3002" })
      ])
    ]);
  }
  function renderTools() {
    const allTools = state.snapshot?.capabilities?.effectiveTools || [];
    const filtered = state.toolFilter === "all" ? allTools : allTools.filter((t) => t.group === state.toolFilter);
    return el("section", { class: "lw-card" }, [
      el("div", { class: "lw-card-head" }, [
        el("div", {}, [
          el("h2", { text: "\u805A\u5408\u5DE5\u5177\u76EE\u5F55" }),
          el("p", { class: "lw-muted", text: "\u7EDF\u4E00\u5C55\u793A\u5185\u7F6E Linux Docker \u6C99\u7BB1\u5DE5\u5177\u4E0E\u8FDB\u7A0B\u5916\u7B2C\u4E09\u65B9 MCP / \u63D2\u4EF6\u5DE5\u5177\u3002" })
        ]),
        el("div", { class: "lw-row" }, [
          ["all", "\u5168\u90E8"],
          ["fileRead", "\u6587\u4EF6\u8BFB"],
          ["fileWrite", "\u6587\u4EF6\u5199"],
          ["exec", "\u5BB9\u5668\u547D\u4EE4"],
          ["mcp", "\u7B2C\u4E09\u65B9 MCP"]
        ].map(([key, label]) => el("button", {
          type: "button",
          class: `lw-tab ${state.toolFilter === key ? "active" : ""}`,
          text: label,
          onClick: () => {
            state.toolFilter = key;
            render();
          }
        })))
      ]),
      el("div", { class: "lw-table-wrap" }, [
        el("table", { class: "lw-table" }, [
          el("thead", {}, [el("tr", {}, [
            el("th", { text: "\u5DE5\u5177\u6807\u8BC6" }),
            el("th", { text: "\u8FD0\u884C\u8FB9\u754C" }),
            el("th", { text: "\u72B6\u6001" }),
            el("th", { text: "\u8C03\u7528\u7EDF\u8BA1" })
          ])]),
          el("tbody", {}, filtered.map((tool) => el("tr", {}, [
            el("td", {}, [
              el("div", { class: "lw-mono", text: tool.name }),
              el("div", { class: "lw-muted", text: tool.title || "" })
            ]),
            el("td", {}, [
              el("span", {
                class: `lw-pill ${tool.external ? "lw-pill-warn" : "lw-pill-ok"}`,
                text: tool.external ? "\u8FDB\u7A0B\u5916 MCP\uFF08\u975E\u5BB9\u5668\uFF09" : "Docker \u53EA\u8BFB\u6C99\u7BB1"
              })
            ]),
            el("td", {}, [
              el("span", { class: `lw-pill ${tool.enabled ? "lw-pill-ok" : "lw-pill-err"}`, text: tool.enabled ? "\u53EF\u7528" : "\u505C\u7528" })
            ]),
            el("td", { class: "lw-mono", text: `\u603B ${tool.stats?.totalCalls || 0} / \u963B ${tool.stats?.blockedCount || 0}` })
          ])))
        ])
      ])
    ]);
  }
  function renderDeclarativePanels() {
    const panels = state.snapshot?.panels || [];
    if (!panels.length) {
      return el("section", { class: "lw-card" }, [
        el("h2", { text: "\u58F0\u660E\u5F0F\u6269\u5C55\u9762\u677F\uFF08console:panel@1\uFF09" }),
        el("p", { class: "lw-muted", text: "\u5F53\u524D\u672A\u6302\u8F7D\u6CE8\u518C\u6269\u5C55\u9762\u677F\u7684\u63D2\u4EF6\u3002\u4EFB\u4F55\u5B9E\u73B0 console:panel@1 \u5951\u7EA6\u7684\u8FDB\u7A0B\u5916\u63D2\u4EF6\uFF08\u5982\u9632\u6CC4\u6F0F\u3001\u51B3\u7B56\u53F0\u8D26\u6216\u72EC\u7ACB LLM \u5185\u5BB9\u5BA1\u6838\u63D2\u4EF6\uFF09\u5747\u4F1A\u5728\u6B64\u81EA\u52A8\u53EA\u8BFB\u6E32\u67D3\uFF0C\u65E0\u9700\u4FEE\u6539\u63A7\u5236\u53F0\u6E90\u7801\u3002" })
      ]);
    }
    return el("div", { class: "lw-panel-grid" }, panels.map((panel) => {
      const statusTone = panel.status === "ok" ? "ok" : panel.status === "warn" ? "warn" : panel.status === "error" ? "err" : "info";
      const cardChildren = [
        el("div", { class: "lw-card-head" }, [
          el("div", {}, [
            el("h3", { text: panel.title }),
            panel.subtitle ? el("p", { class: "lw-muted", text: panel.subtitle }) : null
          ]),
          el("div", { class: "lw-row" }, [
            el("span", { class: "lw-pill", text: panel.category }),
            el("span", { class: `lw-pill lw-pill-${statusTone}`, text: panel.status })
          ])
        ])
      ];
      if (panel.summary?.length) {
        cardChildren.push(el("div", { class: "lw-summary-strip" }, panel.summary.map((kpi) => el("div", { class: "lw-kpi" }, [
          el("div", { class: "lw-kpi-label", text: kpi.label }),
          el("div", { class: "lw-kpi-value", text: kpi.value })
        ]))));
      }
      if (panel.notices?.length) {
        for (const notice of panel.notices) {
          const cls = notice.tone === "err" ? "err" : notice.tone === "warn" ? "warn" : notice.tone === "ok" ? "ok" : "info";
          cardChildren.push(el("div", { class: `lw-banner lw-banner-${cls} lw-mb-sm`, text: notice.text }));
        }
      }
      const tables = Array.isArray(panel.tables) && panel.tables.length ? panel.tables : panel.table?.columns?.length ? [panel.table] : [];
      for (const table of tables) {
        if (!table?.columns?.length) continue;
        if (table.title) {
          cardChildren.push(el("h4", { class: "lw-table-title", text: table.title }));
        }
        cardChildren.push(el("div", { class: "lw-table-wrap lw-mb-sm" }, [
          el("table", { class: "lw-table" }, [
            el("thead", {}, [el("tr", {}, table.columns.map((col) => el("th", { text: col })))]),
            el("tbody", {}, (table.rows || []).map((row) => el("tr", {}, row.map((cell) => el("td", { class: "lw-mono", text: cell })))))
          ])
        ]));
      }
      const safeLinks = Array.isArray(panel.links) ? panel.links.filter((link) => link && isSafeNavigationUrl(link.href, { allowRelative: true })) : [];
      if (safeLinks.length) {
        cardChildren.push(el("div", { class: "lw-row" }, safeLinks.map((link) => el("a", {
          class: "lw-btn",
          href: link.href,
          target: "_blank",
          rel: "noopener noreferrer",
          text: link.label
        }))));
      }
      return el("section", { class: "lw-card", "data-panel-id": panel.id }, cardChildren);
    }));
  }
  function render() {
    clearNode(root);
    const main = el("main", { class: "lw-shell" });
    if (state.error) main.append(el("div", { class: "lw-banner lw-banner-err", role: "alert", text: state.error }));
    if (!state.session?.authenticated) {
      main.append(renderLockedGate());
    } else if (state.tab === "audit") {
      main.append(renderAudit());
    } else if (state.tab === "tools") {
      main.append(renderTools());
    } else if (state.tab === "panels") {
      main.append(renderDeclarativePanels());
    } else {
      main.append(renderOverview());
    }
    root.append(renderTopbar(), main);
  }
  void boot();
})();
