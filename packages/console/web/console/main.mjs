// SPDX-License-Identifier: AGPL-3.0-only
// Ring 3 isolated Console Origin UI — Strictly read-only telemetry, audit stream, tool catalog, and declarative console:panel@1 renderer.
import {
  clearNode,
  createOriginClient,
  el,
  initThemeToggle,
  readMeta,
} from '../shared/client.mjs';

const client = createOriginClient({ storageKey: 'loomward_console_tab_token' });
const theme = initThemeToggle();
const root = document.getElementById('app');

const state = {
  session: null,
  snapshot: null,
  trustOrigin: readMeta('loomward-trust-origin'),
  tab: 'overview',
  toolFilter: 'all',
  sseStatus: 'idle',
  liveKernelEvents: [],
  error: '',
  stopSse: null,
};

function extractAndScrubTicketFromHash() {
  const rawHash = window.location.hash || '';
  const match = rawHash.match(/ticket=([A-Za-z0-9_-]{32,80})/);
  if (!match) return null;
  try {
    window.history.replaceState(null, '', window.location.pathname + window.location.search);
  } catch {}
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
  state.stopSse = client.connectSse('/api/events', {
    onStatus(status) {
      state.sseStatus = status;
      if (status === 'unauthorized') {
        stopStream();
        client.clearTabToken();
        state.snapshot = null;
        state.liveKernelEvents = [];
        if (state.session) state.session.authenticated = false;
      }
      render();
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
}

async function boot() {
  const handoffTicket = extractAndScrubTicketFromHash();
  try {
    const sess = await client.api('/api/console/session');
    state.session = sess;
    if (sess.trustOrigin) state.trustOrigin = sess.trustOrigin;

    if (handoffTicket) {
      const exchanged = await client.api('/api/console/session/exchange', {
        method: 'POST',
        body: { ticket: handoffTicket },
      });
      state.session = {
        authenticated: true,
        role: exchanged.role,
        sessionPersistence: exchanged.sessionPersistence,
        trustOrigin: exchanged.trustOrigin || state.trustOrigin,
      };
    }

    if (state.session?.authenticated) {
      state.snapshot = await client.api('/api/status');
      state.liveKernelEvents = Array.isArray(state.snapshot?.channelEvents) ? [...state.snapshot.channelEvents].reverse() : [];
      startStream();
    }
  } catch (err) {
    state.error = err?.message || 'Console 初始化失败。';
  }
  render();
}

async function handleLogout() {
  try {
    stopStream();
    await client.api('/api/console/logout', { method: 'POST', body: {} });
  } catch {}
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

  return el('header', { class: 'lw-topbar' }, [
    el('div', { class: 'lw-topbar-inner' }, [
      el('div', { class: 'lw-brand' }, [
        el('div', { class: 'lw-console-mark', 'aria-hidden': 'true', text: '织' }),
        el('div', {}, [
          el('div', { class: 'lw-row' }, [
            el('h1', { class: 'lw-brand-title', text: 'LoomWard · Console' }),
            el('span', { class: 'lw-pill lw-pill-info', text: 'Ring 3 只读观测面' }),
          ]),
          el('p', { class: 'lw-brand-sub', text: '实时审计、工具目录与声明式扩展面板（修改能力与批准须跳转 Trust Origin）' }),
        ]),
      ]),
      authed
        ? el('nav', { class: 'lw-tabs', role: 'tablist' }, [
            ['overview', '运行概览'],
            ['audit', `实时审计${pendingCount ? ` (${pendingCount})` : ''}`],
            ['tools', '工具目录'],
            ['panels', `扩展面板 (${panelsCount})`],
          ].map(([id, label]) => el('button', {
            type: 'button',
            class: `lw-tab ${state.tab === id ? 'active' : ''}`,
            role: 'tab',
            'aria-selected': String(state.tab === id),
            text: label,
            onClick: () => { state.tab = id; render(); },
          })))
        : null,
      el('div', { class: 'lw-row' }, [
        authed
          ? el('span', {
              class: `lw-pill ${state.sseStatus === 'connected' ? 'lw-pill-ok' : 'lw-pill-warn'}`,
              text: state.sseStatus === 'connected' ? '实时通道在线' : '连接中',
            })
          : null,
        state.trustOrigin
          ? el('a', {
              class: 'lw-btn lw-btn-trust',
              href: state.trustOrigin,
              target: '_blank',
              rel: 'noopener noreferrer',
              text: '打开 Trust Origin',
            })
          : null,
        el('button', {
          type: 'button',
          class: 'lw-btn',
          text: theme.current() === 'dark' ? '浅色' : '深色',
          onClick: () => { theme.toggle(); render(); },
        }),
        authed
          ? el('button', { type: 'button', class: 'lw-btn', text: '锁定只读会话', onClick: handleLogout })
          : null,
      ]),
    ]),
  ]);
}

function renderLockedGate() {
  return el('section', { class: 'lw-card' }, [
    el('div', { class: 'lw-card-head' }, [
      el('div', {}, [
        el('h2', { text: 'Console Origin 只读会话未解锁' }),
        el('p', { class: 'lw-muted', text: '出于双源物理隔离原则，Console Origin 不接收 PassKey 或强密码。请先在 Trust Origin 完成验证并点击「打开观测控制台」。' }),
      ]),
      el('span', { class: 'lw-pill lw-pill-warn', text: '双源隔离保护' }),
    ]),
    state.trustOrigin
      ? el('a', {
          class: 'lw-btn lw-btn-trust',
          href: state.trustOrigin,
          text: `前往 Trust Origin (${state.trustOrigin}) 解锁`,
        })
      : el('p', { class: 'lw-muted', text: '未配置 Trust Origin 地址。' }),
  ]);
}

function renderOverview() {
  const snap = state.snapshot || {};
  const daemon = snap.daemon || {};
  const cap = snap.capabilities || {};
  const kernel = snap.kernel || { roots: [], units: [] };
  const pending = snap.approvals?.pendingCount || 0;

  return el('div', { class: 'lw-stack-md' }, [
    pending > 0
      ? el('div', { class: 'lw-banner lw-banner-warn lw-row lw-between' }, [
          el('span', { text: `当前有 ${pending} 条待人工复核审批的工具请求，请前往独立 Trust Origin 复核参数。` }),
          state.trustOrigin
            ? el('a', { class: 'lw-btn lw-btn-trust', href: state.trustOrigin, target: '_blank', rel: 'noopener noreferrer', text: '去 Trust Origin 审批' })
            : null,
        ])
      : null,
    el('div', { class: 'lw-grid' }, [
      el('div', { class: 'lw-kpi' }, [
        el('div', { class: 'lw-kpi-label', text: '云端连接状态' }),
        el('div', { class: 'lw-kpi-value', text: daemon.online ? '在线' : '离线' }),
      ]),
      el('div', { class: 'lw-kpi' }, [
        el('div', { class: 'lw-kpi-label', text: '工作区挂载姿态' }),
        el('div', { class: 'lw-kpi-value', text: cap.mountMode || 'unknown' }),
      ]),
      el('div', { class: 'lw-kpi' }, [
        el('div', { class: 'lw-kpi-label', text: '内核根插件 / 进程外扩展' }),
        el('div', { class: 'lw-kpi-value', text: `${kernel.roots?.length || 0} / ${kernel.units?.length || 0}` }),
      ]),
      el('div', { class: 'lw-kpi' }, [
        el('div', { class: 'lw-kpi-label', text: '声明式扩展面板' }),
        el('div', { class: 'lw-kpi-value', text: String(snap.panels?.length || 0) }),
      ]),
    ]),
    el('section', { class: 'lw-card' }, [
      el('div', { class: 'lw-card-head' }, [
        el('div', {}, [
          el('h2', { text: '只读能力策略摘要' }),
          el('p', { class: 'lw-muted', text: 'Console Origin 仅允许观测当前姿态；如需切换开关，请前往 Trust Origin。' }),
        ]),
        el('span', { class: 'lw-pill lw-pill-info', text: '只读视图' }),
      ]),
      el('div', { class: 'lw-row' }, [
        el('span', { class: `lw-pill ${cap.fileRead ? 'lw-pill-ok' : 'lw-pill-err'}`, text: `文件读取：${cap.fileRead ? '开' : '关'}` }),
        el('span', { class: `lw-pill ${cap.fileWrite ? 'lw-pill-warn' : 'lw-pill-ok'}`, text: `文件写入：${cap.fileWrite ? '开' : '关（只读容器）'}` }),
        el('span', { class: `lw-pill ${cap.allowExec ? 'lw-pill-warn' : 'lw-pill-ok'}`, text: `容器命令：${cap.allowExec ? '开' : '关'}` }),
      ]),
    ]),
  ]);
}

function renderAudit() {
  const events = state.snapshot?.events || [];
  const rows = events.slice(0, 40).map(ev => el('tr', {}, [
    el('td', { class: 'lw-mono', text: ev.time || '' }),
    el('td', {}, [el('span', { class: `lw-pill lw-pill-${ev.tone === 'ok' ? 'ok' : ev.tone === 'err' ? 'err' : 'info'}`, text: ev.label || ev.source })]),
    el('td', { class: 'lw-mono', text: ev.name || '' }),
    el('td', { class: 'lw-muted lw-mono', text: ev.detail || '' }),
  ]));

  const channelRows = state.liveKernelEvents.slice(0, 15).map(ev => el('tr', {}, [
    el('td', { class: 'lw-mono', text: ev.time || '' }),
    el('td', { class: 'lw-mono', text: ev.type || '' }),
    el('td', { class: 'lw-muted lw-mono', text: JSON.stringify(ev.meta || {}) }),
  ]));

  return el('div', { class: 'lw-stack-md' }, [
    el('section', { class: 'lw-card' }, [
      el('div', { class: 'lw-card-head' }, [
        el('div', {}, [
          el('h2', { text: '实时内核控制通道事件（仅元数据）' }),
          el('p', { class: 'lw-muted', text: '经进程内总线或私有 0600 control.sock 推送，零正文与凭据暴露。' }),
        ]),
        el('span', { class: 'lw-pill lw-pill-info', text: `${state.liveKernelEvents.length} 条` }),
      ]),
      channelRows.length
        ? el('div', { class: 'lw-table-wrap' }, [
            el('table', { class: 'lw-table' }, [
              el('thead', {}, [el('tr', {}, [el('th', { text: '时间' }), el('th', { text: '事件类型' }), el('th', { text: '元数据' })])]),
              el('tbody', {}, channelRows),
            ]),
          ])
        : el('p', { class: 'lw-muted', text: '暂无实时控制通道事件。' }),
    ]),
    el('section', { class: 'lw-card' }, [
      el('h2', { text: '审计与连接器遥测流' }),
      rows.length
        ? el('div', { class: 'lw-table-wrap' }, [
            el('table', { class: 'lw-table' }, [
              el('thead', {}, [el('tr', {}, [el('th', { text: '时间' }), el('th', { text: '状态' }), el('th', { text: '工具 / 事件' }), el('th', { text: '摘要' })])]),
              el('tbody', {}, rows),
            ]),
          ])
        : el('p', { class: 'lw-muted', text: '暂无历史审计记录。' }),
    ]),
  ]);
}

function renderTools() {
  const allTools = state.snapshot?.capabilities?.effectiveTools || [];
  const filtered = state.toolFilter === 'all'
    ? allTools
    : allTools.filter(t => t.group === state.toolFilter);

  return el('section', { class: 'lw-card' }, [
    el('div', { class: 'lw-card-head' }, [
      el('div', {}, [
        el('h2', { text: '聚合工具目录' }),
        el('p', { class: 'lw-muted', text: '统一展示内置 Linux Docker 沙箱工具与进程外第三方 MCP / 插件工具。' }),
      ]),
      el('div', { class: 'lw-row' }, [
        ['all', '全部'], ['fileRead', '文件读'], ['fileWrite', '文件写'], ['exec', '容器命令'], ['mcp', '第三方 MCP'],
      ].map(([key, label]) => el('button', {
        type: 'button',
        class: `lw-tab ${state.toolFilter === key ? 'active' : ''}`,
        text: label,
        onClick: () => { state.toolFilter = key; render(); },
      }))),
    ]),
    el('div', { class: 'lw-table-wrap' }, [
      el('table', { class: 'lw-table' }, [
        el('thead', {}, [el('tr', {}, [
          el('th', { text: '工具标识' }),
          el('th', { text: '运行边界' }),
          el('th', { text: '状态' }),
          el('th', { text: '调用统计' }),
        ])]),
        el('tbody', {}, filtered.map(tool => el('tr', {}, [
          el('td', {}, [
            el('div', { class: 'lw-mono', text: tool.name }),
            el('div', { class: 'lw-muted', text: tool.title || '' }),
          ]),
          el('td', {}, [
            el('span', {
              class: `lw-pill ${tool.external ? 'lw-pill-warn' : 'lw-pill-ok'}`,
              text: tool.external ? '进程外 MCP（非容器）' : 'Docker 只读沙箱',
            }),
          ]),
          el('td', {}, [
            el('span', { class: `lw-pill ${tool.enabled ? 'lw-pill-ok' : 'lw-pill-err'}`, text: tool.enabled ? '可用' : '停用' }),
          ]),
          el('td', { class: 'lw-mono', text: `总 ${tool.stats?.totalCalls || 0} / 阻 ${tool.stats?.blockedCount || 0}` }),
        ]))),
      ]),
    ]),
  ]);
}

function renderDeclarativePanels() {
  const panels = state.snapshot?.panels || [];
  if (!panels.length) {
    return el('section', { class: 'lw-card' }, [
      el('h2', { text: '声明式扩展面板（console:panel@1）' }),
      el('p', { class: 'lw-muted', text: '当前未挂载注册扩展面板的插件。任何实现 console:panel@1 契约的进程外插件（如防泄漏、决策台账或独立 LLM 内容审核插件）均会在此自动只读渲染，无需修改控制台源码。' }),
    ]);
  }

  return el('div', { class: 'lw-panel-grid' }, panels.map(panel => {
    const statusTone = panel.status === 'ok' ? 'ok' : panel.status === 'warn' ? 'warn' : panel.status === 'error' ? 'err' : 'info';
    const cardChildren = [
      el('div', { class: 'lw-card-head' }, [
        el('div', {}, [
          el('h3', { text: panel.title }),
          panel.subtitle ? el('p', { class: 'lw-muted', text: panel.subtitle }) : null,
        ]),
        el('div', { class: 'lw-row' }, [
          el('span', { class: 'lw-pill', text: panel.category }),
          el('span', { class: `lw-pill lw-pill-${statusTone}`, text: panel.status }),
        ]),
      ]),
    ];

    if (panel.summary?.length) {
      cardChildren.push(el('div', { class: 'lw-summary-strip' }, panel.summary.map(kpi => el('div', { class: 'lw-kpi' }, [
        el('div', { class: 'lw-kpi-label', text: kpi.label }),
        el('div', { class: 'lw-kpi-value', text: kpi.value }),
      ]))));
    }

    if (panel.notices?.length) {
      for (const notice of panel.notices) {
        const cls = notice.tone === 'err' ? 'err' : notice.tone === 'warn' ? 'warn' : notice.tone === 'ok' ? 'ok' : 'info';
        cardChildren.push(el('div', { class: `lw-banner lw-banner-${cls} lw-mb-sm`, text: notice.text }));
      }
    }

    const tables = Array.isArray(panel.tables) && panel.tables.length
      ? panel.tables
      : (panel.table?.columns?.length ? [panel.table] : []);
    for (const table of tables) {
      if (!table?.columns?.length) continue;
      if (table.title) {
        cardChildren.push(el('h4', { class: 'lw-table-title', text: table.title }));
      }
      cardChildren.push(el('div', { class: 'lw-table-wrap lw-mb-sm' }, [
        el('table', { class: 'lw-table' }, [
          el('thead', {}, [el('tr', {}, table.columns.map(col => el('th', { text: col })))]),
          el('tbody', {}, (table.rows || []).map(row => el('tr', {}, row.map(cell => el('td', { class: 'lw-mono', text: cell }))))),
        ]),
      ]));
    }

    if (panel.links?.length) {
      cardChildren.push(el('div', { class: 'lw-row' }, panel.links.map(link => el('a', {
        class: 'lw-btn',
        href: link.href,
        target: '_blank',
        rel: 'noopener noreferrer',
        text: link.label,
      }))));
    }

    return el('section', { class: 'lw-card', 'data-panel-id': panel.id }, cardChildren);
  }));
}

function render() {
  clearNode(root);
  const main = el('main', { class: 'lw-shell' });
  if (state.error) main.append(el('div', { class: 'lw-banner lw-banner-err', role: 'alert', text: state.error }));

  if (!state.session?.authenticated) {
    main.append(renderLockedGate());
  } else if (state.tab === 'audit') {
    main.append(renderAudit());
  } else if (state.tab === 'tools') {
    main.append(renderTools());
  } else if (state.tab === 'panels') {
    main.append(renderDeclarativePanels());
  } else {
    main.append(renderOverview());
  }

  root.append(renderTopbar(), main);
}

void boot();
