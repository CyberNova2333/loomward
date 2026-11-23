// SPDX-License-Identifier: AGPL-3.0-only
// Ring 2 isolated Trust Origin UI — Zero extension scripts/panels.
import {
  b64urlToBytes,
  bytesToB64url,
  clearNode,
  createOriginClient,
  el,
  initThemeToggle,
  readMeta,
} from '../shared/client.mjs';

const client = createOriginClient({ storageKey: 'loomward_trust_tab_token' });
const theme = initThemeToggle();
const root = document.getElementById('app');

const state = {
  auth: null,
  snapshot: null,
  consoleOrigin: readMeta('loomward-console-origin'),
  sseStatus: 'idle',
  error: '',
  notice: '',
  busy: false,
  reviewModal: null,
  stopSse: null,
  countdownTimer: null,
};

function setError(msg) {
  state.error = msg || '';
  if (msg) state.notice = '';
  render();
}

function setNotice(msg) {
  state.notice = msg || '';
  if (msg) state.error = '';
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
      await refreshAuthState();
    }
  } finally {
    state.busy = false;
    render();
  }
}

async function refreshAuthState() {
  const auth = await client.api('/api/auth/state');
  state.auth = auth;
  if (auth.consoleOrigin) state.consoleOrigin = auth.consoleOrigin;
  if (auth.authenticated) {
    const snap = await client.api('/api/status');
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
  state.stopSse = client.connectSse('/api/events', {
    onStatus(status) {
      state.sseStatus = status;
      if (status === 'unauthorized') {
        stopLiveResources();
        state.snapshot = null;
        void refreshAuthState();
      } else {
        render();
      }
    },
    onEvent(name, payload) {
      if (name === 'status') {
        state.snapshot = payload;
        render();
      }
    },
  });
  state.countdownTimer = setInterval(() => {
    if (state.snapshot?.approvals?.pendingCount > 0 || state.reviewModal) {
      render();
    }
  }, 1000);
}

async function handlePasskeyLogin() {
  await runMutation(async () => {
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
    setNotice('PassKey 注册并登录成功。');
    await refreshAuthState();
  });
}

async function handleOpenConsole() {
  await runMutation(async () => {
    const issued = await client.api('/api/trust/issue-console-ticket', { method: 'POST', body: {} });
    if (issued.handoffUrl) {
      window.open(issued.handoffUrl, '_blank', 'noopener');
      setNotice('已签发一次性 60 秒只读观测票据并打开 Console Origin。');
    }
  });
}

async function handleLogout() {
  await runMutation(async () => {
    stopLiveResources();
    await client.api('/api/auth/logout', { method: 'POST', body: {} });
    client.clearTabToken();
    state.snapshot = null;
    state.reviewModal = null;
    setNotice('已锁定退出，并同步撤销所有关联的只读控制台会话。');
    await refreshAuthState();
  });
}

function renderTopbar() {
  const authed = Boolean(state.auth?.authenticated);
  return el('header', { class: 'lw-topbar' }, [
    el('div', { class: 'lw-topbar-inner' }, [
      el('div', { class: 'lw-brand' }, [
        el('div', { class: 'lw-trust-shield', 'aria-hidden': 'true', text: '盾' }),
        el('div', {}, [
          el('div', { class: 'lw-row' }, [
            el('h1', { class: 'lw-brand-title', text: 'LoomWard · 织盾' }),
            el('span', { class: 'lw-pill lw-pill-trust', text: 'Trust Origin · Ring 2 零扩展' }),
          ]),
          el('p', { class: 'lw-brand-sub', text: '独立认证、精确逐参复核审批与核心能力熔断控制面' }),
        ]),
      ]),
      el('div', { class: 'lw-row' }, [
        el('span', {
          class: `lw-pill ${authed ? 'lw-pill-ok' : 'lw-pill-warn'}`,
          text: authed ? `已认证 (${state.auth.authMethod})` : '未解锁',
        }),
        authed && state.consoleOrigin
          ? el('button', {
              type: 'button',
              class: 'lw-btn lw-btn-primary',
              disabled: state.busy,
              text: '打开观测控制台 (Console)',
              onClick: handleOpenConsole,
            })
          : null,
        el('button', {
          type: 'button',
          class: 'lw-btn',
          text: theme.current() === 'dark' ? '浅色' : '深色',
          onClick: () => { theme.toggle(); render(); },
        }),
        authed
          ? el('button', {
              type: 'button',
              class: 'lw-btn',
              disabled: state.busy,
              text: '锁定退出',
              onClick: handleLogout,
            })
          : null,
      ]),
    ]),
  ]);
}

function renderAuthGate() {
  const auth = state.auth || {};
  const needPasskey = Boolean(auth.requirePasskey || auth.hostPasskeySupported || (auth.passkeys?.length > 0));
  const pwInput = el('input', { type: 'password', class: 'lw-input', placeholder: '输入本机强密码（≥14 位）', autocomplete: 'current-password' });
  const ticketInput = el('input', { type: 'text', class: 'lw-input lw-mono', placeholder: '终端 webui-auth init 签发的一次性 setupToken' });
  const labelInput = el('input', { type: 'text', class: 'lw-input', placeholder: 'PassKey 备注名称（如 YubiKey / Touch ID）' });

  const body = [];
  if (!auth.initialized) {
    body.push(el('p', { class: 'lw-muted', text: '首次初始化须在本机终端执行 webui-auth init 获取一次性 setupToken，再在此独立信任面完成凭据绑定。' }));
    body.push(ticketInput);
    if (needPasskey) {
      body.push(labelInput);
      body.push(el('button', {
        type: 'button',
        class: 'lw-btn lw-btn-trust',
        disabled: state.busy,
        text: '使用 PassKey 完成初始化',
        onClick: () => handlePasskeyEnroll(ticketInput.value.trim(), labelInput.value.trim()),
      }));
    } else {
      body.push(pwInput);
      body.push(el('div', { class: 'lw-row' }, [
        el('button', {
          type: 'button',
          class: 'lw-btn lw-btn-trust',
          disabled: state.busy,
          text: '配置强密码并解锁',
          onClick: () => runMutation(async () => {
            await client.api('/api/auth/setup/password', {
              method: 'POST',
              body: { setupToken: ticketInput.value.trim(), password: pwInput.value },
            });
            pwInput.value = '';
            await refreshAuthState();
          }),
        }),
        el('button', {
          type: 'button',
          class: 'lw-btn',
          disabled: state.busy,
          text: '改用 PassKey 初始化',
          onClick: () => handlePasskeyEnroll(ticketInput.value.trim(), 'Local PassKey'),
        }),
      ]));
    }
  } else if (needPasskey) {
    body.push(el('p', { class: 'lw-muted', text: '本机已启用强制 PassKey（WebAuthn）验证，仅允许在当前独立信任面解锁。' }));
    body.push(el('button', {
      type: 'button',
      class: 'lw-btn lw-btn-trust',
      disabled: state.busy,
      text: '使用 PassKey 解锁信任面',
      onClick: handlePasskeyLogin,
    }));
  } else {
    body.push(pwInput);
    body.push(el('button', {
      type: 'button',
      class: 'lw-btn lw-btn-trust',
      disabled: state.busy,
      text: '验证强密码解锁',
      onClick: () => runMutation(async () => {
        await client.api('/api/auth/login/password', {
          method: 'POST',
          body: { password: pwInput.value },
        });
        pwInput.value = '';
        await refreshAuthState();
      }),
    }));
  }

  return el('section', { class: 'lw-card' }, [
    el('div', { class: 'lw-card-head' }, [
      el('div', {}, [
        el('h2', { text: '独立信任面身份验证' }),
        el('p', { class: 'lw-muted', text: 'Trust Origin 物理隔离于控制台与全部扩展插件，所有 PassKey、审批与开关仅在此生效。' }),
      ]),
      el('span', { class: 'lw-pill lw-pill-warn', text: auth.initialized ? '已锁定' : '待初始化' }),
    ]),
    el('div', { style: 'display:flex;flex-direction:column;gap:10px;max-width:480px;' }, body),
  ]);
}

function renderApprovalsCard() {
  const items = state.snapshot?.approvals?.items || [];
  const list = items.length
    ? items.map(item => {
        const leftSec = Math.max(0, Math.ceil((Date.parse(item.expiresAt) - Date.now()) / 1000));
        return el('div', { class: 'lw-approval-item' }, [
          el('div', { class: 'lw-row', style: 'justify-content:space-between;' }, [
            el('strong', { class: 'lw-mono', text: `${item.tool}  #${item.idShort}` }),
            el('span', { class: `lw-pill ${leftSec <= 30 ? 'lw-pill-err' : 'lw-pill-warn'}`, text: `剩余 ${leftSec}s` }),
          ]),
          el('div', { class: 'lw-muted lw-mono', text: `client=${item.clientId || 'unknown'} · ${item.alreadyApproved ? '已签发待消费' : '等待人工复核'}` }),
          el('div', { class: 'lw-row' }, [
            item.approvable
              ? el('button', {
                  type: 'button',
                  class: 'lw-btn lw-btn-trust',
                  disabled: state.busy || leftSec <= 0,
                  text: '复核完整参数',
                  onClick: () => runMutation(async () => {
                    const review = await client.api('/api/approvals/review', { method: 'POST', body: { id: item.id } });
                    state.reviewModal = { ...review, tool: item.tool, expiresAt: item.expiresAt };
                  }),
                })
              : null,
            item.id
              ? el('button', {
                  type: 'button',
                  class: 'lw-btn lw-btn-danger',
                  disabled: state.busy,
                  text: '拒绝并移除',
                  onClick: () => runMutation(async () => {
                    const res = await client.api('/api/approvals/reject', { method: 'POST', body: { id: item.id } });
                    if (res.snapshot) state.snapshot = res.snapshot;
                    setNotice(`已拒绝请求 #${item.idShort}。`);
                  }),
                })
              : null,
          ]),
        ]);
      })
    : [el('p', { class: 'lw-muted', text: '当前无待人工批准的工具请求。' })];

  return el('section', { class: 'lw-card' }, [
    el('div', { class: 'lw-card-head' }, [
      el('div', {}, [
        el('h2', { text: '精确逐参复核审批队列' }),
        el('p', { class: 'lw-muted', text: '仅在 Trust Origin 展示完整未脱敏参数，批准后单次消费并登记 24h 防重放账本。' }),
      ]),
      el('span', { class: `lw-pill ${items.length ? 'lw-pill-warn' : 'lw-pill-ok'}`, text: `${items.length} 条待审` }),
    ]),
    el('div', { style: 'display:flex;flex-direction:column;gap:10px;' }, list),
  ]);
}

function renderCapabilitiesCard() {
  const cap = state.snapshot?.capabilities || {};
  const makeToggle = (label, desc, field, value) => el('div', { class: 'lw-switch-row' }, [
    el('div', {}, [
      el('strong', { text: label }),
      el('div', { class: 'lw-muted', text: desc }),
    ]),
    el('button', {
      type: 'button',
      class: `lw-btn ${value ? 'lw-btn-trust' : ''}`,
      disabled: state.busy,
      text: value ? '已启用（点击关闭）' : '已关闭（点击启用）',
      onClick: () => runMutation(async () => {
        const res = await client.api('/api/capabilities', { method: 'POST', body: { [field]: !value } });
        if (res.snapshot) state.snapshot = res.snapshot;
        setNotice(`已更新能力开关：${label} -> ${!value ? '开启' : '关闭'}。`);
      }),
    }),
  ]);

  return el('section', { class: 'lw-card' }, [
    el('div', { class: 'lw-card-head' }, [
      el('div', {}, [
        el('h2', { text: '核心能力总熔断闸门' }),
        el('p', { class: 'lw-muted', text: '写入工作区外 0600 capabilities.json，实时生效且无需重启连接器。' }),
      ]),
      el('span', { class: `lw-pill ${cap.mountMode === 'readwrite' ? 'lw-pill-warn' : 'lw-pill-ok'}`, text: `挂载：${cap.mountMode || 'unknown'}` }),
    ]),
    makeToggle('文件读取 (fileRead)', '控制 read_file / list_directory / search_files 及容器工作区读取', 'fileRead', Boolean(cap.fileRead)),
    makeToggle('文件写入 (fileWrite)', '关闭后禁止文件写入并将容器 /workspace 自动降级为 :readonly', 'fileWrite', Boolean(cap.fileWrite)),
    makeToggle('容器命令 (allowExec)', '控制一次性只读 Linux 容器内 exec_command 执行能力', 'allowExec', Boolean(cap.allowExec)),
  ]);
}

function renderSessionAndServiceCard() {
  const persistence = state.auth?.sessionPersistence || 'tab';
  const serviceBtn = (label, action) => el('button', {
    type: 'button',
    class: 'lw-btn',
    disabled: state.busy,
    text: label,
    onClick: () => runMutation(async () => {
      const res = await client.api('/api/service', { method: 'POST', body: { action } });
      if (res.snapshot) state.snapshot = res.snapshot;
      setNotice(`服务操作 ${action} 已完成。`);
    }),
  });

  return el('section', { class: 'lw-card' }, [
    el('div', { class: 'lw-card-head' }, [
      el('div', {}, [
        el('h2', { text: '会话隔离与宿主服务控制' }),
        el('p', { class: 'lw-muted', text: '默认采用标签页隔离认证（X-LoomWard-Tab-Auth），关闭标签页自动重新锁定。' }),
      ]),
      el('span', { class: 'lw-pill lw-pill-info', text: persistence === 'tab' ? '标签页隔离' : '浏览器会话' }),
    ]),
    el('div', { class: 'lw-row', style: 'margin-bottom:12px;' }, [
      el('button', {
        type: 'button',
        class: `lw-btn ${persistence === 'tab' ? 'lw-btn-trust' : ''}`,
        disabled: state.busy || persistence === 'tab',
        text: '切回标签页隔离（推荐）',
        onClick: () => runMutation(async () => {
          const res = await client.api('/api/auth/settings', { method: 'POST', body: { sessionPersistence: 'tab' } });
          if (res.authState) state.auth = res.authState;
          if (res.snapshot) state.snapshot = res.snapshot;
          setNotice('已启用标签页隔离认证并轮换令牌。');
        }),
      }),
      el('button', {
        type: 'button',
        class: `lw-btn ${persistence === 'browser' ? 'lw-btn-trust' : ''}`,
        disabled: state.busy || persistence === 'browser',
        text: '允许同浏览器复用会话',
        onClick: () => runMutation(async () => {
          const res = await client.api('/api/auth/settings', { method: 'POST', body: { sessionPersistence: 'browser' } });
          if (res.authState) state.auth = res.authState;
          if (res.snapshot) state.snapshot = res.snapshot;
          setNotice('已切换为浏览器会话模式。');
        }),
      }),
    ]),
    el('div', { class: 'lw-row' }, [
      serviceBtn('启动连接器', 'start'),
      serviceBtn('重启连接器', 'restart'),
      serviceBtn('停止连接器', 'stop'),
    ]),
  ]);
}

function renderReviewModal() {
  const modal = state.reviewModal;
  if (!modal) return null;
  const leftSec = Math.max(0, Math.ceil((Date.parse(modal.expiresAt) - Date.now()) / 1000));
  return el('div', { class: 'lw-modal-backdrop', role: 'dialog', 'aria-modal': 'true' }, [
    el('div', { class: 'lw-modal' }, [
      el('div', { class: 'lw-row', style: 'justify-content:space-between;' }, [
        el('h3', { text: `精确参数复核 · ${modal.tool}` }),
        el('span', { class: `lw-pill ${leftSec <= 20 ? 'lw-pill-err' : 'lw-pill-warn'}`, text: `剩余 ${leftSec}s` }),
      ]),
      el('div', { class: 'lw-muted lw-mono', text: `policyDigest: ${modal.digest}` }),
      el('pre', { class: 'lw-pre', text: modal.requestText }),
      el('div', { class: 'lw-row', style: 'justify-content:flex-end;' }, [
        el('button', {
          type: 'button',
          class: 'lw-btn',
          text: '取消',
          onClick: () => { state.reviewModal = null; render(); },
        }),
        el('button', {
          type: 'button',
          class: 'lw-btn lw-btn-trust',
          disabled: state.busy || leftSec <= 0,
          text: '确认批准一次',
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

function render() {
  clearNode(root);
  const children = [renderTopbar()];
  const main = el('main', { class: 'lw-shell' });
  if (state.error) main.append(el('div', { class: 'lw-banner lw-banner-err', role: 'alert', text: state.error }));
  if (state.notice) main.append(el('div', { class: 'lw-banner lw-banner-ok', role: 'status', text: state.notice }));

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

void refreshAuthState().catch(err => setError(err?.message || '无法连接 Trust Origin。'));
