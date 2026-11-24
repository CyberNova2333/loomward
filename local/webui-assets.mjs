// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).

function escapeHtmlAttr(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

export function renderWebUiHtml({ csrfToken }) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="agentdock-csrf" content="${escapeHtmlAttr(csrfToken)}" />
  <title>AgentDock Bridge · 本机控制台</title>
  <link rel="stylesheet" href="/styles.css" />
  <script defer src="/app.js"></script>
</head>
<body>
  <div class="docs-deco" aria-hidden="true">
    <div class="docs-deco-orb docs-deco-orb-a"></div>
    <div class="docs-deco-orb docs-deco-orb-b"></div>
  </div>
  <div class="docs-deco-band" aria-hidden="true"></div>

  <header class="topbar" aria-label="导航与系统状态栏">
    <div class="topbar-inner">
      <div class="topbar-left">
        <div class="brand">
          <div class="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <rect x="3" y="3" width="7" height="7" rx="1.5"></rect>
              <rect x="14" y="3" width="7" height="7" rx="1.5"></rect>
              <rect x="3" y="14" width="7" height="7" rx="1.5"></rect>
              <path d="M14 17.5h7"></path>
              <path d="M17.5 14v7"></path>
            </svg>
          </div>
          <div class="brand-copy">
            <div class="brand-title-row">
              <h1>AgentDock Bridge</h1>
              <span class="brand-tag">Console</span>
            </div>
            <p class="subtitle">受保护的本机沙盒控制台</p>
          </div>
        </div>

        <nav class="nav-tabs" id="nav-tabs" role="tablist" aria-label="功能分区导航" hidden>
          <button type="button" class="nav-tab active" id="tab-btn-overview" data-tab="overview" role="tab" aria-selected="true" aria-controls="view-overview">
            <span>状态与开关</span>
          </button>
          <button type="button" class="nav-tab" id="tab-btn-audit" data-tab="audit" role="tab" aria-selected="false" aria-controls="view-audit">
            <span>实时审计</span>
            <span class="nav-badge" id="nav-badge-audit" hidden>0</span>
          </button>
          <button type="button" class="nav-tab" id="tab-btn-tools" data-tab="tools" role="tab" aria-selected="false" aria-controls="view-tools">
            <span>工具说明</span>
            <span class="nav-badge" id="nav-badge-tools">10</span>
          </button>
          <button type="button" class="nav-tab" id="tab-btn-mcp" data-tab="mcp" role="tab" aria-selected="false" aria-controls="view-mcp">
            <span>第三方 MCP</span>
            <span class="nav-badge" id="nav-badge-mcp" hidden>0</span>
          </button>
        </nav>
      </div>

      <div class="status-strip">
        <div class="pill pill-neutral" id="auth-status-pill">
          <span class="dot dot-warn" id="auth-status-dot"></span>
          <span id="auth-status-label">正在检查访问凭据…</span>
        </div>
        <div class="pill pill-neutral" id="sse-pill" role="status" aria-live="polite" hidden>
          <span class="dot dot-warn" id="sse-dot"></span>
          <span id="sse-label">等待认证</span>
        </div>
        <div class="pill pill-neutral" id="systemd-pill" hidden>
          <span class="dot" id="systemd-dot"></span>
          <span id="systemd-label">自启动检查中</span>
        </div>
        <div class="pill pill-neutral" id="gateway-pill" hidden>
          <span class="dot" id="gateway-dot"></span>
          <span id="gateway-label">连接状态检查中</span>
        </div>
        <button type="button" class="action-btn action-icon" id="btn-theme" title="切换明暗主题" aria-label="切换明暗主题">
          <svg class="icon-sun" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <circle cx="12" cy="12" r="4"></circle>
            <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"></path>
          </svg>
          <svg class="icon-moon" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"></path>
          </svg>
          <span id="theme-label">深色</span>
        </button>
        <button type="button" class="action-btn action-quiet" id="btn-logout" hidden>锁定退出</button>
      </div>
    </div>
  </header>

  <div class="shell">
    <div class="alert-banner" id="error-banner" hidden role="alert"></div>

    <section class="auth-gate" id="auth-gate" aria-label="本机控制台安全认证">
      <article class="panel auth-panel">
        <div class="panel-head">
          <div>
            <h2 id="auth-title">本机控制台身份认证</h2>
            <p class="panel-note" id="auth-subtitle">必须完成本机身份验证，方能查看运行遥测或切换文件读写能力。</p>
          </div>
          <span class="mount-badge" id="auth-policy-badge">安全门禁已锁定</span>
        </div>

        <div class="auth-body" id="auth-body">
          <div class="auth-notice" id="auth-cli-guide" hidden>
            <p>WebUI 安全策略尚未在本机初始化，任何未授权网络请求均无法接管初始化权限。</p>
            <p>请在本机终端运行以下命令之一后继续：</p>
            <ul>
              <li>推荐初始化引导（支持自动绑定 PassKey 或强密码）：<code>~/.agentdock-bridge/webui-auth init</code></li>
              <li>无 PassKey 机器直接设置强密码：<code>~/.agentdock-bridge/webui-auth set-password</code></li>
            </ul>
          </div>

          <div class="auth-field" id="setup-ticket-group" hidden>
            <label for="input-setup-ticket">一次性本机初始化口令（由 <code>webui-auth init</code> 在本机终端输出）</label>
            <input type="text" id="input-setup-ticket" class="input-control mono" autocomplete="off" placeholder="AD-..." />
          </div>

          <div class="auth-section" id="passkey-section" hidden>
            <p class="panel-note" id="passkey-explain">检测到当前环境支持 PassKey（WebAuthn 用户验证），系统强制使用 PassKey 保护本机权限控制。</p>
            <div class="auth-field" id="passkey-label-group" hidden>
              <label for="input-passkey-label">PassKey 设备名称</label>
              <input type="text" id="input-passkey-label" class="input-control" maxlength="48" placeholder="例如：本机浏览器 / YubiKey" />
            </div>
            <div class="auth-actions">
              <button type="button" class="action-btn action-primary" id="btn-passkey-login" hidden>使用 PassKey 验证解锁</button>
              <button type="button" class="action-btn action-primary" id="btn-passkey-enroll" hidden>绑定并强制启用 PassKey</button>
            </div>
          </div>

          <form class="auth-section" id="password-form" hidden>
            <div class="auth-field">
              <label for="input-password" id="label-input-password">强密码</label>
              <input type="password" id="input-password" class="input-control" autocomplete="current-password" />
            </div>
            <div class="auth-field" id="password-confirm-group" hidden>
              <label for="input-password-confirm">确认强密码（至少 14 位，须同时含大写、小写、数字与特殊符号）</label>
              <input type="password" id="input-password-confirm" class="input-control" autocomplete="new-password" />
            </div>
            <div class="auth-actions">
              <button type="submit" class="action-btn action-primary" id="btn-password-submit">验证解锁</button>
              <button type="button" class="action-btn" id="btn-setup-hardware-passkey" hidden>改用外接安全密钥注册 PassKey</button>
            </div>
          </form>

          <div class="auth-actions" id="auth-refresh-row">
            <button type="button" class="action-btn" id="btn-auth-recheck">重新检测认证状态</button>
          </div>
        </div>
      </article>
    </section>

    <main class="dashboard" id="workbench" hidden>
      <!-- Page 1: 状态与开关 -->
      <section class="tab-view" id="view-overview" role="tabpanel" aria-labelledby="tab-btn-overview">
        <div class="kpi-strip" aria-label="实时运行摘要">
          <button type="button" class="kpi-card kpi-interactive" id="kpi-card-tools" title="前往查看工具说明">
            <div class="kpi-label">已开放 MCP 工具</div>
            <div class="kpi-value mono" id="kpi-tools-ratio">—</div>
            <div class="kpi-sub" id="kpi-tools-sub">正在同步能力策略…</div>
          </button>
          <article class="kpi-card">
            <div class="kpi-label">沙盒挂载姿态</div>
            <div class="kpi-value mono" id="kpi-mount-mode">—</div>
            <div class="kpi-sub" id="kpi-mount-sub">等待容器与网络信息…</div>
          </article>
          <button type="button" class="kpi-card kpi-interactive" id="kpi-card-audit" title="前往查看审计日志">
            <div class="kpi-label">近期审计调用窗口</div>
            <div class="kpi-value mono" id="kpi-audit-total">—</div>
            <div class="kpi-sub" id="kpi-audit-sub">最近 200 条受保护记录</div>
          </button>
          <button type="button" class="kpi-card kpi-interactive" id="kpi-card-queue" title="前往实时审计页查看并批准">
            <div class="kpi-label">待批准与活跃沙盒</div>
            <div class="kpi-value mono" id="kpi-live-queue">—</div>
            <div class="kpi-sub" id="kpi-live-sub">可在「实时审计」页实时批准或终端 approve</div>
          </button>
        </div>

        <div class="overview-grid">
          <article class="panel panel-breakers" id="panel-capabilities" data-posture="full">
            <div class="panel-head">
              <div>
                <h2>文件与执行能力开关</h2>
                <p class="panel-note">修改立即写入工作区外私有策略文件，对后续请求实时生效，无需重启连接器。</p>
              </div>
              <span class="mount-badge" id="mount-mode-badge">挂载模式检测中</span>
            </div>

            <div class="preset-bar" role="group" aria-label="快速切换工作模式">
              <button type="button" class="preset-btn" id="preset-full" data-preset="full">完整读写</button>
              <button type="button" class="preset-btn" id="preset-readonly" data-preset="readonly">仅只读</button>
              <button type="button" class="preset-btn" id="preset-locked" data-preset="locked">禁用文件读写</button>
            </div>

            <div class="breaker-list">
              <div class="breaker-row">
                <div class="breaker-meta">
                  <div class="breaker-title">读取文件能力</div>
                  <div class="breaker-desc">控制 <code>read_file</code>、<code>list_directory</code>、<code>search_files</code>；关闭时同步阻塞容器执行以防间接读取。</div>
                </div>
                <button type="button" class="switch" id="toggle-read" role="switch" aria-checked="true" aria-label="切换读取文件能力">
                  <span class="switch-track"><span class="switch-thumb"></span></span>
                  <span class="switch-text" id="label-read">开启</span>
                </button>
              </div>

              <div class="breaker-row">
                <div class="breaker-meta">
                  <div class="breaker-title">写入文件能力</div>
                  <div class="breaker-desc">控制 <code>write_file</code>、<code>edit_file</code>、<code>delete_file</code>；关闭后容器内 <code>/workspace</code> 强制 <code>readonly</code>。</div>
                </div>
                <button type="button" class="switch" id="toggle-write" role="switch" aria-checked="true" aria-label="切换写入文件能力">
                  <span class="switch-track"><span class="switch-thumb"></span></span>
                  <span class="switch-text" id="label-write">开启</span>
                </button>
              </div>

              <div class="breaker-row">
                <div class="breaker-meta">
                  <div class="breaker-title">容器命令执行</div>
                  <div class="breaker-desc">控制 <code>exec_command</code>（运行中作业的 <code>command_status</code> / <code>stop_command</code> 始终保留）。</div>
                </div>
                <button type="button" class="switch" id="toggle-exec" role="switch" aria-checked="true" aria-label="切换容器命令执行能力">
                  <span class="switch-track"><span class="switch-thumb"></span></span>
                  <span class="switch-text" id="label-exec">开启</span>
                </button>
              </div>
            </div>

            <div class="quick-tools-wrap">
              <div class="quick-tools-head">
                <span>单工具独立开关（点击工具名查看详细契约，右侧开关可单独停用或启用单个工具）</span>
                <span class="mono-muted" id="policy-updated-at">默认策略</span>
              </div>
              <div class="quick-tool-chips" id="overview-tool-chips"></div>
            </div>
          </article>

          <article class="panel panel-host">
            <div class="panel-head">
              <div>
                <h2>宿主运行状态与受保护锚点</h2>
                <p class="panel-note">仅展示进程标识、挂载锚点与验证边界，绝不读取文件内容或凭据。</p>
              </div>
              <button type="button" class="action-btn" id="btn-upgrade-passkey" hidden>绑定硬件 PassKey</button>
            </div>

            <dl class="facts-grid">
              <div class="fact-item fact-wide">
                <dt>宿主机挂载目录</dt>
                <dd class="mono" id="fact-workspace">—</dd>
              </div>
              <div class="fact-item fact-wide">
                <dt>网关地址与健康探针</dt>
                <dd class="mono" id="fact-origin">—</dd>
              </div>
              <div class="fact-item">
                <dt>守护进程 / 连接器</dt>
                <dd class="mono" id="fact-pids">—</dd>
              </div>
              <div class="fact-item">
                <dt>systemd 自启动</dt>
                <dd class="mono" id="fact-systemd">—</dd>
              </div>
              <div class="fact-item">
                <dt>固定容器镜像</dt>
                <dd class="mono" id="fact-image">—</dd>
              </div>
              <div class="fact-item">
                <dt>Node 工具链与凭据</dt>
                <dd class="mono" id="fact-security">—</dd>
              </div>
            </dl>

            <div class="breaker-row policy-config-row">
              <div class="breaker-meta">
                <div class="breaker-title">开机自启动（systemd --user）</div>
                <div class="breaker-desc" id="autostart-desc">检测用户级 systemd 开机自启动（agentdock-bridge / agentdock-webui）与 linger 状态…</div>
              </div>
              <button type="button" class="switch" id="toggle-autostart" role="switch" aria-checked="false" aria-label="切换开机自启动">
                <span class="switch-track"><span class="switch-thumb"></span></span>
                <span class="switch-text" id="label-autostart">—</span>
              </button>
            </div>

            <div class="breaker-row policy-config-row">
              <div class="breaker-meta">
                <div class="breaker-title">标签页隔离认证（关闭标签页即须重认证）</div>
                <div class="breaker-desc" id="session-policy-desc">当前为标签页临时会话：关闭或新开标签页必须重新通过 PassKey / 强密码解锁，防止持久化 Cookie 被复用。</div>
              </div>
              <button type="button" class="switch" id="toggle-tab-auth" role="switch" aria-checked="true" aria-label="切换标签页隔离认证策略">
                <span class="switch-track"><span class="switch-thumb"></span></span>
                <span class="switch-text" id="label-tab-auth">已启用</span>
              </button>
            </div>

            <div class="service-actions" role="group" aria-label="后台服务控制">
              <button type="button" class="action-btn action-primary" id="btn-service-start">启动后台</button>
              <button type="button" class="action-btn" id="btn-service-restart">重启后台</button>
              <button type="button" class="action-btn action-danger" id="btn-service-stop">停止后台</button>
              <button type="button" class="action-btn action-quiet" id="btn-refresh">立即刷新</button>
            </div>
          </article>
        </div>

        <div class="overview-grid security-grid">
          <article class="panel" id="panel-passkeys">
            <div class="panel-head">
              <div>
                <h2>PassKey 密钥管理</h2>
                <p class="panel-note">支持绑定多枚平台指纹或外接安全密钥；为防弱降级，最后 1 枚活跃 PassKey 禁止直接删除。</p>
              </div>
              <span class="counter-badge" id="passkeys-count">0</span>
            </div>

            <div class="auth-notice" id="passkey-hw-note" hidden></div>

            <ul class="compact-list passkey-list" id="passkeys-list"></ul>

            <div class="passkey-enroll-bar" id="passkey-enroll-bar">
              <input class="input-control" id="input-new-passkey-label" type="text" maxlength="48" placeholder="新密钥备注（如：备用 YubiKey / 笔记本指纹）" aria-label="新 PassKey 备注名称">
              <button type="button" class="action-btn action-primary" id="btn-add-passkey">+ 添加 PassKey</button>
            </div>
          </article>

          <article class="panel" id="panel-password-security">
            <div class="panel-head">
              <div>
                <h2>强密码重置与认证切换</h2>
                <p class="panel-note">修改强密码（≥ 14 位）或在非硬件强制 PassKey 主机切换认证方式；操作后立即使旧会话失效。</p>
              </div>
              <span class="meta-pill" id="security-mode-pill">检测中</span>
            </div>

            <div class="inline-feedback" id="security-feedback" role="status" aria-live="polite" hidden></div>

            <div class="auth-notice" id="password-locked-notice" hidden>
              当前主机或浏览器环境已支持并强制要求 PassKey（<span id="password-locked-reason">检测到平台或浏览器 PassKey 支持</span>），为防止凭据降级风险，已禁止回退使用纯密码认证。
            </div>

            <form class="auth-section" id="security-password-form" hidden>
              <div class="auth-field" id="security-current-password-group">
                <label for="input-current-password">当前强密码</label>
                <input class="input-control" id="input-current-password" type="password" autocomplete="current-password" placeholder="输入当前强密码确认身份">
              </div>
              <div class="auth-field">
                <label for="input-reset-password" id="label-reset-password">新强密码（≥ 14 位，须同时含大写、小写、数字与特殊符号）</label>
                <input class="input-control" id="input-reset-password" type="password" autocomplete="new-password" minlength="14" required placeholder="至少 14 个字符，含大小写字母、数字与特殊符号">
              </div>
              <div class="auth-field">
                <label for="input-reset-password-confirm">确认新强密码</label>
                <input class="input-control" id="input-reset-password-confirm" type="password" autocomplete="new-password" minlength="14" required placeholder="再次输入新密码">
              </div>
              <div class="auth-actions">
                <button type="submit" class="action-btn action-primary" id="btn-reset-password">重置强密码</button>
              </div>
            </form>
          </article>
        </div>
      </section>

      <!-- Page 2: 实时审计 -->
      <section class="tab-view" id="view-audit" role="tabpanel" aria-labelledby="tab-btn-audit" hidden>
        <div class="telemetry-row">
          <article class="panel panel-compact">
            <div class="panel-head">
              <div>
                <h2>本机待人工批准</h2>
                <p class="panel-note">选择请求核对来源、权限和完整参数后，可批准执行一次。也可使用终端 <code>~/.agentdock-bridge/approve</code>。</p>
              </div>
              <span class="counter-badge" id="approvals-count">0</span>
            </div>
            <ul class="compact-list" id="approvals-list"></ul>
          </article>

          <article class="panel panel-compact">
            <div class="panel-head">
              <div>
                <h2>活跃 Docker 沙盒容器</h2>
                <p class="panel-note">仅统计带本机安装标签的一次性只读镜像容器。</p>
              </div>
              <span class="counter-badge" id="containers-count">0</span>
            </div>
            <ul class="compact-list" id="containers-list"></ul>
          </article>
        </div>

        <article class="panel panel-stream">
          <div class="panel-head panel-head-wrap">
            <div>
              <h2>实时运行与工具审计流水</h2>
              <p class="panel-note">展开记录可查看工具、结果、耗时和容器执行策略。</p>
            </div>
            <div class="stream-controls">
              <span class="meta-pill" id="events-summary-pill">0 条记录</span>
              <div class="filter-bar" role="group" aria-label="日志过滤">
                <button type="button" class="filter-btn active" data-filter="all" aria-pressed="true">全部</button>
                <button type="button" class="filter-btn" data-filter="audit" aria-pressed="false">工具审计</button>
                <button type="button" class="filter-btn" data-filter="connector" aria-pressed="false">连接周期</button>
              </div>
            </div>
          </div>

          <div class="stream-wrap">
            <table class="stream-table">
              <thead>
                <tr>
                  <th class="col-chevron" aria-label="展开状态"></th>
                  <th>时间</th>
                  <th>来源</th>
                  <th>工具 / 事件</th>
                  <th>参数对象与结果摘要</th>
                </tr>
              </thead>
              <tbody id="events-tbody"></tbody>
            </table>
            <div class="empty-state" id="events-empty" hidden>暂无工具审计或连接事件记录。</div>
          </div>
        </article>
      </section>

      <!-- Page 3: 工具说明（Docs-Site ApiExplorer 双栏式专业目录 + 详情工作台） -->
      <section class="tab-view" id="view-tools" role="tabpanel" aria-labelledby="tab-btn-tools" hidden>
        <div class="tools-explorer">
          <aside class="tools-catalog" aria-label="MCP 工具分类目录">
            <div class="catalog-search-box">
              <input type="search" id="tool-search" class="search-control" placeholder="搜索工具名称、说明或参数名…" aria-label="搜索 MCP 工具" />
              <div class="chip-bar" role="group" aria-label="按工具分类筛选">
                <button type="button" class="tool-filter-btn active" data-tool-group="all" aria-pressed="true">全部</button>
                <button type="button" class="tool-filter-btn" data-tool-group="read" aria-pressed="false">读取</button>
                <button type="button" class="tool-filter-btn" data-tool-group="write" aria-pressed="false">写入</button>
                <button type="button" class="tool-filter-btn" data-tool-group="exec" aria-pressed="false">执行</button>
                <button type="button" class="tool-filter-btn" data-tool-group="context" aria-pressed="false">环境</button>
                <button type="button" class="tool-filter-btn" data-tool-group="mcp" aria-pressed="false">第三方 MCP</button>
              </div>
            </div>

            <div class="catalog-list" id="tool-grid"></div>
            <div class="empty-state" id="tools-empty" hidden>没有匹配当前筛选条件的 MCP 工具。</div>
          </aside>

          <div class="tools-detail-stage">
            <div class="detail-stage-bar">
              <div>
                <h2 class="stage-heading">MCP 工具参数契约与运行时说明</h2>
                <p class="panel-note">对照实时能力开关状态，完整呈现工具授权作用域、审批要求、安全守卫与近期调用统计。</p>
              </div>
              <div class="tool-bulk-actions">
                <button type="button" class="action-btn action-sm" id="btn-tools-expand">全部展开</button>
                <button type="button" class="action-btn action-sm" id="btn-tools-collapse">全部收起</button>
              </div>
            </div>

            <div class="tool-detail-container" id="tool-detail-pane"></div>
          </div>
        </div>
      </section>

      <!-- Page 4: 第三方 MCP 接入配置 -->
      <section class="tab-view" id="view-mcp" role="tabpanel" aria-labelledby="tab-btn-mcp" hidden>
        <article class="panel mcp-banner">
          <div class="panel-head panel-head-wrap">
            <div>
              <h2>第三方 MCP 服务接入与工具聚合</h2>
              <p class="panel-note">支持接入本机 <code>stdio</code> 子进程或远程 <code>Streamable HTTP</code> MCP 服务；工具自动以 <code>mcp__&lt;serverId&gt;__&lt;tool&gt;</code> 聚合进 AgentDock。<strong>第三方 MCP 运行在 Docker 容器沙盒之外</strong>，每次调用仍须经本机精确审批，配置独立保存于工作区外 <code>0600</code> 私有文件 <code>mcp-servers.json</code>。</p>
            </div>
            <div class="mcp-banner-stats">
              <span class="meta-pill is-brand" id="mcp-summary-servers">0 个服务</span>
              <span class="meta-pill is-on" id="mcp-summary-tools">0 个可用工具</span>
            </div>
          </div>
        </article>

        <div class="alert-banner" id="mcp-registry-error" hidden role="alert"></div>

        <div class="mcp-grid">
          <article class="panel" id="panel-mcp-list">
            <div class="panel-head">
              <div>
                <h2>已配置的 MCP 服务</h2>
                <p class="panel-note">修改启停、单工具开关或同步工具后实时生效，无需重启后台连接器。</p>
              </div>
              <div class="tool-bulk-actions">
                <span class="counter-badge" id="mcp-servers-count">0</span>
                <button type="button" class="action-btn action-sm action-primary" id="btn-mcp-new">+ 新增服务</button>
              </div>
            </div>

            <div class="mcp-servers-stack" id="mcp-servers-list"></div>
          </article>

          <article class="panel" id="panel-mcp-editor">
            <div class="panel-head panel-head-wrap">
              <div>
                <h2 id="mcp-editor-title">新增第三方 MCP 服务</h2>
                <p class="panel-note" id="mcp-editor-subtitle">环境变量与自定义请求头采用只写保护：保存后仅展示键名，绝不在界面或日志中回显密钥值。</p>
              </div>
              <div class="mcp-editor-tabs" role="tablist" aria-label="配置录入方式">
                <button type="button" class="mcp-editor-tab active" id="mcp-mode-form" role="tab" aria-selected="true" aria-controls="mcp-server-form">表单配置</button>
                <button type="button" class="mcp-editor-tab" id="mcp-mode-json" role="tab" aria-selected="false" aria-controls="mcp-import-form">JSON 导入</button>
              </div>
            </div>

            <div class="inline-feedback" id="mcp-feedback" role="status" aria-live="polite" hidden></div>

            <form class="auth-section" id="mcp-server-form" role="tabpanel" aria-labelledby="mcp-mode-form">
              <div class="form-grid-2">
                <div class="auth-field">
                  <label for="input-mcp-id">服务标识 ID</label>
                  <input class="input-control mono" id="input-mcp-id" type="text" maxlength="32" required placeholder="小写字母/数字开头结尾（可含 _/-，不可含 __），如 github" autocomplete="off" />
                </div>
                <div class="auth-field">
                  <label for="input-mcp-name">显示名称</label>
                  <input class="input-control" id="input-mcp-name" type="text" maxlength="80" required placeholder="例如：GitHub MCP" autocomplete="off" />
                </div>
              </div>

              <div class="auth-field">
                <label for="input-mcp-desc">备注说明（可选）</label>
                <input class="input-control" id="input-mcp-desc" type="text" maxlength="240" placeholder="简述该 MCP 提供的能力范围或使用注意" autocomplete="off" />
              </div>

              <div class="form-grid-2">
                <div class="auth-field">
                  <label for="select-mcp-transport">传输协议</label>
                  <select class="select-control" id="select-mcp-transport">
                    <option value="stdio">stdio（本机子进程命令）</option>
                    <option value="http">http（远程 / 回环 Streamable HTTP）</option>
                  </select>
                </div>
                <div class="auth-field">
                  <label for="input-mcp-timeout">调用超时 (ms)</label>
                  <input class="input-control mono" id="input-mcp-timeout" type="number" min="3000" max="100000" step="1" value="30000" />
                </div>
              </div>

              <div class="mcp-transport-group" id="mcp-stdio-fields">
                <div class="auth-field">
                  <label for="input-mcp-command">启动命令（直接 exec，不经 shell 解释）</label>
                  <input class="input-control mono" id="input-mcp-command" type="text" maxlength="512" placeholder="例如：npx、uvx、node、python3 或绝对路径" autocomplete="off" />
                </div>
                <div class="auth-field">
                  <label for="input-mcp-args">命令参数（每行一个参数，也支持直接粘贴 JSON 字符串数组）</label>
                  <textarea class="textarea-control mono" id="input-mcp-args" rows="3" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" placeholder="-y&#10;@modelcontextprotocol/server-memory"></textarea>
                </div>
                <div class="auth-field">
                  <label for="input-mcp-cwd">工作目录 cwd（可选，留空将使用隔离空临时目录；不可指向受保护状态目录或符号链接）</label>
                  <input class="input-control mono" id="input-mcp-cwd" type="text" maxlength="1024" placeholder="留空则使用独立 0700 空目录" autocomplete="off" />
                </div>
                <div class="auth-field">
                  <label for="input-mcp-env">环境变量（每行一条 KEY=VALUE；编辑时留空将保留已存密钥）</label>
                  <div class="mcp-secret-chips" id="mcp-existing-env-keys" hidden></div>
                  <textarea class="textarea-control mono" id="input-mcp-env" rows="3" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" placeholder="GITHUB_PERSONAL_ACCESS_TOKEN=ghp_..."></textarea>
                </div>
              </div>

              <div class="mcp-transport-group" id="mcp-http-fields" hidden>
                <div class="auth-field">
                  <label for="input-mcp-url">Streamable HTTP 端点 URL（必须 https://，或本机回环 http://localhost）</label>
                  <input class="input-control mono" id="input-mcp-url" type="url" maxlength="2048" placeholder="https://mcp.example.com/mcp" autocomplete="off" />
                </div>
                <div class="auth-field">
                  <label for="input-mcp-headers">自定义 HTTP 请求头（每行一条 Header-Name: value；编辑时留空将保留已存请求头）</label>
                  <div class="mcp-secret-chips" id="mcp-existing-header-keys" hidden></div>
                  <textarea class="textarea-control mono" id="input-mcp-headers" rows="3" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" placeholder="Authorization: Bearer ..."></textarea>
                </div>
              </div>

              <label class="checkbox-row" id="mcp-replace-secrets-row" hidden>
                <input type="checkbox" id="input-mcp-replace-secrets" />
                <span>清空并替换既有密钥（修改启动命令、参数、工作目录或 HTTP 源地址时须勾选，避免旧凭据泄露至新目标）</span>
              </label>

              <label class="checkbox-row">
                <input type="checkbox" id="input-mcp-enabled" checked />
                <span>保存后立即启用该第三方 MCP 服务（对外通过 <code>tools/list</code> 暴露）</span>
              </label>

              <div class="auth-actions">
                <button type="submit" class="action-btn action-primary" id="btn-mcp-save-probe">保存并测试连接</button>
                <button type="button" class="action-btn" id="btn-mcp-save-only">仅保存配置</button>
                <button type="button" class="action-btn action-quiet" id="btn-mcp-cancel">重置表单</button>
              </div>
            </form>

            <form class="auth-section" id="mcp-import-form" role="tabpanel" aria-labelledby="mcp-mode-json" hidden>
              <div class="auth-field">
                <label for="input-mcp-json">标准 MCP JSON 配置（兼容 Claude Desktop / Cursor <code>mcpServers</code> 与 VS Code <code>servers</code>）</label>
                <textarea class="textarea-control mono" id="input-mcp-json" rows="10" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" placeholder='{&#10;  "mcpServers": {&#10;    "memory": {&#10;      "command": "npx",&#10;      "args": ["-y", "@modelcontextprotocol/server-memory"]&#10;    },&#10;    "docs": {&#10;      "url": "https://mcp.example.com/mcp",&#10;      "headers": {&#10;        "Authorization": "Bearer ..."&#10;      }&#10;    }&#10;  }&#10;}'></textarea>
              </div>
              <div class="auth-actions">
                <button type="submit" class="action-btn action-primary" id="btn-mcp-import-probe">导入并测试连接</button>
                <button type="button" class="action-btn" id="btn-mcp-import-only">仅导入配置</button>
              </div>
            </form>
          </article>
        </div>
      </section>
    </main>
  </div>
</body>
</html>
`;
}

export const WEBUI_CSS = `*,
*::before,
*::after {
  box-sizing: border-box;
}

[hidden] {
  display: none !important;
}

:root {
  --adv-primary: #0c5cab;
  --adv-secondary: #0a4a8a;
  --adv-bright: #589fe4;
  --adv-cyan: #38bdf8;
  --adv-canvas: #fafafa;
  --adv-surface: #ffffff;
  --adv-elevated: #f4f4f5;
  --adv-text: #09090b;
  --adv-text-2: #3f3f46;
  --adv-muted: #52525b;
  --adv-line: rgba(9, 9, 11, 0.1);
  --adv-line-strong: rgba(9, 9, 11, 0.18);
  --adv-grid: rgba(12, 92, 171, 0.055);
  --adv-tint-primary: rgba(12, 92, 171, 0.1);
  --adv-tint-primary-border: rgba(12, 92, 171, 0.24);
  --adv-tint-ok: rgba(16, 185, 129, 0.12);
  --adv-tint-warn: rgba(245, 158, 11, 0.14);
  --adv-tint-err: rgba(239, 68, 68, 0.1);
  --adv-ok: #047857;
  --adv-warn: #9a3412;
  --adv-err: #b91c1c;
  --adv-ctx: #4f46e5;
  --adv-code-bg: #f6f8fa;
  --adv-code-text: #24292e;
  --adv-nav-bg: rgba(250, 250, 250, 0.84);
  --adv-shadow-sm: 0 1px 2px rgba(9, 9, 11, 0.06), 0 4px 12px -6px rgba(9, 9, 11, 0.16);
  --adv-shadow: 0 2px 4px rgba(9, 9, 11, 0.06), 0 12px 28px -14px rgba(9, 9, 11, 0.22);
  --adv-inner-light: inset 0 1px 0 rgba(255, 255, 255, 0.72);
  --font-sans: "IBM Plex Sans", "PingFang SC", "Microsoft YaHei UI", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --font-mono: "JetBrains Mono", "Fira Code", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  --r-sm: 6px;
  --r-md: 10px;
  --r-lg: 12px;
  --ease: cubic-bezier(0.25, 0.46, 0.45, 0.94);
  color-scheme: light;
}

:root.dark {
  --adv-primary: #589fe4;
  --adv-secondary: #0a4a8a;
  --adv-bright: #7fbcf0;
  --adv-canvas: #09090b;
  --adv-surface: #111114;
  --adv-elevated: #18181b;
  --adv-text: #fafafa;
  --adv-text-2: #d4d4d8;
  --adv-muted: #a1a1aa;
  --adv-line: rgba(250, 250, 250, 0.11);
  --adv-line-strong: rgba(250, 250, 250, 0.2);
  --adv-grid: rgba(88, 159, 228, 0.05);
  --adv-tint-primary: rgba(88, 159, 228, 0.14);
  --adv-tint-primary-border: rgba(88, 159, 228, 0.3);
  --adv-ok: #10b981;
  --adv-warn: #f59e0b;
  --adv-err: #f87171;
  --adv-ctx: #818cf8;
  --adv-code-bg: #0d1117;
  --adv-code-text: #e6edf3;
  --adv-nav-bg: rgba(9, 9, 11, 0.78);
  --adv-shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.45), 0 4px 12px -6px rgba(0, 0, 0, 0.55);
  --adv-shadow: 0 2px 4px rgba(0, 0, 0, 0.48), 0 14px 30px -16px rgba(0, 0, 0, 0.72);
  --adv-inner-light: inset 0 1px 0 rgba(255, 255, 255, 0.06);
  color-scheme: dark;
}

html,
body {
  margin: 0;
  padding: 0;
  min-height: 100%;
  overflow-x: clip;
}

body {
  font-family: var(--font-sans);
  font-size: 14px;
  line-height: 1.6;
  color: var(--adv-text);
  background-color: var(--adv-canvas);
  background-image:
    radial-gradient(560px 360px at 86% -6%, rgba(12, 92, 171, 0.1), transparent 70%),
    radial-gradient(640px 460px at -8% 26%, rgba(10, 74, 138, 0.08), transparent 72%),
    linear-gradient(transparent 31px, var(--adv-grid) 31px, var(--adv-grid) 32px, transparent 32px),
    linear-gradient(90deg, transparent 31px, var(--adv-grid) 31px, var(--adv-grid) 32px, transparent 32px);
  background-size: auto, auto, 32px 32px, 32px 32px;
  background-attachment: fixed;
  -webkit-font-smoothing: antialiased;
}

:root.dark body {
  background-image:
    radial-gradient(560px 360px at 86% -6%, rgba(88, 159, 228, 0.11), transparent 70%),
    radial-gradient(640px 460px at -8% 26%, rgba(56, 189, 248, 0.07), transparent 72%),
    linear-gradient(transparent 31px, var(--adv-grid) 31px, var(--adv-grid) 32px, transparent 32px),
    linear-gradient(90deg, transparent 31px, var(--adv-grid) 31px, var(--adv-grid) 32px, transparent 32px);
}

.docs-deco {
  position: fixed;
  inset: 0;
  z-index: 0;
  pointer-events: none;
  overflow: hidden;
}

.docs-deco-band {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  height: 2px;
  z-index: 1001;
  pointer-events: none;
  background: linear-gradient(90deg, var(--adv-primary), var(--adv-cyan) 55%, var(--adv-secondary));
  opacity: 0.96;
}

.docs-deco-orb {
  position: fixed;
  border-radius: 50%;
  filter: blur(60px);
  opacity: 0.65;
}

.docs-deco-orb-a {
  width: 360px;
  height: 360px;
  top: -120px;
  right: -60px;
  background: radial-gradient(circle, rgba(12, 92, 171, 0.18), transparent 68%);
}

.docs-deco-orb-b {
  width: 440px;
  height: 440px;
  top: 28%;
  left: -170px;
  background: radial-gradient(circle, rgba(56, 189, 248, 0.12), transparent 68%);
}

:root.dark .docs-deco-orb-a {
  background: radial-gradient(circle, rgba(88, 159, 228, 0.16), transparent 68%);
}

:root.dark .docs-deco-orb-b {
  background: radial-gradient(circle, rgba(56, 189, 248, 0.1), transparent 68%);
}

.mono {
  font-family: var(--font-mono);
}

.mono-muted {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--adv-muted);
}

code {
  font-family: var(--font-mono);
  font-size: 0.88em;
  background: var(--adv-tint-primary);
  color: var(--adv-primary);
  border: 1px solid var(--adv-tint-primary-border);
  border-radius: 4px;
  padding: 1px 5px;
}

.topbar {
  position: sticky;
  top: 2px;
  z-index: 40;
  background: var(--adv-nav-bg);
  backdrop-filter: blur(14px) saturate(1.2);
  -webkit-backdrop-filter: blur(14px) saturate(1.2);
  border-bottom: 1px solid var(--adv-line);
}

.topbar-inner {
  max-width: 1460px;
  margin: 0 auto;
  padding: 10px 24px;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.topbar-left {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 16px;
}

.brand {
  display: flex;
  align-items: center;
  gap: 11px;
}

.brand-mark {
  width: 36px;
  height: 36px;
  border-radius: var(--r-md);
  background: linear-gradient(135deg, #0c5cab, #0a4a8a);
  color: #ffffff;
  display: grid;
  place-items: center;
  box-shadow: var(--adv-shadow-sm), var(--adv-inner-light);
  flex-shrink: 0;
}

.brand-title-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.brand h1 {
  margin: 0;
  font-size: 16px;
  font-weight: 700;
  letter-spacing: -0.015em;
  color: var(--adv-text);
  line-height: 1.25;
}

.brand-tag {
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 600;
  padding: 1px 7px;
  border-radius: 999px;
  background: var(--adv-tint-primary);
  color: var(--adv-primary);
  border: 1px solid var(--adv-tint-primary-border);
}

.subtitle {
  margin: 1px 0 0;
  font-size: 12px;
  color: var(--adv-muted);
}

.nav-tabs {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 4px;
}

.nav-tab {
  position: relative;
  appearance: none;
  border: 0;
  background: transparent;
  color: var(--adv-text-2);
  font-family: var(--font-sans);
  font-size: 13px;
  font-weight: 600;
  padding: 7px 10px;
  border-radius: var(--r-sm);
  display: inline-flex;
  align-items: center;
  gap: 5px;
  cursor: pointer;
  transition: color 0.18s var(--ease), background 0.18s var(--ease);
}

.nav-tab:hover {
  color: var(--adv-primary);
  background: var(--adv-tint-primary);
}

.nav-tab.active {
  color: var(--adv-primary);
}

.nav-tab::after {
  content: "";
  position: absolute;
  left: 10px;
  right: 10px;
  bottom: 1px;
  height: 2px;
  border-radius: 2px;
  background: linear-gradient(90deg, var(--adv-primary), var(--adv-cyan));
  transform: scaleX(0);
  transform-origin: 0 50%;
  transition: transform 0.24s var(--ease);
}

.nav-tab.active::after {
  transform: scaleX(1);
}

.nav-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 20px;
  padding: 1px 6px;
  border-radius: 999px;
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 700;
  background: var(--adv-elevated);
  border: 1px solid var(--adv-line);
  color: var(--adv-text-2);
}

.nav-badge.has-alert {
  background: var(--adv-tint-warn);
  border-color: rgba(245, 158, 11, 0.35);
  color: var(--adv-warn);
}

.status-strip {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}

.pill {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  padding: 5px 10px;
  border-radius: 999px;
  font-family: var(--font-mono);
  font-size: 11.5px;
  font-weight: 500;
  background: var(--adv-surface);
  border: 1px solid var(--adv-line);
  color: var(--adv-text-2);
  box-shadow: var(--adv-shadow-sm);
}

.pill-online {
  border-color: rgba(16, 185, 129, 0.35);
  background: var(--adv-tint-ok);
  color: var(--adv-ok);
}

.pill-warn {
  border-color: rgba(245, 158, 11, 0.38);
  background: var(--adv-tint-warn);
  color: var(--adv-warn);
}

.pill-locked {
  border-color: rgba(239, 68, 68, 0.35);
  background: var(--adv-tint-err);
  color: var(--adv-err);
}

.pill-neutral {
  background: var(--adv-elevated);
}

.dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--adv-muted);
  flex-shrink: 0;
}

.dot-online {
  background: var(--adv-ok);
}

.dot-warn {
  background: var(--adv-warn);
}

.dot-locked {
  background: var(--adv-err);
}

.shell {
  position: relative;
  z-index: 1;
  max-width: 1460px;
  margin: 0 auto;
  padding: 20px 24px 40px;
}

.alert-banner {
  margin-bottom: 16px;
  padding: 12px 16px;
  border-radius: var(--r-md);
  background: var(--adv-tint-err);
  border: 1px solid rgba(239, 68, 68, 0.35);
  color: var(--adv-err);
  font-weight: 600;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.auth-gate {
  display: flex;
  justify-content: center;
  padding: 26px 0 42px;
}

.auth-panel {
  width: min(650px, 100%);
}

.auth-body {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.auth-notice {
  padding: 12px 14px;
  border-radius: var(--r-sm);
  background: var(--adv-elevated);
  border: 1px solid var(--adv-line);
  border-left: 3px solid var(--adv-primary);
  font-size: 13px;
  color: var(--adv-text-2);
}

.auth-notice p {
  margin: 0 0 8px;
}

.auth-notice ul {
  margin: 0;
  padding-left: 18px;
}

.auth-notice li + li {
  margin-top: 4px;
}

.auth-section {
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding: 14px;
  border-radius: var(--r-md);
  background: var(--adv-elevated);
  border: 1px solid var(--adv-line);
}

.auth-field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.auth-field label {
  font-size: 13px;
  font-weight: 600;
  color: var(--adv-text);
}

.input-control,
.search-control {
  width: 100%;
  height: 36px;
  padding: 0 12px;
  border: 1px solid var(--adv-line-strong);
  border-radius: var(--r-sm);
  font-size: 13px;
  background: var(--adv-surface);
  color: var(--adv-text);
  transition: border-color 0.18s var(--ease), box-shadow 0.18s var(--ease);
}

.input-control:focus,
.search-control:focus {
  outline: 2px solid transparent;
  border-color: var(--adv-primary);
  box-shadow: 0 0 0 3px var(--adv-tint-primary);
}

.auth-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.tab-view {
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.kpi-strip {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 14px;
}

.kpi-card {
  background: var(--adv-surface);
  border: 1px solid var(--adv-line);
  border-radius: var(--r-lg);
  padding: 14px 16px;
  box-shadow: var(--adv-shadow-sm), var(--adv-inner-light);
  display: flex;
  flex-direction: column;
  gap: 4px;
  text-align: left;
  font-family: inherit;
  color: inherit;
}

.kpi-interactive {
  cursor: pointer;
  transition: transform 0.16s var(--ease), border-color 0.16s var(--ease), box-shadow 0.16s var(--ease);
}

.kpi-interactive:hover {
  transform: translateY(-2px);
  border-color: var(--adv-primary);
  box-shadow: var(--adv-shadow), var(--adv-inner-light);
}

.kpi-label {
  font-size: 12px;
  font-weight: 600;
  color: var(--adv-muted);
}

.kpi-value {
  font-size: 20px;
  font-weight: 700;
  color: var(--adv-text);
  letter-spacing: -0.02em;
}

.kpi-sub {
  font-size: 12px;
  color: var(--adv-text-2);
}

.overview-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 18px;
  align-items: start;
}

.panel {
  background: var(--adv-surface);
  border: 1px solid var(--adv-line);
  border-radius: var(--r-lg);
  padding: 18px 20px;
  box-shadow: var(--adv-shadow-sm), var(--adv-inner-light);
}

.panel-breakers {
  border-top: 3px solid var(--adv-ok);
}

.panel-breakers[data-posture="readonly"] {
  border-top-color: var(--adv-warn);
}

.panel-breakers[data-posture="locked"] {
  border-top-color: var(--adv-err);
}

.panel-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 14px;
}

.panel-head-wrap {
  flex-wrap: wrap;
}

.panel h2,
.stage-heading {
  margin: 0;
  font-size: 15.5px;
  font-weight: 700;
  letter-spacing: -0.01em;
  color: var(--adv-text);
}

.panel h2::after,
.stage-heading::after {
  content: "";
  display: block;
  width: 36px;
  height: 2.5px;
  margin-top: 6px;
  border-radius: 2px;
  background: linear-gradient(90deg, var(--adv-primary), var(--adv-cyan));
}

.panel-note {
  margin: 6px 0 0;
  font-size: 12.5px;
  color: var(--adv-muted);
  line-height: 1.5;
}

.mount-badge {
  display: inline-flex;
  align-items: center;
  flex-shrink: 0;
  padding: 4px 10px;
  border-radius: 999px;
  font-family: var(--font-mono);
  font-size: 11.5px;
  font-weight: 600;
  border: 1px solid var(--adv-line);
  background: var(--adv-elevated);
  color: var(--adv-text-2);
}

.mount-badge.is-readwrite {
  background: var(--adv-tint-ok);
  border-color: rgba(16, 185, 129, 0.35);
  color: var(--adv-ok);
}

.mount-badge.is-readonly {
  background: var(--adv-tint-warn);
  border-color: rgba(245, 158, 11, 0.38);
  color: var(--adv-warn);
}

.mount-badge.is-locked {
  background: var(--adv-tint-err);
  border-color: rgba(239, 68, 68, 0.35);
  color: var(--adv-err);
}

.preset-bar {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
  margin-bottom: 14px;
}

.preset-btn,
.filter-btn,
.tool-filter-btn,
.action-btn {
  appearance: none;
  border: 1px solid var(--adv-line-strong);
  background: var(--adv-surface);
  color: var(--adv-text);
  font-family: var(--font-sans);
  font-size: 12.5px;
  font-weight: 600;
  border-radius: var(--r-sm);
  padding: 7px 11px;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  transition: background 0.16s var(--ease), border-color 0.16s var(--ease), color 0.16s var(--ease), transform 0.14s var(--ease);
}

.preset-btn:hover:not(:disabled),
.filter-btn:hover:not(:disabled),
.tool-filter-btn:hover:not(:disabled),
.action-btn:hover:not(:disabled) {
  background: var(--adv-elevated);
  border-color: var(--adv-primary);
}

.preset-btn.active,
.filter-btn.active,
.tool-filter-btn.active {
  background: linear-gradient(135deg, #0c5cab, #0a4a8a);
  border-color: transparent;
  color: #ffffff;
}

.action-primary {
  background: linear-gradient(135deg, #0c5cab, #0a4a8a);
  border-color: transparent;
  color: #ffffff;
}

.action-primary:hover:not(:disabled) {
  background: linear-gradient(135deg, #0a4a8a, #083d73);
  border-color: transparent;
  color: #ffffff;
}

.action-danger {
  color: var(--adv-err);
  border-color: rgba(239, 68, 68, 0.35);
  background: var(--adv-tint-err);
}

.action-danger:hover:not(:disabled) {
  background: rgba(239, 68, 68, 0.18);
  border-color: var(--adv-err);
}

.action-quiet {
  margin-left: auto;
}

.action-sm {
  padding: 5px 9px;
  font-size: 12px;
}

.action-icon {
  padding: 5px 10px;
  font-size: 12px;
}

.icon-moon {
  display: none;
}

:root.dark .icon-sun {
  display: none;
}

:root.dark .icon-moon {
  display: inline-block;
}

button:disabled {
  opacity: 0.48;
  cursor: not-allowed;
}

.breaker-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.breaker-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  padding: 11px 13px;
  background: var(--adv-elevated);
  border: 1px solid var(--adv-line);
  border-radius: var(--r-md);
}

.breaker-meta {
  min-width: 0;
}

.breaker-title {
  font-size: 13.5px;
  font-weight: 700;
  color: var(--adv-text);
}

.breaker-desc {
  margin-top: 2px;
  font-size: 12px;
  color: var(--adv-text-2);
  line-height: 1.45;
}

.switch {
  flex-shrink: 0;
  display: inline-flex;
  align-items: center;
  gap: 7px;
  border: 1px solid var(--adv-line);
  background: var(--adv-surface);
  border-radius: 999px;
  padding: 4px 10px 4px 5px;
  cursor: pointer;
  color: var(--adv-text);
}

.switch-track {
  position: relative;
  width: 34px;
  height: 19px;
  border-radius: 999px;
  background: #a1a1aa;
  transition: background 0.18s var(--ease);
}

:root.dark .switch-track {
  background: #52525b;
}

.switch-thumb {
  position: absolute;
  top: 2.5px;
  left: 2.5px;
  width: 14px;
  height: 14px;
  border-radius: 50%;
  background: #ffffff;
  transition: transform 0.18s var(--ease);
}

.switch[aria-checked="true"] .switch-track {
  background: var(--adv-ok);
}

.switch[aria-checked="true"] .switch-thumb {
  transform: translateX(15px);
}

.switch-text {
  font-family: var(--font-mono);
  font-size: 11.5px;
  font-weight: 700;
  min-width: 26px;
  text-align: center;
}

.quick-tools-wrap {
  margin-top: 14px;
  padding-top: 12px;
  border-top: 1px solid var(--adv-line);
}

.quick-tools-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 10px;
  font-size: 12px;
  font-weight: 600;
  color: var(--adv-text-2);
  margin-bottom: 9px;
}

.quick-tool-chips {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px;
}

.tool-chip-item {
  border: 1px solid var(--adv-line);
  background: var(--adv-elevated);
  border-radius: var(--r-sm);
  padding: 6px 8px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  min-width: 0;
  transition: border-color 0.16s var(--ease), background 0.16s var(--ease);
}

.tool-chip-item:hover {
  border-color: var(--adv-primary);
}

.tool-chip-item.is-off {
  opacity: 0.72;
  border-style: dashed;
}

.tool-chip-link {
  appearance: none;
  border: 0;
  background: transparent;
  padding: 0;
  margin: 0;
  flex: 1 1 auto;
  min-width: 0;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: var(--adv-text);
  font-family: var(--font-mono);
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  text-align: left;
}

.tool-chip-name {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.tool-chip-link:hover {
  color: var(--adv-primary);
}

.tool-chip-state {
  flex-shrink: 0;
  font-family: var(--font-sans);
  font-size: 10.5px;
  font-weight: 600;
  color: var(--adv-muted);
}

.mini-switch {
  appearance: none;
  flex-shrink: 0;
  display: inline-flex;
  align-items: center;
  border: 1px solid var(--adv-line);
  background: var(--adv-surface);
  border-radius: 999px;
  padding: 2px;
  cursor: pointer;
}

.mini-switch .switch-track {
  width: 28px;
  height: 16px;
}

.mini-switch .switch-thumb {
  top: 2px;
  left: 2px;
  width: 12px;
  height: 12px;
}

.mini-switch[aria-checked="true"] .switch-track {
  background: var(--adv-ok);
}

.mini-switch[aria-checked="true"] .switch-thumb {
  transform: translateX(12px);
}

.facts-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
  margin: 0 0 14px;
}

.fact-item {
  padding: 10px 12px;
  background: var(--adv-elevated);
  border: 1px solid var(--adv-line);
  border-radius: var(--r-sm);
  min-width: 0;
}

.fact-wide {
  grid-column: 1 / -1;
}

.fact-item dt {
  font-size: 11px;
  font-weight: 600;
  color: var(--adv-muted);
  margin-bottom: 2px;
}

.fact-item dd {
  margin: 0;
  font-size: 12px;
  color: var(--adv-text);
  word-break: break-word;
}

.service-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

/* ---------- Page 2: 实时审计与队列 ---------- */

.telemetry-row {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}

.panel-compact {
  padding: 16px 18px;
}

.counter-badge {
  min-width: 28px;
  height: 26px;
  padding: 0 8px;
  border-radius: 6px;
  background: var(--adv-tint-primary);
  border: 1px solid var(--adv-tint-primary-border);
  color: var(--adv-primary);
  font-family: var(--font-mono);
  font-weight: 700;
  font-size: 12px;
  display: inline-grid;
  place-items: center;
}

.compact-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 7px;
}

.compact-list li {
  padding: 8px 11px;
  background: var(--adv-elevated);
  border: 1px solid var(--adv-line);
  border-radius: var(--r-sm);
  font-family: var(--font-mono);
  font-size: 12px;
  display: flex;
  justify-content: space-between;
  gap: 8px;
}

.compact-list li.is-empty {
  color: var(--adv-muted);
  font-family: var(--font-sans);
}

.stream-controls {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}

.filter-bar {
  display: flex;
  gap: 6px;
}

.filter-btn {
  padding: 5px 10px;
  font-size: 12px;
}

.stream-wrap {
  max-height: 580px;
  overflow: auto;
  border: 1px solid var(--adv-line);
  border-radius: var(--r-md);
}

.stream-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12.5px;
}

.stream-table thead th {
  position: sticky;
  top: 0;
  z-index: 2;
  background: var(--adv-elevated);
  color: var(--adv-text-2);
  text-align: left;
  font-weight: 700;
  padding: 9px 10px;
  border-bottom: 1px solid var(--adv-line);
}

.col-chevron {
  width: 28px;
}

.event-row {
  cursor: pointer;
  transition: background 0.14s var(--ease);
}

.event-row:hover td {
  background: var(--adv-tint-primary);
}

.stream-table tbody td {
  padding: 8px 10px;
  border-bottom: 1px solid var(--adv-line);
  vertical-align: middle;
}

.event-row[data-open="true"] td {
  background: var(--adv-tint-primary);
  border-bottom-color: transparent;
}

.event-expand-btn {
  appearance: none;
  border: 0;
  background: transparent;
  padding: 2px;
  color: var(--adv-muted);
  cursor: pointer;
  display: inline-grid;
  place-items: center;
}

.event-detail-row td {
  background: var(--adv-elevated);
  padding: 11px 14px;
}

.trace-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.trace-kv {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 8px;
  border-radius: 5px;
  background: var(--adv-surface);
  border: 1px solid var(--adv-line);
  font-size: 11.5px;
}

.trace-k {
  color: var(--adv-muted);
  font-weight: 600;
}

.trace-v {
  font-family: var(--font-mono);
  color: var(--adv-text);
  font-weight: 600;
}

.trace-privacy-note {
  margin: 8px 0 0;
  font-size: 11.5px;
  color: var(--adv-muted);
}

.tag {
  display: inline-block;
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 600;
  padding: 2px 7px;
  border-radius: 4px;
  border: 1px solid transparent;
}

.tag-ok {
  background: var(--adv-tint-ok);
  border-color: rgba(16, 185, 129, 0.34);
  color: var(--adv-ok);
}

.tag-err {
  background: var(--adv-tint-err);
  border-color: rgba(239, 68, 68, 0.34);
  color: var(--adv-err);
}

.tag-info {
  background: var(--adv-tint-primary);
  border-color: var(--adv-tint-primary-border);
  color: var(--adv-primary);
}

/* ---------- Page 3: 工具说明（ApiExplorer 左目录 + 右详情工作区） ---------- */

.tools-explorer {
  display: grid;
  grid-template-columns: 300px minmax(0, 1fr);
  gap: 18px;
  align-items: start;
}

.tools-catalog {
  position: sticky;
  top: 78px;
  max-height: calc(100vh - 98px);
  display: flex;
  flex-direction: column;
  background: var(--adv-surface);
  border: 1px solid var(--adv-line);
  border-radius: var(--r-lg);
  box-shadow: var(--adv-shadow-sm), var(--adv-inner-light);
  overflow: hidden;
}

.catalog-search-box {
  padding: 12px;
  border-bottom: 1px solid var(--adv-line);
  background: var(--adv-elevated);
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.chip-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
}

.tool-filter-btn {
  padding: 4px 9px;
  font-size: 11px;
  border-radius: 999px;
}

.catalog-list {
  overflow-y: auto;
  padding: 8px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.catalog-item {
  width: 100%;
  appearance: none;
  border: 1px solid transparent;
  background: transparent;
  color: var(--adv-text);
  border-radius: var(--r-sm);
  padding: 9px 10px;
  display: flex;
  align-items: flex-start;
  gap: 9px;
  text-align: left;
  cursor: pointer;
  transition: background 0.14s var(--ease), border-color 0.14s var(--ease);
}

.catalog-item:hover {
  background: var(--adv-elevated);
}

.catalog-item.is-selected {
  background: var(--adv-tint-primary);
  border-color: var(--adv-primary);
}

.catalog-item.is-disabled {
  opacity: 0.68;
}

.catalog-item-text {
  display: flex;
  flex-direction: column;
  min-width: 0;
  flex: 1 1 auto;
  gap: 2px;
}

.catalog-item-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
}

.catalog-item-name {
  font-family: var(--font-mono);
  font-size: 12.5px;
  font-weight: 700;
  color: var(--adv-text);
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.catalog-item-role {
  font-size: 11.5px;
  color: var(--adv-muted);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.catalog-item-count {
  font-family: var(--font-mono);
  font-size: 10.5px;
  color: var(--adv-muted);
}

.tools-detail-stage {
  display: flex;
  flex-direction: column;
  gap: 14px;
  min-width: 0;
}

.detail-stage-bar {
  background: var(--adv-surface);
  border: 1px solid var(--adv-line);
  border-radius: var(--r-lg);
  padding: 14px 18px;
  box-shadow: var(--adv-shadow-sm), var(--adv-inner-light);
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.tool-bulk-actions {
  display: flex;
  gap: 6px;
}

.tool-detail-container {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.tool-hero-card,
.tool-section-card {
  background: var(--adv-surface);
  border: 1px solid var(--adv-line);
  border-radius: var(--r-lg);
  box-shadow: var(--adv-shadow-sm), var(--adv-inner-light);
  overflow: hidden;
}

.tool-hero-card {
  padding: 18px 20px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.tool-hero-badges {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 7px;
}

.tool-hero-title-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.tool-hero-title-meta {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 10px;
}

.tool-hero-control {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}

.tool-hero-name {
  margin: 0;
  font-family: var(--font-mono);
  font-size: 20px;
  font-weight: 700;
  color: var(--adv-text);
}

.tool-hero-role {
  font-size: 13.5px;
  font-weight: 600;
  color: var(--adv-text-2);
}

.tool-signature-bar {
  padding: 8px 11px;
  border-radius: var(--r-sm);
  background: var(--adv-elevated);
  border: 1px solid var(--adv-line);
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--adv-text);
  overflow-x: auto;
}

.tool-desc-box {
  font-size: 13.5px;
  color: var(--adv-text-2);
  line-height: 1.65;
}

.tool-blocked-note {
  padding: 9px 12px;
  border-radius: var(--r-sm);
  background: var(--adv-tint-err);
  border: 1px solid rgba(239, 68, 68, 0.32);
  color: var(--adv-err);
  font-size: 12.5px;
  font-weight: 600;
}

.tool-section-trigger {
  width: 100%;
  appearance: none;
  border: 0;
  background: transparent;
  color: var(--adv-text);
  padding: 13px 18px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  text-align: left;
  cursor: pointer;
}

.tool-section-trigger:hover {
  background: var(--adv-elevated);
}

.tool-section-title-wrap {
  display: flex;
  align-items: center;
  gap: 9px;
}

.tool-section-title {
  font-size: 14px;
  font-weight: 700;
}

.tool-section-body {
  padding: 0 18px 18px;
  border-top: 1px solid var(--adv-line);
  padding-top: 14px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.tool-section-card[data-open="true"] .chevron-icon,
.event-row[data-open="true"] .chevron-icon {
  transform: rotate(90deg);
  color: var(--adv-primary);
}

.chevron-icon {
  color: var(--adv-muted);
  transition: transform 0.18s var(--ease);
  flex-shrink: 0;
}

.kind-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 46px;
  padding: 2px 7px;
  border-radius: 5px;
  font-family: var(--font-mono);
  font-size: 10.5px;
  font-weight: 700;
  color: #ffffff;
  flex-shrink: 0;
}

.kind-READ {
  background: #047857;
}

.kind-WRITE {
  background: #0c5cab;
}

.kind-EXEC {
  background: #b45309;
}

.kind-CTX {
  background: #4f46e5;
}

.meta-pill {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: 999px;
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 600;
  background: var(--adv-elevated);
  border: 1px solid var(--adv-line);
  color: var(--adv-text-2);
}

.meta-pill.is-on {
  background: var(--adv-tint-ok);
  border-color: rgba(16, 185, 129, 0.32);
  color: var(--adv-ok);
}

.meta-pill.is-off {
  background: var(--adv-tint-err);
  border-color: rgba(239, 68, 68, 0.32);
  color: var(--adv-err);
}

.meta-pill.is-warn {
  background: var(--adv-tint-warn);
  border-color: rgba(245, 158, 11, 0.35);
  color: var(--adv-warn);
}

.meta-pill.is-brand {
  background: var(--adv-tint-primary);
  border-color: var(--adv-tint-primary-border);
  color: var(--adv-primary);
}

.tool-bounds-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.bound-card {
  padding: 12px 14px;
  border-radius: var(--r-sm);
  border: 1px solid var(--adv-line);
  background: var(--adv-elevated);
}

.bound-card-ok {
  border-left: 3px solid var(--adv-ok);
}

.bound-card-limit {
  border-left: 3px solid var(--adv-warn);
}

.bound-card h3 {
  margin: 0 0 7px;
  font-size: 13px;
  font-weight: 700;
  color: var(--adv-text);
}

.bound-list {
  margin: 0;
  padding-left: 17px;
  font-size: 12.5px;
  color: var(--adv-text-2);
  display: flex;
  flex-direction: column;
  gap: 5px;
}

.param-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.param-row {
  padding: 10px 12px;
  border-radius: var(--r-sm);
  background: var(--adv-elevated);
  border: 1px solid var(--adv-line);
}

.param-head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 7px;
}

.req-pill {
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
}

.req-pill.is-req {
  background: var(--adv-tint-err);
  color: var(--adv-err);
}

.req-pill.is-opt {
  background: var(--adv-surface);
  border: 1px solid var(--adv-line);
  color: var(--adv-muted);
}

.param-desc {
  margin: 5px 0 0;
  font-size: 12.5px;
  color: var(--adv-text-2);
}

.sample-box {
  border: 1px solid var(--adv-line);
  border-radius: var(--r-sm);
  overflow: hidden;
  background: var(--adv-code-bg);
}

.sample-box-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 7px 11px;
  border-bottom: 1px solid var(--adv-line);
  background: var(--adv-elevated);
  font-size: 12px;
  font-weight: 600;
  color: var(--adv-text-2);
}

.sample-pre {
  margin: 0;
  padding: 12px 14px;
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.55;
  color: var(--adv-code-text);
  overflow-x: auto;
}

.policy-config-row {
  margin-bottom: 14px;
}

.empty-state {
  padding: 24px;
  text-align: center;
  color: var(--adv-muted);
  font-size: 13px;
}

.security-grid {
  align-items: stretch;
}

.passkey-list {
  margin-bottom: 12px;
}

.compact-list li.passkey-item {
  align-items: center;
  font-family: var(--font-sans);
  padding: 10px 12px;
  gap: 12px;
}

.passkey-meta {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.passkey-title-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  font-weight: 700;
  color: var(--adv-text);
}

.passkey-sub {
  font-family: var(--font-mono);
  font-size: 11.5px;
  color: var(--adv-muted);
  word-break: break-all;
}

.passkey-enroll-bar {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 8px;
  align-items: center;
}

.inline-feedback {
  margin-bottom: 12px;
  padding: 10px 12px;
  border-radius: var(--r-sm);
  font-size: 12.5px;
  font-weight: 600;
}

.inline-feedback.is-ok {
  background: var(--adv-tint-ok);
  border: 1px solid rgba(16, 185, 129, 0.35);
  color: var(--adv-ok);
}

.inline-feedback.is-err {
  background: var(--adv-tint-err);
  border: 1px solid rgba(239, 68, 68, 0.35);
  color: var(--adv-err);
}

.compact-list li.approval-card {
  flex-direction: column;
  align-items: stretch;
  gap: 8px;
  padding: 11px 12px;
  font-family: var(--font-sans);
}

.approval-card-head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.approval-card-title {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
}

.approval-digest {
  font-family: var(--font-mono);
  font-size: 11.5px;
  color: var(--adv-muted);
  word-break: break-all;
}

.approval-review {
  width: min(48rem, 95vw);
  padding: 18px 20px;
  color: var(--adv-text);
  background: var(--adv-surface);
  border: 1px solid var(--adv-line);
  border-radius: var(--r-md);
}

.approval-review h2 {
  margin: 0 0 12px;
  font-size: 16px;
}

.approval-review .approval-digest {
  margin: 10px 0 12px;
}

.approval-review::backdrop {
  background: rgb(0 0 0 / 45%);
}

.approval-args-pre {
  margin: 0;
  padding: 8px 10px;
  border-radius: var(--r-sm);
  border: 1px solid var(--adv-line);
  background: var(--adv-code-bg);
  color: var(--adv-code-text);
  font-family: var(--font-mono);
  font-size: 11.5px;
  line-height: 1.45;
  max-height: 52vh;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
}

.approval-actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}

a:focus-visible,
button:focus-visible,
input:focus-visible,
select:focus-visible,
textarea:focus-visible,
summary:focus-visible,
pre[tabindex="0"]:focus-visible {
  outline: 2px solid var(--adv-primary);
  outline-offset: 2px;
}

.kind-MCP {
  background: rgba(139, 92, 246, 0.14);
  border: 1px solid rgba(139, 92, 246, 0.34);
  color: #6d28d9;
}

:root.dark .kind-MCP {
  background: rgba(167, 139, 250, 0.16);
  border-color: rgba(167, 139, 250, 0.36);
  color: #c4b5fd;
}

/* ---------- Page 4: 第三方 MCP 接入配置 ---------- */

.mcp-banner {
  border-left: 3px solid var(--adv-primary);
}

.mcp-banner-stats {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.mcp-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.15fr) minmax(0, 0.85fr);
  gap: 18px;
  align-items: start;
}

.mcp-servers-stack {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.mcp-server-card {
  border: 1px solid var(--adv-line);
  background: var(--adv-elevated);
  border-radius: var(--r-md);
  padding: 13px 14px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.mcp-server-card.is-disabled {
  opacity: 0.78;
  border-style: dashed;
}

.mcp-server-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 10px;
}

.mcp-server-title-wrap {
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
}

.mcp-server-title-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
}

.mcp-server-name {
  font-size: 14.5px;
  font-weight: 700;
  color: var(--adv-text);
}

.mcp-server-desc {
  font-size: 12.5px;
  color: var(--adv-text-2);
}

.mcp-server-cmd {
  padding: 7px 10px;
  border-radius: var(--r-sm);
  border: 1px solid var(--adv-line);
  background: var(--adv-surface);
  font-family: var(--font-mono);
  font-size: 11.5px;
  color: var(--adv-text);
  word-break: break-all;
}

.mcp-server-error {
  padding: 8px 10px;
  border-radius: var(--r-sm);
  border: 1px solid rgba(239, 68, 68, 0.34);
  background: var(--adv-tint-err);
  color: var(--adv-err);
  font-size: 12px;
  word-break: break-word;
}

.mcp-secret-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.secret-chip {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 2px 8px;
  border-radius: 999px;
  border: 1px solid var(--adv-line-strong);
  background: var(--adv-surface);
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--adv-text-2);
}

.secret-chip-remove {
  appearance: none;
  border: 0;
  background: transparent;
  color: var(--adv-err);
  font-weight: 700;
  cursor: pointer;
  padding: 0 2px;
  line-height: 1;
}

.secret-chip.is-marked-delete {
  text-decoration: line-through;
  opacity: 0.55;
  border-color: rgba(239, 68, 68, 0.45);
}

.mcp-server-actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 7px;
}

.mcp-tools-drawer {
  border-top: 1px solid var(--adv-line);
  padding-top: 9px;
}

.mcp-tools-drawer summary {
  cursor: pointer;
  font-size: 12px;
  font-weight: 600;
  color: var(--adv-text-2);
  user-select: none;
}

.mcp-tools-list {
  margin-top: 8px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.mcp-tool-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 6px 9px;
  border-radius: var(--r-sm);
  border: 1px solid var(--adv-line);
  background: var(--adv-surface);
}

.mcp-tool-info {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.mcp-tool-desc {
  font-size: 11.5px;
  color: var(--adv-muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.mcp-editor-tabs {
  display: inline-flex;
  border: 1px solid var(--adv-line-strong);
  border-radius: var(--r-sm);
  overflow: hidden;
  background: var(--adv-elevated);
}

.mcp-editor-tab {
  appearance: none;
  border: 0;
  background: transparent;
  color: var(--adv-text-2);
  font-family: var(--font-sans);
  font-size: 12px;
  font-weight: 600;
  padding: 6px 11px;
  cursor: pointer;
}

.mcp-editor-tab.active {
  background: linear-gradient(135deg, #0c5cab, #0a4a8a);
  color: #ffffff;
}

.form-grid-2 {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
  align-items: end;
}

.mcp-transport-group {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.select-control,
.textarea-control {
  width: 100%;
  border: 1px solid var(--adv-line-strong);
  border-radius: var(--r-sm);
  font-size: 13px;
  background: var(--adv-surface);
  color: var(--adv-text);
  transition: border-color 0.18s var(--ease), box-shadow 0.18s var(--ease);
}

.select-control {
  height: 36px;
  padding: 0 10px;
}

.textarea-control {
  padding: 8px 11px;
  line-height: 1.5;
  resize: vertical;
  font-family: var(--font-sans);
}

.textarea-control.mono {
  font-family: var(--font-mono);
  font-size: 12px;
}

.select-control:focus,
.textarea-control:focus {
  outline: 2px solid transparent;
  border-color: var(--adv-primary);
  box-shadow: 0 0 0 3px var(--adv-tint-primary);
}

.checkbox-row {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12.5px;
  color: var(--adv-text);
  cursor: pointer;
}

@media (max-width: 1100px) {
  .kpi-strip {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .overview-grid,
  .tools-explorer,
  .mcp-grid {
    grid-template-columns: 1fr;
  }

  .tools-catalog {
    position: static;
    max-height: none;
  }
}

@media (max-width: 680px) {
  .topbar-inner,
  .shell {
    padding-left: 14px;
    padding-right: 14px;
  }

  .kpi-strip,
  .telemetry-row,
  .facts-grid,
  .tool-bounds-grid,
  .quick-tool-chips,
  .passkey-enroll-bar,
  .form-grid-2 {
    grid-template-columns: 1fr;
  }

  .action-quiet {
    margin-left: 0;
  }
}

@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    transition: none !important;
    animation: none !important;
  }
}
`;

export const WEBUI_JS = `(() => {
  'use strict';

  const csrfMeta = document.querySelector('meta[name="agentdock-csrf"]');
  let csrfToken = csrfMeta ? csrfMeta.getAttribute('content') || '' : '';
  const THEME_STORAGE_KEY = 'agentdock_webui_theme';
  const TAB_AUTH_STORAGE_KEY = 'agentdock_webui_tab_token';
  const VALID_TABS = new Set(['overview', 'audit', 'tools', 'mcp']);
  const PRE_AUTH_ENDPOINTS = new Set([
    '/api/auth/login/password',
    '/api/auth/setup/password',
    '/api/auth/passkey/login/options',
    '/api/auth/passkey/login/verify',
    '/api/auth/setup/passkey/options',
    '/api/auth/setup/passkey/verify',
    '/api/auth/passkey/report-support',
    '/api/auth/logout',
  ]);

  const els = {
    errorBanner: document.getElementById('error-banner'),
    navTabs: document.getElementById('nav-tabs'),
    tabButtons: Array.from(document.querySelectorAll('.nav-tab')),
    navBadgeAudit: document.getElementById('nav-badge-audit'),
    navBadgeTools: document.getElementById('nav-badge-tools'),
    navBadgeMcp: document.getElementById('nav-badge-mcp'),
    viewOverview: document.getElementById('view-overview'),
    viewAudit: document.getElementById('view-audit'),
    viewTools: document.getElementById('view-tools'),
    viewMcp: document.getElementById('view-mcp'),
    authStatusPill: document.getElementById('auth-status-pill'),
    authStatusDot: document.getElementById('auth-status-dot'),
    authStatusLabel: document.getElementById('auth-status-label'),
    ssePill: document.getElementById('sse-pill'),
    sseDot: document.getElementById('sse-dot'),
    sseLabel: document.getElementById('sse-label'),
    systemdPill: document.getElementById('systemd-pill'),
    systemdDot: document.getElementById('systemd-dot'),
    systemdLabel: document.getElementById('systemd-label'),
    gatewayPill: document.getElementById('gateway-pill'),
    gatewayDot: document.getElementById('gateway-dot'),
    gatewayLabel: document.getElementById('gateway-label'),
    btnTheme: document.getElementById('btn-theme'),
    themeLabel: document.getElementById('theme-label'),
    btnLogout: document.getElementById('btn-logout'),
    authGate: document.getElementById('auth-gate'),
    authTitle: document.getElementById('auth-title'),
    authSubtitle: document.getElementById('auth-subtitle'),
    authPolicyBadge: document.getElementById('auth-policy-badge'),
    authCliGuide: document.getElementById('auth-cli-guide'),
    setupTicketGroup: document.getElementById('setup-ticket-group'),
    inputSetupTicket: document.getElementById('input-setup-ticket'),
    passkeySection: document.getElementById('passkey-section'),
    passkeyExplain: document.getElementById('passkey-explain'),
    passkeyLabelGroup: document.getElementById('passkey-label-group'),
    inputPasskeyLabel: document.getElementById('input-passkey-label'),
    btnPasskeyLogin: document.getElementById('btn-passkey-login'),
    btnPasskeyEnroll: document.getElementById('btn-passkey-enroll'),
    passwordForm: document.getElementById('password-form'),
    labelInputPassword: document.getElementById('label-input-password'),
    inputPassword: document.getElementById('input-password'),
    passwordConfirmGroup: document.getElementById('password-confirm-group'),
    inputPasswordConfirm: document.getElementById('input-password-confirm'),
    btnPasswordSubmit: document.getElementById('btn-password-submit'),
    btnSetupHardwarePasskey: document.getElementById('btn-setup-hardware-passkey'),
    btnAuthRecheck: document.getElementById('btn-auth-recheck'),
    workbench: document.getElementById('workbench'),
    kpiCardTools: document.getElementById('kpi-card-tools'),
    kpiCardAudit: document.getElementById('kpi-card-audit'),
    kpiCardQueue: document.getElementById('kpi-card-queue'),
    kpiToolsRatio: document.getElementById('kpi-tools-ratio'),
    kpiToolsSub: document.getElementById('kpi-tools-sub'),
    kpiMountMode: document.getElementById('kpi-mount-mode'),
    kpiMountSub: document.getElementById('kpi-mount-sub'),
    kpiAuditTotal: document.getElementById('kpi-audit-total'),
    kpiAuditSub: document.getElementById('kpi-audit-sub'),
    kpiLiveQueue: document.getElementById('kpi-live-queue'),
    kpiLiveSub: document.getElementById('kpi-live-sub'),
    panelCapabilities: document.getElementById('panel-capabilities'),
    mountBadge: document.getElementById('mount-mode-badge'),
    presetFull: document.getElementById('preset-full'),
    presetReadonly: document.getElementById('preset-readonly'),
    presetLocked: document.getElementById('preset-locked'),
    toggleRead: document.getElementById('toggle-read'),
    toggleWrite: document.getElementById('toggle-write'),
    toggleExec: document.getElementById('toggle-exec'),
    labelRead: document.getElementById('label-read'),
    labelWrite: document.getElementById('label-write'),
    labelExec: document.getElementById('label-exec'),
    policyUpdatedAt: document.getElementById('policy-updated-at'),
    overviewToolChips: document.getElementById('overview-tool-chips'),
    toolGrid: document.getElementById('tool-grid'),
    toolDetailPane: document.getElementById('tool-detail-pane'),
    toolsEmpty: document.getElementById('tools-empty'),
    toolSearch: document.getElementById('tool-search'),
    btnToolsExpand: document.getElementById('btn-tools-expand'),
    btnToolsCollapse: document.getElementById('btn-tools-collapse'),
    toolFilterButtons: Array.from(document.querySelectorAll('.tool-filter-btn')),
    btnUpgradePasskey: document.getElementById('btn-upgrade-passkey'),
    factWorkspace: document.getElementById('fact-workspace'),
    factOrigin: document.getElementById('fact-origin'),
    factPids: document.getElementById('fact-pids'),
    factSystemd: document.getElementById('fact-systemd'),
    factImage: document.getElementById('fact-image'),
    factSecurity: document.getElementById('fact-security'),
    toggleAutostart: document.getElementById('toggle-autostart'),
    labelAutostart: document.getElementById('label-autostart'),
    autostartDesc: document.getElementById('autostart-desc'),
    toggleTabAuth: document.getElementById('toggle-tab-auth'),
    labelTabAuth: document.getElementById('label-tab-auth'),
    sessionPolicyDesc: document.getElementById('session-policy-desc'),
    passkeysCount: document.getElementById('passkeys-count'),
    passkeysList: document.getElementById('passkeys-list'),
    passkeyHwNote: document.getElementById('passkey-hw-note'),
    passkeyEnrollBar: document.getElementById('passkey-enroll-bar'),
    inputNewPasskeyLabel: document.getElementById('input-new-passkey-label'),
    btnAddPasskey: document.getElementById('btn-add-passkey'),
    securityModePill: document.getElementById('security-mode-pill'),
    securityFeedback: document.getElementById('security-feedback'),
    passwordLockedNotice: document.getElementById('password-locked-notice'),
    passwordLockedReason: document.getElementById('password-locked-reason'),
    securityPasswordForm: document.getElementById('security-password-form'),
    securityCurrentPasswordGroup: document.getElementById('security-current-password-group'),
    inputCurrentPassword: document.getElementById('input-current-password'),
    labelResetPassword: document.getElementById('label-reset-password'),
    inputResetPassword: document.getElementById('input-reset-password'),
    inputResetPasswordConfirm: document.getElementById('input-reset-password-confirm'),
    btnResetPassword: document.getElementById('btn-reset-password'),
    btnStart: document.getElementById('btn-service-start'),
    btnRestart: document.getElementById('btn-service-restart'),
    btnStop: document.getElementById('btn-service-stop'),
    btnRefresh: document.getElementById('btn-refresh'),
    approvalsCount: document.getElementById('approvals-count'),
    approvalsList: document.getElementById('approvals-list'),
    containersCount: document.getElementById('containers-count'),
    containersList: document.getElementById('containers-list'),
    eventsSummaryPill: document.getElementById('events-summary-pill'),
    eventsTbody: document.getElementById('events-tbody'),
    eventsEmpty: document.getElementById('events-empty'),
    filterButtons: Array.from(document.querySelectorAll('.filter-btn')),
    mcpSummaryServers: document.getElementById('mcp-summary-servers'),
    mcpSummaryTools: document.getElementById('mcp-summary-tools'),
    mcpRegistryError: document.getElementById('mcp-registry-error'),
    mcpServersCount: document.getElementById('mcp-servers-count'),
    mcpServersList: document.getElementById('mcp-servers-list'),
    btnMcpNew: document.getElementById('btn-mcp-new'),
    mcpEditorTitle: document.getElementById('mcp-editor-title'),
    mcpModeForm: document.getElementById('mcp-mode-form'),
    mcpModeJson: document.getElementById('mcp-mode-json'),
    mcpFeedback: document.getElementById('mcp-feedback'),
    mcpServerForm: document.getElementById('mcp-server-form'),
    mcpImportForm: document.getElementById('mcp-import-form'),
    inputMcpId: document.getElementById('input-mcp-id'),
    inputMcpName: document.getElementById('input-mcp-name'),
    inputMcpDesc: document.getElementById('input-mcp-desc'),
    selectMcpTransport: document.getElementById('select-mcp-transport'),
    inputMcpTimeout: document.getElementById('input-mcp-timeout'),
    mcpStdioFields: document.getElementById('mcp-stdio-fields'),
    mcpHttpFields: document.getElementById('mcp-http-fields'),
    inputMcpCommand: document.getElementById('input-mcp-command'),
    inputMcpArgs: document.getElementById('input-mcp-args'),
    inputMcpCwd: document.getElementById('input-mcp-cwd'),
    inputMcpEnv: document.getElementById('input-mcp-env'),
    mcpExistingEnvKeys: document.getElementById('mcp-existing-env-keys'),
    inputMcpUrl: document.getElementById('input-mcp-url'),
    inputMcpHeaders: document.getElementById('input-mcp-headers'),
    mcpExistingHeaderKeys: document.getElementById('mcp-existing-header-keys'),
    mcpReplaceSecretsRow: document.getElementById('mcp-replace-secrets-row'),
    inputMcpReplaceSecrets: document.getElementById('input-mcp-replace-secrets'),
    inputMcpEnabled: document.getElementById('input-mcp-enabled'),
    btnMcpSaveProbe: document.getElementById('btn-mcp-save-probe'),
    btnMcpSaveOnly: document.getElementById('btn-mcp-save-only'),
    btnMcpCancel: document.getElementById('btn-mcp-cancel'),
    inputMcpJson: document.getElementById('input-mcp-json'),
    btnMcpImportProbe: document.getElementById('btn-mcp-import-probe'),
    btnMcpImportOnly: document.getElementById('btn-mcp-import-only'),
  };

  let latestSnapshot = null;
  let activeTab = readTabFromHash();
  let activeFilter = 'all';
  let activeToolGroup = 'all';
  let toolSearchQuery = '';
  let selectedToolName = 'read_file';
  let pendingMutation = false;
  let sseController = null;
  let sseReconnectTimer = null;
  let currentAuthState = null;
  let browserUvpa = false;
  let editingMcpServerId = null;
  let editingMcpTransport = null;
  let editingMcpHasSecrets = false;
  let editingMcpInitialUrl = '';
  let editingMcpUrlRedacted = false;
  let pendingDeleteMcpId = null;
  let pendingDeleteMcpTimer = null;
  let policyErrorText = '';
  let actionErrorText = '';
  let activeReview = null;
  let countdownTimer = null;
  const markedDeleteEnvKeys = new Set();
  const markedDeleteHeaderKeys = new Set();
  const mcpDrawerOpenState = new Map();
  const lastRenderSig = { tools: '', events: '', approvals: '', mcp: '' };
  const expandedSections = new Set(['params', 'bounds', 'sample']);
  const expandedEvents = new Set();

  function getTabToken() {
    try { return sessionStorage.getItem(TAB_AUTH_STORAGE_KEY) || ''; } catch { return ''; }
  }

  function setTabToken(token) {
    try {
      if (token) sessionStorage.setItem(TAB_AUTH_STORAGE_KEY, token);
      else sessionStorage.removeItem(TAB_AUTH_STORAGE_KEY);
    } catch {}
  }

  function authHeaders(extra = {}) {
    const token = getTabToken();
    return token ? { ...extra, 'x-agentdock-tab-auth': token } : { ...extra };
  }

  function readTabFromHash() {
    const h = String(window.location.hash || '').replace(/^#/, '').toLowerCase();
    return VALID_TABS.has(h) ? h : 'overview';
  }

  function clearPendingDeleteMcp() {
    pendingDeleteMcpId = null;
    if (pendingDeleteMcpTimer) {
      clearTimeout(pendingDeleteMcpTimer);
      pendingDeleteMcpTimer = null;
    }
  }

  function switchTab(nextTab, { syncHash = true } = {}) {
    if (!VALID_TABS.has(nextTab)) return;
    if (activeTab !== nextTab && pendingDeleteMcpId) {
      clearPendingDeleteMcp();
      lastRenderSig.mcp = '';
      if (latestSnapshot) renderMcpServers(latestSnapshot);
    }
    activeTab = nextTab;
    for (const btn of els.tabButtons) {
      const active = btn.getAttribute('data-tab') === nextTab;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-selected', active ? 'true' : 'false');
    }
    els.viewOverview.hidden = nextTab !== 'overview';
    els.viewAudit.hidden = nextTab !== 'audit';
    els.viewTools.hidden = nextTab !== 'tools';
    if (els.viewMcp) els.viewMcp.hidden = nextTab !== 'mcp';
    if (syncHash && window.location.hash !== '#' + nextTab) {
      try { history.replaceState(null, '', '#' + nextTab); } catch {}
    }
  }

  function applyTheme(isDark) {
    document.documentElement.classList.toggle('dark', Boolean(isDark));
    if (els.themeLabel) els.themeLabel.textContent = isDark ? '浅色' : '深色';
    try { localStorage.setItem(THEME_STORAGE_KEY, isDark ? 'dark' : 'light'); } catch {}
  }

  (function initTheme() {
    let saved = null;
    try { saved = localStorage.getItem(THEME_STORAGE_KEY); } catch {}
    if (saved === 'dark' || saved === 'light') {
      applyTheme(saved === 'dark');
    } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      applyTheme(true);
    } else {
      applyTheme(false);
    }
  })();

  function createChevronSvg() {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('class', 'chevron-icon');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('width', '15');
    svg.setAttribute('height', '15');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2.2');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', 'm9 18 6-6-6-6');
    svg.appendChild(path);
    return svg;
  }

  function renderErrorBanner() {
    const msg = policyErrorText || actionErrorText;
    if (!msg) {
      els.errorBanner.hidden = true;
      els.errorBanner.replaceChildren();
      return;
    }
    els.errorBanner.replaceChildren();
    const span = document.createElement('span');
    span.textContent = msg;
    els.errorBanner.appendChild(span);
    if (!policyErrorText && actionErrorText) {
      const dismiss = document.createElement('button');
      dismiss.type = 'button';
      dismiss.className = 'action-btn action-sm';
      dismiss.textContent = '关闭';
      dismiss.addEventListener('click', () => {
        actionErrorText = '';
        renderErrorBanner();
      });
      els.errorBanner.appendChild(dismiss);
    }
    els.errorBanner.hidden = false;
  }

  function showError(message) {
    actionErrorText = message ? String(message) : '';
    renderErrorBanner();
  }

  function showSecurityFeedback(tone, message) {
    if (!els.securityFeedback) return;
    if (!message) {
      els.securityFeedback.hidden = true;
      els.securityFeedback.textContent = '';
      els.securityFeedback.className = 'inline-feedback';
      return;
    }
    els.securityFeedback.className = 'inline-feedback ' + (tone === 'ok' ? 'is-ok' : 'is-err');
    els.securityFeedback.textContent = message;
    els.securityFeedback.hidden = false;
  }

  function isToolParentGroupEnabled(snap, tool) {
    const caps = snap?.capabilities;
    if (!caps || !tool) return false;
    if (tool.external) return Boolean(tool.serverEnabled);
    if (caps.error) {
      return tool.group === 'context' || (tool.group === 'execControl' && snap?.sandbox?.configAllowExec === true);
    }
    if (tool.group === 'fileRead') return Boolean(caps.fileRead);
    if (tool.group === 'fileWrite') return Boolean(caps.fileWrite);
    if (tool.group === 'exec') return Boolean(caps.fileRead && caps.allowExec && snap?.sandbox?.configAllowExec === true);
    if (tool.group === 'execControl') return snap?.sandbox?.configAllowExec === true;
    return true;
  }

  function matchesToolGroupFilter(tool, groupFilter) {
    if (!groupFilter || groupFilter === 'all') return true;
    if (groupFilter === 'read') return tool.group === 'fileRead';
    if (groupFilter === 'write') return tool.group === 'fileWrite';
    if (groupFilter === 'exec') return tool.group === 'exec' || tool.group === 'execControl';
    if (groupFilter === 'context') return tool.group === 'context';
    if (groupFilter === 'mcp') return tool.group === 'mcp' || Boolean(tool.external);
    return tool.group === groupFilter;
  }

  function openToolInExplorer(toolName) {
    activeToolGroup = 'all';
    toolSearchQuery = '';
    if (els.toolSearch) els.toolSearch.value = '';
    for (const btn of els.toolFilterButtons) {
      const active = btn.getAttribute('data-tool-group') === 'all';
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-pressed', active ? 'true' : 'false');
    }
    selectedToolName = toolName;
    lastRenderSig.tools = '';
    switchTab('tools');
    if (latestSnapshot) renderToolExplorer(latestSnapshot);
  }

  function showMcpFeedback(tone, message) {
    if (!els.mcpFeedback) return;
    if (!message) {
      els.mcpFeedback.hidden = true;
      els.mcpFeedback.textContent = '';
      els.mcpFeedback.className = 'inline-feedback';
      return;
    }
    els.mcpFeedback.className = 'inline-feedback ' + (tone === 'ok' ? 'is-ok' : 'is-err');
    els.mcpFeedback.textContent = message;
    els.mcpFeedback.hidden = false;
  }

  function setPill(pill, dot, labelEl, tone, text) {
    pill.className = 'pill ' + (tone === 'online' ? 'pill-online' : tone === 'locked' ? 'pill-locked' : tone === 'warn' ? 'pill-warn' : 'pill-neutral');
    dot.className = 'dot ' + (tone === 'online' ? 'dot-online' : tone === 'locked' ? 'dot-locked' : tone === 'warn' ? 'dot-warn' : '');
    labelEl.textContent = text;
  }

  function b64urlToBuf(str) {
    const pad = '='.repeat((4 - (str.length % 4)) % 4);
    const base64 = (str + pad).replaceAll('-', '+').replaceAll('_', '/');
    const raw = atob(base64);
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out.buffer;
  }

  function bufToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  }

  async function detectBrowserPasskeySupport() {
    try {
      if (window.PublicKeyCredential && typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
        browserUvpa = await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      }
    } catch {
      browserUvpa = false;
    }
    return browserUvpa;
  }

  function ensureLocalhostForWebAuthn() {
    if (window.location.hostname === '127.0.0.1' || window.location.hostname === '[::1]' || window.location.hostname === '::1') {
      const portPart = window.location.port ? ':' + window.location.port : '';
      const target = 'http://localhost' + portPart + window.location.pathname + window.location.search + window.location.hash;
      window.location.replace(target);
      return true;
    }
    return false;
  }

  function formatTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '—';
    return d.toLocaleTimeString('zh-CN', { hour12: false });
  }

  function setSwitchState(btn, labelEl, checked, disabled = false) {
    btn.setAttribute('aria-checked', checked ? 'true' : 'false');
    btn.disabled = disabled || pendingMutation;
    labelEl.textContent = checked ? '开启' : '关闭';
  }

  function disconnectSse() {
    if (sseReconnectTimer) {
      clearTimeout(sseReconnectTimer);
      sseReconnectTimer = null;
    }
    if (sseController) {
      sseController.abort();
      sseController = null;
    }
  }

  function updateApprovalCountdowns() {
    const now = Date.now();
    if (els.approvalsList) {
      for (const el of els.approvalsList.querySelectorAll('.approval-countdown')) {
        const exp = el.getAttribute('data-expires-at');
        if (!exp) continue;
        const ms = new Date(exp).getTime() - now;
        if (!Number.isFinite(ms)) el.textContent = '待批准';
        else if (ms <= 0) el.textContent = '已过期';
        else el.textContent = Math.ceil(ms / 1000) + 's 后过期';
      }
    }
    if (activeReview && activeReview.dialog?.open && Number.isFinite(activeReview.expiresAt) && now >= activeReview.expiresAt) {
      activeReview.approveBtn.disabled = true;
      activeReview.statusEl.textContent = '该审批请求已过期，无法批准。';
    }
  }

  function startCountdownTimer() {
    if (countdownTimer) return;
    countdownTimer = setInterval(updateApprovalCountdowns, 1000);
  }

  function stopCountdownTimer() {
    if (countdownTimer) {
      clearInterval(countdownTimer);
      countdownTimer = null;
    }
  }

  function clearSensitiveUiState() {
    stopCountdownTimer();
    latestSnapshot = null;
    lastRenderSig.tools = '';
    lastRenderSig.events = '';
    lastRenderSig.approvals = '';
    lastRenderSig.mcp = '';
    mcpDrawerOpenState.clear();
    expandedEvents.clear();
    selectedToolName = 'read_file';
    activeToolGroup = 'all';
    toolSearchQuery = '';
    activeFilter = 'all';
    if (els.toolSearch) els.toolSearch.value = '';
    for (const btn of els.toolFilterButtons) {
      const active = btn.getAttribute('data-tool-group') === 'all';
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-pressed', active ? 'true' : 'false');
    }
    for (const btn of els.filterButtons) {
      const active = btn.getAttribute('data-filter') === 'all';
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-pressed', active ? 'true' : 'false');
    }
    clearPendingDeleteMcp();
    resetMcpForm();
    if (els.inputMcpJson) els.inputMcpJson.value = '';
    if (els.inputPassword) els.inputPassword.value = '';
    if (els.inputPasswordConfirm) els.inputPasswordConfirm.value = '';
    if (els.inputSetupTicket) els.inputSetupTicket.value = '';
    if (els.inputCurrentPassword) els.inputCurrentPassword.value = '';
    if (els.inputResetPassword) els.inputResetPassword.value = '';
    if (els.inputResetPasswordConfirm) els.inputResetPasswordConfirm.value = '';
    if (els.inputPasskeyLabel) els.inputPasskeyLabel.value = '';
    if (els.inputNewPasskeyLabel) els.inputNewPasskeyLabel.value = '';
    showSecurityFeedback(null, '');
    showMcpFeedback(null, '');
    policyErrorText = '';
    actionErrorText = '';
    renderErrorBanner();
    for (const dlg of document.querySelectorAll('.approval-review')) {
      try { if (dlg.open) dlg.close(); } catch {}
      dlg.remove();
    }
    activeReview = null;
    if (els.approvalsList) els.approvalsList.replaceChildren();
    if (els.containersList) els.containersList.replaceChildren();
    if (els.eventsTbody) els.eventsTbody.replaceChildren();
    if (els.mcpServersList) els.mcpServersList.replaceChildren();
    if (els.passkeysList) els.passkeysList.replaceChildren();
    if (els.overviewToolChips) els.overviewToolChips.replaceChildren();
    if (els.toolGrid) els.toolGrid.replaceChildren();
    if (els.toolDetailPane) els.toolDetailPane.replaceChildren();
    if (els.factWorkspace) els.factWorkspace.textContent = '—';
    if (els.factOrigin) els.factOrigin.textContent = '—';
    if (els.factPids) els.factPids.textContent = '—';
    if (els.factSystemd) els.factSystemd.textContent = '—';
    if (els.factImage) els.factImage.textContent = '—';
    if (els.factSecurity) els.factSecurity.textContent = '—';
    if (els.mcpRegistryError) { els.mcpRegistryError.hidden = true; els.mcpRegistryError.textContent = ''; }
    if (els.kpiToolsRatio) els.kpiToolsRatio.textContent = '—';
    if (els.kpiToolsSub) els.kpiToolsSub.textContent = '';
    if (els.kpiMountMode) els.kpiMountMode.textContent = '—';
    if (els.kpiMountSub) els.kpiMountSub.textContent = '';
    if (els.kpiAuditTotal) els.kpiAuditTotal.textContent = '—';
    if (els.kpiAuditSub) els.kpiAuditSub.textContent = '';
    if (els.kpiLiveQueue) els.kpiLiveQueue.textContent = '—';
    if (els.kpiLiveSub) els.kpiLiveSub.textContent = '';
    if (els.eventsSummaryPill) els.eventsSummaryPill.textContent = '0 条记录';
    if (els.policyUpdatedAt) els.policyUpdatedAt.textContent = '默认策略';
    if (els.mcpSummaryServers) els.mcpSummaryServers.textContent = '0 个服务';
    if (els.mcpSummaryTools) els.mcpSummaryTools.textContent = '0 个可用工具';
    if (els.approvalsCount) els.approvalsCount.textContent = '0';
    if (els.containersCount) els.containersCount.textContent = '0';
    if (els.passkeysCount) els.passkeysCount.textContent = '0';
    if (els.mcpServersCount) els.mcpServersCount.textContent = '0';
    if (els.autostartDesc) els.autostartDesc.textContent = '';
    if (els.sessionPolicyDesc) els.sessionPolicyDesc.textContent = '';
    if (els.navBadgeAudit) { els.navBadgeAudit.hidden = true; els.navBadgeAudit.textContent = '0'; }
    if (els.navBadgeMcp) { els.navBadgeMcp.hidden = true; els.navBadgeMcp.textContent = '0'; }
  }

  function setDashboardVisible(visible) {
    els.authGate.hidden = visible;
    els.workbench.hidden = !visible;
    els.navTabs.hidden = !visible;
    els.ssePill.hidden = !visible;
    els.systemdPill.hidden = !visible;
    els.gatewayPill.hidden = !visible;
    els.btnLogout.hidden = !visible;
    if (visible) {
      switchTab(activeTab, { syncHash: false });
      startCountdownTimer();
    } else {
      clearSensitiveUiState();
    }
  }

  function renderAuthGate(auth) {
    currentAuthState = auth;
    disconnectSse();
    setDashboardVisible(false);

    if (auth.error) {
      setPill(els.authStatusPill, els.authStatusDot, els.authStatusLabel, 'locked', '安全策略异常');
      showError('安全配置文件异常或位于挂载工作区内部：' + auth.error);
      els.authPolicyBadge.textContent = '配置异常已锁定';
      els.authCliGuide.hidden = true;
      els.setupTicketGroup.hidden = true;
      els.passkeySection.hidden = true;
      els.passwordForm.hidden = true;
      return;
    }

    const forcePasskey = Boolean(auth.passkeyRequired || auth.hostPasskeySupported || browserUvpa);
    const tabPolicyNote = (auth.sessionPersistence || 'tab') === 'tab' ? '（单标签页隔离：关闭重开须重认证）' : '（跨标签页会话）';

    if (auth.mode === 'passkey') {
      setPill(els.authStatusPill, els.authStatusDot, els.authStatusLabel, 'warn', '等待 PassKey 验证');
      els.authPolicyBadge.textContent = 'PassKey 强制认证';
      if (auth.passkeyCount > 0) {
        els.authTitle.textContent = '使用 PassKey 解锁本机控制台';
        els.authSubtitle.textContent = '本机已启用硬件 / 平台 PassKey 强制认证，禁止降级使用密码登录' + tabPolicyNote + '。';
        els.authCliGuide.hidden = true;
        els.setupTicketGroup.hidden = true;
        els.passkeySection.hidden = false;
        els.passkeyExplain.textContent = '点击下方按钮完成 PassKey 用户验证后进入监控台。';
        els.passkeyLabelGroup.hidden = true;
        els.btnPasskeyLogin.hidden = false;
        els.btnPasskeyEnroll.hidden = true;
        els.passwordForm.hidden = true;
      } else {
        els.authTitle.textContent = '需要绑定本机 PassKey';
        els.authSubtitle.textContent = '检测到机器或浏览器支持 PassKey，必须先完成绑定方可解锁。';
        els.authCliGuide.hidden = false;
        els.setupTicketGroup.hidden = false;
        els.passkeySection.hidden = false;
        els.passkeyExplain.textContent = '请输入在本机终端运行 webui-auth init 生成的一次性初始化口令并绑定 PassKey。';
        els.passkeyLabelGroup.hidden = false;
        els.btnPasskeyLogin.hidden = true;
        els.btnPasskeyEnroll.hidden = false;
        els.passwordForm.hidden = true;
      }
      return;
    }

    if (auth.mode === 'password') {
      setPill(els.authStatusPill, els.authStatusDot, els.authStatusLabel, 'warn', '等待强密码验证');
      els.authPolicyBadge.textContent = '强密码认证';
      els.authTitle.textContent = '使用强密码解锁本机控制台';
      els.authSubtitle.textContent = '未检测到 PassKey 认证器，当前由工作区外私有存储的强密码散列保护。';
      els.authCliGuide.hidden = true;
      els.setupTicketGroup.hidden = true;
      els.passkeySection.hidden = true;
      els.passwordForm.hidden = false;
      els.labelInputPassword.textContent = '输入强密码';
      els.inputPassword.setAttribute('autocomplete', 'current-password');
      els.passwordConfirmGroup.hidden = true;
      els.btnPasswordSubmit.textContent = '验证强密码解锁';
      els.btnSetupHardwarePasskey.hidden = true;
      return;
    }

    setPill(els.authStatusPill, els.authStatusDot, els.authStatusLabel, 'locked', '需要本机终端初始化');
    els.authPolicyBadge.textContent = forcePasskey ? '待绑定 PassKey' : '待设置强密码';
    els.authTitle.textContent = '初始化 WebUI 本机访问凭据';
    els.authSubtitle.textContent = '初始化凭据必须经由本机终端授权，防止容器或远端 Agent 抢先设定权限。';
    els.authCliGuide.hidden = false;
    els.setupTicketGroup.hidden = false;

    if (forcePasskey) {
      els.passkeySection.hidden = false;
      els.passkeyExplain.textContent = '当前设备或浏览器支持 PassKey，按策略强制注册 PassKey（不支持退回仅密码模式）。';
      els.passkeyLabelGroup.hidden = false;
      els.btnPasskeyLogin.hidden = true;
      els.btnPasskeyEnroll.hidden = false;
      els.passwordForm.hidden = true;
    } else {
      els.passkeySection.hidden = true;
      els.passwordForm.hidden = false;
      els.labelInputPassword.textContent = '设置强密码（≥ 14 位）';
      els.inputPassword.setAttribute('autocomplete', 'new-password');
      els.passwordConfirmGroup.hidden = false;
      els.btnPasswordSubmit.textContent = '保存强密码并启用控制台';
      els.btnSetupHardwarePasskey.hidden = !window.PublicKeyCredential;
    }
  }

  function makePill(text, cls = 'meta-pill') {
    const el = document.createElement('span');
    el.className = cls;
    el.textContent = text;
    return el;
  }

  function getFilteredTools(snap) {
    const tools = snap?.capabilities?.effectiveTools || [];
    const q = toolSearchQuery.trim().toLowerCase();
    return tools.filter(tool => {
      if (!matchesToolGroupFilter(tool, activeToolGroup)) return false;
      if (!q) return true;
      if (tool.name.toLowerCase().includes(q)) return true;
      if ((tool.title || '').toLowerCase().includes(q)) return true;
      if ((tool.description || '').toLowerCase().includes(q)) return true;
      return (tool.parameters || []).some(p => p.name.toLowerCase().includes(q));
    });
  }

  function buildCollapsibleSection(id, title, badgeText, renderBody) {
    const isOpen = expandedSections.has(id);
    const card = document.createElement('section');
    card.className = 'tool-section-card';
    card.setAttribute('data-section', id);
    card.setAttribute('data-open', isOpen ? 'true' : 'false');

    const trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.className = 'tool-section-trigger';
    trigger.setAttribute('aria-expanded', isOpen ? 'true' : 'false');

    const left = document.createElement('span');
    left.className = 'tool-section-title-wrap';
    left.appendChild(createChevronSvg());
    const t = document.createElement('span');
    t.className = 'tool-section-title';
    t.textContent = title;
    left.appendChild(t);

    trigger.append(left, makePill(badgeText, 'meta-pill'));
    trigger.addEventListener('click', () => {
      if (expandedSections.has(id)) expandedSections.delete(id);
      else expandedSections.add(id);
      lastRenderSig.tools = '';
      if (latestSnapshot) {
        renderToolExplorer(latestSnapshot);
        els.toolDetailPane.querySelector('.tool-section-card[data-section="' + id + '"] .tool-section-trigger')?.focus();
      }
    });
    card.appendChild(trigger);

    if (isOpen) {
      const body = document.createElement('div');
      body.className = 'tool-section-body';
      renderBody(body);
      card.appendChild(body);
    }
    return card;
  }

  function renderToolExplorer(snap) {
    const filtered = getFilteredTools(snap);
    const allTools = snap?.capabilities?.effectiveTools || [];
    let selected = filtered.find(t => t.name === selectedToolName) || filtered[0] || allTools.find(t => t.name === selectedToolName) || allTools[0];
    if (selected) selectedToolName = selected.name;

    const toolSig = JSON.stringify({
      activeToolGroup,
      toolSearchQuery,
      selectedToolName,
      pendingMutation,
      expanded: [...expandedSections].sort(),
      allowOutbound: Boolean(snap?.sandbox?.allowOutbound),
      configAllowExec: Boolean(snap?.sandbox?.configAllowExec),
      caps: { r: snap?.capabilities?.fileRead, w: snap?.capabilities?.fileWrite, e: snap?.capabilities?.allowExec, err: snap?.capabilities?.error },
      tools: allTools,
    });
    if (toolSig === lastRenderSig.tools) return;
    lastRenderSig.tools = toolSig;

    els.toolGrid.replaceChildren();
    els.toolsEmpty.hidden = filtered.length > 0;

    for (const tool of filtered) {
      const st = tool.stats || {};
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'catalog-item' + (tool.name === selectedToolName ? ' is-selected' : '') + (tool.enabled ? '' : ' is-disabled');
      btn.dataset.catalogTool = tool.name;
      btn.setAttribute('aria-pressed', tool.name === selectedToolName ? 'true' : 'false');

      const kind = document.createElement('span');
      kind.className = 'kind-badge kind-' + (tool.kind || 'CTX');
      kind.textContent = tool.kind || 'MCP';

      const textWrap = document.createElement('span');
      textWrap.className = 'catalog-item-text';

      const topRow = document.createElement('span');
      topRow.className = 'catalog-item-top';
      const nameEl = document.createElement('span');
      nameEl.className = 'catalog-item-name';
      nameEl.textContent = tool.name;
      const countEl = document.createElement('span');
      countEl.className = 'catalog-item-count';
      countEl.textContent = st.totalCalls > 0 ? st.totalCalls + ' 次' : (tool.enabled ? '就绪' : '停用');
      topRow.append(nameEl, countEl);

      const roleEl = document.createElement('span');
      roleEl.className = 'catalog-item-role';
      roleEl.textContent = tool.title || '';

      textWrap.append(topRow, roleEl);
      btn.append(kind, textWrap);
      btn.addEventListener('click', () => {
        selectedToolName = tool.name;
        lastRenderSig.tools = '';
        if (latestSnapshot) {
          renderToolExplorer(latestSnapshot);
          for (const el of els.toolGrid.querySelectorAll('.catalog-item')) {
            if (el.dataset.catalogTool === tool.name) { el.focus(); break; }
          }
        }
      });
      els.toolGrid.appendChild(btn);
    }

    els.toolDetailPane.replaceChildren();
    if (!selected) return;

    const st = selected.stats || {};
    const hero = document.createElement('section');
    hero.className = 'tool-hero-card';

    const badges = document.createElement('div');
    badges.className = 'tool-hero-badges';
    const heroKind = document.createElement('span');
    heroKind.className = 'kind-badge kind-' + (selected.kind || 'CTX');
    heroKind.textContent = selected.kind || 'MCP';
    badges.appendChild(heroKind);
    badges.appendChild(makePill(selected.enabled ? '策略已启用' : '当前已拦截关闭', 'meta-pill ' + (selected.enabled ? 'is-on' : 'is-off')));
    badges.appendChild(makePill(selected.requiresApproval ? '需本机 WebUI / 终端批准' : '控制面免人工审批', 'meta-pill ' + (selected.requiresApproval ? 'is-brand' : '')));
    for (const scope of selected.scopes || []) {
      badges.appendChild(makePill('scope:' + scope, 'meta-pill is-brand'));
    }
    const ann = selected.annotations || {};
    badges.appendChild(makePill(ann.readOnlyHint ? 'readOnlyHint' : '写/执行变更', 'meta-pill'));
    if (ann.destructiveHint) badges.appendChild(makePill('destructiveHint', 'meta-pill is-warn'));
    if (selected.external) {
      badges.appendChild(makePill('非容器沙盒（宿主 stdio / 外部 HTTP）', 'meta-pill is-warn'));
    } else if (ann.openWorldHint) {
      badges.appendChild(makePill(snap.sandbox?.allowOutbound ? 'outbound 需批准' : '强制 --network none', 'meta-pill'));
    }

    const titleRow = document.createElement('div');
    titleRow.className = 'tool-hero-title-row';
    const titleMeta = document.createElement('div');
    titleMeta.className = 'tool-hero-title-meta';
    const h3 = document.createElement('h3');
    h3.className = 'tool-hero-name';
    h3.textContent = selected.name;
    const roleSpan = document.createElement('span');
    roleSpan.className = 'tool-hero-role';
    roleSpan.textContent = selected.title || '';
    titleMeta.append(h3, roleSpan);

    const parentOn = isToolParentGroupEnabled(snap, selected);
    const heroControl = document.createElement('div');
    heroControl.className = 'tool-hero-control';
    const heroSwitch = document.createElement('button');
    heroSwitch.type = 'button';
    heroSwitch.className = 'switch';
    heroSwitch.id = 'tool-hero-switch';
    heroSwitch.setAttribute('data-tool-hero-switch', selected.name);
    heroSwitch.setAttribute('role', 'switch');
    heroSwitch.setAttribute('aria-checked', selected.enabled ? 'true' : 'false');
    heroSwitch.setAttribute('aria-label', '独立开关 ' + selected.name);
    heroSwitch.disabled = pendingMutation || (!parentOn && !selected.individuallyDisabled);
    const heroTrack = document.createElement('span');
    heroTrack.className = 'switch-track';
    const heroThumb = document.createElement('span');
    heroThumb.className = 'switch-thumb';
    heroTrack.appendChild(heroThumb);
    const heroText = document.createElement('span');
    heroText.className = 'switch-text';
    heroText.textContent = selected.individuallyDisabled
      ? '单工具已关'
      : (!parentOn ? (selected.external ? '服务已停用' : '总开关限制') : (selected.enabled ? '已启用' : '已停用'));
    heroSwitch.append(heroTrack, heroText);
    heroSwitch.addEventListener('click', () => {
      if (pendingMutation) return;
      if (selected.external) {
        postControlAction('/api/mcp-servers/toggle', {
          id: selected.serverId,
          toolName: selected.rawToolName,
          enabled: Boolean(selected.individuallyDisabled),
        });
      } else {
        postControlAction('/api/capabilities', {
          tools: { [selected.name]: Boolean(selected.individuallyDisabled) },
        });
      }
    });
    heroControl.appendChild(heroSwitch);
    titleRow.append(titleMeta, heroControl);

    const sig = document.createElement('div');
    sig.className = 'tool-signature-bar';
    const paramSig = (selected.parameters || []).map(p => (p.required ? p.name : p.name + '?') + ': ' + p.type).join(', ');
    sig.textContent = 'tools/call -> ' + selected.name + '({ ' + paramSig + ' })';

    const desc = document.createElement('div');
    desc.className = 'tool-desc-box';
    desc.textContent = selected.description || '—';

    const statBar = document.createElement('div');
    statBar.className = 'tool-hero-badges';
    statBar.appendChild(makePill('近期调用 ' + (st.totalCalls || 0) + ' 次', 'meta-pill'));
    statBar.appendChild(makePill('成功 ' + (st.successCount || 0), 'meta-pill is-on'));
    if (st.failureCount > 0) statBar.appendChild(makePill('失败 ' + st.failureCount, 'meta-pill is-off'));
    if (st.blockedCount > 0) statBar.appendChild(makePill('策略拦截 ' + st.blockedCount, 'meta-pill is-warn'));
    if (st.pendingApprovalCount > 0) statBar.appendChild(makePill('待批 ' + st.pendingApprovalCount, 'meta-pill is-warn'));
    if (st.lastUsedAt) {
      const ms = st.lastDurationMs !== null && st.lastDurationMs !== undefined ? ' · ' + st.lastDurationMs + 'ms' : '';
      statBar.appendChild(makePill('最近 ' + formatTime(st.lastUsedAt) + ms, 'meta-pill'));
    }

    hero.append(badges, titleRow, sig, desc, statBar);
    if (!selected.enabled && selected.disabledReason) {
      const blockedBox = document.createElement('div');
      blockedBox.className = 'tool-blocked-note';
      blockedBox.textContent = '当前拦截说明：' + selected.disabledReason;
      hero.appendChild(blockedBox);
    }
    els.toolDetailPane.appendChild(hero);

    // Collapsible Section 1: 参数契约 Schema
    els.toolDetailPane.appendChild(buildCollapsibleSection(
      'params',
      '参数契约与字段校验 Schema',
      (selected.parameters?.length || 0) + ' 个字段',
      body => {
        if (!selected.parameters || !selected.parameters.length) {
          const noneNote = document.createElement('div');
          noneNote.className = 'mono-muted';
          noneNote.textContent = '无入参字段（接受空对象 {}）。';
          body.appendChild(noneNote);
          return;
        }
        const paramList = document.createElement('div');
        paramList.className = 'param-list';
        for (const param of selected.parameters) {
          const row = document.createElement('div');
          row.className = 'param-row';
          const head = document.createElement('div');
          head.className = 'param-head';
          const pCode = document.createElement('code');
          pCode.textContent = param.name;
          head.appendChild(pCode);
          head.appendChild(makePill(param.type, 'meta-pill'));
          const req = document.createElement('span');
          req.className = 'req-pill ' + (param.required ? 'is-req' : 'is-opt');
          req.textContent = param.required ? '必填' : '可选';
          head.appendChild(req);
          if (Array.isArray(param.enumValues) && param.enumValues.length) {
            head.appendChild(makePill('enum: ' + param.enumValues.join(' | '), 'meta-pill is-brand'));
          }
          if (param.minimum !== null || param.maximum !== null) {
            const rangeLabel = (param.minimum !== null ? param.minimum : '-∞') + ' .. ' + (param.maximum !== null ? param.maximum : '+∞');
            head.appendChild(makePill('range: ' + rangeLabel, 'meta-pill'));
          }
          const pDesc = document.createElement('p');
          pDesc.className = 'param-desc';
          pDesc.textContent = param.description || '—';
          row.append(head, pDesc);
          paramList.appendChild(row);
        }
        body.appendChild(paramList);
      },
    ));

    // Collapsible Section 2: 能力边界与安全守卫
    els.toolDetailPane.appendChild(buildCollapsibleSection(
      'bounds',
      '能力保证与硬性安全守卫',
      selected.external ? '外部 MCP 契约' : '沙盒契约',
      body => {
        const boundsGrid = document.createElement('div');
        boundsGrid.className = 'tool-bounds-grid';
        const makeBoundCard = (title, items, cls) => {
          const box = document.createElement('div');
          box.className = 'bound-card ' + cls;
          const h3El = document.createElement('h3');
          h3El.textContent = title;
          const ul = document.createElement('ul');
          ul.className = 'bound-list';
          for (const line of items || []) {
            const li = document.createElement('li');
            li.textContent = line;
            ul.appendChild(li);
          }
          box.append(h3El, ul);
          return box;
        };
        boundsGrid.append(
          makeBoundCard('工具能力与运行时保证', selected.canDo, 'bound-card-ok'),
          makeBoundCard('硬性限额与安全守卫', selected.limits, 'bound-card-limit'),
        );
        body.appendChild(boundsGrid);
      },
    ));

    // Collapsible Section 3: JSON-RPC 调用骨架
    if (selected.sampleCall) {
      els.toolDetailPane.appendChild(buildCollapsibleSection(
        'sample',
        'MCP JSON-RPC 2.0 调用结构示例',
        '结构模板',
        body => {
          const sampleBox = document.createElement('div');
          sampleBox.className = 'sample-box';
          const sampleHead = document.createElement('div');
          sampleHead.className = 'sample-box-head';
          const sampleLabel = document.createElement('span');
          sampleLabel.textContent = '标准请求结构（占位参数，不含任何宿主私密内容）';
          const copyBtn = document.createElement('button');
          copyBtn.type = 'button';
          copyBtn.className = 'action-btn action-sm';
          copyBtn.textContent = '复制结构';
          const jsonText = JSON.stringify(selected.sampleCall, null, 2);
          copyBtn.addEventListener('click', async () => {
            try {
              if (!navigator.clipboard?.writeText) throw new Error();
              await navigator.clipboard.writeText(jsonText);
              copyBtn.textContent = '已复制';
              setTimeout(() => { copyBtn.textContent = '复制结构'; }, 1400);
            } catch {
              copyBtn.textContent = '复制受限';
              setTimeout(() => { copyBtn.textContent = '复制结构'; }, 1400);
            }
          });
          sampleHead.append(sampleLabel, copyBtn);
          const pre = document.createElement('pre');
          pre.className = 'sample-pre';
          pre.textContent = jsonText;
          sampleBox.append(sampleHead, pre);
          body.appendChild(sampleBox);
        },
      ));
    }
  }

  function renderCapabilities(snap) {
    const caps = snap.capabilities;
    const hasPolicyError = Boolean(caps.error);
    const readOn = Boolean(caps.fileRead);
    const writeOn = Boolean(caps.fileWrite);
    const execOn = Boolean(caps.allowExec);
    const execConfigEnabled = snap.sandbox.configAllowExec === true;

    let posture = 'full';
    let mountText = '读写挂载 readwrite';
    let mountClass = 'mount-badge is-readwrite';
    if (hasPolicyError || (!readOn && !writeOn)) {
      posture = 'locked';
      mountText = hasPolicyError ? '策略校验异常 · 已锁定' : '文件读写已禁用';
      mountClass = 'mount-badge is-locked';
    } else if (readOn && !writeOn) {
      posture = 'readonly';
      mountText = '仅只读模式 · readonly';
      mountClass = 'mount-badge is-readonly';
    } else if (!readOn && writeOn) {
      posture = 'readonly';
      mountText = '禁止读文件 · 仅追加/新建受控';
      mountClass = 'mount-badge is-readonly';
    }

    els.panelCapabilities.setAttribute('data-posture', posture);
    els.mountBadge.textContent = mountText;
    els.mountBadge.className = mountClass;

    els.presetFull.classList.toggle('active', readOn && writeOn && !hasPolicyError);
    els.presetReadonly.classList.toggle('active', readOn && !writeOn && !hasPolicyError);
    els.presetLocked.classList.toggle('active', !readOn && !writeOn && !hasPolicyError);
    els.presetFull.disabled = pendingMutation;
    els.presetReadonly.disabled = pendingMutation;
    els.presetLocked.disabled = pendingMutation;

    setSwitchState(els.toggleRead, els.labelRead, readOn);
    setSwitchState(els.toggleWrite, els.labelWrite, writeOn);
    setSwitchState(els.toggleExec, els.labelExec, execOn, !execConfigEnabled);

    els.policyUpdatedAt.textContent = caps.updatedAt
      ? '策略更新于 ' + formatTime(caps.updatedAt)
      : '使用默认启用策略';

    const tools = caps.effectiveTools || [];
    const builtinTools = tools.filter(t => !t.external);
    const extTools = tools.filter(t => t.external);
    const enabledCount = tools.filter(t => t.enabled).length;
    els.kpiToolsRatio.textContent = enabledCount + ' / ' + tools.length;
    els.kpiToolsSub.textContent =
      '读:' + (readOn ? '开' : '关') + ' · 写:' + (writeOn ? '开' : '关') + ' · 执行:' + (execOn ? '开' : '关') +
      (extTools.length ? ' · 第三方 MCP:' + extTools.filter(t => t.enabled).length + '/' + extTools.length : '');
    els.navBadgeTools.textContent = enabledCount + '/' + tools.length;

    els.kpiMountMode.textContent = (hasPolicyError || (!readOn && !writeOn)) ? 'locked' : (caps.mountMode || posture);
    els.kpiMountSub.textContent = snap.sandbox?.allowOutbound ? '出站需逐条审批' : '强制隔离 --network none';

    els.overviewToolChips.replaceChildren();
    for (const tool of builtinTools) {
      const parentOn = isToolParentGroupEnabled(snap, tool);
      const item = document.createElement('div');
      item.className = 'tool-chip-item ' + (tool.enabled ? 'is-on' : 'is-off');

      const linkBtn = document.createElement('button');
      linkBtn.type = 'button';
      linkBtn.className = 'tool-chip-link';
      linkBtn.title = '查看 ' + tool.name + ' 详细信息';
      const dot = document.createElement('span');
      dot.className = 'dot ' + (tool.enabled ? 'dot-online' : 'dot-locked');
      const label = document.createElement('span');
      label.className = 'tool-chip-name';
      label.textContent = tool.name;
      linkBtn.append(dot, label);
      if (tool.individuallyDisabled) {
        const stateTag = document.createElement('span');
        stateTag.className = 'tool-chip-state';
        stateTag.textContent = '单停';
        linkBtn.appendChild(stateTag);
      } else if (!parentOn) {
        const stateTag = document.createElement('span');
        stateTag.className = 'tool-chip-state';
        stateTag.textContent = '组关';
        linkBtn.appendChild(stateTag);
      }
      linkBtn.addEventListener('click', () => {
        openToolInExplorer(tool.name);
      });

      const toggleBtn = document.createElement('button');
      toggleBtn.type = 'button';
      toggleBtn.className = 'mini-switch';
      toggleBtn.setAttribute('data-tool-toggle', tool.name);
      toggleBtn.setAttribute('role', 'switch');
      toggleBtn.setAttribute('aria-checked', tool.enabled ? 'true' : 'false');
      toggleBtn.setAttribute('aria-label', '独立开关 ' + tool.name);
      toggleBtn.title = !parentOn && !tool.individuallyDisabled
        ? '需先开启上方对应能力总开关'
        : (tool.individuallyDisabled ? '点击恢复启用 ' + tool.name : '点击单独停用 ' + tool.name);
      toggleBtn.disabled = pendingMutation || (!parentOn && !tool.individuallyDisabled);
      const track = document.createElement('span');
      track.className = 'switch-track';
      const thumb = document.createElement('span');
      thumb.className = 'switch-thumb';
      track.appendChild(thumb);
      toggleBtn.appendChild(track);
      toggleBtn.addEventListener('click', ev => {
        ev.stopPropagation();
        if (pendingMutation) return;
        postControlAction('/api/capabilities', {
          tools: { [tool.name]: Boolean(tool.individuallyDisabled) },
        });
      });

      item.append(linkBtn, toggleBtn);
      els.overviewToolChips.appendChild(item);
    }

    renderToolExplorer(snap);
  }

  function renderSecurityPanels(snap) {
    const sec = snap.security || {};
    const passkeys = Array.isArray(sec.passkeys) ? sec.passkeys : [];
    const busy = pendingMutation;

    if (els.passkeysCount) els.passkeysCount.textContent = String(passkeys.length);
    if (els.passkeyHwNote) {
      if (!window.PublicKeyCredential) {
        const portPart = window.location.port ? ':' + window.location.port : '';
        els.passkeyHwNote.hidden = false;
        els.passkeyHwNote.textContent = '当前浏览器未检测到 WebAuthn 接口；请使用现代浏览器访问 http://localhost' + portPart + ' 绑定 PassKey。';
      } else {
        els.passkeyHwNote.hidden = true;
        els.passkeyHwNote.textContent = '';
      }
    }

    if (els.passkeysList) {
      els.passkeysList.replaceChildren();
      if (!passkeys.length) {
        const li = document.createElement('li');
        li.className = 'is-empty';
        li.textContent = '尚未绑定任何 PassKey；当前处于强密码认证保护模式。';
        els.passkeysList.appendChild(li);
      } else {
        for (const pk of passkeys) {
          const li = document.createElement('li');
          li.className = 'passkey-item';

          const meta = document.createElement('div');
          meta.className = 'passkey-meta';

          const titleRow = document.createElement('div');
          titleRow.className = 'passkey-title-row';
          const nameSpan = document.createElement('span');
          nameSpan.textContent = pk.label || 'Local PassKey';
          titleRow.appendChild(nameSpan);
          if (pk.alg !== undefined && pk.alg !== null) {
            const algNames = { '-7': 'ES256', '-8': 'EdDSA', '-35': 'ES384', '-257': 'RS256' };
            titleRow.appendChild(makePill(algNames[String(pk.alg)] || ('ALG ' + pk.alg), 'meta-pill is-brand'));
          }
          if (Array.isArray(pk.transports) && pk.transports.length) {
            titleRow.appendChild(makePill(pk.transports.join('/'), 'meta-pill'));
          }

          const sub = document.createElement('div');
          sub.className = 'passkey-sub';
          const createdTxt = pk.createdAt ? '创建 ' + formatTime(pk.createdAt) : '已绑定';
          const usedTxt = pk.lastUsedAt ? ' · 最近验证 ' + formatTime(pk.lastUsedAt) : '';
          sub.textContent = 'ID ' + (pk.idShort || '—') + ' · ' + createdTxt + usedTxt;

          meta.append(titleRow, sub);

          const delBtn = document.createElement('button');
          delBtn.type = 'button';
          delBtn.className = 'action-btn action-sm action-danger';
          delBtn.setAttribute('data-passkey-delete', pk.id);
          delBtn.textContent = '移除密钥';
          delBtn.disabled = busy || passkeys.length <= 1;
          delBtn.title = passkeys.length <= 1
            ? '至少保留 1 枚活跃 PassKey（请先添加备用密钥再移除）'
            : '移除该 PassKey 凭据';
          delBtn.addEventListener('click', () => {
            if (pendingMutation) return;
            showSecurityFeedback(null, '');
            postControlAction('/api/auth/passkey/delete', { credentialId: pk.id })
              .then(out => {
                if (out?.ok) showSecurityFeedback('ok', '已移除 PassKey：' + (pk.label || pk.idShort));
              });
          });

          li.append(meta, delBtn);
          els.passkeysList.appendChild(li);
        }
      }
    }

    if (els.passkeyEnrollBar && els.btnAddPasskey) {
      els.passkeyEnrollBar.hidden = !window.PublicKeyCredential;
      els.btnAddPasskey.disabled = busy;
    }

    if (els.securityModePill) {
      if (sec.mode === 'passkey') {
        els.securityModePill.textContent = sec.hostPasskeySupported ? '硬件强制 PassKey' : 'PassKey 已启用';
        els.securityModePill.className = 'meta-pill is-brand';
      } else {
        els.securityModePill.textContent = '强密码认证模式';
        els.securityModePill.className = 'meta-pill is-on';
      }
    }

    const lockPasswordMode = Boolean(sec.hardwarePasskeyEnforced || sec.hostPasskeySupported || (sec.mode === 'passkey' && browserUvpa));
    if (els.passwordLockedNotice && els.securityPasswordForm) {
      if (lockPasswordMode) {
        els.passwordLockedNotice.hidden = false;
        els.securityPasswordForm.hidden = true;
        if (els.passwordLockedReason) {
          els.passwordLockedReason.textContent = (sec.hardwarePasskeyEnforced || sec.hostPasskeySupported)
            ? '宿主机硬件/系统已原生支持或曾强制启用 PassKey'
            : '当前浏览器支持平台用户验证 PassKey（UVPA）';
        }
      } else if (sec.mode === 'passkey') {
        els.passwordLockedNotice.hidden = true;
        els.securityPasswordForm.hidden = false;
        els.securityPasswordForm.dataset.submitMode = 'switch';
        if (els.securityCurrentPasswordGroup) els.securityCurrentPasswordGroup.hidden = true;
        if (els.inputCurrentPassword) els.inputCurrentPassword.required = false;
        if (els.labelResetPassword) {
          els.labelResetPassword.textContent = '设置强密码并切换为纯密码认证（≥ 14 位，须含大小写、数字与特殊符号，将清空已绑定 PassKey）';
        }
        if (els.btnResetPassword) {
          els.btnResetPassword.textContent = '切换为强密码认证';
          els.btnResetPassword.disabled = busy;
        }
      } else {
        els.passwordLockedNotice.hidden = true;
        els.securityPasswordForm.hidden = false;
        els.securityPasswordForm.dataset.submitMode = 'reset';
        if (els.securityCurrentPasswordGroup) els.securityCurrentPasswordGroup.hidden = false;
        if (els.inputCurrentPassword) els.inputCurrentPassword.required = true;
        if (els.labelResetPassword) {
          els.labelResetPassword.textContent = '新强密码（≥ 14 位，须同时含大写、小写、数字与特殊符号）';
        }
        if (els.btnResetPassword) {
          els.btnResetPassword.textContent = '重置强密码';
          els.btnResetPassword.disabled = busy;
        }
      }
    }
  }

  function renderHostFacts(snap) {
    const d = snap.daemon;
    const s = snap.sandbox;
    const sys = snap.systemd;
    const sec = snap.security || {};

    if (sec.mode === 'passkey') {
      setPill(els.authStatusPill, els.authStatusDot, els.authStatusLabel, 'online', 'PassKey 已认证（' + (sec.passkeyCount || 1) + ' 枚密钥）');
      els.btnUpgradePasskey.hidden = true;
    } else {
      setPill(els.authStatusPill, els.authStatusDot, els.authStatusLabel, 'online', '强密码已认证');
      els.btnUpgradePasskey.hidden = !window.PublicKeyCredential;
    }
    els.btnUpgradePasskey.disabled = pendingMutation;

    if (d.supervisorAlive && d.connectorAlive && d.online) {
      setPill(els.gatewayPill, els.gatewayDot, els.gatewayLabel, 'online', '网关在线');
    } else if (d.supervisorAlive && d.connectorAlive) {
      setPill(els.gatewayPill, els.gatewayDot, els.gatewayLabel, 'warn', '连接器运行 · 等待网关');
    } else {
      setPill(els.gatewayPill, els.gatewayDot, els.gatewayLabel, 'locked', '后台连接器已停止');
    }

    if (!sys.supported) {
      setPill(els.systemdPill, els.systemdDot, els.systemdLabel, 'neutral', '非 systemd 平台');
    } else if (sys.enabled && sys.active) {
      setPill(els.systemdPill, els.systemdDot, els.systemdLabel, 'online', '自启动已启用');
    } else if (sys.enabled) {
      setPill(els.systemdPill, els.systemdDot, els.systemdLabel, 'warn', '自启动已启用（未运行）');
    } else {
      setPill(els.systemdPill, els.systemdDot, els.systemdLabel, 'neutral', '未启用自启动');
    }

    els.factWorkspace.textContent = s.workspace ? s.workspace + ' -> /workspace' : '未配置工作区';
    const probeSummary = d.gatewayReachable
      ? '（探针 HTTP ' + d.gatewayStatus + '，' + d.gatewayLatencyMs + ' ms）'
      : d.gatewayStatus
        ? '（探针 HTTP ' + d.gatewayStatus + '）'
        : '（网关当前不可达）';
    els.factOrigin.textContent = (d.origin || '未配置') + ' ' + probeSummary;

    const supText = d.supervisorAlive ? '守护 PID ' + d.supervisorPid : '守护已停';
    const connText = d.connectorAlive ? '连接器 PID ' + d.connectorPid : '连接器已停';
    els.factPids.textContent = supText + ' · ' + connText;

    if (sys.supported) {
      els.factSystemd.textContent =
        'bridge: ' + (sys.bridgeEnabled ? '开机启用' : '未启用') + '/' + (sys.bridgeActive ? '运行中' : '停止') +
        ' · webui: ' + (sys.webuiEnabled ? '开机启用' : '未启用') +
        ' · linger: ' + (sys.linger ? '已开启' : '未开启');
    } else {
      els.factSystemd.textContent = '仅 Linux 支持 user systemd 检查';
    }

    els.factImage.textContent = (s.imageShort || '未固定') + ' · Docker ' + (s.dockerContext || '-') + (s.dockerOk ? '（正常）' : '（不可达）');
    els.factSecurity.textContent = 'Node ' + (s.nodeVersion || '-') + ' · ' + (s.secretBackend || '-') + ' · 逐条审批=' + (s.requireLocalApproval ? '强制' : '异常');

    const busy = pendingMutation;
    const anyRunning = Boolean(d.supervisorAlive || d.connectorAlive);
    els.btnStart.disabled = busy || anyRunning;
    els.btnStop.disabled = busy || !anyRunning;
    els.btnRestart.disabled = busy;

    if (els.toggleAutostart && els.labelAutostart && els.autostartDesc) {
      if (!sys.supported) {
        els.toggleAutostart.setAttribute('aria-checked', 'false');
        els.toggleAutostart.disabled = true;
        els.labelAutostart.textContent = '不支持';
        els.autostartDesc.textContent = '当前操作系统不使用 Linux systemd --user 托管开机自启动。';
      } else {
        const autoOn = Boolean(sys.enabled);
        els.toggleAutostart.setAttribute('aria-checked', autoOn ? 'true' : 'false');
        els.toggleAutostart.disabled = busy || !sys.installed;
        els.labelAutostart.textContent = autoOn ? '已开启' : '已关闭';
        els.autostartDesc.textContent = !sys.installed
          ? '未检测到 systemd user unit；请先在本机运行 ~/.agentdock-bridge/service install 安装服务单元。'
          : 'bridge=' + (sys.bridgeEnabled ? '自启' : '关闭') + ' · webui=' + (sys.webuiEnabled ? '自启' : '关闭') + ' · linger=' + (sys.linger ? '已开' : '未开') + '（关闭自启不影响当前 WebUI 会话）。';
      }
    }

    const tabScoped = (sec.sessionPersistence || 'tab') !== 'browser';
    if (els.toggleTabAuth && els.labelTabAuth && els.sessionPolicyDesc) {
      els.toggleTabAuth.setAttribute('aria-checked', tabScoped ? 'true' : 'false');
      els.toggleTabAuth.disabled = busy;
      els.labelTabAuth.textContent = tabScoped ? '已启用' : '跨标签';
      els.sessionPolicyDesc.textContent = tabScoped
        ? '当前为标签页临时会话：关闭当前标签或打开新标签时，必须重新通过 PassKey / 强密码验证解锁。'
        : '当前允许浏览器会话持续（最多 12 小时 / 空闲 30 分钟内关闭重开免重验）；关闭本开关前请确认本机环境可信。';
    }

    renderSecurityPanels(snap);
  }

  function renderTelemetry(snap) {
    const approvals = snap.approvals || { pendingCount: 0, items: [] };
    const pendingCount = approvals.pendingCount || 0;
    els.approvalsCount.textContent = String(pendingCount);
    els.navBadgeAudit.hidden = pendingCount === 0;
    els.navBadgeAudit.textContent = String(pendingCount);
    els.navBadgeAudit.classList.toggle('has-alert', pendingCount > 0);

    if (activeReview && activeReview.dialog?.open) {
      const liveItem = (approvals.items || []).find(i => i.id === activeReview.id);
      if (liveItem?.expiresAt) {
        activeReview.expiresAt = new Date(liveItem.expiresAt).getTime();
      }
      const expired = Number.isFinite(activeReview.expiresAt) && Date.now() >= activeReview.expiresAt;
      if (!liveItem || liveItem.alreadyApproved || expired) {
        activeReview.approveBtn.disabled = true;
        activeReview.statusEl.textContent = !liveItem || expired
          ? '该审批请求已过期或已被移除，无法批准。'
          : '该请求已被签发一次性批准（等待消费）。';
      }
    }

    const approvalsSig = JSON.stringify({ pendingMutation, items: approvals.items || [] });
    if (approvalsSig !== lastRenderSig.approvals) {
      lastRenderSig.approvals = approvalsSig;
      els.approvalsList.replaceChildren();
      if (!approvals.items || !approvals.items.length) {
        const li = document.createElement('li');
        li.className = 'is-empty';
        li.textContent = '当前没有等待本机放行的请求。';
        els.approvalsList.appendChild(li);
      } else {
        for (const item of approvals.items) {
          if (!item.id) {
            const li = document.createElement('li');
            const left = document.createElement('span');
            left.textContent = item.tool + ' · ' + item.idShort + ' · 仅终端 approve';
            const right = document.createElement('span');
            right.className = 'approval-countdown';
            right.setAttribute('data-expires-at', item.expiresAt || '');
            const sec = Math.max(0, Math.round((new Date(item.expiresAt).getTime() - Date.now()) / 1000));
            right.textContent = Number.isFinite(sec) ? sec + 's 后过期' : '待批';
            li.append(left, right);
            els.approvalsList.appendChild(li);
            continue;
          }

          const li = document.createElement('li');
          li.className = 'approval-card';
          li.setAttribute('data-approval-id', item.id);

          const head = document.createElement('div');
          head.className = 'approval-card-head';

          const titleWrap = document.createElement('div');
          titleWrap.className = 'approval-card-title';
          titleWrap.appendChild(makePill(item.tool, 'meta-pill is-brand'));
          titleWrap.appendChild(makePill('#' + item.idShort, 'meta-pill'));
          if (item.clientId) {
            titleWrap.appendChild(makePill(item.clientId, 'meta-pill'));
          }

          const sec = Math.max(0, Math.round((new Date(item.expiresAt).getTime() - Date.now()) / 1000));
          const statusPill = makePill(
            item.alreadyApproved ? '已签发一次性批准（等待执行）' : (Number.isFinite(sec) ? sec + 's 后过期' : '待批准'),
            'meta-pill ' + (item.alreadyApproved ? 'is-on' : 'is-warn'),
          );
          if (!item.alreadyApproved) {
            statusPill.classList.add('approval-countdown');
            statusPill.setAttribute('data-expires-at', item.expiresAt || '');
          }
          head.append(titleWrap, statusPill);

          const actions = document.createElement('div');
          actions.className = 'approval-actions';

          const approveBtn = document.createElement('button');
          approveBtn.type = 'button';
          approveBtn.className = 'action-btn action-primary action-sm';
          approveBtn.setAttribute('data-review-id', item.id);
          approveBtn.textContent = item.alreadyApproved ? '已批准（等待消费）' : '复核完整请求';
          approveBtn.disabled = pendingMutation || Boolean(item.alreadyApproved);
          approveBtn.addEventListener('click', () => {
            if (pendingMutation) return;
            openApprovalReview(item.id);
          });

          const rejectBtn = document.createElement('button');
          rejectBtn.type = 'button';
          rejectBtn.className = 'action-btn action-danger action-sm';
          rejectBtn.setAttribute('data-reject-id', item.id);
          rejectBtn.textContent = '拒绝并移除';
          rejectBtn.disabled = pendingMutation;
          rejectBtn.addEventListener('click', () => {
            if (pendingMutation) return;
            postControlAction('/api/approvals/reject', { id: item.id });
          });

          actions.append(approveBtn, rejectBtn);
          li.append(head, actions);
          els.approvalsList.appendChild(li);
        }
      }
    } else {
      updateApprovalCountdowns();
    }

    const containers = snap.sandbox?.runningContainers || [];
    els.containersCount.textContent = String(containers.length);
    els.containersList.replaceChildren();
    if (!containers.length) {
      const li = document.createElement('li');
      li.className = 'is-empty';
      li.textContent = snap.sandbox?.dockerOk ? '当前无运行中一次性沙盒容器。' : 'Docker 守护进程不可达。';
      els.containersList.appendChild(li);
    } else {
      for (const container of containers) {
        const li = document.createElement('li');
        const left = document.createElement('span');
        left.textContent = container.id;
        const right = document.createElement('span');
        right.textContent = container.status;
        li.append(left, right);
        els.containersList.appendChild(li);
      }
    }

    const tel = snap.telemetry || {};
    const totalCalls = tel.totalAuditCalls || 0;
    els.kpiAuditTotal.textContent = totalCalls + ' 次执行';
    els.kpiAuditSub.textContent = '成功 ' + (tel.totalAuditSuccess || 0) + ' · 失败 ' + (tel.totalAuditFailed || 0) + ' · 拦截 ' + (tel.totalBlocked || 0);

    els.kpiLiveQueue.textContent = pendingCount + ' 待批 / ' + containers.length + ' 容器';
    els.kpiLiveSub.textContent = pendingCount > 0
      ? '点击前往「实时审计」页批准或拒绝'
      : '无积压待审批操作（点击看实时审计）';
  }

  function renderEventMetaGrid(item) {
    const metaLabels = [
      ['reason', '结果代码'],
      ['durationMs', '执行耗时'],
      ['mountMode', '挂载姿态'],
      ['mode', '运行模式'],
      ['network', '容器网络'],
      ['exitCode', '退出码'],
      ['bytesRead', '文件读取字节数'],
      ['bytesWritten', '文件写入字节数'],
      ['stdoutBytes', '标准输出字节数'],
      ['stderrBytes', '标准错误字节数'],
      ['outputBytes', '输出字节数'],
      ['serverId', '第三方 MCP'],
      ['timedOut', '超时'],
      ['cancelled', '取消'],
      ['tool', '涉及工具'],
      ['capability', '触发能力'],
      ['approvalIdShort', '审批短码'],
      ['route', '连接路由'],
      ['status', 'HTTP 状态'],
      ['code', '状态码'],
      ['outcome', '结果标识'],
      ['jobIdPrefix', '容器作业号'],
    ];
    const meta = item.meta || {};
    const grid = document.createElement('div');
    grid.className = 'trace-grid';

    const appendKv = (k, v) => {
      const cell = document.createElement('div');
      cell.className = 'trace-kv';
      const sk = document.createElement('span');
      sk.className = 'trace-k';
      sk.textContent = k;
      const sv = document.createElement('span');
      sv.className = 'trace-v';
      sv.textContent = v;
      cell.append(sk, sv);
      grid.appendChild(cell);
    };

    appendKv('时间戳', item.time || '—');
    appendKv('记录来源', item.source === 'audit' ? '沙盒审计 audit.jsonl' : '连接器状态 connector.log');
    for (const [key, label] of metaLabels) {
      if (meta[key] === undefined || meta[key] === null || meta[key] === '') continue;
      let val = String(meta[key]);
      if (key === 'durationMs') val = val + ' ms';
      if (typeof meta[key] === 'boolean') val = meta[key] ? '是' : '否';
      appendKv(label, val);
    }
    return grid;
  }

  function renderEvents(snap) {
    const list = (snap.events || []).filter(item => activeFilter === 'all' || item.source === activeFilter);
    const eventsSig = JSON.stringify({ activeFilter, expanded: [...expandedEvents].sort(), list });
    if (eventsSig === lastRenderSig.events) return;
    lastRenderSig.events = eventsSig;

    els.eventsSummaryPill.textContent = list.length + ' 条记录';
    els.eventsTbody.replaceChildren();
    els.eventsEmpty.hidden = list.length > 0;
    for (const item of list) {
      const eventKey = item.key || (item.source + ':' + item.time + ':' + item.name);
      const isOpen = expandedEvents.has(eventKey);

      const tr = document.createElement('tr');
      tr.className = 'event-row';
      tr.setAttribute('data-open', isOpen ? 'true' : 'false');

      const tdChev = document.createElement('td');
      const btnChev = document.createElement('button');
      btnChev.type = 'button';
      btnChev.className = 'event-expand-btn';
      btnChev.dataset.eventKey = eventKey;
      btnChev.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
      btnChev.setAttribute('aria-label', '展开或收起事件详情');
      btnChev.appendChild(createChevronSvg());
      tdChev.appendChild(btnChev);

      const tdTime = document.createElement('td');
      tdTime.className = 'mono';
      tdTime.textContent = formatTime(item.time);

      const tdSrc = document.createElement('td');
      tdSrc.textContent = item.source === 'audit' ? '审计' : '连接';

      const tdName = document.createElement('td');
      tdName.className = 'mono';
      tdName.textContent = item.name || '—';

      const tdDetail = document.createElement('td');
      const tag = document.createElement('span');
      tag.className = 'tag ' + (item.tone === 'ok' ? 'tag-ok' : item.tone === 'err' ? 'tag-err' : 'tag-info');
      tag.textContent = item.label || '记录';
      tdDetail.appendChild(tag);
      if (item.detail) {
        const span = document.createElement('span');
        span.className = 'mono-muted';
        span.textContent = ' ' + item.detail;
        tdDetail.appendChild(span);
      }

      tr.append(tdChev, tdTime, tdSrc, tdName, tdDetail);
      tr.addEventListener('click', ev => {
        const restoreBtnFocus = ev.target instanceof Element && Boolean(ev.target.closest('.event-expand-btn'));
        if (expandedEvents.has(eventKey)) expandedEvents.delete(eventKey);
        else expandedEvents.add(eventKey);
        lastRenderSig.events = '';
        if (latestSnapshot) {
          renderEvents(latestSnapshot);
          if (restoreBtnFocus) {
            for (const el of els.eventsTbody.querySelectorAll('.event-expand-btn')) {
              if (el.dataset.eventKey === eventKey) { el.focus(); break; }
            }
          }
        }
      });
      els.eventsTbody.appendChild(tr);

      if (isOpen) {
        const dtr = document.createElement('tr');
        dtr.className = 'event-detail-row';
        const dtd = document.createElement('td');
        dtd.colSpan = 5;
        dtd.appendChild(renderEventMetaGrid(item));
        dtr.appendChild(dtd);
        els.eventsTbody.appendChild(dtr);
      }
    }
  }

  function setMcpEditorMode(mode) {
    const isJson = mode === 'json';
    if (els.mcpModeForm) {
      els.mcpModeForm.classList.toggle('active', !isJson);
      els.mcpModeForm.setAttribute('aria-selected', !isJson ? 'true' : 'false');
    }
    if (els.mcpModeJson) {
      els.mcpModeJson.classList.toggle('active', isJson);
      els.mcpModeJson.setAttribute('aria-selected', isJson ? 'true' : 'false');
    }
    if (els.mcpServerForm) els.mcpServerForm.hidden = isJson;
    if (els.mcpImportForm) els.mcpImportForm.hidden = !isJson;
  }

  function syncMcpTransportFields() {
    const transport = els.selectMcpTransport?.value || 'stdio';
    const isHttp = transport === 'http';
    if (els.mcpStdioFields) els.mcpStdioFields.hidden = isHttp;
    if (els.mcpHttpFields) els.mcpHttpFields.hidden = !isHttp;
    for (const el of [els.inputMcpCommand, els.inputMcpArgs, els.inputMcpCwd, els.inputMcpEnv]) {
      if (el) el.disabled = isHttp;
    }
    for (const el of [els.inputMcpUrl, els.inputMcpHeaders]) {
      if (el) el.disabled = !isHttp;
    }
    if (els.mcpReplaceSecretsRow) {
      els.mcpReplaceSecretsRow.hidden = !(editingMcpServerId && editingMcpHasSecrets && transport === editingMcpTransport);
    }
  }

  function renderExistingSecretChips(container, keys, markedSet, labelPrefix) {
    if (!container) return;
    container.replaceChildren();
    if (!keys || !keys.length) {
      container.hidden = true;
      return;
    }
    container.hidden = false;
    for (const key of keys) {
      const chip = document.createElement('span');
      const marked = markedSet.has(key);
      chip.className = 'secret-chip' + (marked ? ' is-marked-delete' : '');
      const txt = document.createElement('span');
      txt.textContent = labelPrefix + key;
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'secret-chip-remove';
      btn.dataset.secretKey = key;
      btn.textContent = marked ? '撤销' : '×';
      btn.title = marked ? '取消删除该密钥' : '保存时移除该已存密钥';
      btn.setAttribute('aria-label', marked ? '撤销删除已存密钥 ' + key : '保存时移除已存密钥 ' + key);
      btn.addEventListener('click', () => {
        if (markedSet.has(key)) markedSet.delete(key);
        else markedSet.add(key);
        renderExistingSecretChips(container, keys, markedSet, labelPrefix);
        for (const el of container.querySelectorAll('.secret-chip-remove')) {
          if (el.dataset.secretKey === key) { el.focus(); break; }
        }
      });
      chip.append(txt, btn);
      container.appendChild(chip);
    }
  }

  function resetMcpForm() {
    editingMcpServerId = null;
    editingMcpTransport = null;
    editingMcpHasSecrets = false;
    editingMcpInitialUrl = '';
    editingMcpUrlRedacted = false;
    markedDeleteEnvKeys.clear();
    markedDeleteHeaderKeys.clear();
    if (els.mcpEditorTitle) els.mcpEditorTitle.textContent = '新增第三方 MCP 服务';
    if (els.inputMcpId) { els.inputMcpId.value = ''; els.inputMcpId.readOnly = false; }
    if (els.inputMcpName) els.inputMcpName.value = '';
    if (els.inputMcpDesc) els.inputMcpDesc.value = '';
    if (els.selectMcpTransport) els.selectMcpTransport.value = 'stdio';
    if (els.inputMcpTimeout) els.inputMcpTimeout.value = '30000';
    if (els.inputMcpCommand) els.inputMcpCommand.value = '';
    if (els.inputMcpArgs) els.inputMcpArgs.value = '';
    if (els.inputMcpCwd) els.inputMcpCwd.value = '';
    if (els.inputMcpEnv) els.inputMcpEnv.value = '';
    if (els.inputMcpUrl) els.inputMcpUrl.value = '';
    if (els.inputMcpHeaders) els.inputMcpHeaders.value = '';
    if (els.inputMcpReplaceSecrets) els.inputMcpReplaceSecrets.checked = false;
    if (els.inputMcpEnabled) els.inputMcpEnabled.checked = true;
    renderExistingSecretChips(els.mcpExistingEnvKeys, [], markedDeleteEnvKeys, '已存 ');
    renderExistingSecretChips(els.mcpExistingHeaderKeys, [], markedDeleteHeaderKeys, '已存 ');
    syncMcpTransportFields();
  }

  function formatArgsForEditor(args) {
    if (!Array.isArray(args) || !args.length) return '';
    const needsJson = args.some(a =>
      typeof a !== 'string' ||
      a === '' ||
      a.trim() !== a ||
      a.startsWith('[') ||
      /[\\r\\n]/.test(a),
    );
    return needsJson ? JSON.stringify(args) : args.join('\\n');
  }

  function loadServerIntoMcpForm(srv, { keepFeedback = false, focus = true, preserveUrlInput = false } = {}) {
    setMcpEditorMode('form');
    editingMcpServerId = srv.id;
    editingMcpTransport = srv.transport || 'stdio';
    editingMcpHasSecrets = Boolean(srv.hasSecrets || (srv.envKeys || []).length || (srv.headerKeys || []).length);
    markedDeleteEnvKeys.clear();
    markedDeleteHeaderKeys.clear();
    if (els.mcpEditorTitle) els.mcpEditorTitle.textContent = '编辑第三方 MCP：' + srv.name;
    if (els.inputMcpId) { els.inputMcpId.value = srv.id; els.inputMcpId.readOnly = true; }
    if (els.inputMcpName) els.inputMcpName.value = srv.name || '';
    if (els.inputMcpDesc) els.inputMcpDesc.value = srv.description || '';
    if (els.selectMcpTransport) els.selectMcpTransport.value = srv.transport || 'stdio';
    if (els.inputMcpTimeout) els.inputMcpTimeout.value = String(srv.timeoutMs || 30000);
    if (els.inputMcpCommand) els.inputMcpCommand.value = srv.command || '';
    if (els.inputMcpArgs) els.inputMcpArgs.value = formatArgsForEditor(srv.args);
    if (els.inputMcpCwd) els.inputMcpCwd.value = srv.cwd || '';
    if (els.inputMcpEnv) els.inputMcpEnv.value = '';
    const currentUrlInput = els.inputMcpUrl ? els.inputMcpUrl.value.trim() : '';
    if (preserveUrlInput && currentUrlInput) {
      editingMcpUrlRedacted = Boolean(srv.urlRedacted) && currentUrlInput === (srv.url || '');
      editingMcpInitialUrl = currentUrlInput;
    } else {
      editingMcpUrlRedacted = Boolean(srv.urlRedacted);
      editingMcpInitialUrl = srv.url || '';
      if (els.inputMcpUrl) els.inputMcpUrl.value = srv.url || '';
    }
    if (els.inputMcpHeaders) els.inputMcpHeaders.value = '';
    if (els.inputMcpReplaceSecrets) els.inputMcpReplaceSecrets.checked = false;
    if (els.inputMcpEnabled) els.inputMcpEnabled.checked = Boolean(srv.enabled);
    renderExistingSecretChips(els.mcpExistingEnvKeys, srv.envKeys || [], markedDeleteEnvKeys, '已存 ');
    renderExistingSecretChips(els.mcpExistingHeaderKeys, srv.headerKeys || [], markedDeleteHeaderKeys, '已存 ');
    syncMcpTransportFields();
    if (!keepFeedback) showMcpFeedback(null, '');
    if (focus) els.inputMcpName?.focus();
  }

  function parseArgsInput(raw) {
    const trimmed = String(raw || '').trim();
    if (!trimmed) return [];
    if (trimmed.startsWith('[')) {
      const parsed = JSON.parse(trimmed);
      if (!Array.isArray(parsed)) throw new Error('JSON 参数格式必须是字符串数组。');
      return parsed.map(String);
    }
    return trimmed.split(/\\r?\\n/).map(line => line.trim()).filter(Boolean);
  }

  function parseKvLines(raw, separator, label) {
    const out = Object.create(null);
    const lines = String(raw || '').split(/\\r?\\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith('#')) continue;
      const idx = line.indexOf(separator);
      if (idx <= 0) {
        throw new Error(label + ' 第 ' + (i + 1) + ' 行格式错误（每行应为 键' + separator + '值）。');
      }
      const key = line.slice(0, idx).trim();
      const val = line.slice(idx + 1).trim();
      if (!key) throw new Error(label + ' 第 ' + (i + 1) + ' 行键名不能为空。');
      out[key] = val;
    }
    return out;
  }

  function renderMcpServers(snap) {
    const reg = snap?.mcpServers || { serverCount: 0, enabledServerCount: 0, totalToolCount: 0, enabledToolCount: 0, items: [], error: null };
    const items = Array.isArray(reg.items) ? reg.items : [];
    const busy = pendingMutation;

    if (pendingDeleteMcpId && !items.some(s => s.id === pendingDeleteMcpId)) {
      clearPendingDeleteMcp();
    }

    if (els.btnMcpNew) els.btnMcpNew.disabled = busy;
    if (els.btnMcpSaveProbe) els.btnMcpSaveProbe.disabled = busy;
    if (els.btnMcpSaveOnly) els.btnMcpSaveOnly.disabled = busy;
    if (els.btnMcpImportProbe) els.btnMcpImportProbe.disabled = busy;
    if (els.btnMcpImportOnly) els.btnMcpImportOnly.disabled = busy;

    if (els.navBadgeMcp) {
      els.navBadgeMcp.hidden = reg.serverCount === 0;
      els.navBadgeMcp.textContent = String(reg.enabledServerCount || 0);
    }
    if (els.mcpSummaryServers) {
      els.mcpSummaryServers.textContent = reg.enabledServerCount + ' / ' + reg.serverCount + ' 个服务已启用';
    }
    if (els.mcpSummaryTools) {
      els.mcpSummaryTools.textContent = reg.enabledToolCount + ' / ' + reg.totalToolCount + ' 个聚合工具可用';
    }
    if (els.mcpServersCount) els.mcpServersCount.textContent = String(items.length);
    if (els.mcpRegistryError) {
      if (reg.error) {
        els.mcpRegistryError.hidden = false;
        els.mcpRegistryError.textContent = '第三方 MCP 配置文件校验异常（已安全闭锁加载）：' + reg.error;
      } else {
        els.mcpRegistryError.hidden = true;
        els.mcpRegistryError.textContent = '';
      }
    }

    if (!els.mcpServersList) return;
    const mcpSig = JSON.stringify({ busy, pendingDeleteMcpId, items });
    if (mcpSig === lastRenderSig.mcp) return;
    lastRenderSig.mcp = mcpSig;

    els.mcpServersList.replaceChildren();
    if (!items.length) {
      const empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.textContent = '尚未接入任何第三方 MCP 服务。可在右侧表单新增 stdio / HTTP MCP，或直接粘贴 Claude / Cursor 标准 mcpServers JSON 一键导入。';
      els.mcpServersList.appendChild(empty);
      return;
    }

    for (const srv of items) {
      const card = document.createElement('div');
      card.className = 'mcp-server-card' + (srv.enabled ? '' : ' is-disabled');
      card.setAttribute('data-mcp-server-id', srv.id);

      const head = document.createElement('div');
      head.className = 'mcp-server-head';

      const titleWrap = document.createElement('div');
      titleWrap.className = 'mcp-server-title-wrap';
      const titleRow = document.createElement('div');
      titleRow.className = 'mcp-server-title-row';

      const nameEl = document.createElement('span');
      nameEl.className = 'mcp-server-name';
      nameEl.textContent = srv.name;
      titleRow.appendChild(nameEl);
      titleRow.appendChild(makePill(srv.transport === 'http' ? 'HTTP' : 'STDIO', 'meta-pill is-brand'));
      titleRow.appendChild(makePill(srv.id, 'meta-pill'));

      if (srv.lastProbeOk === true) {
        titleRow.appendChild(makePill('已同步 ' + srv.toolCount + ' 工具', 'meta-pill is-on'));
      } else if (srv.lastProbeOk === false) {
        titleRow.appendChild(makePill('连接失败', 'meta-pill is-off'));
      } else {
        titleRow.appendChild(makePill('待探测', 'meta-pill is-warn'));
      }
      titleWrap.appendChild(titleRow);

      if (srv.description) {
        const descEl = document.createElement('div');
        descEl.className = 'mcp-server-desc';
        descEl.textContent = srv.description;
        titleWrap.appendChild(descEl);
      }

      const srvSwitch = document.createElement('button');
      srvSwitch.type = 'button';
      srvSwitch.className = 'switch';
      srvSwitch.setAttribute('role', 'switch');
      srvSwitch.setAttribute('aria-checked', srv.enabled ? 'true' : 'false');
      srvSwitch.setAttribute('aria-label', '启用或停用第三方 MCP 服务 ' + srv.name);
      srvSwitch.setAttribute('data-mcp-server-toggle', srv.id);
      srvSwitch.disabled = busy;
      const track = document.createElement('span');
      track.className = 'switch-track';
      const thumb = document.createElement('span');
      thumb.className = 'switch-thumb';
      track.appendChild(thumb);
      const swText = document.createElement('span');
      swText.className = 'switch-text';
      swText.textContent = srv.enabled ? '开启' : '停用';
      srvSwitch.append(track, swText);
      srvSwitch.addEventListener('click', () => {
        if (pendingMutation) return;
        postControlAction('/api/mcp-servers/toggle', { id: srv.id, enabled: !srv.enabled });
      });

      head.append(titleWrap, srvSwitch);

      const cmdBox = document.createElement('div');
      cmdBox.className = 'mcp-server-cmd';
      if (srv.transport === 'stdio') {
        const argStr = (srv.args || []).join(' ');
        cmdBox.textContent = srv.command + (argStr ? ' ' + argStr : '') + (srv.cwd ? '   [cwd: ' + srv.cwd + ']' : '');
      } else {
        cmdBox.textContent = srv.url;
      }

      card.append(head, cmdBox);

      const secretKeys = srv.transport === 'stdio' ? (srv.envKeys || []) : (srv.headerKeys || []);
      if (secretKeys.length) {
        const chips = document.createElement('div');
        chips.className = 'mcp-secret-chips';
        const prefix = srv.transport === 'stdio' ? 'ENV ' : 'HEADER ';
        for (const key of secretKeys) {
          const chip = document.createElement('span');
          chip.className = 'secret-chip';
          chip.textContent = prefix + key + ' (已私密保存 · 不回显)';
          chips.appendChild(chip);
        }
        card.appendChild(chips);
      }

      if (srv.lastProbeOk === false && srv.lastProbeError) {
        const errBox = document.createElement('div');
        errBox.className = 'mcp-server-error';
        errBox.textContent = '最近探测失败：' + srv.lastProbeError;
        card.appendChild(errBox);
      }

      const actions = document.createElement('div');
      actions.className = 'mcp-server-actions';

      const probeBtn = document.createElement('button');
      probeBtn.type = 'button';
      probeBtn.className = 'action-btn action-sm action-primary';
      probeBtn.setAttribute('data-mcp-probe', srv.id);
      probeBtn.textContent = '测试连接并同步工具';
      probeBtn.disabled = busy;
      probeBtn.addEventListener('click', async () => {
        if (pendingMutation) return;
        showMcpFeedback(null, '');
        const out = await postControlAction('/api/mcp-servers/probe', { id: srv.id }, {
          onError: msg => showMcpFeedback('err', msg),
        });
        if (out?.probe) {
          if (out.probe.ok) {
            showMcpFeedback('ok', '服务「' + srv.name + '」连接成功（' + out.probe.latencyMs + 'ms），已同步 ' + (out.probe.tools?.length || 0) + ' 个 MCP 工具。');
          } else {
            showMcpFeedback('err', '服务「' + srv.name + '」探测失败：' + (out.probe.error || '未知错误'));
          }
        }
      });

      const editBtn = document.createElement('button');
      editBtn.type = 'button';
      editBtn.className = 'action-btn action-sm';
      editBtn.setAttribute('data-mcp-edit', srv.id);
      editBtn.textContent = '编辑配置';
      editBtn.disabled = busy;
      editBtn.addEventListener('click', () => loadServerIntoMcpForm(srv));

      const isConfirming = pendingDeleteMcpId === srv.id;
      const delBtn = document.createElement('button');
      delBtn.type = 'button';
      delBtn.className = 'action-btn action-sm action-danger';
      delBtn.setAttribute('data-mcp-delete', srv.id);
      delBtn.textContent = isConfirming ? '确认移除？' : '删除';
      delBtn.disabled = busy;
      delBtn.addEventListener('click', async () => {
        if (pendingMutation) return;
        if (pendingDeleteMcpId !== srv.id) {
          clearPendingDeleteMcp();
          pendingDeleteMcpId = srv.id;
          pendingDeleteMcpTimer = setTimeout(() => {
            if (pendingDeleteMcpId === srv.id) {
              clearPendingDeleteMcp();
              lastRenderSig.mcp = '';
              if (latestSnapshot) renderMcpServers(latestSnapshot);
            }
          }, 6000);
          lastRenderSig.mcp = '';
          if (latestSnapshot) {
            renderMcpServers(latestSnapshot);
            els.mcpServersList.querySelector('[data-mcp-delete="' + srv.id + '"]')?.focus();
          }
          return;
        }
        clearPendingDeleteMcp();
        const out = await postControlAction('/api/mcp-servers/delete', { id: srv.id }, {
          onError: msg => showMcpFeedback('err', msg),
        });
        if (out?.ok) {
          mcpDrawerOpenState.delete(srv.id);
          if (editingMcpServerId === srv.id) resetMcpForm();
          showMcpFeedback('ok', '已移除第三方 MCP 服务「' + srv.name + '」。');
        }
      });

      actions.append(probeBtn, editBtn, delBtn);
      if (isConfirming) {
        const cancelDelBtn = document.createElement('button');
        cancelDelBtn.type = 'button';
        cancelDelBtn.className = 'action-btn action-sm';
        cancelDelBtn.textContent = '取消';
        cancelDelBtn.disabled = busy;
        cancelDelBtn.addEventListener('click', () => {
          clearPendingDeleteMcp();
          lastRenderSig.mcp = '';
          if (latestSnapshot) {
            renderMcpServers(latestSnapshot);
            els.mcpServersList.querySelector('[data-mcp-delete="' + srv.id + '"]')?.focus();
          }
        });
        actions.appendChild(cancelDelBtn);
      }

      const metaNote = document.createElement('span');
      metaNote.className = 'mono-muted action-quiet';
      metaNote.textContent = '超时 ' + Math.round((srv.timeoutMs || 30000) / 1000) + 's' + (srv.lastProbeAt ? ' · 探测 ' + formatTime(srv.lastProbeAt) : '');

      actions.appendChild(metaNote);
      card.appendChild(actions);

      if (Array.isArray(srv.tools) && srv.tools.length) {
        const drawer = document.createElement('details');
        drawer.className = 'mcp-tools-drawer';
        drawer.open = mcpDrawerOpenState.has(srv.id) ? mcpDrawerOpenState.get(srv.id) : (srv.tools.length <= 6);
        drawer.addEventListener('toggle', () => {
          mcpDrawerOpenState.set(srv.id, drawer.open);
        });
        const summary = document.createElement('summary');
        summary.textContent = '已发现工具列表（' + srv.enabledToolCount + ' / ' + srv.toolCount + ' 已开启，可逐项启停）';
        drawer.appendChild(summary);

        const list = document.createElement('div');
        list.className = 'mcp-tools-list';
        for (const tool of srv.tools) {
          const row = document.createElement('div');
          row.className = 'mcp-tool-row';

          const info = document.createElement('div');
          info.className = 'mcp-tool-info';
          const linkBtn = document.createElement('button');
          linkBtn.type = 'button';
          linkBtn.className = 'tool-chip-link';
          const dot = document.createElement('span');
          dot.className = 'dot ' + (tool.enabled ? 'dot-online' : 'dot-locked');
          const nameSpan = document.createElement('span');
          nameSpan.className = 'tool-chip-name';
          nameSpan.textContent = tool.fullName;
          linkBtn.append(dot, nameSpan);
          linkBtn.addEventListener('click', () => {
            openToolInExplorer(tool.fullName);
          });
          info.appendChild(linkBtn);
          if (tool.description) {
            const descSpan = document.createElement('span');
            descSpan.className = 'mcp-tool-desc';
            descSpan.textContent = tool.description;
            info.appendChild(descSpan);
          }

          const mini = document.createElement('button');
          mini.type = 'button';
          mini.className = 'mini-switch';
          mini.setAttribute('role', 'switch');
          mini.setAttribute('aria-checked', tool.enabled ? 'true' : 'false');
          mini.setAttribute('aria-label', '开关工具 ' + tool.fullName);
          mini.setAttribute('data-mcp-tool-toggle', tool.fullName);
          mini.disabled = busy || (!srv.enabled && !tool.individuallyDisabled);
          const mTrack = document.createElement('span');
          mTrack.className = 'switch-track';
          const mThumb = document.createElement('span');
          mThumb.className = 'switch-thumb';
          mTrack.appendChild(mThumb);
          mini.appendChild(mTrack);
          mini.addEventListener('click', () => {
            if (pendingMutation) return;
            postControlAction('/api/mcp-servers/toggle', {
              id: srv.id,
              toolName: tool.name,
              enabled: Boolean(tool.individuallyDisabled),
            });
          });

          row.append(info, mini);
          list.appendChild(row);
        }
        drawer.appendChild(list);
        card.appendChild(drawer);
      }

      els.mcpServersList.appendChild(card);
    }
  }

  async function submitMcpSave({ probe }) {
    showError(null);
    showMcpFeedback(null, '');
    try {
      const transport = els.selectMcpTransport.value;
      const payload = {
        id: els.inputMcpId.value.trim(),
        name: els.inputMcpName.value.trim(),
        description: els.inputMcpDesc.value.trim(),
        transport,
        timeoutMs: Number(els.inputMcpTimeout.value || 30000),
        enabled: Boolean(els.inputMcpEnabled.checked),
        probe: Boolean(probe),
        ...(editingMcpServerId && els.inputMcpReplaceSecrets?.checked ? { replaceSecrets: true } : {}),
      };
      let keepRedactedUrl = false;
      if (transport === 'stdio') {
        payload.command = els.inputMcpCommand.value.trim();
        payload.args = parseArgsInput(els.inputMcpArgs.value);
        payload.cwd = els.inputMcpCwd.value.trim();
        const envPatch = parseKvLines(els.inputMcpEnv.value, '=', '环境变量');
        if (Object.keys(envPatch).length) payload.env = envPatch;
        if (markedDeleteEnvKeys.size) payload.removeEnvKeys = [...markedDeleteEnvKeys];
      } else {
        const urlVal = els.inputMcpUrl.value.trim();
        keepRedactedUrl = Boolean(
          editingMcpServerId &&
          editingMcpTransport === 'http' &&
          editingMcpUrlRedacted &&
          urlVal === editingMcpInitialUrl,
        );
        if (!keepRedactedUrl) payload.url = urlVal;
        const headerPatch = parseKvLines(els.inputMcpHeaders.value, ':', '请求头');
        if (Object.keys(headerPatch).length) payload.headers = headerPatch;
        if (markedDeleteHeaderKeys.size) payload.removeHeaderKeys = [...markedDeleteHeaderKeys];
      }
      const out = await postControlAction('/api/mcp-servers/save', payload, {
        onError: msg => showMcpFeedback('err', msg),
      });
      if (!out?.ok) return;
      const savedName = out.server?.name || payload.name || payload.id;
      if (out.probe) {
        if (out.probe.ok) {
          showMcpFeedback('ok', '已保存并成功连接「' + savedName + '」（' + out.probe.latencyMs + 'ms），同步到 ' + (out.probe.tools?.length || 0) + ' 个工具。');
          resetMcpForm();
        } else {
          showMcpFeedback('err', '配置已保存，但连接探测失败（已保留表单便于继续修改）：' + (out.probe.error || '请检查命令/端点与鉴权头'));
          if (out.server) loadServerIntoMcpForm(out.server, { keepFeedback: true, focus: false, preserveUrlInput: !keepRedactedUrl });
        }
      } else {
        showMcpFeedback('ok', '第三方 MCP 配置「' + savedName + '」已保存。');
        resetMcpForm();
      }
    } catch (err) {
      showMcpFeedback('err', err?.message || '保存配置失败');
    }
  }

  async function submitMcpImport({ probe }) {
    showError(null);
    showMcpFeedback(null, '');
    const rawText = String(els.inputMcpJson?.value || '').trim();
    if (!rawText) {
      showMcpFeedback('err', '请先粘贴标准 MCP JSON 配置。');
      return;
    }
    try {
      JSON.parse(rawText);
    } catch {
      showMcpFeedback('err', '输入的 JSON 语法有误，请检查括号与逗号。');
      return;
    }
    const out = await postControlAction('/api/mcp-servers/import', { json: rawText, probe: Boolean(probe) }, {
      onError: msg => showMcpFeedback('err', msg),
    });
    if (out?.ok) {
      if (els.inputMcpJson) els.inputMcpJson.value = '';
      const ids = out.importedIds || [];
      const probeEntries = Object.entries(out.probes || {});
      const failedProbes = probeEntries.filter(([, p]) => !p?.ok);
      if (failedProbes.length) {
        const failNames = failedProbes.map(([id, p]) => id + '（' + (p?.error || '失败') + '）').join('；');
        showMcpFeedback('err', '已导入 ' + ids.length + ' 个服务，但有 ' + failedProbes.length + ' 个探测失败：' + failNames);
      } else if (probe && probeEntries.length) {
        const totalTools = probeEntries.reduce((sum, [, p]) => sum + (p?.toolCount || 0), 0);
        showMcpFeedback('ok', '成功导入并连通 ' + ids.length + ' 个第三方 MCP 服务（共同步 ' + totalTools + ' 个工具）：' + ids.join(', '));
      } else {
        showMcpFeedback('ok', '成功导入 ' + ids.length + ' 个第三方 MCP 服务：' + ids.join(', '));
      }
    }
  }

  function renderInteractiveSections(snap) {
    if (!snap) return;
    renderCapabilities(snap);
    renderHostFacts(snap);
    renderTelemetry(snap);
    renderMcpServers(snap);
  }

  function renderAll(snap) {
    latestSnapshot = snap;
    policyErrorText = snap.capabilities?.error
      ? '能力策略文件校验失败或不在工作区外（已安全锁定读写）：' + snap.capabilities.error
      : '';
    renderErrorBanner();
    renderCapabilities(snap);
    renderHostFacts(snap);
    renderTelemetry(snap);
    renderEvents(snap);
    renderMcpServers(snap);
  }

  async function openApprovalReview(id) {
    if (activeReview?.dialog) {
      if (activeReview.dialog.open && activeReview.id === id) return;
      const prev = activeReview.dialog;
      activeReview = null;
      try { if (prev.open) prev.close(); } catch {}
      prev.remove();
    }
    const pendingItem = (latestSnapshot?.approvals?.items || []).find(i => i.id === id);
    const initialExpiresAt = pendingItem?.expiresAt ? new Date(pendingItem.expiresAt).getTime() : NaN;
    const dialog = document.createElement('dialog');
    dialog.className = 'approval-review';
    dialog.setAttribute('aria-labelledby', 'review-heading');
    const heading = document.createElement('h2');
    heading.id = 'review-heading';
    heading.textContent = '复核完整请求';
    const request = document.createElement('pre');
    request.className = 'approval-args-pre';
    request.tabIndex = 0;
    request.textContent = '正在读取请求…';
    const digest = document.createElement('p');
    digest.className = 'approval-digest';
    const actions = document.createElement('div');
    actions.className = 'approval-actions';
    const cancel = document.createElement('button');
    cancel.type = 'button';
    cancel.className = 'action-btn';
    cancel.textContent = '关闭';
    cancel.autofocus = true;
    cancel.addEventListener('click', () => dialog.close());
    const approve = document.createElement('button');
    approve.type = 'button';
    approve.className = 'action-btn action-primary';
    approve.textContent = '批准执行一次';
    approve.disabled = true;
    actions.append(cancel, approve);
    dialog.append(heading, request, digest, actions);
    document.body.append(dialog);
    let userClosed = false;
    activeReview = { id, dialog, approveBtn: approve, statusEl: digest, expiresAt: initialExpiresAt };
    dialog.addEventListener('close', () => {
      userClosed = true;
      if (activeReview?.dialog === dialog) activeReview = null;
      dialog.remove();
    }, { once: true });
    dialog.showModal();

    try {
      const review = await apiPost('/api/approvals/review', { id });
      if (!dialog.open || activeReview?.dialog !== dialog) return;
      request.textContent = review.requestText;
      const liveItem = (latestSnapshot?.approvals?.items || []).find(i => i.id === id);
      const itemExpiresAt = liveItem?.expiresAt ? new Date(liveItem.expiresAt).getTime() : initialExpiresAt;
      activeReview.expiresAt = itemExpiresAt;
      if (!liveItem || liveItem.alreadyApproved || (Number.isFinite(itemExpiresAt) && Date.now() >= itemExpiresAt)) {
        approve.disabled = true;
        digest.textContent = !liveItem || (Number.isFinite(itemExpiresAt) && Date.now() >= itemExpiresAt)
          ? '该审批请求已过期或已被移除，无法批准。'
          : '该请求已被签发一次性批准（等待消费）。';
        return;
      }
      digest.textContent = '复核摘要 ' + review.digest;
      approve.disabled = pendingMutation;
      approve.addEventListener('click', () => {
        if (pendingMutation) return;
        approve.disabled = true;
        dialog.close();
        postControlAction('/api/approvals/approve', { id, digest: review.digest });
      }, { once: true });
    } catch (err) {
      const msg = err?.message || '无法读取待批请求';
      if (dialog.open) request.textContent = msg;
      else if (!userClosed || err?.isAuthError) showError(msg);
    }
  }

  async function apiPost(endpoint, payload) {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: authHeaders({
        'content-type': 'application/json',
        'x-agentdock-csrf': csrfToken,
      }),
      body: JSON.stringify(payload),
    });
    const body = await response.json().catch(() => ({}));
    const isAuthFailure =
      (response.status === 401 && !PRE_AUTH_ENDPOINTS.has(endpoint)) ||
      (response.status === 403 && body.code === 'AUTH_CONFIG_ERROR');
    if (isAuthFailure) {
      setTabToken('');
      await refreshAuthAndBoot();
      const err = new Error(body.error || '会话已过期或标签页认证失效，请重新验证解锁。');
      err.isAuthError = true;
      throw err;
    }
    if (!response.ok) {
      throw new Error(body.error || '操作失败（HTTP ' + response.status + '）');
    }
    return body;
  }

  async function postControlAction(endpoint, payload, { onError } = {}) {
    showError(null);
    pendingMutation = true;
    renderInteractiveSections(latestSnapshot);
    try {
      const body = await apiPost(endpoint, payload);
      if (body.csrfToken) csrfToken = body.csrfToken;
      if (body.tabToken) {
        setTabToken(body.tabToken);
        void connectEvents();
      }
      if (body.snapshot) renderAll(body.snapshot);
      else await fetchSnapshot();
      return body;
    } catch (err) {
      const msg = err?.message || '操作失败';
      showError(msg);
      if (typeof onError === 'function') onError(msg);
      return null;
    } finally {
      pendingMutation = false;
      renderInteractiveSections(latestSnapshot);
    }
  }

  async function fetchSnapshot() {
    try {
      const response = await fetch('/api/status', {
        cache: 'no-store',
        headers: authHeaders(),
      });
      const body = await response.json().catch(() => ({}));
      if (response.status === 401 || (response.status === 403 && body.code === 'AUTH_CONFIG_ERROR')) {
        setTabToken('');
        await refreshAuthAndBoot();
        return;
      }
      if (!response.ok) throw new Error(body.error || '读取状态失败（HTTP ' + response.status + '）');
      renderAll(body);
    } catch (err) {
      showError(err?.message || '无法拉取本机状态');
    }
  }

  async function connectEvents() {
    disconnectSse();
    const ctrl = new AbortController();
    sseController = ctrl;

    const scheduleReconnect = () => {
      if (sseController !== ctrl || ctrl.signal.aborted) return;
      setPill(els.ssePill, els.sseDot, els.sseLabel, 'warn', '实时流重连中…');
      sseReconnectTimer = setTimeout(() => {
        if (sseController === ctrl && !ctrl.signal.aborted) {
          void connectEvents();
        }
      }, 1500);
    };

    try {
      const response = await fetch('/api/events', {
        cache: 'no-store',
        headers: authHeaders({ accept: 'text/event-stream' }),
        signal: ctrl.signal,
      });
      if (response.status === 401) {
        setTabToken('');
        await refreshAuthAndBoot();
        return;
      }
      if (response.status === 403) {
        const errBody = await response.json().catch(() => ({}));
        if (errBody.code === 'AUTH_CONFIG_ERROR') {
          setTabToken('');
          await refreshAuthAndBoot();
          return;
        }
        scheduleReconnect();
        return;
      }
      if (!response.ok || !response.body) {
        scheduleReconnect();
        return;
      }
      setPill(els.ssePill, els.sseDot, els.sseLabel, 'online', 'SSE 实时监控中');

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      while (sseController === ctrl && !ctrl.signal.aborted) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let boundary;
        while ((boundary = buffer.search(/\\r?\\n\\r?\\n/)) >= 0) {
          const block = buffer.slice(0, boundary);
          const sepMatch = buffer.slice(boundary).match(/^\\r?\\n\\r?\\n/);
          buffer = buffer.slice(boundary + (sepMatch ? sepMatch[0].length : 2));
          let eventName = 'message';
          const dataLines = [];
          for (const line of block.split(/\\r?\\n/)) {
            if (!line || line.startsWith(':')) continue;
            if (line.startsWith('event:')) eventName = line.slice(6).trim();
            else if (line.startsWith('data:')) dataLines.push(line.slice(5).trimStart());
          }
          if (eventName === 'status' && dataLines.length) {
            try {
              const snap = JSON.parse(dataLines.join('\\n'));
              setPill(els.ssePill, els.sseDot, els.sseLabel, 'online', 'SSE 实时监控中');
              renderAll(snap);
            } catch {}
          }
        }
      }
      if (sseController === ctrl && !ctrl.signal.aborted) scheduleReconnect();
    } catch {
      if (sseController === ctrl && !ctrl.signal.aborted) {
        fetch('/api/auth/state', { cache: 'no-store', headers: authHeaders() })
          .then(async r => {
            if (!r.ok) {
              scheduleReconnect();
              return;
            }
            const auth = await r.json();
            if (auth.csrfToken) csrfToken = auth.csrfToken;
            if (auth.error || !auth.authenticated) {
              setTabToken('');
              renderAuthGate(auth);
            } else {
              scheduleReconnect();
            }
          })
          .catch(() => scheduleReconnect());
      }
    }
  }

  async function enrollPasskeyFlow({ useOverviewLabel = false } = {}) {
    if (pendingMutation) return;
    if (ensureLocalhostForWebAuthn()) return;
    if (!window.PublicKeyCredential) {
      const portPart = window.location.port ? ':' + window.location.port : '';
      throw new Error('当前浏览器不支持 WebAuthn / PassKey，请使用支持 WebAuthn 的现代浏览器并访问 http://localhost' + portPart);
    }
    showError(null);
    showSecurityFeedback(null, '');
    pendingMutation = true;
    renderInteractiveSections(latestSnapshot);
    try {
      const setupToken = els.inputSetupTicket.value.trim();
      const overviewVal = els.inputNewPasskeyLabel ? els.inputNewPasskeyLabel.value.trim() : '';
      const gateVal = els.inputPasskeyLabel ? els.inputPasskeyLabel.value.trim() : '';
      const label = (useOverviewLabel ? (overviewVal || '备用 PassKey') : (gateVal || overviewVal || 'Local PassKey'));
      const optRes = await apiPost('/api/auth/setup/passkey/options', { setupToken });
      const pk = optRes.publicKey;
      const creationOptions = {
        ...pk,
        challenge: b64urlToBuf(pk.challenge),
        user: { ...pk.user, id: b64urlToBuf(pk.user.id) },
        excludeCredentials: (pk.excludeCredentials || []).map(item => ({
          ...item,
          id: b64urlToBuf(item.id),
        })),
      };
      const cred = await navigator.credentials.create({ publicKey: creationOptions });
      if (!cred) throw new Error('未完成 PassKey 创建。');
      const serialized = {
        id: cred.id,
        type: cred.type,
        response: {
          clientDataJSON: bufToB64url(cred.response.clientDataJSON),
          attestationObject: bufToB64url(cred.response.attestationObject),
          transports: typeof cred.response.getTransports === 'function' ? cred.response.getTransports() : [],
        },
      };
      const verified = await apiPost('/api/auth/setup/passkey/verify', {
        challengeId: optRes.challengeId,
        credential: serialized,
        label,
        setupToken,
      });
      if (verified.csrfToken) csrfToken = verified.csrfToken;
      if (verified.tabToken) setTabToken(verified.tabToken);
      els.inputSetupTicket.value = '';
      if (els.inputPasskeyLabel) els.inputPasskeyLabel.value = '';
      if (els.inputNewPasskeyLabel) els.inputNewPasskeyLabel.value = '';
      pendingMutation = false;
      await refreshAuthAndBoot();
      if (verified.authState?.authenticated) {
        showSecurityFeedback('ok', 'PassKey「' + label + '」绑定成功，当前标签页会话令牌已刷新。');
      }
    } finally {
      pendingMutation = false;
      renderInteractiveSections(latestSnapshot);
    }
  }

  async function loginPasskeyFlow() {
    if (ensureLocalhostForWebAuthn()) return;
    if (!window.PublicKeyCredential) {
      throw new Error('当前浏览器不支持 WebAuthn / PassKey。');
    }
    showError(null);
    const optRes = await apiPost('/api/auth/passkey/login/options', {});
    const pk = optRes.publicKey;
    const requestOptions = {
      ...pk,
      challenge: b64urlToBuf(pk.challenge),
      allowCredentials: (pk.allowCredentials || []).map(item => ({
        ...item,
        id: b64urlToBuf(item.id),
      })),
    };
    const assertion = await navigator.credentials.get({ publicKey: requestOptions });
    if (!assertion) throw new Error('已取消 PassKey 验证。');
    const serialized = {
      id: assertion.id,
      type: assertion.type,
      response: {
        clientDataJSON: bufToB64url(assertion.response.clientDataJSON),
        authenticatorData: bufToB64url(assertion.response.authenticatorData),
        signature: bufToB64url(assertion.response.signature),
        userHandle: assertion.response.userHandle ? bufToB64url(assertion.response.userHandle) : null,
      },
    };
    const verified = await apiPost('/api/auth/passkey/login/verify', {
      challengeId: optRes.challengeId,
      credential: serialized,
    });
    if (verified.csrfToken) csrfToken = verified.csrfToken;
    if (verified.tabToken) setTabToken(verified.tabToken);
    await refreshAuthAndBoot();
  }

  async function refreshAuthAndBoot() {
    await detectBrowserPasskeySupport();
    const res = await fetch('/api/auth/state', {
      cache: 'no-store',
      headers: authHeaders(),
    });
    const auth = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(auth.error || '无法读取认证状态（HTTP ' + res.status + '）');
    }
    currentAuthState = auth;
    if (auth.csrfToken) csrfToken = auth.csrfToken;

    if ((auth.mode === 'passkey' || auth.passkeyRequired || browserUvpa) && ensureLocalhostForWebAuthn()) {
      return;
    }

    if (auth.error || !auth.authenticated) {
      setTabToken('');
      renderAuthGate(auth);
      return;
    }

    if (auth.authMethod === 'password' && browserUvpa) {
      const upgraded = await apiPost('/api/auth/passkey/report-support', { uvpa: true });
      if (upgraded.csrfToken) csrfToken = upgraded.csrfToken;
      setTabToken('');
      renderAuthGate(upgraded.authState);
      return;
    }

    showError(null);
    setDashboardVisible(true);
    await fetchSnapshot();
    void connectEvents();
  }

  for (const btn of els.tabButtons) {
    btn.addEventListener('click', () => {
      switchTab(btn.getAttribute('data-tab') || 'overview');
    });
  }
  window.addEventListener('hashchange', () => {
    switchTab(readTabFromHash(), { syncHash: false });
  });

  els.kpiCardTools.addEventListener('click', () => switchTab('tools'));
  els.kpiCardAudit.addEventListener('click', () => switchTab('audit'));
  els.kpiCardQueue.addEventListener('click', () => switchTab('audit'));

  els.btnTheme.addEventListener('click', () => {
    applyTheme(!document.documentElement.classList.contains('dark'));
  });

  els.btnPasskeyEnroll.addEventListener('click', () => {
    enrollPasskeyFlow().catch(err => showError(err?.message || 'PassKey 注册失败'));
  });

  els.btnPasskeyLogin.addEventListener('click', () => {
    loginPasskeyFlow().catch(err => showError(err?.message || 'PassKey 验证失败'));
  });

  els.btnSetupHardwarePasskey.addEventListener('click', () => {
    enrollPasskeyFlow().catch(err => showError(err?.message || 'PassKey 注册失败'));
  });

  els.btnUpgradePasskey.addEventListener('click', () => {
    enrollPasskeyFlow({ useOverviewLabel: true }).catch(err => {
      showError(err?.message || 'PassKey 绑定失败');
      showSecurityFeedback('err', err?.message || 'PassKey 绑定失败');
    });
  });

  if (els.btnAddPasskey) {
    els.btnAddPasskey.addEventListener('click', () => {
      enrollPasskeyFlow({ useOverviewLabel: true }).catch(err => {
        showError(err?.message || 'PassKey 添加失败');
        showSecurityFeedback('err', err?.message || 'PassKey 添加失败');
      });
    });
  }

  if (els.securityPasswordForm) {
    els.securityPasswordForm.addEventListener('submit', async ev => {
      ev.preventDefault();
      if (pendingMutation) return;
      showError(null);
      showSecurityFeedback(null, '');
      const submitMode = els.securityPasswordForm.dataset.submitMode || 'reset';
      const password = els.inputResetPassword.value;
      const confirm = els.inputResetPasswordConfirm.value;
      if (password !== confirm) {
        showSecurityFeedback('err', '两次输入的新强密码不一致。');
        return;
      }
      pendingMutation = true;
      renderInteractiveSections(latestSnapshot);
      try {
        let out;
        if (submitMode === 'switch') {
          out = await apiPost('/api/auth/passkey/switch-password', { password });
        } else {
          const currentPassword = els.inputCurrentPassword.value;
          out = await apiPost('/api/auth/setup/password', { currentPassword, password });
        }
        if (out.csrfToken) csrfToken = out.csrfToken;
        if (out.tabToken) setTabToken(out.tabToken);
        els.inputCurrentPassword.value = '';
        els.inputResetPassword.value = '';
        els.inputResetPasswordConfirm.value = '';
        pendingMutation = false;
        if (out.snapshot) renderAll(out.snapshot);
        await refreshAuthAndBoot();
        showSecurityFeedback('ok', submitMode === 'switch' ? '已切换为强密码认证模式，旧会话已全部失效。' : '强密码已重置，所有旧会话已失效。');
      } catch (err) {
        showSecurityFeedback('err', err?.message || '强密码更新失败');
      } finally {
        pendingMutation = false;
        renderInteractiveSections(latestSnapshot);
      }
    });
  }

  els.passwordForm.addEventListener('submit', async ev => {
    ev.preventDefault();
    showError(null);
    try {
      const password = els.inputPassword.value;
      if (currentAuthState?.mode === 'uninitialized') {
        const confirm = els.inputPasswordConfirm.value;
        if (password !== confirm) {
          throw new Error('两次输入的强密码不一致。');
        }
        const setupToken = els.inputSetupTicket.value.trim();
        const body = await apiPost('/api/auth/setup/password', { setupToken, password });
        if (body.csrfToken) csrfToken = body.csrfToken;
        if (body.tabToken) setTabToken(body.tabToken);
        els.inputSetupTicket.value = '';
      } else {
        const body = await apiPost('/api/auth/login/password', { password });
        if (body.csrfToken) csrfToken = body.csrfToken;
        if (body.tabToken) setTabToken(body.tabToken);
      }
      els.inputPassword.value = '';
      els.inputPasswordConfirm.value = '';
      await refreshAuthAndBoot();
    } catch (err) {
      showError(err?.message || '认证失败');
    }
  });

  els.btnLogout.addEventListener('click', async () => {
    let logoutErr = null;
    disconnectSse();
    try {
      const out = await apiPost('/api/auth/logout', {});
      if (out.csrfToken) csrfToken = out.csrfToken;
    } catch (err) {
      logoutErr = err;
    }
    setTabToken('');
    clearSensitiveUiState();
    await refreshAuthAndBoot().catch(() => {});
    if (logoutErr) showError('退出请求未完整确认：' + (logoutErr?.message || '请刷新页面确认锁定状态'));
  });

  els.btnAuthRecheck.addEventListener('click', () => {
    showError(null);
    refreshAuthAndBoot().catch(err => showError(err?.message || '状态刷新失败'));
  });

  if (els.toggleAutostart) {
    els.toggleAutostart.addEventListener('click', () => {
      if (!latestSnapshot || pendingMutation) return;
      const enabled = Boolean(latestSnapshot.systemd?.enabled);
      postControlAction('/api/service', { action: enabled ? 'disable-autostart' : 'enable-autostart' }).catch(() => {});
    });
  }

  if (els.toggleTabAuth) {
    els.toggleTabAuth.addEventListener('click', () => {
      if (!latestSnapshot || pendingMutation) return;
      const cur = latestSnapshot.security?.sessionPersistence || 'tab';
      postControlAction('/api/auth/settings', { sessionPersistence: cur === 'tab' ? 'browser' : 'tab' }).catch(() => {});
    });
  }

  els.toggleRead.addEventListener('click', () => {
    if (!latestSnapshot || pendingMutation) return;
    postControlAction('/api/capabilities', { fileRead: !latestSnapshot.capabilities.fileRead });
  });

  els.toggleWrite.addEventListener('click', () => {
    if (!latestSnapshot || pendingMutation) return;
    postControlAction('/api/capabilities', { fileWrite: !latestSnapshot.capabilities.fileWrite });
  });

  els.toggleExec.addEventListener('click', () => {
    if (!latestSnapshot || pendingMutation) return;
    postControlAction('/api/capabilities', { allowExec: !latestSnapshot.capabilities.allowExec });
  });

  els.presetFull.addEventListener('click', () => {
    if (pendingMutation) return;
    postControlAction('/api/capabilities', { fileRead: true, fileWrite: true });
  });
  els.presetReadonly.addEventListener('click', () => {
    if (pendingMutation) return;
    postControlAction('/api/capabilities', { fileRead: true, fileWrite: false });
  });
  els.presetLocked.addEventListener('click', () => {
    if (pendingMutation) return;
    postControlAction('/api/capabilities', { fileRead: false, fileWrite: false });
  });

  els.btnStart.addEventListener('click', () => {
    if (pendingMutation) return;
    postControlAction('/api/service', { action: 'start' });
  });
  els.btnStop.addEventListener('click', () => {
    if (pendingMutation) return;
    postControlAction('/api/service', { action: 'stop' });
  });
  els.btnRestart.addEventListener('click', () => {
    if (pendingMutation) return;
    postControlAction('/api/service', { action: 'restart' });
  });
  els.btnRefresh.addEventListener('click', () => fetchSnapshot());

  els.toolSearch.addEventListener('input', () => {
    toolSearchQuery = els.toolSearch.value || '';
    lastRenderSig.tools = '';
    if (latestSnapshot) renderToolExplorer(latestSnapshot);
  });

  els.btnToolsExpand.addEventListener('click', () => {
    expandedSections.add('params');
    expandedSections.add('bounds');
    expandedSections.add('sample');
    lastRenderSig.tools = '';
    if (latestSnapshot) renderToolExplorer(latestSnapshot);
  });

  els.btnToolsCollapse.addEventListener('click', () => {
    expandedSections.clear();
    lastRenderSig.tools = '';
    if (latestSnapshot) renderToolExplorer(latestSnapshot);
  });

  for (const btn of els.toolFilterButtons) {
    btn.addEventListener('click', () => {
      activeToolGroup = btn.getAttribute('data-tool-group') || 'all';
      for (const other of els.toolFilterButtons) {
        const active = other === btn;
        other.classList.toggle('active', active);
        other.setAttribute('aria-pressed', active ? 'true' : 'false');
      }
      lastRenderSig.tools = '';
      if (latestSnapshot) renderToolExplorer(latestSnapshot);
    });
  }

  for (const btn of els.filterButtons) {
    btn.addEventListener('click', () => {
      activeFilter = btn.getAttribute('data-filter') || 'all';
      for (const other of els.filterButtons) {
        const active = other === btn;
        other.classList.toggle('active', active);
        other.setAttribute('aria-pressed', active ? 'true' : 'false');
      }
      lastRenderSig.events = '';
      if (latestSnapshot) renderEvents(latestSnapshot);
    });
  }

  if (els.mcpModeForm) els.mcpModeForm.addEventListener('click', () => setMcpEditorMode('form'));
  if (els.mcpModeJson) els.mcpModeJson.addEventListener('click', () => setMcpEditorMode('json'));
  if (els.selectMcpTransport) els.selectMcpTransport.addEventListener('change', syncMcpTransportFields);
  if (els.btnMcpNew) {
    els.btnMcpNew.addEventListener('click', () => {
      setMcpEditorMode('form');
      resetMcpForm();
      showMcpFeedback(null, '');
      els.inputMcpId?.focus();
    });
  }
  if (els.btnMcpCancel) {
    els.btnMcpCancel.addEventListener('click', () => {
      resetMcpForm();
      showMcpFeedback(null, '');
    });
  }
  if (els.mcpServerForm) {
    els.mcpServerForm.addEventListener('submit', ev => {
      ev.preventDefault();
      if (!pendingMutation) void submitMcpSave({ probe: true });
    });
  }
  if (els.btnMcpSaveOnly) {
    els.btnMcpSaveOnly.addEventListener('click', () => {
      if (pendingMutation) return;
      if (els.mcpServerForm && !els.mcpServerForm.reportValidity()) return;
      void submitMcpSave({ probe: false });
    });
  }
  if (els.mcpImportForm) {
    els.mcpImportForm.addEventListener('submit', ev => {
      ev.preventDefault();
      if (!pendingMutation) void submitMcpImport({ probe: true });
    });
  }
  if (els.btnMcpImportOnly) {
    els.btnMcpImportOnly.addEventListener('click', () => {
      if (!pendingMutation) void submitMcpImport({ probe: false });
    });
  }
  syncMcpTransportFields();

  refreshAuthAndBoot().catch(err => showError(err?.message || '无法连接本机 WebUI 状态接口'));
})();
`;
