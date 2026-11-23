# 指南变更记录

条目按时间先后排列，最新记录位于末尾。历史条目保留当时的仓库和验证状态；其中“无首个提交”及 MkDocs 记录不代表当前配置。当前使用与源码阅读从[指南入口](README.md)开始，运行验证按[修复与验证快照](../SECURITY-FIXES.md)中的版本和时间解释。

## 2026-10-29：建立主流程指南并对齐文档入口

- 触发：用户授权 widened docs sync；同步决策为 `foreground patch`，在共享工作树完成指定文档层。
- 建立阅读路径、主流程、代码地图、两遍源码证据与阅读质量审计；范围限定为 一个敏感 MCP 工具请求从本机待批准到一次执行。
- 保留中文 README 的现有正确内容，补齐英文入口和文档站操作；AGENTS 成为规则单一来源，CLAUDE 简短引用。
- 新建 MkDocs 1.6.1 内置主题站点；验证输出写入仓库外目录，保留业务构建产物。
- 验证：`validate_repo_docs.py --lite` 与 `mkdocs build --strict` 均退出 0；源码链接 INFO 和保留提示见独立维护报告。未跑业务测试，不代表生产验证。
- 边界：不逐项覆盖 OAuth 所有事务、Windows 安装/凭据轮换、全部文件 ACL 分支和容器生命周期；没有重新验收线上网关、Docker 镜像或已安装副本。

校验限制：因为无首个提交，校验器保留缺 SHA 提示；不得用虚构值消除提示。

Synced through：不可用（尚无首个提交，HEAD 不存在；以本次工作树调查为基线，不伪造 SHA）。

## 统一维护复核（2026-10-29）

补齐中英 README 入口、贡献与安全说明；AGENTS 为规范正文，CLAUDE 为引用入口。补充钩子检查暂存内容、提交标题及推送新增历史，保留项目原有检查；安装步骤与边界见根 SECURITY 和 CONTRIBUTING。独立站点采用 VitePress 默认主题，源码链接在网页中保留为精确路径。

仓库尚无首个提交；不伪造同步 SHA。

文档结构校验和站点构建均退出 0；共用护栏的 9 项隔离测试通过。业务测试、生产部署和远端发布未因此视为通过。大文件扫描边界见 SECURITY。

## 文档站恢复默认主题（2026-10-29）

按用户要求统一使用 VitePress 默认主题，移除额外配色、字体、圆角和入场动效。指南正文、源码定位及导航保留；文档依赖与业务依赖分开。新建站点从 MkDocs 迁移为 VitePress，既有两个 VitePress 站点使用原生主题入口。
## 2026-10-30：同步第五轮修复的使用入口与批准预算

- 触发：安全与批准流程修复；同步决策为 `foreground patch`，保留 Lite 指南范围。
- 中英 README 与指南入口改为默认 `%USERPROFILE%\.agentdock-bridge`；说明所有者及祖先路径检查、旧状态迁移后重发待批准请求，以及本轮保留连接密码与授权代次。
- 主流程补充紧凑 JSON 的最终字节预算与超限拒绝，所有参数和元数据仍完整绑定；代码地图补充只读 Docker 初始化查询策略及验证入口。
- 定向核对当前管理脚本、批准存储、连接器和 Docker 查询源码；不把文档更新当作迁移或生产验收。实际测试与部署结果见根目录 `SECURITY-FIXES.md`。
- 验证：`validate_repo_docs.py --lite` 退出 0，0 errors、1 warning；日志在 `artifacts/fix-round5/repo-docs-validation.txt`。唯一提示为缺少同步 SHA：同步时仓库尚无首个提交、HEAD 不存在，不伪造同步值。

首次签名提交建立后补齐同步锚点；后续变更仅整理换行和本条记录，不改变运行行为。

Synced through 9b483eebeeadd90b98bc01c8a71a3daf4bdbd93b

## 2026-10-30 23:27 +08:00：保留清理故障后的任务控制

- 触发：最终审查发现清理故障同时封锁已有任务查询和停止；同步决策为 `foreground patch`。
- 中英 README 和主流程说明故障时只拒绝新命令、文件操作，保留所属客户端对已有任务的查询与停止；取消和权限校验继续生效。
- 证据表记录控制分支与关闭检查的顺序。未确认清理仍按失败报告，不自动重试；容器时限和可信本机停止入口继续有效。
- 本条基于下列提交及本次修复工作树的源码核对；实际业务测试、运行副本更新与部署结果另见根目录 `SECURITY-FIXES.md`。
- 验证：`validate_repo_docs.py --lite` 退出 0，0 errors、0 warnings；日志在 `artifacts/fix-final-01/repo-docs-validation.txt`。

Synced through 5ded65ef08bb6e15b81ce1e22b7fe66dda567abb

## 2026-10-31 00:07 +08:00：规范指南并对齐验证快照

- 触发：用户要求按 `repo-docs` 规范项目文档、提交信息和双语 README；采用 widened docs sync，前台决策为 `foreground patch`，保留 Lite 加代码地图的阅读范围。
- 指南入口区分源码、运行副本、镜像和版本验收；主流程补充客户端 RPC ID 与桥接请求 ID 的用途，以及批准、预算和故障恢复的局部验证入口。
- 代码地图修正沙箱与工具运行器的符号归属，补齐本机批准、文件策略、云端入口和运维脚本的改动导航，明确文档站与维护工具不参与主请求路径。
- 证据与质量审计移除过时的当前状态断言，统一链接已有验证快照。云端管理登录恢复后的部署补验已完成，不再保留为未解决缺口；历史记录仍保留原有语境。
- 项目已获授权采用 GNU AGPLv3，指南许可说明链接根目录 `LICENSE`，标识为 `AGPL-3.0-only`。
- 验证：文档结构与链接校验退出 0，0 errors、0 warnings；VitePress 默认主题站点构建通过。两个包及锁文件的许可字段一致，依赖内容未变，完整 `LICENSE` 与下载源摘要一致。日志保存在本机 `artifacts/docs-normalization-20261031/`。
- 验证范围：重新核对实际源码、精确符号、回归断言和已保存验收记录；本轮未执行业务回归、服务启停或部署。包许可元数据已更新，运行副本的 28 文件一致性仍按 `8e4afdd` 的既有快照解释。

Synced through 8e4afdd2e62ff6f6e2fd58cada0a2b75a50abcc8

## 2026-11-10 11:58 +08:00：README 切换 pnpm 指令并记录部署当日的安装器修复与部署专用值脱敏

- 触发：用户要求把网关重新部署到既定域名并完成本机配置，随后要求筛查混入仓库的本机配置与个人信息、过滤后提交；发现中英根 README 仍残留 `npm.cmd` 指令，而仓库已无 `package-lock.json`，照做会直接失败；同步决策为 `foreground patch`。
- 中英 README 的依赖安装、开发检查与文档站命令改为 pnpm 形式，与 `AGENTS.md`、`repo-docs/README.md` 一致；wrangler 调用保持 `node_modules\.bin` 形式不变。
- 同轮部署事实：修复 `scripts/Install-Hardened.ps1` 运行副本依赖安装（补上锁文件内固定的 pnpm CLI 引用，并把 pnpm 12 已移除的 `--omit=dev --no-audit --no-fund` 调整为 `--frozen-lockfile --prod --ignore-scripts`）；重建并固定镜像 `agentdock-dev:2026-11-10`（镜像内 `/opt/bridge` 关键文件 SHA-256 与源码一致）；重装受保护运行副本（28 文件清单）。公网 `/healthz` 曾返回 `{"ok":true,"connectorOnline":true}`。
- 部署专用值脱敏：移除云端页面与测试中的硬编码部署域名（首页端点改由 `PUBLIC_ORIGIN` 渲染，反钓鱼提示改通用文案，测试改用 `bridge.example.test`）；`Setup.ps1` 默认 Origin 改回示例地址；`Manage.ps1` 探针与 `Secrets.ps1` 密码窗口标题改读本机 `config.json` 的 `origin`；`record-deployment.mjs`/`record-hardening.mjs` 的 Cloudflare 账户 ID 与主机名改为显式命令行参数，并把安装清单核对中的 `package-lock.json` 对齐为 `pnpm-lock.yaml`。历史提交中仍含上述部署值，未获重写授权，按原样保留。
- 部署环境注记：本机沙箱层曾向 `%USERPROFILE%\.agentdock-bridge` 与 `%USERPROFILE%\.agentdock-toolchains` 添加 `CodexSandboxUsers:(RX)` ACE，触发 `Assert-PrivateState` 拒绝全部可信入口；本次已移除并复核两树无多余主体。若再次出现同类拒绝，先检查这两个控制目录的 ACL。
- 验证：`pnpm run check` 通过；`pnpm test` 101 项（99 通过、0 失败、2 项 Docker 集成测试在未启用 `AGENTDOCK_DOCKER_TEST` 时按预期跳过）。本轮未运行 Docker 集成回归，也未执行停止/重启公网验收。

Synced through 90295b3（README 与安装器修复在工作树，未提交）

## 2026-11-10：历史脱敏、接入说明纠正与完整部署复验

- 触发：接续部署与发布任务，复核源码、历史和实际运行状态；同步决策为 `foreground patch`。
- 对 27 个既有提交执行历史清理，去除旧平台依赖和引用，替换历史部署账户、域名与本机绝对路径；分别重新签名并校验文件树、日期和父子关系。历史条目中的旧提交编号和当时的验证限制仍按原有时间解释，本条记录后续复验结果。
- 容器保留 GitHub CLI，凭据隔离测试改为覆盖通用 `_TOKEN` 变量；本机发布工具置于仓库外，主历史使用 GitHub 身份，镜像发布使用独立密钥与身份映射。
- 根 README 修正管理脚本地址来源；文档站的首页、快速入门、配置与排错页改为实际的远端 OAuth/MCP 接入和受保护安装流程，移除不存在的本地入口和环境变量示例。指南入口更新源码基线。
- 验证：语法检查通过；显式启用 Docker 后全量 101 项通过，0 失败、0 跳过。首次全量运行中的一项测试及新副本首次启动遇到 Windows PowerShell 安全扫描组件的 `AccessViolation`；保留失败证据，单项和全量重跑及可信启动重试均成功，未修改系统安全设置。
- 部署复验：重新构建并固定镜像、重装受保护运行副本；28 个安装文件、固定 Node 和镜像内关键源文件摘要一致。停止后公网 503、重启后公网 200；公网验收 9 项通过，覆盖 OAuth、文件增读改删、无网命令和令牌刷新。临时授权已撤销、旧令牌返回 401，探针无残留。云端源码未变，沿用已核实的部署版本。
- 边界：以上是独立验收客户端的实际调用；未在 ChatGPT 账户中添加或验证连接。操作证据、旧版本备份与失败日志保留在仓库外，不随文档发布。
- 文档验证：VitePress 构建通过；指南校验 0 errors、1 warning（既有 `DESIGN.md` 缺少同步规则提示）。

Synced through 110e5cd6a1219ea4448d94c3f897b65e92d3d081

## 2026-11-15：升级 Standard 源码指南并重置文档站与双语入口

- 触发：全仓文档体系重构（Tier B），从“Lite 加代码地图”升级为完整 Standard 体系，清除 `docs-site/` 中的历史通用模板文案并按“一处事实，一处归属”重划根目录 README、文档站与源码指南边界。
- 新增 `repo-docs/modules/` 三篇概念模块（云端 OAuth 2.1 与中继、本地精确批准与防重放账本、容器沙箱与文件安全策略）与 `repo-docs/glossary.md`（覆盖反复出现的专有符号与状态码）；同步补齐 `code-map.md` 中 `test/` 分节，校准 `walkthroughs/one-real-run.md`、`source-evidence.md` 与 `quality-review.md`。
- 本轮核对事实：核实当前 HEAD `56ee943` 下的全部源码模块与 `wrangler.jsonc.example`、`scripts/*.ps1`、Root `.cmd` 入口；补充说明 `cloud/index.mjs`（`READ_TOOLS`/`EXEC_TOOLS`）与 `local/request-policy.mjs`（10 项 `toolScopes`）工具集收敛差异，以及当前生产连接器强依赖 Windows DPAPI 与 PowerShell ACL 的平台边界。
- 实测基线：`pnpm run check` 通过；`pnpm test` 运行 101 项测试（Linux 环境下 86 项通过、0 失败、15 项 Windows/Docker 专属测试按条件跳过）。不把文档刷新视作 Windows 实机或公网再部署验收。

Synced through 56ee943

## 2026-11-20：新增 Linux 与 macOS 宿主支持及跨平台文档同步

- 触发：用户要求完成 Linux 与 macOS 宿主支持改造并触发 `repo-docs` Sync gate；同步决策为 `foreground patch`。
- 新增 POSIX 宿主安全与管理实现：`local/host-safety.mjs`（`0700`/`0600` 权限、全祖先路径写保护、硬链接与二进制 SHA-256 校验、`/proc` 与 `ps` 防 PID 复用识别及动态链接器环境变量清理）、`local/host-secrets.mjs`（macOS Keychain、Linux Secret Service 与 `0600` `posix-file` 两步轮换）、`local/node-toolchains.mjs`（官方 Node `24.22.1` 多平台 SHA-256 安装校验）与 `scripts/host-cli.mjs`（`setup`/`install`/`start`/`stop`/`status`/`approve`/`password` 与私有 `supervisor.sock` 守护锁）。
- 跨平台运行时适配：`local/connector.mjs` 在非 Windows 上分派 `exportSecretsSync`、支持大小写代理环境变量与 macOS `scutil --proxy`；`local/sandbox.mjs` 按平台选择默认 Docker context（Linux `default` / Windows 与 macOS `desktop-linux`）、透传 `XDG_RUNTIME_DIR`、在 `darwin` 同步小写化 `fileLocks`、并在原生 Linux 动态映射非 root 宿主 UID/GID 至 `container/runner.mjs`（拒绝 `0`）；同步适配 `scripts/verify-lifecycle.mjs` 与 `test/sandbox.test.mjs`。
- 验证范围与边界：保留现有 Windows PowerShell 与 DPAPI/ACL 流程；新增 `test/posix-host.test.mjs`（9 项 POSIX 宿主、凭据轮换、UID 传递与守护启停测试在 Linux 工作区全部通过）。本机未获 Docker 守护进程访问权限，亦未在真实 macOS 与 Windows 实机重新跑完整容器与 Keychain/DPAPI 回归。

Synced through 4bff65b（含工作树未提交改造与修复）

## 2026-11-20（全量代码审查修复与二轮复审）：安全边界、并发事务、性能与文档一致性对齐

- 触发：全仓代码审查（云端、沙箱/批准/策略、宿主凭据/生命周期、前端/CI/守卫/测试）发现并全量修复问题，随后在同会话无子 Agent 条件下完成二轮复审与 `repo-docs` Sync gate（决策为 `foreground patch`）。
- 云端网关（`cloud/`）：`BridgeRelay.limit` 改用 DO SQLite `rate_limits` 同步事务与批量过期删除并移除死代码 `/guard`；`AuthStore` 修复非 BMP 字符上界 `\u{10FFFF}`、跳过空提交并新增 `refresh-by-grant:` 索引在 `revokeFamily` 与删 grant 时级联清理 `refresh:*`；`AuthTransactions` 重试次数升至 12 轮、`other` 通道升至 16，并在二轮复审中修复并发 refresh 导致的 `AuthStore` 脏读异常重试竞态；`cloud/index.mjs` 统一 `callDo` 容错与脱敏日志、CORS 非 HTML/已检 Origin/去重 `Vary`、`OPTIONS` 预检、IPv6 `/64` 限流归一化及移除死代码 `/oauth/token/revoke`。
- 沙箱与本地策略（`container/`、`local/`）：`runner.mjs` 改用单调时钟与 `os.constants.signals` 并与 `file-worker.mjs` 同步提升标准输入上限至 1.4 MB；`LocalApprovals` 先清扫过期记录再判 1024 上限，新增元数据缓存并延续写入前即时过期复核、`approval-cli.mjs` 扩大 `safeText` 转义范围与可读预览；`RequestReceipts` 在满载时先逐条清理过期记录并校验 `lstat`/512 B；`file-safety.mjs` / `tools.mjs` / `sandbox.mjs` 补齐 `darwin` NFC 大小写归一化、`O_NONBLOCK` 读、`--init`、Windows 宿主路径校验、`SandboxUserError` 脱敏、`file-worker` 4 MiB 输出上限与审计日志串行化；`local/connector.mjs` 支持 `fields` 按需导出、`NO_PROXY` 绕过（含 IPv6 `[::1]` 归一化）、`pong` 后重置重试计数与原子 status/log 队列。
- 宿主脚手架、文档站与维护脚本（`scripts/`、`docs-site/`、`tools/`、`.github/`）：加固 `host-cli.mjs` 锁与进程退出清理、`Secrets.ps1` / `Setup.ps1` / `Manage.ps1` / `Rotate-Secrets.ps1` / `Install-*.ps1` 的原子临时文件与规范路径校验（含修复 `Secrets.ps1 -Action Create` 末尾反斜杠父目录判断）；修复 `docs-site/.vitepress/data/api-spec.ts`、组件可访问性与 i18n 开放重定向；抽取 `.github/scripts/sync_assets_licenses.py` 并收紧 `MIRROR_SLUG_RE` 拦截 `./..` 路径段、`tools/repo_maintenance_guard.py` 扩展敏感路径匹配与分批暂存扫描；同步 `docs-site/`、`README.en.md` 与 `repo-docs/` 契约与证据数字。
- 验证范围与边界：本机（Linux x86_64）在最终改动后将运行 `pnpm run check`、全量 Node 回归（当前套件共 123 项，Windows/Docker 专属测试共 15 项按平台条件跳过）、`validate_repo_docs.py`、`docs-site` 构建、`repo_maintenance_guard.py status` 与 `sync_assets_licenses.py --check --dry-run`；真实 Windows 实机（DPAPI/PowerShell ACL）、macOS Keychain 与开启 `AGENTDOCK_DOCKER_TEST` 的 Docker 容器集成仍待对应实机验证。

Synced through 4bff65b（含工作树全量审计修复与二轮复审改动）

## 2026-11-21：新增实时文件读写能力开关、本机监控 WebUI 与 systemd 自启动入口

- 触发：按用户要求配置 Linux 开机自启动后台服务，并设计本地 WebUI 实时监控运行情况与动态开关文件读写能力；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- 新增[实时能力开关](../local/capabilities.mjs)（`<stateDir>/capabilities.json`，`0600` 损坏闭锁）并接入 `BridgeConnector` 与 `createSandboxRuntime`：`fileRead: false` 拦截文件读取工具与 `exec_command`，`fileWrite: false` 禁用写入工具并将 `exec_command` 容器挂载自动降为 `:readonly`，所有变更在无需重启连接器的情况下立即对后续请求生效。
- 新增[本机监控 WebUI](../local/webui.mjs)与[界面资源](../local/webui-assets.mjs)：严格仅监听回环接口（默认 `127.0.0.1:18797`），通过 `Host`、`Origin`、`Sec-Fetch-Site`、`SameSite=Strict` Cookie 与 `X-AgentDock-CSRF` 防护 CSRF 与 DNS 重绑定，经 `/api/events` SSE 推送守护/连接器状态、待批计数、活跃容器与脱敏审计流（不暴露凭据、正文与远程代批）。
- 扩展[POSIX 宿主管理 CLI](../scripts/host-cli.mjs)：安装阶段额外生成受保护的 `0700` `run-service` 与 `webui` 包装脚本，新增 `webui` 与 Linux `service`（管理 `~/.config/systemd/user/{agentdock-bridge,agentdock-webui}.service`）子命令，并同步更新 `package.json` `check` 与 `repo-docs/` 模块文档和代码地图。
- 验证：新增 [能力与 WebUI 回归](../test/capabilities-webui.test.mjs) 5 项用例（含启用 `AGENTDOCK_DOCKER_TEST=1` 的真实 Docker `:readonly` 挂载验证）；全量静态检查与 `node --test` 在本机完成验证。

## 2026-11-21（安全加固）：WebUI 强制 PassKey / 强密码鉴权与配置文件工作区外隔离

- 触发：按用户安全要求，防止 Agent 从远端或容器访问 WebUI 修改权限，并强制认证及能力配置文件置于挂载工作区之外；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- 新增 [WebAuthn / CBOR 校验](../local/webauthn.mjs) 与 [WebUI 认证模块](../local/webui-auth.mjs)：探测宿主（Windows Hello、macOS Touch ID、Linux FIDO2 HID / `fprintd`）与浏览器（UVPA）的 PassKey 能力；机器/浏览器支持或已注册 PassKey 时强制使用 `localhost` WebAuthn（`UP`+`UV`、`signCount` 防重放）并禁止回退密码登录；不支持时强制校验 ≥ 14 位含大小写/数字/符号的 `scrypt` 强密码；初始化须经本机交互终端 `~/.agentdock-bridge/webui-auth init|set-password|reset` 生成单次 setup ticket 或口令，防止未授权请求抢先设置。
- 强化工作区外隔离：在 [capabilities.mjs](../local/capabilities.mjs)、[webui-auth.mjs](../local/webui-auth.mjs)、[connector.mjs](../local/connector.mjs)、[sandbox.mjs](../local/sandbox.mjs)、[webui.mjs](../local/webui.mjs) 与 [host-cli.mjs](../scripts/host-cli.mjs) 中通过 `assertConfigOutsideWorkspace` 强制校验 `config.json`、`capabilities.json` 与 `webui-auth.json` 的真实路径（含禁止符号链接跨越）均在工作区根目录之外，否则失败关闭。
- 收紧 [webui.mjs](../local/webui.mjs) 与 [webui-assets.mjs](../local/webui-assets.mjs)：所有状态查询、SSE 事件流、能力开关与服务启停接口在未获认证会话前一律返回 `401`，登录增加 5 次失败指数冷却限流（`429`），切换认证态或登出时同步轮换会话与 CSRF 令牌。
- 验证：[能力与 WebUI 回归](../test/capabilities-webui.test.mjs) 扩展至 7 项用例（覆盖工作区内部/符号链接拦截、未认证 `401`、强密码 + `429` 限流、ES256 CBOR PassKey 注册/验证/重放拒绝及真 Docker `:readonly` 沙盒），均在本机通过；同步完成系统部署与端到端实测。

## 2026-11-21（WebUI 工具细节检查器、真实审计与标签页隔离认证）

- 触发：按用户要求优化 WebUI 视觉风格（对齐系列项目 VitePress 文档站配色与结构），按用途拆分为「状态与开关 / 实时审计 / 工具说明」分页，在实时审计页展示真实调用参数与输出明细，并将默认会话收紧为**标签页级别（关闭重开须重新 PassKey/密码解锁）且提供配置切换按钮**；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- 审计流水与工具契约：在 [request-policy.mjs](../local/request-policy.mjs) 导出 `getToolScopes`，在 [sandbox.mjs](../local/sandbox.mjs) 导出 `buildSandboxTools` 并为 `audit.jsonl` 记录有界工具参数（`args`）与执行结果/标准输出（`result`）；[connector.mjs](../local/connector.mjs) 补充 `target` 提示至拦截/待批日志；[webui.mjs](../local/webui.mjs) 返回 10 项工具的 Schema、权限/审批规则、近 200 条统计计数与可展开的 `auditArgs` / `auditResult`。
- 标签页级会话控制与多分页 UI：在 [webui-auth.mjs](../local/webui-auth.mjs) 新增持久化配置项 `sessionPersistence`（默认 `'tab'`，可选 `'browser'`）与 `setSessionPersistenceSync`；[webui.mjs](../local/webui.mjs) 新增 `X-AgentDock-Tab-Auth` 逐标签页校验及 `POST /api/auth/settings`；[webui-assets.mjs](../local/webui-assets.mjs) 使用 `sessionStorage` + `fetch()` 流式 SSE 实现关页即锁的标签页级鉴权，并按文档站视觉规范完成三分页交互与配置开关重构。
- 验证：[能力与 WebUI 回归](../test/capabilities-webui.test.mjs) 完整验证标签页隔离 `401`、配置持久化切换、PassKey 绑定、真 Docker `:readonly` 沙盒与真实审计详情回显，并同步更新 [local-approval-and-replay.md](modules/local-approval-and-replay.md)；在最终改动后完成 `pnpm run check`、含 `AGENTDOCK_DOCKER_TEST=1` 的 `pnpm test`、`validate_repo_docs.py`、`docs-site` 构建与多标签页真实浏览器 E2E 实测。

## 2026-11-21（WebUI 全功能操作台补齐）：PassKey/强密码管理、自启动开关、单工具开关与实时批准

- 触发：按用户要求补齐 WebUI 的 PassKey 管理、开机自启动管理、强密码重置/切换、单 MCP 工具独立开关以及实时待人工批准操作；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- 单工具独立开关：[capabilities.mjs](../local/capabilities.mjs) 新增持久化并校验失效关闭的 `tools` 覆写映射；[webui.mjs](../local/webui.mjs) 在 `POST /api/capabilities` 与快照 `effectiveTools[].individuallyDisabled` 中同步单工具开关，[webui-assets.mjs](../local/webui-assets.mjs) 在「状态与开关」与「工具说明」详情页均提供独立开关按钮。
- PassKey、密码重置与自启动管理：[webui-auth.mjs](../local/webui-auth.mjs) 新增 `deletePasskeySync`（禁止删除最后 1 枚密钥）与 `switchToStrongPasswordSync`（硬件不支持/未强制时允许切回），并脱敏返回 `passkeys` 元数据列表；[webui.mjs](../local/webui.mjs) 在 `POST /api/auth/setup/password` 验证现密码 `currentPassword`、新增 `/api/auth/passkey/delete` 与 `/api/auth/passkey/switch-password`，并在 `/api/service` 新增 `enable-autostart` / `disable-autostart`（禁用自启不带 `--now`，避免中断当前控制台响应）。
- 实时待人工批准：在[webui.mjs](../local/webui.mjs) 读取已校验待批请求完整参数与 SHA-256 `policyDigest`，新增经 PassKey/强密码与标签页令牌鉴权的 `POST /api/approvals/approve`（复核摘要后复用 `approveRequest` 签发一次性 `.approved.json`）与 `POST /api/approvals/reject`；[webui-assets.mjs](../local/webui-assets.mjs) 在「实时审计」页卡片化呈现参数与批准/拒绝按钮。
- 验证与部署：在[capabilities-webui.test.mjs](../test/capabilities-webui.test.mjs) 新增 3 项完整单测与 HTTP 集成测试，同步更新 [local-approval-and-replay.md](modules/local-approval-and-replay.md) 与 [code-map.md](code-map.md)；随后将运行 `pnpm run check`、含 `AGENTDOCK_DOCKER_TEST=1` 的 `pnpm test`、无头 Chromium E2E 与指南/站点构建校核，并以非破坏性重装部署至 `~/.agentdock-bridge` 保留已绑定的用户 PassKey。

## 2026-11-21（第三方 MCP 聚合接入与独立配置页面）

- 触发：按用户要求新增额外配置界面并允许 AgentDock 接入第三方 MCP 服务；同时保留工作树已收紧的仅元数据审计遥测与两步弹窗复核审批边界；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- 新增 [第三方 MCP 注册表](../local/mcp-registry.mjs) 与 [外部 MCP 客户端](../local/mcp-client.mjs)：在工作区外受保护状态目录维护 `0600` 的 `mcp-servers.json`（强制 `assertConfigOutsideWorkspace`、无符号链接/硬链接、拦截高危环境变量覆写与针对本机 WebUI/网关的自循环 HTTP SSRF、环境变量与请求头密钥仅写入不回显），零外部依赖实现 `stdio`（`shell: false` 与净化环境）与 `Streamable HTTP`（支持 JSON 与 SSE 响应、禁重定向）握手、工具发现与会话池管理，并在 `audit.jsonl` 中仅记录结构化遥测元数据（`tool`、`serverId`、`durationMs`、`outputBytes`）。
- 接入主链路与 WebUI 配置页：更新 [request-policy.mjs](../local/request-policy.mjs) 与 [connector.mjs](../local/connector.mjs) 聚合 `mcp__<serverId>__<tool>` 工具并强制完整三项 OAuth Scope、实时能力开关检查、精确本机审批及 24 小时防重放账本；在 [webui.mjs](../local/webui.mjs) 新增 `/api/mcp-servers/*`（增改、标准 `mcpServers`/`servers` JSON 导入、服务/单工具开关、实连探测同步、移除）接口；在 [webui-assets.mjs](../local/webui-assets.mjs) 新增独立「第三方 MCP」导航页（表单配置、只写密钥标签管理、标准 JSON 导入、探测同步与逐工具启停）及「工具说明」的「第三方 MCP」筛选。
- 验证：新增 [external-mcp.test.mjs](../test/external-mcp.test.mjs) 覆盖文件安全、密钥防回显、自循环 SSRF 拦截、真实 `stdio` 与 `Streamable HTTP (SSE)` MCP 服务端到端审批与执行；完成后执行 `pnpm run check`、含 `AGENTDOCK_DOCKER_TEST=1` 与 `AGENTDOCK_TEST_IMAGE=agentdock-dev:2026-10-28` 的 `pnpm test`、无头 Chromium 四分页 E2E、`validate_repo_docs.py`、`docs-site` 构建及受保护副本非破坏性重装。

Synced through 4bff65b（含工作树能力开关、WebUI 强制鉴权、第三方 MCP 接入配置与自启动更新）

## 2026-11-21：补齐 WebUI 完整请求复核与沙箱回归

- 在 Linux、macOS 受保护 WebUI 的待批列表选中请求后，控制台按需显示完整来源、授权范围和参数。签发时重新检查记录、时限和复核摘要。退出登录立即结束对应会话的实时事件流。见[本机批准流程](modules/local-approval-and-replay.md)。
- 审计日志保留工具、运行策略、耗时、退出码和字节数。查看历史日志时仅选取元数据，WebUI 仅在单条复核响应中返回完整请求。关闭文件写入后，新建文件容器和命令容器均使用只读工作区挂载。见[沙箱策略](modules/container-sandbox-and-file-policy.md)。
- 三项真实 Docker 测试共用显式镜像选择，在同一 Docker context 解析镜像、执行与核对清理。GitHub 检查任务检出完整历史以核对贡献清单。
- Linux x86_64 验证使用 Node 26.13.1。常规回归共 134 项，118 通过、16 跳过。指定本机现有镜像摘要并启用 Docker 后，120 通过、14 项按平台跳过。Chromium 使用临时凭据核验长参数末尾、转义字符、批准标记与新标签页重新认证。语法检查、资产清单只读核验和文档站构建通过。指南校验 0 错误、6 条提示，涉及术语表和根目录文档的同步规则。
- 本轮验收范围为工作树、临时状态目录及本地测试容器。Windows DPAPI/NTFS ACL、macOS Keychain、受保护运行副本和公网部署需分别验收。

Synced through 4bff65b（含本次未提交的工作树修复）

## 2026-11-22：WebUI 控制面与第三方 MCP 三路代码审查全量安全加固与修复

- 触发：用户发起三路并行子 Agent 代码审查（第三方 MCP 运行时安全、WebUI 认证与 API、WebUI 前端与文档），并授权全量修复查出的 `1 Critical`、`13 High` 及关键 `Medium`/`Low` 问题；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- 第三方 MCP 执行隔离与协议加固（[request-policy.mjs](../local/request-policy.mjs)、[mcp-registry.mjs](../local/mcp-registry.mjs)、[mcp-client.mjs](../local/mcp-client.mjs)、[connector.mjs](../local/connector.mjs)）：
  - `stdio` 子进程改用最小 OS 环境变量白名单与默认独立 `0700` 空临时目录（不再继承宿主凭据变量或默认工作区目录），扩展高危环境变量黑名单（含 `LD_AUDIT`、`BASH_ENV`、`PYTHONSTARTUP`、`DBUS_SESSION_BUS_ADDRESS`、`SSH_AUTH_SOCK`、`DOCKER_HOST` 与 `AGENTDOCK_*`），每次 `spawn` 前以 `assertSafeStdioCwd` 复验无符号链接且不与受保护状态目录重叠，并使用独立进程组清理与 `stdin` 异步写错误兜底（防止 `EPIPE` 崩溃）。
  - `Streamable HTTP` 改用零依赖 `node:http`/`node:https` 自定义 DNS `lookup` 校验拦截 DNS 重绑定、私网/保留/元数据 IP（`0.0.0.0/8`、`10.0.0.0/8`、`100.64.0.0/10`、`169.254.0.0/16`、`172.16.0.0/12`、`192.168.0.0/16`、`fe80::/10`、`fc00::/7`、IPv4 映射/嵌入 IPv6 及非 `127.0.0.1` 回环）与末尾点域名绕过；`BridgeConnector` 默认把回环 WebUI 端口纳入 `blockedOrigins`；实现增量流式 SSE 解析、HTTP `404` 会话失效后标记关闭并在下次调用重建、服务端主动 JSON-RPC 请求应答防 ID 冲突与严格响应校验。
  - 收紧 `SERVER_ID_RE` 禁止 `__` 及末尾 `_` 消除跨服务工具名歧义；修改 `command`/`args`/`cwd` 或 HTTP `origin` 时禁止静默沿用旧密钥（须显式 `replaceSecrets: true`）；本地探测诊断与 HTTP 失败响应均在截断前执行密钥脱敏，云端工具错误仅返回脱敏状态码/通用错误而不透传原始 `stderr` 或响应正文；`ensureSession` 增加单飞合并与重载校验，`tools/list` 仅返回已缓存/活跃工具并受 `1 MiB` 聚合字节预算约束；外部工具注解一律强制保守（`readOnlyHint: false`、`destructiveHint: true`）；支持原子批量导入 `upsertMcpServersSync` 与 `O_NOFOLLOW` 审计追加。
- WebUI 认证、API 与状态存储加固（[capabilities.mjs](../local/capabilities.mjs)、[webauthn.mjs](../local/webauthn.mjs)、[webui-auth.mjs](../local/webui-auth.mjs)、[webui.mjs](../local/webui.mjs)）：
  - 修复 `POST /api/auth/passkey/switch-password` 仅允许活跃 PassKey 会话调用（防止密码登录态绕过现密码核验）；持久化 `hardwarePasskeyEnforced` 防热拔 FIDO2 降级；`webauthn.mjs` 支持带 `ED`（`0x80`）CBOR 扩展字段的真实认证器注册并拒绝 `crossOrigin: true` 与弱 RSA/错配算法；`detectHostPasskeySupport` 增加 60 秒 TTL 缓存避免阻塞事件循环。
  - 统一 `capabilities.json`、`webui-auth.json`、`mcp-servers.json` 与日志尾部读取为 `O_RDONLY | O_NOFOLLOW` + `fstatSync` 消除 TOCTOU；收紧已认证会话的严格会话 CSRF 校验、分离注册/登录挑战并绑定 `sid`、对错误 `setupToken` 纳入 5 次退避限流、未认证 `/api/auth/state` 脱敏隐藏 PassKey 备注与票据状态；为 `/api/mcp-servers/save` 增加字段白名单防 Mass Assignment、受限并发/截止期探测防中途中删报 `500`；审批拒绝支持移除损坏 `.request.json` 且对 `clientId` 经 `safeText` 转义；服务操作单飞互斥并支持非 Linux 错误码 `400`；`sha256OfSnapshot` 排除易抖动的 `gatewayLatencyMs`，审计事件改用内容哈希稳定 `key`。
- WebUI 前端与指南同步（[webui-assets.mjs](../local/webui-assets.mjs)、[local-approval-and-replay.md](modules/local-approval-and-replay.md)、[code-map.md](code-map.md)）：
  - 修复工具说明页分组筛选（`fileRead`/`fileWrite`/`exec`/`execControl`/`context`/`mcp`）与父组总开关禁用逻辑；第三方 MCP 工具详情明确标注「非容器沙盒（宿主 stdio / 外部 HTTP）」与「外部 MCP 契约」；锁屏与退出登录立即清空内存快照、关闭全部弹窗并清除密钥/密码输入 DOM；基于分区签名与错误横幅分离消除 SSE 轮询冲刷焦点/展开态/错误提示；补充删除 6 秒自动回滚与取消按钮、探测失败保留表单、隐藏传输字段禁用与无障碍/对比度优化；同步文档明确第三方 MCP 运行在容器沙盒之外并修正 `notifications/initialized`/`notifications/cancelled` 表述。
- 验证与部署：在 [external-mcp.test.mjs](../test/external-mcp.test.mjs) 与 [capabilities-webui.test.mjs](../test/capabilities-webui.test.mjs) 补充全面安全与协议回归，在无头 Chromium E2E 补充工具分组筛选、写能力关闭组锁、非容器徽章与登出清空表单断言，并完成对 `~/.agentdock-bridge` 受保护运行副本的非破坏性重装（保留既有用户 PassKey）。

Synced through 4bff65b（含本轮三路代码审查全量修复与验证）

## 2026-11-22（二轮对抗性审查全量修复）：前端冻结修复、CSRF/限流/会话竞态、SSRF 与截断前脱敏

- 触发：用户对一轮修复结果发起第二轮三路对抗性子 Agent 代码审查（WebUI 认证与 API、第三方 MCP 安全与协议、WebUI 前端与指南准确性）并授权全量修复查出的 `1 Critical`、`11 High`、`14 Medium` 及关键 `Low`/文档问题；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- WebUI 前端与交互修复（[webui-assets.mjs](../local/webui-assets.mjs)）：
  - 修复密码重置与 PassKey 绑定后因 `pendingMutation` 在 `refreshAuthAndBoot()` 期间仍为 `true` 导致仪表盘所有开关/按钮永久冻结的阻断缺陷（`C1`）；统一 `renderInteractiveSections()`，并补齐预设与服务按钮的 `pendingMutation` 防重入保护。
  - 修复编辑带查询参数或 `#hash` 的 HTTP MCP 服务时界面回填脱敏 URL 导致误覆写原 URL 的缺陷（`H4`），仅在用户实际改动 URL 时提交 `url` 字段，探测失败时保留输入内容；仅在同传输协议下展示 `replaceSecrets` 勾选项。
  - 新增 1 秒级审批倒计时定时器（离屏清理）与弹窗过期失效守卫（`H5`、`M12`）；区分 `PRE_AUTH_ENDPOINTS` 与 `AUTH_CONFIG_ERROR` 错误码，切换至标签页隔离模式后主动以新 `tabToken` 重连 SSE（`H6`、`H7`、`M13`）；登出与锁屏彻底清空全部 DOM 计数/缓存/弹窗并汇报登出失败（`M10`）；修正 `capabilities.json` 异常时外部 MCP 与豁免工具的父开关状态判断（`M11`）；补齐 WCAG AA 对比度、装饰球层叠顺序、工具名省略、键盘焦点恢复及 `Object.create(null)` 键值解析（`M14`）。
- WebUI 认证与 API 加固（[webui.mjs](../local/webui.mjs)、[webui-auth.mjs](../local/webui-auth.mjs)、[webauthn.mjs](../local/webauthn.mjs)、[capabilities.mjs](../local/capabilities.mjs)、[package.json](../package.json)）：
  - 未认证 `GET /api/auth/state` 自动补发 `PRE_AUTH_COOKIE` 与预认证 `csrfToken`，修复会话过期/服务重启/多标签页场景下免刷新重登录触发 `403 CSRF` 的故障（`H1`）；对密码/PassKey 登录端点在读取请求体后二次复核 5 次失败限流并限制请求体 10 秒超时与精确 `Content-Type`（`H2`）；全部已认证 `POST` 路由在读完请求体后通过 `readAuthenticatedJson` 复核会话有效性（`M1`）。
  - `runBoundedProbe` 改用 `res.on('close')` 在客户端中途断连时及时中止底层探测（`H3`），`/api/mcp-servers/save` 捕获并发探测冲突 `409`/`429` 仍返回已保存配置与最新快照，`/api/mcp-servers/import` 在断连时提前退出并短暂等待探测槽（`M4`）；`refreshAndBroadcast` 改用单飞合并队列且 `broadcast: false` 不吞噬未推送变更（`M3`）；`POST /api/auth/settings` 切回 `tab` 模式时先刷新快照再轮换 `tabToken` 并断开旧 SSE（`H7`）。
  - Linux `/sys/class/hidraw` 热插拔实时检测（仅缓存 `fprintd-list` 60 秒）消除硬件 PassKey 强制态陈旧窗口（`M2`）；`webauthn.mjs` 拒绝重复 CBOR Map 键、`topOrigin`、认证断言中的 `AT` 标志及错配 EC 曲线，并限制 `authData`/`signature` 上限（`L4`）；补齐静态资源 `CORP: same-origin` 与 `Sec-Fetch-Site` 检查、审批文件 `fstat` 缓存签名、包装脚本 `assertTrustedBinary` / Windows 绝对 `cmd.exe` 校验、`loadWorkspaceRootsFromStateConfig` 符号链接检查，并将剩余 8 个生产 `.mjs` 模块纳入 `pnpm run check`。
- 第三方 MCP 安全与协议加固（[mcp-registry.mjs](../local/mcp-registry.mjs)、[mcp-client.mjs](../local/mcp-client.mjs)）：
  - `ensureSession` 单飞连接改为独立每调用方 `AbortSignal` 等待（仅全部等待者取消、配置变更或 `hub.close()` 时中止共享握手，且 `hub.close()` 等待在途连接清理临时目录，`H9`）。
  - 完整 8×16 位 IPv6 展开与全量 IPv4/IPv6 私网/CGNAT/保留/多播/内嵌地址（`10/8`、`100.64/10`、`172.16/12`、`192.168/16`、`64:ff9b::/96`、`2002::/16`、`::ffff:` 等）拦截，拒绝 `https://localhost` 与末尾点回环；每会话使用独立 `http.Agent`/`https.Agent` 并在关闭时销毁，仅对非 IP 域名设置 TLS SNI `servername`（`H10`、`M6`）。
  - 所有错误输出、HTTP 响应正文与 `stderr` 均在 8 KiB 窗口内先脱敏（含 URL 查询/片断密钥与剥离 `Bearer` 前缀后的裸令牌）再截断（`H11`）；修改 `cwd` 同样触发 `replaceSecrets` 保护并拒绝 Windows UNC 路径，扩展 `LD_*`/`DYLD_*`/`JAVA_TOOL_OPTIONS`/`PYTHONHOME` 等黑名单（`H8`、`M7`）；修复 `HTTP 404` 会话过期与 `close()` 幂等清理、Windows `taskkill /T /F`、Schema 属性名/枚举清洗与 `array.items` 保留（`M5`、`M8`、`M9`）。
- 指南与回归同步（[local-approval-and-replay.md](modules/local-approval-and-replay.md)、[code-map.md](code-map.md)、[external-mcp.test.mjs](../test/external-mcp.test.mjs)、[capabilities-webui.test.mjs](../test/capabilities-webui.test.mjs)）：
  - 修正批准状态机补充第三方 MCP 工具、修正 `code-map.md` 中 `container/runner.mjs` 与 `container/file-worker.mjs` 符号归属、WebUI 回环绑定与默认标签页会话描述及 `approval-cli.mjs` 调用方；新增 2 项二轮专项安全与可靠性回归测试并扩展无头 Chromium 端到端校验（密码重置后控制面不冻结、脱敏 URL 编辑不覆写、同标签页登出后免刷新重登录）。
  - 验证范围与边界：本机（Linux x86_64）在最终改动后完成非破坏性受保护副本重装（保留既有用户 PassKey）、`pnpm run check`（全量 31 个 `.mjs` 模块）、含显式 `AGENTDOCK_DOCKER_TEST=1` 与本机已固定测试镜像的 `pnpm test`、无头 Chromium 四分页 E2E、`validate_repo_docs.py`、`docs-site` 构建、`repo_maintenance_guard.py status` 与 `sync_assets_licenses.py --check --dry-run`；Windows DPAPI/NTFS ACL、`cmd.exe` 包装与 macOS Keychain 仍需在对应实机验证。

Synced through 4bff65b（含二轮对抗性审查全量修复与验证）

## 2026-11-23：归档收尾、项目更名为 LoomWard · 织盾并落地 Cordis 4 Monorepo 骨架

- 触发：用户授权收尾提交工作树改动并双端归档旧仓库，随后更名并切入以 Cordis 4 为微内核的 `pnpm workspace` monorepo 架构；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- 归档与收尾：本仓库原工作树按云端、本地运行时与文档/CI 拆分为 3 条签名提交（`4eed460`、`8c66c3c`、`f74b7f5`）并双端推送至 `main` 与 `archive/agentdock-worker-remote`；原 `agent-decisions-dashboard` 与 `claude-code-antileak-hooks` 双端追平并分别归档至本仓库 `archive/agent-decisions-dashboard`、`archive/claude-code-antileak-hooks` 后移除对应独立本地目录；`modelbridge` 与 `cloudforge` 保持独立仓库维护（其中 `modelbridge` 已顺带收尾提交并双端同步至 `54e941a`）。
- 更名与 Monorepo 骨架：项目正式更名为 **LoomWard · 织盾**（`loomward` / `@loomward/*`），配置根目录 `pnpm-workspace.yaml`（`packages/*`、`plugins/*`，继续与独立 `docs-site/` 隔离）；落地零宿主原语包 [packages/shared](../packages/shared/README.md)（契约校验、RPM JCS+SHA-256、60 秒 `BootRun` 逆序回滚、`ImplSlot`/`MechanismSlot`）与 Cordis 4 微内核包 [packages/kernel](../packages/kernel/README.md)（`createLoomWardKernel`、`PolicyTree` 与静态机械分层守卫 `layering.test.mjs`），建立核心根包骨架 `packages/{cloud-relay,sandbox,host,console}` 与声明 `executionBoundary: "out-of-process"` 的扩展插件骨架 `plugins/{antileak,decisions,mcp-hub,adapters}`；既有 `cloud/`、`local/`、`container/`、`scripts/` 与 `test/` 完整保留并在渐进迁移期间持续受回归保护。
- 同步入口：更新 `package.json`、`meta.json`、`AGENTS.md`、`README.md`、`README.en.md`、`docs-site/.vitepress/config.mts`、`repo-docs/README.md`、`repo-docs/code-map.md` 与 CI 测试入口（`pnpm run test:ci`）。
- 验证边界：将执行 `pnpm install` 锁定 `cordis@4.0.0-rc.11` 与 workspace 链接，验证 `pnpm run check`、`pnpm run test:ci`（既有桥接套件 + 新增 `packages/shared` 与 `packages/kernel` 单元与分层守卫测试）、`validate_repo_docs.py`、`docs-site` 构建、`repo_maintenance_guard.py status` 与 `sync_assets_licenses.py --check --dry-run`。远端仓库改名与本地目录路径重命名留待用户下一步显式执行。

Synced through f74b7f56d1fd88a97df322c8cd4df95f9aaff279（本节对应其后的 LoomWard 更名与 monorepo 骨架工作树）

## 2026-11-23（Phase 1）：Cordis 4 KernelGuard、冻结 RPM、统一调度流水线与 Monorepo 受保护安装器

- 触发：按既定分阶段实施计划落地 Phase 1（Cordis 4 微内核运行时化、核心根插件与进程外 `mcp-hub` 接线、受保护安装器 monorepo 适配）；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- 共享原语与微内核守卫（[packages/shared](../packages/shared/src/index.mjs)、[packages/kernel](../packages/kernel/src/index.mjs)）：
  - `@loomward/shared` 新增 `guard-types.mjs`（`VAULT_SLOT`、`AUDIT_CODES`、`REJECT_CODES`、`formatActionNode`、`buildPermissionSubject`、`sanitizeAuditMetadata`），并在 `contracts.mjs` 扩展可选 `registers`/`writes` 写边声明校验，同时保持零 `node:*`/零 `cordis` 边界。
  - `@loomward/kernel` 补齐全部 7 大标准插槽（新增 `policy: 'closed'` 的 `vault:backend@1`）、`KernelGuard`（Cordis `internal/get` 瀑布拦截、非 root 访问闭锁凭据槽阻断与审计、声明写边核验、单飞 `ask-on-use` 异步提权与卸载中断、热卸载 `AUDIT_TRUSTED_WRITE_OFF`）、无状态 `GuardRule[]` 管线（`rules.mjs`）及真实源码字节哈希的冻结 RPM 构造/核验（`rpm-builder.mjs`），并在 `control` 上暴露特权 `mountExtensionUnit`/`unmountExtensionUnit`。
- 根插件与进程外扩展运行时化（[packages/cloud-relay](../packages/cloud-relay/src/index.mjs)、[packages/sandbox](../packages/sandbox/src/index.mjs)、[packages/host](../packages/host/src/index.mjs)、[plugins/mcp-hub](../plugins/mcp-hub/src/index.mjs)）：
  - `@loomward/cloud-relay` 导出规范中继协议常量与桥接 URL 校验；`@loomward/sandbox` 在保持 `local/*.mjs` 与 `container/Dockerfile` 完全自包含的前提下封装 `sandbox-docker` 工具提供者；`@loomward/plugin-mcp-hub` 以 `out-of-process` 扩展身份注册 `mcp-hub` 提供者并在卸载时清理子进程与会话。
  - `@loomward/host` 落地 `vault.mjs`、`pipeline.mjs`（`createToolDispatchPipeline`，完整保留 `policy:rule@1` 前置拒绝 → `tool:invoke@1@before` 预检阻断 → 精确参数批准先删后写 24h `RequestReceipts` → 独占 `stop_command` 并发通道与 `StopReceipts` → `tool:provider@1` 派发 → `tool:invoke@1@after`）、双 `gateway:ingress@1` 实现（`cloudflare-wss` 远程中继与 `local-mcp-direct` 本机直连入口）及 `daemon.mjs`（`startLoomWardDaemon`）。
- 受保护安装器升级（[scripts/host-cli.mjs](../scripts/host-cli.mjs)）：`installHardened` 同步复制 `pnpm-workspace.yaml`、`packages/`、`plugins/`（跳过 `test/` 与 `node_modules/`），在发布目录写入冻结 `rpm.json` 并将 `rpmManifestHash` 及全树 SHA-256 记入 `installation.json`；继续非破坏性兼容既有 `~/.agentdock-bridge` 状态目录。
- 验证范围与边界：本机（Linux x86_64）在最终改动后执行 `pnpm install --frozen-lockfile`、`pnpm run check`、`pnpm run layering`、`pnpm run test:ci`（覆盖既有桥接回归 + `@loomward/{shared,kernel,host}` 单元与集成测试 + `posix-host` monorepo 安装验证）、`validate_repo_docs.py`、`docs-site` 构建、`repo_maintenance_guard.py status` 与 `sync_assets_licenses.py --check --dry-run`；不涉及修改本机运行中的 `~/.agentdock-bridge` 生产副本、公网部署或 Windows/macOS 实机验证。

Synced through aa016c0（含 Phase 1 工作树改动）

## 2026-11-23（Phase 2）：`@loomward/console` 双源物理隔离控制台、控制通道与低耦合扩展契约

- 触发：落地 Phase 2（双源回环控制台 + 模块化离线前端构建 + 实时内核控制通道），并同步为后续可独立剥离交付的外部 LLM 内容审核插件预留零耦合声明式面板与输入/输出审查契约；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- 低耦合共享契约（[packages/shared](../packages/shared/src/index.mjs)、[packages/host/src/pipeline.mjs](../packages/host/src/pipeline.mjs)、[local/approvals.mjs](../local/approvals.mjs)）：
  - 新增 `panel-schema.mjs`（`CONSOLE_PANEL_SCHEMA_VERSION`、`validateConsolePanelDecl`、`sanitizeConsolePanelSnapshot`），以纯 JSON 声明式结构表达指标卡片、表格、提示与安全链接（过滤 `javascript:` 等危险协议，零任意 HTML/JS 注入），让任何外部插件无需修改 `@loomward/console` 即可自动渲染只读面板。
  - 新增 `content-guard.mjs`（`CONTENT_INSPECT_PROTOCOL_VERSION`、`buildContentInspectRequest`、`validateContentInspectVerdict`），定义独立的 `input`/`output` 内容审查协议（`allow | redact | escalate | block`，输入阶段禁止静默改写）；`ToolDispatchPipeline` 与 `LocalApprovals` 同步支持前置钩子 `forceApproval: true`（在内容审核判定 `escalate` 时对原本免批工具也强制进入人工审批）及后置钩子输出脱敏。
- 双源回环控制台与离线前端（[packages/console](../packages/console/src/index.mjs)）：
  - 物理拆分 **Trust Origin（Ring 2，默认 `127.0.0.1:18798`）** 与 **Console Origin（Ring 3，默认 `127.0.0.1:18797`）**：各自独立 Cookie（`loomward_trust_sid` / `loomward_console_sid`）、独立 `Origin`/`Host`/`Sec-Fetch-Site`/`X-LoomWard-CSRF`/`X-LoomWard-Tab-Auth` 校验与 `CORP`/`COOP` 隔离；Trust Origin 拒绝 `/api/panels`（`403 CONSOLE_ORIGIN_ONLY`），Console Origin 拒绝全部写操作/认证/审批端点（`403 TRUST_ORIGIN_REQUIRED`）。
  - 落地 `session-broker.mjs`（Trust Origin 签发单次 60 秒只读移交票据，Console Origin 经 `#ticket` 片段立即擦除并同源兑换，Trust 登出或改密实时级联吊销关联 Console 会话与 SSE 流）与 `control-channel.mjs`（进程内总线 + POSIX 私有 `0600` `control.sock` 仅元数据实时推送，消除常规文件轮询）。
  - 拆分前端至模块化源码 `packages/console/web/{shared,trust,console}`，经 `esbuild` 离线零 CDN 构建至 `packages/console/dist/{trust,console}.{js,css}`，接入 Cordis 4 `console` 根插件与 `startLoomWardDaemon`。
- 验证范围与边界：本机（Linux x86_64）运行 `pnpm run build:console`、`pnpm install --frozen-lockfile`、`pnpm run check`、`pnpm run layering`、`pnpm run test:ci`（覆盖既有 158 项回归 + 新增 `panel-schema`/`content-guard` 单测与 `dual-origin-console.test.mjs` 跨源隔离、ES256 PassKey、两步审批、`control.sock` 实时推送及模拟独立 LLM 内容审核插件联调）、`validate_repo_docs.py`、`docs-site` 构建、`repo_maintenance_guard.py status` 与 `sync_assets_licenses.py --check --dry-run`。既有 `local/webui*.mjs` 兼容保留，未改动本机 `~/.agentdock-bridge` 运行副本。

Synced through 32ab5c1（含 Phase 2 工作树改动）

## 2026-11-23（Phase 3）：整合归档项目落地进程外 `@loomward/plugin-antileak` 与 `@loomward/plugin-decisions`

- 触发：按分阶段实施计划推进 Phase 3，将已归档的 `archive/claude-code-antileak-hooks` 与 `archive/agent-decisions-dashboard` 正式以严格 `out-of-process` 扩展插件形态集成入 LoomWard 微内核；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- `@loomward/plugin-antileak`（[plugins/antileak](../plugins/antileak/src/index.mjs)）：
  - 从 `archive/claude-code-antileak-hooks` 引入离线 R1–R7 策略引擎至 `plugins/antileak/engine/{policy.json,check.py,doctor.py,refresh-private.py,resolve-private.py}`，支持通过 `LOOMWARD_ANTILEAK_POLICY` / `LOOMWARD_ANTILEAK_CACHE` 将私有名单种子与 6 小时动态缓存严格隔离在工作区外私有状态目录，绝不入仓。
  - 新增 `runner.mjs`（`shell: false`、最小净化环境、绝不传递 `--net`、5 秒超时与 1 MiB 预算）对接 `ContentInspect v1` 协议并接入 `tool:invoke@1@before`（命中 R1/R4/R7 规则或私有缓存缺失/过期均在进入审批队列前 fail-closed 阻断），同时注册只读 `console:panel@1` 面板展示缓存新鲜度与拦截计数。
- `@loomward/plugin-decisions`（[plugins/decisions](../plugins/decisions/src/index.mjs)）：
  - 从 `archive/agent-decisions-dashboard` 引入零第三方依赖 Python 标准库 + SQLite 回环台账核心至 `plugins/decisions/service/core/*.py`。
  - 新增 `service-manager.mjs`（严格限定回环地址、支持托管子进程按需启停与卸载清理），向 `tool:provider@1` 注册命名空间工具 `mcp__decisions__export_context`、`mcp__decisions__check_consistency` 与受本机人工审批保护的 `mcp__decisions__record`（透传 CAS `expected_version` 乐观锁冲突 `409` 与 `request_id` 幂等回执），并注册只读 `console:panel@1` 台账状态面板。
- 测试与工作区脚本：更新根目录 `package.json` 使 `test:workspace` 与 `test:ci` 覆盖 `plugins/*/test/*.test.mjs`，并在 `.gitignore` 忽略 `__pycache__/` 与 `*.pyc`。
- 验证范围与边界：本机（Linux x86_64）运行 `pnpm install --frozen-lockfile`、`pnpm run check`（含 Python `py_compile`）、`pnpm run layering`、`pnpm run test:ci`（覆盖既有 162 项 + 新增真实 Python 子进程 `antileak.test.mjs` 与真实 SQLite 回环服务 `decisions.test.mjs`）、`validate_repo_docs.py`、`docs-site` 构建、`repo_maintenance_guard.py status` 与 `sync_assets_licenses.py --check --dry-run`；不改动本机运行中的 `~/.agentdock-bridge` 副本或远端部署。

Synced through c3d1cd2（含 Phase 3 工作树改动）

## 2026-11-23（Phase 4）：独立外部项目适配、Windows 受保护安装对齐与终轮对抗安全加固

- 触发：完成分阶段实施计划最终阶段（Phase 4），补齐 `@loomward/plugin-adapters`、对齐 Windows `Install-Hardened.ps1` 的 monorepo/RPM 安装契约，并针对双源边界、微内核插槽、前置钩子链与网络 SSRF 执行终轮对抗性安全审查；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- `@loomward/plugin-adapters`（[plugins/adapters](../plugins/adapters/src/index.mjs)）：
  - 在不改动独立仓库 `CloudForge` 与 `ModelBridge` 源码本体的前提下，以严格 `out-of-process` 扩展落地双适配器与共享网络边界守卫（[network.mjs](../plugins/adapters/src/network.mjs)：强制远端 HTTPS、拒绝内嵌凭据/元数据 IP/默认私网与回环 SSRF、禁用 HTTP 重定向降级与有界响应读取）。
  - [cloudforge.mjs](../plugins/adapters/src/cloudforge.mjs) 支持 `/.well-known/cloudforge` 匿名元数据探针、RFC 9728/8414 OAuth 2.1 + PKCE `S256` 发现与令牌流、JSON/SSE Streamable HTTP `/mcp` 工具聚合（`mcp__cloudforge__*`，标注读/写风险并全量经由本机逐参人工审批与 24h 防重放账本），并注册只读 `console:panel@1`。
  - [modelbridge.mjs](../plugins/adapters/src/modelbridge.mjs) 提供 `/api/auth/status`、`/api/usage/summary`（递归剥离敏感键）与可选 `/v1/models` 只读观测，硬上限 `12,000ms` 对齐 ModelBridge 超时预算与四态密钥隔离，并注册只读 `console:panel@1`（绝不接触或回显密钥）。
- Windows 受保护安装对齐（[scripts/generate-rpm.mjs](../scripts/generate-rpm.mjs)、[scripts/Install-Hardened.ps1](../scripts/Install-Hardened.ps1)、[scripts/host-cli.mjs](../scripts/host-cli.mjs)）：
  - 抽取跨平台冻结 `rpm.json` 生成脚本，使 Windows `Install-Hardened.ps1` 与 POSIX `host-cli.mjs` 统一复制 `pnpm-workspace.yaml`、`packages/`、`plugins/`（跳过 `test/`、`node_modules/`、`__pycache__/`、`*.pyc`）并在 `installation.json` 中记录 `rpmManifestHash` 与全树 SHA-256。
- 终轮对抗性安全审查与加固：
  - **高危加固 1（`tool:invoke@1` 禁止 `replace` 钩子）**：[packages/kernel/src/boot.mjs](../packages/kernel/src/boot.mjs)、[packages/kernel/src/rules.mjs](../packages/kernel/src/rules.mjs) 与 [packages/shared/src/slots.mjs](../packages/shared/src/slots.mjs) 为 `tool:invoke@1` 锁定 `allowReplace: false`，从结构上杜绝扩展插件替换核心 `LocalApprovals` + 24h `RequestReceipts` 调度主链。
  - **高危加固 2（前置钩子单调阻断与单调强制审批锁存）**：`MechanismSlot.run` 在任一 `before` 钩子返回 `blocked: true` 时立即短路且禁止后续钩子解除阻断或观测受阻载荷；任一 `before` 钩子返回 `forceApproval: true` 时单调锁存，后续钩子无法降级为免审批。
  - **中危加固 3（回环 HTTPS SSRF、防泄漏深层递归与 `control.sock` 误删防护）**：[network.mjs](../plugins/adapters/src/network.mjs) 默认阻止 `https://127.0.0.1` / `https://localhost.` 回环 SSRF；[plugins/antileak/src/index.mjs](../plugins/antileak/src/index.mjs) 为 `extractInspectableText` 增加深度（32）、循环引用与 1 MiB 字符上限；[packages/console/src/control-channel.mjs](../packages/console/src/control-channel.mjs) 拒绝覆盖或删除已存在的非 socket 普通文件或目录。
- 验证范围与边界：本机（Linux x86_64）在最终改动后执行 `pnpm install --frozen-lockfile`、`pnpm run build:console`、`pnpm run check`、`pnpm run layering`、`pnpm run test:ci`（覆盖既有 166 项 + 新增 `adapters.test.mjs` 与终轮安全加固回归测试）、`scripts/generate-rpm.mjs` CLI 实测、`validate_repo_docs.py`、`pnpm --dir docs-site run docs:build`、`repo_maintenance_guard.py status` 与 `sync_assets_licenses.py --check --dry-run`；Windows PowerShell 与真实 Docker 专属用例在非对应环境按条件跳过，未触碰本机 `~/.agentdock-bridge` 运行副本与独立仓 `cloudforge`/`modelbridge`。

Synced through f52606d（含 Phase 4 工作树改动）

## 2026-11-23（全栈基座四路对抗性代码审查与深度加固）：Cordis 4 微内核防逃逸、调度管线闭锁、双源控制台最小权限与进程外扩展命名空间隔离

- 触发：用户要求在进一步扩展独立 LLM 内容审核插件前「先进行一次代码审查，把基座的质量打好」；发起四路并行研究子 Agent 对微内核/安装器、宿主调度管线/入口、双源回环控制台、进程外四插件执行深度对抗性代码审查，全量修复查出的 `8 Critical`、`16 High` 与 `18 Medium/Low` 问题；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- Wave 1 — 微内核、共享原语与受保护安装器（[packages/shared](../packages/shared/src/index.mjs)、[packages/kernel](../packages/kernel/src/index.mjs)、[scripts/generate-rpm.mjs](../scripts/generate-rpm.mjs)、[scripts/host-cli.mjs](../scripts/host-cli.mjs)、[scripts/Install-Hardened.ps1](../scripts/Install-Hardened.ps1)）：
  - `KernelGuard` 改用闭包私有 `WeakMap` 存储单元状态并构造零原型受限上下文门面 `createRestrictedFacade` 与插槽包装器 `wrapSlot`，彻底剥离 `ctx.root` / `reflect` / `registry` / `events` / `fiber` / `Symbol.for('cordis.original')` / `registerBuiltin` 等 Cordis 4 原型链与反射逃逸路径（`C2`、`C3`、`H3`）；`mountExtensionUnit` 强制 `contract.kind === 'extension-plugin'`、单飞防并发重复挂载与 `fiber.state === 2` 校验，阻止扩展伪造 `root-plugin` 或劫持 `ROOT_ONLY_SERVICES`（`C4`、`H2`）。
  - `withDeadline` 为每步逆序回滚增加 2 秒独立超时保护，防止挂起的 Cordis 根插件 `fiber.dispose()` 永久死锁启动器（`C5`）；`PolicyTree` 修复末尾 `*` 匹配、命名空间通配与字典序优先级 dominance，并强制剥离闭锁插槽（`H1`）；`MechanismSlot` 支持 `order` 数值优先级排序、防 getter TOCTOU 与原始值返回冲刷单调锁存（`H4`）；`panel-schema.mjs` 与 `content-guard.mjs` 将 `ToolBlockedError` 与 `applyOutputRedaction`（同时脱敏 `content` 与 `structuredContent`）下沉至 `@loomward/shared`，支持多表 `tables`、清洗控制字符/Bidi 覆盖与 `//`/`/\` 协议相对链接。
  - `generate-rpm.mjs`、`host-cli.mjs` 与 `Install-Hardened.ps1` 补齐顶层目录符号链接校验、双向工作区重叠拦截与 `pnpm install` 后冻结 `rpm.json` 生成及篡改复验（`H5`）。
- Wave 2 — 宿主调度管线、双入口与沙箱闭锁联动（[packages/host](../packages/host/src/pipeline.mjs)、[packages/sandbox](../packages/sandbox/src/index.mjs)、[local/sandbox.mjs](../local/sandbox.mjs)）：
  - `ToolDispatchPipeline` 将 `inflight` 单飞去重、并发通道上限与 `AbortController` 超时定时器前移至 `findOwningProvider` 与 `evaluatePolicyRules` 之前，对异常策略裁决严格 fail-closed，并对 `tools/list` / `collectExternalToolScopes` 做单提供者故障隔离（`H6`、`H7`）；当免批工具被前置内容审核钩子标记 `forceApproval: true` 时，在人工批准消费后补写 24h `RequestReceipts` 持久化防重放回执（`H7`）。
  - `local/sandbox.mjs` 暴露 `isLockedDown()` / `isClosed()` 并在 `createSandboxToolProvider.checkToolEnabled()` 中联动熔断：容器清理失败后在进入审批队列前直接阻断非控制工具，仅保留 `command_status` / `stop_command`（`C6`）。
  - `ingress-relay.mjs` 修复 `notifications/*` 空响应帧、将 `socketRequests` 改为按请求 `Set` 并在异步消息处理与 `socket.send` 外层包裹异常保护；`ingress-local.mjs` 强制检查 `running` 状态；`daemon.mjs` 自动加载校验落盘 `rpm.json`、注入网关与双源回环 `blockedOrigins`，并在启动失败时逆序回滚（`H8`、`H9`）。
- Wave 3A — 进程外扩展插件（[plugins/mcp-hub](../plugins/mcp-hub/src/index.mjs)、[plugins/antileak](../plugins/antileak/src/index.mjs)、[plugins/decisions](../plugins/decisions/src/index.mjs)、[plugins/adapters](../plugins/adapters/src/index.mjs)）：
  - `mcp-hub` 修复 `ownsTool()` 仅匹配 `mcp-servers.json` 中已配置服务并保留 `'decisions'` / `'cloudforge'` 一方命名空间，解决启用 `enableMcpHub: true` 时劫持全部 `mcp__*` 工具的阻断缺陷（`C1`），同时注册只读 `console:panel@1` 面板。
  - `antileak` 递归提取对象键名与顶层标量，在超过 `1 MiB` 或深度 `> 32` 时强制 fail-closed（`ANTILEAK-INPUT-TOO-LARGE` / `ANTILEAK-DEPTH-EXCEEDED`）防填充截断绕过（`C7`）；`runner.mjs` 修复预中止 `AbortSignal` TDZ、传入 `-B` / `PYTHONDONTWRITEBYTECODE=1` / `LOOMWARD_ANTILEAK_*`、按 UTF-8 字节预算流式解码并将阻断原因脱敏为规则分类号（零私有仓名或密钥前缀回显，`H14`）；`check.py` 补齐 `import stat` 与 `O_NOFOLLOW` 4 MiB 缓存上限。
  - `decisions` 修复面板只读轮询误拉起 Python 子进程、`close()` 与启动竞态、子进程 `SIGTERM -> SIGKILL` 回收、`.`/`..` `topic_id` 路径穿越拦截及表格 `workflow_state` 字段映射（`H15`）。
  - `adapters` 在 `network.mjs` 实现完整 8 段 IPv6 解析（覆盖 `[::ffff:169.254.169.254]`、NAT64 `64:ff9b::`、6to4 `2002::`、`fe80::/10`、`fc00::/7`）与 DNS 解析 IP 校验（`C8`）；`cloudforge.mjs` 校验 RFC 8414 `issuer`、改为严格只读前缀白名单（默认写权限，`H16`）、清洗远端工具元数据并严格匹配 SSE JSON-RPC 响应帧；`modelbridge.mjs` 将 `getApiKey()` 纳入异常保护、扩展密钥值脱敏并增加 5 秒单飞快照缓存。
- Wave 3B — 双源回环控制台（[packages/console](../packages/console/src/index.mjs)）：
  - `http-security.mjs` 允许 `GET /` 顶层文档导航跨回环站点跳转，同时对全部 `/*.js`、`/*.css` 与 `/api/*` 维持严格 `Sec-Fetch-Site: same-origin`（`H10`）；`session-broker.mjs` 在 `trustSessions` 淘汰、切回 `tab` 模式与删除 PassKey 时级联吊销关联 Console 会话并在兑换票据时复核 PassKey 强制策略（`H11`）；`panel-registry.mjs` 向面板传入超时 `AbortSignal` 并强制非根插件 `executionBoundary: 'out-of-process'`；`server.mjs` 在 `sha256OfSnapshot` 中剥离 `updatedAt` 且仅在 Console 需要时采集扩展面板；`console-server.mjs` 最小化 Ring 3 快照中的 Ring 2 敏感元数据（`H12`）；`trust/main.mjs` 与 `console/main.mjs` 消除全部内联 `style` 属性（零 CSP 违例）、改为原地更新审批倒计时 DOM（保留复核弹窗滚动位置，`H13`）、同步擦除 URL `#ticket` 并在 `127.0.0.1` 下自动引导至 `localhost` 执行 WebAuthn。
- 验证范围与边界：本机（Linux x86_64）完成 `pnpm run build:console`、`pnpm run check`、`pnpm run layering`、`pnpm run test:ci`（176 项测试：160 通过、0 失败、16 项按平台/Docker 跳过）、`validate_repo_docs.py`、`pnpm --dir docs-site run docs:build`、`repo_maintenance_guard.py pre-commit` 与 `sync_assets_licenses.py --check --dry-run`。

Synced through 3b7e919（含全栈基座四路代码审查与深度加固工作树改动）

## 2026-11-23（二轮对抗性代码审查与深层逃逸封堵）：`ctx.intercept` 原始 Context 逃逸修复、`console:panel@1` 闭包隔离、默认 DNS SSRF 校验与异步会话复验

- 触发：用户在完成首轮 42 项基座加固（`d88bd6e`）后要求「再次进行一次代码审查」；对微内核、宿主调度管线、双源控制台与进程外四插件执行二轮逐行对抗性复审，发现并修复 `1 Critical` 与 `7 High` 深层边界问题；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- 微内核与共享原语（[packages/kernel/src/guard.mjs](../packages/kernel/src/guard.mjs)、[packages/kernel/src/boot.mjs](../packages/kernel/src/boot.mjs)、[packages/kernel/src/rules.mjs](../packages/kernel/src/rules.mjs)、[packages/kernel/src/policy-tree.mjs](../packages/kernel/src/policy-tree.mjs)、[packages/shared/src/guard-types.mjs](../packages/shared/src/guard-types.mjs)、[packages/shared/src/slots.mjs](../packages/shared/src/slots.mjs)）：
  - **Critical `R2-C1`（`ctx.intercept` 返回原始 Cordis `Context` 逃逸）**：Cordis 4 的 `rawCtx.intercept(name, config)` 返回带 `.root` 的子 `Context` 对象而非清理函数，旧实现因 `typeof dispose === 'function'` 为假直接将原始 `Context` 返回给扩展插件；现统一将其包装为受限零原型门面 `createRestrictedFacade`，并新增受 `writes.isolateProvides` 白名单约束的 `ctx.isolate(names)`。
  - **High `R2-H1`（`console:panel@1` 跨插件闭包隔离与根专属服务扩充）**：从扩展插件的 `ImplSlot` 门面移除 `entries()` / `current()` 并在 `ImplSlot.#assertReadAllowed` 中对所有受追踪扩展调用方强制鉴权，防止扩展插件经 `ctx.get('console:panel@1').entries()` 读取其他插件的 `getSnapshot` 闭包；将 `console:loopback`、`host:vault`、`host:approval-ledger` 纳入 `ROOT_ONLY_SERVICES`，且 `wrapService` 在未配置 `serviceMethods` 时同样包裹活跃态与符号剥离代理。
  - **High `R2-H2`（扩展挂载 `fiber.state === 2` 与未声明 `serviceMethods` 拦截）**：`mountExtensionUnit` 在 `await fiber` 后强制校验 `fiber.state === 2`；`slotDeclarationRule` 与 `compileUnitGrant` 拒绝未在 `contract.consumes` 中声明的 `serviceMethods` 目标（`GUARD_SLOT_UNDECLARED`）。
- 宿主调度管线与双入口（[packages/host/src/pipeline.mjs](../packages/host/src/pipeline.mjs)、[packages/host/src/ingress-relay.mjs](../packages/host/src/ingress-relay.mjs)、[packages/host/src/ingress-local.mjs](../packages/host/src/ingress-local.mjs)）：
  - **High `R2-H3` & `R2-H4`**：`isValidJsonRpcReply` 强制校核响应 `id` 与请求 `id` 一致；免批工具在触发 `forceApproval: true` 并获批后同步登记内存 `controlReceipts` 与持久化 `effectiveReceipts`；`ingress-relay.mjs` 将 `lastPong` 初始化为连接建立时刻并引入 `receivedPong` 标志，避免首个 20s 心跳周期误断连；`ingress-local.mjs` 增加 `startEpoch` 防止 `start()` 等待期间调用 `stop()` 被反向置回 `running = true`。
- 进程外扩展插件与双源控制台（[plugins/antileak](../plugins/antileak/engine/check.py)、[plugins/decisions](../plugins/decisions/src/service-manager.mjs)、[plugins/adapters](../plugins/adapters/src/network.mjs)、[packages/console](../packages/console/src/console-server.mjs)）：
  - **High `R2-H5` & `R2-H6`**：修复 `check.py` `load_cache()` 在非普通文件/超限分支提前返回导致的 `fd` 泄漏，并对 `POLICY_PATH` 启用 `O_NOFOLLOW` + `1 MiB` 校验；`extractInspectablePayload` 支持提取 `Uint8Array` / `ArrayBufferView` 载荷；`network.mjs` `fetchBounded` 在使用默认 `globalThis.fetch` 时自动启用 `dns.promises.lookup` 防 DNS 重绑定 SSRF；`cloudforge.mjs` 强制要求 RFC 8414 `issuer` 字段存在且匹配；`modelbridge.mjs` 过滤原型键并脱敏常见 API Key 前缀；`decisions` `httpJsonRequest` 严格锁定路径不脱离回环 `origin`。
  - **High `R2-H7`**：`console-server.mjs` 在 `GET /api/status`、`GET /api/panels` 与 `GET /api/panels/:id` 异步采集面板完成后二次复验会话有效性（防并发吊销泄露在途快照）；`trust-server.mjs` 在审批拒绝时校核 `nlink === 1` 并在会话策略切换时清理其它旧会话；`connectControlSocket` 在 POSIX 上校验 `0600` 权限与当前用户 UID。
- 验证范围与边界：本机（Linux x86_64）运行 `pnpm run check`、`pnpm run layering`、`pnpm run test:ci`（176 项测试：160 通过、0 失败、16 跳过）、`validate_repo_docs.py`、`pnpm --dir docs-site run docs:build`、`repo_maintenance_guard.py pre-commit` 与 `sync_assets_licenses.py --check --dry-run`。

Synced through d88bd6e（含二轮对抗性代码审查与深层逃逸封堵工作树改动）

## 2026-11-23（三轮收官代码审查与原子权限/协议收口）：防泄漏动态缓存 `0600` 原子写、`initialize` 控制路由收口与 `deepFreezeClone` 防环优化

- 触发：用户要求「最后进行一次代码审查」；对尚未逐行复读的辅助脚本、Python 缓存刷新器、控制 RPC 分发分支与静态分层测试做最终收官排查，修复 `4 High/Medium` 边界问题；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- 防泄漏缓存刷新与句柄安全（[plugins/antileak/engine/refresh-private.py](../plugins/antileak/engine/refresh-private.py)、[plugins/antileak/engine/resolve-private.py](../plugins/antileak/engine/resolve-private.py)、[plugins/antileak/engine/check.py](../plugins/antileak/engine/check.py)）：
  - **High `R3-H1` & `R3-H2`**：`refresh-private.py` 与 `resolve-private.py` 写 `private-repos.json` 与 `.resolve.json` 时改为 `0700` 目录 + `O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW` `0600` 带 PID 临时文件，并在 `with os.fdopen(...)` 显式关闭句柄后再执行 `os.replace`，防止私有仓名/R4 业务标识缓存以默认 `0644` 权限落盘或因未关闭句柄在 Windows 下替换失败；统一 `SEED`、`CNB_TOKEN_FILE`、`msgfile` 与 `extra` 的 `with open(...)` 上下文管理。
- 宿主调度控制路由与分层守卫（[packages/host/src/pipeline.mjs](../packages/host/src/pipeline.mjs)、[packages/shared/src/panel-schema.mjs](../packages/shared/src/panel-schema.mjs)、[packages/kernel/test/layering.test.mjs](../packages/kernel/test/layering.test.mjs)）：
  - **High `R3-H3` & `R3-H4`**：移除 `handleControlRpc` 中将 `initialize` / `ping` 抢先转发给 `sandbox-docker.handleRpc` 的冗余分支，确保 `initialize` 始终返回 LoomWard 规范 `serverInfo: { name: 'loomward', version: '3.0.0-alpha.0' }`；`deepFreezeClone` 增加 `Object.isFrozen(node)` 短路并在单次 `tools/call` 中复用 `frozenBody` / `frozenAuth`；`panel-schema.mjs` 在 `tables: []` 为空数组时仍回退保留有效 `table`；`layering.test.mjs` 机械禁止 `@loomward/{shared,kernel,cloud-relay}` 出现越出 `packages/` 的相对导入。
- 验证范围与边界：本机（Linux x86_64）运行 `pnpm run check`、`pnpm run layering`、工作区与插件测试、`validate_repo_docs.py` 与 `repo_maintenance_guard.py pre-commit`。

Synced through bd32c2e（含三轮收官代码审查修复工作树改动）

## 2026-11-23（四轮终审代码审查）：托管决策台账单进程写能力令牌、错误脱敏与 `SIGTERM` 事务排空

- 触发：用户要求「再最后进行一次代码审查」；深入排查 `plugins/decisions/service/core/*.py` 托管子进程边界与 `plugins/mcp-hub` 直接调用防线，发现并修复 `4 High` 问题；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- 托管决策台账审批绕过封堵（`R4-H1`、[plugins/decisions/src/service-manager.mjs](../plugins/decisions/src/service-manager.mjs)、[plugins/decisions/service/core/server.py](../plugins/decisions/service/core/server.py)）：
  - 在 `spawnService: true` 托管模式下，由宿主机为每次拉起的 Python 台账子进程生成 256-bit 随机能力令牌 `LOOMWARD_DECISIONS_SERVICE_TOKEN`；`server.py` 启动导入时立即 `os.environ.pop(...)`（杜绝子 `git` 进程继承）并在全部 `POST` 写路由上以 `hmac.compare_digest` 强制校核 `X-LoomWard-Service-Token`，防止本机其他进程直接向回环端口发起 `POST` 绕过 LoomWard 人工审批流水线；在 [decisions.test.mjs](../plugins/decisions/test/decisions.test.mjs) 新增直连 `POST /api/topic/create` 返回 `401` 回归断言。
- 5xx 宿主路径脱敏、`mcp-hub` 纵深命名空间防护与 `SIGTERM` 优雅停机（`R4-H2`、`R4-H3`、`R4-H4`、[plugins/decisions/src/index.mjs](../plugins/decisions/src/index.mjs)、[plugins/mcp-hub/src/index.mjs](../plugins/mcp-hub/src/index.mjs)）：
  - 截断并脱敏决策台账服务端 `5xx` 异常与未白名单客户端错误消息，防止宿主绝对路径或 SQLite 细节回传至远端调用方；在 `mcp-hub` 的 `callTool()` 中补充 `RESERVED_FIRST_PARTY_SERVERS` 纵深拦截；为 `server.py` 注册 `SIGTERM` 优雅停机处理（触发 `httpd.shutdown()` 与 `httpd.server_close()` 排空在途写事务）并修复 `--port 0` 命令行解析。
- 验证范围与边界：本机（Linux x86_64）运行 `pnpm run check`、`pnpm run layering`、`pnpm run test:ci`（176 项测试：160 通过、0 失败、16 按平台/Docker 跳过）、`validate_repo_docs.py`、`pnpm --dir docs-site run docs:build`、`repo_maintenance_guard.py pre-commit` 与 `sync_assets_licenses.py --check --dry-run`。

Synced through 85b97da（含四轮终审代码审查修复工作树改动）
