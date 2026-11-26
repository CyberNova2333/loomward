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
- 进程外扩展插件与双源控制台（[plugins/antileak](../plugins/antileak/engine/check.py)、[plugins/decisions](../plugins/decisions/src/service-manager.mjs)、[plugins/adapters](../plugins/adapters/src/network.mjs)、原 `packages/console/src/console-server.mjs`）：
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

## 2026-11-24（五轮全库代码审查）：审批摘要规范化、状态文件无 TOCTOU 句柄读取、决策台账软链阻断与外部适配加固

- 触发：用户要求「再进行一次代码审查」；覆盖 `local/`、`cloud/`、`container/` 与 `packages/*`、`plugins/*` 跨层接缝，修复 `6 High` 真实缺陷；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- 审批与状态文件边界（`R5-H1`、`R5-H2`、[local/request-policy.mjs](../local/request-policy.mjs)、[local/approval-store.mjs](../local/approval-store.mjs)、[local/receipts.mjs](../local/receipts.mjs)、[packages/console/src/http-security.mjs](../packages/console/src/http-security.mjs)、[local/webui.mjs](../local/webui.mjs)）：
  - `canonical()` 对齐 `JSON.stringify` 语义（省略对象 `undefined` 键并将数组 `undefined` 项规范为 `null`），消除编程式调用传入可选 `undefined` 字段后经落盘再读取导致 `validRequest` 摘要失配、永久无法批准的缺陷。
  - `approval-store.mjs` `readJson()`、`receipts.mjs` `readReceiptFile()` 及 `http-security.mjs` / `webui.mjs` `readTrustedJsonFile()` 全面改用 `O_RDONLY | O_NOFOLLOW`（异步路径附 `O_NONBLOCK`）+ `fstat` 校验与按句柄有界读取，封堵 `lstat -> readFile` 软链切换 TOCTOU、硬链别名及超限读取。
- 决策台账软链防穿越、生产连接器心跳、控制台会话同步吊销与适配器契约（`R5-H3`–`R5-H6`、[plugins/decisions/service/core/markdown_parser.py](../plugins/decisions/service/core/markdown_parser.py)、[plugins/decisions/service/core/recovery.py](../plugins/decisions/service/core/recovery.py)、[plugins/decisions/service/core/decision_service.py](../plugins/decisions/service/core/decision_service.py)、[local/connector.mjs](../local/connector.mjs)、原 `packages/console/src/trust-server.mjs`、[plugins/adapters/src/cloudforge.mjs](../plugins/adapters/src/cloudforge.mjs)、[plugins/adapters/src/modelbridge.mjs](../plugins/adapters/src/modelbridge.mjs)）：
  - `markdown_parser.py`、`recovery.py` 与 `decision_service.py` 拒绝跟随 `decisions/*.md` 符号链接并限制单文件读取上限（`10 MiB` + `O_NOFOLLOW`），防止符号链接把宿主文件索引进 SQLite 台账与导出上下文。
  - `local/connector.mjs` 同步补齐 `lastPong = Date.now()` 与 `receivedPong` 心跳宽限逻辑，消除首次 `pong` 略超 20s 时误断连问题。
  - `trust-server.mjs` 在切换 `sessionPersistence: 'tab'` 落盘后立即同步轮换 `tabToken` 并吊销其它 Trust 会话、子 Console 会话与 SSE 流，不再等待异步快照刷新完成。
  - `cloudforge.mjs` 与 `modelbridge.mjs` 补齐数组内嵌套 Schema 对象递归清洗、非 SSE JSON-RPC `id`/`jsonrpc` 强校验、并发 `diagnostic` 探针句柄归属隔离及中止信号免污染 5s 缓存。
- 验证范围与边界：本机（Linux x86_64）运行 `pnpm run check`、`pnpm run layering`、`pnpm run test:ci`（178 项测试：162 通过、0 失败、16 按平台/Docker 跳过）、Python 字节码检查、`validate_repo_docs.py`、`pnpm --dir docs-site run docs:build`、`repo_maintenance_guard.py pre-commit` 与 `sync_assets_licenses.py --check --dry-run`。

Synced through aeffb89（含五轮全库代码审查修复工作树改动）

## 2026-11-24（六轮代码审查）：Trust 票据 DOM 零回显、控制通道多字节 UTF-8 与工具链/脚本边界加固

- 触发：用户要求再次「进行一次代码审查」；覆盖此前尚未逐行复核的 `local/node-toolchains.mjs`、`packages/console/web/*`、`packages/console/src/{html,control-channel}.mjs`、`packages/host/src/daemon.mjs`、`local/webui.mjs` 及 `scripts/{cloudflare-api.mjs,State-Safety.ps1,Manage.ps1}`，修复 `6 High` 真实问题；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- 控制台前端与双源隔离（`R6-H2`、`R6-H3`、原 `packages/console/web/trust/main.mjs`、[packages/console/web/console/main.mjs](../packages/console/web/console/main.mjs)、[packages/console/web/shared/client.mjs](../packages/console/web/shared/client.mjs)）：
  - 修复 `window.open(url, '_blank', 'noopener')` 按 HTML 规范恒返回 `null` 导致每次点击「打开观测控制台」都将一次性 `#ticket` 凭据回显到 Trust Origin DOM 通知栏的泄露缺陷；改为 `noopener,noreferrer` 且不再回显原始票据 URL，并重新打包原 `packages/console/dist/trust.js`。
  - 补充客户端 `isSafeNavigationUrl()` 协议校验、WebAuthn `::1` 回环重定向、SSE `status` 重绘保留审批复核弹窗滚动位置及 `\r\n\r\n`/服务端断流即时更新离线状态。
- 控制通道、工具链与运维脚本边界（`R6-H1`、`R6-H4`–`R6-H6`、[local/host-safety.mjs](../local/host-safety.mjs)、[local/node-toolchains.mjs](../local/node-toolchains.mjs)、[packages/console/src/control-channel.mjs](../packages/console/src/control-channel.mjs)、[packages/console/src/html.mjs](../packages/console/src/html.mjs)、[local/webui.mjs](../local/webui.mjs)、[packages/host/src/daemon.mjs](../packages/host/src/daemon.mjs)、[scripts/cloudflare-api.mjs](../scripts/cloudflare-api.mjs)、[scripts/State-Safety.ps1](../scripts/State-Safety.ps1)、[scripts/Manage.ps1](../scripts/Manage.ps1)）：
  - `sha256FileSync()` 与 `node-toolchains.mjs` 清单读取改用 `O_RDONLY | O_NOFOLLOW` + `fstat`，Node 下载强制 `128 MiB` 上限与流完整性检查；`daemon.mjs` 读取 `rpm.json` 与 `local/webui.mjs` 读取 `secrets.meta.json`/`connector-status.json` 改用无 TOCTOU 有界句柄读，`defaultGatewayProbe` 拒绝内嵌凭据并强制 `TLSv1.2`。
  - `control-channel.mjs` 全面改用 `StringDecoder('utf8')` 防跨帧中文乱码、校核目录属主 UID 并为 `connectControlSocket` 挂载默认错误监听；`html.mjs` 限制静态资源白名单；`cloudflare-api.mjs` 禁止重定向与 `/client/v4/` 路径逃逸；Windows `State-Safety.ps1` 补齐 `NODE_USE_ENV_PROXY`/`ELECTRON_RUN_AS_NODE` 清理，`Manage.ps1` 为 `/healthz` 响应增加 `64 KiB` 读取上限。
- 验证范围与边界：本机（Linux x86_64）运行 `pnpm run build:console`、`pnpm run check`、`pnpm run layering`、`pnpm run test:ci`（180 项测试：164 通过、0 失败、16 按平台/Docker 跳过）、`validate_repo_docs.py`、`pnpm --dir docs-site run docs:build`、`repo_maintenance_guard.py pre-commit` 与 `sync_assets_licenses.py --check --dry-run`。

Synced through c525fcd（含六轮代码审查修复工作树改动）

## 2026-11-24（七轮全库对抗性代码审查）：微内核沙箱逃逸封堵、OAuth 重放吊销、双源控制台竞态与多语言引擎/脚本加固

- 触发：用户要求「继续」推进多轮代码审查与「循环审查直到查不出新问题为止」；第 7 轮经 5 路并行对抗性审计并对照 `cordis@4.0.0-rc.11`、`ws@8.22.0`、`@cloudflare/workers-oauth-provider@1.2.4` 实际依赖验证，共核实并修复 **43 项**真实缺陷（`2 Critical`、`29 High`、`12 Medium/Low`）；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- 微内核、共享原语与宿主调度（[packages/kernel/src/guard.mjs](../packages/kernel/src/guard.mjs)、[boot.mjs](../packages/kernel/src/boot.mjs)、[policy-tree.mjs](../packages/kernel/src/policy-tree.mjs)、[packages/shared/src/slots.mjs](../packages/shared/src/slots.mjs)、[panel-schema.mjs](../packages/shared/src/panel-schema.mjs)、[contracts.mjs](../packages/shared/src/contracts.mjs)、[content-guard.mjs](../packages/shared/src/content-guard.mjs)、[packages/host/src/ingress-relay.mjs](../packages/host/src/ingress-relay.mjs)、[ingress-local.mjs](../packages/host/src/ingress-local.mjs)、[pipeline.mjs](../packages/host/src/pipeline.mjs)）：
  - 封堵 Cordis 4 `TRACKER` / `Context` / `Fiber`（含异步返回值）逃逸、`check` 回调伪造、同步 `ctx.effect` / `ctx.on` `this` 泄漏与 `reflect._getImpl` 绕过 `getTraceable`；改用可扩展影子目标重构 `wrapService` 代理以封闭 `has`/`ownKeys`/`getPrototypeOf`/`call`/`apply`/`bind`/`__proto__` 与 `constructor` 访问；`bindContext` 跳过 `#rootFibers` 保住 `control.getService()`；`ctx.isolate` 逐项迭代隔离；为扩展与根卸载/停机引入 `disposeFiberBounded(fiber, 2000)` 有界停机及停机态幂等检查；`PolicyTree` 闭锁规则补全具名动作节点并采用 `matchPermissionNode` 语义判定越权请求。
  - `MechanismSlot.run` 与 `@loomward/shared` 契约/面板/内容守卫校验全面采用单次本地快照读取消除 Getter-TOCTOU（`after` 默认与只读钩子禁止篡改不可变输入）；`ingress-relay.mjs`（与 `local/connector.mjs`）在 `unexpected-response` 时显式销毁请求与底层 socket 打破 `CONNECTING` 永久挂起；`pipeline.mjs` 与 `ingress-local.mjs` 通过 `normalizeErrorRpcId` 规范错误回包 `id`。
- 云端网关、外部 MCP 与双源控制台（[cloud/index.mjs](../cloud/index.mjs)、[cloud/auth-store.mjs](../cloud/auth-store.mjs)、[local/connector.mjs](../local/connector.mjs)、[local/mcp-registry.mjs](../local/mcp-registry.mjs)、[local/mcp-client.mjs](../local/mcp-client.mjs)、[local/webui-assets.mjs](../local/webui-assets.mjs)、原 `packages/console/src/trust-server.mjs`、原 `packages/console/src/console-server.mjs`、[server.mjs](../packages/console/src/server.mjs)、原 `packages/console/web/trust/main.mjs`、[console/main.mjs](../packages/console/web/console/main.mjs)、原 `packages/console/dist/trust.js`）：
  - 移除 `codeWasUsed`/`consumeCode` 拦截，严格恢复 RFC 9700 / OAuth 2.1 §4.1.2 授权码重放即吊销整条 grant 的契约；修复 `/oauth/revoke` 在 `grant_type=` 空值表单下的 `SyntaxError` `503` 崩溃。
  - `mcp-registry.mjs` 脱敏覆写含裸查询参数与 URL hash 的凭据片段，`mcp-client.mjs` 按 `lastProbeAt` 精确失效 `cachedTools` 热缓存，`webui-assets.mjs` 修复探测失败时勿以 `%5BREDACTED%5D` 覆写已存密钥。
  - `trust-server.mjs` 将 `sessionPersistence: 'tab'` 切换中会破坏前置鉴权的 `tabToken` 轮换推迟至 `await refreshSnapshot` 之后（同时提前同步撤销其它会话与 Console 权限），前端收到新 `tabToken` 立即重启 SSE；`server.mjs` 补齐 `Trust` 端口绑定失败清理；`console-server.mjs` 兼容 `passkeyRequired ?? requirePasskey`；`console/main.mjs` 将过期 `#ticket` 兑换隔离捕获以免阻断既有浏览器会话加载。
- 进程外扩展插件与 Python/PowerShell/运维脚本（[plugins/antileak/engine/check.py](../plugins/antileak/engine/check.py)、[resolve-private.py](../plugins/antileak/engine/resolve-private.py)、[refresh-private.py](../plugins/antileak/engine/refresh-private.py)、[doctor.py](../plugins/antileak/engine/doctor.py)、[plugins/decisions/service/core/markdown_parser.py](../plugins/decisions/service/core/markdown_parser.py)、[decision_service.py](../plugins/decisions/service/core/decision_service.py)、[config.py](../plugins/decisions/service/core/config.py)、[git_engine.py](../plugins/decisions/service/core/git_engine.py)、[server.py](../plugins/decisions/service/core/server.py)、[plugins/decisions/src/service-manager.mjs](../plugins/decisions/src/service-manager.mjs)、[plugins/adapters/src/network.mjs](../plugins/adapters/src/network.mjs)、[scripts/host-cli.mjs](../scripts/host-cli.mjs)、[scripts/record-hardening.mjs](../scripts/record-hardening.mjs)、[scripts/State-Safety.ps1](../scripts/State-Safety.ps1)、[scripts/Manage.ps1](../scripts/Manage.ps1)、[scripts/Secrets.ps1](../scripts/Secrets.ps1)、[tools/repo_maintenance_guard.py](../tools/repo_maintenance_guard.py)、[local/host-safety.mjs](../local/host-safety.mjs)）：
  - 防泄漏引擎收敛策略正则预编译（fail-closed）、严格 base64 匹配与 ASCII 仓库候选提取、保护合法 `#` 提交正文并补全根提交与 `%x00` Git 解析；私有仓刷新与解析统一分离令牌开关、fail-closed 与 `O_CREAT | O_EXCL | O_NOFOLLOW` 独占临时文件；`doctor.py` 修复句柄泄漏与缺失目录崩溃。
  - 决策台账加强 YAML 字符串/Unicode 行分隔符与前端元数据校验、经 `parse_markdown_file`（`O_NOFOLLOW`）安全读盘、补齐回滚路径与参数校验及解析 `repo_root`/`base_dir`；`service-manager.mjs` 与 `server.py` 消除端口 TOCTOU 改为 `LOOMWARD_READY` 握手与 `/api/status` HMAC-SHA256 `token_proof` 校验（令牌仅随 `POST` 发送）。
  - 外部适配器规范化尾部点号域名，并在默认 HTTP/HTTPS 请求改为直连 `node:http`/`node:https`（自定义钉死 IP 查找、强制 `TLSv1.2`、阻断 `3xx` 重定向并将 DNS 查询纳入同一超时与 `AbortSignal`）。
  - 安装/守护/守卫脚本修复 systemd 单元 `%`/`$` 转义、多段重启与孤儿连接器清理、`record-hardening.mjs` 对 `rpm.json` 哈希兼容、`git ls-files --literal-pathspecs`、`State-Safety.ps1` `//host/share` 拦截、`Manage.ps1`/`Secrets.ps1` 路径规范化及 macOS `ps` `TZ=UTC` 钉死。
- 验证范围与边界：本机（Linux x86_64）运行 `node --check`（脚本）、`python3 -m py_compile`（全部 Python 引擎与守卫）、`pnpm run build:console`、`pnpm run check`、`pnpm run layering`（3/3）、`pnpm run test:ci`（188 项测试：172 通过、0 失败、16 按平台/Docker 跳过）、`validate_repo_docs.py`、`pnpm --dir docs-site run docs:build` 与 `sync_assets_licenses.py --check --dry-run`。

Synced through 3d53c2c（含七轮全库代码审查修复工作树改动）

## 2026-11-24（八轮全库对抗性代码审查）：微内核符号与在途停机隔离、SSRF 协议头修复、宿主与多语言引擎/脚本加固

- 触发：用户要求「循环审查直到查不出新问题为止」并持续推进（`继续`）；第 8 轮经 5 路并行对抗性审计与回归验证闭环，共核实并修复 **32 项**既定缺陷（`1 Critical`、`12 High`、`14 Medium`、`5 Low`）及回归验证中暴露的 5 项深层接缝缺陷；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- 微内核、共享原语与沙箱（[packages/shared/src/slots.mjs](../packages/shared/src/slots.mjs)、[deadline.mjs](../packages/shared/src/deadline.mjs)、[packages/kernel/src/boot.mjs](../packages/kernel/src/boot.mjs)、[guard.mjs](../packages/kernel/src/guard.mjs)、[policy-tree.mjs](../packages/kernel/src/policy-tree.mjs)、[packages/sandbox/src/index.mjs](../packages/sandbox/src/index.mjs)、[packages/host/src/pipeline.mjs](../packages/host/src/pipeline.mjs)）：
  - `MechanismSlot.run` 向 `before`/`replace`/次参 `after` 传递浅冻结副本，拦截钩子就地篡改 `input.toolName`/`input.forceApproval` 及通过返回 `undefined` 绕过不可变输入/单调批准锁存。
  - 移除 `withDeadline`/`runBoundedStep`/`disposeFiberBounded` 看门狗定时器 `.unref()`，防止挂起扩展析构时 Node 因事件循环无活动句柄提前以退出码 `13` 退出；`control.stop()` 对 `inFlightMounts` 建立 `Promise.race` 中止竞态句柄并清除映射后再逐一卸载。
  - `PolicyTree` `nodeTouchesForbiddenTarget` 剥离 `#<method>` 后缀双探 `#*` 与裸目标，防止具名方法 `extraNodes` 绕过闭锁槽；`KernelGuard` 屏蔽全量 `Symbol.for('cordis.*')` 符号、`hasCordisInternalRef`、`isSameOrCordisShadow` 链式 `return this`、自定义 Symbol 方法代理及 `methods.isolate` 单次快照、`methods.provide` 内部引用/符号拦截、`effect`/`on` 异步清理归零。
  - `@loomward/sandbox` `apply()` 将计算后的 `effectiveRoots` 与 `allowOutbound` 透传进 `createSandboxRuntime`（附可选测试注入回调 `createRuntime`）；`handleControlRpc` 仅对无 `id` 的 `notifications/*` 返回 `undefined`，含 `id` 通知返回 `-32601`。
- 云端与本地核心、双源控制台及进程外插件/引擎（[local/connector.mjs](../local/connector.mjs)、[host-safety.mjs](../local/host-safety.mjs)、[mcp-client.mjs](../local/mcp-client.mjs)、[sandbox.mjs](../local/sandbox.mjs)、[webui.mjs](../local/webui.mjs)、原 `packages/console/src/trust-server.mjs`、[plugins/adapters/src/network.mjs](../plugins/adapters/src/network.mjs)、[plugins/antileak/engine/check.py](../plugins/antileak/engine/check.py)、[resolve-private.py](../plugins/antileak/engine/resolve-private.py)、[plugins/decisions/service/core/decision_service.py](../plugins/decisions/service/core/decision_service.py)、[git_engine.py](../plugins/decisions/service/core/git_engine.py)、[markdown_parser.py](../plugins/decisions/service/core/markdown_parser.py)、[plugins/decisions/src/service-manager.mjs](../plugins/decisions/src/service-manager.mjs)）：
  - 修正 `connector.mjs` 停止回执三目反转并保护 `socket.send`；`host-safety.mjs` 将 `NODE_USE_ENV_PROXY`/`ELECTRON_RUN_AS_NODE` 纳入清理并全量校核多工作区根目录；`mcp-client.mjs` 拒绝期望响应下的空白 HTTP 200 正文并在唯一等待者中止时立即驱逐 `connecting`；`local/sandbox.mjs` 修复含 `id` `notifications/*` 误返 `undefined`；`trust-server.mjs` 与 `webui.mjs` 用 `try/finally` 保护会话切换刷新且收敛 `/api/mcp-servers/probe` 非 HTTP 4xx 异常（保留 `409`/`429`/`499`）。
  - `network.mjs` 拒绝空标签主机并直接按字面 IP 实施 `allowLoopbackHttp`/`allowPrivateNetwork`/元数据 IP 拦截（标定 `UNSAFE_TARGET_URL` 错误码），并将 `Array.isArray(headers)` 置于 `forEach` 判定之前避免 `[k, v][]` 元组请求头误走 `Array.prototype.forEach`。
  - `check.py` 将 `RESOLVE_IGNORE` 初始化移入策略 fail-closed 保护区、用正向先行断言提取 `.git`/多段 URL slug 候选并进一步收紧 `in_b64_run`；`resolve-private.py` 启用大小写无关配对、`rpartition('/')` 适配多段群组路径及 `__main__` 入口守卫；`decision_service.py` 先初始化回滚状态变量防止备份失败引发 `UnboundLocalError`/损坏活库、`git_engine.py` 过滤不存在未跟踪路径、`markdown_parser.py` 全量切换 `_split_lines_lf`、`service-manager.mjs` 校验数字字符串端口并在退出时清空句柄使只读探针不副作用拉起子进程。
- 脚本与机械守卫（[scripts/record-hardening.mjs](../scripts/record-hardening.mjs)、[scripts/Manage.ps1](../scripts/Manage.ps1)、[scripts/host-cli.mjs](../scripts/host-cli.mjs)、[packages/kernel/test/layering.test.mjs](../packages/kernel/test/layering.test.mjs)）：
  - `record-hardening.mjs` 改为相对引入共享哈希、`O_NOFOLLOW` + `fstat` 防逃逸核验 `sourceRoot` 扩展与工作区包/插件并修正 `buildReleaseRpm({ sourceRoot: root, destinationRoot: root })`；`Manage.ps1` 修复 `-Action Stop` 等候连接器退出及 `-Action Run` 快速失败退避自增死锁；`host-cli.mjs` 前置 `clearNodeOverrides()`、严格校验 Docker context 与清理环境并以原子写入写 systemd 单元；`layering.test.mjs` 升级为词法状态机扫描器阻断字符串内 `/*...*/`、正则 `/`、无空格导入与动态加载器绕过。
- 验证范围与边界：本机（Linux x86_64）运行 `node --check`、`python3 -m py_compile`、`pnpm run build:console`、`pnpm run check`、`pnpm run layering`（4/4）与 `pnpm run test:ci`（197 项测试：181 通过、0 失败、16 按 Windows/Docker 条件跳过）；`pwsh` 本机未安装（Windows `.ps1` 未实机运行）。

Synced through 7ce1226（含八轮全库代码审查修复工作树改动）

## 2026-11-24（九、十轮全库对抗性代码审查与零问题收敛）：外部 MCP 单飞与探针隔离、Guard Symbol 强转、决策轮次/元文件防护、CNB 多段群组与全词法分层守卫

- 触发：第 9 轮 5 路并行审查在 `b5218a7` 上核实并修复 **10 项**真实缺陷（`9 Medium`、`1 Low`），随后经第 10 轮 5 路对抗性复审全部收敛为 `NO GENUINE ISSUES FOUND`（`audit-core`、`audit-console`、`audit-plugins` 与 `audit-scripts` 一次通过，`audit-kernel` 对 `packages/kernel/test/layering.test.mjs` 词法状态机连续深度攻防迭代闭环后归零）；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- 本地核心与双源控制台（[local/mcp-client.mjs](../local/mcp-client.mjs)、原 `packages/console/src/trust-server.mjs`、[local/webui.mjs](../local/webui.mjs)、原 `packages/console/test/dual-origin-console.test.mjs`、[capabilities-webui.test.mjs](../test/capabilities-webui.test.mjs)、[external-mcp.test.mjs](../test/external-mcp.test.mjs)）：
  - `mcp-client.mjs` `ensureSession` 预登记 `selfRecord` 至 `connecting` 并把 `createStdioMcpSession` / `createHttpMcpSession` 同步构造纳入同一 `try/catch/finally` 守卫（`if (session) await session.close().catch(() => {})`），修复缺失 `cwd` 等同步构造异常导致 `selfRecord` 悬空与 `session.close()` `TypeError`，新增重试恢复回归测试。
  - `trust-server.mjs` 与 `webui.mjs` 抽离 `runAndPersistBoundedProbe` 并将 `runBoundedProbe` 与 `saveMcpProbeResultSync` 解耦：Trust Origin `POST /api/mcp-servers/import` 补齐有界批量探针（上限 `8` 台启用服务、`2` 并发 worker、`45s` 总预算、`conflictMode: 'record'`）；`POST /api/mcp-servers/save` 使用 `conflictMode: 'return'`，在 `409`/`429` 时保留 HTTP `200` 响应契约且不覆写磁盘既有探测态、遇到 `499`（断连/关停）直接重抛、普通探针失败经 `redactSecretsFromText` 脱敏后再持久化，并透传非 `NOT_FOUND` 写入异常；补齐 `dual-origin-console.test.mjs` 与 `capabilities-webui.test.mjs` 回归用例。
- 微内核与机械分层守卫（[packages/kernel/src/guard.mjs](../packages/kernel/src/guard.mjs)、[kernel.test.mjs](../packages/kernel/test/kernel.test.mjs)、[layering.test.mjs](../packages/kernel/test/layering.test.mjs)）：
  - `guard.mjs` `wrapMethodMember` 在无 `serviceMethods` 与受控方法双分支统一使用 `const memberLabel = String(memberName)`，消除 `[Symbol.iterator]()` 等 Symbol 方法调用在 `#assertUnitActive` 与 `sanitizeServiceReturn` 拼接时触发 `TypeError`（附 `kernel.test.mjs` 回归断言）。
  - `layering.test.mjs` 升级 `scanJsSource` / `parseImportSpecifiersFromSource` 词法状态机：补全字符串/模板转义解码（`decodeJsEscapeAt`）、行终止符与 ASI（`debugger`/`break`/`continue`/`import`/`export ... from`、`return`/`throw`/`yield`、`async [no LineTerminator here] function`）、嵌套括号与尾逗号动态加载器、`?.` 可选链、字符串别名再导出 `export * as "str"`、`classStack` 嵌套继承头、`template_part` 上下文、`for` 头部上下文 `of` 判定、`private_ident` `#ident` 与 `#!` Shebang，以及 `??`/`??=` 不入 `ternaryStack` 与 `;` 按当前深度清栈；新增全部用例均经 `node --input-type=module --check` 对等核验。
- 进程外扩展与多语言引擎（[plugins/decisions/service/core/recovery.py](../plugins/decisions/service/core/recovery.py)、[decision_service.py](../plugins/decisions/service/core/decision_service.py)、[decisions.test.mjs](../plugins/decisions/test/decisions.test.mjs)、[plugins/antileak/engine/refresh-private.py](../plugins/antileak/engine/refresh-private.py)、[check.py](../plugins/antileak/engine/check.py)、[antileak.test.mjs](../plugins/antileak/test/antileak.test.mjs)）：
  - `recovery.py` 与 `decision_service.py` 共享 `reconstruct_rounds_from_discussion` 统一匹配 `第 N 轮` 与 `Round N`（忽略大小写）并将未匹配项隔离进 `unmatched_items` 防 `rounds_map` 键碰撞覆写；新增 `_resolve_metadata_json_path`、`_read_regular_json_bytes`（`is_symlink()`、`O_RDONLY | O_NOFOLLOW | O_NONBLOCK`、`S_ISREG` 与 `10 MiB` 上限）及 `_atomic_write_bytes`，加固 `check_consistency`、`rollback_full` 与 `record_verification` 对 `metadata.json` 的读写与回滚清理（附 `decisions.test.mjs` 回归用例）。
  - `refresh-private.py` 按全部已遍历 `cnb_groups` 路径分段（`gp.split('/')`）填充 `owners`；`check.py` `slug_candidates` 对 `RX_SLUG` 裸候选同样大小写无关剥离 `.git` 后缀并在 `resolve_unknown` 合并 `cnb_groups` 分段，防止空/仅公开子群组或 `.git` 裸名绕过 `--net` 解析（附 `antileak.test.mjs` 回归用例）。
- 验证范围与边界：本机（Linux x86_64）运行 `node --check scripts/cloudflare-api.mjs scripts/record-hardening.mjs scripts/host-cli.mjs`、`python3 -m py_compile`、`pnpm run build:console`、`pnpm run check`、`pnpm run layering`（10 项全部通过）、`pnpm run test:ci`（209 项测试：193 通过、0 失败、16 按 Windows/Docker 条件跳过）、`validate_repo_docs.py`、`pnpm --dir docs-site run docs:build`、`sync_assets_licenses.py --check --dry-run` 与 `repo_maintenance_guard.py pre-commit`；`pwsh` 本机未安装，Windows `.ps1` 与 `AGENTDOCK_DOCKER_TEST=1` 用例未实机执行。

Synced through b5218a7（含九、十轮全库代码审查修复与零问题收敛工作树改动）

## 2026-11-25：实施多模态 LLM 内容审查插件（`@loomward/plugin-llm-moderation`）、内核密钥绑定与端到端原生流式通道

- 触发：用户批准多模态 LLM 内容审查实施计划并授权开始实施，且明确要求保留并显式记录旧入口的非流式降级兼容处理；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- 共享契约、SSRF 防线与微内核扩展（[packages/shared/src/index.mjs](../packages/shared/src/index.mjs)、[network-policy.mjs](../packages/shared/src/network-policy.mjs)、[plugin-secrets.mjs](../packages/shared/src/plugin-secrets.mjs)、[moderation-config.mjs](../packages/shared/src/moderation-config.mjs)、[content-guard.mjs](../packages/shared/src/content-guard.mjs)、[packages/kernel/src/boot.mjs](../packages/kernel/src/boot.mjs)、[guard.mjs](../packages/kernel/src/guard.mjs)、[plugins/adapters/src/network.mjs](../plugins/adapters/src/network.mjs)）：
  - 下沉纯零依赖 IPv4/IPv6/NAT64/Origin SSRF 校验原语至 `@loomward/shared` 并由 `@loomward/plugin-adapters` 复用；新增扩展命名空间凭据契约（`plugin:secrets@1` / `host:plugin-secrets-admin`）、策略配置校验（`local-only` / `guard-plus-canary` / `cloud-first` / `hybrid-tiered`，预设 `strict` / `balanced` / `experimental-resilient`）及向下兼容的 `ContentInspect v2` 多模态包、流水线分阶段（`combined` / `stream_*`）、`inducement` 遥测与局部脱敏结构。
  - Cordis 内核新增不可替换 `tool:stream@1` 流式机制槽（`allowReplace: false`）；`KernelGuard` 屏蔽 `PLUGIN_SECRET_BINDER`、禁止对 `plugin:secrets@1` 执行 `isolate`/`intercept`，并在 `wrapResolvedValue` 内按真实 caller `state.unitId` 强制绑定命名空间。
- 端到端原生流式、Ring 2 只写密钥与策略界面（[cloud/index.mjs](../cloud/index.mjs)、[cloud/relay.mjs](../cloud/relay.mjs)、[cloud/security.mjs](../cloud/security.mjs)、[packages/cloud-relay/src/protocol.mjs](../packages/cloud-relay/src/protocol.mjs)、[packages/host/src/pipeline.mjs](../packages/host/src/pipeline.mjs)、[plugin-secrets.mjs](../packages/host/src/plugin-secrets.mjs)、[ingress-relay.mjs](../packages/host/src/ingress-relay.mjs)、[ingress-local.mjs](../packages/host/src/ingress-local.mjs)、[daemon.mjs](../packages/host/src/daemon.mjs)、[local/moderation-config.mjs](../local/moderation-config.mjs)、原 `packages/console/src/trust-server.mjs`、原 `packages/console/web/trust/main.mjs`）：
  - `POST /mcp` 支持独占 `Accept: text/event-stream` 或 `_meta.loomwardStream` 协商，`BridgeRelay`（`MAX_STREAM_CHUNKS=512`、`MAX_STREAM_TOTAL_BYTES=8 MiB`）与宿主机流水线打通先本机审批后分片推流通道，`tool:stream@1` 保持 `releaseChunks` / `heldBack` 尾部暂留与即时中止控制；宿主机提供 `0600` 分仓 `createPluginSecretsStore`，Ring 2 Trust Origin（`18798`）新增只写插件密钥管理与内容安全策略开关（Ring 3 只读控制台严禁写操作）。
  - **显式记录降级兼容处理（待后续补齐）**：直接通过 [连接器主流程](../local/connector.mjs) / `scripts/host-cli.mjs` 启动的旧版 v2 独立路径暂不消费 `message.stream`，仍仅回传单帧 `{ type: 'response' }`，由 [中继对象](../cloud/relay.mjs) 自动降级为单事件 SSE 后关流；已在 [云端网关、OAuth 2.1 与中继交接](modules/cloud-oauth-and-relay.md) 与 `local/connector.mjs` 中显式标记，后续统一迁移或补齐流式能力。
- 多模态审查插件与 Python 引擎（[plugins/llm-moderation/src/index.mjs](../plugins/llm-moderation/src/index.mjs)、[stream-session.mjs](../plugins/llm-moderation/src/stream-session.mjs)、[service-manager.mjs](../plugins/llm-moderation/src/service-manager.mjs)、[engine/router.py](../plugins/llm-moderation/engine/router.py)、[canary_probe.py](../plugins/llm-moderation/engine/canary_probe.py)、[media_sanitizer.py](../plugins/llm-moderation/engine/media_sanitizer.py)、[eval_runner.py](../plugins/llm-moderation/engine/eval_runner.py)、[engine/backends/](../plugins/llm-moderation/engine/backends/)）：
  - 在 `tool:invoke@1` 上以 `order: 50` 严格晚于离线 `antileak`（`order: 10`）执行，全面覆盖 `input-only` / `output-only` / `combined` 关联（`InvocationCorrelationStore`）及 `tool:stream@1` 跨块滑窗（`StreamInspectSession`）；独立 Python 回环子进程（`LOOMWARD_READY` + HMAC 握手 + `X-LoomWard-Service-Token`）统合 Local Guard（Ollama/vLLM/ModelBridge/规则库）、无工具 Nonce 沙箱防诱导金丝雀探针与 `eval_runner.py` 基准评测器、四大云端审核驱动（OpenAI/Webhook、阿里云绿网、腾讯云天御、百度 AIP）及多模态安全预检（按模态缺失解码依赖时 fail-closed，不影响纯文本/云端链路）。
- 验证范围与边界：本机（Linux x86_64）完成 `pnpm run build:console`、`pnpm run check`（全工作区 + Python 字节码编译）、`pnpm run layering`（10/10）、`pnpm run test:ci`（218 项测试：202 通过、0 失败、16 按 Windows/Docker 条件跳过，含 `plugins/llm-moderation` Node 集成与 Python `unittest` 云端签名/SSRF/评测全套），同步校验 `repo-docs`、VitePress 文档站构建、许可摘要核对与维护守卫。

Synced through 6e6ea7d（含 `@loomward/plugin-llm-moderation`、原生流式通道与 Trust 密钥策略配置工作树改动）

## 2026-11-25（控制台架构合并）：收拢双源界面为单源统一回环控制台

- 触发：用户确认服务端部署无需浏览端 Trust Origin / Console Origin 物理分源隔离，明确要求「合并为单源统一面板」；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- 单源后端合并与契约清理（[packages/console/src/unified-server.mjs](../packages/console/src/unified-server.mjs)、[server.mjs](../packages/console/src/server.mjs)、[session-broker.mjs](../packages/console/src/session-broker.mjs)、[html.mjs](../packages/console/src/html.mjs)、[index.mjs](../packages/console/src/index.mjs)、[contract.mjs](../packages/console/src/contract.mjs)、[guard-types.mjs](../packages/shared/src/guard-types.mjs)、[panel-schema.mjs](../packages/shared/src/panel-schema.mjs)、[daemon.mjs](../packages/host/src/daemon.mjs)）：
  - 删除独立 Trust Origin（`18798`）监听、`console:trust-origin` 服务声明与 60s 跨源 `#ticket` 移交逻辑；由 `startUnifiedConsole` 在单一回环端口（默认 `127.0.0.1:18797`）提供 `console:loopback` 服务，完整保留 `Host`/`Origin`/`Sec-Fetch-Site`/CSRF、`X-LoomWard-Tab-Auth`、WebAuthn PassKey ES256、两步逐参审批、能力总开关、只写插件密钥、多模态策略配置、MCP 探针与 SSE 实时推送。
  - 声明式扩展面板（`console:panel@1`）仍保持纯 JSON 与 `textContent`/安全 URL 过滤只读渲染约束，严禁插件注入可执行脚本或 HTML。
- 前端重构与离线构建同步（[packages/console/web/console/main.mjs](../packages/console/web/console/main.mjs)、[console.css](../packages/console/web/console/console.css)、[build-web.mjs](../packages/console/scripts/build-web.mjs)）：
  - 移除 `web/trust/` 与 `dist/trust.*`，合并为单一 `console.{js,css}` 离线包并采用文档站一致的分组侧边导航栏（`运行总览` / `安全与治理` / `扩展与观测` 共 8 项独立专注视图：系统概览、待审审批队列、能力开关与服务、LLM 审查策略、插件密钥库、声明式扩展面板、实时审计通道、聚合工具目录，配合移动端抽屉与草稿防覆盖），彻底替代多栏卡片堆叠与跨源弹窗。
- 验证范围与边界：本机（Linux x86_64）运行 `pnpm run build:console`、`pnpm run check`、`pnpm run layering`、`pnpm run test:ci`、Chromium CDP 桌面/移动端无报错无水平溢出视觉核验、`validate_repo_docs.py`、`pnpm --dir docs-site run docs:build`、`sync_assets_licenses.py --check --dry-run` 与 `repo_maintenance_guard.py pre-commit`；`pwsh` 本机未安装，Windows `.ps1` 与 `AGENTDOCK_DOCKER_TEST=1` 用例未实机执行。

Synced through 6e6ea7d（含单源统一回环控制台工作树改动）

## 2026-11-25（本地模型接入升级）：Ollama 运行时安装/拉取托管、原生 `/api/chat` 适配与局域网 GPU 边界收敛

- 触发：用户要求为本地模型功能加入安装与接入 Ollama 能力，并在提问确认后明确范围：统一控制台受控安装/启停/拉取托管、`allowPrivateNetwork` 按端点放行受信任局域网 GPU HTTP（仍持续阻断云元数据与公网明文 HTTP），以及 Ollama 原生 `/api/tags`/`/api/ps`/`/api/chat`、`think: false` 与条件化 `format: "json"` 全适配；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- 共享网络策略、审核配置与 Python 审查引擎（[packages/shared/src/network-policy.mjs](../packages/shared/src/network-policy.mjs)、[moderation-config.mjs](../packages/shared/src/moderation-config.mjs)、[plugins/llm-moderation/engine/net_guard.py](../plugins/llm-moderation/engine/net_guard.py)、[common.py](../plugins/llm-moderation/engine/backends/common.py)、[local_guard.py](../plugins/llm-moderation/engine/backends/local_guard.py)、[small_model.py](../plugins/llm-moderation/engine/backends/small_model.py)、[router.py](../plugins/llm-moderation/engine/router.py)）：
  - `assertSafeIntegrationOrigin` / `assertSafeTargetUrl` 与 `net_guard.py` 支持仅在显式启用 `allowPrivateNetwork` 时允许受信任私有局域网 HTTP 节点，在 Python `ipaddress` 判定中前置拦截链路本地/元地址（避免 `169.254.169.254` 因 `is_private == True` 绕过）并持续阻断公网明文 `http://` 与 DNS 重绑定。
  - `validateModerationConfig` 为 `localGuard`（`http`/`ollama`/`managed-python`）与 `canary`（`http`/`ollama`）补齐 `think`（默认 `false`）与 `allowPrivateNetwork`（默认 `false`），当 `kind: 'ollama'` 未填端点时默认指向 `http://127.0.0.1:11434/`。
  - Python 引擎原生适配 Ollama `/api/chat`：下发 `think: false` 并剥离 `<think>...</think>`，对通用模型启用 `format: "json"` 而对 `llama-guard`/`shieldgemma` 保留原生输出格式，并直传多模态图像 `images` base64 数组。
- 宿主运行时托管、统一控制台路由/UI 与宿主 CLI（[local/ollama.mjs](../local/ollama.mjs)、[packages/console/src/unified-server.mjs](../packages/console/src/unified-server.mjs)、[server.mjs](../packages/console/src/server.mjs)、[packages/console/web/console/main.mjs](../packages/console/web/console/main.mjs)、[console.css](../packages/console/web/console/console.css)、[scripts/host-cli.mjs](../scripts/host-cli.mjs)）：
  - 新增 [local/ollama.mjs](../local/ollama.mjs) 实现二进制探测、剥离凭据环境变量后的受控安装（强制 `confirmInstall: true`）、仅回环 `ollama serve` 拉起、NDJSON 模型拉取进度追踪及钉死 IP 的 `/api/version` + `/api/tags` + `/api/ps` + `/api/chat` 推理测速，配套 `host-cli.mjs ollama <status|install|start|pull|test>`。
  - 单源统一控制台新增 `/api/moderation/ollama/{status,install,start,pull,test}` 与侧边栏「LLM 审查策略」内的 Ollama 运行时面板（自动发现本机模型、`VRAM 常驻` 标示、5 款 Guard/Canary 安全模型一键拉取、`think: false` 与局域网 HTTP 显式开关），并补充 [plugins/llm-moderation/README.md](../plugins/llm-moderation/README.md)、[repo-docs/code-map.md](code-map.md) 与 [meta.json](../meta.json) 同步说明。
  - 交互与视觉体验重构（[packages/console/web/shared/client.mjs](../packages/console/web/shared/client.mjs)、[theme.css](../packages/console/web/shared/theme.css)、[packages/console/web/console/main.mjs](../packages/console/web/console/main.mjs)、[console.css](../packages/console/web/console/console.css)）：去嵌套箱格改为 VitePress 式开放细分割线排版（`.lw-doc-split` 左表右固定旁栏 + `.lw-view-tabs` 分页），加入本地 SVG 矢量图标（`svgEl`）与单张系统数据流矢量推演图（`.lw-svg-diagram` + Delta 变更脉冲光环与动画数据线、`.lw-delta-bar` 差异对照条 `还原`/`热生效`），重塑自定义下拉选择框（`.lw-select-box`）、极简左边线单选列表（`.lw-radio-item`）、分段选择器（`.lw-seg`）、无框细分割线拨片开关（`.lw-setting-row`/`.lw-switch-pill`）及分组操作按钮（`.lw-btn-group`）；同期在「能力开关与宿主服务」切换为四态细线态势条（`.lw-stat-strip`）与无框开关行。
- 验证范围与边界：本机（Linux x86_64）运行 `pnpm run build:console`、`pnpm run check`、`pnpm run layering`（10/10）、`pnpm run test:ci`（含 [shared.test.mjs](../packages/shared/test/shared.test.mjs)、[unified-console.test.mjs](../packages/console/test/unified-console.test.mjs) 新增 mock Ollama HTTP 路由与 SSRF 回归，以及 [engine_suite.py](../plugins/llm-moderation/test/engine_suite.py) 原生 `/api/chat` 与局域网 SSRF 单测）、Chromium 无报错视觉与响应式校验、`validate_repo_docs.py`、`pnpm --dir docs-site run docs:build`、`sync_assets_licenses.py --check --dry-run` 与 `repo_maintenance_guard.py pre-commit`；自动安装脚手架与大模型拉取行为在自动化测试中经 `ollamaHooks` 与本地 mock server 验证，`pwsh` 与 `AGENTDOCK_DOCKER_TEST=1` 用例按平台条件跳过。

Synced through 6e6ea7d（含 Ollama 本机/局域网模型接入与生命周期托管工作树改动）

## 2026-11-25（云端 API 协议审计与内联密钥录入）：对照四大厂商官方文档修正签名/载荷并内嵌只写凭据配置

- 触发：用户质疑控制台「LLM 审查策略」缺少云端 API 密钥输入框，并要求核对各厂商云端内容安全 API 官方文档；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- 官方文档核对与后端协议修正（[cloud_aliyun.py](../plugins/llm-moderation/engine/backends/cloud_aliyun.py)、[cloud_tencent.py](../plugins/llm-moderation/engine/backends/cloud_tencent.py)、[cloud_baidu.py](../plugins/llm-moderation/engine/backends/cloud_baidu.py)、[cloud_openai.py](../plugins/llm-moderation/engine/backends/cloud_openai.py)、[router.py](../plugins/llm-moderation/engine/router.py)、[engine_suite.py](../plugins/llm-moderation/test/engine_suite.py)）：
  - **阿里云内容安全 2.0（`green-cip`）**：`_sign_acs3` 与 `_call_aliyun_action` 对齐 `application/x-www-form-urlencoded; charset=utf-8`（`TextModerationPlus` 规范名 `llm_query_moderation` / `llm_response_moderation`、`ServiceParameters` JSON）；移除捏造的 `imageBase64`/`data` 字段，针对内联图片/音视频裸字节显式抛出不可重试 `UpstreamError(400)`（官方要求先经 `DescribeUploadToken` 传至 OSS 或传远程 URL）。
  - **腾讯云天御（`2020-12-29`）**：修正音频路径为空占位任务的问题，改用官方同步接口 `CreateAudioModerationSyncTask`（`FileFormat` + `FileContent` + `DataId`），新增 `_resolve_tencent_url` 在自定义端点下按服务前缀自动映射 `tms.` / `ims.` / `ams.` / `vms.` 子域，VMS 内联视频裸字节改为显式拒绝；保持 `TMS` `TextModeration` 与 `IMS` `ImageModeration`（`FileContent`）。
  - **百度智能云 AIP**：为 `img_censor/v2/user_defined` 补充静态/GIF `imgType`，音频升级至 `/rest/2.0/solution/v1/voice_censor/v3/user_defined`（`fmt` / `base64` / `rate=16000`），移除 `video_censor` 假占位 `"videoUrl": "inline"` 并对内联视频显式拒绝。
  - **OpenAI Moderation Compat（`omni-moderation-latest`）**：修正仅含内联音频/视频且无有效文本/图片时不再回退发送 synthetic `"(empty)"` 造成静默放行，连同 [router.py](../plugins/llm-moderation/engine/router.py) `_extract_combined_text` 对空字典 `{}` 的保护一并收紧。
  - 扩充 [engine_suite.py](../plugins/llm-moderation/test/engine_suite.py) 第 7 组单元测试 `test_cloud_vendor_protocol_payloads_and_media_constraints`，验证四大云端接口真实表单/JSON 协议细节与不支持内联二进制的 fail-closed / 回退契约。
- 单源控制台内联密钥录入与地域选择（[packages/console/web/console/main.mjs](../packages/console/web/console/main.mjs)、[console.css](../packages/console/web/console/console.css)、[plugins/llm-moderation/README.md](../plugins/llm-moderation/README.md)）：
  - 在「LLM 审查策略 → 2. 校验范围与云端外发授权」中直接集成按厂商动态切换的 `cloudRegion` 下拉选择框（阿里云 `cn-*`、腾讯云 `ap-*`）、官方协议与媒体限制细线说明，以及无嵌套框 `.lw-cred-strip` 只写 API 密钥表单（按厂商渲染 `OPENAI_API_KEY`、`ALIYUN_ACCESS_KEY_ID` / `SECRET`、`TENCENT_SECRET_ID` / `KEY`、`BAIDU_API_KEY` / `SECRET_KEY`、`WEBHOOK_API_KEY`）。
  - 支持在页内独立点击 `只写保存云端 API 密钥` 或随策略保存一并提交 `/api/plugin-secrets/save`，保存后即时清空内存草稿并返回键名就绪状态（后端仍严格只写不回显明文），同步在右侧 `.lw-svg-diagram` 云端节点显示缺失密钥提示。
- 验证范围与边界：本机（Linux x86_64）运行 `pnpm run build:console`、`pnpm run check`、`pnpm run layering`（10/10）、`pnpm run test:ci`（221 项：205 通过、0 失败、16 按 Windows/Docker 条件跳过）、`python3 -m unittest plugins/llm-moderation/test/engine_suite.py`（7/7 通过）、Chromium CDP 无控制台报错与响应式（1440px/390px）校验、`validate_repo_docs.py`、`pnpm --dir docs-site run docs:build`、`sync_assets_licenses.py --check --dry-run` 与 `tools/repo_maintenance_guard.py pre-commit`；各云厂商外发协议均通过本地 mock HTTPS 分发器断言请求体、签名头与错误码，`pwsh` 与 `AGENTDOCK_DOCKER_TEST=1` 用例按平台条件跳过。

Synced through 6e6ea7d（含云端 API 官方协议对齐与控制台内联密钥配置工作树改动）

## 2026-11-25（全控制台无箱体直观化重构）：统一 8 页可视化拓扑、状态机与审计归类

- 触发：用户要求「其他页面也做的更直观一些」，延续去嵌套箱体、引入矢量示意图与清晰边界呈现的设计规范。
- 全页可视化与共享原语抽离（[packages/console/web/console/main.mjs](../packages/console/web/console/main.mjs)、[console.css](../packages/console/web/console/console.css)）：
  - 在 `ICON_SHAPES` 中补全侧栏导航与各域原生 SVG 图标（`home`、`clipboardCheck`、`sliders`、`key`、`layoutPanel`、`activity`、`wrench`、`file`、`search`、`clock`），并抽离共享 `makeStatStrip`、`svgNodeBox`、`formatMetaChips` 与 `classifyToolBoundary` 消除跨页重复实现。
  - **系统概览**、**待审审批队列**（含复核弹窗顶栏边界/单次预算摘要）、**能力开关与宿主服务** 与 **扩展插件密钥库**：全部升级为 `.lw-doc-split` 左右开放分栏，右侧分别实时渲染系统信任拓扑 SVG、人工两步审批与 24h 防重放状态机 SVG、宿主 `:ro/:rw`/Docker/会话边界 SVG 及 KernelGuard 凭据隔离流向 SVG；审批项补充 300s 倒计时进度条，密钥库补充常用键名模板与明文显隐开关。
  - **声明式扩展面板**、**实时审计通道** 与 **聚合工具目录**：移除外层嵌套卡片改用无箱体 `.lw-section`、`.lw-metric-ledger` 紧致网格与 `.lw-doc-callout` 提示，审计页新增 `.lw-seg` 4 态筛选并将 `control.sock` 原始 JSON 拆解为 `.lw-meta-chips` 结构化标签，工具目录加入无损失焦实时检索框与调用/拦截比可视化条。
- 审计日志归类修复与回归验证（[local/webui.mjs](../local/webui.mjs)、[unified-console.test.mjs](../packages/console/test/unified-console.test.mjs)）：
  - 在 `local/webui.mjs` 以 `CONNECTOR_EVENT_META` 映射替代硬编码回退 `'err'` 的分支，确保 `plugin_secret_saved`、`moderation_config_saved` 与 `moderation_ollama_*` 正确输出 `ok`/`info` 与中文状态标签（附 `unified-console.test.mjs` 回归断言）。
- 验证范围与边界：本机完成 `pnpm run build:console`、`pnpm run check`、`pnpm run layering`（10/10）、`pnpm run test:ci`（221 项：205 通过、0 失败、16 按 Windows/Docker 条件跳过）、`python3 -m unittest plugins/llm-moderation/test/engine_suite.py`（7/7 通过）、Chromium CDP 全 8 页桌面（1440px）与移动端（390px）零控制台报错零溢出视觉校验、`validate_repo_docs.py`、`pnpm --dir docs-site run docs:build`、`sync_assets_licenses.py --check --dry-run` 与 `tools/repo_maintenance_guard.py pre-commit`；`pwsh` 与 `AGENTDOCK_DOCKER_TEST=1` 用例按平台条件跳过。

Synced through 6e6ea7d（含全控制台 8 页可视化重构与审计归类修复工作树改动）

## 2026-11-25（APIFox 接口工作台、Agent 安全围栏配置与 LoomWard 品牌标识）：补齐双栏契约调试台、R1–R7 与第三方 MCP 围栏界面及全仓品牌视觉

- 触发：用户询问原版 APIFox 式接口工作台与 Agent 围栏配置入口，并要求生成 LoomWard 品牌 Logo 并按各仓库规范部署；触发 `repo-docs` Sync gate（决策为 `foreground patch`）。
- 品牌资产与文档/控制台署名部署（[assets/README.md](../assets/README.md)、[loomward-brand.png](../assets/loomward-brand.png)、[loomward-icon.svg](../assets/loomward-icon.svg)、[loomward-logo.svg](../assets/loomward-logo.svg)、[docs-site/public/brand/](../docs-site/public/brand/loomward-icon.svg)、[README.md](../README.md)、[README.en.md](../README.en.md)、[config.mts](../docs-site/.vitepress/config.mts)、[html.mjs](../packages/console/src/html.mjs)、[unified-server.mjs](../packages/console/src/unified-server.mjs)、[ASSETS_LICENSES.md](../ASSETS_LICENSES.md)）：
  - 生成深海黑曜石与钴蓝/亮青交织盾徽品牌图（去白底抗锯齿透明 PNG 母版 + 512/256/32 文档站尺寸）及同源矢量图标/横幅 Wordmark，接入中英 README 页头、VitePress 导航栏 `logo` 与 Hero 图、控制台严格 `img-src 'self'` CSP 下的 `/brand-icon.svg` 顶栏徽标及 `ASSETS_LICENSES.md` 第 4.1/4.3 条资产清单。
- Agent 安全围栏后端与前端页面（[local/antileak-config.mjs](../local/antileak-config.mjs)、[unified-server.mjs](../packages/console/src/unified-server.mjs)、[webui.mjs](../local/webui.mjs)、[packages/console/web/console/main.mjs](../packages/console/web/console/main.mjs)）：
  - 新增 `local/antileak-config.mjs` 与 `/api/fencing/{config,test,refresh,doctor}`（附 [unified-console.test.mjs](../packages/console/test/unified-console.test.mjs) 私有仓名单不泄漏、非法正则拒绝与离线测试回归）；控制台侧边栏「安全与治理」新增「Agent 安全围栏」，以双标签页统筹 **R1–R7 防泄漏规则矩阵 + 策略编辑 + 离线 Dry-Run / 缓存刷新 / 自检** 与 **第三方 MCP 服务接入（stdio / Streamable HTTP / JSON 导入 / 探测 / 外部工具单独开关）**。
- APIFox 双栏接口工作台、能力单工具独立开关与可展开审计 Transport JSON（[packages/console/web/console/main.mjs](../packages/console/web/console/main.mjs)、[console.css](../packages/console/web/console/console.css)、[unified-console.test.mjs](../packages/console/test/unified-console.test.mjs)）：
  - 将「聚合工具目录」重构为「API 接口工作台」APIFox 双栏工作区，支持 **MCP 工具契约** 与 **控制台 HTTP API** 模式切换、分组筛选、实时参数构建生成 JSON-RPC 2.0 / cURL 负载、单工具实时熔断开关、Schema 表格与只读 GET 实时探测；
  - 在「能力开关与服务」恢复工作区能力快捷预设与 **单工具独立开关矩阵**（支持内置沙箱与第三方 MCP 逐项启停并统一对齐 `/api/mcp-servers/toggle` 参数 `id`）；
  - 在「实时审计通道」为每次工具调用与 `control.sock` 事件恢复可点击展开/一键全部展开的详细 Trace 字段（耗时/挂载/读写字节/退出码）及完整脱敏 **Transport JSON** 检视与复制。
- 本地免初始化预览模式（[packages/console/src/session-broker.mjs](../packages/console/src/session-broker.mjs)、[server.mjs](../packages/console/src/server.mjs)、[unified-server.mjs](../packages/console/src/unified-server.mjs)、[scripts/preview-console.mjs](../scripts/preview-console.mjs)、[packages/console/web/console/main.mjs](../packages/console/web/console/main.mjs)）：
  - 新增显式 `previewAutoSession`（默认关闭、严格限定回环端口且当正式凭据已初始化时自动失效），通过 `GET /api/auth/state` 与 `POST /api/auth/preview` 在保持 `HttpOnly` Cookie、`X-LoomWard-CSRF`、`X-LoomWard-Tab-Auth` 及同源校验不变的前提下实现 `pnpm run preview` 本地临时预览开箱即用；退出登录后仍按 Cookie 锁定并展示「一键进入本地预览（免初始化）」。
- 验证范围与边界：本机（Linux x86_64）运行 `pnpm run build:console`、`pnpm run check`、`pnpm run layering`、`pnpm run test:ci`、`python3 -m unittest plugins/llm-moderation/test/engine_suite.py`、Chromium 无报错视觉与交互/响应式核验、`validate_repo_docs.py`、`pnpm --dir docs-site run docs:build`、`sync_assets_licenses.py --check --dry-run` 与 `tools/repo_maintenance_guard.py pre-commit`；`pwsh` 与 `AGENTDOCK_DOCKER_TEST=1` 用例按平台条件跳过。

Synced through 6e6ea7d（含 APIFox 接口工作台、Agent 安全围栏与品牌 Logo 部署工作树改动）

## 2026-11-26 LoomWard 主线跨平台复验

将原验收分支的本机 Docker 端点校验、Windows 运行库诊断、凭据子进程及 OAuth 撤销回归同步到 LoomWard 的安装与运行入口。macOS 的只读挂载用例先解析系统临时目录的真实路径，正式运行时继续拒绝带符号链接的受保护路径。端点和测试参数见[容器沙箱与文件策略](modules/container-sandbox-and-file-policy.md)。

| 测试环境 | 结果 |
| --- | --- |
| Windows 11 x64，普通测试用户 | DPAPI、Docker 端点与受保护管理共 14 项通过，Docker/NTFS 另有 4 项通过。安装器生成 RPM 清单，使用私有目录的启动、状态、停止入口验证了监督进程与连接器的生命周期。 |
| macOS 15.8.3 x64 | 临时钥匙串完成创建、读取及本地轮换，原钥匙串设置已恢复。安装、RPM 清单与受保护启停通过。宿主管理、WebUI 和真实容器等 29 项测试全部通过。 |
| Linux x86_64 | 以主线和本批补丁运行语法检查、站点构建及真实 Docker 全量回归。210 项中 196 项通过，14 项按环境跳过。加入当时工作区中的并行开发改动后，224 项中 210 项通过，14 项跳过。 |

两台隔离客体均用固定 Node 24.22.1 和各自的 Moby 29.9.2，引擎运行同一镜像 `sha256:ef51fede32df12c340844bf36798c61f0d3220e0a7aab156e3d6e204d31c641e`。测试网关使用客体回环地址，结束时两端按安装标签查询均为零个残留容器。

Synced through 50633e740a8dbc3ed1c5d0d3c03aae8ed97147e7

## 2026-11-26 受保护升级中断恢复与双端验收

Windows 11 和 macOS 15.8.3 的隔离副本分别通过 9 项发布检查。安装清单无法替换时，两端均从原入口启动了旧版本并正常停止。解除文件占用或不可变标志后，重试激活了新版本，原生凭据、Passkey 登记、待批准请求、能力配置、控制台端口和出站限制均保留。容器读到了工作区文件，写入被只读文件系统拒绝，结束时两端按安装标签查询均为零个容器。源码包 SHA-256 为 `28ad36afbbcd63d3b41732fd8352bb53a840067a9ebcf1aa8f63e97ab54b85c4`，两端使用上次主线复验的同一固定镜像。[复验步骤](walkthroughs/one-real-run.md#在发布前复验受保护安装)

Linux 启用真实 Docker 后运行串行回归，共 226 项，212 项通过，14 项 Windows 专属测试按平台跳过。两套控制台通过同一组请求变更、写权限撤回和注销断流断言。审核基线的 5 条放行样本与 2 条拦截样本均与标注一致，调换两条基线判定后按方向列出了两个样本 ID 并退出 1。[共同行为测试](../test/console-policy-contract.test.mjs) · [离线基线](../plugins/llm-moderation/test/fixtures/offline-baseline.json)

Synced through c7350086925b6146a7a8ee519f4eee9f5d46401b（含本次工作树变更）

## 2026-11-26 活动发布、流式中继与双端复验

受保护启动器和源码检出的前台命令均从活动发布加载宿主，校验冻结 RPM 后再接入流式中继。POSIX 的 `webui` 入口启动统一控制台，沿用已有认证记录和服务管理入口。宿主为审核扩展提供读取策略的接口，私有配置和插件密钥在 Windows 上使用原生 ACL 校验。[连接器入口](../local/connector.mjs) · [管理入口回归](../test/posix-host.test.mjs) · [审核扩展](../plugins/llm-moderation/README.md)

Windows 11、macOS 15.8.3 两台隔离副本分别通过全部 10 项检查。DPAPI 和 Keychain 可读回原凭据。升级中断后启动旧发布、重试后启动新发布，两次都收到了匹配请求 ID 的 `stream_end` 和沙箱报告的只读挂载模式。两端还实际运行了容器：能读工作区文件，写入被文件系统拒绝，结束后本次安装的容器计数为零。私有审核策略与插件密钥的保存、读取和密钥删除均通过。[复验步骤](walkthroughs/one-real-run.md) · [验收断言](../tools/acceptance/guest.mjs)

- 源码提交为 `925d952ea4ef9bd72abae5d3f3b605c45238eb2b`，打包范围内工作树干净。
- 两端源码包 SHA-256 为 `af6bc8eaa276325974baceb5347fbc63e9fdab2685997332118a95a66487ee0a`。
- 两端 Docker 镜像 ID 为 `sha256:ef51fede32df12c340844bf36798c61f0d3220e0a7aab156e3d6e204d31c641e`。
- Linux 从干净检出启用真实 Docker 运行 227 项回归，213 项通过，14 项 Windows 专属测试按平台跳过。控制台构建产物可重现，文档站构建通过。离线审核基线 5 个放行样本和 2 个拦截样本均与标注一致。

Synced through 925d952ea4ef9bd72abae5d3f3b605c45238eb2b

## 2026-11-26 在 Windows 11 补验 Linux 跳过的 14 项

在本机 Windows 11 专业版（Build 26300）的隔离副本内，用普通测试账户、Windows PowerShell 5.1 和 Node.js `v24.22.1` 运行了 Linux 跳过的全部 14 项。受保护启动与管理 7 项、DPAPI 凭据子进程 4 项、NTFS 权限 2 项和 Windows 路径 1 项均通过。按文档命令从已提交源码复跑，分组汇总为 13/13 和 1/1，均无跳过。Docker 使用本机 `default` 上下文和固定镜像 `sha256:ef51fede32df12c340844bf36798c61f0d3220e0a7aab156e3d6e204d31c641e`。[复验命令和测试文件](walkthroughs/one-real-run.md#在-windows-上补验-linux-跳过的-14-项)

模块来源检查读取 `Get-Acl` 的模块清单完整路径，并核对凭据和代理子进程实际使用的系统目录。命名空间路径测试在临时工作区中执行，拒绝写入后目录为空。真实 Docker 文件测试确认自定义 NTFS ACL 和原内容得到保留，继承 ACL 的文件可正常编辑。[PowerShell 管理回归](../test/management-safety.test.mjs) · [凭据回归](../test/secret-process.test.mjs) · [NTFS 回归](../test/windows-acl.test.mjs)

Synced through 89dedbc9c68e5383e942a70b1d23f78de0c5a2fc

## 2026-11-26 控制台工作台与本地预览

系统概览集中展示待审批请求、云端中继、工作区挂载和进程外扩展，运行拓扑的节点可进入对应操作页。窄屏通过顶栏菜单导航，拓扑默认折叠。预览启动器在当前用户主目录创建临时状态，正常退出时清理。[控制台界面](../packages/console/web/console/main.mjs) · [预览入口](../scripts/preview-console.mjs)

在本机回环预览中，使用 Chromium 检查了九个页面在 320、390、768、1024 和 1440 像素宽度下的导航与页面宽度。使用模拟待审请求检查了复核弹窗的完整摘要、键盘焦点和取消操作。

Synced through 90dcda7c69c1e8a11b724172d4c27299414fe578

## 2026-11-26 Edge 与 Safari 窄屏键盘验收

| 本机测试副本 | 浏览器 | 验收视口宽度（CSS 像素） | 结果 |
| --- | --- | --- | --- |
| Windows 11 专业版，Build 26300 | Edge 158.0.4370.45 | 626、390、320 | 89/89 通过 |
| macOS Sequoia 15.8.3，24H241 | Safari 18.6 | 650、390、320 | 89/89 通过 |

两端运行相同的离线前端资源。Edge 使用原生窗口及两个窄视口；Safari 直接调整原生窗口宽度，保留默认键盘偏好。复验时，用 Tab 和 Shift+Tab 进出抽屉、展开拓扑并从节点进入审批队列。在焦点停留于开关、节点、复核入口或确认按钮时，由控制台发送一次状态推送，检查能否继续操作同一控件。基线版本会在推送后丢失焦点，Safari 还会跳过部分按钮。

审批使用隔离临时目录中的一条测试请求。Esc 和默认“取消”均返回原请求；明确选择“确认批准一次”后，检查批准记录摘要与请求一致、焦点返回队列标题。本次只核验界面与批准记录，未启动执行器。[复核操作](modules/local-approval-and-replay.md) · [请求夹具示例](../packages/console/test/unified-console.test.mjs)

Synced through 0ba9bc39f29af71fc6ccd358f3ac80ea1cc0b949
