# 代码地图

先沿[一次真实操作的阶段交接](walkthroughs/one-real-run.md)建立端到端概念，再按本页的目录与职责定位具体实现、测试及运维脚本。关键机制的原理说明拆分在三篇模块文档中，本页只提供目录对照与修改入口。

| 路径 | 职责 | 关键代码 | 与主流程的关系 |
| --- | --- | --- | --- |
| `packages/` | LoomWard monorepo 核心包（共享契约、Cordis 4 微内核、中继、沙箱、宿主与双源控制台） | `packages/shared/`、`packages/kernel/`、`packages/{cloud-relay,sandbox,host,console}/` | 提供零宿主 RPM/插槽原语、Cordis 启动校验、`PolicyTree` 与机械分层守卫（`pnpm run layering`），渐进承接原根目录模块 |
| `plugins/` | 严格进程外边界（`out-of-process`）的平台扩展插件 | `plugins/{antileak,decisions,mcp-hub,adapters}/` | 分别承接 `archive/claude-code-antileak-hooks`、`archive/agent-decisions-dashboard`、第三方 MCP 聚合与独立项目（CloudForge / ModelBridge）适配 |
| `cloud/` | 云端 OAuth 2.1、中继与活性判定 | `index.mjs`、`relay.mjs`、`auth-store.mjs` | 承载公网接入、代次授权与 WebSocket 信封派发，详见[云端网关与中继模块](modules/cloud-oauth-and-relay.md) |
| `local/` | 连接器、本机批准、防重放、宿主安全与沙箱文件策略 | `connector.mjs`、`approvals.mjs`、`sandbox.mjs`、`host-safety.mjs`、`host-secrets.mjs` | 把关二审、一次批准、账本登记、跨平台凭据与容器策略，详见[本地批准与防重放模块](modules/local-approval-and-replay.md)及[容器沙箱与文件策略模块](modules/container-sandbox-and-file-policy.md) |
| `container/` | 容器镜像与内部命令/文件执行入口 | `runner.mjs`、`file-worker.mjs`、`Dockerfile` | 降权为非特权开发用户（默认 `1000` 或按 Linux 宿主 UID/GID 映射）隔离执行命令或禁用命令的文件工具 |
| `scripts/` | 跨平台受保护安装、凭据托管、生命周期守护与公网验收 | `host-cli.mjs`、`Install-Hardened.ps1`、`Secrets.ps1`、`Manage.ps1`、`acceptance-v2.mjs` | 管理私有状态目录、固定 Node 校验、轮换和显式验收 |
| `test/` | 本地批准、文件安全、POSIX/Windows 宿主安全与沙箱故障回归 | `connector.test.mjs`、`posix-host.test.mjs`、`sandbox-recovery.test.mjs`、`file-hardening.test.mjs` | 覆盖连接器、预算、Unicode、POSIX/Windows 权限与清理故障逻辑 |

## `packages/`

| 重要代码 | 功能 | 关键符号 | 调用方 / 使用方 |
| --- | --- | --- | --- |
| [共享契约与原语](../packages/shared/src/index.mjs) | 零宿主、零运行时依赖的契约校验（含 `registers`/`writes` 写边）、守卫错误与审计脱敏码（`guard-types.mjs`）、声明式面板契约（`panel-schema.mjs`）、独立内容审查协议（`content-guard.mjs`）、RPM JCS+SHA-256、60 秒 `BootRun` 回滚与插槽原语 | `validateContractDecl` / `createFrozenRpm` / `withDeadline` / `ImplSlot` / `MechanismSlot` / `VAULT_SLOT` / `validateConsolePanelDecl` / `validateContentInspectVerdict` | `@loomward/kernel` 与全部根包/插件；[共享原语测试](../packages/shared/test/shared.test.mjs) |
| [Cordis 微内核与守卫](../packages/kernel/src/index.mjs) | 基于 Cordis 4 的 7 大标准插槽（含闭锁 `vault:backend@1`）、`KernelGuard` AOP 拦截与单飞异步提权（`guard.mjs`）、无状态规则管线（`rules.mjs`）、`PolicyTree`（`policy-tree.mjs`）及冻结 RPM 构造/核验（`rpm-builder.mjs`） | `createLoomWardKernel` / `PLATFORM_SLOTS` / `KernelGuard` / `evaluateGuard` / `buildWorkspaceRpm` / `verifyWorkspaceRpm` | `@loomward/host` 守护入口；[内核测试](../packages/kernel/test/kernel.test.mjs)与[机械分层守卫](../packages/kernel/test/layering.test.mjs) |
| [云端中继协议根包](../packages/cloud-relay/src/index.mjs) | 提供与 `cloud/security.mjs`、`cloud/liveness.mjs` 对齐的规范协议上限、OAuth 作用域、心跳窗口与桥接 URL 校验 | `assertValidBridgeOrigin` / `buildBridgeWebSocketUrl` / `BUILTIN_TOOL_SCOPES` | Cordis `relay:cloud-worker` 服务与中继入口 |
| [沙箱运行器根包](../packages/sandbox/src/index.mjs) | 将自包含 `local/sandbox.mjs` 适配为 `tool:provider@1` 的内置 `sandbox-docker` 实现并托管容器关闭清理 | `createSandboxToolProvider` / `BUILTIN_SANDBOX_TOOLS` | Cordis `tool:provider@1` 与 `sandbox:docker` 服务 |
| [宿主核心与调度流水线](../packages/host/src/index.mjs) | 提供闭锁凭据后端（`vault.mjs`）、统一安全调度流水线（`pipeline.mjs`：`policy:rule@1` → `tool:invoke@1@before` → 精确本机批准先删后记 24h 账本 → 专用 `stop_command` 通道 → `tool:provider@1` → `tool:invoke@1@after`）、远程 WSS/本地直连双入口（`ingress-relay.mjs` / `ingress-local.mjs`）与完整守护装配（`daemon.mjs`） | `createHostVaultBackend` / `createToolDispatchPipeline` / `createCloudflareRelayIngress` / `createLocalMcpIngress` / `startLoomWardDaemon` | Cordis `host:dispatch` / `gateway:ingress@1` 与[调度守护集成测试](../packages/host/test/pipeline-and-daemon.test.mjs) |
| [双源回环控制台](../packages/console/src/index.mjs) | 物理拆分 Ring 2 独立信任面（`trust-server.mjs`，默认 `127.0.0.1:18798`，零扩展代码/面板，承接 PassKey/强密码、两步逐参审批、能力总开关、MCP 配置与服务控制）与 Ring 3 只读观测面（`console-server.mjs`，默认 `127.0.0.1:18797`，承接只读状态、SSE 实时流、工具目录与零 JS 注入声明式 `console:panel@1` 宿主），通过单次 60s 移交票据与关联注销会话代理（`session-broker.mjs`）、进程内/私有 `0600` `control.sock` 控制通道（`control-channel.mjs`）及零 CDN 离线构建前端（`web/` → `dist/`）解耦 | `startDualOriginConsole` / `createDualOriginSessionBroker` / `createControlChannel` / `connectControlSocket` / `createConsolePanelCollector` | Cordis `console:loopback`、`console:trust-origin`、`console:panel@1` 与[双源控制台测试](../packages/console/test/dual-origin-console.test.mjs) |

## `plugins/`

| 重要代码 | 功能 | 关键符号 | 调用方 / 使用方 |
| --- | --- | --- | --- |
| [防泄漏护栏插件](../plugins/antileak/src/index.mjs) | 承接 `archive/claude-code-antileak-hooks` 离线策略引擎（`plugins/antileak/engine/{check,doctor,refresh-private,resolve-private}.py`、`plugins/antileak/engine/policy.json`），以无 shell 离线子进程（零宿主凭据、禁 `--net`）将 R1–R7 校验经 `ContentInspect v1` 接入 `tool:invoke@1@before`（缓存缺失/过期 fail-closed 阻断于审批前），并注册只读 `console:panel@1` 缓存健康面板 | `createAntileakEngineRunner` / `extractInspectableText` / `apply` | Cordis `mountExtensionUnit`、`tool:invoke@1`、`console:panel@1` 与[防泄漏插件测试](../plugins/antileak/test/antileak.test.mjs) |
| [人机决策台账插件](../plugins/decisions/src/index.mjs) | 承接 `archive/agent-decisions-dashboard` 纯标准库 Python + SQLite 回环台账服务（`service/core/*.py`），仅允许回环接入或托管子进程，向 `tool:provider@1` 暴露 `mcp__decisions__{export_context,check_consistency,record}`（含 CAS `expected_version` 乐观锁与 `request_id` 幂等，写入强制经本机审批），并注册只读 `console:panel@1` 台账面板 | `createDecisionsServiceClient` / `createDecisionsToolProvider` / `DECISIONS_TOOLS` / `apply` | Cordis `mountExtensionUnit`、`tool:provider@1`、`console:panel@1` 与[决策台账插件测试](../plugins/decisions/test/decisions.test.mjs) |
| [第三方 MCP 聚合插件](../plugins/mcp-hub/src/index.mjs) | 以进程外扩展身份声明 `tool:provider@1` 注册写边，封装 `local/mcp-client.mjs` 为标准工具提供者并在卸载时清理子进程与 HTTP 会话 | `createMcpHubToolProvider` / `createMcpHubDescriptor` | Cordis `mountExtensionUnit` 与 `tool:provider@1` 插槽 |
| [外部独立项目适配](../plugins/adapters/src/contract.mjs) | 声明对接独立仓库 `CloudForge` 与 `ModelBridge` 的受控接口契约 | `STANDALONE_INTEGRATIONS` | 平台 `tool:provider@1` 与 `console:panel@1` 插槽 |

## `cloud/`

| 重要代码 | 功能 | 关键符号 | 调用方 / 使用方 |
| --- | --- | --- | --- |
| [云端入口](../cloud/index.mjs) | 路由 OAuth、`/mcp`、`/bridge` 与 `/healthz`，实现所有者密码登录 | `AuthCoordinator` / `route` / `authorize` | Worker 请求；[云端集成测试](../cloud/integration.test.mjs) |
| [中继对象](../cloud/relay.mjs) | 独占单连接器 WebSocket、派发信封、隔离停止通道并执行限流 | `BridgeRelay` | 云端入口；[传输与重连测试](../cloud/transport.test.mjs) |
| [状态存储与事务](../cloud/auth-store.mjs) | 以 SQLite 保存 OAuth 状态、跟踪刷新令牌家族并协调并发通道 | `AuthStore` / `AuthTransactions` / `AuthQueue` | 云端入口与 `auth-transactions.mjs`、`auth-queue.mjs`；[事务并发测试](../cloud/auth-transactions.test.mjs) |
| [协议校验与活性](../cloud/security.mjs) | 校验 RPC 上限、CORS 来源、CSP 头、密码哈希与心跳窗口 | `validateRpc` / `verifyOwnerPassword` / `connectionLiveness` | 云端入口与 `liveness.mjs`；[安全边界测试](../cloud/security.test.mjs) |

## `local/`

| 重要代码 | 功能 | 关键符号 | 调用方 / 使用方 |
| --- | --- | --- | --- |
| [连接器主流程](../local/connector.mjs) | 探测代理、建立 WSS、分平台导出密钥并串行驱动批准/账本/运行器 | `BridgeConnector` / `loadSecrets` / `proxyCandidates` | `Manage.ps1` 与 `host-cli.mjs`；[连接器测试](../test/connector.test.mjs)、[密钥子进程测试](../test/secret-process.test.mjs)与[POSIX 宿主测试](../test/posix-host.test.mjs) |
| [POSIX 宿主安全](../local/host-safety.mjs) | 检查 Linux/macOS 私有状态 `0700` 权限、祖先链写保护、硬链接、固定 Node 与防 PID 复用进程标识 | `assertPrivateState` / `assertPinnedNode` / `findOwnedProcess` / `clearNodeOverrides` | `host-cli.mjs` 与 `host-secrets.mjs`；[POSIX 宿主测试](../test/posix-host.test.mjs) |
| [POSIX 凭据管理](../local/host-secrets.mjs) | 在 macOS Keychain、Linux Secret Service 与 `0600` 私有文件间执行创建、导出、上传与两步轮换 | `createSecrets` / `exportSecretsSync` / `rotateSecretsSync` | `connector.mjs` 与 `host-cli.mjs`；[POSIX 宿主测试](../test/posix-host.test.mjs) |
| [POSIX Node 工具链](../local/node-toolchains.mjs) | 按 `linux`/`darwin` (`x64`/`arm64`) 校验官方 Node `24.22.1` SHA-256 与签名并安装到私有目录 | `ensurePinnedNodeRuntime` / `getDistribution` | `host-cli.mjs`；[POSIX 宿主测试](../test/posix-host.test.mjs) |
| [请求策略](../local/request-policy.mjs) | 信封过期与深度预算校验、10 项内置工具白名单、已登记第三方 MCP 命名空间工具校验（`mcp__<serverId>__<tool>`）及参数规范化摘要 | `validateRequestEnvelope` / `approvalSubject` / `APPROVAL_EXEMPT_TOOLS` / `getToolScopes` / `isValidExternalToolName` | 连接器、WebUI 与批准模块；[连接器测试](../test/connector.test.mjs)、[第三方 MCP 测试](../test/external-mcp.test.mjs) |
| [实时能力开关](../local/capabilities.mjs) | 管理 `capabilities.json`（`0600` 损坏闭锁、强制位于工作区外）并实时开关文件读、文件写、容器命令及单工具 `tools` 覆写 | `assertConfigOutsideWorkspace` / `readCapabilitiesSync` / `writeCapabilitiesSync` / `isToolEnabled` | 连接器、沙箱与 WebUI；[能力与界面测试](../test/capabilities-webui.test.mjs) |
| [WebUI 认证与 WebAuthn](../local/webui-auth.mjs) | 管理工作区外 `webui-auth.json`（`0600`），检测宿主与浏览器 PassKey 支持，提供 PassKey 多密钥删改、强密码重置与可选回退（含 [webauthn.mjs](../local/webauthn.mjs)） | `detectHostPasskeySupport` / `validateStrongPassword` / `enrollPasskeySync` / `deletePasskeySync` / `switchToStrongPasswordSync` / `verifyRegistrationResponse` / `verifyAuthenticationResponse` | `webui.mjs` 与 `host-cli.mjs`；[能力与界面测试](../test/capabilities-webui.test.mjs) |
| [本机监控 WebUI](../local/webui.mjs) | 仅绑定回环接口（`127.0.0.1` / `localhost` / `::1`，默认 `127.0.0.1`）的鉴权监控与控制面板，默认启用标签页隔离认证（可切换为浏览器持久化会话）与 `Host`/`Origin`/`CSRF`/`CORP` 拦截，提供单工具开关、PassKey/密码管理、systemd 自启动切换、第三方 MCP 配置页与两步复核实时待批（`webui-assets.mjs`） | `startWebUiServer` / `collectStatusSnapshot` / `renderWebUiHtml` | `~/.agentdock-bridge/webui` 与 `host-cli.mjs`；[能力与界面测试](../test/capabilities-webui.test.mjs)、[第三方 MCP 测试](../test/external-mcp.test.mjs) |
| [第三方 MCP 注册表与客户端](../local/mcp-registry.mjs) | 管理工作区外 `0600` 的 `mcp-servers.json`（只写密钥不回显、改命令/参数/工作目录/源地址防密钥沿用、禁止自循环与私网/保留 IP SSRF、支持标准 `mcpServers` JSON 原子导入）及在容器沙盒外运行的零依赖 `stdio` / `Streamable HTTP` 聚合客户端（[mcp-client.mjs](../local/mcp-client.mjs)，含最小环境白名单、隔离临时 `cwd`、独立每会话 Agent 与 DNS 重绑定校验、流式 SSE） | `readMcpServersSync` / `upsertMcpServerSync` / `upsertMcpServersSync` / `parseStandardMcpJson` / `probeMcpServer` / `createExternalMcpHub` | `connector.mjs`、`webui.mjs` 与 `host-cli.mjs`；[第三方 MCP 测试](../test/external-mcp.test.mjs) |
| [批准与预算存储](../local/approvals.mjs) | 管理 5 分钟待批队列、按紧凑 UTF-8 字节上限原子发布并清理孤儿临时文件 | `LocalApprovals` / `atomicJson` / `validRequest` | 连接器与 `approval-store.mjs`；[批准预算测试](../test/approval-budget.test.mjs) |
| [本机批准 CLI](../local/approval-cli.mjs) | 控制字符与 bidi 字符转义展示参数，校验口令并写入一次性批准标记 | `safeText` / `approveRequest` | 受保护的 `Approve.ps1`、`~/.agentdock-bridge/approve` 与 `local/webui.mjs`；[连接器测试](../test/connector.test.mjs)、[能力与界面测试](../test/capabilities-webui.test.mjs) |
| [三类防重放账本](../local/receipts.mjs) | 提供 24 小时持久请求账本与控制/停止内存防重放限额 | `RequestReceipts` / `TransientReceipts` / `StopReceipts` | 连接器；[控制账本测试](../test/control-receipts.test.mjs) |
| [沙箱运行接线](../local/sandbox.mjs) | 管理单工作区隔离容器参数、租约心跳、归属检查与清理故障关闭状态 | `createSandboxRuntime` | 连接器；[故障恢复测试](../test/sandbox-recovery.test.mjs)与[真实 Docker 回归](../test/sandbox.test.mjs) |
| [工具协议与文件策略](../local/tools.mjs) | 定义 7 项文件工具和 3 项命令工具，结合逐级 `lstat`、版本检查和原子替换 | `TOOL_DEFINITIONS` / `createToolRuntime` / `createFilePolicy` | 容器文件入口与 `file-safety.mjs`；[工具回归](../test/tools.test.mjs)与[文件加固测试](../test/file-hardening.test.mjs) |
| [Windows 替换与 Docker 查询](../local/windows-acl.mjs) | 拒绝覆盖含自定义显式 NTFS ACL 的文件，仅对只读初始探针提供单次超时重试 | `createWindowsReplacementGuard` / `queryDockerState` | 沙箱与 `docker-query.mjs`；[ACL 测试](../test/windows-acl.test.mjs)与[查询测试](../test/docker-query.test.mjs) |

## `container/`

| 重要代码 | 功能 | 关键符号 | 调用方 / 使用方 |
| --- | --- | --- | --- |
| [容器监督与文件入口](../container/runner.mjs) | 监控 20 秒宿主租约、降权为非特权开发用户（默认 `1000` 或按 Linux 非 root 宿主 UID/GID 映射）启动 Bash 或禁用命令的文件工作器（[file-worker.mjs](../container/file-worker.mjs)） | `runner.mjs`（`parseChildId`） / `file-worker.mjs`（`readJsonInput`） | `local/sandbox.mjs` 与 `container/file-worker.mjs`；[容器输入测试](../test/container-input.test.mjs) |
| [容器构建清单](../container/Dockerfile) | 固定 `node:24-trixie-slim` 摘要与开发工具链并设置只读 `/opt/bridge` | `ENTRYPOINT` | 维护者构建本地开发镜像前导输入 |

## `scripts/`

| 重要代码 | 功能 | 关键符号 | 调用方 / 使用方 |
| --- | --- | --- | --- |
| [POSIX 统一宿主管理](../scripts/host-cli.mjs) | 在 Linux 与 macOS 执行 `setup`/`install`/`start`/`stop`/`status`/`webui`/`webui-auth`/`service`/`approve`/`password`/`rotate-secrets`，安装阶段同步复制 `pnpm-workspace.yaml`、`packages/`、`plugins/`、生成冻结 `rpm.json`（摘要记入 `installation.json`）并生成 `0700` 包装器 | `setupHost` / `installHardened` / `runSupervisor` / `runWebUi` / `manageWebUiAuth` / `manageSystemdUserServices` | `~/.agentdock-bridge/{start,stop,status,run-service,webui,webui-auth,service,approve,password}`、user systemd 单元与[POSIX 宿主测试](../test/posix-host.test.mjs) |
| [初始化与受保护安装](../scripts/Install-Hardened.ps1) | Windows 初始化配置与凭据、校验并安装私有固定 Node，生成受保护副本与 `.cmd` 入口 | `Setup.ps1` / `Install-NodeRuntime.ps1` / `Install-Hardened.ps1` | Windows 维护者显式安装；[管理安全测试](../test/management-safety.test.mjs) |
| [状态守护与进程管理](../scripts/Manage.ps1) | 检查完整祖先路径与所有者 ACL、生成防 PID 复用的托管进程并响应停机标记 | `Assert-PrivateState` / `Assert-PinnedNode` / `OwnedProcess` | 根目录与状态目录下的 `.cmd` 入口、`State-Safety.ps1`、`Approve.ps1` |
| [凭据加密与轮换](../scripts/Secrets.ps1) | 通过 Windows DPAPI 生成、导出、弹窗展示、上传与双步安全轮换本地与云端密钥 | `Secrets.ps1` / `Rotate-Secrets.ps1` | Windows 连接器启动、`ShowPassword.cmd` 与运维轮换；[凭据子进程测试](../test/secret-process.test.mjs) |
| [公网与生命周期验收](../scripts/acceptance-v2.mjs) | 验证 OAuth/容器/刷新/停止重启及录制部署元数据（仅显式命令行执行） | `acceptance-v2.mjs` / `verify-lifecycle.mjs` | 维护者发布与变更核验，历史结果见[修复与验证快照](../SECURITY-FIXES.md) |

## `test/`

| 重要代码 | 功能 | 关键符号 | 调用方 / 使用方 |
| --- | --- | --- | --- |
| [核心安全与策略回归](../test/connector.test.mjs) | 覆盖批准/账本顺序、记录字节上限、异常 Unicode、符号链接、Windows ACL 与凭据子进程隔离 | `connector.test.mjs` / `approval-budget.test.mjs` / `unicode-policy.test.mjs` | `pnpm test` 主体套件（Windows 专属测试按平台跳过） |
| [POSIX 宿主与跨平台沙箱回归](../test/posix-host.test.mjs) | 覆盖 POSIX `0700` 状态与祖先链、防 PID 复用、`posix-file` 两步轮换、Linux 非 `1000` UID 映射、包装器启停、能力开关、本机 WebUI 安全约束与第三方 MCP 聚合/隔离回归 | `posix-host.test.mjs` / `audit-remediations.test.mjs` / `capabilities-webui.test.mjs` / `external-mcp.test.mjs` | `pnpm test`（Linux/macOS 运行，Windows 跳过） |
| [沙箱与控制面回归](../test/sandbox-recovery.test.mjs) | 覆盖清理失败退守与归属保留、控制/停止账本互不干扰、Docker 查询与管理路径安全 | `sandbox-recovery.test.mjs` / `control-receipts.test.mjs` / `management-safety.test.mjs` | `pnpm test` 及显式开启 `AGENTDOCK_DOCKER_TEST` 后的 `sandbox.test.mjs` |

## 修改入口与验证

涉及客户端认证、CORS、OAuth 作用域或刷新家族时，先查看[云端网关、OAuth 2.1 与中继交接](modules/cloud-oauth-and-relay.md)与 `cloud/*.test.mjs`；修改批准字段、摘要结构或防重放语义时，需同步核对 `local/request-policy.mjs`、`LocalApprovals` 与 `RequestReceipts` 的顺序不变量。变动容器挂载参数、文件策略或清理故障逻辑前，先对照[容器沙箱与文件安全策略](modules/container-sandbox-and-file-policy.md)确认属主控制与工作区边界不会被绕过。

改动本地源码并不会自动更新已安装运行副本或已固定 Docker 镜像。核心专有名词与状态码释义集中在[术语表](glossary.md)。

## 覆盖范围

上述导航覆盖生产运行时、构建定义与配套测试，未将非运行时辅助目录纳入主链：独立文档站与本地开发配置位于根目录 `docs-site/`（含静态结构图）与 `wrangler.jsonc.example`；维护安全钩子脚本位于 `tools/repo_maintenance_guard.py`；本地审计报告与运行时凭据、快照材料留在被忽略的私有或本机目录中，不随代码或文档站发布。过往版本的公网验收与镜像核对结果请参照[修复与验证快照](../SECURITY-FIXES.md)。

证据状态：除特别标注外，本页基于当前源码已确认。
