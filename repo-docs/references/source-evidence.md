# 源码证据审计

这是固定源码审计记录。历史审阅锚点与版本验收快照保留在[修复与验证快照](../../SECURITY-FIXES.md)；本轮于 2026-11-15 按最新当前源码完成从 Lite 到 Standard 体系的全面核对与模块拆分。行为解释由主流程与三篇概念模块承载，目录索引由[代码地图](../code-map.md)承载。

## 遍历记录

| 遍历 | 实际检查 | 得到的依据 |
| --- | --- | --- |
| Pass 1 | 根目录清单、`package.json`、`wrangler.jsonc.example`、`cloud/`、`local/`、`container/`、`scripts/` 与 `test/` 全部源文件清单 | 确认真实三层架构（Worker + 双 Durable Objects / Windows DPAPI 本地连接器 / Linux 容器）、实际命令与平台支持边界 |
| Pass 2 | 逐行核对 `cloud/index.mjs`、`relay.mjs`、`auth-store.mjs`、`auth-transactions.mjs`、`security.mjs`、`local/*.mjs`、`container/*` 及对应 PowerShell 加固脚本 | 核实 OAuth 代次 `owner-v2-*`、心跳窗口、批准紧凑字节预算、unlink 先行账本顺序、Docker 加固参数、Windows ACL 守卫与清理故障退守语义 |
| 测试与运行复核 | 在当前工作区执行 `pnpm run check`、`node --test --test-concurrency=1 test/*.test.mjs cloud/*.test.mjs` 并复查历史快照说明 | 验证静态语法与 Linux 可测回归（共 123 项：108 通过 / 0 失败 / 15 项 Windows/Docker 专属测试按平台跳过）；实机 Windows/macOS/Docker 与公网验收仍按[修复与验证快照](../../SECURITY-FIXES.md)对应版本解释 |

## 覆盖与排除

Standard 指南已完整覆盖三条运行主线：云端 OAuth 2.1 与中继、本机精确批准与三类防重放账本、容器沙箱与文件安全策略。`docs-site/`（文档站配置与交互式结构图）、`tools/repo_maintenance_guard.py`（本地离线维护守卫）以及仓库外的本地状态/证据目录不参与运行时工具请求链路，未展开源码级详解。

文档结构与构建检查仅验证文档系统一致性，不等于重新部署 Cloudflare Worker、重装 `~/.agentdock-bridge` / `%USERPROFILE%\.agentdock-bridge` 运行副本或跑完 Windows/macOS/Docker 实机端到端回归。

## 声明与证据

| Claim | Evidence | Confidence | Caveat | Used by |
| --- | --- | --- | --- | --- |
| 网关把授权状态与设备通道拆分在两个 SQLite DO，并通过密码哈希代次 `owner-v2-*` 隔离旧授权 | [云端入口](../../cloud/index.mjs) 搜索 `AuthCoordinator`、`owner-v2-`；[中继对象](../../cloud/relay.mjs) 搜索 `BridgeRelay` | 已确认 | `OWNER_PASSWORD_HASH` 变更会令旧代次全部客户端失效 | [云端网关与中继](../modules/cloud-oauth-and-relay.md) |
| 授权与令牌端点实施严格速率限制、PKCE `S256`、零脚本 CSP 合并与刷新家族吊销 | [云端入口](../../cloud/index.mjs) 搜索 `rate`、`showConsent`、`revokeFamily`；[事务并发](../../cloud/auth-transactions.mjs) | 已确认 | 外部 CIMD 拉取移出提交锁；`AuthTransactions` 对冲突或并发写入引发的陈旧视图异常最多重试 `12` 轮，超限返回 503 | [云端网关与中继](../modules/cloud-oauth-and-relay.md) |
| 中继通过 `FIRST_HEARTBEAT_GRACE`（10s）与 `HEARTBEAT_MAX_AGE`（65s）判活，并隔离 `stop_command` 通道 | [中继对象](../../cloud/relay.mjs) 搜索 `stopping`；[活性判定](../../cloud/liveness.mjs) | 已确认 | `cloud/index.mjs` 兼容列出 `agentdock_context`/`get_command` 等 12 个名称，本地 `request-policy.mjs` 与 `sandbox.mjs` 仅放行 10 项工具 | [云端网关与中继](../modules/cloud-oauth-and-relay.md) |
| 本机连接器按宿主平台分流加载密钥（Windows DPAPI / POSIX Keychain、Secret Service 或 `0600`），且先验信封再查 `toolScopes` | [连接器](../../local/connector.mjs) 搜索 `loadSecrets`；[POSIX 凭据](../../local/host-secrets.mjs)；[请求策略](../../local/request-policy.mjs) 搜索 `toolScopes` | 已确认 | 无头 Linux 宿主在无 Secret Service 会话时默认使用 `0600` 文件存储，防容器与跨用户读取但不如 Keychain/DPAPI 防同用户离线副本 | [本地批准与防重放](../modules/local-approval-and-replay.md) |
| 敏感请求先消费 `.approved.json`/`.request.json` 再写 24 小时 `RequestReceipts`，超 1.2 MB 前置拒绝 | [批准状态机](../../local/approvals.mjs) 搜索 `unlink`；[批准存储](../../local/approval-store.mjs) 搜索 `MAX_RECORD_BYTES`；[防重放账本](../../local/receipts.mjs) | 已确认 | 消费后若容器执行前崩溃不会自动重跑；超时亦不能推定无副作用 | [一次真实操作](../walkthroughs/one-real-run.md)、[本地批准与防重放](../modules/local-approval-and-replay.md) |
| `StopReceipts` 与独立队列保证控制流量耗尽时仍可停止任务 | [防重放账本](../../local/receipts.mjs) 搜索 `StopReceipts`；[控制账本测试](../../test/control-receipts.test.mjs) | 已确认 | 最多保留 128 条按 FIFO 淘汰，安全依赖运行时不重启已结束任务 | [本地批准与防重放](../modules/local-approval-and-replay.md) |
| 容器启用 `--init`、只读根、非特权 UID/GID（Win/macOS 为 1000，Linux 按非 root 宿主映射）、20s 租约监控，文件工具强制路径与 Windows DACL 守卫 | [沙箱接线](../../local/sandbox.mjs) 搜索 `createSandboxRuntime`；[命令监督](../../container/runner.mjs)；[文件策略](../../local/file-safety.mjs)；[Windows 守卫](../../local/windows-acl.mjs) | 已确认 | 容器内工程挂载刻意可读写，不能防止工程内部秘密被已授权工具读取 | [容器沙箱与文件策略](../modules/container-sandbox-and-file-policy.md) |
| 容器清理失败后封锁新操作，但保留属主对其余任务 `command_status`/`stop_command` 控制 | [沙箱接线](../../local/sandbox.mjs) 搜索 `cleanupConfirmed`、`closed`；[故障恢复测试](../../test/sandbox-recovery.test.mjs) | 已确认 | 清理失败不自动重试，`cleanup_confirmed: false` 须人工在宿主检查 Docker | [一次真实操作](../walkthroughs/one-real-run.md)、[容器沙箱与文件策略](../modules/container-sandbox-and-file-policy.md) |
| 历史真实 Windows ACL、固定 Docker 镜像与公网验收属于对应版本的快照记录 | [修复与验证快照](../../SECURITY-FIXES.md) 与 [指南变更记录](../change-log.md) | 已核对 | 当前环境为 Linux 开发机，15 项 Windows/Docker 专属测试自动跳过 | [指南入口](../README.md) |

## 证伪检查与读者下一问

证伪检查：如果修改参数路径后仍能复用同一批准标记，或者在写入 `RequestReceipts` 之前启动了容器进程，则本机单次精确批准模型失效；如果 `cleanupConfirmed` 为 `false` 时属主客户无法查询或停止已有任务，则故障降级模型失效；如果修改非 ASCII 客户端刷新令牌撤销未能联动吊销族内访问/刷新令牌，则 OAuth 轮换审计结论失效。

读者下一问：在无 Windows DPAPI 的 Linux 或 macOS 宿主上托管连接器时，安全边界有何差异？答案集中在 [POSIX 宿主安全](../../local/host-safety.mjs)、[POSIX 凭据管理](../../local/host-secrets.mjs)、[POSIX 工具链](../../local/node-toolchains.mjs) 与 [宿主管理 CLI](../../scripts/host-cli.mjs)：macOS 默认使用登录 Keychain，桌面 Linux 默认使用 Secret Service，无图形会话 Linux 使用 `0600` 私有文件（`posix-file`），同时原生 Linux 容器按宿主非 root UID/GID 匹配工作区属主。

## 验证边界

当前文档站由 `docs-site/.vitepress/config.mts` 通过 `guideLinks` 插件导入本指南并构建静态站，站内把 `repo-docs/` 之外的源码路径渲染为精确仓库路径，不随站发布本地凭据或私钥。文档校验与构建结果记入[指南变更记录](../change-log.md)。

证据状态：除特别标注外，本页基于当前源码已确认。
