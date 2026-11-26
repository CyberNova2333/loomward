# 本地精确批准与防重放账本

本地连接器运行在受保护的宿主环境中，在云端中继与容器执行器之间增加第二道控制闸门：云端 OAuth 令牌只证明调用方获得过会话授权，真正触及项目文件或启动 Bash 命令前，仍必须在本地核对请求信封、等待人工确认精确参数，并在副作用发生前完成一次性批准消费与防重放登记。

云端信封如何打包并发起连接，见[云端网关、OAuth 2.1 与中继交接](cloud-oauth-and-relay.md)；批准通过后容器如何挂载项目与约束文件替换，见[容器沙箱与文件安全策略](container-sandbox-and-file-policy.md)。

## 宿主启动边界与代理链

[连接器入口](../../local/connector.mjs)从受保护状态目录（默认 `~/.agentdock-bridge`，Windows 为 `%USERPROFILE%\.agentdock-bridge`）读取 `config.json`，并调用 `loadSecrets` 导出本机凭据：

- **Windows（`win32`）**：通过最小环境变量和系统目录工作路径启动独立 `powershell.exe` 子进程，从 Windows DPAPI 加密文件 `secrets.dpapi` 中导出密钥到内存。
- **macOS / Linux（POSIX）**：调用[POSIX 凭据管理](../../local/host-secrets.mjs)的 `exportSecretsSync`，先校验私有状态目录权限，再严格按 `secrets.meta.json` 记录的后端（`macos-keychain`、`linux-secret-service` 或 `posix-file` `0600` 私有文件）读取凭据，不在运行期静默降级。

导出密钥后，连接器立即剥离 `AGENTDOCK_BRIDGE_TOKEN` 等进程环境变量，不向容器或子进程传递底层诊断细节。

受保护入口校验私有发布目录的冻结 RPM，启动[宿主守护进程](../../packages/host/src/daemon.mjs)。[中继入口](../../packages/host/src/ingress-relay.mjs)通过 `proxyCandidates` 依次尝试环境变量 `HTTPS_PROXY`/`https_proxy`/`HTTP_PROXY`/`http_proxy`、系统代理配置（Windows 注册表 `Internet Settings` 或 macOS `scutil --proxy`）与直连路由，以 `Bearer BRIDGE_TOKEN` 建立 `wss://<origin>/bridge` 连接（禁用压缩与重定向，单帧上限 `1,200,000` 字节）。连接每 `20` 秒发送 ping 心跳帧，超过 `65000` 毫秒未收到 `pong` 即断开重连，退避上限 `30` 秒加随机抖动。连接器主进程每秒轮询 `stop.request`，触发时关闭中继与沙箱。

## 信封校验与十项工具策略

收到云端发来的 `request` 帧后，连接器调用[本地请求策略](../../local/request-policy.mjs)的 `validateRequestEnvelope` 执行离线二审：

- **信封与时限预算**：校验 `id` 格式与时间窗口（`issuedAt` 最多允许领先本地时钟 `5000` 毫秒，`deadline - issuedAt <= 110000` 毫秒且未过期），并用 `boundedJson` 限制 JSON 结构总节点数不超过 `20000`、深度不超过 `32`。
- **本地工具与作用域白名单**：基础 MCP 方法（`initialize`、`ping`、`tools/list`、`notifications/initialized`、`notifications/cancelled`）要求 `computer:read`；内置工具调用严格收敛为 `toolScopes` 中的 10 个工具，其中 `write_file`/`edit_file`/`delete_file` 要求 `computer:read` + `computer:write`，`exec_command`/`command_status`/`stop_command` 要求 `computer:read` + `computer:execute`。当所有者通过受保护 WebUI 在工作区外 `mcp-servers.json` 中显式接入并启用第三方 MCP 服务时，仅已登记且不含 `__` 歧义的命名空间工具 `mcp__<serverId>__<tool>` 允许在持有完整三项权限（`computer:read`、`computer:write`、`computer:execute`）的前提下通过二审并进入本机精确审批。即便云端初步放行，未登记或旧名称工具也会在本地拒绝。
- **实时能力闸门、第三方 MCP 执行边界与受认证本机 WebUI**：收到 `tools/call` 后，连接器在进入批准队列与请求账本之前实时读取 `<stateDir>/capabilities.json`（由[实时能力开关](../../local/capabilities.mjs)以 `O_NOFOLLOW` + `fstat` 核验工作区外路径、`0600` 与单硬链接，支持读写/执行组开关及按工具独立覆写 `tools`，异常即按关闭读/写闭锁）及 `<stateDir>/mcp-servers.json`（由[第三方 MCP 注册表](../../local/mcp-registry.mjs)与[外部 MCP 客户端](../../local/mcp-client.mjs)核验工作区外 `0600` 权限、拒绝自循环/私网/元数据/保留 IP SSRF 与 DNS 重绑定、过滤高危环境变量，并在宿主侧以最小环境白名单与默认隔离空临时目录启动 `stdio` 子进程或调用 `Streamable HTTP` 端点——**第三方 MCP 运行在 Docker 容器沙盒之外，不受容器文件系统/网络隔离约束**，每次调用均强制经本机精确审批且单工具保守标记为 `destructiveHint: true`）。本机监控、操作与能力切换由[本机监控 WebUI](../../local/webui.mjs)与[WebUI 认证模块](../../local/webui-auth.mjs)（含[WebAuthn 校验](../../local/webauthn.mjs)）守护：强制存储凭据的 `webui-auth.json`、`capabilities.json` 与 `mcp-servers.json` 位于挂载工作区之外；仅绑定回环接口，默认启用**标签页隔离认证**（除 `HttpOnly; SameSite=Strict` 会话 Cookie 外，每次登录颁发的 `tabToken` 仅保存在当前浏览器标签页的 `sessionStorage`，并通过 `X-AgentDock-Tab-Auth` 校验——关闭或新开标签页即必须重新认证，并可在控制台开关切换为浏览器持久化会话）；支持宿主/浏览器 PassKey 时强制使用 `localhost` WebAuthn（持久化 `hardwarePasskeyEnforced` 防热拔降级，兼容 CBOR 扩展字段并拒绝重复 CBOR 键、`crossOrigin`/`topOrigin` 及错配曲线）并禁止回退密码，否则要求 ≥ 14 位 `scrypt` 强密码；控制台分页展示「状态与开关 / 实时审计 / 工具说明 / 第三方 MCP」，支持 PassKey 多密钥管理（添加/删除非最后密钥）、强密码验证重置、Linux `systemd --user` 开机自启动开关、单工具独立启停以及第三方 `stdio` / `Streamable HTTP` MCP 服务的表单/标准 JSON 原子导入（环境变量与请求头密钥仅写入不回显，修改命令、参数、工作目录或 HTTP 源地址时须显式声明 `replaceSecrets`）。实时审计页显示工具名、耗时、退出码和字节数。沙箱与外部 MCP 客户端写日志时仅保留执行元数据，界面读取旧日志时也会过滤参数、文件正文和命令输出。SSE 推送复核会话有效性并带背压断连，退出登录会立即清空前端敏感表单状态并关闭该会话的事件流。

## 精确批准状态机与记录预算

`APPROVAL_EXEMPT_TOOLS` 仅豁免只读上下文与任务控制三项工具（`computer_context`、`command_status`、`stop_command`）；其余 7 项内置文件或命令工具以及所有已启用的第三方 MCP 聚合工具（`mcp__<serverId>__<tool>`）首次到达时均要求本机交互确认：

1. **绑定精确摘要**：`approvalSubject` 把 `{ origin, authorization, method, params }` 规范化排序并计算 SHA-256 摘要（`digest`）。该摘要包含客户端标识、授予作用域、网关源、方法名和完整参数，刻意排除外层客户端 JSON-RPC `id`，允许客户端在人工批准后使用新的 RPC ID 重试同一操作；若路径、内容、模式或 `network` 等任一参数变更，摘要改变并重新要求批准。
2. **紧凑序列化与发布预算**：[批准存储](../../local/approval-store.mjs)限定待批准请求（`.request.json`）上限为 `1200000` 字节（约 1.2 MB），已批准标记（`.approved.json`）上限为 512 字节。`atomicJson` 在创建临时文件前先按紧凑 JSON 计算最终 UTF-8 字节长度，超限直接抛出 `ApprovalRecordTooLargeError`（返回 `APPROVAL_RECORD_TOO_LARGE`），防止缩进放大或超长参数污染本机批准界面；发布通过只读独占文件（`wx`）、刷盘后硬链接原子创建，避免覆盖同名批准。
3. **队列容量与人工确认界面**：[批准状态机](../../local/approvals.mjs)限制单条待批记录有效期 `5` 分钟（`300000` 毫秒），队列上限 `64` 条、单客户端上限 `8` 条；写入前先清扫已过期 `.request.json` 与陈旧临时文件，若残留条目仍超过 `1024` 才拒绝入队并要求维护清理。用户既可通过 `Approve.cmd` / `~/.agentdock-bridge/approve` 启动[批准终端界面](../../local/approval-cli.mjs)（使用 `safeText` 将控制字符及 Unicode 双向/隐形格式字符转义为 `\uXXXX`，确认输入 `APPROVE <uuid>`），也可在通过 PassKey / 强密码及标签页隔离认证的[本机监控 WebUI](../../local/webui.mjs)「实时审计」页选择「复核完整请求」。列表仅含摘要信息，`POST /api/approvals/review` 按需读取选中的请求，展示网关来源、授权范围和完整参数，并转义不可见控制字符。确认时 `POST /api/approvals/approve` 重新核对记录摘要，两条入口均由 `approveRequest` 发布一次性的 `.approved.json`。

## 消费顺序与三类防重放账本

对需要批准的请求，[宿主调度流水线](../../packages/host/src/pipeline.mjs)按以下顺序执行：

1. **预查持久账本**：调用 `RequestReceipts.inspect` 只读检查 `<stateDir>/request-receipts/<sha256(id)>.json`；若该桥接请求 ID 已执行或存在摘要冲突，直接拒绝而不再生成新的待批准记录。
2. **先消费再登记**：当 `LocalApprovals.authorize` 找到匹配的 `.approved.json` 时，**先同步删除 `.approved.json` 与 `.request.json`**，随后再调用 `RequestReceipts.claim` 写入 24 小时持久账本（最多 `10000` 条，单条上限 512 字节，遇损坏或半写入文件按 `duplicate_or_incomplete` 失败关闭）。
3. **控制通道与停止隔离**：豁免工具与只读协议请求使用内存态[防重放账本](../../local/receipts.mjs)——普通控制采用 `TransientReceipts`（总上限 `1000`、单客户端 `100`、存活 `120` 秒），而 `stop_command` 独占 `StopReceipts`（上限 `128`、满时按 FIFO 淘汰最旧记录）以及本地 `4` 并发槽（单客户端限 `2`），确保普通控制流打满时仍能下发停止指令。

## 宿主目录加固与典型判定表

在宿主侧保护上，Windows 与 POSIX（Linux/macOS）遵循相同的“私有目录、祖先写保护、固定 Node 与环境变量剥离”原则：

- **Windows 宿主**：[状态安全校验](../../scripts/State-Safety.ps1)与[安装脚本](../../scripts/Install-Hardened.ps1)约束 `%USERPROFILE%\.agentdock-bridge` 与 `%USERPROFILE%\.agentdock-toolchains` 位于工作区之外，检查整条祖先路径所有者与 ACL（仅当前用户 SID 与 `SYSTEM` 可写入，拒绝链接与多硬链接），核对官方 Node `24.22.1` SHA-256 与 OpenJS 签名，并清除 `NODE_OPTIONS`、`NODE_PATH`、`NODE_TLS_REJECT_UNAUTHORIZED`、`NODE_EXTRA_CA_CERTS`。
- **Linux / macOS 宿主**：[POSIX 宿主安全](../../local/host-safety.mjs)、[POSIX 工具链](../../local/node-toolchains.mjs)与[宿主管理 CLI](../../scripts/host-cli.mjs)强制 `~/.agentdock-bridge` 与 `~/.agentdock-toolchains` 为 `0700` 且全祖先路径无符号链接与非受信任组/全局写入（macOS 允许系统路径常见的 `admin` 组写如 `/Applications`），核对对应平台官方 Node `24.22.1` 归档及二进制 SHA-256（macOS 附加 `codesign --verify`），守护进程通过私有 Unix 域套接字 `supervisor.sock` 与 `/proc/<pid>/stat` 或 `ps -o lstart=,comm=` 防止 PID 复用，并在包装器与子进程中额外清理 `LD_PRELOAD`、`LD_LIBRARY_PATH`、`DYLD_INSERT_LIBRARIES`、`DYLD_LIBRARY_PATH`、`DYLD_FRAMEWORK_PATH`。Linux 上还可通过 `host-cli.mjs service install` 注册由受保护 `run-service` / `webui` 包装器驱动的 `systemd --user` 自启动单元（`agentdock-bridge.service` 与 `agentdock-webui.service`）。

首次触发待批准请求时，客户端收到的 JSON-RPC 错误载荷形如下例（已脱敏）：

```json
{
  "jsonrpc": "2.0",
  "id": 21,
  "error": {
    "code": -32001,
    "message": "Local approval is required. Open the protected Approve.cmd (or approve) on your computer, review this request, then retry the same tool arguments.",
    "data": {
      "code": "LOCAL_APPROVAL_REQUIRED",
      "approval_id": "0d9c8e12-41af-4f87-9d18-7a2b5c9f1104",
      "expires_at": "2026-11-10T04:05:00.000Z",
      "tool": "read_file"
    }
  }
}
```

典型批准与重放场景的可观察行为如下：

| 输入与队列条件 | 连接器行为与结果 | 验证依据 |
| --- | --- | --- |
| 首次调用 `read_file` 等敏感工具 | 写入 `.request.json` 并返回 `LOCAL_APPROVAL_REQUIRED`，文件与命令均未触碰 | [连接器集成测试](../../test/connector.test.mjs) |
| 5 分钟内输入 `APPROVE <uuid>` 并以同参数、新 RPC ID 重试 | 先删 `.approved.json` 与 `.request.json`，再写 `RequestReceipts`，随后仅执行一次 | [连接器集成测试](../../test/connector.test.mjs) |
| 重试时修改路径或开启 `network: "outbound"` | `approvalSubject` 摘要变化，原有批准不匹配并创建新待批记录 | [连接器集成测试](../../test/connector.test.mjs) |
| 携带深层元数据使紧凑 JSON 超过 `1,200,000` 字节 | 发布前拒绝并返回 `APPROVAL_RECORD_TOO_LARGE`，不生成损坏文件 | [批准预算测试](../../test/approval-budget.test.mjs) |
| 断线或重连后使用同一桥接请求 ID 重试 | `RequestReceipts` 拦截并返回 `already_attempted`，不重放工具副作用或结果 | [控制账本测试](../../test/control-receipts.test.mjs) |

## 定向验证入口

在已安装依赖的开发环境中运行以下定向回归即可核对上述边界（Windows ACL、Node 签名与管理进程检查在非 Windows 宿主会自动跳过）：

```sh
node --test test/connector.test.mjs test/approval-budget.test.mjs test/control-receipts.test.mjs test/secret-process.test.mjs
```

通过批准并登记后，请求正式交由 Docker 执行：继续阅读[容器沙箱与文件安全策略](container-sandbox-and-file-policy.md)，或通过[代码地图](../code-map.md)核对对应源码与测试文件。

证据状态：除特别标注外，本页基于当前源码已确认。
