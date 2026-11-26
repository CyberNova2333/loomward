# 一个文件读取请求怎样获得一次执行

当远端智能体需要读取工程中的文件或执行命令时，云端认证先确认客户端身份和权限，但连接器不会把云端鉴权直接等同于本机执行权，仍须由本机对精确参数人工放行后再交给容器运行。以下用测试中的中性文件请求，把云端、本机与容器三个阶段的交接串联起来。

真正的难点在于，即使客户端已持有效令牌，也可能提出未预期的路径操作或重复投递同一个网络请求，因此本机批准、账本登记和隔离执行必须按不可颠倒的顺序交接。

## Step 1: 身份确认与信封装箱

远端客户端向 `/mcp` 发送 JSON-RPC 请求后，云端入口先按配置域名和协议版本拦截畸形或超大请求体，再由授权协调器核对单人密码登录取得的令牌与所需作用域（读取文件至少需要 `computer:read`）。随后，中继对象把调用方身份、授予权限、请求原文和 110 秒截止时间封装进内部信封，通过唯一的设备 WebSocket 发往连接器。

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "read_file",
    "arguments": { "path": "/workspace/canary.txt" }
  }
}
```

这是脱敏的中性示例；实际挂载的工程目录仍可能含本地敏感文件，批准前应核对实际路径与请求意图。云端并发通道、刷新令牌家族撤销与心跳窗口判据，详见[云端网关、OAuth 2.1 与中继交接](../modules/cloud-oauth-and-relay.md)。

## Step 2: 本地二审与未批准入队

连接器收到帧后，先运行[本地请求策略](../../local/request-policy.mjs)中的 `validateRequestEnvelope` 重新核查截止时间、嵌套深度、作用域和 10 项工具白名单，同时预先核对持久防重放账本，确认该桥接请求 ID 未曾执行过。除了查看环境、查询已有命令与停止命令三项豁免工具外，其余敏感文件与命令调用若尚无匹配批准，即向客户端返回 `LOCAL_APPROVAL_REQUIRED`，实际操作尚未启动。

待批准记录会把网关源、客户端标识、已授权作用域、方法与完整参数一起规范化计算 SHA-256 摘要（故意排除外层客户端 JSON-RPC ID，从而允许审批后用新的 RPC ID 重试），在核对紧凑 UTF-8 字节数不超过 1,200,000 字节上限后原子落盘。用户在 `~/.agentdock-bridge`（Windows 为 `%USERPROFILE%\.agentdock-bridge`）运行 `approve` / `Approve.cmd`，即可在[批准终端界面](../../local/approval-cli.mjs)看到经过控制字符与双向排版转义的完整请求参数，输入精确确认口令后生成有效期 5 分钟的一次性批准文件。

## Step 3: 同参数重试消费批准并记账

客户端以相同工具和参数再次发起调用时，[宿主调度流水线](../../packages/host/src/pipeline.mjs)按固定顺序完成交接：

| 请求情形 | 可观察结果 | 源码边界依据 |
| --- | --- | --- |
| 首次请求，尚未在本机确认 | 返回 `LOCAL_APPROVAL_REQUIRED`，待批准文件落盘 | [批准状态机](../../local/approvals.mjs) |
| 同一客户端、同参数在 5 分钟内重试 | 先删除批准文件，再写入 24 小时执行账本，随后仅执行一次 | [防重放账本](../../local/receipts.mjs) |
| 重试时改动路径或开启 `network: "outbound"` | 参数摘要失配，拒绝旧批准并生成新的待批记录 | [批准存储](../../local/approval-store.mjs) |
| 完整待批记录超过 1,200,000 字节上限 | 拒绝入队并返回 `APPROVAL_RECORD_TOO_LARGE` | [批准预算测试](../../test/approval-budget.test.mjs) |
| 重复使用已经登记的桥接请求 ID | 返回 `already_attempted` 或冲突拒绝，不重放执行 | [连接器测试](../../test/connector.test.mjs) |

先删除批准文件、再写入持久账本、最后进入运行器的顺序非常关键：即便执行途中发生断线或超 110 秒超时，已消费的批准与已落盘的账本都不会允许同一次请求自动二次运行，但超时也不能自动推定容器内毫无副作用。完整批准预算、控制通道隔离与 Windows DPAPI/ACL 保护，见[本地精确批准与防重放账本](../modules/local-approval-and-replay.md)。

## Step 4: 容器执行与清理故障退守

登记完成后，请求进入[沙箱运行时](../../local/sandbox.mjs)，通过固定 SHA-256 摘要的开发镜像启动一次性容器（只绑定单一工作区到 `/workspace`，只读根文件系统、丢弃多余内核权能并默认断网）。文件任务走标准输入交给容器内的[文件运行器](../../container/file-worker.mjs)执行，该运行器内部固定禁用命令执行并逐级核查符号链接、多硬链接、UTF-8 编码与 Windows 自定义 ACL；命令任务则在 5 秒宿主心跳租约监控下由 [命令监督入口](../../container/runner.mjs) 降权为非特权开发用户（默认 `1000` 或匹配 Linux 宿主非 root UID/GID）跑起 Bash。

例如，一旦某个任务结束后的容器清理失败（`cleanup_confirmed` 为 `false`），连接器立即把全局运行状态置为关闭，拒绝之后所有新的命令和文件操作；与此同时，检查任务归属客户端的控制分支仍保持在关闭拦截之前，因此原客户端依然可以查询或停止自己尚未结束的其余容器任务，只是未确认清理的任务会继续上报未知运行状态，等待人工本机检查 Docker。容器加固参数与文件替换守卫的细节，见[容器沙箱与文件安全策略](../modules/container-sandbox-and-file-policy.md)。

## Step 5: 局部回归验证与证据界限

在完成依赖安装后的任意开发环境中，可以直接复现批准交接、预算超限和清理故障下的归属控制逻辑（真实 Docker 容器与 Windows ACL 测试会按环境条件自动启用或跳过）：

```sh
node --test test/connector.test.mjs test/approval-budget.test.mjs test/sandbox-recovery.test.mjs
pnpm run check
```

上述局部回归分别使用临时状态目录、本地回环 WebSocket 和沙箱受控模拟边界，不能自动替代真实 Windows 宿主 ACL 校验、固定开发镜像内集成回归或公网端到端验收；历史上随安全修复记录在案的真实部署、镜像校验与公网回归快照统一保存于[修复与验证快照](../../SECURITY-FIXES.md)。需要按目录快速找到其他模块或测试文件时，继续浏览[代码地图寻找源码与测试入口](../code-map.md)；要核对每项断言对应的源码依据与排除项，查看[源码证据审计与边界](../references/source-evidence.md)。

证据状态：除特别标注外，本页基于当前源码已确认。

### 在发布前复验受保护安装

先停掉待升级的连接器。安装器把代码、依赖和文件摘要写入新的私有发布目录及其同名 `.installation.json`，逐个原子替换管理入口，最后替换 `config.json`。启动入口据此选择发布版本。中途退出后可从原入口启动旧版本，也可停止后重跑安装。复核文件摘要时按活动配置的 `sourceRoot` 选择同名清单，状态根目录的 `installation.json` 是最近一次准备发布的兼容副本。[POSIX 安装器](../../scripts/host-cli.mjs) · [Windows 安装器](../../scripts/Install-Hardened.ps1)

两台隔离测试机都需要已登录的专用桌面账户、本地 Docker 引擎、相同镜像 ID 和按项目版本固定的 Node、pnpm。各账户在主目录保存 `.loomward-acceptance.json`，其中 `node`、`pnpm`、`docker` 是客体可执行文件的绝对路径，`context` 是本地 Docker 上下文名。macOS 使用开启了主机密钥校验的 SSH 别名，Windows 使用 libvirt 的 QEMU Guest Agent 安排普通权限的交互式任务。宿主 Python 需要能导入 `libvirt` 与 `libvirt_qemu`。将已核对的完整镜像 ID 赋给 `LOOMWARD_TEST_IMAGE` 后，在仓库根目录执行：

```sh
python3 tools/acceptance/run.py --image "$LOOMWARD_TEST_IMAGE" \
  --mac-ssh loomward-test-mac --windows-domain loomward-test-windows --windows-user loomward-test
```

两台客体收到同一份源码包，并在各自的临时状态目录中验证原生凭据读回、插件密钥写入与删除、审核配置读回和 Docker 只读挂载。两次启动均通过回环 WebSocket 发送只读的 `computer_context` 请求，检查 `stream_end` 终帧中的请求 ID 和只读挂载模式。Windows 占用清单文件，macOS 为清单设置临时不可变标志。两端都验证旧版本在升级中断后仍可启动，再重试升级并核对凭据、Passkey 注册记录、能力设置和待批准请求。报告记录提交、工作树状态、源码包摘要、镜像 ID 和每项检查结果。双端均通过且各自标签下的容器计数为零，才会输出 `accepted: true`。可以用 `--only darwin` 或 `--only win32` 诊断单台客体。[双端验收入口](../../tools/acceptance/run.py) · [客体验收步骤](../../tools/acceptance/guest.mjs)

控制台的共同行为可用 `node --test test/console-policy-contract.test.mjs` 复验。离线审核基线从插件目录运行以下命令，报告会列出放行变拦截、拦截变放行及增删的样本 ID；发生变化时退出码为 1。[控制台契约测试](../../test/console-policy-contract.test.mjs) · [标注样本](../../plugins/llm-moderation/test/fixtures/offline-policy.jsonl)

```sh
cd plugins/llm-moderation
python3 -m engine.eval_runner --dataset test/fixtures/offline-policy.jsonl --baseline test/fixtures/offline-baseline.json
```

### 在 Windows 上补验 Linux 跳过的 14 项

在已登录的专用 Windows 测试账户中，从仓库根目录运行以下 PowerShell 命令。使用上节的客体配置文件，并将 `LOOMWARD_TEST_IMAGE` 设为该 Docker 引擎中已准备好的完整镜像 ID。

```powershell
$lab = Get-Content -Raw (Join-Path $env:USERPROFILE '.loomward-acceptance.json') | ConvertFrom-Json
$env:Path = (Split-Path -Parent $lab.node) + ';' + $env:Path
$env:AGENTDOCK_DOCKER_TEST = '1'
$env:AGENTDOCK_TEST_DOCKER = $lab.docker
$env:AGENTDOCK_TEST_CONTEXT = $lab.context
$env:AGENTDOCK_TEST_IMAGE = $env:LOOMWARD_TEST_IMAGE
& $lab.pnpm install --frozen-lockfile --ignore-scripts
if ($LASTEXITCODE) { throw '依赖安装失败' }

& $lab.node --test --test-concurrency=1 test/management-safety.test.mjs test/secret-process.test.mjs test/windows-acl.test.mjs
if ($LASTEXITCODE) { throw 'Windows 管理、凭据或 ACL 回归失败' }
& $lab.node --test '--test-name-pattern=^Windows alternate streams and device aliases' test/tools.test.mjs
if ($LASTEXITCODE) { throw 'Windows 文件路径回归失败' }
```

两次汇总应分别为 13 项和 1 项通过，跳过数均为零。Docker 用例会核对自定义 ACL 文件的原始内容及安全描述符，并实际编辑一个继承 ACL 的普通文件。[管理入口](../../test/management-safety.test.mjs) · [凭据子进程](../../test/secret-process.test.mjs) · [NTFS 与 Docker](../../test/windows-acl.test.mjs) · [文件路径](../../test/tools.test.mjs)
