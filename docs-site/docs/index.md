---
title: 项目定位与部署流程
description: 了解 AgentDock Bridge 的三层信任模型、平台边界，以及从零到首次批准执行的完整部署步骤。
---

# 项目定位与部署流程

AgentDock Bridge 是一个**单人专用的远程 MCP 代理网关**：把远端支持 MCP 与 OAuth 2.1 的客户端（如 ChatGPT）经由 Cloudflare Workers 连接到你自己的本机开发环境，并在每次敏感文件或命令调用前强制经过本机终端的人工逐参数批准，最后把实际操作隔离在只读 Linux Docker 容器中执行。

## 系统定位与平台边界

在开始部署前，先核对以下三条硬性边界（按当前源码核实）：

| 维度 | 当前支持事实 | 边界与说明 |
| --- | --- | --- |
| 云端入口 | Cloudflare Workers + 双 SQLite Durable Objects（`AuthCoordinator`、`BridgeRelay`） | 公开流量仅接受 HTTPS（仅本机开发测试放行 `127.0.0.1` / `localhost` / `[::1]`） |
| 生产本地宿主 | **Windows x64**（PowerShell + DPAPI + NTFS ACL）与 **Linux / macOS**（`host-cli.mjs` + Keychain / Secret Service / `0600` 文件） | Windows 额外校验显式 NTFS DACL 替换；无图形会话的 Linux 宿主若无 Keyring 会话默认回退至 `0600` `posix-file` |
| 工具执行环境 | **Linux 容器**（`node:24-trixie-slim`，Windows/macOS 默认 `desktop-linux` 且 UID `1000`；Linux 默认 `default` 且匹配宿主非 root UID/GID） | 严格挂载**单一**工作区到 `/workspace`；项目内部文件对已批准的工具刻意可读写 |

> **安全边界提示**：Cloudflare 边缘节点和上游 AI 客户端平台都能看到经过 `/mcp` 的工具参数与返回正文；本网关保护的是**未经你本机批准，任何调用都无法执行**，并非对中继链路不可见的端到端加密。
>
> **交互式接口参考**：需逐项查阅 OAuth 2.1 端点、`WSS /bridge` 与 10 个 MCP 工具参数及明确限制，可直接使用 [API 与组件参考](/api-reference/)。

## 前置准备

1. **云端环境**：拥有可绑定自定义 HTTPS 域名（或 `workers.dev` 子域）的 Cloudflare 账户，并在本机完成 Wrangler 登录认证。
2. **宿主与运行依赖（Windows / macOS / Linux）**：
   - Node.js 24+ 与 `pnpm@12.6.0`（用于开发仓库检查与运行安装脚本；受保护运行副本会另外下载校验官方固定版本 Node `24.22.1`）。
   - Docker Desktop（Windows / macOS，`desktop-linux` 或 `orbstack`/`colima` 等本地 `unix:///` / `npipe://` 上下文）或原生 Linux Docker Engine（`default` 上下文）。
3. **独立工程目录**：选择一个**绝对路径**且位于 `~/.agentdock-bridge`（Windows 为 `%USERPROFILE%\.agentdock-bridge`）与代码克隆目录之外的工程目录用于容器挂载（后文用 `<workspace-path>` 表示）。

## 端到端部署主流程

### 1. 检出验证与 Worker 配置准备

在受信任的代码克隆目录安装依赖并运行静态检查及跨平台测试：

```powershell
pnpm install --frozen-lockfile
pnpm run check
pnpm test
```

复制模板生成本机私有 `wrangler.jsonc`（已被 `.gitignore` 忽略，严禁提交真实域名或凭据）：

```powershell
Copy-Item wrangler.jsonc.example wrangler.jsonc
```

编辑 `wrangler.jsonc` 中的 `vars.PUBLIC_ORIGIN`，将其改为你的实际 HTTPS 网关根地址（不含尾部斜杠与路径，例如 `https://<your-bridge-domain>`）。

### 2. 初始化本机凭据与加密配置

运行初始化脚本生成强随机 `BRIDGE_TOKEN`（32 字节 Base64url）与 `OWNER_PASSWORD`（24 字节 Base64url + 100,000 轮 PBKDF2-SHA256 哈希），并按宿主平台存储：

- **Windows（PowerShell）**：通过 Windows DPAPI 加密写入 `%USERPROFILE%\.agentdock-bridge\secrets.dpapi` 并上传密钥：

```powershell
.\scripts\Setup.ps1 -Roots "<workspace-path>" -Origin "https://<your-bridge-domain>"
.\scripts\Secrets.ps1 -Action Upload
```

- **Linux / macOS（POSIX）**：macOS 默认写入登录 Keychain，Linux 桌面默认写入 Secret Service（无图形会话回退为 `0600` `secrets.json`，可用 `--secret-backend` 指定）：

```sh
node scripts/host-cli.mjs setup --roots "<workspace-path>" --origin "https://<your-bridge-domain>"
node scripts/host-cli.mjs upload-secrets
```

### 3. 构建固定摘要的开发容器镜像

使用仓库根目录上下文构建离线开发镜像，确保工具链与 `/opt/bridge` 内文件一致（`-t` 标签仅用于安装器查找并锁死 `sha256:...` 摘要）：

```powershell
docker build -f container/Dockerfile -t agentdock-dev:2026-10-28 .
```

### 4. 安装受保护运行副本与部署云端网关

安装器会校验状态目录及整条祖先路径权限、下载并验证对应平台官方 Node `24.22.1`（存放于 `~/.agentdock-toolchains`）、锁死 Docker 镜像摘要，并将运行副本安装到 `~/.agentdock-bridge/runtime-*`：

```powershell
# Windows
.\scripts\Install-Hardened.ps1 -Workspace "<workspace-path>"
pnpm run deploy
```

```sh
# Linux / macOS（可选追加 --context / --docker / --proxy）
node scripts/host-cli.mjs install --workspace "<workspace-path>"
pnpm run deploy
```

> **提示**：如果需要经由代理下载官方 Node 压缩包，Windows 可追加 `-Proxy "http://127.0.0.1:<port>"`，POSIX 可追加 `--proxy "http://127.0.0.1:<port>"`。安装器在 `config.json` 中默认开启 `allowExec: true`、`requireLocalApproval: true` 与 `sandbox.allowOutbound: true`（单次联网仍需本机人工在 `Approve.cmd` 或 `approve` 批准）。

### 5. 启动连接器并完成首次 OAuth 与人工批准

**务必从受保护状态目录中的可信入口启动与管理连接器**（仓库根目录的同名 `.cmd` 文件仅作为 Windows 转发入口）：

```powershell
# Windows
& "$env:USERPROFILE\.agentdock-bridge\Start.cmd"
& "$env:USERPROFILE\.agentdock-bridge\Status.cmd"
```

```sh
# Linux / macOS
~/.agentdock-bridge/start
~/.agentdock-bridge/status
```

确认公网健康探针 `/healthz` 返回 `{"ok":true,"connectorOnline":true}` 后，按以下三步完成首次接入：

1. 在远端 MCP 客户端填入网关地址 `https://<your-bridge-domain>/mcp`。
2. 客户端拉起 OAuth 2.1 授权页后，核对客户端名称、回调主机与申请的作用域；在本地运行 `Password.cmd`（Windows）或 `~/.agentdock-bridge/password`（Linux / macOS）查看连接密码并登录批准。
3. 当客户端首次调用敏感工具并收到 `LOCAL_APPROVAL_REQUIRED` 时，在本地交互终端运行 `Approve.cmd`（Windows）或 `~/.agentdock-bridge/approve`（Linux / macOS），逐行核对参数并输入精确口令 `APPROVE <uuid>`，随后在 5 分钟内用完全相同的参数重试执行。

## 下一步

- 查核全部配置文件字段、脚本参数与 Secrets 轮换命令：[配置矩阵与运维脚本](/docs/configuration)
- 排查 `503` 离线、ACL 权限拒绝或清理锁死：[部署与运行排错 FAQ](/docs/faq)
- 审阅 OAuth 端点、10 项工具上限与容器参数契约：[OAuth、工具、批准与沙箱契约](/docs/contracts)
