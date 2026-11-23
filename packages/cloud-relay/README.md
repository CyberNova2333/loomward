# `@loomward/cloud-relay`

LoomWard 的云端边缘 OAuth 2.1 + `BridgeRelay` 中继根插件包。

- **职责**：作为 `gateway:ingress@1` 实现位之一，把公网 HTTPS `/mcp` 与 OAuth 2.1 授权经反向 `WSS /bridge` 接入本地内核。
- **迁移来源**：根目录 `cloud/`（完整历史归档于 `archive/agentdock-worker-remote`）。
