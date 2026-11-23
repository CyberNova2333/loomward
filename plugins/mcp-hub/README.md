# `@loomward/plugin-mcp-hub`

第三方 `stdio` 与 `Streamable HTTP` MCP 聚合接入插件（`executionBoundary: "out-of-process"`）。

- **迁移来源**：根目录 `local/{mcp-registry,mcp-client}.mjs`（归档于 `archive/agentdock-worker-remote`）。
- **设计定位**：在 Docker 容器沙箱外运行，强制最小环境白名单、隔离空临时目录、私网/保留 IP 与 DNS 重绑定拦截、8 KiB 截断前密钥脱敏，且所有聚合工具均受本机精确审批与 `destructiveHint: true` 约束。
