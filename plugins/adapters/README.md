# `@loomward/plugin-adapters`

面向独立维护外部项目的受控接口适配层（`executionBoundary: "out-of-process"`）。

以下项目保持独立仓库与独立部署，本插件仅定义协议对接与状态观测接口，不耦合其源码本体：

- **CloudForge**（`CyberNova2333/cloudforge`）：对接其 OAuth 2.1 Streamable HTTP `/mcp` 端点（31+3 工具）及 PR/CI 只读状态探针。
- **ModelBridge**（`CyberNova2333/modelbridge`）：对接其多协议 LLM 网关与自建 SQLite 状态服务的健康检查与路由观测接口，严格保留四态凭据隔离。
