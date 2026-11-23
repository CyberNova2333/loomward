# `@loomward/console`

LoomWard 的本机回环双源控制台根插件包（参考 Weftale 独立信任源架构）：

- **Trust Origin（独立回环端口）**：仅承载零扩展核心安全面——PassKey/WebAuthn 与强密码认证、精确请求复核审批、总能力熔断与插件签名信任决策。
- **Console Origin**：承载综合仪表板、实时审计遥测、MCP 与第三方扩展面板视图（经 `console:panel@1` 插槽声明，与 Trust Origin 物理隔离）。
- **迁移来源**：根目录 `local/{webui,webui-assets,webui-auth,webauthn}.mjs`。
