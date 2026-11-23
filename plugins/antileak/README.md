# `@loomward/plugin-antileak`

R1–R7 双层防泄漏策略与工具调用前离线拦截插件（`executionBoundary: "out-of-process"`）。

- **整合来源**：`archive/claude-code-antileak-hooks`（原独立仓库已双端归档至本仓库）。
- **设计定位**：挂载于 `policy:rule@1` 与 `tool:invoke@1`（`@before` 阶段），通过独立子进程调用离线 fail-closed 三态（`pass` / `violation` / `error`）规则引擎，不向内核主进程暴露私有名单或凭据。
