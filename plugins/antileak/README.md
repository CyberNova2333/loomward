# `@loomward/plugin-antileak`

R1–R7 双层防泄漏策略与工具调用前离线拦截插件（`executionBoundary: "out-of-process"`）。

- **整合来源**：`archive/claude-code-antileak-hooks`（原独立仓库已双端归档至本仓库）。
- **设计定位**：挂载于 `policy:rule@1` 与 `tool:invoke@1`（`@before` 阶段），通过独立子进程调用离线 fail-closed 三态（`pass` / `violation` / `error`）规则引擎，不向内核主进程暴露私有名单或凭据。
- **控制台与配置管理**：统一控制台左侧「Agent 安全围栏」通过 [`local/antileak-config.mjs`](../../local/antileak-config.mjs) 管理 `<stateDir>/antileak/policy.json`（`0600`），提供 R1–R7 全规则配置、离线 Dry-Run（`check.py content`）、缓存刷新（`refresh-private.py`）与自检（`doctor.py`），并严格屏蔽缓存中的私有名单与种子模式原文。
