# `@loomward/plugin-decisions`

人机协作决策台账、三轴状态治理与受控上下文导出插件（`executionBoundary: "out-of-process"`）。

- **整合来源**：`archive/agent-decisions-dashboard`（原独立仓库已双端归档至本仓库）。
- **设计定位**：托管或桥接本机回环决策台账服务，把按 `topic_scope` 过滤的只读上下文与受审批的台账写入封装为标准 `tool:provider@1` 工具，并在控制台提供状态卡片。
