# `@loomward/shared`

零宿主耦合、零运行时第三方依赖的共享契约与原语包（禁止导入 `node:*`、`cordis`、宿主或业务插件）：

- `src/contracts.mjs`：根插件与扩展插件的声明式契约校验（含强制 `executionBoundary` 声明）。
- `src/rpm.mjs`：构建期根插件清单（RPM）形状校验、规范化序列化与 SHA-256 摘要同算。
- `src/deadline.mjs`：启动期限控制（默认 60 秒）与后进先出（LIFO）逆序事务回滚。
- `src/slots.mjs`：`ImplSlot`（实现位）与 `MechanismSlot`（`before`/`after`/`replace` 机制插槽）及 `WriteAuthorizer` 写边守卫。
