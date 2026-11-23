# `@loomward/kernel`

LoomWard 的 **Cordis 4** 微内核与策略守卫层（参考 Weftale 内核与安全模型，并针对 Node.js 宿主机边界适配）：

- `src/boot.mjs`：基于 Cordis `Context` 启动微内核；在 `BOOT_DEADLINE_MS`（60 秒）内校验冻结 RPM 形状、SHA-256 摘要及全部根插件入口字节哈希，失败即 LIFO 逆序回滚；注册平台级标准插槽并仅向启动调用方返回 `KernelControl`。
- `src/policy-tree.mjs`：纯函数 `PolicyTree`（`Subject × Action × Resource × Condition`），支持通配符匹配、高精确度优先与同精确度 `deny > escalate > allow` 收敛。
- `test/layering.test.mjs`：机械分层守卫，静态扫描并拦截 `packages/shared` 的宿主依赖、非内核包对 `cordis` 的直接运行时导入以及插件间静态互导。
