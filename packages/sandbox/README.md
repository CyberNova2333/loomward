# `@loomward/sandbox`

LoomWard 的只读 Linux Docker 容器沙箱与文件安全策略根插件包。

- **职责**：提供一次性容器执行、20 秒租约看门狗、路径与符号链接守卫、Windows 自定义 NTFS ACL 拦截及清理失败退守。
- **迁移来源**：根目录 `container/` 与 `local/{sandbox,tools,file-safety,windows-acl,docker-query}.mjs`（完整历史归档于 `archive/agentdock-worker-remote`）。
