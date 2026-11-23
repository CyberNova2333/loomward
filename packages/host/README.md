# `@loomward/host`

LoomWard 的跨平台受保护宿主运行时、凭据保管库、审批状态机与防重放账本根插件包。

- **职责**：封装 Windows（DPAPI/NTFS ACL/PowerShell）与 Linux/macOS（Keychain/Secret Service/`0600`、祖先写保护、固定 Node `24.22.1` SHA-256、守护锁），并承接精确审批与 24h 持久防重放账本。
- **迁移来源**：根目录 `local/{connector,approvals,approval-store,approval-cli,receipts,request-policy,capabilities,host-safety,host-secrets,node-toolchains}.mjs` 与 `scripts/`。
