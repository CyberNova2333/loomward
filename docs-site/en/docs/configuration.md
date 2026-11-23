---
title: Configuration & Scripts Matrix
description: Reference for wrangler.jsonc, Cloudflare Secrets, local config.json, environment variables, and PowerShell scripts.
---

::: warning AI Translation Notice
Translated/synchronized from the authoritative Chinese documentation ([配置矩阵与运维脚本](/docs/configuration)). Check source files or Chinese docs if subtle phrasing differs.
:::

# Configuration & Scripts Matrix

Configuration is separated cleanly into **Cloudflare Worker configuration** and the **protected local state directory** (default `%USERPROFILE%\.agentdock-bridge`). Never commit `wrangler.jsonc`, `.dev.vars`, or `secrets.dpapi`.

## 1. Cloudflare Worker (`wrangler.jsonc` & Secrets)

| Setting | Example / Binding | Purpose |
| --- | --- | --- |
| `main` | `cloud/index.mjs` | Edge entrypoint exporting default `fetch`, `BridgeRelay`, and `AuthCoordinator` |
| `compatibility_date` / flags | `2026-10-28`, `nodejs_compat`, `global_fetch_strictly_public` | Enables Node compatibility and restricts Worker fetches to public endpoints |
| `preview_urls` | `false` | Disables ephemeral preview hostnames that bypass `PUBLIC_ORIGIN` checks |
| `vars.PUBLIC_ORIGIN` | `https://bridge.example.test` | Required HTTPS origin checked against request host, CORS, and consent POST origin |
| `durable_objects.bindings` | `RELAY` (`BridgeRelay`), `AUTH` (`AuthCoordinator`) | SQLite-backed DOs initialized via migrations `v1` and `v2` |
| Secret `BRIDGE_TOKEN` | Min 32-char URL-safe random secret | Shared bearer token for `WSS /bridge` and IP rate-limit key salt |
| Secret `OWNER_PASSWORD_HASH` | `pbkdf2-sha256$100000$<salt>$<hash>` | Verifies owner login; SHA-256 shifts `AUTH` generation `owner-v2-<hash>` |

## 2. Protected State Directory (`~/.agentdock-bridge` / `%USERPROFILE%\.agentdock-bridge`)

On Windows, NTFS ACLs restrict FullControl to the current user SID and `SYSTEM` (`S-1-5-18`); on Linux and macOS, `local/host-safety.mjs` enforces `0700` ownership and ancestor write protection:

- `secrets.dpapi` (Windows DPAPI) or `secrets.meta.json` + Keychain / Secret Service / `0600` `secrets.json` (POSIX).
- `config.json`: Connector configuration (see table below).
- `runtime-<timestamp>-<id>/` & `installation.json`: Isolated copy of `local/`, `scripts/`, `package.json`, `pnpm-lock.yaml`, production deps, and SHA-256 manifest.
- `{Start,Stop,Status,Password,Approve}.cmd` (Windows) or `{start,stop,status,password,approve}` (`0700` POSIX wrappers clearing preload/linker env vars).
- `approvals/`, `request-receipts/`, and `supervisor.sock` (POSIX single-instance lock).

| `config.json` Field | Writer | Meaning & Constraint |
| --- | --- | --- |
| `origin` | `Setup.ps1` / `host-cli.mjs setup` | Matches Worker `PUBLIC_ORIGIN` (HTTPS required outside loopback tests) |
| `roots` / `defaultCwd` | `Install-Hardened.ps1 -Workspace` / `host-cli.mjs install --workspace` | Exactly **one** explicit directory mounted at `/workspace` (must not contain `stateDir` or `sourceRoot`) |
| `sourceRoot` | `Install-Hardened.ps1` / `host-cli.mjs install` | Must equal running script root; blocks launching from unhardened folders |
| `nodePath` / `nodeRoot` / `nodeSha256` | `Install-NodeRuntime.ps1` / `node-toolchains.mjs` | Pinned Node `24.22.1` under `~/.agentdock-toolchains`, verified on every start/approval |
| `allowExec` | `setup` (`false`) -> `install` (`true`) | Enables `exec_command`, `command_status`, `stop_command` on the sandbox (`file-worker.mjs` keeps `false`) |
| `requireLocalApproval` | `true` | Required by `Manage.ps1` and `host-cli.mjs` before connector start |
| `sandbox.enabled` / `image` / `dockerPath` / `context` / `allowOutbound` | `Install-Hardened.ps1` / `host-cli.mjs install` | Pinned `sha256:<64-hex>` image, `nlink === 1` `docker`, `desktop-linux` (Win/macOS) or `default` (Linux) context, outbound toggle (`true` by default) |

## 3. Environment Variables, npm/pnpm & Host Scripts

| Variable / Script | Scope & Notes |
| --- | --- |
| `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` | Optional proxies (plus bypass list) probed alongside Windows WinINet or macOS `scutil --proxy` and direct route |
| `AGENTDOCK_DOCKER_TEST` | Enables real container integration tests in `test/sandbox.test.mjs` |
| `AGENTDOCK_BRIDGE_TOKEN` | Explicitly deleted from `process.env` at connector startup |
| `NODE_OPTIONS`, `NODE_PATH`, `NODE_TLS_REJECT_UNAUTHORIZED`, `NODE_EXTRA_CA_CERTS` | Cleared by `Clear-NodeOverrides` before launching Node |
| `pnpm run dev` | Starts `wrangler dev --ip 127.0.0.1 --port 8797` for loopback testing |
| `pnpm run check` / `pnpm test` | Syntax check across modules & Node test runner (`test/*.test.mjs cloud/*.test.mjs`) |
| `scripts/Manage.ps1` / `scripts/host-cli.mjs` | Host lifecycle (`start`, `stop`, `status`, `approve`, `password`, `setup`, `install`) with process start-time anti-PID-reuse checks |
| `scripts/Rotate-Secrets.ps1` / `host-cli.mjs rotate-secrets` | Two-step rotation (stage `next` -> `wrangler secret bulk` -> promote to `current`) while stopped |
| `scripts/acceptance-v2.mjs` / `verify-lifecycle.mjs` | Explicit maintainer live verification against public `/healthz` and `/mcp` |

## 4. Rotating Credentials Safely

1. Run `Stop.cmd` (Windows) or `~/.agentdock-bridge/stop` (Linux/macOS) and verify both supervisor and connector exited.
2. Run `.\scripts\Rotate-Secrets.ps1` (Windows) or `node scripts/host-cli.mjs rotate-secrets` (Linux/macOS). If Cloudflare upload fails, staged credentials remain so retries are idempotent; once committed, old OAuth tokens fail immediately due to the shifted `owner-v2-*` DO generation.
3. Re-authenticate MCP clients using the new password shown by `Password.cmd` or `~/.agentdock-bridge/password`.
