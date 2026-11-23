---
title: Overview & Setup Workflow
description: Scope boundaries, trust model, and end-to-end deployment flow for AgentDock Bridge.
---

::: warning AI Translation Notice
Translated/synchronized from the authoritative Chinese documentation ([简体中文文档](/docs/)). Check source files or Chinese docs if subtle phrasing differs.
:::

# Overview & Setup Workflow

AgentDock Bridge is a **single-owner personal remote MCP gateway**. It connects remote MCP clients (such as ChatGPT) over Cloudflare Workers OAuth 2.1 + PKCE to your local workstation, waits for explicit human approval of exact arguments in a local terminal, and executes file and Bash tools inside a read-only Linux Docker container.

## Runtime Scope & Platform Boundaries

| Layer | Supported Runtime | Key Boundaries |
| --- | --- | --- |
| Cloud Edge | Cloudflare Workers + two SQLite Durable Objects (`AuthCoordinator`, `BridgeRelay`) | Production requests require HTTPS (`127.0.0.1` / `localhost` / `[::1]` allowed for local tests) |
| Production Host | **Windows x64** (`scripts/*.ps1`, DPAPI, NTFS ACL) and **Linux / macOS** (`scripts/host-cli.mjs`, Keychain / Secret Service / `0600`) | Windows additionally guards custom NTFS DACLs before replacement; headless Linux without a keyring uses `0600` `posix-file` |
| Execution Sandbox | Linux container (`node:24-trixie-slim`, `desktop-linux` UID `1000` on Win/macOS, `default` matching host non-root UID/GID on Linux) | Mounts **one** explicit workspace at `/workspace`; approved tools can read/write project-local files |

> **Trust Notice**: Cloudflare and your upstream AI client platform still observe `/mcp` arguments and results in transit. This bridge guarantees that no local action runs without owner OAuth consent and exact `Approve.cmd` confirmation.
>
> **Interactive Reference**: Browse every OAuth endpoint, `WSS /bridge` rule, and all 10 MCP tool schemas with explicit bounds in the [API & Component Reference](/en/api-reference/).

## Prerequisites

1. A Cloudflare account with HTTPS domain routing (`PUBLIC_ORIGIN`) and authenticated `wrangler`.
2. **Windows / macOS / Linux** with Node.js 24+, `pnpm@12.6.0`, and local Docker (Docker Desktop `desktop-linux` on Windows/macOS, OrbStack/Colima on macOS, or native Docker Engine `default` on Linux).
3. An explicit workspace directory (`<workspace-path>`) strictly separate from `~/.agentdock-bridge` (`%USERPROFILE%\.agentdock-bridge` on Windows) and your source checkout.

## Step-by-Step Deployment Workflow

### 1. Validate Checkout & Prepare `wrangler.jsonc`

```powershell
pnpm install --frozen-lockfile
pnpm run check
pnpm test
Copy-Item wrangler.jsonc.example wrangler.jsonc
```

Set `vars.PUBLIC_ORIGIN` in `wrangler.jsonc` to your deployed HTTPS origin (for example `https://<your-bridge-domain>` without a trailing slash). `wrangler.jsonc` is ignored by Git and must never be committed.

### 2. Initialize Protected Host Secrets & Upload to Cloudflare

```powershell
# Windows (PowerShell + DPAPI)
.\scripts\Setup.ps1 -Roots "<workspace-path>" -Origin "https://<your-bridge-domain>"
.\scripts\Secrets.ps1 -Action Upload
```

```sh
# Linux / macOS (Keychain, Secret Service, or 0600 posix-file)
node scripts/host-cli.mjs setup --roots "<workspace-path>" --origin "https://<your-bridge-domain>"
node scripts/host-cli.mjs upload-secrets
```

Setup generates a 32-byte URL-safe `BRIDGE_TOKEN`, a 24-byte `OWNER_PASSWORD`, and a 100,000-iteration PBKDF2-SHA256 `OWNER_PASSWORD_HASH`, storing them in DPAPI (`secrets.dpapi` on Windows), macOS Keychain, Linux Secret Service (`secret-tool`), or a `0600` file on headless Linux, and pipes only `BRIDGE_TOKEN` and `OWNER_PASSWORD_HASH` into `wrangler secret bulk`.

### 3. Build the Pinned Development Image

```sh
docker build -f container/Dockerfile -t agentdock-dev:2026-10-28 .
```

### 4. Install the Hardened Host Copy & Deploy the Worker

```powershell
# Windows
.\scripts\Install-Hardened.ps1 -Workspace "<workspace-path>"
pnpm run deploy
```

```sh
# Linux / macOS
node scripts/host-cli.mjs install --workspace "<workspace-path>"
pnpm run deploy
```

The installer verifies ancestor permissions, downloads and checksum-verifies pinned Node `24.22.1` under `~/.agentdock-toolchains` (with Authenticode on Windows / `codesign` on macOS), pins the container `sha256:...` digest, copies `local/` and `scripts/` into a versioned `runtime-*` folder with frozen production dependencies, and generates trusted launchers under `~/.agentdock-bridge`.

### 5. Start Connector, Connect MCP Client, and Approve Requests

```powershell
# Windows
& "$env:USERPROFILE\.agentdock-bridge\Start.cmd"
& "$env:USERPROFILE\.agentdock-bridge\Status.cmd"
```

```sh
# Linux / macOS
~/.agentdock-bridge/start
~/.agentdock-bridge/status
```

1. Confirm `/healthz` returns `200` (`{"ok":true,"connectorOnline":true}`).
2. Add `https://<your-bridge-domain>/mcp` in your remote MCP client.
3. On the OAuth consent page, verify the client identity and callback URI, then enter the password shown by `Password.cmd` (Windows) or `~/.agentdock-bridge/password` (Linux/macOS).
4. When a file or command tool returns `LOCAL_APPROVAL_REQUIRED`, run `Approve.cmd` (Windows) or `~/.agentdock-bridge/approve` (Linux/macOS), inspect the escaped JSON arguments, type `APPROVE <uuid>`, and retry with identical arguments within 5 minutes.

## Next Steps

- Full parameter, script, and rotation matrix: [Configuration & Scripts Matrix](/en/docs/configuration)
- Error diagnosis (`503`, `APPROVAL_RECORD_TOO_LARGE`, ACL failures): [Deployment & Runtime FAQ](/en/docs/faq)
- HTTP/OAuth, MCP tool schemas, replay ordering & sandbox flags: [Contracts & Boundaries](/en/docs/contracts)
