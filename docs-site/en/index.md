---
layout: home

hero:
  name: AgentDock Bridge
  text: Personal Remote MCP Bridge
  tagline: Authenticates remote MCP clients via Cloudflare Workers OAuth 2.1 + PKCE, requires exact manual approval on a hardened Windows, macOS, or Linux host, and executes workspace tools in a read-only Linux Docker container.
  actions:
    - theme: brand
      text: Getting Started
      link: /en/docs/
    - theme: alt
      text: API & Tools
      link: /en/api-reference/
    - theme: alt
      text: Contracts & Boundaries
      link: /en/docs/contracts
    - theme: alt
      text: Internals & Code Map
      link: /en/docs/architecture

features:
  - title: Edge OAuth 2.1 & Password Generations
    details: Splits AuthCoordinator and BridgeRelay across two SQLite Durable Objects with mandatory PKCE S256, zero-script CSP consent HTML, and generation rotation on password change.
  - title: Exact Local Approval & Replay Ledger
    details: Sensitive tools bind origin, client identity, scopes, and full arguments into a canonical SHA-256 digest for Approve.cmd or approve, consuming the grant before claiming a 24h durable receipt.
  - title: Disposable Linux Sandbox & Host Guards
    details: Runs with --read-only, --cap-drop ALL (SETUID/SETGID only), unprivileged UID, and --network none by default while blocking symlink escapes, lone surrogates, and NTFS DACL loss.
---

::: warning AI Translation Notice
English documentation pages are translated/synchronized from the authoritative Chinese source ([简体中文首页](/)) using inspected repository facts. Refer to the Chinese pages or source files if any subtle phrasing differs.
:::

## Capabilities & Explicit Limits

::: info What AgentDock Bridge Delivers
- **Authenticated Edge OAuth 2.1 & Outbound WSS**: Separates `AuthCoordinator` and `BridgeRelay` SQLite DOs and dials out over `WSS /bridge` without opening inbound ports on your router.
- **Per-Parameter `Approve.cmd` / `approve` & Anti-Replay Ledger**: Every mutating/read/exec call outside `computer_context`, `command_status`, and `stop_command` hashes exact arguments for manual terminal confirmation, unlinking `.approved.json` before recording 24h `RequestReceipts`.
- **10 Hardened MCP Tools inside Disposable Linux Containers**: Executes inside `--init`, `--read-only`, `--cap-drop ALL` (`SETUID`/`SETGID`), unprivileged UID/GID (`1000` on Win/macOS or non-root Linux host IDs), and `--network none` containers with `expected_sha256` CAS checks and Windows DACL guards.
:::

::: warning Explicit Non-Goals & Hard Boundaries
- **Single-Owner & Host Storage Boundaries**: Supports one `owner` and one `/workspace` root with zero multi-tenancy; Windows uses DPAPI and NTFS ACLs, macOS uses login Keychain by default, and headless Linux without a keyring falls back to `0600` file storage (`posix-file`).
- **Not Blind E2E Encryption**: Cloudflare edge nodes and your upstream AI client platform still observe `/mcp` arguments and outputs, and approved tools intentionally read files inside `/workspace`.
- **Strict Payload Caps & Cleanup Lockout**: Uses `POST /mcp` JSON-RPC 2.0 (no SSE streams) capped at `1 MiB` ingress / `2 MiB` reply / `110s` deadline; unconfirmed `docker rm -f` halts new tasks until reset.
:::

## Architecture Overview

<DiagramFrame
  src="/diagrams/worker-architecture.html"
  title="AgentDock Bridge Topology (pan / zoom / inspect supported)"
  aspect="940 / 448"
  new-tab-label="Open Fullscreen ↗"
/>

> **Implementation Note**: The diagram visualizes the four high-level zones from client gateway to sandbox. In actual source code, client RPC uses HTTP `POST /mcp` (JSON-RPC 2.0 rather than SSE log streams), `OAuth 2.1 + PKCE (S256)`, outbound connector WebSocket `WSS /bridge`, and per-invocation `docker start --attach` after `Approve.cmd` or `approve`.

## Verification & Client Endpoint Quick Check

Run static syntax checks and cross-platform tests with Node.js 24+ and `pnpm@12.6.0` (platform-specific or real Docker tests skip automatically when prerequisites are absent):

```sh
pnpm install --frozen-lockfile
pnpm run check
pnpm test
```

Production deployments configure Cloudflare Workers (`wrangler deploy`) and install a protected host copy (Windows via `Setup.ps1` + `Install-Hardened.ps1`; Linux/macOS via `node scripts/host-cli.mjs setup` + `install`). Configure compatible remote MCP clients with your deployed `PUBLIC_ORIGIN` endpoint:

```text
https://<your-bridge-domain>/mcp
```

## Documentation Guide

::: tip Quick Navigation by Role & Goal
- **Self-hosting for the first time**: Read [Overview & Setup](/en/docs/) and [Configuration Matrix](/en/docs/configuration) for Worker deployment, DPAPI/Keychain/Secret Service setup, pinned Node/Docker install, and key rotation;
- **Diagnosing 503, approval, or ACL errors**: See [Deployment & Runtime FAQ](/en/docs/faq) for `/healthz`, `LOCAL_APPROVAL_REQUIRED`, host permission checks, and cleanup lockouts;
- **Integrating MCP clients or auditing security**: Read [OAuth, Tools & Sandbox Contracts](/en/docs/contracts) for HTTP/OAuth limits, 4 scopes, 10 tool schemas, replay ordering, and Docker flags;
- **Tracing internals or changing code**: Explore [Architecture & ADRs](/en/docs/architecture), [End-to-End Walkthrough](/en/docs/walkthrough), and [Source & Test Code Map](/en/docs/code-map).
:::
