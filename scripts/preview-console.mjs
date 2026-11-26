#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Zero-initialization ephemeral local loopback preview launcher (`pnpm run preview`).
// Runs ONLY on 127.0.0.1 inside an isolated temporary state directory; never used by installed production daemons.
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { startLoomWardDaemon } from '../packages/host/src/daemon.mjs';
import { writeModerationConfigSync } from '../local/moderation-config.mjs';
import { writeAntileakConfigSync } from '../local/antileak-config.mjs';

function parsePreviewArgs(argv = process.argv.slice(2)) {
  let consolePort = 0;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--port' && argv[i + 1]) {
      const n = Number(argv[++i]);
      if (!Number.isInteger(n) || n < 0 || n > 65535) {
        throw new Error('Invalid --port argument; expected integer 0..65535.');
      }
      consolePort = n;
    } else if (arg === '--help' || arg === '-h') {
      console.log('Usage: node scripts/preview-console.mjs [--port <18797|0>]');
      process.exit(0);
    }
  }
  return { consolePort };
}

async function startSampleMockModelServer() {
  const srv = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ choices: [{ message: { content: '{"safe":true,"score":0.05,"categories":[]}' } }] }));
    });
  });
  await new Promise(resolve => srv.listen(0, '127.0.0.1', resolve));
  return { server: srv, url: `http://127.0.0.1:${srv.address().port}` };
}

const { consolePort } = parsePreviewArgs();
const base = await fs.mkdtemp(path.join(os.homedir(), '.loomward-preview-'));
await fs.chmod(base, 0o700);
const stateDir = path.join(base, 'state');
const workspace = path.join(base, 'workspace');
await fs.mkdir(stateDir, { mode: 0o700 });
await fs.mkdir(workspace, { mode: 0o700 });

await fs.writeFile(path.join(workspace, 'README.md'), '# LoomWard Local Preview Workspace (Read-Only Demo)\n', { mode: 0o600 });
await fs.writeFile(path.join(stateDir, 'config.json'), JSON.stringify({
  origin: 'https://preview.example.test',
  roots: [workspace],
  defaultCwd: workspace,
  allowExec: false,
  allowOutbound: false,
  requireLocalApproval: true,
}, null, 2), { mode: 0o600 });
await fs.writeFile(path.join(stateDir, 'secrets.meta.json'), JSON.stringify({ backend: 'posix-file' }), { mode: 0o600 });
await fs.writeFile(path.join(stateDir, 'secrets.json'), JSON.stringify({
  bridgeToken: `preview-${crypto.randomBytes(24).toString('hex')}`,
  ownerPasswordHash: 'pbkdf2-sha256$100000$preview$hash',
}), { mode: 0o600 });

// Seed sample sanitized audit telemetry & synthetic offline antileak cache
await fs.writeFile(path.join(stateDir, 'audit.jsonl'), [
  JSON.stringify({ time: new Date(Date.now() - 45_000).toISOString(), tool: 'read_file', success: true, reason: 'ok', durationMs: 14, mountMode: 'readonly', bytesRead: 2048 }),
  JSON.stringify({ time: new Date(Date.now() - 12_000).toISOString(), tool: 'exec_command', success: true, reason: 'ok', durationMs: 36, mountMode: 'readonly', mode: 'sync', network: 'none', exitCode: 0, stdoutBytes: 256, stderrBytes: 0 }),
].join('\n') + '\n', { mode: 0o600 });

const nowSec = Math.floor(Date.now() / 1000);
await fs.mkdir(path.join(stateDir, 'antileak'), { recursive: true, mode: 0o700 });
await fs.writeFile(path.join(stateDir, 'antileak', 'private-repos.json'), JSON.stringify({
  generated_at: nowSec,
  expires_at: nowSec + 28800,
  status: 'fresh',
  sources: ['preview-seed'],
  owners: ['preview-org'],
  private: ['preview-org/internal-demo-repo'],
  patterns: [],
}), { mode: 0o600 });

writeAntileakConfigSync(stateDir, {
  expectedOwners: ['preview-org'],
  privateCacheTtl: 28800,
}, { workspaceRoots: [workspace], requirePrivateState: true });

const mockLlm = await startSampleMockModelServer();
writeModerationConfigSync(stateDir, {
  mode: 'local-only',
  policyProfile: 'balanced',
  defaultScope: 'combined',
  cloudOptIn: false,
  localGuard: { kind: 'ollama', endpoint: 'http://127.0.0.1:11434', model: 'qwen3.5:9b', think: false, timeoutMs: 5000 },
}, { workspaceRoots: [workspace], requirePrivateState: true });

const daemon = await startLoomWardDaemon({
  rootDir: path.resolve(import.meta.dirname, '..'),
  stateDir,
  origin: 'https://preview.example.test',
  workspaceRoots: [workspace],
  allowExec: false,
  sandboxRuntime: {
    async handleRpc(body) {
      if (body.method === 'initialize') {
        return { jsonrpc: '2.0', id: body.id ?? null, result: { protocolVersion: '2025-11-25', serverInfo: { name: 'preview', version: '1' } } };
      }
      if (body.method === 'tools/list') {
        return { jsonrpc: '2.0', id: body.id ?? null, result: { tools: [] } };
      }
      return { jsonrpc: '2.0', id: body.id ?? null, result: { content: [{ type: 'text', text: 'preview-ok' }] } };
    },
    async close() {},
    isClosed: () => false,
  },
  relay: { autoStart: false },
  enableMcpHub: false,
  enableLlmModeration: false,
  secretLoader: () => ({ bridgeToken: `preview-${crypto.randomBytes(16).toString('hex')}` }),
  approvals: { authorize: async () => ({ approved: true, id: 'apr-preview', expiresAt: Date.now() + 60_000 }) },
  consoleConfig: {
    enabled: true,
    host: '127.0.0.1',
    consolePort,
    previewAutoSession: true,
    enableControlSocket: false,
    requirePrivateState: true,
  },
});

const consoleSvc = daemon.control.getService('console:loopback');
console.log(JSON.stringify({
  status: 'PREVIEW_READY',
  url: consoleSvc.url,
  previewAutoSession: true,
  workspace,
  note: '本地预览模式（免初始化引导码与密码）；直接在浏览器打开 url 即可访问，Ctrl+C 退出并清理临时目录。',
}, null, 2));

let stopping = false;
async function shutdown() {
  if (stopping) return;
  stopping = true;
  await daemon.stop().catch(() => {});
  await new Promise(r => mockLlm.server.close(r));
  await fs.rm(base, { recursive: true, force: true }).catch(() => {});
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
