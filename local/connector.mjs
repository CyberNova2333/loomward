// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import WebSocket from 'ws';
import { HttpsProxyAgent } from 'https-proxy-agent';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { RequestReceipts, TransientReceipts, StopReceipts } from './receipts.mjs';
import { LocalApprovals } from './approvals.mjs';
import { ApprovalRecordTooLargeError } from './approval-store.mjs';
import { validateRequestEnvelope, requiresApproval, isValidExternalToolName } from './request-policy.mjs';
import { exportSecretsSync } from './host-secrets.mjs';
import { readCapabilitiesSync, isToolEnabled } from './capabilities.mjs';
import { createExternalMcpHub } from './mcp-client.mjs';

export const defaultStateDirectory = () => path.join(os.homedir(), '.agentdock-bridge');
function windowsPowerShell() {
  const systemRoot = process.env.SystemRoot || 'C:\\Windows';
  if (!path.isAbsolute(systemRoot) || systemRoot.startsWith('\\\\')) throw new Error('Cannot locate the Windows system shell.');
  const system32 = path.join(systemRoot, 'System32');
  const shellHome = path.join(system32, 'WindowsPowerShell', 'v1.0');
  // Module imports and CLR startup must not inherit project/toolchain overrides.
  // Use the OS directory as cwd as well, rather than a caller-controlled project.
  return {
    executable: path.join(shellHome, 'powershell.exe'), cwd: shellHome,
    env: { SystemRoot: systemRoot, WINDIR: systemRoot, USERPROFILE: os.homedir(),
      PATH: system32, PSModulePath: path.join(shellHome, 'Modules') },
  };
}

export function loadSecrets(stateDir, { fields } = {}) {
  if (process.platform !== 'win32') return exportSecretsSync(stateDir, { fields });
  const script = path.resolve(import.meta.dirname, '..', 'scripts', 'Secrets.ps1');
  try {
    const { executable, env, cwd } = windowsPowerShell();
    const json = execFileSync(executable, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-File', script,
      '-Action', 'Export', '-StateDir', stateDir], { env, cwd, windowsHide: true, encoding: 'utf8', maxBuffer: 65536, timeout: 15000,
      stdio: ['ignore', 'pipe', 'pipe'] });
    const data = JSON.parse(json.replace(/^\uFEFF/, ''));
    if (Array.isArray(fields) && fields.length) {
      const subset = {};
      for (const field of fields) subset[field] = data[field];
      return subset;
    }
    return data;
  } catch {
    // execFileSync errors can contain captured credential output and shell diagnostics.
    // Never attach the original error or relay either stream to callers or logs.
    throw new Error('Protected credential loading failed. Check the trusted local installation.');
  }
}

let cachedOsProxies = { key: '', expiresAt: 0, values: [] };

function normalizeProxyCandidate(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  try {
    const parsed = new URL(withScheme);
    if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) return null;
    if (parsed.pathname === '/' && !parsed.search && !parsed.hash && !trimmed.endsWith('/')) return parsed.origin;
    return parsed.toString();
  } catch {
    return null;
  }
}

function bypassesNoProxy(targetOrigin) {
  if (!targetOrigin) return false;
  let hostname, port;
  try {
    const parsed = new URL(targetOrigin);
    hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
  } catch { return false; }
  const rules = (process.env.NO_PROXY || process.env.no_proxy || '')
    .split(',')
    .map(item => item.trim().toLowerCase())
    .filter(Boolean);
  for (const rule of rules) {
    if (rule === '*') return true;
    const [ruleHostPart, rulePort] = rule.startsWith('[')
      ? [rule.slice(1, rule.indexOf(']')), rule.slice(rule.indexOf(']') + 2)]
      : rule.split(':');
    if (rulePort && rulePort !== port) continue;
    const cleanRule = ruleHostPart.replace(/^\.+/, '');
    if (!cleanRule) continue;
    if (hostname === cleanRule || hostname.endsWith(`.${cleanRule}`)) return true;
  }
  return false;
}

function osProxyCandidates() {
  const now = Date.now();
  const key = `${process.platform}:${process.arch}`;
  if (cachedOsProxies.key === key && now < cachedOsProxies.expiresAt) return cachedOsProxies.values;
  const values = [];
  if (process.platform === 'win32') {
    try {
      const script = String.raw`$p=Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop; if($p.ProxyEnable -eq 1){[Console]::Write("$($p.ProxyServer)|$($p.ProxyOverride)")}`;
      const { executable, env, cwd } = windowsPowerShell();
      const raw = execFileSync(executable, ['-NoProfile', '-NonInteractive', '-Command', script], { env, cwd, encoding: 'utf8', windowsHide: true, timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
      const [value = ''] = raw.split('|');
      const server = value.includes('=') ? value.match(/(?:^|;)https=([^;]+)/)?.[1] || value.match(/(?:^|;)http=([^;]+)/)?.[1] : value;
      const normalized = normalizeProxyCandidate(server);
      if (normalized) values.push(normalized);
    } catch { /* Direct and environment routes remain usable. */ }
  } else if (process.platform === 'darwin') {
    try {
      const output = execFileSync('/usr/sbin/scutil', ['--proxy'], { encoding: 'utf8', timeout: 3000, stdio: ['ignore', 'pipe', 'ignore'] });
      const pick = (enableKey, hostKey, portKey) => {
        if (!new RegExp(`\\b${enableKey}\\s*:\\s*1\\b`).test(output)) return null;
        const host = output.match(new RegExp(`\\b${hostKey}\\s*:\\s*(\\S+)`))?.[1];
        const port = output.match(new RegExp(`\\b${portKey}\\s*:\\s*(\\d+)`))?.[1];
        if (!host || !port) return null;
        const formattedHost = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
        return normalizeProxyCandidate(`http://${formattedHost}:${port}`);
      };
      const server = pick('HTTPSEnable', 'HTTPSProxy', 'HTTPSPort') || pick('HTTPEnable', 'HTTPProxy', 'HTTPPort');
      if (server) values.push(server);
    } catch { /* Direct and environment routes remain usable. */ }
  }
  cachedOsProxies = { key, expiresAt: now + 30000, values };
  return values;
}

export function proxyCandidates(targetOrigin) {
  if (bypassesNoProxy(targetOrigin)) return [null];
  const options = [null];
  for (const value of [process.env.HTTPS_PROXY, process.env.https_proxy, process.env.HTTP_PROXY, process.env.http_proxy]) {
    const normalized = normalizeProxyCandidate(value);
    if (normalized) options.push(normalized);
  }
  for (const candidate of osProxyCandidates()) options.push(candidate);
  return [...new Set(options)].sort((a, b) => Number(Boolean(b)) - Number(Boolean(a)));
}

class ConnectorReporter {
  constructor(stateDir, origin) {
    this.stateDir = stateDir;
    this.origin = origin;
    this.logQueue = Promise.resolve();
    this.statusQueue = Promise.resolve();
    this.lastOnline = null;
    this.lastStatusAt = 0;
  }

  record(event, fields = {}) {
    if (!this.stateDir) return Promise.resolve();
    const action = this.logQueue.then(async () => {
      try {
        const log = path.join(this.stateDir, 'connector.log');
        const info = await fs.stat(log).catch(() => null);
        if (info?.size > 1024 * 1024) {
          await fs.unlink(`${log}.1`).catch(() => {});
          await fs.rename(log, `${log}.1`).catch(() => {});
        }
        await fs.appendFile(log, JSON.stringify({ time: new Date().toISOString(), event, ...fields }) + '\n', { mode: 0o600 });
      } catch { /* Logging must not expose transport failures or interrupt tools. */ }
    });
    this.logQueue = action.catch(() => {});
    return action;
  }

  status(online, { force = false } = {}) {
    if (!this.stateDir) return Promise.resolve();
    const now = Date.now();
    if (!force && this.lastOnline === online && now - this.lastStatusAt < 60000) return Promise.resolve();
    this.lastOnline = online;
    this.lastStatusAt = now;
    const action = this.statusQueue.then(async () => {
      const target = path.join(this.stateDir, 'connector-status.json');
      const temp = path.join(this.stateDir, `.status-${process.pid}-${Math.random().toString(16).slice(2)}.tmp`);
      try {
        const payload = JSON.stringify({
          pid: process.pid, online, updatedAt: new Date().toISOString(), origin: this.origin,
        }, null, 2);
        const handle = await fs.open(temp, 'wx', 0o600);
        try { await handle.writeFile(payload, 'utf8'); await handle.sync(); } finally { await handle.close(); }
        await fs.rename(temp, target);
      } catch {
        await fs.rm(temp, { force: true }).catch(() => {});
      }
    });
    this.statusQueue = action.catch(() => {});
    return action;
  }

}

export class BridgeConnector extends ConnectorReporter {
  constructor({ origin, bridgeToken, runtime, stateDir, allowExec = true, workspaceRoots, externalMcpHub, auditFile, webuiPort = 18797, blockedOrigins = [], proxyProvider = proxyCandidates, socketFactory }) {
    const url = new URL(origin);
    if (!['https:', 'http:'].includes(url.protocol) || (url.protocol === 'http:' && !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname))) {
      throw new Error('The bridge requires HTTPS, except on loopback for tests');
    }
    if (url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('Expected an origin without a path or credentials');
    super(stateDir, url.origin);
    this.url = new URL('/bridge', url);
    this.url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
    this.token = bridgeToken;
    this.runtime = runtime;
    this.allowExec = allowExec !== false;
    this.workspaceRoots = workspaceRoots;
    const effectiveBlockedOrigins = [
      this.origin,
      ...(Number.isSafeInteger(webuiPort) && webuiPort > 0 && webuiPort <= 65535
        ? [`http://127.0.0.1:${webuiPort}`, `http://localhost:${webuiPort}`, `http://[::1]:${webuiPort}`]
        : []),
      ...(Array.isArray(blockedOrigins) ? blockedOrigins : []),
    ];
    this.externalMcpHub = externalMcpHub !== undefined
      ? externalMcpHub
      : (stateDir
          ? createExternalMcpHub({
              stateDir,
              workspaceRoots,
              auditFile: auditFile || path.join(stateDir, 'audit.jsonl'),
              blockedOrigins: effectiveBlockedOrigins,
            })
          : null);
    this.proxyProvider = proxyProvider;
    this.socketFactory = socketFactory || ((target, options) => new WebSocket(target, options));
    this.running = false;
    this.retries = 0;
    this.inflight = new Map();
    this.receipts = new RequestReceipts(stateDir);
    this.controlReceipts = new TransientReceipts();
    this.stopReceipts = new StopReceipts();
    this.approvals = new LocalApprovals(stateDir, this.origin);
  }

  async start() {
    if (this.running) return this.starting;
    this.running = true;
    this.starting = (async () => {
      try {
        await Promise.all([this.receipts.ready, this.approvals.ready]);
        if (this.running) this.connect();
      } catch (error) { this.running = false; throw error; }
    })();
    return this.starting;
  }

  connect() {
    if (!this.running) return;
    if ([WebSocket.OPEN, WebSocket.CONNECTING].includes(this.socket?.readyState)) return;
    let candidate = null;
    try {
      const routes = this.proxyProvider(this.origin);
      candidate = routes[this.retries % routes.length] || null;
      let agent;
      if (candidate) {
        try { agent = new HttpsProxyAgent(candidate); } catch { agent = undefined; candidate = null; }
      }
      const socket = this.socketFactory(this.url, {
        headers: { authorization: `Bearer ${this.token}` },
        agent,
        handshakeTimeout: 15000,
        maxPayload: 1200000,
        perMessageDeflate: false,
        followRedirects: false,
      });
      this.socket = socket;
      let lastPong = Date.now();
      let receivedPong = false;
      let beat;
      socket.on('open', () => {
        if (!this.running || this.socket !== socket) { socket.terminate(); return; }
        lastPong = Date.now();
        this.record('connected', { route: candidate ? 'proxy' : 'direct' });
        this.status(false, { force: true });
        try { socket.send('{"type":"ping"}'); } catch {}
        beat = setInterval(() => {
          if (Date.now() - lastPong > 65000) return socket.terminate();
          if (socket.readyState === WebSocket.OPEN) {
            try { socket.send(JSON.stringify({ type: 'ping' })); } catch {}
          }
          this.status(receivedPong && Date.now() - lastPong <= 65000);
        }, 20000);
      });
      socket.on('unexpected-response', (request, response) => {
        this.record('socket_unexpected_response', { status: Number(response?.statusCode) || 0 });
        try { response?.resume(); } catch {}
        try { request?.destroy(); } catch {}
        try { socket.terminate(); } catch {}
      });
      socket.on('message', async (data, isBinary) => {
        if (!this.running || this.socket !== socket) return;
        let message;
        try { if (isBinary) throw new Error(); message = JSON.parse(data.toString()); if (!message || Array.isArray(message) || typeof message !== 'object') throw new Error(); } catch { socket.close(1003, 'Invalid bridge frame'); return; }
        if (message.type === 'pong') { this.retries = 0; receivedPong = true; lastPong = Date.now(); this.status(true); return; }
        if (message.type === 'cancel' && typeof message.id === 'string') { this.inflight.get(message.id)?.controller.abort(); return; }
        if (message.type !== 'request') return;
        // Direct BridgeConnector clients use the legacy single-response protocol.
        const safeErrId = raw => (raw === null || (typeof raw === 'number' && Number.isFinite(raw)) || (typeof raw === 'string' && raw.length <= 256) ? raw : null);
        const send = body => {
          if (socket.readyState !== WebSocket.OPEN) return;
          let encoded = JSON.stringify({ type: 'response', id: message.id, body });
          if (Buffer.byteLength(encoded) > 2 * 1024 * 1024) encoded = JSON.stringify({ type: 'response', id: message.id, body: { jsonrpc: '2.0', id: safeErrId(message.body?.id), error: { code: -32603, message: 'Tool result exceeds the bridge limit; request a smaller range' } } });
          try { socket.send(encoded); } catch {}
        };
        const errorReply = (text, data) => send({ jsonrpc: '2.0', id: safeErrId(message.body?.id), error: { code: -32001, message: text, ...(data ? { data } : {}) } });
        let authorized;
        try {
          authorized = validateRequestEnvelope(message, Date.now(), {
            externalToolScopes: this.externalMcpHub?.getConfiguredToolScopes(),
          });
        }
        catch (error) { errorReply(error.message); return; }
        if (this.stateDir && authorized.body.method === 'tools/call') {
          const calledName = authorized.body.params?.name;
          if (isValidExternalToolName(calledName)) {
            const extCheck = this.externalMcpHub
              ? this.externalMcpHub.checkToolEnabled(calledName)
              : { enabled: false, capability: 'external_mcp', reason: 'External MCP support is unavailable.' };
            if (!extCheck.enabled) {
              this.record('capability_blocked', {
                tool: calledName,
                capability: extCheck.capability,
              });
              errorReply(extCheck.reason, { code: 'CAPABILITY_DISABLED', tool: calledName, capability: extCheck.capability });
              return;
            }
          } else {
            const livePolicy = readCapabilitiesSync(this.stateDir, {
              configAllowExec: this.allowExec,
              workspaceRoots: this.workspaceRoots,
            });
            const capabilityCheck = isToolEnabled(calledName, livePolicy, { configAllowExec: this.allowExec });
            if (!capabilityCheck.enabled) {
              this.record('capability_blocked', {
                tool: calledName,
                capability: capabilityCheck.capability,
              });
              errorReply(capabilityCheck.reason, { code: 'CAPABILITY_DISABLED', tool: calledName, capability: capabilityCheck.capability });
              return;
            }
          }
        }
        if (this.inflight.has(message.id)) { errorReply('Request ID is already being processed.'); return; }
        const stopping = authorized.body.method === 'tools/call' && authorized.body.params?.name === 'stop_command';
        const lane = [...this.inflight.values()].filter(active => active.stopping === stopping);
        if (lane.length >= (stopping ? 4 : 16) || (stopping && lane.filter(active => active.clientId === authorized.authorization.clientId).length >= 2)) {
          errorReply('Too many requests in this control lane.', { reason: 'inflight_capacity' }); return;
        }
        const controller = new AbortController();
        const deadline = setTimeout(() => controller.abort(), Math.max(1, message.deadline - Date.now()));
        this.inflight.set(message.id, { controller, socket, stopping, clientId: authorized.authorization.clientId });
        try {
          const persistent = requiresApproval(authorized.body);
          let prior;
          if (persistent) prior = await this.receipts.inspect(message);
          else {
            // Keep stop admission independent of ordinary control traffic. Cross-lane
            // ID conflicts are still rejected while their bounded receipt survives.
            const memReceipts = stopping ? this.stopReceipts : this.controlReceipts;
            prior = memReceipts.inspect(message);
            if (prior.acquired) prior = memReceipts.claim(message);
          }
          if (!prior.acquired) { errorReply('This request ID was already attempted or its control budget is exhausted.', { reason: prior.reason }); return; }
          controller.signal.throwIfAborted();
          const approval = await this.approvals.authorize(authorized.body, authorized.authorization, { signal: controller.signal });
          const approveCommand = process.platform === 'win32' ? 'Approve.cmd' : 'approve';
          if (!approval.approved) {
            this.record('approval_required', {
              tool: authorized.body.params.name,
              approvalIdShort: String(approval.id || '').slice(0, 8),
            });
            errorReply(`Local approval is required. Open the protected ${approveCommand} on your computer, review this request, then retry the same tool arguments.`, { code: 'LOCAL_APPROVAL_REQUIRED', approval_id: approval.id, expires_at: new Date(approval.expiresAt).toISOString(), tool: authorized.body.params.name });
            return;
          }
          controller.signal.throwIfAborted();
          if (persistent) {
            const claim = await this.receipts.claim(message);
            if (!claim.acquired) { errorReply('This request ID was already attempted; its result is not replayed.', { reason: claim.reason }); return; }
          }
          controller.signal.throwIfAborted();
          let body;
          if (authorized.body.method === 'tools/call' && isValidExternalToolName(authorized.body.params?.name) && this.externalMcpHub) {
            const extResult = await this.externalMcpHub.callTool(
              authorized.body.params.name,
              authorized.body.params?.arguments ?? {},
              { signal: controller.signal },
            );
            body = { jsonrpc: '2.0', id: authorized.body.id ?? null, result: extResult };
          } else {
            body = await this.runtime.handleRpc(authorized.body, { signal: controller.signal, authorization: authorized.authorization, requestId: message.id });
            if (authorized.body.method === 'tools/list' && this.externalMcpHub && Array.isArray(body?.result?.tools)) {
              const extTools = await this.externalMcpHub.listTools({ signal: controller.signal });
              if (extTools.length) {
                body = { ...body, result: { ...body.result, tools: [...body.result.tools, ...extTools] } };
              }
            }
          }
          send(body);
        } catch (error) {
          let reason = 'runtime_error';
          if (controller.signal.aborted) {
            reason = 'aborted';
            errorReply('Local request was cancelled or expired.');
          } else if (error instanceof ApprovalRecordTooLargeError) {
            reason = 'approval_record_too_large';
            errorReply('Request exceeds the local approval size limit. Reduce the request arguments or metadata.', { code: 'APPROVAL_RECORD_TOO_LARGE' });
          } else {
            if (/^[A-Z0-9_]{1,48}$/.test(error?.code || '')) reason = error.code;
            else if (error?.message?.includes('capacity') || error?.message?.includes('queue is full')) reason = 'local_capacity';
            errorReply('Local policy or tool failed; request was not retried.');
          }
          this.record('tool_runtime_error', { reason });
        } finally { clearTimeout(deadline); this.inflight.delete(message.id); }
      });
      socket.on('error', error => this.record('socket_error', { code: /^[A-Z0-9_]+$/.test(error.code || '') ? error.code : 'HANDSHAKE_OR_NETWORK' }));
      socket.on('close', (code) => {
        clearInterval(beat);
        for (const active of this.inflight.values()) if (active.socket === socket) active.controller.abort();
        if (this.socket !== socket) return;
        this.status(false, { force: true });
        this.record('disconnected', { code });
        this.schedule();
      });
    } catch (error) {
      this.record('connection_setup_failed', { code: /^[A-Z0-9_]{1,48}$/.test(error?.code || '') ? error.code : 'SETUP_ERROR' });
      this.schedule();
    }
  }

  schedule() {
    if (!this.running) return;
    clearTimeout(this.timer);
    this.retries += 1;
    const delay = Math.min(30000, 1000 * 2 ** Math.min(this.retries - 1, 5)) + Math.floor(Math.random() * 500);
    this.timer = setTimeout(() => this.connect(), delay);
  }

  async stop() {
    this.running = false;
    clearTimeout(this.timer);
    for (const active of this.inflight.values()) active.controller.abort();
    const socket = this.socket;
    if (socket && socket.readyState !== WebSocket.CLOSED) await new Promise(resolve => {
      const timer = setTimeout(() => { socket.terminate(); resolve(); }, 1500);
      socket.once('close', () => { clearTimeout(timer); resolve(); });
      if (socket.readyState === WebSocket.OPEN) socket.close(1000, 'Local connector stopped');
      else socket.terminate();
    });
    if (this.externalMcpHub) await this.externalMcpHub.close();
    await this.runtime.close();
    await this.status(false, { force: true });
    await this.logQueue;
    await this.statusQueue;
  }
}

async function main() {
  const stateDir = path.resolve(process.argv[2] || defaultStateDirectory());
  let reporter;
  let stopPoll;
  try {
    const config = JSON.parse(await fs.readFile(path.join(stateDir, 'config.json'), 'utf8'));
    reporter = new ConnectorReporter(stateDir, config.origin);
    if (config.sandbox?.enabled !== true || config.requireLocalApproval !== true) {
      throw new Error('Protected startup requires a Docker sandbox and local approval.');
    }
    const secrets = loadSecrets(stateDir, { fields: ['bridgeToken'] });
    delete process.env.AGENTDOCK_BRIDGE_TOKEN;
    const { startLoomWardDaemon } = await import('../packages/host/src/daemon.mjs');
    const port = Number.isSafeInteger(config.webuiPort) ? config.webuiPort : 18797;
    const daemon = await startLoomWardDaemon({
      requireFrozenRpm: true,
      origin: config.origin,
      stateDir,
      workspaceRoots: config.roots,
      sandboxConfig: { ...config, stateDir, auditFile: path.join(stateDir, 'audit.jsonl') },
      allowExec: config.allowExec === true,
      allowOutbound: config.sandbox.allowOutbound === true,
      relay: { origin: config.origin, bridgeToken: secrets.bridgeToken },
      mcpHubBlockedOrigins: ['localhost', '127.0.0.1', '[::1]'].map(host => `http://${host}:${port}`),
      enableLlmModeration: await fs.stat(path.join(stateDir, 'moderation', 'config.json')).then(
        () => true, error => { if (error.code !== 'ENOENT') throw error; return false; },
      ),
      record: (event, fields) => reporter.record(event, fields),
      status: (online, options) => reporter.status(online, options),
    });
    secrets.bridgeToken = undefined;
    let stopping = false;
    const shutdown = async (exitCode = 0) => {
      if (stopping) return;
      stopping = true;
      clearInterval(stopPoll);
      await daemon.stop();
      await reporter.status(false, { force: true });
      await Promise.all([reporter.logQueue, reporter.statusQueue]);
      process.exit(exitCode);
    };
    process.on('SIGINT', () => void shutdown(0));
    process.on('SIGTERM', () => void shutdown(0));
    process.on('uncaughtException', async () => { await reporter.record('uncaught_exception'); await shutdown(1); });
    process.on('unhandledRejection', async () => { await reporter.record('unhandled_rejection'); await shutdown(1); });
    // The local manager requests a clean stop without terminating unrelated processes.
    stopPoll = setInterval(async () => {
      if (await fs.access(path.join(stateDir, 'stop.request')).then(() => true, () => false)) {
        await shutdown(0);
      }
    }, 1000);
  } catch (error) {
    clearInterval(stopPoll);
    if (reporter) await reporter.record('startup_failed', { code: /^[A-Z0-9_]{1,48}$/.test(error?.code || '') ? error.code : 'STARTUP_ERROR' });
    else {
      try {
        await fs.appendFile(path.join(stateDir, 'connector.log'), JSON.stringify({
          time: new Date().toISOString(),
          event: 'startup_failed',
          code: /^[A-Z0-9_]{1,48}$/.test(error?.code || '') ? error.code : 'STARTUP_ERROR',
        }) + '\n', { mode: 0o600 });
      } catch {}
    }
    throw error;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename)) main().catch(() => {
  console.error('Connector startup failed. Check the local installation and protected configuration.');
  process.exitCode = 1;
});
