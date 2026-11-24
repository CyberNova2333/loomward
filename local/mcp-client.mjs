// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import { execFile, spawn } from 'node:child_process';
import {
  MAX_CACHED_TOOLS_PER_SERVER,
  assertSafeMcpHttpUrl,
  assertSafeStdioCwd,
  formatExternalToolName,
  isBlockedIpAddress,
  isForbiddenEnvKey,
  mcpServersFilePath,
  normalizeCachedTool,
  parseExternalToolName,
  readMcpServersSync,
  redactSecretsFromText,
  sanitizeMetadataText,
  serverConfigFingerprint,
} from './mcp-registry.mjs';

const MCP_PROTOCOL_VERSION = '2025-11-25';
const PROTOCOL_VERSION_RE = /^\d{4}-\d{2}-\d{2}$/;
const SESSION_ID_RE = /^[\x21-\x7e]{1,256}$/;
const MAX_MCP_MESSAGE_BYTES = 2 * 1024 * 1024;
const MAX_AGGREGATE_TOOLS_BYTES = 1024 * 1024;
const MAX_STDERR_BYTES = 2048;
const IDLE_SESSION_TTL_MS = 5 * 60 * 1000;
const EXTERNAL_TOOL_SCOPES = ['computer:read', 'computer:write', 'computer:execute'];
const PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const SAFE_BASE_ENV_KEYS = new Set([
  'PATH',
  'HOME',
  'USERPROFILE',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'TERM',
  'TZ',
  'TMPDIR',
  'TEMP',
  'TMP',
  ...(process.platform === 'win32'
    ? ['SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'APPDATA', 'LOCALAPPDATA', 'HOMEDRIVE', 'HOMEPATH']
    : []),
]);

const RESERVED_HTTP_HEADERS = new Set([
  'host',
  'content-length',
  'transfer-encoding',
  'connection',
  'upgrade',
  'keep-alive',
  'proxy-connection',
  'te',
  'trailer',
  'content-type',
  'accept',
  'mcp-protocol-version',
  'mcp-session-id',
  'origin',
  'sec-fetch-site',
  'sec-fetch-mode',
  'sec-fetch-dest',
]);

function normalizeCallToolResult(raw) {
  if (!raw || typeof raw !== 'object') {
    return { content: [{ type: 'text', text: String(raw ?? '') }] };
  }
  const content = Array.isArray(raw.content)
    ? raw.content
        .filter(item => item && typeof item === 'object' && typeof item.type === 'string')
        .slice(0, 64)
    : [{ type: 'text', text: typeof raw === 'string' ? raw : JSON.stringify(raw) }];
  const out = {
    content,
    ...(raw.isError === true ? { isError: true } : {}),
    ...(raw.structuredContent !== undefined ? { structuredContent: raw.structuredContent } : {}),
  };
  if (Buffer.byteLength(JSON.stringify(out), 'utf8') > MAX_MCP_MESSAGE_BYTES - 16384) {
    return {
      content: [{ type: 'text', text: 'External MCP tool output exceeded the 2 MiB bridge payload limit.' }],
      isError: true,
    };
  }
  return out;
}

function buildSanitizedChildEnv(serverEnv) {
  const env = Object.create(null);
  for (const [key, val] of Object.entries(process.env)) {
    if (typeof val !== 'string') continue;
    const upper = key.toUpperCase();
    if (!SAFE_BASE_ENV_KEYS.has(upper) || isForbiddenEnvKey(key)) continue;
    env[key] = val;
  }
  for (const [k, v] of Object.entries(serverEnv || {})) {
    if (PROTO_KEYS.has(k) || isForbiddenEnvKey(k)) continue;
    if (process.platform === 'win32') {
      const upper = k.toUpperCase();
      for (const existingKey of Object.keys(env)) {
        if (existingKey.toUpperCase() === upper && existingKey !== k) delete env[existingKey];
      }
    }
    env[k] = String(v);
  }
  return { ...env };
}

function isMatchingRpcResponse(obj, expectedId) {
  return Boolean(
    obj &&
    typeof obj === 'object' &&
    !Array.isArray(obj) &&
    !Object.hasOwn(obj, 'method') &&
    obj.id === expectedId &&
    (Object.hasOwn(obj, 'result') || Object.hasOwn(obj, 'error')),
  );
}

function classifySafeErrorCategory(err) {
  if (err?.category) return err.category;
  const msg = String(err?.message || '');
  if (/timed out/i.test(msg)) return 'timeout';
  if (/cancelled|aborted/i.test(msg)) return 'cancelled';
  if (/blocked|reserved IP|cannot target|redirect/i.test(msg)) return 'blocked endpoint';
  if (/HTTP (\d{3})/.test(msg)) return `HTTP ${RegExp.$1}`;
  if (/exited/i.test(msg)) return 'process exited';
  if (/launch|ENOENT|EACCES/i.test(msg)) return 'launch error';
  if (/limit/i.test(msg)) return 'payload limit exceeded';
  return 'transport error';
}

function killPosixGroup(pid, sig) {
  if (process.platform === 'win32' || !Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(-pid, sig);
    return true;
  } catch {
    return false;
  }
}

function windowsTaskkillPath() {
  const sysRoot = process.env.SystemRoot || 'C:\\Windows';
  return path.join(sysRoot, 'System32', 'taskkill.exe');
}

function runWindowsTaskkill(pid) {
  return new Promise(resolve => {
    if (!Number.isInteger(pid) || pid <= 0) {
      resolve();
      return;
    }
    try {
      execFile(
        windowsTaskkillPath(),
        ['/T', '/F', '/PID', String(pid)],
        { windowsHide: true, timeout: 3000 },
        () => resolve(),
      );
    } catch {
      resolve();
    }
  });
}

function createStdioMcpSession(serverConfig, { stateDir } = {}) {
  let child = null;
  let childPid = null;
  let closed = false;
  let closePromise = null;
  let nextId = 1;
  let buffer = Buffer.alloc(0);
  let stderrText = '';
  let exitInfo = null;
  let exitGraceTimer = null;
  let tempCwd = null;
  const stderrDecoder = new StringDecoder('utf8');
  const pending = new Map();

  const cleanupTempCwd = () => {
    if (!tempCwd) return;
    const dir = tempCwd;
    tempCwd = null;
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
  };

  const rejectAll = reason => {
    for (const entry of pending.values()) {
      clearTimeout(entry.timer);
      entry.reject(reason);
    }
    pending.clear();
  };

  const safeWriteLine = (wire, onErr) => {
    if (closed || !child?.stdin?.writable) {
      onErr?.(new Error('External MCP stdio process is not running.'));
      return;
    }
    try {
      child.stdin.write(wire + '\n', err => {
        if (err) onErr?.(err);
      });
    } catch (err) {
      onErr?.(err);
    }
  };

  const handleMessage = msg => {
    if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return;
    if (Object.hasOwn(msg, 'method') && typeof msg.method === 'string') {
      // Server-initiated request: reply cleanly instead of colliding with pending client IDs.
      if (Object.hasOwn(msg, 'id') && msg.id !== null && msg.id !== undefined) {
        if (msg.method === 'ping') {
          safeWriteLine(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: {} }));
        } else {
          safeWriteLine(JSON.stringify({
            jsonrpc: '2.0',
            id: msg.id,
            error: { code: -32601, message: 'Method not supported by AgentDock MCP client.' },
          }));
        }
      }
      return;
    }
    if (!Object.hasOwn(msg, 'id') || msg.id === null || msg.id === undefined) return;
    if (!Object.hasOwn(msg, 'result') && !Object.hasOwn(msg, 'error')) return;
    const entry = pending.get(msg.id);
    if (!entry) return;
    pending.delete(msg.id);
    clearTimeout(entry.timer);
    if (msg.error) {
      const err = new Error(redactSecretsFromText(String(msg.error.message || `MCP server error (${msg.error.code ?? 'unknown'})`), serverConfig, 300));
      err.rpcCode = msg.error.code;
      entry.reject(err);
    } else {
      entry.resolve(msg.result);
    }
  };

  const compactBuffer = () => {
    if (buffer.length === 0) {
      buffer = Buffer.alloc(0);
    } else if (buffer.buffer.byteLength > 65536 && buffer.length < buffer.buffer.byteLength / 4) {
      buffer = Buffer.from(buffer);
    }
  };

  const parseStdoutBuffer = () => {
    while (buffer.length > 0) {
      if (closed && pending.size === 0) {
        buffer = Buffer.alloc(0);
        return;
      }
      if (buffer.length > MAX_MCP_MESSAGE_BYTES) {
        const err = new Error('External MCP stdio response exceeded 2 MiB limit.');
        err.category = 'payload limit exceeded';
        buffer = Buffer.alloc(0);
        rejectAll(err);
        void close();
        return;
      }
      // Support optional Content-Length LSP-style framing in addition to standard newline-delimited JSON.
      const headPreview = buffer.subarray(0, Math.min(32, buffer.length)).toString('ascii');
      if (/^Content-Length:\s*\d+/i.test(headPreview)) {
        const crlfIdx = buffer.indexOf('\r\n\r\n');
        const lfIdx = buffer.indexOf('\n\n');
        let sepIdx = -1;
        let sepLen = 0;
        if (crlfIdx !== -1 && (lfIdx === -1 || crlfIdx < lfIdx)) {
          sepIdx = crlfIdx;
          sepLen = 4;
        } else if (lfIdx !== -1) {
          sepIdx = lfIdx;
          sepLen = 2;
        }
        if (sepIdx === -1) return;
        const headerStr = buffer.subarray(0, sepIdx).toString('ascii');
        const lenMatch = headerStr.match(/Content-Length:\s*(\d+)/i);
        const contentLen = lenMatch ? Number(lenMatch[1]) : -1;
        if (!Number.isSafeInteger(contentLen) || contentLen < 0 || contentLen > MAX_MCP_MESSAGE_BYTES) {
          buffer = Buffer.alloc(0);
          rejectAll(new Error('Invalid Content-Length frame from external MCP server.'));
          void close();
          return;
        }
        const total = sepIdx + sepLen + contentLen;
        if (buffer.length < total) return;
        const bodyText = buffer.subarray(sepIdx + sepLen, total).toString('utf8');
        buffer = buffer.subarray(total);
        compactBuffer();
        try { handleMessage(JSON.parse(bodyText)); } catch {}
        continue;
      }

      const nlIdx = buffer.indexOf(0x0a);
      if (nlIdx === -1) return;
      const line = buffer.subarray(0, nlIdx).toString('utf8').trim();
      buffer = buffer.subarray(nlIdx + 1);
      compactBuffer();
      if (!line) continue;
      try {
        handleMessage(JSON.parse(line));
      } catch {
        // Ignore non-JSON diagnostic noise emitted to stdout.
      }
    }
  };

  let spawnCwd;
  if (serverConfig.cwd) {
    spawnCwd = assertSafeStdioCwd(serverConfig.cwd, stateDir);
    let st;
    try {
      st = fs.lstatSync(spawnCwd);
    } catch {
      throw new Error('Configured MCP server cwd does not exist.');
    }
    if (st.isSymbolicLink() || !st.isDirectory()) {
      throw new Error('Configured MCP server cwd must be an existing non-symlink directory.');
    }
  } else {
    tempCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'agentdock-mcp-'));
    if (process.platform !== 'win32') {
      try { fs.chmodSync(tempCwd, 0o700); } catch {}
    }
    spawnCwd = tempCwd;
  }

  try {
    child = spawn(serverConfig.command, serverConfig.args || [], {
      cwd: spawnCwd,
      env: buildSanitizedChildEnv(serverConfig.env),
      shell: false,
      detached: process.platform !== 'win32',
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    childPid = child.pid || null;
  } catch (err) {
    cleanupTempCwd();
    throw err;
  }

  child.stdin.on('error', () => {});
  child.stdout.on('error', () => {});
  child.stderr.on('error', () => {});

  child.stdout.on('data', chunk => {
    if (closed && pending.size === 0) return;
    if (buffer.length + chunk.length > MAX_MCP_MESSAGE_BYTES) {
      const err = new Error('External MCP stdio response exceeded 2 MiB limit.');
      err.category = 'payload limit exceeded';
      buffer = Buffer.alloc(0);
      rejectAll(err);
      void close();
      return;
    }
    buffer = buffer.length ? Buffer.concat([buffer, chunk]) : Buffer.from(chunk);
    parseStdoutBuffer();
  });

  child.stderr.on('data', chunk => {
    stderrText = (stderrText + stderrDecoder.write(chunk)).slice(-MAX_STDERR_BYTES);
  });

  const buildExitError = () => {
    const code = exitInfo?.code ?? 'null';
    const sig = exitInfo?.signal ?? 'none';
    const cleanFull = redactSecretsFromText(stderrText.trim(), serverConfig, MAX_STDERR_BYTES);
    const preview = cleanFull.slice(-240);
    const suffix = preview ? ` (${preview})` : '';
    const err = new Error(`External MCP stdio server exited (code=${code}, signal=${sig})${suffix}`);
    err.category = 'process exited';
    return err;
  };

  child.on('error', err => {
    closed = true;
    clearTimeout(exitGraceTimer);
    const outErr = new Error(`Failed to launch stdio MCP server: ${err.code || 'spawn error'}`);
    outErr.category = 'launch error';
    rejectAll(outErr);
    if (!closePromise) cleanupTempCwd();
  });

  child.on('exit', (code, signal) => {
    exitInfo = { code, signal };
    closed = true;
    exitGraceTimer = setTimeout(() => {
      if (pending.size > 0) rejectAll(buildExitError());
    }, 250);
    exitGraceTimer.unref?.();
  });

  child.on('close', () => {
    closed = true;
    clearTimeout(exitGraceTimer);
    stderrText = (stderrText + stderrDecoder.end()).slice(-MAX_STDERR_BYTES);
    if (pending.size > 0) rejectAll(buildExitError());
    if (!closePromise) {
      killPosixGroup(childPid, 'SIGKILL');
      cleanupTempCwd();
    }
  });

  function sendNotification(method, params = {}) {
    if (closed || !child?.stdin?.writable) return;
    const payload = JSON.stringify({ jsonrpc: '2.0', method, ...(Object.keys(params).length ? { params } : {}) });
    safeWriteLine(payload);
  }

  function request(method, params, { timeoutMs = serverConfig.timeoutMs || 30000, signal } = {}) {
    if (signal?.aborted) {
      const err = new Error('External MCP request cancelled.');
      err.category = 'cancelled';
      return Promise.reject(err);
    }
    if (closed || !child?.stdin?.writable) {
      const err = new Error('External MCP stdio process is not running.');
      err.category = 'process exited';
      return Promise.reject(err);
    }
    const id = nextId++;
    return new Promise((resolve, reject) => {
      let settled = false;
      const cleanup = () => {
        if (signal && onAbort) signal.removeEventListener('abort', onAbort);
      };
      const onAbort = () => {
        if (settled) return;
        settled = true;
        const entry = pending.get(id);
        if (entry) {
          pending.delete(id);
          clearTimeout(entry.timer);
        }
        sendNotification('notifications/cancelled', { requestId: id, reason: 'Request cancelled by AgentDock' });
        const err = new Error('External MCP request cancelled.');
        err.category = 'cancelled';
        reject(err);
      };
      if (signal) signal.addEventListener('abort', onAbort, { once: true });

      const timer = setTimeout(() => {
        if (settled || !pending.has(id)) return;
        settled = true;
        pending.delete(id);
        cleanup();
        sendNotification('notifications/cancelled', { requestId: id, reason: 'Timeout' });
        const err = new Error(`External MCP request "${method}" timed out after ${timeoutMs}ms.`);
        err.category = 'timeout';
        reject(err);
      }, Math.max(1, timeoutMs));

      pending.set(id, {
        timer,
        resolve: val => {
          if (settled) return;
          settled = true;
          cleanup();
          resolve(val);
        },
        reject: err => {
          if (settled) return;
          settled = true;
          cleanup();
          reject(err);
        },
      });

      const wire = JSON.stringify({ jsonrpc: '2.0', id, method, ...(params !== undefined ? { params } : {}) });
      safeWriteLine(wire, writeErr => {
        if (settled) return;
        const entry = pending.get(id);
        if (!entry) return;
        settled = true;
        pending.delete(id);
        clearTimeout(entry.timer);
        cleanup();
        const err = new Error(`Failed to write to stdio MCP server: ${writeErr?.code || 'write error'}`);
        err.category = 'transport error';
        reject(err);
      });
    });
  }

  async function close() {
    if (closePromise) return closePromise;
    closePromise = (async () => {
      closed = true;
      clearTimeout(exitGraceTimer);
      rejectAll(new Error('External MCP stdio session closed.'));
      const proc = child;
      child = null;
      if (proc) {
        try { proc.stdin?.end(); } catch {}
        if (process.platform === 'win32') {
          if (proc.exitCode === null && proc.signalCode === null) {
            await new Promise(resolve => {
              let done = false;
              const finish = () => {
                if (done) return;
                done = true;
                clearTimeout(t);
                resolve();
              };
              proc.once('close', finish);
              const t = setTimeout(finish, 200);
              t.unref?.();
            });
          }
          if (proc.exitCode === null && proc.signalCode === null) {
            await runWindowsTaskkill(childPid);
            try { if (proc.exitCode === null) proc.kill(); } catch {}
          }
        } else {
          if (proc.exitCode === null && proc.signalCode === null) {
            await new Promise(resolve => {
              let done = false;
              let killTimer = null;
              let finishTimer = null;
              const finish = () => {
                if (done) return;
                done = true;
                clearTimeout(killTimer);
                clearTimeout(finishTimer);
                resolve();
              };
              proc.once('close', finish);
              if (!killPosixGroup(childPid, 'SIGTERM')) {
                try { proc.kill('SIGTERM'); } catch {}
              }
              killTimer = setTimeout(() => {
                if (!killPosixGroup(childPid, 'SIGKILL')) {
                  try { proc.kill('SIGKILL'); } catch {}
                }
                finishTimer = setTimeout(finish, 300);
                finishTimer.unref?.();
              }, 1200);
              killTimer.unref?.();
            });
          }
          // Ensure any surviving grandchildren in the detached process group are terminated even if leader exited early.
          killPosixGroup(childPid, 'SIGKILL');
        }
      }
      cleanupTempCwd();
    })();
    return closePromise;
  }

  return {
    isClosed: () => closed,
    getStderrPreview: () => redactSecretsFromText(stderrText.trim(), serverConfig, MAX_STDERR_BYTES),
    request,
    sendNotification,
    close,
  };
}

function createSafeDnsLookup({ allowLoopback127, requireLoopbackOnly = false }) {
  return (hostname, options, callback) => {
    let opts = options;
    let cb = callback;
    if (typeof options === 'function') {
      cb = options;
      opts = {};
    } else if (typeof options === 'number') {
      opts = { family: options };
    } else if (!options || typeof options !== 'object') {
      opts = {};
    }
    const wantAll = opts.all === true;
    dns.lookup(hostname, { ...opts, all: true }, (err, addresses) => {
      if (err) {
        cb(err);
        return;
      }
      if (!Array.isArray(addresses) || !addresses.length) {
        cb(new Error('DNS resolution returned no addresses.'));
        return;
      }
      for (const addr of addresses) {
        if (requireLoopbackOnly) {
          const bare = String(addr.address || '').toLowerCase();
          if (bare !== '127.0.0.1' && bare !== '::1') {
            const blockedErr = new Error('Plaintext HTTP MCP server must resolve strictly to loopback (127.0.0.1 or ::1).');
            blockedErr.category = 'blocked endpoint';
            cb(blockedErr);
            return;
          }
        }
        if (isBlockedIpAddress(addr.address, { allowLoopback127 })) {
          const blockedErr = new Error('HTTP MCP server resolved to a blocked or reserved IP address.');
          blockedErr.category = 'blocked endpoint';
          cb(blockedErr);
          return;
        }
      }
      if (wantAll) {
        cb(null, addresses);
      } else {
        cb(null, addresses[0].address, addresses[0].family);
      }
    });
  };
}

function extractMatchingRpcFromSseBlock(block, expectedId) {
  const dataLines = [];
  for (const rawLine of block.split(/\r?\n/)) {
    if (rawLine.startsWith('data:')) {
      const rest = rawLine.slice(5);
      dataLines.push(rest.startsWith(' ') ? rest.slice(1) : rest);
    }
  }
  if (!dataLines.length) return null;
  const payload = dataLines.join('\n').trim();
  if (!payload || payload === '[DONE]') return null;
  try {
    const parsed = JSON.parse(payload);
    if (Array.isArray(parsed)) {
      return parsed.find(item => isMatchingRpcResponse(item, expectedId)) || null;
    }
    return isMatchingRpcResponse(parsed, expectedId) ? parsed : null;
  } catch {
    return null;
  }
}

function createHttpMcpSession(serverConfig, { blockedOrigins = [] } = {}) {
  const endpointUrl = assertSafeMcpHttpUrl(serverConfig.url, { blockedOrigins });
  const initParsed = new URL(endpointUrl);
  const mod = initParsed.protocol === 'https:' ? https : http;
  // Dedicated per-session agent prevents globalAgent keep-alive socket reuse from bypassing createSafeDnsLookup.
  const sessionAgent = new mod.Agent({ keepAlive: true, maxSockets: 4 });
  let closed = false;
  let expired = false;
  let closePromise = null;
  let nextId = 1;
  let sessionId = null;
  let negotiatedProtocol = MCP_PROTOCOL_VERSION;
  const activeRequests = new Set();

  const buildHeaders = ({ includeBodyHeaders = true, contentLength = 0 } = {}) => {
    const headers = Object.create(null);
    for (const [k, v] of Object.entries(serverConfig.headers || {})) {
      if (PROTO_KEYS.has(k) || RESERVED_HTTP_HEADERS.has(k.toLowerCase())) continue;
      headers[k] = String(v);
    }
    headers.accept = 'application/json, text/event-stream';
    headers['mcp-protocol-version'] = negotiatedProtocol;
    if (includeBodyHeaders) {
      headers['content-type'] = 'application/json';
      headers['content-length'] = String(contentLength);
    }
    if (sessionId) headers['mcp-session-id'] = sessionId;
    return { ...headers };
  };

  function sendSafeHttp({ method, bodyText = null, timeoutMs, signal, expectedId = null, expectResponse = true, useAgent = true }) {
    const safeStr = assertSafeMcpHttpUrl(endpointUrl, { blockedOrigins });
    const parsed = new URL(safeStr);
    const isHttps = parsed.protocol === 'https:';
    const bareHost = parsed.hostname.replace(/^\[|\]$/g, '');
    const hostClean = parsed.hostname.toLowerCase().replace(/\.+$/, '');
    const isLoopbackName = hostClean === '127.0.0.1' || hostClean === 'localhost' || hostClean === '[::1]';
    const allowLoopback127 = !isHttps && isLoopbackName;
    const reqMod = isHttps ? https : http;
    const bodyBuf = bodyText !== null ? Buffer.from(bodyText, 'utf8') : null;
    const reqHeaders = buildHeaders({
      includeBodyHeaders: bodyBuf !== null,
      contentLength: bodyBuf ? bodyBuf.length : 0,
    });
    const sentSessionId = Boolean(sessionId);

    return new Promise((resolve, reject) => {
      if (signal?.aborted) {
        const err = new Error('External MCP HTTP request cancelled.');
        err.category = 'cancelled';
        reject(err);
        return;
      }

      let settled = false;
      let activeRes = null;
      const done = (err, val) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (signal) signal.removeEventListener('abort', onAbort);
        activeRequests.delete(req);
        if (err) reject(err);
        else resolve(val);
      };

      const req = reqMod.request(
        {
          protocol: parsed.protocol,
          hostname: bareHost,
          port: parsed.port || (isHttps ? 443 : 80),
          path: parsed.pathname + parsed.search,
          method,
          headers: reqHeaders,
          agent: useAgent ? sessionAgent : false,
          lookup: createSafeDnsLookup({ allowLoopback127, requireLoopbackOnly: !isHttps }),
          ...(isHttps && net.isIP(bareHost) === 0 ? { servername: bareHost } : {}),
        },
        res => {
          activeRes = res;
          res.on('error', err => {
            if (!settled) done(err);
          });

          const status = res.statusCode || 0;
          if (status >= 300 && status < 400) {
            const err = new Error('External MCP HTTP redirects are not allowed.');
            err.category = 'blocked endpoint';
            done(err);
            res.destroy();
            return;
          }

          if (status === 404 && sentSessionId) {
            sessionId = null;
            expired = true;
          }

          const returnedSession = typeof res.headers['mcp-session-id'] === 'string'
            ? res.headers['mcp-session-id'].trim()
            : '';
          if (status >= 200 && status < 300 && returnedSession && SESSION_ID_RE.test(returnedSession)) {
            sessionId = returnedSession;
          }

          if (!expectResponse && (status === 202 || status === 204)) {
            res.resume();
            done(null, undefined);
            return;
          }

          const declared = res.headers['content-length'];
          if (typeof declared === 'string' && /^\d+$/.test(declared) && Number(declared) > MAX_MCP_MESSAGE_BYTES) {
            const err = new Error('External MCP HTTP response exceeded 2 MiB limit.');
            err.category = 'payload limit exceeded';
            done(err);
            res.destroy();
            return;
          }

          const ct = String(res.headers['content-type'] || '').toLowerCase();
          const isOk = status >= 200 && status < 300;
          const isSse = isOk && expectResponse && ct.includes('text/event-stream');

          if (isSse) {
            const decoder = new StringDecoder('utf8');
            let sseBuf = '';
            let bytes = 0;

            res.on('data', chunk => {
              if (settled) return;
              bytes += chunk.length;
              if (bytes > MAX_MCP_MESSAGE_BYTES) {
                const err = new Error('External MCP HTTP SSE response exceeded 2 MiB limit.');
                err.category = 'payload limit exceeded';
                done(err);
                res.destroy();
                return;
              }
              sseBuf += decoder.write(chunk);
              let match;
              while ((match = /\r?\n\r?\n/.exec(sseBuf)) !== null) {
                const block = sseBuf.slice(0, match.index);
                sseBuf = sseBuf.slice(match.index + match[0].length);
                const rpcMsg = extractMatchingRpcFromSseBlock(block, expectedId);
                if (rpcMsg) {
                  if (rpcMsg.error) {
                    const err = new Error(redactSecretsFromText(String(rpcMsg.error.message || `MCP server error (${rpcMsg.error.code ?? 'unknown'})`), serverConfig, 300));
                    err.rpcCode = rpcMsg.error.code;
                    done(err);
                  } else {
                    done(null, rpcMsg.result);
                  }
                  res.destroy();
                  return;
                }
              }
            });

            res.on('end', () => {
              if (settled) return;
              sseBuf += decoder.end();
              if (sseBuf.trim()) {
                const rpcMsg = extractMatchingRpcFromSseBlock(sseBuf, expectedId);
                if (rpcMsg) {
                  if (rpcMsg.error) {
                    const err = new Error(redactSecretsFromText(String(rpcMsg.error.message || `MCP server error (${rpcMsg.error.code ?? 'unknown'})`), serverConfig, 300));
                    err.rpcCode = rpcMsg.error.code;
                    done(err);
                  } else {
                    done(null, rpcMsg.result);
                  }
                  return;
                }
              }
              done(new Error('External MCP HTTP SSE stream ended without a matching JSON-RPC response.'));
            });
            return;
          }

          const chunks = [];
          let bytes = 0;
          res.on('data', chunk => {
            if (settled) return;
            bytes += chunk.length;
            if (bytes > MAX_MCP_MESSAGE_BYTES) {
              const err = new Error('External MCP HTTP response exceeded 2 MiB limit.');
              err.category = 'payload limit exceeded';
              done(err);
              res.destroy();
              return;
            }
            chunks.push(chunk);
          });
          res.on('end', () => {
            if (settled) return;
            const rawText = Buffer.concat(chunks).toString('utf8');
            if (!isOk) {
              const preview = redactSecretsFromText(rawText, serverConfig, 200);
              const err = new Error(`External MCP HTTP ${status}: ${preview || res.statusMessage || 'Request failed'}`);
              err.category = `HTTP ${status}`;
              done(err);
              return;
            }
            if (!expectResponse) {
              done(null, undefined);
              return;
            }
            if (!rawText.trim()) {
              done(new Error('External MCP HTTP server returned an empty response body.'));
              return;
            }
            let parsedBody;
            try {
              parsedBody = JSON.parse(rawText);
            } catch {
              done(new Error('External MCP HTTP server returned invalid JSON.'));
              return;
            }
            const rpcMsg = Array.isArray(parsedBody)
              ? parsedBody.find(item => isMatchingRpcResponse(item, expectedId)) || null
              : (isMatchingRpcResponse(parsedBody, expectedId) ? parsedBody : null);
            if (!rpcMsg) {
              done(new Error('External MCP HTTP server returned an unreadable or mismatched JSON-RPC payload.'));
              return;
            }
            if (rpcMsg.error) {
              const err = new Error(redactSecretsFromText(String(rpcMsg.error.message || `MCP server error (${rpcMsg.error.code ?? 'unknown'})`), serverConfig, 300));
              err.rpcCode = rpcMsg.error.code;
              done(err);
              return;
            }
            done(null, rpcMsg.result);
          });
        },
      );

      activeRequests.add(req);

      const onAbort = () => {
        const err = new Error('External MCP HTTP request cancelled.');
        err.category = 'cancelled';
        done(err);
        try { activeRes?.destroy(); } catch {}
        try { req.destroy(); } catch {}
      };
      if (signal) signal.addEventListener('abort', onAbort, { once: true });

      const timer = setTimeout(() => {
        const err = new Error(`External MCP HTTP request timed out after ${timeoutMs}ms.`);
        err.category = 'timeout';
        done(err);
        try { activeRes?.destroy(); } catch {}
        try { req.destroy(); } catch {}
      }, Math.max(1, timeoutMs));
      timer.unref?.();

      req.on('error', err => {
        if (!settled) done(err);
      });

      if (bodyBuf) req.write(bodyBuf);
      req.end();
    });
  }

  async function postJsonRpc(payload, { timeoutMs = serverConfig.timeoutMs || 30000, signal, expectResponse = true } = {}) {
    if (closed || expired) {
      const err = new Error('External MCP HTTP session is closed.');
      err.category = 'transport error';
      throw err;
    }
    return sendSafeHttp({
      method: 'POST',
      bodyText: JSON.stringify(payload),
      timeoutMs,
      signal,
      expectedId: payload.id,
      expectResponse,
    });
  }

  return {
    isClosed: () => closed || expired,
    getStderrPreview: () => '',
    setNegotiatedProtocol: proto => {
      if (typeof proto === 'string' && PROTOCOL_VERSION_RE.test(proto)) negotiatedProtocol = proto;
    },
    async request(method, params, opts = {}) {
      const id = nextId++;
      return postJsonRpc(
        { jsonrpc: '2.0', id, method, ...(params !== undefined ? { params } : {}) },
        { ...opts, expectResponse: true },
      );
    },
    async sendNotification(method, params = {}, opts = {}) {
      try {
        await postJsonRpc(
          { jsonrpc: '2.0', method, ...(Object.keys(params).length ? { params } : {}) },
          { ...opts, expectResponse: false },
        );
      } catch {
        // Best-effort notification.
      }
    },
    async close() {
      if (closePromise) return closePromise;
      closePromise = (async () => {
        closed = true;
        for (const req of [...activeRequests]) {
          try { req.destroy(); } catch {}
        }
        activeRequests.clear();
        const sidToDelete = sessionId;
        sessionId = null;
        if (sidToDelete) {
          sessionId = sidToDelete;
          try {
            await sendSafeHttp({
              method: 'DELETE',
              bodyText: null,
              timeoutMs: 2000,
              expectResponse: false,
              useAgent: false,
            }).catch(() => {});
          } catch {}
          sessionId = null;
        }
        try { sessionAgent.destroy(); } catch {}
      })();
      return closePromise;
    },
  };
}

async function initializeAndList(session, { timeoutMs = 30000, signal } = {}) {
  const deadline = Date.now() + Math.max(1000, timeoutMs);
  const remaining = () => {
    const left = deadline - Date.now();
    if (left <= 0) {
      const err = new Error(`External MCP initialization timed out after ${timeoutMs}ms.`);
      err.category = 'timeout';
      throw err;
    }
    return left;
  };

  const initResult = await session.request(
    'initialize',
    {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'agentdock-bridge', version: '2.0.0' },
    },
    { timeoutMs: remaining(), signal },
  );
  if (typeof session.setNegotiatedProtocol === 'function' && typeof initResult?.protocolVersion === 'string') {
    session.setNegotiatedProtocol(initResult.protocolVersion);
  }
  await session.sendNotification('notifications/initialized', {}, { timeoutMs: Math.min(remaining(), 5000), signal });

  const discovered = [];
  const seenNames = new Set();
  const seenCursors = new Set();
  let cursor;
  for (let page = 0; page < 8; page++) {
    const listRes = await session.request('tools/list', cursor ? { cursor } : {}, { timeoutMs: remaining(), signal });
    const batch = Array.isArray(listRes?.tools) ? listRes.tools : [];
    for (const rawTool of batch) {
      const clean = normalizeCachedTool(rawTool);
      if (!clean || seenNames.has(clean.name)) continue;
      seenNames.add(clean.name);
      discovered.push(clean);
      if (discovered.length >= MAX_CACHED_TOOLS_PER_SERVER) break;
    }
    if (discovered.length >= MAX_CACHED_TOOLS_PER_SERVER) break;
    const nextCursor = listRes?.nextCursor;
    if (typeof nextCursor !== 'string' || !nextCursor || seenCursors.has(nextCursor)) break;
    seenCursors.add(nextCursor);
    cursor = nextCursor;
  }

  const serverInfo = initResult?.serverInfo && typeof initResult.serverInfo === 'object'
    ? {
        name: typeof initResult.serverInfo.name === 'string'
          ? sanitizeMetadataText(initResult.serverInfo.name, 120) || 'MCP Server'
          : 'MCP Server',
        version: typeof initResult.serverInfo.version === 'string'
          ? sanitizeMetadataText(initResult.serverInfo.version, 64)
          : '',
      }
    : null;

  return {
    protocolVersion: typeof initResult?.protocolVersion === 'string' && PROTOCOL_VERSION_RE.test(initResult.protocolVersion)
      ? initResult.protocolVersion
      : MCP_PROTOCOL_VERSION,
    serverInfo,
    tools: discovered,
  };
}

export async function probeMcpServer(serverConfig, { stateDir, blockedOrigins = [], signal } = {}) {
  const startedAt = Date.now();
  let session;
  try {
    session = serverConfig.transport === 'stdio'
      ? createStdioMcpSession(serverConfig, { stateDir })
      : createHttpMcpSession(serverConfig, { blockedOrigins });
  } catch (err) {
    return {
      ok: false,
      latencyMs: Math.max(0, Date.now() - startedAt),
      error: redactSecretsFromText(err?.message || 'Failed to initialize external MCP server.', serverConfig),
    };
  }
  try {
    const info = await initializeAndList(session, { timeoutMs: serverConfig.timeoutMs || 30000, signal });
    return {
      ok: true,
      latencyMs: Math.max(0, Date.now() - startedAt),
      ...info,
    };
  } catch (err) {
    const stderrPreview = redactSecretsFromText(session.getStderrPreview?.() || '', serverConfig, 400);
    return {
      ok: false,
      latencyMs: Math.max(0, Date.now() - startedAt),
      error: redactSecretsFromText(err?.message || 'Failed to connect to external MCP server.', serverConfig),
      ...(stderrPreview ? { stderrPreview } : {}),
    };
  } finally {
    await session.close().catch(() => {});
  }
}

export function createExternalMcpHub({ stateDir, workspaceRoots, auditFile, blockedOrigins = [] } = {}) {
  const resolvedState = path.resolve(stateDir);
  const sessions = new Map(); // serverId -> { fingerprint, session, lastUsedAt, tools }
  const connecting = new Map(); // serverId -> { fingerprint, controller, waiters: Set<symbol>, promise }
  const liveToolsByServer = new Map(); // serverId -> Tool[]
  const lastProbeAtByServer = new Map(); // serverId -> string | null
  let cachedFileSig = '';
  let cachedRegistry = { exists: false, servers: [], error: null };
  let auditQueue = Promise.resolve();
  let closed = false;

  const appendAudit = entry => {
    if (!auditFile) return Promise.resolve();
    const record = JSON.stringify({ time: new Date().toISOString(), ...entry }) + '\n';
    auditQueue = auditQueue
      .then(async () => {
        const flags = fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT | (fs.constants.O_NOFOLLOW || 0);
        const handle = await fsp.open(auditFile, flags, 0o600);
        try {
          await handle.writeFile(record, 'utf8');
        } finally {
          await handle.close();
        }
      })
      .catch(() => {});
    return auditQueue;
  };

  function loadRegistry() {
    const filePath = mcpServersFilePath(resolvedState);
    let sig = 'missing';
    try {
      const st = fs.lstatSync(filePath, { bigint: true });
      sig = `${st.dev}:${st.ino}:${st.size}:${st.mtimeNs}:${st.ctimeNs}:${st.mode}:${st.uid}:${st.nlink}:${st.isSymbolicLink()}`;
    } catch (err) {
      sig = err?.code === 'ENOENT' ? 'missing' : `error:${err?.code || 'unknown'}`;
    }
    if (sig !== cachedFileSig) {
      cachedFileSig = sig;
      cachedRegistry = readMcpServersSync(resolvedState, { workspaceRoots, blockedOrigins });
      // Evict pooled sessions, abort stale in-flight handshakes, and clear live tool caches.
      const validFpById = new Map();
      if (!cachedRegistry.error) {
        for (const srv of cachedRegistry.servers) {
          if (!srv.enabled) continue;
          const fp = serverConfigFingerprint(srv);
          validFpById.set(srv.id, fp);
          const diskProbeAt = srv.lastProbeAt || null;
          if (lastProbeAtByServer.has(srv.id) && lastProbeAtByServer.get(srv.id) !== diskProbeAt) {
            liveToolsByServer.delete(srv.id);
          }
          lastProbeAtByServer.set(srv.id, diskProbeAt);
          const pooled = sessions.get(srv.id);
          if (pooled && pooled.fingerprint !== fp) {
            sessions.delete(srv.id);
            liveToolsByServer.delete(srv.id);
            void pooled.session.close().catch(() => {});
          }
          const inflight = connecting.get(srv.id);
          if (inflight && inflight.fingerprint !== fp) {
            inflight.controller.abort(new Error('External MCP server configuration changed.'));
            connecting.delete(srv.id);
          }
        }
      }
      for (const [id, pooled] of sessions.entries()) {
        if (!validFpById.has(id)) {
          sessions.delete(id);
          liveToolsByServer.delete(id);
          void pooled.session.close().catch(() => {});
        }
      }
      for (const [id, inflight] of connecting.entries()) {
        if (!validFpById.has(id)) {
          inflight.controller.abort(new Error('External MCP server disabled or removed.'));
          connecting.delete(id);
        }
      }
      for (const id of [...liveToolsByServer.keys()]) {
        if (!validFpById.has(id)) {
          liveToolsByServer.delete(id);
        }
      }
      for (const id of [...lastProbeAtByServer.keys()]) {
        if (!validFpById.has(id)) {
          lastProbeAtByServer.delete(id);
        }
      }
    }
    return cachedRegistry;
  }

  function awaitWithCallerSignal(record, signal) {
    if (signal?.aborted) {
      const err = new Error('External MCP request cancelled.');
      err.category = 'cancelled';
      return Promise.reject(err);
    }
    const token = Symbol('waiter');
    record.waiters.add(token);
    return new Promise((resolve, reject) => {
      let settled = false;
      const cleanup = () => {
        record.waiters.delete(token);
        if (signal && onAbort) signal.removeEventListener('abort', onAbort);
      };
      const onAbort = () => {
        if (settled) return;
        settled = true;
        cleanup();
        // Only cancel the shared handshake when NO other waiter still needs it.
        if (record.waiters.size === 0) {
          if (connecting.get(record.serverId) === record) {
            connecting.delete(record.serverId);
          }
          record.controller.abort(new Error('External MCP request cancelled.'));
        }
        const err = new Error('External MCP request cancelled.');
        err.category = 'cancelled';
        reject(err);
      };
      if (signal) signal.addEventListener('abort', onAbort, { once: true });

      record.promise.then(
        val => {
          if (settled) return;
          settled = true;
          cleanup();
          resolve(val);
        },
        err => {
          if (settled) return;
          settled = true;
          cleanup();
          reject(err);
        },
      );
    });
  }

  async function ensureSession(serverConfig, { signal } = {}) {
    if (closed) throw new Error('External MCP hub is closed.');
    if (signal?.aborted) {
      const err = new Error('External MCP request cancelled.');
      err.category = 'cancelled';
      throw err;
    }
    const fp = serverConfigFingerprint(serverConfig);
    const existing = sessions.get(serverConfig.id);
    if (existing && existing.fingerprint === fp && !existing.session.isClosed()) {
      existing.lastUsedAt = Date.now();
      return existing;
    }
    if (existing) {
      sessions.delete(serverConfig.id);
      liveToolsByServer.delete(serverConfig.id);
      void existing.session.close().catch(() => {});
    }

    let record = connecting.get(serverConfig.id);
    if (record && (record.fingerprint !== fp || record.controller.signal.aborted)) {
      record.controller.abort(new Error('External MCP server configuration superseded.'));
      connecting.delete(serverConfig.id);
      record = null;
    }

    if (!record) {
      const controller = new AbortController();
      const waiters = new Set();
      let selfRecord = null;
      const connectPromise = (async () => {
        const session = serverConfig.transport === 'stdio'
          ? createStdioMcpSession(serverConfig, { stateDir: resolvedState })
          : createHttpMcpSession(serverConfig, { blockedOrigins });
        try {
          const info = await initializeAndList(session, {
            timeoutMs: serverConfig.timeoutMs || 30000,
            signal: controller.signal,
          });
          const latestReg = loadRegistry();
          const latestSrv = !latestReg.error
            ? latestReg.servers.find(s => s.id === serverConfig.id && s.enabled)
            : null;
          if (closed || controller.signal.aborted || !latestSrv || serverConfigFingerprint(latestSrv) !== fp) {
            await session.close().catch(() => {});
            throw new Error('External MCP server configuration changed or was disabled during connection.');
          }
          const entry = { fingerprint: fp, session, lastUsedAt: Date.now(), tools: info.tools };
          sessions.set(serverConfig.id, entry);
          liveToolsByServer.set(serverConfig.id, info.tools);
          return entry;
        } catch (err) {
          await session.close().catch(() => {});
          throw err;
        } finally {
          if (connecting.get(serverConfig.id) === selfRecord) {
            connecting.delete(serverConfig.id);
          }
        }
      })();
      // Prevent unhandledRejection when all callers aborted before connectPromise settles.
      connectPromise.catch(() => {});
      selfRecord = { serverId: serverConfig.id, fingerprint: fp, controller, waiters, promise: connectPromise };
      connecting.set(serverConfig.id, selfRecord);
      record = selfRecord;
    }

    return awaitWithCallerSignal(record, signal);
  }

  function getServerTools(server) {
    return liveToolsByServer.get(server.id) || server.cachedTools || [];
  }

  function getConfiguredToolScopes() {
    const reg = loadRegistry();
    const map = new Map();
    if (reg.error) return map;
    for (const server of reg.servers) {
      for (const tool of getServerTools(server)) {
        map.set(formatExternalToolName(server.id, tool.name), [...EXTERNAL_TOOL_SCOPES]);
      }
    }
    return map;
  }

  function checkToolEnabled(fullToolName) {
    const parsed = parseExternalToolName(fullToolName);
    if (!parsed) {
      return { enabled: false, capability: 'external_mcp', reason: 'Invalid external MCP tool identifier.' };
    }
    const reg = loadRegistry();
    if (reg.error) {
      return { enabled: false, capability: `mcp:${parsed.serverId}`, reason: `External MCP registry is locked: ${reg.error}` };
    }
    const server = reg.servers.find(s => s.id === parsed.serverId);
    if (!server) {
      return { enabled: false, capability: `mcp:${parsed.serverId}`, reason: `External MCP server "${parsed.serverId}" is not configured.` };
    }
    if (!server.enabled) {
      return { enabled: false, capability: `mcp:${parsed.serverId}`, reason: `External MCP server "${server.name}" is disabled in local AgentDock settings.` };
    }
    if ((server.disabledTools || []).includes(parsed.toolName)) {
      return { enabled: false, capability: `mcp:${fullToolName}`, reason: `External MCP tool "${fullToolName}" is individually disabled in local AgentDock settings.` };
    }
    const tools = getServerTools(server);
    if (!tools.some(t => t.name === parsed.toolName)) {
      return { enabled: false, capability: `mcp:${fullToolName}`, reason: `Tool "${parsed.toolName}" is not registered on external MCP server "${server.name}".` };
    }
    return { enabled: true, server, rawToolName: parsed.toolName };
  }

  async function listTools() {
    const reg = loadRegistry();
    if (reg.error || !reg.servers.length) return [];
    const results = [];
    let aggregateBytes = 0;
    for (const server of reg.servers) {
      if (!server.enabled) continue;
      const serverTools = getServerTools(server);
      const disabledSet = new Set(server.disabledTools || []);
      for (const tool of serverTools) {
        if (disabledSet.has(tool.name)) continue;
        const item = {
          name: formatExternalToolName(server.id, tool.name),
          description: `[MCP: ${server.name}] ${tool.description || tool.name}`.trim(),
          inputSchema: tool.inputSchema || { type: 'object', properties: {}, required: [] },
          annotations: {
            readOnlyHint: false,
            destructiveHint: true,
            idempotentHint: false,
            openWorldHint: true,
          },
        };
        const itemBytes = Buffer.byteLength(JSON.stringify(item), 'utf8');
        if (aggregateBytes + itemBytes > MAX_AGGREGATE_TOOLS_BYTES) break;
        aggregateBytes += itemBytes;
        results.push(item);
      }
      if (aggregateBytes >= MAX_AGGREGATE_TOOLS_BYTES) break;
    }
    return results;
  }

  async function callTool(fullToolName, args = {}, { signal } = {}) {
    const startedAt = Date.now();
    if (args !== undefined && (typeof args !== 'object' || args === null || Array.isArray(args))) {
      return { content: [{ type: 'text', text: 'External MCP tool arguments must be a JSON object.' }], isError: true };
    }
    const check = checkToolEnabled(fullToolName);
    if (!check.enabled) {
      await appendAudit({
        tool: fullToolName,
        external: true,
        success: false,
        reason: 'policy',
        durationMs: Math.max(0, Date.now() - startedAt),
      });
      return { content: [{ type: 'text', text: check.reason }], isError: true };
    }
    const { server, rawToolName } = check;
    let entry;
    try {
      entry = await ensureSession(server, { signal });
    } catch (err) {
      await appendAudit({
        tool: fullToolName,
        external: true,
        serverId: server.id,
        success: false,
        reason: signal?.aborted ? 'aborted' : 'mcp_connect_error',
        durationMs: Math.max(0, Date.now() - startedAt),
      });
      if (signal?.aborted) throw err;
      const category = classifySafeErrorCategory(err);
      return {
        content: [{
          type: 'text',
          text: `Failed to connect to external MCP server "${server.name}" (${category}). Check local WebUI for diagnostics.`,
        }],
        isError: true,
      };
    }

    const postCheck = checkToolEnabled(fullToolName);
    if (!postCheck.enabled) {
      await appendAudit({
        tool: fullToolName,
        external: true,
        serverId: server.id,
        success: false,
        reason: 'policy',
        durationMs: Math.max(0, Date.now() - startedAt),
      });
      return { content: [{ type: 'text', text: postCheck.reason }], isError: true };
    }

    try {
      // Never auto-retry tools/call after transmission because remote/local side effects may have occurred.
      const rawOut = await entry.session.request(
        'tools/call',
        { name: rawToolName, arguments: args ?? {} },
        { timeoutMs: server.timeoutMs || 30000, signal },
      );
      entry.lastUsedAt = Date.now();
      const normalized = normalizeCallToolResult(rawOut);
      const outputBytes = Buffer.byteLength(JSON.stringify(normalized), 'utf8');
      await appendAudit({
        tool: fullToolName,
        external: true,
        serverId: server.id,
        success: normalized.isError !== true,
        reason: normalized.isError === true ? 'tool_error' : 'ok',
        durationMs: Math.max(0, Date.now() - startedAt),
        outputBytes,
      });
      return normalized;
    } catch (err) {
      if (entry.session.isClosed() && sessions.get(server.id) === entry) {
        sessions.delete(server.id);
        liveToolsByServer.delete(server.id);
        void entry.session.close().catch(() => {});
      }
      await appendAudit({
        tool: fullToolName,
        external: true,
        serverId: server.id,
        success: false,
        reason: signal?.aborted ? 'aborted' : 'mcp_call_error',
        durationMs: Math.max(0, Date.now() - startedAt),
      });
      if (signal?.aborted) throw err;
      const safeMessage = err?.rpcCode !== undefined
        ? `External MCP tool "${fullToolName}" error (${err.rpcCode}): ${redactSecretsFromText(err.message, server, 300)}`
        : `External MCP tool "${fullToolName}" failed (${classifySafeErrorCategory(err)}). Check local WebUI for diagnostics.`;
      return { content: [{ type: 'text', text: safeMessage }], isError: true };
    }
  }

  const idleTimer = setInterval(() => {
    const now = Date.now();
    for (const [id, entry] of sessions.entries()) {
      if (entry.session.isClosed() || now - entry.lastUsedAt > IDLE_SESSION_TTL_MS) {
        sessions.delete(id);
        liveToolsByServer.delete(id);
        void entry.session.close().catch(() => {});
      }
    }
  }, 60000);
  idleTimer.unref?.();

  async function close() {
    closed = true;
    clearInterval(idleTimer);
    const inflightRecords = [...connecting.values()];
    connecting.clear();
    for (const rec of inflightRecords) {
      rec.controller.abort(new Error('External MCP hub closed.'));
    }
    const active = [...sessions.values()];
    sessions.clear();
    liveToolsByServer.clear();
    await Promise.allSettled([
      ...inflightRecords.map(rec => rec.promise),
      ...active.map(entry => entry.session.close()),
    ]);
    await auditQueue;
  }

  return {
    getConfiguredToolScopes,
    checkToolEnabled,
    listTools,
    callTool,
    close,
  };
}
