// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Out-of-process manager and strict loopback HTTP client for the Python+SQLite decision ledger service.
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import { spawn } from 'node:child_process';

const SERVICE_ROOT = path.resolve(import.meta.dirname, '..', 'service');
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

function assertLoopbackUrl(rawUrl) {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== 'http:') {
    throw new Error('Decisions ledger client only permits loopback http:// endpoints.');
  }
  const host = parsed.hostname.toLowerCase();
  if (host !== '127.0.0.1' && host !== 'localhost' && host !== '[::1]' && host !== '::1') {
    throw new Error(`Decisions ledger endpoint must bind strictly to loopback (got ${host}).`);
  }
  return parsed.origin;
}

function findFreeLoopbackPort(host = '127.0.0.1') {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, host, () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      srv.close(err => (err ? reject(err) : resolve(port)));
    });
  });
}

function sanitizedServiceEnv() {
  const env = {
    PYTHONUTF8: '1',
    PYTHONIOENCODING: 'utf-8',
    PYTHONDONTWRITEBYTECODE: '1',
  };
  for (const key of ['PATH', 'LANG', 'LC_ALL', 'LC_CTYPE', 'HOME', 'USERPROFILE', 'TMPDIR', 'TEMP', 'TMP', 'SystemRoot', 'WINDIR']) {
    if (typeof process.env[key] === 'string') env[key] = process.env[key];
  }
  return env;
}

function httpJsonRequest(baseUrl, pathname, { method = 'GET', body, timeoutMs = 10000, signal } = {}) {
  const origin = assertLoopbackUrl(baseUrl);
  const parsed = new URL(pathname, origin);
  const payloadBuf = body !== undefined ? Buffer.from(JSON.stringify(body), 'utf8') : null;
  const headers = {
    Accept: 'application/json',
    ...(payloadBuf !== null
      ? { 'Content-Type': 'application/json', 'Content-Length': String(payloadBuf.length) }
      : {}),
  };

  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error('Decisions service request cancelled.'));
      return;
    }
    let settled = false;
    const done = (err, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', onAbort);
      if (err) reject(err);
      else resolve(value);
    };

    const req = http.request({
      hostname: parsed.hostname.replace(/^\[|\]$/g, ''),
      port: parsed.port || 80,
      path: parsed.pathname + parsed.search,
      method,
      headers,
      timeout: timeoutMs,
    }, res => {
      const chunks = [];
      let bytes = 0;
      res.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > MAX_RESPONSE_BYTES) {
          req.destroy();
          done(new Error('Decisions service response exceeded 2 MiB limit.'));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = text ? JSON.parse(text) : {}; } catch {}
        done(null, { status: res.statusCode || 0, data: json, rawText: text });
      });
      res.on('error', err => done(err));
    });

    const onAbort = () => {
      req.destroy();
      done(new Error('Decisions service request cancelled.'));
    };
    if (signal) signal.addEventListener('abort', onAbort, { once: true });

    const timer = setTimeout(() => {
      req.destroy();
      done(new Error(`Decisions service request timed out after ${timeoutMs}ms.`));
    }, Math.max(500, timeoutMs));
    timer.unref?.();

    req.on('error', err => done(err));
    if (payloadBuf) req.write(payloadBuf);
    req.end();
  });
}

export function createDecisionsServiceClient({
  baseUrl = null,
  pythonPath = process.platform === 'win32' ? 'python' : 'python3',
  configPath = null,
  host = '127.0.0.1',
  port = 0,
  spawnService = false,
  timeoutMs = 10000,
} = {}) {
  let activeBaseUrl = baseUrl ? assertLoopbackUrl(baseUrl) : null;
  let child = null;
  let starting = null;
  let closed = false;

  async function ensureRunning({ signal } = {}) {
    if (closed) throw new Error('Decisions ledger plugin is closed.');
    if (activeBaseUrl && !spawnService) return activeBaseUrl;
    if (activeBaseUrl && child && child.exitCode === null) return activeBaseUrl;
    if (!spawnService) {
      throw new Error('Decisions ledger service baseUrl is not configured.');
    }
    if (!configPath) {
      throw new Error('Decisions ledger spawnService requires an explicit configPath.');
    }
    if (starting) return starting;

    starting = (async () => {
      const targetPort = port > 0 ? port : await findFreeLoopbackPort(host);
      const url = assertLoopbackUrl(`http://${host}:${targetPort}`);
      const proc = spawn(
        pythonPath,
        ['-B', '-m', 'core.server', '--config', path.resolve(configPath), '--host', host, '--port', String(targetPort), '--no-browser'],
        {
          cwd: SERVICE_ROOT,
          shell: false,
          windowsHide: true,
          env: sanitizedServiceEnv(),
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      );
      child = proc;
      let exited = false;
      proc.once('exit', () => { exited = true; });
      proc.stdout?.resume();
      proc.stderr?.resume();

      const deadline = Date.now() + Math.max(3000, timeoutMs);
      while (Date.now() < deadline && !closed && !exited) {
        if (signal?.aborted) break;
        try {
          const probe = await httpJsonRequest(url, '/api/status', { timeoutMs: 1000 });
          if (probe.status === 200 && probe.data?.status === 'ok') {
            activeBaseUrl = url;
            return url;
          }
        } catch {}
        await new Promise(r => setTimeout(r, 120));
      }
      try { proc.kill('SIGTERM'); } catch {}
      throw new Error('Failed to start out-of-process Decisions SQLite service.');
    })().finally(() => {
      starting = null;
    });
    return starting;
  }

  async function requestJson(pathname, opts = {}) {
    const url = await ensureRunning({ signal: opts.signal });
    return httpJsonRequest(url, pathname, { timeoutMs, ...opts });
  }

  async function getStatus(opts = {}) {
    const res = await requestJson('/api/status', opts);
    if (res.status !== 200) throw new Error(res.data?.message || `Decisions status HTTP ${res.status}`);
    return res.data;
  }

  async function listTopics(opts = {}) {
    const res = await requestJson('/api/topics', opts);
    if (res.status !== 200) throw new Error(res.data?.message || `Decisions topics HTTP ${res.status}`);
    return res.data;
  }

  async function exportContext({ module: mod, topicId, pathKeyword } = {}, opts = {}) {
    const params = new URLSearchParams();
    if (mod) params.set('module', String(mod));
    if (topicId) params.set('topic_id', String(topicId));
    if (pathKeyword) params.set('path', String(pathKeyword));
    const qs = params.toString();
    const res = await requestJson(`/api/agent/context${qs ? `?${qs}` : ''}`, opts);
    if (res.status !== 200) throw new Error(res.data?.message || `Decisions context HTTP ${res.status}`);
    return res.data;
  }

  async function checkConsistency(opts = {}) {
    const res = await requestJson('/api/recovery/check', opts);
    if (res.status !== 200) throw new Error(res.data?.message || `Decisions consistency HTTP ${res.status}`);
    return res.data;
  }

  async function recordDecision({ action = 'create', topicId, payload = {}, expectedVersion, requestId } = {}, opts = {}) {
    const body = {
      ...payload,
      ...(expectedVersion !== undefined ? { expected_version: expectedVersion } : {}),
      ...(requestId ? { request_id: requestId } : {}),
    };
    if (action === 'save') {
      if (typeof topicId !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(topicId)) {
        throw new Error('Valid topic_id is required when action="save".');
      }
      const res = await requestJson(`/api/topic/${encodeURIComponent(topicId)}/save`, { method: 'POST', body, ...opts });
      return res;
    }
    if (action === 'create') {
      const res = await requestJson('/api/topic/create', { method: 'POST', body, ...opts });
      return res;
    }
    throw new Error(`Unsupported decisions record action: ${String(action)}`);
  }

  async function close() {
    closed = true;
    const proc = child;
    child = null;
    if (proc && proc.exitCode === null && proc.signalCode === null) {
      await new Promise(resolve => {
        const timer = setTimeout(() => {
          try { proc.kill('SIGKILL'); } catch {}
          resolve();
        }, 2000);
        timer.unref?.();
        proc.once('exit', () => { clearTimeout(timer); resolve(); });
        try { proc.kill('SIGTERM'); } catch { clearTimeout(timer); resolve(); }
      });
    }
  }

  return Object.freeze({
    ensureRunning,
    getStatus,
    listTopics,
    exportContext,
    checkConsistency,
    recordDecision,
    getBaseUrl: () => activeBaseUrl,
    isClosed: () => closed,
    close,
  });
}
