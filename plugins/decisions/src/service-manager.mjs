// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Out-of-process manager and strict loopback HTTP client for the Python+SQLite decision ledger service.
import crypto from 'node:crypto';
import http from 'node:http';
import path from 'node:path';
import { spawn } from 'node:child_process';

const SERVICE_ROOT = path.resolve(import.meta.dirname, '..', 'service');
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const VALID_TOPIC_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function formatLoopbackHostForUrl(host) {
  const trimmed = String(host || '').trim();
  const bare = trimmed.replace(/^\[|\]$/g, '');
  return bare.includes(':') ? `[${bare}]` : bare;
}

export function assertLoopbackHost(rawHost) {
  const bare = String(rawHost || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (bare !== '127.0.0.1' && bare !== 'localhost' && bare !== '::1') {
    throw new Error(`Decisions ledger endpoint must bind strictly to loopback (got ${rawHost}).`);
  }
  return bare;
}

function assertLoopbackUrl(rawUrl) {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== 'http:') {
    throw new Error('Decisions ledger client only permits loopback http:// endpoints.');
  }
  if (parsed.username || parsed.password || (parsed.pathname && parsed.pathname !== '/') || parsed.search || parsed.hash) {
    throw new Error('Decisions ledger baseUrl must be a bare loopback origin without credentials or path.');
  }
  assertLoopbackHost(parsed.hostname);
  return parsed.origin;
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

function normalizeTimeoutMs(raw, fallback = 10000) {
  const n = Number(raw);
  return Number.isFinite(n) ? Math.max(500, Math.trunc(n)) : fallback;
}

function httpJsonRequest(baseUrl, pathname, { method = 'GET', body, timeoutMs = 10000, signal, token = null, extraHeaders = null } = {}) {
  const origin = assertLoopbackUrl(baseUrl);
  if (typeof pathname !== 'string' || !pathname.startsWith('/') || pathname.startsWith('//')) {
    throw new Error('Invalid decisions loopback request path.');
  }
  const parsed = new URL(pathname, origin);
  if (parsed.origin !== origin) {
    throw new Error('Decisions loopback request path cannot escape service origin.');
  }
  const effectiveTimeout = normalizeTimeoutMs(timeoutMs, 10000);
  const payloadBuf = body !== undefined ? Buffer.from(JSON.stringify(body), 'utf8') : null;
  const headers = {
    Accept: 'application/json',
    ...(extraHeaders && typeof extraHeaders === 'object' ? extraHeaders : {}),
    ...(typeof token === 'string' && token ? { 'X-LoomWard-Service-Token': token } : {}),
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
    let timer = null;
    const done = (err, value) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
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
      timeout: effectiveTimeout,
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

    timer = setTimeout(() => {
      req.destroy();
      done(new Error(`Decisions service request timed out after ${effectiveTimeout}ms.`));
    }, effectiveTimeout);
    timer.unref?.();

    req.on('error', err => done(err));
    if (payloadBuf) req.write(payloadBuf);
    req.end();
  });
}

function terminateChildProcess(proc) {
  if (!proc || proc.exitCode !== null || proc.signalCode !== null) {
    return Promise.resolve();
  }
  return new Promise(resolve => {
    const timer = setTimeout(() => {
      try { proc.kill('SIGKILL'); } catch {}
      resolve();
    }, 2000);
    timer.unref?.();
    proc.once('exit', () => {
      clearTimeout(timer);
      resolve();
    });
    try {
      proc.kill('SIGTERM');
    } catch {
      clearTimeout(timer);
      resolve();
    }
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
  serviceToken = null,
} = {}) {
  const safeHost = assertLoopbackHost(host);
  const boundedTimeoutMs = normalizeTimeoutMs(timeoutMs, 10000);
  let activeBaseUrl = baseUrl ? assertLoopbackUrl(baseUrl) : null;
  let child = null;
  let starting = null;
  let closed = false;
  // Per-process write capability: managed ledger writes must go through LoomWard's approval pipeline.
  let activeToken = typeof serviceToken === 'string' && serviceToken ? serviceToken : null;

  async function ensureRunning({ signal } = {}) {
    if (closed) throw new Error('Decisions ledger plugin is closed.');
    if (signal?.aborted) throw new Error('Decisions service request cancelled.');
    if (activeBaseUrl && !spawnService) return activeBaseUrl;
    if (activeBaseUrl && child && child.exitCode === null && child.signalCode === null) return activeBaseUrl;
    if (!spawnService) {
      throw new Error('Decisions ledger service baseUrl is not configured.');
    }
    if (!configPath) {
      throw new Error('Decisions ledger spawnService requires an explicit configPath.');
    }

    if (!starting) {
      starting = (async () => {
        const parsedPort = Number(port);
        const targetPort = Number.isInteger(parsedPort) && parsedPort > 0 && parsedPort <= 65535 ? parsedPort : 0;
        if (closed) throw new Error('Decisions ledger plugin is closed.');
        const spawnToken = crypto.randomBytes(32).toString('base64url');
        const proc = spawn(
          pythonPath,
          ['-B', '-m', 'core.server', '--config', path.resolve(configPath), '--host', safeHost, '--port', String(targetPort), '--no-browser'],
          {
            cwd: SERVICE_ROOT,
            shell: false,
            windowsHide: true,
            env: { ...sanitizedServiceEnv(), LOOMWARD_DECISIONS_SERVICE_TOKEN: spawnToken },
            stdio: ['ignore', 'pipe', 'pipe'],
          },
        );
        child = proc;
        activeToken = spawnToken;
        let exited = false;
        let spawnErr = null;
        let readyPort = 0;
        let stdoutBuf = '';
        proc.on('error', err => {
          spawnErr = err;
          exited = true;
        });
        proc.once('exit', () => {
          exited = true;
          if (child === proc) {
            child = null;
            if (spawnService) {
              activeBaseUrl = null;
              activeToken = null;
            }
          }
        });
        proc.stdout?.on('data', chunk => {
          stdoutBuf += chunk.toString('utf8');
          if (stdoutBuf.length > 65536) stdoutBuf = stdoutBuf.slice(-16384);
          let nl;
          while ((nl = stdoutBuf.indexOf('\n')) >= 0) {
            const line = stdoutBuf.slice(0, nl).trim();
            stdoutBuf = stdoutBuf.slice(nl + 1);
            if (!readyPort && line.startsWith('LOOMWARD_READY ')) {
              try {
                const parsed = JSON.parse(line.slice('LOOMWARD_READY '.length));
                const bound = Number(parsed?.port);
                if (Number.isInteger(bound) && bound > 0 && bound <= 65535 && (targetPort === 0 || bound === targetPort)) {
                  readyPort = bound;
                }
              } catch {}
            }
          }
        });
        proc.stderr?.resume();

        const deadline = Date.now() + Math.max(3000, boundedTimeoutMs);
        while (Date.now() < deadline && !closed && !exited) {
          if (readyPort > 0) {
            const url = assertLoopbackUrl(`http://${formatLoopbackHostForUrl(safeHost)}:${readyPort}`);
            try {
              const challenge = crypto.randomBytes(16).toString('hex');
              const expectedProof = crypto.createHmac('sha256', spawnToken).update(`status:${challenge}`, 'utf8').digest('hex');
              const probe = await httpJsonRequest(url, '/api/status', {
                timeoutMs: 1000,
                extraHeaders: { 'X-LoomWard-Challenge': challenge },
              });
              const actualProof = typeof probe.data?.token_proof === 'string' ? probe.data.token_proof : '';
              const proofMatches =
                actualProof.length === expectedProof.length
                && crypto.timingSafeEqual(Buffer.from(actualProof, 'utf8'), Buffer.from(expectedProof, 'utf8'));
              if (probe.status === 200 && probe.data?.status === 'ok' && proofMatches) {
                if (closed) break;
                activeBaseUrl = url;
                return url;
              }
            } catch {}
          }
          await new Promise(r => setTimeout(r, 80));
        }
        if (child === proc) child = null;
        if (spawnService) activeToken = null;
        await terminateChildProcess(proc);
        throw new Error(spawnErr ? `Failed to spawn Decisions service (${spawnErr.code || 'spawn_error'}).` : 'Failed to start out-of-process Decisions SQLite service.');
      })().finally(() => {
        starting = null;
      });
      starting.catch(() => {});
    }

    if (!signal) return starting;
    return new Promise((resolve, reject) => {
      const onAbort = () => reject(new Error('Decisions service request cancelled.'));
      if (signal.aborted) {
        onAbort();
        return;
      }
      signal.addEventListener('abort', onAbort, { once: true });
      starting.then(
        val => {
          signal.removeEventListener('abort', onAbort);
          resolve(val);
        },
        err => {
          signal.removeEventListener('abort', onAbort);
          reject(err);
        },
      );
    });
  }

  async function requestJson(pathname, opts = {}) {
    const url = await ensureRunning({ signal: opts.signal });
    const method = String(opts.method || 'GET').toUpperCase();
    return httpJsonRequest(url, pathname, {
      timeoutMs: boundedTimeoutMs,
      ...opts,
      token: method === 'POST' ? activeToken : null,
    });
  }

  async function getStatus(opts = {}) {
    const res = await requestJson('/api/status', opts);
    if (res.status !== 200) throw new Error(`Decisions status HTTP ${res.status}`);
    return res.data;
  }

  async function listTopics(opts = {}) {
    const res = await requestJson('/api/topics', opts);
    if (res.status !== 200) throw new Error(`Decisions topics HTTP ${res.status}`);
    return res.data;
  }

  async function exportContext({ module: mod, topicId, pathKeyword } = {}, opts = {}) {
    if (topicId !== undefined && topicId !== null && topicId !== '') {
      if (typeof topicId !== 'string' || !VALID_TOPIC_ID_RE.test(topicId) || topicId === '.' || topicId === '..') {
        throw new Error('Invalid topic_id for exportContext.');
      }
    }
    const params = new URLSearchParams();
    if (mod) params.set('module', String(mod));
    if (topicId) params.set('topic_id', String(topicId));
    if (pathKeyword) params.set('path', String(pathKeyword));
    const qs = params.toString();
    const res = await requestJson(`/api/agent/context${qs ? `?${qs}` : ''}`, opts);
    if (res.status !== 200) throw new Error(`Decisions context HTTP ${res.status}`);
    return res.data;
  }

  async function checkConsistency(opts = {}) {
    const res = await requestJson('/api/recovery/check', opts);
    if (res.status !== 200) throw new Error(`Decisions consistency HTTP ${res.status}`);
    return res.data;
  }

  async function recordDecision({ action = 'create', topicId, payload = {}, expectedVersion, requestId } = {}, opts = {}) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      throw new Error('Decisions record payload must be a plain object.');
    }
    const body = {
      ...payload,
      ...(expectedVersion !== undefined ? { expected_version: expectedVersion } : {}),
      ...(requestId ? { request_id: requestId } : {}),
    };
    if (action === 'save') {
      if (typeof topicId !== 'string' || !VALID_TOPIC_ID_RE.test(topicId) || topicId === '.' || topicId === '..') {
        throw new Error('Valid topic_id is required when action="save".');
      }
      return requestJson(`/api/topic/${encodeURIComponent(topicId)}/save`, { method: 'POST', body, ...opts });
    }
    if (action === 'create') {
      if (topicId !== undefined && topicId !== null && topicId !== '') {
        if (typeof topicId !== 'string' || !VALID_TOPIC_ID_RE.test(topicId) || topicId === '.' || topicId === '..') {
          throw new Error('Invalid topic_id for action="create".');
        }
        if (body.id === undefined) body.id = topicId;
      }
      if (body.id !== undefined && body.id !== null && body.id !== '') {
        if (typeof body.id !== 'string' || !VALID_TOPIC_ID_RE.test(body.id) || body.id === '.' || body.id === '..') {
          throw new Error('Invalid payload.id for action="create".');
        }
      }
      return requestJson('/api/topic/create', { method: 'POST', body, ...opts });
    }
    throw new Error(`Unsupported decisions record action: ${String(action)}`);
  }

  async function close() {
    closed = true;
    const inflight = starting;
    if (inflight) {
      await inflight.catch(() => {});
    }
    const proc = child;
    child = null;
    activeBaseUrl = null;
    if (spawnService) activeToken = null;
    await terminateChildProcess(proc);
  }

  return Object.freeze({
    ensureRunning,
    getStatus,
    listTopics,
    exportContext,
    checkConsistency,
    recordDecision,
    getBaseUrl: () => (spawnService && (!child || child.exitCode !== null || child.signalCode !== null) ? null : activeBaseUrl),
    isClosed: () => closed,
    close,
  });
}
