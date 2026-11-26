// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Out-of-process manager and strict loopback HTTP client for the Python multimodal LLM moderation engine.
import crypto from 'node:crypto';
import http from 'node:http';
import path from 'node:path';
import { spawn } from 'node:child_process';
import {
  CONTENT_INSPECT_V2_PROTOCOL_VERSION,
  validateContentInspectVerdict,
} from '@loomward/shared';

const PLUGIN_ROOT = path.resolve(import.meta.dirname, '..');
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

const PROVIDER_SECRET_KEYS = Object.freeze({
  'openai-compat': Object.freeze(['OPENAI_API_KEY']),
  webhook: Object.freeze(['WEBHOOK_API_KEY', 'OPENAI_API_KEY']),
  'aliyun-green': Object.freeze(['ALIYUN_ACCESS_KEY_ID', 'ALIYUN_ACCESS_KEY_SECRET']),
  'tencent-tms': Object.freeze(['TENCENT_SECRET_ID', 'TENCENT_SECRET_KEY']),
  'baidu-aip': Object.freeze(['BAIDU_API_KEY', 'BAIDU_SECRET_KEY']),
});

function formatLoopbackHostForUrl(host) {
  const bare = String(host || '').trim().replace(/^\[|\]$/g, '');
  return bare.includes(':') ? `[${bare}]` : bare;
}

export function assertLoopbackHost(rawHost) {
  const bare = String(rawHost || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (bare !== '127.0.0.1' && bare !== 'localhost' && bare !== '::1') {
    throw new Error(`LLM moderation engine endpoint must bind strictly to loopback (got ${rawHost}).`);
  }
  return bare;
}

function assertLoopbackUrl(rawUrl) {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== 'http:') {
    throw new Error('LLM moderation engine client only permits loopback http:// endpoints.');
  }
  if (parsed.username || parsed.password || (parsed.pathname && parsed.pathname !== '/') || parsed.search || parsed.hash) {
    throw new Error('LLM moderation engine baseUrl must be a bare loopback origin without credentials or path.');
  }
  assertLoopbackHost(parsed.hostname);
  return parsed.origin;
}

function sanitizedEngineEnv() {
  const env = {
    PYTHONUTF8: '1',
    PYTHONIOENCODING: 'utf-8',
    PYTHONDONTWRITEBYTECODE: '1',
  };
  for (const key of ['PATH', 'LANG', 'LC_ALL', 'LC_CTYPE', 'HOME', 'USERPROFILE', 'TMPDIR', 'TEMP', 'TMP', 'SystemRoot', 'WINDIR', 'SSL_CERT_FILE', 'SSL_CERT_DIR']) {
    if (typeof process.env[key] === 'string') env[key] = process.env[key];
  }
  return env;
}

function normalizeTimeoutMs(raw, fallback = 15000) {
  const n = Number(raw);
  return Number.isFinite(n) ? Math.max(500, Math.trunc(n)) : fallback;
}

function httpJsonRequest(baseUrl, pathname, { method = 'GET', body, timeoutMs = 15000, signal, token = null, extraHeaders = null } = {}) {
  const origin = assertLoopbackUrl(baseUrl);
  if (typeof pathname !== 'string' || !pathname.startsWith('/') || pathname.startsWith('//')) {
    throw new Error('Invalid moderation engine loopback path.');
  }
  const parsed = new URL(pathname, origin);
  if (parsed.origin !== origin) {
    throw new Error('Moderation engine request path cannot escape service origin.');
  }
  const effectiveTimeout = normalizeTimeoutMs(timeoutMs, 15000);
  const payloadBuf = body !== undefined ? Buffer.from(JSON.stringify(body), 'utf8') : null;
  const headers = {
    Accept: 'application/json',
    ...(extraHeaders && typeof extraHeaders === 'object' ? extraHeaders : {}),
    ...(typeof token === 'string' && token ? { 'X-LoomWard-Service-Token': token } : {}),
    ...(payloadBuf !== null ? { 'Content-Type': 'application/json', 'Content-Length': String(payloadBuf.length) } : {}),
  };

  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error('LLM moderation request cancelled.'));
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
          done(new Error('LLM moderation engine response exceeded 2 MiB limit.'));
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
      done(new Error('LLM moderation request cancelled.'));
    };
    if (signal) signal.addEventListener('abort', onAbort, { once: true });

    timer = setTimeout(() => {
      req.destroy();
      done(new Error(`LLM moderation engine timed out after ${effectiveTimeout}ms.`));
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

function resolveScopedAuthCredentials(secretsFacade, config) {
  if (!secretsFacade || typeof secretsFacade.hasSecret !== 'function' || typeof secretsFacade.getSecret !== 'function') {
    return {};
  }
  const auth = {};
  const maybeRead = key => {
    try {
      if (secretsFacade.hasSecret(key)) {
        const val = secretsFacade.getSecret(key);
        if (typeof val === 'string' && val.length > 0) auth[key] = val;
      }
    } catch {}
  };
  maybeRead('LOCAL_GUARD_API_KEY');
  maybeRead('CANARY_API_KEY');
  if (config?.cloudOptIn === true) {
    const providerKeys = PROVIDER_SECRET_KEYS[config.cloudProvider] || [];
    for (const key of providerKeys) {
      maybeRead(key);
    }
  }
  return auth;
}

export function buildFailClosedModerationVerdict(stage, reason, { ruleId = 'MODERATION-ENGINE-ERROR', requestId = '', decision = null } = {}) {
  const resolvedDecision = decision || (stage === 'input' || stage === 'stream_start' ? 'block' : 'block');
  return validateContentInspectVerdict({
    protocolVersion: CONTENT_INSPECT_V2_PROTOCOL_VERSION,
    decision: resolvedDecision,
    categories: ['moderation.fail_closed'],
    ruleId,
    failClosed: true,
    reason,
    ...(requestId ? { requestId } : {}),
  }, { stage });
}

export function createModerationEngineClient({
  baseUrl = null,
  pythonPath = process.platform === 'win32' ? 'python' : 'python3',
  host = '127.0.0.1',
  port = 0,
  spawnService = !baseUrl,
  timeoutMs = 15000,
  serviceToken = null,
  secretsFacade = null,
  workspaceRoots = [],
  inspectTransport = null,
} = {}) {
  const safeHost = assertLoopbackHost(host);
  const boundedTimeoutMs = normalizeTimeoutMs(timeoutMs, 15000);
  let activeBaseUrl = baseUrl ? assertLoopbackUrl(baseUrl) : null;
  let child = null;
  let starting = null;
  let closed = false;
  let activeToken = typeof serviceToken === 'string' && serviceToken ? serviceToken : null;

  async function ensureRunning({ signal } = {}) {
    if (typeof inspectTransport === 'function') return 'in-process://mock-transport';
    if (closed) throw new Error('LLM moderation engine client is closed.');
    if (signal?.aborted) throw new Error('LLM moderation request cancelled.');
    if (activeBaseUrl && !spawnService) return activeBaseUrl;
    if (activeBaseUrl && child && child.exitCode === null && child.signalCode === null) return activeBaseUrl;
    if (!spawnService) {
      throw new Error('LLM moderation engine baseUrl is not configured.');
    }

    if (!starting) {
      starting = (async () => {
        const parsedPort = Number(port);
        const targetPort = Number.isInteger(parsedPort) && parsedPort > 0 && parsedPort <= 65535 ? parsedPort : 0;
        if (closed) throw new Error('LLM moderation engine client is closed.');
        const spawnToken = crypto.randomBytes(32).toString('base64url');
        const proc = spawn(
          pythonPath,
          ['-B', '-m', 'engine.server', '--host', safeHost, '--port', String(targetPort)],
          {
            cwd: PLUGIN_ROOT,
            shell: false,
            windowsHide: true,
            env: {
              ...sanitizedEngineEnv(),
              LOOMWARD_MODERATION_SERVICE_TOKEN: spawnToken,
            },
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

        const deadline = Date.now() + Math.max(4000, boundedTimeoutMs);
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
              const proofMatches = actualProof.length === expectedProof.length
                && crypto.timingSafeEqual(Buffer.from(actualProof, 'utf8'), Buffer.from(expectedProof, 'utf8'));
              if (probe.status === 200 && probe.data?.status === 'ok' && proofMatches) {
                if (closed) break;
                activeBaseUrl = url;
                return url;
              }
            } catch {}
          }
          await new Promise(r => setTimeout(r, 60));
        }
        if (child === proc) child = null;
        if (spawnService) activeToken = null;
        await terminateChildProcess(proc);
        throw new Error(spawnErr ? `Failed to spawn LLM moderation engine (${spawnErr.code || 'spawn_error'}).` : 'Failed to start out-of-process LLM moderation engine.');
      })().finally(() => {
        starting = null;
      });
      starting.catch(() => {});
    }

    if (!signal) return starting;
    return new Promise((resolve, reject) => {
      const onAbort = () => reject(new Error('LLM moderation request cancelled.'));
      if (signal.aborted) {
        onAbort();
        return;
      }
      signal.addEventListener('abort', onAbort, { once: true });
      starting.then(
        val => { signal.removeEventListener('abort', onAbort); resolve(val); },
        err => { signal.removeEventListener('abort', onAbort); reject(err); },
      );
    });
  }

  async function inspect(inspectRequest, config, { signal } = {}) {
    const stage = inspectRequest?.stage || 'input';
    try {
      const auth = resolveScopedAuthCredentials(secretsFacade, config);
      const body = {
        request: inspectRequest,
        config,
        auth,
        workspaceRoots: Array.isArray(workspaceRoots) ? workspaceRoots : [],
      };
      if (typeof inspectTransport === 'function') {
        const rawVerdict = await inspectTransport(body, { signal });
        return validateContentInspectVerdict(rawVerdict, {
          stage,
          expectedProtocolVersion: CONTENT_INSPECT_V2_PROTOCOL_VERSION,
        });
      }
      const url = await ensureRunning({ signal });
      const res = await httpJsonRequest(url, '/api/inspect', {
        method: 'POST',
        body,
        timeoutMs: boundedTimeoutMs,
        signal,
        token: activeToken,
      });
      if (res.status !== 200 || !res.data?.verdict) {
        throw new Error(`Moderation engine returned HTTP ${res.status}`);
      }
      const verdict = validateContentInspectVerdict(res.data.verdict, {
        stage,
        expectedProtocolVersion: CONTENT_INSPECT_V2_PROTOCOL_VERSION,
      });
      return {
        verdict,
        telemetry: res.data.telemetry || null,
      };
    } catch (error) {
      const isCancelled = signal?.aborted;
      const failDecision = (stage === 'input' || stage === 'stream_start')
        && config?.fallback?.onAllFailedInput === 'escalate'
        ? 'escalate'
        : 'block';
      return {
        verdict: buildFailClosedModerationVerdict(
          stage,
          isCancelled
            ? 'LLM content moderation cancelled (fail-closed).'
            : `LLM content moderation unavailable: ${error?.message || 'engine error'}.`,
          {
            ruleId: isCancelled ? 'MODERATION-CANCELLED' : 'MODERATION-ENGINE-UNAVAILABLE',
            requestId: inspectRequest?.requestId || '',
            decision: isCancelled ? 'block' : failDecision,
          },
        ),
        telemetry: { engineUsed: 'fail-closed', fallbackUsed: false },
      };
    }
  }

  async function getHealth({ signal } = {}) {
    if (typeof inspectTransport === 'function') {
      return { status: 'ok', mode: 'mock-transport' };
    }
    if (!activeBaseUrl || closed) return null;
    try {
      const res = await httpJsonRequest(activeBaseUrl, '/api/status', {
        timeoutMs: 1200,
        signal,
        token: activeToken,
      });
      return res.status === 200 ? res.data : null;
    } catch {
      return null;
    }
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
    inspect,
    getHealth,
    close,
    isClosed: () => closed,
    getBaseUrl: () => activeBaseUrl,
  });
}
