// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Safe host lifecycle manager and SSRF-pinned HTTP client for local or authorized LAN Ollama runtimes.
import crypto from 'node:crypto';
import dns from 'node:dns';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { StringDecoder } from 'node:string_decoder';
import {
  assertSafeEndpointUrl,
  assertSafeTargetUrl,
  classifyIpLiteral,
  isLoopbackHost,
} from '../packages/shared/src/network-policy.mjs';

const execFileAsync = promisify(execFile);

export const DEFAULT_OLLAMA_ORIGIN = 'http://127.0.0.1:11434';
const MODEL_TAG_RE = /^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,127}$/;
const MAX_OLLAMA_JSON_BYTES = 2 * 1024 * 1024;
const MAX_INSTALL_SCRIPT_BYTES = 512 * 1024;
const MAX_PULL_JOBS = 8;

export const OLLAMA_RECOMMENDED_MODELS = Object.freeze([
  Object.freeze({
    id: 'llama-guard3:1b',
    role: 'guard',
    sizeLabel: '1.6 GB',
    label: 'Llama Guard 3 · 1B',
    desc: '轻量专用安全分类器，适合常规 CPU / 小显存本机部署',
  }),
  Object.freeze({
    id: 'llama-guard3:8b',
    role: 'guard',
    sizeLabel: '4.9 GB',
    label: 'Llama Guard 3 · 8B',
    desc: '高精度安全护栏分类模型，适合独立显卡或 GPU 节点',
  }),
  Object.freeze({
    id: 'shieldgemma:2b',
    role: 'guard',
    sizeLabel: '1.7 GB',
    label: 'ShieldGemma · 2B',
    desc: 'Google 轻量级安全策略审核分类器',
  }),
  Object.freeze({
    id: 'qwen2.5:0.5b',
    role: 'canary',
    sizeLabel: '398 MB',
    label: 'Qwen 2.5 · 0.5B',
    desc: '超低延迟 Zero-Tool 防诱导金丝雀探针（约 400MB）',
  }),
  Object.freeze({
    id: 'qwen3:0.6b',
    role: 'canary',
    sizeLabel: '523 MB',
    label: 'Qwen 3 · 0.6B',
    desc: '新一代极速轻量探针（原生支持 think: false）',
  }),
]);

export function assertValidOllamaModelTag(rawModel) {
  if (typeof rawModel !== 'string') throw new TypeError('Ollama model tag must be a string.');
  const trimmed = rawModel.trim();
  if (!MODEL_TAG_RE.test(trimmed) || trimmed.includes('..') || trimmed.endsWith('/') || trimmed.endsWith(':')) {
    throw new Error(`Invalid Ollama model tag: ${String(rawModel).slice(0, 64)}`);
  }
  return trimmed;
}

export function sanitizedOllamaEnv() {
  const env = {};
  const keys = [
    'PATH', 'HOME', 'USERPROFILE', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TERM', 'TZ',
    'TMPDIR', 'TEMP', 'TMP', 'OLLAMA_MODELS', 'OLLAMA_DEBUG',
    'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy',
    ...(process.platform === 'win32'
      ? ['SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'APPDATA', 'LOCALAPPDATA', 'HOMEDRIVE', 'HOMEPATH']
      : []),
  ];
  for (const k of keys) {
    if (typeof process.env[k] === 'string') env[k] = process.env[k];
  }
  return env;
}

export function normalizeOllamaEndpoint(rawEndpoint, { allowPrivateNetwork = false, blockedOrigins = [] } = {}) {
  const input = typeof rawEndpoint === 'string' && rawEndpoint.trim() ? rawEndpoint.trim() : DEFAULT_OLLAMA_ORIGIN;
  const validated = assertSafeEndpointUrl(input, {
    allowLoopbackHttp: true,
    allowPrivateNetwork,
    blockedOrigins,
    label: 'ollama',
  });
  return new URL(validated).origin;
}

async function resolvePinnedOllamaTarget(urlStr, { allowPrivateNetwork = false, blockedOrigins = [], dnsLookup = dns.promises.lookup } = {}) {
  const { parsed, bareHost, ipClass, isLoopback, isHttps } = assertSafeTargetUrl(urlStr, {
    allowLoopbackHttp: true,
    allowPrivateNetwork,
    blockedOrigins,
  });

  if (ipClass !== 'domain') {
    const family = bareHost.includes(':') ? 6 : 4;
    return { parsed, address: bareHost, family, servername: bareHost, isHttps };
  }

  if (isLoopback) {
    return { parsed, address: '127.0.0.1', family: 4, servername: 'localhost', isHttps };
  }

  const records = await dnsLookup(bareHost, { all: true });
  const list = Array.isArray(records) ? records : [records];
  if (!list.length) {
    throw new Error(`DNS lookup returned no addresses for Ollama host ${bareHost}.`);
  }
  for (const rec of list) {
    const cls = classifyIpLiteral(rec.address);
    if (cls === 'blocked') {
      throw new Error(`Blocked DNS target IP (${rec.address}) for Ollama host ${bareHost}.`);
    }
    if (cls === 'loopback') continue;
    if (cls === 'private') {
      if (!allowPrivateNetwork) {
        throw new Error(`Resolved private IP (${rec.address}) for ${bareHost} requires allowPrivateNetwork.`);
      }
      continue;
    }
    if (!isHttps) {
      throw new Error(`Plaintext http:// cannot target resolved public IP (${rec.address}) for ${bareHost}.`);
    }
  }
  const primary = list[0];
  return {
    parsed,
    address: primary.address,
    family: primary.family === 6 ? 6 : 4,
    servername: bareHost,
    isHttps,
  };
}

export async function ollamaHttpRequest(urlStr, {
  method = 'GET',
  body = null,
  timeoutMs = 5000,
  maxBytes = MAX_OLLAMA_JSON_BYTES,
  allowPrivateNetwork = false,
  blockedOrigins = [],
  signal,
  dnsLookup,
} = {}) {
  const pinned = await resolvePinnedOllamaTarget(urlStr, { allowPrivateNetwork, blockedOrigins, dnsLookup });
  const payload = body !== null && body !== undefined ? Buffer.from(JSON.stringify(body), 'utf8') : null;
  const transport = pinned.isHttps ? https : http;
  const defaultPort = pinned.isHttps ? 443 : 80;
  const targetPort = pinned.parsed.port ? Number(pinned.parsed.port) : defaultPort;

  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error('Ollama request aborted.'));
      return;
    }
    let settled = false;
    let timer = null;
    const done = (err, val) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', onAbort);
      if (err) reject(err);
      else resolve(val);
    };

    const req = transport.request({
      host: pinned.address,
      family: pinned.family,
      port: targetPort,
      path: pinned.parsed.pathname + pinned.parsed.search,
      method,
      ...(pinned.isHttps ? { servername: pinned.servername, minVersion: 'TLSv1.2' } : {}),
      headers: {
        Host: pinned.parsed.host,
        Accept: 'application/json',
        ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': String(payload.length) } : {}),
      },
      timeout: timeoutMs,
    }, res => {
      if (res.statusCode >= 300 && res.statusCode < 400) {
        res.resume();
        done(new Error(`Unexpected redirect HTTP ${res.statusCode} from Ollama endpoint.`));
        return;
      }
      const chunks = [];
      let bytes = 0;
      res.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > maxBytes) {
          req.destroy();
          done(new Error('Ollama response exceeded byte limit.'));
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
      done(new Error('Ollama request cancelled.'));
    };
    if (signal) signal.addEventListener('abort', onAbort, { once: true });

    timer = setTimeout(() => {
      req.destroy();
      done(new Error(`Ollama request timed out after ${timeoutMs}ms.`));
    }, timeoutMs);
    timer.unref?.();

    req.on('error', err => done(err));
    if (payload) req.write(payload);
    req.end();
  });
}

export async function ollamaStreamPull(urlStr, model, {
  timeoutMs = 15 * 60 * 1000,
  allowPrivateNetwork = false,
  blockedOrigins = [],
  signal,
  dnsLookup,
  onProgress,
} = {}) {
  const cleanModel = assertValidOllamaModelTag(model);
  const pullUrl = `${urlStr.replace(/\/+$/, '')}/api/pull`;
  const pinned = await resolvePinnedOllamaTarget(pullUrl, { allowPrivateNetwork, blockedOrigins, dnsLookup });
  const payload = Buffer.from(JSON.stringify({ model: cleanModel, stream: true }), 'utf8');
  const transport = pinned.isHttps ? https : http;
  const defaultPort = pinned.isHttps ? 443 : 80;
  const targetPort = pinned.parsed.port ? Number(pinned.parsed.port) : defaultPort;

  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error('Ollama pull aborted.'));
      return;
    }
    let settled = false;
    let timer = null;
    const done = (err, val) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', onAbort);
      if (err) reject(err);
      else resolve(val);
    };

    const req = transport.request({
      host: pinned.address,
      family: pinned.family,
      port: targetPort,
      path: pinned.parsed.pathname,
      method: 'POST',
      ...(pinned.isHttps ? { servername: pinned.servername, minVersion: 'TLSv1.2' } : {}),
      headers: {
        Host: pinned.parsed.host,
        'Content-Type': 'application/json',
        'Content-Length': String(payload.length),
        Accept: 'application/x-ndjson, application/json',
      },
      timeout: timeoutMs,
    }, res => {
      if (res.statusCode >= 300 && res.statusCode < 400) {
        res.resume();
        done(new Error(`Unexpected redirect HTTP ${res.statusCode} during Ollama pull.`));
        return;
      }
      const decoder = new StringDecoder('utf8');
      let buf = '';
      let lastStatus = 'starting';
      let lastError = null;
      const processLine = line => {
        const trimmed = line.trim();
        if (!trimmed) return;
        let obj;
        try { obj = JSON.parse(trimmed); } catch { return; }
        if (typeof obj.error === 'string' && obj.error) {
          lastError = obj.error;
        }
        if (typeof obj.status === 'string') {
          lastStatus = obj.status;
        }
        const total = Number(obj.total);
        const completed = Number(obj.completed);
        const percent = Number.isFinite(total) && total > 0 && Number.isFinite(completed)
          ? Math.max(0, Math.min(100, Math.round((completed / total) * 100)))
          : null;
        onProgress?.({
          status: lastStatus,
          ...(typeof obj.digest === 'string' ? { digest: obj.digest.slice(0, 24) } : {}),
          ...(Number.isFinite(total) ? { total } : {}),
          ...(Number.isFinite(completed) ? { completed } : {}),
          percent,
          ...(lastError ? { error: lastError } : {}),
        });
      };

      res.on('data', chunk => {
        buf += decoder.write(chunk);
        if (buf.length > 256 * 1024) buf = buf.slice(-65536);
        let nl;
        while ((nl = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, nl);
          buf = buf.slice(nl + 1);
          processLine(line);
        }
      });
      res.on('end', () => {
        buf += decoder.end();
        if (buf.trim()) processLine(buf);
        if (lastError) {
          done(new Error(lastError));
        } else if (res.statusCode < 200 || res.statusCode >= 300) {
          done(new Error(`Ollama pull failed with HTTP ${res.statusCode}.`));
        } else {
          done(null, { ok: true, model: cleanModel, status: lastStatus || 'success' });
        }
      });
      res.on('error', err => done(err));
    });

    const onAbort = () => {
      req.destroy();
      done(new Error('Ollama pull cancelled.'));
    };
    if (signal) signal.addEventListener('abort', onAbort, { once: true });

    timer = setTimeout(() => {
      req.destroy();
      done(new Error(`Ollama pull timed out after ${Math.round(timeoutMs / 1000)}s.`));
    }, timeoutMs);
    timer.unref?.();

    req.on('error', err => done(err));
    req.write(payload);
    req.end();
  });
}

function candidateBinaryPaths() {
  const home = os.homedir();
  const exe = process.platform === 'win32' ? 'ollama.exe' : 'ollama';
  const pathDirs = String(process.env.PATH || '').split(path.delimiter).filter(Boolean).map(dir => path.join(dir, exe));
  if (process.platform === 'win32') {
    const localApp = process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local');
    return [
      path.join(localApp, 'Programs', 'Ollama', 'ollama.exe'),
      ...pathDirs,
    ];
  }
  return [
    path.join(home, '.local', 'bin', 'ollama'),
    path.join(home, '.local', 'share', 'ollama', 'current', 'bin', 'ollama'),
    '/usr/local/bin/ollama',
    '/opt/homebrew/bin/ollama',
    '/usr/bin/ollama',
    ...pathDirs,
  ];
}

export async function detectOllamaBinary() {
  const seen = new Set();
  const env = sanitizedOllamaEnv();
  for (const candidate of candidateBinaryPaths()) {
    const resolved = path.resolve(candidate);
    if (seen.has(resolved)) continue;
    seen.add(resolved);
    try {
      await fsp.access(resolved, fs.constants.X_OK);
      const { stdout, stderr } = await execFileAsync(resolved, ['--version'], {
        shell: false,
        timeout: 3000,
        windowsHide: true,
        env,
      });
      const text = `${stdout || ''} ${stderr || ''}`.trim();
      const match = text.match(/(\d+\.\d+(?:\.\d+)*)/);
      return {
        installed: true,
        binaryPath: resolved,
        version: match ? match[1] : text.slice(0, 48) || 'installed',
      };
    } catch {}
  }
  return {
    installed: false,
    binaryPath: null,
    version: null,
  };
}

function formatOllamaSize(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n <= 0) return '';
  if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(1)} GB`;
  return `${Math.round(n / 1024 ** 2)} MB`;
}

export async function probeOllamaStatus({
  endpoint,
  allowPrivateNetwork = false,
  blockedOrigins = [],
  timeoutMs = 3000,
  dnsLookup,
  detectBinary = detectOllamaBinary,
} = {}) {
  const normalized = normalizeOllamaEndpoint(endpoint, { allowPrivateNetwork, blockedOrigins });
  const parsed = new URL(normalized);
  const isLoopback = isLoopbackHost(parsed.hostname);

  const [binary, verRes, tagsRes, psRes] = await Promise.all([
    detectBinary().catch(() => ({ installed: false, binaryPath: null, version: null })),
    ollamaHttpRequest(`${normalized}/api/version`, { timeoutMs, allowPrivateNetwork, blockedOrigins, dnsLookup }).catch(err => ({ error: err?.message })),
    ollamaHttpRequest(`${normalized}/api/tags`, { timeoutMs, allowPrivateNetwork, blockedOrigins, dnsLookup }).catch(() => null),
    ollamaHttpRequest(`${normalized}/api/ps`, { timeoutMs, allowPrivateNetwork, blockedOrigins, dnsLookup }).catch(() => null),
  ]);

  const running = Boolean(verRes && !verRes.error && verRes.status === 200);
  const models = Array.isArray(tagsRes?.data?.models)
    ? tagsRes.data.models.slice(0, 64).map(m => ({
        name: String(m.name || m.model || ''),
        sizeBytes: Number(m.size || 0),
        sizeLabel: formatOllamaSize(m.size),
        parameterSize: String(m.details?.parameter_size || ''),
        quantization: String(m.details?.quantization_level || ''),
        family: String(m.details?.family || ''),
        capabilities: Array.isArray(m.capabilities) ? m.capabilities.slice(0, 8) : [],
      })).filter(m => m.name)
    : [];

  const loadedModels = Array.isArray(psRes?.data?.models)
    ? psRes.data.models.slice(0, 16).map(m => ({
        name: String(m.name || m.model || ''),
        sizeBytes: Number(m.size || 0),
        expiresAt: typeof m.expires_at === 'string' ? m.expires_at : null,
      })).filter(m => m.name)
    : [];

  return {
    ok: true,
    endpoint: normalized,
    isLoopback,
    allowPrivateNetwork: Boolean(allowPrivateNetwork),
    installed: Boolean(binary?.installed),
    binaryPath: binary?.binaryPath || null,
    binaryVersion: binary?.version || null,
    running,
    version: running && typeof verRes.data?.version === 'string' ? verRes.data.version : null,
    models,
    loadedModels,
    recommendedModels: OLLAMA_RECOMMENDED_MODELS,
    error: !running ? (verRes?.error || 'Ollama service is not reachable on this endpoint.') : null,
  };
}

async function fetchHttpsScriptBounded(rawUrl, maxHops = 3) {
  let current = rawUrl;
  for (let hop = 0; hop <= maxHops; hop++) {
    assertSafeTargetUrl(current, { allowLoopbackHttp: false, allowPrivateNetwork: false });
    const parsed = new URL(current);
    if (parsed.protocol !== 'https:') throw new Error('Installer script download requires HTTPS.');
    const res = await new Promise((resolve, reject) => {
      const req = https.get(current, { minVersion: 'TLSv1.2', timeout: 30_000 }, reply => {
        if (reply.statusCode >= 300 && reply.statusCode < 400 && reply.headers.location) {
          reply.resume();
          resolve({ redirect: new URL(reply.headers.location, current).toString() });
          return;
        }
        if (reply.statusCode !== 200) {
          reply.resume();
          reject(new Error(`Installer download failed with HTTP ${reply.statusCode}.`));
          return;
        }
        const chunks = [];
        let bytes = 0;
        reply.on('data', c => {
          bytes += c.length;
          if (bytes > MAX_INSTALL_SCRIPT_BYTES) {
            req.destroy();
            reject(new Error('Installer script exceeded 512 KiB size limit.'));
            return;
          }
          chunks.push(c);
        });
        reply.on('end', () => resolve({ body: Buffer.concat(chunks).toString('utf8') }));
        reply.on('error', reject);
      });
      req.on('error', reject);
      req.setTimeout(30_000, () => { req.destroy(); reject(new Error('Installer download timed out.')); });
    });
    if (res.redirect) {
      current = res.redirect;
      continue;
    }
    return res.body;
  }
  throw new Error('Too many redirects downloading Ollama installer.');
}

function runBoundedProcess(bin, args, { env, timeoutMs = 300_000, windowsHide = true } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, {
      shell: false,
      windowsHide,
      stdio: ['ignore', 'pipe', 'pipe'],
      env,
    });
    let output = '';
    const appendOut = chunk => {
      output += chunk.toString('utf8');
      if (output.length > 16384) output = output.slice(-8192);
    };
    child.stdout?.on('data', appendOut);
    child.stderr?.on('data', appendOut);
    const timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch {}
      reject(new Error(`Process timed out after ${Math.round(timeoutMs / 1000)}s.`));
    }, timeoutMs);
    timer.unref?.();
    child.on('error', err => {
      clearTimeout(timer);
      reject(err);
    });
    child.on('exit', code => {
      clearTimeout(timer);
      if (code === 0) resolve({ output });
      else reject(new Error(`Command ${path.basename(bin)} exited with code ${code}: ${output.trim().slice(-400)}`));
    });
  });
}

export async function installOllamaBinary({ detectBinary = detectOllamaBinary } = {}) {
  const existing = await detectBinary();
  if (existing.installed) {
    return {
      ok: true,
      alreadyInstalled: true,
      installed: true,
      binaryPath: existing.binaryPath,
      version: existing.version,
    };
  }
  const env = sanitizedOllamaEnv();
  if (process.platform === 'linux') {
    const scriptText = await fetchHttpsScriptBounded('https://ollama.com/install.sh');
    if (!scriptText || scriptText.length < 64) {
      throw new Error('Downloaded Ollama install script is unexpectedly empty.');
    }
    const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'lw-ollama-inst-'));
    await fsp.chmod(tmpDir, 0o700);
    const scriptPath = path.join(tmpDir, 'install.sh');
    try {
      const fd = fs.openSync(scriptPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o700);
      try { fs.writeFileSync(fd, scriptText, 'utf8'); } finally { fs.closeSync(fd); }
      await runBoundedProcess('sh', [scriptPath], { env, timeoutMs: 300_000 });
    } finally {
      await fsp.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
    }
  } else if (process.platform === 'darwin') {
    let brewPath = null;
    for (const cand of ['/opt/homebrew/bin/brew', '/usr/local/bin/brew']) {
      try { await fsp.access(cand, fs.constants.X_OK); brewPath = cand; break; } catch {}
    }
    if (!brewPath) {
      throw new Error('Homebrew is required to auto-install Ollama on macOS, or install manually from https://ollama.com/download.');
    }
    await runBoundedProcess(brewPath, ['install', '--cask', 'ollama'], { env, timeoutMs: 300_000 });
  } else if (process.platform === 'win32') {
    await runBoundedProcess('winget.exe', ['install', '-e', '--id', 'Ollama.Ollama', '--accept-package-agreements', '--accept-source-agreements'], { env, timeoutMs: 300_000 });
  } else {
    throw new Error(`Unsupported platform for automatic Ollama installation: ${process.platform}`);
  }

  const after = await detectBinary();
  if (!after.installed) {
    throw new Error('Ollama installer finished, but the ollama binary could not be verified.');
  }
  return {
    ok: true,
    alreadyInstalled: false,
    installed: true,
    binaryPath: after.binaryPath,
    version: after.version,
  };
}

export async function startOllamaDaemon({
  endpoint = DEFAULT_OLLAMA_ORIGIN,
  blockedOrigins = [],
  startupTimeoutMs = 12_000,
  detectBinary = detectOllamaBinary,
  dnsLookup,
} = {}) {
  const normalized = normalizeOllamaEndpoint(endpoint, { allowPrivateNetwork: false, blockedOrigins });
  const parsed = new URL(normalized);
  if (!isLoopbackHost(parsed.hostname)) {
    throw new Error('Local Ollama service start is permitted only for loopback endpoints.');
  }
  const existing = await ollamaHttpRequest(`${normalized}/api/version`, { timeoutMs: 1200, blockedOrigins, dnsLookup }).catch(() => null);
  if (existing?.status === 200) {
    return {
      ok: true,
      alreadyRunning: true,
      running: true,
      endpoint: normalized,
      version: existing.data?.version || null,
    };
  }

  const bin = await detectBinary();
  if (!bin.installed || !bin.binaryPath) {
    const err = new Error('Ollama is not installed on this machine; install Ollama first.');
    err.status = 400;
    throw err;
  }

  const hostPort = parsed.port || '11434';
  const bindHost = parsed.hostname;
  const child = spawn(bin.binaryPath, ['serve'], {
    shell: false,
    detached: true,
    windowsHide: true,
    stdio: ['ignore', 'ignore', 'pipe'],
    env: {
      ...sanitizedOllamaEnv(),
      OLLAMA_HOST: `${bindHost}:${hostPort}`,
    },
  });

  let exited = false;
  let exitErr = '';
  child.on('error', err => { exited = true; exitErr = err?.message || 'spawn error'; });
  child.on('exit', code => { exited = true; if (!exitErr) exitErr = `exited with code ${code}`; });
  child.stderr?.on('data', chunk => {
    exitErr = (exitErr + chunk.toString('utf8')).slice(-512);
  });

  const deadline = Date.now() + Math.max(3000, startupTimeoutMs);
  while (Date.now() < deadline && !exited) {
    const probe = await ollamaHttpRequest(`${normalized}/api/version`, { timeoutMs: 800, blockedOrigins, dnsLookup }).catch(() => null);
    if (probe?.status === 200) {
      child.stderr?.destroy();
      child.unref();
      return {
        ok: true,
        alreadyRunning: false,
        started: true,
        running: true,
        pid: child.pid || null,
        endpoint: normalized,
        version: probe.data?.version || null,
      };
    }
    await new Promise(r => setTimeout(r, 200));
  }

  try { child.kill('SIGTERM'); } catch {}
  throw new Error(`Failed to start local Ollama daemon: ${exitErr || 'startup timeout'}`);
}

export async function testOllamaModelInference({
  endpoint = DEFAULT_OLLAMA_ORIGIN,
  model,
  allowPrivateNetwork = false,
  blockedOrigins = [],
  think = false,
  timeoutMs = 20_000,
  dnsLookup,
} = {}) {
  const cleanModel = assertValidOllamaModelTag(model);
  const normalized = normalizeOllamaEndpoint(endpoint, { allowPrivateNetwork, blockedOrigins });
  const startedAt = Date.now();
  const res = await ollamaHttpRequest(`${normalized}/api/chat`, {
    method: 'POST',
    timeoutMs,
    allowPrivateNetwork,
    blockedOrigins,
    dnsLookup,
    body: {
      model: cleanModel,
      messages: [{ role: 'user', content: 'Reply ONLY with JSON: {"ok":true}' }],
      stream: false,
      think: Boolean(think),
      format: 'json',
      options: { temperature: 0, num_predict: 32 },
    },
  });
  const latencyMs = Date.now() - startedAt;
  if (res.status < 200 || res.status >= 300) {
    const errText = res.data?.error || res.rawText?.slice(0, 200) || `HTTP ${res.status}`;
    throw new Error(`Ollama inference test failed: ${errText}`);
  }
  const replyText = String(res.data?.message?.content || res.data?.response || '').trim();
  return {
    ok: true,
    endpoint: normalized,
    model: cleanModel,
    latencyMs,
    replyPreview: replyText.slice(0, 160),
  };
}

export function createOllamaController({
  getBlockedOrigins = () => [],
  controlChannel = null,
  prober = probeOllamaStatus,
  installer = installOllamaBinary,
  starter = startOllamaDaemon,
  puller = ollamaStreamPull,
  tester = testOllamaModelInference,
} = {}) {
  const pullJobs = new Map();
  const pullControllers = new Map();
  let installInFlight = false;
  let startInFlight = false;

  function pruneJobs() {
    while (pullJobs.size > MAX_PULL_JOBS) {
      const oldest = pullJobs.keys().next().value;
      if (pullJobs.get(oldest)?.status === 'pulling') break;
      pullJobs.delete(oldest);
    }
  }

  return Object.freeze({
    async status({ endpoint, allowPrivateNetwork = false } = {}) {
      const info = await prober({
        endpoint,
        allowPrivateNetwork: Boolean(allowPrivateNetwork),
        blockedOrigins: getBlockedOrigins(),
      });
      return {
        ...info,
        pullJobs: [...pullJobs.values()],
      };
    },
    async install() {
      if (installInFlight) {
        const err = new Error('Ollama installation is already in progress.');
        err.status = 409;
        throw err;
      }
      installInFlight = true;
      try {
        const result = await installer();
        controlChannel?.publish({
          type: 'moderation.ollama_installed',
          alreadyInstalled: Boolean(result.alreadyInstalled),
        });
        return result;
      } finally {
        installInFlight = false;
      }
    },
    async start({ endpoint } = {}) {
      if (startInFlight) {
        const err = new Error('Ollama service start is already in progress.');
        err.status = 409;
        throw err;
      }
      startInFlight = true;
      try {
        const result = await starter({
          endpoint,
          blockedOrigins: getBlockedOrigins(),
        });
        controlChannel?.publish({
          type: 'moderation.ollama_started',
          alreadyRunning: Boolean(result.alreadyRunning),
        });
        return result;
      } finally {
        startInFlight = false;
      }
    },
    async pull({ endpoint, model, allowPrivateNetwork = false } = {}) {
      const cleanModel = assertValidOllamaModelTag(model);
      const normalized = normalizeOllamaEndpoint(endpoint, {
        allowPrivateNetwork: Boolean(allowPrivateNetwork),
        blockedOrigins: getBlockedOrigins(),
      });
      for (const existing of pullJobs.values()) {
        if (existing.model === cleanModel && existing.endpoint === normalized && existing.status === 'pulling') {
          return { ok: true, job: { ...existing }, deduplicated: true };
        }
      }
      pruneJobs();
      const jobId = crypto.randomBytes(8).toString('hex');
      const job = {
        id: jobId,
        model: cleanModel,
        endpoint: normalized,
        status: 'pulling',
        detail: 'connecting',
        percent: null,
        error: null,
        startedAt: new Date().toISOString(),
        finishedAt: null,
      };
      pullJobs.set(jobId, job);

      const ctrl = new AbortController();
      pullControllers.set(jobId, ctrl);
      const runPromise = (async () => {
        try {
          await puller(normalized, cleanModel, {
            allowPrivateNetwork: Boolean(allowPrivateNetwork),
            blockedOrigins: getBlockedOrigins(),
            signal: ctrl.signal,
            onProgress(ev) {
              if (typeof ev?.status === 'string') job.detail = ev.status;
              if (Number.isFinite(ev?.percent)) job.percent = ev.percent;
            },
          });
          job.status = 'completed';
          job.percent = 100;
          job.detail = 'success';
          job.finishedAt = new Date().toISOString();
          controlChannel?.publish({ type: 'moderation.ollama_pull_completed', model: cleanModel });
        } catch (err) {
          job.status = 'failed';
          job.error = err?.message || 'Pull failed.';
          job.finishedAt = new Date().toISOString();
          controlChannel?.publish({ type: 'moderation.ollama_pull_failed', model: cleanModel });
        } finally {
          pullControllers.delete(jobId);
        }
      })();
      // Give fast synchronous/mock pulls a brief window to settle cleanly in one roundtrip while staying non-blocking for multi-GB pulls.
      await Promise.race([runPromise, new Promise(r => setTimeout(r, 150))]);
      return { ok: true, job: { ...job } };
    },
    async testModel({ endpoint, model, allowPrivateNetwork = false, think = false } = {}) {
      return tester({
        endpoint,
        model,
        allowPrivateNetwork: Boolean(allowPrivateNetwork),
        blockedOrigins: getBlockedOrigins(),
        think: Boolean(think),
      });
    },
    close() {
      for (const ctrl of pullControllers.values()) ctrl.abort();
      pullControllers.clear();
    },
  });
}
