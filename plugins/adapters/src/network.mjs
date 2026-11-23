// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Shared network boundary checks & bounded JSON/SSE HTTP helpers for standalone project adapters.
import net from 'node:net';

export const DEFAULT_MAX_RESPONSE_BYTES = 512 * 1024;

function isLoopbackHost(hostname) {
  const lower = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  if (lower === 'localhost' || lower === '::1') return true;
  if (/^127\.(?:\d{1,3}\.){2}\d{1,3}$/.test(lower)) return true;
  return false;
}

function classifyIpLiteral(hostname) {
  const bare = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  const version = net.isIP(bare);
  if (!version) return 'domain';
  if (version === 4) {
    const parts = bare.split('.').map(Number);
    if (parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return 'blocked';
    const [a, b] = parts;
    if (a === 127) return 'loopback';
    if (a === 0 || (a === 169 && b === 254)) return 'blocked';
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127)) {
      return 'private';
    }
    if (a >= 224) return 'blocked';
    return 'public';
  }
  if (bare === '::1') return 'loopback';
  if (bare === '::' || bare.startsWith('fe80:') || bare.startsWith('fe9') || bare.startsWith('fea') || bare.startsWith('feb') || bare.startsWith('ff')) {
    return 'blocked';
  }
  if (bare.startsWith('::ffff:')) {
    const mapped = bare.slice('::ffff:'.length);
    if (net.isIP(mapped) === 4) return classifyIpLiteral(mapped);
  }
  if (bare.startsWith('fc') || bare.startsWith('fd')) return 'private';
  return 'public';
}

export function assertSafeIntegrationOrigin(
  rawUrl,
  { allowLoopbackHttp = false, allowPrivateNetwork = false, label = 'integration' } = {},
) {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
    throw new TypeError(`${label} origin must be a non-empty URL string.`);
  }
  const trimmed = rawUrl.trim();
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) {
    throw new Error(`${label} origin must not contain control characters.`);
  }
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error(`Invalid ${label} origin URL.`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(`${label} origin must not embed credentials.`);
  }
  if (parsed.search || parsed.hash) {
    throw new Error(`${label} origin must not include query strings or fragments.`);
  }
  if (parsed.pathname && parsed.pathname !== '/') {
    throw new Error(`${label} origin must not include a path suffix; pass the bare origin.`);
  }

  const loopback = isLoopbackHost(parsed.hostname);
  const ipClass = classifyIpLiteral(parsed.hostname);
  if (ipClass === 'blocked') {
    throw new Error(`${label} origin targets a blocked link-local, multicast, or unspecified IP.`);
  }
  if ((loopback || ipClass === 'loopback') && !allowLoopbackHttp && !allowPrivateNetwork) {
    throw new Error(`${label} origin targets a loopback address; enable allowLoopbackHttp or allowPrivateNetwork explicitly if intended.`);
  }
  if (ipClass === 'private' && !allowPrivateNetwork) {
    throw new Error(`${label} origin targets a private network IP; enable allowPrivateNetwork explicitly if intended.`);
  }

  if (parsed.protocol === 'https:') {
    return parsed.origin;
  }
  if (parsed.protocol === 'http:' && allowLoopbackHttp && loopback) {
    return parsed.origin;
  }
  throw new Error(`${label} origin must use https:// (or loopback http:// only when allowLoopbackHttp is enabled).`);
}

export function assertSafeEndpointUrl(
  rawUrl,
  { allowLoopbackHttp = false, allowPrivateNetwork = false, expectedOrigin = null, label = 'endpoint' } = {},
) {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
    throw new TypeError(`${label} URL must be a non-empty string.`);
  }
  let parsed;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    throw new Error(`Invalid ${label} URL.`);
  }
  const origin = assertSafeIntegrationOrigin(parsed.origin, {
    allowLoopbackHttp,
    allowPrivateNetwork,
    label,
  });
  if (expectedOrigin && origin !== expectedOrigin) {
    throw new Error(`${label} URL origin mismatch (expected ${expectedOrigin}, received ${origin}).`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(`${label} URL must not embed credentials.`);
  }
  return parsed.toString();
}

export async function readBoundedText(response, maxBytes = DEFAULT_MAX_RESPONSE_BYTES) {
  const declared = Number(response.headers?.get?.('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new Error(`Upstream response exceeded ${maxBytes} byte limit.`);
  }
  if (!response.body || typeof response.body.getReader !== 'function') {
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > maxBytes) {
      throw new Error(`Upstream response exceeded ${maxBytes} byte limit.`);
    }
    return text;
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        try { await reader.cancel(); } catch {}
        throw new Error(`Upstream response exceeded ${maxBytes} byte limit.`);
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    try { reader.releaseLock(); } catch {}
  }
  return Buffer.concat(chunks, total).toString('utf8');
}

export async function fetchBounded(
  url,
  {
    method = 'GET',
    headers = {},
    body = undefined,
    timeoutMs = 10_000,
    maxBytes = DEFAULT_MAX_RESPONSE_BYTES,
    fetchImpl = globalThis.fetch,
  } = {},
) {
  if (typeof fetchImpl !== 'function') {
    throw new Error('No fetch implementation available.');
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error(`Request timed out after ${timeoutMs}ms.`)), timeoutMs);
  timer.unref?.();
  const startedAt = Date.now();
  try {
    const response = await fetchImpl(url, {
      method,
      headers,
      body,
      redirect: 'error',
      signal: controller.signal,
    });
    const text = await readBoundedText(response, maxBytes);
    return {
      ok: response.ok,
      status: response.status,
      headers: response.headers,
      text,
      latencyMs: Math.max(0, Date.now() - startedAt),
    };
  } catch (error) {
    if (controller.signal.aborted) {
      const err = new Error(`Upstream request timed out after ${timeoutMs}ms.`);
      err.code = 'UPSTREAM_TIMEOUT';
      throw err;
    }
    const err = new Error(`Upstream request failed (${error?.code || error?.name || 'network_error'}).`);
    err.code = error?.code || 'UPSTREAM_NETWORK_ERROR';
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

export function parseSseJsonRpcFrames(sseText) {
  const frames = [];
  let dataLines = [];
  const flush = () => {
    if (!dataLines.length) return;
    const payload = dataLines.join('\n').trim();
    dataLines = [];
    if (!payload || payload === '[DONE]') return;
    try {
      frames.push(JSON.parse(payload));
    } catch {
      // Ignore malformed/non-JSON comment frames.
    }
  };
  for (const rawLine of String(sseText || '').split(/\r?\n/)) {
    if (rawLine === '') {
      flush();
    } else if (rawLine.startsWith('data:')) {
      dataLines.push(rawLine.slice(5).trimStart());
    }
  }
  flush();
  return frames;
}
