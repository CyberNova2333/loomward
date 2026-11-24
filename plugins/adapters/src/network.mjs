// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Shared network boundary checks, full 8-hextet IPv6 SSRF classifier, DNS IP check, & bounded JSON/SSE HTTP helpers for standalone project adapters.
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';

export const DEFAULT_MAX_RESPONSE_BYTES = 512 * 1024;

function isLoopbackHost(hostname) {
  const lower = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  if (lower === 'localhost' || lower === '::1') return true;
  if (/^127\.(?:\d{1,3}\.){2}\d{1,3}$/.test(lower)) return true;
  return false;
}

function classifyIpv4Octets([a, b, c, d]) {
  if ([a, b, c, d].some(n => !Number.isInteger(n) || n < 0 || n > 255)) return 'blocked';
  if (a === 127) return 'loopback';
  if (
    a === 0
    || (a === 169 && b === 254)
    || (a === 192 && b === 0 && c === 0)
    || (a === 192 && b === 0 && c === 2)
    || (a === 198 && b === 51 && c === 100)
    || (a === 203 && b === 0 && c === 113)
    || (a === 198 && (b === 18 || b === 19))
    || a >= 224
  ) {
    return 'blocked';
  }
  if (
    a === 10
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168)
    || (a === 100 && b >= 64 && b <= 127)
  ) {
    return 'private';
  }
  return 'public';
}

function parseIpv6Hextets(addr) {
  const zoneIdx = addr.indexOf('%');
  const raw = (zoneIdx >= 0 ? addr.slice(0, zoneIdx) : addr).toLowerCase();
  if (!raw || raw.includes(':::')) return null;

  let working = raw;
  const lastColon = working.lastIndexOf(':');
  if (lastColon !== -1 && working.slice(lastColon + 1).includes('.')) {
    const ipv4Part = working.slice(lastColon + 1);
    if (net.isIP(ipv4Part) !== 4) return null;
    const [a, b, c, d] = ipv4Part.split('.').map(Number);
    const hi = ((a << 8) | b).toString(16);
    const lo = ((c << 8) | d).toString(16);
    working = `${working.slice(0, lastColon)}:${hi}:${lo}`;
  }

  const dblParts = working.split('::');
  if (dblParts.length > 2) return null;
  const parseSide = s => (s ? s.split(':') : []);
  const left = parseSide(dblParts[0]);
  const right = dblParts.length === 2 ? parseSide(dblParts[1]) : [];
  if (dblParts.length === 1 && left.length !== 8) return null;
  if (dblParts.length === 2 && left.length + right.length >= 8) return null;

  const missing = dblParts.length === 2 ? 8 - (left.length + right.length) : 0;
  const full = [...left, ...Array(missing).fill('0'), ...right];
  if (full.length !== 8) return null;

  const hextets = [];
  for (const part of full) {
    if (!/^[0-9a-f]{1,4}$/.test(part)) return null;
    hextets.push(Number.parseInt(part, 16));
  }
  return hextets;
}

export function classifyIpLiteral(hostname) {
  const bare = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  const version = net.isIP(bare);
  if (!version) return 'domain';
  if (version === 4) {
    return classifyIpv4Octets(bare.split('.').map(Number));
  }
  const h = parseIpv6Hextets(bare);
  if (!h) return 'blocked';

  // ::1 loopback and :: unspecified
  const allZeroPrefix = h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0;
  if (allZeroPrefix && h[5] === 0 && h[6] === 0 && h[7] === 1) return 'loopback';
  if (allZeroPrefix && h[5] === 0 && h[6] === 0 && h[7] === 0) return 'blocked';

  // IPv4-mapped (::ffff:0:0/96) and IPv4-compatible (::/96)
  if (allZeroPrefix && (h[5] === 0xffff || h[5] === 0)) {
    return classifyIpv4Octets([h[6] >> 8, h[6] & 0xff, h[7] >> 8, h[7] & 0xff]);
  }
  // NAT64 well-known prefix 64:ff9b::/96 and 64:ff9b:1::/48
  if (h[0] === 0x0064 && h[1] === 0xff9b && ((h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0) || h[2] === 1)) {
    return classifyIpv4Octets([h[6] >> 8, h[6] & 0xff, h[7] >> 8, h[7] & 0xff]);
  }
  // 6to4 (2002::/16) embeds IPv4 in h[1], h[2]
  if (h[0] === 0x2002) {
    return classifyIpv4Octets([h[1] >> 8, h[1] & 0xff, h[2] >> 8, h[2] & 0xff]);
  }
  // Link-local fe80::/10, site-local fec0::/10, multicast ff00::/8, discard 0100::/64, docs 2001:db8::/32
  if (
    (h[0] & 0xffc0) === 0xfe80
    || (h[0] & 0xffc0) === 0xfec0
    || (h[0] & 0xff00) === 0xff00
    || (h[0] === 0x0100 && h[1] === 0 && h[2] === 0 && h[3] === 0)
    || (h[0] === 0x2001 && h[1] === 0x0db8)
  ) {
    return 'blocked';
  }
  // Unique Local fc00::/7
  if ((h[0] & 0xfe00) === 0xfc00) {
    return 'private';
  }
  return 'public';
}

function canonicalOriginKey(parsed) {
  const host = String(parsed.hostname || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  const formattedHost = host.includes(':') ? `[${host}]` : host;
  const port = parsed.port ? `:${parsed.port}` : '';
  return `${parsed.protocol.toLowerCase()}//${formattedHost}${port}`;
}

function normalizeOriginList(blockedOrigins = []) {
  const set = new Set();
  if (!Array.isArray(blockedOrigins)) return set;
  for (const item of blockedOrigins) {
    if (typeof item !== 'string' || !item.trim()) continue;
    try {
      set.add(canonicalOriginKey(new URL(item.trim())));
    } catch {}
  }
  return set;
}

export function assertSafeIntegrationOrigin(
  rawUrl,
  { allowLoopbackHttp = false, allowPrivateNetwork = false, blockedOrigins = [], label = 'integration' } = {},
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

  const blockedSet = normalizeOriginList(blockedOrigins);
  if (blockedSet.has(canonicalOriginKey(parsed))) {
    throw new Error(`${label} origin is in the blockedOrigins exclusion list.`);
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
  if (parsed.protocol === 'http:' && allowLoopbackHttp && (loopback || ipClass === 'loopback')) {
    return parsed.origin;
  }
  throw new Error(`${label} origin must use https:// (or loopback http:// only when allowLoopbackHttp is enabled).`);
}

export function assertSafeEndpointUrl(
  rawUrl,
  { allowLoopbackHttp = false, allowPrivateNetwork = false, blockedOrigins = [], expectedOrigin = null, label = 'endpoint' } = {},
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
    blockedOrigins,
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

export async function assertSafeResolvedHostname(
  urlStr,
  { allowLoopbackHttp = false, allowPrivateNetwork = false, dnsLookup = dns.promises.lookup } = {},
) {
  const parsed = new URL(urlStr);
  const bare = parsed.hostname.replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  if (net.isIP(bare) || isLoopbackHost(bare)) return;
  if (typeof dnsLookup !== 'function') return;
  const records = await dnsLookup(bare, { all: true, verbatim: true });
  if (!Array.isArray(records) || records.length === 0) {
    throw new Error('DNS resolution returned no addresses.');
  }
  for (const rec of records) {
    const cls = classifyIpLiteral(rec?.address);
    if (cls === 'blocked') {
      throw new Error('Resolved DNS address targets a blocked link-local or metadata IP.');
    }
    if (cls === 'loopback' && !allowLoopbackHttp && !allowPrivateNetwork) {
      throw new Error('Resolved DNS address targets a loopback IP.');
    }
    if (cls === 'private' && !allowPrivateNetwork) {
      throw new Error('Resolved DNS address targets a private network IP.');
    }
  }
}

export async function readBoundedText(response, maxBytes = DEFAULT_MAX_RESPONSE_BYTES) {
  const declared = Number(response.headers?.get?.('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) {
    try { await response.body?.cancel?.(); } catch {}
    const err = new Error(`Upstream response exceeded ${maxBytes} byte limit.`);
    err.code = 'UPSTREAM_PAYLOAD_TOO_LARGE';
    throw err;
  }
  if (!response.body || typeof response.body.getReader !== 'function') {
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > maxBytes) {
      const err = new Error(`Upstream response exceeded ${maxBytes} byte limit.`);
      err.code = 'UPSTREAM_PAYLOAD_TOO_LARGE';
      throw err;
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
        const err = new Error(`Upstream response exceeded ${maxBytes} byte limit.`);
        err.code = 'UPSTREAM_PAYLOAD_TOO_LARGE';
        throw err;
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    try { reader.releaseLock(); } catch {}
  }
  return Buffer.concat(chunks, total).toString('utf8');
}

function createPinnedSafeLookup({
  allowLoopbackHttp = false,
  allowPrivateNetwork = false,
  dnsLookup = dns.promises.lookup,
} = {}) {
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
    const bare = String(hostname || '').replace(/^\[|\]$/g, '').replace(/\.+$/, '');
    const wantAll = opts.all === true;
    const directVer = net.isIP(bare);
    if (directVer) {
      const cls = classifyIpLiteral(bare);
      if (cls === 'blocked' || (cls === 'loopback' && !allowLoopbackHttp && !allowPrivateNetwork) || (cls === 'private' && !allowPrivateNetwork)) {
        cb(new Error('Target IP address is blocked by network boundary policy.'));
        return;
      }
      if (wantAll) cb(null, [{ address: bare, family: directVer }]);
      else cb(null, bare, directVer);
      return;
    }
    Promise.resolve(dnsLookup(bare, { all: true, verbatim: true }))
      .then(records => {
        if (!Array.isArray(records) || records.length === 0) {
          cb(new Error('DNS resolution returned no addresses.'));
          return;
        }
        const safe = [];
        for (const rec of records) {
          const cls = classifyIpLiteral(rec?.address);
          if (cls === 'blocked') {
            cb(new Error('Resolved DNS address targets a blocked link-local or metadata IP.'));
            return;
          }
          if (cls === 'loopback' && !allowLoopbackHttp && !allowPrivateNetwork) {
            cb(new Error('Resolved DNS address targets a loopback IP.'));
            return;
          }
          if (cls === 'private' && !allowPrivateNetwork) {
            cb(new Error('Resolved DNS address targets a private network IP.'));
            return;
          }
          safe.push({ address: rec.address, family: rec.family || net.isIP(rec.address) || 4 });
        }
        if (wantAll) cb(null, safe);
        else cb(null, safe[0].address, safe[0].family);
      })
      .catch(err => cb(err));
  };
}

function sendPinnedNodeRequest(
  url,
  {
    method = 'GET',
    headers = {},
    body = undefined,
    maxBytes = DEFAULT_MAX_RESPONSE_BYTES,
    signal,
    allowLoopbackHttp = false,
    allowPrivateNetwork = false,
    dnsLookup = dns.promises.lookup,
  },
) {
  const parsed = new URL(url);
  const isHttps = parsed.protocol === 'https:';
  const reqMod = isHttps ? https : http;
  const bareHost = parsed.hostname.replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  const payloadBuf = body === undefined || body === null
    ? null
    : (Buffer.isBuffer(body) || body instanceof Uint8Array ? Buffer.from(body) : Buffer.from(String(body), 'utf8'));
  const reqHeaders = {};
  if (headers && typeof headers === 'object') {
    for (const [k, v] of Object.entries(headers)) {
      if (v !== undefined) reqHeaders[k] = String(v);
    }
  }
  if (payloadBuf !== null && !Object.keys(reqHeaders).some(k => k.toLowerCase() === 'content-length')) {
    reqHeaders['content-length'] = String(payloadBuf.length);
  }

  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason || new Error('Upstream request was cancelled.'));
      return;
    }
    let settled = false;
    let req = null;
    const done = (err, val) => {
      if (settled) return;
      settled = true;
      if (signal) signal.removeEventListener('abort', onAbort);
      if (err) reject(err);
      else resolve(val);
    };
    const onAbort = () => {
      try { req?.destroy(signal.reason || new Error('Upstream request was cancelled.')); } catch {}
      done(signal.reason || new Error('Upstream request was cancelled.'));
    };
    if (signal) signal.addEventListener('abort', onAbort, { once: true });

    req = reqMod.request(
      {
        protocol: parsed.protocol,
        hostname: bareHost,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method,
        headers: reqHeaders,
        agent: false,
        lookup: createPinnedSafeLookup({ allowLoopbackHttp, allowPrivateNetwork, dnsLookup }),
        ...(isHttps ? { minVersion: 'TLSv1.2' } : {}),
        ...(isHttps && net.isIP(bareHost) === 0 ? { servername: bareHost } : {}),
      },
      res => {
        const status = res.statusCode || 0;
        if (status >= 300 && status < 400) {
          res.destroy();
          done(new Error('HTTP redirects are disabled by network boundary policy.'));
          return;
        }
        const declared = Number(res.headers?.['content-length']);
        if (Number.isFinite(declared) && declared > maxBytes) {
          res.destroy();
          const err = new Error(`Upstream response exceeded ${maxBytes} byte limit.`);
          err.code = 'UPSTREAM_PAYLOAD_TOO_LARGE';
          done(err);
          return;
        }
        const chunks = [];
        let total = 0;
        res.on('data', chunk => {
          if (settled) return;
          total += chunk.length;
          if (total > maxBytes) {
            res.destroy();
            const err = new Error(`Upstream response exceeded ${maxBytes} byte limit.`);
            err.code = 'UPSTREAM_PAYLOAD_TOO_LARGE';
            done(err);
            return;
          }
          chunks.push(chunk);
        });
        res.on('aborted', () => done(new Error('Upstream response stream aborted.')));
        res.on('error', err => done(err));
        res.on('end', () => {
          if (!res.complete) {
            done(new Error('Upstream response stream ended prematurely.'));
            return;
          }
          const respHeaders = new Headers();
          for (const [k, v] of Object.entries(res.headers || {})) {
            if (Array.isArray(v)) {
              for (const item of v) respHeaders.append(k, String(item));
            } else if (v !== undefined) {
              respHeaders.set(k, String(v));
            }
          }
          done(null, {
            ok: status >= 200 && status < 300,
            status,
            headers: respHeaders,
            text: Buffer.concat(chunks, total).toString('utf8'),
          });
        });
      },
    );
    req.on('error', err => done(err));
    if (payloadBuf !== null) req.write(payloadBuf);
    req.end();
  });
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
    signal = null,
    allowLoopbackHttp = false,
    allowPrivateNetwork = false,
    dnsLookup = null,
  } = {},
) {
  if (typeof fetchImpl !== 'function') {
    throw new Error('No fetch implementation available.');
  }
  if (signal?.aborted) {
    const err = new Error('Upstream request was cancelled.');
    err.code = 'UPSTREAM_ABORTED';
    throw err;
  }
  const controller = new AbortController();
  let timedOut = false;
  const onCallerAbort = () => controller.abort(new Error('Upstream request was cancelled.'));
  if (signal) {
    signal.addEventListener('abort', onCallerAbort, { once: true });
  }
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort(new Error(`Request timed out after ${timeoutMs}ms.`));
  }, timeoutMs);
  timer.unref?.();
  const startedAt = Date.now();
  try {
    if (fetchImpl === globalThis.fetch) {
      const effectiveDnsLookup = dnsLookup ?? dns.promises.lookup;
      const result = await sendPinnedNodeRequest(url, {
        method,
        headers,
        body,
        maxBytes,
        signal: controller.signal,
        allowLoopbackHttp,
        allowPrivateNetwork,
        dnsLookup: effectiveDnsLookup,
      });
      return {
        ...result,
        latencyMs: Math.max(0, Date.now() - startedAt),
      };
    }

    if (dnsLookup) {
      await Promise.race([
        assertSafeResolvedHostname(url, {
          allowLoopbackHttp,
          allowPrivateNetwork,
          dnsLookup,
        }),
        new Promise((_resolve, reject) => {
          if (controller.signal.aborted) {
            reject(controller.signal.reason || new Error('Upstream request was aborted.'));
            return;
          }
          controller.signal.addEventListener(
            'abort',
            () => reject(controller.signal.reason || new Error('Upstream request was aborted.')),
            { once: true },
          );
        }),
      ]);
    }
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
    if (error?.code === 'UPSTREAM_PAYLOAD_TOO_LARGE') throw error;
    if (timedOut) {
      const err = new Error(`Upstream request timed out after ${timeoutMs}ms.`);
      err.code = 'UPSTREAM_TIMEOUT';
      throw err;
    }
    if (signal?.aborted || controller.signal.aborted) {
      const err = new Error('Upstream request was cancelled.');
      err.code = 'UPSTREAM_ABORTED';
      throw err;
    }
    const err = new Error(`Upstream request failed (${error?.code || error?.name || 'network_error'}).`);
    err.code = error?.code || 'UPSTREAM_NETWORK_ERROR';
    throw err;
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener('abort', onCallerAbort);
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
