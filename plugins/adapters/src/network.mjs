// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Shared network boundary checks, full 8-hextet IPv6 SSRF classifier, DNS IP check, & bounded JSON/SSE HTTP helpers for standalone project adapters.
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import {
  assertSafeEndpointUrl,
  assertSafeIntegrationOrigin,
  assertSafeTargetUrl,
  classifyIpLiteral,
  isLoopbackHost,
  unsafeTargetUrlError,
} from '@loomward/shared';

export const DEFAULT_MAX_RESPONSE_BYTES = 512 * 1024;
export {
  assertSafeEndpointUrl,
  assertSafeIntegrationOrigin,
  classifyIpLiteral,
};

function validateResolvedRecords(records, { allowLoopbackHttp = false, allowPrivateNetwork = false } = {}) {
  if (!Array.isArray(records) || records.length === 0) {
    throw unsafeTargetUrlError('DNS resolution returned no addresses.');
  }
  const safe = [];
  for (const rec of records) {
    const addr = typeof rec?.address === 'string' ? rec.address.trim() : '';
    const ver = net.isIP(addr.split('%')[0]);
    if (!ver) {
      throw unsafeTargetUrlError('DNS resolution returned an invalid non-IP address.');
    }
    const cls = classifyIpLiteral(addr);
    if (cls === 'blocked' || cls === 'domain') {
      throw unsafeTargetUrlError('Resolved DNS address targets a blocked link-local or metadata IP.');
    }
    if (cls === 'loopback' && !allowLoopbackHttp && !allowPrivateNetwork) {
      throw unsafeTargetUrlError('Resolved DNS address targets a loopback IP.');
    }
    if (cls === 'private' && !allowPrivateNetwork) {
      throw unsafeTargetUrlError('Resolved DNS address targets a private network IP.');
    }
    safe.push({ address: addr, family: rec.family || ver });
  }
  return safe;
}

export async function assertSafeResolvedHostname(
  urlStr,
  { allowLoopbackHttp = false, allowPrivateNetwork = false, dnsLookup = dns.promises.lookup } = {},
) {
  const { bareHost } = assertSafeTargetUrl(urlStr, { allowLoopbackHttp, allowPrivateNetwork });
  if (net.isIP(bareHost) || isLoopbackHost(bareHost)) return;
  if (typeof dnsLookup !== 'function') return;
  const records = await dnsLookup(bareHost, { all: true, verbatim: true });
  validateResolvedRecords(records, { allowLoopbackHttp, allowPrivateNetwork });
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
        const safe = validateResolvedRecords(records, { allowLoopbackHttp, allowPrivateNetwork });
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
  const { parsed, bareHost, isHttps } = assertSafeTargetUrl(url, { allowLoopbackHttp, allowPrivateNetwork });
  const reqMod = isHttps ? https : http;
  const payloadBuf = body === undefined || body === null
    ? null
    : (Buffer.isBuffer(body) || body instanceof Uint8Array ? Buffer.from(body) : Buffer.from(String(body), 'utf8'));
  const reqHeaders = {};
  if (headers) {
    if (Array.isArray(headers)) {
      for (const pair of headers) {
        if (Array.isArray(pair) && pair.length >= 2 && pair[1] !== undefined && pair[1] !== null) {
          reqHeaders[String(pair[0])] = String(pair[1]);
        }
      }
    } else if (typeof headers.entries === 'function') {
      for (const [k, v] of headers.entries()) {
        if (v !== undefined && v !== null) reqHeaders[String(k)] = String(v);
      }
    } else if (typeof headers.forEach === 'function') {
      headers.forEach((v, k) => {
        if (v !== undefined && v !== null) reqHeaders[String(k)] = String(v);
      });
    } else if (typeof headers === 'object') {
      for (const [k, v] of Object.entries(headers)) {
        if (v !== undefined && v !== null) reqHeaders[k] = String(v);
      }
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
    assertSafeTargetUrl(url, { allowLoopbackHttp, allowPrivateNetwork });
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
