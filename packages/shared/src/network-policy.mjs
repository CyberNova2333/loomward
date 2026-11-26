// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Pure zero-Node SSRF IPv4/IPv6 classifier and integration URL validator shared across plugins without cross-plugin imports.

function parseIpv4Octets(bare) {
  if (typeof bare !== 'string' || !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(bare)) return null;
  const parts = bare.split('.');
  const octets = [];
  for (const part of parts) {
    if (part.length > 1 && part.startsWith('0')) return null;
    const num = Number(part);
    if (!Number.isInteger(num) || num < 0 || num > 255) return null;
    octets.push(num);
  }
  return octets;
}

export function classifyIpv4Octets(octets) {
  if (!Array.isArray(octets) || octets.length !== 4) return 'blocked';
  const [a, b, c, d] = octets;
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

export function parseIpv6Hextets(addr) {
  if (typeof addr !== 'string' || !addr.includes(':')) return null;
  const zoneIdx = addr.indexOf('%');
  const raw = (zoneIdx >= 0 ? addr.slice(0, zoneIdx) : addr).toLowerCase();
  if (!raw || raw.includes(':::')) return null;

  let working = raw;
  const lastColon = working.lastIndexOf(':');
  if (lastColon !== -1 && working.slice(lastColon + 1).includes('.')) {
    const ipv4Part = working.slice(lastColon + 1);
    const octets = parseIpv4Octets(ipv4Part);
    if (!octets) return null;
    const [a, b, c, d] = octets;
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

export function isIpLiteralVersion(hostname) {
  const bare = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  if (!bare) return 0;
  if (parseIpv4Octets(bare)) return 4;
  return parseIpv6Hextets(bare) ? 6 : 0;
}

export function isLoopbackHost(hostname) {
  const lower = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  if (lower === 'localhost' || lower === '::1') return true;
  if (/^127\.(?:\d{1,3}\.){2}\d{1,3}$/.test(lower)) return Boolean(parseIpv4Octets(lower));
  return false;
}

export function classifyIpLiteral(hostname) {
  const bare = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  const ipv4 = parseIpv4Octets(bare);
  if (ipv4) {
    return classifyIpv4Octets(ipv4);
  }
  if (!bare.includes(':')) return 'domain';
  const h = parseIpv6Hextets(bare);
  if (!h) return 'blocked';

  const allZeroPrefix = h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0;
  if (allZeroPrefix && h[5] === 0 && h[6] === 0 && h[7] === 1) return 'loopback';
  if (allZeroPrefix && h[5] === 0 && h[6] === 0 && h[7] === 0) return 'blocked';

  if (allZeroPrefix && (h[5] === 0xffff || h[5] === 0)) {
    return classifyIpv4Octets([h[6] >> 8, h[6] & 0xff, h[7] >> 8, h[7] & 0xff]);
  }
  if (h[0] === 0x0064 && h[1] === 0xff9b && ((h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0) || h[2] === 1)) {
    return classifyIpv4Octets([h[6] >> 8, h[6] & 0xff, h[7] >> 8, h[7] & 0xff]);
  }
  if (h[0] === 0x2002) {
    return classifyIpv4Octets([h[1] >> 8, h[1] & 0xff, h[2] >> 8, h[2] & 0xff]);
  }
  if (
    (h[0] & 0xffc0) === 0xfe80
    || (h[0] & 0xffc0) === 0xfec0
    || (h[0] & 0xff00) === 0xff00
    || (h[0] === 0x0100 && h[1] === 0 && h[2] === 0 && h[3] === 0)
    || (h[0] === 0x2001 && h[1] === 0x0db8)
  ) {
    return 'blocked';
  }
  if ((h[0] & 0xfe00) === 0xfc00) {
    return 'private';
  }
  return 'public';
}

export function canonicalOriginKey(parsed) {
  const host = String(parsed.hostname || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  const formattedHost = host.includes(':') ? `[${host}]` : host;
  const port = parsed.port ? `:${parsed.port}` : '';
  return `${parsed.protocol.toLowerCase()}//${formattedHost}${port}`;
}

export function assertValidHostname(rawHostname, label = 'integration') {
  const rawBare = String(rawHostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  const bareHost = rawBare.replace(/\.+$/, '');
  if (!bareHost || rawBare.includes('..')) {
    throw new Error(`Invalid ${label} target hostname.`);
  }
  return bareHost;
}

export function normalizeOriginList(blockedOrigins = []) {
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

export function unsafeTargetUrlError(message) {
  const err = new Error(message);
  err.code = 'UNSAFE_TARGET_URL';
  return err;
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

  const bareHost = assertValidHostname(parsed.hostname, label);
  const blockedSet = normalizeOriginList(blockedOrigins);
  if (blockedSet.has(canonicalOriginKey(parsed))) {
    throw new Error(`${label} origin is in the blockedOrigins exclusion list.`);
  }

  const loopback = isLoopbackHost(bareHost);
  const ipClass = classifyIpLiteral(bareHost);
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
  if (parsed.protocol === 'http:') {
    if ((allowLoopbackHttp || allowPrivateNetwork) && (loopback || ipClass === 'loopback')) {
      return parsed.origin;
    }
    if (allowPrivateNetwork && (ipClass === 'private' || ipClass === 'domain')) {
      return parsed.origin;
    }
  }
  throw new Error(`${label} origin must use https:// (or loopback/authorized-private http:// only).`);
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

export function assertSafeTargetUrl(urlStr, { allowLoopbackHttp = false, allowPrivateNetwork = false, blockedOrigins = [] } = {}) {
  const parsed = new URL(urlStr);
  const proto = parsed.protocol.toLowerCase();
  if (proto !== 'https:' && proto !== 'http:') {
    throw unsafeTargetUrlError('Upstream request only permits http:// or https:// protocols.');
  }
  if (parsed.username || parsed.password) {
    throw unsafeTargetUrlError('Upstream request URL must not embed credentials.');
  }
  const bareHost = assertValidHostname(parsed.hostname, 'request');
  const blockedSet = normalizeOriginList(blockedOrigins);
  if (blockedSet.has(canonicalOriginKey(parsed))) {
    throw unsafeTargetUrlError('Target origin is in the blockedOrigins exclusion list.');
  }
  const loopback = isLoopbackHost(bareHost);
  const cls = classifyIpLiteral(bareHost);
  if (cls === 'blocked') {
    throw unsafeTargetUrlError('Target IP address is blocked by network boundary policy.');
  }
  if (cls === 'loopback' && !allowLoopbackHttp && !allowPrivateNetwork) {
    throw unsafeTargetUrlError('Target IP address is blocked by network boundary policy.');
  }
  if (cls === 'private' && !allowPrivateNetwork) {
    throw unsafeTargetUrlError('Target IP address is blocked by network boundary policy.');
  }
  if (proto === 'http:') {
    const httpLoopbackOk = (allowLoopbackHttp || allowPrivateNetwork) && (loopback || cls === 'loopback');
    const httpPrivateOk = allowPrivateNetwork && (cls === 'private' || cls === 'domain');
    if (!httpLoopbackOk && !httpPrivateOk) {
      throw unsafeTargetUrlError('Upstream plaintext http:// is permitted only for loopback or explicitly authorized private network targets.');
    }
  }
  return { parsed, bareHost, ipClass: cls, isLoopback: loopback, isHttps: proto === 'https:' };
}
