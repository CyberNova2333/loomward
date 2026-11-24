// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  assertConfigOutsideWorkspace,
  hasSymlinkComponent,
  loadWorkspaceRootsFromStateConfig,
  resolveRealPathAllowMissingLeaf,
} from './capabilities.mjs';
import { beneath } from './file-safety.mjs';
import { assertPrivateState } from './host-safety.mjs';
import { EXTERNAL_TOOL_NAME } from './request-policy.mjs';

export const MCP_SERVERS_FILE = 'mcp-servers.json';
export const MAX_MCP_SERVERS = 32;
export const MAX_CACHED_TOOLS_PER_SERVER = 200;
export const MAX_MCP_FILE_BYTES = 2 * 1024 * 1024;
export const MAX_TOOL_SCHEMA_BYTES = 16384;
export const MAX_TOOL_PROPERTIES = 64;
export const SERVER_ID_RE = /^[a-z0-9](?:(?:_(?!_)|[a-z0-9-]){0,30}[a-z0-9-])?$/;
export const RAW_TOOL_NAME_RE = /^[A-Za-z0-9_.-]{1,64}$/;
export const EXTERNAL_TOOL_NAME_RE = EXTERNAL_TOOL_NAME;

const ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const HEADER_KEY_RE = /^[A-Za-z0-9-]{1,64}$/;
const HEADER_VALUE_RE = /^[\t\x20-\x7e]*$/;
const PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export const FORBIDDEN_ENV_KEYS = new Set([
  'NODE_OPTIONS',
  'NODE_PATH',
  'NODE_TLS_REJECT_UNAUTHORIZED',
  'NODE_EXTRA_CA_CERTS',
  'NODE_USE_ENV_PROXY',
  'ELECTRON_RUN_AS_NODE',
  'LD_PRELOAD',
  'LD_LIBRARY_PATH',
  'LD_AUDIT',
  'LD_DEBUG',
  'LD_DEBUG_OUTPUT',
  'GCONV_PATH',
  'GLIBC_TUNABLES',
  'DYLD_INSERT_LIBRARIES',
  'DYLD_LIBRARY_PATH',
  'DYLD_FRAMEWORK_PATH',
  'DYLD_FORCE_FLAT_NAMESPACE',
  'DYLD_FALLBACK_LIBRARY_PATH',
  'DYLD_FALLBACK_FRAMEWORK_PATH',
  'BASH_ENV',
  'ENV',
  'ZDOTDIR',
  'PYTHONSTARTUP',
  'PYTHONPATH',
  'PYTHONHOME',
  'JAVA_TOOL_OPTIONS',
  '_JAVA_OPTIONS',
  'JDK_JAVA_OPTIONS',
  'RUBYOPT',
  'PERL5OPT',
  'DOTNET_STARTUP_HOOKS',
  'DBUS_SESSION_BUS_ADDRESS',
  'SSH_AUTH_SOCK',
  'DOCKER_HOST',
  'DOCKER_CONTEXT',
  'AGENTDOCK_BRIDGE_TOKEN',
  'AGENTDOCK_OWNER_PASSWORD',
]);

const FORBIDDEN_HEADERS = new Set([
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

export function mcpServersFilePath(stateDir) {
  return path.join(path.resolve(stateDir), MCP_SERVERS_FILE);
}

export function isForbiddenEnvKey(key) {
  const upper = String(key || '').toUpperCase();
  return (
    FORBIDDEN_ENV_KEYS.has(upper) ||
    upper.startsWith('AGENTDOCK_') ||
    upper.startsWith('LD_') ||
    upper.startsWith('DYLD_')
  );
}

export function sanitizeMetadataText(value, maxLength = 512) {
  if (typeof value !== 'string') return '';
  const wellFormed = value.isWellFormed() ? value : value.toWellFormed();
  const sliced = wellFormed
    .replace(/[\p{Cc}\p{Cf}\u2028\u2029\u{e0000}-\u{e007f}]/gu, ch => (ch === '\n' || ch === '\t' ? ' ' : ''))
    .slice(0, maxLength);
  return sliced.isWellFormed() ? sliced : sliced.toWellFormed();
}

export function redactSecretsFromText(text, serverConfig = null, maxLength = 512) {
  // Redact on a larger pre-truncation window so secrets straddling maxLength are never partially leaked.
  let out = String(text || '').slice(0, 8192);
  if (serverConfig && typeof serverConfig === 'object') {
    const secretSet = new Set();
    const addSecret = candidate => {
      if (typeof candidate === 'string' && candidate.length >= 4) secretSet.add(candidate);
    };
    for (const v of Object.values(serverConfig.env || {})) addSecret(v);
    for (const v of Object.values(serverConfig.headers || {})) {
      addSecret(v);
      if (typeof v === 'string') {
        const sub = /^\S+\s+(\S{4,})$/.exec(v.trim());
        if (sub) addSecret(sub[1]);
      }
    }
    if (typeof serverConfig.url === 'string' && serverConfig.url) {
      try {
        const parsed = new URL(serverConfig.url);
        if (parsed.search && parsed.search.length > 1) {
          for (const seg of parsed.search.slice(1).split('&')) {
            if (!seg) continue;
            const eq = seg.indexOf('=');
            const rawSecret = eq >= 0 ? seg.slice(eq + 1) : seg;
            addSecret(rawSecret);
            try {
              const decoded = decodeURIComponent(rawSecret.replaceAll('+', ' '));
              addSecret(decoded);
              addSecret(encodeURIComponent(decoded));
            } catch {}
          }
        }
        for (const [, val] of parsed.searchParams) {
          addSecret(val);
          try { addSecret(encodeURIComponent(val)); } catch {}
        }
        if (parsed.hash && parsed.hash.length > 1) {
          const rawHash = parsed.hash.slice(1);
          addSecret(rawHash);
          try { addSecret(decodeURIComponent(rawHash)); } catch {}
        }
      } catch {}
    }
    const secretVals = [...secretSet].sort((a, b) => b.length - a.length);
    for (const secret of secretVals) {
      out = out.replaceAll(secret, '[REDACTED]');
    }
  }
  out = out.replace(/\b(Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{6,}/gi, '$1 [REDACTED]');
  out = out.replace(/([?&](?:api[_-]?key|token|secret|key|auth|password|access_token|sig|jwt|pat|credential|client_secret)=)[^&#\s]+/gi, '$1[REDACTED]');
  return sanitizeMetadataText(out, maxLength);
}

export function redactUrlForDisplay(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return '';
  try {
    const parsed = new URL(rawUrl);
    if (parsed.search && parsed.search.length > 1) {
      const redactedSegs = parsed.search
        .slice(1)
        .split('&')
        .filter(Boolean)
        .map(seg => {
          const eq = seg.indexOf('=');
          if (eq >= 0) {
            return `${seg.slice(0, eq)}=%5BREDACTED%5D`;
          }
          return '%5BREDACTED%5D';
        });
      parsed.search = redactedSegs.length ? `?${redactedSegs.join('&')}` : '';
    }
    if (parsed.hash && parsed.hash.length > 1) {
      parsed.hash = '#[REDACTED]';
    }
    return parsed.toString();
  } catch {
    return '';
  }
}

export function formatExternalToolName(serverId, toolName) {
  if (!SERVER_ID_RE.test(String(serverId || '')) || !RAW_TOOL_NAME_RE.test(String(toolName || ''))) {
    throw new Error('Invalid external MCP server ID or tool name.');
  }
  return `mcp__${serverId}__${toolName}`;
}

export function parseExternalToolName(fullName) {
  if (typeof fullName !== 'string') return null;
  const match = EXTERNAL_TOOL_NAME_RE.exec(fullName);
  if (!match) return null;
  return { serverId: match[1], toolName: match[2] };
}

export function isValidExternalToolName(fullName) {
  return parseExternalToolName(fullName) !== null;
}

export function slugifyServerId(raw) {
  const normalized = String(raw || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/_+/g, '_')
    .replace(/^[^a-z0-9]+/, '')
    .replace(/-+/g, '-')
    .slice(0, 32)
    .replace(/_+$/, '');
  return SERVER_ID_RE.test(normalized) ? normalized : '';
}

function assertCleanString(value, field, { maxLength = 2048, allowEmpty = false, allowNewlines = false } = {}) {
  if (typeof value !== 'string') throw new Error(`${field} must be a string.`);
  if (!value.isWellFormed()) throw new Error(`${field} contains invalid Unicode.`);
  if (value.includes('\0')) throw new Error(`${field} must not contain NUL bytes.`);
  if (!allowNewlines && /[\r\n]/.test(value)) throw new Error(`${field} must not contain line breaks.`);
  if (!allowEmpty && !value.trim()) throw new Error(`${field} cannot be empty.`);
  if (value.length > maxLength) throw new Error(`${field} exceeds maximum length (${maxLength}).`);
  return value;
}

function stripTrailingDots(hostname) {
  return String(hostname || '').toLowerCase().replace(/\.+$/, '');
}

function isIpv4Blocked(ip, { allowLoopback127 = false } = {}) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b, c, d] = parts;
  if (a === 0) return true; // 0.0.0.0/8 unspecified
  if (a === 10) return true; // 10.0.0.0/8 private
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT / cloud metadata (e.g. 100.100.100.200)
  if (a === 127) {
    return !(allowLoopback127 && b === 0 && c === 0 && d === 1);
  }
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local / cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 private
  if (a === 192 && b === 0 && c === 0) return true; // 192.0.0.0/24 IETF protocol assignments
  if (a === 192 && b === 168) return true; // 192.168.0.0/16 private
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 benchmarking
  if (a >= 224) return true; // 224.0.0.0/4 multicast & 240.0.0.0/4 reserved/broadcast
  return false;
}

function parseIpv6Hextets(rawIp) {
  let addr = rawIp;
  // Convert trailing embedded IPv4 dotted-quad into two 16-bit hextets.
  const lastColon = addr.lastIndexOf(':');
  if (lastColon !== -1 && addr.slice(lastColon + 1).includes('.')) {
    const v4 = addr.slice(lastColon + 1);
    if (net.isIP(v4) !== 4) return null;
    const octets = v4.split('.').map(Number);
    const hi = ((octets[0] << 8) | octets[1]).toString(16);
    const lo = ((octets[2] << 8) | octets[3]).toString(16);
    addr = `${addr.slice(0, lastColon + 1)}${hi}:${lo}`;
  }
  const halves = addr.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  if (halves.length === 1 && left.length !== 8) return null;
  const missing = 8 - (left.length + right.length);
  if (missing < 0 || (halves.length === 2 && missing === 0)) return null;
  const full = [...left, ...Array(missing).fill('0'), ...right];
  if (full.length !== 8) return null;
  const out = new Uint16Array(8);
  for (let i = 0; i < 8; i++) {
    if (!/^[0-9a-f]{1,4}$/i.test(full[i])) return null;
    out[i] = parseInt(full[i], 16);
  }
  return out;
}

function hextetsToIpv4(hi, lo) {
  return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
}

export function isBlockedIpAddress(rawIp, { allowLoopback127 = false } = {}) {
  const ip = String(rawIp || '').trim().toLowerCase().replace(/^\[|\]$/g, '').split('%')[0];
  const ver = net.isIP(ip);
  if (ver === 4) return isIpv4Blocked(ip, { allowLoopback127 });
  if (ver === 6) {
    const h = parseIpv6Hextets(ip);
    if (!h) return true;
    const isZero = (start, end) => {
      for (let i = start; i < end; i++) if (h[i] !== 0) return false;
      return true;
    };
    if (isZero(0, 8)) return true; // ::/128 unspecified
    if (isZero(0, 7) && h[7] === 1) return !allowLoopback127; // ::1/128 loopback
    if ((h[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
    if ((h[0] & 0xffc0) === 0xfec0) return true; // fec0::/10 deprecated site-local
    if ((h[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 ULA
    if ((h[0] & 0xff00) === 0xff00) return true; // ff00::/8 multicast
    if (h[0] === 0x0100 && isZero(1, 4)) return true; // 100::/64 discard-only
    // IPv4-mapped (::ffff:0:0/96), IPv4-translated (::ffff:0:0:0/96), IPv4-compatible (::/96)
    if (isZero(0, 5) && h[5] === 0xffff) return isIpv4Blocked(hextetsToIpv4(h[6], h[7]), { allowLoopback127: false });
    if (isZero(0, 4) && h[4] === 0xffff && h[5] === 0) return isIpv4Blocked(hextetsToIpv4(h[6], h[7]), { allowLoopback127: false });
    if (isZero(0, 6)) return isIpv4Blocked(hextetsToIpv4(h[6], h[7]), { allowLoopback127: false });
    // NAT64 well-known prefix (64:ff9b::/96) & local-use NAT64 (64:ff9b:1::/48)
    if (h[0] === 0x0064 && h[1] === 0xff9b && isZero(2, 6)) return isIpv4Blocked(hextetsToIpv4(h[6], h[7]), { allowLoopback127: false });
    if (h[0] === 0x0064 && h[1] === 0xff9b && h[2] === 0x0001) return true;
    // 6to4 (2002::/16) embeds IPv4 in hextets 1 and 2
    if (h[0] === 0x2002) return isIpv4Blocked(hextetsToIpv4(h[1], h[2]), { allowLoopback127: false });
    return false;
  }
  return false;
}

export function assertSafeMcpHttpUrl(rawUrl, { blockedOrigins = [] } = {}) {
  if (typeof rawUrl !== 'string') throw new Error('HTTP MCP server URL must be a string.');
  const cleaned = assertCleanString(rawUrl.trim(), 'url', { maxLength: 2048 });
  let parsed;
  try {
    parsed = new URL(cleaned);
  } catch {
    throw new Error('HTTP MCP server URL is not a valid URL.');
  }
  const rawHostLower = parsed.hostname.toLowerCase();
  const hostname = stripTrailingDots(rawHostLower);
  const rawBareHost = hostname.replace(/^\[|\]$/g, '');
  const isLoopbackName = hostname === '127.0.0.1' || hostname === 'localhost' || hostname === '[::1]';
  if (isLoopbackName && rawHostLower.endsWith('.')) {
    throw new Error('HTTP MCP server loopback host must not contain trailing dots.');
  }
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLoopbackName)) {
    throw new Error('HTTP MCP server URL must use https:// (http:// is only permitted on localhost/127.0.0.1/[::1]).');
  }
  if (parsed.protocol === 'https:' && isLoopbackName) {
    throw new Error('HTTP MCP server URL targets a blocked or reserved IP address.');
  }
  if (parsed.username || parsed.password) {
    throw new Error('HTTP MCP server URL must not embed credentials; pass tokens via custom headers instead.');
  }
  if (net.isIP(rawBareHost)) {
    const allowLoopback = parsed.protocol === 'http:' && (rawBareHost === '127.0.0.1' || rawBareHost === '::1');
    if (isBlockedIpAddress(rawBareHost, { allowLoopback127: allowLoopback })) {
      throw new Error('HTTP MCP server URL targets a blocked or reserved IP address.');
    }
  }
  const pPort = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
  for (const blocked of blockedOrigins) {
    if (!blocked) continue;
    try {
      const b = new URL(blocked);
      const bHost = stripTrailingDots(b.hostname);
      const bPort = b.port || (b.protocol === 'https:' ? '443' : '80');
      const bLoopback = bHost === '127.0.0.1' || bHost === 'localhost' || bHost === '[::1]';
      const sameHostAndPort = bHost === hostname && bPort === pPort;
      const bothLoopbackSamePort = bLoopback && isLoopbackName && bPort === pPort;
      if (sameHostAndPort || bothLoopbackSamePort) {
        throw new Error('HTTP MCP server URL cannot target AgentDock itself.');
      }
    } catch (err) {
      if (err?.message?.includes('cannot target AgentDock')) throw err;
    }
  }
  return parsed.toString();
}

export function assertSafeStdioCwd(rawCwd, stateDir) {
  if (typeof rawCwd !== 'string') throw new Error('cwd must be a string.');
  const cwd = assertCleanString(rawCwd.trim(), 'cwd', { maxLength: 1024 });
  if (cwd.startsWith('\\\\') || (process.platform === 'win32' && cwd.startsWith('//'))) {
    throw new Error('MCP server cwd must not use UNC or device-namespace paths.');
  }
  if (!path.isAbsolute(cwd)) {
    throw new Error('MCP server cwd must be an absolute path.');
  }
  if (hasSymlinkComponent(cwd)) {
    throw new Error('MCP server cwd must not traverse symbolic links.');
  }
  const resolvedCwd = resolveRealPathAllowMissingLeaf(cwd);
  if (stateDir) {
    const resolvedState = resolveRealPathAllowMissingLeaf(stateDir);
    if (beneath(resolvedCwd, resolvedState) || beneath(resolvedState, resolvedCwd)) {
      throw new Error('MCP server cwd cannot overlap the protected AgentDock state directory.');
    }
  }
  return resolvedCwd;
}

function normalizeEnvMap(rawEnv, existingEnv = {}, { removeKeys = [], replaceAll = false } = {}) {
  const next = Object.create(null);
  if (!replaceAll && existingEnv && typeof existingEnv === 'object') {
    for (const [k, v] of Object.entries(existingEnv)) {
      if (!PROTO_KEYS.has(k) && ENV_KEY_RE.test(k) && !isForbiddenEnvKey(k) && typeof v === 'string') {
        next[k] = v;
      }
    }
  }
  if (Array.isArray(removeKeys)) {
    for (const key of removeKeys) {
      if (typeof key === 'string' && !PROTO_KEYS.has(key)) delete next[key];
    }
  }
  if (rawEnv !== undefined && rawEnv !== null) {
    if (typeof rawEnv !== 'object' || Array.isArray(rawEnv)) {
      throw new Error('env must be a key-value object.');
    }
    for (const [k, v] of Object.entries(rawEnv)) {
      const key = String(k).trim();
      if (PROTO_KEYS.has(key) || !ENV_KEY_RE.test(key)) {
        throw new Error(`Invalid environment variable name: ${key}`);
      }
      if (isForbiddenEnvKey(key)) {
        throw new Error(`Environment variable "${key}" is blocked for host safety.`);
      }
      if (v === null || v === undefined) {
        delete next[key];
        continue;
      }
      if (typeof v !== 'string') throw new Error(`env.${key} must be a string.`);
      next[key] = assertCleanString(v, `env.${key}`, { maxLength: 8192, allowEmpty: true, allowNewlines: false });
    }
  }
  if (Object.keys(next).length > 64) {
    throw new Error('At most 64 environment variables may be configured per MCP server.');
  }
  return { ...next };
}

function normalizeHeadersMap(rawHeaders, existingHeaders = {}, { removeKeys = [], replaceAll = false } = {}) {
  const next = Object.create(null);
  if (!replaceAll && existingHeaders && typeof existingHeaders === 'object') {
    for (const [k, v] of Object.entries(existingHeaders)) {
      if (!PROTO_KEYS.has(k) && HEADER_KEY_RE.test(k) && !FORBIDDEN_HEADERS.has(k.toLowerCase()) && typeof v === 'string') {
        next[k] = v;
      }
    }
  }
  if (Array.isArray(removeKeys)) {
    for (const key of removeKeys) {
      if (typeof key === 'string') {
        const lower = key.toLowerCase();
        for (const existingKey of Object.keys(next)) {
          if (existingKey.toLowerCase() === lower) delete next[existingKey];
        }
      }
    }
  }
  if (rawHeaders !== undefined && rawHeaders !== null) {
    if (typeof rawHeaders !== 'object' || Array.isArray(rawHeaders)) {
      throw new Error('headers must be a key-value object.');
    }
    for (const [k, v] of Object.entries(rawHeaders)) {
      const key = String(k).trim();
      if (PROTO_KEYS.has(key) || !HEADER_KEY_RE.test(key)) {
        throw new Error(`Invalid HTTP header name: ${key}`);
      }
      if (FORBIDDEN_HEADERS.has(key.toLowerCase())) {
        throw new Error(`HTTP header "${key}" is reserved and cannot be overridden.`);
      }
      if (v === null || v === undefined) {
        for (const existingKey of Object.keys(next)) {
          if (existingKey.toLowerCase() === key.toLowerCase()) delete next[existingKey];
        }
        continue;
      }
      if (typeof v !== 'string') throw new Error(`headers.${key} must be a string.`);
      const val = assertCleanString(v, `headers.${key}`, { maxLength: 8192, allowEmpty: true, allowNewlines: false });
      if (!HEADER_VALUE_RE.test(val)) {
        throw new Error(`headers.${key} must contain only printable ASCII characters.`);
      }
      for (const existingKey of Object.keys(next)) {
        if (existingKey.toLowerCase() === key.toLowerCase() && existingKey !== key) delete next[existingKey];
      }
      next[key] = val;
    }
  }
  if (Object.keys(next).length > 32) {
    throw new Error('At most 32 custom HTTP headers may be configured per MCP server.');
  }
  return { ...next };
}

const ALLOWED_SCHEMA_TYPES = new Set(['string', 'number', 'integer', 'boolean', 'array', 'object']);

function sanitizeArrayItemsSchema(rawItems) {
  if (!rawItems || typeof rawItems !== 'object' || Array.isArray(rawItems)) {
    return { type: 'string' };
  }
  const itemType = typeof rawItems.type === 'string' && ALLOWED_SCHEMA_TYPES.has(rawItems.type)
    ? rawItems.type
    : 'string';
  const out = { type: itemType };
  if (typeof rawItems.description === 'string' && rawItems.description) {
    out.description = sanitizeMetadataText(rawItems.description, 256);
  }
  if (itemType === 'array') {
    out.items = { type: 'string' };
  }
  return out;
}

function sanitizeInputSchema(rawSchema) {
  const fallback = { type: 'object', properties: {}, required: [] };
  if (!rawSchema || typeof rawSchema !== 'object' || Array.isArray(rawSchema)) return fallback;
  try {
    const serialized = JSON.stringify(rawSchema);
    if (!serialized || Buffer.byteLength(serialized, 'utf8') > MAX_TOOL_SCHEMA_BYTES) return fallback;
  } catch {
    return fallback;
  }
  const cleanProps = Object.create(null);
  const rawProps = rawSchema.properties;
  if (rawProps && typeof rawProps === 'object' && !Array.isArray(rawProps)) {
    let count = 0;
    for (const [propName, propDef] of Object.entries(rawProps)) {
      if (count >= MAX_TOOL_PROPERTIES) break;
      if (PROTO_KEYS.has(propName) || !propName || propName.length > 128) continue;
      if (sanitizeMetadataText(propName, 128) !== propName) continue;
      if (!propDef || typeof propDef !== 'object' || Array.isArray(propDef)) continue;
      const propType = typeof propDef.type === 'string' && ALLOWED_SCHEMA_TYPES.has(propDef.type)
        ? propDef.type
        : 'string';
      const entry = { type: propType };
      if (typeof propDef.description === 'string' && propDef.description) {
        entry.description = sanitizeMetadataText(propDef.description, 512);
      }
      if (Array.isArray(propDef.enum) && propDef.enum.length <= 32) {
        const cleanEnum = [];
        const seenEnum = new Set();
        for (const v of propDef.enum) {
          let cleanVal = null;
          if (typeof v === 'string') cleanVal = sanitizeMetadataText(v, 160);
          else if (typeof v === 'number' && Number.isFinite(v)) cleanVal = v;
          else if (typeof v === 'boolean') cleanVal = v;
          if (cleanVal !== null && !seenEnum.has(cleanVal)) {
            seenEnum.add(cleanVal);
            cleanEnum.push(cleanVal);
          }
        }
        if (cleanEnum.length > 0) entry.enum = cleanEnum;
      }
      if (Number.isFinite(propDef.minimum)) entry.minimum = propDef.minimum;
      if (Number.isFinite(propDef.maximum)) entry.maximum = propDef.maximum;
      if (propType === 'array') {
        entry.items = sanitizeArrayItemsSchema(propDef.items);
      }
      cleanProps[propName] = entry;
      count += 1;
    }
  }
  const required = Array.isArray(rawSchema.required)
    ? [...new Set(rawSchema.required.filter(r => typeof r === 'string' && Object.hasOwn(cleanProps, r)))]
    : [];
  return {
    type: 'object',
    properties: { ...cleanProps },
    required,
    ...(rawSchema.additionalProperties === false ? { additionalProperties: false } : {}),
  };
}

export function normalizeCachedTool(rawTool) {
  if (!rawTool || typeof rawTool !== 'object' || Array.isArray(rawTool)) return null;
  if (typeof rawTool.name !== 'string' || !RAW_TOOL_NAME_RE.test(rawTool.name)) return null;
  const description = typeof rawTool.description === 'string'
    ? sanitizeMetadataText(rawTool.description, 2048)
    : '';
  const title = typeof rawTool.title === 'string'
    ? sanitizeMetadataText(rawTool.title, 160)
    : '';
  return {
    name: rawTool.name,
    ...(title ? { title } : {}),
    description,
    inputSchema: sanitizeInputSchema(rawTool.inputSchema),
    // Never trust external servers to self-declare readOnly/idempotent/non-destructive hints.
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
  };
}

function normalizeServerInfo(rawInfo) {
  if (!rawInfo || typeof rawInfo !== 'object' || Array.isArray(rawInfo)) return null;
  const name = typeof rawInfo.name === 'string' ? sanitizeMetadataText(rawInfo.name, 120) : '';
  const version = typeof rawInfo.version === 'string' ? sanitizeMetadataText(rawInfo.version, 64) : '';
  return name || version ? { name: name || 'MCP Server', version } : null;
}

function normalizeCachedToolsList(rawList) {
  if (!Array.isArray(rawList)) return [];
  const seen = new Set();
  const out = [];
  for (const item of rawList) {
    const clean = normalizeCachedTool(item);
    if (!clean || seen.has(clean.name)) continue;
    seen.add(clean.name);
    out.push(clean);
    if (out.length >= MAX_CACHED_TOOLS_PER_SERVER) break;
  }
  return out;
}

function validateServerEntry(
  raw,
  { stateDir, existing = null, blockedOrigins = [], replaceSecrets = false, allowProbeMetadata = false } = {},
) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('MCP server definition must be an object.');
  }
  if (typeof raw.id !== 'string') {
    throw new Error('Server ID must be a string.');
  }
  const id = raw.id.trim();
  if (!SERVER_ID_RE.test(id)) {
    throw new Error('Server ID must start with a-z/0-9, end with a-z/0-9/-, contain no "__", and be <= 32 chars.');
  }
  const rawName = raw.name === undefined ? id : raw.name;
  if (typeof rawName !== 'string') throw new Error('name must be a string.');
  const name = assertCleanString(rawName.trim(), 'name', { maxLength: 80 });
  const rawDesc = raw.description === undefined ? '' : raw.description;
  if (typeof rawDesc !== 'string') throw new Error('description must be a string.');
  const description = rawDesc.trim()
    ? assertCleanString(rawDesc.trim(), 'description', { maxLength: 240, allowEmpty: true })
    : '';

  if (typeof raw.transport !== 'string') throw new Error('Transport must be "stdio" or "http".');
  const rawTransport = raw.transport.trim().toLowerCase();
  const transport = (rawTransport === 'streamable-http' || rawTransport === 'streamablehttp' || rawTransport === 'http')
    ? 'http'
    : rawTransport === 'stdio'
      ? 'stdio'
      : '';
  if (!transport) throw new Error('Transport must be "stdio" or "http".');

  const enabled = raw.enabled === undefined ? (existing ? existing.enabled : true) : Boolean(raw.enabled);
  const timeoutRaw = raw.timeoutMs === undefined ? (existing?.timeoutMs ?? 30000) : Number(raw.timeoutMs);
  if (!Number.isSafeInteger(timeoutRaw) || timeoutRaw < 3000 || timeoutRaw > 100000) {
    throw new Error('timeoutMs must be an integer between 3000 and 100000.');
  }

  let command = '';
  let args = [];
  let cwd = '';
  let env = {};
  let url = '';
  let headers = {};
  let endpointChanged = !existing || existing.transport !== transport;

  const removeEnvKeys = Array.isArray(raw.removeEnvKeys) ? raw.removeEnvKeys : [];
  const removeHeaderKeys = Array.isArray(raw.removeHeaderKeys) ? raw.removeHeaderKeys : [];

  if (transport === 'stdio') {
    if (typeof raw.command !== 'string') throw new Error('command must be a string.');
    command = assertCleanString(raw.command.trim(), 'command', { maxLength: 512 });
    const rawArgs = raw.args === undefined ? (existing?.transport === 'stdio' ? existing.args : []) : raw.args;
    if (!Array.isArray(rawArgs) || rawArgs.length > 64) {
      throw new Error('args must be an array of at most 64 strings.');
    }
    args = rawArgs.map((item, idx) => {
      if (typeof item !== 'string') throw new Error(`args[${idx}] must be a string.`);
      return assertCleanString(item, `args[${idx}]`, { maxLength: 2048, allowEmpty: true, allowNewlines: true });
    });
    const rawCwd = raw.cwd === undefined ? (existing?.transport === 'stdio' ? (existing.cwd || '') : '') : raw.cwd;
    if (rawCwd !== undefined && rawCwd !== '') {
      cwd = assertSafeStdioCwd(rawCwd, stateDir);
    }
    const existingEnv = existing?.transport === 'stdio' ? existing.env : {};
    const cmdOrArgsChanged = existing?.transport === 'stdio' && (
      command !== existing.command ||
      JSON.stringify(args) !== JSON.stringify(existing.args) ||
      cwd !== (existing.cwd || '')
    );
    if (cmdOrArgsChanged) endpointChanged = true;
    const hasRetainedSecrets = Object.keys(existingEnv || {}).some(k => !removeEnvKeys.includes(k));
    if (cmdOrArgsChanged && hasRetainedSecrets && !replaceSecrets) {
      throw new Error('Changing command, args, or cwd while environment secrets are saved requires clearing or re-entering secrets (replaceSecrets: true).');
    }
    env = normalizeEnvMap(raw.env, cmdOrArgsChanged ? {} : existingEnv, {
      removeKeys: removeEnvKeys,
      replaceAll: replaceSecrets,
    });
  } else {
    const rawUrl = raw.url === undefined && existing?.transport === 'http' ? existing.url : raw.url;
    url = assertSafeMcpHttpUrl(rawUrl, { blockedOrigins });
    const existingHeaders = existing?.transport === 'http' ? existing.headers : {};
    let originChanged = false;
    if (existing?.transport === 'http' && existing.url) {
      try {
        originChanged = new URL(url).origin.toLowerCase() !== new URL(existing.url).origin.toLowerCase();
      } catch {
        originChanged = true;
      }
      if (url !== existing.url) endpointChanged = true;
    }
    const hasRetainedHeaders = Object.keys(existingHeaders || {}).some(
      k => !removeHeaderKeys.some(rm => String(rm).toLowerCase() === k.toLowerCase()),
    );
    if (originChanged && hasRetainedHeaders && !replaceSecrets) {
      throw new Error('Changing the HTTP MCP origin while custom headers are saved requires clearing or re-entering headers (replaceSecrets: true).');
    }
    headers = normalizeHeadersMap(raw.headers, originChanged ? {} : existingHeaders, {
      removeKeys: removeHeaderKeys,
      replaceAll: replaceSecrets,
    });
  }

  const disabledTools = endpointChanged && !allowProbeMetadata
    ? []
    : Array.isArray(raw.disabledTools)
      ? [...new Set(raw.disabledTools.filter(t => typeof t === 'string' && RAW_TOOL_NAME_RE.test(t)))]
      : (Array.isArray(existing?.disabledTools) ? [...existing.disabledTools] : []);

  const cachedTools = allowProbeMetadata
    ? normalizeCachedToolsList(raw.cachedTools)
    : (endpointChanged ? [] : normalizeCachedToolsList(existing?.cachedTools));

  const lastProbeAt = allowProbeMetadata
    ? (typeof raw.lastProbeAt === 'string' ? raw.lastProbeAt.slice(0, 64) : null)
    : (endpointChanged ? null : (existing?.lastProbeAt ?? null));
  const lastProbeOk = allowProbeMetadata
    ? (typeof raw.lastProbeOk === 'boolean' ? raw.lastProbeOk : null)
    : (endpointChanged ? null : (existing?.lastProbeOk ?? null));
  const lastProbeError = allowProbeMetadata
    ? (typeof raw.lastProbeError === 'string' ? sanitizeMetadataText(raw.lastProbeError, 512) : null)
    : (endpointChanged ? null : (existing?.lastProbeError ?? null));
  const serverInfo = allowProbeMetadata
    ? normalizeServerInfo(raw.serverInfo)
    : (endpointChanged ? null : normalizeServerInfo(existing?.serverInfo));

  const nowIso = new Date().toISOString();
  return {
    id,
    name,
    description,
    transport,
    enabled,
    command,
    args,
    cwd,
    env,
    url,
    headers,
    timeoutMs: timeoutRaw,
    disabledTools,
    cachedTools,
    lastProbeAt,
    lastProbeOk,
    lastProbeError,
    serverInfo,
    createdAt: typeof existing?.createdAt === 'string' ? existing.createdAt : (allowProbeMetadata && typeof raw.createdAt === 'string' ? raw.createdAt : nowIso),
    updatedAt: allowProbeMetadata && typeof raw.updatedAt === 'string' ? raw.updatedAt : nowIso,
  };
}

function writePrivateMcpJsonSync(filePath, data) {
  const dir = path.dirname(filePath);
  const serialized = JSON.stringify(data, null, 2) + '\n';
  if (Buffer.byteLength(serialized, 'utf8') > MAX_MCP_FILE_BYTES) {
    throw new Error('MCP server configuration exceeds maximum file size (2 MiB).');
  }
  const temp = path.join(dir, `.mcp-servers-${crypto.randomUUID()}.tmp`);
  const fd = fs.openSync(
    temp,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0),
    0o600,
  );
  try {
    fs.writeFileSync(fd, serialized, 'utf8');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    if (process.platform !== 'win32') fs.chmodSync(temp, 0o600);
    fs.renameSync(temp, filePath);
  } catch (error) {
    fs.rmSync(temp, { force: true });
    throw error;
  }
}

function assertWritableStateDir(stateDir, requirePrivateState) {
  const resolved = path.resolve(stateDir);
  if (requirePrivateState && process.platform !== 'win32') {
    return assertPrivateState(resolved);
  }
  const st = fs.lstatSync(resolved);
  if (st.isSymbolicLink() || !st.isDirectory()) {
    throw new Error('State directory must be a real directory.');
  }
  return resolved;
}

export function readMcpServersSync(stateDir, { workspaceRoots, blockedOrigins = [] } = {}) {
  const resolvedState = path.resolve(stateDir);
  const filePath = mcpServersFilePath(resolvedState);

  try {
    const roots = workspaceRoots ?? loadWorkspaceRootsFromStateConfig(resolvedState);
    assertConfigOutsideWorkspace(filePath, roots);
  } catch (err) {
    return {
      exists: fs.lstatSync(filePath, { throwIfNoEntry: false }) !== undefined,
      servers: [],
      updatedAt: null,
      error: err?.message || 'MCP server registry must reside outside the mounted workspace.',
    };
  }

  let fd;
  try {
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  } catch (err) {
    if (err?.code === 'ENOENT') {
      return { exists: false, servers: [], updatedAt: null, error: null };
    }
    return {
      exists: true,
      servers: [],
      updatedAt: null,
      error: err?.code === 'ELOOP' ? 'MCP server configuration must not be a symbolic link.' : 'Cannot open MCP server configuration.',
    };
  }

  let rawText;
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1) {
      return { exists: true, servers: [], updatedAt: null, error: 'MCP server configuration must be a regular single-link file.' };
    }
    if (stat.size > MAX_MCP_FILE_BYTES) {
      return { exists: true, servers: [], updatedAt: null, error: 'MCP server configuration exceeds maximum size.' };
    }
    if (process.platform !== 'win32') {
      if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
        return { exists: true, servers: [], updatedAt: null, error: 'MCP server configuration has an untrusted owner.' };
      }
      if ((stat.mode & 0o077) !== 0) {
        return { exists: true, servers: [], updatedAt: null, error: 'MCP server configuration permissions must be 0600.' };
      }
    }
    rawText = fs.readFileSync(fd, 'utf8');
  } finally {
    fs.closeSync(fd);
  }

  try {
    const parsed = JSON.parse(rawText);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || !Array.isArray(parsed.servers)) {
      throw new Error('Invalid MCP server configuration structure.');
    }
    if (parsed.servers.length > MAX_MCP_SERVERS) {
      throw new Error(`MCP server list exceeds limit (${MAX_MCP_SERVERS}).`);
    }
    const seen = new Set();
    const servers = [];
    for (const raw of parsed.servers) {
      const normalized = validateServerEntry(raw, {
        stateDir: resolvedState,
        blockedOrigins,
        replaceSecrets: true,
        allowProbeMetadata: true,
      });
      if (seen.has(normalized.id)) throw new Error(`Duplicate MCP server ID: ${normalized.id}`);
      seen.add(normalized.id);
      servers.push(normalized);
    }
    return {
      exists: true,
      servers,
      updatedAt: typeof parsed.updatedAt === 'string' ? parsed.updatedAt : null,
      error: null,
    };
  } catch (err) {
    return {
      exists: true,
      servers: [],
      updatedAt: null,
      error: err?.message || 'MCP server configuration is corrupted.',
    };
  }
}

function saveMcpServersSync(stateDir, servers, { workspaceRoots, requirePrivateState = true } = {}) {
  const resolvedState = assertWritableStateDir(stateDir, requirePrivateState);
  const filePath = mcpServersFilePath(resolvedState);
  const roots = workspaceRoots ?? loadWorkspaceRootsFromStateConfig(resolvedState);
  assertConfigOutsideWorkspace(filePath, roots);
  writePrivateMcpJsonSync(filePath, {
    version: 1,
    updatedAt: new Date().toISOString(),
    servers,
  });
}

export function upsertMcpServerSync(
  stateDir,
  serverInput,
  { workspaceRoots, requirePrivateState = true, blockedOrigins = [], replaceSecrets = false } = {},
) {
  const resolvedState = path.resolve(stateDir);
  const current = readMcpServersSync(resolvedState, { workspaceRoots, blockedOrigins });
  if (current.error) throw new Error(current.error);

  const id = typeof serverInput?.id === 'string' ? serverInput.id.trim() : '';
  const idx = current.servers.findIndex(s => s.id === id);
  if (idx === -1 && current.servers.length >= MAX_MCP_SERVERS) {
    throw new Error(`Maximum number of MCP servers (${MAX_MCP_SERVERS}) reached.`);
  }
  const existing = idx >= 0 ? current.servers[idx] : null;
  const normalized = validateServerEntry(serverInput, {
    stateDir: resolvedState,
    existing,
    blockedOrigins,
    replaceSecrets,
    allowProbeMetadata: false,
  });

  const nextServers = [...current.servers];
  if (idx >= 0) nextServers[idx] = normalized;
  else nextServers.push(normalized);

  saveMcpServersSync(resolvedState, nextServers, { workspaceRoots, requirePrivateState });
  return normalized;
}

export function upsertMcpServersSync(
  stateDir,
  serverInputs,
  { workspaceRoots, requirePrivateState = true, blockedOrigins = [], replaceSecrets = true } = {},
) {
  if (!Array.isArray(serverInputs) || !serverInputs.length) {
    throw new Error('At least one MCP server configuration is required.');
  }
  const resolvedState = path.resolve(stateDir);
  const current = readMcpServersSync(resolvedState, { workspaceRoots, blockedOrigins });
  if (current.error) throw new Error(current.error);

  const nextServers = [...current.servers];
  const saved = [];
  const batchIds = new Set();

  for (const input of serverInputs) {
    const id = typeof input?.id === 'string' ? input.id.trim() : '';
    if (batchIds.has(id)) {
      throw new Error(`Duplicate MCP server ID in import batch: ${id}`);
    }
    batchIds.add(id);
    const idx = nextServers.findIndex(s => s.id === id);
    if (idx === -1 && nextServers.length >= MAX_MCP_SERVERS) {
      throw new Error(`Maximum number of MCP servers (${MAX_MCP_SERVERS}) reached.`);
    }
    const existing = idx >= 0 ? nextServers[idx] : null;
    const normalized = validateServerEntry(input, {
      stateDir: resolvedState,
      existing,
      blockedOrigins,
      replaceSecrets,
      allowProbeMetadata: false,
    });
    if (idx >= 0) nextServers[idx] = normalized;
    else nextServers.push(normalized);
    saved.push(normalized);
  }

  saveMcpServersSync(resolvedState, nextServers, { workspaceRoots, requirePrivateState });
  return saved;
}

export function deleteMcpServerSync(
  stateDir,
  serverId,
  { workspaceRoots, requirePrivateState = true, blockedOrigins = [] } = {},
) {
  if (typeof serverId !== 'string' || !SERVER_ID_RE.test(serverId)) {
    throw new Error('Invalid MCP server ID.');
  }
  const current = readMcpServersSync(stateDir, { workspaceRoots, blockedOrigins });
  if (current.error) throw new Error(current.error);
  const nextServers = current.servers.filter(s => s.id !== serverId);
  if (nextServers.length === current.servers.length) {
    const err = new Error(`MCP server "${serverId}" not found.`);
    err.code = 'NOT_FOUND';
    throw err;
  }
  saveMcpServersSync(stateDir, nextServers, { workspaceRoots, requirePrivateState });
  return { deleted: serverId, remaining: nextServers.length };
}

export function toggleMcpServerSync(
  stateDir,
  { id, enabled, toolName },
  { workspaceRoots, requirePrivateState = true, blockedOrigins = [] } = {},
) {
  if (typeof id !== 'string' || !SERVER_ID_RE.test(id)) throw new Error('Invalid MCP server ID.');
  if (typeof enabled !== 'boolean') throw new Error('enabled must be a boolean.');

  const current = readMcpServersSync(stateDir, { workspaceRoots, blockedOrigins });
  if (current.error) throw new Error(current.error);
  const idx = current.servers.findIndex(s => s.id === id);
  if (idx === -1) throw new Error(`MCP server "${id}" not found.`);

  const target = { ...current.servers[idx], disabledTools: [...(current.servers[idx].disabledTools || [])] };
  if (toolName !== undefined) {
    if (typeof toolName !== 'string' || !RAW_TOOL_NAME_RE.test(toolName)) {
      throw new Error('Invalid MCP tool name.');
    }
    const set = new Set(target.disabledTools);
    if (enabled) set.delete(toolName);
    else set.add(toolName);
    target.disabledTools = [...set];
  } else {
    target.enabled = enabled;
  }
  target.updatedAt = new Date().toISOString();

  const nextServers = [...current.servers];
  nextServers[idx] = target;
  saveMcpServersSync(stateDir, nextServers, { workspaceRoots, requirePrivateState });
  return target;
}

export function serverConfigFingerprint(srv) {
  return crypto.createHash('sha256').update(JSON.stringify({
    transport: srv.transport,
    command: srv.command,
    args: srv.args,
    cwd: srv.cwd,
    env: srv.env,
    url: srv.url,
    headers: srv.headers,
    timeoutMs: srv.timeoutMs,
  })).digest('hex');
}

export function saveMcpProbeResultSync(
  stateDir,
  serverId,
  probeResult,
  { workspaceRoots, requirePrivateState = true, blockedOrigins = [], expectedFingerprint = null } = {},
) {
  const current = readMcpServersSync(stateDir, { workspaceRoots, blockedOrigins });
  if (current.error) throw new Error(current.error);
  const idx = current.servers.findIndex(s => s.id === serverId);
  if (idx === -1) {
    const err = new Error(`MCP server "${serverId}" not found.`);
    err.code = 'NOT_FOUND';
    throw err;
  }
  const existing = current.servers[idx];
  if (expectedFingerprint && serverConfigFingerprint(existing) !== expectedFingerprint) {
    return existing;
  }

  const sanitizedError = probeResult.ok
    ? null
    : redactSecretsFromText(probeResult.error || 'Probe failed.', existing);

  const updated = {
    ...existing,
    lastProbeAt: new Date().toISOString(),
    lastProbeOk: Boolean(probeResult.ok),
    lastProbeError: sanitizedError,
    serverInfo: probeResult.ok && probeResult.serverInfo ? normalizeServerInfo(probeResult.serverInfo) : existing.serverInfo,
    cachedTools: probeResult.ok && Array.isArray(probeResult.tools)
      ? normalizeCachedToolsList(probeResult.tools)
      : existing.cachedTools,
    updatedAt: new Date().toISOString(),
  };

  const nextServers = [...current.servers];
  nextServers[idx] = updated;
  saveMcpServersSync(stateDir, nextServers, { workspaceRoots, requirePrivateState });
  return updated;
}

export function parseStandardMcpJson(rawInput) {
  const parsed = typeof rawInput === 'string' ? JSON.parse(rawInput) : rawInput;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('MCP JSON must be an object (e.g. { "mcpServers": { ... } }).');
  }
  const mapSource = (parsed.mcpServers && typeof parsed.mcpServers === 'object' && !Array.isArray(parsed.mcpServers))
    ? parsed.mcpServers
    : (parsed.servers && typeof parsed.servers === 'object' && !Array.isArray(parsed.servers))
      ? parsed.servers
      : (typeof parsed.id === 'string' && (parsed.command || parsed.url))
        ? { [parsed.id]: parsed }
        : null;
  if (!mapSource) {
    throw new Error('Expected an object containing "mcpServers" (Claude/Cursor format) or "servers" (VS Code format).');
  }
  const entries = Object.entries(mapSource);
  if (!entries.length) throw new Error('No MCP servers found in the provided JSON.');
  if (entries.length > MAX_MCP_SERVERS) {
    throw new Error(`Too many servers in import payload (max ${MAX_MCP_SERVERS}).`);
  }
  const seenIds = new Set();
  const results = [];
  for (const [rawKey, spec] of entries) {
    if (!spec || typeof spec !== 'object' || Array.isArray(spec)) {
      throw new Error(`Invalid configuration for server "${rawKey}".`);
    }
    const id = slugifyServerId(typeof spec.id === 'string' && spec.id.trim() ? spec.id : rawKey);
    if (!id) throw new Error(`Cannot derive a valid server ID from "${rawKey}".`);
    if (seenIds.has(id)) {
      throw new Error(`Duplicate MCP server ID "${id}" derived from "${rawKey}".`);
    }
    seenIds.add(id);
    const url = spec.url || spec.httpUrl || spec.serverUrl || '';
    const command = spec.command || '';
    const declaredType = String(spec.transport || spec.type || '').toLowerCase();
    const transport = (declaredType === 'http' || declaredType === 'streamable-http' || declaredType === 'streamablehttp' || (!command && url))
      ? 'http'
      : 'stdio';
    results.push({
      id,
      name: typeof spec.name === 'string' && spec.name.trim() ? spec.name.trim() : rawKey,
      description: typeof spec.description === 'string' ? spec.description.trim() : '',
      transport,
      enabled: spec.disabled === true ? false : (spec.enabled === undefined ? true : Boolean(spec.enabled)),
      command,
      args: Array.isArray(spec.args) ? spec.args : [],
      cwd: typeof spec.cwd === 'string' ? spec.cwd : '',
      env: spec.env && typeof spec.env === 'object' && !Array.isArray(spec.env) ? spec.env : {},
      url,
      headers: spec.headers && typeof spec.headers === 'object' && !Array.isArray(spec.headers) ? spec.headers : {},
      timeoutMs: Number.isSafeInteger(spec.timeoutMs) ? Math.min(100000, Math.max(3000, spec.timeoutMs)) : 30000,
    });
  }
  return results;
}

export function publicMcpServerSummary(server) {
  const disabledSet = new Set(server.disabledTools || []);
  const envKeys = Object.keys(server.env || {}).sort();
  const headerKeys = Object.keys(server.headers || {}).sort();
  const tools = (server.cachedTools || []).map(tool => ({
    name: tool.name,
    fullName: formatExternalToolName(server.id, tool.name),
    title: tool.title || '',
    description: tool.description || '',
    inputSchema: tool.inputSchema,
    annotations: tool.annotations,
    enabled: Boolean(server.enabled && !disabledSet.has(tool.name)),
    individuallyDisabled: disabledSet.has(tool.name),
  }));
  const displayUrl = server.transport === 'http' ? redactUrlForDisplay(server.url) : '';
  return {
    id: server.id,
    name: server.name,
    description: server.description || '',
    transport: server.transport,
    enabled: Boolean(server.enabled),
    command: server.transport === 'stdio' ? server.command : '',
    args: server.transport === 'stdio' ? [...(server.args || [])] : [],
    cwd: server.transport === 'stdio' ? (server.cwd || '') : '',
    url: displayUrl,
    urlRedacted: server.transport === 'http' && displayUrl !== server.url,
    envKeys,
    headerKeys,
    hasSecrets: envKeys.length > 0 || headerKeys.length > 0,
    timeoutMs: server.timeoutMs,
    disabledTools: [...disabledSet],
    toolCount: tools.length,
    enabledToolCount: tools.filter(t => t.enabled).length,
    tools,
    lastProbeAt: server.lastProbeAt || null,
    lastProbeOk: server.lastProbeOk ?? null,
    lastProbeError: server.lastProbeError || null,
    serverInfo: server.serverInfo || null,
    createdAt: server.createdAt || null,
    updatedAt: server.updatedAt || null,
  };
}

export function publicMcpRegistrySnapshot(stateDir, { workspaceRoots, blockedOrigins = [] } = {}) {
  const registry = readMcpServersSync(stateDir, { workspaceRoots, blockedOrigins });
  const items = registry.servers.map(publicMcpServerSummary);
  return {
    exists: registry.exists,
    error: registry.error,
    updatedAt: registry.updatedAt,
    serverCount: items.length,
    enabledServerCount: items.filter(s => s.enabled).length,
    totalToolCount: items.reduce((sum, s) => sum + s.toolCount, 0),
    enabledToolCount: items.reduce((sum, s) => sum + s.enabledToolCount, 0),
    items,
  };
}
