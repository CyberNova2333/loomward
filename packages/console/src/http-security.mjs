// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { assertPrivateFile, assertPrivateState } from '../../../local/host-safety.mjs';
import { isLoopbackHost } from '../../../local/webui.mjs';

export { isLoopbackHost };

export const MAX_JSON_BODY = 65536;
export const CSRF_HEADER = 'x-loomward-csrf';
export const LEGACY_CSRF_HEADER = 'x-agentdock-csrf';
export const TAB_AUTH_HEADER = 'x-loomward-tab-auth';
export const LEGACY_TAB_AUTH_HEADER = 'x-agentdock-tab-auth';

export function validTokenId(val) {
  return typeof val === 'string' && /^[A-Za-z0-9_-]{32,80}$/.test(val);
}

export function timingSafeEqualText(a, b) {
  const ab = Buffer.from(String(a || ''), 'utf8');
  const bb = Buffer.from(String(b || ''), 'utf8');
  return ab.length > 0 && ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

export function parseCookieHeader(header = '') {
  const map = new Map();
  for (const part of String(header).split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const key = part.slice(0, eq).trim();
    const val = part.slice(eq + 1).trim();
    if (key) map.set(key, val);
  }
  return map;
}

export function getCsrfHeader(req) {
  return String(req.headers[CSRF_HEADER] || req.headers[LEGACY_CSRF_HEADER] || '');
}

export function getTabAuthHeader(req) {
  return String(req.headers[TAB_AUTH_HEADER] || req.headers[LEGACY_TAB_AUTH_HEADER] || '');
}

export function allowedHostsForPort(boundPort) {
  return new Set([
    `127.0.0.1:${boundPort}`,
    `localhost:${boundPort}`,
    `[::1]:${boundPort}`,
  ]);
}

export function allowedOriginsForPort(boundPort) {
  return new Set([
    `http://127.0.0.1:${boundPort}`,
    `http://localhost:${boundPort}`,
    `http://[::1]:${boundPort}`,
  ]);
}

export function formatLoopbackOrigin(host, port) {
  const h = String(host || '127.0.0.1');
  const formattedHost = h.includes(':') && !h.startsWith('[') ? `[${h}]` : h;
  return `http://${formattedHost}:${port}`;
}

export function verifyHostForPort(req, boundPort) {
  const hostHeader = String(req.headers.host || '').toLowerCase();
  return allowedHostsForPort(boundPort).has(hostHeader);
}

export function verifyOriginForPort(req, boundPort) {
  const origin = String(req.headers.origin || '').toLowerCase();
  return allowedOriginsForPort(boundPort).has(origin);
}

export function verifyFetchSiteSameOriginOrNone(req, allowTopNavigation = false) {
  const site = req.headers['sec-fetch-site'];
  if (!site) return true;
  if (site === 'same-origin') return true;
  if (!allowTopNavigation) return false;
  if (site === 'none') return true;
  if (req.method === 'GET' && (site === 'same-site' || site === 'cross-site')) {
    const mode = req.headers['sec-fetch-mode'];
    const dest = req.headers['sec-fetch-dest'];
    if (!mode && !dest) return site === 'same-site';
    return mode === 'navigate' && dest === 'document';
  }
  return false;
}

export function applySecurityHeaders(res, contentType, extra = {}) {
  res.setHeader('Content-Type', contentType);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  );
  for (const [k, v] of Object.entries(extra)) res.setHeader(k, v);
}

export function sendJson(res, status, data, extraHeaders = {}) {
  applySecurityHeaders(res, 'application/json; charset=utf-8', extraHeaders);
  res.statusCode = status;
  res.end(JSON.stringify(data));
}

export async function readBodyJson(req, { maxBytes = MAX_JSON_BODY, timeoutMs = 10000 } = {}) {
  const contentType = String(req.headers['content-type'] || '').toLowerCase().trim();
  if (!/^application\/json(?:\s*;|$)/.test(contentType)) {
    const err = new Error('Content-Type must be application/json.');
    err.status = 415;
    throw err;
  }
  const chunks = [];
  let size = 0;
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    req.destroy(Object.assign(new Error('Request body timeout.'), { status: 408 }));
  }, timeoutMs);
  timer.unref?.();
  try {
    for await (const chunk of req) {
      size += chunk.length;
      if (size > maxBytes) {
        const err = new Error('Request payload too large.');
        err.status = 413;
        throw err;
      }
      chunks.push(chunk);
    }
  } catch (err) {
    if (timedOut) {
      const timeoutErr = new Error('Request body timeout.');
      timeoutErr.status = 408;
      throw timeoutErr;
    }
    if (Number.isInteger(err?.status)) throw err;
    const aborted = new Error('Request body stream aborted.');
    aborted.status = 400;
    throw aborted;
  } finally {
    clearTimeout(timer);
  }
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error();
    return parsed;
  } catch {
    const err = new Error('Invalid JSON payload.');
    err.status = 400;
    throw err;
  }
}

export function validateStateDir(stateDir, requirePrivateState) {
  const resolved = path.resolve(stateDir);
  if (!requirePrivateState) return resolved;
  if (process.platform !== 'win32') return assertPrivateState(resolved);
  const stat = fs.lstatSync(resolved);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error('Private state must be an ordinary non-linked directory.');
  }
  return resolved;
}

const MAX_TRUSTED_JSON_BYTES = 2 * 1024 * 1024;

export function readTrustedJsonFile(filePath, requirePrivateState) {
  if (requirePrivateState && process.platform !== 'win32') {
    assertPrivateFile(filePath);
  }
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1) {
      throw new Error('Configuration file must be a regular single-link file.');
    }
    if (stat.size > MAX_TRUSTED_JSON_BYTES) {
      throw new Error('Configuration file exceeds maximum allowed size.');
    }
    if (requirePrivateState && process.platform !== 'win32') {
      if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
        throw new Error('Private file has an untrusted owner.');
      }
      if ((stat.mode & 0o077) !== 0) {
        throw new Error('Private file permissions must restrict access to the owner (0600).');
      }
    }
    return JSON.parse(fs.readFileSync(fd, 'utf8'));
  } finally {
    fs.closeSync(fd);
  }
}

export function appendSanitizedConnectorLog(stateDir, event, fields = {}) {
  try {
    const logPath = path.join(stateDir, 'connector.log');
    const fd = fs.openSync(
      logPath,
      fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT | (fs.constants.O_NOFOLLOW || 0),
      0o600,
    );
    try {
      fs.writeFileSync(fd, JSON.stringify({
        time: new Date().toISOString(),
        event,
        ...fields,
      }) + '\n', 'utf8');
    } finally {
      fs.closeSync(fd);
    }
  } catch {}
}
