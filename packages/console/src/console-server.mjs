// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Ring 3 isolated Console Origin HTTP server (default 127.0.0.1:18797).
// Strictly read-only telemetry, SSE audit stream, tool catalog, and declarative console:panel@1 host.
import http from 'node:http';
import { publicWebUiAuthSummary } from '../../../local/webui-auth.mjs';
import {
  applySecurityHeaders,
  formatLoopbackOrigin,
  parseCookieHeader,
  readBodyJson,
  sendJson,
  verifyFetchSiteSameOriginOrNone,
  verifyHostForPort,
  verifyOriginForPort,
} from './http-security.mjs';
import { CONSOLE_SID_COOKIE } from './session-broker.mjs';
import { loadBuiltAsset, renderConsoleOriginHtml } from './html.mjs';

const MAX_SSE_CLIENTS = 16;

const TRUST_ONLY_PREFIXES = [
  '/api/auth/',
  '/api/approvals/',
  '/api/trust/',
  '/api/capabilities',
  '/api/service',
  '/api/mcp-servers/',
];

function isTrustOnlyRoute(method, pathname) {
  if (method !== 'GET' && pathname === '/api/mcp-servers') return true;
  return TRUST_ONLY_PREFIXES.some(prefix => pathname === prefix || pathname.startsWith(prefix));
}

export async function createConsoleOriginServer({
  host = '127.0.0.1',
  port = 18797,
  broker,
  panelCollector,
  loadCurrentAuthRecord,
  refreshSnapshot,
  getLastSnapshot,
  getTrustOrigin,
  getKernelSummary = () => ({ roots: [], units: [] }),
  getRecentChannelEvents = () => [],
}) {
  const sseClients = new Map();
  let actualPort = port;

  const getConsoleOrigin = () => formatLoopbackOrigin(host, actualPort);

  function verifyPreAuthMutation(req) {
    if (!verifyOriginForPort(req, actualPort)) return false;
    if (!verifyFetchSiteSameOriginOrNone(req, false)) return false;
    return broker.verifyConsolePreAuthCsrf(req);
  }

  function verifyAuthMutation(req, session) {
    if (!verifyOriginForPort(req, actualPort)) return false;
    if (!verifyFetchSiteSameOriginOrNone(req, false)) return false;
    return broker.verifyAuthenticatedCsrf(req, session);
  }

  function sendStreamFrame(client, req, authRecord, frame) {
    if (client.writableEnded) {
      sseClients.delete(client);
      return;
    }
    if (client.writableLength > 512 * 1024) {
      sseClients.delete(client);
      try { client.destroy(); } catch {}
      return;
    }
    if (broker.authenticateConsoleSession(req, authRecord, false)) client.write(frame);
    else {
      sseClients.delete(client);
      client.end();
    }
  }

  function enrichSnapshot(snap, panels) {
    const rawKernel = getKernelSummary() || {};
    const sanitizedSecurity = snap?.security
      ? {
          initialized: Boolean(snap.security.initialized),
          mode: snap.security.mode,
          requirePasskey: Boolean(snap.security.requirePasskey),
          passkeyCount: Number(snap.security.passkeyCount || 0),
          sessionPersistence: snap.security.sessionPersistence || 'tab',
        }
      : undefined;
    const sanitizedApprovals = snap?.approvals
      ? {
          pendingCount: Number(snap.approvals.pendingCount || 0),
          items: Array.isArray(snap.approvals.items)
            ? snap.approvals.items.map(item => ({
                idShort: item.idShort,
                tool: item.tool,
                clientId: item.clientId,
                expiresAt: item.expiresAt,
                alreadyApproved: Boolean(item.alreadyApproved),
              }))
            : [],
        }
      : undefined;
    return {
      ...snap,
      ...(sanitizedSecurity ? { security: sanitizedSecurity } : {}),
      ...(sanitizedApprovals ? { approvals: sanitizedApprovals } : {}),
      originRole: 'console',
      readOnly: true,
      trustOrigin: getTrustOrigin(),
      consoleOrigin: getConsoleOrigin(),
      kernel: {
        roots: Array.isArray(rawKernel.roots) ? rawKernel.roots : [],
        units: Array.isArray(rawKernel.units) ? rawKernel.units : [],
      },
      channelEvents: getRecentChannelEvents(),
      panels,
    };
  }

  function broadcastSnapshot(snap, panels, authRecord) {
    if (!sseClients.size) return;
    const frame = `event: status\ndata: ${JSON.stringify(enrichSnapshot(snap, panels))}\n\n`;
    for (const [client, req] of sseClients) sendStreamFrame(client, req, authRecord, frame);
  }

  function broadcastChannelEvent(event, authRecord) {
    if (!sseClients.size) return;
    const frame = `event: kernel\ndata: ${JSON.stringify(event)}\n\n`;
    for (const [client, req] of sseClients) sendStreamFrame(client, req, authRecord, frame);
  }

  function dropStreamsForSids(sids, all = false) {
    if (all) {
      for (const client of sseClients.keys()) client.end();
      sseClients.clear();
      return;
    }
    const targetSet = new Set(sids || []);
    if (!targetSet.size) return;
    for (const [client, req] of sseClients) {
      const sid = parseCookieHeader(req.headers.cookie).get(CONSOLE_SID_COOKIE);
      if (targetSet.has(sid)) {
        sseClients.delete(client);
        client.end();
      }
    }
  }

  const server = http.createServer(async (req, res) => {
    try {
      if (!verifyHostForPort(req, actualPort)) {
        return sendJson(res, 403, { error: 'Rejected untrusted Host header.' });
      }
      if (!req.url || !req.url.startsWith('/') || req.url.startsWith('//')) {
        return sendJson(res, 400, { error: 'Invalid request path.' });
      }
      let reqUrl;
      try {
        reqUrl = new URL(req.url, `http://127.0.0.1:${actualPort}`);
      } catch {
        return sendJson(res, 400, { error: 'Malformed request URL.' });
      }

      // Hard physical isolation: ALL privileged security/trust actions are rejected on Console Origin.
      if (isTrustOnlyRoute(req.method, reqUrl.pathname)) {
        return sendJson(res, 403, {
          error: 'Privileged security actions are strictly isolated to the Trust Origin.',
          code: 'TRUST_ORIGIN_REQUIRED',
          trustOrigin: getTrustOrigin(),
        });
      }

      if (req.method === 'GET' && reqUrl.pathname === '/') {
        if (!verifyFetchSiteSameOriginOrNone(req, true)) {
          return sendJson(res, 403, { error: 'Cross-site access denied.' });
        }
        const authRecord = loadCurrentAuthRecord();
        const session = broker.authenticateConsoleSession(req, authRecord);
        const headersToSet = [];
        let csrfToken;
        if (session) {
          csrfToken = session.csrfToken;
        } else {
          const pre = broker.ensurePreAuthCookie(req, { kind: 'console' });
          csrfToken = pre.csrfToken;
          if (pre.setCookie) headersToSet.push(pre.setCookie);
        }
        applySecurityHeaders(res, 'text/html; charset=utf-8');
        if (headersToSet.length) res.setHeader('Set-Cookie', headersToSet);
        res.statusCode = 200;
        res.end(renderConsoleOriginHtml({ csrfToken, trustOrigin: getTrustOrigin() }));
        return;
      }

      if (req.method === 'GET' && reqUrl.pathname === '/console.css') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        applySecurityHeaders(res, 'text/css; charset=utf-8');
        res.statusCode = 200;
        res.end(loadBuiltAsset('console.css'));
        return;
      }

      if (req.method === 'GET' && reqUrl.pathname === '/console.js') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        applySecurityHeaders(res, 'application/javascript; charset=utf-8');
        res.statusCode = 200;
        res.end(loadBuiltAsset('console.js'));
        return;
      }

      if (req.method === 'GET' && reqUrl.pathname === '/api/console/session') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        if (req.headers.origin && !verifyOriginForPort(req, actualPort)) return sendJson(res, 403, { error: 'Cross-origin request rejected.' });
        const authRecord = loadCurrentAuthRecord();
        const session = broker.authenticateConsoleSession(req, authRecord);
        if (session) {
          return sendJson(res, 200, {
            authenticated: true,
            role: 'console-readonly',
            originRole: 'console',
            csrfToken: session.csrfToken,
            sessionPersistence: authRecord.sessionPersistence || 'tab',
            trustOrigin: getTrustOrigin(),
          });
        }
        const pre = broker.ensurePreAuthCookie(req, { kind: 'console' });
        const extra = pre.setCookie ? { 'Set-Cookie': pre.setCookie } : {};
        return sendJson(res, 200, {
          authenticated: false,
          role: 'console-readonly',
          originRole: 'console',
          csrfToken: pre.csrfToken,
          sessionPersistence: authRecord.sessionPersistence || 'tab',
          trustOrigin: getTrustOrigin(),
        }, extra);
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/console/session/exchange') {
        if (!verifyPreAuthMutation(req)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        const body = await readBodyJson(req);
        const authRecord = loadCurrentAuthRecord();
        if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' });
        const session = broker.exchangeConsoleHandoffTicket(body?.ticket, authRecord);
        if (!session) {
          return sendJson(res, 401, { error: 'Invalid, expired, or already used Console handoff ticket.' });
        }
        return sendJson(res, 200, {
          ok: true,
          role: 'console-readonly',
          csrfToken: session.csrfToken,
          tabToken: session.tabToken,
          sessionPersistence: session.sessionPersistence,
          trustOrigin: getTrustOrigin(),
        }, { 'Set-Cookie': broker.loginCookies('console', session.sid) });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/console/logout') {
        const cookies = parseCookieHeader(req.headers.cookie);
        const sid = cookies.get(CONSOLE_SID_COOKIE);
        const activeSession = broker.getConsoleSessionBySid(sid);
        if (activeSession) {
          if (!verifyAuthMutation(req, activeSession)) return sendJson(res, 403, { error: 'CSRF validation failed.' });
        } else if (!verifyPreAuthMutation(req)) {
          return sendJson(res, 403, { error: 'CSRF validation failed.' });
        }
        await readBodyJson(req);
        if (sid) broker.revokeConsoleSession(sid);
        const nextCsrf = broker.resetPreAuthCookies('console');
        return sendJson(res, 200, { ok: true, csrfToken: nextCsrf.csrfToken }, { 'Set-Cookie': nextCsrf.setCookies });
      }

      // Authenticated read-only Console routes below.
      const authRecord = loadCurrentAuthRecord();
      if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' });
      const session = broker.authenticateConsoleSession(req, authRecord);
      if (!session) {
        return sendJson(res, 401, {
          error: 'Console Origin read-only session required. Unlock via Trust Origin first.',
          code: 'CONSOLE_AUTH_REQUIRED',
          trustOrigin: getTrustOrigin(),
          mode: publicWebUiAuthSummary(authRecord).mode,
        });
      }

      if (req.method === 'GET' && reqUrl.pathname === '/api/status') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        const [snap, panels] = await Promise.all([
          refreshSnapshot({ force: false }),
          panelCollector.collectAll({ originRole: 'console' }),
        ]);
        return sendJson(res, 200, enrichSnapshot(snap, panels));
      }

      if (req.method === 'GET' && reqUrl.pathname === '/api/panels') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        const panels = await panelCollector.collectAll({ originRole: 'console' });
        return sendJson(res, 200, { ok: true, panels });
      }

      if (req.method === 'GET' && reqUrl.pathname.startsWith('/api/panels/')) {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        const panelId = reqUrl.pathname.slice('/api/panels/'.length);
        if (!/^[a-z][a-z0-9-]{1,47}$/.test(panelId)) {
          return sendJson(res, 400, { error: 'Invalid panel ID.' });
        }
        const panel = await panelCollector.collectById(panelId, { originRole: 'console' });
        if (!panel) return sendJson(res, 404, { error: 'Console panel not found.' });
        return sendJson(res, 200, { ok: true, panel });
      }

      if (req.method === 'GET' && reqUrl.pathname === '/api/events') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site event stream rejected.' });
        if (sseClients.size >= MAX_SSE_CLIENTS) return sendJson(res, 429, { error: 'Too many active Console monitoring streams.' });
        res.writeHead(200, {
          'Content-Type': 'text/event-stream; charset=utf-8',
          'Cache-Control': 'no-store',
          Connection: 'keep-alive',
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
          'Referrer-Policy': 'no-referrer',
          'Cross-Origin-Resource-Policy': 'same-origin',
          'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
        });
        sseClients.set(res, req);
        const dropClient = () => sseClients.delete(res);
        req.on('close', dropClient);
        res.on('error', dropClient);
        res.on('close', dropClient);
        const cached = getLastSnapshot() || await refreshSnapshot({ force: false, broadcast: false });
        const panels = await panelCollector.collectAll({ originRole: 'console' });
        if (res.writableEnded || res.destroyed) return;
        const freshAuth = loadCurrentAuthRecord();
        sendStreamFrame(res, req, freshAuth, `event: status\ndata: ${JSON.stringify(enrichSnapshot(cached, panels))}\n\n`);
        return;
      }

      return sendJson(res, 404, { error: 'Not found.' });
    } catch (error) {
      const status = Number.isInteger(error?.status) ? error.status : 500;
      const message = status < 500 ? error.message : 'Internal Console error.';
      if (!res.headersSent) return sendJson(res, status, { error: message });
      res.end();
    }
  });

  await new Promise((resolve, reject) => {
    const onError = err => reject(err);
    server.once('error', onError);
    server.listen(port, host, () => {
      server.removeListener('error', onError);
      const addr = server.address();
      actualPort = typeof addr === 'object' && addr ? addr.port : port;
      resolve();
    });
  });

  const heartbeatTimer = setInterval(() => {
    if (!sseClients.size) return;
    let auth;
    try { auth = loadCurrentAuthRecord(); } catch {}
    for (const [client, req] of sseClients) sendStreamFrame(client, req, auth, ': keepalive\n\n');
  }, 15000);
  heartbeatTimer.unref?.();

  return Object.freeze({
    server,
    host,
    port: actualPort,
    url: getConsoleOrigin(),
    hasSseClients: () => sseClients.size > 0,
    broadcastSnapshot,
    broadcastChannelEvent,
    dropStreamsForSids,
    async close() {
      clearInterval(heartbeatTimer);
      for (const client of sseClients.keys()) client.end();
      sseClients.clear();
      await new Promise(resolve => {
        server.closeAllConnections?.();
        server.close(resolve);
      });
    },
  });
}
