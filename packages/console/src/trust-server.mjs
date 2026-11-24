// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Ring 2 isolated Trust Origin HTTP server (default 127.0.0.1:18798).
// Zero extension scripts, styles, or console:panel@1 views are ever served on this origin.
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { TOOL_DEFINITIONS } from '../../../local/tools.mjs';
import { isValidExternalToolName, digest as policyDigest } from '../../../local/request-policy.mjs';
import { APPROVAL_ID, MAX_RECORD_BYTES, readJson, validRequest } from '../../../local/approval-store.mjs';
import { approveRequest } from '../../../local/approval-cli.mjs';
import { writeCapabilitiesSync } from '../../../local/capabilities.mjs';
import {
  deleteMcpServerSync,
  parseStandardMcpJson,
  publicMcpRegistrySnapshot,
  publicMcpServerSummary,
  readMcpServersSync,
  redactSecretsFromText,
  saveMcpProbeResultSync,
  serverConfigFingerprint,
  toggleMcpServerSync,
  upsertMcpServerSync,
  upsertMcpServersSync,
} from '../../../local/mcp-registry.mjs';
import { probeMcpServer } from '../../../local/mcp-client.mjs';
import { verifyAuthenticationResponse, verifyRegistrationResponse, toBase64Url } from '../../../local/webauthn.mjs';
import {
  deletePasskeySync,
  enrollPasskeySync,
  markPasskeyRequiredSync,
  publicWebUiAuthSummary,
  setSessionPersistenceSync,
  setStrongPasswordSync,
  switchToStrongPasswordSync,
  updatePasskeySignCountSync,
  verifySetupTicketMatch,
  verifyStrongPassword,
} from '../../../local/webui-auth.mjs';
import {
  appendSanitizedConnectorLog,
  applySecurityHeaders,
  formatLoopbackOrigin,
  parseCookieHeader,
  readBodyJson,
  readTrustedJsonFile,
  sendJson,
  timingSafeEqualText,
  verifyFetchSiteSameOriginOrNone,
  verifyHostForPort,
  verifyOriginForPort,
} from './http-security.mjs';
import { TRUST_SID_COOKIE } from './session-broker.mjs';
import { loadBuiltAsset, renderTrustOriginHtml } from './html.mjs';

const KNOWN_TOOL_NAMES = new Set(TOOL_DEFINITIONS.map(def => def.name));
const MAX_SSE_CLIENTS = 16;

function safeUserLabel() {
  try {
    return os.userInfo().username || 'owner';
  } catch {
    return 'owner';
  }
}

function pickEditableMcpFields(body) {
  const allowed = [
    'id', 'name', 'description', 'transport', 'enabled', 'command', 'args', 'cwd',
    'env', 'removeEnvKeys', 'url', 'headers', 'removeHeaderKeys', 'timeoutMs', 'disabledTools',
  ];
  const out = {};
  for (const key of allowed) {
    if (Object.hasOwn(body, key)) out[key] = body[key];
  }
  return out;
}

export async function createTrustOriginServer({
  host = '127.0.0.1',
  port = 18798,
  stateDir,
  requirePrivateState = true,
  broker,
  controlChannel,
  loadCurrentWorkspaceRoots,
  loadCurrentAuthRecord,
  refreshSnapshot,
  getLastSnapshot,
  getConsoleOrigin,
  getBlockedOrigins,
  passkeyDetector,
  mcpProber = probeMcpServer,
  serviceController,
  getKernelSummary = () => ({ roots: [], units: [], pendingTrustDecisions: [] }),
  trustDecider = null,
}) {
  const sseClients = new Map();
  const activeProbes = new Set();
  const activeProbeIds = new Set();
  const shutdownController = new AbortController();
  let serviceActionInFlight = false;
  let actualPort = port;

  const getTrustOrigin = () => formatLoopbackOrigin(host, actualPort);

  function checkRateLimit(res) {
    const retrySec = broker.getLockoutRemainingSec();
    if (retrySec > 0) {
      res.setHeader('Retry-After', String(retrySec));
      sendJson(res, 429, { error: `Too many failed authentication attempts. Retry in ${retrySec}s.`, retryAfterSec: retrySec });
      return false;
    }
    return true;
  }

  function formatAuthStatePayload(authRecord, session) {
    return {
      authenticated: Boolean(session),
      authMethod: session ? session.authMethod : null,
      originRole: 'trust',
      consoleOrigin: getConsoleOrigin(),
      ...(session ? { csrfToken: session.csrfToken } : {}),
      lockedUntilMs: broker.getLockedUntilMs(),
      ...publicWebUiAuthSummary(authRecord, { includePrivateMeta: Boolean(session) }),
    };
  }

  function isSetupAuthorized(req, authRecord, bodySetupToken) {
    const session = broker.authenticateTrustSession(req, authRecord);
    if (session) return { ok: true, via: 'session', session };
    if (verifySetupTicketMatch(authRecord, bodySetupToken)) return { ok: true, via: 'ticket', session: null };
    return { ok: false };
  }

  function verifyPreAuthMutation(req) {
    if (!verifyOriginForPort(req, actualPort)) return false;
    if (!verifyFetchSiteSameOriginOrNone(req, false)) return false;
    return broker.verifyTrustPreAuthCsrf(req);
  }

  function verifyAuthMutation(req, session) {
    if (!verifyOriginForPort(req, actualPort)) return false;
    if (!verifyFetchSiteSameOriginOrNone(req, false)) return false;
    return broker.verifyAuthenticatedCsrf(req, session);
  }

  async function readAuthenticatedJson(req, res, session) {
    const body = await readBodyJson(req);
    const freshAuth = loadCurrentAuthRecord();
    if (freshAuth.error) {
      sendJson(res, 403, { error: freshAuth.error, code: 'AUTH_CONFIG_ERROR' });
      return null;
    }
    const live = broker.authenticateTrustSession(req, freshAuth, true);
    if (!live || live !== session) {
      sendJson(res, 401, {
        error: 'Trust Origin authentication is required.',
        mode: publicWebUiAuthSummary(freshAuth).mode,
      });
      return null;
    }
    return { body, authRecord: freshAuth };
  }

  function sanitizeProbeForClient(rawProbe, serverConfig) {
    if (!rawProbe || typeof rawProbe !== 'object') {
      return { ok: false, latencyMs: 0, error: 'Probe failed.' };
    }
    if (rawProbe.ok) {
      return {
        ok: true,
        latencyMs: Number.isFinite(rawProbe.latencyMs) ? rawProbe.latencyMs : 0,
        ...(rawProbe.protocolVersion ? { protocolVersion: rawProbe.protocolVersion } : {}),
        ...(rawProbe.serverInfo ? { serverInfo: rawProbe.serverInfo } : {}),
        tools: Array.isArray(rawProbe.tools) ? rawProbe.tools : [],
      };
    }
    return {
      ok: false,
      latencyMs: Number.isFinite(rawProbe.latencyMs) ? rawProbe.latencyMs : 0,
      error: redactSecretsFromText(rawProbe.error || 'Failed to connect to external MCP server.', serverConfig),
    };
  }

  async function runBoundedProbe(serverConfig, res, blockedOrigins, maxWallMs = 30000) {
    if (res.closed && !res.writableEnded) {
      const err = new Error('Client disconnected during probe.');
      err.status = 499;
      throw err;
    }
    if (activeProbes.size >= 3) {
      const err = new Error('Too many concurrent MCP connection probes in progress.');
      err.status = 429;
      throw err;
    }
    if (activeProbeIds.has(serverConfig.id)) {
      const err = new Error(`A probe for MCP server "${serverConfig.id}" is already in progress.`);
      err.status = 409;
      throw err;
    }
    const ctrl = new AbortController();
    const timeoutMs = Math.min(Number(serverConfig.timeoutMs) || 30000, maxWallMs);
    const timer = setTimeout(() => ctrl.abort(new Error(`Probe timed out after ${timeoutMs}ms.`)), Math.max(1000, timeoutMs));
    timer.unref?.();
    const onResClose = () => {
      if (!res.writableEnded) ctrl.abort(new Error('Client disconnected during probe.'));
    };
    const onShutdown = () => ctrl.abort(new Error('Trust Origin shutting down.'));
    res.on('close', onResClose);
    if (shutdownController.signal.aborted) ctrl.abort(new Error('Trust Origin shutting down.'));
    else shutdownController.signal.addEventListener('abort', onShutdown, { once: true });

    activeProbes.add(ctrl);
    activeProbeIds.add(serverConfig.id);
    try {
      const raw = await mcpProber(serverConfig, { stateDir, blockedOrigins, signal: ctrl.signal });
      return sanitizeProbeForClient(raw, serverConfig);
    } finally {
      clearTimeout(timer);
      res.off('close', onResClose);
      shutdownController.signal.removeEventListener('abort', onShutdown);
      activeProbes.delete(ctrl);
      activeProbeIds.delete(serverConfig.id);
    }
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
    if (broker.authenticateTrustSession(req, authRecord, false)) client.write(frame);
    else {
      sseClients.delete(client);
      client.end();
    }
  }

  function broadcastSnapshot(snap, authRecord) {
    if (!sseClients.size) return;
    const payload = { ...snap, originRole: 'trust', consoleOrigin: getConsoleOrigin(), kernel: getKernelSummary() };
    const frame = `event: status\ndata: ${JSON.stringify(payload)}\n\n`;
    for (const [client, req] of sseClients) sendStreamFrame(client, req, authRecord, frame);
  }

  function dropStreamsForSid(sid) {
    if (!sid) {
      for (const client of sseClients.keys()) client.end();
      sseClients.clear();
      return;
    }
    for (const [client, req] of sseClients) {
      if (parseCookieHeader(req.headers.cookie).get(TRUST_SID_COOKIE) === sid) {
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

      // Extension panels NEVER execute or render on Trust Origin.
      if (reqUrl.pathname === '/api/panels' || reqUrl.pathname.startsWith('/api/panels/')) {
        return sendJson(res, 403, {
          error: 'Extension panels are forbidden on the isolated Trust Origin.',
          code: 'CONSOLE_ORIGIN_ONLY',
          consoleOrigin: getConsoleOrigin(),
        });
      }

      if (req.method === 'GET' && reqUrl.pathname === '/') {
        if (!verifyFetchSiteSameOriginOrNone(req, true)) {
          return sendJson(res, 403, { error: 'Cross-site access denied.' });
        }
        const authRecord = loadCurrentAuthRecord();
        const session = broker.authenticateTrustSession(req, authRecord);
        const headersToSet = [];
        let csrfToken;
        if (session) {
          csrfToken = session.csrfToken;
        } else {
          const pre = broker.ensurePreAuthCookie(req, { kind: 'trust' });
          csrfToken = pre.csrfToken;
          if (pre.setCookie) headersToSet.push(pre.setCookie);
        }
        applySecurityHeaders(res, 'text/html; charset=utf-8');
        if (headersToSet.length) res.setHeader('Set-Cookie', headersToSet);
        res.statusCode = 200;
        res.end(renderTrustOriginHtml({ csrfToken, consoleOrigin: getConsoleOrigin() }));
        return;
      }

      if (req.method === 'GET' && reqUrl.pathname === '/trust.css') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        applySecurityHeaders(res, 'text/css; charset=utf-8');
        res.statusCode = 200;
        res.end(loadBuiltAsset('trust.css'));
        return;
      }

      if (req.method === 'GET' && reqUrl.pathname === '/trust.js') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        applySecurityHeaders(res, 'application/javascript; charset=utf-8');
        res.statusCode = 200;
        res.end(loadBuiltAsset('trust.js'));
        return;
      }

      if (req.method === 'GET' && reqUrl.pathname === '/api/auth/state') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        if (req.headers.origin && !verifyOriginForPort(req, actualPort)) return sendJson(res, 403, { error: 'Cross-origin request rejected.' });
        const authRecord = loadCurrentAuthRecord();
        const session = broker.authenticateTrustSession(req, authRecord);
        if (session) return sendJson(res, 200, formatAuthStatePayload(authRecord, session));
        const pre = broker.ensurePreAuthCookie(req, { kind: 'trust' });
        const extra = pre.setCookie ? { 'Set-Cookie': pre.setCookie } : {};
        return sendJson(res, 200, { ...formatAuthStatePayload(authRecord, null), csrfToken: pre.csrfToken }, extra);
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/auth/setup/password') {
        if (!verifyPreAuthMutation(req)) return sendJson(res, 403, { error: 'CSRF validation failed.' });
        const body = await readBodyJson(req);
        const roots = loadCurrentWorkspaceRoots();
        const authRecord = loadCurrentAuthRecord();
        if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' });
        const hasTicketInput = typeof body.setupToken === 'string' && body.setupToken.trim().length > 0;
        if (hasTicketInput && !checkRateLimit(res)) return;
        const authz = isSetupAuthorized(req, authRecord, body.setupToken);
        if (!authz.ok) {
          if (hasTicketInput) broker.recordAuthFailure();
          return sendJson(res, 401, { error: 'Valid single-use setup code from local webui-auth init is required.' });
        }
        if (authz.via === 'session' && !verifyAuthMutation(req, authz.session)) {
          return sendJson(res, 403, { error: 'Authenticated CSRF validation failed.' });
        }
        if (authz.via === 'session' && authRecord.passwordHash && !authRecord.requirePasskey) {
          if (!checkRateLimit(res)) return;
          if (typeof body.currentPassword !== 'string' || !verifyStrongPassword(body.currentPassword, authRecord.passwordHash)) {
            broker.recordAuthFailure();
            return sendJson(res, 401, { error: '当前强密码验证失败，无法重置密码。' });
          }
        }
        try {
          const updated = setStrongPasswordSync(stateDir, {
            password: body.password,
            setupToken: body.setupToken,
            allowBypassTicket: authz.via === 'session',
            workspaceRoots: roots,
            requirePrivateState,
            passkeyDetector,
          });
          broker.invalidateAllSessions();
          broker.clearAuthFailures();
          const newSession = broker.createTrustSession('password', updated.authVersion, updated.sessionPersistence);
          appendSanitizedConnectorLog(stateDir, 'webui_auth', { outcome: 'password_configured' });
          controlChannel?.publish({ type: 'trust.auth', outcome: 'password_configured' });
          return sendJson(res, 200, {
            ok: true,
            csrfToken: newSession.csrfToken,
            tabToken: newSession.tabToken,
            authState: formatAuthStatePayload(updated, newSession),
          }, { 'Set-Cookie': broker.loginCookies('trust', newSession.sid) });
        } catch (err) {
          const status = /PassKey/i.test(err?.message || '') ? 403 : 400;
          return sendJson(res, status, { error: err?.message || 'Cannot configure password.' });
        }
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/auth/passkey/report-support') {
        if (!verifyPreAuthMutation(req)) return sendJson(res, 403, { error: 'CSRF validation failed.' });
        const body = await readBodyJson(req);
        const roots = loadCurrentWorkspaceRoots();
        const authRecord = loadCurrentAuthRecord();
        if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' });
        const hasTicketInput = typeof body.setupToken === 'string' && body.setupToken.trim().length > 0;
        if (hasTicketInput && !checkRateLimit(res)) return;
        const authz = isSetupAuthorized(req, authRecord, body.setupToken);
        if (!authz.ok) {
          if (hasTicketInput) broker.recordAuthFailure();
          return sendJson(res, 401, { error: 'Authentication or setup code required.' });
        }
        if (authz.via === 'session' && !verifyAuthMutation(req, authz.session)) {
          return sendJson(res, 403, { error: 'Authenticated CSRF validation failed.' });
        }
        if (body.uvpa === true) {
          const wasRequired = Boolean(authRecord.requirePasskey);
          const updated = markPasskeyRequiredSync(stateDir, {
            workspaceRoots: roots,
            requirePrivateState,
            passkeyDetector,
          });
          if (!wasRequired) {
            broker.invalidateAllSessions();
            appendSanitizedConnectorLog(stateDir, 'webui_auth', { outcome: 'passkey_enforced' });
            const nextCsrf = broker.resetPreAuthCookies('trust');
            return sendJson(res, 200, {
              ok: true,
              csrfToken: nextCsrf.csrfToken,
              authState: formatAuthStatePayload(updated, null),
            }, { 'Set-Cookie': nextCsrf.setCookies });
          }
          return sendJson(res, 200, { ok: true, authState: formatAuthStatePayload(updated, authz.session) });
        }
        return sendJson(res, 200, { ok: true, authState: formatAuthStatePayload(authRecord, authz.session) });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/auth/setup/passkey/options') {
        if (!verifyPreAuthMutation(req)) return sendJson(res, 403, { error: 'CSRF validation failed.' });
        const body = await readBodyJson(req);
        const authRecord = loadCurrentAuthRecord();
        if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' });
        const hasTicketInput = typeof body.setupToken === 'string' && body.setupToken.trim().length > 0;
        if (hasTicketInput && !checkRateLimit(res)) return;
        const authz = isSetupAuthorized(req, authRecord, body.setupToken);
        if (!authz.ok) {
          if (hasTicketInput) broker.recordAuthFailure();
          return sendJson(res, 401, { error: 'Valid setup code or active authenticated session is required.' });
        }
        if (authz.via === 'session' && !verifyAuthMutation(req, authz.session)) {
          return sendJson(res, 403, { error: 'Authenticated CSRF validation failed.' });
        }
        const { challengeId, challenge } = broker.issueWebAuthnChallenge('register', authz.session?.sid || null);
        return sendJson(res, 200, {
          challengeId,
          publicKey: {
            challenge,
            rp: { name: 'LoomWard Trust Origin', id: 'localhost' },
            user: {
              id: toBase64Url(crypto.createHash('sha256').update(stateDir).digest().subarray(0, 16)),
              name: safeUserLabel(),
              displayName: 'LoomWard Owner',
            },
            pubKeyCredParams: [
              { type: 'public-key', alg: -7 },
              { type: 'public-key', alg: -35 },
              { type: 'public-key', alg: -257 },
              { type: 'public-key', alg: -8 },
            ],
            timeout: 120000,
            attestation: 'none',
            authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
            excludeCredentials: authRecord.passkeys.map(pk => ({
              type: 'public-key',
              id: pk.id,
              ...(Array.isArray(pk.transports) && pk.transports.length ? { transports: pk.transports } : {}),
            })),
          },
        });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/auth/setup/passkey/verify') {
        if (!verifyPreAuthMutation(req)) return sendJson(res, 403, { error: 'CSRF validation failed.' });
        const body = await readBodyJson(req);
        const roots = loadCurrentWorkspaceRoots();
        const authRecord = loadCurrentAuthRecord();
        if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' });
        const hasTicketInput = typeof body.setupToken === 'string' && body.setupToken.trim().length > 0;
        if (hasTicketInput && !checkRateLimit(res)) return;
        const authz = isSetupAuthorized(req, authRecord, body.setupToken);
        if (!authz.ok) {
          if (hasTicketInput) broker.recordAuthFailure();
          return sendJson(res, 401, { error: 'Valid setup code or authenticated session is required.' });
        }
        if (authz.via === 'session' && !verifyAuthMutation(req, authz.session)) {
          return sendJson(res, 403, { error: 'Authenticated CSRF validation failed.' });
        }
        try {
          const ch = broker.consumeWebAuthnChallenge(body.challengeId, 'register', authz.session?.sid || null);
          const verified = verifyRegistrationResponse({
            credential: body.credential,
            expectedChallenge: ch.challenge,
            expectedRpId: 'localhost',
            allowedOrigins: new Set([`http://localhost:${actualPort}`]),
          });
          const updated = enrollPasskeySync(stateDir, {
            credential: verified,
            label: body.label || 'Local PassKey',
            workspaceRoots: roots,
            requirePrivateState,
            passkeyDetector,
          });
          broker.invalidateAllSessions();
          broker.clearAuthFailures();
          const newSession = broker.createTrustSession('passkey', updated.authVersion, updated.sessionPersistence);
          appendSanitizedConnectorLog(stateDir, 'webui_auth', { outcome: 'passkey_enrolled' });
          controlChannel?.publish({ type: 'trust.auth', outcome: 'passkey_enrolled' });
          return sendJson(res, 200, {
            ok: true,
            csrfToken: newSession.csrfToken,
            tabToken: newSession.tabToken,
            authState: formatAuthStatePayload(updated, newSession),
          }, { 'Set-Cookie': broker.loginCookies('trust', newSession.sid) });
        } catch (err) {
          return sendJson(res, 400, { error: err?.message || 'PassKey registration verification failed.' });
        }
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/auth/login/password') {
        if (!verifyPreAuthMutation(req)) return sendJson(res, 403, { error: 'CSRF validation failed.' });
        if (!checkRateLimit(res)) return;
        const body = await readBodyJson(req);
        if (!checkRateLimit(res)) return;
        const authRecord = loadCurrentAuthRecord();
        if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' });
        if (authRecord.requirePasskey || authRecord.passkeys.length > 0 || authRecord.hostPasskeySupported) {
          return sendJson(res, 403, { error: 'PassKey authentication is mandatory on this machine.' });
        }
        if (!authRecord.initialized || !authRecord.passwordHash) {
          return sendJson(res, 401, { error: 'Strong password is not configured yet.' });
        }
        if (!verifyStrongPassword(body.password, authRecord.passwordHash)) {
          broker.recordAuthFailure();
          appendSanitizedConnectorLog(stateDir, 'webui_auth', { outcome: 'password_failed' });
          return sendJson(res, 401, { error: 'Invalid Trust Origin password.' });
        }
        broker.clearAuthFailures();
        const newSession = broker.createTrustSession('password', authRecord.authVersion, authRecord.sessionPersistence);
        appendSanitizedConnectorLog(stateDir, 'webui_auth', { outcome: 'password_login_ok' });
        return sendJson(res, 200, {
          ok: true,
          csrfToken: newSession.csrfToken,
          tabToken: newSession.tabToken,
          authState: formatAuthStatePayload(authRecord, newSession),
        }, { 'Set-Cookie': broker.loginCookies('trust', newSession.sid) });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/auth/passkey/login/options') {
        if (!verifyPreAuthMutation(req)) return sendJson(res, 403, { error: 'CSRF validation failed.' });
        if (!checkRateLimit(res)) return;
        await readBodyJson(req);
        if (!checkRateLimit(res)) return;
        const authRecord = loadCurrentAuthRecord();
        if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' });
        if (!authRecord.passkeys.length) return sendJson(res, 400, { error: 'No PassKey is enrolled yet.' });
        const { challengeId, challenge } = broker.issueWebAuthnChallenge('login');
        return sendJson(res, 200, {
          challengeId,
          publicKey: {
            challenge,
            rpId: 'localhost',
            timeout: 120000,
            userVerification: 'required',
            allowCredentials: authRecord.passkeys.map(pk => ({
              type: 'public-key',
              id: pk.id,
              ...(Array.isArray(pk.transports) && pk.transports.length ? { transports: pk.transports } : {}),
            })),
          },
        });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/auth/passkey/login/verify') {
        if (!verifyPreAuthMutation(req)) return sendJson(res, 403, { error: 'CSRF validation failed.' });
        if (!checkRateLimit(res)) return;
        const body = await readBodyJson(req);
        if (!checkRateLimit(res)) return;
        const roots = loadCurrentWorkspaceRoots();
        const authRecord = loadCurrentAuthRecord();
        if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' });
        try {
          const ch = broker.consumeWebAuthnChallenge(body.challengeId, 'login', null);
          const stored = authRecord.passkeys.find(pk => pk.id === body.credential?.id);
          if (!stored) throw new Error('Unknown PassKey credential.');
          const { newSignCount } = verifyAuthenticationResponse({
            credential: body.credential,
            storedPasskey: stored,
            expectedChallenge: ch.challenge,
            expectedRpId: 'localhost',
            allowedOrigins: new Set([`http://localhost:${actualPort}`]),
          });
          updatePasskeySignCountSync(stateDir, {
            credentialId: stored.id,
            newSignCount,
            workspaceRoots: roots,
            requirePrivateState,
            passkeyDetector,
          });
          broker.clearAuthFailures();
          const refreshed = loadCurrentAuthRecord();
          const newSession = broker.createTrustSession('passkey', refreshed.authVersion, refreshed.sessionPersistence);
          appendSanitizedConnectorLog(stateDir, 'webui_auth', { outcome: 'passkey_login_ok' });
          return sendJson(res, 200, {
            ok: true,
            csrfToken: newSession.csrfToken,
            tabToken: newSession.tabToken,
            authState: formatAuthStatePayload(refreshed, newSession),
          }, { 'Set-Cookie': broker.loginCookies('trust', newSession.sid) });
        } catch (err) {
          broker.recordAuthFailure();
          appendSanitizedConnectorLog(stateDir, 'webui_auth', { outcome: 'passkey_failed' });
          return sendJson(res, 401, { error: err?.message || 'PassKey authentication failed.' });
        }
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/auth/logout') {
        const cookies = parseCookieHeader(req.headers.cookie);
        const sid = cookies.get(TRUST_SID_COOKIE);
        const activeSession = broker.getTrustSessionBySid(sid);
        if (activeSession) {
          if (!verifyAuthMutation(req, activeSession)) return sendJson(res, 403, { error: 'CSRF validation failed.' });
        } else if (!verifyPreAuthMutation(req)) {
          return sendJson(res, 403, { error: 'CSRF validation failed.' });
        }
        await readBodyJson(req);
        if (sid) broker.revokeTrustSession(sid);
        const nextCsrf = broker.resetPreAuthCookies('trust');
        return sendJson(res, 200, { ok: true, csrfToken: nextCsrf.csrfToken }, { 'Set-Cookie': nextCsrf.setCookies });
      }

      // Authenticated Trust Origin endpoints below.
      const authRecord = loadCurrentAuthRecord();
      if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' });
      const session = broker.authenticateTrustSession(req, authRecord);
      if (!session) {
        return sendJson(res, 401, {
          error: 'Trust Origin authentication is required.',
          mode: publicWebUiAuthSummary(authRecord).mode,
        });
      }

      if (req.method === 'GET' && reqUrl.pathname === '/api/status') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        const snap = await refreshSnapshot({ force: false });
        return sendJson(res, 200, {
          ...snap,
          originRole: 'trust',
          consoleOrigin: getConsoleOrigin(),
          trustOrigin: getTrustOrigin(),
          kernel: getKernelSummary(),
        });
      }

      if (req.method === 'GET' && reqUrl.pathname === '/api/events') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site event stream rejected.' });
        if (sseClients.size >= MAX_SSE_CLIENTS) return sendJson(res, 429, { error: 'Too many active Trust streams.' });
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
        const cached = getLastSnapshot();
        if (cached) {
          const payload = { ...cached, originRole: 'trust', consoleOrigin: getConsoleOrigin(), kernel: getKernelSummary() };
          sendStreamFrame(res, req, authRecord, `event: status\ndata: ${JSON.stringify(payload)}\n\n`);
        } else {
          await refreshSnapshot({ force: false });
        }
        return;
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/trust/issue-console-ticket') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const issued = broker.issueConsoleHandoffTicket(session);
        const consoleOrigin = getConsoleOrigin();
        return sendJson(res, 200, {
          ok: true,
          ticket: issued.ticket,
          expiresAt: issued.expiresAt,
          consoleOrigin,
          handoffUrl: consoleOrigin ? `${consoleOrigin}/#ticket=${issued.ticket}` : null,
        });
      }

      if (req.method === 'GET' && reqUrl.pathname === '/api/trust/units') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        return sendJson(res, 200, { ok: true, ...getKernelSummary() });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/trust/decide') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const { body } = parsed;
        if (typeof body?.decisionId !== 'string' || typeof body?.approved !== 'boolean') {
          return sendJson(res, 400, { error: 'decisionId and boolean approved are required.' });
        }
        if (typeof trustDecider !== 'function') {
          return sendJson(res, 404, { error: 'No pending extension trust decision found.' });
        }
        const resolved = await trustDecider(body.decisionId, body.approved);
        if (!resolved) return sendJson(res, 404, { error: 'Pending trust decision not found or expired.' });
        controlChannel?.publish({
          type: 'trust.unit_decision',
          decisionId: body.decisionId.slice(0, 16),
          approved: body.approved,
        });
        return sendJson(res, 200, { ok: true, decisionId: body.decisionId, approved: body.approved });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/capabilities') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const { body } = parsed;
        const roots = loadCurrentWorkspaceRoots();
        const config = readTrustedJsonFile(path.join(stateDir, 'config.json'), requirePrivateState);
        const patch = {};
        if (Object.hasOwn(body, 'fileRead')) patch.fileRead = body.fileRead;
        if (Object.hasOwn(body, 'fileWrite')) patch.fileWrite = body.fileWrite;
        if (Object.hasOwn(body, 'allowExec')) patch.allowExec = body.allowExec;
        if (Object.hasOwn(body, 'tools')) patch.tools = body.tools;
        if (!Object.keys(patch).length) return sendJson(res, 400, { error: 'No capability fields provided.' });
        let updated;
        try {
          updated = writeCapabilitiesSync(stateDir, patch, {
            configAllowExec: config?.allowExec === true,
            requirePrivateState,
            workspaceRoots: roots,
          });
        } catch (err) {
          return sendJson(res, 400, { error: err?.message || 'Invalid capability update.' });
        }
        const modeLabel = `read=${updated.fileRead ? 'on' : 'off'},write=${updated.fileWrite ? 'on' : 'off'},exec=${updated.allowExec ? 'on' : 'off'}`;
        appendSanitizedConnectorLog(stateDir, 'capability_changed', { mode: modeLabel });
        controlChannel?.publish({ type: 'capability.changed', mode: modeLabel });
        const snap = await refreshSnapshot({ force: true });
        return sendJson(res, 200, { ok: true, capabilities: updated, snapshot: snap });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/auth/settings') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const targetMode = parsed.body?.sessionPersistence;
        if (targetMode !== 'tab' && targetMode !== 'browser') {
          return sendJson(res, 400, { error: 'sessionPersistence must be "tab" or "browser".' });
        }
        const roots = loadCurrentWorkspaceRoots();
        const updated = setSessionPersistenceSync(stateDir, {
          sessionPersistence: targetMode,
          workspaceRoots: roots,
          requirePrivateState,
          passkeyDetector,
        });
        let rotatedTabToken = session.tabToken;
        if (targetMode === 'tab') {
          rotatedTabToken = crypto.randomBytes(32).toString('base64url');
          session.authVersion = updated.authVersion;
          session.sessionPersistence = 'tab';
          broker.pruneOtherTrustSessions(session.sid);
          broker.revokeChildConsoleSessions?.(session.sid);
        } else {
          broker.updateAllSessionsPersistence(updated.authVersion, 'browser');
          broker.pruneOtherTrustSessions(session.sid);
        }
        appendSanitizedConnectorLog(stateDir, 'webui_auth', { outcome: `session_policy_${targetMode}` });
        let snap = null;
        try {
          snap = await refreshSnapshot({ force: true, broadcast: targetMode !== 'tab' });
        } finally {
          if (targetMode === 'tab') {
            session.tabToken = rotatedTabToken;
            dropStreamsForSid(null);
          }
        }
        return sendJson(res, 200, {
          ok: true,
          csrfToken: session.csrfToken,
          ...(targetMode === 'tab' ? { tabToken: rotatedTabToken } : {}),
          authState: formatAuthStatePayload(updated, session),
          snapshot: snap,
        });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/auth/passkey/delete') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const roots = loadCurrentWorkspaceRoots();
        let updated;
        try {
          updated = deletePasskeySync(stateDir, {
            credentialId: parsed.body?.credentialId,
            workspaceRoots: roots,
            requirePrivateState,
            passkeyDetector,
          });
        } catch (err) {
          return sendJson(res, 400, { error: err?.message || 'Cannot delete PassKey.' });
        }
        session.authVersion = updated.authVersion;
        broker.pruneOtherTrustSessions(session.sid);
        broker.revokeChildConsoleSessions?.(session.sid);
        appendSanitizedConnectorLog(stateDir, 'webui_auth', { outcome: 'passkey_deleted' });
        const snap = await refreshSnapshot({ force: true });
        return sendJson(res, 200, {
          ok: true,
          csrfToken: session.csrfToken,
          authState: formatAuthStatePayload(updated, session),
          snapshot: snap,
        });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/auth/passkey/switch-password') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const { body, authRecord: freshAuth } = parsed;
        if (session.authMethod !== 'passkey' || freshAuth.passkeys.length === 0) {
          return sendJson(res, 403, { error: 'Switching to strong password requires an active PassKey session.' });
        }
        const roots = loadCurrentWorkspaceRoots();
        let updated;
        try {
          updated = switchToStrongPasswordSync(stateDir, {
            password: body?.password,
            workspaceRoots: roots,
            requirePrivateState,
            passkeyDetector,
          });
        } catch (err) {
          const status = /PassKey/i.test(err?.message || '') ? 403 : 400;
          return sendJson(res, status, { error: err?.message || 'Cannot switch to password mode.' });
        }
        broker.invalidateAllSessions();
        const newSession = broker.createTrustSession('password', updated.authVersion, updated.sessionPersistence);
        appendSanitizedConnectorLog(stateDir, 'webui_auth', { outcome: 'switched_to_password' });
        const snap = await refreshSnapshot({ force: true, broadcast: false });
        return sendJson(res, 200, {
          ok: true,
          csrfToken: newSession.csrfToken,
          tabToken: newSession.tabToken,
          authState: formatAuthStatePayload(updated, newSession),
          snapshot: snap,
        }, { 'Set-Cookie': broker.loginCookies('trust', newSession.sid) });
      }

      const reviewing = reqUrl.pathname === '/api/approvals/review';
      if (req.method === 'POST' && (reviewing || reqUrl.pathname === '/api/approvals/approve')) {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const { body } = parsed;
        if (typeof body?.id !== 'string' || !APPROVAL_ID.test(body.id) || (!reviewing && (typeof body.digest !== 'string' || !/^[a-f0-9]{64}$/.test(body.digest)))) {
          return sendJson(res, 400, { error: 'Invalid approval ID or review digest.' });
        }
        const approvalsDir = path.join(stateDir, 'approvals');
        if (fs.lstatSync(approvalsDir, { throwIfNoEntry: false })?.isSymbolicLink()) {
          return sendJson(res, 400, { error: 'Approval directory must not be a link.' });
        }
        const pending = await readJson(path.join(approvalsDir, `${body.id}.request.json`)).catch(() => null);
        if (!validRequest(pending, body.id, Date.now())) {
          return sendJson(res, 404, { error: 'Pending approval request not found or expired.' });
        }
        const digest = policyDigest(pending);
        if (reviewing) {
          const { safeText } = await import('../../../local/approval-cli.mjs');
          const requestText = JSON.stringify(pending.request, null, 2).split('\n').map(safeText).join('\n');
          return sendJson(res, 200, { id: pending.id, digest, requestText });
        }
        if (!timingSafeEqualText(digest, body.digest)) {
          return sendJson(res, 409, { error: 'Approval request changed during review; refresh and inspect again.' });
        }
        try {
          await approveRequest(approvalsDir, pending);
        } catch (err) {
          return sendJson(res, 409, { error: err?.message || 'Failed to publish approval.' });
        }
        const rawApprovedTool = typeof pending.request?.params?.name === 'string' ? pending.request.params.name : '';
        const safeTool = (KNOWN_TOOL_NAMES.has(rawApprovedTool) || isValidExternalToolName(rawApprovedTool)) ? rawApprovedTool : 'unknown';
        appendSanitizedConnectorLog(stateDir, 'approval_granted', { tool: safeTool, approvalIdShort: pending.id.slice(0, 8) });
        controlChannel?.publish({ type: 'approval.granted', tool: safeTool, approvalIdShort: pending.id.slice(0, 8) });
        const snap = await refreshSnapshot({ force: true });
        return sendJson(res, 200, { ok: true, id: pending.id, snapshot: snap });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/approvals/reject') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const { body } = parsed;
        if (typeof body?.id !== 'string' || !APPROVAL_ID.test(body.id)) {
          return sendJson(res, 400, { error: 'Invalid approval ID.' });
        }
        const approvalsDir = path.join(stateDir, 'approvals');
        try {
          const dirStat = fs.lstatSync(approvalsDir);
          if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) {
            return sendJson(res, 400, { error: 'Approval directory must not be a link.' });
          }
          const approvedPath = path.join(approvalsDir, `${body.id}.approved.json`);
          const apStat = fs.lstatSync(approvedPath, { throwIfNoEntry: false });
          if (apStat) {
            if (apStat.isSymbolicLink() || !apStat.isFile() || apStat.nlink !== 1) return sendJson(res, 400, { error: 'Invalid approval marker file.' });
            try { fs.unlinkSync(approvedPath); } catch (e) { if (e?.code !== 'ENOENT') throw e; }
          }
          const reqPath = path.join(approvalsDir, `${body.id}.request.json`);
          const st = fs.lstatSync(reqPath);
          if (st.isSymbolicLink() || !st.isFile() || st.nlink !== 1) return sendJson(res, 400, { error: 'Invalid approval file.' });
          let loggedTool = 'unknown';
          try {
            const fd = fs.openSync(reqPath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
            try {
              const fst = fs.fstatSync(fd);
              if (fst.isFile() && fst.size <= MAX_RECORD_BYTES) {
                const raw = JSON.parse(fs.readFileSync(fd, 'utf8'));
                const candidate = typeof raw?.request?.params?.name === 'string' ? raw.request.params.name : '';
                if (KNOWN_TOOL_NAMES.has(candidate) || isValidExternalToolName(candidate)) loggedTool = candidate;
              }
            } finally { fs.closeSync(fd); }
          } catch {}
          fs.unlinkSync(reqPath);
          appendSanitizedConnectorLog(stateDir, 'approval_rejected', { tool: loggedTool, approvalIdShort: body.id.slice(0, 8) });
          controlChannel?.publish({ type: 'approval.rejected', tool: loggedTool, approvalIdShort: body.id.slice(0, 8) });
        } catch (err) {
          if (err?.code === 'ENOENT') return sendJson(res, 404, { error: 'Approval request already removed or expired.' });
          return sendJson(res, 400, { error: err?.message || 'Cannot remove approval request.' });
        }
        const snap = await refreshSnapshot({ force: true });
        return sendJson(res, 200, { ok: true, id: body.id, snapshot: snap });
      }

      if (req.method === 'GET' && reqUrl.pathname === '/api/mcp-servers') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        const roots = loadCurrentWorkspaceRoots();
        const mcpServers = publicMcpRegistrySnapshot(stateDir, { workspaceRoots: roots, blockedOrigins: getBlockedOrigins() });
        return sendJson(res, 200, { ok: true, mcpServers });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/mcp-servers/save') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const { body } = parsed;
        const roots = loadCurrentWorkspaceRoots();
        const blockedOrigins = getBlockedOrigins();
        let saved;
        try {
          saved = upsertMcpServerSync(stateDir, pickEditableMcpFields(body), {
            workspaceRoots: roots,
            requirePrivateState,
            blockedOrigins,
            replaceSecrets: body?.replaceSecrets === true,
          });
        } catch (err) {
          return sendJson(res, 400, { error: err?.message || 'Invalid MCP server configuration.' });
        }
        appendSanitizedConnectorLog(stateDir, 'mcp_server_updated', { serverId: saved.id, mode: saved.transport });
        let probe = null;
        let deletedDuringProbe = false;
        if (body?.probe === true) {
          const fp = serverConfigFingerprint(saved);
          try {
            probe = await runBoundedProbe(saved, res, blockedOrigins, 30000);
            try {
              saved = saveMcpProbeResultSync(stateDir, saved.id, probe, {
                workspaceRoots: roots,
                requirePrivateState,
                blockedOrigins,
                expectedFingerprint: fp,
              });
            } catch (err) {
              if (err?.code === 'NOT_FOUND') deletedDuringProbe = true;
              else throw err;
            }
          } catch (err) {
            probe = { ok: false, latencyMs: 0, error: redactSecretsFromText(err?.message || 'Probe failed.', saved) };
          }
          appendSanitizedConnectorLog(stateDir, 'mcp_server_probed', {
            serverId: saved.id,
            outcome: probe.ok ? `ok_${probe.tools?.length || 0}` : 'failed',
          });
        }
        controlChannel?.publish({ type: 'mcp.updated', serverId: saved.id });
        const snap = await refreshSnapshot({ force: true });
        return sendJson(res, 200, { ok: true, server: deletedDuringProbe ? null : publicMcpServerSummary(saved), probe, snapshot: snap });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/mcp-servers/import') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const roots = loadCurrentWorkspaceRoots();
        const blockedOrigins = getBlockedOrigins();
        let parsedList;
        try { parsedList = parseStandardMcpJson(parsed.body?.json ?? parsed.body?.config); }
        catch (err) { return sendJson(res, 400, { error: err?.message || 'Invalid standard MCP JSON payload.' }); }
        let savedEntries;
        try {
          savedEntries = upsertMcpServersSync(stateDir, parsedList, {
            workspaceRoots: roots,
            requirePrivateState,
            blockedOrigins,
            replaceSecrets: true,
          });
        } catch (err) {
          return sendJson(res, 400, { error: err?.message || 'Failed to save imported MCP servers.' });
        }
        const importedIds = savedEntries.map(s => s.id);
        appendSanitizedConnectorLog(stateDir, 'mcp_server_imported', { outcome: `count=${importedIds.length}` });
        controlChannel?.publish({ type: 'mcp.imported', count: importedIds.length });
        const snap = await refreshSnapshot({ force: true });
        return sendJson(res, 200, { ok: true, importedIds, probes: {}, snapshot: snap });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/mcp-servers/toggle') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const { body } = parsed;
        const roots = loadCurrentWorkspaceRoots();
        const blockedOrigins = getBlockedOrigins();
        let updated;
        try {
          updated = toggleMcpServerSync(
            stateDir,
            { id: body?.id, enabled: body?.enabled, toolName: body?.toolName },
            { workspaceRoots: roots, requirePrivateState, blockedOrigins },
          );
        } catch (err) {
          return sendJson(res, 400, { error: err?.message || 'Cannot update MCP server toggle.' });
        }
        appendSanitizedConnectorLog(stateDir, 'mcp_server_toggled', { serverId: updated.id });
        controlChannel?.publish({ type: 'mcp.toggled', serverId: updated.id });
        const snap = await refreshSnapshot({ force: true });
        return sendJson(res, 200, { ok: true, server: publicMcpServerSummary(updated), snapshot: snap });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/mcp-servers/probe') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const roots = loadCurrentWorkspaceRoots();
        const blockedOrigins = getBlockedOrigins();
        const reg = readMcpServersSync(stateDir, { workspaceRoots: roots, blockedOrigins });
        if (reg.error) return sendJson(res, 400, { error: reg.error });
        const target = reg.servers.find(s => s.id === parsed.body?.id);
        if (!target) return sendJson(res, 404, { error: 'MCP server not found.' });
        const fp = serverConfigFingerprint(target);
        let probe;
        try {
          probe = await runBoundedProbe(target, res, blockedOrigins, 30000);
        } catch (err) {
          if (Number.isInteger(err?.status)) throw err;
          probe = { ok: false, latencyMs: 0, error: redactSecretsFromText(err?.message || 'Probe failed.', target) };
        }
        let updated = target;
        let deletedDuringProbe = false;
        try {
          updated = saveMcpProbeResultSync(stateDir, target.id, probe, {
            workspaceRoots: roots,
            requirePrivateState,
            blockedOrigins,
            expectedFingerprint: fp,
          });
        } catch (err) {
          if (err?.code === 'NOT_FOUND') deletedDuringProbe = true;
          else throw err;
        }
        appendSanitizedConnectorLog(stateDir, 'mcp_server_probed', {
          serverId: target.id,
          outcome: probe.ok ? `ok_${probe.tools?.length || 0}` : 'failed',
        });
        const snap = await refreshSnapshot({ force: true });
        return sendJson(res, 200, { ok: true, probe, server: deletedDuringProbe ? null : publicMcpServerSummary(updated), snapshot: snap });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/mcp-servers/delete') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const roots = loadCurrentWorkspaceRoots();
        const blockedOrigins = getBlockedOrigins();
        let removed;
        try {
          removed = deleteMcpServerSync(stateDir, parsed.body?.id, {
            workspaceRoots: roots,
            requirePrivateState,
            blockedOrigins,
          });
        } catch (err) {
          return sendJson(res, err?.code === 'NOT_FOUND' ? 404 : 400, { error: err?.message || 'Cannot delete MCP server.' });
        }
        appendSanitizedConnectorLog(stateDir, 'mcp_server_deleted', { serverId: removed.deleted });
        controlChannel?.publish({ type: 'mcp.deleted', serverId: removed.deleted });
        const snap = await refreshSnapshot({ force: true });
        return sendJson(res, 200, { ok: true, ...removed, snapshot: snap });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/service') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const { body } = parsed;
        if (!['start', 'stop', 'restart', 'enable-autostart', 'disable-autostart'].includes(body.action)) {
          return sendJson(res, 400, { error: 'Unsupported service action.' });
        }
        if (serviceActionInFlight) return sendJson(res, 409, { error: 'Another service action is already in progress.' });
        serviceActionInFlight = true;
        try {
          await serviceController(body.action);
        } finally {
          serviceActionInFlight = false;
        }
        appendSanitizedConnectorLog(stateDir, 'service_action', { outcome: body.action });
        controlChannel?.publish({ type: 'service.action', action: body.action });
        const snap = await refreshSnapshot({ force: true });
        return sendJson(res, 200, { ok: true, action: body.action, snapshot: snap });
      }

      return sendJson(res, 404, { error: 'Not found.' });
    } catch (error) {
      const status = Number.isInteger(error?.status) ? error.status : 500;
      const message = status < 500 ? error.message : 'Internal Trust Origin error.';
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
    url: getTrustOrigin(),
    hasSseClients: () => sseClients.size > 0,
    broadcastSnapshot,
    dropStreamsForSid,
    async close() {
      clearInterval(heartbeatTimer);
      shutdownController.abort();
      for (const ctrl of activeProbes) ctrl.abort();
      activeProbes.clear();
      activeProbeIds.clear();
      for (const client of sseClients.keys()) client.end();
      sseClients.clear();
      await new Promise(resolve => {
        server.closeAllConnections?.();
        server.close(resolve);
      });
    },
  });
}
