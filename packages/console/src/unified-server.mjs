// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Single-Origin loopback HTTP server (default 127.0.0.1:18797):
// serves authentication (PassKey/WebAuthn & strong password), exact two-step approvals,
// capability switches, moderation policy & write-only plugin secrets, MCP registry/probes,
// SSE live telemetry, tool catalog, and read-only declarative console:panel@1 views.
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
import { readModerationConfigSync, writeModerationConfigSync } from '../../../local/moderation-config.mjs';
import {
  readAntileakConfigSync,
  writeAntileakConfigSync,
  validatePythonRegexList,
  runAntileakDryRun,
  runAntileakDoctor,
  runAntileakRefresh,
} from '../../../local/antileak-config.mjs';
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
  isLoopbackHost,
  parseCookieHeader,
  readBodyJson,
  readTrustedJsonFile,
  sendJson,
  timingSafeEqualText,
  verifyFetchSiteSameOriginOrNone,
  verifyHostForPort,
  verifyOriginForPort,
} from './http-security.mjs';
import { CONSOLE_PREVIEW_LOCKED_COOKIE, CONSOLE_SID_COOKIE } from './session-broker.mjs';
import { BRAND_ICON_SVG, loadBuiltAsset, renderConsoleHtml } from './html.mjs';

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

function mapCredentialDescriptors(passkeys) {
  return passkeys.map(pk => ({
    type: 'public-key',
    id: pk.id,
    ...(Array.isArray(pk.transports) && pk.transports.length ? { transports: pk.transports } : {}),
  }));
}

export async function createUnifiedConsoleServer({
  host = '127.0.0.1',
  port = 18797,
  stateDir,
  requirePrivateState = true,
  broker,
  controlChannel,
  panelCollector,
  loadCurrentWorkspaceRoots,
  loadCurrentAuthRecord,
  refreshSnapshot,
  getLastSnapshot,
  getBlockedOrigins,
  passkeyDetector,
  mcpProber = probeMcpServer,
  serviceController,
  getKernelSummary = () => ({ roots: [], units: [], pendingTrustDecisions: [] }),
  getRecentChannelEvents = () => [],
  trustDecider = null,
  getPluginSecretsAdmin = () => null,
  ollamaController = null,
  previewAutoSession = false,
}) {
  if (previewAutoSession && !isLoopbackHost(host)) {
    throw new Error('Preview auto-session mode is strictly restricted to loopback hosts.');
  }
  const sseClients = new Map();
  const activeProbes = new Set();
  const activeProbeIds = new Set();
  const shutdownController = new AbortController();
  let serviceActionInFlight = false;
  let actualPort = port;

  const getConsoleOrigin = () => formatLoopbackOrigin(host, actualPort);
  const isPreviewAutoEligible = authRecord => Boolean(
    previewAutoSession === true
    && isLoopbackHost(host)
    && authRecord
    && !authRecord.error
    && !authRecord.initialized,
  );

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
      previewMode: Boolean(session?.authMethod === 'preview'),
      previewAvailable: isPreviewAutoEligible(authRecord),
      originRole: 'unified',
      consoleOrigin: getConsoleOrigin(),
      ...(session ? { csrfToken: session.csrfToken } : {}),
      lockedUntilMs: broker.getLockedUntilMs(),
      ...publicWebUiAuthSummary(authRecord, { includePrivateMeta: Boolean(session) }),
    };
  }

  function isSetupAuthorized(req, authRecord, bodySetupToken) {
    const session = broker.authenticateSession(req, authRecord);
    if (session) return { ok: true, via: 'session', session };
    if (verifySetupTicketMatch(authRecord, bodySetupToken)) return { ok: true, via: 'ticket', session: null };
    return { ok: false };
  }

  function verifyPreAuthMutation(req) {
    if (!verifyOriginForPort(req, actualPort)) return false;
    if (!verifyFetchSiteSameOriginOrNone(req, false)) return false;
    return broker.verifyPreAuthCsrf(req);
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
    const live = broker.authenticateSession(req, freshAuth, true);
    if (!live || live !== session) {
      sendJson(res, 401, {
        error: 'Console authentication is required.',
        code: 'CONSOLE_AUTH_REQUIRED',
        mode: publicWebUiAuthSummary(freshAuth).mode,
      });
      return null;
    }
    return { body, authRecord: freshAuth };
  }

  function enrichSnapshot(snap, panels) {
    const rawKernel = getKernelSummary() || {};
    const normalizedSecurity = snap?.security
      ? {
          ...snap.security,
          requirePasskey: Boolean(snap.security.passkeyRequired ?? snap.security.requirePasskey),
        }
      : undefined;
    return {
      ...snap,
      ...(normalizedSecurity ? { security: normalizedSecurity } : {}),
      originRole: 'unified',
      consoleOrigin: getConsoleOrigin(),
      kernel: {
        roots: Array.isArray(rawKernel.roots) ? rawKernel.roots : [],
        units: Array.isArray(rawKernel.units) ? rawKernel.units : [],
        pendingTrustDecisions: Array.isArray(rawKernel.pendingTrustDecisions) ? rawKernel.pendingTrustDecisions : [],
      },
      channelEvents: getRecentChannelEvents(),
      panels: Array.isArray(panels) ? panels : [],
    };
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
    if (broker.authenticateSession(req, authRecord, false)) client.write(frame);
    else {
      sseClients.delete(client);
      client.end();
    }
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
    const onShutdown = () => ctrl.abort(new Error('Console server shutting down.'));
    res.on('close', onResClose);
    if (shutdownController.signal.aborted) ctrl.abort(new Error('Console server shutting down.'));
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

  async function runAndPersistBoundedProbe(
    target,
    res,
    { roots, blockedOrigins, maxWallMs = 30000, conflictMode = 'rethrow' } = {},
  ) {
    const fp = serverConfigFingerprint(target);
    let probe;
    try {
      probe = await runBoundedProbe(target, res, blockedOrigins, maxWallMs);
    } catch (err) {
      if (Number.isInteger(err?.status)) {
        if ((err.status === 409 || err.status === 429) && conflictMode !== 'rethrow') {
          const fallback = conflictMode === 'record' ? 'Probe skipped.' : 'Probe unavailable.';
          return {
            probe: {
              ok: false,
              latencyMs: 0,
              error: redactSecretsFromText(err?.message || fallback, target),
            },
            server: target,
            deletedDuringProbe: false,
            status: err.status,
          };
        }
        throw err;
      }
      probe = {
        ok: false,
        latencyMs: 0,
        error: redactSecretsFromText(err?.message || 'Probe failed.', target),
      };
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
    return {
      probe,
      server: updated,
      deletedDuringProbe,
      status: null,
    };
  }

  async function handlePreAuthRoute(req, res, pathname) {
    if (req.method === 'GET' && pathname === '/') {
      if (!verifyFetchSiteSameOriginOrNone(req, true)) {
        return sendJson(res, 403, { error: 'Cross-site access denied.' }), true;
      }
      const authRecord = loadCurrentAuthRecord();
      const session = broker.authenticateSession(req, authRecord);
      const headersToSet = [];
      let csrfToken;
      if (session) {
        csrfToken = session.csrfToken;
      } else {
        const pre = broker.ensurePreAuthCookie(req);
        csrfToken = pre.csrfToken;
        if (pre.setCookie) headersToSet.push(pre.setCookie);
      }
      applySecurityHeaders(res, 'text/html; charset=utf-8');
      if (headersToSet.length) res.setHeader('Set-Cookie', headersToSet);
      res.statusCode = 200;
      res.end(renderConsoleHtml({ csrfToken }));
      return true;
    }

    if (req.method === 'GET' && (pathname === '/console.css' || pathname === '/console.js')) {
      if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site request rejected.' }), true;
      applySecurityHeaders(res, pathname.endsWith('.css') ? 'text/css; charset=utf-8' : 'application/javascript; charset=utf-8');
      res.statusCode = 200;
      res.end(loadBuiltAsset(pathname.slice(1)));
      return true;
    }

    if (req.method === 'GET' && (pathname === '/brand-icon.svg' || pathname === '/favicon.svg')) {
      if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site request rejected.' }), true;
      applySecurityHeaders(res, 'image/svg+xml; charset=utf-8');
      res.statusCode = 200;
      res.end(BRAND_ICON_SVG);
      return true;
    }

    if (req.method === 'GET' && pathname === '/api/auth/state') {
      if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site request rejected.' }), true;
      if (req.headers.origin && !verifyOriginForPort(req, actualPort)) return sendJson(res, 403, { error: 'Cross-origin request rejected.' }), true;
      const authRecord = loadCurrentAuthRecord();
      const session = broker.authenticateSession(req, authRecord);
      if (session) return sendJson(res, 200, formatAuthStatePayload(authRecord, session)), true;
      const cookies = parseCookieHeader(req.headers.cookie);
      if (isPreviewAutoEligible(authRecord) && cookies.get(CONSOLE_PREVIEW_LOCKED_COOKIE) !== '1') {
        const previewSession = broker.createSession('preview', authRecord.authVersion || 0, authRecord.sessionPersistence || 'tab');
        appendSanitizedConnectorLog(stateDir, 'webui_auth', { outcome: 'preview_auto_session' });
        return sendJson(res, 200, {
          ...formatAuthStatePayload(authRecord, previewSession),
          tabToken: previewSession.tabToken,
        }, { 'Set-Cookie': broker.loginCookies(previewSession.sid) }), true;
      }
      const pre = broker.ensurePreAuthCookie(req);
      const extra = pre.setCookie ? { 'Set-Cookie': pre.setCookie } : {};
      return sendJson(res, 200, { ...formatAuthStatePayload(authRecord, null), csrfToken: pre.csrfToken }, extra), true;
    }

    if (req.method === 'POST' && pathname === '/api/auth/preview') {
      if (!verifyPreAuthMutation(req)) return sendJson(res, 403, { error: 'CSRF validation failed.' }), true;
      await readBodyJson(req);
      const authRecord = loadCurrentAuthRecord();
      if (!isPreviewAutoEligible(authRecord)) {
        return sendJson(res, 403, { error: 'Local preview zero-initialization mode is disabled or real console credentials are configured.' }), true;
      }
      const previewSession = broker.createSession('preview', authRecord.authVersion || 0, authRecord.sessionPersistence || 'tab');
      appendSanitizedConnectorLog(stateDir, 'webui_auth', { outcome: 'preview_manual_enter' });
      return sendJson(res, 200, {
        ok: true,
        csrfToken: previewSession.csrfToken,
        tabToken: previewSession.tabToken,
        authState: formatAuthStatePayload(authRecord, previewSession),
      }, { 'Set-Cookie': broker.loginCookies(previewSession.sid) }), true;
    }

    if (req.method === 'POST' && pathname === '/api/auth/setup/password') {
      if (!verifyPreAuthMutation(req)) return sendJson(res, 403, { error: 'CSRF validation failed.' }), true;
      const body = await readBodyJson(req);
      const roots = loadCurrentWorkspaceRoots();
      const authRecord = loadCurrentAuthRecord();
      if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' }), true;
      const hasTicketInput = typeof body.setupToken === 'string' && body.setupToken.trim().length > 0;
      if (hasTicketInput && !checkRateLimit(res)) return true;
      const authz = isSetupAuthorized(req, authRecord, body.setupToken);
      if (!authz.ok) {
        if (hasTicketInput) broker.recordAuthFailure();
        return sendJson(res, 401, { error: 'Valid single-use setup code from local webui-auth init is required.' }), true;
      }
      if (authz.via === 'session' && !verifyAuthMutation(req, authz.session)) {
        return sendJson(res, 403, { error: 'Authenticated CSRF validation failed.' }), true;
      }
      if (authz.via === 'session' && authRecord.passwordHash && !authRecord.requirePasskey) {
        if (!checkRateLimit(res)) return true;
        if (typeof body.currentPassword !== 'string' || !verifyStrongPassword(body.currentPassword, authRecord.passwordHash)) {
          broker.recordAuthFailure();
          return sendJson(res, 401, { error: '当前强密码验证失败，无法重置密码。' }), true;
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
        const newSession = broker.createSession('password', updated.authVersion, updated.sessionPersistence);
        appendSanitizedConnectorLog(stateDir, 'webui_auth', { outcome: 'password_configured' });
        controlChannel?.publish({ type: 'auth.configured', outcome: 'password_configured' });
        return sendJson(res, 200, {
          ok: true,
          csrfToken: newSession.csrfToken,
          tabToken: newSession.tabToken,
          authState: formatAuthStatePayload(updated, newSession),
        }, { 'Set-Cookie': broker.loginCookies(newSession.sid) }), true;
      } catch (err) {
        const status = /PassKey/i.test(err?.message || '') ? 403 : 400;
        return sendJson(res, status, { error: err?.message || 'Cannot configure password.' }), true;
      }
    }

    if (req.method === 'POST' && pathname === '/api/auth/passkey/report-support') {
      if (!verifyPreAuthMutation(req)) return sendJson(res, 403, { error: 'CSRF validation failed.' }), true;
      const body = await readBodyJson(req);
      const roots = loadCurrentWorkspaceRoots();
      const authRecord = loadCurrentAuthRecord();
      if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' }), true;
      const hasTicketInput = typeof body.setupToken === 'string' && body.setupToken.trim().length > 0;
      if (hasTicketInput && !checkRateLimit(res)) return true;
      const authz = isSetupAuthorized(req, authRecord, body.setupToken);
      if (!authz.ok) {
        if (hasTicketInput) broker.recordAuthFailure();
        return sendJson(res, 401, { error: 'Authentication or setup code required.' }), true;
      }
      if (authz.via === 'session' && !verifyAuthMutation(req, authz.session)) {
        return sendJson(res, 403, { error: 'Authenticated CSRF validation failed.' }), true;
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
          const nextCsrf = broker.resetPreAuthCookies();
          return sendJson(res, 200, {
            ok: true,
            csrfToken: nextCsrf.csrfToken,
            authState: formatAuthStatePayload(updated, null),
          }, { 'Set-Cookie': nextCsrf.setCookies }), true;
        }
        return sendJson(res, 200, { ok: true, authState: formatAuthStatePayload(updated, authz.session) }), true;
      }
      return sendJson(res, 200, { ok: true, authState: formatAuthStatePayload(authRecord, authz.session) }), true;
    }

    if (req.method === 'POST' && pathname === '/api/auth/setup/passkey/options') {
      if (!verifyPreAuthMutation(req)) return sendJson(res, 403, { error: 'CSRF validation failed.' }), true;
      const body = await readBodyJson(req);
      const authRecord = loadCurrentAuthRecord();
      if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' }), true;
      const hasTicketInput = typeof body.setupToken === 'string' && body.setupToken.trim().length > 0;
      if (hasTicketInput && !checkRateLimit(res)) return true;
      const authz = isSetupAuthorized(req, authRecord, body.setupToken);
      if (!authz.ok) {
        if (hasTicketInput) broker.recordAuthFailure();
        return sendJson(res, 401, { error: 'Valid setup code or active authenticated session is required.' }), true;
      }
      if (authz.via === 'session' && !verifyAuthMutation(req, authz.session)) {
        return sendJson(res, 403, { error: 'Authenticated CSRF validation failed.' }), true;
      }
      const { challengeId, challenge } = broker.issueWebAuthnChallenge('register', authz.session?.sid || null);
      return sendJson(res, 200, {
        challengeId,
        publicKey: {
          challenge,
          rp: { name: 'LoomWard Console', id: 'localhost' },
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
          excludeCredentials: mapCredentialDescriptors(authRecord.passkeys),
        },
      }), true;
    }

    if (req.method === 'POST' && pathname === '/api/auth/setup/passkey/verify') {
      if (!verifyPreAuthMutation(req)) return sendJson(res, 403, { error: 'CSRF validation failed.' }), true;
      const body = await readBodyJson(req);
      const roots = loadCurrentWorkspaceRoots();
      const authRecord = loadCurrentAuthRecord();
      if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' }), true;
      const hasTicketInput = typeof body.setupToken === 'string' && body.setupToken.trim().length > 0;
      if (hasTicketInput && !checkRateLimit(res)) return true;
      const authz = isSetupAuthorized(req, authRecord, body.setupToken);
      if (!authz.ok) {
        if (hasTicketInput) broker.recordAuthFailure();
        return sendJson(res, 401, { error: 'Valid setup code or authenticated session is required.' }), true;
      }
      if (authz.via === 'session' && !verifyAuthMutation(req, authz.session)) {
        return sendJson(res, 403, { error: 'Authenticated CSRF validation failed.' }), true;
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
        const newSession = broker.createSession('passkey', updated.authVersion, updated.sessionPersistence);
        appendSanitizedConnectorLog(stateDir, 'webui_auth', { outcome: 'passkey_enrolled' });
        controlChannel?.publish({ type: 'auth.configured', outcome: 'passkey_enrolled' });
        return sendJson(res, 200, {
          ok: true,
          csrfToken: newSession.csrfToken,
          tabToken: newSession.tabToken,
          authState: formatAuthStatePayload(updated, newSession),
        }, { 'Set-Cookie': broker.loginCookies(newSession.sid) }), true;
      } catch (err) {
        return sendJson(res, 400, { error: err?.message || 'PassKey registration verification failed.' }), true;
      }
    }

    if (req.method === 'POST' && pathname === '/api/auth/login/password') {
      if (!verifyPreAuthMutation(req)) return sendJson(res, 403, { error: 'CSRF validation failed.' }), true;
      if (!checkRateLimit(res)) return true;
      const body = await readBodyJson(req);
      if (!checkRateLimit(res)) return true;
      const authRecord = loadCurrentAuthRecord();
      if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' }), true;
      if (authRecord.requirePasskey || authRecord.passkeys.length > 0 || authRecord.hostPasskeySupported) {
        return sendJson(res, 403, { error: 'PassKey authentication is mandatory on this machine.' }), true;
      }
      if (!authRecord.initialized || !authRecord.passwordHash) {
        return sendJson(res, 401, { error: 'Strong password is not configured yet.' }), true;
      }
      if (!verifyStrongPassword(body.password, authRecord.passwordHash)) {
        broker.recordAuthFailure();
        appendSanitizedConnectorLog(stateDir, 'webui_auth', { outcome: 'password_failed' });
        return sendJson(res, 401, { error: 'Invalid console password.' }), true;
      }
      broker.clearAuthFailures();
      const newSession = broker.createSession('password', authRecord.authVersion, authRecord.sessionPersistence);
      appendSanitizedConnectorLog(stateDir, 'webui_auth', { outcome: 'password_login_ok' });
      return sendJson(res, 200, {
        ok: true,
        csrfToken: newSession.csrfToken,
        tabToken: newSession.tabToken,
        authState: formatAuthStatePayload(authRecord, newSession),
      }, { 'Set-Cookie': broker.loginCookies(newSession.sid) }), true;
    }

    if (req.method === 'POST' && pathname === '/api/auth/passkey/login/options') {
      if (!verifyPreAuthMutation(req)) return sendJson(res, 403, { error: 'CSRF validation failed.' }), true;
      if (!checkRateLimit(res)) return true;
      await readBodyJson(req);
      if (!checkRateLimit(res)) return true;
      const authRecord = loadCurrentAuthRecord();
      if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' }), true;
      if (!authRecord.passkeys.length) return sendJson(res, 400, { error: 'No PassKey is enrolled yet.' }), true;
      const { challengeId, challenge } = broker.issueWebAuthnChallenge('login');
      return sendJson(res, 200, {
        challengeId,
        publicKey: {
          challenge,
          rpId: 'localhost',
          timeout: 120000,
          userVerification: 'required',
          allowCredentials: mapCredentialDescriptors(authRecord.passkeys),
        },
      }), true;
    }

    if (req.method === 'POST' && pathname === '/api/auth/passkey/login/verify') {
      if (!verifyPreAuthMutation(req)) return sendJson(res, 403, { error: 'CSRF validation failed.' }), true;
      if (!checkRateLimit(res)) return true;
      const body = await readBodyJson(req);
      if (!checkRateLimit(res)) return true;
      const roots = loadCurrentWorkspaceRoots();
      const authRecord = loadCurrentAuthRecord();
      if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' }), true;
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
        const newSession = broker.createSession('passkey', refreshed.authVersion, refreshed.sessionPersistence);
        appendSanitizedConnectorLog(stateDir, 'webui_auth', { outcome: 'passkey_login_ok' });
        return sendJson(res, 200, {
          ok: true,
          csrfToken: newSession.csrfToken,
          tabToken: newSession.tabToken,
          authState: formatAuthStatePayload(refreshed, newSession),
        }, { 'Set-Cookie': broker.loginCookies(newSession.sid) }), true;
      } catch (err) {
        broker.recordAuthFailure();
        appendSanitizedConnectorLog(stateDir, 'webui_auth', { outcome: 'passkey_failed' });
        return sendJson(res, 401, { error: err?.message || 'PassKey authentication failed.' }), true;
      }
    }

    if (req.method === 'POST' && pathname === '/api/auth/logout') {
      const cookies = parseCookieHeader(req.headers.cookie);
      const sid = cookies.get(CONSOLE_SID_COOKIE);
      const activeSession = broker.getSessionBySid(sid);
      if (activeSession) {
        if (!verifyAuthMutation(req, activeSession)) return sendJson(res, 403, { error: 'CSRF validation failed.' }), true;
      } else if (!verifyPreAuthMutation(req)) {
        return sendJson(res, 403, { error: 'CSRF validation failed.' }), true;
      }
      await readBodyJson(req);
      if (sid) broker.revokeSession(sid);
      let lockPreview = false;
      try {
        lockPreview = previewAutoSession === true && !loadCurrentAuthRecord().initialized;
      } catch {}
      const nextCsrf = broker.resetPreAuthCookies({ previewLocked: lockPreview });
      return sendJson(res, 200, { ok: true, csrfToken: nextCsrf.csrfToken }, { 'Set-Cookie': nextCsrf.setCookies }), true;
    }

    return false;
  }

  async function handleMcpRoute(req, res, pathname, session) {
    if (req.method === 'GET' && pathname === '/api/mcp-servers') {
      if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site request rejected.' }), true;
      const roots = loadCurrentWorkspaceRoots();
      const mcpServers = publicMcpRegistrySnapshot(stateDir, { workspaceRoots: roots, blockedOrigins: getBlockedOrigins() });
      return sendJson(res, 200, { ok: true, mcpServers }), true;
    }

    if (req.method === 'POST' && pathname === '/api/mcp-servers/save') {
      if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' }), true;
      const parsed = await readAuthenticatedJson(req, res, session);
      if (!parsed) return true;
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
        return sendJson(res, 400, { error: err?.message || 'Invalid MCP server configuration.' }), true;
      }
      appendSanitizedConnectorLog(stateDir, 'mcp_server_updated', { serverId: saved.id, mode: saved.transport });
      let probe = null;
      let deletedDuringProbe = false;
      if (body?.probe === true) {
        ({ probe, server: saved, deletedDuringProbe } = await runAndPersistBoundedProbe(saved, res, {
          roots,
          blockedOrigins,
          maxWallMs: 30000,
          conflictMode: 'return',
        }));
        appendSanitizedConnectorLog(stateDir, 'mcp_server_probed', {
          serverId: saved.id,
          outcome: probe.ok ? `ok_${probe.tools?.length || 0}` : 'failed',
        });
      }
      controlChannel?.publish({ type: 'mcp.updated', serverId: saved.id });
      const snap = await refreshSnapshot({ force: true });
      return sendJson(res, 200, { ok: true, server: deletedDuringProbe ? null : publicMcpServerSummary(saved), probe, snapshot: snap }), true;
    }

    if (req.method === 'POST' && pathname === '/api/mcp-servers/import') {
      if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' }), true;
      const parsed = await readAuthenticatedJson(req, res, session);
      if (!parsed) return true;
      const { body } = parsed;
      const roots = loadCurrentWorkspaceRoots();
      const blockedOrigins = getBlockedOrigins();
      let parsedList;
      try { parsedList = parseStandardMcpJson(body?.json ?? body?.config); }
      catch (err) { return sendJson(res, 400, { error: err?.message || 'Invalid standard MCP JSON payload.' }), true; }
      let savedEntries;
      try {
        savedEntries = upsertMcpServersSync(stateDir, parsedList, {
          workspaceRoots: roots,
          requirePrivateState,
          blockedOrigins,
          replaceSecrets: true,
        });
      } catch (err) {
        return sendJson(res, 400, { error: err?.message || 'Failed to save imported MCP servers.' }), true;
      }
      const importedIds = savedEntries.map(s => s.id);
      appendSanitizedConnectorLog(stateDir, 'mcp_server_imported', { outcome: `count=${importedIds.length}` });
      const probes = {};
      if (body?.probe === true) {
        const enabledTargets = savedEntries.filter(s => s.enabled);
        const toProbe = enabledTargets.slice(0, 8);
        for (const skipped of enabledTargets.slice(8)) {
          probes[skipped.id] = { ok: false, toolCount: 0, error: 'Skipped automatic probe (batch limit 8); probe individually.' };
        }
        const deadline = Date.now() + 45000;
        let cursor = 0;
        const worker = async () => {
          while (cursor < toProbe.length) {
            if (res.closed && !res.writableEnded) break;
            const srv = toProbe[cursor++];
            let left = deadline - Date.now();
            if (left < 1500) {
              probes[srv.id] = { ok: false, toolCount: 0, error: 'Batch probe time budget exceeded; probe individually.' };
              continue;
            }
            const slotDeadline = Math.min(deadline - 1500, Date.now() + 3000);
            while (
              activeProbes.size >= 3 &&
              Date.now() < slotDeadline &&
              !(res.closed && !res.writableEnded) &&
              !shutdownController.signal.aborted
            ) {
              await new Promise(r => setTimeout(r, 250));
            }
            if (res.closed && !res.writableEnded) break;
            left = deadline - Date.now();
            if (left < 1500) {
              probes[srv.id] = { ok: false, toolCount: 0, error: 'Batch probe time budget exceeded; probe individually.' };
              continue;
            }
            const { probe, status } = await runAndPersistBoundedProbe(srv, res, {
              roots,
              blockedOrigins,
              maxWallMs: Math.min(left, 20000),
              conflictMode: 'record',
            });
            probes[srv.id] = {
              ok: probe.ok,
              toolCount: probe.tools?.length || 0,
              ...(status ? { status } : {}),
              error: probe.error || null,
            };
          }
        };
        await Promise.all(Array.from({ length: Math.min(2, toProbe.length) }, worker));
      }
      controlChannel?.publish({ type: 'mcp.imported', count: importedIds.length });
      const snap = await refreshSnapshot({ force: true });
      return sendJson(res, 200, { ok: true, importedIds, probes, snapshot: snap }), true;
    }

    if (req.method === 'POST' && pathname === '/api/mcp-servers/toggle') {
      if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' }), true;
      const parsed = await readAuthenticatedJson(req, res, session);
      if (!parsed) return true;
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
        return sendJson(res, 400, { error: err?.message || 'Cannot update MCP server toggle.' }), true;
      }
      appendSanitizedConnectorLog(stateDir, 'mcp_server_toggled', { serverId: updated.id });
      controlChannel?.publish({ type: 'mcp.toggled', serverId: updated.id });
      const snap = await refreshSnapshot({ force: true });
      return sendJson(res, 200, { ok: true, server: publicMcpServerSummary(updated), snapshot: snap }), true;
    }

    if (req.method === 'POST' && pathname === '/api/mcp-servers/probe') {
      if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' }), true;
      const parsed = await readAuthenticatedJson(req, res, session);
      if (!parsed) return true;
      const roots = loadCurrentWorkspaceRoots();
      const blockedOrigins = getBlockedOrigins();
      const reg = readMcpServersSync(stateDir, { workspaceRoots: roots, blockedOrigins });
      if (reg.error) return sendJson(res, 400, { error: reg.error }), true;
      const target = reg.servers.find(s => s.id === parsed.body?.id);
      if (!target) return sendJson(res, 404, { error: 'MCP server not found.' }), true;
      const { probe, server: updated, deletedDuringProbe } = await runAndPersistBoundedProbe(target, res, {
        roots,
        blockedOrigins,
        maxWallMs: 30000,
        conflictMode: 'rethrow',
      });
      appendSanitizedConnectorLog(stateDir, 'mcp_server_probed', {
        serverId: target.id,
        outcome: probe.ok ? `ok_${probe.tools?.length || 0}` : 'failed',
      });
      const snap = await refreshSnapshot({ force: true });
      return sendJson(res, 200, { ok: true, probe, server: deletedDuringProbe ? null : publicMcpServerSummary(updated), snapshot: snap }), true;
    }

    if (req.method === 'POST' && pathname === '/api/mcp-servers/delete') {
      if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' }), true;
      const parsed = await readAuthenticatedJson(req, res, session);
      if (!parsed) return true;
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
        return sendJson(res, err?.code === 'NOT_FOUND' ? 404 : 400, { error: err?.message || 'Cannot delete MCP server.' }), true;
      }
      appendSanitizedConnectorLog(stateDir, 'mcp_server_deleted', { serverId: removed.deleted });
      controlChannel?.publish({ type: 'mcp.deleted', serverId: removed.deleted });
      const snap = await refreshSnapshot({ force: true });
      return sendJson(res, 200, { ok: true, ...removed, snapshot: snap }), true;
    }

    return false;
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

      if (await handlePreAuthRoute(req, res, reqUrl.pathname)) return;

      // Authenticated Single-Origin endpoints below.
      const authRecord = loadCurrentAuthRecord();
      if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' });
      const session = broker.authenticateSession(req, authRecord);
      if (!session) {
        return sendJson(res, 401, {
          error: 'Console authentication is required.',
          code: 'CONSOLE_AUTH_REQUIRED',
          mode: publicWebUiAuthSummary(authRecord).mode,
        });
      }

      if (req.method === 'GET' && reqUrl.pathname === '/api/status') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        const [snap, panels] = await Promise.all([
          refreshSnapshot({ force: false }),
          panelCollector.collectAll({ originRole: 'unified' }),
        ]);
        if (!broker.authenticateSession(req, loadCurrentAuthRecord(), false)) {
          return sendJson(res, 401, { error: 'Console session was revoked.', code: 'CONSOLE_AUTH_REQUIRED' });
        }
        return sendJson(res, 200, enrichSnapshot(snap, panels));
      }

      if (req.method === 'GET' && reqUrl.pathname === '/api/panels') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        const panels = await panelCollector.collectAll({ originRole: 'unified' });
        if (!broker.authenticateSession(req, loadCurrentAuthRecord(), false)) {
          return sendJson(res, 401, { error: 'Console session was revoked.', code: 'CONSOLE_AUTH_REQUIRED' });
        }
        return sendJson(res, 200, { ok: true, panels });
      }

      if (req.method === 'GET' && reqUrl.pathname.startsWith('/api/panels/')) {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        const panelId = reqUrl.pathname.slice('/api/panels/'.length);
        if (!/^[a-z][a-z0-9-]{1,47}$/.test(panelId)) {
          return sendJson(res, 400, { error: 'Invalid panel ID.' });
        }
        const panel = await panelCollector.collectById(panelId, { originRole: 'unified' });
        if (!broker.authenticateSession(req, loadCurrentAuthRecord(), false)) {
          return sendJson(res, 401, { error: 'Console session was revoked.', code: 'CONSOLE_AUTH_REQUIRED' });
        }
        if (!panel) return sendJson(res, 404, { error: 'Console panel not found.' });
        return sendJson(res, 200, { ok: true, panel });
      }

      if (req.method === 'GET' && reqUrl.pathname === '/api/events') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site event stream rejected.' });
        if (sseClients.size >= MAX_SSE_CLIENTS) return sendJson(res, 429, { error: 'Too many active console monitoring streams.' });
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
        const panels = await panelCollector.collectAll({ originRole: 'unified' });
        if (res.writableEnded || res.destroyed) return;
        const freshAuth = loadCurrentAuthRecord();
        sendStreamFrame(res, req, freshAuth, `event: status\ndata: ${JSON.stringify(enrichSnapshot(cached, panels))}\n\n`);
        return;
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
        if (session.authMethod === 'preview') {
          return sendJson(res, 400, { error: '本地预览免初始化模式下无需修改持久化会话策略。' });
        }
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
          broker.pruneOtherSessions(session.sid);
        } else {
          broker.updateAllSessionsPersistence(updated.authVersion, 'browser');
          broker.pruneOtherSessions(session.sid);
        }
        appendSanitizedConnectorLog(stateDir, 'webui_auth', { outcome: `session_policy_${targetMode}` });
        let snap = null;
        try {
          snap = await refreshSnapshot({ force: true, broadcast: targetMode !== 'tab' });
        } finally {
          if (targetMode === 'tab') {
            session.tabToken = rotatedTabToken;
            dropStreamsForSids([], true);
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
        broker.pruneOtherSessions(session.sid);
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
        const newSession = broker.createSession('password', updated.authVersion, updated.sessionPersistence);
        appendSanitizedConnectorLog(stateDir, 'webui_auth', { outcome: 'switched_to_password' });
        const snap = await refreshSnapshot({ force: true, broadcast: false });
        return sendJson(res, 200, {
          ok: true,
          csrfToken: newSession.csrfToken,
          tabToken: newSession.tabToken,
          authState: formatAuthStatePayload(updated, newSession),
          snapshot: snap,
        }, { 'Set-Cookie': broker.loginCookies(newSession.sid) });
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

      if (await handleMcpRoute(req, res, reqUrl.pathname, session)) return;

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

      if (req.method === 'GET' && reqUrl.pathname === '/api/plugin-secrets/meta') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        const admin = getPluginSecretsAdmin();
        if (!admin) return sendJson(res, 503, { error: 'Plugin secrets admin service is unavailable.' });
        return sendJson(res, 200, { ok: true, units: admin.listUnitsMeta() });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/plugin-secrets/save') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        const admin = getPluginSecretsAdmin();
        if (!admin) return sendJson(res, 503, { error: 'Plugin secrets admin service is unavailable.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const { body } = parsed;
        try {
          const meta = admin.setSecrets(body?.unitId, body?.secrets, { replace: body?.replace === true });
          appendSanitizedConnectorLog(stateDir, 'plugin_secret_saved', {
            unitId: meta.unitId,
            outcome: `keys=${meta.keys.length}`,
          });
          controlChannel?.publish({ type: 'plugin.secrets_updated', unitId: meta.unitId });
          await refreshSnapshot({ force: true }).catch(() => {});
          return sendJson(res, 200, { ok: true, meta });
        } catch (err) {
          return sendJson(res, 400, { error: redactSecretsFromText(err?.message || 'Invalid plugin secret update.') });
        }
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/plugin-secrets/delete') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        const admin = getPluginSecretsAdmin();
        if (!admin) return sendJson(res, 503, { error: 'Plugin secrets admin service is unavailable.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const { body } = parsed;
        try {
          const resDel = admin.deleteSecret(body?.unitId, body?.key);
          appendSanitizedConnectorLog(stateDir, 'plugin_secret_deleted', {
            unitId: resDel.meta.unitId,
            outcome: resDel.deleted ? 'deleted' : 'absent',
          });
          controlChannel?.publish({ type: 'plugin.secrets_updated', unitId: resDel.meta.unitId });
          await refreshSnapshot({ force: true }).catch(() => {});
          return sendJson(res, 200, { ok: true, ...resDel });
        } catch (err) {
          return sendJson(res, 400, { error: redactSecretsFromText(err?.message || 'Invalid plugin secret deletion.') });
        }
      }

      if (req.method === 'GET' && reqUrl.pathname === '/api/moderation/config') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        const roots = loadCurrentWorkspaceRoots();
        const blockedOrigins = getBlockedOrigins();
        const config = readModerationConfigSync(stateDir, {
          workspaceRoots: roots,
          requirePrivateState,
          blockedOrigins,
        });
        return sendJson(res, 200, { ok: true, config });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/moderation/config') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const roots = loadCurrentWorkspaceRoots();
        const blockedOrigins = getBlockedOrigins();
        try {
          const updated = writeModerationConfigSync(
            stateDir,
            parsed.body?.config && typeof parsed.body.config === 'object' ? parsed.body.config : parsed.body,
            { workspaceRoots: roots, requirePrivateState, blockedOrigins },
          );
          appendSanitizedConnectorLog(stateDir, 'moderation_config_saved', {
            mode: updated.mode,
            outcome: `${updated.policyProfile}:cloud=${updated.cloudOptIn ? 'on' : 'off'}`,
          });
          controlChannel?.publish({
            type: 'moderation.config_updated',
            mode: updated.mode,
            policyProfile: updated.policyProfile,
            cloudOptIn: updated.cloudOptIn,
          });
          await refreshSnapshot({ force: true }).catch(() => {});
          return sendJson(res, 200, { ok: true, config: updated });
        } catch (err) {
          return sendJson(res, 400, { error: redactSecretsFromText(err?.message || 'Invalid moderation configuration.') });
        }
      }

      if (req.method === 'GET' && reqUrl.pathname === '/api/moderation/ollama/status') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        if (!ollamaController) return sendJson(res, 503, { error: 'Ollama controller is unavailable.' });
        const roots = loadCurrentWorkspaceRoots();
        const blockedOrigins = getBlockedOrigins();
        const savedCfg = readModerationConfigSync(stateDir, {
          workspaceRoots: roots,
          requirePrivateState,
          blockedOrigins,
        });
        const qEndpoint = reqUrl.searchParams.get('endpoint');
        const qPrivate = reqUrl.searchParams.get('allowPrivateNetwork');
        const endpoint = qEndpoint !== null && qEndpoint.trim() ? qEndpoint.trim() : savedCfg.localGuard?.endpoint;
        const allowPrivateNetwork = qPrivate !== null
          ? qPrivate === '1' || qPrivate === 'true'
          : Boolean(savedCfg.localGuard?.allowPrivateNetwork);
        try {
          const statusPayload = await ollamaController.status({ endpoint, allowPrivateNetwork });
          return sendJson(res, 200, statusPayload);
        } catch (err) {
          return sendJson(res, Number.isInteger(err?.status) ? err.status : 400, {
            error: redactSecretsFromText(err?.message || 'Failed to probe Ollama status.'),
          });
        }
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/moderation/ollama/install') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        if (!ollamaController) return sendJson(res, 503, { error: 'Ollama controller is unavailable.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        if (parsed.body?.confirmInstall !== true) {
          return sendJson(res, 400, { error: 'Explicit confirmInstall: true confirmation is required to install Ollama.' });
        }
        try {
          const result = await ollamaController.install();
          appendSanitizedConnectorLog(stateDir, 'moderation_ollama_install', {
            outcome: result.alreadyInstalled ? 'already_installed' : 'installed',
          });
          return sendJson(res, 200, result);
        } catch (err) {
          return sendJson(res, Number.isInteger(err?.status) ? err.status : 400, {
            error: redactSecretsFromText(err?.message || 'Ollama installation failed.'),
          });
        }
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/moderation/ollama/start') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        if (!ollamaController) return sendJson(res, 503, { error: 'Ollama controller is unavailable.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        try {
          const result = await ollamaController.start({ endpoint: parsed.body?.endpoint });
          appendSanitizedConnectorLog(stateDir, 'moderation_ollama_start', {
            outcome: result.alreadyRunning ? 'already_running' : 'started',
          });
          return sendJson(res, 200, result);
        } catch (err) {
          return sendJson(res, Number.isInteger(err?.status) ? err.status : 400, {
            error: redactSecretsFromText(err?.message || 'Failed to start local Ollama daemon.'),
          });
        }
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/moderation/ollama/pull') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        if (!ollamaController) return sendJson(res, 503, { error: 'Ollama controller is unavailable.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        try {
          const out = await ollamaController.pull({
            endpoint: parsed.body?.endpoint,
            model: parsed.body?.model,
            allowPrivateNetwork: parsed.body?.allowPrivateNetwork === true,
          });
          appendSanitizedConnectorLog(stateDir, 'moderation_ollama_pull', {
            model: out.job?.model || 'unknown',
            outcome: out.job?.status || 'pulling',
          });
          return sendJson(res, out.job?.status === 'pulling' ? 202 : 200, out);
        } catch (err) {
          return sendJson(res, Number.isInteger(err?.status) ? err.status : 400, {
            error: redactSecretsFromText(err?.message || 'Failed to pull Ollama model.'),
          });
        }
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/moderation/ollama/test') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        if (!ollamaController) return sendJson(res, 503, { error: 'Ollama controller is unavailable.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        try {
          const result = await ollamaController.testModel({
            endpoint: parsed.body?.endpoint,
            model: parsed.body?.model,
            allowPrivateNetwork: parsed.body?.allowPrivateNetwork === true,
            think: parsed.body?.think === true,
          });
          return sendJson(res, 200, result);
        } catch (err) {
          return sendJson(res, Number.isInteger(err?.status) ? err.status : 400, {
            error: redactSecretsFromText(err?.message || 'Ollama model inference test failed.'),
          });
        }
      }

      if (req.method === 'GET' && reqUrl.pathname === '/api/fencing/config') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        const roots = loadCurrentWorkspaceRoots();
        try {
          const data = readAntileakConfigSync(stateDir, { workspaceRoots: roots, requirePrivateState });
          return sendJson(res, 200, { ok: true, ...data });
        } catch (err) {
          return sendJson(res, 400, { error: redactSecretsFromText(err?.message || 'Unable to load anti-leak fencing policy.') });
        }
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/fencing/config') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const roots = loadCurrentWorkspaceRoots();
        const patch = parsed.body?.config && typeof parsed.body.config === 'object' ? parsed.body.config : parsed.body;
        try {
          await validatePythonRegexList([
            ...(Array.isArray(patch?.forbiddenPatterns) ? patch.forbiddenPatterns : []),
            ...(Array.isArray(patch?.secretRegexes) ? patch.secretRegexes : []),
          ]);
          const updated = writeAntileakConfigSync(stateDir, patch, { workspaceRoots: roots, requirePrivateState });
          appendSanitizedConnectorLog(stateDir, 'fencing_policy_saved', {
            outcome: 'saved',
          });
          controlChannel?.publish({
            type: 'fencing.policy_updated',
            cacheStatus: updated.cache?.status || 'missing',
          });
          await refreshSnapshot({ force: true }).catch(() => {});
          return sendJson(res, 200, { ok: true, ...updated });
        } catch (err) {
          return sendJson(res, 400, { error: redactSecretsFromText(err?.message || 'Invalid anti-leak fencing configuration.') });
        }
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/fencing/test') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const roots = loadCurrentWorkspaceRoots();
        try {
          const result = await runAntileakDryRun(stateDir, {
            text: typeof parsed.body?.text === 'string' ? parsed.body.text : '',
            workspaceRoots: roots,
            requirePrivateState,
          });
          appendSanitizedConnectorLog(stateDir, 'fencing_dry_run', {
            outcome: result.decision,
          });
          return sendJson(res, 200, { ok: true, result });
        } catch (err) {
          return sendJson(res, 400, { error: redactSecretsFromText(err?.message || 'Anti-leak dry-run inspection failed.') });
        }
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/fencing/refresh') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const roots = loadCurrentWorkspaceRoots();
        try {
          const result = await runAntileakRefresh(stateDir, { workspaceRoots: roots, requirePrivateState });
          appendSanitizedConnectorLog(stateDir, 'fencing_cache_refreshed', {
            outcome: result.ok ? 'ok' : 'error',
          });
          controlChannel?.publish({
            type: 'fencing.cache_refreshed',
            cacheStatus: result.cache?.status || 'missing',
          });
          await refreshSnapshot({ force: true }).catch(() => {});
          return sendJson(res, 200, { ok: true, result });
        } catch (err) {
          return sendJson(res, 400, { error: redactSecretsFromText(err?.message || 'Failed to refresh anti-leak private cache.') });
        }
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/fencing/doctor') {
        if (!verifyAuthMutation(req, session)) return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed.' });
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const roots = loadCurrentWorkspaceRoots();
        try {
          const result = await runAntileakDoctor(stateDir, { workspaceRoots: roots, requirePrivateState });
          appendSanitizedConnectorLog(stateDir, 'fencing_doctor_checked', {
            outcome: result.ok ? 'ok' : 'warn',
          });
          return sendJson(res, 200, { ok: true, result });
        } catch (err) {
          return sendJson(res, 400, { error: redactSecretsFromText(err?.message || 'Anti-leak doctor check failed.') });
        }
      }

      return sendJson(res, 404, { error: 'Not found.' });
    } catch (error) {
      const status = Number.isInteger(error?.status) ? error.status : 500;
      const message = status < 500 ? error.message : 'Internal console error.';
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
