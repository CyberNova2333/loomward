// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Single-origin session, CSRF, WebAuthn challenge, and rate-limit broker.
import crypto from 'node:crypto';
import {
  getCsrfHeader,
  getTabAuthHeader,
  parseCookieHeader,
  timingSafeEqualText,
  validTokenId,
} from './http-security.mjs';

export const CONSOLE_PRE_COOKIE = 'loomward_console_pre';
export const CONSOLE_SID_COOKIE = 'loomward_console_sid';
export const CONSOLE_PREVIEW_LOCKED_COOKIE = 'loomward_preview_locked';

const MAX_SESSIONS = 16;
const SESSION_IDLE_MS = 30 * 60 * 1000;
const SESSION_MAX_MS = 12 * 60 * 60 * 1000;
const CHALLENGE_TTL_MS = 120 * 1000;
const MAX_CHALLENGES = 32;
const AUTH_FAILURE_LIMIT = 5;

export function createConsoleSessionBroker({
  allowPreviewSession = false,
  onSessionsRevoked = () => {},
} = {}) {
  const csrfSecret = crypto.randomBytes(32);
  const sessions = new Map();
  const registerChallenges = new Map();
  const loginChallenges = new Map();

  let failedAttempts = 0;
  let lockedUntilMs = 0;

  const deriveCsrf = (kind, id) =>
    crypto.createHmac('sha256', csrfSecret).update(`console:${kind}:${id}`).digest('base64url');

  function pruneSessions(now = Date.now()) {
    for (const [key, item] of sessions) {
      if (item.expiresAt <= now || (item.lastSeenAt && now - item.lastSeenAt > SESSION_IDLE_MS)) {
        revokeSession(key);
      }
    }
    while (sessions.size >= MAX_SESSIONS) {
      const oldestKey = sessions.keys().next().value;
      revokeSession(oldestKey);
    }
  }

  function createSession(authMethod, authVersion, sessionPersistence = 'tab') {
    const now = Date.now();
    pruneSessions(now);
    const sid = crypto.randomBytes(32).toString('base64url');
    const csrfToken = deriveCsrf('auth', sid);
    const tabToken = crypto.randomBytes(32).toString('base64url');
    const session = {
      sid,
      role: 'console-admin',
      csrfToken,
      tabToken,
      authMethod,
      authVersion,
      sessionPersistence: sessionPersistence === 'browser' ? 'browser' : 'tab',
      createdAt: now,
      lastSeenAt: now,
      expiresAt: now + SESSION_MAX_MS,
    };
    sessions.set(sid, session);
    return session;
  }

  function authenticateSession(req, authRecord, touch = true) {
    if (!authRecord || authRecord.error) return null;
    const cookies = parseCookieHeader(req.headers.cookie);
    const sid = cookies.get(CONSOLE_SID_COOKIE);
    if (!validTokenId(sid)) return null;
    const session = sessions.get(sid);
    if (!session) return null;
    if (session.authMethod === 'preview') {
      // Ephemeral preview sessions are strictly disallowed whenever real auth is initialized or preview is disabled.
      if (!allowPreviewSession || authRecord.initialized) {
        revokeSession(sid);
        return null;
      }
    } else if (!authRecord.initialized) {
      return null;
    }
    const now = Date.now();
    if (session.expiresAt <= now || now - session.lastSeenAt > SESSION_IDLE_MS) {
      revokeSession(sid);
      return null;
    }
    if (session.authMethod !== 'preview' && session.authVersion !== authRecord.authVersion) {
      revokeSession(sid);
      return null;
    }
    if (session.authMethod !== 'preview' && (authRecord.requirePasskey || authRecord.passkeys.length > 0) && session.authMethod !== 'passkey') {
      revokeSession(sid);
      return null;
    }
    const persistence = session.sessionPersistence || authRecord.sessionPersistence || 'tab';
    if (persistence === 'tab') {
      const providedTab = getTabAuthHeader(req);
      if (!providedTab || !timingSafeEqualText(providedTab, session.tabToken)) {
        return null;
      }
    }
    if (touch) session.lastSeenAt = now;
    return session;
  }

  function revokeSession(sid) {
    sessions.delete(sid);
    onSessionsRevoked({ sids: [sid], all: false });
  }

  function invalidateAllSessions() {
    sessions.clear();
    onSessionsRevoked({ sids: [], all: true });
  }

  function pruneOtherSessions(keepSid) {
    for (const otherSid of [...sessions.keys()]) {
      if (otherSid !== keepSid) revokeSession(otherSid);
    }
  }

  function updateAllSessionsPersistence(authVersion, persistence) {
    for (const s of sessions.values()) {
      s.authVersion = authVersion;
      s.sessionPersistence = persistence;
    }
  }

  function verifyPreAuthCsrf(req) {
    const provided = getCsrfHeader(req);
    if (!provided) return false;
    const cookies = parseCookieHeader(req.headers.cookie);
    const sid = cookies.get(CONSOLE_SID_COOKIE);
    const session = validTokenId(sid) ? sessions.get(sid) : null;
    if (session && timingSafeEqualText(provided, session.csrfToken)) return true;
    const preId = cookies.get(CONSOLE_PRE_COOKIE);
    if (!validTokenId(preId)) return false;
    return timingSafeEqualText(provided, deriveCsrf('pre', preId));
  }

  function verifyAuthenticatedCsrf(req, session) {
    const provided = getCsrfHeader(req);
    return Boolean(session && timingSafeEqualText(provided, session.csrfToken));
  }

  function ensurePreAuthCookie(req) {
    const cookies = parseCookieHeader(req.headers.cookie);
    let preId = cookies.get(CONSOLE_PRE_COOKIE);
    let setCookie = null;
    if (!validTokenId(preId)) {
      preId = crypto.randomBytes(24).toString('base64url');
      setCookie = `${CONSOLE_PRE_COOKIE}=${preId}; HttpOnly; SameSite=Strict; Path=/`;
    }
    return { preId, csrfToken: deriveCsrf('pre', preId), setCookie };
  }

  function resetPreAuthCookies({ previewLocked = false } = {}) {
    const preId = crypto.randomBytes(24).toString('base64url');
    return {
      csrfToken: deriveCsrf('pre', preId),
      setCookies: [
        `${CONSOLE_SID_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`,
        `${CONSOLE_PRE_COOKIE}=${preId}; HttpOnly; SameSite=Strict; Path=/`,
        previewLocked
          ? `${CONSOLE_PREVIEW_LOCKED_COOKIE}=1; HttpOnly; SameSite=Strict; Path=/`
          : `${CONSOLE_PREVIEW_LOCKED_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`,
      ],
    };
  }

  function loginCookies(sid) {
    return [
      `${CONSOLE_SID_COOKIE}=${sid}; HttpOnly; SameSite=Strict; Path=/`,
      `${CONSOLE_PRE_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`,
      `${CONSOLE_PREVIEW_LOCKED_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`,
    ];
  }

  function issueWebAuthnChallenge(kind, sid = null) {
    const store = kind === 'register' ? registerChallenges : loginChallenges;
    const now = Date.now();
    for (const [key, item] of store) {
      if (item.expiresAt <= now) store.delete(key);
    }
    while (store.size >= MAX_CHALLENGES) {
      store.delete(store.keys().next().value);
    }
    const challenge = crypto.randomBytes(32).toString('base64url');
    const challengeId = crypto.randomBytes(16).toString('base64url');
    store.set(challengeId, {
      kind,
      challenge,
      sid: sid || null,
      expiresAt: now + CHALLENGE_TTL_MS,
    });
    return { challengeId, challenge };
  }

  function consumeWebAuthnChallenge(challengeId, expectedKind, expectedSid = null) {
    if (typeof challengeId !== 'string' || !challengeId) {
      throw new Error('PassKey challenge expired or invalid.');
    }
    const store = expectedKind === 'register' ? registerChallenges : loginChallenges;
    const entry = store.get(challengeId);
    if (!entry || entry.kind !== expectedKind || entry.sid !== (expectedSid || null)) {
      throw new Error('PassKey challenge expired or invalid.');
    }
    store.delete(challengeId);
    if (entry.expiresAt <= Date.now()) {
      throw new Error('PassKey challenge expired or invalid.');
    }
    return entry;
  }

  function recordAuthFailure() {
    failedAttempts += 1;
    if (failedAttempts >= AUTH_FAILURE_LIMIT) {
      const exponent = Math.min(4, failedAttempts - AUTH_FAILURE_LIMIT);
      lockedUntilMs = Date.now() + 60 * 1000 * (2 ** exponent);
    }
  }

  function clearAuthFailures() {
    failedAttempts = 0;
    lockedUntilMs = 0;
  }

  function getLockoutRemainingSec() {
    const now = Date.now();
    if (lockedUntilMs <= now) return 0;
    return Math.ceil((lockedUntilMs - now) / 1000);
  }

  function clearAll() {
    sessions.clear();
    registerChallenges.clear();
    loginChallenges.clear();
  }

  return Object.freeze({
    createSession,
    authenticateSession,
    revokeSession,
    invalidateAllSessions,
    pruneOtherSessions,
    updateAllSessionsPersistence,
    verifyPreAuthCsrf,
    verifyAuthenticatedCsrf,
    ensurePreAuthCookie,
    resetPreAuthCookies,
    loginCookies,
    issueWebAuthnChallenge,
    consumeWebAuthnChallenge,
    recordAuthFailure,
    clearAuthFailures,
    getLockoutRemainingSec,
    getLockedUntilMs: () => (lockedUntilMs > Date.now() ? lockedUntilMs : 0),
    getSessionBySid: sid => (validTokenId(sid) ? sessions.get(sid) || null : null),
    clearAll,
  });
}
