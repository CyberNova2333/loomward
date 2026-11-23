// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Dual-origin session & single-use read-only Console handoff ticket broker.
import crypto from 'node:crypto';
import {
  getCsrfHeader,
  getTabAuthHeader,
  parseCookieHeader,
  timingSafeEqualText,
  validTokenId,
} from './http-security.mjs';

export const TRUST_PRE_COOKIE = 'loomward_trust_pre';
export const TRUST_SID_COOKIE = 'loomward_trust_sid';
export const CONSOLE_PRE_COOKIE = 'loomward_console_pre';
export const CONSOLE_SID_COOKIE = 'loomward_console_sid';

const MAX_SESSIONS = 16;
const MAX_TICKETS = 16;
const SESSION_IDLE_MS = 30 * 60 * 1000;
const SESSION_MAX_MS = 12 * 60 * 60 * 1000;
const HANDOFF_TICKET_TTL_MS = 60 * 1000;
const CHALLENGE_TTL_MS = 120 * 1000;
const MAX_CHALLENGES = 32;
const AUTH_FAILURE_LIMIT = 5;

export function createDualOriginSessionBroker({ onSessionsRevoked = () => {} } = {}) {
  const trustCsrfSecret = crypto.randomBytes(32);
  const consoleCsrfSecret = crypto.randomBytes(32);
  const trustSessions = new Map();
  const consoleSessions = new Map();
  const handoffTickets = new Map();
  const registerChallenges = new Map();
  const loginChallenges = new Map();

  let failedAttempts = 0;
  let lockedUntilMs = 0;

  const deriveTrustCsrf = (kind, id) =>
    crypto.createHmac('sha256', trustCsrfSecret).update(`trust:${kind}:${id}`).digest('base64url');
  const deriveConsoleCsrf = (kind, id) =>
    crypto.createHmac('sha256', consoleCsrfSecret).update(`console:${kind}:${id}`).digest('base64url');

  function pruneMap(map, now = Date.now(), onEvict = null) {
    for (const [key, item] of map) {
      if (item.expiresAt <= now || (item.lastSeenAt && now - item.lastSeenAt > SESSION_IDLE_MS)) {
        if (onEvict) onEvict(key);
        else map.delete(key);
      }
    }
    while (map.size >= MAX_SESSIONS) {
      const oldestKey = map.keys().next().value;
      if (onEvict) onEvict(oldestKey);
      else map.delete(oldestKey);
    }
  }

  function pruneTickets(now = Date.now()) {
    for (const [tok, item] of handoffTickets) {
      if (item.expiresAt <= now) handoffTickets.delete(tok);
    }
    while (handoffTickets.size >= MAX_TICKETS) {
      handoffTickets.delete(handoffTickets.keys().next().value);
    }
  }

  function createTrustSession(authMethod, authVersion, sessionPersistence = 'tab') {
    const now = Date.now();
    pruneMap(trustSessions, now, sid => revokeTrustSession(sid));
    const sid = crypto.randomBytes(32).toString('base64url');
    const csrfToken = deriveTrustCsrf('auth', sid);
    const tabToken = crypto.randomBytes(32).toString('base64url');
    const session = {
      sid,
      role: 'trust-admin',
      csrfToken,
      tabToken,
      authMethod,
      authVersion,
      sessionPersistence: sessionPersistence === 'browser' ? 'browser' : 'tab',
      createdAt: now,
      lastSeenAt: now,
      expiresAt: now + SESSION_MAX_MS,
    };
    trustSessions.set(sid, session);
    return session;
  }

  function authenticateTrustSession(req, authRecord, touch = true) {
    if (!authRecord || authRecord.error || !authRecord.initialized) return null;
    const cookies = parseCookieHeader(req.headers.cookie);
    const sid = cookies.get(TRUST_SID_COOKIE);
    if (!validTokenId(sid)) return null;
    const session = trustSessions.get(sid);
    if (!session) return null;
    const now = Date.now();
    if (session.expiresAt <= now || now - session.lastSeenAt > SESSION_IDLE_MS) {
      revokeTrustSession(sid);
      return null;
    }
    if (session.authVersion !== authRecord.authVersion) {
      revokeTrustSession(sid);
      return null;
    }
    if ((authRecord.requirePasskey || authRecord.passkeys.length > 0) && session.authMethod !== 'passkey') {
      revokeTrustSession(sid);
      return null;
    }
    const persistence = authRecord.sessionPersistence || 'tab';
    if (persistence === 'tab') {
      const providedTab = getTabAuthHeader(req);
      if (!providedTab || !timingSafeEqualText(providedTab, session.tabToken)) {
        return null;
      }
    }
    if (touch) session.lastSeenAt = now;
    return session;
  }

  function issueConsoleHandoffTicket(trustSession) {
    if (!trustSession || !trustSessions.has(trustSession.sid)) {
      throw new Error('Active Trust Origin session is required.');
    }
    const now = Date.now();
    pruneTickets(now);
    const ticket = crypto.randomBytes(32).toString('base64url');
    const expiresAt = now + HANDOFF_TICKET_TTL_MS;
    handoffTickets.set(ticket, {
      parentTrustSid: trustSession.sid,
      authMethod: trustSession.authMethod,
      authVersion: trustSession.authVersion,
      sessionPersistence: trustSession.sessionPersistence,
      expiresAt,
    });
    return { ticket, expiresAt: new Date(expiresAt).toISOString() };
  }

  function exchangeConsoleHandoffTicket(ticket, authRecord) {
    if (!validTokenId(ticket)) return null;
    const entry = handoffTickets.get(ticket);
    if (!entry) return null;
    // Single-use: always burn ticket immediately on inspection.
    handoffTickets.delete(ticket);
    const now = Date.now();
    if (entry.expiresAt <= now) return null;
    const parent = trustSessions.get(entry.parentTrustSid);
    if (!parent || parent.expiresAt <= now || (parent.lastSeenAt && now - parent.lastSeenAt > SESSION_IDLE_MS)) {
      return null;
    }
    if (!authRecord || authRecord.error || !authRecord.initialized) return null;
    if (entry.authVersion !== authRecord.authVersion) return null;
    if ((authRecord.requirePasskey || (Array.isArray(authRecord.passkeys) && authRecord.passkeys.length > 0)) && entry.authMethod !== 'passkey') {
      return null;
    }

    pruneMap(consoleSessions, now, csid => revokeConsoleSession(csid));
    const sid = crypto.randomBytes(32).toString('base64url');
    const csrfToken = deriveConsoleCsrf('auth', sid);
    const tabToken = crypto.randomBytes(32).toString('base64url');
    const session = {
      sid,
      role: 'console-readonly',
      parentTrustSid: parent.sid,
      csrfToken,
      tabToken,
      authMethod: entry.authMethod,
      authVersion: authRecord.authVersion,
      sessionPersistence: authRecord.sessionPersistence === 'browser' ? 'browser' : 'tab',
      createdAt: now,
      lastSeenAt: now,
      expiresAt: Math.min(parent.expiresAt, now + SESSION_MAX_MS),
    };
    consoleSessions.set(sid, session);
    return session;
  }

  function authenticateConsoleSession(req, authRecord, touch = true) {
    if (!authRecord || authRecord.error || !authRecord.initialized) return null;
    const cookies = parseCookieHeader(req.headers.cookie);
    const sid = cookies.get(CONSOLE_SID_COOKIE);
    if (!validTokenId(sid)) return null;
    const session = consoleSessions.get(sid);
    if (!session) return null;
    const now = Date.now();
    if (session.expiresAt <= now || now - session.lastSeenAt > SESSION_IDLE_MS) {
      consoleSessions.delete(sid);
      return null;
    }
    if (!trustSessions.has(session.parentTrustSid)) {
      consoleSessions.delete(sid);
      return null;
    }
    if (session.authVersion !== authRecord.authVersion) {
      consoleSessions.delete(sid);
      return null;
    }
    if ((authRecord.requirePasskey || authRecord.passkeys.length > 0) && session.authMethod !== 'passkey') {
      consoleSessions.delete(sid);
      return null;
    }
    const persistence = authRecord.sessionPersistence || 'tab';
    if (persistence === 'tab') {
      const providedTab = getTabAuthHeader(req);
      if (!providedTab || !timingSafeEqualText(providedTab, session.tabToken)) {
        return null;
      }
    }
    if (touch) session.lastSeenAt = now;
    return session;
  }

  function revokeChildConsoleSessions(trustSid) {
    const revokedConsoleSids = [];
    for (const [csid, cs] of consoleSessions) {
      if (cs.parentTrustSid === trustSid) {
        consoleSessions.delete(csid);
        revokedConsoleSids.push(csid);
      }
    }
    for (const [tok, entry] of handoffTickets) {
      if (entry.parentTrustSid === trustSid) handoffTickets.delete(tok);
    }
    if (revokedConsoleSids.length) {
      onSessionsRevoked({ trustSid: null, consoleSids: revokedConsoleSids, all: false });
    }
    return revokedConsoleSids;
  }

  function revokeTrustSession(trustSid) {
    trustSessions.delete(trustSid);
    const revokedConsoleSids = [];
    for (const [csid, cs] of consoleSessions) {
      if (cs.parentTrustSid === trustSid) {
        consoleSessions.delete(csid);
        revokedConsoleSids.push(csid);
      }
    }
    for (const [tok, entry] of handoffTickets) {
      if (entry.parentTrustSid === trustSid) handoffTickets.delete(tok);
    }
    onSessionsRevoked({ trustSid, consoleSids: revokedConsoleSids, all: false });
  }

  function revokeConsoleSession(consoleSid) {
    consoleSessions.delete(consoleSid);
    onSessionsRevoked({ trustSid: null, consoleSids: [consoleSid], all: false });
  }

  function invalidateAllSessions() {
    trustSessions.clear();
    consoleSessions.clear();
    handoffTickets.clear();
    onSessionsRevoked({ trustSid: null, consoleSids: [], all: true });
  }

  function pruneOtherTrustSessions(keepTrustSid) {
    for (const otherSid of [...trustSessions.keys()]) {
      if (otherSid !== keepTrustSid) revokeTrustSession(otherSid);
    }
  }

  function updateAllSessionsPersistence(authVersion, persistence) {
    for (const s of trustSessions.values()) {
      s.authVersion = authVersion;
      s.sessionPersistence = persistence;
    }
    for (const s of consoleSessions.values()) {
      s.authVersion = authVersion;
      s.sessionPersistence = persistence;
    }
  }

  function verifyTrustPreAuthCsrf(req) {
    const provided = getCsrfHeader(req);
    if (!provided) return false;
    const cookies = parseCookieHeader(req.headers.cookie);
    const sid = cookies.get(TRUST_SID_COOKIE);
    const session = validTokenId(sid) ? trustSessions.get(sid) : null;
    if (session && timingSafeEqualText(provided, session.csrfToken)) return true;
    const preId = cookies.get(TRUST_PRE_COOKIE);
    if (!validTokenId(preId)) return false;
    return timingSafeEqualText(provided, deriveTrustCsrf('pre', preId));
  }

  function verifyConsolePreAuthCsrf(req) {
    const provided = getCsrfHeader(req);
    if (!provided) return false;
    const cookies = parseCookieHeader(req.headers.cookie);
    const sid = cookies.get(CONSOLE_SID_COOKIE);
    const session = validTokenId(sid) ? consoleSessions.get(sid) : null;
    if (session && timingSafeEqualText(provided, session.csrfToken)) return true;
    const preId = cookies.get(CONSOLE_PRE_COOKIE);
    if (!validTokenId(preId)) return false;
    return timingSafeEqualText(provided, deriveConsoleCsrf('pre', preId));
  }

  function verifyAuthenticatedCsrf(req, session) {
    const provided = getCsrfHeader(req);
    return Boolean(session && timingSafeEqualText(provided, session.csrfToken));
  }

  function ensurePreAuthCookie(req, { kind }) {
    const cookieName = kind === 'trust' ? TRUST_PRE_COOKIE : CONSOLE_PRE_COOKIE;
    const derive = kind === 'trust' ? deriveTrustCsrf : deriveConsoleCsrf;
    const cookies = parseCookieHeader(req.headers.cookie);
    let preId = cookies.get(cookieName);
    let setCookie = null;
    if (!validTokenId(preId)) {
      preId = crypto.randomBytes(24).toString('base64url');
      setCookie = `${cookieName}=${preId}; HttpOnly; SameSite=Strict; Path=/`;
    }
    return { preId, csrfToken: derive('pre', preId), setCookie };
  }

  function resetPreAuthCookies(kind) {
    const preCookie = kind === 'trust' ? TRUST_PRE_COOKIE : CONSOLE_PRE_COOKIE;
    const sidCookie = kind === 'trust' ? TRUST_SID_COOKIE : CONSOLE_SID_COOKIE;
    const derive = kind === 'trust' ? deriveTrustCsrf : deriveConsoleCsrf;
    const preId = crypto.randomBytes(24).toString('base64url');
    return {
      csrfToken: derive('pre', preId),
      setCookies: [
        `${sidCookie}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`,
        `${preCookie}=${preId}; HttpOnly; SameSite=Strict; Path=/`,
      ],
    };
  }

  function loginCookies(kind, sid) {
    const preCookie = kind === 'trust' ? TRUST_PRE_COOKIE : CONSOLE_PRE_COOKIE;
    const sidCookie = kind === 'trust' ? TRUST_SID_COOKIE : CONSOLE_SID_COOKIE;
    return [
      `${sidCookie}=${sid}; HttpOnly; SameSite=Strict; Path=/`,
      `${preCookie}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`,
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
    trustSessions.clear();
    consoleSessions.clear();
    handoffTickets.clear();
    registerChallenges.clear();
    loginChallenges.clear();
  }

  return Object.freeze({
    createTrustSession,
    authenticateTrustSession,
    issueConsoleHandoffTicket,
    exchangeConsoleHandoffTicket,
    authenticateConsoleSession,
    revokeTrustSession,
    revokeChildConsoleSessions,
    revokeConsoleSession,
    invalidateAllSessions,
    pruneOtherTrustSessions,
    updateAllSessionsPersistence,
    verifyTrustPreAuthCsrf,
    verifyConsolePreAuthCsrf,
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
    getTrustSessionBySid: sid => (validTokenId(sid) ? trustSessions.get(sid) || null : null),
    getConsoleSessionBySid: sid => (validTokenId(sid) ? consoleSessions.get(sid) || null : null),
    clearAll,
  });
}
