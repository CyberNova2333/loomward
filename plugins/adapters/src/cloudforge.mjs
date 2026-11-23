// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Out-of-process adapter for standalone CloudForge (OAuth 2.1 + PKCE discovery, /.well-known/cloudforge probe, Streamable HTTP /mcp).
import crypto from 'node:crypto';
import { validateConsolePanelDecl } from '@loomward/shared';
import {
  DEFAULT_MAX_RESPONSE_BYTES,
  assertSafeEndpointUrl,
  assertSafeIntegrationOrigin,
  fetchBounded,
  parseSseJsonRpcFrames,
} from './network.mjs';

export const CLOUDFORGE_TOOL_PREFIX = 'mcp__cloudforge__';
const VALID_REMOTE_TOOL_NAME = /^[A-Za-z0-9_.-]{1,64}$/;
const WRITE_OR_MODERATOR_HINT =
  /(?:^|[_.-])(create|update|delete|remove|merge|push|close|reopen|approve|reject|moderate|moderator|ban|unban|grant|revoke|trigger|dispatch|release|publish|edit|write|set|add|commit|review|comment|label|assign|archive|transfer|admin)(?:$|[_.-])/i;

function base64Url(bytes) {
  return Buffer.from(bytes)
    .toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '');
}

export function generatePkcePair() {
  const verifier = base64Url(crypto.randomBytes(32));
  const challenge = base64Url(crypto.createHash('sha256').update(verifier, 'utf8').digest());
  return Object.freeze({
    verifier,
    challenge,
    method: 'S256',
  });
}

export function classifyCloudForgeToolRisk(remoteName) {
  return WRITE_OR_MODERATOR_HINT.test(String(remoteName || '')) ? 'write' : 'read';
}

export function createCloudForgeClient({
  origin,
  getAccessToken = null,
  fetchImpl = globalThis.fetch,
  allowLoopbackHttp = false,
  allowPrivateNetwork = false,
  timeoutMs = 10_000,
  maxBytes = DEFAULT_MAX_RESPONSE_BYTES,
  clientInfo = { name: 'loomward-cloudforge-adapter', version: '3.0.0-alpha.0' },
} = {}) {
  const safeOrigin = assertSafeIntegrationOrigin(origin, {
    allowLoopbackHttp,
    allowPrivateNetwork,
    label: 'CloudForge',
  });
  const boundedTimeout = Math.min(Math.max(100, Number(timeoutMs) || 10_000), 15_000);
  const resourceUrl = `${safeOrigin}/mcp`;

  let nextRpcId = 1;
  let cachedTools = null;
  let lastProbe = null;
  let lastError = null;
  let callCount = 0;

  async function resolveToken() {
    if (typeof getAccessToken !== 'function') return null;
    const token = await getAccessToken();
    return typeof token === 'string' && token.trim() ? token.trim() : null;
  }

  async function probeWellKnown({ diagnostic = false } = {}) {
    const suffix = diagnostic ? '/.well-known/cloudforge?diagnostic=1' : '/.well-known/cloudforge';
    const url = `${safeOrigin}${suffix}`;
    try {
      const res = await fetchBounded(url, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        timeoutMs: boundedTimeout,
        maxBytes,
        fetchImpl,
      });
      if (!res.ok) {
        const snapshot = {
          reachable: false,
          status: res.status,
          latencyMs: res.latencyMs,
          installationId: null,
          version: null,
          schemaDigest: null,
          accessRuntime: null,
          error: `HTTP ${res.status}`,
        };
        lastProbe = snapshot;
        lastError = snapshot.error;
        return snapshot;
      }
      const parsed = JSON.parse(res.text);
      const accessRuntime = parsed?.accessRuntime && typeof parsed.accessRuntime === 'object'
        ? {
            protocol: parsed.accessRuntime.protocol ?? null,
            ready: Boolean(parsed.accessRuntime.ready),
            minimumProtocol: parsed.accessRuntime.minimumProtocol ?? null,
            schemaMode: typeof parsed.accessRuntime.schemaMode === 'string' ? parsed.accessRuntime.schemaMode : null,
            rolePublishingEnabled: typeof parsed.accessRuntime.rolePublishingEnabled === 'boolean'
              ? parsed.accessRuntime.rolePublishingEnabled
              : null,
            revision: parsed.accessRuntime.revision ?? null,
            reason: typeof parsed.accessRuntime.reason === 'string' ? parsed.accessRuntime.reason : null,
          }
        : null;
      const snapshot = {
        reachable: true,
        status: res.status,
        latencyMs: res.latencyMs,
        installationId: typeof parsed?.installationId === 'string' ? parsed.installationId : null,
        version: typeof parsed?.version === 'string' ? parsed.version : null,
        schemaDigest: typeof parsed?.schemaDigest === 'string' ? parsed.schemaDigest : null,
        accessRuntime,
        error: null,
      };
      lastProbe = snapshot;
      lastError = null;
      return snapshot;
    } catch (error) {
      const snapshot = {
        reachable: false,
        status: 0,
        latencyMs: 0,
        installationId: null,
        version: null,
        schemaDigest: null,
        accessRuntime: null,
        error: error.message || 'CloudForge metadata probe failed.',
      };
      lastProbe = snapshot;
      lastError = snapshot.error;
      return snapshot;
    }
  }

  async function discoverOAuth() {
    const prmRes = await fetchBounded(`${safeOrigin}/.well-known/oauth-protected-resource/mcp`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      timeoutMs: boundedTimeout,
      maxBytes,
      fetchImpl,
    });
    if (!prmRes.ok) {
      throw new Error(`CloudForge protected resource metadata unavailable (HTTP ${prmRes.status}).`);
    }
    const protectedResource = JSON.parse(prmRes.text);
    if (!Array.isArray(protectedResource?.authorization_servers) || !protectedResource.authorization_servers.length) {
      throw new Error('CloudForge protected resource metadata is missing authorization_servers.');
    }
    const issuerRaw = String(protectedResource.authorization_servers[0]);
    const issuerUrl = new URL(issuerRaw);
    const issuerOrigin = assertSafeIntegrationOrigin(issuerUrl.origin, {
      allowLoopbackHttp,
      allowPrivateNetwork,
      label: 'CloudForge OAuth issuer',
    });
    const issuerPath = issuerUrl.pathname.replace(/\/+$/, '');
    const candidates = issuerPath && issuerPath !== '/'
      ? [`${issuerOrigin}/.well-known/oauth-authorization-server${issuerPath}`, `${issuerOrigin}/.well-known/oauth-authorization-server`]
      : [`${issuerOrigin}/.well-known/oauth-authorization-server`];

    let authServer = null;
    for (const candidateUrl of candidates) {
      const res = await fetchBounded(candidateUrl, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        timeoutMs: boundedTimeout,
        maxBytes,
        fetchImpl,
      });
      if (res.ok) {
        authServer = JSON.parse(res.text);
        break;
      }
    }
    if (!authServer || typeof authServer !== 'object') {
      throw new Error('CloudForge OAuth authorization server metadata unavailable.');
    }
    const methods = Array.isArray(authServer.code_challenge_methods_supported)
      ? authServer.code_challenge_methods_supported
      : [];
    if (!methods.includes('S256')) {
      throw new Error('CloudForge OAuth server does not advertise PKCE S256 support.');
    }
    const authorizationEndpoint = assertSafeEndpointUrl(authServer.authorization_endpoint, {
      allowLoopbackHttp,
      allowPrivateNetwork,
      label: 'CloudForge authorization_endpoint',
    });
    const tokenEndpoint = assertSafeEndpointUrl(authServer.token_endpoint, {
      allowLoopbackHttp,
      allowPrivateNetwork,
      label: 'CloudForge token_endpoint',
    });
    const registrationEndpoint = authServer.registration_endpoint
      ? assertSafeEndpointUrl(authServer.registration_endpoint, {
          allowLoopbackHttp,
          allowPrivateNetwork,
          label: 'CloudForge registration_endpoint',
        })
      : null;

    return Object.freeze({
      resource: typeof protectedResource.resource === 'string' ? protectedResource.resource : resourceUrl,
      issuer: authServer.issuer || issuerRaw,
      authorizationEndpoint,
      tokenEndpoint,
      registrationEndpoint,
      pkceMethods: Object.freeze([...methods]),
    });
  }

  function buildAuthorizationUrl({
    authorizationEndpoint,
    clientId,
    redirectUri,
    scope = 'openid profile email offline_access',
    state,
    pkce = generatePkcePair(),
  }) {
    const safeEndpoint = assertSafeEndpointUrl(authorizationEndpoint, {
      allowLoopbackHttp,
      allowPrivateNetwork,
      label: 'CloudForge authorization_endpoint',
    });
    if (!clientId || !redirectUri || !state) {
      throw new TypeError('clientId, redirectUri, and state are required for OAuth 2.1 authorization.');
    }
    const url = new URL(safeEndpoint);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', String(clientId));
    url.searchParams.set('redirect_uri', String(redirectUri));
    url.searchParams.set('scope', String(scope));
    url.searchParams.set('code_challenge', pkce.challenge);
    url.searchParams.set('code_challenge_method', 'S256');
    url.searchParams.set('state', String(state));
    url.searchParams.set('resource', resourceUrl);
    return { url: url.toString(), pkce };
  }

  async function exchangeCode({ tokenEndpoint, clientId, code, redirectUri, codeVerifier }) {
    const safeEndpoint = assertSafeEndpointUrl(tokenEndpoint, {
      allowLoopbackHttp,
      allowPrivateNetwork,
      label: 'CloudForge token_endpoint',
    });
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: String(code || ''),
      redirect_uri: String(redirectUri || ''),
      client_id: String(clientId || ''),
      code_verifier: String(codeVerifier || ''),
      resource: resourceUrl,
    });
    const res = await fetchBounded(safeEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: body.toString(),
      timeoutMs: boundedTimeout,
      maxBytes,
      fetchImpl,
    });
    if (!res.ok) {
      throw new Error(`CloudForge token exchange failed (HTTP ${res.status}).`);
    }
    const parsed = JSON.parse(res.text);
    if (typeof parsed?.access_token !== 'string' || !parsed.access_token) {
      throw new Error('CloudForge token response did not include an access_token.');
    }
    return parsed;
  }

  async function refreshToken({ tokenEndpoint, clientId, refreshToken: token }) {
    const safeEndpoint = assertSafeEndpointUrl(tokenEndpoint, {
      allowLoopbackHttp,
      allowPrivateNetwork,
      label: 'CloudForge token_endpoint',
    });
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: String(token || ''),
      client_id: String(clientId || ''),
      resource: resourceUrl,
    });
    const res = await fetchBounded(safeEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: body.toString(),
      timeoutMs: boundedTimeout,
      maxBytes,
      fetchImpl,
    });
    if (!res.ok) {
      throw new Error(`CloudForge token refresh failed (HTTP ${res.status}).`);
    }
    return JSON.parse(res.text);
  }

  async function mcpRequest(method, params = {}) {
    const token = await resolveToken();
    const id = nextRpcId++;
    const headers = {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
    const res = await fetchBounded(resourceUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
      timeoutMs: boundedTimeout,
      maxBytes,
      fetchImpl,
    });
    if (res.status === 401) {
      const challenge = res.headers?.get?.('www-authenticate') || '';
      const err = new Error('CloudForge MCP requires OAuth 2.1 Bearer authentication.');
      err.code = 'CLOUDFORGE_UNAUTHORIZED';
      err.wwwAuthenticate = challenge;
      throw err;
    }
    if (!res.ok) {
      const err = new Error(`CloudForge MCP request failed (HTTP ${res.status}).`);
      err.code = 'CLOUDFORGE_HTTP_ERROR';
      err.status = res.status;
      throw err;
    }
    const contentType = String(res.headers?.get?.('content-type') || '').toLowerCase();
    let payload;
    if (contentType.includes('text/event-stream')) {
      const frames = parseSseJsonRpcFrames(res.text);
      payload = frames.find(frame => frame && frame.id === id) || frames[frames.length - 1];
      if (!payload) {
        throw new Error('CloudForge SSE stream returned no JSON-RPC response frame.');
      }
    } else {
      payload = JSON.parse(res.text);
    }
    if (payload?.error) {
      const err = new Error(payload.error.message || 'CloudForge MCP returned JSON-RPC error.');
      err.code = 'CLOUDFORGE_RPC_ERROR';
      err.rpcCode = payload.error.code;
      throw err;
    }
    return payload?.result;
  }

  async function initialize() {
    return mcpRequest('initialize', {
      protocolVersion: '2025-03-26',
      capabilities: {},
      clientInfo,
    });
  }

  async function listTools({ refresh = false } = {}) {
    if (cachedTools && !refresh) return cachedTools;
    const result = await mcpRequest('tools/list', {});
    const remoteTools = Array.isArray(result?.tools) ? result.tools : [];
    const normalized = [];
    for (const tool of remoteTools) {
      if (!tool || typeof tool.name !== 'string' || !VALID_REMOTE_TOOL_NAME.test(tool.name)) continue;
      const risk = classifyCloudForgeToolRisk(tool.name);
      normalized.push({
        name: `${CLOUDFORGE_TOOL_PREFIX}${tool.name}`,
        remoteName: tool.name,
        description: String(tool.description || `CloudForge tool ${tool.name}`),
        inputSchema: tool.inputSchema && typeof tool.inputSchema === 'object'
          ? tool.inputSchema
          : { type: 'object', properties: {} },
        annotations: {
          risk,
          readOnlyHint: risk === 'read',
          requiresLocalApproval: true,
        },
      });
    }
    cachedTools = normalized;
    return cachedTools;
  }

  async function callTool(namespacedName, args = {}) {
    if (typeof namespacedName !== 'string' || !namespacedName.startsWith(CLOUDFORGE_TOOL_PREFIX)) {
      return {
        isError: true,
        content: [{ type: 'text', text: `Unknown CloudForge tool: ${String(namespacedName)}` }],
      };
    }
    const remoteName = namespacedName.slice(CLOUDFORGE_TOOL_PREFIX.length);
    if (!VALID_REMOTE_TOOL_NAME.test(remoteName)) {
      return {
        isError: true,
        content: [{ type: 'text', text: 'Invalid CloudForge remote tool name.' }],
      };
    }
    callCount += 1;
    try {
      const result = await mcpRequest('tools/call', {
        name: remoteName,
        arguments: args && typeof args === 'object' && !Array.isArray(args) ? args : {},
      });
      if (result && Array.isArray(result.content)) {
        return {
          ...(result.isError ? { isError: true } : {}),
          content: result.content,
        };
      }
      return {
        content: [{ type: 'text', text: JSON.stringify(result ?? null, null, 2) }],
      };
    } catch (error) {
      lastError = error.message;
      return {
        isError: true,
        content: [{ type: 'text', text: error.message || 'CloudForge tool invocation failed.' }],
      };
    }
  }

  function getCachedTools() {
    return cachedTools ? [...cachedTools] : [];
  }

  function getStats() {
    return Object.freeze({
      origin: safeOrigin,
      resourceUrl,
      discoveredTools: cachedTools ? cachedTools.length : 0,
      writeTools: cachedTools ? cachedTools.filter(t => t.annotations.risk === 'write').length : 0,
      callCount,
      lastProbe,
      lastError,
      tokenConfigured: typeof getAccessToken === 'function',
    });
  }

  return Object.freeze({
    origin: safeOrigin,
    resourceUrl,
    probeWellKnown,
    discoverOAuth,
    buildAuthorizationUrl,
    exchangeCode,
    refreshToken,
    initialize,
    listTools,
    getCachedTools,
    callTool,
    getStats,
  });
}

export function createCloudForgeToolProvider(client) {
  let closed = false;
  return Object.freeze({
    id: 'cloudforge',
    executionBoundary: 'out-of-process',
    ownsTool(toolName) {
      if (closed || typeof toolName !== 'string' || !toolName.startsWith(CLOUDFORGE_TOOL_PREFIX)) return false;
      const cached = client.getCachedTools();
      if (!cached.length) return VALID_REMOTE_TOOL_NAME.test(toolName.slice(CLOUDFORGE_TOOL_PREFIX.length));
      return cached.some(tool => tool.name === toolName);
    },
    getToolScopes() {
      const map = new Map();
      for (const tool of client.getCachedTools()) {
        map.set(
          tool.name,
          tool.annotations?.risk === 'write'
            ? ['computer:read', 'computer:write']
            : ['computer:read'],
        );
      }
      return map;
    },
    checkToolEnabled(toolName) {
      if (closed) {
        return { enabled: false, capability: 'cloudforge', reason: 'CloudForge adapter is closed.' };
      }
      if (!this.ownsTool(toolName)) {
        return { enabled: false, capability: 'cloudforge', reason: 'Unknown CloudForge tool.' };
      }
      return { enabled: true, capability: 'cloudforge' };
    },
    async listTools() {
      if (closed) return [];
      const tools = await client.listTools();
      return tools.map(({ remoteName: _remote, ...pub }) => structuredClone(pub));
    },
    async callTool(toolName, args) {
      if (closed) {
        return { isError: true, content: [{ type: 'text', text: 'CloudForge adapter is closed.' }] };
      }
      return client.callTool(toolName, args);
    },
    async close() {
      closed = true;
    },
  });
}

export function createCloudForgePanel(client, { origin = null } = {}) {
  return validateConsolePanelDecl({
    id: 'cloudforge',
    title: 'CloudForge · 独立仓库适配',
    subtitle: '独立维护的 Git / OAuth 2.1 MCP 托管平台（只读观测 + 经本机审批的工具聚合）',
    order: 40,
    async getSnapshot() {
      if (!client) {
        return {
          status: 'idle',
          summary: [
            { label: '连接状态', value: '未配置', tone: 'neutral' },
            { label: '仓库归属', value: '独立维护（standalone）', tone: 'neutral' },
          ],
          notices: [
            { tone: 'info', text: '未配置 CloudForge 实例地址；本体保持独立仓库维护，不与 LoomWard 代码耦合。' },
          ],
        };
      }
      const probe = await client.probeWellKnown();
      const stats = client.getStats();
      const runtime = probe.accessRuntime;
      const runtimeState = !probe.reachable
        ? '不可达'
        : runtime?.ready
          ? '就绪'
          : `未就绪 (${runtime?.reason || 'unavailable'})`;
      const tone = !probe.reachable ? 'err' : runtime?.ready ? 'ok' : 'warn';
      const summary = [
        { label: '元数据探针', value: runtimeState, tone },
        { label: '实例版本', value: probe.version || '未知', tone: 'neutral' },
        { label: '已发现 MCP 工具', value: String(stats.discoveredTools), tone: 'neutral' },
        { label: '累计工具调用', value: String(stats.callCount), tone: 'neutral' },
      ];
      const rows = [
        ['实例地址', stats.origin],
        ['安装标识', probe.installationId || '—'],
        ['Access Runtime 协议', runtime ? `v${runtime.protocol ?? '?'} (${runtime.schemaMode || 'default'})` : '—'],
        ['OAuth 凭据回调', stats.tokenConfigured ? '已注入（不落盘不回显）' : '仅匿名只读探针'],
      ];
      const notices = [];
      if (!probe.reachable && probe.error) {
        notices.push({ tone: 'warn', text: `探针异常：${probe.error}` });
      }
      if (stats.writeTools > 0) {
        notices.push({
          tone: 'info',
          text: `已识别 ${stats.writeTools} 项写/审核类 CloudForge 工具，全部经 LoomWard 本机逐参人工审批与 24h 防重放账本门控。`,
        });
      }
      return {
        status: !probe.reachable ? 'error' : runtime?.ready ? 'ok' : 'degraded',
        summary,
        tables: [{ title: 'CloudForge 实例摘要', columns: ['字段', '值'], rows }],
        notices,
        links: origin || stats.origin ? [{ label: '打开 CloudForge 控制台', href: origin || stats.origin }] : [],
      };
    },
  });
}
