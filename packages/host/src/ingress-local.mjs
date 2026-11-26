// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import crypto from 'node:crypto';

const DEFAULT_LOCAL_SCOPES = Object.freeze(['computer:read', 'computer:write', 'computer:execute']);

export function createLocalMcpIngress({
  pipeline,
  clientId = 'local-mcp-client',
  defaultScopes = DEFAULT_LOCAL_SCOPES,
} = {}) {
  if (!pipeline || typeof pipeline.handleRequest !== 'function') {
    throw new Error('createLocalMcpIngress requires a ToolDispatchPipeline.');
  }

  let running = false;
  let startEpoch = 0;
  const activeControllers = new Set();

  return Object.freeze({
    id: 'local-mcp-direct',
    kind: 'local-direct',
    async start() {
      const epoch = ++startEpoch;
      await pipeline.ready();
      if (epoch === startEpoch) {
        running = true;
      }
    },
    async stop() {
      startEpoch += 1;
      running = false;
      for (const ctrl of [...activeControllers]) {
        ctrl.abort();
        activeControllers.delete(ctrl);
      }
    },
    async dispatchRpc(
      body,
      {
        requestId = `local_${crypto.randomUUID().replaceAll('-', '')}`,
        clientId: callerClientId = clientId,
        scope = defaultScopes,
        timeoutMs = 60_000,
        signal,
      } = {},
    ) {
      if (!running) {
        const rawId = body?.id;
        const safeId = rawId === null || (typeof rawId === 'number' && Number.isFinite(rawId)) || (typeof rawId === 'string' && rawId.length <= 256)
          ? rawId
          : null;
        return {
          jsonrpc: '2.0',
          id: safeId,
          error: { code: -32001, message: 'Local ingress is not running.' },
        };
      }
      const now = Date.now();
      const rawTimeout = Number(timeoutMs);
      const boundedTimeout = Math.max(1000, Math.min(100_000, Number.isFinite(rawTimeout) ? Math.trunc(rawTimeout) : 60_000));
      const envelope = {
        type: 'request',
        id: requestId,
        issuedAt: now,
        deadline: now + boundedTimeout,
        authorization: {
          userId: 'owner',
          clientId: callerClientId,
          scope: [...scope],
        },
        body,
      };
      const reqController = new AbortController();
      const onCallerAbort = () => reqController.abort();
      if (signal) {
        if (signal.aborted) reqController.abort();
        else signal.addEventListener('abort', onCallerAbort, { once: true });
      }
      activeControllers.add(reqController);
      try {
        return await pipeline.handleRequest(envelope, { signal: reqController.signal });
      } finally {
        if (signal) signal.removeEventListener('abort', onCallerAbort);
        activeControllers.delete(reqController);
      }
    },
    async dispatchRpcStream(
      body,
      {
        requestId = `local_${crypto.randomUUID().replaceAll('-', '')}`,
        clientId: callerClientId = clientId,
        scope = defaultScopes,
        timeoutMs = 60_000,
        signal,
        onChunk,
      } = {},
    ) {
      if (!running) {
        const rawId = body?.id;
        const safeId = rawId === null || (typeof rawId === 'number' && Number.isFinite(rawId)) || (typeof rawId === 'string' && rawId.length <= 256)
          ? rawId
          : null;
        return {
          jsonrpc: '2.0',
          id: safeId,
          error: { code: -32001, message: 'Local ingress is not running.' },
        };
      }
      const now = Date.now();
      const rawTimeout = Number(timeoutMs);
      const boundedTimeout = Math.max(1000, Math.min(100_000, Number.isFinite(rawTimeout) ? Math.trunc(rawTimeout) : 60_000));
      const envelope = {
        type: 'request',
        id: requestId,
        issuedAt: now,
        deadline: now + boundedTimeout,
        authorization: {
          userId: 'owner',
          clientId: callerClientId,
          scope: [...scope],
        },
        body,
      };
      const reqController = new AbortController();
      const onCallerAbort = () => reqController.abort();
      if (signal) {
        if (signal.aborted) reqController.abort();
        else signal.addEventListener('abort', onCallerAbort, { once: true });
      }
      activeControllers.add(reqController);
      try {
        return await pipeline.handleStreamRequest(envelope, { signal: reqController.signal, onChunk });
      } finally {
        if (signal) signal.removeEventListener('abort', onCallerAbort);
        activeControllers.delete(reqController);
      }
    },
    health() {
      return { running, kind: 'local-direct' };
    },
  });
}
