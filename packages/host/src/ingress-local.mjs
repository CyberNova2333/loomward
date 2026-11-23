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

  return Object.freeze({
    id: 'local-mcp-direct',
    kind: 'local-direct',
    async start() {
      await pipeline.ready();
      running = true;
    },
    async stop() {
      running = false;
      pipeline.abortAll();
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
      const now = Date.now();
      const boundedTimeout = Math.max(1000, Math.min(100_000, Number(timeoutMs) || 60_000));
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
      return pipeline.handleRequest(envelope, { signal });
    },
    health() {
      return { running, kind: 'local-direct' };
    },
  });
}
