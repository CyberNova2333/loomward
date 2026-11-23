// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
export { contract } from './contract.mjs';
export {
  MAX_RPC_BYTES,
  MAX_REPLY_BYTES,
  MAX_WS_PAYLOAD_BYTES,
  HEARTBEAT_INTERVAL_MS,
  HEARTBEAT_MAX_AGE_MS,
  FIRST_HEARTBEAT_GRACE_MS,
  REQUEST_MAX_TTL_MS,
  COMPUTER_SCOPES,
  OAUTH_SCOPES,
  PROTOCOL_VERSIONS,
  APPROVAL_EXEMPT_TOOLS,
  BUILTIN_TOOL_SCOPES,
  assertValidBridgeOrigin,
  buildBridgeWebSocketUrl,
} from './protocol.mjs';

import * as protocol from './protocol.mjs';

export const name = 'cloud-relay';

export function apply(ctx) {
  ctx.provide('relay:cloud-worker', Object.freeze({
    status: 'ready',
    legacyEntry: 'cloud/index.mjs',
    protocol: Object.freeze({
      maxRpcBytes: protocol.MAX_RPC_BYTES,
      maxReplyBytes: protocol.MAX_REPLY_BYTES,
      maxWsPayloadBytes: protocol.MAX_WS_PAYLOAD_BYTES,
      heartbeatIntervalMs: protocol.HEARTBEAT_INTERVAL_MS,
      heartbeatMaxAgeMs: protocol.HEARTBEAT_MAX_AGE_MS,
      firstHeartbeatGraceMs: protocol.FIRST_HEARTBEAT_GRACE_MS,
      requestMaxTtlMs: protocol.REQUEST_MAX_TTL_MS,
      computerScopes: protocol.COMPUTER_SCOPES,
      oauthScopes: protocol.OAUTH_SCOPES,
      protocolVersions: protocol.PROTOCOL_VERSIONS,
    }),
    assertValidBridgeOrigin: protocol.assertValidBridgeOrigin,
    buildBridgeWebSocketUrl: protocol.buildBridgeWebSocketUrl,
  }));
}
