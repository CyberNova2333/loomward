// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).

export const MAX_RPC_BYTES = 1024 * 1024;
export const MAX_REPLY_BYTES = 2 * 1024 * 1024;
export const MAX_WS_PAYLOAD_BYTES = 1_200_000;
export const HEARTBEAT_INTERVAL_MS = 20_000;
export const HEARTBEAT_MAX_AGE_MS = 65_000;
export const FIRST_HEARTBEAT_GRACE_MS = 10_000;
export const REQUEST_MAX_TTL_MS = 110_000;

export const COMPUTER_SCOPES = Object.freeze(['computer:read', 'computer:write', 'computer:execute']);
export const OAUTH_SCOPES = Object.freeze([...COMPUTER_SCOPES, 'offline_access']);
export const PROTOCOL_VERSIONS = Object.freeze(['2025-11-25', '2025-06-18', '2025-03-26']);
export const APPROVAL_EXEMPT_TOOLS = Object.freeze(['computer_context', 'command_status', 'stop_command']);

export const BUILTIN_TOOL_SCOPES = Object.freeze({
  computer_context: Object.freeze(['computer:read']),
  list_directory: Object.freeze(['computer:read']),
  read_file: Object.freeze(['computer:read']),
  search_files: Object.freeze(['computer:read']),
  write_file: Object.freeze(['computer:read', 'computer:write']),
  edit_file: Object.freeze(['computer:read', 'computer:write']),
  delete_file: Object.freeze(['computer:read', 'computer:write']),
  exec_command: Object.freeze(['computer:read', 'computer:execute']),
  command_status: Object.freeze(['computer:read', 'computer:execute']),
  stop_command: Object.freeze(['computer:read', 'computer:execute']),
});

export function assertValidBridgeOrigin(origin) {
  const url = new URL(origin);
  const isLoopback = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  if (!['https:', 'http:'].includes(url.protocol) || (url.protocol === 'http:' && !isLoopback)) {
    throw new Error('The bridge requires HTTPS, except on loopback for tests.');
  }
  if (url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('Expected a canonical origin without a path or credentials.');
  }
  return url;
}

export function buildBridgeWebSocketUrl(origin) {
  const base = assertValidBridgeOrigin(origin);
  const wsUrl = new URL('/bridge', base);
  wsUrl.protocol = base.protocol === 'https:' ? 'wss:' : 'ws:';
  return wsUrl;
}
