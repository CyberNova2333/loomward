// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
export { contract } from './contract.mjs';

export const name = 'plugin-mcp-hub';

export function createMcpHubDescriptor() {
  return Object.freeze({
    id: 'mcp-hub',
    boundary: 'out-of-process',
    transports: ['stdio', 'streamable-http'],
    legacyEntries: ['local/mcp-registry.mjs', 'local/mcp-client.mjs'],
  });
}
