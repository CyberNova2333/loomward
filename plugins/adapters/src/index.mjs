// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
export { contract } from './contract.mjs';

export const name = 'plugin-adapters';

export const STANDALONE_INTEGRATIONS = Object.freeze({
  cloudforge: Object.freeze({
    repository: 'https://github.com/CyberNova2333/cloudforge',
    protocol: 'oauth2.1-streamable-http-mcp',
    ownership: 'standalone',
  }),
  modelbridge: Object.freeze({
    repository: 'https://github.com/CyberNova2333/modelbridge',
    protocol: 'http-gateway-and-state-telemetry',
    ownership: 'standalone',
  }),
});
