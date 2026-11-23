// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Cordis 4 extension plugin entry for standalone external integrations (CloudForge + ModelBridge).
import { contract } from './contract.mjs';
import {
  CLOUDFORGE_TOOL_PREFIX,
  classifyCloudForgeToolRisk,
  createCloudForgeClient,
  createCloudForgePanel,
  createCloudForgeToolProvider,
  generatePkcePair,
} from './cloudforge.mjs';
import {
  MODELBRIDGE_MAX_TIMEOUT_MS,
  createModelBridgeClient,
  createModelBridgePanel,
} from './modelbridge.mjs';
import {
  DEFAULT_MAX_RESPONSE_BYTES,
  assertSafeEndpointUrl,
  assertSafeIntegrationOrigin,
  assertSafeResolvedHostname,
  classifyIpLiteral,
  fetchBounded,
  parseSseJsonRpcFrames,
} from './network.mjs';

export {
  contract,
  CLOUDFORGE_TOOL_PREFIX,
  MODELBRIDGE_MAX_TIMEOUT_MS,
  DEFAULT_MAX_RESPONSE_BYTES,
  classifyIpLiteral,
  assertSafeIntegrationOrigin,
  assertSafeEndpointUrl,
  assertSafeResolvedHostname,
  fetchBounded,
  parseSseJsonRpcFrames,
  generatePkcePair,
  classifyCloudForgeToolRisk,
  createCloudForgeClient,
  createCloudForgeToolProvider,
  createCloudForgePanel,
  createModelBridgeClient,
  createModelBridgePanel,
};

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

export function apply(ctx, options = {}) {
  const disposers = [];

  const cloudforgeClient = options.cloudforge?.origin
    ? createCloudForgeClient(options.cloudforge)
    : null;
  const modelbridgeClient = options.modelbridge?.origin
    ? createModelBridgeClient(options.modelbridge)
    : null;

  let provider = null;
  const toolProviderSlot = ctx.get('tool:provider@1');
  if (toolProviderSlot && cloudforgeClient) {
    provider = createCloudForgeToolProvider(cloudforgeClient);
    const release = toolProviderSlot.register('cloudforge', provider);
    if (typeof release === 'function') disposers.push(release);
  }

  const panelSlot = ctx.get('console:panel@1');
  if (panelSlot) {
    const cfPanel = createCloudForgePanel(cloudforgeClient, { origin: options.cloudforge?.origin || null });
    const releaseCf = panelSlot.register('cloudforge', cfPanel);
    if (typeof releaseCf === 'function') disposers.push(releaseCf);

    const mbPanel = createModelBridgePanel(modelbridgeClient, { origin: options.modelbridge?.origin || null });
    const releaseMb = panelSlot.register('modelbridge', mbPanel);
    if (typeof releaseMb === 'function') disposers.push(releaseMb);
  }

  ctx.effect(() => async () => {
    while (disposers.length) {
      const dispose = disposers.pop();
      try { dispose(); } catch {}
    }
    if (provider) {
      await provider.close();
    }
  }, 'adapters:close');
}
