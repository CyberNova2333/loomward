// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Bounded 0600 out-of-workspace configuration loader and per-tool policy resolver for @loomward/plugin-llm-moderation.
import { readModerationConfigSync } from '../../../local/moderation-config.mjs';
import { DEFAULT_MODERATION_CONFIG, validateModerationConfig } from '@loomward/shared';

export { moderationConfigFilePath } from '../../../local/moderation-config.mjs';

export function loadEffectiveModerationConfig({
  stateDir = null,
  inlineConfig = null,
  workspaceRoots = [],
  blockedOrigins = [],
  preferInlineConfig = false,
} = {}) {
  if (preferInlineConfig && inlineConfig && typeof inlineConfig === 'object') {
    return validateModerationConfig(inlineConfig, { blockedOrigins });
  }
  const diskConfig = readModerationConfigSync(stateDir, { workspaceRoots, blockedOrigins, fallback: null });
  if (diskConfig) return diskConfig;
  if (inlineConfig && typeof inlineConfig === 'object') {
    return validateModerationConfig(inlineConfig, { blockedOrigins });
  }
  return DEFAULT_MODERATION_CONFIG;
}

export function resolveToolModerationPolicy(config, toolName) {
  const safeName = typeof toolName === 'string' ? toolName : '';
  const exempt = Array.isArray(config?.exemptTools) && config.exemptTools.includes(safeName);
  const override = safeName && config?.perToolOverrides && Object.hasOwn(config.perToolOverrides, safeName)
    ? config.perToolOverrides[safeName]
    : null;
  const enabled = config?.enabled !== false && (!override || override.enabled !== false);
  const scope = override?.scope ?? config?.defaultScope ?? DEFAULT_MODERATION_CONFIG.defaultScope;
  const mode = override?.mode ?? config?.mode ?? DEFAULT_MODERATION_CONFIG.mode;
  const policyProfile = override?.policyProfile ?? config?.policyProfile ?? DEFAULT_MODERATION_CONFIG.policyProfile;
  return Object.freeze({
    enabled,
    exempt,
    scope,
    mode,
    policyProfile,
  });
}
