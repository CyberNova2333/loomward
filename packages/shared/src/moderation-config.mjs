// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Shared, zero-Node configuration schema, policy presets, and validator for @loomward/plugin-llm-moderation.
import { assertSafeEndpointUrl } from './network-policy.mjs';

export const MODERATION_CONFIG_VERSION = 1;
export const MODERATION_MODES = Object.freeze([
  'local-only',
  'guard-plus-canary',
  'cloud-first',
  'hybrid-tiered',
]);
export const MODERATION_POLICY_PROFILES = Object.freeze([
  'strict',
  'balanced',
  'experimental-resilient',
]);
export const MODERATION_SCOPES = Object.freeze([
  'input-only',
  'output-only',
  'combined',
]);
export const MODERATION_CLOUD_PROVIDERS = Object.freeze([
  'openai-compat',
  'webhook',
  'aliyun-green',
  'tencent-tms',
  'baidu-aip',
]);
export const MODERATION_STREAM_REDACT_POLICIES = Object.freeze([
  'mask-continue',
  'strict-block',
]);

export const POLICY_PROFILE_DEFAULTS = Object.freeze({
  strict: Object.freeze({
    fallbackChain: Object.freeze([]),
    onAllFailedInput: 'block',
    onAllFailedOutput: 'block',
    onCanaryUnavailable: 'block',
    defaultScope: 'combined',
  }),
  balanced: Object.freeze({
    fallbackChain: Object.freeze(['local-guard']),
    onAllFailedInput: 'escalate',
    onAllFailedOutput: 'block',
    onCanaryUnavailable: 'escalate',
    defaultScope: 'combined',
  }),
  'experimental-resilient': Object.freeze({
    fallbackChain: Object.freeze(['local-guard']),
    onAllFailedInput: 'escalate',
    onAllFailedOutput: 'block',
    onCanaryUnavailable: 'ignore-if-guard-confident',
    defaultScope: 'combined',
  }),
});

export const DEFAULT_MODERATION_CONFIG = Object.freeze({
  schemaVersion: MODERATION_CONFIG_VERSION,
  enabled: true,
  mode: 'local-only',
  policyProfile: 'experimental-resilient',
  defaultScope: 'combined',
  cloudOptIn: false,
  cloudProvider: 'openai-compat',
  cloudEndpoint: null,
  cloudRegion: null,
  localGuard: Object.freeze({
    kind: 'http',
    endpoint: null,
    model: 'llama-guard-3',
    timeoutMs: 8_000,
    think: false,
    allowPrivateNetwork: false,
  }),
  canary: Object.freeze({
    kind: 'http',
    enabled: false,
    endpoint: null,
    model: 'qwen2.5-0.5b',
    maxTokens: 96,
    temperature: 0.1,
    shadowMode: true,
    escalateOnInduced: true,
    onCanaryUnavailable: 'ignore-if-guard-confident',
    think: false,
    allowPrivateNetwork: false,
  }),
  injectionAlerts: Object.freeze({ clientThreshold: 3, globalThreshold: 10 }),
  thresholds: Object.freeze({
    grayZoneLow: 0.25,
    grayZoneHigh: 0.8,
  }),
  fallback: Object.freeze({
    chain: Object.freeze(['local-guard']),
    onAllFailedInput: 'escalate',
    onAllFailedOutput: 'block',
  }),
  streaming: Object.freeze({
    overlapChars: 128,
    holdbackChars: 160,
    maxPendingBytes: 256 * 1024,
    redactPolicy: 'mask-continue',
  }),
  media: Object.freeze({
    scanWorkspacePaths: false,
    maxImageBytes: 20 * 1024 * 1024,
    maxImagePixels: 4096 * 4096,
    maxAudioSec: 180,
    maxVideoSec: 120,
    maxVideoFrames: 16,
  }),
  perToolOverrides: Object.freeze({}),
  exemptTools: Object.freeze(['computer_context', 'command_status', 'stop_command']),
});

function clampInt(val, min, max, fallback) {
  const num = Number(val);
  if (!Number.isFinite(num)) return fallback;
  return Math.max(min, Math.min(max, Math.trunc(num)));
}

function clampProb(val, fallback) {
  const num = Number(val);
  if (!Number.isFinite(num) || num < 0 || num > 1) return fallback;
  return num;
}

function normalizeEndpoint(raw, opts, label) {
  if (raw === undefined || raw === null || raw === '') return null;
  if (typeof raw !== 'string') throw new TypeError(`${label} must be a URL string or null.`);
  const trimmed = raw.trim();
  if (!trimmed) return null;
  return assertSafeEndpointUrl(trimmed, { ...opts, label });
}

function normalizeToolName(name) {
  if (typeof name !== 'string' || !/^[a-zA-Z0-9._:-]{1,128}$/.test(name)) {
    throw new TypeError(`Invalid tool identifier in moderation config: ${String(name)}`);
  }
  return name;
}

export function validateModerationConfig(raw = {}, { blockedOrigins = [] } = {}) {
  if (raw === null || raw === undefined) raw = {};
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    throw new TypeError('Moderation config must be an object.');
  }
  const policyProfile = raw.policyProfile ?? DEFAULT_MODERATION_CONFIG.policyProfile;
  if (!MODERATION_POLICY_PROFILES.includes(policyProfile)) {
    throw new Error(`Invalid moderation policyProfile: ${String(policyProfile)}`);
  }
  const preset = POLICY_PROFILE_DEFAULTS[policyProfile];
  const mode = raw.mode ?? DEFAULT_MODERATION_CONFIG.mode;
  if (!MODERATION_MODES.includes(mode)) {
    throw new Error(`Invalid moderation mode: ${String(mode)}`);
  }
  const defaultScope = raw.defaultScope ?? preset.defaultScope;
  if (!MODERATION_SCOPES.includes(defaultScope)) {
    throw new Error(`Invalid moderation defaultScope: ${String(defaultScope)}`);
  }
  const cloudProvider = raw.cloudProvider ?? DEFAULT_MODERATION_CONFIG.cloudProvider;
  if (!MODERATION_CLOUD_PROVIDERS.includes(cloudProvider)) {
    throw new Error(`Invalid moderation cloudProvider: ${String(cloudProvider)}`);
  }

  const rawLg = raw.localGuard && typeof raw.localGuard === 'object' ? raw.localGuard : {};
  const lgKind = rawLg.kind ?? DEFAULT_MODERATION_CONFIG.localGuard.kind;
  if (!['http', 'ollama', 'managed-python'].includes(lgKind)) {
    throw new Error(`Invalid localGuard.kind: ${String(lgKind)}`);
  }
  const lgAllowPrivate = rawLg.allowPrivateNetwork === true;
  const lgRawEndpoint = lgKind === 'ollama' && rawLg.endpoint === undefined
    ? 'http://127.0.0.1:11434'
    : rawLg.endpoint;
  const localGuard = Object.freeze({
    kind: lgKind,
    endpoint: normalizeEndpoint(lgRawEndpoint, { allowLoopbackHttp: true, allowPrivateNetwork: lgAllowPrivate, blockedOrigins }, 'localGuard.endpoint'),
    model: typeof rawLg.model === 'string' && rawLg.model.trim() ? rawLg.model.trim().slice(0, 128) : DEFAULT_MODERATION_CONFIG.localGuard.model,
    timeoutMs: clampInt(rawLg.timeoutMs, 500, 60_000, DEFAULT_MODERATION_CONFIG.localGuard.timeoutMs),
    think: rawLg.think === true,
    allowPrivateNetwork: lgAllowPrivate,
  });

  const rawCanary = raw.canary && typeof raw.canary === 'object' ? raw.canary : {};
  const canaryKind = rawCanary.kind ?? DEFAULT_MODERATION_CONFIG.canary.kind;
  if (!['http', 'ollama'].includes(canaryKind)) {
    throw new Error(`Invalid canary.kind: ${String(canaryKind)}`);
  }
  const onCanaryUnavailable = rawCanary.onCanaryUnavailable ?? preset.onCanaryUnavailable;
  if (!['ignore-if-guard-confident', 'escalate', 'block'].includes(onCanaryUnavailable)) {
    throw new Error(`Invalid canary.onCanaryUnavailable: ${String(onCanaryUnavailable)}`);
  }
  const canaryAllowPrivate = rawCanary.allowPrivateNetwork === true;
  const canaryRawEndpoint = canaryKind === 'ollama' && rawCanary.endpoint === undefined
    ? 'http://127.0.0.1:11434'
    : rawCanary.endpoint;
  const canary = Object.freeze({
    kind: canaryKind,
    enabled: rawCanary.enabled === true || mode === 'guard-plus-canary',
    endpoint: normalizeEndpoint(canaryRawEndpoint, { allowLoopbackHttp: true, allowPrivateNetwork: canaryAllowPrivate, blockedOrigins }, 'canary.endpoint'),
    model: typeof rawCanary.model === 'string' && rawCanary.model.trim() ? rawCanary.model.trim().slice(0, 128) : DEFAULT_MODERATION_CONFIG.canary.model,
    maxTokens: clampInt(rawCanary.maxTokens, 16, 256, DEFAULT_MODERATION_CONFIG.canary.maxTokens),
    temperature: Math.max(0, Math.min(0.5, Number.isFinite(Number(rawCanary.temperature)) ? Number(rawCanary.temperature) : DEFAULT_MODERATION_CONFIG.canary.temperature)),
    shadowMode: rawCanary.shadowMode !== undefined ? Boolean(rawCanary.shadowMode) : DEFAULT_MODERATION_CONFIG.canary.shadowMode,
    escalateOnInduced: rawCanary.escalateOnInduced !== false,
    onCanaryUnavailable,
    think: rawCanary.think === true,
    allowPrivateNetwork: canaryAllowPrivate,
  });

  const rawThresh = raw.thresholds && typeof raw.thresholds === 'object' ? raw.thresholds : {};
  const grayZoneLow = clampProb(rawThresh.grayZoneLow, DEFAULT_MODERATION_CONFIG.thresholds.grayZoneLow);
  const grayZoneHigh = clampProb(rawThresh.grayZoneHigh, DEFAULT_MODERATION_CONFIG.thresholds.grayZoneHigh);
  if (grayZoneLow > grayZoneHigh) {
    throw new Error('thresholds.grayZoneLow cannot exceed thresholds.grayZoneHigh.');
  }

  const rawFallback = raw.fallback && typeof raw.fallback === 'object' ? raw.fallback : {};
  const rawChain = Array.isArray(rawFallback.chain) ? rawFallback.chain : preset.fallbackChain;
  const fallbackChain = [];
  for (const item of rawChain) {
    if (!['local-guard', 'canary', 'cloud'].includes(item)) {
      throw new Error(`Invalid fallback chain target: ${String(item)}`);
    }
    if (!fallbackChain.includes(item)) fallbackChain.push(item);
  }
  const onAllFailedInput = rawFallback.onAllFailedInput ?? preset.onAllFailedInput;
  if (!['escalate', 'block'].includes(onAllFailedInput)) {
    throw new Error(`Invalid fallback.onAllFailedInput: ${String(onAllFailedInput)}`);
  }
  const onAllFailedOutput = rawFallback.onAllFailedOutput ?? preset.onAllFailedOutput;
  if (!['block', 'warn-experimental'].includes(onAllFailedOutput)) {
    throw new Error(`Invalid fallback.onAllFailedOutput: ${String(onAllFailedOutput)}`);
  }
  if (policyProfile === 'strict' && onAllFailedOutput !== 'block') {
    throw new Error('Strict policyProfile forbids warn-experimental output fallback.');
  }

  const rawStream = raw.streaming && typeof raw.streaming === 'object' ? raw.streaming : {};
  const redactPolicy = rawStream.redactPolicy ?? DEFAULT_MODERATION_CONFIG.streaming.redactPolicy;
  if (!MODERATION_STREAM_REDACT_POLICIES.includes(redactPolicy)) {
    throw new Error(`Invalid streaming.redactPolicy: ${String(redactPolicy)}`);
  }

  const alertConfig = raw.injectionAlerts === undefined ? {} : raw.injectionAlerts;
  if (!alertConfig || typeof alertConfig !== 'object' || Array.isArray(alertConfig)) {
    throw new TypeError('injectionAlerts must be an object.');
  }
  const injectionAlerts = { ...DEFAULT_MODERATION_CONFIG.injectionAlerts };
  for (const field of Object.keys(injectionAlerts)) {
    if (!Object.hasOwn(alertConfig, field)) continue;
    const value = alertConfig[field];
    if (!Number.isInteger(value) || value < 1 || value > 1000) {
      throw new RangeError(`injectionAlerts.${field} must be an integer between 1 and 1000.`);
    }
    injectionAlerts[field] = value;
  }

  const rawMedia = raw.media && typeof raw.media === 'object' ? raw.media : {};
  const overrides = {};
  if (raw.perToolOverrides !== undefined) {
    if (!raw.perToolOverrides || typeof raw.perToolOverrides !== 'object' || Array.isArray(raw.perToolOverrides)) {
      throw new TypeError('perToolOverrides must be an object.');
    }
    const entries = Object.entries(raw.perToolOverrides);
    if (entries.length > 128) {
      throw new RangeError('perToolOverrides cannot exceed 128 tools.');
    }
    for (const [k, v] of entries) {
      const toolKey = normalizeToolName(k);
      if (!v || typeof v !== 'object' || Array.isArray(v)) {
        throw new TypeError(`Invalid perToolOverrides entry for ${toolKey}.`);
      }
      const toolOverride = {};
      if (v.enabled !== undefined) toolOverride.enabled = Boolean(v.enabled);
      if (v.scope !== undefined) {
        if (!MODERATION_SCOPES.includes(v.scope)) throw new Error(`Invalid override scope for ${toolKey}: ${String(v.scope)}`);
        toolOverride.scope = v.scope;
      }
      if (v.mode !== undefined) {
        if (!MODERATION_MODES.includes(v.mode)) throw new Error(`Invalid override mode for ${toolKey}: ${String(v.mode)}`);
        toolOverride.mode = v.mode;
      }
      if (v.policyProfile !== undefined) {
        if (!MODERATION_POLICY_PROFILES.includes(v.policyProfile)) throw new Error(`Invalid override policyProfile for ${toolKey}: ${String(v.policyProfile)}`);
        toolOverride.policyProfile = v.policyProfile;
      }
      overrides[toolKey] = Object.freeze(toolOverride);
    }
  }

  const exemptTools = Array.isArray(raw.exemptTools)
    ? [...new Set(raw.exemptTools.map(normalizeToolName))].slice(0, 64)
    : [...DEFAULT_MODERATION_CONFIG.exemptTools];

  return Object.freeze({
    schemaVersion: MODERATION_CONFIG_VERSION,
    enabled: raw.enabled !== false,
    mode,
    policyProfile,
    injectionAlerts: Object.freeze(injectionAlerts),
    defaultScope,
    cloudOptIn: raw.cloudOptIn === true,
    cloudProvider,
    cloudEndpoint: normalizeEndpoint(raw.cloudEndpoint, { allowLoopbackHttp: false, allowPrivateNetwork: false, blockedOrigins }, 'cloudEndpoint'),
    cloudRegion: typeof raw.cloudRegion === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(raw.cloudRegion.trim()) ? raw.cloudRegion.trim() : null,
    localGuard,
    canary,
    thresholds: Object.freeze({ grayZoneLow, grayZoneHigh }),
    fallback: Object.freeze({
      chain: Object.freeze(fallbackChain),
      onAllFailedInput,
      onAllFailedOutput,
    }),
    streaming: Object.freeze({
      overlapChars: clampInt(rawStream.overlapChars, 32, 1024, DEFAULT_MODERATION_CONFIG.streaming.overlapChars),
      holdbackChars: clampInt(rawStream.holdbackChars, 32, 2048, DEFAULT_MODERATION_CONFIG.streaming.holdbackChars),
      maxPendingBytes: clampInt(rawStream.maxPendingBytes, 16_384, 2 * 1024 * 1024, DEFAULT_MODERATION_CONFIG.streaming.maxPendingBytes),
      redactPolicy,
    }),
    media: Object.freeze({
      scanWorkspacePaths: rawMedia.scanWorkspacePaths === true,
      maxImageBytes: clampInt(rawMedia.maxImageBytes, 1024, 32 * 1024 * 1024, DEFAULT_MODERATION_CONFIG.media.maxImageBytes),
      maxImagePixels: clampInt(rawMedia.maxImagePixels, 1024, 32_000_000, DEFAULT_MODERATION_CONFIG.media.maxImagePixels),
      maxAudioSec: clampInt(rawMedia.maxAudioSec, 5, 600, DEFAULT_MODERATION_CONFIG.media.maxAudioSec),
      maxVideoSec: clampInt(rawMedia.maxVideoSec, 5, 300, DEFAULT_MODERATION_CONFIG.media.maxVideoSec),
      maxVideoFrames: clampInt(rawMedia.maxVideoFrames, 1, 32, DEFAULT_MODERATION_CONFIG.media.maxVideoFrames),
    }),
    perToolOverrides: Object.freeze(overrides),
    exemptTools: Object.freeze(exemptTools),
  });
}
