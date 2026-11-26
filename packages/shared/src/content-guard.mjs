// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Standalone-friendly, zero-dependency protocol contract for out-of-process content moderation and anti-leak inspectors.

export const CONTENT_INSPECT_PROTOCOL_VERSION = 1;
export const CONTENT_INSPECT_V2_PROTOCOL_VERSION = 2;
export const CONTENT_INSPECT_SUPPORTED_VERSIONS = Object.freeze([
  CONTENT_INSPECT_PROTOCOL_VERSION,
  CONTENT_INSPECT_V2_PROTOCOL_VERSION,
]);
export const CONTENT_INSPECT_STAGES = Object.freeze(['input', 'output']);
export const CONTENT_INSPECT_EXTENDED_STAGES = Object.freeze([
  'input',
  'output',
  'combined',
  'stream_start',
  'stream_chunk',
  'stream_end',
]);
export const CONTENT_INSPECT_DECISIONS = Object.freeze(['allow', 'redact', 'escalate', 'block']);
export const CONTENT_INSPECT_MODALITIES = Object.freeze(['text', 'image', 'audio', 'video', 'document']);
export const CONTENT_INSPECT_REF_KINDS = Object.freeze(['inline', 'sandbox-fd', 'workspace-ref']);

const CATEGORY_RE = /^[a-z][a-z0-9._-]{0,47}$/;
const RULE_ID_RE = /^[A-Za-z0-9._:-]{1,64}$/;
const UNSAFE_REASON_RE = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u200e\u200f\u061c\u202a-\u202e\u2066-\u2069]/g;

function clampReason(value, maxLen = 240) {
  if (typeof value !== 'string') return '';
  const cleaned = value.replace(UNSAFE_REASON_RE, '').trim();
  const points = Array.from(cleaned);
  return points.length > maxLen ? `${points.slice(0, maxLen - 1).join('')}…` : cleaned;
}

export class ToolBlockedError extends Error {
  constructor(message, { code = 'TOOL_HOOK_BLOCKED', rule = null } = {}) {
    super(clampReason(String(message || 'Tool call blocked by local safety hook.'), 240) || 'Tool call blocked by local safety hook.');
    this.name = 'ToolBlockedError';
    this.code = typeof code === 'string' && /^[A-Z0-9_]{1,48}$/.test(code) ? code : 'TOOL_HOOK_BLOCKED';
    this.rule = typeof rule === 'string' && RULE_ID_RE.test(rule) ? rule : null;
  }
}

const MIME_TYPE_RE = /^[a-z0-9][a-z0-9.+-]{0,31}\/[a-z0-9][a-z0-9.+-]{0,63}$/i;
const SHA256_HEX_RE = /^[a-f0-9]{64}$/i;
const INLINE_SAFE_LIMIT_BYTES = 24 * 1024 * 1024;

function normalizeModalityPacket(raw, idx) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new TypeError(`Modality packet at index ${idx} must be an object.`);
  }
  const modality = raw.modality;
  if (!CONTENT_INSPECT_MODALITIES.includes(modality)) {
    throw new TypeError(`Invalid modality at index ${idx}: ${String(modality)}`);
  }
  const refKind = raw.refKind ?? 'inline';
  if (!CONTENT_INSPECT_REF_KINDS.includes(refKind)) {
    throw new TypeError(`Invalid modality refKind at index ${idx}: ${String(refKind)}`);
  }
  const mimeType = typeof raw.mimeType === 'string' && MIME_TYPE_RE.test(raw.mimeType.trim())
    ? raw.mimeType.trim().toLowerCase()
    : null;
  const sha256 = typeof raw.sha256 === 'string' && SHA256_HEX_RE.test(raw.sha256)
    ? raw.sha256.toLowerCase()
    : null;
  const byteLength = Number.isInteger(raw.byteLength) && raw.byteLength >= 0 && raw.byteLength <= INLINE_SAFE_LIMIT_BYTES
    ? raw.byteLength
    : null;
  const sourceIndex = Number.isInteger(raw.sourceIndex) && raw.sourceIndex >= 0 ? raw.sourceIndex : null;
  return Object.freeze({
    modality,
    refKind,
    ...(mimeType ? { mimeType } : {}),
    ...(sha256 ? { sha256 } : {}),
    ...(byteLength !== null ? { byteLength } : {}),
    ...(sourceIndex !== null ? { sourceIndex } : {}),
    ...(typeof raw.inlineData === 'string' && refKind === 'inline' ? { inlineData: raw.inlineData } : {}),
  });
}

export function normalizeModalityPackets(rawList) {
  if (rawList === undefined || rawList === null) return Object.freeze([]);
  if (!Array.isArray(rawList) || rawList.length > 64) {
    throw new TypeError('modalityPackets must be an array of at most 64 items.');
  }
  return Object.freeze(rawList.map((item, idx) => normalizeModalityPacket(item, idx)));
}

export function buildContentInspectRequest({
  protocolVersion = CONTENT_INSPECT_PROTOCOL_VERSION,
  stage,
  requestId,
  toolName,
  providerName = null,
  payload,
  modalityPackets = null,
  streamId = null,
  seq = null,
  metadata = {},
} = {}) {
  if (!CONTENT_INSPECT_SUPPORTED_VERSIONS.includes(protocolVersion)) {
    throw new TypeError(`Unsupported content inspection protocolVersion: ${String(protocolVersion)}`);
  }
  const allowedStages = protocolVersion === CONTENT_INSPECT_PROTOCOL_VERSION
    ? CONTENT_INSPECT_STAGES
    : CONTENT_INSPECT_EXTENDED_STAGES;
  if (!allowedStages.includes(stage)) {
    throw new TypeError(`Invalid content inspection stage: ${String(stage)}`);
  }
  if (typeof toolName !== 'string' || !toolName.length) {
    throw new TypeError('Content inspection requires a non-empty toolName.');
  }
  if (seq !== null && (!Number.isInteger(seq) || seq < 0)) {
    throw new TypeError(`Invalid content inspection stream sequence: ${String(seq)}`);
  }
  const normalizedPackets = modalityPackets !== null ? normalizeModalityPackets(modalityPackets) : null;
  const safeMeta = metadata && typeof metadata === 'object' && !Array.isArray(metadata)
    ? Object.freeze({ ...metadata })
    : Object.freeze({});
  return Object.freeze({
    protocolVersion,
    stage,
    requestId: typeof requestId === 'string' ? requestId.slice(0, 128) : '',
    toolName: toolName.slice(0, 128),
    ...(typeof providerName === 'string' && providerName ? { providerName: providerName.slice(0, 64) } : {}),
    ...(typeof streamId === 'string' && streamId ? { streamId: streamId.slice(0, 128) } : {}),
    ...(seq !== null ? { seq } : {}),
    ...(normalizedPackets !== null ? { modalityPackets: normalizedPackets } : {}),
    payload: payload === undefined ? null : payload,
    metadata: safeMeta,
  });
}

function normalizeRedactionEntries(rawList) {
  if (!Array.isArray(rawList) || rawList.length === 0 || rawList.length > 64) {
    throw new Error('Verdict redactions must be a non-empty array of up to 64 entries.');
  }
  return Object.freeze(rawList.map((raw, i) => {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      throw new Error(`Invalid verdict redaction entry at index ${i}.`);
    }
    const index = raw.index;
    const modality = raw.modality;
    const rawText = raw.replacementText;
    const rawRuleId = raw.ruleId;
    if (!Number.isInteger(index) || index < 0 || index >= 64) {
      throw new Error(`Invalid redaction target index: ${String(index)}`);
    }
    if (modality !== undefined && !CONTENT_INSPECT_MODALITIES.includes(modality)) {
      throw new Error(`Invalid redaction modality: ${String(modality)}`);
    }
    if (rawRuleId !== undefined && rawRuleId !== null && (typeof rawRuleId !== 'string' || !RULE_ID_RE.test(rawRuleId))) {
      throw new Error(`Invalid redaction ruleId: ${String(rawRuleId)}`);
    }
    const replacementText = clampReason(rawText ?? '[REDACTED]', 1024) || '[REDACTED]';
    return Object.freeze({
      index,
      ...(modality ? { modality } : {}),
      ...(rawRuleId ? { ruleId: rawRuleId } : {}),
      replacementText,
    });
  }));
}

function normalizeInducementTelemetry(raw) {
  if (raw === undefined || raw === null) return null;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('Verdict inducement telemetry must be an object.');
  }
  const tested = Boolean(raw.tested);
  const canaryInduced = Boolean(raw.canaryInduced);
  const canaryModel = typeof raw.canaryModel === 'string' ? clampReason(raw.canaryModel, 64) : '';
  const validateScore = (v, label) => {
    if (v === undefined || v === null) return null;
    if (typeof v !== 'number' || !Number.isFinite(v) || v < 0 || v > 1) {
      throw new Error(`Inducement ${label} must be a finite number in [0, 1].`);
    }
    return v;
  };
  const guardPrimaryScore = validateScore(raw.guardPrimaryScore, 'guardPrimaryScore');
  const canaryOutputRiskScore = validateScore(raw.canaryOutputRiskScore, 'canaryOutputRiskScore');
  return Object.freeze({
    tested,
    canaryInduced,
    ...(canaryModel ? { canaryModel } : {}),
    ...(guardPrimaryScore !== null ? { guardPrimaryScore } : {}),
    ...(canaryOutputRiskScore !== null ? { canaryOutputRiskScore } : {}),
  });
}

export function validateContentInspectVerdict(verdict, { stage = 'input', expectedProtocolVersion = null } = {}) {
  if (!CONTENT_INSPECT_EXTENDED_STAGES.includes(stage)) {
    throw new TypeError(`Invalid content inspection stage: ${String(stage)}`);
  }
  if (!verdict || typeof verdict !== 'object' || Array.isArray(verdict)) {
    throw new Error('Content inspection verdict must be an object.');
  }
  const protocolVersion = verdict.protocolVersion;
  const decision = verdict.decision;
  const hasRedactedPayload = Object.hasOwn(verdict, 'redactedPayload');
  const redactedPayload = hasRedactedPayload ? verdict.redactedPayload : undefined;
  const hasRedactions = Object.hasOwn(verdict, 'redactions') && verdict.redactions !== undefined && verdict.redactions !== null;
  const rawRedactions = hasRedactions ? verdict.redactions : null;
  const rawCategories = verdict.categories ?? [];
  const rawScore = verdict.score;
  const rawRuleId = verdict.ruleId;
  const rawReason = verdict.reason;
  const rawRequestId = verdict.requestId;
  const rawFailClosed = verdict.failClosed;
  const rawLatencyMs = verdict.latencyMs;
  const rawInducement = verdict.inducement;

  if (!CONTENT_INSPECT_SUPPORTED_VERSIONS.includes(protocolVersion)) {
    throw new Error(`Unsupported content inspection verdict protocolVersion: ${String(protocolVersion)}`);
  }
  if (expectedProtocolVersion !== null && protocolVersion !== expectedProtocolVersion) {
    throw new Error(`Mismatched content inspection verdict protocolVersion: ${String(protocolVersion)}`);
  }
  if (protocolVersion === CONTENT_INSPECT_PROTOCOL_VERSION && !CONTENT_INSPECT_STAGES.includes(stage)) {
    throw new TypeError(`Invalid content inspection stage for v1 verdict: ${String(stage)}`);
  }
  if (!CONTENT_INSPECT_DECISIONS.includes(decision)) {
    throw new Error(`Invalid content inspection decision: ${String(decision)}`);
  }
  if (decision === 'redact' && (stage === 'input' || stage === 'stream_start')) {
    throw new Error('Input stage content inspection cannot silently rewrite arguments with redact; use block or escalate.');
  }
  if (decision === 'escalate' && !['input', 'stream_start'].includes(stage)) {
    throw new Error('Output stage content inspection cannot escalate post-execution; use allow, redact, or block.');
  }
  const redactions = hasRedactions && protocolVersion === CONTENT_INSPECT_V2_PROTOCOL_VERSION
    ? normalizeRedactionEntries(rawRedactions)
    : null;
  if (decision === 'redact' && (!hasRedactedPayload || redactedPayload === undefined) && !redactions) {
    throw new Error('Redaction verdict requires an explicit redactedPayload.');
  }
  if (!Array.isArray(rawCategories) || rawCategories.length > 32) {
    throw new Error('Verdict categories must be an array of up to 32 strings.');
  }
  const categories = [];
  const seenCategories = new Set();
  for (const cat of rawCategories) {
    if (typeof cat !== 'string' || !CATEGORY_RE.test(cat)) {
      throw new Error(`Invalid verdict category: ${String(cat)}`);
    }
    if (!seenCategories.has(cat)) {
      seenCategories.add(cat);
      categories.push(cat);
    }
  }
  let score = null;
  if (rawScore !== undefined && rawScore !== null) {
    if (typeof rawScore !== 'number' || !Number.isFinite(rawScore) || rawScore < 0 || rawScore > 1) {
      throw new Error('Verdict score must be a finite number in [0, 1].');
    }
    score = rawScore;
  }
  let ruleId = null;
  if (rawRuleId !== undefined && rawRuleId !== null) {
    if (typeof rawRuleId !== 'string' || !RULE_ID_RE.test(rawRuleId)) {
      throw new Error(`Invalid verdict ruleId: ${String(rawRuleId)}`);
    }
    ruleId = rawRuleId;
  }
  const reason = clampReason(rawReason, 240);
  const requestId = typeof rawRequestId === 'string' && rawRequestId ? rawRequestId.slice(0, 128) : null;
  const failClosed = typeof rawFailClosed === 'boolean' ? rawFailClosed : null;
  const latencyMs = typeof rawLatencyMs === 'number' && Number.isFinite(rawLatencyMs) && rawLatencyMs >= 0
    ? Math.trunc(rawLatencyMs)
    : null;
  const inducement = protocolVersion === CONTENT_INSPECT_V2_PROTOCOL_VERSION
    ? normalizeInducementTelemetry(rawInducement)
    : null;

  return Object.freeze({
    protocolVersion,
    decision,
    categories: Object.freeze(categories),
    ...(score !== null ? { score } : {}),
    ...(ruleId !== null ? { ruleId } : {}),
    ...(reason ? { reason } : {}),
    ...(requestId !== null ? { requestId } : {}),
    ...(failClosed !== null ? { failClosed } : {}),
    ...(latencyMs !== null ? { latencyMs } : {}),
    ...(inducement !== null ? { inducement } : {}),
    ...(decision === 'redact' && hasRedactedPayload ? { redactedPayload } : {}),
    ...(decision === 'redact' && redactions ? { redactions } : {}),
  });
}

/**
 * Safely apply an output-stage ContentInspect redaction verdict to an MCP tool result,
 * redacting both `content` (supporting whole-payload or per-item multimodal `redactions[]`)
 * and `structuredContent` so unredacted text or media never leaks in parallel fields.
 */
export function applyOutputRedaction(rpcReply, verdict, { stage = 'output' } = {}) {
  const checked = validateContentInspectVerdict(verdict, { stage });
  if (checked.decision !== 'redact') return rpcReply;
  if (!rpcReply || typeof rpcReply !== 'object' || !rpcReply.result || typeof rpcReply.result !== 'object') {
    return rpcReply;
  }
  if (Array.isArray(checked.redactions) && checked.redactions.length > 0 && Array.isArray(rpcReply.result.content)) {
    const nextContent = rpcReply.result.content.map(item => (item && typeof item === 'object' ? { ...item } : item));
    const redactedIndices = [];
    for (const entry of checked.redactions) {
      if (entry.index < nextContent.length) {
        nextContent[entry.index] = { type: 'text', text: entry.replacementText };
        redactedIndices.push(entry.index);
      }
    }
    const nextResult = {
      ...rpcReply.result,
      content: nextContent,
    };
    if (Object.hasOwn(nextResult, 'structuredContent')) {
      nextResult.structuredContent = {
        redacted: true,
        partiallyRedacted: true,
        redactedIndices,
        ...(checked.ruleId ? { ruleId: checked.ruleId } : {}),
      };
    }
    return {
      ...rpcReply,
      result: nextResult,
    };
  }
  const text = typeof checked.redactedPayload === 'string'
    ? checked.redactedPayload
    : JSON.stringify(checked.redactedPayload);
  const nextResult = {
    ...rpcReply.result,
    content: [{ type: 'text', text }],
  };
  if (Object.hasOwn(nextResult, 'structuredContent')) {
    nextResult.structuredContent = {
      redacted: true,
      ...(checked.ruleId ? { ruleId: checked.ruleId } : {}),
      text,
    };
  }
  return {
    ...rpcReply,
    result: nextResult,
  };
}
