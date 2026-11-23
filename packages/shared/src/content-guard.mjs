// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Standalone-friendly, zero-dependency protocol contract for out-of-process content moderation and anti-leak inspectors.

export const CONTENT_INSPECT_PROTOCOL_VERSION = 1;
export const CONTENT_INSPECT_STAGES = Object.freeze(['input', 'output']);
export const CONTENT_INSPECT_DECISIONS = Object.freeze(['allow', 'redact', 'escalate', 'block']);

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

export function buildContentInspectRequest({
  stage,
  requestId,
  toolName,
  providerName = null,
  payload,
  metadata = {},
} = {}) {
  if (!CONTENT_INSPECT_STAGES.includes(stage)) {
    throw new TypeError(`Invalid content inspection stage: ${String(stage)}`);
  }
  if (typeof toolName !== 'string' || !toolName.length) {
    throw new TypeError('Content inspection requires a non-empty toolName.');
  }
  const safeMeta = metadata && typeof metadata === 'object' && !Array.isArray(metadata)
    ? Object.freeze({ ...metadata })
    : Object.freeze({});
  return Object.freeze({
    protocolVersion: CONTENT_INSPECT_PROTOCOL_VERSION,
    stage,
    requestId: typeof requestId === 'string' ? requestId.slice(0, 128) : '',
    toolName: toolName.slice(0, 128),
    ...(typeof providerName === 'string' && providerName ? { providerName: providerName.slice(0, 64) } : {}),
    payload: payload === undefined ? null : payload,
    metadata: safeMeta,
  });
}

export function validateContentInspectVerdict(verdict, { stage = 'input' } = {}) {
  if (!CONTENT_INSPECT_STAGES.includes(stage)) {
    throw new TypeError(`Invalid content inspection stage: ${String(stage)}`);
  }
  if (!verdict || typeof verdict !== 'object' || Array.isArray(verdict)) {
    throw new Error('Content inspection verdict must be an object.');
  }
  if (verdict.protocolVersion !== CONTENT_INSPECT_PROTOCOL_VERSION) {
    throw new Error(`Unsupported content inspection verdict protocolVersion: ${String(verdict.protocolVersion)}`);
  }
  if (!CONTENT_INSPECT_DECISIONS.includes(verdict.decision)) {
    throw new Error(`Invalid content inspection decision: ${String(verdict.decision)}`);
  }
  if (verdict.decision === 'redact' && stage === 'input') {
    throw new Error('Input stage content inspection cannot silently rewrite arguments with redact; use block or escalate.');
  }
  if (verdict.decision === 'escalate' && stage === 'output') {
    throw new Error('Output stage content inspection cannot escalate post-execution; use allow, redact, or block.');
  }
  if (verdict.decision === 'redact' && (!Object.hasOwn(verdict, 'redactedPayload') || verdict.redactedPayload === undefined)) {
    throw new Error('Redaction verdict requires an explicit redactedPayload.');
  }
  const rawCategories = verdict.categories ?? [];
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
  if (verdict.score !== undefined && verdict.score !== null) {
    if (typeof verdict.score !== 'number' || !Number.isFinite(verdict.score) || verdict.score < 0 || verdict.score > 1) {
      throw new Error('Verdict score must be a finite number in [0, 1].');
    }
    score = verdict.score;
  }
  let ruleId = null;
  if (verdict.ruleId !== undefined && verdict.ruleId !== null) {
    if (typeof verdict.ruleId !== 'string' || !RULE_ID_RE.test(verdict.ruleId)) {
      throw new Error(`Invalid verdict ruleId: ${String(verdict.ruleId)}`);
    }
    ruleId = verdict.ruleId;
  }
  const reason = clampReason(verdict.reason, 240);
  const requestId = typeof verdict.requestId === 'string' && verdict.requestId ? verdict.requestId.slice(0, 128) : null;
  const failClosed = typeof verdict.failClosed === 'boolean' ? verdict.failClosed : null;
  const latencyMs = typeof verdict.latencyMs === 'number' && Number.isFinite(verdict.latencyMs) && verdict.latencyMs >= 0
    ? Math.trunc(verdict.latencyMs)
    : null;

  return Object.freeze({
    protocolVersion: CONTENT_INSPECT_PROTOCOL_VERSION,
    decision: verdict.decision,
    categories: Object.freeze(categories),
    ...(score !== null ? { score } : {}),
    ...(ruleId !== null ? { ruleId } : {}),
    ...(reason ? { reason } : {}),
    ...(requestId !== null ? { requestId } : {}),
    ...(failClosed !== null ? { failClosed } : {}),
    ...(latencyMs !== null ? { latencyMs } : {}),
    ...(verdict.decision === 'redact' ? { redactedPayload: verdict.redactedPayload } : {}),
  });
}

/**
 * Safely apply an output-stage ContentInspect redaction verdict to an MCP tool result,
 * redacting both `content` and `structuredContent` so unredacted text never leaks in parallel fields.
 */
export function applyOutputRedaction(rpcReply, verdict) {
  const checked = validateContentInspectVerdict(verdict, { stage: 'output' });
  if (checked.decision !== 'redact') return rpcReply;
  if (!rpcReply || typeof rpcReply !== 'object' || !rpcReply.result || typeof rpcReply.result !== 'object') {
    return rpcReply;
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
