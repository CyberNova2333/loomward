// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Standalone-friendly, zero-dependency protocol contract for out-of-process content moderation and anti-leak inspectors.

export const CONTENT_INSPECT_PROTOCOL_VERSION = 1;
export const CONTENT_INSPECT_STAGES = Object.freeze(['input', 'output']);
export const CONTENT_INSPECT_DECISIONS = Object.freeze(['allow', 'redact', 'escalate', 'block']);

const CATEGORY_RE = /^[a-z][a-z0-9._-]{0,47}$/;
const RULE_ID_RE = /^[A-Za-z0-9._:-]{1,64}$/;

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
  return Object.freeze({
    protocolVersion: CONTENT_INSPECT_PROTOCOL_VERSION,
    stage,
    requestId: typeof requestId === 'string' ? requestId.slice(0, 128) : '',
    toolName: toolName.slice(0, 128),
    ...(typeof providerName === 'string' && providerName ? { providerName: providerName.slice(0, 64) } : {}),
    payload: payload === undefined ? null : payload,
    metadata: metadata && typeof metadata === 'object' && !Array.isArray(metadata) ? { ...metadata } : {},
  });
}

export function validateContentInspectVerdict(verdict, { stage = 'input' } = {}) {
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
  const rawCategories = verdict.categories ?? [];
  if (!Array.isArray(rawCategories) || rawCategories.length > 32) {
    throw new Error('Verdict categories must be an array of up to 32 strings.');
  }
  const categories = [];
  for (const cat of rawCategories) {
    if (typeof cat !== 'string' || !CATEGORY_RE.test(cat)) {
      throw new Error(`Invalid verdict category: ${String(cat)}`);
    }
    categories.push(cat);
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
  const reason = typeof verdict.reason === 'string' ? verdict.reason.slice(0, 240) : '';
  return Object.freeze({
    protocolVersion: CONTENT_INSPECT_PROTOCOL_VERSION,
    decision: verdict.decision,
    categories: Object.freeze(categories),
    ...(score !== null ? { score } : {}),
    ...(ruleId !== null ? { ruleId } : {}),
    ...(reason ? { reason } : {}),
    ...(verdict.decision === 'redact' && Object.hasOwn(verdict, 'redactedPayload')
      ? { redactedPayload: verdict.redactedPayload }
      : {}),
  });
}
