// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Bounded in-memory correlation store linking input digests to output/stream stages without persistent plaintext retention.

const DEFAULT_MAX_ENTRIES = 256;
const DEFAULT_MAX_TEXT_CHARS = 16 * 1024;
const DEFAULT_TTL_MS = 15 * 60 * 1000;

export function createInvocationCorrelationStore({
  maxEntries = DEFAULT_MAX_ENTRIES,
  maxTextChars = DEFAULT_MAX_TEXT_CHARS,
  ttlMs = DEFAULT_TTL_MS,
  now = () => Date.now(),
} = {}) {
  const inputEntries = new Map();
  const handledStreams = new Map();

  function clampDigest(text) {
    if (typeof text !== 'string' || !text) return '';
    return text.length > maxTextChars ? `${text.slice(0, maxTextChars - 1)}…` : text;
  }

  function prune() {
    const cutoff = now() - ttlMs;
    for (const [key, item] of inputEntries.entries()) {
      if (item.createdAt < cutoff) {
        item.textDigest = '';
        inputEntries.delete(key);
      }
    }
    for (const [key, ts] of handledStreams.entries()) {
      if (ts < cutoff) handledStreams.delete(key);
    }
  }

  function evictOverflow(targetMap, limit) {
    while (targetMap.size >= limit) {
      const oldestKey = targetMap.keys().next().value;
      if (oldestKey === undefined) break;
      const oldVal = targetMap.get(oldestKey);
      if (oldVal && typeof oldVal === 'object') oldVal.textDigest = '';
      targetMap.delete(oldestKey);
    }
  }

  function recordInput(requestId, { toolName = '', providerName = '', textDigest = '', modalityCount = 0 } = {}) {
    if (typeof requestId !== 'string' || !requestId) return;
    prune();
    evictOverflow(inputEntries, maxEntries);
    inputEntries.set(requestId, {
      toolName: String(toolName),
      providerName: String(providerName),
      textDigest: clampDigest(textDigest),
      modalityCount: Number.isInteger(modalityCount) && modalityCount >= 0 ? modalityCount : 0,
      createdAt: now(),
    });
  }

  function consumeInput(requestId) {
    if (typeof requestId !== 'string' || !requestId) return null;
    prune();
    const item = inputEntries.get(requestId) || null;
    if (item) {
      inputEntries.delete(requestId);
    }
    return item;
  }

  function peekInput(requestId) {
    if (typeof requestId !== 'string' || !requestId) return null;
    prune();
    return inputEntries.get(requestId) || null;
  }

  function markStreamHandled(requestId) {
    if (typeof requestId !== 'string' || !requestId) return;
    evictOverflow(handledStreams, maxEntries);
    handledStreams.set(requestId, now());
  }

  function consumeStreamHandled(requestId) {
    if (typeof requestId !== 'string' || !requestId) return false;
    return handledStreams.delete(requestId);
  }

  function dispose() {
    for (const item of inputEntries.values()) {
      item.textDigest = '';
    }
    inputEntries.clear();
    handledStreams.clear();
  }

  return Object.freeze({
    recordInput,
    consumeInput,
    peekInput,
    markStreamHandled,
    consumeStreamHandled,
    prune,
    dispose,
    size: () => inputEntries.size,
  });
}
