// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Stateful streaming holdback and overlap window manager for tool:stream@1 incremental moderation.

function safeUtf16Boundary(text, desiredIndex) {
  if (desiredIndex <= 0) return 0;
  if (desiredIndex >= text.length) return text.length;
  const code = text.charCodeAt(desiredIndex - 1);
  // Avoid slicing between a UTF-16 high surrogate and low surrogate.
  if (code >= 0xd800 && code <= 0xdbff) {
    return desiredIndex - 1;
  }
  return desiredIndex;
}

function safeOverlapSlice(text, maxChars) {
  if (!text || maxChars <= 0) return '';
  if (text.length <= maxChars) return text;
  let start = text.length - maxChars;
  const code = text.charCodeAt(start);
  if (code >= 0xdc00 && code <= 0xdfff && start + 1 < text.length) {
    start += 1;
  }
  return text.slice(start);
}

function extractTextFromChunk(rawChunk) {
  if (typeof rawChunk === 'string') return rawChunk;
  if (!rawChunk || typeof rawChunk !== 'object') return '';
  if (typeof rawChunk.text === 'string' && (!rawChunk.type || rawChunk.type === 'text' || rawChunk.type === 'delta')) {
    return rawChunk.text;
  }
  return null;
}

function toBlockResult(verdict, fallbackRule = 'MODERATION-STREAM-BLOCK') {
  const isFailClosed = verdict?.failClosed === true || (Array.isArray(verdict?.categories) && verdict.categories.includes('moderation.fail_closed'));
  return {
    blocked: true,
    code: isFailClosed ? 'MODERATION_FAIL_CLOSED' : 'MODERATION_STREAM_BLOCKED',
    rule: verdict?.ruleId || fallbackRule,
    reason: verdict?.reason || 'Blocked by real-time streaming content moderation.',
    verdict,
  };
}

export class StreamInspectSession {
  #streamId;
  #requestId;
  #toolName;
  #providerName;
  #overlapChars;
  #holdbackChars;
  #maxPendingBytes;
  #redactPolicy;
  #pendingText = '';
  #overlapTail = '';
  #seq = 0;
  #aborted = false;
  #abortResult = null;
  #finalized = false;
  #sawChunks = false;

  constructor({
    streamId = '',
    requestId = '',
    toolName = '',
    providerName = '',
    overlapChars = 128,
    holdbackChars = 160,
    maxPendingBytes = 256 * 1024,
    redactPolicy = 'mask-continue',
  } = {}) {
    this.#streamId = String(streamId || '');
    this.#requestId = String(requestId || '');
    this.#toolName = String(toolName || '');
    this.#providerName = String(providerName || '');
    this.#overlapChars = Math.max(16, Math.trunc(Number(overlapChars) || 128));
    this.#holdbackChars = Math.max(0, Math.trunc(Number(holdbackChars) || 160));
    this.#maxPendingBytes = Math.max(4096, Math.trunc(Number(maxPendingBytes) || (256 * 1024)));
    this.#redactPolicy = redactPolicy === 'strict-block' ? 'strict-block' : 'mask-continue';
  }

  get isAborted() {
    return this.#aborted;
  }

  get isFinalized() {
    return this.#finalized;
  }

  abort(reason = 'Stream inspection cancelled.') {
    if (this.#aborted) return;
    this.#aborted = true;
    this.#pendingText = '';
    this.#overlapTail = '';
    this.#abortResult = {
      blocked: true,
      code: 'MODERATION_STREAM_BLOCKED',
      rule: 'MODERATION-STREAM-ABORTED',
      reason,
    };
  }

  #latchBlock(result) {
    this.#aborted = true;
    this.#pendingText = '';
    this.#overlapTail = '';
    this.#abortResult = result;
    return result;
  }

  async #inspectTextBuffer(stage, inspectFn) {
    if (!this.#pendingText.length) {
      return { blocked: false, releaseChunks: [], heldBack: false, verdict: null };
    }
    const windowText = this.#overlapTail + this.#pendingText;
    const seq = this.#seq++;
    const verdict = await inspectFn({
      stage,
      streamId: this.#streamId,
      requestId: this.#requestId,
      toolName: this.#toolName,
      providerName: this.#providerName,
      seq,
      payload: {
        text: windowText,
        pendingLength: this.#pendingText.length,
        overlapLength: this.#overlapTail.length,
      },
      modalityPackets: [{ modality: 'text', refKind: 'inline', inlineData: windowText }],
    });

    if (verdict.decision === 'block') {
      return this.#latchBlock(toBlockResult(verdict));
    }

    if (verdict.decision === 'redact') {
      if (this.#redactPolicy === 'strict-block') {
        return this.#latchBlock(toBlockResult({
          ...verdict,
          decision: 'block',
          reason: verdict.reason || 'Redacted stream segment rejected under strict-block policy.',
        }, 'MODERATION-STREAM-STRICT-REDACT'));
      }
      const rawRedacted = typeof verdict.redactedPayload === 'string'
        ? verdict.redactedPayload
        : '[REDACTED]';
      // Extract only the newly pending suffix if the overlap prefix remained verbatim; otherwise mask conservatively.
      let safeEmit = '[REDACTED]';
      if (this.#overlapTail.length === 0) {
        safeEmit = rawRedacted;
      } else if (rawRedacted.startsWith(this.#overlapTail)) {
        safeEmit = rawRedacted.slice(this.#overlapTail.length);
      }
      this.#overlapTail = safeOverlapSlice(rawRedacted, this.#overlapChars);
      this.#pendingText = '';
      return {
        blocked: false,
        heldBack: false,
        releaseChunks: safeEmit ? [{ type: 'text', text: safeEmit, redacted: true }] : [],
        verdict,
      };
    }

    if (stage === 'stream_end') {
      const flushed = this.#pendingText;
      this.#overlapTail = safeOverlapSlice(this.#overlapTail + flushed, this.#overlapChars);
      this.#pendingText = '';
      return {
        blocked: false,
        heldBack: false,
        releaseChunks: flushed ? [{ type: 'text', text: flushed }] : [],
        verdict,
      };
    }

    if (this.#pendingText.length <= this.#holdbackChars) {
      return {
        blocked: false,
        heldBack: true,
        releaseChunks: [],
        verdict,
      };
    }

    const cut = safeUtf16Boundary(this.#pendingText, this.#pendingText.length - this.#holdbackChars);
    if (cut <= 0) {
      return {
        blocked: false,
        heldBack: true,
        releaseChunks: [],
        verdict,
      };
    }
    const released = this.#pendingText.slice(0, cut);
    this.#pendingText = this.#pendingText.slice(cut);
    this.#overlapTail = safeOverlapSlice(this.#overlapTail + released, this.#overlapChars);
    return {
      blocked: false,
      heldBack: this.#pendingText.length > 0,
      releaseChunks: [{ type: 'text', text: released }],
      verdict,
    };
  }

  async pushChunk(rawChunk, inspectFn) {
    if (this.#aborted) return this.#abortResult;
    if (this.#finalized) {
      return { blocked: true, code: 'MODERATION_STREAM_BLOCKED', rule: 'MODERATION-STREAM-ENDED', reason: 'Stream already finalized.' };
    }
    this.#sawChunks = true;

    const text = extractTextFromChunk(rawChunk);
    if (text === null) {
      // Flush held-back text before handling a non-text chunk (image/audio/structured event) in strict sequence.
      const priorTextGate = await this.#inspectTextBuffer('stream_end', inspectFn);
      if (priorTextGate.blocked) return priorTextGate;

      const seq = this.#seq++;
      const obj = rawChunk && typeof rawChunk === 'object' ? rawChunk : { value: rawChunk };
      const packet = obj.type === 'image' || obj.type === 'audio' || obj.type === 'video' || obj.type === 'document'
        ? [{
            modality: obj.type,
            refKind: 'inline',
            ...(typeof obj.mimeType === 'string' ? { mimeType: obj.mimeType } : {}),
            ...(typeof obj.data === 'string' ? { inlineData: obj.data } : {}),
          }]
        : null;
      const chunkVerdict = await inspectFn({
        stage: 'stream_chunk',
        streamId: this.#streamId,
        requestId: this.#requestId,
        toolName: this.#toolName,
        providerName: this.#providerName,
        seq,
        payload: obj,
        modalityPackets: packet,
      });
      if (chunkVerdict.decision === 'block') {
        return this.#latchBlock(toBlockResult(chunkVerdict));
      }
      if (chunkVerdict.decision === 'redact') {
        if (this.#redactPolicy === 'strict-block') {
          return this.#latchBlock(toBlockResult({ ...chunkVerdict, decision: 'block' }, 'MODERATION-STREAM-STRICT-REDACT'));
        }
        return {
          blocked: false,
          heldBack: false,
          releaseChunks: [
            ...priorTextGate.releaseChunks,
            { type: 'text', text: typeof chunkVerdict.redactedPayload === 'string' ? chunkVerdict.redactedPayload : '[REDACTED]', redacted: true },
          ],
          verdict: chunkVerdict,
        };
      }
      return {
        blocked: false,
        heldBack: false,
        releaseChunks: [...priorTextGate.releaseChunks, obj],
        verdict: chunkVerdict,
      };
    }

    if (!text.length) {
      return {
        blocked: false,
        heldBack: this.#pendingText.length > 0,
        releaseChunks: [],
        verdict: null,
      };
    }

    const nextPending = this.#pendingText + text;
    if (Buffer.byteLength(nextPending, 'utf8') > this.#maxPendingBytes) {
      return this.#latchBlock({
        blocked: true,
        code: 'MODERATION_STREAM_BUFFER_OVERFLOW',
        rule: 'MODERATION-STREAM-MAX-PENDING',
        reason: `Stream holdback buffer exceeded ${this.#maxPendingBytes} byte limit.`,
      });
    }
    this.#pendingText = nextPending;
    return this.#inspectTextBuffer('stream_chunk', inspectFn);
  }

  async finalize(rawFinalResult, inspectFn) {
    if (this.#aborted) return this.#abortResult;
    if (this.#finalized) {
      return { blocked: false, releaseChunks: [], result: rawFinalResult, verdict: null };
    }
    this.#finalized = true;

    const tailGate = await this.#inspectTextBuffer('stream_end', inspectFn);
    if (tailGate.blocked) return tailGate;

    const finalPackets = this.#sawChunks
      ? extractNonTextResultPackets(rawFinalResult)
      : extractAllFinalResultPackets(rawFinalResult);
    let finalResult = rawFinalResult;
    let endVerdict = tailGate.verdict;
    if (finalPackets.length > 0) {
      endVerdict = await inspectFn({
        stage: 'stream_end',
        streamId: this.#streamId,
        requestId: this.#requestId,
        toolName: this.#toolName,
        providerName: this.#providerName,
        seq: this.#seq++,
        payload: rawFinalResult,
        modalityPackets: finalPackets,
      });
      if (endVerdict.decision === 'block') {
        return this.#latchBlock(toBlockResult(endVerdict));
      }
      if (endVerdict.decision === 'redact') {
        if (this.#redactPolicy === 'strict-block') {
          return this.#latchBlock(toBlockResult({ ...endVerdict, decision: 'block' }, 'MODERATION-STREAM-STRICT-REDACT'));
        }
        finalResult = applyInlineResultRedaction(rawFinalResult, endVerdict);
      }
    }

    this.#overlapTail = '';
    return {
      blocked: false,
      releaseChunks: tailGate.releaseChunks,
      result: finalResult,
      verdict: endVerdict,
    };
  }
}

export function extractNonTextResultPackets(result) {
  const content = Array.isArray(result?.content) ? result.content : [];
  const packets = [];
  content.forEach((item, sourceIndex) => {
    if (!item || typeof item !== 'object') return;
    if (item.type === 'image' || item.type === 'audio' || item.type === 'video' || item.type === 'document') {
      packets.push({
        modality: item.type,
        refKind: 'inline',
        sourceIndex,
        ...(typeof item.mimeType === 'string' ? { mimeType: item.mimeType } : {}),
        ...(typeof item.data === 'string' ? { inlineData: item.data } : {}),
      });
    }
  });
  return packets;
}

export function extractAllFinalResultPackets(result) {
  const packets = extractNonTextResultPackets(result);
  const textParts = [];
  if (Array.isArray(result?.content)) {
    for (const item of result.content) {
      if (item && typeof item === 'object' && item.type === 'text' && typeof item.text === 'string') {
        textParts.push(item.text);
      }
    }
  }
  if (result?.structuredContent !== undefined) {
    try {
      textParts.push(JSON.stringify(result.structuredContent));
    } catch {}
  }
  const combined = textParts.join('\n').trim();
  if (combined) {
    packets.unshift({ modality: 'text', refKind: 'inline', inlineData: combined });
  }
  return packets.slice(0, 64);
}

export function applyInlineResultRedaction(result, verdict) {
  if (!result || typeof result !== 'object') return result;
  if (Array.isArray(verdict?.redactions) && Array.isArray(result.content)) {
    const nextContent = result.content.map(item => (item && typeof item === 'object' ? { ...item } : item));
    for (const entry of verdict.redactions) {
      if (entry.index >= 0 && entry.index < nextContent.length) {
        nextContent[entry.index] = { type: 'text', text: entry.replacementText };
      }
    }
    return { ...result, content: nextContent };
  }
  const replacement = typeof verdict?.redactedPayload === 'string'
    ? verdict.redactedPayload
    : JSON.stringify(verdict?.redactedPayload ?? '[REDACTED]');
  return { ...result, content: [{ type: 'text', text: replacement }] };
}
