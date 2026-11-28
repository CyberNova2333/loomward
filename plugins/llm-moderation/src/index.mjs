// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Out-of-process Cordis 4 extension plugin entry for multimodal LLM content moderation and native holdback streaming.
import {
  CONTENT_INSPECT_V2_PROTOCOL_VERSION,
  PLUGIN_SECRETS_SLOT,
  applyOutputRedaction,
  buildContentInspectRequest,
  validateConsolePanelDecl,
} from '@loomward/shared';
import { contract } from './contract.mjs';
import {
  loadEffectiveModerationConfig,
  resolveToolModerationPolicy,
} from './config-store.mjs';
import { createInvocationCorrelationStore } from './correlation.mjs';
import {
  StreamInspectSession,
  applyInlineResultRedaction,
  extractNonTextResultPackets,
} from './stream-session.mjs';
import { createModerationEngineClient } from './service-manager.mjs';

export { contract } from './contract.mjs';
export {
  moderationConfigFilePath,
  loadEffectiveModerationConfig,
  resolveToolModerationPolicy,
} from './config-store.mjs';
export { createInvocationCorrelationStore } from './correlation.mjs';
export { StreamInspectSession } from './stream-session.mjs';
export { createModerationEngineClient } from './service-manager.mjs';

export const name = 'plugin-llm-moderation';

const MAX_RECENT_EVENTS = 12;
const MAX_CORRELATION_DIGEST_CHARS = 8 * 1024;
const WORKSPACE_MEDIA_PATH_RE = /\.(?:png|jpe?g|webp|gif|svg|wav|mp3|ogg|flac|mp4|webm|pdf)$/i;

const CANARY_INJECTION_RULES = new Set([
  'CANARY-DELIMITER-BREAK', 'CANARY-FAKE-TOOL-CALL', 'CANARY-COMPLIED-OVERRIDE', 'CANARY-UNSAFE-COMPLIANCE',
]);

function injectionCategory(verdict) {
  if (verdict.ruleId === 'MOD-RULE-PROMPT-INJECTION') return 'prompt.injection';
  const category = verdict.categories?.find(value => value === 'prompt.injection' || value === 'prompt.indirect_injection');
  if (category) return category;
  if (verdict.inducement?.canaryInduced && CANARY_INJECTION_RULES.has(verdict.ruleId)) return 'prompt.inducement';
  return null;
}

function summarizeTextFromValue(value, limit = MAX_CORRELATION_DIGEST_CHARS) {
  if (typeof value === 'string') return value.slice(0, limit);
  if (value === null || value === undefined) return '';
  try {
    const json = JSON.stringify(value);
    return typeof json === 'string' ? json.slice(0, limit) : '';
  } catch {
    return '[unserializable]';
  }
}

function collectInputModalityPackets(args, { scanWorkspacePaths = false } = {}) {
  const packets = [];
  const pushInline = (modality, text, extra = {}) => {
    if (packets.length >= 64) return;
    packets.push({
      modality,
      refKind: 'inline',
      ...(typeof text === 'string' ? { inlineData: text } : {}),
      ...extra,
    });
  };
  const visit = (val, depth = 0) => {
    if (depth > 6 || packets.length >= 64 || val === null || val === undefined) return;
    if (typeof val === 'string') {
      if (scanWorkspacePaths && WORKSPACE_MEDIA_PATH_RE.test(val.trim()) && val.trim().length <= 512) {
        packets.push({
          modality: inferModalityFromPath(val.trim()),
          refKind: 'workspace-ref',
          inlineData: undefined,
          mimeType: inferMimeFromPath(val.trim()),
          workspacePath: val.trim(),
        });
      }
      return;
    }
    if (Array.isArray(val)) {
      val.forEach(item => visit(item, depth + 1));
      return;
    }
    if (typeof val === 'object') {
      if (val.type === 'image' || val.type === 'audio' || val.type === 'video' || val.type === 'document') {
        pushInline(val.type, typeof val.data === 'string' ? val.data : '', {
          ...(typeof val.mimeType === 'string' ? { mimeType: val.mimeType } : {}),
        });
        return;
      }
      if (typeof val.path === 'string' && scanWorkspacePaths && WORKSPACE_MEDIA_PATH_RE.test(val.path.trim())) {
        packets.push({
          modality: inferModalityFromPath(val.path.trim()),
          refKind: 'workspace-ref',
          mimeType: inferMimeFromPath(val.path.trim()),
        });
      }
      for (const v of Object.values(val)) {
        visit(v, depth + 1);
      }
    }
  };
  visit(args);
  const textDigest = summarizeTextFromValue(args);
  if (textDigest) {
    packets.unshift({ modality: 'text', refKind: 'inline', inlineData: textDigest });
  }
  return packets.slice(0, 64);
}

function collectOutputModalityPackets(result) {
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
    textParts.push(summarizeTextFromValue(result.structuredContent));
  }
  const combinedText = textParts.join('\n').trim();
  if (combinedText) {
    packets.unshift({ modality: 'text', refKind: 'inline', inlineData: combinedText });
  }
  return packets.slice(0, 64);
}

function inferModalityFromPath(filePath) {
  const lower = filePath.toLowerCase();
  if (/\.(png|jpe?g|webp|gif|svg)$/.test(lower)) return 'image';
  if (/\.(wav|mp3|ogg|flac)$/.test(lower)) return 'audio';
  if (/\.(mp4|webm)$/.test(lower)) return 'video';
  return 'document';
}

function inferMimeFromPath(filePath) {
  const lower = filePath.toLowerCase();
  if (lower.endsWith('.png')) return 'image/png';
  if (lower.endsWith('.jpg') || lower.endsWith('.jpeg')) return 'image/jpeg';
  if (lower.endsWith('.webp')) return 'image/webp';
  if (lower.endsWith('.gif')) return 'image/gif';
  if (lower.endsWith('.svg')) return 'image/svg+xml';
  if (lower.endsWith('.wav')) return 'audio/wav';
  if (lower.endsWith('.mp3')) return 'audio/mpeg';
  if (lower.endsWith('.ogg')) return 'audio/ogg';
  if (lower.endsWith('.flac')) return 'audio/flac';
  if (lower.endsWith('.mp4')) return 'video/mp4';
  if (lower.endsWith('.webm')) return 'video/webm';
  return 'application/pdf';
}

export async function apply(ctx, cfg = {}) {
  const invokeSlot = ctx.get('tool:invoke@1');
  const streamSlot = ctx.get('tool:stream@1');
  const panelSlot = ctx.get('console:panel@1');
  const secretsFacade = contract.consumes.includes(PLUGIN_SECRETS_SLOT) ? ctx.get(PLUGIN_SECRETS_SLOT) : null;

  const client = cfg.client || createModerationEngineClient({
    baseUrl: cfg.engineBaseUrl || null,
    pythonPath: cfg.pythonPath,
    spawnService: cfg.spawnService ?? !cfg.engineBaseUrl,
    timeoutMs: cfg.timeoutMs,
    serviceToken: cfg.serviceToken || null,
    secretsFacade,
    workspaceRoots: cfg.workspaceRoots || [],
    inspectTransport: cfg.inspectTransport || null,
  });

  const correlation = createInvocationCorrelationStore();
  const activeStreams = new Map();
  const stats = {
    inspectedInput: 0,
    inspectedOutput: 0,
    inspectedCombined: 0,
    inspectedStreamChunks: 0,
    blocked: 0,
    redacted: 0,
    escalated: 0,
    failClosed: 0,
    canaryTested: 0,
    canaryInduced: 0,
    fallbackUsed: 0,
    recentEvents: [],
  };

  function getConfig() {
    return loadEffectiveModerationConfig({
      stateDir: cfg.stateDir || null,
      readStoredConfig: cfg.readStoredConfig,
      inlineConfig: cfg.moderation || cfg.inlineConfig || null,
      blockedOrigins: cfg.blockedOrigins || [],
      preferInlineConfig: cfg.preferInlineConfig === true,
    });
  }

  function recordVerdict(stage, toolName, verdict, telemetry) {
    if (stage === 'input') stats.inspectedInput += 1;
    else if (stage === 'combined') stats.inspectedCombined += 1;
    else if (stage === 'stream_chunk' || stage === 'stream_end') stats.inspectedStreamChunks += 1;
    else stats.inspectedOutput += 1;

    if (verdict?.inducement?.tested) stats.canaryTested += 1;
    if (verdict?.inducement?.canaryInduced) stats.canaryInduced += 1;
    if (telemetry?.fallbackUsed) stats.fallbackUsed += 1;
    if (verdict?.failClosed) stats.failClosed += 1;
    if (verdict?.decision === 'block') stats.blocked += 1;
    else if (verdict?.decision === 'redact') stats.redacted += 1;
    else if (verdict?.decision === 'escalate') stats.escalated += 1;

    if (verdict && verdict.decision !== 'allow') {
      stats.recentEvents.unshift({
        time: new Date().toISOString().slice(11, 19),
        tool: String(toolName || '').slice(0, 48),
        stage,
        decision: verdict.decision,
        ruleId: verdict.ruleId || (verdict.inducement?.canaryInduced ? 'CANARY-INDUCED' : 'MODERATION'),
        engine: String(telemetry?.engineUsed || 'engine').slice(0, 32),
      });
      if (stats.recentEvents.length > MAX_RECENT_EVENTS) {
        stats.recentEvents.length = MAX_RECENT_EVENTS;
      }
    }
  }

  async function inspectWithConfig(requestObj, config, { signal, clientRef, includesInput = false } = {}) {
    const out = await client.inspect(requestObj, config, { signal });
    // Support mock transport returning direct verdict or { verdict, telemetry }
    const verdict = out?.verdict ?? out;
    const telemetry = out?.telemetry ?? {};
    recordVerdict(requestObj.stage, requestObj.toolName, verdict, telemetry);
    const rule = injectionCategory(verdict);
    if (rule && !verdict.failClosed && cfg.recordInjection) {
      const { stage, requestId, toolName } = requestObj;
      const stream = stage === 'stream_chunk' || stage === 'stream_end';
      // The engine inspects output packets first. Its fallback payload can include the correlated input.
      const hasOutputText = requestObj.modalityPackets?.some(p => p.modality === 'text' && p.inlineData?.trim());
      const mixed = includesInput && !hasOutputText;
      let action = verdict.decision;
      if (action === 'redact' && (stage === 'input' || (stream && config.streaming.redactPolicy === 'strict-block'))) action = 'block';
      if (action === 'escalate' && stage !== 'input') action = stream ? 'allow' : 'block';
      cfg.recordInjection({
        clientRef, requestId, toolName, rule, action, stage,
        source: stage === 'input' ? 'input' : mixed ? 'combined' : 'output',
      }, config.injectionAlerts);
    }
    return verdict;
  }

  if (cfg.eagerStart === true) {
    await client.ensureRunning();
  }

  if (invokeSlot) {
    // Must execute AFTER offline R1-R7 anti-leak guardrail (order: 10).
    invokeSlot.hook('before', async input => {
      const config = getConfig();
      const policy = resolveToolModerationPolicy(config, input.toolName);
      if (!policy.enabled || policy.exempt) {
        return input;
      }
      const scopedConfig = {
        ...config,
        mode: policy.mode,
        policyProfile: policy.policyProfile,
      };
      const args = input.body?.params?.arguments ?? {};
      const packets = collectInputModalityPackets(args, {
        scanWorkspacePaths: scopedConfig.media.scanWorkspacePaths,
      });

      if (policy.scope === 'combined') {
        correlation.recordInput(input.requestId, {
          toolName: input.toolName,
          providerName: input.providerName || '',
          textDigest: summarizeTextFromValue(args),
          modalityCount: packets.length,
        });
      }

      if (policy.scope === 'output-only') {
        return input;
      }

      const req = buildContentInspectRequest({
        protocolVersion: CONTENT_INSPECT_V2_PROTOCOL_VERSION,
        stage: 'input',
        requestId: input.requestId,
        toolName: input.toolName,
        providerName: input.providerName || null,
        payload: args,
        modalityPackets: packets,
        metadata: {
          mode: policy.mode,
          policyProfile: policy.policyProfile,
          scope: policy.scope,
        },
      });
      const verdict = await inspectWithConfig(req, scopedConfig, { signal: input.signal, clientRef: input.clientRef });
      if (verdict.decision === 'allow') return input;
      if (verdict.decision === 'escalate') {
        return {
          ...input,
          forceApproval: true,
        };
      }
      const isFailClosed = verdict.failClosed === true;
      return {
        ...input,
        blocked: true,
        code: isFailClosed ? 'MODERATION_FAIL_CLOSED' : 'MODERATION_BLOCKED',
        rule: verdict.ruleId || 'MODERATION-INPUT-BLOCKED',
        reason: verdict.reason || 'Tool call blocked by LLM content moderation.',
      };
    }, { order: 50 });

    invokeSlot.hook('after', async (output, input) => {
      if (correlation.consumeStreamHandled(input.requestId)) {
        correlation.consumeInput(input.requestId);
        return output;
      }
      const config = getConfig();
      const policy = resolveToolModerationPolicy(config, input.toolName);
      if (!policy.enabled || policy.exempt || policy.scope === 'input-only') {
        correlation.consumeInput(input.requestId);
        return output;
      }
      if (!output || typeof output !== 'object' || output.error || !output.result) {
        correlation.consumeInput(input.requestId);
        return output;
      }
      const scopedConfig = {
        ...config,
        mode: policy.mode,
        policyProfile: policy.policyProfile,
      };
      const correlatedInput = policy.scope === 'combined' ? correlation.consumeInput(input.requestId) : null;
      const stage = policy.scope === 'combined' && correlatedInput ? 'combined' : 'output';
      const packets = collectOutputModalityPackets(output.result);
      const req = buildContentInspectRequest({
        protocolVersion: CONTENT_INSPECT_V2_PROTOCOL_VERSION,
        stage,
        requestId: input.requestId,
        toolName: input.toolName,
        providerName: input.providerName || null,
        payload: stage === 'combined'
          ? { inputDigest: correlatedInput.textDigest, result: output.result }
          : output.result,
        modalityPackets: packets,
        metadata: {
          mode: policy.mode,
          policyProfile: policy.policyProfile,
          scope: policy.scope,
        },
      });
      const verdict = await inspectWithConfig(req, scopedConfig, {
        signal: input.signal, clientRef: input.clientRef, includesInput: Boolean(correlatedInput),
      });
      if (verdict.decision === 'allow') return output;
      if (verdict.decision === 'redact') {
        return applyOutputRedaction(output, verdict, { stage });
      }
      return {
        blocked: true,
        code: verdict.failClosed ? 'MODERATION_FAIL_CLOSED' : 'MODERATION_OUTPUT_BLOCKED',
        rule: verdict.ruleId || 'MODERATION-OUTPUT-BLOCKED',
        reason: verdict.reason || 'Tool output blocked by LLM content moderation.',
      };
    }, { order: 50 });
  }

  if (streamSlot) {
    streamSlot.hook('before', async meta => meta, { order: 50 });

    streamSlot.hook('after', async (output, meta) => {
      const config = getConfig();
      const policy = resolveToolModerationPolicy(config, meta.toolName);
      if (!policy.enabled || policy.exempt || policy.scope === 'input-only') {
        return output;
      }
      const scopedConfig = {
        ...config,
        mode: policy.mode,
        policyProfile: policy.policyProfile,
      };

      const runStreamInspect = async ({ stage, streamId, requestId, toolName, providerName, seq, payload, modalityPackets }) => {
        const correlated = policy.scope === 'combined' ? correlation.peekInput(requestId) : null;
        const req = buildContentInspectRequest({
          protocolVersion: CONTENT_INSPECT_V2_PROTOCOL_VERSION,
          stage,
          requestId,
          streamId,
          seq,
          toolName,
          providerName: providerName || null,
          payload: correlated ? { inputDigest: correlated.textDigest, chunk: payload } : payload,
          modalityPackets: modalityPackets || null,
          metadata: {
            mode: policy.mode,
            policyProfile: policy.policyProfile,
            scope: policy.scope,
          },
        });
        return inspectWithConfig(req, scopedConfig, {
          signal: meta.signal, clientRef: meta.clientRef, includesInput: Boolean(correlated),
        });
      };

      if (meta.phase === 'stream_start') {
        const session = new StreamInspectSession({
          streamId: meta.streamId,
          requestId: meta.requestId,
          toolName: meta.toolName,
          providerName: meta.providerName || '',
          overlapChars: scopedConfig.streaming.overlapChars,
          holdbackChars: scopedConfig.streaming.holdbackChars,
          maxPendingBytes: scopedConfig.streaming.maxPendingBytes,
          redactPolicy: scopedConfig.streaming.redactPolicy,
        });
        activeStreams.set(meta.streamId, session);
        if (meta.signal) {
          meta.signal.addEventListener('abort', () => {
            session.abort('Tool stream aborted before completion.');
            activeStreams.delete(meta.streamId);
          }, { once: true });
        }
        return output;
      }

      if (meta.phase === 'stream_chunk') {
        const session = activeStreams.get(meta.streamId);
        if (!session) return output;
        const res = await session.pushChunk(output, runStreamInspect);
        if (res.blocked) {
          activeStreams.delete(meta.streamId);
          correlation.markStreamHandled(meta.requestId);
          return {
            blocked: true,
            code: res.code,
            rule: res.rule,
            reason: res.reason,
          };
        }
        return {
          heldBack: res.heldBack,
          releaseChunks: res.releaseChunks,
        };
      }

      if (meta.phase === 'stream_end') {
        const session = activeStreams.get(meta.streamId);
        activeStreams.delete(meta.streamId);
        correlation.markStreamHandled(meta.requestId);
        if (!session) return output;
        const rawResult = output && typeof output === 'object' ? output.result : output;
        const res = await session.finalize(rawResult, runStreamInspect);
        if (res.blocked) {
          return {
            blocked: true,
            code: res.code,
            rule: res.rule,
            reason: res.reason,
          };
        }
        if (res.verdict?.decision === 'redact' && res.result !== undefined) {
          return {
            releaseChunks: res.releaseChunks,
            result: applyInlineResultRedaction(res.result, res.verdict),
          };
        }
        return {
          releaseChunks: res.releaseChunks,
          result: res.result,
        };
      }

      return output;
    }, { order: 50 });
  }

  if (panelSlot) {
    panelSlot.register('llm-moderation', validateConsolePanelDecl({
      id: 'llm-moderation',
      title: '多模态内容安全审查',
      subtitle: 'Local Guard + Canary 防诱导探针 + 云端审核 API（独立 / 合并 / 流式）',
      category: 'moderation',
      order: 20,
      executionBoundary: 'out-of-process',
      getSnapshot() {
        const config = getConfig();
        const totalInspected = stats.inspectedInput + stats.inspectedOutput + stats.inspectedCombined;
        const status = stats.failClosed > 0
          ? 'error'
          : (stats.blocked > 0 || stats.canaryInduced > 0 ? 'warn' : 'ok');
        const notices = [];
        if (config.cloudOptIn) {
          notices.push({
            tone: 'info',
            text: `云端内容审查已授权开启（Provider: ${config.cloudProvider}），策略生效中；离线 anti-leak 仍优先于外发执行。`,
          });
        } else {
          notices.push({
            tone: 'info',
            text: '当前处于纯本机审查模式（cloudOptIn=false），可在侧边栏「LLM 审查策略」与「插件密钥库」配置云端开关与密钥。',
          });
        }
        return {
          status,
          summary: [
            { label: '审查模式', value: config.mode, tone: 'info' },
            { label: '回退策略', value: config.policyProfile, tone: 'info' },
            { label: '累计预检', value: String(totalInspected), tone: 'info' },
            { label: '流式分块', value: String(stats.inspectedStreamChunks), tone: 'info' },
            { label: 'Canary诱导命中', value: `${stats.canaryInduced}/${stats.canaryTested}`, tone: stats.canaryInduced > 0 ? 'warn' : 'ok' },
            { label: '阻断/脱敏/升级', value: `${stats.blocked}/${stats.redacted}/${stats.escalated}`, tone: stats.blocked > 0 ? 'warn' : 'ok' },
            { label: '自动回退', value: String(stats.fallbackUsed), tone: stats.fallbackUsed > 0 ? 'warn' : 'ok' },
          ],
          table: {
            columns: ['时间', '工具', '阶段', '动作', '规则码', '执行引擎'],
            rows: stats.recentEvents.slice(0, 10).map(ev => [
              ev.time,
              ev.tool,
              ev.stage,
              ev.decision,
              ev.ruleId,
              ev.engine,
            ]),
          },
          notices,
        };
      },
    }));
  }

  ctx.effect(() => async () => {
    for (const session of activeStreams.values()) {
      session.abort('LLM moderation plugin unloading.');
    }
    activeStreams.clear();
    correlation.dispose();
    if (!cfg.client && typeof client.close === 'function') {
      await client.close();
    }
  }, 'llm-moderation:close');
}
