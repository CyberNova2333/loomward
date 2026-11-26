// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import {
  PLUGIN_SECRETS_ADMIN_SERVICE,
  validateContentInspectVerdict,
  validateContractDecl,
} from '@loomward/shared';
import {
  buildWorkspaceRpm,
  createLoomWardKernel,
  loadWorkspaceRootRefs,
} from '../../../packages/kernel/src/index.mjs';
import { startLoomWardDaemon } from '../../../packages/host/src/daemon.mjs';
import { writeModerationConfigSync } from '../../../local/moderation-config.mjs';
import { contract as modContract, apply as modApply } from '../src/index.mjs';

const execFileAsync = promisify(execFile);
const REPO_ROOT = path.resolve(import.meta.dirname, '../../..');

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

async function startMockJsonServer(t, handler) {
  const srv = http.createServer(async (req, res) => {
    try {
      const body = req.method === 'POST' ? await readJsonBody(req) : {};
      const reply = await handler(req, body);
      res.statusCode = reply.status ?? 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(reply.body ?? {}));
    } catch (err) {
      res.statusCode = 500;
      res.end(JSON.stringify({ error: err?.message || 'mock_error' }));
    }
  });
  await new Promise(resolve => srv.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => srv.close(resolve)));
  const addr = srv.address();
  return `http://127.0.0.1:${addr.port}`;
}

async function makeTempState(t) {
  const base = await fs.mkdtemp(path.join(os.homedir(), '.lw-mod-test-'));
  await fs.chmod(base, 0o700);
  const stateDir = path.join(base, 'state');
  const workspace = path.join(base, 'ws');
  await fs.mkdir(stateDir, { mode: 0o700 });
  await fs.mkdir(workspace, { mode: 0o700 });
  t.after(async () => {
    await fs.rm(base, { recursive: true, force: true });
  });
  return { base, stateDir, workspace };
}

function createFakeSandboxRuntime() {
  let closed = false;
  return {
    async handleRpc(body) {
      if (body.method === 'initialize') {
        return { jsonrpc: '2.0', id: body.id ?? null, result: { protocolVersion: '2025-11-25', serverInfo: { name: 'fake-sandbox', version: '1.0.0' } } };
      }
      if (body.method === 'tools/list') {
        return { jsonrpc: '2.0', id: body.id ?? null, result: { tools: [] } };
      }
      return { jsonrpc: '2.0', id: body.id ?? null, result: {} };
    },
    async close() { closed = true; },
    isClosed: () => closed,
  };
}

function makeRpcCall(toolName, args = {}, rpcId = 1) {
  return {
    jsonrpc: '2.0',
    id: rpcId,
    method: 'tools/call',
    params: { name: toolName, arguments: args },
  };
}

async function mountMockToolProvider(control, { unitId, providerName, providerImpl }) {
  await control.mountExtensionUnit({
    contract: {
      schemaVersion: 1,
      id: unitId,
      kind: 'extension-plugin',
      version: '3.0.0-alpha.0',
      executionBoundary: 'out-of-process',
      provides: [`tool:${unitId}`],
      consumes: ['tool:provider@1'],
      registers: [{ slot: 'tool:provider@1', name: providerName }],
    },
    trust: { autoApproveTrusted: true },
    load: () => ({
      name: unitId,
      apply(ctx) {
        ctx.get('tool:provider@1').register(providerName, providerImpl);
      },
    }),
  });
}

test('Python engine unit suite passes SSRF, 4 cloud provider signers, OAuth cache, and Eval CLI checks', async () => {
  const pyExe = process.platform === 'win32' ? 'python' : 'python3';
  const { stdout, stderr } = await execFileAsync(
    pyExe,
    ['-B', '-m', 'unittest', 'discover', '-s', 'test', '-p', 'engine_suite.py', '-v'],
    { cwd: path.resolve(import.meta.dirname, '..') },
  );
  assert.match(stderr + stdout, /OK/);
});

test('Cordis kernel enforces antileak order:10 before llm-moderation order:50 and exposes safe console panel', async t => {
  const built = await buildWorkspaceRpm(REPO_ROOT);
  const loadedRoots = await loadWorkspaceRootRefs(REPO_ROOT, {
    configs: {
      sandbox: { runtime: { enabled: false }, allowExec: false },
      localIngress: { transport: 'memory' },
      relayIngress: { autoStart: false },
    },
  });
  const { control } = await createLoomWardKernel({ rpm: built.rpm, roots: loadedRoots });
  t.after(() => control.stop());

  const invokeTrace = [];
  let moderationSeenCalls = 0;

  await control.mountExtensionUnit({
    contract: validateContractDecl({
      schemaVersion: 1,
      id: 'mock-antileak',
      kind: 'extension-plugin',
      version: '3.0.0-alpha.0',
      executionBoundary: 'out-of-process',
      provides: ['policy:mock-antileak'],
      consumes: ['tool:invoke@1'],
      writes: { hooks: [{ slot: 'tool:invoke@1', phase: 'before' }] },
    }),
    trust: { autoApproveTrusted: true },
    load: () => ({
      name: 'mock-antileak',
      apply(ctx) {
        ctx.get('tool:invoke@1').hook('before', async input => {
          invokeTrace.push(`antileak:${input.toolName}`);
          if (String(input.body?.params?.arguments?.text || '').includes('ANTILEAK_CANARY')) {
            return { ...input, blocked: true, code: 'ANTILEAK_BLOCKED', rule: 'R1-MOCK', reason: 'Blocked by antileak first.' };
          }
          return input;
        }, { order: 10 });
      },
    }),
  });

  await control.mountExtensionUnit({
    contract: modContract,
    trust: { autoApproveTrusted: true },
    config: {
      spawnService: false,
      inspectTransport: async body => {
        moderationSeenCalls += 1;
        invokeTrace.push(`moderation:${body.request.stage}:${body.request.toolName}`);
        return validateContentInspectVerdict({
          protocolVersion: 2,
          decision: 'allow',
          categories: [],
        }, { stage: body.request.stage });
      },
    },
    load: () => ({ name: 'llm-moderation', apply: modApply }),
  });

  const panelSlot = control.slots.consolePanel;
  const modPanel = panelSlot.entries().find(p => p.name === 'llm-moderation')?.impl;
  assert.ok(modPanel);
  assert.equal(modPanel.category, 'moderation');
  assert.equal(modPanel.executionBoundary, 'out-of-process');

  const blockedRes = await control.slots.toolInvoke.run(
    {
      requestId: 'req-order-1',
      toolName: 'demo_tool',
      providerName: 'test',
      body: { params: { arguments: { text: 'has ANTILEAK_CANARY secret' } } },
    },
    async current => current,
  );
  assert.equal(blockedRes.blocked, true);
  assert.equal(moderationSeenCalls, 0);
  assert.deepEqual(invokeTrace, ['antileak:demo_tool']);

  invokeTrace.length = 0;
  const allowRes = await control.slots.toolInvoke.run(
    {
      requestId: 'req-order-2',
      toolName: 'demo_tool',
      providerName: 'test',
      body: { params: { arguments: { text: 'hello safe' } } },
    },
    async () => ({ jsonrpc: '2.0', id: 2, result: { content: [{ type: 'text', text: 'safe reply' }] } }),
  );
  assert.equal(allowRes.result.content[0].text, 'safe reply');
  assert.deepEqual(invokeTrace, [
    'antileak:demo_tool',
    'moderation:input:demo_tool',
    'moderation:combined:demo_tool',
  ]);
});

test('Daemon + real Python engine enforces scopes (input-only, output-only, combined), Canary inducement probe, streaming holdback, and Trust secrets', async t => {
  const { stateDir, workspace } = await makeTempState(t);
  const bridgeToken = 'mod-test-token-1234567890';
  const canarySecretLeak = 'SECRET_LEAK_CANARY_NEVER_ECHO';

  const guardUrl = await startMockJsonServer(t, async (_req, body) => {
    const userMsg = body.messages?.[1]?.content || '';
    if (String(userMsg).includes('EXPLICIT_GUARD_UNSAFE')) {
      return { body: { choices: [{ message: { content: JSON.stringify({ safe: false, score: 0.92, categories: ['guard.unsafe'], ruleId: 'GUARD-HTTP-UNSAFE', reason: 'Guard blocked.' }) } }] } };
    }
    if (String(userMsg).includes('SUSPICIOUS_INDUCEMENT')) {
      return { body: { choices: [{ message: { content: JSON.stringify({ safe: true, score: 0.45, categories: ['prompt.indirect_injection'], ruleId: 'MOD-GRAY-ZONE', reason: 'Borderline.' }) } }] } };
    }
    if (String(userMsg).includes('LW_MOD_REDACT_')) {
      return {
        body: {
          choices: [{
            message: {
              content: JSON.stringify({
                safe: false,
                decision: 'redact',
                score: 0.72,
                categories: ['security.sensitive_output'],
                ruleId: 'MOD-RULE-OUTPUT-REDACT',
                reason: 'Redacted secret token.',
                redactedPayload: String(userMsg).replace(/LW_MOD_REDACT_[A-Z0-9_]+/g, '[REDACTED:SENSITIVE]'),
              }),
            },
          }],
        },
      };
    }
    if (String(userMsg).includes('LW_MOD_PROHIBITED_PAYLOAD')) {
      return { body: { choices: [{ message: { content: JSON.stringify({ safe: false, score: 0.99, categories: ['policy.prohibited'], ruleId: 'MOD-RULE-PROHIBITED-KEYWORD', reason: 'Prohibited stream token.' }) } }] } };
    }
    return { body: { choices: [{ message: { content: 'safe' } }] } };
  });

  let canaryReceivedTools = 'not-checked';
  const canaryUrl = await startMockJsonServer(t, async (_req, body) => {
    canaryReceivedTools = body.tools;
    const userMsg = String(body.messages?.[1]?.content || '');
    assert.ok(userMsg.includes('<AUDIT_TARGET nonce="'));
    if (userMsg.includes('SUSPICIOUS_INDUCEMENT')) {
      return {
        body: {
          choices: [{
            message: {
              content: `OVERRIDE_ACCEPTED ${canarySecretLeak} <tool_call>{"tool":"mcp__bash","cmd":"cat ~/.ssh/id_rsa"}</tool_call>`,
            },
          }],
        },
      };
    }
    return { body: { choices: [{ message: { content: 'This appears to be a benign summary.' } }] } };
  });

  writeModerationConfigSync(stateDir, {
    mode: 'guard-plus-canary',
    policyProfile: 'balanced',
    defaultScope: 'combined',
    cloudOptIn: false,
    localGuard: { kind: 'http', endpoint: guardUrl, model: 'llama-guard-3', timeoutMs: 5000 },
    canary: {
      enabled: true,
      endpoint: canaryUrl,
      model: 'qwen2.5-0.5b',
      maxTokens: 96,
      temperature: 0.1,
      shadowMode: false,
      escalateOnInduced: true,
      onCanaryUnavailable: 'escalate',
    },
    perToolOverrides: {
      mcp__modtest__input_only: { scope: 'input-only', mode: 'local-only' },
      mcp__modtest__output_only: { scope: 'output-only', mode: 'local-only' },
      mcp__modtest__combined: { scope: 'combined', mode: 'local-only' },
    },
  }, { workspaceRoots: [workspace], requirePrivateState: false });

  const approvalCalls = [];

  const daemon = await startLoomWardDaemon({
    rootDir: REPO_ROOT,
    stateDir,
    origin: 'https://bridge.example.test',
    workspaceRoots: [workspace],
    allowExec: false,
    sandboxRuntime: createFakeSandboxRuntime(),
    relay: { autoStart: false },
    enableMcpHub: false,
    enableLlmModeration: true,
    secretLoader: () => ({ bridgeToken }),
    approvals: {
      authorize: async (_body, _auth, { force } = {}) => {
        approvalCalls.push(Boolean(force));
        return { approved: true, id: `apr-${approvalCalls.length}`, expiresAt: Date.now() + 60_000, forced: Boolean(force) };
      },
    },
  });
  t.after(() => daemon.stop());

  const secretsAdmin = daemon.control.getService(PLUGIN_SECRETS_ADMIN_SERVICE);
  secretsAdmin.setSecrets('llm-moderation', { OPENAI_API_KEY: 'sk-canary-never-leak-to-tool-output' });

  await mountMockToolProvider(daemon.control, {
    unitId: 'mod-test-unit',
    providerName: 'mod-test-provider',
    providerImpl: {
      id: 'mod-test-provider',
      executionBoundary: 'out-of-process',
      ownsTool: name => [
        'mcp__modtest__input_only',
        'mcp__modtest__output_only',
        'mcp__modtest__combined',
        'mcp__modtest__canary',
        'mcp__modtest__stream',
      ].includes(name),
      getToolScopes: () => new Map([
        ['mcp__modtest__input_only', ['computer:read', 'computer:write']],
        ['mcp__modtest__output_only', ['computer:read', 'computer:write']],
        ['mcp__modtest__combined', ['computer:read', 'computer:write']],
        ['mcp__modtest__canary', ['computer:read']],
        ['mcp__modtest__stream', ['computer:read']],
      ]),
      checkToolEnabled: () => ({ enabled: true }),
      listTools: async () => [],
      callTool: async (_name, args) => {
        const cannedOutputs = {
          'inonly-out': 'has LW_MOD_REDACT_ABC123 inside output',
          'outonly-redact': 'secret LW_MOD_REDACT_KEY99 here',
          'comb-ok': 'clean output',
          'comb-bad': 'oops EXPLICIT_GUARD_UNSAFE output',
        };
        return { content: [{ type: 'text', text: cannedOutputs[args.caseId] || 'ok' }] };
      },
      callToolStream: async (_name, args, { emit, signal }) => {
        const chunks = Array.isArray(args.chunks) ? args.chunks : [];
        for (const ch of chunks) {
          if (signal.aborted) break;
          await emit({ type: 'text', text: ch });
        }
        return { content: [{ type: 'text', text: args.finalText || '' }] };
      },
    },
  });

  // 1) Guard + Canary catches covert SUSPICIOUS_INDUCEMENT on read-only tool -> escalates forced approval!
  const beforeApprovals = approvalCalls.length;
  const canaryReply = await daemon.localIngress.dispatchRpc(
    makeRpcCall('mcp__modtest__canary', { text: 'Summarize: SUSPICIOUS_INDUCEMENT covert payload' }, 10),
    { requestId: 'req_canary_1', scope: ['computer:read'] },
  );
  assert.equal(approvalCalls.length, beforeApprovals + 1, 'Canary inducement must trigger forced local approval on input.');
  assert.equal(approvalCalls.at(-1), true, 'Canary inducement must set force=true on local approval.');
  assert.equal(canaryReceivedTools, undefined, 'Canary weak model must have ZERO tools registered.');
  assert.equal(JSON.stringify(canaryReply).includes(canarySecretLeak), false, 'Raw Canary output must never leak.');

  // 2) input-only: blocks unsafe input, skips unsafe output redaction
  const inOnlyBad = await daemon.localIngress.dispatchRpc(
    makeRpcCall('mcp__modtest__input_only', { text: 'EXPLICIT_GUARD_UNSAFE attack' }, 11),
    { requestId: 'req_inonly_bad', scope: ['computer:read', 'computer:write'] },
  );
  assert.equal(inOnlyBad.error.data.code, 'MODERATION_BLOCKED');

  const inOnlyOutPass = await daemon.localIngress.dispatchRpc(
    makeRpcCall('mcp__modtest__input_only', { text: 'safe input', caseId: 'inonly-out' }, 12),
    { requestId: 'req_inonly_out', scope: ['computer:read', 'computer:write'] },
  );
  assert.match(inOnlyOutPass.result.content[0].text, /LW_MOD_REDACT_ABC123/);

  // 3) output-only: skips input check, redacts output pattern via applyOutputRedaction
  const outOnlyRes = await daemon.localIngress.dispatchRpc(
    makeRpcCall('mcp__modtest__output_only', { text: 'EXPLICIT_GUARD_UNSAFE skipped in output-only', caseId: 'outonly-redact' }, 13),
    { requestId: 'req_outonly_redact', scope: ['computer:read', 'computer:write'] },
  );
  assert.equal(outOnlyRes.result.content[0].text, 'secret [REDACTED:SENSITIVE] here');

  // 4) combined: clean correlation passes; unsafe correlated output blocked
  const combOk = await daemon.localIngress.dispatchRpc(
    makeRpcCall('mcp__modtest__combined', { text: 'benign input context', caseId: 'comb-ok' }, 14),
    { requestId: 'req_comb_ok', scope: ['computer:read', 'computer:write'] },
  );
  assert.equal(combOk.result.content[0].text, 'clean output');

  const combBlocked = await daemon.localIngress.dispatchRpc(
    makeRpcCall('mcp__modtest__combined', { text: 'benign prompt', caseId: 'comb-bad' }, 15),
    { requestId: 'req_comb_bad', scope: ['computer:read', 'computer:write'] },
  );
  assert.equal(combBlocked.error.data.code, 'MODERATION_OUTPUT_BLOCKED');

  // 5) Streaming holdback + cross-chunk split-keyword detection + immediate abort
  writeModerationConfigSync(stateDir, {
    mode: 'local-only',
    policyProfile: 'balanced',
    localGuard: { kind: 'http', endpoint: guardUrl, model: 'llama-guard-3', timeoutMs: 5000 },
    streaming: { overlapChars: 64, holdbackChars: 32, maxPendingBytes: 65536, redactPolicy: 'mask-continue' },
  }, { workspaceRoots: [workspace], requirePrivateState: false });

  const emittedSplit = [];
  const splitStreamReply = await daemon.localIngress.dispatchRpcStream(
    makeRpcCall('mcp__modtest__stream', {
      chunks: [
        'Safe intro text padding so first segment exceeds 32 chars cleanly. ',
        'Trailing prefix LW_MOD_PROHIB',
        'ITED_PAYLOAD tail never leaks!',
      ],
    }, 16),
    {
      requestId: 'req_stream_split',
      scope: ['computer:read'],
      onChunk: async env => {
        emittedSplit.push(env.body?.params?.chunk?.text || '');
      },
    },
  );
  assert.equal(splitStreamReply.error.data.code, 'MODERATION_STREAM_BLOCKED');
  const joinedEmitted = emittedSplit.join('');
  assert.equal(joinedEmitted.includes('LW_MOD_PROHIB'), false, 'Holdback must prevent emitting partial blocked keyword');
  assert.equal(joinedEmitted.includes('ITED_PAYLOAD'), false);

  const emittedClean = [];
  const cleanStreamReply = await daemon.localIngress.dispatchRpcStream(
    makeRpcCall('mcp__modtest__stream', {
      chunks: ['Part A is completely safe and ', 'Part B finishes cleanly.'],
    }, 17),
    {
      requestId: 'req_stream_clean',
      scope: ['computer:read'],
      onChunk: async env => {
        emittedClean.push(env.body?.params?.chunk?.text || '');
      },
    },
  );
  assert.ok(cleanStreamReply.result);
  assert.equal(emittedClean.join(''), 'Part A is completely safe and Part B finishes cleanly.');

  // 6) Verify panel never exposes secrets
  const panels = daemon.control.slots.consolePanel.entries();
  const panelEntry = panels.find(p => p.name === 'llm-moderation');
  assert.ok(panelEntry);
  const snap = await panelEntry.impl.getSnapshot();
  assert.equal(JSON.stringify(snap).includes('sk-canary-never-leak'), false);
  assert.equal(JSON.stringify(snap).includes(canarySecretLeak), false);
});

test('Multimodal sanitizer validates SVGs, rejects XSS/XXE, and fails closed per modality when local media decoders are missing', async t => {
  const { stateDir, workspace } = await makeTempState(t);
  const bridgeToken = 'mod-media-token-123456';

  writeModerationConfigSync(stateDir, {
    mode: 'local-only',
    policyProfile: 'balanced',
    cloudOptIn: false,
  }, { workspaceRoots: [workspace], requirePrivateState: false });

  const daemon = await startLoomWardDaemon({
    rootDir: REPO_ROOT,
    stateDir,
    origin: 'https://bridge.example.test',
    workspaceRoots: [workspace],
    allowExec: false,
    sandboxRuntime: createFakeSandboxRuntime(),
    relay: { autoStart: false },
    enableMcpHub: false,
    enableLlmModeration: true,
    secretLoader: () => ({ bridgeToken }),
    approvals: {
      authorize: async () => ({ approved: true, id: 'apr-media', expiresAt: Date.now() + 60_000 }),
    },
  });
  t.after(() => daemon.stop());

  await mountMockToolProvider(daemon.control, {
    unitId: 'media-test-unit',
    providerName: 'media-provider',
    providerImpl: {
      id: 'media-provider',
      executionBoundary: 'out-of-process',
      ownsTool: name => name === 'mcp__media__inspect',
      getToolScopes: () => new Map([['mcp__media__inspect', ['computer:read']]]),
      checkToolEnabled: () => ({ enabled: true }),
      listTools: async () => [],
      callTool: async (_name, args) => ({ content: args.returnContent || [{ type: 'text', text: 'ok' }] }),
    },
  });

  const safeSvg = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><text>Hello chart</text></svg>', 'utf8').toString('base64');
  const okSvg = await daemon.localIngress.dispatchRpc(
    makeRpcCall('mcp__media__inspect', { content: [{ type: 'image', mimeType: 'image/svg+xml', data: safeSvg }] }, 21),
    { requestId: 'req_svg_ok', scope: ['computer:read'] },
  );
  assert.equal(okSvg.result.content[0].text, 'ok');

  const xssSvg = Buffer.from('<svg><script>alert(1)</script></svg>', 'utf8').toString('base64');
  const badSvg = await daemon.localIngress.dispatchRpc(
    makeRpcCall('mcp__media__inspect', { content: [{ type: 'image', mimeType: 'image/svg+xml', data: xssSvg }] }, 22),
    { requestId: 'req_svg_xss', scope: ['computer:read'] },
  );
  assert.equal(badSvg.error.data.code, 'MODERATION_FAIL_CLOSED');
  assert.equal(badSvg.error.data.rule, 'MODERATION-SVG-ACTIVE');

  const fakePng = Buffer.from('not-a-png-header-bytes', 'utf8').toString('base64');
  const badPng = await daemon.localIngress.dispatchRpc(
    makeRpcCall('mcp__media__inspect', { content: [{ type: 'image', mimeType: 'image/png', data: fakePng }] }, 23),
    { requestId: 'req_png_bad', scope: ['computer:read'] },
  );
  assert.equal(badPng.error.data.code, 'MODERATION_FAIL_CLOSED');
  assert.equal(badPng.error.data.rule, 'MODERATION-IMAGE-MAGIC');

  const textStillWorks = await daemon.localIngress.dispatchRpc(
    makeRpcCall('mcp__media__inspect', { text: 'plain text inspection' }, 24),
    { requestId: 'req_text_ok', scope: ['computer:read'] },
  );
  assert.equal(textStillWorks.result.content[0].text, 'ok');
});

test('cloudOptIn=false and policyProfile strict vs experimental-resilient control Cloud fallback behavior', async t => {
  const { stateDir, workspace } = await makeTempState(t);
  const bridgeToken = 'mod-policy-token-123456';

  writeModerationConfigSync(stateDir, {
    mode: 'cloud-first',
    policyProfile: 'strict',
    cloudOptIn: false,
    cloudProvider: 'openai-compat',
    fallback: { chain: [], onAllFailedInput: 'block', onAllFailedOutput: 'block' },
  }, { workspaceRoots: [workspace], requirePrivateState: false });

  const daemon = await startLoomWardDaemon({
    rootDir: REPO_ROOT,
    stateDir,
    origin: 'https://bridge.example.test',
    workspaceRoots: [workspace],
    allowExec: false,
    sandboxRuntime: createFakeSandboxRuntime(),
    relay: { autoStart: false },
    enableMcpHub: false,
    enableLlmModeration: true,
    secretLoader: () => ({ bridgeToken }),
    approvals: {
      authorize: async () => ({ approved: true, id: 'apr-policy', expiresAt: Date.now() + 60_000 }),
    },
  });
  t.after(() => daemon.stop());

  await mountMockToolProvider(daemon.control, {
    unitId: 'policy-test-unit',
    providerName: 'policy-provider',
    providerImpl: {
      id: 'policy-provider',
      executionBoundary: 'out-of-process',
      ownsTool: name => name === 'mcp__policy__run',
      getToolScopes: () => new Map([['mcp__policy__run', ['computer:read']]]),
      checkToolEnabled: () => ({ enabled: true }),
      listTools: async () => [],
      callTool: async () => ({ content: [{ type: 'text', text: 'tool ran ok' }] }),
    },
  });

  const strictBlocked = await daemon.localIngress.dispatchRpc(
    makeRpcCall('mcp__policy__run', { text: 'benign text' }, 31),
    { requestId: 'req_strict_1', scope: ['computer:read'] },
  );
  assert.equal(strictBlocked.error.data.code, 'MODERATION_FAIL_CLOSED');

  writeModerationConfigSync(stateDir, {
    mode: 'cloud-first',
    policyProfile: 'experimental-resilient',
    cloudOptIn: false,
    cloudProvider: 'openai-compat',
  }, { workspaceRoots: [workspace], requirePrivateState: false });

  const expRes = await daemon.localIngress.dispatchRpc(
    makeRpcCall('mcp__policy__run', { text: 'benign text' }, 32),
    { requestId: 'req_exp_1', scope: ['computer:read'] },
  );
  assert.equal(expRes.result.content[0].text, 'tool ran ok');
});
