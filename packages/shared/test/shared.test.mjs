// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AUDIT_CODES,
  BOOT_DEADLINE_MS,
  BootDeadlineError,
  CLOSED_SLOTS,
  ImplSlot,
  MechanismSlot,
  REJECT_CODES,
  SlotError,
  VAULT_SLOT,
  assertSafeEndpointUrl,
  buildContentInspectRequest,
  buildPermissionSubject,
  canonicalJson,
  computeManifestHash,
  createFrozenRpm,
  formatActionNode,
  isRpmShape,
  isSafeUnicodeString,
  mechanismActionKind,
  sanitizeAuditMetadata,
  sanitizeConsolePanelSnapshot,
  serviceInvokeActionKind,
  sha256Tagged,
  validateConsolePanelDecl,
  validateContentInspectVerdict,
  validateContractDecl,
  validateModerationConfig,
  withDeadline,
} from '../src/index.mjs';

test('canonicalJson sorts keys deterministically and RPM verifies shape and hash', async () => {
  assert.equal(canonicalJson({ b: 1, a: [2, { d: 4, c: 3 }] }), '{"a":[2,{"c":3,"d":4}],"b":1}');
  const hash = await sha256Tagged('entry-bytes');
  const rpm = await createFrozenRpm({
    target: 'runtime',
    rootPlugins: [
      { id: 'sandbox', version: '3.0.0-alpha.0', entryHash: hash, provides: ['sandbox:docker'] },
      { id: 'host', version: '3.0.0-alpha.0', entryHash: hash, provides: ['host:platform'] },
    ],
  });
  assert.equal(isRpmShape(rpm), true);
  assert.equal(await computeManifestHash(rpm), rpm.manifestHash);
  assert.equal(isRpmShape({ ...rpm, extraField: true }), false);
});

test('validateContractDecl enforces executionBoundary and registers/writes declarations', () => {
  const valid = validateContractDecl({
    schemaVersion: 1,
    id: 'antileak',
    kind: 'extension-plugin',
    version: '3.0.0-alpha.0',
    executionBoundary: 'out-of-process',
    provides: ['policy:antileak'],
    consumes: ['tool:invoke@1'],
    registers: [{ slot: 'policy:rule@1', name: 'antileak-rule' }],
    writes: {
      hooks: [{ slot: 'tool:invoke@1', phase: 'before' }],
      intercepts: [],
      isolateProvides: [],
    },
  });
  assert.equal(valid.executionBoundary, 'out-of-process');
  assert.equal(valid.registers.length, 1);
  assert.equal(valid.writes.hooks[0].phase, 'before');

  assert.throws(() => validateContractDecl({
    schemaVersion: 1,
    id: 'bad-ext',
    kind: 'extension-plugin',
    version: '3.0.0-alpha.0',
    executionBoundary: 'in-process-root',
  }), /cannot declare executionBoundary/);

  assert.throws(() => validateContractDecl({
    schemaVersion: 1,
    id: 'bad-hook',
    kind: 'extension-plugin',
    version: '3.0.0-alpha.0',
    executionBoundary: 'out-of-process',
    writes: { hooks: [{ slot: 'tool:invoke@1', phase: 'invalid' }] },
  }), /Invalid hook write phase/);
});

test('guard-types helpers format action nodes, build subjects, and strip forbidden secret audit fields', () => {
  assert.equal(VAULT_SLOT, 'vault:backend@1');
  assert.ok(CLOSED_SLOTS.includes(VAULT_SLOT));
  assert.ok(AUDIT_CODES.AUDIT_VAULT_ACCESS_DENIED);
  assert.ok(REJECT_CODES.GUARD_POLICY_CLOSED);
  assert.equal(BOOT_DEADLINE_MS, 60_000);

  assert.equal(mechanismActionKind('before'), 'mechanism.hook.before');
  assert.equal(serviceInvokeActionKind('write'), 'service.invoke.write');
  assert.equal(
    formatActionNode({ kind: 'service.invoke.write', target: 'host:dispatch', method: 'exec' }),
    'service.invoke.write:host:dispatch#exec',
  );
  assert.equal(
    formatActionNode({ kind: 'impl.register', target: 'tool:provider@1' }),
    'impl.register:tool:provider@1',
  );

  const contract = validateContractDecl({
    schemaVersion: 1,
    id: 'mcp-hub',
    kind: 'extension-plugin',
    version: '3.0.0-alpha.0',
    executionBoundary: 'out-of-process',
  });
  const subject = buildPermissionSubject(contract, { signed: true, trustLevel: 'official', isolated: true });
  assert.deepEqual(subject, {
    unitId: 'mcp-hub',
    kind: 'extension-plugin',
    executionBoundary: 'out-of-process',
    signed: true,
    trustLevel: 'official',
    isolated: true,
  });

  assert.equal(isSafeUnicodeString('hello-世界'), true);
  assert.equal(isSafeUnicodeString('bad\0null'), false);
  assert.equal(isSafeUnicodeString('\uD800'), false);

  const clean = sanitizeAuditMetadata({
    unitId: 'mcp-hub',
    code: AUDIT_CODES.AUDIT_UNIT_MOUNTED,
    bridgeToken: 'secret-token-value',
    stdout: 'raw command output',
    content: 'private file contents',
    count: 2,
  });
  assert.deepEqual(clean, { unitId: 'mcp-hub', code: 'AUDIT_UNIT_MOUNTED', count: 2 });
});

test('withDeadline runs LIFO rollback on error and immediately undoes late registrations after timeout', async () => {
  const log = [];
  await assert.rejects(
    () => withDeadline(500, async run => {
      run.add(() => log.push('a'));
      run.add(() => log.push('b'));
      throw new Error('boom');
    }),
    /boom/,
  );
  assert.deepEqual(log, ['b', 'a']);

  const lateLog = [];
  let releaseGate;
  const gate = new Promise(resolve => { releaseGate = resolve; });
  await assert.rejects(
    () => withDeadline(30, async run => {
      run.add(() => lateLog.push('early'));
      await gate;
      run.add(() => lateLog.push('late'));
      run.live();
    }),
    BootDeadlineError,
  );
  releaseGate();
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.deepEqual(lateLog, ['early', 'late']);
});

test('ImplSlot and MechanismSlot enforce authorization, report release, and track replace state', async () => {
  const events = [];
  const authorizer = {
    authorize(_caller, req) {
      events.push(`auth:${req.kind}:${req.slot}`);
    },
    released(_caller, req) {
      events.push(`rel:${req.kind}:${req.slot}`);
    },
  };
  const slot = new ImplSlot({ name: 'tool:provider@1', cardinality: 'multi', policy: 'trusted' }, () => authorizer);
  slot.registerBuiltin('builtin-default', { kind: 'default' });
  assert.equal(slot.has('builtin-default'), true);
  assert.throws(() => slot.register('untracked', {}), SlotError);

  const trackedCaller = {
    effect(fn) {
      return fn();
    },
  };
  const ORIGINAL = Symbol.for('cordis.original');
  const proxied = Object.create(slot, {
    ctx: { value: trackedCaller },
    [ORIGINAL]: { value: slot },
  });
  const dispose = proxied.register('custom', { kind: 'custom' });
  assert.deepEqual(slot.names(), ['builtin-default', 'custom']);
  dispose();
  assert.deepEqual(slot.names(), ['builtin-default']);
  assert.ok(events.includes('rel:register:tool:provider@1'));

  const mech = new MechanismSlot({ name: 'tool:invoke@1', policy: 'trusted' }, () => authorizer);
  const mechProxy = Object.create(mech, {
    ctx: { value: trackedCaller },
    [ORIGINAL]: { value: mech },
  });
  assert.equal(mech.hasReplace(), false);
  const unhookBefore = mechProxy.hook('before', input => ({ ...input, checked: true }));
  const unhookReplace = mechProxy.hook('replace', (input, base) => base({ ...input, replaced: true }));
  assert.equal(mech.hasReplace(), true);
  const result = await mech.run({ tool: 'read_file' }, x => ({ ok: true, ...x }));
  assert.deepEqual(result, { ok: true, tool: 'read_file', checked: true, replaced: true });
  unhookBefore();
  unhookReplace();
  assert.equal(mech.hasReplace(), false);
  assert.ok(events.includes('rel:hook:tool:invoke@1'));
});

test('panel-schema and content-guard contracts validate declarative panels and input/output moderation verdicts', () => {
  const decl = validateConsolePanelDecl({
    id: 'llm-moderation',
    title: 'LLM 内容审核引擎',
    subtitle: '独立进程外内容风控与合规审核',
    category: 'moderation',
    order: 20,
    executionBoundary: 'out-of-process',
  });
  assert.equal(decl.readOnly, true);
  assert.equal(decl.category, 'moderation');

  const snap = sanitizeConsolePanelSnapshot(decl, {
    status: 'ok',
    summary: [{ label: '已审核', value: '128', tone: 'ok' }],
    table: { columns: ['时间', '裁决'], rows: [['12:00', 'allow']] },
    links: [
      { label: 'Safe Docs', href: 'https://example.test/docs' },
      { label: 'XSS Attempt', href: 'javascript:alert(1)' },
    ],
  });
  assert.equal(snap.links.length, 1);
  assert.equal(snap.links[0].href, 'https://example.test/docs');

  const req = buildContentInspectRequest({
    stage: 'input',
    requestId: 'req-1',
    toolName: 'write_file',
    providerName: 'sandbox-docker',
    payload: { path: 'notes.md', content: 'hello' },
  });
  assert.equal(req.protocolVersion, 1);

  const escalated = validateContentInspectVerdict({
    protocolVersion: 1,
    decision: 'escalate',
    categories: ['policy.review'],
    score: 0.72,
    ruleId: 'MOD-01',
    reason: 'Needs human review',
  }, { stage: 'input' });
  assert.equal(escalated.decision, 'escalate');

  // Input stage forbids silent redaction; output stage allows redaction.
  assert.throws(() => validateContentInspectVerdict({
    protocolVersion: 1,
    decision: 'redact',
    categories: ['pii'],
    redactedPayload: '[redacted]',
  }, { stage: 'input' }), /cannot silently rewrite/);

  const redacted = validateContentInspectVerdict({
    protocolVersion: 1,
    decision: 'redact',
    categories: ['pii'],
    redactedPayload: '[redacted]',
  }, { stage: 'output' });
  assert.equal(redacted.redactedPayload, '[redacted]');
});

test('MechanismSlot enforces monotonic blocked/forceApproval latches and allowReplace=false guard', async () => {
  const trackedCaller = { effect: fn => fn() };
  const ORIGINAL = Symbol.for('cordis.original');
  const mech = new MechanismSlot({ name: 'tool:invoke@1', policy: 'trusted', allowReplace: false });
  const proxy = Object.create(mech, {
    ctx: { value: trackedCaller },
    [ORIGINAL]: { value: mech },
  });

  // Replace hooks are structurally forbidden when allowReplace=false.
  assert.throws(() => proxy.hook('replace', (input, base) => base(input)), SlotError);

  // Downstream before-hook cannot downgrade forceApproval=true back to false.
  const u1 = proxy.hook('before', input => ({ ...input, forceApproval: true }));
  const u2 = proxy.hook('before', input => ({ ...input, forceApproval: false, touched: true }));
  const escalated = await mech.run({ tool: 'command_status' }, x => x);
  assert.equal(escalated.forceApproval, true);
  assert.equal(escalated.touched, true);
  u1();
  u2();

  // Downstream before-hook cannot un-block or observe an already blocked request.
  let downstreamRan = false;
  const b1 = proxy.hook('before', input => ({ ...input, blocked: true, code: 'ANTILEAK_BLOCKED' }));
  const b2 = proxy.hook('before', input => {
    downstreamRan = true;
    return { ...input, blocked: false };
  });
  const blocked = await mech.run({ tool: 'write_file' }, x => x);
  assert.equal(blocked.blocked, true);
  assert.equal(blocked.code, 'ANTILEAK_BLOCKED');
  assert.equal(downstreamRan, false);
  b1();
  b2();

  // Primitive/null return or getter TOCTOU cannot wipe forceApproval or skip downstream before-hooks.
  const n1 = proxy.hook('before', input => ({ ...input, forceApproval: true }), { order: 10 });
  const n2 = proxy.hook('before', () => null, { order: 20 });
  const survivedNull = await mech.run({ tool: 'command_status' }, x => x);
  assert.equal(survivedNull.forceApproval, true);
  n1();
  n2();

  let flip = 0;
  let secondHookSawIt = false;
  const g1 = proxy.hook('before', input => ({
    ...input,
    get blocked() {
      flip += 1;
      return flip === 1;
    },
  }), { order: 10 });
  const g2 = proxy.hook('before', input => {
    secondHookSawIt = true;
    return input;
  }, { order: 20 });
  const getterBlocked = await mech.run({ tool: 'exec_command' }, x => x);
  assert.equal(getterBlocked.blocked, true);
  assert.equal(secondHookSawIt, false);
  g1();
  g2();

  // Deterministic order: order=10 runs before order=100 even when registered second.
  const orderTrace = [];
  const o2 = proxy.hook('before', input => { orderTrace.push('external-llm-100'); return input; }, { order: 100 });
  const o1 = proxy.hook('before', input => { orderTrace.push('offline-antileak-10'); return input; }, { order: 10 });
  await mech.run({ tool: 'read_file' }, x => x);
  assert.deepEqual(orderTrace, ['offline-antileak-10', 'external-llm-100']);
  o1();
  o2();

  // After-hook monotonic blocked latch prevents downstream after-hook from unblocking output.
  let after2Ran = false;
  const a1 = proxy.hook('after', out => ({ ...out, blocked: true, code: 'MOD_OUTPUT_BLOCKED' }), { order: 10 });
  const a2 = proxy.hook('after', out => { after2Ran = true; return { ...out, blocked: false }; }, { order: 20 });
  const afterOut = await mech.run({ tool: 'read_file' }, () => ({ jsonrpc: '2.0', id: 1, result: {} }));
  assert.equal(afterOut.blocked, true);
  assert.equal(after2Ran, false);
  a1();
  a2();
});

test('MechanismSlot protects frozen toolName/body from before-hook shadowing and shared validators resist getter TOCTOU', async () => {
  const trackedCaller = { effect: fn => fn() };
  const ORIGINAL = Symbol.for('cordis.original');
  const mech = new MechanismSlot({ name: 'tool:invoke@1', policy: 'trusted', allowReplace: false });
  const proxy = Object.create(mech, {
    ctx: { value: trackedCaller },
    [ORIGINAL]: { value: mech },
  });

  let downstreamToolName = null;
  let downstreamPath = null;
  const realBody = Object.freeze({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: Object.freeze({ name: 'write_file', arguments: Object.freeze({ path: 'secret.txt' }) }) });
  const h1 = proxy.hook('before', input => ({
    ...input,
    toolName: 'computer_context',
    body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'computer_context', arguments: {} } },
  }), { order: 0 });
  const h2 = proxy.hook('before', input => {
    downstreamToolName = input.toolName;
    downstreamPath = input.body?.params?.arguments?.path;
    return input;
  }, { order: 10 });
  const finalInput = await mech.run(Object.freeze({ toolName: 'write_file', body: realBody }), x => x);
  assert.equal(downstreamToolName, 'write_file');
  assert.equal(downstreamPath, 'secret.txt');
  assert.equal(finalInput.toolName, 'write_file');
  h1();
  h2();

  // B9: flipping getter on l.href / item.tone cannot sneak javascript: into panel links or unvalidated tones.
  const decl = validateConsolePanelDecl({
    id: 'getter-test',
    title: 'Getter Guard',
    category: 'security',
    executionBoundary: 'out-of-process',
  });
  let hrefReads = 0;
  let toneReads = 0;
  const evilLink = {
    label: 'Link',
    get href() {
      hrefReads += 1;
      return hrefReads === 1 ? 'https://safe.example.test' : 'javascript:alert(1)';
    },
  };
  const evilSummary = {
    label: 'M',
    value: '1',
    get tone() {
      toneReads += 1;
      return toneReads === 1 ? 'ok' : 'evil-tone';
    },
  };
  const snap = sanitizeConsolePanelSnapshot(decl, { status: 'ok', summary: [evilSummary], links: [evilLink] });
  assert.equal(hrefReads, 1);
  assert.equal(snap.links[0].href, 'https://safe.example.test');
  assert.equal(toneReads, 1);
  assert.equal(snap.summary[0].tone, 'ok');
});

test('Round 8 MechanismSlot immutability: hooks cannot mutate frozen inputs in-place or reset forceApproval via undefined return', async () => {
  const trackedCaller = { effect: fn => fn() };
  const ORIGINAL = Symbol.for('cordis.original');
  const mech = new MechanismSlot({ name: 'r8-immut-test', immutableInput: true });
  const proxy = Object.create(mech, {
    ctx: { value: trackedCaller },
    [ORIGINAL]: { value: mech },
  });
  const events = [];
  proxy.hook('before', input => {
    assert.equal(Object.isFrozen(input), true);
    assert.throws(() => { input.toolName = 'computer_context'; }, TypeError);
    assert.throws(() => { input.forceApproval = false; }, TypeError);
    events.push(['before', input.toolName, input.forceApproval]);
    return undefined;
  }, { order: 0 });
  proxy.hook('replace', (input, next) => {
    assert.equal(Object.isFrozen(input), true);
    assert.throws(() => { input.toolName = 'tampered'; }, TypeError);
    events.push(['replace', input.toolName, input.forceApproval]);
    return next(input);
  }, { order: 0 });
  proxy.hook('after', (result, input) => {
    assert.equal(Object.isFrozen(input), true);
    assert.throws(() => { input.toolName = 'tampered_after'; }, TypeError);
    events.push(['after', input.toolName, input.forceApproval]);
    return result;
  }, { order: 0 });

  const input = { toolName: 'exec_command', forceApproval: true };
  const res = await mech.run(input, x => ({ ok: true, toolName: x.toolName, forceApproval: x.forceApproval }));
  assert.equal(res.toolName, 'exec_command');
  assert.equal(res.forceApproval, true);
  assert.equal(input.toolName, 'exec_command');
  assert.deepEqual(events, [
    ['before', 'exec_command', true],
    ['replace', 'exec_command', true],
    ['after', 'exec_command', true],
  ]);
});

test('ContentInspect v2 validates multimodal packets, stream stages, inducement telemetry, and partial redactions', async () => {
  const {
    CONTENT_INSPECT_V2_PROTOCOL_VERSION,
    buildContentInspectRequest,
    validateContentInspectVerdict,
    applyOutputRedaction,
    classifyIpLiteral,
    assertSafeIntegrationOrigin,
    assertValidPluginNamespace,
    assertValidPluginSecretKey,
    assertValidPluginSecretValue,
    PLUGIN_SECRETS_ADMIN_SERVICE,
    ROOT_ONLY_SERVICES,
  } = await import('../src/index.mjs');

  assert.equal(ROOT_ONLY_SERVICES.includes(PLUGIN_SECRETS_ADMIN_SERVICE), true);
  assert.equal(classifyIpLiteral('::ffff:169.254.169.254'), 'blocked');
  assert.equal(classifyIpLiteral('64:ff9b::10.0.0.1'), 'private');
  assert.equal(classifyIpLiteral('93.184.216.34'), 'public');
  assert.equal(assertSafeIntegrationOrigin('https://api.example.com'), 'https://api.example.com');
  assert.throws(() => assertSafeIntegrationOrigin('https://[::ffff:127.0.0.1]'), /loopback/);
  assert.equal(assertValidPluginNamespace('llm-moderation'), 'llm-moderation');
  assert.throws(() => assertValidPluginNamespace('../escape'), TypeError);
  assert.equal(assertValidPluginSecretKey('OPENAI_API_KEY'), 'OPENAI_API_KEY');
  assert.throws(() => assertValidPluginSecretKey('lowercase_key'), TypeError);
  assert.equal(assertValidPluginSecretValue('secret-val'), 'secret-val');
  assert.throws(() => assertValidPluginSecretValue('bad\0value'), TypeError);

  const req = buildContentInspectRequest({
    protocolVersion: CONTENT_INSPECT_V2_PROTOCOL_VERSION,
    stage: 'stream_chunk',
    requestId: 'stream-req-1',
    streamId: 'st-1',
    seq: 3,
    toolName: 'exec_command',
    modalityPackets: [
      { modality: 'image', refKind: 'inline', mimeType: 'image/png', byteLength: 1024 },
    ],
    payload: { chunk: 'hello' },
  });
  assert.equal(req.protocolVersion, 2);
  assert.equal(req.streamId, 'st-1');
  assert.equal(req.modalityPackets.length, 1);

  assert.throws(() => validateContentInspectVerdict({
    protocolVersion: 2,
    decision: 'escalate',
    categories: ['safety.review'],
  }, { stage: 'stream_chunk' }), /cannot escalate/);

  const partialVerdict = validateContentInspectVerdict({
    protocolVersion: 2,
    decision: 'redact',
    categories: ['safety.image'],
    ruleId: 'MOD-IMG-1',
    inducement: {
      tested: true,
      canaryInduced: false,
      guardPrimaryScore: 0.12,
      canaryOutputRiskScore: 0.05,
      canaryModel: 'qwen-0.5b',
    },
    redactions: [{ index: 1, modality: 'image', replacementText: '[REDACTED_IMAGE: MOD-IMG-1]' }],
  }, { stage: 'output' });
  assert.equal(partialVerdict.inducement.canaryInduced, false);
  assert.equal(partialVerdict.redactions.length, 1);

  const originalReply = {
    jsonrpc: '2.0',
    id: 7,
    result: {
      content: [
        { type: 'text', text: 'safe intro text' },
        { type: 'image', data: 'AAAA', mimeType: 'image/png' },
      ],
      structuredContent: { raw: 'secret' },
    },
  };
  const redactedReply = applyOutputRedaction(originalReply, partialVerdict, { stage: 'output' });
  assert.equal(redactedReply.result.content[0].text, 'safe intro text');
  assert.deepEqual(redactedReply.result.content[1], { type: 'text', text: '[REDACTED_IMAGE: MOD-IMG-1]' });
  assert.equal(redactedReply.result.structuredContent.partiallyRedacted, true);
  assert.deepEqual(redactedReply.result.structuredContent.redactedIndices, [1]);
});

test('assertSafeEndpointUrl & validateModerationConfig support Ollama defaults and opt-in LAN HTTP while still blocking metadata/public HTTP', () => {
  assert.throws(
    () => assertSafeEndpointUrl('http://192.168.1.50:11434', { allowLoopbackHttp: true, allowPrivateNetwork: false }),
    /SSRF|private|loopback/i,
  );
  assert.equal(
    assertSafeEndpointUrl('http://192.168.1.50:11434/api/chat', { allowLoopbackHttp: true, allowPrivateNetwork: true }),
    'http://192.168.1.50:11434/api/chat',
  );
  assert.throws(
    () => assertSafeEndpointUrl('http://169.254.169.254/latest/meta-data/', { allowLoopbackHttp: true, allowPrivateNetwork: true }),
    /SSRF|blocked|metadata/i,
  );
  assert.throws(
    () => assertSafeEndpointUrl('http://93.184.216.34:11434/api/chat', { allowLoopbackHttp: true, allowPrivateNetwork: true }),
    /SSRF|https|public/i,
  );

  const ollamaDefaulted = validateModerationConfig({
    localGuard: { kind: 'ollama', model: 'qwen3.5:9b' },
  });
  assert.equal(ollamaDefaulted.localGuard.kind, 'ollama');
  assert.equal(ollamaDefaulted.localGuard.endpoint, 'http://127.0.0.1:11434/');
  assert.equal(ollamaDefaulted.localGuard.model, 'qwen3.5:9b');
  assert.equal(ollamaDefaulted.localGuard.think, false);
  assert.equal(ollamaDefaulted.localGuard.allowPrivateNetwork, false);

  assert.throws(
    () => validateModerationConfig({
      localGuard: { kind: 'ollama', endpoint: 'http://192.168.1.50:11434', allowPrivateNetwork: false },
    }),
  );

  const lanApproved = validateModerationConfig({
    mode: 'guard-plus-canary',
    localGuard: {
      kind: 'ollama',
      endpoint: 'http://192.168.1.50:11434',
      model: 'llama-guard3:8b',
      think: false,
      allowPrivateNetwork: true,
    },
    canary: {
      enabled: true,
      kind: 'ollama',
      model: 'qwen3:0.6b',
      allowPrivateNetwork: true,
    },
  });
  assert.equal(lanApproved.localGuard.endpoint, 'http://192.168.1.50:11434/');
  assert.equal(lanApproved.localGuard.allowPrivateNetwork, true);
  assert.equal(lanApproved.canary.endpoint, 'http://127.0.0.1:11434/');
  assert.equal(lanApproved.canary.think, false);

  assert.throws(
    () => validateModerationConfig({
      localGuard: { kind: 'ollama', endpoint: 'http://169.254.169.254/latest', allowPrivateNetwork: true },
    }),
  );
});
