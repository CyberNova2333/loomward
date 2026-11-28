// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createInjectionAlertStore } from '../local/injection-alerts.mjs';
import { digest } from '../local/request-policy.mjs';
import { validateModerationConfig } from '../packages/shared/src/moderation-config.mjs';

const limits = { clientThreshold: 2, globalThreshold: 3 };
const windowMs = 600_000;
const event = (client, requestId, extra = {}) => ({
  clientRef: digest(client), requestId, toolName: 'read_file',
  stage: 'input', source: 'input', rule: 'prompt.injection', action: 'block', ...extra,
});

test('existing moderation configs get independent limits and invalid thresholds are rejected', () => {
  assert.deepEqual(validateModerationConfig({}).injectionAlerts, { clientThreshold: 3, globalThreshold: 10 });
  assert.deepEqual(validateModerationConfig({ injectionAlerts: { globalThreshold: 2 } }).injectionAlerts, { clientThreshold: 3, globalThreshold: 2 });
  for (const value of [null, [], { clientThreshold: 0 }, { globalThreshold: 1001 }, { clientThreshold: '2' }, { globalThreshold: 1.5 }]) {
    assert.throws(() => validateModerationConfig({ injectionAlerts: value }), /injectionAlerts/);
  }
});

test('windows deduplicate requests across stages and retries; each scope re-arms on its own expiry', t => {
  let time = 1000;
  const store = createInjectionAlertStore({ now: () => time });
  t.after(() => store.close());
  const record = (client, id, extra) => store.record(event(client, id, extra), limits);
  record('A', 'first');
  time += 100;
  record('A', 'second');
  const firstId = store.snapshot().items[0].id;
  record('A', 'second', { stage: 'stream_chunk', source: 'output', rule: 'prompt.indirect_injection', action: 'redact' });
  record('A', 'second', { stage: 'stream_end', source: 'output' });
  assert.deepEqual(store.snapshot().items.map(i => [i.id, i.count, i.inputs, i.outputs]), [[firstId, 2, 2, 1]]);
  record('B', 'second'); // Distinct authenticated client using the same envelope ID.
  let global = store.snapshot().items.find(i => i.scope === 'global');
  assert.equal(global.clients, 2);
  assert.equal(global.count, 3);
  time = 1000 + windowMs;
  assert.equal(store.snapshot().activeCount, 0);
  record('A', 'first', { source: 'output', stage: 'stream_chunk' });
  assert.equal(store.snapshot().activeCount, 0, 'late retry must not start a new episode');
  record('A', 'third');
  const reopened = store.snapshot();
  assert.equal(reopened.activeCount, 2);
  assert.equal(reopened.items.filter(i => !i.active).length, 2);
  assert.ok(reopened.items.some(i => i.scope === 'global' && i.active && i.id !== global.id));
  time += 1;
  record('B', 'fourth');
  global = store.snapshot().items.find(i => i.scope === 'global' && i.active);
  assert.equal(global.count, 4);
  assert.equal(store.snapshot().items.filter(i => i.scope === 'global').length, 2);
  time += 24 * 3600_000;
  assert.deepEqual(store.snapshot(), { activeCount: 0, items: [] });
});

test('separate readers and restarted writers share deduplication and only store sanitized fields', t => {
  const stateDir = fs.mkdtempSync(path.join(os.homedir(), '.loomward-alert-test-'));
  const reader = createInjectionAlertStore({ stateDir, readOnly: true });
  let writer = createInjectionAlertStore({ stateDir });
  t.after(() => { reader.close(); writer.close(); fs.rmSync(stateDir, { recursive: true, force: true }); });
  assert.deepEqual(reader.snapshot().items, []);
  const input = event('private-client-id', 'private-request-id', {
    toolName: 'private-tool-name', reason: 'private-reason', prompt: 'private-prompt',
  });
  writer.record(input, limits);
  writer.close();
  writer = createInjectionAlertStore({ stateDir });
  writer.record(input, limits);
  assert.deepEqual(reader.snapshot().items, []);
  writer.record({ ...input, requestId: 'another-request' }, limits);
  const [alert] = reader.snapshot().items;
  assert.equal(alert.count, 2);
  assert.equal(alert.samples[1].request, digest(input.requestId));
  assert.match(alert.samples[1].tool, /^tool-[a-f0-9]+$/);
  assert.doesNotMatch(JSON.stringify(alert), /private-/);
  const file = path.join(stateDir, 'injection-alerts.sqlite');
  assert.doesNotMatch(fs.readFileSync(file).toString('latin1'), /private-/);
  assert.throws(() => createInjectionAlertStore({ stateDir, workspaceRoots: [stateDir], readOnly: true }).snapshot());
  reader.close();
  writer.close();
  fs.linkSync(file, path.join(stateDir, 'alias'));
  assert.throws(() => reader.snapshot());
});

test('editing one threshold applies on new hits without reopening the other scope', t => {
  const store = createInjectionAlertStore({});
  t.after(() => store.close());
  const initial = { clientThreshold: 1, globalThreshold: 2 };
  store.record(event('client', 'first'), initial);
  store.record(event('client', 'second'), initial);
  const first = store.snapshot().items;
  const globalId = first.find(item => item.scope === 'global').id;
  const next = { ...initial, clientThreshold: 4 };
  store.record(event('client', 'third'), next);
  assert.deepEqual(store.snapshot().items.filter(item => item.active).map(item => item.id), [globalId]);
  store.record(event('client', 'fourth'), next);
  const newClient = store.snapshot().items.find(item => item.scope === 'client' && item.active);
  assert.equal(newClient.threshold, 4);
  assert.equal(newClient.count, 4);
  assert.notEqual(newClient.id, first.find(item => item.scope === 'client').id);
});

test('a distributed spike not reaching any individual limit triggers just the global alert', t => {
  const store = createInjectionAlertStore({});
  t.after(() => store.close());
  for (const client of ['one', 'two', 'three']) store.record(event(client, 'request'), limits);
  const { activeCount, items } = store.snapshot();
  assert.equal(activeCount, 1);
  assert.equal(items[0].scope, 'global');
  assert.equal(items[0].clients, 3);
});
