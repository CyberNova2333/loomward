import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { TransientReceipts, StopReceipts, RequestReceipts } from '../local/receipts.mjs';
import { digest } from '../local/request-policy.mjs';

const frame = (clientId, id, method = 'ping') => ({ id, authorization: { clientId }, body: { jsonrpc: '2.0', id, method } });

test('ordinary control receipts are fair per client, client-scoped, and bounded after expiry', () => {
  let now = 1000;
  const cache = new TransientReceipts({ now: () => now, maximum: 12, perClientMaximum: 3 });
  const original = frame('noisy-client', 'same-id');
  for (const message of [original, frame('noisy-client', 'second'), frame('noisy-client', 'third')]) assert.equal(cache.claim(message).acquired, true);
  assert.equal(cache.claim(frame('noisy-client', 'fourth')).reason, 'control_client_capacity');
  assert.equal(cache.claim(original).reason, 'already_attempted');
  assert.equal(cache.claim({ ...original, body: { ...original.body, method: 'initialize' } }).reason, 'request_id_conflict');
  assert.equal(cache.claim(frame('independent-client', 'same-id')).acquired, true);
  for (let index = 0; index < 100; index++) cache.claim(frame(`client-${index}`, 'first'));
  assert.equal(cache.records.size, 12);
  assert.ok(cache.clients.size <= 12);
  assert.equal(cache.claim(frame('new-client', 'first')).reason, 'control_capacity');
  now += 120001;
  assert.equal(cache.claim(frame('noisy-client', 'fresh')).acquired, true);
  assert.equal(cache.records.size, 1);
  assert.equal(cache.clients.size, 1);
});

test('stop receipts retain recent duplicate conflicts without a capacity rejection', () => {
  const cache = new StopReceipts({ now: () => 1000, maximum: 2 });
  const original = frame('owner-client', 'stop-1', 'stop_command');
  assert.equal(cache.claim(original).acquired, true);
  assert.equal(cache.claim(original).reason, 'already_attempted');
  assert.equal(cache.claim({ ...original, body: { ...original.body, id: 'changed' } }).reason, 'request_id_conflict');
  for (let index = 0; index < 100; index++) assert.equal(cache.claim(frame(`client-${index}`, `stop-${index}`, 'stop_command')).acquired, true);
  assert.equal(cache.records.size, 2);
  assert.equal(cache.clients.size, 2);
  // The bounded old record has been evicted. A repeated stop is harmless and
  // is still checked against the current job owner by the runtime.
  assert.equal(cache.claim(original).acquired, true);
  assert.equal(cache.records.size, 2);
});

test('RequestReceipts evicts expired entries before enforcing maximum capacity and rejects oversized receipt files', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'agentdock-receipts-test-'));
  t.after(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });
  let now = 1_700_000_000_000;
  const receipts = new RequestReceipts(dir, { now: () => now, maximum: 2 });
  const req1 = { id: 'req-1', authorization: { clientId: 'c1' }, body: { jsonrpc: '2.0', id: '1', method: 'tools/call', params: { name: 'read_file' } } };
  const req2 = { id: 'req-2', authorization: { clientId: 'c1' }, body: { jsonrpc: '2.0', id: '2', method: 'tools/call', params: { name: 'read_file' } } };
  const req3 = { id: 'req-3', authorization: { clientId: 'c1' }, body: { jsonrpc: '2.0', id: '3', method: 'tools/call', params: { name: 'read_file' } } };
  assert.equal((await receipts.claim(req1)).acquired, true);
  assert.equal((await receipts.claim(req2)).acquired, true);
  now += 24 * 60 * 60 * 1000 + 1000;
  // Must evict expired receipts even before next hourly cleanup window elapses.
  assert.equal((await receipts.claim(req3)).acquired, true);

  const oversizedReq = { id: 'req-big', authorization: { clientId: 'c1' }, body: { jsonrpc: '2.0', id: '4', method: 'tools/call', params: { name: 'read_file' } } };
  await fs.writeFile(path.join(receipts.directory, `${digest(oversizedReq.id)}.json`), 'x'.repeat(600));
  assert.deepEqual(await receipts.claim(oversizedReq), { acquired: false, reason: 'duplicate_or_incomplete' });
});
