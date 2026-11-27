// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import test from 'node:test';
import { verifyDockerReadiness } from '../tools/acceptance/docker-readiness.mjs';

const image = 'sha256:' + 'a'.repeat(64);
const localContext = JSON.stringify([{ Endpoints: { docker: { Host: 'unix:///rd/docker.sock' } } }]);
const cliError = stderr => Object.assign(new Error('Docker CLI failed'), { stderr });

function probe(replies, options = {}, context = 'default') {
  const calls = [];
  const metrics = { contextAttempts: 0, engineAttempts: 0, waitMs: 0 };
  const query = (args, timeout) => {
    calls.push({ args, timeout });
    const reply = replies.shift();
    if (reply instanceof Error) throw reply;
    assert.notEqual(reply, undefined, 'unexpected Docker command');
    return reply;
  };
  const done = verifyDockerReadiness({ query, metrics, image, context }, { retryMs: 1, ...options });
  return { calls, metrics, done };
}

test('a cold local engine retries version before inspecting the pinned image once', async () => {
  const run = probe([cliError('context not found'), localContext, cliError('open //./pipe/docker_engine: The system cannot find the file specified.'),
    Object.assign(new Error(), { code: 'ETIMEDOUT' }), '29.9.2', image]);
  await run.done;
  assert.deepEqual(run.calls.map(({ args }) => args), [
    ...Array(2).fill(['context', 'inspect', 'default']), ...Array(3).fill(['version', '--format', '{{.Server.Version}}']),
    ['image', 'inspect', image, '--format', '{{.Id}}'],
  ]);
  assert.equal(run.metrics.contextAttempts, 2);
  assert.equal(run.metrics.engineAttempts, 3);
  assert.ok(run.metrics.waitMs >= 0);
});

test('a stalled local engine is bounded by one deadline; each probe uses the remaining time', async () => {
  const run = probe([localContext, cliError('connection refused')], { timeoutMs: 25, retryMs: 100 });
  await assert.rejects(run.done, { code: 'DOCKER_ENGINE_TIMEOUT' });
  assert.deepEqual(run.calls.map(({ args }) => args[0]), ['context', 'version']);
  assert.ok(run.calls[1].timeout > 0 && run.calls[1].timeout <= 25);
  assert.ok(run.metrics.waitMs >= 24);
});

test('invalid context names, unknown contexts and remote endpoints fail before engine access', async () => {
  for (const [context, replies] of [
    ['--debug', []], [null, []], ['missing', [cliError('context not found')]],
    ['remote', [JSON.stringify([{ Endpoints: { docker: { Host: 'tcp://remote:2375' } } }])]],
  ]) {
    const run = probe([...replies], { timeoutMs: 40, retryMs: 100 }, context);
    await assert.rejects(run.done, { code: 'DOCKER_CONTEXT_INVALID' });
    assert.equal(run.calls.length, replies.length);
    assert.equal(run.metrics.contextAttempts, replies.length);
    assert.equal(run.metrics.engineAttempts, 0);
  }
});

test('permanent CLI, access and image errors keep distinct causes without startup retries', async () => {
  for (const [replies, code] of [
    [[Object.assign(new Error(), { code: 'ENOENT' })], 'DOCKER_CLI_UNAVAILABLE'],
    [[localContext, cliError('cannot connect to the Docker daemon: permission denied')], 'DOCKER_ENGINE_QUERY_FAILED'],
    [[localContext, '29.9.2', cliError('Error: No such image: test')], 'DOCKER_IMAGE_MISSING'],
    [[localContext, '29.9.2', 'sha256:' + 'b'.repeat(64)], 'DOCKER_IMAGE_MISMATCH'],
    [[localContext, '29.9.2', cliError('connection reset')], 'DOCKER_IMAGE_INSPECT_FAILED'],
  ]) {
    const run = probe([...replies]);
    await assert.rejects(run.done, { code });
    assert.equal(run.calls.length, replies.length);
  }
});
