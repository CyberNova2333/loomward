import test from 'node:test';
import assert from 'node:assert/strict';
import { isLocalDockerEndpoint, queryDockerState } from '../local/docker-query.mjs';

test('a timed-out read-only Docker query can recover once with a bounded deadline', async () => {
  const calls = [];
  const result = await queryDockerState(async (args, timeout) => {
    calls.push({ args, timeout });
    if (calls.length === 1) throw Object.assign(new Error('query timeout'), { killed: true, signal: 'SIGTERM' });
    return { stdout: 'container-id' };
  }, ['ps', '-aq']);
  assert.equal(result.stdout, 'container-id');
  assert.deepEqual(calls.map(call => call.timeout), [30000, 30000]);
});

test('Docker retries remain bounded and do not hide permanent failures or repeat mutations', async () => {
  let attempts = 0;
  await assert.rejects(queryDockerState(async () => { attempts++; throw Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }); }, ['context', 'inspect', 'desktop-linux']), /timeout/);
  assert.equal(attempts, 2);
  attempts = 0;
  await assert.rejects(queryDockerState(async () => { attempts++; throw new Error('image missing'); }, ['image', 'inspect', 'missing']), /image missing/);
  assert.equal(attempts, 1);
  for (const operation of ['create', 'start', 'rm', 'exec', 'run']) {
    await assert.rejects(queryDockerState(async () => { throw new Error('must not run'); }, [operation, 'test']), /Only read-only/);
  }
});

test('Docker contexts must resolve to a host-local socket or Windows pipe', () => {
  assert.ok(isLocalDockerEndpoint('unix:///Users/test account/.rd/docker.sock', 'darwin'));
  assert.ok(isLocalDockerEndpoint('npipe:////./pipe/docker_engine', 'win32'));
  for (const endpoint of ['unix:///', 'unix:////server/share', 'npipe:////server/pipe/docker_engine', 'npipe:////./pipe/', 'tcp://localhost:2375']) {
    assert.equal(isLocalDockerEndpoint(endpoint, 'win32'), false);
  }
  assert.equal(isLocalDockerEndpoint('npipe:////./pipe/docker_engine', 'linux'), false);
});
