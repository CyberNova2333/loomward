// SPDX-License-Identifier: AGPL-3.0-only
import { setTimeout as sleep } from 'node:timers/promises';
import { isLocalDockerEndpoint } from '../../local/docker-query.mjs';

function failure(code) {
  return Object.assign(new Error(code), { code });
}

function engineStarting(error) {
  if (error.code === 'ETIMEDOUT') return true;
  const detail = String(error.stderr ?? '');
  if (/permission denied|access is denied/i.test(detail)) return false;
  return /cannot connect to the Docker daemon|connection refused|connection reset|no such file or directory|system cannot find the (file|path) specified|context deadline exceeded|i\/o timeout|service unavailable|\bEOF\b/i.test(detail);
}

// Inspect the context locally before the first command that contacts a daemon.
export async function verifyDockerReadiness({ context, image, query, metrics }, { timeoutMs = 180000, retryMs = 2000 } = {}) {
  if (typeof context !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(context)) throw failure('DOCKER_CONTEXT_INVALID');
  const start = performance.now();
  const deadline = start + timeoutMs;
  async function waitFor(probe, timeoutCode) {
    while (true) {
      const remaining = Math.floor(deadline - performance.now());
      if (remaining <= 0) throw failure(timeoutCode);
      if (probe(Math.min(5000, remaining))) return;
      await sleep(Math.min(retryMs, Math.max(0, Math.ceil(deadline - performance.now()))));
    }
  }

  try {
    await waitFor(timeout => {
      metrics.contextAttempts++;
      let inspected;
      try {
        inspected = JSON.parse(query(['context', 'inspect', context], timeout));
      } catch (error) {
        if (['ENOENT', 'EACCES', 'EPERM'].includes(error.code)) throw failure('DOCKER_CLI_UNAVAILABLE');
        // Desktop engines can create the named context during startup.
        if (/context not found/i.test(String(error.stderr ?? '')) || error.code === 'ETIMEDOUT') return false;
        throw failure('DOCKER_CONTEXT_INVALID');
      }
      if (!isLocalDockerEndpoint(inspected?.[0]?.Endpoints?.docker?.Host)) throw failure('DOCKER_CONTEXT_INVALID');
      return true;
    }, 'DOCKER_CONTEXT_INVALID');

    await waitFor(timeout => {
      metrics.engineAttempts++;
      let version;
      try {
        version = query(['version', '--format', '{{.Server.Version}}'], timeout);
      } catch (error) {
        if (engineStarting(error)) return false;
        throw failure('DOCKER_ENGINE_QUERY_FAILED');
      }
      if (!version) throw failure('DOCKER_ENGINE_QUERY_FAILED');
      return true;
    }, 'DOCKER_ENGINE_TIMEOUT');
  } finally {
    metrics.waitMs = Math.round(performance.now() - start);
  }

  let actual;
  try {
    actual = query(['image', 'inspect', image, '--format', '{{.Id}}'], 15000);
  } catch (error) {
    if (/no such (image|object)\b/i.test(String(error.stderr ?? ''))) throw failure('DOCKER_IMAGE_MISSING');
    throw failure('DOCKER_IMAGE_INSPECT_FAILED');
  }
  if (actual !== image) throw failure('DOCKER_IMAGE_MISMATCH');
}
