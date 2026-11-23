// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Out-of-process offline runner for plugins/antileak/engine/check.py (never passes --net, minimal sanitized env, fail-closed).
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { StringDecoder } from 'node:string_decoder';
import { validateContentInspectVerdict } from '@loomward/shared';

const ENGINE_DIR = path.resolve(import.meta.dirname, '..', 'engine');
const DEFAULT_CHECK_SCRIPT = path.join(ENGINE_DIR, 'check.py');
const DEFAULT_POLICY_FILE = path.join(ENGINE_DIR, 'policy.json');
const DEFAULT_REFRESH_SCRIPT = path.join(ENGINE_DIR, 'refresh-private.py');
const DEFAULT_RESOLVE_SCRIPT = path.join(ENGINE_DIR, 'resolve-private.py');
export const MAX_INPUT_BYTES = 1024 * 1024;
const MAX_OUTPUT_BYTES = 16384;

function sanitizedChildEnv({ policyPath, cachePath }) {
  const env = {
    PYTHONUTF8: '1',
    PYTHONIOENCODING: 'utf-8',
    PYTHONDONTWRITEBYTECODE: '1',
    LOOMWARD_ANTILEAK_POLICY: policyPath,
    LOOMWARD_ANTILEAK_CACHE: cachePath,
    LOOMWARD_ANTILEAK_REFRESH: DEFAULT_REFRESH_SCRIPT,
    LOOMWARD_ANTILEAK_RESOLVE: DEFAULT_RESOLVE_SCRIPT,
  };
  for (const key of ['PATH', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TMPDIR', 'TEMP', 'TMP', 'SystemRoot', 'WINDIR']) {
    if (typeof process.env[key] === 'string') env[key] = process.env[key];
  }
  return env;
}

function classifyViolationFromStderr(rawStderr) {
  const text = String(rawStderr || '');
  if (/私有仓名|R1/i.test(text)) {
    return {
      ruleId: 'ANTILEAK-R1',
      reason: 'Blocked by offline anti-leak guardrail (R1 private repository reference).',
    };
  }
  if (/业务标识|R4/i.test(text)) {
    return {
      ruleId: 'ANTILEAK-R4',
      reason: 'Blocked by offline anti-leak guardrail (R4 internal business identifier).',
    };
  }
  if (/凭据|secret|token|R7/i.test(text)) {
    return {
      ruleId: 'ANTILEAK-R7',
      reason: 'Blocked by offline anti-leak guardrail (R7 credential or secret pattern).',
    };
  }
  return {
    ruleId: 'ANTILEAK-R1-R7',
    reason: 'Blocked by offline R1-R7 anti-leak guardrail.',
  };
}

export function createAntileakEngineRunner({
  pythonPath = process.platform === 'win32' ? 'python' : 'python3',
  checkScriptPath = DEFAULT_CHECK_SCRIPT,
  policyPath = DEFAULT_POLICY_FILE,
  cachePath,
  timeoutMs = 5000,
} = {}) {
  const resolvedPolicy = path.resolve(policyPath);
  const resolvedCache = cachePath ? path.resolve(cachePath) : '';
  const boundedTimeoutMs = Number.isFinite(Number(timeoutMs)) ? Math.max(500, Math.trunc(Number(timeoutMs))) : 5000;
  const activeChildren = new Set();
  let closed = false;

  function inspectCacheHealth() {
    if (!resolvedCache) {
      return { status: 'missing', expiresAt: null, ageSec: null, sourceCount: 0, patternCount: 0 };
    }
    let fd;
    try {
      fd = fs.openSync(resolvedCache, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    } catch (err) {
      return {
        status: err?.code === 'ENOENT' ? 'missing' : 'error',
        expiresAt: null,
        ageSec: null,
        sourceCount: 0,
        patternCount: 0,
      };
    }
    try {
      const st = fs.fstatSync(fd);
      if (!st.isFile() || st.size > 4 * 1024 * 1024) {
        return { status: 'error', expiresAt: null, ageSec: null, sourceCount: 0, patternCount: 0 };
      }
      const parsed = JSON.parse(fs.readFileSync(fd, 'utf8'));
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || parsed.status === 'error') {
        return { status: 'error', expiresAt: null, ageSec: null, sourceCount: 0, patternCount: 0 };
      }
      const nowSec = Math.floor(Date.now() / 1000);
      const hasExp = typeof parsed.expires_at === 'number' && Number.isFinite(parsed.expires_at);
      const hasGen = typeof parsed.generated_at === 'number' && Number.isFinite(parsed.generated_at);
      const fresh = hasExp && nowSec <= parsed.expires_at;
      return {
        status: fresh ? 'fresh' : hasGen ? 'stale' : 'error',
        expiresAt: hasExp ? new Date(parsed.expires_at * 1000).toISOString() : null,
        ageSec: hasGen ? Math.max(0, nowSec - Math.floor(parsed.generated_at)) : null,
        sourceCount: Array.isArray(parsed.sources) ? parsed.sources.length : 0,
        patternCount: Array.isArray(parsed.patterns) ? parsed.patterns.length : 0,
      };
    } catch {
      return { status: 'error', expiresAt: null, ageSec: null, sourceCount: 0, patternCount: 0 };
    } finally {
      try { fs.closeSync(fd); } catch {}
    }
  }

  function inspectText(text, { signal } = {}) {
    if (closed) {
      return Promise.resolve(validateContentInspectVerdict({
        protocolVersion: 1,
        decision: 'block',
        categories: ['antileak.fail_closed'],
        ruleId: 'ANTILEAK-CLOSED',
        failClosed: true,
        reason: 'Anti-leak engine runner is closed (fail-closed).',
      }, { stage: 'input' }));
    }
    if (signal?.aborted) {
      return Promise.resolve(validateContentInspectVerdict({
        protocolVersion: 1,
        decision: 'block',
        categories: ['antileak.fail_closed'],
        ruleId: 'ANTILEAK-CANCELLED',
        failClosed: true,
        reason: 'Anti-leak inspection cancelled before completion (fail-closed).',
      }, { stage: 'input' }));
    }
    if (!resolvedCache) {
      return Promise.resolve(validateContentInspectVerdict({
        protocolVersion: 1,
        decision: 'block',
        categories: ['antileak.fail_closed'],
        ruleId: 'ANTILEAK-CACHE-UNCONFIGURED',
        failClosed: true,
        reason: 'Anti-leak private repository cache path is not configured (fail-closed).',
      }, { stage: 'input' }));
    }

    const inputText = typeof text === 'string' ? text : '';
    const inputBytes = Buffer.from(inputText, 'utf8');
    if (inputBytes.length > MAX_INPUT_BYTES) {
      return Promise.resolve(validateContentInspectVerdict({
        protocolVersion: 1,
        decision: 'block',
        categories: ['antileak.fail_closed'],
        ruleId: 'ANTILEAK-INPUT-TOO-LARGE',
        failClosed: true,
        reason: 'Tool payload exceeds offline anti-leak inspection budget (1 MiB).',
      }, { stage: 'input' }));
    }

    return new Promise(resolve => {
      let settled = false;
      let stdout = '';
      let stderr = '';
      let stdoutBytes = 0;
      let stderrBytes = 0;
      const outDecoder = new StringDecoder('utf8');
      const errDecoder = new StringDecoder('utf8');
      let child = null;
      let timer = null;

      const killChild = () => {
        if (!child) return;
        activeChildren.delete(child);
        try { child.kill('SIGKILL'); } catch {}
      };

      const finish = verdict => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        if (child) activeChildren.delete(child);
        if (signal && onAbort) signal.removeEventListener('abort', onAbort);
        resolve(validateContentInspectVerdict(verdict, { stage: 'input' }));
      };

      const onAbort = () => {
        killChild();
        finish({
          protocolVersion: 1,
          decision: 'block',
          categories: ['antileak.fail_closed'],
          ruleId: 'ANTILEAK-CANCELLED',
          failClosed: true,
          reason: 'Anti-leak inspection cancelled before completion (fail-closed).',
        });
      };
      if (signal?.aborted) {
        onAbort();
        return;
      }
      if (signal) signal.addEventListener('abort', onAbort, { once: true });

      timer = setTimeout(() => {
        killChild();
        finish({
          protocolVersion: 1,
          decision: 'block',
          categories: ['antileak.fail_closed'],
          ruleId: 'ANTILEAK-TIMEOUT',
          failClosed: true,
          reason: `Offline anti-leak engine timed out after ${boundedTimeoutMs}ms (fail-closed).`,
        });
      }, boundedTimeoutMs);
      timer.unref?.();

      try {
        // Strictly offline: never pass --net; -B prevents bytecode pollution; shell: false; zero host credentials in env.
        child = spawn(pythonPath, ['-B', checkScriptPath, 'content'], {
          shell: false,
          windowsHide: true,
          env: sanitizedChildEnv({ policyPath: resolvedPolicy, cachePath: resolvedCache }),
          stdio: ['pipe', 'pipe', 'pipe'],
        });
        activeChildren.add(child);
      } catch {
        finish({
          protocolVersion: 1,
          decision: 'block',
          categories: ['antileak.fail_closed'],
          ruleId: 'ANTILEAK-SPAWN-ERROR',
          failClosed: true,
          reason: 'Offline anti-leak engine failed to launch (fail-closed).',
        });
        return;
      }

      child.stdin.on('error', () => {});
      child.stdout.on('data', chunk => {
        if (stdoutBytes >= MAX_OUTPUT_BYTES) return;
        const slice = chunk.length > MAX_OUTPUT_BYTES - stdoutBytes
          ? chunk.subarray(0, MAX_OUTPUT_BYTES - stdoutBytes)
          : chunk;
        stdoutBytes += slice.length;
        stdout += outDecoder.write(slice);
      });
      child.stderr.on('data', chunk => {
        if (stderrBytes >= MAX_OUTPUT_BYTES) return;
        const slice = chunk.length > MAX_OUTPUT_BYTES - stderrBytes
          ? chunk.subarray(0, MAX_OUTPUT_BYTES - stderrBytes)
          : chunk;
        stderrBytes += slice.length;
        stderr += errDecoder.write(slice);
      });
      child.on('error', () => {
        finish({
          protocolVersion: 1,
          decision: 'block',
          categories: ['antileak.fail_closed'],
          ruleId: 'ANTILEAK-SPAWN-ERROR',
          failClosed: true,
          reason: 'Offline anti-leak engine process failed (fail-closed).',
        });
      });
      child.on('close', code => {
        stdout += outDecoder.end();
        stderr += errDecoder.end();
        const status = stdout.trim().split(/\s+/)[0] || '';
        if (code === 0 && status === 'pass') {
          finish({
            protocolVersion: 1,
            decision: 'allow',
            categories: [],
          });
          return;
        }
        if (status === 'violation') {
          const classified = classifyViolationFromStderr(stderr);
          finish({
            protocolVersion: 1,
            decision: 'block',
            categories: ['antileak.violation'],
            ruleId: classified.ruleId,
            failClosed: false,
            reason: classified.reason,
          });
          return;
        }
        const isCacheStale = /过期|缺失|缓存/.test(stderr);
        finish({
          protocolVersion: 1,
          decision: 'block',
          categories: ['antileak.fail_closed'],
          ruleId: isCacheStale ? 'ANTILEAK-CACHE-STALE' : 'ANTILEAK-ENGINE-ERROR',
          failClosed: true,
          reason: isCacheStale
            ? 'Offline anti-leak private repository cache is missing or expired (fail-closed).'
            : 'Offline anti-leak engine returned an internal verification error (fail-closed).',
        });
      });

      child.stdin.end(inputBytes);
    });
  }

  async function close() {
    closed = true;
    for (const proc of [...activeChildren]) {
      activeChildren.delete(proc);
      try { proc.kill('SIGKILL'); } catch {}
    }
  }

  return Object.freeze({
    inspectText,
    inspectCacheHealth,
    close,
    policyPath: resolvedPolicy,
    cachePath: resolvedCache,
  });
}
