// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Out-of-process offline runner for plugins/antileak/engine/check.py (never passes --net, minimal sanitized env, fail-closed).
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { validateContentInspectVerdict } from '@loomward/shared';

const ENGINE_DIR = path.resolve(import.meta.dirname, '..', 'engine');
const DEFAULT_CHECK_SCRIPT = path.join(ENGINE_DIR, 'check.py');
const DEFAULT_POLICY_FILE = path.join(ENGINE_DIR, 'policy.json');
const MAX_INPUT_BYTES = 1024 * 1024;
const MAX_OUTPUT_BYTES = 16384;

function sanitizedChildEnv({ policyPath, cachePath }) {
  const env = {
    PYTHONUTF8: '1',
    PYTHONIOENCODING: 'utf-8',
    LOOMWARD_ANTILEAK_POLICY: policyPath,
    LOOMWARD_ANTILEAK_CACHE: cachePath,
  };
  for (const key of ['PATH', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TMPDIR', 'TEMP', 'TMP', 'SystemRoot', 'WINDIR']) {
    if (typeof process.env[key] === 'string') env[key] = process.env[key];
  }
  return env;
}

function clampReason(raw, fallback) {
  const cleaned = String(raw || '')
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!cleaned) return fallback;
  return cleaned.length > 220 ? `${cleaned.slice(0, 219)}…` : cleaned;
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
      if (!parsed || typeof parsed !== 'object' || parsed.status === 'error') {
        return { status: 'error', expiresAt: null, ageSec: null, sourceCount: 0, patternCount: 0 };
      }
      const nowSec = Math.floor(Date.now() / 1000);
      const exp = Number(parsed.expires_at);
      const gen = Number(parsed.generated_at);
      const fresh = Number.isFinite(exp) && nowSec <= exp;
      return {
        status: fresh ? 'fresh' : Number.isFinite(gen) ? 'stale' : 'error',
        expiresAt: Number.isFinite(exp) ? new Date(exp * 1000).toISOString() : null,
        ageSec: Number.isFinite(gen) ? Math.max(0, nowSec - Math.floor(gen)) : null,
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
    if (!resolvedCache) {
      return Promise.resolve(validateContentInspectVerdict({
        protocolVersion: 1,
        decision: 'block',
        categories: ['antileak.fail_closed'],
        ruleId: 'ANTILEAK-CACHE-UNCONFIGURED',
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
        reason: 'Tool payload exceeds offline anti-leak inspection budget (1 MiB).',
      }, { stage: 'input' }));
    }

    return new Promise(resolve => {
      let settled = false;
      let stdout = '';
      let stderr = '';
      let child;

      const finish = verdict => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (signal && onAbort) signal.removeEventListener('abort', onAbort);
        resolve(validateContentInspectVerdict(verdict, { stage: 'input' }));
      };

      const killChild = () => {
        try { child?.kill('SIGKILL'); } catch {}
      };

      const onAbort = () => {
        killChild();
        finish({
          protocolVersion: 1,
          decision: 'block',
          categories: ['antileak.fail_closed'],
          ruleId: 'ANTILEAK-CANCELLED',
          reason: 'Anti-leak inspection cancelled before completion (fail-closed).',
        });
      };
      if (signal?.aborted) {
        onAbort();
        return;
      }
      if (signal) signal.addEventListener('abort', onAbort, { once: true });

      const timer = setTimeout(() => {
        killChild();
        finish({
          protocolVersion: 1,
          decision: 'block',
          categories: ['antileak.fail_closed'],
          ruleId: 'ANTILEAK-TIMEOUT',
          reason: `Offline anti-leak engine timed out after ${timeoutMs}ms (fail-closed).`,
        });
      }, Math.max(500, timeoutMs));
      timer.unref?.();

      try {
        // Strictly offline: never pass --net; shell: false; zero host credentials in env.
        child = spawn(pythonPath, [checkScriptPath, 'content'], {
          shell: false,
          windowsHide: true,
          env: sanitizedChildEnv({ policyPath: resolvedPolicy, cachePath: resolvedCache }),
          stdio: ['pipe', 'pipe', 'pipe'],
        });
      } catch {
        finish({
          protocolVersion: 1,
          decision: 'block',
          categories: ['antileak.fail_closed'],
          ruleId: 'ANTILEAK-SPAWN-ERROR',
          reason: 'Offline anti-leak engine failed to launch (fail-closed).',
        });
        return;
      }

      child.stdin.on('error', () => {});
      child.stdout.on('data', chunk => {
        if (stdout.length < MAX_OUTPUT_BYTES) stdout += chunk.toString('utf8');
      });
      child.stderr.on('data', chunk => {
        if (stderr.length < MAX_OUTPUT_BYTES) stderr += chunk.toString('utf8');
      });
      child.on('error', () => {
        finish({
          protocolVersion: 1,
          decision: 'block',
          categories: ['antileak.fail_closed'],
          ruleId: 'ANTILEAK-SPAWN-ERROR',
          reason: 'Offline anti-leak engine process failed (fail-closed).',
        });
      });
      child.on('close', code => {
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
          finish({
            protocolVersion: 1,
            decision: 'block',
            categories: ['antileak.violation'],
            ruleId: 'ANTILEAK-R1-R7',
            reason: clampReason(stderr, 'Blocked by offline R1-R7 anti-leak guardrail.'),
          });
          return;
        }
        finish({
          protocolVersion: 1,
          decision: 'block',
          categories: ['antileak.fail_closed'],
          ruleId: /过期|缺失|缓存/.test(stderr) ? 'ANTILEAK-CACHE-STALE' : 'ANTILEAK-ENGINE-ERROR',
          reason: clampReason(stderr, 'Offline anti-leak engine returned error or stale cache (fail-closed).'),
        });
      });

      child.stdin.end(inputBytes);
    });
  }

  return Object.freeze({
    inspectText,
    inspectCacheHealth,
    policyPath: resolvedPolicy,
    cachePath: resolvedCache,
  });
}
