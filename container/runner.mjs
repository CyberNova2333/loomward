// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// PID 1 is a small trusted supervisor. Development commands run as uid/gid 1000.
// Their stdin is never the control pipe; they cannot renew the host's lease.
import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';

export function parseChildId(raw, fallback = 1000) {
  if (raw === undefined || raw === null || raw === '') return fallback;
  const parsed = Number(raw);
  // Never permit UID/GID 0 (PID 1 supervisor) or invalid IDs for child tasks.
  return Number.isSafeInteger(parsed) && parsed > 0 && parsed <= 65534 ? parsed : fallback;
}

function runSupervisor() {
  let child, started = false, lastLease = performance.now(), timer, drainTimer;
  const childUid = parseChildId(process.env.AGENTDOCK_CHILD_UID, 1000);
  const childGid = parseChildId(process.env.AGENTDOCK_CHILD_GID, 1000);
  const finish = code => process.exit(Number.isInteger(code) ? Math.max(0, Math.min(255, code)) : 1);
  const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  const lease = setInterval(() => { if (performance.now() - lastLease > 20000) finish(125); }, 2000);
  process.on('SIGTERM', () => finish(143));
  process.on('SIGINT', () => finish(130));
  lines.on('close', () => finish(125));
  lines.on('line', line => {
    if (Buffer.byteLength(line) > 1400000) return finish(125);
    let message;
    try { message = JSON.parse(line); } catch { return finish(125); }
    if (started) { if (message.type === 'lease') lastLease = performance.now(); return; }
    started = true;
    if (!['file', 'command'].includes(message.kind) || !Number.isSafeInteger(message.timeout) || message.timeout < 100 || message.timeout > 3600000) return finish(125);
    const executable = message.kind === 'file' ? '/usr/local/bin/node' : '/bin/bash';
    const args = message.kind === 'file' ? ['/opt/bridge/container/file-worker.mjs'] : ['--noprofile', '--norc', '-c', message.cmd];
    const cwd = message.cwd || '/workspace';
    if (typeof cwd !== 'string' || !(cwd === '/workspace' || cwd.startsWith('/workspace/')) || cwd.split('/').includes('..')) return finish(125);
    const env = { PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', HOME: '/home/developer', LANG: 'C.UTF-8', NO_COLOR: '1', PYTHONUNBUFFERED: '1', GOTOOLCHAIN: 'local', GOPATH: '/home/developer/go', GOCACHE: '/home/developer/.cache/go-build', CARGO_HOME: '/home/developer/.cargo', WRANGLER_SEND_METRICS: 'false' };
    child = spawn(executable, args, { cwd, uid: childUid, gid: childGid, env, stdio: ['pipe', 'pipe', 'pipe'] });
    child.stdout.pipe(process.stdout); child.stderr.pipe(process.stderr);
    child.once('error', () => finish(126));
    // Flush complete output when possible. Descendants retaining output pipes get
    // at most one second; a forced drain expiry reports failure instead of success.
    child.once('exit', () => { drainTimer = setTimeout(() => finish(125), 1000); });
    child.once('close', (code, signal) => {
      clearTimeout(timer); clearTimeout(drainTimer); clearInterval(lease);
      const exitCode = code !== null ? code : (signal && os.constants.signals[signal] ? 128 + os.constants.signals[signal] : 1);
      const fallback = setTimeout(() => finish(125), 1000);
      process.stdout.write('', () => process.stderr.write('', () => { clearTimeout(fallback); finish(exitCode); }));
    });
    child.stdin.on('error', () => {});
    child.stdin.end(message.kind === 'file' ? JSON.stringify(message.body) : undefined);
    timer = setTimeout(() => finish(124), message.timeout);
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename)) {
  runSupervisor();
}
