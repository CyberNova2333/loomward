// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import fs from 'node:fs/promises';
import path from 'node:path';
import https from 'node:https';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { defaultStateDirectory, proxyCandidates } from '../local/connector.mjs';
const exec = promisify(execFile);
const stateDir = defaultStateDirectory();
const config = JSON.parse(await fs.readFile(path.join(stateDir, 'config.json'), 'utf8'));
const manage = action => {
  if (process.platform === 'win32') {
    const shell = path.join(process.env.SystemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    return exec(shell, ['-NoProfile', '-ExecutionPolicy', 'RemoteSigned', '-File', path.join(config.sourceRoot, 'scripts', 'Manage.ps1'), '-Action', action, '-StateDir', stateDir], { timeout: 30000, windowsHide: true });
  }
  const nodeExe = config.nodePath || process.execPath;
  return exec(nodeExe, [path.join(config.sourceRoot, 'scripts', 'host-cli.mjs'), action.toLowerCase(), '--state-dir', stateDir], { timeout: 30000 });
};
function probeHealth(origin, proxy) {
  return new Promise((resolve, reject) => {
    let agent;
    if (proxy) {
      try { agent = new HttpsProxyAgent(proxy); } catch (error) { return reject(error); }
    }
    let settled = false;
    const done = fn => value => { if (!settled) { settled = true; fn(value); } };
    const req = https.get(`${origin.replace(/\/+$/, '')}/healthz`, { timeout: 8000, minVersion: 'TLSv1.2', agent }, res => {
      let text = '';
      res.on('data', chunk => {
        text += chunk;
        if (text.length > 4096) req.destroy(new Error('Health response too large'));
      });
      res.on('end', () => { try { done(resolve)({ status: res.statusCode, body: JSON.parse(text) }); } catch { done(reject)(new Error('Invalid health response')); } });
      res.on('close', () => done(reject)(new Error('Health connection closed')));
      res.on('error', done(reject));
    });
    req.on('timeout', () => req.destroy(new Error('Health timeout')));
    req.on('error', done(reject));
  });
}
export async function health() {
  let lastError = new Error('Health check failed');
  for (const proxy of proxyCandidates(config.origin)) {
    try { return await probeHealth(config.origin, proxy); }
    catch (error) { lastError = error; }
  }
  throw lastError;
}
async function waitHealth(wanted) {
  // Startup may perform three read-only Docker queries, each with one bounded
  // retry. Allow their full budget; shutdown remains deliberately short.
  const deadline = Date.now() + (wanted === 200 ? 210000 : 35000);
  do {
    try { const current = await health(); if (current.status === wanted) return current; } catch {}
    await new Promise(resolve => setTimeout(resolve, 1000));
  } while (Date.now() < deadline);
  throw new Error('Public health did not reach the expected state');
}
const record = { time: new Date().toISOString(), success: false };
try {
  await manage('Stop');
  record.stopped = await waitHealth(503);
  const local = JSON.parse(await fs.readFile(path.join(stateDir, 'connector-status.json'), 'utf8'));
  if (local.online !== false) throw new Error('Local stop not confirmed');
  await manage('Start');
  record.restarted = await waitHealth(200);
  record.success = true;
  console.log('PASS graceful stop -> public 503 -> restart -> public 200');
} finally {
  if (!record.success) await manage('Start').catch(() => {});
  await fs.writeFile(new URL('../artifacts/lifecycle-v2.json', import.meta.url), JSON.stringify(record, null, 2));
}
