// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import https from 'node:https';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { computeManifestHash } from '../packages/shared/src/index.mjs';
import { cloudflare } from './cloudflare-api.mjs';
import { buildReleaseRpm } from './generate-rpm.mjs';
import { defaultStateDirectory, proxyCandidates } from '../local/connector.mjs';
const exec = promisify(execFile);
const readRegularBuffer = async filePath => {
  const handle = await fs.open(filePath, fsSync.constants.O_RDONLY | (fsSync.constants.O_NOFOLLOW || 0));
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) {
      throw new Error(`Expected regular file: ${filePath}`);
    }
    const chunks = [];
    const buf = Buffer.allocUnsafe(65536);
    while (true) {
      const { bytesRead } = await handle.read(buf, 0, buf.length, null);
      if (bytesRead === 0) break;
      chunks.push(Buffer.from(buf.subarray(0, bytesRead)));
    }
    return Buffer.concat(chunks);
  } finally {
    await handle.close();
  }
};
const sha256Buffer = buf => crypto.createHash('sha256').update(buf).digest('hex');
const sha256File = async filePath => sha256Buffer(await readRegularBuffer(filePath));
function assertSafeSourceChild(resolvedSourceRoot, relative) {
  if (!relative || typeof relative !== 'string' || relative.includes('\0') || path.isAbsolute(relative)) {
    throw new Error(`Invalid installed runtime path: '${String(relative)}'`);
  }
  const normalized = relative.replaceAll('\\', '/');
  const segments = normalized.split('/');
  if (segments.some(seg => !seg || seg === '.' || seg === '..')) {
    throw new Error(`Invalid installed runtime path: '${relative}'`);
  }
  const candidate = path.resolve(resolvedSourceRoot, ...segments);
  const rel = path.relative(resolvedSourceRoot, candidate);
  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new Error(`Installed runtime path escapes sourceRoot: '${relative}'`);
  }
  return candidate;
}
const MAX_HEALTH_BYTES = 1024 * 1024;
const probeHealth = async origin => {
  const url = `${origin.replace(/\/+$/, '')}/healthz`;
  let lastError = new Error('Health request failed');
  for (const proxy of proxyCandidates(origin)) {
    try {
      return await new Promise((resolve, reject) => {
        let agent;
        if (proxy) agent = new HttpsProxyAgent(proxy);
        let settled = false;
        const done = fn => value => { if (!settled) { settled = true; fn(value); } };
        const req = https.get(url, { timeout: 15000, minVersion: 'TLSv1.2', agent }, res => {
          const chunks = [];
          let bytes = 0;
          res.on('data', chunk => {
            bytes += chunk.length;
            if (bytes > MAX_HEALTH_BYTES) { req.destroy(new Error('Health response exceeds byte limit')); return; }
            chunks.push(chunk);
          });
          res.on('end', () => { try { done(resolve)({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }); } catch { done(reject)(new Error('Invalid health')); } });
          res.on('close', () => done(reject)(new Error('Health connection closed')));
          res.on('error', done(reject));
        });
        req.on('error', done(reject));
        req.on('timeout', () => req.destroy(new Error('Health timeout')));
      });
    } catch (error) { lastError = error; }
  }
  throw lastError;
};
const root = path.resolve(import.meta.dirname, '..');
const stateDir = defaultStateDirectory();
const config = JSON.parse(await fs.readFile(path.join(stateDir, 'config.json'), 'utf8'));
const installation = JSON.parse(await fs.readFile(path.join(stateDir, 'installation.json'), 'utf8'));
const acceptance = JSON.parse(await fs.readFile(path.join(root, 'artifacts/acceptance-v2-result.json'), 'utf8'));
const lifecycle = JSON.parse(await fs.readFile(path.join(root, 'artifacts/lifecycle-v2.json'), 'utf8'));
const testOutput = await fs.readFile(path.join(root, process.env.AGENTDOCK_TEST_REPORT || 'artifacts/fix-round5/final-tests.txt'), 'utf8');
const passed = Number(testOutput.match(/pass (\d+)/)?.[1]);
const failed = Number(testOutput.match(/fail (\d+)/)?.[1]);
const skipped = Number(testOutput.match(/skipped (\d+)/)?.[1]);
const cancelled = Number(testOutput.match(/cancelled (\d+)/)?.[1]);
if (!acceptance.success || !lifecycle.success || !passed || failed !== 0 || skipped !== 0 || cancelled !== 0) throw new Error('Verification is incomplete');
if (!config.nodeRoot || !/^[a-f0-9]{64}$/.test(config.nodeSha256 || '') || await sha256File(config.nodePath) !== config.nodeSha256) throw new Error('Private Node integrity verification failed');
const [account] = process.argv.slice(2);
if (!/^[a-f0-9]{32}$/.test(account || '')) throw new Error('Usage: node scripts/record-hardening.mjs <cloudflare-account-id>');
const hostname = new URL(config.origin).hostname;
const [domains, deployments] = await Promise.all([
  cloudflare(`/accounts/${account}/workers/domains`),
  cloudflare(`/accounts/${account}/workers/scripts/agentdock-bridge/deployments`),
]);
if (!domains.some(domain => domain.hostname === hostname && domain.service === 'agentdock-bridge')) throw new Error('Domain binding mismatch');
const health = await probeHealth(config.origin);
if (health.status !== 200 || !health.body.connectorOnline) throw new Error('Public connector is offline');
const hashes = {};
async function walk(directory) {
  for (const item of await fs.readdir(directory, { withFileTypes: true })) {
    if (['node_modules', '.git', '.wrangler', 'artifacts'].includes(item.name)) continue;
    const file = path.join(directory, item.name);
    if (item.isDirectory()) await walk(file);
    else if (item.isFile()) hashes[path.relative(root, file).replaceAll('\\', '/')] = await sha256File(file);
  }
}
await walk(root);
const resolvedSourceRoot = path.resolve(config.sourceRoot);
let sawRpmManifest = false;
for (const [relative, hash] of Object.entries(installation.sha256)) {
  const normRel = relative.replaceAll('\\', '/');
  const installed = assertSafeSourceChild(resolvedSourceRoot, relative);
  if (normRel === 'rpm.json') {
    sawRpmManifest = true;
    const rawRpm = await readRegularBuffer(installed);
    if (sha256Buffer(rawRpm) !== hash) throw new Error('Installed runtime integrity mismatch');
    const installedRpm = JSON.parse(rawRpm.toString('utf8'));
    if (
      !installation.rpmManifestHash
      || installedRpm?.manifestHash !== installation.rpmManifestHash
      || await computeManifestHash(installedRpm) !== installation.rpmManifestHash
    ) {
      throw new Error('Installed RPM manifest hash mismatch');
    }
    const expectedRpm = await buildReleaseRpm({ sourceRoot: root, destinationRoot: root });
    if (expectedRpm.manifestHash !== installedRpm.manifestHash) {
      throw new Error('Installed runtime RPM differs from reviewed source');
    }
    continue;
  }
  if (await sha256File(installed) !== hash) throw new Error('Installed runtime integrity mismatch');
  if (hashes[normRel] !== hash) throw new Error('Installed runtime differs from reviewed source');
}
if (!sawRpmManifest) throw new Error('Installed runtime RPM manifest is missing');
const installedFiles = new Set(Object.keys(installation.sha256).map(relative => relative.replaceAll('\\', '/')));
if (!installedFiles.has('rpm.json')) throw new Error('Installed runtime RPM manifest is missing');
const isRequiredRuntimeRel = relative => {
  if (relative.startsWith('local/') || relative.startsWith('scripts/')) return true;
  if (['package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml'].includes(relative)) return true;
  if (relative.startsWith('packages/') || relative.startsWith('plugins/')) {
    const segments = relative.split('/');
    if (segments.some(seg => seg.startsWith('.'))) return false;
    if (segments.includes('test') || segments.includes('__pycache__')) return false;
    if (/\.test\.[cm]?[jt]s$|\.pyc$/i.test(relative)) return false;
    return true;
  }
  return false;
};
for (const relative of Object.keys(hashes)) {
  if (isRequiredRuntimeRel(relative) && !installedFiles.has(relative)) throw new Error(`Reviewed runtime file is missing from the installation: ${relative}`);
}
const inventory = await exec(config.sandbox.dockerPath, ['--context', config.sandbox.context, 'run', '--rm', '--network', 'none', '--read-only', '--entrypoint', '/bin/cat', config.sandbox.image, '/opt/bridge/os-packages.txt', '/opt/bridge/npm-packages.json'], { windowsHide: true, timeout: 15000, maxBuffer: 1024 * 1024 });
await fs.writeFile(path.join(root, 'artifacts/container-packages.txt'), inventory.stdout);
const record = { time: new Date().toISOString(), review: 'fix-round5-2026-10-30', fixedFindings: ['R5-01','R5-02','R5-03'], hardening: ['full consent CSP', 'private-state ancestor trust', 'bounded read-only Docker initialization retries'], accountId: account, worker: 'agentdock-bridge', mcpUrl: `${config.origin}/mcp`, deployment: deployments.deployments?.[0] || deployments[0], health, tests: { passed, failed, skipped, cancelled }, acceptance, lifecycle, runtime: config.sourceRoot, nodeRuntime: {path:config.nodePath,root:config.nodeRoot,sha256:config.nodeSha256}, workspace: config.roots, containerPath: '/workspace', image: config.sandbox.image, localApprovalRequired: true, secretsRotatedThisRound: false, oldOAuthGrantsInvalidated: false, stateDirectory: stateDir, sourceSha256: hashes, limitations: ['Full mounted-project access includes any project-local credentials.', 'Worker remains a trusted intermediary for content and output.', 'Custom Windows file ACLs cause file-tool replacements to be refused; approved shell access is unrestricted within projects.', 'CLIs are installed without copying host login credentials.', 'ChatGPT account connection is not tested.'] };
await fs.writeFile(path.join(root, 'artifacts/hardening-deployment.json'), JSON.stringify(record, null, 2));
console.log(JSON.stringify({ worker: record.worker, health: health.status, tests: record.tests, acceptance: acceptance.success, image: record.image }));
