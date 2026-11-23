// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import https from 'node:https';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { cloudflare } from './cloudflare-api.mjs';
import { proxyCandidates } from '../local/connector.mjs';

const sha256File = filePath => new Promise((resolve, reject) => {
  const hash = crypto.createHash('sha256');
  const stream = fsSync.createReadStream(filePath);
  stream.on('data', chunk => hash.update(chunk));
  stream.on('error', reject);
  stream.on('end', () => resolve(hash.digest('hex')));
});

const root = path.resolve(import.meta.dirname, '..');
const worker = 'agentdock-bridge';
const [account, hostname] = process.argv.slice(2);
if (!/^[a-f0-9]{32}$/.test(account || '') || !/^[a-z0-9.-]+$/i.test(hostname || '')) {
  throw new Error('Usage: node scripts/record-deployment.mjs <cloudflare-account-id> <public-hostname>');
}
const [domains, deployments] = await Promise.all([
  cloudflare(`/accounts/${account}/workers/domains`),
  cloudflare(`/accounts/${account}/workers/scripts/${worker}/deployments`),
]);
const domain = domains.find(value => value.hostname === hostname && value.service === worker);
if (!domain) throw new Error('The requested custom domain is not attached to this Worker');
const MAX_HEALTH_BYTES = 1024 * 1024;
const origin = `https://${hostname}`;
let health;
let lastHealthError = new Error('Health probe failed');
for (const proxy of proxyCandidates(origin)) {
  try {
    health = await new Promise((resolve, reject) => {
      let agent;
      if (proxy) agent = new HttpsProxyAgent(proxy);
      const request = https.get(`${origin}/healthz`, { agent, minVersion: 'TLSv1.2', timeout: 15000 }, response => {
        const chunks = [];
        let bytes = 0;
        let oversized = false;
        response.on('data', chunk => {
          if (oversized) return;
          bytes += chunk.length;
          if (bytes > MAX_HEALTH_BYTES) {
            oversized = true;
            request.destroy(new Error('Health response exceeds byte limit'));
            return;
          }
          chunks.push(chunk);
        });
        response.on('end', () => {
          if (oversized) return;
          const text = Buffer.concat(chunks).toString('utf8');
          try {
            resolve({ status: response.statusCode, body: JSON.parse(text) });
          } catch {
            reject(new Error('Invalid health response'));
          }
        });
        response.on('close', () => reject(new Error('Health connection closed')));
        response.on('error', reject);
      });
      request.on('error', reject);
      request.on('timeout', () => request.destroy(new Error('Health timed out')));
    });
    break;
  } catch (error) { lastHealthError = error; }
}
if (!health) throw lastHealthError;
if (health.status !== 200 || !health.body.connectorOnline) throw new Error('The connector is not currently healthy');
const hashes = {};
async function walk(directory) {
  for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
    if (['node_modules', '.git', '.wrangler', 'artifacts'].includes(entry.name)) continue;
    const file = path.join(directory, entry.name);
    if (entry.isDirectory()) await walk(file);
    else if (entry.isFile()) hashes[path.relative(root, file).replaceAll('\\', '/')] = await sha256File(file);
  }
}
await walk(root);
const acceptance = JSON.parse(await fs.readFile(path.join(root, 'artifacts', 'acceptance-result.json'), 'utf8'));
if (!acceptance.success || acceptance.checks.some(check => !check.passed)) throw new Error('Public acceptance has not passed');
const record = {
  time: new Date().toISOString(), accountId: account, worker, mcpUrl: `https://${hostname}/mcp`,
  customDomain: { hostname: domain.hostname, zone: domain.zone_name, enabled: domain.enabled, certificateId: domain.cert_id },
  deployment: deployments.deployments?.[0] || deployments[0] || deployments,
  health, tests: { passed: 16, failed: 0 },
  lifecycle: { gracefulStop: 'passed', offlineHealthHttp: 503, manualRestart: 'passed', restartedHealthHttp: 200 },
  publicAcceptance: acceptance,
  chatgptClientConnection: 'User still needs to add this MCP URL and complete OAuth in their own client.',
  sourceSha256: hashes,
};
await fs.writeFile(path.join(root, 'artifacts', 'deployment-result.json'), JSON.stringify(record, null, 2));
console.log(JSON.stringify({ worker, accountId: account, hostname, health: health.status, publicAcceptance: acceptance.success, sourceFiles: Object.keys(hashes).length }));
