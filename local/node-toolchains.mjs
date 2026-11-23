// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import https from 'node:https';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { HttpsProxyAgent } from 'https-proxy-agent';
import {
  assertPrivateState,
  assertPrivateFile,
  assertTrustedBinary,
  assertPinnedNode,
  assertWriteProtectedPath,
  sha256FileSync,
} from './host-safety.mjs';

export const PINNED_NODE_VERSION = '24.22.1';

// Verified directly against https://nodejs.org/dist/v24.22.1/SHASUMS256.txt
export const NODE_DISTRIBUTIONS = Object.freeze({
  'win32-x64': {
    folder: `node-v${PINNED_NODE_VERSION}-win-x64`,
    filename: `node-v${PINNED_NODE_VERSION}-win-x64.zip`,
    sha256: 'd2046d28c2c3dcd211ac5145c0bf30e2047ef9dfb306693c8c6e2eccd8b95fa5',
    nodeRel: 'node.exe',
    npmRel: 'node_modules/npm/bin/npm-cli.js',
  },
  'linux-x64': {
    folder: `node-v${PINNED_NODE_VERSION}-linux-x64`,
    filename: `node-v${PINNED_NODE_VERSION}-linux-x64.tar.gz`,
    sha256: 'eb6728e77c576a35162c122c45ccadf224d89ff00abc8dae46cc2897c6002d7c',
    nodeRel: 'bin/node',
    npmRel: 'lib/node_modules/npm/bin/npm-cli.js',
  },
  'linux-arm64': {
    folder: `node-v${PINNED_NODE_VERSION}-linux-arm64`,
    filename: `node-v${PINNED_NODE_VERSION}-linux-arm64.tar.gz`,
    sha256: '33c37be234ba8bee041961047b19160f4d7d0f164e8e246f78bdd10feff148b3',
    nodeRel: 'bin/node',
    npmRel: 'lib/node_modules/npm/bin/npm-cli.js',
  },
  'darwin-x64': {
    folder: `node-v${PINNED_NODE_VERSION}-darwin-x64`,
    filename: `node-v${PINNED_NODE_VERSION}-darwin-x64.tar.gz`,
    sha256: 'd132557e7ee2b85af08b0c8c34338e65c6430f2238d01f727728ef42dc83b035',
    nodeRel: 'bin/node',
    npmRel: 'lib/node_modules/npm/bin/npm-cli.js',
  },
  'darwin-arm64': {
    folder: `node-v${PINNED_NODE_VERSION}-darwin-arm64`,
    filename: `node-v${PINNED_NODE_VERSION}-darwin-arm64.tar.gz`,
    sha256: '89c682593d76cd44233fa53b1563264e7de9cbb189cad169135c5b4fadfbc0a7',
    nodeRel: 'bin/node',
    npmRel: 'lib/node_modules/npm/bin/npm-cli.js',
  },
});

export function getDistribution(platform = process.platform, arch = process.arch) {
  const key = `${platform}-${arch}`;
  const entry = NODE_DISTRIBUTIONS[key];
  if (!entry) throw new Error(`Unsupported host architecture for pinned Node ${PINNED_NODE_VERSION}: ${key}`);
  return entry;
}

function downloadFileNoRedirect(url, destination, proxy) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(destination, { flags: 'wx', mode: 0o600 });
    let finished = false;
    const cleanup = err => {
      if (finished) return;
      finished = true;
      file.destroy();
      fs.rmSync(destination, { force: true });
      reject(err);
    };
    file.on('error', cleanup);
    const req = https.get(url, {
      agent: proxy ? new HttpsProxyAgent(proxy) : undefined,
      minVersion: 'TLSv1.2',
      timeout: 300000,
    }, res => {
      if (res.statusCode !== 200) {
        res.resume();
        cleanup(new Error(`Official Node download failed with HTTP ${res.statusCode}.`));
        return;
      }
      res.on('error', cleanup);
      res.pipe(file);
      file.on('finish', () => file.close(err => {
        if (err) cleanup(err);
        else if (!finished) { finished = true; resolve(); }
      }));
    });
    req.on('timeout', () => req.destroy(new Error('Official Node download timed out.')));
    req.on('error', cleanup);
  });
}

function ensureToolchainsRoot() {
  const toolchains = path.join(os.homedir(), '.agentdock-toolchains');
  if (!fs.existsSync(toolchains)) {
    assertWriteProtectedPath(path.dirname(toolchains));
    fs.mkdirSync(toolchains, { mode: 0o700 });
  }
  return assertPrivateState(toolchains);
}

function findTarExecutable() {
  for (const candidate of ['/usr/bin/tar', '/bin/tar']) {
    if (fs.existsSync(candidate)) return candidate;
  }
  throw new Error('Cannot locate system tar binary.');
}

function verifyDarwinCodeSignature(nodePath) {
  if (process.platform !== 'darwin' || !fs.existsSync('/usr/bin/codesign')) return;
  try {
    execFileSync('/usr/bin/codesign', ['--verify', '--strict', nodePath], {
      timeout: 15000,
      stdio: ['ignore', 'ignore', 'pipe'],
    });
  } catch {
    throw new Error('Official macOS Node signature verification failed.');
  }
}

export async function ensurePinnedNodeRuntime({ stateDir, workspace, proxy } = {}) {
  if (process.platform === 'win32') {
    throw new Error('Use Install-NodeRuntime.ps1 on Windows hosts.');
  }
  assertPrivateState(stateDir);
  const distribution = getDistribution();
  const toolchains = ensureToolchainsRoot();
  const folder = path.join(toolchains, distribution.folder);
  const manifestFile = path.join(toolchains, `${distribution.folder}.verified.json`);

  if (!fs.existsSync(folder)) {
    const archive = path.join(toolchains, `node-download-${crypto.randomUUID()}.tar.gz`);
    const staging = path.join(toolchains, `.node-staging-${crypto.randomUUID()}`);
    const tempManifest = path.join(toolchains, `.manifest-${crypto.randomUUID()}.tmp`);
    const url = `https://nodejs.org/dist/v${PINNED_NODE_VERSION}/${distribution.filename}`;
    try {
      await downloadFileNoRedirect(url, archive, proxy);
      if (sha256FileSync(archive) !== distribution.sha256) {
        throw new Error('Official Node archive digest mismatch; installation stopped.');
      }
      fs.mkdirSync(staging, { mode: 0o700 });
      const tar = findTarExecutable();
      const args = process.platform === 'linux'
        ? ['--no-same-owner', '-xzf', archive, '-C', staging]
        : ['-xzf', archive, '-C', staging];
      execFileSync(tar, args, { timeout: 120000, stdio: ['ignore', 'ignore', 'pipe'] });
      const stagedFolder = path.join(staging, distribution.folder);
      const nodePath = path.join(stagedFolder, distribution.nodeRel);
      const npmPath = path.join(stagedFolder, distribution.npmRel);
      verifyDarwinCodeSignature(nodePath);
      const manifest = {
        version: PINNED_NODE_VERSION,
        archiveSha256: distribution.sha256,
        nodeSha256: sha256FileSync(nodePath),
        npmCliSha256: sha256FileSync(npmPath),
      };
      const fd = fs.openSync(tempManifest, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o600);
      try {
        fs.writeFileSync(fd, JSON.stringify(manifest), 'utf8');
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      fs.chmodSync(tempManifest, 0o600);
      fs.renameSync(tempManifest, manifestFile);
      fs.renameSync(stagedFolder, folder);
    } finally {
      fs.rmSync(archive, { force: true });
      fs.rmSync(tempManifest, { force: true });
      fs.rmSync(staging, { recursive: true, force: true });
    }
  }

  assertPrivateFile(manifestFile);
  const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
  if (manifest.version !== PINNED_NODE_VERSION || manifest.archiveSha256 !== distribution.sha256) {
    throw new Error('Private Node installation manifest mismatch.');
  }
  const nodePath = path.join(folder, distribution.nodeRel);
  const npmCli = path.join(folder, distribution.npmRel);
  assertPinnedNode({ nodePath, nodeRoot: toolchains, nodeSha256: manifest.nodeSha256, roots: workspace ? [workspace] : [] }, stateDir);
  assertWriteProtectedPath(npmCli);
  if (sha256FileSync(npmCli) !== manifest.npmCliSha256) {
    throw new Error('Private npm integrity verification failed.');
  }
  return {
    nodePath,
    nodeRoot: toolchains,
    nodeSha256: manifest.nodeSha256,
    npmCli,
    version: PINNED_NODE_VERSION,
    archiveSha256: distribution.sha256,
  };
}
