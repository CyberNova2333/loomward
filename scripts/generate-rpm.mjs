// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Cross-platform frozen RPM generator used by POSIX (host-cli.mjs) and Windows (Install-Hardened.ps1) hardened installers.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const CORE_ROOT_PLUGIN_IDS = Object.freeze(['cloud-relay', 'sandbox', 'host', 'console']);

export async function buildReleaseRpm({ sourceRoot, destinationRoot }) {
  const srcRoot = path.resolve(sourceRoot);
  const dstRoot = path.resolve(destinationRoot);
  const { createFrozenRpm, sha256Tagged, validateContractDecl } = await import(
    pathToFileURL(path.join(srcRoot, 'packages', 'shared', 'src', 'index.mjs')).href
  );
  const rootPlugins = [];
  for (const id of CORE_ROOT_PLUGIN_IDS) {
    const contractFile = path.join(srcRoot, 'packages', id, 'src', 'contract.mjs');
    const entryFile = path.join(dstRoot, 'packages', id, 'src', 'index.mjs');
    const mod = await import(pathToFileURL(contractFile).href);
    const contract = validateContractDecl(mod.contract);
    const entryHash = await sha256Tagged(fs.readFileSync(entryFile));
    rootPlugins.push({
      id: contract.id,
      version: contract.version,
      entryHash,
      provides: [...contract.provides],
    });
  }
  return createFrozenRpm({ target: 'runtime', rootPlugins });
}

export async function writeReleaseRpmFile({ sourceRoot, destinationRoot, outFile = null }) {
  const rpm = await buildReleaseRpm({ sourceRoot, destinationRoot });
  const targetPath = outFile ? path.resolve(outFile) : path.join(path.resolve(destinationRoot), 'rpm.json');
  const tempPath = path.join(path.dirname(targetPath), `.tmp-rpm-${crypto.randomUUID()}.json`);
  const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0);
  const fd = fs.openSync(tempPath, flags, 0o600);
  try {
    fs.writeFileSync(fd, JSON.stringify(rpm, null, 2), 'utf8');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    if (process.platform !== 'win32') fs.chmodSync(tempPath, 0o600);
    fs.renameSync(tempPath, targetPath);
  } catch (error) {
    fs.rmSync(tempPath, { force: true });
    throw error;
  }
  return { rpm, rpmPath: targetPath };
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const val = argv[i + 1];
    if (val === undefined || val.startsWith('--')) throw new Error(`Missing value for --${key}`);
    args[key] = val;
    i += 1;
  }
  return args;
}

const isEntry = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename);
if (isEntry) {
  const args = parseArgs(process.argv.slice(2));
  if (!args.source || !args.dest) {
    console.error('Usage: node scripts/generate-rpm.mjs --source <checkoutDir> --dest <releaseDir> [--out <rpmPath>]');
    process.exit(1);
  }
  const { rpm, rpmPath } = await writeReleaseRpmFile({
    sourceRoot: args.source,
    destinationRoot: args.dest,
    outFile: args.out || null,
  });
  console.log(JSON.stringify({ rpmPath, manifestHash: rpm.manifestHash }));
}
