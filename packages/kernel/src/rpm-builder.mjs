// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  REJECT_CODES,
  computeManifestHash,
  createFrozenRpm,
  isRpmShape,
  sha256Tagged,
  validateContractDecl,
} from '@loomward/shared';
import { StartupRejectedError } from './boot.mjs';

export const DEFAULT_ROOT_PLUGIN_SPECS = Object.freeze([
  Object.freeze({
    id: 'cloud-relay',
    contractPath: 'packages/cloud-relay/src/contract.mjs',
    entryPath: 'packages/cloud-relay/src/index.mjs',
  }),
  Object.freeze({
    id: 'sandbox',
    contractPath: 'packages/sandbox/src/contract.mjs',
    entryPath: 'packages/sandbox/src/index.mjs',
  }),
  Object.freeze({
    id: 'host',
    contractPath: 'packages/host/src/contract.mjs',
    entryPath: 'packages/host/src/index.mjs',
  }),
  Object.freeze({
    id: 'console',
    contractPath: 'packages/console/src/contract.mjs',
    entryPath: 'packages/console/src/index.mjs',
  }),
]);

export async function buildWorkspaceRpm(
  rootDir,
  { specs = DEFAULT_ROOT_PLUGIN_SPECS, target = 'runtime' } = {},
) {
  const resolvedRoot = path.resolve(rootDir);
  const rootPlugins = [];
  const entries = [];

  for (const spec of specs) {
    const absContract = path.join(resolvedRoot, spec.contractPath);
    const absEntry = path.join(resolvedRoot, spec.entryPath);
    const contractMod = await import(pathToFileURL(absContract).href);
    const contract = validateContractDecl(contractMod.contract);
    if (contract.id !== spec.id || contract.kind !== 'root-plugin') {
      throw new StartupRejectedError(REJECT_CODES.GUARD_CONTRACT_MISMATCH, spec.id);
    }
    const bytes = await fs.readFile(absEntry);
    const entryHash = await sha256Tagged(bytes);
    rootPlugins.push({
      id: contract.id,
      version: contract.version,
      entryHash,
      provides: [...contract.provides],
    });
    entries.push({
      id: contract.id,
      contract,
      entryPath: spec.entryPath,
      absEntry,
      entryHash,
    });
  }

  const rpm = await createFrozenRpm({ target, rootPlugins });
  return { rpm, entries };
}

export async function verifyWorkspaceRpm(
  rootDir,
  rpm,
  { specs = DEFAULT_ROOT_PLUGIN_SPECS } = {},
) {
  if (!isRpmShape(rpm)) {
    throw new StartupRejectedError(REJECT_CODES.GUARD_RPM_INVALID_SHAPE, 'rpm');
  }
  const expectedHash = await computeManifestHash(rpm);
  if (expectedHash !== rpm.manifestHash) {
    throw new StartupRejectedError(REJECT_CODES.GUARD_RPM_HASH_MISMATCH, 'rpm');
  }

  const resolvedRoot = path.resolve(rootDir);
  const specMap = new Map(specs.map(spec => [spec.id, spec]));
  if (specMap.size !== rpm.rootPlugins.length) {
    throw new StartupRejectedError(REJECT_CODES.GUARD_ROOT_ENTRY_MISMATCH, 'rpm', 'Root plugin inventory size mismatch.');
  }

  for (const entry of rpm.rootPlugins) {
    const spec = specMap.get(entry.id);
    if (!spec) {
      throw new StartupRejectedError(REJECT_CODES.GUARD_ROOT_ENTRY_MISMATCH, entry.id);
    }
    const absContract = path.join(resolvedRoot, spec.contractPath);
    const absEntry = path.join(resolvedRoot, spec.entryPath);
    const contractMod = await import(pathToFileURL(absContract).href);
    const contract = validateContractDecl(contractMod.contract);
    const sameProvides = Array.isArray(entry.provides)
      && contract.provides.length === entry.provides.length
      && [...contract.provides].sort().every((val, idx) => val === [...entry.provides].sort()[idx]);
    if (
      contract.id !== entry.id
      || contract.version !== entry.version
      || contract.kind !== 'root-plugin'
      || !sameProvides
    ) {
      throw new StartupRejectedError(REJECT_CODES.GUARD_CONTRACT_MISMATCH, entry.id);
    }
    const actualHash = await sha256Tagged(await fs.readFile(absEntry));
    if (actualHash !== entry.entryHash) {
      throw new StartupRejectedError(REJECT_CODES.GUARD_ROOT_HASH_MISMATCH, entry.id);
    }
  }
  return true;
}

export async function loadWorkspaceRootRefs(
  rootDir,
  { specs = DEFAULT_ROOT_PLUGIN_SPECS, configs = {} } = {},
) {
  const resolvedRoot = path.resolve(rootDir);
  const refs = [];
  for (const spec of specs) {
    const absContract = path.join(resolvedRoot, spec.contractPath);
    const absEntry = path.join(resolvedRoot, spec.entryPath);
    const contractMod = await import(pathToFileURL(absContract).href);
    const contract = validateContractDecl(contractMod.contract);
    refs.push({
      id: contract.id,
      contract,
      config: configs[contract.id],
      bytes: () => fs.readFile(absEntry),
      load: () => import(pathToFileURL(absEntry).href),
    });
  }
  return refs;
}
