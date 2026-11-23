// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Mechanical layering guard modeled on Weftale's static dependency boundary tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { validateContractDecl } from '@loomward/shared';

const REPO_ROOT = path.resolve(import.meta.dirname, '../../..');

function walkSourceFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === 'test' || entry.name === 'dist') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walkSourceFiles(full));
    else if (/\.(?:mjs|js|ts|mts)$/.test(entry.name)) out.push(full);
  }
  return out;
}

function parseImportSpecifiers(filePath) {
  const text = fs.readFileSync(filePath, 'utf8');
  const specs = [];
  for (const m of text.matchAll(/^\s*(?:import|export)\s+(type\s+)?[^'"]*?from\s+['"]([^'"]+)['"]/gm)) {
    specs.push({ spec: m[2], typeOnly: Boolean(m[1]) });
  }
  for (const m of text.matchAll(/^\s*import\s+['"]([^'"]+)['"]/gm)) {
    specs.push({ spec: m[1], typeOnly: false });
  }
  for (const m of text.matchAll(/\bimport\(\s*['"]([^'"]+)['"]\s*\)/g)) {
    specs.push({ spec: m[1], typeOnly: false });
  }
  return specs;
}

function rel(filePath) {
  return path.relative(REPO_ROOT, filePath).split(path.sep).join('/');
}

test('layering: @loomward/shared has zero Node/host/cordis/kernel/plugin imports', () => {
  const sharedFiles = walkSourceFiles(path.join(REPO_ROOT, 'packages/shared/src'));
  assert.ok(sharedFiles.length > 0);
  const violations = [];
  for (const file of sharedFiles) {
    for (const imp of parseImportSpecifiers(file)) {
      const target = imp.spec.startsWith('.') ? rel(path.resolve(path.dirname(file), imp.spec)) : imp.spec;
      if (
        /^node:|^cordis(?:\/|$)|^@loomward\/(?!shared$)/.test(target)
        || target.startsWith('packages/kernel')
        || target.startsWith('packages/host')
        || target.startsWith('plugins/')
      ) {
        violations.push(`${rel(file)} -> ${imp.spec}`);
      }
    }
  }
  assert.deepEqual(violations, []);
});

test('layering: non-kernel packages and plugins never import cordis at runtime or cross-import sibling packages', () => {
  const packagesDir = path.join(REPO_ROOT, 'packages');
  const pluginsDir = path.join(REPO_ROOT, 'plugins');
  const violations = [];

  for (const [groupName, groupDir] of [['packages', packagesDir], ['plugins', pluginsDir]]) {
    if (!fs.existsSync(groupDir)) continue;
    for (const entry of fs.readdirSync(groupDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const ownName = entry.name;
      const srcDir = path.join(groupDir, ownName, 'src');
      for (const file of walkSourceFiles(srcDir)) {
        for (const imp of parseImportSpecifiers(file)) {
          if (imp.typeOnly) continue;
          if (!(groupName === 'packages' && ownName === 'kernel') && /^cordis(?:\/|$)/.test(imp.spec)) {
            violations.push(`${rel(file)} -> ${imp.spec} (only @loomward/kernel may import cordis)`);
          }
          if (imp.spec.startsWith('.')) {
            const target = rel(path.resolve(path.dirname(file), imp.spec));
            const parts = target.split('/');
            if ((parts[0] === 'packages' || parts[0] === 'plugins') && (parts[0] !== groupName || parts[1] !== ownName)) {
              violations.push(`${rel(file)} -> ${imp.spec} (cross-package relative import)`);
            }
          }
          if (groupName === 'plugins' && /^@loomward\/plugin-/.test(imp.spec) && imp.spec !== `@loomward/plugin-${ownName}`) {
            violations.push(`${rel(file)} -> ${imp.spec} (cross-plugin direct import)`);
          }
        }
      }
    }
  }
  assert.deepEqual(violations, []);
});

test('layering: every workspace root package and extension plugin declares a valid contract', async () => {
  const rootsDir = path.join(REPO_ROOT, 'packages');
  const pluginsDir = path.join(REPO_ROOT, 'plugins');
  const checked = [];

  for (const [groupName, groupDir] of [['packages', rootsDir], ['plugins', pluginsDir]]) {
    if (!fs.existsSync(groupDir)) continue;
    for (const entry of fs.readdirSync(groupDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      if (groupName === 'packages' && (entry.name === 'shared' || entry.name === 'kernel')) continue;
      const contractPath = path.join(groupDir, entry.name, 'src/contract.mjs');
      assert.equal(fs.existsSync(contractPath), true, `Missing contract: ${rel(contractPath)}`);
      const mod = await import(pathToFileURL(contractPath).href);
      const decl = validateContractDecl(mod.contract);
      if (groupName === 'plugins') {
        assert.equal(decl.kind, 'extension-plugin');
        assert.equal(decl.executionBoundary, 'out-of-process', `Plugin ${decl.id} must declare out-of-process executionBoundary`);
      } else {
        assert.equal(decl.kind, 'root-plugin');
      }
      checked.push(decl.id);
    }
  }
  assert.ok(checked.length >= 8, `Expected at least 8 declared packages/plugins, got ${checked.length}`);
});
