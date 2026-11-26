// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Offline zero-CDN asset builder for @loomward/console.
import fs from 'node:fs/promises';
import path from 'node:path';
import esbuild from 'esbuild';

const PKG_ROOT = path.resolve(import.meta.dirname, '..');
const WEB_DIR = path.join(PKG_ROOT, 'web');
const DIST_DIR = path.join(PKG_ROOT, 'dist');

async function build() {
  await fs.mkdir(DIST_DIR, { recursive: true });
  await Promise.all([
    esbuild.build({
      entryPoints: [path.join(WEB_DIR, 'console', 'main.mjs')],
      bundle: true,
      format: 'iife',
      platform: 'browser',
      target: ['es2022'],
      minify: false,
      legalComments: 'none',
      outfile: path.join(DIST_DIR, 'console.js'),
    }),
    esbuild.build({
      entryPoints: [path.join(WEB_DIR, 'console', 'console.css')],
      bundle: true,
      minify: false,
      outfile: path.join(DIST_DIR, 'console.css'),
    }),
  ]);
  const built = await fs.readdir(DIST_DIR);
  console.log(`Built @loomward/console offline assets: ${built.sort().join(', ')}`);
}

build().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
