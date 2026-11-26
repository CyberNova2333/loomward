// SPDX-License-Identifier: AGPL-3.0-only
import fs from 'node:fs';
import path from 'node:path';
import { assertPinnedNode, assertPrivateFile, assertPrivateState } from '../local/host-safety.mjs';

// The wrapper may already have been updated when an upgrade is interrupted.
// The only activation record is config.json, replaced after every entry is ready.
const [stateDir, action, ...args] = process.argv.slice(2);
const state = assertPrivateState(stateDir);
const config = JSON.parse(fs.readFileSync(assertPrivateFile(path.join(state, 'config.json')), 'utf8'));
const release = config.sourceRoot;
if (!config.requireLocalApproval || !config.sandbox?.enabled || typeof release !== 'string' ||
    path.dirname(release) !== state || !/^runtime-\d{8}-\d{6}-[a-f0-9]{8}$/.test(path.basename(release))) {
  throw new Error('No protected release is active.');
}
assertPrivateState(release);
const cli = assertPrivateFile(path.join(release, 'scripts', 'host-cli.mjs'));
const node = assertPinnedNode(config, state);
process.execve(node, [node, cli, action, '--state-dir', state, ...args], process.env);
