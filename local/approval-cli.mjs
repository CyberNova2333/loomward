// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import fs from 'node:fs/promises';
import path from 'node:path';
import readline from 'node:readline/promises';
import { digest } from './request-policy.mjs';
import { REQUEST_FILE, MAX_APPROVED_RECORD_BYTES, readJson, validRequest, atomicJson } from './approval-store.mjs';

// Terminal control, bidi, invisible formatting, and tag characters are displayed as literal escapes.
export const safeText = value => String(value).replace(/[\p{Cc}\p{Cf}\u00a0\u2028\u2029\u{e0000}-\u{e007f}]/gu, character => {
  const code = character.codePointAt(0);
  return code > 0xffff ? `\\u{${code.toString(16)}}` : `\\u${code.toString(16).padStart(4, '0')}`;
});

export async function approveRequest(directory, pending, now = Date.now()) {
  if (!validRequest(pending, pending.id, now)) throw new Error('This request is invalid or expired.');
  // Re-read the protected record after review to detect replacement while the prompt was open.
  const current = await readJson(path.join(directory, `${pending.id}.request.json`));
  if (digest(current) !== digest(pending)) throw new Error('This request changed during review.');
  try {
    await atomicJson(path.join(directory, `${pending.id}.approved.json`), { hash: pending.hash, expiresAt: pending.expiresAt }, MAX_APPROVED_RECORD_BYTES);
  } catch (error) {
    if (error?.code === 'EEXIST') throw new Error('This request already has a pending unused approval.');
    throw error;
  }
}

export async function loadPendingRequests(directory, now = Date.now()) {
  if ((await fs.lstat(directory)).isSymbolicLink()) throw new Error('Approval directory must not be a link.');
  const records = [];
  for (const name of await fs.readdir(directory)) {
    const identified = REQUEST_FILE.exec(name);
    if (!identified) continue;
    const file = path.join(directory, name);
    let record;
    try { record = await readJson(file); } catch { continue; }
    if (!validRequest(record, identified[1], now)) continue;
    if (records.length >= 64) throw new Error('Approval queue exceeds the allowed limit.');
    records.push(record);
  }
  records.sort((a, b) => a.createdAt - b.createdAt);
  return records;
}

async function main() {
  if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error('Approval requires an interactive local terminal.');
  const stateDir = path.resolve(process.argv[2]);
  const directory = path.join(stateDir, 'approvals');
  const records = await loadPendingRequests(directory);
  if (!records.length) { console.log('No unexpired requests await approval.'); return; }
  console.log('Pending requests. Cloud-provided identity and request text are untrusted; approve only the action you intended.');
  records.forEach((record, index) => console.log(`${index + 1}. ${safeText(record.request.params?.name)} | ${safeText(record.request.authorization?.clientId)} | ${record.id}`));
  const prompt = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    const selection = (await prompt.question('Select a number to review (Enter cancels): ')).trim();
    if (!/^[1-9][0-9]?$/.test(selection)) { console.log('Cancelled.'); return; }
    const pending = records[Number(selection) - 1];
    if (!pending) { console.log('Cancelled.'); return; }
    console.log('\n=== REQUEST SUMMARY ===');
    const summaryArgs = pending.request.params?.arguments || {};
    console.log(`Tool: ${safeText(pending.request.params?.name || '')}`);
    console.log(`Client: ${safeText(pending.request.authorization?.clientId || '')}`);
    if (typeof summaryArgs.path === 'string') console.log(`Path: ${safeText(summaryArgs.path)}`);
    if (typeof summaryArgs.cwd === 'string') console.log(`Cwd: ${safeText(summaryArgs.cwd)}`);
    if (typeof summaryArgs.cmd === 'string' && summaryArgs.cmd.includes('\n')) {
      console.log('\nCommand preview (escaped control characters, exact value in JSON below):');
      for (const line of summaryArgs.cmd.split('\n').slice(0, 40)) console.log(`  ${safeText(line)}`);
    }
    if (typeof summaryArgs.content === 'string' && summaryArgs.content.includes('\n')) {
      console.log('\nContent preview (first 40 lines, exact value in JSON below):');
      for (const line of summaryArgs.content.split('\n').slice(0, 40)) console.log(`  ${safeText(line)}`);
    }
    console.log('\nExact request, including every argument:');
    for (const line of JSON.stringify(pending.request, null, 2).split('\n')) console.log(safeText(line));
    console.log(`\nExpires: ${new Date(pending.expiresAt).toISOString()}`);
    const required = `APPROVE ${pending.id}`;
    const answer = await prompt.question(`To permit this exact request once, type ${required}\nAnything else cancels: `);
    if (answer !== required) { console.log('Cancelled.'); return; }
    await approveRequest(directory, pending);
    console.log('Approved once. Retry the same tool arguments in the client before the expiry time.');
  } finally { prompt.close(); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename)) main().catch(error => {
  console.error(safeText(error.message));
  process.exitCode = 1;
});
