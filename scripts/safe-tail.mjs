// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Wrangler tail events contain request headers. This filter only prints metadata;
// raw events remain inside the pipe and are never written to disk or the chat.
let buffer = '';
let collecting = false;
let partial = '';
function processLine(line) {
  if (!collecting && !line.trim().startsWith('{')) return;
  collecting = true;
  buffer += line + '\n';
  try {
    const value = JSON.parse(buffer);
    let pathname;
    const rawUrl = value.event?.request?.url;
    if (typeof rawUrl === 'string' && rawUrl.length > 0) {
      try { pathname = new URL(rawUrl).pathname; } catch {}
    }
    console.log(JSON.stringify({
      time: value.eventTimestamp,
      outcome: value.outcome,
      ...(pathname === undefined ? {} : { path: pathname }),
      status: value.event?.response?.status,
      exceptions: value.exceptions?.map(exception => ({ name: exception.name })),
    }));
    buffer = '';
    collecting = false;
  } catch {
    if (buffer.length > 256 * 1024 || (!line.startsWith(' ') && !line.startsWith('\t') && line.trim() === '}')) {
      buffer = '';
      collecting = false;
    }
  }
}
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => {
  partial += chunk;
  if (partial.length > 1024 * 1024) { partial = ''; buffer = ''; collecting = false; return; }
  const lines = partial.split('\n');
  partial = lines.pop();
  for (const line of lines) processLine(line);
});
process.stdin.on('end', () => {
  if (partial) { processLine(partial); partial = ''; }
});
