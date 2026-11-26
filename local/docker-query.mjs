// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
export function isLocalDockerEndpoint(endpoint, platform = process.platform) {
  if (typeof endpoint !== 'string' || /[\\\x00-\x1f\x7f]/.test(endpoint)) return false;
  if (endpoint.startsWith('unix:///')) {
    const socket = endpoint.slice('unix:///'.length);
    return socket.length > 0 && !socket.startsWith('/');
  }
  const prefix = 'npipe:////./pipe/';
  if (platform !== 'win32' || !endpoint.startsWith(prefix)) return false;
  const pipe = endpoint.slice(prefix.length);
  return pipe.length > 0 && !pipe.includes('/');
}

// Initialization queries are read-only. Retrying them cannot repeat a command
// or file mutation; all create/start/remove operations keep their own policy.
export async function queryDockerState(run, args) {
  const readOnly = (args[0] === 'context' && args[1] === 'inspect') ||
    (args[0] === 'image' && args[1] === 'inspect') || args[0] === 'ps';
  if (!readOnly) throw new Error('Only read-only Docker initialization queries may be retried.');
  try { return await run(args, 30000); }
  catch (error) {
    if (error.code !== 'ETIMEDOUT' && !(error.killed && error.signal === 'SIGTERM')) throw error;
    return run(args, 30000);
  }
}
