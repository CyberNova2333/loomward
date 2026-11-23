// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Use Wrangler's existing OAuth login locally. Never print its token or HTTP headers.
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

async function resolveCloudflareToken() {
  if (process.env.CLOUDFLARE_API_TOKEN) return process.env.CLOUDFLARE_API_TOKEN.trim();
  const home = os.homedir();
  const candidates = process.platform === 'win32'
    ? [
        ...(process.env.APPDATA ? [path.join(process.env.APPDATA, 'xdg.config', '.wrangler', 'config', 'default.toml')] : []),
        path.join(home, '.wrangler', 'config', 'default.toml'),
      ]
    : [
        ...(process.env.XDG_CONFIG_HOME ? [path.join(process.env.XDG_CONFIG_HOME, '.wrangler', 'config', 'default.toml')] : []),
        ...(process.platform === 'darwin' ? [path.join(home, 'Library', 'Preferences', '.wrangler', 'config', 'default.toml')] : []),
        path.join(home, '.config', '.wrangler', 'config', 'default.toml'),
        path.join(home, '.wrangler', 'config', 'default.toml'),
      ];
  for (const file of candidates) {
    try {
      const text = await fs.readFile(file, 'utf8');
      const token = text.match(/^oauth_token\s*=\s*"([^"]+)"/m)?.[1];
      if (token) return token;
    } catch {}
  }
  throw new Error('Wrangler OAuth login or CLOUDFLARE_API_TOKEN not found');
}

export async function cloudflare(pathname, options = {}) {
  const token = await resolveCloudflareToken();
  const response = await fetch(`https://api.cloudflare.com/client/v4${pathname}`, {
    ...options,
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', ...options.headers },
    signal: AbortSignal.timeout(30000),
  });
  const data = await response.json();
  if (!response.ok || !data.success) throw new Error(`Cloudflare ${response.status}: ${JSON.stringify(data.errors)}`);
  return data.result;
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename)) {
  const resource = process.argv[2];
  if (!resource?.startsWith('/')) throw new Error('Pass a Cloudflare API resource path');
  console.log(JSON.stringify(await cloudflare(resource), null, 2));
}
