// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import fs from 'node:fs';
import path from 'node:path';

const DIST_DIR = path.resolve(import.meta.dirname, '..', 'dist');

function escapeHtmlAttr(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

const ALLOWED_ASSETS = new Set(['console.css', 'console.js']);
const assetCache = new Map();

export const BRAND_ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" fill="none" role="img" aria-label="LoomWard">
  <defs>
    <linearGradient id="lw-sb" x1="16" y1="8" x2="112" y2="120" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="#0f172a" />
      <stop offset="100%" stop-color="#111d35" />
    </linearGradient>
    <linearGradient id="lw-co" x1="28" y1="22" x2="100" y2="104" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="#1d6fd8" />
      <stop offset="100%" stop-color="#0c5cab" />
    </linearGradient>
    <linearGradient id="lw-cy" x1="100" y1="22" x2="28" y2="104" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="#67e8f9" />
      <stop offset="100%" stop-color="#38bdf8" />
    </linearGradient>
  </defs>
  <path d="M64 8L108 26V58C108 87.5 89 109.5 64 120C39 109.5 20 87.5 20 58V26L64 8Z" fill="url(#lw-sb)" stroke="#1e3a5f" stroke-width="2.5" />
  <path d="M64 15L100 30V58C100 83 84 102 64 111.5C44 102 28 83 28 58V30L64 15Z" fill="#091326" />
  <g stroke-width="9" stroke-linecap="round" stroke-linejoin="round">
    <path d="M35 34L64 46L93 84L64 98L38 84L79 44" stroke="url(#lw-co)" />
    <path d="M93 34L64 46L35 84L64 98L90 84L49 44" stroke="#091326" stroke-width="14" />
    <path d="M93 34L64 46L35 84L64 98L90 84L49 44" stroke="url(#lw-cy)" />
    <path d="M51 54L77 77" stroke="#091326" stroke-width="14" />
    <path d="M47 50L81 81" stroke="url(#lw-co)" />
  </g>
</svg>
`;

export function loadBuiltAsset(fileName) {
  if (!ALLOWED_ASSETS.has(fileName)) {
    throw new Error(`Unknown console asset: ${String(fileName)}`);
  }
  if (assetCache.has(fileName)) return assetCache.get(fileName);
  const fullPath = path.join(DIST_DIR, fileName);
  const content = fs.readFileSync(fullPath, 'utf8');
  assetCache.set(fileName, content);
  return content;
}

export function clearAssetCache() {
  assetCache.clear();
}

export function renderConsoleHtml({ csrfToken }) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="loomward-csrf" content="${escapeHtmlAttr(csrfToken)}" />
  <meta name="loomward-origin-role" content="unified" />
  <title>LoomWard · 织盾 · 安全管控平台</title>
  <link rel="icon" type="image/svg+xml" href="/brand-icon.svg" />
  <link rel="stylesheet" href="/console.css" />
  <script defer src="/console.js"></script>
</head>
<body data-origin-role="unified">
  <div id="app" class="lw-root">
    <noscript>LoomWard 安全控制台需要启用本地 JavaScript（零外部 CDN、严格同源 CSP）。</noscript>
  </div>
</body>
</html>`;
}
