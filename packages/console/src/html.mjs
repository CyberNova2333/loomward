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

const assetCache = new Map();

export function loadBuiltAsset(fileName) {
  if (assetCache.has(fileName)) return assetCache.get(fileName);
  const fullPath = path.join(DIST_DIR, fileName);
  const content = fs.readFileSync(fullPath, 'utf8');
  assetCache.set(fileName, content);
  return content;
}

export function clearAssetCache() {
  assetCache.clear();
}

export function renderTrustOriginHtml({ csrfToken, consoleOrigin = '' }) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="loomward-csrf" content="${escapeHtmlAttr(csrfToken)}" />
  <meta name="loomward-origin-role" content="trust" />
  <meta name="loomward-console-origin" content="${escapeHtmlAttr(consoleOrigin)}" />
  <title>LoomWard · 织盾 · Trust Origin 独立信任面</title>
  <link rel="stylesheet" href="/trust.css" />
  <script defer src="/trust.js"></script>
</head>
<body data-origin-role="trust">
  <div id="app" class="lw-root">
    <noscript>LoomWard Trust Origin 需要启用本地 JavaScript（零外部 CDN、严格同源 CSP）。</noscript>
  </div>
</body>
</html>`;
}

export function renderConsoleOriginHtml({ csrfToken, trustOrigin = '' }) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="loomward-csrf" content="${escapeHtmlAttr(csrfToken)}" />
  <meta name="loomward-origin-role" content="console" />
  <meta name="loomward-trust-origin" content="${escapeHtmlAttr(trustOrigin)}" />
  <title>LoomWard · 织盾 · Console 观测控制台</title>
  <link rel="stylesheet" href="/console.css" />
  <script defer src="/console.js"></script>
</head>
<body data-origin-role="console">
  <div id="app" class="lw-root">
    <noscript>LoomWard Console 需要启用本地 JavaScript（零外部 CDN、严格同源 CSP）。</noscript>
  </div>
</body>
</html>`;
}
