// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { startUnifiedConsole } from '../../packages/console/src/server.mjs';
import { digest } from '../../local/request-policy.mjs';
import { openNativeBrowser, waitFor } from './native-browser.mjs';

const focused = selector => document.activeElement.matches(selector);
const drawerOpen = () => document.querySelector('.lw-work-area').inert;
const dialogOpen = () => !!document.querySelector('[role="dialog"]');
const queueHeading = () => document.activeElement.matches('h1') && document.activeElement.textContent === '审批队列';
const mapExpanded = expanded =>
  document.querySelector('#lw-map-toggle').getAttribute('aria-expanded') === String(expanded) &&
  Boolean(document.querySelector('#lw-flow-map').getClientRects().length) === expanded;

async function refreshFocusedElement(browser, server) {
  await browser.evaluate(() => { window.keyboardTestPreviousFocus = document.activeElement; });
  await server.refreshSnapshot({ force: true });
  await waitFor(() => browser.evaluate(() => !window.keyboardTestPreviousFocus.isConnected));
}

async function runViewport(browser, server, width, row, fixture) {
  const { evaluate, press } = browser;
  // A distinct URL ensures we never inspect the previous document after Page.navigate.
  const search = '?keyboard-width=' + width;
  await browser.resize(width);
  await browser.navigate(server.url + '/' + search);
  await waitFor(() => evaluate(query => location.search === query && !!document.querySelector('.lw-stream-state.is-online'), search), 40000);
  const viewport = await evaluate(() => ({
    width: innerWidth, clientWidth: document.documentElement.clientWidth, scrollWidth: document.documentElement.scrollWidth,
  }));
  row.width = viewport.width;
  assert(width === 650 ? row.width > 390 && row.width <= 720 : row.width === width);
  assert(viewport.scrollWidth <= viewport.clientWidth + 1);

  async function expect(name, browserCondition, ...args) {
    row.failedStep = name;
    await waitFor(() => evaluate(browserCondition, ...args), 3500);
    row.passed.push(name);
    delete row.failedStep;
  }
  const expectFocus = (name, selector) => expect(name, focused, selector);
  const setupFocus = selector => evaluate(s => document.querySelector(s).focus(), selector);

  const opener = '#lw-menu-open', close = '#lw-menu-close';
  const overview = '[data-nav-id="overview"]', audit = '[data-nav-id="audit"]';
  await press('Tab');
  await expectFocus('menuEntry', opener);
  await press('Enter');
  await expect('drawerOpens', () => document.activeElement.matches('[data-nav-id="overview"]') && document.querySelector('.lw-work-area').inert);
  await press('ShiftTab');
  await expectFocus('drawerClose', close);
  await press('ShiftTab');
  await expectFocus('drawerReverseWrap', '[data-nav-id="panels"]');
  await press('Tab');
  await expectFocus('drawerForwardWrap', close);
  await press('Escape');
  await expect('drawerEscape', () => document.activeElement.id === 'lw-menu-open' && !document.querySelector('.lw-work-area').inert);
  await press('Enter');
  await waitFor(() => evaluate(drawerOpen));
  await press('Tab');
  await expectFocus('drawerApprovals', '[data-nav-id="approvals"]');
  await press('Tab');
  await expectFocus('drawerAudit', audit);
  await press('Enter');
  await expect('drawerNavigation', () => document.activeElement.matches('h1') && document.activeElement.textContent === '实时审计' && !document.querySelector('.lw-work-area').inert);

  // Set up the next independent interaction on the overview page.
  await setupFocus(opener);
  await press('Enter');
  await waitFor(() => evaluate(drawerOpen));
  await setupFocus(overview);
  await press('Enter');
  const toggle = '#lw-map-toggle';
  await expect('mapInitiallyClosed', mapExpanded, false);
  await setupFocus(toggle);
  await press('Space');
  await expect('mapSpace', mapExpanded, true);
  assert(await evaluate(focused, toggle));
  await refreshFocusedElement(browser, server);
  await expectFocus('mapToggleRefresh', toggle);
  await press('Tab');
  const relay = '#lw-flow-relay';
  await expectFocus('mapFirstNode', relay);
  await refreshFocusedElement(browser, server);
  await expectFocus('mapNodeRefresh', relay);
  await press('ShiftTab');
  await waitFor(() => evaluate(focused, toggle));
  await press('Enter');
  await expect('mapCollapse', mapExpanded, false);
  await press('Enter');
  await waitFor(() => evaluate(mapExpanded, true));
  await press('Tab');
  await press('Tab');
  await expectFocus('mapApprovalsNode', '#lw-flow-approvals');
  await press('Enter');
  await expect('mapOpensQueue', queueHeading);

  const trigger = '#lw-review-' + fixture.id;
  const cancel = '#lw-review-cancel', confirm = '#lw-review-confirm', request = '#lw-review-request';
  await press('Tab');
  await expectFocus('queueReviewEntry', trigger);
  await press('Enter');
  await expect('reviewOpens', () => document.activeElement.id === 'lw-review-cancel' && document.querySelector('.lw-app-frame').inert);
  await expect('reviewContents', hash => {
    const modal = document.querySelector('.lw-modal');
    return modal.innerText.includes(hash) && document.querySelector('#lw-review-request').textContent.includes('native-keyboard.txt') &&
      modal.scrollWidth <= modal.clientWidth + 1;
  }, fixture.reviewDigest);
  await press('ShiftTab');
  await expectFocus('reviewText', request);
  await press('ShiftTab');
  await expectFocus('reviewReverseWrap', confirm);
  await press('Tab');
  await expectFocus('reviewForwardWrap', request);
  await press('Tab');
  await expectFocus('reviewCancel', cancel);
  await press('Tab');
  await expectFocus('reviewConfirm', confirm);
  await refreshFocusedElement(browser, server);
  await expectFocus('reviewConfirmRefresh', confirm);
  await press('Escape');
  await expect('reviewEscape', selector => document.activeElement.matches(selector) && !document.querySelector('.lw-app-frame').inert, trigger);
  await refreshFocusedElement(browser, server);
  await expectFocus('reviewEntryRefresh', trigger);
  await press('Enter');
  await waitFor(() => evaluate(focused, cancel));
  await press('Enter');
  await expect('reviewDefaultCancel', selector => document.activeElement.matches(selector) && !document.querySelector('[role="dialog"]'), trigger);
  await assert.rejects(fs.stat(fixture.approvedFile), { code: 'ENOENT' });
}

export async function verifyKeyboard(root, report) {
  // Keep the profile and synthetic state under the outer runner's disposable job directory.
  const work = await fs.mkdtemp(path.join(root, '.keyboard-'));
  const stateDir = path.join(work, 'state'), workspace = path.join(work, 'workspace');
  const id = crypto.randomUUID();
  const origin = 'https://example.invalid';
  const request = {
    origin, authorization: { userId: 'fixture', clientId: 'native-ui', scope: ['computer:read'] },
    method: 'tools/call', params: { name: 'read_file', arguments: { path: '/workspace/native-keyboard.txt' } },
  };
  const hash = digest(request);
  const approvals = path.join(stateDir, 'approvals');
  const approvedFile = path.join(approvals, id + '.approved.json');
  let server, browser;
  try {
    await fs.mkdir(workspace, { mode: 0o700 });
    await fs.mkdir(approvals, { recursive: true, mode: 0o700 });
    await fs.writeFile(path.join(stateDir, 'config.json'), JSON.stringify({
      origin, roots: [workspace], defaultCwd: workspace, allowExec: false, requireLocalApproval: true,
    }), { mode: 0o600 });
    report.phase = 'browser';
    browser = await openNativeBrowser(work);
    report.browser = browser.version;
    const now = Date.now();
    const pending = { id, hash, createdAt: now, expiresAt: now + 300000, request };
    await fs.writeFile(path.join(approvals, id + '.request.json'), JSON.stringify(pending), { mode: 0o600 });
    report.phase = 'console';
    const offline = async () => ({});
    server = await startUnifiedConsole({
      stateDir, host: '127.0.0.1', consolePort: 0, enableControlSocket: false, previewAutoSession: true,
      gatewayProbe: offline, dockerProbe: offline, systemdProbe: offline, passkeyDetector: () => ({ supported: false }),
      pollIntervalMs: 60000,
    });
    for (const name of ['console.js', 'console.css']) {
      const response = await fetch(server.url + '/' + name, { signal: AbortSignal.timeout(10000) });
      assert(response.ok);
      const bytes = Buffer.from(await response.arrayBuffer());
      assert((await fs.readFile(path.join(root, 'packages/console/dist', name))).equals(bytes));
      report.assets[name] = crypto.createHash('sha256').update(bytes).digest('hex');
    }
    report.phase = 'keyboard';
    for (const requestedWidth of [650, 390, 320]) {
      const row = { requestedWidth, passed: [] };
      report.viewports.push(row);
      await runViewport(browser, server, requestedWidth, row, { id, reviewDigest: digest(pending), approvedFile });
    }
    // The final cancel left focus on the same pending request. Only this explicit Enter may approve it.
    report.phase = 'approval';
    await browser.press('Enter');
    await waitFor(() => browser.evaluate(focused, '#lw-review-cancel'));
    await browser.press('Tab');
    assert(await browser.evaluate(focused, '#lw-review-confirm'));
    await browser.press('Enter');
    await waitFor(async () => !(await browser.evaluate(dialogOpen)), 30000);
    assert.equal(JSON.parse(await fs.readFile(approvedFile, 'utf8')).hash, hash);
    report.approval.digestMatched = true;
    // Check the settled state too, after the post-approval status update has been rendered.
    await waitFor(() => browser.evaluate(queueHeading));
    await refreshFocusedElement(browser, server);
    await waitFor(() => browser.evaluate(queueHeading));
    report.approval.queueFocusRestored = true;
  } finally {
    try { await browser?.close(); }
    finally {
      try { await server?.close(); }
      finally { await fs.rm(work, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 }); }
    }
  }
  report.phase = 'complete';
}
