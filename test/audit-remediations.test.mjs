import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import {
  STORAGE_KEY_USER_LANG,
  checkAndApplyLanguageRedirect,
  getTargetRedirectUrl,
  resetLanguageSwitcherListenerForTests,
  setupLanguageSwitcherListener,
  syncLanguageOnRoute,
} from '../docs-site/.vitepress/theme/i18n.ts';
import { beneath } from '../local/file-safety.mjs';
import { createSandboxRuntime } from '../local/sandbox.mjs';
import { loadPendingRequests, safeText } from '../local/approval-cli.mjs';
import { digest } from '../local/request-policy.mjs';

const exec = promisify(execFile);

function makeMemoryStorage(initial = {}) {
  const store = new Map(Object.entries(initial));
  return {
    getItem: key => (store.has(key) ? store.get(key) : null),
    setItem: (key, value) => { store.set(key, String(value)); },
    removeItem: key => { store.delete(key); },
  };
}

test('i18n getTargetRedirectUrl collapses leading slashes/backslashes and whitespace to prevent open redirects', () => {
  assert.equal(getTargetRedirectUrl('zh', '/en//evil.com'), '/evil.com');
  assert.equal(getTargetRedirectUrl('zh', '/en/\n/evil.com'), '/evil.com');
  assert.equal(getTargetRedirectUrl('zh', '/en///evil.com'), '/evil.com');
  assert.equal(getTargetRedirectUrl('zh', '/en/\\evil.com'), '/evil.com');
  assert.equal(getTargetRedirectUrl('zh', '/en/\\\\evil.com'), '/evil.com');
  assert.equal(getTargetRedirectUrl('zh', '/sub/en//evil.com', '/sub/'), '/sub/evil.com');
  assert.equal(getTargetRedirectUrl('zh', '/en/docs', ''), '/docs');
  assert.equal(getTargetRedirectUrl('zh', '/en/docs', '//evil.com'), '/evil.com/docs');

  assert.equal(getTargetRedirectUrl('en', '/'), '/en/');
  assert.equal(getTargetRedirectUrl('en', '/docs/contracts'), '/en/docs/contracts');
  assert.equal(getTargetRedirectUrl('zh', '/en/'), '/');
  assert.equal(getTargetRedirectUrl('zh', '/en/docs/contracts'), '/docs/contracts');
  assert.equal(getTargetRedirectUrl('en', '/en/docs'), null);
  assert.equal(getTargetRedirectUrl('zh', '/docs'), null);
});

test('i18n checkAndApplyLanguageRedirect enforces same-origin redirects and ignores non-translation nav clicks', () => {
  const globalKeys = ['window', 'document', 'localStorage', 'navigator', 'Element'];
  const savedDescriptors = Object.fromEntries(
    globalKeys.map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)]),
  );
  const setGlobal = (key, value) => Object.defineProperty(globalThis, key, {
    value,
    configurable: true,
    writable: true,
  });
  try {
    const replaced = [];
    const storage = makeMemoryStorage({ [STORAGE_KEY_USER_LANG]: 'zh' });
    setGlobal('localStorage', storage);
    setGlobal('navigator', { languages: ['zh-CN'], language: 'zh-CN' });
    setGlobal('window', {
      location: {
        origin: 'https://docs.example.test',
        pathname: '/en//evil.com',
        search: '',
        hash: '',
        replace: url => { replaced.push(url); },
      },
    });
    assert.equal(checkAndApplyLanguageRedirect('/'), true);
    assert.deepEqual(replaced, ['/evil.com']);

    // Opaque origin cannot construct a valid same-origin target URL and fails closed.
    replaced.length = 0;
    globalThis.window.location.origin = 'null';
    globalThis.window.location.pathname = '/en/docs';
    assert.equal(checkAndApplyLanguageRedirect('/'), false);
    assert.deepEqual(replaced, []);

    // Translation switcher listener only treats translation containers as language switcher links.
    const listeners = [];
    class FakeElement {
      constructor(classes, attrs = {}, parent = null) {
        this.classes = new Set(classes);
        this.attrs = attrs;
        this.parent = parent;
      }
      getAttribute(name) { return this.attrs[name] ?? null; }
      closest(selector) {
        const wanted = selector.split(',').map(s => s.trim());
        let cursor = this;
        while (cursor) {
          for (const item of wanted) {
            if (item.startsWith('.') && cursor.classes.has(item.slice(1))) return cursor;
            if (!item.startsWith('.') && cursor.attrs.tagName === item) return cursor;
          }
          cursor = cursor.parent;
        }
        return null;
      }
    }
    setGlobal('Element', FakeElement);
    setGlobal('document', {
      addEventListener(type, fn) { if (type === 'click') listeners.push(fn); },
      removeEventListener() {},
    });
    resetLanguageSwitcherListenerForTests();
    setupLanguageSwitcherListener();
    assert.equal(listeners.length, 1);

    storage.setItem(STORAGE_KEY_USER_LANG, 'en');
    const navMenuLink = new FakeElement(['VPNavBarMenuLink'], { tagName: 'a', href: '/docs/' });
    listeners[0]({ target: navMenuLink });
    assert.equal(storage.getItem(STORAGE_KEY_USER_LANG), 'en');

    const navScreenMenuLink = new FakeElement(['VPNavScreenMenuLink'], { tagName: 'a', href: '/docs/' });
    listeners[0]({ target: navScreenMenuLink });
    assert.equal(storage.getItem(STORAGE_KEY_USER_LANG), 'en');

    const translationMenu = new FakeElement(['VPNavBarTranslations']);
    const translationLink = new FakeElement([], { tagName: 'a', href: '/docs/' }, translationMenu);
    listeners[0]({ target: translationLink });
    assert.equal(storage.getItem(STORAGE_KEY_USER_LANG), 'zh');

    const screenTranslations = new FakeElement(['VPNavScreenTranslations']);
    const screenTranslationLink = new FakeElement([], { tagName: 'a', href: '/en/docs/' }, screenTranslations);
    listeners[0]({ target: screenTranslationLink });
    assert.equal(storage.getItem(STORAGE_KEY_USER_LANG), 'en');

    // syncLanguageOnRoute must strip non-root base paths before deciding locale.
    syncLanguageOnRoute('/repo-subpath/docs/', '/repo-subpath/');
    assert.equal(storage.getItem(STORAGE_KEY_USER_LANG), 'zh');
    syncLanguageOnRoute('/repo-subpath/en/docs/', '/repo-subpath/');
    assert.equal(storage.getItem(STORAGE_KEY_USER_LANG), 'en');
    resetLanguageSwitcherListenerForTests();
  } finally {
    for (const [key, descriptor] of Object.entries(savedDescriptors)) {
      if (descriptor === undefined) delete globalThis[key];
      else Object.defineProperty(globalThis, key, descriptor);
    }
  }
});

test('sandbox beneath() and createSandboxRuntime block ..state prefixes and bidirectional overlaps', async t => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'agentdock-sandbox-beneath-'));
  t.after(async () => {
    await fs.rm(base, { recursive: true, force: true });
  });

  const workspace = path.join(base, 'workspace');
  const dotDotState = path.join(workspace, '..state');
  const nestedWorkspace = path.join(base, 'state-parent', 'workspace');
  const stateParent = path.join(base, 'state-parent');
  const fakeDocker = path.join(workspace, '..docker');
  await fs.mkdir(dotDotState, { recursive: true });
  await fs.mkdir(nestedWorkspace, { recursive: true });
  await fs.writeFile(fakeDocker, 'not-a-docker-binary');

  assert.equal(beneath(dotDotState, workspace), true);
  assert.equal(beneath(path.join(workspace, '..'), workspace), false);
  assert.equal(beneath(path.join(base, 'outside'), workspace), false);

  const baseConfig = {
    allowExec: false,
    sandbox: { enabled: true, image: `sha256:${'a'.repeat(64)}`, dockerPath: fakeDocker, context: 'desktop-linux' },
  };

  // stateDir named ..state inside workspace must be rejected.
  await assert.rejects(
    createSandboxRuntime({ ...baseConfig, roots: [workspace], stateDir: dotDotState }),
    /outside the mounted workspace/,
  );

  // workspace inside stateDir (beneath(root, state)) must be rejected.
  await assert.rejects(
    createSandboxRuntime({ ...baseConfig, roots: [nestedWorkspace], stateDir: stateParent }),
    /outside the mounted workspace/,
  );

  // dockerPath named ..docker inside workspace must be rejected.
  const externalState = path.join(base, 'external-state');
  await fs.mkdir(externalState);
  await assert.rejects(
    createSandboxRuntime({ ...baseConfig, roots: [workspace], stateDir: externalState }),
    /trusted file outside the workspace/,
  );

  // workspace inside runtime directory (beneath(root, import.meta.dirname)) must be rejected.
  const runtimeDir = path.join(base, 'runtime');
  await fs.mkdir(runtimeDir);
  for (const file of await fs.readdir(new URL('../local/', import.meta.url))) {
    if (file.endsWith('.mjs')) {
      await fs.copyFile(new URL(`../local/${file}`, import.meta.url), path.join(runtimeDir, file));
    }
  }
  const insideRuntime = path.join(runtimeDir, 'nested-workspace');
  await fs.mkdir(insideRuntime);
  const { createSandboxRuntime: isolatedCreate } = await import(pathToFileURL(path.join(runtimeDir, 'sandbox.mjs')).href);
  await assert.rejects(
    isolatedCreate({ ...baseConfig, roots: [insideRuntime], stateDir: externalState }),
    /outside the mounted workspace/,
  );
});

test('approval-cli loadPendingRequests validates records before enforcing the 64-item queue cap', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'agentdock-approval-cli-'));
  t.after(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });
  const now = 1_700_000_000_000;
  const makeRecord = async (createdAt, index) => {
    const id = randomUUID();
    const request = {
      origin: 'https://example.test',
      authorization: { userId: 'owner', clientId: 'cli-test', scope: ['computer:read'] },
      method: 'tools/call',
      params: { name: 'read_file', arguments: { path: `/workspace/f-${index}.txt` } },
    };
    const record = { id, hash: digest(request), createdAt, expiresAt: createdAt + 300000, request };
    await fs.writeFile(path.join(dir, `${id}.request.json`), JSON.stringify(record));
    return id;
  };

  for (let i = 0; i < 64; i++) await makeRecord(now - 1000 + i, i);
  // Expired and corrupt request files must not trip the 64-valid-record limit.
  await makeRecord(now - 400000, 'expired');
  await fs.writeFile(path.join(dir, `${randomUUID()}.request.json`), '{');

  const loaded = await loadPendingRequests(dir, now);
  assert.equal(loaded.length, 64);
  assert.ok(loaded[0].createdAt <= loaded[63].createdAt);

  // A 65th valid unexpired request must trigger the queue cap.
  await makeRecord(now - 10, 'overflow');
  await assert.rejects(loadPendingRequests(dir, now), /Approval queue exceeds the allowed limit/);
});

test('repo_maintenance_guard passes timeout=30 to git subprocesses and exits non-zero on TimeoutExpired', async () => {
  const script = `
import io
import subprocess
import sys
from contextlib import redirect_stderr
from unittest import mock

sys.path.insert(0, 'tools')
import repo_maintenance_guard as guard

seen_timeouts = []
def fake_run(cmd, **kwargs):
    seen_timeouts.append((cmd[:2], kwargs.get('timeout')))
    raise subprocess.TimeoutExpired(cmd, kwargs.get('timeout'))

stderr = io.StringIO()
with mock.patch.object(guard.subprocess, 'run', side_effect=fake_run):
    with mock.patch.object(sys, 'argv', ['repo_maintenance_guard.py', 'status']):
        with redirect_stderr(stderr):
            code = guard.main()

assert code == 1, f'expected exit 1, got {code}'
assert seen_timeouts == [(['git', 'rev-parse'], 30)], seen_timeouts
assert '超时' in stderr.getvalue(), stderr.getvalue()

cat_timeouts = []
def fake_pushed_run(cmd, **kwargs):
    cat_timeouts.append((cmd[:3], kwargs.get('timeout')))
    if cmd[:2] == ['git', 'rev-parse']:
        return subprocess.CompletedProcess(cmd, 0, stdout=b'abc123\\n', stderr=b'')
    raise subprocess.TimeoutExpired(cmd, kwargs.get('timeout'))

line = b'refs/heads/main ' + b'a' * 40 + b' refs/heads/main ' + b'b' * 40 + b'\\n'
with mock.patch.object(guard.subprocess, 'run', side_effect=fake_pushed_run):
    try:
        guard.pushed(line, {})
        raise AssertionError('expected TimeoutExpired')
    except subprocess.TimeoutExpired:
        pass

assert (['git', 'cat-file', '-e'], 30) in cat_timeouts, cat_timeouts
print('GUARD_OK')
`;
  const { stdout } = await exec('python3', ['-B', '-c', script], {
    cwd: path.resolve(import.meta.dirname, '..'),
  });
  assert.equal(stdout.trim(), 'GUARD_OK');
});

test('approval-cli safeText escapes format/invisible Unicode and guards cover blocked paths, scissors, ObjectBatch, and mirror slug', async () => {
  assert.equal(safeText('a\u200bb\u202ec\u00a0d\u{e0041}e'), 'a\\u200bb\\u202ec\\u00a0d\\u{e0041}e');

  const script = `
import re
import sys
from unittest import mock

sys.path.insert(0, 'tools')
sys.path.insert(0, '.github/scripts')
import repo_maintenance_guard as guard
import sync_assets_licenses as sync_mod

# Blocked path checks
assert guard.blocked_path('.dev.vars')
assert guard.blocked_path('secrets.dpapi')
assert guard.blocked_path('wrangler.jsonc')
assert guard.blocked_path('.env.test')
assert not guard.blocked_path('.env.example')
assert not guard.blocked_path('wrangler.jsonc.example')

# Commit -v scissors diff must not trigger secret scan
synthetic_key = "AKIA" + "1234567890" + "ABCDEF"
msg = "feat(cloud): add feature\\n\\n# ------------------------ >8 ------------------------\\n# " + synthetic_key + "\\n"
assert guard.message_problems(msg) == [], guard.message_problems(msg)

# Allowlist rejects symlinked entries
with mock.patch.object(guard, 'git', return_value=b'120000 deadbeef 0\\t.repo-security-allowlist.json\\n'):
    try:
        guard.allowlist(guard.Path('.'))
        raise AssertionError('Expected symlinked allowlist rejection')
    except ValueError:
        pass

# Mirror slug regex matches production enforcement
assert sync_mod.MIRROR_SLUG_RE.fullmatch('CyberNova2333/agentdock-worker-remote')
assert not sync_mod.MIRROR_SLUG_RE.fullmatch('CyberNova2333/bad?query=1')
assert not sync_mod.MIRROR_SLUG_RE.fullmatch('../escape')
assert not sync_mod.MIRROR_SLUG_RE.fullmatch('./escape')
assert not sync_mod.MIRROR_SLUG_RE.fullmatch('org/..')
assert hasattr(sync_mod, 'redact_url_userinfo')
print('EXTENDED_GUARDS_OK')
`;
  const { stdout } = await exec('python3', ['-B', '-c', script], {
    cwd: path.resolve(import.meta.dirname, '..'),
  });
  assert.equal(stdout.trim(), 'EXTENDED_GUARDS_OK');
});
