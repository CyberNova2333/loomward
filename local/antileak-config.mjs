// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Safe out-of-workspace configuration, cache health telemetry, and offline dry-run / doctor helpers for @loomward/plugin-antileak (R1-R7).
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { StringDecoder } from 'node:string_decoder';
import { redactSecretsFromText } from './mcp-registry.mjs';
import { assertConfigOutsideWorkspace, loadWorkspaceRootsFromStateConfig } from './capabilities.mjs';
import { assertPrivateFile, assertPrivateState } from './host-safety.mjs';

const MAX_POLICY_BYTES = 128 * 1024;
const MAX_CACHE_BYTES = 4 * 1024 * 1024;
const MAX_LIST_ITEMS = 64;
const MAX_ITEM_CHARS = 256;
const MAX_DRY_RUN_BYTES = 256 * 1024;
const MAX_CHILD_OUTPUT_BYTES = 32 * 1024;
const DEFAULT_TTL_SECONDS = 28800;
const DEFAULT_RESOLVE_TTL_SECONDS = 86400;

export const DEFAULT_EXEMPT_TOOLS = Object.freeze([
  'computer_context',
  'command_status',
  'stop_command',
]);

export const ANTILEAK_RULES_CATALOG = Object.freeze([
  Object.freeze({
    id: 'R1',
    name: '动态私有仓名拦截',
    stage: 'content / commit / push',
    controlField: 'expectedOwners / privateCacheTtl / resolveBudget',
    summary: '依据本机 private-repos.json 动态名单与归属者清单拦截未脱敏私有仓名；缓存缺失或过期强制 fail-closed。',
  }),
  Object.freeze({
    id: 'R2',
    name: '敏感模式与术语正则',
    stage: 'content / commit / push',
    controlField: 'forbiddenPatterns',
    summary: '匹配 forbidden_patterns 正则规则并结合高熵 Base64 启发式过滤图片/音频内嵌误报。',
  }),
  Object.freeze({
    id: 'R3',
    name: 'Agent 合著与提交规范守卫',
    stage: 'commit',
    controlField: 'commit hook',
    summary: '确保提交消息包含清晰的 Co-authored-by 协作签名与提交者追溯信息。',
  }),
  Object.freeze({
    id: 'R4',
    name: '动态业务标识与 Push 内容重审',
    stage: 'commit / push',
    controlField: 'resignExempt',
    summary: '对私有种子提取的 patterns 正则及待推送提交新增行实施全量复扫，支持 patch-id 重签豁免开关。',
  }),
  Object.freeze({
    id: 'R5',
    name: 'Agent 分支前缀保护',
    stage: 'push',
    controlField: 'agentBranchPrefixes',
    summary: '阻止向 claude/、codex/、chatgpt/ 等自动分支前缀直接推送未经审查或含敏感信息的提交。',
  }),
  Object.freeze({
    id: 'R6',
    name: '独立 SSH 签名指纹与邮箱校验',
    stage: 'commit / push',
    controlField: 'agentSigningFingerprint / agentProviderEmails',
    summary: '使用 ssh-keygen -Y 对 gpgsig 密码学验签并比对独立 Signing Key 指纹，同时拦截 Agent 提供商 noreply 邮箱。',
  }),
  Object.freeze({
    id: 'R7',
    name: '凭据与私钥硬拦截',
    stage: 'content / commit / push',
    controlField: 'secretRegexes',
    summary: '强拦截 SSH/RSA 私钥、GitHub/云厂商令牌与 SK 密钥；命中回显强制脱敏至前 8 字符。',
  }),
]);

export function resolveAntileakEnginePaths(repoRoot = path.resolve(import.meta.dirname, '..')) {
  const engineDir = path.join(path.resolve(repoRoot), 'plugins', 'antileak', 'engine');
  return Object.freeze({
    engineDir,
    defaultPolicyPath: path.join(engineDir, 'policy.json'),
    checkScript: path.join(engineDir, 'check.py'),
    doctorScript: path.join(engineDir, 'doctor.py'),
    refreshScript: path.join(engineDir, 'refresh-private.py'),
  });
}

export function antileakStateDir(stateDir) {
  return path.join(path.resolve(stateDir), 'antileak');
}

export function antileakPolicyFilePath(stateDir) {
  return path.join(antileakStateDir(stateDir), 'policy.json');
}

export function antileakCacheFilePath(stateDir) {
  return path.join(antileakStateDir(stateDir), 'private-repos.json');
}

function readJsonNoFollowSync(filePath, maxBytes, { requireOwner = false } = {}) {
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0);
  let fd;
  try {
    fd = fs.openSync(filePath, flags);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > maxBytes) {
      throw new Error(`Security policy file exceeds size or link invariants: ${path.basename(filePath)}`);
    }
    if (requireOwner) {
      assertPrivateFile(filePath);
    }
    const text = fs.readFileSync(fd, 'utf8');
    const parsed = text.trim() ? JSON.parse(text) : {};
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error(`Expected JSON object in ${path.basename(filePath)}.`);
    }
    return parsed;
  } finally {
    try { fs.closeSync(fd); } catch {}
  }
}

function loadDefaultEnginePolicy() {
  const { defaultPolicyPath } = resolveAntileakEnginePaths();
  try {
    const raw = readJsonNoFollowSync(defaultPolicyPath, MAX_POLICY_BYTES, { requireOwner: false });
    return raw || {};
  } catch {
    return {};
  }
}

function normalizeStringArray(value, fallback = [], { label = 'list', toolNamesOnly = false } = {}) {
  const src = value !== undefined ? value : fallback;
  if (!Array.isArray(src)) {
    throw new Error(`${label} must be an array of strings.`);
  }
  if (src.length > MAX_LIST_ITEMS) {
    throw new Error(`${label} cannot contain more than ${MAX_LIST_ITEMS} entries.`);
  }
  const seen = new Set();
  const out = [];
  for (const item of src) {
    if (typeof item !== 'string') {
      throw new Error(`${label} entries must be strings.`);
    }
    const trimmed = item.trim();
    if (!trimmed) continue;
    if (trimmed.length > MAX_ITEM_CHARS || /[\r\n\0]/.test(trimmed)) {
      throw new Error(`${label} entry exceeds length limit or contains invalid control characters.`);
    }
    if (toolNamesOnly && !/^[A-Za-z0-9._:-]{1,64}$/.test(trimmed)) {
      throw new Error(`Invalid exempt tool identifier: ${trimmed}`);
    }
    if (!seen.has(trimmed)) {
      seen.add(trimmed);
      out.push(trimmed);
    }
  }
  return out;
}

function normalizeBoundedInt(value, fallback, min, max, label) {
  if (value === undefined || value === null || value === '') return fallback;
  const num = Number(value);
  if (!Number.isInteger(num) || num < min || num > max) {
    throw new Error(`${label} must be an integer between ${min} and ${max}.`);
  }
  return num;
}

function normalizeFingerprint(value, fallback = '') {
  const raw = typeof value === 'string' ? value.trim() : typeof fallback === 'string' ? fallback.trim() : '';
  if (!raw) return '';
  if (!/^(?:SHA256:)?[A-Za-z0-9+/=_-]{8,128}$/.test(raw)) {
    throw new Error('Agent signing fingerprint must be empty or a valid SSH SHA256 fingerprint.');
  }
  return raw.startsWith('SHA256:') ? raw : `SHA256:${raw}`;
}

function normalizeCnbApiUrl(value, fallback = 'https://api.cnb.cool') {
  const raw = typeof value === 'string' ? value.trim() : (typeof fallback === 'string' ? fallback.trim() : '');
  if (!raw) return 'https://api.cnb.cool';
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error('cnbApi must be a valid HTTPS URL.');
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
    throw new Error('cnbApi must use HTTPS without embedded credentials.');
  }
  return parsed.toString().replace(/\/$/, '');
}

export function normalizeAntileakPolicy(rawInput = {}, existing = {}, stateDir = '') {
  const defaults = loadDefaultEnginePolicy();
  const base = { ...defaults, ...existing };
  const input = rawInput && typeof rawInput === 'object' && !Array.isArray(rawInput) ? rawInput : {};

  const forbiddenPatterns = normalizeStringArray(
    input.forbiddenPatterns ?? input.forbidden_patterns,
    base.forbidden_patterns || [],
    { label: 'forbiddenPatterns' },
  );
  const secretRegexes = normalizeStringArray(
    input.secretRegexes ?? input.secret_regexes,
    base.secret_regexes || [],
    { label: 'secretRegexes' },
  );
  const agentBranchPrefixes = normalizeStringArray(
    input.agentBranchPrefixes ?? input.agent_branch_prefixes,
    base.agent_branch_prefixes || [],
    { label: 'agentBranchPrefixes' },
  );
  const agentProviderEmails = normalizeStringArray(
    input.agentProviderEmails ?? input.agent_provider_emails,
    base.agent_provider_emails || [],
    { label: 'agentProviderEmails' },
  );
  const expectedOwners = normalizeStringArray(
    input.expectedOwners ?? input.expected_owners,
    base.expected_owners || [],
    { label: 'expectedOwners' },
  );
  const resolveIgnore = normalizeStringArray(
    input.resolveIgnore ?? input.resolve_ignore,
    base.resolve_ignore || [],
    { label: 'resolveIgnore' },
  );
  const exemptTools = normalizeStringArray(
    input.exemptTools ?? input.exempt_tools,
    base.exempt_tools || DEFAULT_EXEMPT_TOOLS,
    { label: 'exemptTools', toolNamesOnly: true },
  );

  const agentSigningFingerprint = normalizeFingerprint(
    input.agentSigningFingerprint ?? input.agent_signing_fingerprint,
    base.agent_signing_fingerprint || '',
  );
  const signingInstructionsRaw = input.signingInstructions ?? input.signing_instructions ?? base.signing_instructions ?? '';
  if (typeof signingInstructionsRaw !== 'string' || signingInstructionsRaw.length > 400 || /[\r\n\0]/.test(signingInstructionsRaw)) {
    throw new Error('signingInstructions must be a single concise line up to 400 characters.');
  }
  const privateCacheTtl = normalizeBoundedInt(
    input.privateCacheTtl ?? input.private_cache_ttl,
    Number.isInteger(base.private_cache_ttl) ? base.private_cache_ttl : DEFAULT_TTL_SECONDS,
    300,
    86400,
    'privateCacheTtl',
  );
  const resolveBudget = normalizeBoundedInt(
    input.resolveBudget ?? input.resolve_budget,
    Number.isInteger(base.resolve_budget) ? base.resolve_budget : 30,
    0,
    200,
    'resolveBudget',
  );
  const resolveCacheTtl = normalizeBoundedInt(
    input.resolveCacheTtl ?? input.resolve_cache_ttl,
    Number.isInteger(base.resolve_cache_ttl) ? base.resolve_cache_ttl : DEFAULT_RESOLVE_TTL_SECONDS,
    300,
    604800,
    'resolveCacheTtl',
  );
  const resignExemptRaw = input.resignExempt ?? input.resign_exempt;
  const resignExempt = resignExemptRaw !== undefined
    ? Boolean(resignExemptRaw)
    : (base.resign_exempt !== undefined ? Boolean(base.resign_exempt) : true);
  const cnbApi = normalizeCnbApiUrl(input.cnbApi ?? input.cnb_api, base.cnb_api || 'https://api.cnb.cool');
  const paths = resolveAntileakEnginePaths();
  const safeCachePath = stateDir ? antileakCacheFilePath(stateDir) : paths.engineDir;

  const diskJson = {
    forbidden_patterns: forbiddenPatterns,
    secret_regexes: secretRegexes,
    agent_branch_prefixes: agentBranchPrefixes,
    agent_provider_emails: agentProviderEmails,
    agent_signing_fingerprint: agentSigningFingerprint,
    signing_instructions: signingInstructionsRaw.trim(),
    private_cache: safeCachePath,
    private_cache_ttl: privateCacheTtl,
    refresh_script: paths.refreshScript,
    expected_owners: expectedOwners,
    resolve_script: path.join(paths.engineDir, 'resolve-private.py'),
    resolve_budget: resolveBudget,
    resolve_cache_ttl: resolveCacheTtl,
    resolve_ignore: resolveIgnore,
    resign_exempt: resignExempt,
    exempt_tools: exemptTools,
    cnb_api: cnbApi,
    ...(typeof base.private_seed === 'string' && base.private_seed ? { private_seed: base.private_seed } : {}),
    ...(typeof base.cnb_token_file === 'string' && base.cnb_token_file ? { cnb_token_file: base.cnb_token_file } : {}),
    updated_at: new Date().toISOString(),
  };

  const uiView = {
    forbiddenPatterns,
    secretRegexes,
    agentBranchPrefixes,
    agentProviderEmails,
    agentSigningFingerprint,
    signingInstructions: diskJson.signing_instructions,
    expectedOwners,
    privateCacheTtl,
    resolveBudget,
    resolveCacheTtl,
    resolveIgnore,
    resignExempt,
    exemptTools,
    cnbApi,
    hasCnbTokenFile: Boolean(diskJson.cnb_token_file),
    updatedAt: typeof existing.updated_at === 'string' ? existing.updated_at : null,
  };

  return { diskJson, uiView };
}

export function readAntileakCacheHealthSync(
  stateDir,
  { ttlSeconds = DEFAULT_TTL_SECONDS, workspaceRoots, requirePrivateState = true } = {},
) {
  if (!stateDir) {
    return { status: 'missing', updatedAt: null, expiresInSeconds: 0, privateCount: 0, patternCount: 0, ownerCount: 0 };
  }
  const cachePath = antileakCacheFilePath(stateDir);
  const roots = workspaceRoots ?? loadWorkspaceRootsFromStateConfig(stateDir);
  assertConfigOutsideWorkspace(cachePath, roots);
  const dir = antileakStateDir(stateDir);
  if (fs.existsSync(dir)) {
    assertPrivateState(dir);
  }
  try {
    const raw = readJsonNoFollowSync(cachePath, MAX_CACHE_BYTES, { requireOwner: requirePrivateState });
    if (!raw) {
      return { status: 'missing', updatedAt: null, expiresInSeconds: 0, privateCount: 0, patternCount: 0, ownerCount: 0, sources: [] };
    }
    const nowSec = Date.now() / 1000;
    const genSec = Number.isFinite(raw.generated_at)
      ? Number(raw.generated_at)
      : typeof raw.updated_at === 'string'
        ? Date.parse(raw.updated_at) / 1000
        : Number.isFinite(raw.updated_at) ? Number(raw.updated_at) : NaN;
    const ttl = Number.isFinite(ttlSeconds) && ttlSeconds > 0 ? ttlSeconds : DEFAULT_TTL_SECONDS;
    const expSec = Number.isFinite(raw.expires_at)
      ? Number(raw.expires_at)
      : Number.isFinite(genSec) ? genSec + ttl : NaN;
    const expiresInSeconds = Number.isFinite(expSec) ? Math.max(0, Math.round(expSec - nowSec)) : 0;
    const status = Number.isFinite(expSec) && expSec > nowSec ? 'fresh' : 'stale';
    // Only expose aggregate counts and non-secret source labels to the UI; never return private repo names or pattern strings.
    return {
      status,
      updatedAt: Number.isFinite(genSec) ? new Date(genSec * 1000).toISOString() : null,
      expiresInSeconds,
      privateCount: Array.isArray(raw.private) ? raw.private.length : 0,
      patternCount: Array.isArray(raw.patterns) ? raw.patterns.length : 0,
      ownerCount: Array.isArray(raw.owners) ? raw.owners.length : 0,
      sources: Array.isArray(raw.sources) ? raw.sources.map(s => String(s)).slice(0, 8) : [],
    };
  } catch {
    return { status: 'corrupt', updatedAt: null, expiresInSeconds: 0, privateCount: 0, patternCount: 0, ownerCount: 0, sources: [] };
  }
}

export function readAntileakConfigSync(
  stateDir,
  { workspaceRoots, requirePrivateState = true } = {},
) {
  const roots = workspaceRoots ?? (stateDir ? loadWorkspaceRootsFromStateConfig(stateDir) : []);
  if (!stateDir) {
    const { uiView } = normalizeAntileakPolicy({}, {}, '');
    return {
      exists: false,
      config: uiView,
      cache: { status: 'missing', updatedAt: null, expiresInSeconds: 0, privateCount: 0, patternCount: 0, ownerCount: 0 },
      rules: ANTILEAK_RULES_CATALOG,
      error: null,
    };
  }

  const filePath = antileakPolicyFilePath(stateDir);
  assertConfigOutsideWorkspace(filePath, roots);
  const dir = antileakStateDir(stateDir);
  if (fs.existsSync(dir)) {
    assertPrivateState(dir);
  }
  let existing = null;
  let loadError = null;
  try {
    existing = readJsonNoFollowSync(filePath, MAX_POLICY_BYTES, { requireOwner: requirePrivateState });
  } catch (err) {
    loadError = redactSecretsFromText(err?.message || 'Unable to read anti-leak policy.', null, 240);
  }
  const { uiView } = normalizeAntileakPolicy({}, existing || {}, stateDir);
  const cache = readAntileakCacheHealthSync(stateDir, {
    ttlSeconds: uiView.privateCacheTtl,
    workspaceRoots: roots,
    requirePrivateState,
  });
  return {
    exists: Boolean(existing),
    config: uiView,
    cache,
    rules: ANTILEAK_RULES_CATALOG,
    error: loadError,
  };
}

export function writeAntileakConfigSync(
  stateDir,
  patch,
  { workspaceRoots, requirePrivateState = true } = {},
) {
  if (!stateDir) {
    throw new Error('stateDir is required to save anti-leak configuration.');
  }
  const roots = workspaceRoots ?? loadWorkspaceRootsFromStateConfig(stateDir);
  const filePath = antileakPolicyFilePath(stateDir);
  assertConfigOutsideWorkspace(filePath, roots);
  const dir = antileakStateDir(stateDir);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  assertPrivateState(dir);
  if (process.platform !== 'win32') fs.chmodSync(dir, 0o700);

  let existing = {};
  try {
    existing = readJsonNoFollowSync(filePath, MAX_POLICY_BYTES, { requireOwner: requirePrivateState }) || {};
  } catch (err) {
    if (err?.code !== 'ENOENT') throw err;
  }
  const { diskJson, uiView } = normalizeAntileakPolicy(patch, existing, stateDir);
  uiView.updatedAt = diskJson.updated_at;

  const tmpPath = path.join(dir, `.tmp-al-policy-${crypto.randomUUID()}.json`);
  const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0);
  let fd;
  try {
    fd = fs.openSync(tmpPath, flags, 0o600);
    fs.writeFileSync(fd, JSON.stringify(diskJson, null, 2) + '\n', 'utf8');
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    if (process.platform !== 'win32') fs.chmodSync(tmpPath, 0o600);
    fs.renameSync(tmpPath, filePath);
  } catch (error) {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch {}
    }
    try { fs.rmSync(tmpPath, { force: true }); } catch {}
    throw error;
  }

  const cache = readAntileakCacheHealthSync(stateDir, {
    ttlSeconds: uiView.privateCacheTtl,
    workspaceRoots: roots,
    requirePrivateState,
  });
  return {
    exists: true,
    config: uiView,
    cache,
    rules: ANTILEAK_RULES_CATALOG,
    error: null,
  };
}

function buildSanitizedPythonEnv(stateDir, { includeRefreshAuth = false } = {}) {
  const { engineDir, defaultPolicyPath } = resolveAntileakEnginePaths();
  const policyPath = stateDir && fs.existsSync(antileakPolicyFilePath(stateDir))
    ? antileakPolicyFilePath(stateDir)
    : defaultPolicyPath;
  const cachePath = stateDir ? antileakCacheFilePath(stateDir) : path.join(engineDir, 'private-repos.json');
  const env = {
    PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin',
    LANG: process.env.LANG || 'C.UTF-8',
    LC_ALL: process.env.LC_ALL || 'C.UTF-8',
    PYTHONIOENCODING: 'utf-8',
    PYTHONUTF8: '1',
    LOOMWARD_ANTILEAK_POLICY: policyPath,
    LOOMWARD_ANTILEAK_CACHE: cachePath,
  };
  if (includeRefreshAuth) {
    for (const [k, v] of Object.entries(process.env)) {
      if (typeof v !== 'string') continue;
      if (
        k === 'HOME' ||
        k === 'USERPROFILE' ||
        k === 'CNB_TOKEN' ||
        k === 'CNB_API' ||
        k === 'GH_TOKEN' ||
        /^GH_TOKEN_\d+$/.test(k) ||
        k.startsWith('LOOMWARD_ANTILEAK_')
      ) {
        env[k] = v;
      }
    }
    env.LOOMWARD_ANTILEAK_POLICY = policyPath;
    env.LOOMWARD_ANTILEAK_CACHE = cachePath;
  }
  return env;
}

function spawnPythonScript({ pythonPath = process.env.LOOMWARD_PYTHON_BIN || 'python3', args, stdinText = '', env, timeoutMs = 8000 }) {
  return new Promise(resolve => {
    const startedAt = Date.now();
    let settled = false;
    let stdout = '';
    let stderr = '';
    let stdoutBytes = 0;
    let stderrBytes = 0;
    const outDec = new StringDecoder('utf8');
    const errDec = new StringDecoder('utf8');
    let child;
    let timer;

    const finish = result => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve({ ...result, durationMs: Date.now() - startedAt });
    };

    try {
      child = spawn(pythonPath, ['-B', ...args], {
        shell: false,
        windowsHide: true,
        env,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } catch (err) {
      finish({ ok: false, exitCode: 1, timedOut: false, stdout: '', stderr: err?.message || 'Failed to spawn python3.' });
      return;
    }

    timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch {}
      finish({ ok: false, exitCode: 124, timedOut: true, stdout, stderr: stderr || 'Execution timed out (fail-closed).' });
    }, timeoutMs);
    timer.unref?.();

    child.stdin.on('error', () => {});
    child.stdout.on('data', chunk => {
      if (stdoutBytes >= MAX_CHILD_OUTPUT_BYTES) return;
      const slice = chunk.subarray(0, MAX_CHILD_OUTPUT_BYTES - stdoutBytes);
      stdoutBytes += slice.length;
      stdout += outDec.write(slice);
    });
    child.stderr.on('data', chunk => {
      if (stderrBytes >= MAX_CHILD_OUTPUT_BYTES) return;
      const slice = chunk.subarray(0, MAX_CHILD_OUTPUT_BYTES - stderrBytes);
      stderrBytes += slice.length;
      stderr += errDec.write(slice);
    });
    child.on('error', err => {
      finish({ ok: false, exitCode: 1, timedOut: false, stdout, stderr: err?.message || 'Python subprocess failed.' });
    });
    child.on('close', code => {
      stdout += outDec.end();
      stderr += errDec.end();
      finish({ ok: code === 0, exitCode: Number.isInteger(code) ? code : 1, timedOut: false, stdout, stderr });
    });

    child.stdin.end(Buffer.from(String(stdinText || ''), 'utf8'));
  });
}

export async function validatePythonRegexList(patterns = [], { pythonPath } = {}) {
  const list = Array.isArray(patterns) ? patterns : [];
  if (!list.length) return;
  const script = [
    'import json, re, sys',
    'data = json.loads(sys.stdin.read() or "[]")',
    'for idx, pat in enumerate(data):',
    '    try:',
    '        re.compile(pat)',
    '    except re.error as exc:',
    '        print(f"{idx}:{exc}", file=sys.stderr)',
    '        sys.exit(2)',
  ].join('\n');
  const res = await spawnPythonScript({
    pythonPath,
    args: ['-c', script],
    stdinText: JSON.stringify(list),
    env: buildSanitizedPythonEnv(''),
    timeoutMs: 4000,
  });
  if (!res.ok) {
    const cleanErr = redactSecretsFromText((res.stderr || 'Invalid regular expression syntax.').trim(), null, 180);
    throw new Error(`Invalid regex pattern: ${cleanErr}`);
  }
}

export async function runAntileakDryRun(
  stateDir,
  { text = '', pythonPath, workspaceRoots, requirePrivateState = true, timeoutMs = 6000 } = {},
) {
  if (typeof text !== 'string') {
    throw new Error('Dry-run payload text must be a string.');
  }
  const inputBytes = Buffer.byteLength(text, 'utf8');
  if (inputBytes > MAX_DRY_RUN_BYTES) {
    throw new Error('Dry-run payload exceeds 256 KiB budget.');
  }
  const roots = workspaceRoots ?? (stateDir ? loadWorkspaceRootsFromStateConfig(stateDir) : []);
  if (stateDir) {
    assertConfigOutsideWorkspace(antileakPolicyFilePath(stateDir), roots);
  }
  const current = readAntileakConfigSync(stateDir, { workspaceRoots: roots, requirePrivateState });
  const { checkScript } = resolveAntileakEnginePaths();
  const res = await spawnPythonScript({
    pythonPath,
    args: [checkScript, 'content'],
    stdinText: text,
    env: buildSanitizedPythonEnv(stateDir),
    timeoutMs,
  });
  const statusToken = res.stdout.trim().split(/\s+/)[0] || (res.exitCode === 0 ? 'pass' : 'error');
  const decision = statusToken === 'pass' ? 'pass' : statusToken === 'violation' ? 'violation' : 'error';
  const lines = res.stderr
    .split(/\r?\n/)
    .map(l => redactSecretsFromText(l.trim(), null, 240))
    .filter(Boolean)
    .slice(0, 8);
  return {
    decision,
    failClosed: decision === 'error',
    timedOut: res.timedOut,
    exitCode: res.exitCode,
    durationMs: res.durationMs,
    bytesInspected: inputBytes,
    findings: lines,
    cache: current.cache,
  };
}

export async function runAntileakDoctor(stateDir, { pythonPath, workspaceRoots, requirePrivateState = true, timeoutMs = 8000 } = {}) {
  const roots = workspaceRoots ?? (stateDir ? loadWorkspaceRootsFromStateConfig(stateDir) : []);
  if (stateDir) {
    assertConfigOutsideWorkspace(antileakPolicyFilePath(stateDir), roots);
  }
  const { doctorScript } = resolveAntileakEnginePaths();
  const res = await spawnPythonScript({
    pythonPath,
    args: [doctorScript],
    env: buildSanitizedPythonEnv(stateDir),
    timeoutMs,
  });
  const combined = `${res.stdout}\n${res.stderr}`.split(/\r?\n/);
  const checks = [];
  for (const rawLine of combined) {
    const trimmed = redactSecretsFromText(rawLine.trim(), null, 240);
    if (!trimmed) continue;
    const match = trimmed.match(/^\[(PASS|WARN|FAIL)\]\s*(.+)$/);
    if (match) {
      checks.push({ level: match[1].toLowerCase(), message: match[2].slice(0, 220) });
    }
  }
  return {
    ok: res.ok && !checks.some(c => c.level === 'fail'),
    exitCode: res.exitCode,
    durationMs: res.durationMs,
    checks,
    summaryLine: checks.length
      ? `${checks.filter(c => c.level === 'pass').length} PASS · ${checks.filter(c => c.level === 'warn').length} WARN · ${checks.filter(c => c.level === 'fail').length} FAIL`
      : redactSecretsFromText((res.stdout || res.stderr || 'Completed').trim(), null, 160),
  };
}

export async function runAntileakRefresh(
  stateDir,
  { pythonPath, workspaceRoots, requirePrivateState = true, timeoutMs = 20000 } = {},
) {
  if (!stateDir) {
    throw new Error('stateDir is required to refresh private repository cache.');
  }
  const roots = workspaceRoots ?? loadWorkspaceRootsFromStateConfig(stateDir);
  const dir = antileakStateDir(stateDir);
  assertConfigOutsideWorkspace(dir, roots);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  assertPrivateState(dir);
  if (process.platform !== 'win32') fs.chmodSync(dir, 0o700);

  const cfg = readAntileakConfigSync(stateDir, { workspaceRoots: roots, requirePrivateState });
  const { refreshScript } = resolveAntileakEnginePaths();
  const res = await spawnPythonScript({
    pythonPath,
    args: [refreshScript],
    env: buildSanitizedPythonEnv(stateDir, { includeRefreshAuth: true }),
    timeoutMs,
  });
  const cache = readAntileakCacheHealthSync(stateDir, {
    ttlSeconds: cfg.config.privateCacheTtl,
    workspaceRoots: roots,
    requirePrivateState,
  });
  const redactedMsg = redactSecretsFromText(`${res.stdout}\n${res.stderr}`.trim(), null, 400)
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(Boolean)
    .slice(0, 3)
    .join(' · ')
    .slice(0, 240);
  return {
    ok: res.ok,
    exitCode: res.exitCode,
    durationMs: res.durationMs,
    message: redactedMsg || (res.ok ? 'Private cache refreshed.' : 'Private cache refresh failed.'),
    cache,
  };
}
