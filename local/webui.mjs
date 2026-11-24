// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { TOOL_DEFINITIONS } from './tools.mjs';
import { buildSandboxTools } from './sandbox.mjs';
import {
  APPROVAL_EXEMPT_TOOLS,
  getToolScopes,
  isValidExternalToolName,
  digest as policyDigest,
} from './request-policy.mjs';
import { APPROVAL_ID, REQUEST_FILE, MAX_RECORD_BYTES, readJson, validRequest } from './approval-store.mjs';
import { approveRequest, safeText } from './approval-cli.mjs';
import {
  assertConfigOutsideWorkspace,
  loadWorkspaceRootsFromStateConfig,
  readCapabilitiesSync,
  writeCapabilitiesSync,
  TOOL_CAPABILITY_GROUPS,
  isToolEnabled,
} from './capabilities.mjs';
import {
  mcpServersFilePath,
  readMcpServersSync,
  upsertMcpServerSync,
  upsertMcpServersSync,
  deleteMcpServerSync,
  toggleMcpServerSync,
  saveMcpProbeResultSync,
  parseStandardMcpJson,
  publicMcpServerSummary,
  publicMcpRegistrySnapshot,
  redactSecretsFromText,
  serverConfigFingerprint,
} from './mcp-registry.mjs';
import { probeMcpServer } from './mcp-client.mjs';
import {
  assertPrivateFile,
  assertPrivateState,
  assertTrustedBinary,
  findOwnedProcess,
  sanitizedToolEnv,
} from './host-safety.mjs';
import { SECRET_META_FILE } from './host-secrets.mjs';
import {
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
  toBase64Url,
} from './webauthn.mjs';
import {
  detectHostPasskeySupport,
  readWebUiAuthSync,
  publicWebUiAuthSummary,
  verifySetupTicketMatch,
  verifyStrongPassword,
  setStrongPasswordSync,
  enrollPasskeySync,
  updatePasskeySignCountSync,
  markPasskeyRequiredSync,
  setSessionPersistenceSync,
  deletePasskeySync,
  switchToStrongPasswordSync,
} from './webui-auth.mjs';
import { renderWebUiHtml, WEBUI_CSS, WEBUI_JS } from './webui-assets.mjs';

const execFileAsync = promisify(execFile);
const MAX_JSON_BODY = 65536;
const MAX_SSE_CLIENTS = 16;
const MAX_SESSIONS = 16;
const SESSION_IDLE_MS = 30 * 60 * 1000;
const SESSION_MAX_MS = 12 * 60 * 60 * 1000;
const CHALLENGE_TTL_MS = 120 * 1000;
const MAX_CHALLENGES = 32;
const AUTH_FAILURE_LIMIT = 5;
const PRE_AUTH_COOKIE = 'agentdock_ui_pre';
const SESSION_COOKIE = 'agentdock_ui_sid';

export function isLoopbackHost(host) {
  return host === '127.0.0.1' || host === '::1' || host === 'localhost';
}

function parseCookieHeader(header = '') {
  const map = new Map();
  for (const part of String(header).split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const key = part.slice(0, eq).trim();
    const val = part.slice(eq + 1).trim();
    if (key) map.set(key, val);
  }
  return map;
}

function validateStateDir(stateDir, requirePrivateState) {
  const resolved = path.resolve(stateDir);
  if (!requirePrivateState) return resolved;
  if (process.platform !== 'win32') return assertPrivateState(resolved);
  const stat = fs.lstatSync(resolved);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error('Private state must be an ordinary non-linked directory.');
  }
  return resolved;
}

const MAX_TRUSTED_JSON_BYTES = 2 * 1024 * 1024;

function readTrustedJsonFile(filePath, requirePrivateState) {
  if (requirePrivateState && process.platform !== 'win32') {
    assertPrivateFile(filePath);
  }
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1) {
      throw new Error('Configuration file must be a regular single-link file.');
    }
    if (stat.size > MAX_TRUSTED_JSON_BYTES) {
      throw new Error('Configuration file exceeds maximum allowed size.');
    }
    if (requirePrivateState && process.platform !== 'win32') {
      if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
        throw new Error('Private file has an untrusted owner.');
      }
      if ((stat.mode & 0o077) !== 0) {
        throw new Error('Private file permissions must restrict access to the owner (0600).');
      }
    }
    return JSON.parse(fs.readFileSync(fd, 'utf8'));
  } finally {
    fs.closeSync(fd);
  }
}

function isProcessAliveCrossPlatform(recordFile, expectedSource) {
  if (process.platform !== 'win32') return findOwnedProcess(recordFile, expectedSource);
  try {
    const record = JSON.parse(fs.readFileSync(recordFile, 'utf8'));
    if (!Number.isSafeInteger(record?.pid) || record.pid <= 0) return null;
    process.kill(record.pid, 0);
    return { pid: record.pid };
  } catch {
    return null;
  }
}

function readTailLines(filePath, maxLines = 40, maxBytes = 262144) {
  let fd;
  try {
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  } catch {
    return [];
  }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) return [];
    const start = Math.max(0, stat.size - maxBytes);
    const length = stat.size - start;
    if (!length) return [];
    const buf = Buffer.alloc(length);
    const bytesRead = fs.readSync(fd, buf, 0, length, start);
    if (!bytesRead) return [];
    const lines = buf.subarray(0, bytesRead).toString('utf8').split('\n');
    if (start > 0) lines.shift();
    return lines.filter(Boolean).slice(-maxLines);
  } catch {
    return [];
  } finally {
    try { fs.closeSync(fd); } catch {}
  }
}

const TOOL_META_CATALOG = {
  computer_context: {
    title: '工作区环境与运行时策略探查',
    kind: 'CTX',
    canDo: [
      '返回容器 OS、Node 运行时及唯一允许的工作区根 /workspace',
      '实时反馈 file_read / file_write / command_execution 开关与挂载姿态',
      '声明本地并发上限（文件 4 / 命令 4）与单容器 2 GiB 内存 / 2 CPU 配额',
    ],
    limits: [
      '仅返回脱敏摘要与静态配额，不枚举工程目录树或文件内容',
      '只读探查工具，免人工审批但仍受 MCP 调度开关与作用域约束',
    ],
  },
  list_directory: {
    title: '目录项有界枚举',
    kind: 'READ',
    canDo: [
      '按文件系统顺序列出 /workspace 下单个已批准目录的直属条目与类型',
      '显式返回 truncated 标志提示是否触达 limit 上限',
    ],
    limits: [
      '条目数受 limit 限制（默认 200，硬上限 1000）且拒绝递归枚举',
      '严格拒绝跟随符号链接（symlink）与工作区外路径',
    ],
  },
  read_file: {
    title: 'UTF-8 文件分片读取',
    kind: 'READ',
    canDo: [
      '从字节偏移 offset 读取完整 UTF-8 字符边界切片并返回 next_offset',
      '回传当前文件 SHA-256 摘要供 write_file / edit_file / delete_file 做 CAS 校验',
    ],
    limits: [
      '单次最多读取 256 KiB（262,144 B，默认 64 KiB），文件整体上限 1 MiB',
      '拒绝二进制文件、非法 UTF-8 序列以及落在多字节字符中间的 offset',
    ],
  },
  search_files: {
    title: '工程文本与文件名检索',
    kind: 'READ',
    canDo: [
      '在已批准目录下检索字面量内容或文件名（支持大小写敏感开关）',
      '实时返回 truncated 与 budget_exhausted 提示检索是否提前截断',
    ],
    limits: [
      '固定跳过 .git、node_modules、.wrangler、符号链接及 >1 MiB 文件',
      '单次搜索受 128 目录、5,000 条目、2,000 文件、16 MiB 读取量及 5 秒预算限制',
    ],
  },
  write_file: {
    title: 'UTF-8 文件写入与覆盖保护',
    kind: 'WRITE',
    canDo: [
      '创建新 UTF-8 文本文件，或在显式声明 overwrite=true 时覆写既有文件',
      '支持传入 expected_sha256 检测读取后的并发修改冲突',
    ],
    limits: [
      '单文件正文上限 1 MiB UTF-8，且父目录必须已存在于工作区内',
      '须本机终端 approve 参数摘要放行；Windows 额外拒绝剥离自定义 NTFS ACL 的替换',
    ],
  },
  edit_file: {
    title: '唯一字面量精确替换',
    kind: 'WRITE',
    canDo: [
      '精确查找并替换文件中唯一一次出现的字面量文本片段（非正则）',
      '支持 expected_sha256 做乐观锁并发校验',
    ],
    limits: [
      '若 old_text 不存在、为空或出现多于一次则直接失败拒绝写入',
      '受单文件并发互斥锁、Windows NTFS ACL 保护与本机精确审批约束',
    ],
  },
  delete_file: {
    title: '单文件原子删除',
    kind: 'WRITE',
    canDo: [
      '在精确本机批准后删除工作区内的单个常规文件',
      '支持 expected_sha256 在删除前校验目标文件未发生意外变更',
    ],
    limits: [
      '绝不删除目录，也不支持任何递归或通配符批量删除',
      '符号链接与工作区外路径均在安全校验阶段被拦截',
    ],
  },
  exec_command: {
    title: '隔离容器 Bash 命令执行',
    kind: 'EXEC',
    canDo: [
      '在一次性只读镜像 Linux 容器中执行 sync 或 background 模式 Bash 命令',
      '支持通过 command_id 衔接 command_status / stop_command 管理长耗时构建与测试',
    ],
    limits: [
      '关闭写权限时容器内 /workspace 自动强制以 :readonly 只读绑定挂载',
      '非特权 UID/GID、--cap-drop ALL、不挂载宿主机目录/Docker socket/凭据；默认 --network none',
    ],
  },
  command_status: {
    title: '后台容器命令状态查询',
    kind: 'EXEC',
    canDo: [
      '查询由当前连接器会话发起的容器命令退出码、是否超时及有界输出增量',
      '独立于普通审批队列（控制面豁免人工审批），便于随时跟踪或收尾',
    ],
    limits: [
      '按发起方 OAuth clientId 严格隔离，无法查询其他客户端或旧会话的任务',
      '输出缓冲保留在内存且受容器单次最大输出预算约束',
    ],
  },
  stop_command: {
    title: '终止容器命令与进程树',
    kind: 'EXEC',
    canDo: [
      '在独立停止通道上立即中止由本连接器发起的目标容器及进程树',
      '即使工作区文件能力已全部锁定，仍允许对既有残留作业执行安全停止',
    ],
    limits: [
      '若无法确认 docker rm -f 成功销毁容器，系统立即触发沙盒闭锁拒接后续执行',
      '按客户端 ID 严格鉴权，单客户端停止并发上限为 2（总停止通道上限 4）',
    ],
  },
};

const KNOWN_TOOL_NAMES = new Set(TOOL_DEFINITIONS.map(def => def.name));

function emptyToolStats() {
  return {
    totalCalls: 0,
    successCount: 0,
    failureCount: 0,
    blockedCount: 0,
    pendingApprovalCount: 0,
    lastUsedAt: null,
    lastOutcome: null,
    lastDurationMs: null,
  };
}

function buildSampleArguments(def) {
  const sampleMap = {
    computer_context: {},
    list_directory: { path: '/workspace', limit: 200 },
    read_file: { path: '/workspace/README.md', offset: 0, max_bytes: 65536 },
    write_file: { path: '/workspace/example.txt', content: '<UTF-8 text>', overwrite: false },
    edit_file: { path: '/workspace/example.txt', old_text: '<exact literal>', new_text: '<replacement>' },
    delete_file: { path: '/workspace/example.txt', expected_sha256: '<64-hex sha256>' },
    search_files: { path: '/workspace', query: '<literal>', mode: 'content', limit: 100 },
    exec_command: { cmd: '<bash command>', cwd: '/workspace', mode: 'sync', timeout_ms: 30000 },
    command_status: { command_id: '<uuid>' },
    stop_command: { command_id: '<uuid>' },
  };
  if (!def?.external && Object.hasOwn(sampleMap, def?.name)) return sampleMap[def.name];
  const out = {};
  const rawProps = def?.inputSchema?.properties;
  if (!rawProps || typeof rawProps !== 'object' || Array.isArray(rawProps)) return out;
  let count = 0;
  for (const [k, s] of Object.entries(rawProps)) {
    if (count >= 64) break;
    if (!s || typeof s !== 'object' || Array.isArray(s)) continue;
    if (s.type === 'integer' || s.type === 'number') out[k] = Number.isFinite(s.minimum) ? s.minimum : 1;
    else if (s.type === 'boolean') out[k] = false;
    else if (s.type === 'array') out[k] = [];
    else if (s.type === 'object') out[k] = {};
    else out[k] = '<value>';
    count += 1;
  }
  return out;
}

function stableLineEventKey(prefix, line, occMap) {
  const digest = crypto.createHash('sha256').update(line).digest('hex').slice(0, 12);
  const count = (occMap.get(digest) || 0) + 1;
  occMap.set(digest, count);
  return `${prefix}:${digest}:${count}`;
}

function collectTelemetryAndEvents(stateDir, pendingApprovals) {
  const events = [];
  const statsByTool = Object.fromEntries(TOOL_DEFINITIONS.map(def => [def.name, emptyToolStats()]));
  const summaryStats = {
    totalAuditCalls: 0,
    totalAuditSuccess: 0,
    totalAuditFailed: 0,
    totalBlocked: 0,
    auditWindowLimit: 200,
  };
  const auditOcc = new Map();
  const connOcc = new Map();

  const updateRecency = (stat, time, outcome, durationMs = null) => {
    if (!stat.lastUsedAt || time > stat.lastUsedAt) {
      stat.lastUsedAt = time;
      stat.lastOutcome = outcome;
      stat.lastDurationMs = Number.isFinite(durationMs) ? durationMs : null;
    }
  };

  for (const line of readTailLines(path.join(stateDir, 'audit.jsonl'), 200)) {
    try {
      const raw = JSON.parse(line);
      if (!raw || typeof raw !== 'object') continue;
      const time = typeof raw.time === 'string' ? raw.time : '';
      if (!time) continue;
      if (typeof raw.tool === 'string') {
        const ok = raw.success === true;
        const durationMs = Number.isInteger(raw.durationMs) && raw.durationMs >= 0 ? raw.durationMs : null;
        const reason = typeof raw.reason === 'string' ? raw.reason.slice(0, 48) : (ok ? 'ok' : '');
        const mountMode = raw.mountMode === 'readwrite' || raw.mountMode === 'readonly' ? raw.mountMode : null;
        const mode = raw.mode === 'sync' || raw.mode === 'background' ? raw.mode : null;
        const network = raw.network === 'none' || raw.network === 'outbound' ? raw.network : null;
        const exitCode = Number.isInteger(raw.exitCode) ? raw.exitCode : null;
        const timedOut = typeof raw.timedOut === 'boolean' ? raw.timedOut : null;
        const cancelled = typeof raw.cancelled === 'boolean' ? raw.cancelled : null;

        const isRecognizedTool = KNOWN_TOOL_NAMES.has(raw.tool) || isValidExternalToolName(raw.tool);
        if (isRecognizedTool) {
          if (!Object.hasOwn(statsByTool, raw.tool)) statsByTool[raw.tool] = emptyToolStats();
          const st = statsByTool[raw.tool];
          st.totalCalls += 1;
          if (ok) st.successCount += 1;
          else st.failureCount += 1;
          summaryStats.totalAuditCalls += 1;
          if (ok) summaryStats.totalAuditSuccess += 1;
          else summaryStats.totalAuditFailed += 1;
          updateRecency(st, time, ok ? 'ok' : 'err', durationMs);
        }

        const detailParts = [];
        if (reason && reason !== 'ok') detailParts.push(reason);
        if (mode) detailParts.push(mode);
        if (network) detailParts.push('net=' + network);
        if (mountMode) detailParts.push(mountMode);
        if (exitCode !== null) detailParts.push('exit=' + exitCode);
        if (timedOut) detailParts.push('timeout');
        if (cancelled) detailParts.push('cancelled');
        if (durationMs !== null) detailParts.push(durationMs + 'ms');

        const meta = {};
        if (reason) meta.reason = reason;
        if (durationMs !== null) meta.durationMs = durationMs;
        if (mountMode) meta.mountMode = mountMode;
        if (mode) meta.mode = mode;
        if (network) meta.network = network;
        if (exitCode !== null) meta.exitCode = exitCode;
        if (timedOut !== null) meta.timedOut = timedOut;
        if (cancelled !== null) meta.cancelled = cancelled;
        if (typeof raw.serverId === 'string' && raw.serverId) meta.serverId = raw.serverId.slice(0, 48);
        for (const field of ['bytesRead', 'bytesWritten', 'stdoutBytes', 'stderrBytes', 'outputBytes']) {
          const count = raw[field] ?? raw.result?.[field];
          if (Number.isSafeInteger(count) && count >= 0) meta[field] = count;
        }

        events.push({
          key: stableLineEventKey('audit', line, auditOcc),
          time,
          source: 'audit',
          name: isRecognizedTool ? raw.tool : 'unknown',
          tone: ok ? 'ok' : 'err',
          label: ok ? '通过' : '拒绝',
          detail: detailParts.join(' · '),
          meta,
        });
      } else if (typeof raw.event === 'string') {
        events.push({
          key: stableLineEventKey('audit-ev', line, auditOcc),
          time,
          source: 'audit',
          name: raw.event.slice(0, 48),
          tone: 'err',
          label: '沙盒锁闭',
          detail: typeof raw.jobId === 'string' ? 'job=' + raw.jobId.slice(0, 12) : '',
          meta: typeof raw.jobId === 'string' ? { jobIdPrefix: raw.jobId.slice(0, 12) } : {},
        });
      }
    } catch { /* Ignore partial tail line */ }
  }

  for (const line of readTailLines(path.join(stateDir, 'connector.log'), 200)) {
    try {
      const raw = JSON.parse(line);
      if (!raw || typeof raw !== 'object') continue;
      const time = typeof raw.time === 'string' ? raw.time : '';
      const event = typeof raw.event === 'string' ? raw.event : '';
      if (!time || !event) continue;

      const recognizedTool = typeof raw.tool === 'string' && (KNOWN_TOOL_NAMES.has(raw.tool) || isValidExternalToolName(raw.tool))
        ? raw.tool
        : null;

      if (event === 'capability_blocked' && recognizedTool) {
        if (!Object.hasOwn(statsByTool, recognizedTool)) statsByTool[recognizedTool] = emptyToolStats();
        const st = statsByTool[recognizedTool];
        st.blockedCount += 1;
        summaryStats.totalBlocked += 1;
        updateRecency(st, time, 'blocked', null);
      }

      const tone = event === 'connected' ? 'ok'
        : event === 'approval_granted' ? 'ok'
        : event === 'mcp_server_probed' && typeof raw.outcome === 'string' && raw.outcome.startsWith('ok') ? 'ok'
        : event === 'capability_changed' ? 'info'
        : event === 'webui_auth' || event === 'service_action' ? 'info'
        : event === 'mcp_server_updated' || event === 'mcp_server_imported' || event === 'mcp_server_toggled' || event === 'mcp_server_deleted' ? 'info'
        : event === 'approval_required' ? 'info'
        : event === 'capability_blocked' ? 'err'
        : event === 'approval_rejected' ? 'err'
        : 'err';
      const label = event === 'connected' ? '已连接'
        : event === 'disconnected' ? '已断开'
        : event === 'capability_changed' ? '策略变更'
        : event === 'capability_blocked' ? '策略拦截'
        : event === 'approval_required' ? '等待批准'
        : event === 'approval_granted' ? '已批准一次'
        : event === 'approval_rejected' ? '已拒绝移除'
        : event === 'webui_auth' ? '安全认证'
        : event === 'service_action' ? '服务操作'
        : event === 'mcp_server_updated' ? 'MCP 保存'
        : event === 'mcp_server_imported' ? 'MCP 导入'
        : event === 'mcp_server_toggled' ? 'MCP 开关'
        : event === 'mcp_server_probed' ? 'MCP 探测'
        : event === 'mcp_server_deleted' ? 'MCP 移除'
        : event;

      const meta = {};
      const detailParts = [];
      if (typeof raw.route === 'string') { meta.route = raw.route.slice(0, 32); detailParts.push(meta.route); }
      if (typeof raw.serverId === 'string') { meta.serverId = raw.serverId.slice(0, 48); detailParts.push('mcp:' + meta.serverId); }
      if (typeof raw.tool === 'string') {
        meta.tool = recognizedTool || 'unknown';
        detailParts.push(meta.tool);
      }
      if (typeof raw.capability === 'string') { meta.capability = raw.capability.slice(0, 64); detailParts.push(meta.capability); }
      if (typeof raw.approvalIdShort === 'string') { meta.approvalIdShort = raw.approvalIdShort.slice(0, 12); detailParts.push('id=' + meta.approvalIdShort); }
      if (Number.isInteger(raw.code)) { meta.code = raw.code; detailParts.push(`code=${raw.code}`); }
      else if (typeof raw.code === 'string') { meta.code = raw.code.slice(0, 32); detailParts.push(meta.code); }
      if (Number.isInteger(raw.status)) { meta.status = raw.status; detailParts.push(`HTTP ${raw.status}`); }
      if (typeof raw.mode === 'string') { meta.mode = raw.mode.slice(0, 40); detailParts.push(meta.mode); }
      if (typeof raw.outcome === 'string') { meta.outcome = raw.outcome.slice(0, 40); detailParts.push(meta.outcome); }

      events.push({
        key: stableLineEventKey('conn', line, connOcc),
        time,
        source: 'connector',
        name: event.slice(0, 48),
        tone,
        label,
        detail: detailParts.filter(Boolean).join(' · '),
        meta,
      });
    } catch { /* Ignore partial tail line */ }
  }

  for (const item of pendingApprovals?.items || []) {
    if (item?.tool && (Object.hasOwn(statsByTool, item.tool) || isValidExternalToolName(item.tool))) {
      if (!Object.hasOwn(statsByTool, item.tool)) statsByTool[item.tool] = emptyToolStats();
      statsByTool[item.tool].pendingApprovalCount += 1;
    }
  }

  events.sort((a, b) => (a.time < b.time ? 1 : a.time > b.time ? -1 : 0));
  return { events: events.slice(0, 60), statsByTool, summaryStats };
}

const approvalFileCache = new Map();

function purgeApprovalCachePrefix(dir) {
  const prefix = dir + path.sep;
  for (const cachedPath of [...approvalFileCache.keys()]) {
    if (cachedPath.startsWith(prefix)) approvalFileCache.delete(cachedPath);
  }
}

function readPendingApprovalsMetadata(stateDir) {
  const dir = path.join(stateDir, 'approvals');
  const now = Date.now();
  const items = [];
  const seenPaths = new Set();
  try {
    const dirStat = fs.lstatSync(dir);
    if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) {
      purgeApprovalCachePrefix(dir);
      return { pendingCount: 0, items: [] };
    }
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (!entry.isFile() || !entry.name.endsWith('.request.json')) continue;
      const filePath = path.join(dir, entry.name);
      seenPaths.add(filePath);
      try {
        const st = fs.lstatSync(filePath, { bigint: true });
        if (st.isSymbolicLink() || !st.isFile() || Number(st.size) > MAX_RECORD_BYTES) continue;
        const preSig = `${st.dev}:${st.ino}:${st.size}:${st.mtimeNs}:${st.ctimeNs}`;
        let raw;
        const cached = approvalFileCache.get(filePath);
        if (cached && cached.sig === preSig) {
          raw = cached.raw;
        } else {
          let postSig = preSig;
          const fd = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
          try {
            const fst = fs.fstatSync(fd, { bigint: true });
            if (!fst.isFile() || Number(fst.size) > MAX_RECORD_BYTES) continue;
            postSig = `${fst.dev}:${fst.ino}:${fst.size}:${fst.mtimeNs}:${fst.ctimeNs}`;
            raw = JSON.parse(fs.readFileSync(fd, 'utf8'));
          } finally {
            fs.closeSync(fd);
          }
          if (approvalFileCache.size > 512) approvalFileCache.clear();
          approvalFileCache.set(filePath, { sig: postSig, raw });
        }
        const expiresAt = Number(raw?.expiresAt);
        if (!Number.isFinite(expiresAt) || expiresAt <= now) continue;
        const identified = REQUEST_FILE.exec(entry.name);
        if (identified && validRequest(raw, identified[1], now)) {
          const rawTool = typeof raw.request?.params?.name === 'string' ? raw.request.params.name : '';
          const tool = (Object.hasOwn(TOOL_CAPABILITY_GROUPS, rawTool) || isValidExternalToolName(rawTool)) ? rawTool : 'unknown';
          const approvedFile = path.join(dir, `${raw.id}.approved.json`);
          const apStat = fs.lstatSync(approvedFile, { throwIfNoEntry: false });
          const alreadyApproved = Boolean(apStat && !apStat.isSymbolicLink() && apStat.isFile() && apStat.size <= 512);
          items.push({
            id: raw.id,
            idShort: raw.id.slice(0, 8),
            tool,
            clientId: typeof raw.request?.authorization?.clientId === 'string'
              ? safeText(raw.request.authorization.clientId.slice(0, 128))
              : '',
            hash: typeof raw.hash === 'string' ? raw.hash : '',
            createdAt: new Date(raw.createdAt).toISOString(),
            expiresAt: new Date(expiresAt).toISOString(),
            alreadyApproved,
            approvable: !alreadyApproved,
          });
        } else {
          const rawTool = typeof raw?.tool === 'string' ? raw.tool
            : typeof raw?.body?.params?.name === 'string' ? raw.body.params.name : '';
          const tool = (Object.hasOwn(TOOL_CAPABILITY_GROUPS, rawTool) || isValidExternalToolName(rawTool)) ? rawTool : 'unknown';
          const id = typeof raw?.id === 'string' ? raw.id : entry.name.replace(/\.request\.json$/, '');
          items.push({
            idShort: safeText(id.slice(0, 8)),
            tool,
            approvable: false,
            expiresAt: new Date(expiresAt).toISOString(),
          });
        }
      } catch { /* Skip unreadable partial request */ }
    }
    for (const cachedPath of [...approvalFileCache.keys()]) {
      if (cachedPath.startsWith(dir + path.sep) && !seenPaths.has(cachedPath)) {
        approvalFileCache.delete(cachedPath);
      }
    }
  } catch {
    purgeApprovalCachePrefix(dir);
  }
  items.sort((a, b) => (a.expiresAt < b.expiresAt ? -1 : a.expiresAt > b.expiresAt ? 1 : 0));
  return { pendingCount: items.length, items: items.slice(0, 64) };
}

async function defaultGatewayProbe(origin) {
  if (!origin) return { reachable: false, status: null, latencyMs: null };
  let parsed;
  try {
    parsed = new URL('/healthz', origin);
  } catch {
    return { reachable: false, status: null, latencyMs: null };
  }
  if (parsed.username || parsed.password) return { reachable: false, status: null, latencyMs: null };
  const mod = parsed.protocol === 'https:' ? https : parsed.protocol === 'http:' ? http : null;
  if (!mod) return { reachable: false, status: null, latencyMs: null };
  if (parsed.protocol === 'http:' && !['127.0.0.1', 'localhost', '[::1]'].includes(parsed.hostname)) {
    return { reachable: false, status: null, latencyMs: null };
  }
  const startedAt = Date.now();
  return new Promise(resolve => {
    const req = mod.get(parsed, { timeout: 2500, ...(parsed.protocol === 'https:' ? { minVersion: 'TLSv1.2' } : {}) }, res => {
      res.resume();
      resolve({
        reachable: res.statusCode >= 200 && res.statusCode < 500,
        status: res.statusCode ?? null,
        latencyMs: Date.now() - startedAt,
      });
    });
    req.on('timeout', () => { req.destroy(); resolve({ reachable: false, status: null, latencyMs: null }); });
    req.on('error', () => resolve({ reachable: false, status: null, latencyMs: null }));
  });
}

async function defaultDockerProbe(config, stateDir) {
  const dockerPath = config?.sandbox?.dockerPath;
  const context = config?.sandbox?.context || 'default';
  if (!dockerPath || !path.isAbsolute(dockerPath) || !/^[a-zA-Z0-9._-]{1,64}$/.test(context)) {
    return { dockerOk: false, runningContainers: [] };
  }
  const label = crypto.createHash('sha256').update(stateDir.toLowerCase()).digest('hex').slice(0, 24);
  try {
    const { stdout } = await execFileAsync(
      dockerPath,
      ['--context', context, 'ps', '--filter', `label=cbnv.agentdock.install=${label}`, '--format', '{{.ID}}\t{{.Status}}'],
      { timeout: 3000, windowsHide: true, env: sanitizedToolEnv() },
    );
    const runningContainers = stdout
      .split('\n')
      .map(line => line.trim())
      .filter(Boolean)
      .slice(0, 8)
      .map(line => {
        const [id = '', ...statusParts] = line.split('\t');
        return { id: id.slice(0, 12), status: statusParts.join(' ') || 'running' };
      });
    return { dockerOk: true, runningContainers };
  } catch {
    return { dockerOk: false, runningContainers: [] };
  }
}

async function defaultSystemdProbe() {
  if (process.platform !== 'linux') {
    return { supported: false, installed: false, enabled: false, active: false, bridgeEnabled: false, bridgeActive: false, webuiEnabled: false, linger: false };
  }
  const unitDir = path.join(os.homedir(), '.config', 'systemd', 'user');
  const bridgeUnit = path.join(unitDir, 'agentdock-bridge.service');
  const webuiUnit = path.join(unitDir, 'agentdock-webui.service');
  const installed = fs.existsSync(bridgeUnit);
  const env = sanitizedToolEnv();
  const runCheck = async args => {
    try {
      const { stdout } = await execFileAsync('systemctl', args, { timeout: 2000, env });
      return stdout.trim();
    } catch (error) {
      return String(error?.stdout || '').trim();
    }
  };
  const [bridgeEnabledOut, bridgeActiveOut, webuiEnabledOut] = await Promise.all([
    runCheck(['--user', 'is-enabled', 'agentdock-bridge.service']),
    runCheck(['--user', 'is-active', 'agentdock-bridge.service']),
    fs.existsSync(webuiUnit) ? runCheck(['--user', 'is-enabled', 'agentdock-webui.service']) : Promise.resolve('disabled'),
  ]);
  let linger = false;
  try {
    const user = os.userInfo().username;
    const { stdout } = await execFileAsync('loginctl', ['show-user', user, '-p', 'Linger', '--value'], { timeout: 2000, env });
    linger = stdout.trim() === 'yes';
  } catch {}
  return {
    supported: true,
    installed,
    bridgeEnabled: bridgeEnabledOut === 'enabled',
    bridgeActive: bridgeActiveOut === 'active',
    webuiEnabled: webuiEnabledOut === 'enabled',
    enabled: bridgeEnabledOut === 'enabled',
    active: bridgeActiveOut === 'active',
    linger,
  };
}

function readBoundedJsonNoFollowSync(filePath, maxBytes = 65536) {
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > maxBytes) throw new Error('Invalid metadata file.');
    const buf = Buffer.allocUnsafe(maxBytes + 1);
    let total = 0;
    while (total < buf.length) {
      const n = fs.readSync(fd, buf, total, buf.length - total, total);
      if (!n) break;
      total += n;
    }
    if (total > maxBytes) throw new Error('Metadata file too large.');
    return JSON.parse(buf.subarray(0, total).toString('utf8'));
  } finally {
    fs.closeSync(fd);
  }
}

function readSecretBackendLabel(stateDir) {
  if (process.platform === 'win32') return 'dpapi';
  try {
    const meta = readBoundedJsonNoFollowSync(path.join(stateDir, SECRET_META_FILE));
    return typeof meta?.backend === 'string' ? meta.backend : 'unknown';
  } catch {
    return 'unknown';
  }
}

function readNodeVersionLabel(config) {
  if (typeof config?.nodeRoot !== 'string' || typeof config?.nodePath !== 'string') return process.version;
  const match = path.basename(path.dirname(path.dirname(config.nodePath))).match(/node-v([\d.]+)/);
  return match ? match[1] : process.version;
}

function appendSanitizedConnectorLog(stateDir, event, fields = {}) {
  try {
    const logPath = path.join(stateDir, 'connector.log');
    const fd = fs.openSync(
      logPath,
      fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT | (fs.constants.O_NOFOLLOW || 0),
      0o600,
    );
    try {
      fs.writeFileSync(fd, JSON.stringify({
        time: new Date().toISOString(),
        event,
        ...fields,
      }) + '\n', 'utf8');
    } finally {
      fs.closeSync(fd);
    }
  } catch {}
}

export async function collectStatusSnapshot({
  stateDir,
  runtimeRoot,
  requirePrivateState = false,
  passkeyDetector = detectHostPasskeySupport,
  gatewayProbe = defaultGatewayProbe,
  dockerProbe = defaultDockerProbe,
  systemdProbe = defaultSystemdProbe,
  blockedOrigins = [],
}) {
  const configPath = path.join(stateDir, 'config.json');
  const config = readTrustedJsonFile(configPath, requirePrivateState);
  const workspaceRoots = loadWorkspaceRootsFromStateConfig(stateDir);
  assertConfigOutsideWorkspace(configPath, workspaceRoots);
  const configAllowExec = config?.allowExec === true;
  const capabilities = readCapabilitiesSync(stateDir, { configAllowExec, workspaceRoots });
  const authRecord = readWebUiAuthSync(stateDir, { workspaceRoots, passkeyDetector });
  const mcpServers = publicMcpRegistrySnapshot(stateDir, { workspaceRoots, blockedOrigins });

  const supervisorSource = config?.sourceRoot
    ? path.join(path.resolve(config.sourceRoot), 'scripts', 'host-cli.mjs')
    : path.join(runtimeRoot, 'scripts', 'host-cli.mjs');
  const connectorSource = config?.sourceRoot
    ? path.join(path.resolve(config.sourceRoot), 'local', 'connector.mjs')
    : path.join(runtimeRoot, 'local', 'connector.mjs');

  const supProc = isProcessAliveCrossPlatform(path.join(stateDir, 'supervisor.json'), supervisorSource);
  const connProc = isProcessAliveCrossPlatform(path.join(stateDir, 'connector-process.json'), connectorSource);
  let connectorStatus = null;
  try {
    connectorStatus = readBoundedJsonNoFollowSync(path.join(stateDir, 'connector-status.json'));
  } catch {}

  const [gateway, docker, systemd] = await Promise.all([
    gatewayProbe(config?.origin),
    dockerProbe(config, stateDir),
    systemdProbe(),
  ]);

  const approvals = readPendingApprovalsMetadata(stateDir);
  const { events, statsByTool, summaryStats } = collectTelemetryAndEvents(stateDir, approvals);
  const sandboxTools = buildSandboxTools(config?.sandbox?.allowOutbound === true);

  const effectiveTools = sandboxTools.map(def => {
    const group = TOOL_CAPABILITY_GROUPS[def.name] || 'other';
    const verdict = isToolEnabled(def.name, capabilities, { configAllowExec });
    const meta = TOOL_META_CATALOG[def.name] || { title: def.name, kind: group.toUpperCase(), canDo: [], limits: [] };
    const props = def.inputSchema?.properties || {};
    const requiredSet = new Set(Array.isArray(def.inputSchema?.required) ? def.inputSchema.required : []);
    const parameters = Object.entries(props).map(([paramName, schema]) => ({
      name: paramName,
      type: schema.type || 'string',
      required: requiredSet.has(paramName),
      description: schema.description || '',
      enumValues: Array.isArray(schema.enum) ? schema.enum : null,
      minimum: Number.isFinite(schema.minimum) ? schema.minimum : null,
      maximum: Number.isFinite(schema.maximum) ? schema.maximum : null,
    }));

    return {
      name: def.name,
      title: meta.title,
      group,
      kind: meta.kind,
      enabled: verdict.enabled,
      individuallyDisabled: capabilities.tools?.[def.name] === false,
      disabledReason: verdict.enabled ? null : verdict.reason,
      description: def.description || '',
      scopes: getToolScopes(def.name),
      requiresApproval: !APPROVAL_EXEMPT_TOOLS.has(def.name),
      annotations: {
        readOnlyHint: Boolean(def.annotations?.readOnlyHint),
        destructiveHint: Boolean(def.annotations?.destructiveHint),
        idempotentHint: Boolean(def.annotations?.idempotentHint),
        openWorldHint: Boolean(def.annotations?.openWorldHint),
      },
      canDo: meta.canDo,
      limits: meta.limits,
      parameters,
      sampleCall: {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: def.name,
          arguments: buildSampleArguments(def),
        },
      },
      stats: statsByTool[def.name] || emptyToolStats(),
    };
  });

  for (const srv of mcpServers.items) {
    for (const tool of srv.tools) {
      const rawProps = tool.inputSchema?.properties;
      const propsEntries = rawProps && typeof rawProps === 'object' && !Array.isArray(rawProps)
        ? Object.entries(rawProps).slice(0, 64)
        : [];
      const requiredSet = new Set(Array.isArray(tool.inputSchema?.required) ? tool.inputSchema.required : []);
      const parameters = propsEntries
        .filter(([, schema]) => schema && typeof schema === 'object' && !Array.isArray(schema))
        .map(([paramName, schema]) => ({
          name: paramName,
          type: typeof schema.type === 'string' ? schema.type : 'string',
          required: requiredSet.has(paramName),
          description: typeof schema.description === 'string' ? schema.description : '',
          enumValues: Array.isArray(schema.enum) ? schema.enum : null,
          minimum: Number.isFinite(schema.minimum) ? schema.minimum : null,
          maximum: Number.isFinite(schema.maximum) ? schema.maximum : null,
        }));
      effectiveTools.push({
        name: tool.fullName,
        rawToolName: tool.name,
        external: true,
        serverId: srv.id,
        serverName: srv.name,
        serverEnabled: srv.enabled,
        title: tool.title || ('第三方 MCP · ' + srv.name),
        group: 'mcp',
        kind: 'MCP',
        enabled: tool.enabled,
        individuallyDisabled: tool.individuallyDisabled,
        disabledReason: tool.enabled
          ? null
          : (!srv.enabled
              ? `第三方 MCP 服务 "${srv.name}" 当前已停用。`
              : `该第三方 MCP 工具（${tool.name}）已在本地设置中单独停用。`),
        description: tool.description || tool.name,
        scopes: ['computer:read', 'computer:write', 'computer:execute'],
        requiresApproval: true,
        annotations: {
          readOnlyHint: false,
          destructiveHint: true,
          idempotentHint: false,
          openWorldHint: true,
        },
        canDo: [
          `经由 AgentDock 聚合调用第三方 MCP 服务「${srv.name}」（${srv.transport.toUpperCase()}）的工具 ${tool.name}`,
          '服务配置与密钥单独保存于挂载工作区之外的 0600 私有文件，修改后实时生效无需重启连接器',
        ],
        limits: [
          '注意：第三方 MCP 在 Docker 容器沙盒之外运行（宿主机 stdio 子进程或外部 HTTP 端点），不受容器文件系统/网络隔离限制',
          '每次调用仍强制经由本机 WebUI 复核或终端 approve 精确批准（绑定完整参数摘要）',
          `受 ${Math.round((srv.timeoutMs || 30000) / 1000)} 秒超时、2 MiB 载荷上限与 24 小时防重放账本约束`,
        ],
        parameters,
        sampleCall: {
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: {
            name: tool.fullName,
            arguments: buildSampleArguments({ ...tool, external: true }),
          },
        },
        stats: statsByTool[tool.fullName] || emptyToolStats(),
      });
    }
  }

  return {
    observedAt: new Date().toISOString(),
    security: publicWebUiAuthSummary(authRecord),
    daemon: {
      supervisorAlive: Boolean(supProc),
      supervisorPid: supProc?.pid ?? null,
      connectorAlive: Boolean(connProc),
      connectorPid: connProc?.pid ?? null,
      online: Boolean(connProc && connectorStatus?.online === true),
      statusUpdatedAt: typeof connectorStatus?.updatedAt === 'string' ? connectorStatus.updatedAt : null,
      origin: typeof config?.origin === 'string' ? config.origin : null,
      gatewayReachable: Boolean(gateway?.reachable),
      gatewayStatus: gateway?.status ?? null,
      gatewayLatencyMs: gateway?.latencyMs ?? null,
    },
    capabilities: {
      fileRead: capabilities.fileRead,
      fileWrite: capabilities.fileWrite,
      allowExec: capabilities.allowExec,
      updatedAt: capabilities.updatedAt,
      error: capabilities.error,
      mountMode: capabilities.error ? 'locked' : capabilities.fileWrite ? 'readwrite' : 'readonly',
      effectiveTools,
    },
    mcpServers,
    sandbox: {
      workspace: Array.isArray(config?.roots) && config.roots[0] ? config.roots[0] : null,
      configAllowExec,
      imageDigest: typeof config?.sandbox?.image === 'string' ? config.sandbox.image : null,
      imageShort: typeof config?.sandbox?.image === 'string' ? config.sandbox.image.slice(0, 19) : null,
      dockerContext: typeof config?.sandbox?.context === 'string' ? config.sandbox.context : null,
      allowOutbound: config?.sandbox?.allowOutbound === true,
      requireLocalApproval: config?.requireLocalApproval === true,
      nodeVersion: readNodeVersionLabel(config),
      secretBackend: readSecretBackendLabel(stateDir),
      dockerOk: Boolean(docker?.dockerOk),
      runningContainers: Array.isArray(docker?.runningContainers) ? docker.runningContainers : [],
    },
    systemd,
    approvals,
    telemetry: summaryStats,
    events,
  };
}

function defaultServiceController(stateDir, systemdProbe, requirePrivateState = true) {
  const env = sanitizedToolEnv();
  const validatePosixWrapper = (wrapper, label) => {
    let st;
    try {
      st = fs.lstatSync(wrapper);
    } catch {
      const err = new Error(`Service wrapper "${label}" is not installed.`);
      err.status = 400;
      throw err;
    }
    if (st.isSymbolicLink() || !st.isFile()) {
      const err = new Error(`Service wrapper "${label}" must be a regular non-linked file.`);
      err.status = 400;
      throw err;
    }
    if (requirePrivateState) {
      assertTrustedBinary(wrapper);
    }
    return wrapper;
  };
  const runWrapper = async (baseName, timeout) => {
    if (process.platform === 'win32') {
      const cmdFile = path.join(stateDir, baseName === 'stop' ? 'Stop.cmd' : 'Start.cmd');
      let st;
      try {
        st = fs.lstatSync(cmdFile);
      } catch {
        const err = new Error(`Service script "${path.basename(cmdFile)}" is not installed.`);
        err.status = 400;
        throw err;
      }
      if (st.isSymbolicLink() || !st.isFile() || /[&|<>^%()!"]/.test(cmdFile)) {
        const err = new Error(`Service script "${path.basename(cmdFile)}" failed safety checks.`);
        err.status = 400;
        throw err;
      }
      const cmdExe = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'cmd.exe');
      await execFileAsync(cmdExe, ['/d', '/c', cmdFile], { timeout, windowsHide: true, env });
      return;
    }
    const wrapper = validatePosixWrapper(path.join(stateDir, baseName), baseName);
    await execFileAsync(wrapper, [], { timeout, env });
  };

  return async action => {
    const sys = await systemdProbe();
    if (action === 'enable-autostart') {
      if (!sys.supported) {
        const err = new Error('systemd user services are only supported on Linux.');
        err.status = 400;
        throw err;
      }
      if (!sys.installed) {
        const svcPath = path.join(stateDir, 'service');
        if (!fs.existsSync(svcPath)) {
          const err = new Error('systemd user units are not installed; run ~/.agentdock-bridge/service install first.');
          err.status = 400;
          throw err;
        }
        const validated = validatePosixWrapper(svcPath, 'service');
        await execFileAsync(validated, ['enable'], { timeout: 30000, env });
      } else {
        const unitDir = path.join(os.homedir(), '.config', 'systemd', 'user');
        const units = ['agentdock-bridge.service', fs.existsSync(path.join(unitDir, 'agentdock-webui.service')) ? 'agentdock-webui.service' : null].filter(Boolean);
        await execFileAsync('systemctl', ['--user', 'enable', ...units], { timeout: 25000, env });
      }
      return;
    }
    if (action === 'disable-autostart') {
      if (!sys.supported) {
        const err = new Error('systemd user services are only supported on Linux.');
        err.status = 400;
        throw err;
      }
      if (!sys.installed) {
        const err = new Error('systemd user units are not installed.');
        err.status = 400;
        throw err;
      }
      const unitDir = path.join(os.homedir(), '.config', 'systemd', 'user');
      const units = ['agentdock-bridge.service', fs.existsSync(path.join(unitDir, 'agentdock-webui.service')) ? 'agentdock-webui.service' : null].filter(Boolean);
      await execFileAsync('systemctl', ['--user', 'disable', ...units], { timeout: 25000, env });
      return;
    }
    if (sys.supported && sys.installed && (sys.enabled || sys.active || !fs.existsSync(path.join(stateDir, 'start')))) {
      await execFileAsync('systemctl', ['--user', action, 'agentdock-bridge.service'], { timeout: 25000, env });
    } else if (action === 'restart') {
      await runWrapper('stop', 25000).catch(() => {});
      await runWrapper('start', 15000);
    } else {
      await runWrapper(action === 'stop' ? 'stop' : 'start', 25000);
    }
    if (action === 'start' || action === 'restart') {
      const deadline = Date.now() + 2000;
      const supFile = path.join(stateDir, 'supervisor.json');
      while (Date.now() < deadline && !fs.existsSync(supFile)) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }
  };
}

function pickEditableMcpFields(body) {
  const allowed = [
    'id',
    'name',
    'description',
    'transport',
    'enabled',
    'command',
    'args',
    'cwd',
    'env',
    'removeEnvKeys',
    'url',
    'headers',
    'removeHeaderKeys',
    'timeoutMs',
    'disabledTools',
  ];
  const out = {};
  for (const key of allowed) {
    if (Object.hasOwn(body, key)) out[key] = body[key];
  }
  return out;
}

export async function startWebUiServer({
  stateDir,
  runtimeRoot,
  host = '127.0.0.1',
  port = 18797,
  requirePrivateState = true,
  pollIntervalMs = 1500,
  passkeyDetector = detectHostPasskeySupport,
  gatewayProbe = defaultGatewayProbe,
  dockerProbe = defaultDockerProbe,
  systemdProbe = defaultSystemdProbe,
  mcpProber = probeMcpServer,
  serviceController,
} = {}) {
  if (!isLoopbackHost(host)) {
    throw new Error('AgentDock WebUI must bind strictly to a loopback interface (127.0.0.1, localhost, or ::1).');
  }
  const resolvedState = validateStateDir(stateDir, requirePrivateState);
  const startupConfig = readTrustedJsonFile(path.join(resolvedState, 'config.json'), requirePrivateState);
  const startupRoots = loadWorkspaceRootsFromStateConfig(resolvedState);
  assertConfigOutsideWorkspace(path.join(resolvedState, 'config.json'), startupRoots);
  if (fs.lstatSync(path.join(resolvedState, 'capabilities.json'), { throwIfNoEntry: false })) {
    assertConfigOutsideWorkspace(path.join(resolvedState, 'capabilities.json'), startupRoots);
  }
  if (fs.lstatSync(path.join(resolvedState, 'webui-auth.json'), { throwIfNoEntry: false })) {
    assertConfigOutsideWorkspace(path.join(resolvedState, 'webui-auth.json'), startupRoots);
  }
  if (fs.lstatSync(mcpServersFilePath(resolvedState), { throwIfNoEntry: false })) {
    assertConfigOutsideWorkspace(mcpServersFilePath(resolvedState), startupRoots);
  }
  void startupConfig;

  const resolvedRuntime = path.resolve(runtimeRoot);
  const handleServiceAction = serviceController || defaultServiceController(resolvedState, systemdProbe, requirePrivateState);

  const csrfSecret = crypto.randomBytes(32);
  const sseClients = new Map();
  const sessions = new Map();
  const registerChallenges = new Map();
  const loginChallenges = new Map();
  const activeProbes = new Set();
  const activeProbeIds = new Set();
  const shutdownController = new AbortController();
  let serviceActionInFlight = false;
  let failedAttempts = 0;
  let lockedUntilMs = 0;
  let lastSnapshot = null;
  let lastDigest = '';
  let refreshing = null;
  let queuedRefresh = null;
  let actualPort = port;

  const validTokenId = val => typeof val === 'string' && /^[A-Za-z0-9_-]{32,80}$/.test(val);
  const deriveCsrf = (kind, id) => crypto.createHmac('sha256', csrfSecret).update(`${kind}:${id}`).digest('base64url');
  const timingSafeEqualText = (a, b) => {
    const ab = Buffer.from(String(a || ''), 'utf8');
    const bb = Buffer.from(String(b || ''), 'utf8');
    return ab.length > 0 && ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
  };

  const allowedHosts = boundPort => new Set([
    `127.0.0.1:${boundPort}`,
    `localhost:${boundPort}`,
    `[::1]:${boundPort}`,
  ]);
  const allowedOrigins = boundPort => new Set([
    `http://127.0.0.1:${boundPort}`,
    `http://localhost:${boundPort}`,
    `http://[::1]:${boundPort}`,
  ]);

  function loadCurrentWorkspaceRoots() {
    const configPath = path.join(resolvedState, 'config.json');
    readTrustedJsonFile(configPath, requirePrivateState);
    const roots = loadWorkspaceRootsFromStateConfig(resolvedState);
    assertConfigOutsideWorkspace(configPath, roots);
    return roots;
  }

  function loadCurrentAuthRecord() {
    const roots = loadCurrentWorkspaceRoots();
    return readWebUiAuthSync(resolvedState, { workspaceRoots: roots, passkeyDetector });
  }

  function pruneSessions(now = Date.now()) {
    for (const [sid, session] of sessions) {
      if (session.expiresAt <= now || now - session.lastSeenAt > SESSION_IDLE_MS) {
        sessions.delete(sid);
      }
    }
    while (sessions.size >= MAX_SESSIONS) {
      const oldestKey = sessions.keys().next().value;
      sessions.delete(oldestKey);
    }
  }

  function createAuthenticatedSession(authMethod, authVersion, sessionPersistence = 'tab') {
    const now = Date.now();
    pruneSessions(now);
    const sid = crypto.randomBytes(32).toString('base64url');
    const csrfToken = deriveCsrf('auth', sid);
    const tabToken = crypto.randomBytes(32).toString('base64url');
    sessions.set(sid, {
      sid,
      csrfToken,
      tabToken,
      authMethod,
      authVersion,
      sessionPersistence: sessionPersistence === 'browser' ? 'browser' : 'tab',
      createdAt: now,
      lastSeenAt: now,
      expiresAt: now + SESSION_MAX_MS,
    });
    return { sid, csrfToken, tabToken };
  }

  function authenticateSession(req, authRecord, touch = true) {
    if (!authRecord || authRecord.error || !authRecord.initialized) return null;
    const cookies = parseCookieHeader(req.headers.cookie);
    const sid = cookies.get(SESSION_COOKIE);
    if (!validTokenId(sid)) return null;
    const session = sessions.get(sid);
    if (!session) return null;
    const now = Date.now();
    if (session.expiresAt <= now || now - session.lastSeenAt > SESSION_IDLE_MS) {
      sessions.delete(sid);
      return null;
    }
    if (session.authVersion !== authRecord.authVersion) {
      sessions.delete(sid);
      return null;
    }
    if ((authRecord.requirePasskey || authRecord.passkeys.length > 0) && session.authMethod !== 'passkey') {
      sessions.delete(sid);
      return null;
    }
    const persistence = authRecord.sessionPersistence || 'tab';
    if (persistence === 'tab') {
      const providedTab = String(req.headers['x-agentdock-tab-auth'] || '');
      if (!providedTab || !timingSafeEqualText(providedTab, session.tabToken)) {
        // Keep session alive for the owning tab while forcing new/reopened tabs to re-auth.
        return null;
      }
    }
    if (touch) session.lastSeenAt = now;
    return session;
  }

  function invalidateAllSessions() {
    sessions.clear();
    for (const client of sseClients.keys()) client.end();
    sseClients.clear();
  }

  function challengeStore(kind) {
    return kind === 'register' ? registerChallenges : loginChallenges;
  }

  function issueWebAuthnChallenge(kind, sid = null) {
    const store = challengeStore(kind);
    const now = Date.now();
    for (const [key, item] of store) {
      if (item.expiresAt <= now) store.delete(key);
    }
    while (store.size >= MAX_CHALLENGES) {
      store.delete(store.keys().next().value);
    }
    const challenge = toBase64Url(crypto.randomBytes(32));
    const challengeId = toBase64Url(crypto.randomBytes(16));
    store.set(challengeId, {
      kind,
      challenge,
      sid: sid || null,
      expiresAt: now + CHALLENGE_TTL_MS,
    });
    return { challengeId, challenge };
  }

  function consumeWebAuthnChallenge(challengeId, expectedKind, expectedSid = null) {
    if (typeof challengeId !== 'string' || !challengeId) {
      throw new Error('PassKey challenge expired or invalid.');
    }
    const store = challengeStore(expectedKind);
    const entry = store.get(challengeId);
    if (!entry || entry.kind !== expectedKind || entry.sid !== (expectedSid || null)) {
      throw new Error('PassKey challenge expired or invalid.');
    }
    store.delete(challengeId);
    if (entry.expiresAt <= Date.now()) {
      throw new Error('PassKey challenge expired or invalid.');
    }
    return entry;
  }

  function recordAuthFailure() {
    failedAttempts += 1;
    if (failedAttempts >= AUTH_FAILURE_LIMIT) {
      const exponent = Math.min(4, failedAttempts - AUTH_FAILURE_LIMIT);
      const lockoutMs = 60 * 1000 * (2 ** exponent);
      lockedUntilMs = Date.now() + lockoutMs;
    }
  }

  function clearAuthFailures() {
    failedAttempts = 0;
    lockedUntilMs = 0;
  }

  function checkRateLimit(res) {
    const now = Date.now();
    if (lockedUntilMs > now) {
      const retrySec = Math.ceil((lockedUntilMs - now) / 1000);
      res.setHeader('Retry-After', String(retrySec));
      sendJson(res, 429, { error: `Too many failed authentication attempts. Retry in ${retrySec}s.`, retryAfterSec: retrySec });
      return false;
    }
    return true;
  }

  function applyCommonHeaders(res, contentType, extra = {}) {
    res.setHeader('Content-Type', contentType);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    );
    for (const [k, v] of Object.entries(extra)) res.setHeader(k, v);
  }

  function sendJson(res, status, data, extraHeaders = {}) {
    applyCommonHeaders(res, 'application/json; charset=utf-8', extraHeaders);
    res.statusCode = status;
    res.end(JSON.stringify(data));
  }

  function verifyHost(req) {
    const hostHeader = String(req.headers.host || '').toLowerCase();
    return allowedHosts(actualPort).has(hostHeader);
  }

  function verifyFetchSiteSameOriginOrNone(req, allowNone) {
    const site = req.headers['sec-fetch-site'];
    if (!site) return true;
    return allowNone ? (site === 'same-origin' || site === 'none') : site === 'same-origin';
  }

  function verifyPreAuthCsrf(req) {
    const origin = String(req.headers.origin || '').toLowerCase();
    if (!allowedOrigins(actualPort).has(origin)) return false;
    if (!verifyFetchSiteSameOriginOrNone(req, false)) return false;
    const provided = String(req.headers['x-agentdock-csrf'] || '');
    if (!provided) return false;
    const cookies = parseCookieHeader(req.headers.cookie);
    const sid = cookies.get(SESSION_COOKIE);
    const session = validTokenId(sid) ? sessions.get(sid) : null;
    if (session && timingSafeEqualText(provided, session.csrfToken)) return true;
    const preId = cookies.get(PRE_AUTH_COOKIE);
    if (!validTokenId(preId)) return false;
    return timingSafeEqualText(provided, deriveCsrf('pre', preId));
  }

  function verifyAuthenticatedCsrf(req, session) {
    const origin = String(req.headers.origin || '').toLowerCase();
    if (!allowedOrigins(actualPort).has(origin)) return false;
    if (!verifyFetchSiteSameOriginOrNone(req, false)) return false;
    const provided = String(req.headers['x-agentdock-csrf'] || '');
    return Boolean(session && timingSafeEqualText(provided, session.csrfToken));
  }

  async function readBodyJson(req) {
    const contentType = String(req.headers['content-type'] || '').toLowerCase().trim();
    if (!/^application\/json(?:\s*;|$)/.test(contentType)) {
      const err = new Error('Content-Type must be application/json.');
      err.status = 415;
      throw err;
    }
    const chunks = [];
    let size = 0;
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      req.destroy(Object.assign(new Error('Request body timeout.'), { status: 408 }));
    }, 10000);
    timer.unref?.();
    try {
      for await (const chunk of req) {
        size += chunk.length;
        if (size > MAX_JSON_BODY) {
          const err = new Error('Request payload too large.');
          err.status = 413;
          throw err;
        }
        chunks.push(chunk);
      }
    } catch (err) {
      if (timedOut) {
        const timeoutErr = new Error('Request body timeout.');
        timeoutErr.status = 408;
        throw timeoutErr;
      }
      if (Number.isInteger(err?.status)) throw err;
      const aborted = new Error('Request body stream aborted.');
      aborted.status = 400;
      throw aborted;
    } finally {
      clearTimeout(timer);
    }
    try {
      const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error();
      return parsed;
    } catch {
      const err = new Error('Invalid JSON payload.');
      err.status = 400;
      throw err;
    }
  }

  async function readAuthenticatedJson(req, res, session) {
    const body = await readBodyJson(req);
    const freshAuth = loadCurrentAuthRecord();
    if (freshAuth.error) {
      sendJson(res, 403, { error: freshAuth.error, code: 'AUTH_CONFIG_ERROR' });
      return null;
    }
    const live = authenticateSession(req, freshAuth, true);
    if (!live || live !== session) {
      sendJson(res, 401, {
        error: 'WebUI authentication is required.',
        mode: publicWebUiAuthSummary(freshAuth).mode,
      });
      return null;
    }
    return { body, authRecord: freshAuth };
  }

  function safeUserLabel() {
    try {
      return os.userInfo().username || 'owner';
    } catch {
      return 'owner';
    }
  }

  function sha256OfSnapshot(snap) {
    const comparable = {
      ...snap,
      observedAt: undefined,
      daemon: snap?.daemon ? { ...snap.daemon, gatewayLatencyMs: undefined } : snap?.daemon,
    };
    return crypto.createHash('sha256').update(JSON.stringify(comparable)).digest('hex');
  }

  function sendStreamFrame(client, req, authRecord, frame) {
    if (client.writableEnded) {
      sseClients.delete(client);
      return;
    }
    if (client.writableLength > 512 * 1024) {
      sseClients.delete(client);
      try { client.destroy(); } catch {}
      return;
    }
    if (authenticateSession(req, authRecord, false)) client.write(frame);
    else {
      sseClients.delete(client);
      client.end();
    }
  }

  function currentBlockedOrigins() {
    let origin = null;
    try {
      const cfg = readTrustedJsonFile(path.join(resolvedState, 'config.json'), requirePrivateState);
      if (typeof cfg?.origin === 'string') origin = cfg.origin;
    } catch {}
    return [
      origin,
      `http://127.0.0.1:${actualPort}`,
      `http://localhost:${actualPort}`,
      `http://[::1]:${actualPort}`,
    ].filter(Boolean);
  }

  async function refreshAndBroadcast({ force = false, broadcast = true } = {}) {
    if (refreshing) {
      if (!force) return refreshing;
      if (!queuedRefresh) {
        let resolveQueued;
        let rejectQueued;
        const promise = new Promise((resolve, reject) => {
          resolveQueued = resolve;
          rejectQueued = reject;
        });
        queuedRefresh = { broadcast: Boolean(broadcast), promise, resolve: resolveQueued, reject: rejectQueued };
      } else {
        queuedRefresh.broadcast = queuedRefresh.broadcast || Boolean(broadcast);
      }
      return queuedRefresh.promise;
    }
    refreshing = collectStatusSnapshot({
      stateDir: resolvedState,
      runtimeRoot: resolvedRuntime,
      requirePrivateState,
      passkeyDetector,
      gatewayProbe,
      dockerProbe,
      systemdProbe,
      blockedOrigins: currentBlockedOrigins(),
    }).then(snap => {
      lastSnapshot = snap;
      const digestHash = sha256OfSnapshot(snap);
      if (broadcast && (force || digestHash !== lastDigest)) {
        lastDigest = digestHash;
        const frame = `event: status\ndata: ${JSON.stringify(snap)}\n\n`;
        const auth = loadCurrentAuthRecord();
        for (const [client, req] of sseClients) sendStreamFrame(client, req, auth, frame);
      } else if (sseClients.size === 0 && (force || digestHash !== lastDigest)) {
        lastDigest = digestHash;
      }
      return snap;
    }).finally(() => {
      refreshing = null;
      if (queuedRefresh) {
        const next = queuedRefresh;
        queuedRefresh = null;
        refreshAndBroadcast({ force: true, broadcast: next.broadcast })
          .then(next.resolve, next.reject);
      }
    });
    return refreshing;
  }

  function sessionLoginCookies(sid) {
    return [
      `${SESSION_COOKIE}=${sid}; HttpOnly; SameSite=Strict; Path=/`,
      `${PRE_AUTH_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`,
    ];
  }

  function resetPreAuthCsrf() {
    const preId = crypto.randomBytes(24).toString('base64url');
    const setCookies = [
      `${SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`,
      `${PRE_AUTH_COOKIE}=${preId}; HttpOnly; SameSite=Strict; Path=/`,
    ];
    return { csrfToken: deriveCsrf('pre', preId), setCookies };
  }

  function formatAuthStatePayload(authRecord, session) {
    return {
      authenticated: Boolean(session),
      authMethod: session ? session.authMethod : null,
      ...(session ? { csrfToken: session.csrfToken } : {}),
      lockedUntilMs: lockedUntilMs > Date.now() ? lockedUntilMs : 0,
      ...publicWebUiAuthSummary(authRecord, { includePrivateMeta: Boolean(session) }),
    };
  }

  function sanitizeProbeForClient(rawProbe, serverConfig) {
    if (!rawProbe || typeof rawProbe !== 'object') {
      return { ok: false, latencyMs: 0, error: 'Probe failed.' };
    }
    if (rawProbe.ok) {
      return {
        ok: true,
        latencyMs: Number.isFinite(rawProbe.latencyMs) ? rawProbe.latencyMs : 0,
        ...(rawProbe.protocolVersion ? { protocolVersion: rawProbe.protocolVersion } : {}),
        ...(rawProbe.serverInfo ? { serverInfo: rawProbe.serverInfo } : {}),
        tools: Array.isArray(rawProbe.tools) ? rawProbe.tools : [],
      };
    }
    return {
      ok: false,
      latencyMs: Number.isFinite(rawProbe.latencyMs) ? rawProbe.latencyMs : 0,
      error: redactSecretsFromText(rawProbe.error || 'Failed to connect to external MCP server.', serverConfig),
    };
  }

  async function runBoundedProbe(serverConfig, res, blockedOrigins, maxWallMs = 30000) {
    if (res.closed && !res.writableEnded) {
      const err = new Error('Client disconnected during probe.');
      err.status = 499;
      throw err;
    }
    if (activeProbes.size >= 3) {
      const err = new Error('Too many concurrent MCP connection probes in progress. Please wait and retry.');
      err.status = 429;
      throw err;
    }
    if (activeProbeIds.has(serverConfig.id)) {
      const err = new Error(`A probe for MCP server "${serverConfig.id}" is already in progress.`);
      err.status = 409;
      throw err;
    }
    const ctrl = new AbortController();
    const timeoutMs = Math.min(Number(serverConfig.timeoutMs) || 30000, maxWallMs);
    const timer = setTimeout(() => ctrl.abort(new Error(`Probe timed out after ${timeoutMs}ms.`)), Math.max(1000, timeoutMs));
    timer.unref?.();
    const onResClose = () => {
      if (!res.writableEnded) ctrl.abort(new Error('Client disconnected during probe.'));
    };
    const onShutdown = () => ctrl.abort(new Error('WebUI server shutting down.'));
    res.on('close', onResClose);
    if (shutdownController.signal.aborted) ctrl.abort(new Error('WebUI server shutting down.'));
    else shutdownController.signal.addEventListener('abort', onShutdown, { once: true });

    activeProbes.add(ctrl);
    activeProbeIds.add(serverConfig.id);
    try {
      const raw = await mcpProber(serverConfig, {
        stateDir: resolvedState,
        blockedOrigins,
        signal: ctrl.signal,
      });
      return sanitizeProbeForClient(raw, serverConfig);
    } finally {
      clearTimeout(timer);
      res.off('close', onResClose);
      shutdownController.signal.removeEventListener('abort', onShutdown);
      activeProbes.delete(ctrl);
      activeProbeIds.delete(serverConfig.id);
    }
  }

  function isSetupAuthorized(req, authRecord, bodySetupToken) {
    const session = authenticateSession(req, authRecord);
    if (session) return { ok: true, via: 'session', session };
    if (verifySetupTicketMatch(authRecord, bodySetupToken)) return { ok: true, via: 'ticket', session: null };
    return { ok: false };
  }

  const server = http.createServer(async (req, res) => {
    try {
      if (!verifyHost(req)) {
        return sendJson(res, 403, { error: 'Rejected untrusted Host header.' });
      }
      if (!req.url || !req.url.startsWith('/') || req.url.startsWith('//')) {
        return sendJson(res, 400, { error: 'Invalid request path.' });
      }
      let reqUrl;
      try {
        reqUrl = new URL(req.url, `http://127.0.0.1:${actualPort}`);
      } catch {
        return sendJson(res, 400, { error: 'Malformed request URL.' });
      }

      if (req.method === 'GET' && reqUrl.pathname === '/') {
        if (!verifyFetchSiteSameOriginOrNone(req, true)) {
          return sendJson(res, 403, { error: 'Cross-site access denied.' });
        }
        const authRecord = loadCurrentAuthRecord();
        const session = authenticateSession(req, authRecord);
        const headersToSet = [];
        let csrfToken;
        if (session) {
          csrfToken = session.csrfToken;
        } else {
          const cookies = parseCookieHeader(req.headers.cookie);
          let preId = cookies.get(PRE_AUTH_COOKIE);
          if (!validTokenId(preId)) {
            preId = crypto.randomBytes(24).toString('base64url');
            headersToSet.push(`${PRE_AUTH_COOKIE}=${preId}; HttpOnly; SameSite=Strict; Path=/`);
          }
          csrfToken = deriveCsrf('pre', preId);
        }
        applyCommonHeaders(res, 'text/html; charset=utf-8');
        if (headersToSet.length) res.setHeader('Set-Cookie', headersToSet);
        res.statusCode = 200;
        res.end(renderWebUiHtml({ csrfToken }));
        return;
      }

      if (req.method === 'GET' && reqUrl.pathname === '/styles.css') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) {
          return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        }
        applyCommonHeaders(res, 'text/css; charset=utf-8');
        res.statusCode = 200;
        res.end(WEBUI_CSS);
        return;
      }

      if (req.method === 'GET' && reqUrl.pathname === '/app.js') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) {
          return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        }
        applyCommonHeaders(res, 'application/javascript; charset=utf-8');
        res.statusCode = 200;
        res.end(WEBUI_JS);
        return;
      }

      if (req.method === 'GET' && reqUrl.pathname === '/api/auth/state') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) {
          return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        }
        const authRecord = loadCurrentAuthRecord();
        const session = authenticateSession(req, authRecord);
        if (session) {
          return sendJson(res, 200, formatAuthStatePayload(authRecord, session));
        }
        const cookies = parseCookieHeader(req.headers.cookie);
        let preId = cookies.get(PRE_AUTH_COOKIE);
        const extraHeaders = {};
        if (!validTokenId(preId)) {
          preId = crypto.randomBytes(24).toString('base64url');
          extraHeaders['Set-Cookie'] = `${PRE_AUTH_COOKIE}=${preId}; HttpOnly; SameSite=Strict; Path=/`;
        }
        return sendJson(
          res,
          200,
          {
            ...formatAuthStatePayload(authRecord, null),
            csrfToken: deriveCsrf('pre', preId),
          },
          extraHeaders,
        );
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/auth/setup/password') {
        if (!verifyPreAuthCsrf(req)) return sendJson(res, 403, { error: 'CSRF validation failed.' });
        const body = await readBodyJson(req);
        const roots = loadCurrentWorkspaceRoots();
        const authRecord = loadCurrentAuthRecord();
        if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' });
        const hasTicketInput = typeof body.setupToken === 'string' && body.setupToken.trim().length > 0;
        if (hasTicketInput && !checkRateLimit(res)) return;
        const authz = isSetupAuthorized(req, authRecord, body.setupToken);
        if (!authz.ok) {
          if (hasTicketInput) recordAuthFailure();
          return sendJson(res, 401, { error: 'Valid single-use setup code from ~/.agentdock-bridge/webui-auth init is required.' });
        }
        if (authz.via === 'session' && !verifyAuthenticatedCsrf(req, authz.session)) {
          return sendJson(res, 403, { error: 'Authenticated CSRF validation failed.' });
        }
        if (authz.via === 'session' && authRecord.passwordHash && !authRecord.requirePasskey) {
          if (!checkRateLimit(res)) return;
          if (typeof body.currentPassword !== 'string' || !verifyStrongPassword(body.currentPassword, authRecord.passwordHash)) {
            recordAuthFailure();
            return sendJson(res, 401, { error: '当前强密码验证失败，无法重置密码。' });
          }
        }
        try {
          const updated = setStrongPasswordSync(resolvedState, {
            password: body.password,
            setupToken: body.setupToken,
            allowBypassTicket: authz.via === 'session',
            workspaceRoots: roots,
            requirePrivateState,
            passkeyDetector,
          });
          invalidateAllSessions();
          clearAuthFailures();
          const newSession = createAuthenticatedSession('password', updated.authVersion, updated.sessionPersistence);
          appendSanitizedConnectorLog(resolvedState, 'webui_auth', { outcome: 'password_configured' });
          return sendJson(res, 200, {
            ok: true,
            csrfToken: newSession.csrfToken,
            tabToken: newSession.tabToken,
            authState: formatAuthStatePayload(updated, sessions.get(newSession.sid)),
          }, {
            'Set-Cookie': sessionLoginCookies(newSession.sid),
          });
        } catch (err) {
          const status = /PassKey/i.test(err?.message || '') ? 403 : 400;
          return sendJson(res, status, { error: err?.message || 'Cannot configure password.' });
        }
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/auth/passkey/report-support') {
        if (!verifyPreAuthCsrf(req)) return sendJson(res, 403, { error: 'CSRF validation failed.' });
        const body = await readBodyJson(req);
        const roots = loadCurrentWorkspaceRoots();
        const authRecord = loadCurrentAuthRecord();
        if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' });
        const hasTicketInput = typeof body.setupToken === 'string' && body.setupToken.trim().length > 0;
        if (hasTicketInput && !checkRateLimit(res)) return;
        const authz = isSetupAuthorized(req, authRecord, body.setupToken);
        if (!authz.ok) {
          if (hasTicketInput) recordAuthFailure();
          return sendJson(res, 401, { error: 'Authentication or setup code required.' });
        }
        if (authz.via === 'session' && !verifyAuthenticatedCsrf(req, authz.session)) {
          return sendJson(res, 403, { error: 'Authenticated CSRF validation failed.' });
        }
        if (body.uvpa === true) {
          const wasRequired = Boolean(authRecord.requirePasskey);
          const updated = markPasskeyRequiredSync(resolvedState, {
            workspaceRoots: roots,
            requirePrivateState,
            passkeyDetector,
          });
          if (!wasRequired) {
            invalidateAllSessions();
            appendSanitizedConnectorLog(resolvedState, 'webui_auth', { outcome: 'passkey_enforced' });
            const nextCsrf = resetPreAuthCsrf();
            return sendJson(res, 200, {
              ok: true,
              csrfToken: nextCsrf.csrfToken,
              authState: formatAuthStatePayload(updated, null),
            }, {
              'Set-Cookie': nextCsrf.setCookies,
            });
          }
          return sendJson(res, 200, { ok: true, authState: formatAuthStatePayload(updated, authz.session) });
        }
        return sendJson(res, 200, { ok: true, authState: formatAuthStatePayload(authRecord, authz.session) });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/auth/setup/passkey/options') {
        if (!verifyPreAuthCsrf(req)) return sendJson(res, 403, { error: 'CSRF validation failed.' });
        const body = await readBodyJson(req);
        const authRecord = loadCurrentAuthRecord();
        if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' });
        const hasTicketInput = typeof body.setupToken === 'string' && body.setupToken.trim().length > 0;
        if (hasTicketInput && !checkRateLimit(res)) return;
        const authz = isSetupAuthorized(req, authRecord, body.setupToken);
        if (!authz.ok) {
          if (hasTicketInput) recordAuthFailure();
          return sendJson(res, 401, { error: 'Valid setup code or active authenticated session is required to enroll PassKey.' });
        }
        if (authz.via === 'session' && !verifyAuthenticatedCsrf(req, authz.session)) {
          return sendJson(res, 403, { error: 'Authenticated CSRF validation failed.' });
        }
        const { challengeId, challenge } = issueWebAuthnChallenge('register', authz.session?.sid || null);
        return sendJson(res, 200, {
          challengeId,
          publicKey: {
            challenge,
            rp: { name: 'AgentDock Bridge WebUI', id: 'localhost' },
            user: {
              id: toBase64Url(crypto.createHash('sha256').update(resolvedState).digest().subarray(0, 16)),
              name: safeUserLabel(),
              displayName: 'AgentDock Owner',
            },
            pubKeyCredParams: [
              { type: 'public-key', alg: -7 },
              { type: 'public-key', alg: -35 },
              { type: 'public-key', alg: -257 },
              { type: 'public-key', alg: -8 },
            ],
            timeout: 120000,
            attestation: 'none',
            authenticatorSelection: {
              userVerification: 'required',
              residentKey: 'preferred',
            },
            excludeCredentials: authRecord.passkeys.map(pk => ({
              type: 'public-key',
              id: pk.id,
              ...(Array.isArray(pk.transports) && pk.transports.length ? { transports: pk.transports } : {}),
            })),
          },
        });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/auth/setup/passkey/verify') {
        if (!verifyPreAuthCsrf(req)) return sendJson(res, 403, { error: 'CSRF validation failed.' });
        const body = await readBodyJson(req);
        const roots = loadCurrentWorkspaceRoots();
        const authRecord = loadCurrentAuthRecord();
        if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' });
        const hasTicketInput = typeof body.setupToken === 'string' && body.setupToken.trim().length > 0;
        if (hasTicketInput && !checkRateLimit(res)) return;
        const authz = isSetupAuthorized(req, authRecord, body.setupToken);
        if (!authz.ok) {
          if (hasTicketInput) recordAuthFailure();
          return sendJson(res, 401, { error: 'Valid setup code or authenticated session is required.' });
        }
        if (authz.via === 'session' && !verifyAuthenticatedCsrf(req, authz.session)) {
          return sendJson(res, 403, { error: 'Authenticated CSRF validation failed.' });
        }
        try {
          const ch = consumeWebAuthnChallenge(body.challengeId, 'register', authz.session?.sid || null);
          const verified = verifyRegistrationResponse({
            credential: body.credential,
            expectedChallenge: ch.challenge,
            expectedRpId: 'localhost',
            allowedOrigins: new Set([`http://localhost:${actualPort}`]),
          });
          const updated = enrollPasskeySync(resolvedState, {
            credential: verified,
            label: body.label || 'Local PassKey',
            workspaceRoots: roots,
            requirePrivateState,
            passkeyDetector,
          });
          invalidateAllSessions();
          clearAuthFailures();
          const newSession = createAuthenticatedSession('passkey', updated.authVersion, updated.sessionPersistence);
          appendSanitizedConnectorLog(resolvedState, 'webui_auth', { outcome: 'passkey_enrolled' });
          return sendJson(res, 200, {
            ok: true,
            csrfToken: newSession.csrfToken,
            tabToken: newSession.tabToken,
            authState: formatAuthStatePayload(updated, sessions.get(newSession.sid)),
          }, {
            'Set-Cookie': sessionLoginCookies(newSession.sid),
          });
        } catch (err) {
          return sendJson(res, 400, { error: err?.message || 'PassKey registration verification failed.' });
        }
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/auth/login/password') {
        if (!verifyPreAuthCsrf(req)) return sendJson(res, 403, { error: 'CSRF validation failed.' });
        if (!checkRateLimit(res)) return;
        const body = await readBodyJson(req);
        if (!checkRateLimit(res)) return;
        const authRecord = loadCurrentAuthRecord();
        if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' });
        if (authRecord.requirePasskey || authRecord.passkeys.length > 0 || authRecord.hostPasskeySupported) {
          return sendJson(res, 403, { error: 'PassKey authentication is mandatory on this machine.' });
        }
        if (!authRecord.initialized || !authRecord.passwordHash) {
          return sendJson(res, 401, { error: 'WebUI strong password is not configured yet.' });
        }
        if (!verifyStrongPassword(body.password, authRecord.passwordHash)) {
          recordAuthFailure();
          appendSanitizedConnectorLog(resolvedState, 'webui_auth', { outcome: 'password_failed' });
          return sendJson(res, 401, { error: 'Invalid WebUI password.' });
        }
        clearAuthFailures();
        const newSession = createAuthenticatedSession('password', authRecord.authVersion, authRecord.sessionPersistence);
        appendSanitizedConnectorLog(resolvedState, 'webui_auth', { outcome: 'password_login_ok' });
        return sendJson(res, 200, {
          ok: true,
          csrfToken: newSession.csrfToken,
          tabToken: newSession.tabToken,
          authState: formatAuthStatePayload(authRecord, sessions.get(newSession.sid)),
        }, {
          'Set-Cookie': sessionLoginCookies(newSession.sid),
        });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/auth/passkey/login/options') {
        if (!verifyPreAuthCsrf(req)) return sendJson(res, 403, { error: 'CSRF validation failed.' });
        if (!checkRateLimit(res)) return;
        await readBodyJson(req);
        if (!checkRateLimit(res)) return;
        const authRecord = loadCurrentAuthRecord();
        if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' });
        if (!authRecord.passkeys.length) {
          return sendJson(res, 400, { error: 'No PassKey is enrolled yet.' });
        }
        const { challengeId, challenge } = issueWebAuthnChallenge('login');
        return sendJson(res, 200, {
          challengeId,
          publicKey: {
            challenge,
            rpId: 'localhost',
            timeout: 120000,
            userVerification: 'required',
            allowCredentials: authRecord.passkeys.map(pk => ({
              type: 'public-key',
              id: pk.id,
              ...(Array.isArray(pk.transports) && pk.transports.length ? { transports: pk.transports } : {}),
            })),
          },
        });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/auth/passkey/login/verify') {
        if (!verifyPreAuthCsrf(req)) return sendJson(res, 403, { error: 'CSRF validation failed.' });
        if (!checkRateLimit(res)) return;
        const body = await readBodyJson(req);
        if (!checkRateLimit(res)) return;
        const roots = loadCurrentWorkspaceRoots();
        const authRecord = loadCurrentAuthRecord();
        if (authRecord.error) return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' });
        try {
          const ch = consumeWebAuthnChallenge(body.challengeId, 'login', null);
          const credId = body.credential?.id;
          const stored = authRecord.passkeys.find(pk => pk.id === credId);
          if (!stored) throw new Error('Unknown PassKey credential.');
          const { newSignCount } = verifyAuthenticationResponse({
            credential: body.credential,
            storedPasskey: stored,
            expectedChallenge: ch.challenge,
            expectedRpId: 'localhost',
            allowedOrigins: new Set([`http://localhost:${actualPort}`]),
          });
          updatePasskeySignCountSync(resolvedState, {
            credentialId: stored.id,
            newSignCount,
            workspaceRoots: roots,
            requirePrivateState,
            passkeyDetector,
          });
          clearAuthFailures();
          const refreshed = loadCurrentAuthRecord();
          const newSession = createAuthenticatedSession('passkey', refreshed.authVersion, refreshed.sessionPersistence);
          appendSanitizedConnectorLog(resolvedState, 'webui_auth', { outcome: 'passkey_login_ok' });
          return sendJson(res, 200, {
            ok: true,
            csrfToken: newSession.csrfToken,
            tabToken: newSession.tabToken,
            authState: formatAuthStatePayload(refreshed, sessions.get(newSession.sid)),
          }, {
            'Set-Cookie': sessionLoginCookies(newSession.sid),
          });
        } catch (err) {
          recordAuthFailure();
          appendSanitizedConnectorLog(resolvedState, 'webui_auth', { outcome: 'passkey_failed' });
          return sendJson(res, 401, { error: err?.message || 'PassKey authentication failed.' });
        }
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/auth/logout') {
        const cookies = parseCookieHeader(req.headers.cookie);
        const sid = cookies.get(SESSION_COOKIE);
        const activeSession = validTokenId(sid) ? sessions.get(sid) : null;
        if (activeSession) {
          if (!verifyAuthenticatedCsrf(req, activeSession)) return sendJson(res, 403, { error: 'CSRF validation failed.' });
        } else if (!verifyPreAuthCsrf(req)) {
          return sendJson(res, 403, { error: 'CSRF validation failed.' });
        }
        await readBodyJson(req);
        if (sid) {
          sessions.delete(sid);
          for (const [client, streamReq] of sseClients) {
            if (parseCookieHeader(streamReq.headers.cookie).get(SESSION_COOKIE) === sid) {
              sseClients.delete(client);
              client.end();
            }
          }
        }
        const nextCsrf = resetPreAuthCsrf();
        return sendJson(res, 200, { ok: true, csrfToken: nextCsrf.csrfToken }, {
          'Set-Cookie': nextCsrf.setCookies,
        });
      }

      // Authenticated dashboard endpoints below: ALL reject unauthenticated calls with 401.
      const authRecord = loadCurrentAuthRecord();
      if (authRecord.error) {
        return sendJson(res, 403, { error: authRecord.error, code: 'AUTH_CONFIG_ERROR' });
      }
      const session = authenticateSession(req, authRecord);
      if (!session) {
        return sendJson(res, 401, { error: 'WebUI authentication is required.', mode: publicWebUiAuthSummary(authRecord).mode });
      }

      if (req.method === 'GET' && reqUrl.pathname === '/api/status') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) {
          return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        }
        const snap = await refreshAndBroadcast({ force: false });
        return sendJson(res, 200, snap);
      }

      if (req.method === 'GET' && reqUrl.pathname === '/api/events') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) {
          return sendJson(res, 403, { error: 'Cross-site event stream rejected.' });
        }
        if (sseClients.size >= MAX_SSE_CLIENTS) {
          return sendJson(res, 429, { error: 'Too many active WebUI monitoring streams.' });
        }
        res.writeHead(200, {
          'Content-Type': 'text/event-stream; charset=utf-8',
          'Cache-Control': 'no-store',
          Connection: 'keep-alive',
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
          'Referrer-Policy': 'no-referrer',
          'Cross-Origin-Resource-Policy': 'same-origin',
          'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
        });
        sseClients.set(res, req);
        const dropClient = () => sseClients.delete(res);
        req.on('close', dropClient);
        res.on('error', dropClient);
        res.on('close', dropClient);
        if (lastSnapshot) {
          sendStreamFrame(res, req, authRecord, `event: status\ndata: ${JSON.stringify(lastSnapshot)}\n\n`);
        } else {
          await refreshAndBroadcast({ force: false });
        }
        return;
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/capabilities') {
        if (!verifyAuthenticatedCsrf(req, session)) {
          return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed. Reload the WebUI page.' });
        }
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const { body } = parsed;
        const roots = loadCurrentWorkspaceRoots();
        const config = readTrustedJsonFile(path.join(resolvedState, 'config.json'), requirePrivateState);
        const patch = {};
        if (Object.hasOwn(body, 'fileRead')) patch.fileRead = body.fileRead;
        if (Object.hasOwn(body, 'fileWrite')) patch.fileWrite = body.fileWrite;
        if (Object.hasOwn(body, 'allowExec')) patch.allowExec = body.allowExec;
        if (Object.hasOwn(body, 'tools')) patch.tools = body.tools;
        if (!Object.keys(patch).length) {
          return sendJson(res, 400, { error: 'No capability fields provided.' });
        }
        let updated;
        try {
          updated = writeCapabilitiesSync(resolvedState, patch, {
            configAllowExec: config?.allowExec === true,
            requirePrivateState,
            workspaceRoots: roots,
          });
        } catch (err) {
          return sendJson(res, 400, { error: err?.message || 'Invalid capability update.' });
        }
        appendSanitizedConnectorLog(resolvedState, 'capability_changed', {
          mode: `read=${updated.fileRead ? 'on' : 'off'},write=${updated.fileWrite ? 'on' : 'off'},exec=${updated.allowExec ? 'on' : 'off'}`,
        });
        const snap = await refreshAndBroadcast({ force: true });
        return sendJson(res, 200, { ok: true, capabilities: updated, snapshot: snap });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/auth/settings') {
        if (!verifyAuthenticatedCsrf(req, session)) {
          return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed. Reload the WebUI page.' });
        }
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const { body } = parsed;
        const targetMode = body?.sessionPersistence;
        if (targetMode !== 'tab' && targetMode !== 'browser') {
          return sendJson(res, 400, { error: 'sessionPersistence must be "tab" or "browser".' });
        }
        const roots = loadCurrentWorkspaceRoots();
        const updated = setSessionPersistenceSync(resolvedState, {
          sessionPersistence: targetMode,
          workspaceRoots: roots,
          requirePrivateState,
          passkeyDetector,
        });
        let rotatedTabToken = session.tabToken;
        if (targetMode === 'tab') {
          rotatedTabToken = crypto.randomBytes(32).toString('base64url');
          session.authVersion = updated.authVersion;
          session.sessionPersistence = 'tab';
          for (const otherSid of [...sessions.keys()]) {
            if (otherSid !== session.sid) sessions.delete(otherSid);
          }
        } else {
          for (const s of sessions.values()) {
            s.authVersion = updated.authVersion;
            s.sessionPersistence = 'browser';
          }
        }
        appendSanitizedConnectorLog(resolvedState, 'webui_auth', { outcome: `session_policy_${targetMode}` });
        let snap = null;
        try {
          snap = await refreshAndBroadcast({ force: true, broadcast: targetMode !== 'tab' });
        } finally {
          if (targetMode === 'tab') {
            session.tabToken = rotatedTabToken;
            for (const client of sseClients.keys()) client.end();
            sseClients.clear();
          }
        }
        return sendJson(res, 200, {
          ok: true,
          csrfToken: session.csrfToken,
          ...(targetMode === 'tab' ? { tabToken: rotatedTabToken } : {}),
          authState: formatAuthStatePayload(updated, session),
          snapshot: snap,
        });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/auth/passkey/delete') {
        if (!verifyAuthenticatedCsrf(req, session)) {
          return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed. Reload the WebUI page.' });
        }
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const { body } = parsed;
        const roots = loadCurrentWorkspaceRoots();
        let updated;
        try {
          updated = deletePasskeySync(resolvedState, {
            credentialId: body?.credentialId,
            workspaceRoots: roots,
            requirePrivateState,
            passkeyDetector,
          });
        } catch (err) {
          return sendJson(res, 400, { error: err?.message || 'Cannot delete PassKey.' });
        }
        session.authVersion = updated.authVersion;
        for (const otherSid of [...sessions.keys()]) {
          if (otherSid !== session.sid) sessions.delete(otherSid);
        }
        appendSanitizedConnectorLog(resolvedState, 'webui_auth', { outcome: 'passkey_deleted' });
        const snap = await refreshAndBroadcast({ force: true });
        return sendJson(res, 200, {
          ok: true,
          csrfToken: session.csrfToken,
          authState: formatAuthStatePayload(updated, session),
          snapshot: snap,
        });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/auth/passkey/switch-password') {
        if (!verifyAuthenticatedCsrf(req, session)) {
          return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed. Reload the WebUI page.' });
        }
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const { body, authRecord: freshAuth } = parsed;
        if (session.authMethod !== 'passkey' || freshAuth.passkeys.length === 0) {
          return sendJson(res, 403, { error: 'Switching to strong password requires an active PassKey session.' });
        }
        const roots = loadCurrentWorkspaceRoots();
        let updated;
        try {
          updated = switchToStrongPasswordSync(resolvedState, {
            password: body?.password,
            workspaceRoots: roots,
            requirePrivateState,
            passkeyDetector,
          });
        } catch (err) {
          const status = /PassKey/i.test(err?.message || '') ? 403 : 400;
          return sendJson(res, status, { error: err?.message || 'Cannot switch to password mode.' });
        }
        invalidateAllSessions();
        const newSession = createAuthenticatedSession('password', updated.authVersion, updated.sessionPersistence);
        appendSanitizedConnectorLog(resolvedState, 'webui_auth', { outcome: 'switched_to_password' });
        const snap = await refreshAndBroadcast({ force: true, broadcast: false });
        return sendJson(res, 200, {
          ok: true,
          csrfToken: newSession.csrfToken,
          tabToken: newSession.tabToken,
          authState: formatAuthStatePayload(updated, sessions.get(newSession.sid)),
          snapshot: snap,
        }, {
          'Set-Cookie': sessionLoginCookies(newSession.sid),
        });
      }

      const reviewing = reqUrl.pathname === '/api/approvals/review';
      if (req.method === 'POST' && (reviewing || reqUrl.pathname === '/api/approvals/approve')) {
        if (!verifyAuthenticatedCsrf(req, session)) {
          return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed. Reload the WebUI page.' });
        }
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const { body } = parsed;
        if (typeof body?.id !== 'string' || !APPROVAL_ID.test(body.id) || (!reviewing && (typeof body.digest !== 'string' || !/^[a-f0-9]{64}$/.test(body.digest)))) {
          return sendJson(res, 400, { error: 'Invalid approval ID or review digest.' });
        }
        const approvalsDir = path.join(resolvedState, 'approvals');
        if (fs.lstatSync(approvalsDir, { throwIfNoEntry: false })?.isSymbolicLink()) {
          return sendJson(res, 400, { error: 'Approval directory must not be a link.' });
        }
        const pending = await readJson(path.join(approvalsDir, `${body.id}.request.json`)).catch(() => null);
        if (!validRequest(pending, body.id, Date.now())) {
          return sendJson(res, 404, { error: 'Pending approval request not found or expired.' });
        }
        const digest = policyDigest(pending);
        if (reviewing) {
          const requestText = JSON.stringify(pending.request, null, 2).split('\n').map(safeText).join('\n');
          return sendJson(res, 200, { id: pending.id, digest, requestText });
        }
        if (!timingSafeEqualText(digest, body.digest)) {
          return sendJson(res, 409, { error: 'Approval request changed during review; refresh and inspect again.' });
        }
        try {
          await approveRequest(approvalsDir, pending);
        } catch (err) {
          return sendJson(res, 409, { error: err?.message || 'Failed to publish approval.' });
        }
        const rawApprovedTool = typeof pending.request?.params?.name === 'string' ? pending.request.params.name : '';
        appendSanitizedConnectorLog(resolvedState, 'approval_granted', {
          tool: (KNOWN_TOOL_NAMES.has(rawApprovedTool) || isValidExternalToolName(rawApprovedTool)) ? rawApprovedTool : 'unknown',
          approvalIdShort: pending.id.slice(0, 8),
        });
        const snap = await refreshAndBroadcast({ force: true });
        return sendJson(res, 200, { ok: true, id: pending.id, snapshot: snap });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/approvals/reject') {
        if (!verifyAuthenticatedCsrf(req, session)) {
          return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed. Reload the WebUI page.' });
        }
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const { body } = parsed;
        if (typeof body?.id !== 'string' || !APPROVAL_ID.test(body.id)) {
          return sendJson(res, 400, { error: 'Invalid approval ID.' });
        }
        const approvalsDir = path.join(resolvedState, 'approvals');
        try {
          const dirStat = fs.lstatSync(approvalsDir);
          if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) {
            return sendJson(res, 400, { error: 'Approval directory must not be a link.' });
          }
          const approvedPath = path.join(approvalsDir, `${body.id}.approved.json`);
          const apStat = fs.lstatSync(approvedPath, { throwIfNoEntry: false });
          if (apStat) {
            if (apStat.isSymbolicLink() || !apStat.isFile()) {
              return sendJson(res, 400, { error: 'Invalid approval marker file.' });
            }
            try { fs.unlinkSync(approvedPath); } catch (e) { if (e?.code !== 'ENOENT') throw e; }
          }
          const reqPath = path.join(approvalsDir, `${body.id}.request.json`);
          const st = fs.lstatSync(reqPath);
          if (st.isSymbolicLink() || !st.isFile()) {
            return sendJson(res, 400, { error: 'Invalid approval file.' });
          }
          let loggedTool = 'unknown';
          try {
            const fd = fs.openSync(reqPath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
            try {
              const fst = fs.fstatSync(fd);
              if (fst.isFile() && fst.size <= MAX_RECORD_BYTES) {
                const raw = JSON.parse(fs.readFileSync(fd, 'utf8'));
                const candidate = typeof raw?.request?.params?.name === 'string' ? raw.request.params.name : '';
                if (KNOWN_TOOL_NAMES.has(candidate) || isValidExternalToolName(candidate)) loggedTool = candidate;
              }
            } finally {
              fs.closeSync(fd);
            }
          } catch { /* Allow removing corrupted approval request files */ }
          fs.unlinkSync(reqPath);
          approvalFileCache.delete(reqPath);
          appendSanitizedConnectorLog(resolvedState, 'approval_rejected', {
            tool: loggedTool,
            approvalIdShort: body.id.slice(0, 8),
          });
        } catch (err) {
          if (err?.code === 'ENOENT') {
            return sendJson(res, 404, { error: 'Approval request already removed or expired.' });
          }
          return sendJson(res, 400, { error: err?.message || 'Cannot remove approval request.' });
        }
        const snap = await refreshAndBroadcast({ force: true });
        return sendJson(res, 200, { ok: true, id: body.id, snapshot: snap });
      }

      if (req.method === 'GET' && reqUrl.pathname === '/api/mcp-servers') {
        if (!verifyFetchSiteSameOriginOrNone(req, false)) {
          return sendJson(res, 403, { error: 'Cross-site request rejected.' });
        }
        const roots = loadCurrentWorkspaceRoots();
        const mcpServers = publicMcpRegistrySnapshot(resolvedState, {
          workspaceRoots: roots,
          blockedOrigins: currentBlockedOrigins(),
        });
        return sendJson(res, 200, { ok: true, mcpServers });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/mcp-servers/save') {
        if (!verifyAuthenticatedCsrf(req, session)) {
          return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed. Reload the WebUI page.' });
        }
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const { body } = parsed;
        const roots = loadCurrentWorkspaceRoots();
        const blockedOrigins = currentBlockedOrigins();
        let saved;
        try {
          saved = upsertMcpServerSync(resolvedState, pickEditableMcpFields(body), {
            workspaceRoots: roots,
            requirePrivateState,
            blockedOrigins,
            replaceSecrets: body?.replaceSecrets === true,
          });
        } catch (err) {
          return sendJson(res, 400, { error: err?.message || 'Invalid MCP server configuration.' });
        }
        appendSanitizedConnectorLog(resolvedState, 'mcp_server_updated', {
          serverId: saved.id,
          mode: saved.transport,
        });
        let probe = null;
        let deletedDuringProbe = false;
        if (body?.probe === true) {
          const fp = serverConfigFingerprint(saved);
          try {
            probe = await runBoundedProbe(saved, res, blockedOrigins, 30000);
            try {
              saved = saveMcpProbeResultSync(resolvedState, saved.id, probe, {
                workspaceRoots: roots,
                requirePrivateState,
                blockedOrigins,
                expectedFingerprint: fp,
              });
            } catch (err) {
              if (err?.code === 'NOT_FOUND') deletedDuringProbe = true;
              else throw err;
            }
          } catch (err) {
            probe = {
              ok: false,
              latencyMs: 0,
              error: redactSecretsFromText(err?.message || 'Probe could not be started.', saved),
            };
          }
          appendSanitizedConnectorLog(resolvedState, 'mcp_server_probed', {
            serverId: saved.id,
            outcome: probe.ok ? `ok_${probe.tools?.length || 0}` : 'failed',
          });
        }
        const snap = await refreshAndBroadcast({ force: true });
        return sendJson(res, 200, {
          ok: true,
          server: deletedDuringProbe ? null : publicMcpServerSummary(saved),
          probe,
          snapshot: snap,
        });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/mcp-servers/import') {
        if (!verifyAuthenticatedCsrf(req, session)) {
          return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed. Reload the WebUI page.' });
        }
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const { body } = parsed;
        const roots = loadCurrentWorkspaceRoots();
        const blockedOrigins = currentBlockedOrigins();
        let parsedList;
        try {
          parsedList = parseStandardMcpJson(body?.json ?? body?.config);
        } catch (err) {
          return sendJson(res, 400, { error: err?.message || 'Invalid standard MCP JSON payload.' });
        }
        let savedEntries;
        try {
          savedEntries = upsertMcpServersSync(resolvedState, parsedList, {
            workspaceRoots: roots,
            requirePrivateState,
            blockedOrigins,
            replaceSecrets: true,
          });
        } catch (err) {
          return sendJson(res, 400, { error: err?.message || 'Failed to save imported MCP servers.' });
        }
        const importedIds = savedEntries.map(s => s.id);
        appendSanitizedConnectorLog(resolvedState, 'mcp_server_imported', {
          outcome: `count=${importedIds.length}`,
        });
        const probes = {};
        if (body?.probe === true) {
          const enabledTargets = savedEntries.filter(s => s.enabled);
          const toProbe = enabledTargets.slice(0, 8);
          for (const skipped of enabledTargets.slice(8)) {
            probes[skipped.id] = { ok: false, toolCount: 0, error: 'Skipped automatic probe (batch limit 8); probe individually.' };
          }
          const deadline = Date.now() + 45000;
          let cursor = 0;
          const worker = async () => {
            while (cursor < toProbe.length) {
              if (res.closed && !res.writableEnded) break;
              const srv = toProbe[cursor++];
              let left = deadline - Date.now();
              if (left < 1500) {
                probes[srv.id] = { ok: false, toolCount: 0, error: 'Batch probe time budget exceeded; probe individually.' };
                continue;
              }
              const slotDeadline = Math.min(deadline - 1500, Date.now() + 3000);
              while (
                activeProbes.size >= 3 &&
                Date.now() < slotDeadline &&
                !(res.closed && !res.writableEnded) &&
                !shutdownController.signal.aborted
              ) {
                await new Promise(r => setTimeout(r, 250));
              }
              if (res.closed && !res.writableEnded) break;
              left = deadline - Date.now();
              if (left < 1500) {
                probes[srv.id] = { ok: false, toolCount: 0, error: 'Batch probe time budget exceeded; probe individually.' };
                continue;
              }
              const fp = serverConfigFingerprint(srv);
              try {
                const probe = await runBoundedProbe(srv, res, blockedOrigins, Math.min(left, 20000));
                try {
                  saveMcpProbeResultSync(resolvedState, srv.id, probe, {
                    workspaceRoots: roots,
                    requirePrivateState,
                    blockedOrigins,
                    expectedFingerprint: fp,
                  });
                } catch (err) {
                  if (err?.code !== 'NOT_FOUND') throw err;
                }
                probes[srv.id] = { ok: probe.ok, toolCount: probe.tools?.length || 0, error: probe.error || null };
              } catch (err) {
                probes[srv.id] = { ok: false, toolCount: 0, error: err?.message || 'Probe failed.' };
              }
            }
          };
          await Promise.all(Array.from({ length: Math.min(2, toProbe.length) }, worker));
        }
        const snap = await refreshAndBroadcast({ force: true });
        return sendJson(res, 200, { ok: true, importedIds, probes, snapshot: snap });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/mcp-servers/toggle') {
        if (!verifyAuthenticatedCsrf(req, session)) {
          return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed. Reload the WebUI page.' });
        }
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const { body } = parsed;
        const roots = loadCurrentWorkspaceRoots();
        const blockedOrigins = currentBlockedOrigins();
        let updated;
        try {
          updated = toggleMcpServerSync(
            resolvedState,
            { id: body?.id, enabled: body?.enabled, toolName: body?.toolName },
            { workspaceRoots: roots, requirePrivateState, blockedOrigins },
          );
        } catch (err) {
          return sendJson(res, 400, { error: err?.message || 'Cannot update MCP server toggle.' });
        }
        appendSanitizedConnectorLog(resolvedState, 'mcp_server_toggled', {
          serverId: updated.id,
          outcome: body?.toolName ? `${body.toolName}=${body.enabled ? 'on' : 'off'}` : (updated.enabled ? 'enabled' : 'disabled'),
        });
        const snap = await refreshAndBroadcast({ force: true });
        return sendJson(res, 200, { ok: true, server: publicMcpServerSummary(updated), snapshot: snap });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/mcp-servers/probe') {
        if (!verifyAuthenticatedCsrf(req, session)) {
          return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed. Reload the WebUI page.' });
        }
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const { body } = parsed;
        const roots = loadCurrentWorkspaceRoots();
        const blockedOrigins = currentBlockedOrigins();
        const reg = readMcpServersSync(resolvedState, { workspaceRoots: roots, blockedOrigins });
        if (reg.error) return sendJson(res, 400, { error: reg.error });
        const target = reg.servers.find(s => s.id === body?.id);
        if (!target) return sendJson(res, 404, { error: 'MCP server not found.' });
        const fp = serverConfigFingerprint(target);
        let probe;
        try {
          probe = await runBoundedProbe(target, res, blockedOrigins, 30000);
        } catch (err) {
          if (Number.isInteger(err?.status)) throw err;
          probe = { ok: false, latencyMs: 0, error: redactSecretsFromText(err?.message || 'Probe failed.', target) };
        }
        let updated = target;
        let deletedDuringProbe = false;
        try {
          updated = saveMcpProbeResultSync(resolvedState, target.id, probe, {
            workspaceRoots: roots,
            requirePrivateState,
            blockedOrigins,
            expectedFingerprint: fp,
          });
        } catch (err) {
          if (err?.code === 'NOT_FOUND') deletedDuringProbe = true;
          else throw err;
        }
        appendSanitizedConnectorLog(resolvedState, 'mcp_server_probed', {
          serverId: target.id,
          outcome: probe.ok ? `ok_${probe.tools?.length || 0}` : 'failed',
        });
        const snap = await refreshAndBroadcast({ force: true });
        return sendJson(res, 200, {
          ok: true,
          probe,
          server: deletedDuringProbe ? null : publicMcpServerSummary(updated),
          snapshot: snap,
        });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/mcp-servers/delete') {
        if (!verifyAuthenticatedCsrf(req, session)) {
          return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed. Reload the WebUI page.' });
        }
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const { body } = parsed;
        const roots = loadCurrentWorkspaceRoots();
        const blockedOrigins = currentBlockedOrigins();
        let removed;
        try {
          removed = deleteMcpServerSync(resolvedState, body?.id, {
            workspaceRoots: roots,
            requirePrivateState,
            blockedOrigins,
          });
        } catch (err) {
          const status = err?.code === 'NOT_FOUND' ? 404 : 400;
          return sendJson(res, status, { error: err?.message || 'Cannot delete MCP server.' });
        }
        appendSanitizedConnectorLog(resolvedState, 'mcp_server_deleted', { serverId: removed.deleted });
        const snap = await refreshAndBroadcast({ force: true });
        return sendJson(res, 200, { ok: true, ...removed, snapshot: snap });
      }

      if (req.method === 'POST' && reqUrl.pathname === '/api/service') {
        if (!verifyAuthenticatedCsrf(req, session)) {
          return sendJson(res, 403, { error: 'CSRF or cross-origin validation failed. Reload the WebUI page.' });
        }
        const parsed = await readAuthenticatedJson(req, res, session);
        if (!parsed) return;
        const { body } = parsed;
        if (!['start', 'stop', 'restart', 'enable-autostart', 'disable-autostart'].includes(body.action)) {
          return sendJson(res, 400, { error: 'Unsupported service action.' });
        }
        if (serviceActionInFlight) {
          return sendJson(res, 409, { error: 'Another service action is already in progress.' });
        }
        serviceActionInFlight = true;
        try {
          await handleServiceAction(body.action);
        } finally {
          serviceActionInFlight = false;
        }
        appendSanitizedConnectorLog(resolvedState, 'service_action', { outcome: body.action });
        const snap = await refreshAndBroadcast({ force: true });
        return sendJson(res, 200, { ok: true, action: body.action, snapshot: snap });
      }

      return sendJson(res, 404, { error: 'Not found.' });
    } catch (error) {
      const status = Number.isInteger(error?.status) ? error.status : 500;
      const message = status < 500 ? error.message : 'Internal monitor error.';
      if (!res.headersSent) {
        return sendJson(res, status, { error: message });
      }
      res.end();
    }
  });

  await new Promise((resolve, reject) => {
    const onError = err => reject(err);
    server.once('error', onError);
    server.listen(port, host, () => {
      server.removeListener('error', onError);
      const addr = server.address();
      actualPort = typeof addr === 'object' && addr ? addr.port : port;
      resolve();
    });
  });

  const pollTimer = setInterval(() => {
    if (sseClients.size > 0) void refreshAndBroadcast({ force: false }).catch(() => {});
  }, pollIntervalMs);
  pollTimer.unref?.();

  const heartbeatTimer = setInterval(() => {
    if (!sseClients.size) return;
    let auth;
    try { auth = loadCurrentAuthRecord(); } catch { /* Close streams if auth cannot be verified. */ }
    for (const [client, req] of sseClients) sendStreamFrame(client, req, auth, ': keepalive\n\n');
  }, 15000);
  heartbeatTimer.unref?.();

  return {
    server,
    host,
    port: actualPort,
    url: `http://${host}:${actualPort}`,
    async close() {
      clearInterval(pollTimer);
      clearInterval(heartbeatTimer);
      shutdownController.abort();
      for (const ctrl of activeProbes) ctrl.abort();
      activeProbes.clear();
      activeProbeIds.clear();
      for (const client of sseClients.keys()) client.end();
      sseClients.clear();
      sessions.clear();
      registerChallenges.clear();
      loginChallenges.clear();
      await new Promise(resolve => {
        server.closeAllConnections?.();
        server.close(resolve);
      });
    },
  };
}
