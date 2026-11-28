// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import { createInjectionAlertStore } from '../../../local/injection-alerts.mjs';
import { readModerationConfigSync } from '../../../local/moderation-config.mjs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  PLUGIN_SECRETS_ADMIN_SERVICE,
} from '@loomward/shared';
import {
  buildWorkspaceRpm,
  createLoomWardKernel,
  loadWorkspaceRootRefs,
  verifyWorkspaceRpm,
} from '@loomward/kernel';

const MAX_RPM_FILE_BYTES = 2 * 1024 * 1024;

async function loadOrBuildFrozenRpm(resolvedRoot, explicitRpm, requireFrozenRpm) {
  if (explicitRpm) return explicitRpm;
  const frozenFile = path.join(resolvedRoot, 'rpm.json');
  let handle;
  try {
    handle = await fs.open(frozenFile, constants.O_RDONLY | (constants.O_NOFOLLOW || 0) | (constants.O_NONBLOCK || 0));
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > MAX_RPM_FILE_BYTES) {
      throw new Error('Frozen RPM manifest must be a regular single-link file within the size limit.');
    }
    const buf = Buffer.allocUnsafe(MAX_RPM_FILE_BYTES + 1);
    let total = 0;
    while (total < buf.length) {
      const { bytesRead } = await handle.read(buf, total, buf.length - total, total);
      if (bytesRead === 0) break;
      total += bytesRead;
    }
    if (total > MAX_RPM_FILE_BYTES) {
      throw new Error('Frozen RPM manifest exceeds the maximum allowed size.');
    }
    const parsed = JSON.parse(buf.subarray(0, total).toString('utf8'));
    await verifyWorkspaceRpm(resolvedRoot, parsed);
    return parsed;
  } catch (error) {
    if (!requireFrozenRpm && error?.code === 'ENOENT') {
      return (await buildWorkspaceRpm(resolvedRoot)).rpm;
    }
    throw error;
  } finally {
    if (handle) await handle.close().catch(() => {});
  }
}

export async function startLoomWardDaemon({
  rootDir = path.resolve(import.meta.dirname, '../../..'),
  rpm = null,
  requireFrozenRpm = false,
  stateDir = null,
  origin = 'http://127.0.0.1',
  allowExec = undefined,
  allowOutbound = undefined,
  workspaceRoots,
  sandboxConfig = null,
  sandboxRuntime = null,
  approvals = null,
  receipts = null,
  secretLoader = null,
  relay = null,
  record = () => {},
  status = () => {},
  enableMcpHub = true,
  mcpHub = null,
  mcpHubBlockedOrigins = [],
  enableLlmModeration = false,
  llmModeration = null,
  consoleConfig = null,
  timeoutMs,
} = {}) {
  const resolvedRoot = path.resolve(rootDir);
  const frozenRpm = await loadOrBuildFrozenRpm(resolvedRoot, rpm, requireFrozenRpm);

  const injectionAlerts = createInjectionAlertStore({ stateDir, workspaceRoots });
  let kernelControl = null;
  const effectiveConsoleConfig = consoleConfig
    ? {
        stateDir,
        runtimeRoot: resolvedRoot,
        getKernelSummary: () => ({
          roots: kernelControl ? kernelControl.roots() : [],
          units: kernelControl ? kernelControl.units() : [],
          pendingTrustDecisions: [],
        }),
        getPluginSecretsAdmin: () => (kernelControl ? kernelControl.getService(PLUGIN_SECRETS_ADMIN_SERVICE) : null),
        ...consoleConfig,
      }
    : {};

  const roots = await loadWorkspaceRootRefs(resolvedRoot, {
    configs: {
      sandbox: {
        runtime: sandboxRuntime,
        sandboxConfig,
        stateDir,
        ...(allowExec !== undefined ? { allowExec } : {}),
        ...(allowOutbound !== undefined ? { allowOutbound } : {}),
        workspaceRoots,
      },
      host: {
        stateDir,
        workspaceRoots,
        origin: origin || relay?.origin || 'http://127.0.0.1',
        approvals,
        receipts,
        secretLoader,
        relay,
        record,
        status,
      },
      'cloud-relay': {},
      console: effectiveConsoleConfig,
    },
  });

  const { control } = await createLoomWardKernel({
    rpm: frozenRpm,
    roots,
    ...(timeoutMs !== undefined ? { timeoutMs } : {}),
  });
  kernelControl = control;

  let dispatch;
  let localIngress;
  let relayIngress;
  try {
    const consoleSvc = control.getService('console:loopback');
    const consolePort = consoleSvc?.port || effectiveConsoleConfig?.consolePort || effectiveConsoleConfig?.port || 18797;
    const effectiveBlockedOrigins = [
      ...new Set([
        origin,
        relay?.origin,
        consoleSvc?.url,
        `http://127.0.0.1:${consolePort}`,
        `http://localhost:${consolePort}`,
        `http://[::1]:${consolePort}`,
        ...(Array.isArray(mcpHubBlockedOrigins) ? mcpHubBlockedOrigins : []),
      ].filter(Boolean)),
    ];

    if (enableMcpHub && (mcpHub || stateDir)) {
      const contractPath = path.join(resolvedRoot, 'plugins/mcp-hub/src/contract.mjs');
      const entryPath = path.join(resolvedRoot, 'plugins/mcp-hub/src/index.mjs');
      const { contract } = await import(pathToFileURL(contractPath).href);
      await control.mountExtensionUnit({
        contract,
        load: () => import(pathToFileURL(entryPath).href),
        config: {
          hub: mcpHub,
          stateDir,
          workspaceRoots,
          blockedOrigins: effectiveBlockedOrigins,
        },
        trust: {
          signed: true,
          trustLevel: 'official',
          autoApproveTrusted: true,
        },
      });
    }

    if (enableLlmModeration) {
      const modContractPath = path.join(resolvedRoot, 'plugins/llm-moderation/src/contract.mjs');
      const modEntryPath = path.join(resolvedRoot, 'plugins/llm-moderation/src/index.mjs');
      const { contract: modContract } = await import(pathToFileURL(modContractPath).href);
      await control.mountExtensionUnit({
        contract: modContract,
        load: () => import(pathToFileURL(modEntryPath).href),
        config: {
          stateDir,
          workspaceRoots,
          blockedOrigins: effectiveBlockedOrigins,
          ...(llmModeration && typeof llmModeration === 'object' ? llmModeration : {}),
          recordInjection: (event, limits) => {
            try { injectionAlerts.record(event, limits); }
            catch { void record('injection_alert_store_failed', { outcome: 'write_failed' }); }
          },
          readStoredConfig: () => readModerationConfigSync(stateDir, {
            workspaceRoots, blockedOrigins: effectiveBlockedOrigins, fallback: null,
          }),
        },
        trust: {
          signed: true,
          trustLevel: 'official',
          autoApproveTrusted: true,
        },
      });
    }

    dispatch = control.getService('host:dispatch');
    const platform = control.getService('host:platform');
    localIngress = platform?.ingresses?.local ?? null;
    relayIngress = platform?.ingresses?.relay ?? null;

    await dispatch.ready();
    if (localIngress) await localIngress.start();
    if (relayIngress && relay?.autoStart !== false) await relayIngress.start();
  } catch (error) {
    injectionAlerts.close();
    await control.stop().catch(() => {});
    throw error;
  }

  return Object.freeze({
    control,
    dispatch,
    localIngress,
    relayIngress,
    stop: async () => {
      await Promise.allSettled([
        localIngress ? localIngress.stop() : Promise.resolve(),
        relayIngress ? relayIngress.stop() : Promise.resolve(),
      ]);
      try { await control.stop(); } finally { injectionAlerts.close(); }
    },
  });
}
