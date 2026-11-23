// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  buildWorkspaceRpm,
  createLoomWardKernel,
  loadWorkspaceRootRefs,
} from '@loomward/kernel';

export async function startLoomWardDaemon({
  rootDir = path.resolve(import.meta.dirname, '../../..'),
  rpm = null,
  stateDir = null,
  origin = 'http://127.0.0.1',
  allowExec = true,
  allowOutbound = false,
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
  consoleConfig = null,
  timeoutMs,
} = {}) {
  const resolvedRoot = path.resolve(rootDir);
  const frozenRpm = rpm ?? (await buildWorkspaceRpm(resolvedRoot)).rpm;

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
        ...consoleConfig,
      }
    : {};

  const roots = await loadWorkspaceRootRefs(resolvedRoot, {
    configs: {
      sandbox: {
        runtime: sandboxRuntime,
        sandboxConfig,
        stateDir,
        allowExec,
        allowOutbound,
        workspaceRoots,
      },
      host: {
        stateDir,
        origin,
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
        blockedOrigins: mcpHubBlockedOrigins,
      },
      trust: {
        signed: true,
        trustLevel: 'official',
        autoApproveTrusted: true,
      },
    });
  }

  const dispatch = control.getService('host:dispatch');
  const platform = control.getService('host:platform');
  const localIngress = platform?.ingresses?.local ?? null;
  const relayIngress = platform?.ingresses?.relay ?? null;

  await dispatch.ready();
  if (localIngress) await localIngress.start();
  if (relayIngress && relay?.autoStart !== false) await relayIngress.start();

  return Object.freeze({
    control,
    dispatch,
    localIngress,
    relayIngress,
    stop: async () => {
      await control.stop();
    },
  });
}
