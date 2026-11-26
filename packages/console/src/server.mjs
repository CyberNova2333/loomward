// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Orchestrates the Single-Origin loopback console server (default 127.0.0.1:18797):
// unifies authentication, two-step approvals, capability switches, moderation & secrets config,
// SSE live telemetry, tool catalog, and strictly read-only declarative console:panel@1 views.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  assertConfigOutsideWorkspace,
  loadWorkspaceRootsFromStateConfig,
} from '../../../local/capabilities.mjs';
import { mcpServersFilePath } from '../../../local/mcp-registry.mjs';
import { moderationConfigFilePath } from '../../../local/moderation-config.mjs';
import { createOllamaController } from '../../../local/ollama.mjs';
import { detectHostPasskeySupport, readWebUiAuthSync } from '../../../local/webui-auth.mjs';
import { collectStatusSnapshot, isLoopbackHost } from '../../../local/webui.mjs';
import { readTrustedJsonFile, validateStateDir } from './http-security.mjs';
import { createConsoleSessionBroker } from './session-broker.mjs';
import { createControlChannel } from './control-channel.mjs';
import { createConsolePanelCollector } from './panel-registry.mjs';
import { createUnifiedConsoleServer } from './unified-server.mjs';

export const DEFAULT_CONSOLE_PORT = 18797;

function sha256OfSnapshot(snap, panels) {
  const normalizedPanels = Array.isArray(panels)
    ? panels.map(p => (p && typeof p === 'object' ? { ...p, updatedAt: undefined } : p))
    : undefined;
  const comparable = {
    ...snap,
    observedAt: undefined,
    daemon: snap?.daemon ? { ...snap.daemon, gatewayLatencyMs: undefined } : snap?.daemon,
    panels: normalizedPanels,
  };
  return crypto.createHash('sha256').update(JSON.stringify(comparable)).digest('hex');
}

export async function startUnifiedConsole({
  stateDir,
  runtimeRoot = path.resolve(import.meta.dirname, '../../..'),
  host = '127.0.0.1',
  consolePort,
  port,
  requirePrivateState = true,
  pollIntervalMs = 5000,
  enableControlSocket = true,
  controlSocketPath = null,
  controlChannel: externalChannel = null,
  panelSlot = null,
  staticPanels = [],
  passkeyDetector = detectHostPasskeySupport,
  gatewayProbe,
  dockerProbe,
  systemdProbe,
  mcpProber,
  serviceController = async () => {
    const err = new Error('No service controller configured.');
    err.status = 400;
    throw err;
  },
  getKernelSummary = () => ({ roots: [], units: [], pendingTrustDecisions: [] }),
  trustDecider = null,
  pluginSecretsAdmin = null,
  getPluginSecretsAdmin = null,
  ollamaController = null,
  ollamaHooks = null,
  previewAutoSession = false,
} = {}) {
  if (!isLoopbackHost(host)) {
    throw new Error('LoomWard Console must bind strictly to a loopback interface (127.0.0.1, localhost, or ::1).');
  }
  const previewModeEnabled = previewAutoSession === true;
  const listenPort = consolePort !== undefined ? consolePort : (port !== undefined ? port : DEFAULT_CONSOLE_PORT);

  const resolvedState = validateStateDir(stateDir, requirePrivateState);
  const resolvedRuntime = path.resolve(runtimeRoot);
  const configPath = path.join(resolvedState, 'config.json');
  readTrustedJsonFile(configPath, requirePrivateState);
  const startupRoots = loadWorkspaceRootsFromStateConfig(resolvedState);
  assertConfigOutsideWorkspace(configPath, startupRoots);
  for (const extraFile of [
    path.join(resolvedState, 'capabilities.json'),
    path.join(resolvedState, 'webui-auth.json'),
    mcpServersFilePath(resolvedState),
    moderationConfigFilePath(resolvedState),
  ]) {
    if (fs.lstatSync(extraFile, { throwIfNoEntry: false })) {
      assertConfigOutsideWorkspace(extraFile, startupRoots);
    }
  }

  const ownsChannel = !externalChannel;
  const controlChannel = externalChannel ?? createControlChannel({
    socketPath: enableControlSocket ? (controlSocketPath || path.join(resolvedState, 'control.sock')) : null,
  });
  const panelCollector = createConsolePanelCollector({ panelSlot, staticPanels });

  let consoleServer = null;
  let lastSnapshot = null;
  let lastPanels = null;
  let lastDigest = '';
  let refreshing = null;
  let queuedRefresh = null;

  const broker = createConsoleSessionBroker({
    allowPreviewSession: previewModeEnabled,
    onSessionsRevoked({ sids, all }) {
      if (all) {
        consoleServer?.dropStreamsForSids([], true);
      } else if (sids?.length) {
        consoleServer?.dropStreamsForSids(sids, false);
      }
    },
  });

  function loadCurrentWorkspaceRoots() {
    readTrustedJsonFile(configPath, requirePrivateState);
    const roots = loadWorkspaceRootsFromStateConfig(resolvedState);
    assertConfigOutsideWorkspace(configPath, roots);
    return roots;
  }

  function loadCurrentAuthRecord() {
    const roots = loadCurrentWorkspaceRoots();
    return readWebUiAuthSync(resolvedState, { workspaceRoots: roots, passkeyDetector });
  }

  function getBlockedOrigins() {
    let origin = null;
    try {
      const cfg = readTrustedJsonFile(configPath, requirePrivateState);
      if (typeof cfg?.origin === 'string') origin = cfg.origin;
    } catch {}
    const out = origin ? [origin] : [];
    const activePort = consoleServer?.port;
    if (Number.isInteger(activePort) && activePort > 0) {
      out.push(`http://127.0.0.1:${activePort}`, `http://localhost:${activePort}`, `http://[::1]:${activePort}`);
    }
    return out;
  }

  async function refreshSnapshot({ force = false, broadcast = true } = {}) {
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

    const collectPanels = Boolean(broadcast && consoleServer?.hasSseClients());
    refreshing = Promise.all([
      collectStatusSnapshot({
        stateDir: resolvedState,
        runtimeRoot: resolvedRuntime,
        requirePrivateState,
        passkeyDetector,
        ...(gatewayProbe ? { gatewayProbe } : {}),
        ...(dockerProbe ? { dockerProbe } : {}),
        ...(systemdProbe ? { systemdProbe } : {}),
        blockedOrigins: getBlockedOrigins(),
      }),
      collectPanels
        ? panelCollector.collectAll({ originRole: 'unified' })
        : Promise.resolve(lastPanels),
    ])
      .then(([snap, panels]) => {
        lastSnapshot = snap;
        if (Array.isArray(panels)) lastPanels = panels;
        const effectivePanels = panels ?? lastPanels ?? [];
        const digestHash = sha256OfSnapshot(snap, effectivePanels);
        const anySse = Boolean(consoleServer?.hasSseClients());
        if (broadcast && (force || digestHash !== lastDigest)) {
          lastDigest = digestHash;
          const auth = loadCurrentAuthRecord();
          consoleServer?.broadcastSnapshot(snap, effectivePanels, auth);
        } else if (!anySse && (force || digestHash !== lastDigest)) {
          lastDigest = digestHash;
        }
        return snap;
      })
      .finally(() => {
        refreshing = null;
        if (queuedRefresh) {
          const next = queuedRefresh;
          queuedRefresh = null;
          refreshSnapshot({ force: true, broadcast: next.broadcast }).then(next.resolve, next.reject);
        }
      });

    return refreshing;
  }

  let channelRefreshTimer = null;
  const unsubChannel = controlChannel.subscribe(event => {
    try {
      const auth = loadCurrentAuthRecord();
      consoleServer?.broadcastChannelEvent(event, auth);
    } catch {}
    if (consoleServer?.hasSseClients()) {
      if (!channelRefreshTimer) {
        channelRefreshTimer = setTimeout(() => {
          channelRefreshTimer = null;
          if (consoleServer?.hasSseClients()) {
            void refreshSnapshot({ force: true }).catch(() => {});
          }
        }, 40);
        channelRefreshTimer.unref?.();
      }
    }
  });

  if (enableControlSocket && !controlChannel.getSocketPath()) {
    await controlChannel.startSocketServer(controlSocketPath || path.join(resolvedState, 'control.sock')).catch(() => null);
  }

  const ollama = ollamaController ?? createOllamaController({
    getBlockedOrigins,
    controlChannel,
    ...(ollamaHooks && typeof ollamaHooks === 'object' ? ollamaHooks : {}),
  });

  try {
    consoleServer = await createUnifiedConsoleServer({
      host,
      port: listenPort,
      stateDir: resolvedState,
      requirePrivateState,
      broker,
      controlChannel,
      panelCollector,
      loadCurrentWorkspaceRoots,
      loadCurrentAuthRecord,
      refreshSnapshot,
      getLastSnapshot: () => lastSnapshot,
      getBlockedOrigins,
      passkeyDetector,
      mcpProber,
      serviceController,
      getKernelSummary,
      getRecentChannelEvents: () => controlChannel.recent(),
      trustDecider,
      getPluginSecretsAdmin: () => (
        typeof getPluginSecretsAdmin === 'function' ? getPluginSecretsAdmin() : pluginSecretsAdmin
      ),
      ollamaController: ollama,
      previewAutoSession: previewModeEnabled,
    });
  } catch (err) {
    ollama.close?.();
    unsubChannel();
    if (ownsChannel) await controlChannel.close();
    throw err;
  }

  const fallbackTimer = pollIntervalMs > 0
    ? setInterval(() => {
        if (consoleServer.hasSseClients()) {
          void refreshSnapshot({ force: false }).catch(() => {});
        }
      }, pollIntervalMs)
    : null;
  fallbackTimer?.unref?.();

  return Object.freeze({
    host,
    port: consoleServer.port,
    url: consoleServer.url,
    console: Object.freeze({ port: consoleServer.port, url: consoleServer.url }),
    controlChannel,
    controlSocketPath: controlChannel.getSocketPath(),
    panelCollector,
    refreshSnapshot,
    async close() {
      if (fallbackTimer) clearInterval(fallbackTimer);
      if (channelRefreshTimer) clearTimeout(channelRefreshTimer);
      unsubChannel();
      ollama.close?.();
      broker.clearAll();
      await consoleServer.close();
      if (ownsChannel) await controlChannel.close();
    },
  });
}
