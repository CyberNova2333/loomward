// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Orchestrates physical Dual-Origin loopback servers:
//   - Trust Origin   (default 127.0.0.1:18798): Ring 2 security boundary, zero extension code/panels
//   - Console Origin (default 127.0.0.1:18797): Ring 3 read-only telemetry, SSE, and declarative console:panel@1 host
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  assertConfigOutsideWorkspace,
  loadWorkspaceRootsFromStateConfig,
} from '../../../local/capabilities.mjs';
import { mcpServersFilePath } from '../../../local/mcp-registry.mjs';
import { detectHostPasskeySupport, readWebUiAuthSync } from '../../../local/webui-auth.mjs';
import { collectStatusSnapshot, isLoopbackHost } from '../../../local/webui.mjs';
import { readTrustedJsonFile, validateStateDir } from './http-security.mjs';
import { createDualOriginSessionBroker } from './session-broker.mjs';
import { createControlChannel } from './control-channel.mjs';
import { createConsolePanelCollector } from './panel-registry.mjs';
import { createTrustOriginServer } from './trust-server.mjs';
import { createConsoleOriginServer } from './console-server.mjs';

export const DEFAULT_CONSOLE_PORT = 18797;
export const DEFAULT_TRUST_PORT = 18798;

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

export async function startDualOriginConsole({
  stateDir,
  runtimeRoot = path.resolve(import.meta.dirname, '../../..'),
  host = '127.0.0.1',
  consolePort = DEFAULT_CONSOLE_PORT,
  trustPort = DEFAULT_TRUST_PORT,
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
} = {}) {
  if (!isLoopbackHost(host)) {
    throw new Error('LoomWard Dual-Origin Console must bind strictly to a loopback interface (127.0.0.1, localhost, or ::1).');
  }
  if (consolePort !== 0 && trustPort !== 0 && consolePort === trustPort) {
    throw new Error('Trust Origin and Console Origin must bind to distinct ports for physical origin isolation.');
  }

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

  let trustServer = null;
  let consoleServer = null;
  let lastSnapshot = null;
  let lastDigest = '';
  let refreshing = null;
  let queuedRefresh = null;

  const broker = createDualOriginSessionBroker({
    onSessionsRevoked({ trustSid, consoleSids, all }) {
      if (all) {
        trustServer?.dropStreamsForSid(null);
        consoleServer?.dropStreamsForSids([], true);
      } else {
        if (trustSid) trustServer?.dropStreamsForSid(trustSid);
        if (consoleSids?.length) consoleServer?.dropStreamsForSids(consoleSids, false);
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
    const ports = [trustServer?.port, consoleServer?.port].filter(p => Number.isInteger(p) && p > 0);
    const out = origin ? [origin] : [];
    for (const p of ports) {
      out.push(`http://127.0.0.1:${p}`, `http://localhost:${p}`, `http://[::1]:${p}`);
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

    const needConsolePanels = Boolean(broadcast && consoleServer?.hasSseClients());
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
      needConsolePanels
        ? panelCollector.collectAll({ originRole: 'console' })
        : Promise.resolve(null),
    ])
      .then(([snap, panels]) => {
        lastSnapshot = snap;
        const digestHash = sha256OfSnapshot(snap, panels);
        const anySse = Boolean(trustServer?.hasSseClients() || consoleServer?.hasSseClients());
        if (broadcast && (force || digestHash !== lastDigest)) {
          lastDigest = digestHash;
          const auth = loadCurrentAuthRecord();
          trustServer?.broadcastSnapshot(snap, auth);
          if (panels && consoleServer?.hasSseClients()) {
            consoleServer.broadcastSnapshot(snap, panels, auth);
          }
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
    if (trustServer?.hasSseClients() || consoleServer?.hasSseClients()) {
      if (!channelRefreshTimer) {
        channelRefreshTimer = setTimeout(() => {
          channelRefreshTimer = null;
          if (trustServer?.hasSseClients() || consoleServer?.hasSseClients()) {
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

  try {
    trustServer = await createTrustOriginServer({
      host,
      port: trustPort,
      stateDir: resolvedState,
      requirePrivateState,
      broker,
      controlChannel,
      loadCurrentWorkspaceRoots,
      loadCurrentAuthRecord,
      refreshSnapshot,
      getLastSnapshot: () => lastSnapshot,
      getConsoleOrigin: () => consoleServer?.url || '',
      getBlockedOrigins,
      passkeyDetector,
      mcpProber,
      serviceController,
      getKernelSummary,
      trustDecider,
    });
  } catch (err) {
    unsubChannel();
    if (ownsChannel) await controlChannel.close();
    throw err;
  }

  try {
    consoleServer = await createConsoleOriginServer({
      host,
      port: consolePort,
      broker,
      panelCollector,
      loadCurrentAuthRecord,
      refreshSnapshot,
      getLastSnapshot: () => lastSnapshot,
      getTrustOrigin: () => trustServer?.url || '',
      getKernelSummary,
      getRecentChannelEvents: () => controlChannel.recent(),
    });
  } catch (err) {
    unsubChannel();
    await trustServer.close();
    if (ownsChannel) await controlChannel.close();
    throw err;
  }

  // Fallback low-frequency refresh only when clients are connected and external state files changed out-of-band.
  const fallbackTimer = pollIntervalMs > 0
    ? setInterval(() => {
        if (trustServer.hasSseClients() || consoleServer.hasSseClients()) {
          void refreshSnapshot({ force: false }).catch(() => {});
        }
      }, pollIntervalMs)
    : null;
  fallbackTimer?.unref?.();

  return Object.freeze({
    host,
    trust: Object.freeze({ port: trustServer.port, url: trustServer.url }),
    console: Object.freeze({ port: consoleServer.port, url: consoleServer.url }),
    controlChannel,
    controlSocketPath: controlChannel.getSocketPath(),
    panelCollector,
    refreshSnapshot,
    async close() {
      if (fallbackTimer) clearInterval(fallbackTimer);
      if (channelRefreshTimer) clearTimeout(channelRefreshTimer);
      unsubChannel();
      broker.clearAll();
      await Promise.all([trustServer.close(), consoleServer.close()]);
      if (ownsChannel) await controlChannel.close();
    },
  });
}
