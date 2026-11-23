// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import WebSocket from 'ws';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { proxyCandidates } from '../../../local/connector.mjs';

const MAX_REPLY_BYTES = 2 * 1024 * 1024;
const MAX_WS_PAYLOAD_BYTES = 1_200_000;
const HEARTBEAT_INTERVAL_MS = 20_000;
const HEARTBEAT_MAX_AGE_MS = 65_000;

export function createCloudflareRelayIngress({
  origin,
  bridgeToken,
  pipeline,
  proxyProvider = proxyCandidates,
  socketFactory = (target, options) => new WebSocket(target, options),
  record = () => {},
  status = () => {},
} = {}) {
  const url = new URL(origin);
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  if (!['https:', 'http:'].includes(url.protocol) || (url.protocol === 'http:' && !loopback)) {
    throw new Error('The bridge requires HTTPS, except on loopback for tests');
  }
  if (url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('Expected an origin without a path or credentials');
  }
  const wsUrl = new URL('/bridge', url);
  wsUrl.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';

  const safeRecord = (event, fields) => {
    try { record(event, fields); } catch {}
  };
  const safeStatus = (live, opts) => {
    try { return status(live, opts); } catch { return undefined; }
  };

  let running = false;
  let retries = 0;
  let timer = null;
  let activeSocket = null;
  let starting = null;
  let startEpoch = 0;
  const socketRequests = new Set();

  function schedule() {
    if (!running) return;
    clearTimeout(timer);
    retries += 1;
    const delay = Math.min(30000, 1000 * 2 ** Math.min(retries - 1, 5)) + Math.floor(Math.random() * 500);
    timer = setTimeout(connect, delay);
    timer.unref?.();
  }

  function connect() {
    if (!running) return;
    if ([WebSocket.OPEN, WebSocket.CONNECTING].includes(activeSocket?.readyState)) return;
    let candidate = null;
    try {
      const routes = proxyProvider(url.origin);
      candidate = routes[retries % routes.length] || null;
      let agent;
      if (candidate) {
        try { agent = new HttpsProxyAgent(candidate); } catch { agent = undefined; candidate = null; }
      }
      const socket = socketFactory(wsUrl, {
        headers: { authorization: `Bearer ${bridgeToken}` },
        agent,
        handshakeTimeout: 15000,
        maxPayload: MAX_WS_PAYLOAD_BYTES,
        perMessageDeflate: false,
        followRedirects: false,
      });
      activeSocket = socket;
      let lastPong = 0;
      let beat = null;

      socket.on('open', () => {
        if (!running || activeSocket !== socket) { socket.terminate(); return; }
        safeRecord('connected', { route: candidate ? 'proxy' : 'direct', ingress: 'cloudflare-wss' });
        safeStatus(false, { force: true });
        try { socket.send('{"type":"ping"}'); } catch {}
        beat = setInterval(() => {
          if (Date.now() - lastPong > HEARTBEAT_MAX_AGE_MS) return socket.terminate();
          if (socket.readyState === WebSocket.OPEN) {
            try { socket.send(JSON.stringify({ type: 'ping' })); } catch {}
          }
          safeStatus(Date.now() - lastPong <= HEARTBEAT_MAX_AGE_MS);
        }, HEARTBEAT_INTERVAL_MS);
        beat.unref?.();
      });

      socket.on('unexpected-response', (_request, response) => {
        safeRecord('socket_unexpected_response', { status: Number(response?.statusCode) || 0 });
        try { response?.resume(); } catch {}
      });

      socket.on('message', async (data, isBinary) => {
        if (!running || activeSocket !== socket) return;
        let message;
        try {
          if (isBinary) throw new Error();
          message = JSON.parse(data.toString());
          if (!message || Array.isArray(message) || typeof message !== 'object') throw new Error();
        } catch {
          try { socket.close(1003, 'Invalid bridge frame'); } catch {}
          return;
        }
        if (message.type === 'pong') {
          retries = 0;
          lastPong = Date.now();
          safeStatus(true);
          return;
        }
        if (message.type === 'cancel' && typeof message.id === 'string') {
          for (const active of socketRequests) {
            if (active.socket === socket && active.id === message.id) {
              active.controller.abort();
            }
          }
          return;
        }
        if (message.type !== 'request') return;

        const reqController = new AbortController();
        const entry = {
          id: typeof message.id === 'string' ? message.id : null,
          socket,
          controller: reqController,
        };
        socketRequests.add(entry);
        try {
          const body = await pipeline.handleRequest(message, { signal: reqController.signal });
          if (socket.readyState !== WebSocket.OPEN) return;
          // Note: when body === undefined (e.g., notifications/initialized), JSON.stringify omits `body`
          // and sends `{"type":"response","id":"..."}` which completes Cloudflare Relay's HTTP 202.
          let encoded;
          try {
            encoded = JSON.stringify({ type: 'response', id: message.id, body });
          } catch {
            encoded = JSON.stringify({
              type: 'response',
              id: message.id,
              body: {
                jsonrpc: '2.0',
                id: message.body?.id ?? null,
                error: { code: -32603, message: 'Failed to serialize tool response.' },
              },
            });
          }
          if (Buffer.byteLength(encoded) > MAX_REPLY_BYTES) {
            encoded = JSON.stringify({
              type: 'response',
              id: message.id,
              body: {
                jsonrpc: '2.0',
                id: message.body?.id ?? null,
                error: { code: -32603, message: 'Tool result exceeds the bridge limit; request a smaller range' },
              },
            });
          }
          socket.send(encoded);
        } catch {
          safeRecord('relay_dispatch_error', { ingress: 'cloudflare-wss' });
        } finally {
          socketRequests.delete(entry);
        }
      });

      socket.on('error', error => {
        safeRecord('socket_error', { code: /^[A-Z0-9_]+$/.test(error.code || '') ? error.code : 'HANDSHAKE_OR_NETWORK' });
      });

      socket.on('close', code => {
        clearInterval(beat);
        for (const active of [...socketRequests]) {
          if (active.socket === socket) {
            active.controller.abort();
            socketRequests.delete(active);
          }
        }
        if (activeSocket !== socket) return;
        safeStatus(false, { force: true });
        safeRecord('disconnected', { code });
        schedule();
      });
    } catch (error) {
      safeRecord('connection_setup_failed', { code: /^[A-Z0-9_]{1,48}$/.test(error?.code || '') ? error.code : 'SETUP_ERROR' });
      schedule();
    }
  }

  return Object.freeze({
    id: 'cloudflare-wss',
    kind: 'remote-relay',
    origin: url.origin,
    async start() {
      if (running) return starting;
      running = true;
      const epoch = ++startEpoch;
      starting = (async () => {
        try {
          await pipeline.ready();
          if (running && epoch === startEpoch) connect();
        } catch (error) {
          if (epoch === startEpoch) running = false;
          throw error;
        }
      })();
      return starting;
    },
    async stop() {
      running = false;
      startEpoch += 1;
      clearTimeout(timer);
      for (const active of [...socketRequests]) {
        active.controller.abort();
        socketRequests.delete(active);
      }
      const socket = activeSocket;
      activeSocket = null;
      if (socket && socket.readyState !== WebSocket.CLOSED) {
        await new Promise(resolve => {
          const closeTimer = setTimeout(() => { socket.terminate(); resolve(); }, 1500);
          closeTimer.unref?.();
          socket.once('close', () => { clearTimeout(closeTimer); resolve(); });
          if (socket.readyState === WebSocket.OPEN) {
            try { socket.close(1000, 'Local connector stopped'); } catch { socket.terminate(); }
          } else {
            socket.terminate();
          }
        });
      }
      await Promise.resolve(safeStatus(false, { force: true })).catch(() => {});
    },
    health() {
      return {
        running,
        connected: activeSocket?.readyState === WebSocket.OPEN,
        origin: url.origin,
      };
    },
  });
}
