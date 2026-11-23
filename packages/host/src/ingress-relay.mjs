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

  let running = false;
  let retries = 0;
  let timer = null;
  let activeSocket = null;
  let starting = null;
  const socketRequests = new Map();

  function schedule() {
    if (!running) return;
    clearTimeout(timer);
    retries += 1;
    const delay = Math.min(30000, 1000 * 2 ** Math.min(retries - 1, 5)) + Math.floor(Math.random() * 500);
    timer = setTimeout(connect, delay);
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
        record('connected', { route: candidate ? 'proxy' : 'direct', ingress: 'cloudflare-wss' });
        status(false, { force: true });
        socket.send('{"type":"ping"}');
        beat = setInterval(() => {
          if (Date.now() - lastPong > HEARTBEAT_MAX_AGE_MS) return socket.terminate();
          if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: 'ping' }));
          status(Date.now() - lastPong <= HEARTBEAT_MAX_AGE_MS);
        }, HEARTBEAT_INTERVAL_MS);
      });

      socket.on('unexpected-response', (_request, response) => {
        record('socket_unexpected_response', { status: Number(response?.statusCode) || 0 });
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
          socket.close(1003, 'Invalid bridge frame');
          return;
        }
        if (message.type === 'pong') {
          retries = 0;
          lastPong = Date.now();
          status(true);
          return;
        }
        if (message.type === 'cancel' && typeof message.id === 'string') {
          pipeline.abort(message.id);
          return;
        }
        if (message.type !== 'request') return;

        const reqController = new AbortController();
        const reqKey = typeof message.id === 'string' ? message.id : Symbol('req');
        socketRequests.set(reqKey, { socket, controller: reqController });
        try {
          const body = await pipeline.handleRequest(message, { signal: reqController.signal });
          if (socket.readyState !== WebSocket.OPEN || body === undefined) return;
          let encoded = JSON.stringify({ type: 'response', id: message.id, body });
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
        } finally {
          socketRequests.delete(reqKey);
        }
      });

      socket.on('error', error => {
        record('socket_error', { code: /^[A-Z0-9_]+$/.test(error.code || '') ? error.code : 'HANDSHAKE_OR_NETWORK' });
      });

      socket.on('close', code => {
        clearInterval(beat);
        for (const active of socketRequests.values()) {
          if (active.socket === socket) active.controller.abort();
        }
        if (activeSocket !== socket) return;
        status(false, { force: true });
        record('disconnected', { code });
        schedule();
      });
    } catch (error) {
      record('connection_setup_failed', { code: /^[A-Z0-9_]{1,48}$/.test(error?.code || '') ? error.code : 'SETUP_ERROR' });
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
      starting = (async () => {
        try {
          await pipeline.ready();
          if (running) connect();
        } catch (error) {
          running = false;
          throw error;
        }
      })();
      return starting;
    },
    async stop() {
      running = false;
      clearTimeout(timer);
      for (const active of socketRequests.values()) active.controller.abort();
      pipeline.abortAll();
      const socket = activeSocket;
      if (socket && socket.readyState !== WebSocket.CLOSED) {
        await new Promise(resolve => {
          const closeTimer = setTimeout(() => { socket.terminate(); resolve(); }, 1500);
          socket.once('close', () => { clearTimeout(closeTimer); resolve(); });
          if (socket.readyState === WebSocket.OPEN) socket.close(1000, 'Local connector stopped');
          else socket.terminate();
        });
      }
      status(false, { force: true });
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
