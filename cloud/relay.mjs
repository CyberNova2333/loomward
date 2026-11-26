// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import { DurableObject } from 'cloudflare:workers';
import {
  MAX_REPLY_BYTES,
  MAX_RPC_BYTES,
  MAX_STREAM_CHUNKS,
  MAX_STREAM_FRAME_BYTES,
  MAX_STREAM_TOTAL_BYTES,
  json,
  readLimited,
  validateRpc,
  sha256,
} from './security.mjs';
import { connectionLiveness } from './liveness.mjs';

const textEncoder = new TextEncoder();

function sseEventBytes(payload) {
  return textEncoder.encode(`event: message\ndata: ${JSON.stringify(payload)}\n\n`);
}

function isValidFinalRpc(response, expectedId) {
  return Boolean(
    response
    && typeof response === 'object'
    && !Array.isArray(response)
    && response.jsonrpc === '2.0'
    && response.id === expectedId
    && (('result' in response) !== ('error' in response)),
  );
}

function isValidStreamChunkRpc(body) {
  return Boolean(
    body
    && typeof body === 'object'
    && !Array.isArray(body)
    && body.jsonrpc === '2.0'
    && typeof body.method === 'string'
    && body.method.length > 0
    && body.method.length <= 128
    && !('id' in body),
  );
}

/** One object owns one machine's socket and the associated in-flight calls. */
export class BridgeRelay extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
    this.pending = new Map();
    this.nextCleanup = 0;
    ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS rate_limits (key TEXT PRIMARY KEY, count INTEGER NOT NULL, until INTEGER NOT NULL)');
    ctx.storage.sql.exec('CREATE INDEX IF NOT EXISTS rate_limits_until ON rate_limits(until)');
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('{"type":"ping"}', '{"type":"pong"}'));
  }

  async currentCredential() {
    if (typeof this.env.BRIDGE_TOKEN !== 'string' || this.env.BRIDGE_TOKEN.length < 32) throw new Error('Bridge credentials are unavailable.');
    this.credentialVersion = [...await sha256(this.env.BRIDGE_TOKEN)].map(byte => byte.toString(16).padStart(2, '0')).join('');
  }

  liveConnections() {
    const live = [];
    for (const socket of this.ctx.getWebSockets('machine')) {
      const attachment = socket.deserializeAttachment();
      const acceptedAt = attachment?.acceptedAt;
      const autoBeat = this.ctx.getWebSocketAutoResponseTimestamp(socket)?.getTime();
      const manualBeat = attachment?.lastPingAt;
      const heartbeat = Number.isFinite(autoBeat) || Number.isFinite(manualBeat)
        ? Math.max(Number.isFinite(autoBeat) ? autoBeat : -Infinity, Number.isFinite(manualBeat) ? manualBeat : -Infinity)
        : undefined;
      const state = connectionLiveness(acceptedAt, heartbeat);
      const validCredential = attachment?.credentialVersion === this.credentialVersion;
      if (socket.readyState === WebSocket.OPEN && state.reserved && validCredential) live.push({ socket, ...state });
      else {
        const reason = validCredential ? 'Connector heartbeat expired' : 'Connector credentials changed.';
        try { socket.close(validCredential ? 1001 : 1008, reason); } catch {}
        this.disconnected(socket);
      }
    }
    return live;
  }

  connector() { return this.liveConnections().find(item => item.online)?.socket; }

  async alarm() {
    await this.currentCredential();
    const live = this.liveConnections();
    if (live.length) await this.ctx.storage.setAlarm(Math.max(Date.now() + 1000, Math.min(...live.map(item => item.expiresAt))));
    else await this.ctx.storage.deleteAlarm();
  }

  async fetch(request) {
    await this.currentCredential();
    const path = new URL(request.url).pathname;
    if (path === '/status') { const online = !!this.connector(); return json({ ok: online, connectorOnline: online }, online ? 200 : 503); }
    if (path === '/limit' && request.method === 'POST') return this.limit(request);
    if (path === '/socket' && request.headers.get('upgrade')?.toLowerCase() === 'websocket') {
      if (this.liveConnections().length) return json({ error: 'A connector is already online or completing its heartbeat.' }, 409);
      const pair = new WebSocketPair();
      this.ctx.acceptWebSocket(pair[1], ['machine']);
      pair[1].serializeAttachment({ acceptedAt: Date.now(), credentialVersion: this.credentialVersion });
      await this.ctx.storage.setAlarm(Date.now() + 10000);
      return new Response(null, { status: 101, webSocket: pair[0] });
    }
    if (path !== '/rpc' || request.method !== 'POST') return json({ error: 'Not found.' }, 404);
    const socket = this.connector();
    if (!socket) return json({ error: 'Computer is offline. Start the local connector; the request was not replayed.' }, 503, { 'retry-after': '10' });
    let body, authorization, wantsStream = false;
    try {
      const envelope = JSON.parse(await readLimited(request, MAX_RPC_BYTES + 8192));
      body = validateRpc(envelope.body);
      wantsStream = envelope.wantsStream === true && body.method === 'tools/call' && 'id' in body;
      authorization = envelope.authorization;
      if (authorization?.userId !== 'owner' || typeof authorization.clientId !== 'string' || !authorization.clientId || authorization.clientId.length > 2048 || !Array.isArray(authorization.scope) || authorization.scope.length > 4 || authorization.scope.some(scope => !['computer:read', 'computer:write', 'computer:execute', 'offline_access'].includes(scope))) throw new Error('Invalid authorization envelope.');
    }
    catch (error) { return json({ error: error.message || 'Invalid request.' }, error.status || 400); }
    if (body.method === 'notifications/cancelled') {
      const requestId = body.params?.requestId;
      if ('id' in body || !(typeof requestId === 'string' || (typeof requestId === 'number' && Number.isFinite(requestId)))) return json({ error: 'Invalid cancellation notification.' }, 400);
      // Clients may cancel only their own original JSON-RPC request, not another grant's work.
      for (const [id, pending] of this.pending) if (pending.clientId === authorization.clientId && pending.requestId === requestId) {
        this.cancel(id, json({ jsonrpc: '2.0', id: requestId, error: { code: -32800, message: 'Request cancelled.' } }), { jsonrpc: '2.0', id: requestId, error: { code: -32800, message: 'Request cancelled.' } });
      }
      return new Response(null, { status: 202, headers: { 'cache-control': 'no-store' } });
    }
    // Body reads yield to other calls: re-check capacity immediately before insertion.
    if (socket.readyState !== WebSocket.OPEN || socket !== this.connector()) return json({ error: 'Computer disconnected before dispatch.' }, 503);
    const stopping = body.method === 'tools/call' && body.params?.name === 'stop_command';
    if (stopping && !['computer:read', 'computer:execute'].every(scope => authorization.scope.includes(scope))) return json({ error: 'Command control requires execute permission.' }, 403);
    const lane = [...this.pending.values()].filter(item => item.stopping === stopping);
    if (lane.length >= (stopping ? 4 : 16) || (stopping && lane.filter(item => item.clientId === authorization.clientId).length >= 2)) return json({ error: 'Computer is busy.' }, 429, { 'retry-after': '3' });
    const id = crypto.randomUUID();
    const issuedAt = Date.now();
    if (wantsStream) {
      let streamClosed = false;
      let streamController = null;
      const sendSseAndClose = terminalPayload => {
        if (streamClosed) return;
        streamClosed = true;
        try {
          if (terminalPayload) streamController?.enqueue(sseEventBytes(terminalPayload));
        } catch {}
        try {
          streamController?.close();
        } catch {}
      };
      const sendSseChunk = chunkPayload => {
        if (streamClosed) return false;
        const encoded = sseEventBytes(chunkPayload);
        if (encoded.byteLength > MAX_STREAM_FRAME_BYTES) return false;
        const pending = this.pending.get(id);
        if (!pending || pending.chunkCount >= MAX_STREAM_CHUNKS || pending.totalBytes + encoded.byteLength > MAX_STREAM_TOTAL_BYTES) {
          return false;
        }
        try {
          streamController?.enqueue(encoded);
          pending.chunkCount += 1;
          pending.nextSeq += 1;
          pending.totalBytes += encoded.byteLength;
          return true;
        } catch {
          return false;
        }
      };
      const aborted = () => this.cancel(
        id,
        null,
        { jsonrpc: '2.0', id: body.id ?? null, error: { code: -32800, message: 'Client disconnected; operation was not replayed.' } },
      );
      const timer = setTimeout(
        () => this.cancel(
          id,
          null,
          { jsonrpc: '2.0', id: body.id ?? null, error: { code: -32001, message: 'Computer stream request timed out. Inspect its partial output before retrying.' } },
        ),
        110000,
      );
      const readable = new ReadableStream({
        start: controller => {
          streamController = controller;
        },
        cancel: () => {
          streamClosed = true;
          this.cancel(id, null, null);
        },
      });
      request.signal?.addEventListener('abort', aborted, { once: true });
      this.pending.set(id, {
        socket,
        streaming: true,
        chunkCount: 0,
        nextSeq: 0,
        totalBytes: 0,
        sendSseChunk,
        resolve: terminal => sendSseAndClose(terminal),
        timer,
        requestId: body.id,
        clientId: authorization.clientId,
        stopping,
        notification: false,
        signal: request.signal,
        aborted,
      });
      if (request.signal?.aborted) {
        aborted();
        return json({ error: 'Client disconnected; operation was not replayed.' }, 499);
      }
      try {
        socket.send(JSON.stringify({ type: 'request', id, body, authorization, issuedAt, deadline: issuedAt + 110000, stream: true }));
      } catch {
        this.finish(id, { jsonrpc: '2.0', id: body.id ?? null, error: { code: -32001, message: 'Computer disconnected; operation was not replayed.' } });
        return json({ error: 'Computer disconnected; operation was not replayed.' }, 502);
      }
      return new Response(readable, {
        status: 200,
        headers: {
          'content-type': 'text/event-stream; charset=utf-8',
          'cache-control': 'no-store',
          'x-content-type-options': 'nosniff',
        },
      });
    }
    return new Promise(resolve => {
      const timer = setTimeout(() => this.cancel(id, json({ error: 'Computer request timed out. It may have executed; inspect its result before retrying.' }, 504)), 110000);
      const aborted = () => this.cancel(id, json({ error: 'Client disconnected; operation was not replayed.' }, 499));
      request.signal?.addEventListener('abort', aborted, { once: true });
      this.pending.set(id, { socket, resolve, timer, requestId: body.id, clientId: authorization.clientId, stopping, notification: !('id' in body), signal: request.signal, aborted });
      if (request.signal?.aborted) { aborted(); return; }
      try { socket.send(JSON.stringify({ type: 'request', id, body, authorization, issuedAt, deadline: issuedAt + 110000 })); }
      catch { this.finish(id, json({ error: 'Computer disconnected; operation was not replayed.' }, 502)); }
    });
  }

  async limit(request) {
    const value = await request.json();
    if (typeof value.key !== 'string' || !/^[a-z0-9:-]{1,160}$/.test(value.key) || !Number.isInteger(value.maximum) || value.maximum < 1 || value.maximum > 1000 || !Number.isInteger(value.seconds) || value.seconds < 1 || value.seconds > 86400) return json({ error: 'Invalid limiter input.' }, 400);
    const now = Date.now();
    const result = this.ctx.storage.transactionSync(() => {
      const row = this.ctx.storage.sql.exec('SELECT count, until FROM rate_limits WHERE key = ?', value.key).toArray()[0];
      const active = row && row.until > now;
      const count = active ? row.count : 0;
      const until = active ? row.until : now + value.seconds * 1000;
      if (count >= value.maximum) return { allowed: false, retryAfter: Math.max(1, Math.ceil((until - now) / 1000)) };
      this.ctx.storage.sql.exec(
        'INSERT INTO rate_limits(key, count, until) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET count = excluded.count, until = excluded.until',
        value.key,
        count + 1,
        until,
      );
      return { allowed: true, retryAfter: 0 };
    });
    if (now >= this.nextCleanup) {
      this.nextCleanup = now + 3600000;
      this.ctx.storage.sql.exec('DELETE FROM rate_limits WHERE until <= ?', now);
    }
    return json(result);
  }

  finish(id, response) {
    const pending = this.pending.get(id);
    if (!pending) return;
    this.pending.delete(id);
    clearTimeout(pending.timer);
    pending.signal?.removeEventListener('abort', pending.aborted);
    pending.resolve(response);
  }

  cancel(id, response, streamPayload = null) {
    const pending = this.pending.get(id);
    if (!pending) return;
    if (pending.socket.readyState === WebSocket.OPEN) try { pending.socket.send(JSON.stringify({ type: 'cancel', id })); } catch {}
    if (pending.streaming) {
      this.finish(id, streamPayload);
      return;
    }
    this.finish(id, response);
  }

  async webSocketMessage(socket, data) {
    await this.currentCredential();
    if (socket.deserializeAttachment()?.credentialVersion !== this.credentialVersion) { socket.close(1008, 'Connector credentials changed.'); this.disconnected(socket); return; }
    if (typeof data !== 'string' || new TextEncoder().encode(data).byteLength > MAX_REPLY_BYTES) { socket.close(1009, 'Invalid response size.'); this.disconnected(socket); return; }
    let message;
    try { message = JSON.parse(data); } catch { socket.close(1003, 'Expected JSON.'); this.disconnected(socket); return; }
    if (message?.type === 'ping') {
      const attachment = socket.deserializeAttachment();
      if (attachment) socket.serializeAttachment({ ...attachment, lastPingAt: Date.now() });
      socket.send('{"type":"pong"}');
      return;
    }
    if (message?.type === 'pong') return;
    if (typeof message?.id !== 'string') return;
    const pending = this.pending.get(message.id);
    if (!pending || pending.socket !== socket) return;

    if (message.type === 'stream_chunk' && pending.streaming) {
      if (!Number.isInteger(message.seq) || message.seq !== pending.nextSeq || !isValidStreamChunkRpc(message.body)) {
        this.cancel(
          message.id,
          null,
          { jsonrpc: '2.0', id: pending.requestId ?? null, error: { code: -32603, message: 'Computer returned an invalid stream chunk.' } },
        );
        return;
      }
      if (!pending.sendSseChunk(message.body)) {
        this.cancel(
          message.id,
          null,
          { jsonrpc: '2.0', id: pending.requestId ?? null, error: { code: -32603, message: 'Stream output exceeded bridge chunk or byte limits.' } },
        );
      }
      return;
    }

    if (message.type === 'stream_end' && pending.streaming) {
      const response = message.body;
      const valid = isValidFinalRpc(response, pending.requestId);
      this.finish(
        message.id,
        valid ? response : { jsonrpc: '2.0', id: pending.requestId ?? null, error: { code: -32603, message: 'Computer returned an invalid stream terminal response.' } },
      );
      return;
    }

    if (message.type !== 'response') return;
    if (pending.notification) { this.finish(message.id, new Response(null, { status: 202, headers: { 'cache-control': 'no-store' } })); return; }
    const response = message.body;
    const valid = isValidFinalRpc(response, pending.requestId);
    if (pending.streaming) {
      // Degraded compatibility fallback when a non-streaming connector (e.g. legacy local/connector.mjs) answers a stream request with a single JSON response.
      this.finish(
        message.id,
        valid ? response : { jsonrpc: '2.0', id: pending.requestId ?? null, error: { code: -32603, message: 'Computer returned an invalid JSON-RPC response.' } },
      );
      return;
    }
    this.finish(message.id, valid ? json(response) : json({ error: 'Computer returned an invalid JSON-RPC response.' }, 502));
  }

  disconnected(socket) {
    for (const [id, request] of this.pending) {
      if (request.socket !== socket) continue;
      if (request.streaming) {
        this.finish(id, { jsonrpc: '2.0', id: request.requestId ?? null, error: { code: -32001, message: 'Computer disconnected. Operations are not replayed automatically.' } });
      } else {
        this.finish(id, json({ error: 'Computer disconnected. Operations are not replayed automatically.' }, 502));
      }
    }
  }
  webSocketClose(socket, code) {
    this.disconnected(socket);
    const safeCode = [1005, 1006, 1015].includes(code) || code < 1000 || code >= 5000 ? 1000 : code;
    try { socket.close(safeCode); } catch {}
  }
  webSocketError(socket) { this.disconnected(socket); }
}
