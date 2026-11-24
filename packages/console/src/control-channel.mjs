// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Real-time kernel control & metadata-only event channel (in-process bus + optional 0600 POSIX Unix domain socket).
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import { sanitizeAuditMetadata } from '@loomward/shared';

const MAX_LINE_BYTES = 256 * 1024;
const MAX_SOCKET_CLIENTS = 16;
const MAX_RECENT_EVENTS = 80;

export function createControlChannel({ socketPath = null } = {}) {
  const listeners = new Set();
  const socketClients = new Set();
  const recentEvents = [];
  let server = null;
  let boundSocketPath = null;
  let closed = false;

  function sanitizeEvent(raw) {
    const type = typeof raw?.type === 'string' && /^[a-z0-9._:-]{1,64}$/i.test(raw.type)
      ? raw.type
      : 'kernel.event';
    const meta = sanitizeAuditMetadata(raw?.meta ?? raw ?? {});
    delete meta.type;
    const rawTime = typeof raw?.time === 'string' && raw.time.length > 0 && raw.time.length <= 40
      ? raw.time
      : new Date().toISOString();
    return {
      type,
      time: rawTime,
      meta,
    };
  }

  function publish(rawEvent) {
    if (closed) return null;
    const event = sanitizeEvent(rawEvent);
    recentEvents.push(event);
    if (recentEvents.length > MAX_RECENT_EVENTS) {
      recentEvents.splice(0, recentEvents.length - MAX_RECENT_EVENTS);
    }
    const wire = JSON.stringify(event) + '\n';
    for (const listener of [...listeners]) {
      try { listener(event); } catch {}
    }
    for (const sock of [...socketClients]) {
      if (sock.destroyed || !sock.writable) {
        socketClients.delete(sock);
        continue;
      }
      if (sock.writableLength > MAX_LINE_BYTES) {
        socketClients.delete(sock);
        sock.destroy();
        continue;
      }
      sock.write(wire);
    }
    return event;
  }

  function subscribe(fn) {
    if (typeof fn !== 'function') throw new TypeError('Subscriber must be a function.');
    listeners.add(fn);
    return () => listeners.delete(fn);
  }

  async function startSocketServer(explicitPath = socketPath) {
    if (process.platform === 'win32' || !explicitPath) return null;
    const resolved = path.resolve(explicitPath);
    if (Buffer.byteLength(resolved, 'utf8') > 96) {
      // POSIX sun_path is ~104-108 bytes; fall back silently to in-process bus for long test paths.
      return null;
    }
    const dir = path.dirname(resolved);
    const dirStat = fs.lstatSync(dir);
    if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) {
      throw new Error('Control socket directory must be an ordinary non-linked directory.');
    }
    if (process.platform !== 'win32') {
      if ((dirStat.mode & 0o077) !== 0) {
        throw new Error('Control socket directory must not be group or world accessible (0700 required).');
      }
      if (typeof process.getuid === 'function' && dirStat.uid !== process.getuid()) {
        throw new Error('Control socket directory must be owned by the current user.');
      }
    }
    const existing = fs.lstatSync(resolved, { throwIfNoEntry: false });
    if (existing) {
      if (existing.isSymbolicLink() || !existing.isSocket()) {
        throw new Error('Control socket path must not overwrite an existing non-socket file, directory, or symlink.');
      }
      fs.rmSync(resolved, { force: true });
    }

    const srv = net.createServer(sock => {
      if (socketClients.size >= MAX_SOCKET_CLIENTS) {
        sock.destroy();
        return;
      }
      socketClients.add(sock);
      const decoder = new StringDecoder('utf8');
      let buf = '';
      sock.on('data', chunk => {
        buf += decoder.write(chunk);
        if (Buffer.byteLength(buf, 'utf8') > MAX_LINE_BYTES) {
          sock.destroy();
          return;
        }
        let idx;
        while ((idx = buf.indexOf('\n')) !== -1) {
          const line = buf.slice(0, idx).trim();
          buf = buf.slice(idx + 1);
          if (!line) continue;
          try {
            const msg = JSON.parse(line);
            if (msg?.op === 'publish' && msg.event) {
              publish(msg.event);
            } else if (msg?.op === 'ping') {
              if (sock.writable && !sock.destroyed && sock.writableLength <= MAX_LINE_BYTES) {
                sock.write(JSON.stringify({ type: 'pong', time: new Date().toISOString(), meta: {} }) + '\n');
              }
            }
          } catch {}
        }
      });
      const cleanup = () => socketClients.delete(sock);
      sock.on('close', cleanup);
      sock.on('error', cleanup);
    });

    await new Promise((resolve, reject) => {
      srv.once('error', reject);
      srv.listen(resolved, () => {
        srv.removeListener('error', reject);
        resolve();
      });
    });
    fs.chmodSync(resolved, 0o600);
    server = srv;
    boundSocketPath = resolved;
    return resolved;
  }

  async function close() {
    if (closed) return;
    closed = true;
    listeners.clear();
    for (const sock of [...socketClients]) sock.destroy();
    socketClients.clear();
    if (server) {
      const srv = server;
      server = null;
      await new Promise(resolve => srv.close(resolve));
    }
    if (boundSocketPath) {
      const p = boundSocketPath;
      boundSocketPath = null;
      fs.rmSync(p, { force: true });
    }
  }

  return Object.freeze({
    publish,
    subscribe,
    recent: () => recentEvents.map(item => ({ ...item, meta: { ...item.meta } })),
    startSocketServer,
    getSocketPath: () => boundSocketPath,
    close,
  });
}

export function connectControlSocket(socketPath, { onEvent = () => {}, onError = () => {} } = {}) {
  const resolved = path.resolve(socketPath);
  const st = fs.lstatSync(resolved);
  if (st.isSymbolicLink() || !st.isSocket()) {
    throw new Error('Target control path is not a regular Unix domain socket.');
  }
  if (process.platform !== 'win32') {
    if ((st.mode & 0o077) !== 0) {
      throw new Error('Target control socket must not be group or world accessible (0600 required).');
    }
    if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
      throw new Error('Target control socket is not owned by the current user.');
    }
  }
  const client = net.createConnection(resolved);
  client.on('error', err => {
    try { onError(err); } catch {}
  });
  const decoder = new StringDecoder('utf8');
  let buf = '';
  client.on('data', chunk => {
    buf += decoder.write(chunk);
    if (Buffer.byteLength(buf, 'utf8') > MAX_LINE_BYTES) {
      client.destroy();
      return;
    }
    let idx;
    while ((idx = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, idx).trim();
      buf = buf.slice(idx + 1);
      if (!line) continue;
      try {
        onEvent(JSON.parse(line));
      } catch {}
    }
  });
  return Object.freeze({
    socket: client,
    publish(event) {
      if (client.writable && !client.destroyed) {
        client.write(JSON.stringify({ op: 'publish', event }) + '\n');
      }
    },
    close() {
      client.destroy();
    },
  });
}
