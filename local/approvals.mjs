// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import fs from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { requiresApproval, approvalSubject, digest } from './request-policy.mjs';
import { REQUEST_FILE, MAX_RECORD_BYTES, MAX_APPROVED_RECORD_BYTES, readJson, validRequest, atomicJson, removeRequest } from './approval-store.mjs';

const TTL = 5 * 60 * 1000;
const MAX_PENDING = 64;
const MAX_PER_CLIENT = 8;

export class LocalApprovals {
  constructor(stateDir, origin, { now = Date.now } = {}) {
    this.directory = path.join(stateDir, 'approvals');
    this.origin = origin;
    this.now = now;
    this.cache = new Map();
    this.queue = Promise.resolve();
    this.ready = fs.mkdir(this.directory, { recursive: true, mode: 0o700 }).then(async () => {
      if ((await fs.lstat(this.directory)).isSymbolicLink()) throw new Error('Approval directory must not be a link.');
    });
  }
  authorize(body, authorization, { signal, force = false } = {}) {
    if (!force && !requiresApproval(body)) return Promise.resolve({ approved: true });
    const action = this.queue.then(async () => {
      await this.ready;
      signal?.throwIfAborted();
      const subject = approvalSubject(this.origin, body, authorization);
      const hash = digest(subject);
      const now = this.now();
      const entries = await fs.readdir(this.directory);
      if (entries.length > 4096) throw new Error('Approval storage requires local maintenance.');
      const seen = new Set();
      let count = 0, clientCount = 0, remaining = 0;
      let matchId = null, matchExpiresAt = null;
      for (const name of entries) {
        signal?.throwIfAborted();
        const identified = REQUEST_FILE.exec(name);
        if (!identified) {
          // Recover old interrupted publications without touching an active writer.
          if (/^(?:\.approval-[a-f0-9-]{36}\.tmp|[a-f0-9-]{36}\.approved\.json)$/.test(name)) {
            const orphan = path.join(this.directory, name);
            const stat = await fs.lstat(orphan).catch(() => null);
            if (stat?.isFile() && stat.mtimeMs < now - TTL * 2) await fs.unlink(orphan).catch(() => {});
            else remaining++;
          } else {
            remaining++;
          }
          continue;
        }
        const id = identified[1];
        seen.add(id);
        const file = path.join(this.directory, name);
        const st = await fs.lstat(file).catch(() => null);
        if (!st || st.isSymbolicLink() || !st.isFile() || st.size > MAX_RECORD_BYTES) {
          this.cache.delete(id);
          await removeRequest(this.directory, id);
          continue;
        }
        const version = `${st.dev}:${st.ino}:${st.size}:${st.mtimeMs}:${st.ctimeMs}`;
        let summary = this.cache.get(id);
        if (!summary || summary.version !== version) {
          let pending;
          try { pending = await readJson(file); } catch {}
          if (!validRequest(pending, id, now)) {
            this.cache.delete(id);
            await removeRequest(this.directory, id);
            continue;
          }
          summary = {
            version,
            id: pending.id,
            hash: pending.hash,
            createdAt: pending.createdAt,
            expiresAt: pending.expiresAt,
            clientId: pending.request.authorization?.clientId,
          };
          this.cache.set(id, summary);
        } else if (summary.expiresAt <= now || summary.createdAt > now || summary.expiresAt - summary.createdAt !== TTL) {
          this.cache.delete(id);
          await removeRequest(this.directory, id);
          continue;
        }
        remaining++;
        count++;
        if (summary.clientId === authorization.clientId) clientCount++;
        if (summary.hash === hash) {
          const pending = await readJson(file).catch(() => null);
          if (!validRequest(pending, id, now) || digest(pending.request) !== hash) {
            this.cache.delete(id);
            await removeRequest(this.directory, id);
            count--;
            if (summary.clientId === authorization.clientId) clientCount--;
            continue;
          }
          matchId = pending.id;
          matchExpiresAt = pending.expiresAt;
        }
      }
      for (const cachedId of this.cache.keys()) if (!seen.has(cachedId)) this.cache.delete(cachedId);
      if (remaining > 1024) throw new Error('Approval storage requires local maintenance.');
      if (matchId) {
        const approvedFile = path.join(this.directory, `${matchId}.approved.json`);
        let approval;
        try { approval = await readJson(approvedFile, MAX_APPROVED_RECORD_BYTES); } catch (error) { if (error.code !== 'ENOENT') await fs.unlink(approvedFile).catch(() => {}); }
        if (approval?.hash === hash && approval.expiresAt === matchExpiresAt && approval.expiresAt > this.now()) {
          signal?.throwIfAborted();
          // Consume the approval before starting any side effect; a crash cannot reuse it.
          this.cache.delete(matchId);
          await fs.unlink(approvedFile);
          await fs.unlink(path.join(this.directory, `${matchId}.request.json`));
          return { approved: true };
        }
        return { approved: false, id: matchId, expiresAt: matchExpiresAt };
      }
      if (count >= MAX_PENDING || clientCount >= MAX_PER_CLIENT) throw new Error('Approval queue is full for this client. Review pending requests or wait for expiry.');
      const createdAt = this.now();
      const pending = { id: randomUUID(), hash, createdAt, expiresAt: createdAt + TTL, request: subject };
      signal?.throwIfAborted();
      const file = path.join(this.directory, `${pending.id}.request.json`);
      await atomicJson(file, pending);
      const st = await fs.lstat(file).catch(() => null);
      if (st?.isFile()) {
        this.cache.set(pending.id, {
          version: `${st.dev}:${st.ino}:${st.size}:${st.mtimeMs}:${st.ctimeMs}`,
          id: pending.id,
          hash: pending.hash,
          createdAt: pending.createdAt,
          expiresAt: pending.expiresAt,
          clientId: authorization.clientId,
        });
      }
      return { approved: false, id: pending.id, expiresAt: pending.expiresAt };
    });
    this.queue = action.catch(() => {});
    return action;
  }
}
