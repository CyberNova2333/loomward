// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { assertConfigOutsideWorkspace, TOOL_CAPABILITY_GROUPS } from './capabilities.mjs';
import { assertPrivateFile, assertPrivateState } from './host-safety.mjs';
import { digest } from './request-policy.mjs';

const WINDOW_MS = 10 * 60_000;
const HISTORY_MS = 24 * 60 * 60_000;
const sourceBits = { input: 1, output: 2, combined: 4 };
const schema = `
  CREATE TABLE IF NOT EXISTS hits (
    client TEXT NOT NULL, request TEXT NOT NULL, firstAt INTEGER NOT NULL, sources INTEGER NOT NULL,
    source TEXT NOT NULL, tool TEXT NOT NULL, rule TEXT NOT NULL, action TEXT NOT NULL, stage TEXT NOT NULL,
    PRIMARY KEY (client, request)
  );
  CREATE INDEX IF NOT EXISTS hits_time ON hits(firstAt);
  CREATE INDEX IF NOT EXISTS hits_client_time ON hits(client, firstAt);
  CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scopeKey TEXT NOT NULL, threshold INTEGER NOT NULL,
    openedAt INTEGER NOT NULL, updatedAt INTEGER NOT NULL, activeUntil INTEGER NOT NULL,
    details TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS alerts_updated ON alerts(updatedAt);
  CREATE INDEX IF NOT EXISTS alerts_scope ON alerts(scopeKey, id);
`;

// Check the private parent and existing SQLite sidecars before letting SQLite open any path.
function openFile(stateDir, workspaceRoots, readOnly) {
  const file = path.join(stateDir, 'injection-alerts.sqlite');
  assertConfigOutsideWorkspace(file, workspaceRoots);
  if (readOnly && !fs.lstatSync(file, { throwIfNoEntry: false })) return null;
  assertPrivateState(stateDir);
  if (!readOnly) {
    try { fs.closeSync(fs.openSync(file, 'wx', 0o600)); }
    catch (error) { if (error.code !== 'EEXIST') throw error; }
  }
  assertPrivateFile(file);
  for (const suffix of ['-journal', '-wal', '-shm']) {
    if (fs.lstatSync(file + suffix, { throwIfNoEntry: false })) {
      try { assertPrivateFile(file + suffix); }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
  }
  return new DatabaseSync(file, { readOnly });
}

export function injectionToolRef(toolName) {
  return Object.hasOwn(TOOL_CAPABILITY_GROUPS, toolName) ? toolName : 'tool-' + digest(toolName).slice(0, 16);
}

export function createInjectionAlertStore({ stateDir, workspaceRoots = [], readOnly = false, now = Date.now }) {
  let db;
  function connection() {
    if (db) return db;
    if (readOnly && !stateDir) return null;
    const opened = stateDir ? openFile(stateDir, workspaceRoots, readOnly) : new DatabaseSync(':memory:');
    if (!opened) return null;
    try {
      opened.exec('PRAGMA trusted_schema=OFF; PRAGMA busy_timeout=2000');
      if (!readOnly) opened.exec(schema);
      db = opened;
      return db;
    } catch (error) {
      opened.close();
      throw error;
    }
  }

  function updateScope(key, threshold, time) {
    const where = key === 'global' ? ' WHERE firstAt > ?' : ' WHERE firstAt > ? AND client = ?';
    const args = [time - WINDOW_MS];
    if (key !== 'global') args.push(key);
    const totals = db.prepare(`SELECT count(*) AS count, count(DISTINCT client) AS clients,
      count(*) FILTER (WHERE sources & 1) AS inputs, count(*) FILTER (WHERE sources & 2) AS outputs,
      count(*) FILTER (WHERE sources & 4) AS combined FROM hits${where}`).get(...args);
    const last = db.prepare('SELECT id,threshold,activeUntil FROM alerts WHERE scopeKey=? ORDER BY id DESC LIMIT 1').get(key);
    if (last && last.threshold !== threshold && last.activeUntil > time) {
      db.prepare('UPDATE alerts SET activeUntil=? WHERE id=?').run(time, last.id);
    }
    if (totals.count < threshold) return;
    // When the threshold-th newest request expires the window falls below threshold,
    // even if no new event or console poll occurred at that moment.
    const cutoff = db.prepare(`SELECT firstAt FROM hits${where} ORDER BY firstAt DESC LIMIT 1 OFFSET ?`).get(...args, threshold - 1);
    const until = cutoff.firstAt + WINDOW_MS;
    const samples = db.prepare(`SELECT client,request,tool,rule,action,stage,source FROM hits${where}
      ORDER BY firstAt DESC, rowid DESC LIMIT 5`).all(...args);
    const details = JSON.stringify({ ...totals, samples });
    if (last && last.threshold === threshold && last.activeUntil > time) {
      db.prepare('UPDATE alerts SET updatedAt=?,activeUntil=?,details=? WHERE id=?').run(time, until, details, last.id);
    } else {
      db.prepare('INSERT INTO alerts(scopeKey,threshold,openedAt,updatedAt,activeUntil,details) VALUES(?,?,?,?,?,?)')
        .run(key, threshold, time, time, until, details);
    }
  }

  return {
    record({ clientRef, requestId, toolName, source, stage, rule, action }, limits) {
      if (readOnly) throw new Error('Cannot record hits in a read-only alert store.');
      if (typeof clientRef !== 'string' || !/^[0-9a-f]{64}$/.test(clientRef) || typeof requestId !== 'string' || !requestId ||
          typeof toolName !== 'string' || !Object.hasOwn(sourceBits, source) ||
          !['input', 'output', 'combined', 'stream_chunk', 'stream_end'].includes(stage) ||
          !['prompt.injection', 'prompt.indirect_injection', 'prompt.inducement'].includes(rule) ||
          !['allow', 'redact', 'escalate', 'block'].includes(action)) return;
      const client = clientRef.slice(0, 24);
      const request = digest(requestId); // Same lookup key as the request receipt.
      const tool = injectionToolRef(toolName);
      connection().exec('BEGIN IMMEDIATE');
      try {
        const time = now();
        // Keep deduplication keys for the same 24 hours as the host's replay ledger.
        db.prepare('DELETE FROM hits WHERE firstAt <= ?').run(time - HISTORY_MS);
        db.prepare('DELETE FROM alerts WHERE updatedAt <= ?').run(time - HISTORY_MS);
        const changed = db.prepare(`INSERT INTO hits(client,request,firstAt,sources,source,tool,rule,action,stage)
          VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(client,request) DO UPDATE SET
            sources=hits.sources | excluded.sources, source=excluded.source, rule=excluded.rule, action=excluded.action, stage=excluded.stage
          WHERE hits.firstAt > ? AND ((hits.sources & excluded.sources)=0 OR hits.rule!=excluded.rule OR hits.action!=excluded.action OR hits.stage!=excluded.stage)`)
          .run(client, request, time, sourceBits[source], source, tool, rule, action, stage, time - WINDOW_MS);
        if (changed.changes) {
          updateScope(client, limits.clientThreshold, time);
          updateScope('global', limits.globalThreshold, time);
        }
        db.exec('COMMIT');
      } catch (error) {
        db.exec('ROLLBACK');
        throw error;
      }
    },
    snapshot() {
      if (!connection()) return { activeCount: 0, items: [] };
      const time = now();
      const rows = db.prepare(`SELECT *, (SELECT count(*) FROM alerts WHERE activeUntil > ?) AS activeCount
        FROM alerts WHERE updatedAt > ?
        ORDER BY (activeUntil > ?) DESC, updatedAt DESC, id DESC LIMIT 30`).all(time, time - HISTORY_MS, time);
      return { activeCount: rows[0]?.activeCount ?? 0, items: rows.map(row => ({
        id: row.id, scope: row.scopeKey === 'global' ? 'global' : 'client',
        client: row.scopeKey === 'global' ? null : row.scopeKey, threshold: row.threshold,
        openedAt: row.openedAt, updatedAt: row.updatedAt, active: row.activeUntil > time,
        ...JSON.parse(row.details),
      })) };
    },
    close() { db?.close(); db = null; },
  };
}
