/**
 * Collector orchestrator.
 *
 *   const { syncedCounts, errors, durationMs, syncedAt } = await runSyncAll(db, opts)
 *
 * Every collector runs inside its own try/catch: a missing/locked tool never fails the sync.
 * Cursors are committed only AFTER the collector's events, session states, and timing backfills were persisted,
 * so a crash re-reads (and dedups) rather than loses data.
 */
import { collectAntigravity } from './antigravity.mjs';
import { collectOmniroute } from './omniroute.mjs';
import { collectClaudeCode, collectCodex, collectOpencode, collect9Router, collectIngest } from './external.mjs';
import { debugLog, insertAdaptive, num, setCursor, sha1, tableColumns } from './util.mjs';

export { collectAntigravity, collectOmniroute, collectClaudeCode, collectCodex, collectOpencode, collect9Router, collectIngest };

export const COLLECTORS = /** @type {const} */ ([
  { id: 'antigravity', run: collectAntigravity },
  { id: 'omniroute', run: collectOmniroute },
  { id: 'claude-code', run: collectClaudeCode },
  { id: 'codex', run: collectCodex },
  { id: 'opencode', run: collectOpencode },
  { id: '9router', run: collect9Router },
  { id: 'ingest', run: collectIngest },
]);

/** Fill NOT NULL text columns without overwriting explicit caller values. */
export function sanitizeEvent(e) {
  const out = { ...e };
  // account_id left empty => insertRequestBatch applies `${source_tool}-default` and its own plan inference.
  if (out.account_email === undefined || out.account_email === null) {
    out.account_email = String(out.account_id || '').includes('@') ? out.account_id : '';
  }
  out.model_id = out.model_id || 'unknown';
  out.raw_model = out.raw_model || out.model_id;
  out.model_raw = out.model_raw || out.raw_model;
  out.provider = out.provider || 'unknown';
  out.endpoint_mode = out.endpoint_mode || 'unknown';
  out.endpoint = out.endpoint ?? '';
  out.combo_name = out.combo_name ?? '';
  out.title = out.title ?? '';
  out.workspace = out.workspace ?? '';
  out.status = out.status || 'ok';
  out.created_at = out.created_at || new Date().toISOString();
  for (const k of ['input_tokens', 'output_tokens', 'cache_read_tokens', 'cache_write_tokens', 'reasoning_tokens']) {
    out[k] = Number(out[k]) || 0;
  }
  if (out.uncached_input_tokens === undefined || out.uncached_input_tokens === null) {
    out.uncached_input_tokens = out.input_tokens;
  }
  out.compressed_tokens = Number(out.compressed_tokens) || 0;
  out.context_tokens = Number(out.context_tokens ?? out.input_tokens + out.cache_read_tokens) || 0;
  if (out.context_utilization === undefined && out.context_window) {
    out.context_utilization = out.context_tokens / out.context_window;
  }
  return out;
}

function countRequests(db) {
  try {
    return db.prepare('SELECT COUNT(*) AS c FROM requests').get().c;
  } catch (err) {
    debugLog(err, 'countRequests');
    return 0;
  }
}

function writeQuotas(db, quotas, upsert) {
  let n = 0;
  const now = new Date().toISOString();
  for (const q of quotas) {
    if (upsert) {
      try {
        upsert(db, q);
        n++;
        continue;
      } catch (err) {
        debugLog(err, 'writeQuotas:upsert');
      }
    }
    const ok = insertAdaptive(
      db,
      'quota_snapshots',
      {
        ...q,
        account_id: q.account_id || 'unknown',
        provider: q.provider || '',
        model_id: q.model_id || '',
        quota_id: sha1(`${q.source_tool}|${q.account_id}|${q.model_id}|${q.window_key}|${q.captured_at}|${q.remaining_pct}|${q.tokens_used}`),
        updated_at: now,
      },
      { orIgnore: true },
    );
    if (ok) n++;
  }
  return n;
}

function applySessionStates(db, states, dbHelper) {
  if (!db || !Array.isArray(states) || !states.length) return 0;
  if (typeof dbHelper === 'function') {
    try {
      const res = dbHelper(db, states);
      return typeof res === 'number' ? res : Number(res?.updated ?? states.length) || 0;
    } catch (err) {
      debugLog(err, 'applySessionStates:helper');
    }
  }
  const cols = tableColumns(db, 'sessions');
  const required = ['run_status', 'not_fully_idle', 'killed', 'nesting_depth'];
  if (!required.every((c) => cols.includes(c))) return 0;
  const stmt = db.prepare(
    'UPDATE sessions SET run_status = ?, not_fully_idle = ?, killed = ?, nesting_depth = ? WHERE session_id = ?',
  );
  let updated = 0;
  db.exec('BEGIN');
  try {
    for (const s of states) {
      if (!s?.session_id) continue;
      const r = stmt.run(
        String(s.run_status || ''),
        s.not_fully_idle ? 1 : 0,
        s.killed ? 1 : 0,
        num(s.nesting_depth, 0),
        String(s.session_id),
      );
      updated += Number(r?.changes) || 0;
    }
    db.exec('COMMIT');
  } catch (err) {
    try {
      db.exec('ROLLBACK');
    } catch (rbErr) {
      debugLog(rbErr, 'applySessionStates:rollback');
    }
    debugLog(err, 'applySessionStates:fallback');
  }
  return updated;
}

function applyTimingBackfills(db, updates, dbHelper) {
  if (!db || !Array.isArray(updates) || !updates.length) return 0;
  if (typeof dbHelper === 'function') {
    try {
      const res = dbHelper(db, updates);
      return typeof res === 'number' ? res : Number(res?.updated ?? updates.length) || 0;
    } catch (err) {
      debugLog(err, 'applyTimingBackfills:helper');
    }
  }
  const stmt = db.prepare(
    `UPDATE requests
        SET ttft_ms = COALESCE(ttft_ms, ?),
            ttfr_ms = COALESCE(ttfr_ms, ?),
            ttfa_ms = COALESCE(ttfa_ms, ?),
            tpot_ms = COALESCE(tpot_ms, ?),
            tok_per_sec = COALESCE(tok_per_sec, ?),
            latency_ms = COALESCE(latency_ms, ?)
      WHERE dedup_key = ?`,
  );
  let updated = 0;
  db.exec('BEGIN');
  try {
    for (const u of updates) {
      if (!u?.dedup_key) continue;
      const r = stmt.run(
        u.ttft_ms ?? null,
        u.ttfr_ms ?? null,
        u.ttfa_ms ?? null,
        u.tpot_ms ?? null,
        u.tok_per_sec ?? null,
        u.latency_ms ?? null,
        String(u.dedup_key),
      );
      updated += Number(r?.changes) || 0;
    }
    db.exec('COMMIT');
  } catch (err) {
    try {
      db.exec('ROLLBACK');
    } catch (rbErr) {
      debugLog(rbErr, 'applyTimingBackfills:rollback');
    }
    debugLog(err, 'applyTimingBackfills:fallback');
  }
  return updated;
}

/**
 * @param {import('node:sqlite').DatabaseSync} db  open wiretok database (schema initialised)
 * @param {{sources?:string[], milestoneAt?:string, chunkSize?:number, dryRun?:boolean, insertRequestBatch?:Function, upsertQuotaSnapshot?:Function, updateSessionStates?:Function, backfillRequestTimings?:Function}} [opts]
 * @returns {Promise<{syncedCounts:Record<string,number>, errors:string[], durationMs:number, syncedAt:string, notes:string[], quotaRows:number, sessionStatesUpdated:number, timingBackfilled:number}>}
 */
export async function runSyncAll(db, opts = {}) {
  const t0 = Date.now();
  const errors = [];
  const notes = [];
  const syncedCounts = {};
  let quotaRows = 0;
  let sessionStatesUpdated = 0;
  let timingBackfilled = 0;
  const chunkSize = opts.chunkSize || 2000;

  let insertRequestBatch = opts.insertRequestBatch;
  let upsertQuota = opts.upsertQuotaSnapshot;
  let updateSessionStates = opts.updateSessionStates;
  let backfillRequestTimings = opts.backfillRequestTimings;
  if ((!insertRequestBatch || !updateSessionStates || !backfillRequestTimings) && !opts.dryRun) {
    try {
      const mod = await import('../db/index.mjs');
      insertRequestBatch = insertRequestBatch || mod.insertRequestBatch;
      upsertQuota = upsertQuota || mod.upsertQuotaSnapshot;
      updateSessionStates = updateSessionStates || mod.updateSessionStates;
      backfillRequestTimings = backfillRequestTimings || mod.backfillRequestTimings;
    } catch (e) {
      errors.push(`db: cannot load ../db/index.mjs (${e.message})`);
    }
  }

  const selected = COLLECTORS.filter((c) => !opts.sources || opts.sources.includes(c.id));
  for (const c of selected) {
    try {
      const r = c.run(db, opts);
      for (const e of r.errors || []) errors.push(e);
      for (const n of r.notes || []) notes.push(n);
      const events = (r.events || []).map(sanitizeEvent);
      const before = countRequests(db);
      if (opts.dryRun) {
        syncedCounts[c.id] = events.length;
        continue;
      }
      if (!insertRequestBatch) {
        syncedCounts[c.id] = 0;
        continue;
      }
      let reported = 0;
      for (let i = 0; i < events.length; i += chunkSize) {
        const br = insertRequestBatch(db, events.slice(i, i + chunkSize));
        reported += typeof br === 'number' ? br : Number(br?.inserted) || 0;
      }
      const inserted = Math.max(countRequests(db) - before, reported);
      syncedCounts[c.id] = inserted;
      if (events.length && inserted < events.length) notes.push(`${c.id}: ${events.length - inserted} duplicate/ignored of ${events.length}`);
      if (r.quotas?.length) quotaRows += writeQuotas(db, r.quotas, upsertQuota);
      if (r.sessionStates?.length) {
        sessionStatesUpdated += applySessionStates(db, r.sessionStates, updateSessionStates);
      }
      if (r.timingBackfills?.length) {
        timingBackfilled += applyTimingBackfills(db, r.timingBackfills, backfillRequestTimings);
      }
      for (const cu of r.cursorUpdates || []) {
        const { key, ...rest } = cu;
        setCursor(db, key, { ...rest, source_tool: c.id });
      }
    } catch (e) {
      syncedCounts[c.id] = syncedCounts[c.id] ?? 0;
      errors.push(`${c.id}: ${e.message}`);
    }
  }
  return {
    syncedCounts,
    errors,
    durationMs: Date.now() - t0,
    syncedAt: new Date().toISOString(),
    notes,
    quotaRows,
    sessionStatesUpdated,
    timingBackfilled,
  };
}

export default runSyncAll;
