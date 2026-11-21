/**
 * OmniRoute collector — strictly read-only (`{ readOnly: true }`), incremental.
 *
 * Reads ~/.omniroute/storage.sqlite:
 *   - provider_connections : ONLY id, provider, auth_type, name, email, display_name, "group"
 *                            (NEVER access_token / refresh_token / api_key / id_token / provider_specific_data)
 *   - usage_history        : incremental by autoincrement id (tokens, latency_ms, ttft_ms, provider_cost_usd, endpoint, ...)
 *   - call_logs            : incremental by timestamp (duration, tokens_compressed, combo_name, ...); joined to usage_history
 *   - provider_quota_state / quota_snapshots : -> quota rows for wiretok quota_snapshots
 */
import { getLocalSourcePaths, SEED_MODELS } from '../contracts.mjs';
import {
  computeSpeedMetrics,
  debugLog,
  emptyResult,
  endpointModeFromId,
  exists,
  getCursor,
  getMeta,
  hasTable,
  knownModelSet,
  num,
  numOrNull,
  openReadOnly,
  resolveModel,
  sha1,
  tableColumns,
  toIso,
} from './util.mjs';

/** The only provider_connections columns this module will ever select. */
export const SAFE_CONNECTION_COLUMNS = ['id', 'provider', 'auth_type', 'name', 'email', 'display_name', 'group'];

const MATCH_WINDOW_MS = 4000;

function selectCols(have, wanted, alias = '') {
  return wanted
    .filter((c) => have.includes(c))
    .map((c) => `${alias}${c === 'group' ? '"group"' : c}`)
    .join(', ');
}

export function loadConnections(db) {
  const map = new Map();
  if (!hasTable(db, 'provider_connections')) return map;
  const have = tableColumns(db, 'provider_connections');
  const sel = selectCols(have, SAFE_CONNECTION_COLUMNS);
  if (!sel.includes('id')) return map;
  for (const r of db.prepare(`SELECT ${sel} FROM provider_connections LIMIT 50000`).all()) {
    map.set(r.id, {
      id: r.id,
      provider: r.provider || null,
      auth_type: r.auth_type || null,
      name: r.name || null,
      email: r.email || null,
      display_name: r.display_name || null,
      group: r.group || null,
    });
  }
  return map;
}

function accountFor(conn, fallbackLabel, connectionId) {
  if (conn) return conn.email || conn.display_name || conn.name || `${conn.provider || 'omniroute'}:${conn.id}`;
  return fallbackLabel || (connectionId ? `omniroute:${connectionId}` : 'omniroute');
}

function modeFromEndpoint(ep, pth) {
  const s = `${ep || ''} ${pth || ''}`.toLowerCase();
  if (s.includes('/responses')) return 'responses';
  if (s.includes('/messages')) return 'messages';
  if (s.includes('chat/completions') || s.includes('completions')) return 'chat_completions';
  if (s.includes('generatecontent') || s.includes('gemini')) return 'gemini';
  return 'unknown';
}

/**
 * @param {import('node:sqlite').DatabaseSync|null} db wiretok DB (cursors / milestone)
 * @param {{milestoneAt?:string, dbPath?:string, settleMs?:number, maxRows?:number}} [opts]
 */
export function collectOmniroute(db, opts = {}) {
  const res = emptyResult('omniroute');
  const file = opts.dbPath || getLocalSourcePaths().omnirouteDb;
  if (!exists(file)) {
    res.notes.push('omniroute: storage.sqlite not found');
    return res;
  }
  const src = openReadOnly(file);
  if (!src) {
    res.errors.push('omniroute: could not open storage.sqlite read-only');
    return res;
  }
  try {
    const milestoneIso = opts.milestoneAt || getMeta(db, 'milestone_at') || null;
    const milestoneMs = milestoneIso ? Date.parse(milestoneIso) : null;
    const known = knownModelSet(db);
    const ctxWindow = new Map(SEED_MODELS.map((m) => [m.model_id, m.context_window]));
    const settleMs = opts.settleMs ?? 3000;
    const maxRows = opts.maxRows ?? 200000;
    const cutoffIso = new Date(Date.now() - settleMs).toISOString();

    const conns = loadConnections(src);

    const ucols = hasTable(src, 'usage_history') ? tableColumns(src, 'usage_history') : [];
    const ccols = hasTable(src, 'call_logs') ? tableColumns(src, 'call_logs') : [];

    const uKey = 'omr:usage_history';
    const cKey = 'omr:call_logs';
    const uCur = getCursor(db, uKey);
    const cCur = getCursor(db, cKey);

    /* ---------------- usage_history rows ---------------- */
    const usage = [];
    if (ucols.length) {
      const want = [
        'id', 'provider', 'model', 'connection_id', 'account_key', 'account_label', 'api_key_name',
        'tokens_input', 'tokens_output', 'tokens_cache_read', 'tokens_cache_creation', 'tokens_reasoning',
        'service_tier', 'status', 'success', 'latency_ms', 'ttft_ms', 'error_code', 'timestamp',
        'combo_strategy', 'endpoint', 'provider_credits', 'provider_cost_usd',
      ];
      const sel = want.filter((c) => ucols.includes(c)).join(', ');
      const rows = src
        .prepare(`SELECT ${sel} FROM usage_history WHERE id > ? ORDER BY id ASC LIMIT ?`)
        .all(num(uCur.last_id, 0), maxRows);
      for (const r of rows) usage.push(r);
    }

    /* ---------------- call_logs rows ---------------- */
    const calls = [];
    if (ccols.length) {
      const want = [
        'id', 'timestamp', 'method', 'path', 'status', 'model', 'requested_model', 'provider', 'account',
        'connection_id', 'duration', 'tokens_in', 'tokens_out', 'tokens_cache_read', 'tokens_cache_creation',
        'tokens_reasoning', 'tokens_compressed', 'cache_source', 'request_type', 'source_format', 'target_format',
        'api_key_name', 'combo_name', 'correlation_id', 'ttft_ms', 'session_tag', 'client_session_id',
        'reasoning_effort_requested', 'reasoning_effort_upstream', 'usage_provenance',
      ];
      const sel = want.filter((c) => ccols.includes(c)).join(', ');
      const lastTs = cCur.last_id || '';
      const rows = src
        .prepare(
          `SELECT ${sel} FROM call_logs WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp ASC, id ASC LIMIT ?`,
        )
        .all(lastTs, cutoffIso, maxRows);
      const seen = new Set(cCur.extra?.seenAtLast || []);
      for (const r of rows) {
        if (r.timestamp === lastTs && seen.has(r.id)) continue; // already consumed at the boundary timestamp
        calls.push(r);
      }
    }

    /* ---------------- join usage_history <-> call_logs ---------------- */
    const callMatched = new Set();
    const tsMs = (t) => Date.parse(toIso(t) || '') || 0;
    const callsByConn = new Map();
    for (const c of calls) {
      const k = `${c.connection_id || ''}|${String(c.model || '').toLowerCase()}`;
      const a = callsByConn.get(k) || [];
      a.push(c);
      callsByConn.set(k, a);
    }
    const pairOf = new Map(); // usage.id -> call row
    for (const u of usage) {
      const k = `${u.connection_id || ''}|${String(u.model || '').toLowerCase()}`;
      const cands = callsByConn.get(k) || [];
      const ut = tsMs(u.timestamp);
      let best = null;
      let bestScore = Infinity;
      for (const c of cands) {
        if (callMatched.has(c.id)) continue;
        const dt = Math.abs(tsMs(c.timestamp) - ut);
        if (dt > MATCH_WINDOW_MS) continue;
        const tokMismatch =
          (c.tokens_in !== undefined && u.tokens_input !== undefined && num(c.tokens_in) !== num(u.tokens_input) ? 5000 : 0) +
          (c.tokens_out !== undefined && u.tokens_output !== undefined && num(c.tokens_out) !== num(u.tokens_output) ? 5000 : 0);
        const score = dt + tokMismatch;
        if (score < bestScore) {
          best = c;
          bestScore = score;
        }
      }
      if (best && bestScore < 10000) {
        callMatched.add(best.id);
        pairOf.set(u.id, best);
      }
    }

    const mk = (u, c) => {
      const base = u || {};
      const cl = c || {};
      const connectionId = base.connection_id || cl.connection_id || null;
      const conn = connectionId ? conns.get(connectionId) : null;
      const rawModel = base.model || cl.model || cl.requested_model || null;
      const { model_id, effort } = resolveModel(rawModel || 'unknown', known);
      const created = toIso(base.timestamp || cl.timestamp);
      const created_ms = created ? Date.parse(created) : 0;
      const inTok = num(base.tokens_input ?? cl.tokens_in);
      const outTok = num(base.tokens_output ?? cl.tokens_out);
      const cacheRead = num(base.tokens_cache_read ?? cl.tokens_cache_read);
      const cacheWrite = num(base.tokens_cache_creation ?? cl.tokens_cache_creation);
      const reasoning = num(base.tokens_reasoning ?? cl.tokens_reasoning);
      const endpoint = base.endpoint || cl.path || null;
      const dedup_key = c ? `omr:cl:${cl.id}` : `omr:uh:${base.id}`;
      const status = base.status ?? (cl.status !== undefined ? String(cl.status) : null);
      const ok = base.success !== undefined ? !!base.success : cl.status === undefined || (cl.status >= 200 && cl.status < 400);
      const sessionId = cl.client_session_id || cl.session_tag || cl.correlation_id || null;
      const ttft_ms = numOrNull(base.ttft_ms) ?? numOrNull(cl.ttft_ms);
      const latency_ms = numOrNull(base.latency_ms) ?? numOrNull(cl.duration);
      const genMs =
        latency_ms && latency_ms > 0
          ? ttft_ms && latency_ms > ttft_ms
            ? latency_ms - ttft_ms
            : latency_ms
          : 0;
      const { tpot_ms, tok_per_sec } = computeSpeedMetrics(outTok + reasoning, genMs);
      return {
        dedup_key,
        source_tool: 'omniroute',
        created_at: created,
        completed_at: created_ms && latency_ms ? new Date(created_ms + latency_ms).toISOString() : null,
        session_id: sessionId ? `omr:${sessionId}` : null,
        account_id: accountFor(conn, base.account_label || cl.account || base.account_key, connectionId),
        account_email: conn?.email || null,
        model_id,
        raw_model: rawModel,
        provider: base.provider || cl.provider || conn?.provider || null,
        endpoint_mode: modeFromEndpoint(endpoint, cl.path),
        endpoint,
        input_tokens: inTok,
        output_tokens: outTok,
        cache_read_tokens: cacheRead,
        cache_write_tokens: cacheWrite,
        reasoning_tokens: reasoning,
        compressed_tokens: numOrNull(cl.tokens_compressed),
        context_tokens: inTok + cacheRead,
        context_window: ctxWindow.get(model_id) ?? null,
        ttft_ms,
        tpot_ms,
        tok_per_sec,
        latency_ms,
        provider_cost_usd: numOrNull(base.provider_cost_usd),
        combo_name: cl.combo_name || null,
        status: ok ? 'ok' : `error${status ? ':' + status : ''}`,
        era: milestoneMs === null || created_ms >= milestoneMs ? 'live' : 'pre_milestone',
        workspace: null,
        effort: effort || cl.reasoning_effort_upstream || cl.reasoning_effort_requested || null,
        meta_json: JSON.stringify({
          connection_id: connectionId,
          connection_group: conn?.group || undefined,
          service_tier: base.service_tier || undefined,
          combo_strategy: base.combo_strategy && base.combo_strategy !== 'direct' ? base.combo_strategy : undefined,
          source_format: cl.source_format || undefined,
          target_format: cl.target_format || undefined,
          cache_source: cl.cache_source || undefined,
          usage_provenance: cl.usage_provenance || undefined,
          requested_model: cl.requested_model && cl.requested_model !== rawModel ? cl.requested_model : undefined,
          id_hint: endpointModeFromId(cl.id) || undefined,
          provider_credits: numOrNull(base.provider_credits) ?? undefined,
          joined: !!(u && c),
        }),
      };
    };

    for (const u of usage) res.events.push(mk(u, pairOf.get(u.id) || null));
    for (const c of calls) if (!callMatched.has(c.id)) res.events.push(mk(null, c));

    if (usage.length) {
      res.cursorUpdates.push({ key: uKey, last_id: String(usage[usage.length - 1].id), line_no: usage.length });
    }
    if (calls.length) {
      const maxTs = calls[calls.length - 1].timestamp;
      const seenAtLast = calls.filter((c) => c.timestamp === maxTs).map((c) => c.id);
      res.cursorUpdates.push({ key: cKey, last_id: maxTs, extra: { seenAtLast } });
    }
    res.counts.omniroute = res.events.length;
    res.notes.push(`omniroute: usage_history +${usage.length}, call_logs +${calls.length} (${callMatched.size} joined), connections ${conns.size}`);

    /* ---------------- quotas ---------------- */
    const quotas = [];
    const now = new Date().toISOString();
    if (hasTable(src, 'provider_quota_state')) {
      for (const r of src
        .prepare('SELECT connection_id, model, tokens_used, token_limit, window_start, window_reset, updated_at FROM provider_quota_state LIMIT 50000')
        .all()) {
        const conn = conns.get(r.connection_id);
        const limit = num(r.token_limit);
        quotas.push({
          captured_at: toIso(r.updated_at) || now,
          source_tool: 'omniroute',
          account_id: accountFor(conn, null, r.connection_id),
          provider: conn?.provider || null,
          model_id: resolveModel(r.model, known).model_id,
          window_key: 'provider_quota_state',
          tokens_used: num(r.tokens_used),
          token_limit: limit,
          remaining_pct: limit > 0 ? Math.max(0, Math.min(100, (1 - num(r.tokens_used) / limit) * 100)) : null,
          window_start: toIso(r.window_start),
          window_reset: toIso(r.window_reset),
          is_exhausted: limit > 0 && num(r.tokens_used) >= limit ? 1 : 0,
          raw_json: JSON.stringify({ connection_id: r.connection_id }),
        });
      }
    }
    if (hasTable(src, 'quota_snapshots')) {
      // latest snapshot per (connection, window)
      for (const r of src
        .prepare(
          `SELECT q.provider, q.connection_id, q.window_key, q.remaining_percentage, q.is_exhausted, q.next_reset_at, q.window_duration_ms, q.created_at
             FROM quota_snapshots q
             JOIN (SELECT connection_id, window_key, MAX(id) mid FROM quota_snapshots GROUP BY connection_id, window_key) m ON m.mid = q.id
             LIMIT 50000`,
        )
        .all()) {
        const conn = conns.get(r.connection_id);
        quotas.push({
          captured_at: toIso(r.created_at) || now,
          source_tool: 'omniroute',
          account_id: accountFor(conn, null, r.connection_id),
          provider: r.provider || conn?.provider || null,
          model_id: null,
          window_key: r.window_key,
          tokens_used: null,
          token_limit: null,
          remaining_pct: numOrNull(r.remaining_percentage),
          window_start: null,
          window_reset: toIso(r.next_reset_at),
          is_exhausted: r.is_exhausted ? 1 : 0,
          raw_json: JSON.stringify({ connection_id: r.connection_id, window_duration_ms: r.window_duration_ms }),
        });
      }
    }
    if (quotas.length) {
      const hash = sha1(JSON.stringify(quotas.map(({ captured_at, ...rest }) => rest)));
      const qKey = 'omr:quota_hash';
      if (getCursor(db, qKey).last_id !== hash) {
        res.quotas.push(...quotas);
        res.cursorUpdates.push({ key: qKey, last_id: hash });
      }
    }
  } catch (e) {
    res.errors.push(`omniroute: ${e.message}`);
  } finally {
    try {
      src.close();
    } catch (err) {
      debugLog(err, 'omniroute:close');
    }
  }
  return res;
}
