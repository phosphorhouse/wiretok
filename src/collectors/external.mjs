/**
 * External tool collectors — read-only & incremental.
 *   1) Claude Code   ~/.claude/projects/**\/*.jsonl            (assistant `message.usage` + user/turn_duration timing)
 *   2) Codex         ~/.codex/sessions/**\/*.jsonl             (event_msg token_count + user/reasoning/message timing)
 *   3) OpenCode      ~/.local/share/opencode/opencode.db      (message+part AND session_message+session_v2; readOnly)
 *   4) 9Router       ~/.9router (JSONL / SQLite, best-effort) + <DATA_DIR>/ingest_events.jsonl
 *
 * Token semantics emitted (all sources): input_tokens = UNCACHED input, cache_read_tokens/cache_write_tokens separate,
 * output_tokens EXCLUDES reasoning_tokens, context_tokens = input + cache_read.
 *
 * NEVER touches: ~/.claude/.credentials.json, ~/.codex/auth.json, opencode auth.json / `credential` / `account` /
 * `control_account` tables.
 */
import path from 'node:path';
import { getLocalSourcePaths, INGEST_EVENTS_LOG, SEED_MODELS, SOURCE_TOOLS, ENDPOINT_MODES } from '../contracts.mjs';
import {
  computeSpeedMetrics,
  debugLog,
  emptyResult,
  endpointModeFromId,
  exists,
  getCursor,
  getMeta,
  hasTable,
  isBlockedPath,
  knownModelSet,
  mergeIntervalsMs,
  num,
  numOrNull,
  openReadOnly,
  parseJsonSafe,
  readJsonlIncremental,
  resolveModel,
  sha1,
  tableColumns,
  toIso,
  walkFiles,
} from './util.mjs';

const OPENCODE_PART_CHUNK = 400;

function ctxMap(db) {
  const m = new Map(SEED_MODELS.map((x) => [x.model_id, x.context_window]));
  try {
    if (db) {
      for (const r of db.prepare('SELECT model_id, context_window FROM models LIMIT 50000').all()) {
        if (r.context_window) m.set(r.model_id, r.context_window);
      }
    }
  } catch (err) {
    debugLog(err, 'ctxMap');
  }
  return m;
}

function mkEra(createdIso, milestoneMs) {
  const t = createdIso ? Date.parse(createdIso) : 0;
  return milestoneMs === null || t >= milestoneMs ? 'live' : 'pre_milestone';
}

function milestoneOf(db, opts) {
  const iso = opts.milestoneAt || getMeta(db, 'milestone_at') || null;
  return iso ? Date.parse(iso) : null;
}

function parseMs(val) {
  const iso = toIso(val);
  if (!iso) return null;
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? ms : null;
}

/* ================================================================== */
/* Claude Code                                                         */
/* ================================================================== */
export function collectClaudeCode(db, opts = {}) {
  const res = emptyResult('claude-code');
  const root = opts.claudeProjectsDir || getLocalSourcePaths().claudeProjectsDir;
  if (!exists(root)) {
    res.notes.push('claude-code: ~/.claude/projects not found');
    return res;
  }
  const known = knownModelSet(db);
  const ctx = ctxMap(db);
  const milestoneMs = milestoneOf(db, opts);
  let files = 0;
  let changed = 0;
  for (const file of walkFiles(root, (p, n) => n.endsWith('.jsonl'), 6)) {
    try {
      files++;
      const key = `cc:${path.relative(root, file)}`;
      const cur = getCursor(db, key);
      const r = readJsonlIncremental(file, cur);
      if (!r || (!r.lines.length && !r.reset)) continue;
      changed++;
      const st = r.reset ? {} : { ...(cur.extra || {}) };
      const byMsg = new Map(); // streaming duplicates: keep the last (final) usage per message id
      const timingByMsg = new Map(); // track first reasoning/text chunk timestamps per message id
      let lastMsgKey = null;

      for (const ln of r.lines) {
        const txt = ln.text;
        if (!txt) continue;
        const mightMatter =
          txt.includes('"usage"') ||
          txt.includes('"user"') ||
          txt.includes('"turn_duration"') ||
          txt.includes('"tool_result"');
        if (!mightMatter) continue;
        const o = parseJsonSafe(txt);
        if (!o || typeof o !== 'object') continue;

        if (o.type === 'user') {
          const tsMs = parseMs(o.timestamp);
          if (tsMs) st.lastUserMs = tsMs;
          lastMsgKey = null;
          continue;
        }

        if (o.type === 'system' && o.subtype === 'turn_duration') {
          const durMs = numOrNull(o.durationMs ?? o.duration_ms);
          if (durMs && durMs > 0 && durMs <= 3600000 && lastMsgKey && byMsg.has(lastMsgKey)) {
            const ev = byMsg.get(lastMsgKey);
            ev.latency_ms = Math.round(durMs);
            const genTokens = ev.output_tokens + ev.reasoning_tokens;
            const { tpot_ms, tok_per_sec } = computeSpeedMetrics(genTokens, ev.latency_ms);
            ev.tpot_ms = tpot_ms;
            ev.tok_per_sec = tok_per_sec;
          }
          continue;
        }

        const msg = o?.message;
        const u = msg?.usage;
        if (!u || o.type !== 'assistant') continue;
        if (!msg.model || msg.model === '<synthetic>') continue;
        const sessionId = o.sessionId || path.basename(file, '.jsonl');
        const mid = msg.id || o.uuid || `${sessionId}:${ln.lineNo}`;
        const msgKey = `${sessionId}:${mid}`;
        const { model_id, effort } = resolveModel(msg.model, known);
        const cc = u.cache_creation || {};
        const w5 = num(u.claude_cache_creation_5_m_tokens ?? cc.ephemeral_5m_input_tokens);
        const w1 = num(u.claude_cache_creation_1_h_tokens ?? cc.ephemeral_1h_input_tokens);
        const cacheWrite = num(u.cache_creation_input_tokens) || w5 + w1;
        const inTok = num(u.input_tokens);
        const outTok = num(u.output_tokens);
        const cacheRead = num(u.cache_read_input_tokens);
        const created = toIso(o.timestamp);
        const tsMs = created ? Date.parse(created) : null;

        let tInfo = timingByMsg.get(msgKey);
        if (!tInfo) {
          tInfo = {
            reqStart: Number.isFinite(st.lastUserMs) ? st.lastUserMs : null,
            firstReasonMs: null,
            firstTextMs: null,
          };
          timingByMsg.set(msgKey, tInfo);
        }
        if (tsMs && Array.isArray(msg.content)) {
          for (const block of msg.content) {
            if (!block || typeof block !== 'object') continue;
            if ((block.type === 'thinking' || block.type === 'redacted_thinking') && !tInfo.firstReasonMs) {
              tInfo.firstReasonMs = tsMs;
            } else if (block.type === 'text' && !tInfo.firstTextMs) {
              tInfo.firstTextMs = tsMs;
            }
          }
        }

        const reqStart =
          tInfo.reqStart && tsMs && tsMs > tInfo.reqStart && tsMs - tInfo.reqStart <= 600000
            ? tInfo.reqStart
            : null;
        const latency_ms = reqStart && tsMs ? Math.round(tsMs - reqStart) : null;
        const ttfr_ms =
          reqStart && tInfo.firstReasonMs && tInfo.firstReasonMs >= reqStart
            ? Math.max(1, Math.round(tInfo.firstReasonMs - reqStart))
            : null;
        const ttfa_ms =
          reqStart && tInfo.firstTextMs && tInfo.firstTextMs >= reqStart
            ? Math.max(1, Math.round(tInfo.firstTextMs - reqStart))
            : null;
        // Keep ttft_ms = null when first-token timestamp isn't cleanly recorded
        const ttft_ms = null;
        const { tpot_ms, tok_per_sec } = computeSpeedMetrics(outTok, latency_ms || 0);

        byMsg.set(msgKey, {
          dedup_key: `cc:${sessionId}:${mid}`,
          source_tool: 'claude-code',
          created_at: created,
          completed_at: latency_ms && tsMs ? created : null,
          session_id: sessionId,
          account_id: null,
          model_id,
          raw_model: msg.model,
          provider: null,
          endpoint_mode: endpointModeFromId(msg.id) || 'messages',
          endpoint: null,
          input_tokens: inTok,
          output_tokens: outTok,
          cache_read_tokens: cacheRead,
          cache_write_tokens: cacheWrite,
          cache_write_5m_tokens: w5,
          cache_write_1h_tokens: w1,
          reasoning_tokens: 0,
          context_tokens: inTok + cacheRead,
          context_window: ctx.get(model_id) ?? null,
          ttft_ms,
          ttfr_ms,
          ttfa_ms,
          tpot_ms,
          tok_per_sec,
          latency_ms,
          status: 'ok',
          era: mkEra(created, milestoneMs),
          workspace: o.cwd || null,
          parent_session_id: null,
          effort: effort || null,
          meta_json: JSON.stringify({
            message_id: msg.id || undefined,
            request_id: o.requestId || undefined,
            service_tier: u.service_tier || undefined,
            is_sidechain: o.isSidechain || undefined,
            web_search_requests: u.server_tool_use?.web_search_requests || undefined,
          }),
        });
        lastMsgKey = msgKey;
      }
      const evs = [...byMsg.values()].filter(
        (e) => e.input_tokens + e.output_tokens + e.cache_read_tokens + e.cache_write_tokens > 0,
      );
      res.events.push(...evs);
      res.cursorUpdates.push({
        key,
        byte_offset: r.newOffset,
        line_no: r.newLineNo,
        mtime_ms: Math.round(r.mtimeMs),
        size: r.size,
        extra: st,
      });
    } catch (e) {
      res.errors.push(`claude-code[${path.basename(file)}]: ${e.message}`);
    }
  }
  res.counts['claude-code'] = res.events.length;
  res.notes.push(`claude-code: ${files} files, ${changed} changed, +${res.events.length} requests`);
  return res;
}

/* ================================================================== */
/* Codex                                                               */
/* ================================================================== */
export function collectCodex(db, opts = {}) {
  const res = emptyResult('codex');
  const root = opts.codexSessionsDir || getLocalSourcePaths().codexSessionsDir;
  if (!exists(root)) {
    res.notes.push('codex: ~/.codex/sessions not found');
    return res;
  }
  const known = knownModelSet(db);
  const ctx = ctxMap(db);
  const milestoneMs = milestoneOf(db, opts);
  let files = 0;
  let changed = 0;
  for (const file of walkFiles(root, (p, n) => n.endsWith('.jsonl'), 6)) {
    try {
      files++;
      const key = `codex:${path.relative(root, file)}`;
      const cur = getCursor(db, key);
      const r = readJsonlIncremental(file, cur);
      if (!r || (!r.lines.length && !r.reset)) continue;
      changed++;
      const st = r.reset ? {} : { ...(cur.extra || {}) };
      for (const ln of r.lines) {
        const t = ln.text;
        if (!t) continue;
        const mightMatter =
          t.includes('"session_meta"') ||
          t.includes('"turn_context"') ||
          t.includes('"token_count"') ||
          t.includes('"user_message"') ||
          t.includes('"task_started"') ||
          t.includes('"agent_reasoning"') ||
          t.includes('"agent_message"') ||
          t.includes('"function_call_output"') ||
          t.includes('"custom_tool_call_output"') ||
          t.includes('"response_item"');
        if (!mightMatter) continue;
        const o = parseJsonSafe(t);
        if (!o) continue;
        const p = o.payload || {};
        const tsMs = parseMs(o.timestamp);

        if (o.type === 'session_meta') {
          st.session_id = p.id || st.session_id;
          st.cwd = p.cwd || st.cwd;
          st.originator = p.originator || st.originator;
          st.model_provider = p.model_provider || st.model_provider;
          st.parent = p.forked_from_id || p.parent_thread_id || st.parent || null;
          continue;
        }
        if (o.type === 'turn_context') {
          st.model = p.model || st.model;
          st.effort = p.effort || p.reasoning_effort || p.collaboration_mode?.settings?.reasoning_effort || st.effort || null;
          st.cwd = p.cwd || st.cwd;
          continue;
        }
        if (
          o.type === 'response_item' &&
          ((p.type === 'message' && p.role === 'user') ||
            p.type === 'function_call_output' ||
            p.type === 'custom_tool_call_output')
        ) {
          if (tsMs) {
            st.turnStartMs = tsMs;
            st.firstReasonMs = null;
            st.firstMsgMs = null;
          }
          continue;
        }
        if (o.type === 'event_msg' && (p.type === 'user_message' || p.type === 'task_started')) {
          if (tsMs) {
            st.turnStartMs = tsMs;
            st.firstReasonMs = null;
            st.firstMsgMs = null;
          }
          continue;
        }
        if (o.type === 'event_msg' && p.type === 'agent_reasoning') {
          if (tsMs && st.turnStartMs && tsMs >= st.turnStartMs && !st.firstReasonMs) {
            st.firstReasonMs = tsMs;
          }
          continue;
        }
        if (o.type === 'event_msg' && p.type === 'agent_message') {
          if (tsMs && st.turnStartMs && tsMs >= st.turnStartMs && !st.firstMsgMs) {
            st.firstMsgMs = tsMs;
          }
          continue;
        }
        if (o.type === 'event_msg' && p.type === 'token_count' && p.info) {
          const last = p.info.last_token_usage;
          const total = p.info.total_token_usage;
          if (!last) continue;
          const totalTokens = num(total?.total_tokens, -1);
          if (totalTokens >= 0 && totalTokens === st.last_total) continue; // Codex repeats identical token_count frames
          if (totalTokens >= 0) st.last_total = totalTokens;
          const cached = num(last.cached_input_tokens);
          const rawIn = num(last.input_tokens);
          const reasoning = num(last.reasoning_output_tokens);
          const rawOut = num(last.output_tokens);
          const inTok = Math.max(0, rawIn - cached);
          const outTok = Math.max(0, rawOut - reasoning);
          const { model_id, effort } = resolveModel(st.model || 'unknown', known);
          const created = toIso(o.timestamp);
          const sid = st.session_id || path.basename(file, '.jsonl');

          const reqStart =
            st.turnStartMs && tsMs && tsMs > st.turnStartMs && tsMs - st.turnStartMs <= 600000
              ? st.turnStartMs
              : null;
          const latency_ms = reqStart && tsMs ? Math.round(tsMs - reqStart) : null;
          const ttfr_ms =
            reqStart && st.firstReasonMs && st.firstReasonMs >= reqStart
              ? Math.max(1, Math.round(st.firstReasonMs - reqStart))
              : null;
          const ttfa_ms =
            reqStart && st.firstMsgMs && st.firstMsgMs >= reqStart
              ? Math.max(1, Math.round(st.firstMsgMs - reqStart))
              : null;
          // Do not fabricate ttft_ms when first-token timestamp isn't recorded cleanly
          const ttft_ms = null;
          const { tpot_ms, tok_per_sec } = computeSpeedMetrics(outTok + reasoning, latency_ms || 0);

          res.events.push({
            dedup_key: `codex:${sid}:${ln.lineNo}`,
            source_tool: 'codex',
            created_at: created,
            completed_at: latency_ms && created ? created : null,
            session_id: sid,
            account_id: null,
            model_id,
            raw_model: st.model || null,
            provider: st.model_provider || 'openai',
            endpoint_mode: 'responses',
            endpoint: null,
            input_tokens: inTok,
            output_tokens: outTok,
            cache_read_tokens: cached,
            cache_write_tokens: num(last.cache_write_input_tokens),
            reasoning_tokens: reasoning,
            context_tokens: inTok + cached,
            context_window: numOrNull(p.info.model_context_window) ?? ctx.get(model_id) ?? null,
            ttft_ms,
            ttfr_ms,
            ttfa_ms,
            tpot_ms,
            tok_per_sec,
            latency_ms,
            status: 'ok',
            era: mkEra(created, milestoneMs),
            workspace: st.cwd || null,
            parent_session_id: st.parent || null,
            effort: effort || st.effort || null,
            meta_json: JSON.stringify({
              originator: st.originator || undefined,
              total_tokens_so_far: totalTokens >= 0 ? totalTokens : undefined,
            }),
          });
          if (tsMs) st.turnStartMs = tsMs;
          st.firstReasonMs = null;
          st.firstMsgMs = null;
        }
      }
      res.cursorUpdates.push({ key, byte_offset: r.newOffset, line_no: r.newLineNo, mtime_ms: Math.round(r.mtimeMs), size: r.size, extra: st });
    } catch (e) {
      res.errors.push(`codex[${path.basename(file)}]: ${e.message}`);
    }
  }
  res.counts.codex = res.events.length;
  res.notes.push(`codex: ${files} files, ${changed} changed, +${res.events.length} requests`);
  return res;
}

/* ================================================================== */
/* OpenCode (Dual-Schema: message+part AND session_message+session_v2) */
/* ================================================================== */
export function findOpencodeDb(dirs) {
  for (const d of dirs) {
    const f = path.join(d, 'opencode.db');
    if (exists(f)) return f;
  }
  return null;
}

function loadOpencodePartTimings(src, messageIds) {
  const byMsg = new Map();
  if (!hasTable(src, 'part') || !messageIds.length) return byMsg;
  for (let i = 0; i < messageIds.length; i += OPENCODE_PART_CHUNK) {
    const chunk = messageIds.slice(i, i + OPENCODE_PART_CHUNK);
    const placeholders = chunk.map(() => '?').join(',');
    const partRows = src
      .prepare(
        `SELECT message_id, json_extract(data, '$.type') AS ptype, json_extract(data, '$.time.start') AS t_start, json_extract(data, '$.time.end') AS t_end FROM part WHERE message_id IN (${placeholders}) AND json_extract(data, '$.type') IN ('reasoning', 'text') LIMIT 50000`,
      )
      .all(...chunk);
    for (const pr of partRows) {
      let bucket = byMsg.get(pr.message_id);
      if (!bucket) {
        bucket = { reasoning: [], text: [] };
        byMsg.set(pr.message_id, bucket);
      }
      const entry = { start: numOrNull(pr.t_start), end: numOrNull(pr.t_end) };
      if (pr.ptype === 'reasoning') bucket.reasoning.push(entry);
      else if (pr.ptype === 'text') bucket.text.push(entry);
    }
  }
  return byMsg;
}

function computeOpencodeLegacyTiming(reqStart, completedMs, outTok, reasoning, parts) {
  let firstReason = null;
  let firstText = null;
  const intervals = [];

  if (parts) {
    for (const p of parts.reasoning) {
      if (p.start !== null && reqStart > 0 && p.start >= reqStart) {
        if (firstReason === null || p.start < firstReason) firstReason = p.start;
      }
      if (p.start !== null && p.end !== null && p.end > p.start) {
        intervals.push([p.start, p.end]);
      }
    }
    for (const p of parts.text) {
      if (p.start !== null && reqStart > 0 && p.start >= reqStart) {
        if (firstText === null || p.start < firstText) firstText = p.start;
      }
      if (p.start !== null && p.end !== null && p.end > p.start) {
        intervals.push([p.start, p.end]);
      }
    }
  }

  let firstTok = null;
  if (firstReason !== null && firstText !== null) firstTok = Math.min(firstReason, firstText);
  else firstTok = firstReason ?? firstText;

  const ttfr_ms = firstReason !== null && reqStart > 0 ? Math.max(1, Math.round(firstReason - reqStart)) : null;
  const ttfa_ms = firstText !== null && reqStart > 0 ? Math.max(1, Math.round(firstText - reqStart)) : null;
  const ttft_ms = firstTok !== null && reqStart > 0 ? Math.max(1, Math.round(firstTok - reqStart)) : null;

  const genMs = mergeIntervalsMs(intervals);
  const { tpot_ms, tok_per_sec } = computeSpeedMetrics(outTok + reasoning, genMs);
  const latency_ms =
    completedMs !== null && reqStart > 0 && completedMs >= reqStart
      ? Math.max(0, Math.round(completedMs - reqStart))
      : null;

  return { ttft_ms, ttfr_ms, ttfa_ms, tpot_ms, tok_per_sec, latency_ms };
}

function computeOpencodeV2Timing(d, rowTimeCreated, outTok, reasoning) {
  const reqStart = num(d.time?.created) || num(rowTimeCreated);
  const streamEnd = numOrNull(d.time?.streamed ?? d.time?.completed);
  let firstReason = null;
  let firstText = null;

  if (Array.isArray(d.content)) {
    for (const item of d.content) {
      if (!item || typeof item !== 'object') continue;
      const itemCreated = numOrNull(item.time?.created);
      if (itemCreated === null || (reqStart > 0 && itemCreated < reqStart)) continue;
      if (item.type === 'reasoning') {
        if (firstReason === null || itemCreated < firstReason) firstReason = itemCreated;
      } else if (item.type === 'text') {
        if (firstText === null || itemCreated < firstText) firstText = itemCreated;
      }
    }
  }

  let firstTok = null;
  if (firstReason !== null && firstText !== null) firstTok = Math.min(firstReason, firstText);
  else firstTok = firstReason ?? firstText;

  const ttfr_ms = firstReason !== null && reqStart > 0 ? Math.max(1, Math.round(firstReason - reqStart)) : null;
  const ttfa_ms = firstText !== null && reqStart > 0 ? Math.max(1, Math.round(firstText - reqStart)) : null;
  const ttft_ms = firstTok !== null && reqStart > 0 ? Math.max(1, Math.round(firstTok - reqStart)) : null;

  let genMs = 0;
  if (streamEnd !== null) {
    if (firstReason !== null && streamEnd > firstReason) genMs = streamEnd - firstReason;
    else if (firstText !== null && streamEnd > firstText) genMs = streamEnd - firstText;
    else if (reqStart > 0 && streamEnd > reqStart) genMs = streamEnd - reqStart;
  }
  const { tpot_ms, tok_per_sec } = computeSpeedMetrics(outTok + reasoning, genMs);
  const latency_ms =
    streamEnd !== null && reqStart > 0 && streamEnd >= reqStart
      ? Math.max(0, Math.round(streamEnd - reqStart))
      : null;

  return { ttft_ms, ttfr_ms, ttfa_ms, tpot_ms, tok_per_sec, latency_ms, streamEnd };
}

export function collectOpencode(db, opts = {}) {
  const res = emptyResult('opencode');
  const file = opts.opencodeDb || findOpencodeDb(getLocalSourcePaths().opencodeDirs);
  if (!file) {
    res.notes.push('opencode: opencode.db not found');
    return res;
  }
  const src = openReadOnly(file);
  if (!src) {
    res.errors.push('opencode: could not open opencode.db read-only');
    return res;
  }
  try {
    const known = knownModelSet(db);
    const ctx = ctxMap(db);
    const milestoneMs = milestoneOf(db, opts);
    const dirTag = path.basename(path.dirname(file));
    const maxRows = opts.maxRows ?? 500000;
    const emittedDedupKeys = new Set();
    let legacyChanged = 0;
    let v2Changed = 0;

    /* ---- Pass 1: Legacy `message` + `part` schema ---- */
    if (hasTable(src, 'message')) {
      const key = `opencode:${dirTag}`;
      const cur = getCursor(db, key);
      const last = num(cur.last_id, 0);
      const msgCols = tableColumns(src, 'message');
      const timeCol = msgCols.includes('time_updated') ? 'time_updated' : 'time_created';
      const rows = src
        .prepare(
          `SELECT id, session_id, time_created, ${timeCol} AS time_updated, data FROM message WHERE ${timeCol} > ? ORDER BY ${timeCol} ASC, id ASC LIMIT ?`,
        )
        .all(last, maxRows);
      legacyChanged = rows.length;

      // session metadata: ONLY these columns (never the credential/account tables)
      const sessions = new Map();
      if (hasTable(src, 'session')) {
        const sessCols = tableColumns(src, 'session');
        const sel = ['id', 'parent_id', 'directory', 'title'].filter((c) => sessCols.includes(c)).join(', ');
        if (sel) {
          for (const s of src.prepare(`SELECT ${sel} FROM session LIMIT 50000`).all()) sessions.set(s.id, s);
        }
      }

      const parsedRows = [];
      const assistantIds = [];
      let maxUpdated = last;
      for (const m of rows) {
        maxUpdated = Math.max(maxUpdated, num(m.time_updated));
        const d = parseJsonSafe(m.data);
        if (!d || d.role !== 'assistant') continue;
        parsedRows.push({ m, d });
        assistantIds.push(m.id);
      }

      const partTimings = loadOpencodePartTimings(src, assistantIds);

      for (const { m, d } of parsedRows) {
        const tk = d.tokens || {};
        const inTok = num(tk.input);
        const outTok = num(tk.output);
        const reasoning = num(tk.reasoning);
        const cr = num(tk.cache?.read);
        const cw = num(tk.cache?.write);
        if (inTok + outTok + reasoning + cr + cw <= 0) continue;
        const completed = d.time?.completed;
        if (!completed && !(inTok + outTok > 0)) continue;
        const rawModel = d.modelID || d.model?.modelID || d.model?.id || null;
        const { model_id, effort } = resolveModel(rawModel || 'unknown', known);
        const reqStart = num(d.time?.created) || num(m.time_created);
        const created = toIso(reqStart || m.time_created);
        const completedIso = toIso(completed);
        const sess = sessions.get(m.session_id) || {};
        const timing = computeOpencodeLegacyTiming(reqStart, numOrNull(completed), outTok, reasoning, partTimings.get(m.id));
        const dedup_key = `opencode:${m.id}`;
        emittedDedupKeys.add(dedup_key);

        res.events.push({
          dedup_key,
          source_tool: 'opencode',
          created_at: created,
          completed_at: completedIso,
          session_id: m.session_id,
          account_id: d.providerID ? `opencode:${d.providerID}` : null,
          model_id,
          raw_model: rawModel,
          provider: d.providerID || null,
          endpoint_mode: 'unknown',
          endpoint: null,
          input_tokens: inTok,
          output_tokens: outTok,
          cache_read_tokens: cr,
          cache_write_tokens: cw,
          reasoning_tokens: reasoning,
          context_tokens: inTok + cr,
          context_window: ctx.get(model_id) ?? null,
          ttft_ms: timing.ttft_ms,
          ttfr_ms: timing.ttfr_ms,
          ttfa_ms: timing.ttfa_ms,
          tpot_ms: timing.tpot_ms,
          tok_per_sec: timing.tok_per_sec,
          latency_ms: timing.latency_ms,
          reported_cost_usd: numOrNull(d.cost),
          status: d.error ? 'error' : 'ok',
          era: mkEra(created, milestoneMs),
          workspace: d.path?.cwd || sess.directory || null,
          title: sess.title || null,
          parent_session_id: sess.parent_id || null,
          agent_name: d.agent || d.mode || null,
          effort: d.variant || effort || null,
          meta_json: JSON.stringify({ finish: d.finish || undefined, error: d.error?.name || undefined, schema: 'v1' }),
        });
      }
      if (rows.length) res.cursorUpdates.push({ key, last_id: String(maxUpdated), line_no: rows.length });
    }

    /* ---- Pass 2: OpenCode v2 `session_message` + `session_v2` schema ---- */
    if (hasTable(src, 'session_message')) {
      const keyV2 = `opencode_v2:${dirTag}`;
      const curV2 = getCursor(db, keyV2);
      const lastV2 = num(curV2.last_id, 0);
      const smCols = tableColumns(src, 'session_message');
      const timeColV2 = smCols.includes('time_updated') ? 'time_updated' : 'time_created';
      const hasSessV2 = hasTable(src, 'session_v2');
      const svCols = hasSessV2 ? tableColumns(src, 'session_v2') : [];

      const selectParts = [
        'sm.id',
        'sm.session_id',
        'sm.type',
        'sm.time_created',
        `sm.${timeColV2} AS time_updated`,
        'sm.data',
      ];
      if (hasSessV2) {
        if (svCols.includes('title')) selectParts.push('sv.title AS sess_title');
        if (svCols.includes('directory')) selectParts.push('sv.directory AS sess_directory');
        if (svCols.includes('parent_id')) selectParts.push('sv.parent_id AS sess_parent_id');
      }
      const joinSql = hasSessV2 ? 'LEFT JOIN session_v2 sv ON sv.id = sm.session_id ' : '';
      const v2Rows = src
        .prepare(
          `SELECT ${selectParts.join(', ')} FROM session_message sm ${joinSql}WHERE sm.type IN ('assistant', 'compaction') AND sm.${timeColV2} > ? ORDER BY sm.${timeColV2} ASC, sm.id ASC LIMIT ?`,
        )
        .all(lastV2, maxRows);
      v2Changed = v2Rows.length;

      let maxUpdatedV2 = lastV2;
      for (const sm of v2Rows) {
        maxUpdatedV2 = Math.max(maxUpdatedV2, num(sm.time_updated));
        const dedup_key = `opencode:${sm.id}`;
        if (emittedDedupKeys.has(dedup_key)) continue;
        const d = parseJsonSafe(sm.data);
        if (!d || typeof d !== 'object') continue;
        const tk = d.tokens || {};
        const inTok = num(tk.input);
        const outTok = num(tk.output);
        const reasoning = num(tk.reasoning);
        const cr = num(tk.cache?.read);
        const cw = num(tk.cache?.write);
        if (inTok + outTok + reasoning + cr + cw <= 0) continue;

        const rawModel = d.model?.id || d.modelID || d.model?.modelID || null;
        const provider = d.model?.providerID || d.providerID || null;
        const variant = d.model?.variant || d.variant || null;
        const { model_id, effort } = resolveModel(rawModel || 'unknown', known);
        const timing = computeOpencodeV2Timing(d, sm.time_created, outTok, reasoning);
        const created = toIso(d.time?.created ?? sm.time_created);
        const completedIso = toIso(timing.streamEnd);
        emittedDedupKeys.add(dedup_key);

        res.events.push({
          dedup_key,
          source_tool: 'opencode',
          created_at: created,
          completed_at: completedIso,
          session_id: sm.session_id,
          account_id: provider ? `opencode:${provider}` : null,
          model_id,
          raw_model: rawModel,
          provider,
          endpoint_mode: 'unknown',
          endpoint: null,
          input_tokens: inTok,
          output_tokens: outTok,
          cache_read_tokens: cr,
          cache_write_tokens: cw,
          reasoning_tokens: reasoning,
          context_tokens: inTok + cr,
          context_window: ctx.get(model_id) ?? null,
          ttft_ms: timing.ttft_ms,
          ttfr_ms: timing.ttfr_ms,
          ttfa_ms: timing.ttfa_ms,
          tpot_ms: timing.tpot_ms,
          tok_per_sec: timing.tok_per_sec,
          latency_ms: timing.latency_ms,
          reported_cost_usd: numOrNull(d.cost),
          status: d.error ? 'error' : 'ok',
          era: mkEra(created, milestoneMs),
          workspace: d.path?.cwd || sm.sess_directory || null,
          title: sm.sess_title || null,
          parent_session_id: sm.sess_parent_id || null,
          agent_name: d.agent || d.mode || (sm.type === 'compaction' ? 'compaction' : null),
          effort: variant || effort || null,
          meta_json: JSON.stringify({
            finish: d.finish || undefined,
            error: d.error?.name || undefined,
            msg_type: sm.type || undefined,
            schema: 'v2',
          }),
        });
      }
      if (v2Rows.length) res.cursorUpdates.push({ key: keyV2, last_id: String(maxUpdatedV2), line_no: v2Rows.length });
    }

    /* ---- Pass 3: One-time historical timing backfill for pre-v0.2 OpenCode rows ---- */
    const bfKey = `opencode_timing_v02b:${dirTag}`;
    if (db && getCursor(db, bfKey).last_id !== 'done') {
      try {
        const missingRows = db
          .prepare(
            "SELECT dedup_key FROM requests WHERE source_tool = 'opencode' AND ttft_ms IS NULL LIMIT 50000",
          )
          .all();
        const missingIds = [];
        for (const r of missingRows) {
          if (typeof r.dedup_key !== 'string' || !r.dedup_key.startsWith('opencode:')) continue;
          if (emittedDedupKeys.has(r.dedup_key)) continue;
          missingIds.push(r.dedup_key.slice('opencode:'.length));
        }

        const matchedIds = new Set();
        if (missingIds.length && hasTable(src, 'message')) {
          const legacyCandidates = [];
          for (let i = 0; i < missingIds.length; i += OPENCODE_PART_CHUNK) {
            const chunk = missingIds.slice(i, i + OPENCODE_PART_CHUNK);
            const placeholders = chunk.map(() => '?').join(',');
            const found = src
              .prepare(`SELECT id, time_created, data FROM message WHERE id IN (${placeholders}) LIMIT 50000`)
              .all(...chunk);
            for (const f of found) legacyCandidates.push(f);
          }
          const partMap = loadOpencodePartTimings(src, legacyCandidates.map((r) => r.id));
          for (const m of legacyCandidates) {
            const d = parseJsonSafe(m.data);
            if (!d || d.role !== 'assistant') continue;
            matchedIds.add(m.id);
            const tk = d.tokens || {};
            const reqStart = num(d.time?.created) || num(m.time_created);
            const timing = computeOpencodeLegacyTiming(
              reqStart,
              numOrNull(d.time?.completed),
              num(tk.output),
              num(tk.reasoning),
              partMap.get(m.id),
            );
            if (
              timing.ttft_ms !== null ||
              timing.ttfr_ms !== null ||
              timing.ttfa_ms !== null ||
              timing.tpot_ms !== null ||
              timing.tok_per_sec !== null ||
              timing.latency_ms !== null
            ) {
              res.timingBackfills.push({
                dedup_key: `opencode:${m.id}`,
                ...timing,
              });
            }
          }
        }

        const remainingIds = missingIds.filter((id) => !matchedIds.has(id));
        if (remainingIds.length && hasTable(src, 'session_message')) {
          for (let i = 0; i < remainingIds.length; i += OPENCODE_PART_CHUNK) {
            const chunk = remainingIds.slice(i, i + OPENCODE_PART_CHUNK);
            const placeholders = chunk.map(() => '?').join(',');
            const found = src
              .prepare(`SELECT id, type, time_created, data FROM session_message WHERE id IN (${placeholders}) LIMIT 50000`)
              .all(...chunk);
            for (const sm of found) {
              if (sm.type !== 'assistant' && sm.type !== 'compaction') continue;
              const d = parseJsonSafe(sm.data);
              if (!d || typeof d !== 'object') continue;
              const tk = d.tokens || {};
              const timing = computeOpencodeV2Timing(d, sm.time_created, num(tk.output), num(tk.reasoning));
              if (
                timing.ttft_ms !== null ||
                timing.ttfr_ms !== null ||
                timing.ttfa_ms !== null ||
                timing.tpot_ms !== null ||
                timing.tok_per_sec !== null ||
                timing.latency_ms !== null
              ) {
                res.timingBackfills.push({
                  dedup_key: `opencode:${sm.id}`,
                  ttft_ms: timing.ttft_ms,
                  ttfr_ms: timing.ttfr_ms,
                  ttfa_ms: timing.ttfa_ms,
                  tpot_ms: timing.tpot_ms,
                  tok_per_sec: timing.tok_per_sec,
                  latency_ms: timing.latency_ms,
                });
              }
            }
          }
        }

        res.cursorUpdates.push({ key: bfKey, last_id: 'done', line_no: res.timingBackfills.length });
      } catch (err) {
        debugLog(err, 'collectOpencode:timingBackfill');
      }
    }

    res.counts.opencode = res.events.length;
    res.notes.push(
      `opencode: v1=${legacyChanged}, v2=${v2Changed} changed messages, +${res.events.length} requests, ${res.timingBackfills.length} timing backfills`,
    );
  } catch (e) {
    res.errors.push(`opencode: ${e.message}`);
  } finally {
    try {
      src.close();
    } catch (err) {
      debugLog(err, 'collectOpencode:close');
    }
  }
  return res;
}

/* ================================================================== */
/* Generic records (9Router JSONL / ingest_events.jsonl)               */
/* ================================================================== */

/** Normalize a loosely-shaped usage record (wiretok event shape, OpenAI, Anthropic or router style). */
export function normalizeGenericRecord(o, { defaultTool, known, ctx, milestoneMs, seed }) {
  if (!o || typeof o !== 'object') return null;
  const u = o.usage || {};
  const input = o.input_tokens ?? o.inputTokens ?? o.prompt_tokens ?? o.tokens_in ?? o.tokens_input ?? u.input_tokens ?? u.prompt_tokens;
  const output = o.output_tokens ?? o.outputTokens ?? o.completion_tokens ?? o.tokens_out ?? o.tokens_output ?? u.output_tokens ?? u.completion_tokens;
  const cacheRead =
    o.cache_read_tokens ?? o.cacheReadTokens ?? o.cached_tokens ?? o.tokens_cache_read ?? u.cache_read_input_tokens ??
    u.prompt_tokens_details?.cached_tokens ?? u.input_tokens_details?.cached_tokens ?? 0;
  const cacheWrite = o.cache_write_tokens ?? o.cacheWriteTokens ?? o.tokens_cache_creation ?? u.cache_creation_input_tokens ?? 0;
  const reasoning =
    o.reasoning_tokens ?? o.tokens_reasoning ?? u.output_tokens_details?.reasoning_tokens ?? u.completion_tokens_details?.reasoning_tokens ?? 0;
  if (input === undefined && output === undefined) return null;
  const rawModel = o.raw_model || o.model_id || o.model || null;
  const { model_id, effort } = resolveModel(rawModel || 'unknown', known);
  const created = toIso(o.created_at ?? o.timestamp ?? o.ts ?? o.time ?? o.createdAt);
  const tool = SOURCE_TOOLS.includes(o.source_tool) ? o.source_tool : defaultTool;
  const inTok = num(input);
  const cr = num(cacheRead);
  const mode = ENDPOINT_MODES.includes(o.endpoint_mode) ? o.endpoint_mode : endpointModeFromId(o.id || o.response_id || o.request_id) || 'unknown';
  return {
    dedup_key: o.dedup_key || `${tool}:${o.id || o.request_id || o.response_id || sha1(seed)}`,
    source_tool: tool,
    created_at: created,
    completed_at: toIso(o.completed_at),
    session_id: o.session_id ?? o.sessionId ?? o.conversation_id ?? null,
    account_id: o.account_id ?? o.account ?? o.email ?? null,
    account_email: o.account_email ?? o.email ?? null,
    model_id,
    raw_model: rawModel,
    provider: o.provider ?? null,
    endpoint_mode: mode,
    endpoint: o.endpoint ?? o.path ?? null,
    input_tokens: inTok,
    output_tokens: num(output),
    cache_read_tokens: cr,
    cache_write_tokens: num(cacheWrite),
    cache_write_5m_tokens: numOrNull(o.cache_write_5m_tokens) ?? undefined,
    cache_write_1h_tokens: numOrNull(o.cache_write_1h_tokens) ?? undefined,
    reasoning_tokens: num(reasoning),
    compressed_tokens: numOrNull(o.compressed_tokens ?? o.tokens_compressed),
    context_tokens: o.context_tokens !== undefined ? num(o.context_tokens) : inTok + cr,
    context_window: numOrNull(o.context_window) ?? ctx.get(model_id) ?? null,
    ttft_ms: numOrNull(o.ttft_ms ?? o.ttftMs),
    ttfr_ms: numOrNull(o.ttfr_ms ?? o.ttfrMs),
    ttfa_ms: numOrNull(o.ttfa_ms ?? o.ttfaMs),
    tpot_ms: numOrNull(o.tpot_ms ?? o.tpotMs),
    tok_per_sec: numOrNull(o.tok_per_sec ?? o.tokPerSec),
    latency_ms: numOrNull(o.latency_ms ?? o.duration_ms ?? o.duration ?? o.latencyMs),
    provider_cost_usd: numOrNull(o.provider_cost_usd),
    reported_cost_usd: numOrNull(o.reported_cost_usd ?? o.cost_usd ?? o.cost),
    combo_name: o.combo_name ?? null,
    status: o.status && typeof o.status === 'string' ? o.status : 'ok',
    era: o.era || mkEra(created, milestoneMs),
    workspace: o.workspace ?? o.cwd ?? null,
    title: o.title ?? null,
    parent_session_id: o.parent_session_id ?? null,
    agent_name: o.agent_name ?? null,
    effort: o.effort || effort || null,
    meta_json: typeof o.meta_json === 'string' ? o.meta_json : JSON.stringify({ imported: true }),
  };
}

function collectJsonlFile(db, res, file, key, ctxOpts) {
  const cur = getCursor(db, key);
  const r = readJsonlIncremental(file, cur);
  if (!r || (!r.lines.length && !r.reset)) return 0;
  let n = 0;
  for (const ln of r.lines) {
    if (!ln.text.trim()) continue;
    const o = parseJsonSafe(ln.text);
    const ev = normalizeGenericRecord(o, { ...ctxOpts, seed: `${key}:${ln.text}` });
    if (ev) {
      res.events.push(ev);
      n++;
    }
  }
  res.cursorUpdates.push({ key, byte_offset: r.newOffset, line_no: r.newLineNo, mtime_ms: Math.round(r.mtimeMs), size: r.size });
  return n;
}

/** <DATA_DIR>/ingest_events.jsonl (tee-proxy / manual ingest / hooks). */
export function collectIngest(db, opts = {}) {
  const res = emptyResult('manual-ingest');
  const file = opts.ingestFile || INGEST_EVENTS_LOG;
  if (!exists(file)) return res;
  try {
    const n = collectJsonlFile(db, res, file, 'ingest:events', {
      defaultTool: 'manual-ingest',
      known: knownModelSet(db),
      ctx: ctxMap(db),
      milestoneMs: milestoneOf(db, opts),
    });
    res.counts.ingest = n;
    res.notes.push(`ingest_events.jsonl: +${n}`);
  } catch (e) {
    res.errors.push(`ingest: ${e.message}`);
  }
  return res;
}

/** 9Router: any *.jsonl usage logs and SQLite files with a usage-like table (best-effort, read-only). */
export function collect9Router(db, opts = {}) {
  const res = emptyResult('9router');
  const dirs = (opts.router9Dirs || getLocalSourcePaths().router9Dirs).filter(exists);
  if (!dirs.length) {
    res.notes.push('9router: no data dir found');
    return res;
  }
  const ctxOpts = { defaultTool: '9router', known: knownModelSet(db), ctx: ctxMap(db), milestoneMs: milestoneOf(db, opts) };
  let n = 0;
  for (const dir of dirs) {
    for (const file of walkFiles(dir, (p, nme) => /(usage|request|call|log|history).*\.jsonl$/i.test(nme) || /\.jsonl$/i.test(nme), 4)) {
      if (isBlockedPath(file)) continue;
      try {
        n += collectJsonlFile(db, res, file, `9r:${file}`, ctxOpts);
      } catch (e) {
        res.errors.push(`9router[${path.basename(file)}]: ${e.message}`);
      }
    }
    for (const file of walkFiles(dir, (p, nme) => /\.(sqlite|sqlite3|db)$/i.test(nme) && !/auth|cred|cookie|secret/i.test(nme), 3)) {
      const s = openReadOnly(file);
      if (!s) continue;
      try {
        const tables = s
          .prepare("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1000")
          .all()
          .map((t) => t.name)
          .filter((t) => /usage|request|call_log|history/i.test(t));
        for (const t of tables) {
          const cols = tableColumns(s, t);
          const hasTok = cols.some((c) => /tokens?_?(in|input|out|output)|prompt_tokens|completion_tokens|input_tokens|output_tokens/i.test(c));
          if (!hasTok) continue;
          const safeCols = cols.filter((c) => !/api_?key|access_?token|refresh_?token|id_?token|secret|password|cookie|credential|authorization/i.test(c));
          const ckey = `9r:${file}:${t}`;
          const cur = getCursor(db, ckey);
          const orderCol = cols.includes('id') ? 'id' : 'rowid';
          const rows = s
            .prepare(
              `SELECT ${orderCol === 'rowid' ? 'rowid AS _rid,' : ''} ${safeCols.map((c) => `"${c}"`).join(',')} FROM "${t}" WHERE ${orderCol === 'rowid' ? 'rowid' : '"id"'} > ? ORDER BY ${orderCol === 'rowid' ? 'rowid' : '"id"'} ASC LIMIT 200000`,
            )
            .all(num(cur.last_id, 0));
          for (const r of rows) {
            const rid = r.id ?? r._rid;
            const ev = normalizeGenericRecord(r, { ...ctxOpts, seed: `${ckey}:${rid}` });
            if (ev) {
              ev.dedup_key = `9r:${sha1(ckey)}:${rid}`;
              res.events.push(ev);
              n++;
            }
          }
          if (rows.length) {
            const lastRid = rows[rows.length - 1].id ?? rows[rows.length - 1]._rid;
            res.cursorUpdates.push({ key: ckey, last_id: String(lastRid), line_no: rows.length });
          }
        }
      } catch (e) {
        res.errors.push(`9router[${path.basename(file)}]: ${e.message}`);
      } finally {
        try {
          s.close();
        } catch (err) {
          debugLog(err, 'collect9Router:close');
        }
      }
    }
  }
  res.counts['9router'] = n;
  res.notes.push(`9router: +${n}`);
  return res;
}
