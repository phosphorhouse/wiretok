/**
 * Wiretok collectors — shared read-only helpers.
 * - Incremental JSONL reading with byte-offset cursors
 * - Schema-adaptive helpers for sync_cursors / quota_snapshots (so collectors survive schema tweaks)
 * - Model-id resolution (strips effort/variant suffixes only when the base model is known)
 * - Interval merging & speed metric helpers (TPOT / tok/s)
 *
 * SECURITY: nothing in here reads credential files. Callers must never pass such paths.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { normalizeModelId, SEED_MODELS } from '../contracts.mjs';

export const BLOCKED_BASENAMES = new Set([
  'oauth_creds.json',
  '.credentials.json',
  'auth.json',
  'credentials.json',
  'cookies.sqlite',
]);

export function debugLog(err, ctx = '') {
  if (process.env.WIRETOK_DEBUG === '1') {
    const msg = err instanceof Error ? err.message : String(err || 'unknown error');
    process.stderr.write(`[wiretok:collector${ctx ? `:${ctx}` : ''}] ${msg}\n`);
  }
}

export function isBlockedPath(p) {
  return BLOCKED_BASENAMES.has(path.basename(String(p)).toLowerCase());
}

export function exists(p) {
  try {
    fs.accessSync(p);
    return true;
  } catch (err) {
    debugLog(err, 'exists');
    return false;
  }
}

export function statSafe(p) {
  try {
    return fs.statSync(p);
  } catch (err) {
    debugLog(err, 'statSafe');
    return null;
  }
}

/** Recursively collect files (bounded depth) matching predicate. Never follows into blocked files. */
export function walkFiles(dir, predicate, maxDepth = 8, out = []) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    debugLog(err, 'walkFiles');
    return out;
  }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (maxDepth > 0) walkFiles(p, predicate, maxDepth - 1, out);
    } else if (e.isFile() && !isBlockedPath(p) && predicate(p, e.name)) {
      out.push(p);
    }
  }
  return out;
}

export function sha1(s) {
  return crypto.createHash('sha1').update(String(s)).digest('hex');
}

export function toIso(v) {
  if (v === null || v === undefined || v === '') return null;
  let ms;
  if (typeof v === 'number') ms = v < 1e12 ? v * 1000 : v;
  else if (/^\d+(\.\d+)?$/.test(String(v))) {
    const n = Number(v);
    ms = n < 1e12 ? n * 1000 : n;
  } else {
    let s = String(v);
    // SQLite datetime('now') yields "YYYY-MM-DD HH:MM:SS" in UTC.
    if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?$/.test(s)) s = s.replace(' ', 'T') + 'Z';
    ms = Date.parse(s);
  }
  if (!Number.isFinite(ms)) return null;
  return new Date(ms).toISOString();
}

export function num(v, d = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
}

export function numOrNull(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

/** Merge overlapping [startMs, endMs] intervals and return total non-overlapping duration in ms. */
export function mergeIntervalsMs(intervals) {
  if (!Array.isArray(intervals) || !intervals.length) return 0;
  const valid = [];
  for (const iv of intervals) {
    if (!Array.isArray(iv) || iv.length < 2) continue;
    const s = Number(iv[0]);
    const e = Number(iv[1]);
    if (Number.isFinite(s) && Number.isFinite(e) && e > s) valid.push([s, e]);
  }
  if (!valid.length) return 0;
  valid.sort((a, b) => a[0] - b[0]);
  let total = 0;
  let curS = valid[0][0];
  let curE = valid[0][1];
  for (let i = 1; i < valid.length; i++) {
    const s = valid[i][0];
    const e = valid[i][1];
    if (s <= curE) {
      if (e > curE) curE = e;
    } else {
      total += curE - curS;
      curS = s;
      curE = e;
    }
  }
  total += curE - curS;
  return total;
}

/**
 * Compute bounded TPOT (ms/tok) and generation throughput (tok/s).
 * Guards against noisy sub-20ms clocks and >2000 tok/s spikes.
 */
export function computeSpeedMetrics(genTokens, genMs) {
  if (!Number.isFinite(genMs) || genMs < 20 || !Number.isFinite(genTokens) || genTokens <= 0) {
    return { tpot_ms: null, tok_per_sec: null };
  }
  const tps = genTokens / (genMs / 1000);
  if (!Number.isFinite(tps) || tps <= 0 || tps > 2000) {
    return { tpot_ms: null, tok_per_sec: null };
  }
  return {
    tpot_ms: Math.round((genMs / genTokens) * 100) / 100,
    tok_per_sec: Math.round(((genTokens / genMs) * 1000) * 10) / 10,
  };
}

/** Open a SQLite file strictly read-only. Returns null on failure. */
export function openReadOnly(file) {
  try {
    if (!exists(file)) return null;
    return new DatabaseSync(file, { readOnly: true });
  } catch (err) {
    debugLog(err, 'openReadOnly');
    return null;
  }
}

export function tableColumns(db, table) {
  try {
    return db.prepare(`PRAGMA table_info(${JSON.stringify(String(table))})`).all().map((r) => r.name);
  } catch (err) {
    debugLog(err, 'tableColumns');
    return [];
  }
}

export function hasTable(db, table) {
  try {
    return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type IN ('table','view') AND name = ? LIMIT 1").get(table);
  } catch (err) {
    debugLog(err, 'hasTable');
    return false;
  }
}

/* ------------------------------------------------------------------ */
/* sync_cursors (schema adaptive)                                      */
/* ------------------------------------------------------------------ */

const SYNC_CURSOR_COLUMNS = [
  'source_key',
  'cursor_key',
  'source_tool',
  'byte_offset',
  'line_no',
  'line_offset',
  'last_id',
  'last_rowid',
  'last_timestamp',
  'mtime_ms',
  'size',
  'extra_json',
  'meta_json',
  'updated_at',
  'key',
  'source',
  'id',
  'name',
  'offset',
  'line',
  'cursor',
  'extra',
  'state_json',
];

function cursorKeyColumn(cols) {
  for (const c of ['source_key', 'cursor_key', 'key', 'source', 'id', 'name']) if (cols.includes(c)) return c;
  return cols[0];
}

export function getCursor(db, key) {
  const empty = { byte_offset: 0, line_no: 0, last_id: null, mtime_ms: 0, size: 0, extra: {} };
  if (!db) return empty;
  try {
    const cols = tableColumns(db, 'sync_cursors');
    if (!cols.length) return empty;
    const kc = cursorKeyColumn(cols);
    const sel = SYNC_CURSOR_COLUMNS.filter((c) => cols.includes(c));
    if (!sel.length) return empty;
    const row = db.prepare(`SELECT ${sel.join(', ')} FROM sync_cursors WHERE ${kc} = ? LIMIT 1`).get(key);
    if (!row) return empty;
    let extra = {};
    const ej = row.extra_json ?? row.extra ?? row.state_json ?? null;
    if (ej) {
      try {
        extra = JSON.parse(ej);
      } catch (err) {
        debugLog(err, 'getCursor:parseExtra');
        extra = {};
      }
    }
    return {
      byte_offset: num(row.byte_offset ?? row.offset),
      line_no: num(row.line_no ?? row.line),
      last_id: row.last_id ?? row.cursor ?? null,
      mtime_ms: num(row.mtime_ms),
      size: num(row.size),
      extra,
    };
  } catch (err) {
    debugLog(err, 'getCursor');
    return empty;
  }
}

export function setCursor(db, key, cur) {
  if (!db) return;
  try {
    const cols = tableColumns(db, 'sync_cursors');
    if (!cols.length) return;
    const kc = cursorKeyColumn(cols);
    const row = {
      [kc]: key,
      cursor_key: key,
      source_tool: cur.source_tool ?? '',
      last_rowid: Number.isFinite(Number(cur.last_id)) ? Number(cur.last_id) : 0,
      last_timestamp: cur.last_timestamp ?? null,
      byte_offset: cur.byte_offset ?? 0,
      line_no: cur.line_no ?? 0,
      last_id: cur.last_id ?? null,
      mtime_ms: cur.mtime_ms ?? 0,
      size: cur.size ?? 0,
      extra_json: JSON.stringify(cur.extra ?? {}),
      updated_at: new Date().toISOString(),
    };
    const use = Object.keys(row).filter((k) => cols.includes(k));
    const sql = `INSERT OR REPLACE INTO sync_cursors (${use.join(',')}) VALUES (${use.map(() => '?').join(',')})`;
    db.prepare(sql).run(...use.map((k) => row[k]));
  } catch (err) {
    debugLog(err, 'setCursor');
  }
}

/** Insert a row into `table`, keeping only keys that exist as columns. Returns true on success. */
export function insertAdaptive(db, table, row, { orIgnore = false } = {}) {
  try {
    const cols = tableColumns(db, table);
    if (!cols.length) return false;
    const use = Object.keys(row).filter((k) => cols.includes(k));
    if (!use.length) return false;
    const verb = orIgnore ? 'INSERT OR IGNORE' : 'INSERT';
    db.prepare(`${verb} INTO ${table} (${use.join(',')}) VALUES (${use.map(() => '?').join(',')})`).run(
      ...use.map((k) => {
        const v = row[k];
        if (v !== null && typeof v === 'object') return JSON.stringify(v);
        if (typeof v === 'boolean') return v ? 1 : 0;
        return v === undefined ? null : v;
      }),
    );
    return true;
  } catch (err) {
    debugLog(err, 'insertAdaptive');
    return false;
  }
}

export function getMeta(db, key) {
  try {
    if (!db) return null;
    const cols = tableColumns(db, 'meta');
    if (!cols.length) return null;
    const kc = cols.includes('key') ? 'key' : cols[0];
    const vc = cols.includes('value') ? 'value' : cols[1];
    const r = db.prepare(`SELECT ${vc} AS v FROM meta WHERE ${kc} = ? LIMIT 1`).get(key);
    return r ? r.v : null;
  } catch (err) {
    debugLog(err, 'getMeta');
    return null;
  }
}

/* ------------------------------------------------------------------ */
/* Incremental JSONL                                                   */
/* ------------------------------------------------------------------ */

/**
 * Read complete lines of `file` starting at cursor.byte_offset.
 * Returns { lines: [{ text, lineNo, offset }], newOffset, newLineNo, size, mtimeMs, reset }.
 * Handles truncation/rotation (size < offset => restart from 0). Never reads a trailing partial line.
 * File is opened read-only; contents are never modified.
 */
export function readJsonlIncremental(file, cursor, { maxBytes = 256 * 1024 * 1024 } = {}) {
  const st = statSafe(file);
  if (!st) return null;
  let offset = cursor?.byte_offset || 0;
  let lineNo = cursor?.line_no || 0;
  let reset = false;
  if (st.size < offset) {
    offset = 0;
    lineNo = 0;
    reset = true;
  }
  const base = { lines: [], newOffset: offset, newLineNo: lineNo, size: st.size, mtimeMs: st.mtimeMs, reset };
  if (st.size === offset) return base;
  const len = Math.min(st.size - offset, maxBytes);
  const buf = Buffer.allocUnsafe(len);
  const fd = fs.openSync(file, 'r');
  try {
    fs.readSync(fd, buf, 0, len, offset);
  } finally {
    fs.closeSync(fd);
  }
  const lastNl = buf.lastIndexOf(0x0a);
  if (lastNl < 0) return base; // only a partial line so far
  const text = buf.subarray(0, lastNl + 1).toString('utf8');
  let pos = offset;
  const lines = [];
  let start = 0;
  for (;;) {
    const nl = text.indexOf('\n', start);
    if (nl < 0) break;
    const raw = text.slice(start, nl);
    lineNo += 1;
    lines.push({ text: raw.endsWith('\r') ? raw.slice(0, -1) : raw, lineNo, offset: pos });
    pos += Buffer.byteLength(text.slice(start, nl + 1), 'utf8');
    start = nl + 1;
  }
  return { lines, newOffset: pos, newLineNo: lineNo, size: st.size, mtimeMs: st.mtimeMs, reset };
}

export function parseJsonSafe(s) {
  try {
    return JSON.parse(s);
  } catch (err) {
    debugLog(err, 'parseJsonSafe');
    return null;
  }
}

/* ------------------------------------------------------------------ */
/* Model id resolution                                                 */
/* ------------------------------------------------------------------ */

const VARIANT_SUFFIXES = ['xhigh', 'high', 'medium', 'low', 'minimal', 'max', 'free', 'x-c', 'thinking', 'standard', 'request', 'antigravity'];

export function knownModelSet(db) {
  const set = new Set(SEED_MODELS.map((m) => m.model_id));
  try {
    if (db) for (const r of db.prepare('SELECT model_id FROM models LIMIT 50000').all()) set.add(r.model_id);
  } catch (err) {
    debugLog(err, 'knownModelSet');
  }
  return set;
}

/** Split a trailing reasoning-effort token off a raw model slug. */
export function splitEffort(raw) {
  const m = /-(xhigh|high|medium|low|minimal|max)$/i.exec(String(raw || ''));
  return m ? m[1].toLowerCase() : null;
}

/**
 * Resolve a raw model slug / display name to a canonical model_id.
 * Handles "Gemini 4 Argon (Medium)", "gemini-4-hydrogen-xhigh", "gpt-6-astra-max", "deepseek-v4.1-flash-free", "kr/claude-...".
 * Returns { model_id, effort }.
 */
export function resolveModel(raw, known) {
  if (!raw || typeof raw !== 'string') return { model_id: 'unknown', effort: null };
  let s = raw.trim();
  let effort = null;
  // Display name with trailing "(Effort)"
  const disp = /^(.*?)\s*\((xhigh|high|medium|low|minimal|max)\)\s*$/i.exec(s);
  if (disp) {
    effort = disp[2].toLowerCase();
    s = disp[1];
  }
  if (/\s/.test(s) && !/^orchestrator/i.test(s)) {
    s = s.toLowerCase().replace(/\s+/g, '-');
    if (s.startsWith('claude')) s = s.replace(/\./g, '-'); // Claude seed ids use dashes: claude-sonnet-5-5
  }
  let id = normalizeModelId(s);
  if (known?.has(id)) return { model_id: id, effort: effort || realEffort(s, id) };
  // Strip up to four variant/tier suffixes (…-max, …-free, …-request-antigravity). Stop as soon as a known model appears;
  // if none is known, still use the stripped base so variants of one model share a single pricing row.
  let cur = id;
  let eff = effort;
  const suffixRe = new RegExp(`-(${VARIANT_SUFFIXES.join('|')})$`, 'i');
  for (let i = 0; i < 4; i++) {
    const m = suffixRe.exec(cur);
    if (!m || cur.length - m[0].length < 3) break;
    if (['xhigh', 'high', 'medium', 'low', 'minimal', 'max'].includes(m[1].toLowerCase())) eff = eff || m[1].toLowerCase();
    cur = cur.slice(0, -m[0].length);
    if (known?.has(cur)) return { model_id: cur, effort: eff };
  }
  if (cur !== id) return { model_id: cur, effort: eff };
  return { model_id: id, effort: effort || realEffort(s, id) };
}

/** Effort token present on the raw slug but NOT part of the canonical id (so `qwen3.8-max` is a model, not effort=max). */
function realEffort(raw, id) {
  const sp = splitEffort(raw);
  return sp && !id.endsWith(`-${sp}`) ? sp : null;
}

export function endpointModeFromId(id) {
  const s = String(id || '');
  if (s.startsWith('resp_')) return 'responses';
  if (s.startsWith('msg_')) return 'messages';
  if (s.startsWith('chatcmpl-')) return 'chat_completions';
  return null;
}

export function fileUriToPath(uri) {
  if (!uri || typeof uri !== 'string') return null;
  try {
    if (uri.startsWith('file://')) {
      let p = decodeURIComponent(uri.replace(/^file:\/\//, ''));
      if (/^\/[A-Za-z]:/.test(p)) p = p.slice(1);
      return p.replace(/\//g, path.sep);
    }
  } catch (err) {
    debugLog(err, 'fileUriToPath');
  }
  return uri;
}

export function emptyResult(source) {
  return {
    source,
    events: [],
    cursorUpdates: [],
    quotas: [],
    sessionStates: [],
    timingBackfills: [],
    counts: {},
    errors: [],
    notes: [],
  };
}
