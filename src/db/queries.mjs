/**
 * Wiretok — Parameterized SQLite Queries, Batch Ingest, Overview Analytics & Export
 * Strictly uses parameterized prepared statements (`?`) across all operations.
 */
import crypto from 'node:crypto';
import {
  DEFAULT_FX_USD_TRY,
  SEED_MODELS,
  isSafeObjectKey,
  maskEmail,
  maskIdentifier,
  maskWorkspacePath,
  normalizeModelId,
} from '../contracts.mjs';
import {
  computeAccountValueStats,
  computeRequestCost,
  resolveModelPricing,
} from '../pricing/cost-engine.mjs';
import { getUsdTry } from '../pricing/fx.mjs';

const SYNC_CURSOR_COLS = `
  source_key, cursor_key, source_tool, byte_offset, line_no, line_offset,
  last_id, last_rowid, last_timestamp, mtime_ms, size, extra_json, meta_json, updated_at
`;

const ACCOUNT_COLS = `
  account_id, source_tool, provider, email_or_label, display_name, auth_type,
  plan_type, monthly_fee_usd, daily_budget_usd, monthly_budget_usd, group_name,
  is_active, is_user_configured, created_at, updated_at
`;

const MODEL_COLS = `
  model_id, provider, display_name, context_window, input_per_1m, output_per_1m,
  cache_read_per_1m, cache_write_per_1m, reasoning_per_1m, request_fee_usd,
  credit_multiplier, aa_intelligence, aa_coding, speed_tok_s, release_date,
  source, is_custom, updated_at
`;

const SESSION_COLS = `
  session_id, source_tool, account_id, title, workspace, parent_session_id,
  agent_name, group_id, primary_model_id, context_window, latest_context_tokens,
  peak_context_tokens, total_requests, total_input_tokens, total_output_tokens,
  total_cache_read_tokens, total_cache_write_tokens, total_reasoning_tokens,
  total_api_list_cost_usd, total_billed_cost_usd, total_cache_savings_usd,
  era, started_at, last_event_at, run_status, not_fully_idle, killed, nesting_depth
`;

const REQUEST_COLS = `
  id, dedup_key, created_at, completed_at, era, source_tool, account_id,
  account_email, session_id, step_index, parent_session_id, agent_name, group_id,
  title, workspace, endpoint_mode, endpoint, combo_name, model_raw, raw_model,
  model_id, provider, effort, plan_type, input_tokens, uncached_input_tokens,
  output_tokens, cache_read_tokens, cache_write_tokens, cache_write_5m_tokens,
  cache_write_1h_tokens, cache_ttl_30m_tokens, cache_ttl_12h_tokens,
  reasoning_tokens, compressed_tokens, instructions_tokens, context_tokens,
  context_window, context_utilization, ttft_ms, ttfr_ms, ttfa_ms, tpot_ms,
  latency_ms, tok_per_sec, token_cost_usd, request_fee_usd, tool_surcharge_usd,
  api_list_cost_usd, billed_cost_usd, provider_cost_usd, reported_cost_usd,
  cache_savings_usd, compression_savings_usd, credit_multiplier, service_tier,
  prompt_cache_retention, safety_identifier, response_id, system_fingerprint,
  has_signature, authenticity_score, verdict, status, status_code, meta_json
`;

const FORENSIC_COLS = `
  id, capture_id, created_at, source_tool, endpoint_mode, base_url,
  requested_model, wire_model, self_reported_model, response_id,
  system_fingerprint, service_tier, prompt_cache_key, prompt_cache_retention,
  safety_identifier, has_signature, signature_length, input_tokens, output_tokens,
  cache_read_tokens, cache_write_tokens, cache_ttl_30m_tokens, cache_ttl_12h_tokens,
  reasoning_tokens, instructions_tokens, ttft_ms, ttfr_ms, ttfa_ms, tpot_ms,
  total_ms, tok_per_sec, chunk_count, jitter_ms, authenticity_score, verdict,
  attribution_json, headers_json, analysis_json, raw_excerpt
`;

const QUOTA_COLS = `
  id, quota_id, captured_at, source_tool, account_id, provider, model_id,
  tier_or_model, window_key, tokens_used, token_limit, limit_requests,
  remaining_requests, limit_tokens, remaining_tokens, remaining_pct,
  used_percent, window_start, window_reset, reset_at, is_exhausted,
  status, raw_json, meta_json, updated_at
`;

function debugLog(context, err) {
  if (process.env.WIRETOK_DEBUG) {
    process.stderr.write(`[wiretok] ${context}: ${err?.message || err}\n`);
  }
}

function parseBoolFlag(value, fallback = false) {
  if (value === undefined || value === null) return fallback;
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value !== 0;
  const s = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(s)) return true;
  if (['0', 'false', 'no', 'off', ''].includes(s)) return false;
  return fallback;
}

function toNullableNum(val) {
  if (val === null || val === undefined || val === '') return null;
  const n = Number(val);
  return Number.isFinite(n) ? n : null;
}

function roundNum(val, decimals = 6) {
  const n = Number(val);
  if (!Number.isFinite(n)) return 0;
  const f = 10 ** decimals;
  return Math.round(n * f) / f;
}

function quantile(sortedAsc, q) {
  if (!sortedAsc.length) return 0;
  if (sortedAsc.length === 1) return sortedAsc[0];
  const pos = (sortedAsc.length - 1) * q;
  const base = Math.floor(pos);
  const rest = pos - base;
  const next = sortedAsc[base + 1] !== undefined ? sortedAsc[base + 1] : sortedAsc[base];
  return sortedAsc[base] + rest * (next - sortedAsc[base]);
}

function inferDefaultPlanType(_sourceTool, authType, explicitPlan) {
  if (explicitPlan && ['api', 'subscription', 'free'].includes(explicitPlan)) {
    return explicitPlan;
  }
  const at = String(authType || '').toLowerCase();
  if (at === 'free') return 'free';
  return 'api';
}

/**
 * Get a value from the `meta` table.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {string} key
 * @param {string|null} [fallback=null]
 */
export function getMeta(db, key, fallback = null) {
  const row = db.prepare(`SELECT value FROM meta WHERE key = ? LIMIT 1`).get(String(key));
  return row && row.value !== undefined ? row.value : fallback;
}

/**
 * Set a value in the `meta` table.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {string} key
 * @param {string|number|boolean} value
 */
export function setMeta(db, key, value) {
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO meta (key, value, updated_at)
    VALUES (?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
  `).run(String(key), String(value), now);
  return { key: String(key), value: String(value), updated_at: now };
}

export const setSetting = setMeta;

/**
 * Get global settings from `meta`.
 * @param {import('node:sqlite').DatabaseSync} db
 */
export function getSettings(db) {
  const milestoneAt = getMeta(db, 'milestone_at', new Date().toISOString());
  const fxUsdTry = getUsdTry(db);
  const privacyRaw = getMeta(db, 'privacy_mask', '1');
  const privacyMask = parseBoolFlag(privacyRaw, true);
  const modelsSyncedAt = getMeta(db, 'models_synced_at', null);
  const fxUpdatedAt = getMeta(db, 'fx_updated_at', null);

  return {
    milestone_at: milestoneAt,
    milestoneAt,
    fx_usd_try: fxUsdTry,
    fxUsdTry,
    privacy_mask: privacyMask,
    privacyMask,
    models_synced_at: modelsSyncedAt,
    fx_updated_at: fxUpdatedAt,
  };
}

/**
 * Update global settings (`fx_usd_try`, `privacy_mask`, `milestone_at`).
 * When `milestone_at` is updated, recalculates `era` across `requests` and `sessions`.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {object} patch
 */
export function updateSettings(db, patch = {}) {
  if (patch.fx_usd_try !== undefined || patch.fxUsdTry !== undefined) {
    const fx = Number(patch.fx_usd_try ?? patch.fxUsdTry);
    if (Number.isFinite(fx) && fx > 0) {
      setMeta(db, 'fx_usd_try', String(roundNum(fx, 4)));
      setMeta(db, 'fx_updated_at', new Date().toISOString());
    }
  }

  if (patch.privacy_mask !== undefined || patch.privacyMask !== undefined) {
    const pm = parseBoolFlag(patch.privacy_mask ?? patch.privacyMask, true);
    setMeta(db, 'privacy_mask', pm ? '1' : '0');
    setMeta(db, 'v02_privacy_default', '1');
  }

  if (patch.milestone_at !== undefined || patch.milestoneAt !== undefined) {
    const rawMs = patch.milestone_at ?? patch.milestoneAt;
    const msIso = rawMs === 'now' || !rawMs ? new Date().toISOString() : String(rawMs).trim();
    setMeta(db, 'milestone_at', msIso);
    db.prepare(`
      UPDATE requests
      SET era = CASE WHEN created_at >= ? THEN 'live' ELSE 'pre_milestone' END
    `).run(msIso);
    db.prepare(`
      UPDATE sessions
      SET era = CASE WHEN last_event_at >= ? THEN 'live' ELSE 'pre_milestone' END
    `).run(msIso);
  }

  return getSettings(db);
}

/**
 * Read an incremental sync cursor by key.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {string} sourceKey
 */
export function getSyncCursor(db, sourceKey) {
  const key = String(sourceKey);
  return (
    db
      .prepare(`SELECT ${SYNC_CURSOR_COLS} FROM sync_cursors WHERE source_key = ? OR cursor_key = ? LIMIT 1`)
      .get(key, key) || null
  );
}

/**
 * Upsert an incremental sync cursor.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {string} sourceKey
 * @param {object} data
 */
export function setSyncCursor(db, sourceKey, data = {}) {
  const key = String(sourceKey);
  const now = new Date().toISOString();
  const lineVal = Number(data.line_no ?? data.line_offset ?? 0) || 0;
  const byteVal = Number(data.byte_offset ?? 0) || 0;
  const lastRowid = Number(data.last_rowid ?? 0) || 0;
  const mtimeMs = Number(data.mtime_ms ?? 0) || 0;
  const sizeVal = Number(data.size ?? 0) || 0;
  const extraJson =
    typeof data.extra_json === 'string'
      ? data.extra_json
      : data.extra_json
      ? JSON.stringify(data.extra_json)
      : null;
  const metaJson =
    typeof data.meta_json === 'string'
      ? data.meta_json
      : data.meta_json
      ? JSON.stringify(data.meta_json)
      : extraJson;

  db.prepare(`
    INSERT INTO sync_cursors (
      source_key,
      cursor_key,
      source_tool,
      byte_offset,
      line_no,
      line_offset,
      last_id,
      last_rowid,
      last_timestamp,
      mtime_ms,
      size,
      extra_json,
      meta_json,
      updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(source_key) DO UPDATE SET
      cursor_key = excluded.cursor_key,
      source_tool = CASE WHEN excluded.source_tool != '' THEN excluded.source_tool ELSE sync_cursors.source_tool END,
      byte_offset = excluded.byte_offset,
      line_no = excluded.line_no,
      line_offset = excluded.line_offset,
      last_id = COALESCE(excluded.last_id, sync_cursors.last_id),
      last_rowid = excluded.last_rowid,
      last_timestamp = COALESCE(excluded.last_timestamp, sync_cursors.last_timestamp),
      mtime_ms = excluded.mtime_ms,
      size = excluded.size,
      extra_json = COALESCE(excluded.extra_json, sync_cursors.extra_json),
      meta_json = COALESCE(excluded.meta_json, sync_cursors.meta_json),
      updated_at = excluded.updated_at
  `).run(
    key,
    key,
    String(data.source_tool || ''),
    byteVal,
    lineVal,
    lineVal,
    data.last_id !== undefined ? String(data.last_id) : null,
    lastRowid,
    data.last_timestamp || null,
    mtimeMs,
    sizeVal,
    extraJson,
    metaJson,
    now
  );
}

/**
 * Upsert an account record (never stores tokens, cookies, or secrets).
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {object} account
 */
export function upsertAccount(db, account = {}) {
  const accountId = String(account.account_id || account.id || account.email || 'unknown').trim();
  if (!accountId) return null;
  const now = new Date().toISOString();
  const sourceTool = String(account.source_tool || 'antigravity').trim();
  const provider = String(account.provider || 'google').trim();
  const defaultLabel = accountId === 'antigravity-main' ? 'Antigravity 2.0' : accountId;
  const emailOrLabel = String(
    account.email_or_label || account.email || account.name || defaultLabel
  ).trim();
  const displayName = String(
    account.display_name || account.name || emailOrLabel || defaultLabel
  ).trim();
  const authType = String(account.auth_type || 'oauth').trim();
  const planType = inferDefaultPlanType(sourceTool, authType, account.plan_type);
  const monthlyFee =
    account.monthly_fee_usd !== undefined ? Number(account.monthly_fee_usd) : 0.0;

  db.prepare(`
    INSERT INTO accounts (
      account_id,
      source_tool,
      provider,
      email_or_label,
      display_name,
      auth_type,
      plan_type,
      monthly_fee_usd,
      daily_budget_usd,
      monthly_budget_usd,
      group_name,
      is_active,
      created_at,
      updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(account_id) DO UPDATE SET
      source_tool = CASE WHEN accounts.source_tool = '' THEN excluded.source_tool ELSE accounts.source_tool END,
      provider = CASE WHEN accounts.provider = '' OR accounts.provider = 'unknown' THEN excluded.provider ELSE accounts.provider END,
      email_or_label = CASE WHEN accounts.email_or_label = '' THEN excluded.email_or_label ELSE accounts.email_or_label END,
      display_name = CASE WHEN accounts.display_name = '' THEN excluded.display_name ELSE accounts.display_name END,
      updated_at = excluded.updated_at
  `).run(
    accountId,
    sourceTool,
    provider,
    emailOrLabel,
    displayName,
    authType,
    planType,
    monthlyFee,
    Number(account.daily_budget_usd ?? 0),
    Number(account.monthly_budget_usd ?? 0),
    String(account.group_name || account.group || ''),
    account.is_active !== undefined ? (account.is_active ? 1 : 0) : 1,
    now,
    now
  );

  return db
    .prepare(`SELECT ${ACCOUNT_COLS} FROM accounts WHERE account_id = ? LIMIT 1`)
    .get(accountId);
}

const UPSERT_QUOTA_SQL = `
  INSERT INTO quota_snapshots (
    quota_id,
    captured_at,
    source_tool,
    account_id,
    provider,
    model_id,
    tier_or_model,
    window_key,
    tokens_used,
    token_limit,
    limit_requests,
    remaining_requests,
    limit_tokens,
    remaining_tokens,
    remaining_pct,
    used_percent,
    window_start,
    window_reset,
    reset_at,
    is_exhausted,
    status,
    raw_json,
    meta_json,
    updated_at
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  ON CONFLICT(quota_id) DO UPDATE SET
    captured_at = excluded.captured_at,
    tokens_used = excluded.tokens_used,
    token_limit = excluded.token_limit,
    limit_requests = excluded.limit_requests,
    remaining_requests = excluded.remaining_requests,
    limit_tokens = excluded.limit_tokens,
    remaining_tokens = excluded.remaining_tokens,
    remaining_pct = excluded.remaining_pct,
    used_percent = excluded.used_percent,
    window_start = excluded.window_start,
    window_reset = excluded.window_reset,
    reset_at = excluded.reset_at,
    is_exhausted = excluded.is_exhausted,
    status = excluded.status,
    raw_json = excluded.raw_json,
    meta_json = excluded.meta_json,
    updated_at = excluded.updated_at
`;

function buildQuotaParams(q = {}, now = new Date().toISOString()) {
  const accountId = String(q.account_id || 'unknown');
  const sourceTool = String(q.source_tool || 'omniroute');
  const provider = String(q.provider || '');
  const modelId = String(q.model_id || q.tier_or_model || '');
  const tierOrModel = String(q.tier_or_model || modelId);
  const windowKey = String(q.window_key || 'default');
  const quotaId = String(
    q.quota_id || `${sourceTool}:${accountId}:${provider}:${modelId}:${windowKey}`
  );

  const tokensUsed = q.tokens_used !== undefined && q.tokens_used !== null ? Number(q.tokens_used) : null;
  const tokenLimit =
    q.token_limit !== undefined && q.token_limit !== null
      ? Number(q.token_limit)
      : q.limit_tokens !== undefined && q.limit_tokens !== null
      ? Number(q.limit_tokens)
      : null;
  const remainingTokens =
    q.remaining_tokens !== undefined && q.remaining_tokens !== null
      ? Number(q.remaining_tokens)
      : tokenLimit !== null && tokensUsed !== null
      ? Math.max(0, tokenLimit - tokensUsed)
      : null;
  const remainingPct =
    q.remaining_pct !== undefined && q.remaining_pct !== null
      ? Number(q.remaining_pct)
      : tokenLimit && remainingTokens !== null
      ? roundNum((remainingTokens / tokenLimit) * 100, 2)
      : null;
  const usedPercent =
    q.used_percent !== undefined && q.used_percent !== null
      ? Number(q.used_percent)
      : remainingPct !== null
      ? roundNum(Math.max(0, 100 - remainingPct), 2)
      : null;
  const resetAt = q.reset_at || q.window_reset || null;
  const rawJson =
    typeof q.raw_json === 'string'
      ? q.raw_json
      : q.raw_json
      ? JSON.stringify(q.raw_json)
      : typeof q.meta_json === 'string'
      ? q.meta_json
      : q.meta_json
      ? JSON.stringify(q.meta_json)
      : null;

  return [
    quotaId,
    q.captured_at || now,
    sourceTool,
    accountId,
    provider,
    modelId,
    tierOrModel,
    windowKey,
    tokensUsed,
    tokenLimit,
    q.limit_requests !== undefined && q.limit_requests !== null ? Number(q.limit_requests) : null,
    q.remaining_requests !== undefined && q.remaining_requests !== null
      ? Number(q.remaining_requests)
      : null,
    tokenLimit,
    remainingTokens,
    remainingPct,
    usedPercent,
    q.window_start || null,
    resetAt,
    resetAt,
    q.is_exhausted ? 1 : 0,
    q.status || (q.is_exhausted ? 'exhausted' : 'ok'),
    rawJson,
    rawJson,
    now,
  ];
}

/**
 * Upsert a single quota snapshot row.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {object} q
 */
export function upsertQuotaSnapshot(db, q = {}) {
  const now = new Date().toISOString();
  db.prepare(UPSERT_QUOTA_SQL).run(...buildQuotaParams(q, now));
}

/**
 * Batch upsert quota snapshot rows inside a transaction.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {Array<object>|object} items
 */
export function upsertQuotaSnapshots(db, items = []) {
  const list = Array.isArray(items)
    ? items
    : items && typeof items === 'object'
    ? [items]
    : [];
  if (list.length === 0) {
    return { upserted: 0, total: 0 };
  }

  const now = new Date().toISOString();
  const stmt = db.prepare(UPSERT_QUOTA_SQL);
  let upserted = 0;

  db.exec('BEGIN');
  try {
    for (const item of list) {
      if (!item || typeof item !== 'object') continue;
      const res = stmt.run(...buildQuotaParams(item, now));
      if (res.changes > 0) upserted += 1;
    }
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }

  return { upserted, total: list.length };
}

/**
 * Read latest quota snapshot per (source_tool, account_id, model_id, tier_or_model), bounded up to LIMIT 100.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {number} [limit=100]
 */
function queryLatestQuotaSnapshots(db, limit = 100) {
  const safeLimit = Math.min(100, Math.max(1, Number(limit) || 100));
  return db
    .prepare(
      `SELECT ${QUOTA_COLS}
       FROM (
         SELECT
           ${QUOTA_COLS},
           ROW_NUMBER() OVER (
             PARTITION BY source_tool, account_id, model_id, tier_or_model
             ORDER BY updated_at DESC, captured_at DESC, id DESC
           ) AS rn
         FROM quota_snapshots
       ) latest
       WHERE rn = 1
       ORDER BY updated_at DESC, captured_at DESC, id DESC
       LIMIT ?`
    )
    .all(safeLimit);
}

/**
 * Atomic batch insert of normalized telemetry request events.
 * Automatically computes per-request costs, upserts accounts, and updates session context watermarks.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {Array<object>} events
 */
export function insertRequestBatch(db, events = []) {
  if (!Array.isArray(events) || events.length === 0) {
    return { inserted: 0, updated: 0, skipped: 0, total: 0 };
  }

  const now = new Date().toISOString();
  const milestoneAt = getMeta(db, 'milestone_at', now);

  const modelRows = db.prepare(`SELECT ${MODEL_COLS} FROM models LIMIT 5000`).all();
  const modelsMap = new Map(modelRows.map((m) => [m.model_id, m]));
  for (const s of SEED_MODELS) {
    if (!modelsMap.has(s.model_id)) modelsMap.set(s.model_id, s);
  }

  const accountRows = db.prepare(`SELECT ${ACCOUNT_COLS} FROM accounts LIMIT 2000`).all();
  const accountsMap = new Map(accountRows.map((a) => [a.account_id, a]));

  const insertAccountStmt = db.prepare(`
    INSERT INTO accounts (
      account_id,
      source_tool,
      provider,
      email_or_label,
      display_name,
      auth_type,
      plan_type,
      monthly_fee_usd,
      created_at,
      updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(account_id) DO UPDATE SET
      email_or_label = CASE WHEN accounts.email_or_label = '' AND excluded.email_or_label != '' THEN excluded.email_or_label ELSE accounts.email_or_label END,
      updated_at = excluded.updated_at
  `);

  const insertReqStmt = db.prepare(`
    INSERT OR IGNORE INTO requests (
      dedup_key,
      created_at,
      completed_at,
      era,
      source_tool,
      account_id,
      account_email,
      session_id,
      step_index,
      parent_session_id,
      agent_name,
      group_id,
      title,
      workspace,
      endpoint_mode,
      endpoint,
      combo_name,
      model_raw,
      raw_model,
      model_id,
      provider,
      effort,
      plan_type,
      input_tokens,
      uncached_input_tokens,
      output_tokens,
      cache_read_tokens,
      cache_write_tokens,
      cache_write_5m_tokens,
      cache_write_1h_tokens,
      cache_ttl_30m_tokens,
      cache_ttl_12h_tokens,
      reasoning_tokens,
      compressed_tokens,
      instructions_tokens,
      context_tokens,
      context_window,
      context_utilization,
      ttft_ms,
      ttfr_ms,
      ttfa_ms,
      tpot_ms,
      latency_ms,
      tok_per_sec,
      token_cost_usd,
      request_fee_usd,
      tool_surcharge_usd,
      api_list_cost_usd,
      billed_cost_usd,
      provider_cost_usd,
      reported_cost_usd,
      cache_savings_usd,
      compression_savings_usd,
      credit_multiplier,
      service_tier,
      prompt_cache_retention,
      safety_identifier,
      response_id,
      system_fingerprint,
      has_signature,
      authenticity_score,
      verdict,
      status,
      status_code,
      meta_json
    ) VALUES (
      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
      ?, ?, ?, ?, ?
    )
  `);

  const enrichReqStmt = db.prepare(`
    UPDATE requests
    SET account_id = CASE WHEN requests.account_id IN ('unknown', 'legacy_unattributed', '') AND ? NOT IN ('unknown', 'legacy_unattributed', '') THEN ? ELSE requests.account_id END,
        account_email = CASE WHEN requests.account_email = '' AND ? != '' THEN ? ELSE requests.account_email END,
        title = CASE WHEN requests.title = '' AND ? != '' THEN ? ELSE requests.title END,
        workspace = CASE WHEN requests.workspace = '' AND ? != '' THEN ? ELSE requests.workspace END,
        parent_session_id = COALESCE(requests.parent_session_id, ?),
        agent_name = COALESCE(requests.agent_name, ?),
        group_id = COALESCE(requests.group_id, ?)
    WHERE dedup_key = ?
  `);

  const upsertSessionStmt = db.prepare(`
    INSERT INTO sessions (
      session_id,
      source_tool,
      account_id,
      title,
      workspace,
      parent_session_id,
      agent_name,
      group_id,
      primary_model_id,
      context_window,
      latest_context_tokens,
      peak_context_tokens,
      total_requests,
      total_input_tokens,
      total_output_tokens,
      total_cache_read_tokens,
      total_cache_write_tokens,
      total_reasoning_tokens,
      total_api_list_cost_usd,
      total_billed_cost_usd,
      total_cache_savings_usd,
      era,
      started_at,
      last_event_at,
      run_status,
      not_fully_idle,
      killed,
      nesting_depth
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(session_id) DO UPDATE SET
      account_id = CASE WHEN sessions.account_id IN ('unknown', 'legacy_unattributed', '') AND excluded.account_id NOT IN ('unknown', 'legacy_unattributed', '') THEN excluded.account_id ELSE sessions.account_id END,
      title = CASE WHEN excluded.title != '' THEN excluded.title ELSE sessions.title END,
      workspace = CASE WHEN excluded.workspace != '' THEN excluded.workspace ELSE sessions.workspace END,
      parent_session_id = COALESCE(excluded.parent_session_id, sessions.parent_session_id),
      agent_name = COALESCE(excluded.agent_name, sessions.agent_name),
      group_id = COALESCE(excluded.group_id, sessions.group_id),
      primary_model_id = CASE WHEN excluded.primary_model_id != 'unknown' THEN excluded.primary_model_id ELSE sessions.primary_model_id END,
      context_window = MAX(sessions.context_window, excluded.context_window),
      latest_context_tokens = CASE WHEN excluded.last_event_at >= sessions.last_event_at AND excluded.latest_context_tokens > 0 THEN excluded.latest_context_tokens ELSE sessions.latest_context_tokens END,
      peak_context_tokens = MAX(sessions.peak_context_tokens, excluded.peak_context_tokens),
      total_requests = sessions.total_requests + 1,
      total_input_tokens = sessions.total_input_tokens + excluded.total_input_tokens,
      total_output_tokens = sessions.total_output_tokens + excluded.total_output_tokens,
      total_cache_read_tokens = sessions.total_cache_read_tokens + excluded.total_cache_read_tokens,
      total_cache_write_tokens = sessions.total_cache_write_tokens + excluded.total_cache_write_tokens,
      total_reasoning_tokens = sessions.total_reasoning_tokens + excluded.total_reasoning_tokens,
      total_api_list_cost_usd = ROUND(sessions.total_api_list_cost_usd + excluded.total_api_list_cost_usd, 8),
      total_billed_cost_usd = ROUND(sessions.total_billed_cost_usd + excluded.total_billed_cost_usd, 8),
      total_cache_savings_usd = ROUND(sessions.total_cache_savings_usd + excluded.total_cache_savings_usd, 8),
      era = CASE WHEN excluded.last_event_at >= ? THEN 'live' ELSE sessions.era END,
      started_at = MIN(sessions.started_at, excluded.started_at),
      last_event_at = MAX(sessions.last_event_at, excluded.last_event_at),
      run_status = CASE WHEN excluded.run_status != '' THEN excluded.run_status ELSE sessions.run_status END,
      not_fully_idle = CASE WHEN excluded.not_fully_idle != 0 THEN excluded.not_fully_idle ELSE sessions.not_fully_idle END,
      killed = CASE WHEN excluded.killed != 0 THEN excluded.killed ELSE sessions.killed END,
      nesting_depth = CASE WHEN excluded.nesting_depth > 0 THEN excluded.nesting_depth ELSE sessions.nesting_depth END
  `);

  let inserted = 0;
  let updated = 0;
  let skipped = 0;

  db.exec('BEGIN');
  try {
    for (const ev of events) {
      if (!ev || typeof ev !== 'object') {
        skipped += 1;
        continue;
      }

      const dedupKey = String(
        ev.dedup_key ||
          `${ev.source_tool || 'manual'}:${ev.session_id || 'nosess'}:${ev.step_index ?? ''}:${ev.created_at || now}:${crypto.randomUUID()}`
      ).trim();

      const createdAt = ev.created_at ? String(ev.created_at) : now;
      const completedAt = ev.completed_at ? String(ev.completed_at) : null;
      const era =
        ev.era === 'live' || ev.era === 'pre_milestone'
          ? ev.era
          : createdAt >= milestoneAt
          ? 'live'
          : 'pre_milestone';

      const sourceTool = String(ev.source_tool || 'antigravity').trim();
      const rawModel = String(
        ev.raw_model || ev.model_raw || ev.model || ev.model_id || 'unknown'
      ).trim();
      const normModelId = normalizeModelId(ev.model_id || rawModel);
      const modelRow = resolveModelPricing(normModelId, modelsMap);
      const provider = String(ev.provider || modelRow?.provider || 'unknown').trim();

      const accountId = String(
        ev.account_id || ev.account_email || `${sourceTool}-default`
      ).trim();
      const accountEmail = String(
        ev.account_email || (accountId.includes('@') ? accountId : '')
      ).trim();

      let accountRow = accountsMap.get(accountId);
      if (!accountRow) {
        const planType = inferDefaultPlanType(sourceTool, ev.auth_type, ev.plan_type);
        const monthlyFee = ev.monthly_fee_usd !== undefined ? Number(ev.monthly_fee_usd) : 0.0;
        const label =
          accountEmail ||
          ev.account_label ||
          (accountId === 'antigravity-main' ? 'Antigravity 2.0' : accountId);
        insertAccountStmt.run(
          accountId,
          sourceTool,
          provider,
          label,
          label,
          ev.auth_type || 'api',
          planType,
          monthlyFee,
          now,
          now
        );
        accountRow = {
          account_id: accountId,
          source_tool: sourceTool,
          provider,
          email_or_label: label,
          display_name: label,
          plan_type: planType,
          monthly_fee_usd: monthlyFee,
        };
        accountsMap.set(accountId, accountRow);
      }

      const cost = computeRequestCost(
        {
          ...ev,
          model_id: normModelId,
          provider,
          plan_type: ev.plan_type || accountRow.plan_type,
          provider_cost_usd: ev.provider_cost_usd ?? ev.reported_cost_usd ?? null,
        },
        modelRow,
        accountRow
      );

      const ttftMs = ev.ttft_ms != null ? Number(ev.ttft_ms) : null;
      const ttfrMs = ev.ttfr_ms != null ? Number(ev.ttfr_ms) : null;
      const ttfaMs = ev.ttfa_ms != null ? Number(ev.ttfa_ms) : null;
      const latencyMs =
        ev.latency_ms != null
          ? Number(ev.latency_ms)
          : ev.duration_ms != null
          ? Number(ev.duration_ms)
          : null;

      let tpotMs = ev.tpot_ms != null ? Number(ev.tpot_ms) : null;
      let tokPerSec = ev.tok_per_sec != null ? Number(ev.tok_per_sec) : null;
      const generatedTokens = ev.reasoning_included_in_output
        ? cost.output_tokens
        : cost.output_tokens + cost.reasoning_tokens;
      if (latencyMs && latencyMs > 0 && generatedTokens > 0) {
        const genMs = Math.max(
          1,
          ttftMs != null && ttftMs >= 0 && latencyMs > ttftMs
            ? latencyMs - ttftMs
            : latencyMs
        );
        if (tokPerSec === null) {
          tokPerSec = roundNum((generatedTokens / genMs) * 1000, 2);
        }
        if (tpotMs === null) {
          tpotMs = roundNum(genMs / generatedTokens, 2);
        }
      }

      const title = String(ev.title || '').trim();
      const workspace = String(ev.workspace || '').trim();
      const sessionId = ev.session_id ? String(ev.session_id).trim() : null;
      const parentSessionId = ev.parent_session_id ? String(ev.parent_session_id).trim() : null;
      const agentName = ev.agent_name ? String(ev.agent_name).trim() : null;
      const groupId = ev.group_id ? String(ev.group_id).trim() : null;
      const metaJson =
        typeof ev.meta_json === 'string'
          ? ev.meta_json
          : ev.meta_json
          ? JSON.stringify(ev.meta_json)
          : null;

      const statusStr = String(ev.status || 'ok');
      const statusCode =
        ev.status_code != null
          ? Number(ev.status_code)
          : typeof ev.status === 'number'
          ? ev.status
          : 200;

      const res = insertReqStmt.run(
        dedupKey,
        createdAt,
        completedAt,
        era,
        sourceTool,
        accountId,
        accountEmail,
        sessionId,
        ev.step_index != null ? Number(ev.step_index) : null,
        parentSessionId,
        agentName,
        groupId,
        title,
        workspace,
        String(ev.endpoint_mode || 'unknown'),
        String(ev.endpoint || ''),
        String(ev.combo_name || ''),
        rawModel,
        rawModel,
        cost.model_id,
        cost.provider,
        ev.effort ? String(ev.effort) : null,
        cost.plan_type,
        cost.input_tokens,
        cost.uncached_input_tokens,
        cost.output_tokens,
        cost.cache_read_tokens,
        cost.cache_write_tokens,
        Math.max(0, Number(ev.cache_write_5m_tokens ?? 0) || 0),
        Math.max(0, Number(ev.cache_write_1h_tokens ?? 0) || 0),
        Math.max(0, Number(ev.cache_ttl_30m_tokens ?? 0) || 0),
        Math.max(0, Number(ev.cache_ttl_12h_tokens ?? 0) || 0),
        cost.reasoning_tokens,
        cost.compressed_tokens,
        Math.max(0, Number(ev.instructions_tokens ?? 0) || 0),
        cost.context_tokens,
        cost.context_window,
        cost.context_utilization,
        ttftMs,
        ttfrMs,
        ttfaMs,
        tpotMs,
        latencyMs,
        tokPerSec,
        cost.token_cost_usd,
        cost.request_fee_usd,
        cost.tool_surcharge_usd,
        cost.api_list_cost_usd,
        cost.billed_cost_usd,
        cost.provider_cost_usd,
        ev.reported_cost_usd != null ? Number(ev.reported_cost_usd) : null,
        cost.cache_savings_usd,
        cost.compression_savings_usd,
        cost.credit_multiplier,
        ev.service_tier || null,
        ev.prompt_cache_retention || null,
        ev.safety_identifier || null,
        ev.response_id || null,
        ev.system_fingerprint || null,
        ev.has_signature ? 1 : 0,
        ev.authenticity_score != null ? Number(ev.authenticity_score) : null,
        ev.verdict || null,
        statusStr,
        statusCode,
        metaJson
      );

      if (res.changes > 0) {
        inserted += 1;
        if (sessionId) {
          upsertSessionStmt.run(
            sessionId,
            sourceTool,
            accountId,
            title,
            workspace,
            parentSessionId,
            agentName,
            groupId,
            cost.model_id,
            cost.context_window,
            cost.context_tokens,
            cost.context_tokens,
            cost.input_tokens,
            cost.output_tokens,
            cost.cache_read_tokens,
            cost.cache_write_tokens,
            cost.reasoning_tokens,
            cost.api_list_cost_usd,
            cost.billed_cost_usd,
            cost.cache_savings_usd,
            era,
            createdAt,
            completedAt || createdAt,
            String(ev.run_status || '').trim(),
            ev.not_fully_idle ? 1 : 0,
            ev.killed ? 1 : 0,
            Math.max(0, Math.round(Number(ev.nesting_depth ?? 0) || 0)),
            milestoneAt
          );
        }
      } else {
        skipped += 1;
        // Enrich metadata on existing row if new metadata arrived (without re-adding token counts)
        if (title || workspace || parentSessionId || agentName || accountEmail) {
          const enrichRes = enrichReqStmt.run(
            accountId,
            accountId,
            accountEmail,
            accountEmail,
            title,
            title,
            workspace,
            workspace,
            parentSessionId,
            agentName,
            groupId,
            dedupKey
          );
          if (enrichRes.changes > 0) updated += 1;
        }
      }
    }

    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }

  return {
    inserted,
    updated,
    skipped,
    total: events.length,
  };
}

/**
 * Batch-update live session state flags (`run_status`, `not_fully_idle`, `killed`, `nesting_depth`)
 * inside chunked transactions. Handles empty arrays cleanly.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {Array<object>} [states=[]]
 */
export function updateSessionStates(db, states = []) {
  if (!Array.isArray(states) || states.length === 0) {
    return { updated: 0, total: 0 };
  }

  const stmt = db.prepare(`
    UPDATE sessions
    SET run_status = ?,
        not_fully_idle = ?,
        killed = ?,
        nesting_depth = ?
    WHERE session_id = ?
  `);

  const CHUNK_SIZE = 500;
  let updated = 0;

  for (let i = 0; i < states.length; i += CHUNK_SIZE) {
    const chunk = states.slice(i, i + CHUNK_SIZE);
    db.exec('BEGIN');
    try {
      for (const s of chunk) {
        if (!s || typeof s !== 'object') continue;
        const sessionId = String(
          s.session_id || s.sessionId || s.conversation_id || s.id || ''
        ).trim();
        if (!sessionId) continue;
        const runStatus = String(s.run_status ?? s.status ?? '').trim();
        const notFullyIdle = s.not_fully_idle ?? s.notFullyIdle ? 1 : 0;
        const killed = s.killed ? 1 : 0;
        const nestingDepth = Math.max(
          0,
          Math.round(Number(s.nesting_depth ?? s.nestingDepth ?? 0) || 0)
        );
        const res = stmt.run(runStatus, notFullyIdle, killed, nestingDepth, sessionId);
        if (res.changes > 0) updated += 1;
      }
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  }

  return { updated, total: states.length };
}

/**
 * Batch-backfill timing metrics (`ttft_ms`, `ttfr_ms`, `ttfa_ms`, `tpot_ms`, `tok_per_sec`, `latency_ms`)
 * onto existing `requests` rows by `dedup_key` inside chunked transactions.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {Array<object>} [updates=[]]
 */
export function backfillRequestTimings(db, updates = []) {
  if (!Array.isArray(updates) || updates.length === 0) {
    return { updated: 0, total: 0 };
  }

  const stmt = db.prepare(`
    UPDATE requests
    SET ttft_ms = COALESCE(?, ttft_ms),
        ttfr_ms = COALESCE(?, ttfr_ms),
        ttfa_ms = COALESCE(?, ttfa_ms),
        tpot_ms = COALESCE(?, tpot_ms),
        tok_per_sec = COALESCE(?, tok_per_sec),
        latency_ms = COALESCE(?, latency_ms)
    WHERE dedup_key = ?
  `);

  const CHUNK_SIZE = 500;
  let updated = 0;

  for (let i = 0; i < updates.length; i += CHUNK_SIZE) {
    const chunk = updates.slice(i, i + CHUNK_SIZE);
    db.exec('BEGIN');
    try {
      for (const u of chunk) {
        if (!u || typeof u !== 'object') continue;
        const dedupKey = String(u.dedup_key || u.dedupKey || '').trim();
        if (!dedupKey) continue;
        const ttftMs = toNullableNum(u.ttft_ms);
        const ttfrMs = toNullableNum(u.ttfr_ms);
        const ttfaMs = toNullableNum(u.ttfa_ms);
        const tpotMs = toNullableNum(u.tpot_ms);
        const tokPerSec = toNullableNum(u.tok_per_sec);
        const latencyMs = toNullableNum(u.latency_ms);
        if (
          ttftMs === null &&
          ttfrMs === null &&
          ttfaMs === null &&
          tpotMs === null &&
          tokPerSec === null &&
          latencyMs === null
        ) {
          continue;
        }
        const res = stmt.run(ttftMs, ttfrMs, ttfaMs, tpotMs, tokPerSec, latencyMs, dedupKey);
        if (res.changes > 0) updated += 1;
      }
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  }

  return { updated, total: updates.length };
}

/**
 * Build parameterized SQL WHERE clause and parameter bindings from standard filter object.
 * @param {object} [filters]
 * @param {string} [tableAlias='']
 */
export function buildFilterClause(filters = {}, tableAlias = '') {
  const pfx = tableAlias ? `${tableAlias}.` : '';
  const clauses = [];
  const params = [];

  const era = filters.era;
  if (era && era !== 'all') {
    clauses.push(`${pfx}era = ?`);
    params.push(String(era));
  }

  if (filters.from) {
    clauses.push(`${pfx}created_at >= ?`);
    params.push(String(filters.from).trim());
  }

  if (filters.to) {
    let toIso = String(filters.to).trim();
    if (/^\d{4}-\d{2}-\d{2}$/.test(toIso)) {
      toIso = `${toIso}T23:59:59.999Z`;
    }
    clauses.push(`${pfx}created_at <= ?`);
    params.push(toIso);
  }

  const accountId = filters.accountId || filters.account_id;
  if (accountId && accountId !== 'all') {
    clauses.push(`${pfx}account_id = ?`);
    params.push(String(accountId));
  }

  const modelId = filters.modelId || filters.model_id;
  if (modelId && modelId !== 'all') {
    clauses.push(`(${pfx}model_id = ? OR ${pfx}model_raw = ?)`);
    const norm = normalizeModelId(String(modelId));
    params.push(norm, String(modelId));
  }

  const sourceTool = filters.sourceTool || filters.source_tool;
  if (sourceTool && sourceTool !== 'all') {
    clauses.push(`${pfx}source_tool = ?`);
    params.push(String(sourceTool));
  }

  if (filters.workspace && filters.workspace !== 'all') {
    clauses.push(`${pfx}workspace LIKE ?`);
    params.push(`%${String(filters.workspace).trim()}%`);
  }

  const sessionId = filters.sessionId || filters.session_id;
  if (sessionId) {
    clauses.push(`${pfx}session_id = ?`);
    params.push(String(sessionId));
  }

  if (filters.q) {
    const qLike = `%${String(filters.q).trim()}%`;
    clauses.push(
      `(${pfx}model_id LIKE ? OR ${pfx}model_raw LIKE ? OR ${pfx}account_id LIKE ? OR ${pfx}title LIKE ? OR ${pfx}workspace LIKE ? OR ${pfx}session_id LIKE ? OR ${pfx}endpoint LIKE ?)`
    );
    params.push(qLike, qLike, qLike, qLike, qLike, qLike, qLike);
  }

  const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
  return { whereSql, clauses, params };
}

function maybeMaskAccountFields(obj, privacyMask) {
  if (!privacyMask || !obj) return obj;
  const out = { ...obj };
  if (out.email_or_label && out.email_or_label.includes('@')) {
    out.email_or_label = maskEmail(out.email_or_label);
  }
  if (out.display_name && out.display_name.includes('@')) {
    out.display_name = maskEmail(out.display_name);
  }
  if (out.account_email) {
    out.account_email = maskEmail(out.account_email);
  }
  if (out.account_id && out.account_id.includes('@')) {
    out.account_id_masked = maskEmail(out.account_id);
  }
  if (out.safety_identifier) {
    out.safety_identifier = maskIdentifier(out.safety_identifier);
  }
  if (out.workspace && typeof out.workspace === 'string') {
    out.workspace = maskWorkspacePath(out.workspace);
  }
  if (out.title && typeof out.title === 'string') {
    out.title = maskWorkspacePath(out.title);
  }
  return out;
}

/**
 * List accounts with aggregated token/cost usage, value multipliers, and quota snapshots.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {object} [filters]
 */
export function listAccounts(db, filters = {}) {
  const settings = getSettings(db);
  const privacyMask =
    filters.privacyMask !== undefined ? Boolean(filters.privacyMask) : settings.privacyMask;
  const fxUsdTry = settings.fxUsdTry || DEFAULT_FX_USD_TRY;

  const { whereSql, params } = buildFilterClause(filters);
  const usageRows = db
    .prepare(
      `SELECT
         account_id,
         MAX(source_tool) AS source_tool,
         MAX(provider) AS provider,
         MAX(account_email) AS account_email,
         COUNT(*) AS requests,
         COALESCE(SUM(input_tokens), 0) AS input_tokens,
         COALESCE(SUM(uncached_input_tokens), 0) AS uncached_input_tokens,
         COALESCE(SUM(output_tokens), 0) AS output_tokens,
         COALESCE(SUM(cache_read_tokens), 0) AS cache_read_tokens,
         COALESCE(SUM(cache_write_tokens), 0) AS cache_write_tokens,
         COALESCE(SUM(reasoning_tokens), 0) AS reasoning_tokens,
         COALESCE(SUM(compressed_tokens), 0) AS compressed_tokens,
         COALESCE(SUM(api_list_cost_usd), 0) AS api_list_cost_usd,
         COALESCE(SUM(billed_cost_usd), 0) AS billed_cost_usd,
         COALESCE(SUM(cache_savings_usd), 0) AS cache_savings_usd,
         COALESCE(SUM(compression_savings_usd), 0) AS compression_savings_usd,
         MIN(created_at) AS first_seen_at,
         MAX(created_at) AS last_seen_at
       FROM requests
       ${whereSql}
       GROUP BY account_id`
    )
    .all(...params);

  const usageMap = new Map(usageRows.map((u) => [u.account_id, u]));
  let dbAccounts = db
    .prepare(`SELECT ${ACCOUNT_COLS} FROM accounts ORDER BY is_active DESC, account_id ASC LIMIT 2000`)
    .all();
  const seenIds = new Set(dbAccounts.map((a) => a.account_id));

  for (const u of usageRows) {
    if (!seenIds.has(u.account_id)) {
      const planType = inferDefaultPlanType(u.source_tool, null, null);
      const defaultLabel = u.account_id === 'antigravity-main' ? 'Antigravity 2.0' : u.account_id;
      dbAccounts.push({
        account_id: u.account_id,
        source_tool: u.source_tool || 'antigravity',
        provider: u.provider || 'unknown',
        email_or_label: u.account_email || defaultLabel,
        display_name: u.account_email || defaultLabel,
        auth_type: 'api',
        plan_type: planType,
        monthly_fee_usd: 0.0,
        daily_budget_usd: 0,
        monthly_budget_usd: 0,
        group_name: '',
        is_active: 1,
        is_user_configured: 0,
      });
    }
  }

  const filterAccountId = filters.accountId || filters.account_id;
  if (filterAccountId && filterAccountId !== 'all') {
    dbAccounts = dbAccounts.filter((a) => a.account_id === String(filterAccountId));
  }
  const filterSourceTool = filters.sourceTool || filters.source_tool;
  if (filterSourceTool && filterSourceTool !== 'all') {
    dbAccounts = dbAccounts.filter(
      (a) => a.source_tool === String(filterSourceTool) || usageMap.has(a.account_id)
    );
  }

  const quotaRows = queryLatestQuotaSnapshots(db, 100);
  const quotasByAccount = new Map();
  for (const q of quotaRows) {
    if (!quotasByAccount.has(q.account_id)) quotasByAccount.set(q.account_id, []);
    quotasByAccount.get(q.account_id).push(maybeMaskAccountFields(q, privacyMask));
  }

  const results = dbAccounts.map((acc) => {
    const u = usageMap.get(acc.account_id) || {};
    const requests = Number(u.requests || 0);
    const inputTokens = Number(u.input_tokens || 0);
    const uncachedInputTokens = Number(u.uncached_input_tokens || 0);
    const outputTokens = Number(u.output_tokens || 0);
    const cacheReadTokens = Number(u.cache_read_tokens || 0);
    const cacheWriteTokens = Number(u.cache_write_tokens || 0);
    const reasoningTokens = Number(u.reasoning_tokens || 0);
    const compressedTokens = Number(u.compressed_tokens || 0);
    const totalTokens =
      inputTokens + outputTokens + cacheReadTokens + cacheWriteTokens + reasoningTokens;

    const cacheDenom = uncachedInputTokens + cacheReadTokens;
    const cacheHitPct = cacheDenom > 0 ? roundNum((cacheReadTokens / cacheDenom) * 100, 1) : 0;

    const apiListUsd = roundNum(u.api_list_cost_usd || 0, 6);
    const billedUsd = roundNum(u.billed_cost_usd || 0, 6);
    const cacheSavingsUsd = roundNum(u.cache_savings_usd || 0, 6);
    const compressionSavingsUsd = roundNum(u.compression_savings_usd || 0, 6);
    const avgCostPerRequestUsd = requests > 0 ? roundNum(apiListUsd / requests, 6) : 0;

    const valueStats = computeAccountValueStats(apiListUsd, {
      ...acc,
      billed_cost_usd: billedUsd,
    });

    const row = {
      ...acc,
      requests,
      total_requests: requests,
      input_tokens: inputTokens,
      uncached_input_tokens: uncachedInputTokens,
      output_tokens: outputTokens,
      cache_read_tokens: cacheReadTokens,
      cache_write_tokens: cacheWriteTokens,
      reasoning_tokens: reasoningTokens,
      compressed_tokens: compressedTokens,
      total_tokens: totalTokens,
      cache_hit_pct: cacheHitPct,
      api_list_cost_usd: apiListUsd,
      api_list_cost_try: roundNum(apiListUsd * fxUsdTry, 2),
      billed_cost_usd: billedUsd,
      billed_cost_try: roundNum(billedUsd * fxUsdTry, 2),
      subscription_fee_usd: valueStats.subscription_fee_usd,
      subscription_fee_try: roundNum(valueStats.subscription_fee_usd * fxUsdTry, 2),
      effective_paid_usd: valueStats.effective_paid_usd,
      effective_paid_try: roundNum(valueStats.effective_paid_usd * fxUsdTry, 2),
      list_value_multiplier: valueStats.list_value_multiplier,
      cache_savings_usd: cacheSavingsUsd,
      compression_savings_usd: compressionSavingsUsd,
      total_savings_usd: roundNum(cacheSavingsUsd + compressionSavingsUsd, 6),
      avg_cost_per_request_usd: avgCostPerRequestUsd,
      first_seen_at: u.first_seen_at || acc.created_at || null,
      last_seen_at: u.last_seen_at || acc.updated_at || null,
      quotas: quotasByAccount.get(acc.account_id) || [],
    };

    return maybeMaskAccountFields(row, privacyMask);
  });

  results.sort((a, b) => b.api_list_cost_usd - a.api_list_cost_usd || b.total_tokens - a.total_tokens);
  return results;
}

/**
 * Update account plan, fee, budget, or label.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {string} accountId
 * @param {object} patch
 */
export function updateAccount(db, accountId, patch = {}) {
  const id = String(accountId || '').trim();
  if (!id) throw new Error('updateAccount requires accountId');

  const existing = db
    .prepare(`SELECT ${ACCOUNT_COLS} FROM accounts WHERE account_id = ? LIMIT 1`)
    .get(id);
  const now = new Date().toISOString();
  if (!existing) {
    upsertAccount(db, { account_id: id, ...patch });
  }

  const current = db
    .prepare(`SELECT ${ACCOUNT_COLS} FROM accounts WHERE account_id = ? LIMIT 1`)
    .get(id);
  const planType =
    patch.plan_type && ['api', 'subscription', 'free'].includes(patch.plan_type)
      ? patch.plan_type
      : current.plan_type;
  const planChanged = planType !== current.plan_type;
  const hasExplicitFee =
    patch.monthly_fee_usd !== undefined || patch.subscription_fee_usd !== undefined;
  const monthlyFee = hasExplicitFee
    ? Number(patch.monthly_fee_usd ?? patch.subscription_fee_usd)
    : planChanged && planType !== 'subscription'
    ? 0.0
    : current.monthly_fee_usd;
  const dailyBudget =
    patch.daily_budget_usd !== undefined
      ? Number(patch.daily_budget_usd)
      : current.daily_budget_usd;
  const monthlyBudget =
    patch.monthly_budget_usd !== undefined
      ? Number(patch.monthly_budget_usd)
      : current.monthly_budget_usd;
  const emailOrLabel =
    patch.email_or_label !== undefined
      ? String(patch.email_or_label).trim()
      : current.email_or_label;
  const displayName =
    patch.display_name !== undefined
      ? String(patch.display_name).trim()
      : patch.email_or_label !== undefined
      ? String(patch.email_or_label).trim()
      : current.display_name;
  const groupName =
    patch.group_name !== undefined ? String(patch.group_name).trim() : current.group_name;
  const isActive =
    patch.is_active !== undefined ? (patch.is_active ? 1 : 0) : current.is_active;

  db.exec('BEGIN');
  try {
    db.prepare(`
      UPDATE accounts
      SET plan_type = ?,
          monthly_fee_usd = ?,
          daily_budget_usd = ?,
          monthly_budget_usd = ?,
          email_or_label = ?,
          display_name = ?,
          group_name = ?,
          is_active = ?,
          is_user_configured = 1,
          updated_at = ?
      WHERE account_id = ?
    `).run(
      planType,
      monthlyFee,
      dailyBudget,
      monthlyBudget,
      emailOrLabel,
      displayName,
      groupName,
      isActive,
      now,
      id
    );

    if (planChanged) {
      if (planType === 'subscription' || planType === 'free') {
        db.prepare(`
          UPDATE requests
          SET plan_type = ?, billed_cost_usd = 0
          WHERE account_id = ?
        `).run(planType, id);
        db.prepare(`
          UPDATE sessions
          SET total_billed_cost_usd = 0
          WHERE account_id = ?
        `).run(id);
      } else {
        db.prepare(`
          UPDATE requests
          SET plan_type = 'api',
              billed_cost_usd = CASE
                WHEN provider_cost_usd IS NOT NULL AND provider_cost_usd >= 0 THEN provider_cost_usd
                ELSE api_list_cost_usd
              END
          WHERE account_id = ?
        `).run(id);
        db.prepare(`
          UPDATE sessions
          SET total_billed_cost_usd = total_api_list_cost_usd
          WHERE account_id = ?
        `).run(id);
      }
    }

    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }

  return db
    .prepare(`SELECT ${ACCOUNT_COLS} FROM accounts WHERE account_id = ? LIMIT 1`)
    .get(id);
}

/**
 * List all models in the catalog with aggregated usage statistics.
 * Honors `era`, `from`, `to`, `sourceTool`, `accountId`, `modelId`, and `q` filters.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {object} [filters]
 */
export function listModels(db, filters = {}) {
  const { whereSql, params } = buildFilterClause(filters);
  const usageRows = db
    .prepare(
      `SELECT
         model_id,
         COUNT(*) AS requests,
         COALESCE(SUM(input_tokens), 0) AS input_tokens,
         COALESCE(SUM(output_tokens), 0) AS output_tokens,
         COALESCE(SUM(cache_read_tokens), 0) AS cache_read_tokens,
         COALESCE(SUM(cache_write_tokens), 0) AS cache_write_tokens,
         COALESCE(SUM(reasoning_tokens), 0) AS reasoning_tokens,
         COALESCE(SUM(api_list_cost_usd), 0) AS api_list_cost_usd,
         COALESCE(SUM(billed_cost_usd), 0) AS billed_cost_usd,
         COALESCE(SUM(cache_savings_usd), 0) AS cache_savings_usd,
         AVG(ttft_ms) AS avg_ttft_ms,
         AVG(tok_per_sec) AS avg_tok_per_sec
       FROM requests
       ${whereSql}
       GROUP BY model_id`
    )
    .all(...params);

  const usageMap = new Map(usageRows.map((u) => [u.model_id, u]));
  let models = db
    .prepare(`SELECT ${MODEL_COLS} FROM models ORDER BY is_custom DESC, provider ASC, model_id ASC LIMIT 5000`)
    .all();

  const filterModelId = filters.modelId || filters.model_id;
  if (filterModelId && filterModelId !== 'all') {
    const rawTarget = String(filterModelId).trim();
    const normTarget = normalizeModelId(rawTarget);
    models = models.filter(
      (m) => m.model_id === normTarget || m.model_id === rawTarget
    );
  }

  if (filters.q) {
    const needle = String(filters.q).trim().toLowerCase();
    if (needle) {
      models = models.filter((m) =>
        `${m.model_id} ${m.display_name} ${m.provider}`.toLowerCase().includes(needle)
      );
    }
  }

  return models.map((m) => {
    const u = usageMap.get(m.model_id) || {};
    const requests = Number(u.requests || 0);
    const totalTokens =
      Number(u.input_tokens || 0) +
      Number(u.output_tokens || 0) +
      Number(u.cache_read_tokens || 0) +
      Number(u.cache_write_tokens || 0) +
      Number(u.reasoning_tokens || 0);
    const apiListUsd = roundNum(u.api_list_cost_usd || 0, 6);

    return {
      ...m,
      is_custom: Boolean(m.is_custom),
      requests,
      total_tokens: totalTokens,
      input_tokens: Number(u.input_tokens || 0),
      output_tokens: Number(u.output_tokens || 0),
      cache_read_tokens: Number(u.cache_read_tokens || 0),
      cache_write_tokens: Number(u.cache_write_tokens || 0),
      reasoning_tokens: Number(u.reasoning_tokens || 0),
      api_list_cost_usd: apiListUsd,
      billed_cost_usd: roundNum(u.billed_cost_usd || 0, 6),
      cache_savings_usd: roundNum(u.cache_savings_usd || 0, 6),
      avg_cost_per_request_usd: requests > 0 ? roundNum(apiListUsd / requests, 6) : 0,
      avg_ttft_ms: u.avg_ttft_ms != null ? roundNum(u.avg_ttft_ms, 1) : null,
      avg_tok_per_sec: u.avg_tok_per_sec != null ? roundNum(u.avg_tok_per_sec, 1) : null,
    };
  });
}

/**
 * Create or update a model pricing entry (marks `is_custom = 1` so live sync preserves user overrides).
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {string} modelId
 * @param {object} patch
 */
export function updateModel(db, modelId, patch = {}) {
  const id = normalizeModelId(modelId || patch.model_id);
  if (!id || id === 'unknown') throw new Error('updateModel requires a valid modelId');

  const now = new Date().toISOString();
  const existing = db
    .prepare(`SELECT ${MODEL_COLS} FROM models WHERE model_id = ? LIMIT 1`)
    .get(id);

  const provider = String(patch.provider ?? existing?.provider ?? 'custom').trim();
  const displayName = String(patch.display_name ?? existing?.display_name ?? id).trim();
  const contextWindow = Number(patch.context_window ?? existing?.context_window ?? 1000000);
  const inputPer1M = Number(patch.input_per_1m ?? existing?.input_per_1m ?? 2.0);
  const outputPer1M = Number(patch.output_per_1m ?? existing?.output_per_1m ?? 10.0);
  const cacheReadPer1M = Number(
    patch.cache_read_per_1m ?? existing?.cache_read_per_1m ?? inputPer1M * 0.1
  );
  const cacheWritePer1M = Number(
    patch.cache_write_per_1m ?? existing?.cache_write_per_1m ?? inputPer1M * 1.25
  );
  const reasoningPer1M = Number(
    patch.reasoning_per_1m ?? existing?.reasoning_per_1m ?? outputPer1M
  );
  const requestFeeUsd = Number(patch.request_fee_usd ?? existing?.request_fee_usd ?? 0);
  const creditMultiplier = Number(
    patch.credit_multiplier ?? existing?.credit_multiplier ?? 1.0
  );
  const isCustom = patch.is_custom !== undefined ? (patch.is_custom ? 1 : 0) : 1;

  db.prepare(`
    INSERT INTO models (
      model_id,
      provider,
      display_name,
      context_window,
      input_per_1m,
      output_per_1m,
      cache_read_per_1m,
      cache_write_per_1m,
      reasoning_per_1m,
      request_fee_usd,
      credit_multiplier,
      source,
      is_custom,
      updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'custom', ?, ?)
    ON CONFLICT(model_id) DO UPDATE SET
      provider = excluded.provider,
      display_name = excluded.display_name,
      context_window = excluded.context_window,
      input_per_1m = excluded.input_per_1m,
      output_per_1m = excluded.output_per_1m,
      cache_read_per_1m = excluded.cache_read_per_1m,
      cache_write_per_1m = excluded.cache_write_per_1m,
      reasoning_per_1m = excluded.reasoning_per_1m,
      request_fee_usd = excluded.request_fee_usd,
      credit_multiplier = excluded.credit_multiplier,
      is_custom = excluded.is_custom,
      updated_at = excluded.updated_at
  `).run(
    id,
    provider,
    displayName,
    contextWindow,
    inputPer1M,
    outputPer1M,
    cacheReadPer1M,
    cacheWritePer1M,
    reasoningPer1M,
    requestFeeUsd,
    creditMultiplier,
    isCustom,
    now
  );

  return db
    .prepare(`SELECT ${MODEL_COLS} FROM models WHERE model_id = ? LIMIT 1`)
    .get(id);
}

const REQUEST_SORT_COLUMNS = {
  created_at: 'created_at',
  cost: 'api_list_cost_usd',
  api_list_cost_usd: 'api_list_cost_usd',
  billed_cost_usd: 'billed_cost_usd',
  context_tokens: 'context_tokens',
  context_utilization: 'context_utilization',
  context_pct: 'context_utilization',
  input_tokens: 'input_tokens',
  output_tokens: 'output_tokens',
  cache_read_tokens: 'cache_read_tokens',
  latency_ms: 'latency_ms',
  ttft_ms: 'ttft_ms',
  tok_per_sec: 'tok_per_sec',
  tokens_per_sec: 'tok_per_sec',
};

/**
 * List individual requests with filtering, search, pagination, and sorting.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {object} [filters]
 */
export function listRequests(db, filters = {}) {
  const settings = getSettings(db);
  const privacyMask =
    filters.privacyMask !== undefined ? Boolean(filters.privacyMask) : settings.privacyMask;
  const fxUsdTry = settings.fxUsdTry || DEFAULT_FX_USD_TRY;

  const { whereSql, params } = buildFilterClause(filters);
  const sortKey = REQUEST_SORT_COLUMNS[filters.sort] || 'created_at';
  const sortDir = String(filters.dir || 'DESC').toUpperCase() === 'ASC' ? 'ASC' : 'DESC';
  const limit = Math.min(1000, Math.max(1, Number(filters.limit) || 100));
  const offset = Math.max(0, Number(filters.offset) || 0);

  const countRow = db
    .prepare(`SELECT COUNT(*) AS cnt FROM requests ${whereSql}`)
    .get(...params);
  const total = Number(countRow?.cnt || 0);

  const rows = db
    .prepare(
      `SELECT ${REQUEST_COLS}
       FROM requests
       ${whereSql}
       ORDER BY ${sortKey} ${sortDir}, id DESC
       LIMIT ? OFFSET ?`
    )
    .all(...params, limit, offset);

  const items = rows.map((r) => {
    const contextPct =
      r.context_window > 0 ? roundNum((r.context_tokens / r.context_window) * 100, 1) : 0;
    const item = {
      ...r,
      context_pct: contextPct,
      tokens_per_sec: r.tok_per_sec,
      api_list_cost_try: roundNum((r.api_list_cost_usd || 0) * fxUsdTry, 4),
      billed_cost_try: roundNum((r.billed_cost_usd || 0) * fxUsdTry, 4),
    };
    return maybeMaskAccountFields(item, privacyMask);
  });

  return {
    rows: items,
    items,
    requests: items,
    total,
    limit,
    offset,
    fxUsdTry,
    privacyMask,
  };
}

function buildSessionFilterClause(filters = {}) {
  const clauses = [];
  const params = [];
  if (filters.era && filters.era !== 'all') {
    clauses.push('era = ?');
    params.push(String(filters.era));
  }
  const sourceTool = filters.sourceTool || filters.source_tool;
  if (sourceTool && sourceTool !== 'all') {
    clauses.push('source_tool = ?');
    params.push(String(sourceTool));
  }
  const accountId = filters.accountId || filters.account_id;
  if (accountId && accountId !== 'all') {
    clauses.push('account_id = ?');
    params.push(String(accountId));
  }
  if (filters.workspace && filters.workspace !== 'all') {
    clauses.push('workspace LIKE ?');
    params.push(`%${String(filters.workspace).trim()}%`);
  }
  if (filters.from) {
    clauses.push('last_event_at >= ?');
    params.push(String(filters.from).trim());
  }
  if (filters.to) {
    let toIso = String(filters.to).trim();
    if (/^\d{4}-\d{2}-\d{2}$/.test(toIso)) {
      toIso = `${toIso}T23:59:59.999Z`;
    }
    clauses.push('started_at <= ?');
    params.push(toIso);
  }
  const modelId = filters.modelId || filters.model_id;
  if (modelId && modelId !== 'all') {
    const rawModel = String(modelId).trim();
    const normModel = normalizeModelId(rawModel);
    clauses.push(
      `(primary_model_id = ? OR primary_model_id = ? OR EXISTS (SELECT 1 FROM requests r WHERE r.session_id = sessions.session_id AND (r.model_id = ? OR r.model_raw = ?)))`
    );
    params.push(normModel, rawModel, normModel, rawModel);
  }
  if (filters.q) {
    const qLike = `%${String(filters.q).trim()}%`;
    clauses.push(
      `(session_id LIKE ? OR title LIKE ? OR workspace LIKE ? OR account_id LIKE ? OR primary_model_id LIKE ? OR COALESCE(agent_name, '') LIKE ?)`
    );
    params.push(qLike, qLike, qLike, qLike, qLike, qLike);
  }
  return { clauses, params };
}

function fetchLatestSessionTimings(db, sessionIds) {
  const map = new Map();
  if (!Array.isArray(sessionIds) || sessionIds.length === 0) return map;

  const CHUNK_SIZE = 400;
  for (let i = 0; i < sessionIds.length; i += CHUNK_SIZE) {
    const chunk = sessionIds.slice(i, i + CHUNK_SIZE);
    const placeholders = chunk.map(() => '?').join(', ');
    const rows = db
      .prepare(
        `SELECT session_id, ttft_ms, tpot_ms, tok_per_sec
         FROM (
           SELECT
             session_id,
             ttft_ms,
             tpot_ms,
             tok_per_sec,
             ROW_NUMBER() OVER (
               PARTITION BY session_id
               ORDER BY
                 CASE WHEN ttft_ms IS NOT NULL OR tpot_ms IS NOT NULL OR tok_per_sec IS NOT NULL THEN 0 ELSE 1 END ASC,
                 created_at DESC,
                 id DESC
             ) AS rn
           FROM requests
           WHERE session_id IN (${placeholders})
         ) ranked
         WHERE rn = 1
         LIMIT ?`
      )
      .all(...chunk, chunk.length);
    for (const r of rows) {
      map.set(r.session_id, r);
    }
  }
  return map;
}

function enrichSessionRows(db, rows, fxUsdTry, privacyMask) {
  if (!Array.isArray(rows) || rows.length === 0) return [];
  const timingsMap = fetchLatestSessionTimings(
    db,
    rows.map((s) => s.session_id)
  );

  return rows.map((s) => {
    const windowSize = Number(s.context_window || 1000000);
    const latestCtx = Number(s.latest_context_tokens || 0);
    const activeCtx = Number(s.latest_context_tokens || s.peak_context_tokens || 0);
    const peakCtx = Number(s.peak_context_tokens || activeCtx);
    const utilizationPct = windowSize > 0 ? roundNum((activeCtx / windowSize) * 100, 1) : 0;
    const peakUtilizationPct = windowSize > 0 ? roundNum((peakCtx / windowSize) * 100, 1) : 0;
    const tokensTo65Pct = Math.max(0, Math.round(windowSize * 0.65 - latestCtx));
    const tokensTo80Pct = Math.max(0, Math.round(windowSize * 0.80 - latestCtx));

    const cacheDenom = Number(s.total_input_tokens || 0) + Number(s.total_cache_read_tokens || 0);
    const cacheHitPct =
      cacheDenom > 0 ? roundNum((Number(s.total_cache_read_tokens || 0) / cacheDenom) * 100, 1) : 0;

    let warningLevel = 'normal';
    if (utilizationPct >= 80) warningLevel = 'critical';
    else if (utilizationPct >= 65) warningLevel = 'warning';

    const timing = timingsMap.get(s.session_id);
    const item = {
      ...s,
      utilization_pct: utilizationPct,
      peak_utilization_pct: peakUtilizationPct,
      tokens_to_65_pct: tokensTo65Pct,
      tokens_to_80_pct: tokensTo80Pct,
      latest_ttft_ms: timing?.ttft_ms != null ? roundNum(timing.ttft_ms, 1) : null,
      latest_tpot_ms: timing?.tpot_ms != null ? roundNum(timing.tpot_ms, 2) : null,
      latest_tok_per_sec: timing?.tok_per_sec != null ? roundNum(timing.tok_per_sec, 1) : null,
      cache_hit_pct: cacheHitPct,
      warning_level: warningLevel,
      recommend_compact: utilizationPct >= 65,
      total_api_list_cost_try: roundNum((s.total_api_list_cost_usd || 0) * fxUsdTry, 2),
    };
    return maybeMaskAccountFields(item, privacyMask);
  });
}

/**
 * List sessions with live context pressure / utilization metrics, latest timings, and `/compact` headroom.
 * Honors `era`, `sourceTool`, `accountId`, `workspace`, `from`, `to`, `modelId`, and `q` filters.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {object} [filters]
 */
export function listSessions(db, filters = {}) {
  const settings = getSettings(db);
  const privacyMask =
    filters.privacyMask !== undefined ? Boolean(filters.privacyMask) : settings.privacyMask;
  const fxUsdTry = settings.fxUsdTry || DEFAULT_FX_USD_TRY;

  const { clauses, params } = buildSessionFilterClause(filters);
  const whereSql = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  const limit = Math.min(500, Math.max(1, Number(filters.limit) || 50));

  const rows = db
    .prepare(
      `SELECT ${SESSION_COLS}
       FROM sessions
       ${whereSql}
       ORDER BY last_event_at DESC
       LIMIT ?`
    )
    .all(...params, limit);

  const items = enrichSessionRows(db, rows, fxUsdTry, privacyMask);

  return {
    items,
    sessions: items,
    activeContextSessions: items,
    total: items.length,
    fxUsdTry,
    privacyMask,
  };
}

/**
 * Classify live-only `activeSessions` vs top-6 non-killed idle main `recentSessions`.
 * `activeSessions` strictly excludes killed sessions and idle workers.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {object} [filters]
 */
export function getLiveContext(db, filters = {}) {
  const settings = getSettings(db);
  const privacyMask =
    filters.privacyMask !== undefined ? Boolean(filters.privacyMask) : settings.privacyMask;
  const fxUsdTry = settings.fxUsdTry || DEFAULT_FX_USD_TRY;
  const limit = Math.min(50, Math.max(1, Number(filters.limit) || 15));
  const recentLimit = Math.min(50, Math.max(1, Number(filters.recentLimit) || 6));
  const cutoffIso = new Date(Date.now() - 15 * 60 * 1000).toISOString();

  const { clauses: baseClauses, params: baseParams } = buildSessionFilterClause(filters);

  const activeCondition = `(
    run_status = 'CASCADE_RUN_STATUS_RUNNING'
    OR COALESCE(not_fully_idle, 0) = 1
    OR (
      source_tool NOT LIKE 'antigravity%'
      AND last_event_at >= ?
      AND (latest_context_tokens > 0 OR peak_context_tokens > 0)
    )
  )`;

  const activeClauses = [...baseClauses, 'COALESCE(killed, 0) = 0', activeCondition];
  const activeWhereSql = `WHERE ${activeClauses.join(' AND ')}`;
  const activeRows = db
    .prepare(
      `SELECT ${SESSION_COLS}
       FROM sessions
       ${activeWhereSql}
       ORDER BY last_event_at DESC
       LIMIT ?`
    )
    .all(...baseParams, cutoffIso, limit);

  const recentClauses = [
    ...baseClauses,
    'COALESCE(killed, 0) = 0',
    "(COALESCE(nesting_depth, 0) = 0 OR source_tool NOT LIKE 'antigravity%')",
    '(total_requests > 0 OR latest_context_tokens > 0 OR peak_context_tokens > 0)',
    `NOT ${activeCondition}`,
  ];
  const recentWhereSql = `WHERE ${recentClauses.join(' AND ')}`;
  const recentRows = db
    .prepare(
      `SELECT ${SESSION_COLS}
       FROM sessions
       ${recentWhereSql}
       ORDER BY last_event_at DESC
       LIMIT ?`
    )
    .all(...baseParams, cutoffIso, recentLimit);

  const activeSessions = enrichSessionRows(db, activeRows, fxUsdTry, privacyMask);
  const recentSessions = enrichSessionRows(db, recentRows, fxUsdTry, privacyMask);

  return {
    sessions: activeSessions,
    activeSessions,
    recentSessions,
    recentLimit,
    activeContextSessions: activeSessions,
    fxUsdTry,
    privacyMask,
    updatedAt: new Date().toISOString(),
  };
}

/**
 * Build parent/child Swarm & Subagent cost roll-up trees from sessions.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {object} [filters]
 */
export function getSwarmTrees(db, filters = {}) {
  const { items: allSessions } = listSessions(db, { ...filters, limit: 500 });
  const byId = new Map(allSessions.map((s) => [s.session_id, { ...s, children: [] }]));
  const roots = [];

  for (const node of byId.values()) {
    if (node.parent_session_id && byId.has(node.parent_session_id)) {
      byId.get(node.parent_session_id).children.push(node);
    } else {
      roots.push(node);
    }
  }

  // Compute rolled-up swarm tree totals (root + all descendants)
  function rollupNode(n) {
    let treeRequests = Number(n.total_requests || 0);
    let treeTokens =
      Number(n.total_input_tokens || 0) +
      Number(n.total_output_tokens || 0) +
      Number(n.total_cache_read_tokens || 0) +
      Number(n.total_cache_write_tokens || 0) +
      Number(n.total_reasoning_tokens || 0);
    let treeApiListCostUsd = Number(n.total_api_list_cost_usd || 0);
    let treeCacheSavingsUsd = Number(n.total_cache_savings_usd || 0);

    for (const child of n.children) {
      const c = rollupNode(child);
      treeRequests += c.tree_requests;
      treeTokens += c.tree_tokens;
      treeApiListCostUsd += c.tree_api_list_cost_usd;
      treeCacheSavingsUsd += c.tree_cache_savings_usd;
    }

    n.tree_requests = treeRequests;
    n.tree_tokens = treeTokens;
    n.tree_api_list_cost_usd = roundNum(treeApiListCostUsd, 6);
    n.tree_cache_savings_usd = roundNum(treeCacheSavingsUsd, 6);
    n.worker_count = n.children.length;
    return n;
  }

  const rolledRoots = roots.map(rollupNode);
  // Prioritize multi-agent / swarm trees or active high-cost sessions
  rolledRoots.sort(
    (a, b) =>
      b.worker_count - a.worker_count ||
      b.tree_api_list_cost_usd - a.tree_api_list_cost_usd ||
      String(b.last_event_at).localeCompare(String(a.last_event_at))
  );

  return rolledRoots.slice(0, 30);
}

/**
 * Get comprehensive dashboard overview: KPIs, per-request quantiles, byAccount, byModel, bySource,
 * topExpensiveRequests, timeseries, activeContextSessions, swarmTrees, quotas, FX, milestone, privacy.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {object} [filters]
 */
export function getOverview(db, filters = {}) {
  const settings = getSettings(db);
  const privacyMask =
    filters.privacyMask !== undefined ? Boolean(filters.privacyMask) : settings.privacyMask;
  const fxUsdTry = settings.fxUsdTry || DEFAULT_FX_USD_TRY;
  const milestoneAt = settings.milestoneAt;

  const { whereSql, params } = buildFilterClause(filters);

  const kpiRow =
    db
      .prepare(
        `SELECT
           COUNT(*) AS total_requests,
           COALESCE(SUM(input_tokens), 0) AS input_tokens,
           COALESCE(SUM(uncached_input_tokens), 0) AS uncached_input_tokens,
           COALESCE(SUM(output_tokens), 0) AS output_tokens,
           COALESCE(SUM(cache_read_tokens), 0) AS cache_read_tokens,
           COALESCE(SUM(cache_write_tokens), 0) AS cache_write_tokens,
           COALESCE(SUM(reasoning_tokens), 0) AS reasoning_tokens,
           COALESCE(SUM(compressed_tokens), 0) AS compressed_tokens,
           COALESCE(SUM(api_list_cost_usd), 0) AS api_list_cost_usd,
           COALESCE(SUM(billed_cost_usd), 0) AS billed_cost_usd,
           COALESCE(SUM(cache_savings_usd), 0) AS cache_savings_usd,
           COALESCE(SUM(compression_savings_usd), 0) AS compression_savings_usd,
           AVG(ttft_ms) AS avg_ttft_ms,
           AVG(latency_ms) AS avg_latency_ms,
           AVG(tok_per_sec) AS avg_tok_per_sec
         FROM requests
         ${whereSql}`
      )
      .get(...params) || {};

  // Per-request cost distribution (avg, p50, p95, max)
  const costRows = db
    .prepare(
      `SELECT api_list_cost_usd
       FROM requests
       ${whereSql}
       ORDER BY api_list_cost_usd ASC
       LIMIT 500000`
    )
    .all(...params);
  const sortedCosts = costRows.map((r) => Number(r.api_list_cost_usd || 0));

  const totalRequests = Number(kpiRow.total_requests || 0);
  const apiListCostUsd = roundNum(kpiRow.api_list_cost_usd || 0, 6);
  const billedCostUsd = roundNum(kpiRow.billed_cost_usd || 0, 6);
  const cacheSavingsUsd = roundNum(kpiRow.cache_savings_usd || 0, 6);
  const compressionSavingsUsd = roundNum(kpiRow.compression_savings_usd || 0, 6);
  const totalSavingsUsd = roundNum(cacheSavingsUsd + compressionSavingsUsd, 6);

  const avgCostUsd = totalRequests > 0 ? roundNum(apiListCostUsd / totalRequests, 6) : 0;
  const p50CostUsd = roundNum(quantile(sortedCosts, 0.5), 6);
  const p95CostUsd = roundNum(quantile(sortedCosts, 0.95), 6);
  const maxCostUsd = sortedCosts.length ? roundNum(sortedCosts[sortedCosts.length - 1], 6) : 0;
  const minCostUsd = sortedCosts.length ? roundNum(sortedCosts[0], 6) : 0;

  const perRequestStats = {
    count: totalRequests,
    avg: avgCostUsd,
    p50: p50CostUsd,
    p95: p95CostUsd,
    max: maxCostUsd,
    min: minCostUsd,
    avg_usd: avgCostUsd,
    p50_usd: p50CostUsd,
    p95_usd: p95CostUsd,
    max_usd: maxCostUsd,
    avg_try: roundNum(avgCostUsd * fxUsdTry, 4),
    p50_try: roundNum(p50CostUsd * fxUsdTry, 4),
    p95_try: roundNum(p95CostUsd * fxUsdTry, 4),
    max_try: roundNum(maxCostUsd * fxUsdTry, 4),
  };

  const byAccount = listAccounts(db, { ...filters, privacyMask });

  // Roll up subscription fees & effective paid ONLY across accounts with requests in current filter
  let subscriptionFeesUsd = 0;
  let effectivePaidUsd = 0;
  for (const acc of byAccount) {
    if (acc.requests > 0) {
      if (acc.plan_type === 'subscription') {
        const fee = Number(acc.monthly_fee_usd ?? acc.subscription_fee_usd ?? 0);
        subscriptionFeesUsd += fee;
        effectivePaidUsd += fee;
      } else if (acc.plan_type === 'api') {
        effectivePaidUsd += Number(acc.billed_cost_usd || 0);
      }
    }
  }
  subscriptionFeesUsd = roundNum(subscriptionFeesUsd, 2);
  effectivePaidUsd = roundNum(effectivePaidUsd, 4);
  const listValueMultiplier =
    effectivePaidUsd > 0
      ? roundNum(apiListCostUsd / effectivePaidUsd, 2)
      : apiListCostUsd > 0
      ? null
      : 0;

  const inputTokens = Number(kpiRow.input_tokens || 0);
  const uncachedInputTokens = Number(kpiRow.uncached_input_tokens || 0);
  const outputTokens = Number(kpiRow.output_tokens || 0);
  const cacheReadTokens = Number(kpiRow.cache_read_tokens || 0);
  const cacheWriteTokens = Number(kpiRow.cache_write_tokens || 0);
  const reasoningTokens = Number(kpiRow.reasoning_tokens || 0);
  const compressedTokens = Number(kpiRow.compressed_tokens || 0);
  const totalTokens =
    inputTokens + outputTokens + cacheReadTokens + cacheWriteTokens + reasoningTokens;
  const cacheDenom = uncachedInputTokens + cacheReadTokens;
  const cacheHitPct = cacheDenom > 0 ? roundNum((cacheReadTokens / cacheDenom) * 100, 1) : 0;

  const kpis = {
    requests: totalRequests,
    totalRequests,
    total_requests: totalRequests,
    inputTokens,
    input_tokens: inputTokens,
    uncachedInputTokens,
    uncached_input_tokens: uncachedInputTokens,
    outputTokens,
    output_tokens: outputTokens,
    cacheReadTokens,
    cache_read_tokens: cacheReadTokens,
    cacheWriteTokens,
    cache_write_tokens: cacheWriteTokens,
    reasoningTokens,
    reasoning_tokens: reasoningTokens,
    compressedTokens,
    compressed_tokens: compressedTokens,
    totalTokens,
    total_tokens: totalTokens,
    cacheHitPct,
    cache_hit_pct: cacheHitPct,
    apiListCostUsd,
    api_list_cost_usd: apiListCostUsd,
    apiListCostTry: roundNum(apiListCostUsd * fxUsdTry, 2),
    api_list_cost_try: roundNum(apiListCostUsd * fxUsdTry, 2),
    billedCostUsd,
    billed_cost_usd: billedCostUsd,
    billedCostTry: roundNum(billedCostUsd * fxUsdTry, 2),
    billed_cost_try: roundNum(billedCostUsd * fxUsdTry, 2),
    subscriptionFeesUsd,
    subscription_fees_usd: subscriptionFeesUsd,
    effectivePaidUsd,
    effective_paid_usd: effectivePaidUsd,
    effectivePaidTry: roundNum(effectivePaidUsd * fxUsdTry, 2),
    effective_paid_try: roundNum(effectivePaidUsd * fxUsdTry, 2),
    listValueMultiplier,
    list_value_multiplier: listValueMultiplier,
    cacheSavingsUsd,
    cache_savings_usd: cacheSavingsUsd,
    compressionSavingsUsd,
    compression_savings_usd: compressionSavingsUsd,
    rtkSavingsUsd: compressionSavingsUsd,
    rtk_savings_usd: compressionSavingsUsd,
    totalSavingsUsd,
    total_savings_usd: totalSavingsUsd,
    totalSavingsTry: roundNum(totalSavingsUsd * fxUsdTry, 2),
    total_savings_try: roundNum(totalSavingsUsd * fxUsdTry, 2),
    avgCostPerReq: avgCostUsd,
    avgCostPerRequestUsd: avgCostUsd,
    avg_cost_per_request_usd: avgCostUsd,
    p50CostPerReq: p50CostUsd,
    p95CostPerReq: p95CostUsd,
    maxCostPerReq: maxCostUsd,
    avgTtftMs: kpiRow.avg_ttft_ms != null ? roundNum(kpiRow.avg_ttft_ms, 1) : null,
    avg_ttft_ms: kpiRow.avg_ttft_ms != null ? roundNum(kpiRow.avg_ttft_ms, 1) : null,
    avgLatencyMs: kpiRow.avg_latency_ms != null ? roundNum(kpiRow.avg_latency_ms, 1) : null,
    avg_latency_ms: kpiRow.avg_latency_ms != null ? roundNum(kpiRow.avg_latency_ms, 1) : null,
    avgTokPerSec: kpiRow.avg_tok_per_sec != null ? roundNum(kpiRow.avg_tok_per_sec, 1) : null,
    avg_tok_per_sec: kpiRow.avg_tok_per_sec != null ? roundNum(kpiRow.avg_tok_per_sec, 1) : null,
  };

  // By Model breakdown
  const modelCatalog = new Map(
    db
      .prepare(`SELECT model_id, display_name, provider FROM models LIMIT 5000`)
      .all()
      .map((m) => [m.model_id, m])
  );
  const byModelRows = db
    .prepare(
      `SELECT
         model_id,
         MAX(provider) AS provider,
         COUNT(*) AS requests,
         COALESCE(SUM(input_tokens), 0) AS input_tokens,
         COALESCE(SUM(output_tokens), 0) AS output_tokens,
         COALESCE(SUM(cache_read_tokens), 0) AS cache_read_tokens,
         COALESCE(SUM(cache_write_tokens), 0) AS cache_write_tokens,
         COALESCE(SUM(reasoning_tokens), 0) AS reasoning_tokens,
         COALESCE(SUM(api_list_cost_usd), 0) AS api_list_cost_usd,
         COALESCE(SUM(billed_cost_usd), 0) AS billed_cost_usd,
         COALESCE(SUM(cache_savings_usd), 0) AS cache_savings_usd,
         AVG(ttft_ms) AS avg_ttft_ms,
         AVG(tok_per_sec) AS avg_tok_per_sec
       FROM requests
       ${whereSql}
       GROUP BY model_id
       ORDER BY api_list_cost_usd DESC, requests DESC`
    )
    .all(...params);

  const byModel = byModelRows.map((m) => {
    const cat = modelCatalog.get(m.model_id);
    const reqs = Number(m.requests || 0);
    const listCost = roundNum(m.api_list_cost_usd || 0, 6);
    const totTok =
      Number(m.input_tokens || 0) +
      Number(m.output_tokens || 0) +
      Number(m.cache_read_tokens || 0) +
      Number(m.cache_write_tokens || 0) +
      Number(m.reasoning_tokens || 0);
    return {
      model_id: m.model_id,
      display_name: cat?.display_name || m.model_id,
      provider: cat?.provider || m.provider || 'unknown',
      requests: reqs,
      input_tokens: Number(m.input_tokens || 0),
      output_tokens: Number(m.output_tokens || 0),
      cache_read_tokens: Number(m.cache_read_tokens || 0),
      cache_write_tokens: Number(m.cache_write_tokens || 0),
      reasoning_tokens: Number(m.reasoning_tokens || 0),
      total_tokens: totTok,
      api_list_cost_usd: listCost,
      api_list_cost_try: roundNum(listCost * fxUsdTry, 2),
      billed_cost_usd: roundNum(m.billed_cost_usd || 0, 6),
      cache_savings_usd: roundNum(m.cache_savings_usd || 0, 6),
      avg_cost_per_request_usd: reqs > 0 ? roundNum(listCost / reqs, 6) : 0,
      avg_ttft_ms: m.avg_ttft_ms != null ? roundNum(m.avg_ttft_ms, 1) : null,
      avg_tok_per_sec: m.avg_tok_per_sec != null ? roundNum(m.avg_tok_per_sec, 1) : null,
    };
  });

  // By Source Tool breakdown
  const bySourceRows = db
    .prepare(
      `SELECT
         source_tool,
         COUNT(*) AS requests,
         COALESCE(SUM(input_tokens), 0) AS input_tokens,
         COALESCE(SUM(uncached_input_tokens), 0) AS uncached_input_tokens,
         COALESCE(SUM(output_tokens), 0) AS output_tokens,
         COALESCE(SUM(cache_read_tokens), 0) AS cache_read_tokens,
         COALESCE(SUM(cache_write_tokens), 0) AS cache_write_tokens,
         COALESCE(SUM(reasoning_tokens), 0) AS reasoning_tokens,
         COALESCE(SUM(compressed_tokens), 0) AS compressed_tokens,
         COALESCE(SUM(api_list_cost_usd), 0) AS api_list_cost_usd,
         COALESCE(SUM(billed_cost_usd), 0) AS billed_cost_usd,
         COALESCE(SUM(cache_savings_usd), 0) AS cache_savings_usd,
         COALESCE(SUM(compression_savings_usd), 0) AS compression_savings_usd
       FROM requests
       ${whereSql}
       GROUP BY source_tool
       ORDER BY api_list_cost_usd DESC, requests DESC`
    )
    .all(...params);

  const bySource = bySourceRows.map((s) => {
    const inTok = Number(s.input_tokens || 0);
    const uncachedIn = Number(s.uncached_input_tokens || 0);
    const cacheRead = Number(s.cache_read_tokens || 0);
    const totTok =
      inTok +
      Number(s.output_tokens || 0) +
      cacheRead +
      Number(s.cache_write_tokens || 0) +
      Number(s.reasoning_tokens || 0);
    const denom = uncachedIn + cacheRead;
    const listCost = roundNum(s.api_list_cost_usd || 0, 6);
    return {
      source_tool: s.source_tool,
      requests: Number(s.requests || 0),
      input_tokens: inTok,
      output_tokens: Number(s.output_tokens || 0),
      cache_read_tokens: cacheRead,
      cache_write_tokens: Number(s.cache_write_tokens || 0),
      reasoning_tokens: Number(s.reasoning_tokens || 0),
      compressed_tokens: Number(s.compressed_tokens || 0),
      total_tokens: totTok,
      cache_hit_pct: denom > 0 ? roundNum((cacheRead / denom) * 100, 1) : 0,
      api_list_cost_usd: listCost,
      api_list_cost_try: roundNum(listCost * fxUsdTry, 2),
      billed_cost_usd: roundNum(s.billed_cost_usd || 0, 6),
      cache_savings_usd: roundNum(s.cache_savings_usd || 0, 6),
      compression_savings_usd: roundNum(s.compression_savings_usd || 0, 6),
    };
  });

  // Top Expensive Requests
  const topExpensiveRequests = listRequests(db, {
    ...filters,
    privacyMask,
    sort: 'api_list_cost_usd',
    dir: 'DESC',
    limit: 15,
    offset: 0,
  }).items;

  // Daily Timeseries & Heatmap (newest `daysLimit` dates, ordered ASC)
  const rawDays = Number(filters.days);
  const daysLimit =
    Number.isFinite(rawDays) && rawDays > 0
      ? Math.min(375, Math.max(1, Math.round(rawDays)))
      : 371;

  const tsRows = db
    .prepare(
      `SELECT
         date,
         requests,
         input_tokens,
         uncached_input_tokens,
         cache_read_tokens,
         cache_write_tokens,
         output_tokens,
         reasoning_tokens,
         api_list_cost_usd,
         billed_cost_usd,
         cache_savings_usd
       FROM (
         SELECT
           SUBSTR(created_at, 1, 10) AS date,
           COUNT(*) AS requests,
           COALESCE(SUM(input_tokens), 0) AS input_tokens,
           COALESCE(SUM(uncached_input_tokens), 0) AS uncached_input_tokens,
           COALESCE(SUM(cache_read_tokens), 0) AS cache_read_tokens,
           COALESCE(SUM(cache_write_tokens), 0) AS cache_write_tokens,
           COALESCE(SUM(output_tokens), 0) AS output_tokens,
           COALESCE(SUM(reasoning_tokens), 0) AS reasoning_tokens,
           COALESCE(SUM(api_list_cost_usd), 0) AS api_list_cost_usd,
           COALESCE(SUM(billed_cost_usd), 0) AS billed_cost_usd,
           COALESCE(SUM(cache_savings_usd), 0) AS cache_savings_usd
         FROM requests
         ${whereSql}
         GROUP BY SUBSTR(created_at, 1, 10)
         ORDER BY date DESC
         LIMIT ?
       ) sub
       ORDER BY date ASC`
    )
    .all(...params, daysLimit);

  const timeseries = tsRows.map((d) => {
    const reqs = Number(d.requests || 0);
    const inTok = Number(d.input_tokens || 0);
    const uncachedIn = Number(d.uncached_input_tokens || 0);
    const cacheRead = Number(d.cache_read_tokens || 0);
    const cacheWrite = Number(d.cache_write_tokens || 0);
    const outTok = Number(d.output_tokens || 0);
    const reasonTok = Number(d.reasoning_tokens || 0);
    const totalTok = inTok + cacheRead + cacheWrite + outTok + reasonTok;
    const cacheDenom = uncachedIn + cacheRead;
    const cacheHit = cacheDenom > 0 ? roundNum((cacheRead / cacheDenom) * 100, 1) : 0;
    const apiList = roundNum(d.api_list_cost_usd || 0, 6);
    const billed = roundNum(d.billed_cost_usd || 0, 6);
    return {
      date: d.date,
      count: reqs,
      requests: reqs,
      input_tokens: inTok,
      uncached_input_tokens: uncachedIn,
      cache_read_tokens: cacheRead,
      cache_write_tokens: cacheWrite,
      output_tokens: outTok,
      reasoning_tokens: reasonTok,
      total_tokens: totalTok,
      tokens: totalTok,
      cache_hit_pct: cacheHit,
      api_list_cost_usd: apiList,
      billed_cost_usd: billed,
      cache_savings_usd: roundNum(d.cache_savings_usd || 0, 6),
    };
  });

  const liveCtx = getLiveContext(db, {
    ...filters,
    privacyMask,
    limit: 15,
  });

  const swarmTrees = getSwarmTrees(db, { ...filters, privacyMask });

  const quotas = queryLatestQuotaSnapshots(db, 100).map((q) =>
    maybeMaskAccountFields(q, privacyMask)
  );

  const heatmap = timeseries.map((d) => ({
    date: d.date,
    count: d.requests,
    requests: d.requests,
    tokens: d.tokens,
    api_list_cost_usd: d.api_list_cost_usd,
    billed_cost_usd: d.billed_cost_usd,
    cache_read_tokens: d.cache_read_tokens,
    uncached_input_tokens: d.uncached_input_tokens,
    cache_hit_pct: d.cache_hit_pct,
  }));

  return {
    era: filters.era || 'all',
    kpis,
    perRequestStats,
    byAccount,
    byModel,
    bySource,
    topExpensiveRequests,
    timeseries,
    heatmap,
    activeSessions: liveCtx.activeSessions,
    recentSessions: liveCtx.recentSessions,
    activeContextSessions: liveCtx.activeSessions,
    swarmTrees,
    quotas,
    fxUsdTry,
    fx_usd_try: fxUsdTry,
    milestoneAt,
    milestone_at: milestoneAt,
    privacyMask,
    privacy_mask: privacyMask,
  };
}

/**
 * Sanitize headers object to ensure zero secrets (`authorization`, `x-api-key`, `cookie`) are ever saved.
 * Uses a null-prototype map and rejects `__proto__`, `constructor`, `prototype`.
 * @param {object} headers
 */
function sanitizeHeaders(headers) {
  if (!headers || typeof headers !== 'object') return Object.create(null);
  const clean = Object.create(null);
  for (const [k, v] of Object.entries(headers)) {
    if (!isSafeObjectKey(k) || k === '__proto__' || k === 'constructor' || k === 'prototype') {
      continue;
    }
    const low = k.toLowerCase();
    if (
      low.includes('authorization') ||
      low.includes('api-key') ||
      low.includes('apikey') ||
      low.includes('token') ||
      low.includes('cookie') ||
      low.includes('secret')
    ) {
      continue;
    }
    clean[k] = v;
  }
  return clean;
}

/**
 * Save an SSE forensic capture into `sse_forensics`.
 * Strips any auth headers and masks `safety_identifier` if requested.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {object} capture
 */
export function saveForensicCapture(db, capture = {}) {
  const now = new Date().toISOString();
  const captureId = String(capture.capture_id || capture.id || `cap_${crypto.randomUUID()}`);
  const createdAt = String(capture.created_at || now);
  const sourceTool = String(capture.source_tool || 'forensics');
  const endpointMode = String(capture.endpoint_mode || capture.endpointMode || 'unknown');
  const baseUrl = String(capture.base_url || capture.baseUrl || '');
  const requestedModel = String(capture.requested_model || capture.requestedModel || '');
  const wireModel = String(capture.wire_model || capture.wireModel || capture.model || '');
  const selfReportedModel =
    capture.self_reported_model || capture.selfReportedModel || null;

  const headersObj =
    typeof capture.headers === 'object' && capture.headers !== null
      ? sanitizeHeaders(capture.headers)
      : {};
  const headersJson =
    typeof capture.headers_json === 'string'
      ? capture.headers_json
      : JSON.stringify(headersObj);

  const attributionJson =
    typeof capture.attribution_json === 'string'
      ? capture.attribution_json
      : capture.attribution || capture.usage?.attribution
      ? JSON.stringify(capture.attribution || capture.usage?.attribution)
      : null;

  const analysisJson =
    typeof capture.analysis_json === 'string'
      ? capture.analysis_json
      : capture.analysis
      ? JSON.stringify(capture.analysis)
      : null;

  const rawSafety = capture.safety_identifier || capture.safetyIdentifier || null;
  const safetyIdentifier = rawSafety ? maskIdentifier(String(rawSafety)) : null;

  const rawExcerpt = capture.raw_excerpt || capture.rawExcerpt || null;
  const safeExcerpt =
    typeof rawExcerpt === 'string' ? rawExcerpt.slice(0, 16000) : null;

  db.prepare(`
    INSERT INTO sse_forensics (
      capture_id,
      created_at,
      source_tool,
      endpoint_mode,
      base_url,
      requested_model,
      wire_model,
      self_reported_model,
      response_id,
      system_fingerprint,
      service_tier,
      prompt_cache_key,
      prompt_cache_retention,
      safety_identifier,
      has_signature,
      signature_length,
      input_tokens,
      output_tokens,
      cache_read_tokens,
      cache_write_tokens,
      cache_ttl_30m_tokens,
      cache_ttl_12h_tokens,
      reasoning_tokens,
      instructions_tokens,
      ttft_ms,
      ttfr_ms,
      ttfa_ms,
      tpot_ms,
      total_ms,
      tok_per_sec,
      chunk_count,
      jitter_ms,
      authenticity_score,
      verdict,
      attribution_json,
      headers_json,
      analysis_json,
      raw_excerpt
    ) VALUES (
      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
      ?, ?, ?, ?, ?, ?, ?, ?
    )
    ON CONFLICT(capture_id) DO UPDATE SET
      wire_model = excluded.wire_model,
      self_reported_model = excluded.self_reported_model,
      authenticity_score = excluded.authenticity_score,
      verdict = excluded.verdict,
      attribution_json = excluded.attribution_json,
      analysis_json = excluded.analysis_json
  `).run(
    captureId,
    createdAt,
    sourceTool,
    endpointMode,
    baseUrl,
    requestedModel,
    wireModel,
    selfReportedModel,
    capture.response_id || capture.responseId || null,
    capture.system_fingerprint || capture.systemFingerprint || null,
    capture.service_tier || capture.serviceTier || null,
    capture.prompt_cache_key || capture.promptCacheKey || null,
    capture.prompt_cache_retention || capture.promptCacheRetention || null,
    safetyIdentifier,
    capture.has_signature || capture.hasSignature ? 1 : 0,
    Number(capture.signature_length ?? capture.signatureLength ?? 0) || 0,
    Number(capture.input_tokens ?? capture.inputTokens ?? 0) || 0,
    Number(capture.output_tokens ?? capture.outputTokens ?? 0) || 0,
    Number(capture.cache_read_tokens ?? capture.cacheReadTokens ?? 0) || 0,
    Number(capture.cache_write_tokens ?? capture.cacheWriteTokens ?? 0) || 0,
    Number(capture.cache_ttl_30m_tokens ?? capture.cacheTtl30mTokens ?? 0) || 0,
    Number(capture.cache_ttl_12h_tokens ?? capture.cacheTtl12hTokens ?? 0) || 0,
    Number(capture.reasoning_tokens ?? capture.reasoningTokens ?? 0) || 0,
    Number(capture.instructions_tokens ?? capture.instructionsTokens ?? 0) || 0,
    capture.ttft_ms ?? capture.ttftMs ?? null,
    capture.ttfr_ms ?? capture.ttfrMs ?? null,
    capture.ttfa_ms ?? capture.ttfaMs ?? null,
    capture.tpot_ms ?? capture.tpotMs ?? null,
    capture.total_ms ?? capture.totalMs ?? null,
    capture.tok_per_sec ?? capture.tokPerSec ?? null,
    Number(capture.chunk_count ?? capture.chunkCount ?? 0) || 0,
    capture.jitter_ms ?? capture.jitterMs ?? null,
    Number(capture.authenticity_score ?? capture.authenticityScore ?? 0) || 0,
    String(capture.verdict || 'UNVERIFIED'),
    attributionJson,
    headersJson,
    analysisJson,
    safeExcerpt
  );

  return db
    .prepare(`SELECT ${FORENSIC_COLS} FROM sse_forensics WHERE capture_id = ? LIMIT 1`)
    .get(captureId);
}

/**
 * List saved SSE forensic captures.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {object} [filters]
 */
export function listForensicCaptures(db, filters = {}) {
  const settings = getSettings(db);
  const privacyMask =
    filters.privacyMask !== undefined ? Boolean(filters.privacyMask) : settings.privacyMask;
  const limit = Math.min(200, Math.max(1, Number(filters.limit) || 50));
  const offset = Math.max(0, Number(filters.offset) || 0);

  const clauses = [];
  const params = [];
  if (filters.endpointMode && filters.endpointMode !== 'all') {
    clauses.push('endpoint_mode = ?');
    params.push(String(filters.endpointMode));
  }
  if (filters.verdict && filters.verdict !== 'all') {
    clauses.push('verdict = ?');
    params.push(String(filters.verdict));
  }
  const whereSql = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';

  const rows = db
    .prepare(
      `SELECT ${FORENSIC_COLS}
       FROM sse_forensics
       ${whereSql}
       ORDER BY created_at DESC, id DESC
       LIMIT ? OFFSET ?`
    )
    .all(...params, limit, offset);

  const items = rows.map((r) => {
    let attribution = null;
    let headers = null;
    let analysis = null;
    try {
      if (r.attribution_json) attribution = JSON.parse(r.attribution_json);
    } catch (err) {
      debugLog('listForensicCaptures.attribution_json', err);
    }
    try {
      if (r.headers_json) headers = JSON.parse(r.headers_json);
    } catch (err) {
      debugLog('listForensicCaptures.headers_json', err);
    }
    try {
      if (r.analysis_json) analysis = JSON.parse(r.analysis_json);
    } catch (err) {
      debugLog('listForensicCaptures.analysis_json', err);
    }

    const item = {
      ...r,
      has_signature: Boolean(r.has_signature),
      attribution,
      headers,
      analysis,
    };
    return maybeMaskAccountFields(item, privacyMask);
  });

  return {
    items,
    captures: items,
    total: items.length,
  };
}

function escapeCsvCell(val) {
  if (val === null || val === undefined) return '';
  const s = String(val);
  if (/[",\r\n]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

/**
 * Export filtered requests and overview summary as CSV or JSON string.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {object} [filters]
 * @param {'csv'|'json'} [format='json']
 */
export function exportData(db, filters = {}, format = 'json') {
  const fmt = String(format || filters.format || 'json').toLowerCase();
  const { items } = listRequests(db, { ...filters, limit: 1000, offset: 0 });

  if (fmt === 'csv') {
    const columns = [
      'id',
      'created_at',
      'era',
      'source_tool',
      'account_id',
      'session_id',
      'model_id',
      'provider',
      'plan_type',
      'input_tokens',
      'uncached_input_tokens',
      'cache_read_tokens',
      'cache_write_tokens',
      'output_tokens',
      'reasoning_tokens',
      'compressed_tokens',
      'context_tokens',
      'context_window',
      'context_pct',
      'ttft_ms',
      'tpot_ms',
      'latency_ms',
      'tok_per_sec',
      'api_list_cost_usd',
      'billed_cost_usd',
      'cache_savings_usd',
      'compression_savings_usd',
      'workspace',
      'title',
    ];
    const headerLine = columns.join(',');
    const lines = items.map((row) => columns.map((c) => escapeCsvCell(row[c])).join(','));
    return [headerLine, ...lines].join('\n');
  }

  const overview = getOverview(db, filters);
  return JSON.stringify(
    {
      exported_at: new Date().toISOString(),
      filters,
      kpis: overview.kpis,
      perRequestStats: overview.perRequestStats,
      byAccount: overview.byAccount,
      byModel: overview.byModel,
      bySource: overview.bySource,
      requests: items,
    },
    null,
    2
  );
}
