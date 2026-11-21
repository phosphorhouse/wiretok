/**
 * Wiretok — SQLite WAL Schema, Initialization & Seed Catalog
 * Uses Node.js built-in `node:sqlite` (`DatabaseSync`) with zero external dependencies.
 */
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import {
  DB_PATH,
  DEFAULT_FX_USD_TRY,
  SEED_MODELS,
} from '../contracts.mjs';

const instances = new Map();

/**
 * Open (or return cached) SQLite database with WAL journal mode and schema initialized.
 * @param {string} [dbPath=DB_PATH]
 * @param {{ freshInstance?: boolean }} [opts]
 * @returns {DatabaseSync}
 */
export function openDatabase(dbPath = DB_PATH, opts = {}) {
  const resolvedPath = dbPath === ':memory:' ? ':memory:' : path.resolve(dbPath);
  if (!opts.freshInstance && resolvedPath !== ':memory:' && instances.has(resolvedPath)) {
    const cached = instances.get(resolvedPath);
    if (cached && cached.isOpen !== false) {
      return cached;
    }
  }

  if (resolvedPath !== ':memory:') {
    fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });
  }

  const db = new DatabaseSync(resolvedPath);
  initSchema(db);

  if (resolvedPath !== ':memory:' && !opts.freshInstance) {
    instances.set(resolvedPath, db);
  }
  return db;
}

export const openDb = openDatabase;
export const getDb = openDatabase;
export const initDb = openDatabase;

function debugLog(context, err) {
  if (process.env.WIRETOK_DEBUG) {
    process.stderr.write(`[wiretok] ${context}: ${err?.message || err}\n`);
  }
}

/**
 * Close a database instance and remove from singleton cache.
 * @param {DatabaseSync} [db]
 * @param {string} [dbPath=DB_PATH]
 */
export function closeDatabase(db, dbPath = DB_PATH) {
  const resolvedPath = dbPath === ':memory:' ? ':memory:' : path.resolve(dbPath);
  const target = db || instances.get(resolvedPath);
  if (target) {
    try {
      target.close();
    } catch (err) {
      debugLog('closeDatabase', err);
    }
  }
  instances.delete(resolvedPath);
}

/**
 * Run idempotent v0.2 schema column additions and data migrations.
 * Safe to invoke repeatedly on both fresh and pre-existing databases.
 * @param {DatabaseSync} db
 * @param {string} now
 */
function runV02Migrations(db, now) {
  // 1. Safe ALTER TABLE column migrations via PRAGMA table_info(...)
  const sessionCols = new Set(
    db.prepare('PRAGMA table_info(sessions)').all().map((c) => c.name)
  );
  if (!sessionCols.has('run_status')) {
    db.exec("ALTER TABLE sessions ADD COLUMN run_status TEXT DEFAULT ''");
  }
  if (!sessionCols.has('not_fully_idle')) {
    db.exec('ALTER TABLE sessions ADD COLUMN not_fully_idle INTEGER NOT NULL DEFAULT 0');
  }
  if (!sessionCols.has('killed')) {
    db.exec('ALTER TABLE sessions ADD COLUMN killed INTEGER NOT NULL DEFAULT 0');
  }
  if (!sessionCols.has('nesting_depth')) {
    db.exec('ALTER TABLE sessions ADD COLUMN nesting_depth INTEGER NOT NULL DEFAULT 0');
  }

  const accountCols = new Set(
    db.prepare('PRAGMA table_info(accounts)').all().map((c) => c.name)
  );
  if (!accountCols.has('is_user_configured')) {
    db.exec('ALTER TABLE accounts ADD COLUMN is_user_configured INTEGER NOT NULL DEFAULT 0');
  }

  db.exec(
    'CREATE INDEX IF NOT EXISTS idx_sessions_live_state ON sessions(killed, run_status, not_fully_idle, last_event_at);'
  );

  const getMetaStmt = db.prepare('SELECT value FROM meta WHERE key = ? LIMIT 1');
  const upsertMetaStmt = db.prepare(`
    INSERT INTO meta (key, value, updated_at)
    VALUES (?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
  `);

  // 2. Idempotent one-time privacy default upgrade (privacy_mask '0' -> '1' once unless toggled post-v0.2)
  const privacyMigDone = getMetaStmt.get('v02_privacy_default');
  if (!privacyMigDone) {
    const currentPrivacy = getMetaStmt.get('privacy_mask');
    db.exec('BEGIN');
    try {
      if (!currentPrivacy || currentPrivacy.value === '0') {
        upsertMetaStmt.run('privacy_mask', '1', now);
      }
      upsertMetaStmt.run('v02_privacy_default', '1', now);
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  }

  // 3. Idempotent synthetic $20 subscription fix for unconfigured claude-code-default / codex-default accounts
  const synthMigDone = getMetaStmt.get('v02_fix_synthetic_plans');
  if (!synthMigDone) {
    db.exec('BEGIN');
    try {
      const syntheticToFix = db
        .prepare(`
          SELECT account_id
          FROM accounts
          WHERE account_id IN ('claude-code-default', 'codex-default')
            AND COALESCE(is_user_configured, 0) = 0
            AND plan_type = 'subscription'
            AND monthly_fee_usd = 20.0
          LIMIT 50
        `)
        .all();

      if (syntheticToFix.length > 0) {
        const fixAccountStmt = db.prepare(`
          UPDATE accounts
          SET plan_type = 'api',
              monthly_fee_usd = 0.0,
              updated_at = ?
          WHERE account_id = ?
            AND COALESCE(is_user_configured, 0) = 0
            AND plan_type = 'subscription'
            AND monthly_fee_usd = 20.0
        `);
        const fixReqStmt = db.prepare(`
          UPDATE requests
          SET billed_cost_usd = api_list_cost_usd,
              plan_type = 'api'
          WHERE account_id = ?
        `);
        const fixSessStmt = db.prepare(`
          UPDATE sessions
          SET total_billed_cost_usd = total_api_list_cost_usd
          WHERE account_id = ?
        `);

        for (const row of syntheticToFix) {
          fixAccountStmt.run(now, row.account_id);
          fixReqStmt.run(row.account_id);
          fixSessStmt.run(row.account_id);
        }
      }

      upsertMetaStmt.run('v02_fix_synthetic_plans', '1', now);
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  }

  // 4. Idempotent stale Antigravity email/label cleanup for unconfigured accounts
  const agLabelMigDone = getMetaStmt.get('v02_fix_ag_stale_label');
  if (!agLabelMigDone) {
    db.exec('BEGIN');
    try {
      db.prepare(`
        UPDATE accounts
        SET display_name = 'Antigravity 2.0',
            email_or_label = 'Antigravity 2.0',
            updated_at = ?
        WHERE source_tool = 'antigravity'
          AND COALESCE(is_user_configured, 0) = 0
          AND (
            account_id IN ('antigravity-main', 'antigravity-default')
            OR email_or_label LIKE '%@%'
            OR display_name LIKE '%@%'
            OR display_name = ''
          )
      `).run(now);
      upsertMetaStmt.run('v02_fix_ag_stale_label', '1', now);
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  }
}

/**
 * Initialize PRAGMAs, tables, indexes, and baseline seed rows.
 * @param {DatabaseSync} db
 */
export function initSchema(db) {
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA busy_timeout = 5000;
    PRAGMA synchronous = NORMAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS accounts (
      account_id TEXT PRIMARY KEY,
      source_tool TEXT NOT NULL DEFAULT 'antigravity',
      provider TEXT NOT NULL DEFAULT 'google',
      email_or_label TEXT NOT NULL DEFAULT '',
      display_name TEXT NOT NULL DEFAULT '',
      auth_type TEXT NOT NULL DEFAULT 'oauth',
      plan_type TEXT NOT NULL DEFAULT 'api',
      monthly_fee_usd REAL NOT NULL DEFAULT 0.0,
      daily_budget_usd REAL NOT NULL DEFAULT 0,
      monthly_budget_usd REAL NOT NULL DEFAULT 0,
      group_name TEXT NOT NULL DEFAULT '',
      is_active INTEGER NOT NULL DEFAULT 1,
      is_user_configured INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS models (
      model_id TEXT PRIMARY KEY,
      provider TEXT NOT NULL DEFAULT 'unknown',
      display_name TEXT NOT NULL DEFAULT '',
      context_window INTEGER NOT NULL DEFAULT 1000000,
      input_per_1m REAL NOT NULL DEFAULT 2.0,
      output_per_1m REAL NOT NULL DEFAULT 10.0,
      cache_read_per_1m REAL NOT NULL DEFAULT 0.2,
      cache_write_per_1m REAL NOT NULL DEFAULT 2.5,
      reasoning_per_1m REAL NOT NULL DEFAULT 10.0,
      request_fee_usd REAL NOT NULL DEFAULT 0,
      credit_multiplier REAL NOT NULL DEFAULT 1.0,
      aa_intelligence REAL,
      aa_coding REAL,
      speed_tok_s REAL,
      release_date TEXT,
      source TEXT NOT NULL DEFAULT 'seed',
      is_custom INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      session_id TEXT PRIMARY KEY,
      source_tool TEXT NOT NULL DEFAULT 'antigravity',
      account_id TEXT NOT NULL DEFAULT 'unknown',
      title TEXT NOT NULL DEFAULT '',
      workspace TEXT NOT NULL DEFAULT '',
      parent_session_id TEXT,
      agent_name TEXT,
      group_id TEXT,
      primary_model_id TEXT,
      context_window INTEGER NOT NULL DEFAULT 1000000,
      latest_context_tokens INTEGER NOT NULL DEFAULT 0,
      peak_context_tokens INTEGER NOT NULL DEFAULT 0,
      total_requests INTEGER NOT NULL DEFAULT 0,
      total_input_tokens INTEGER NOT NULL DEFAULT 0,
      total_output_tokens INTEGER NOT NULL DEFAULT 0,
      total_cache_read_tokens INTEGER NOT NULL DEFAULT 0,
      total_cache_write_tokens INTEGER NOT NULL DEFAULT 0,
      total_reasoning_tokens INTEGER NOT NULL DEFAULT 0,
      total_api_list_cost_usd REAL NOT NULL DEFAULT 0,
      total_billed_cost_usd REAL NOT NULL DEFAULT 0,
      total_cache_savings_usd REAL NOT NULL DEFAULT 0,
      era TEXT NOT NULL DEFAULT 'live',
      started_at TEXT NOT NULL,
      last_event_at TEXT NOT NULL,
      run_status TEXT DEFAULT '',
      not_fully_idle INTEGER NOT NULL DEFAULT 0,
      killed INTEGER NOT NULL DEFAULT 0,
      nesting_depth INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      dedup_key TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL,
      completed_at TEXT,
      era TEXT NOT NULL DEFAULT 'live',
      source_tool TEXT NOT NULL DEFAULT 'antigravity',
      account_id TEXT NOT NULL DEFAULT 'unknown',
      account_email TEXT NOT NULL DEFAULT '',
      session_id TEXT,
      step_index INTEGER,
      parent_session_id TEXT,
      agent_name TEXT,
      group_id TEXT,
      title TEXT NOT NULL DEFAULT '',
      workspace TEXT NOT NULL DEFAULT '',
      endpoint_mode TEXT NOT NULL DEFAULT 'unknown',
      endpoint TEXT NOT NULL DEFAULT '',
      combo_name TEXT NOT NULL DEFAULT '',
      model_raw TEXT NOT NULL DEFAULT 'unknown',
      raw_model TEXT NOT NULL DEFAULT 'unknown',
      model_id TEXT NOT NULL DEFAULT 'unknown',
      provider TEXT NOT NULL DEFAULT 'unknown',
      effort TEXT,
      plan_type TEXT NOT NULL DEFAULT 'api',
      input_tokens INTEGER NOT NULL DEFAULT 0,
      uncached_input_tokens INTEGER NOT NULL DEFAULT 0,
      output_tokens INTEGER NOT NULL DEFAULT 0,
      cache_read_tokens INTEGER NOT NULL DEFAULT 0,
      cache_write_tokens INTEGER NOT NULL DEFAULT 0,
      cache_write_5m_tokens INTEGER NOT NULL DEFAULT 0,
      cache_write_1h_tokens INTEGER NOT NULL DEFAULT 0,
      cache_ttl_30m_tokens INTEGER NOT NULL DEFAULT 0,
      cache_ttl_12h_tokens INTEGER NOT NULL DEFAULT 0,
      reasoning_tokens INTEGER NOT NULL DEFAULT 0,
      compressed_tokens INTEGER NOT NULL DEFAULT 0,
      instructions_tokens INTEGER NOT NULL DEFAULT 0,
      context_tokens INTEGER NOT NULL DEFAULT 0,
      context_window INTEGER NOT NULL DEFAULT 1000000,
      context_utilization REAL NOT NULL DEFAULT 0,
      ttft_ms REAL,
      ttfr_ms REAL,
      ttfa_ms REAL,
      tpot_ms REAL,
      latency_ms REAL,
      tok_per_sec REAL,
      token_cost_usd REAL NOT NULL DEFAULT 0,
      request_fee_usd REAL NOT NULL DEFAULT 0,
      tool_surcharge_usd REAL NOT NULL DEFAULT 0,
      api_list_cost_usd REAL NOT NULL DEFAULT 0,
      billed_cost_usd REAL NOT NULL DEFAULT 0,
      provider_cost_usd REAL,
      reported_cost_usd REAL,
      cache_savings_usd REAL NOT NULL DEFAULT 0,
      compression_savings_usd REAL NOT NULL DEFAULT 0,
      credit_multiplier REAL NOT NULL DEFAULT 1.0,
      service_tier TEXT,
      prompt_cache_retention TEXT,
      safety_identifier TEXT,
      response_id TEXT,
      system_fingerprint TEXT,
      has_signature INTEGER NOT NULL DEFAULT 0,
      authenticity_score INTEGER,
      verdict TEXT,
      status TEXT NOT NULL DEFAULT 'ok',
      status_code INTEGER NOT NULL DEFAULT 200,
      meta_json TEXT
    );

    CREATE TABLE IF NOT EXISTS sync_cursors (
      source_key TEXT PRIMARY KEY,
      cursor_key TEXT,
      source_tool TEXT NOT NULL DEFAULT '',
      byte_offset INTEGER NOT NULL DEFAULT 0,
      line_no INTEGER NOT NULL DEFAULT 0,
      line_offset INTEGER NOT NULL DEFAULT 0,
      last_id TEXT,
      last_rowid INTEGER NOT NULL DEFAULT 0,
      last_timestamp TEXT,
      mtime_ms REAL NOT NULL DEFAULT 0,
      size INTEGER NOT NULL DEFAULT 0,
      extra_json TEXT,
      meta_json TEXT,
      updated_at TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS sse_forensics (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      capture_id TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL,
      source_tool TEXT NOT NULL DEFAULT 'forensics',
      endpoint_mode TEXT NOT NULL DEFAULT 'unknown',
      base_url TEXT NOT NULL DEFAULT '',
      requested_model TEXT NOT NULL DEFAULT '',
      wire_model TEXT NOT NULL DEFAULT '',
      self_reported_model TEXT,
      response_id TEXT,
      system_fingerprint TEXT,
      service_tier TEXT,
      prompt_cache_key TEXT,
      prompt_cache_retention TEXT,
      safety_identifier TEXT,
      has_signature INTEGER NOT NULL DEFAULT 0,
      signature_length INTEGER NOT NULL DEFAULT 0,
      input_tokens INTEGER NOT NULL DEFAULT 0,
      output_tokens INTEGER NOT NULL DEFAULT 0,
      cache_read_tokens INTEGER NOT NULL DEFAULT 0,
      cache_write_tokens INTEGER NOT NULL DEFAULT 0,
      cache_ttl_30m_tokens INTEGER NOT NULL DEFAULT 0,
      cache_ttl_12h_tokens INTEGER NOT NULL DEFAULT 0,
      reasoning_tokens INTEGER NOT NULL DEFAULT 0,
      instructions_tokens INTEGER NOT NULL DEFAULT 0,
      ttft_ms REAL,
      ttfr_ms REAL,
      ttfa_ms REAL,
      tpot_ms REAL,
      total_ms REAL,
      tok_per_sec REAL,
      chunk_count INTEGER NOT NULL DEFAULT 0,
      jitter_ms REAL,
      authenticity_score INTEGER NOT NULL DEFAULT 0,
      verdict TEXT NOT NULL DEFAULT 'UNVERIFIED',
      attribution_json TEXT,
      headers_json TEXT,
      analysis_json TEXT,
      raw_excerpt TEXT
    );

    CREATE TABLE IF NOT EXISTS quota_snapshots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      quota_id TEXT UNIQUE,
      captured_at TEXT NOT NULL DEFAULT '',
      source_tool TEXT NOT NULL DEFAULT 'omniroute',
      account_id TEXT NOT NULL DEFAULT 'unknown',
      provider TEXT NOT NULL DEFAULT '',
      model_id TEXT NOT NULL DEFAULT '',
      tier_or_model TEXT NOT NULL DEFAULT '',
      window_key TEXT NOT NULL DEFAULT '',
      tokens_used INTEGER,
      token_limit INTEGER,
      limit_requests INTEGER,
      remaining_requests INTEGER,
      limit_tokens INTEGER,
      remaining_tokens INTEGER,
      remaining_pct REAL,
      used_percent REAL,
      window_start TEXT,
      window_reset TEXT,
      reset_at TEXT,
      is_exhausted INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'ok',
      raw_json TEXT,
      meta_json TEXT,
      updated_at TEXT NOT NULL DEFAULT ''
    );

    CREATE INDEX IF NOT EXISTS idx_requests_created_at ON requests(created_at);
    CREATE INDEX IF NOT EXISTS idx_requests_account_id ON requests(account_id);
    CREATE INDEX IF NOT EXISTS idx_requests_model_id ON requests(model_id);
    CREATE INDEX IF NOT EXISTS idx_requests_source_tool ON requests(source_tool);
    CREATE INDEX IF NOT EXISTS idx_requests_era ON requests(era);
    CREATE INDEX IF NOT EXISTS idx_requests_session_id ON requests(session_id);

    CREATE INDEX IF NOT EXISTS idx_sessions_last_event_at ON sessions(last_event_at);
    CREATE INDEX IF NOT EXISTS idx_sessions_account_id ON sessions(account_id);
    CREATE INDEX IF NOT EXISTS idx_forensics_created_at ON sse_forensics(created_at);
    CREATE INDEX IF NOT EXISTS idx_quotas_account_id ON quota_snapshots(account_id);
  `);

  const now = new Date().toISOString();

  // Seed meta defaults once if unset
  const insertMetaStmt = db.prepare(`
    INSERT OR IGNORE INTO meta (key, value, updated_at)
    VALUES (?, ?, ?)
  `);
  insertMetaStmt.run('milestone_at', now, now);
  insertMetaStmt.run('fx_usd_try', String(DEFAULT_FX_USD_TRY), now);
  insertMetaStmt.run('privacy_mask', '1', now);

  // Run idempotent v0.2 column & data migrations
  runV02Migrations(db, now);

  // Seed baseline November 2026 models via INSERT OR IGNORE
  const insertModelStmt = db.prepare(`
    INSERT OR IGNORE INTO models (
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
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'seed', 0, ?)
  `);

  db.exec('BEGIN');
  try {
    for (const m of SEED_MODELS) {
      insertModelStmt.run(
        m.model_id,
        m.provider || 'unknown',
        m.display_name || m.model_id,
        m.context_window ?? 1000000,
        m.input_per_1m ?? 2.0,
        m.output_per_1m ?? 10.0,
        m.cache_read_per_1m ?? 0.2,
        m.cache_write_per_1m ?? 2.5,
        m.reasoning_per_1m ?? m.output_per_1m ?? 10.0,
        m.request_fee_usd ?? 0,
        m.credit_multiplier ?? 1.0,
        now
      );
    }
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }

  return db;
}
