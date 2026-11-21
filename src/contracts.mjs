/**
 * Wiretok — Shared System Contracts & Constants
 * All modules (DB, Pricing, Collectors, Forensics, Server, CLI, Hooks, UI) MUST import from this file.
 */
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __contractsDir = path.dirname(fileURLToPath(import.meta.url));
export const VERSION = '0.2.0';
export const ROOT_DIR = path.resolve(__contractsDir, '..');
export const DATA_DIR = process.env.WIRETOK_DATA_DIR
  ? path.resolve(process.env.WIRETOK_DATA_DIR)
  : path.join(os.homedir(), '.wiretok');
export const DB_PATH = process.env.WIRETOK_DB_PATH
  ? path.resolve(process.env.WIRETOK_DB_PATH)
  : path.join(DATA_DIR, 'wiretok.sqlite');
export const HOOK_EVENTS_LOG = path.join(DATA_DIR, 'hook_events.jsonl');
export const INGEST_EVENTS_LOG = path.join(DATA_DIR, 'ingest_events.jsonl');
export const FORENSICS_LOG = path.join(DATA_DIR, 'forensics_captures.jsonl');
export const UI_DIR = path.join(ROOT_DIR, 'ui');
export const PLUGIN_DIR = path.join(ROOT_DIR, 'plugins', 'wiretok');

export const DEFAULT_WEB_PORT = 19840;
export const DEFAULT_TEE_PORT = 19841;
export const DEFAULT_FX_USD_TRY = 34.5;

export const ENDPOINT_MODES = /** @type {const} */ ([
  'responses',
  'messages',
  'chat_completions',
  'gemini',
  'unknown',
]);

export const SOURCE_TOOLS = /** @type {const} */ ([
  'antigravity',
  'antigravity-ide',
  'antigravity-cli',
  'omniroute',
  '9router',
  'claude-code',
  'codex',
  'opencode',
  'tee-proxy',
  'manual-ingest',
]);

export const ERAS = /** @type {const} */ (['live', 'pre_milestone']);
export const PLAN_TYPES = /** @type {const} */ (['api', 'subscription', 'free']);
export const VERDICTS = /** @type {const} */ ([
  'VERIFIED_NATIVE',
  'LIKELY_NATIVE',
  'TRANSLATED_PROXY',
  'SUSPECTED_SPOOF',
  'UNVERIFIED',
]);

/**
 * External read-only local data locations on Windows/Unix.
 * NEVER read oauth_creds.json, cookies, or secret tokens from these roots.
 */
export function getLocalSourcePaths() {
  const home = os.homedir();
  const isMac = process.platform === 'darwin';
  const localAppData =
    process.env.LOCALAPPDATA ||
    (isMac ? path.join(home, 'Library', 'Application Support') : process.env.XDG_DATA_HOME || path.join(home, '.local', 'share'));
  const appData =
    process.env.APPDATA ||
    (isMac ? path.join(home, 'Library', 'Application Support') : process.env.XDG_CONFIG_HOME || path.join(home, '.config'));
  const extraOpencode = (process.env.WIRETOK_OPENCODE_DIRS || '')
    .split(path.delimiter)
    .map((s) => s.trim())
    .filter(Boolean);
  const opencodeDirs = [
    path.join(home, '.local', 'share', 'opencode'),
    path.join(localAppData, 'opencode'),
    path.join(appData, 'opencode'),
    ...extraOpencode,
  ];
  return {
    home,
    geminiDir: path.join(home, '.gemini'),
    googleAccountsJson: path.join(home, '.gemini', 'google_accounts.json'),
    antigravityDir: path.join(home, '.gemini', 'antigravity'),
    antigravityIdeDir: path.join(home, '.gemini', 'antigravity-ide'),
    antigravityCliDir: path.join(home, '.gemini', 'antigravity-cli'),
    omnirouteDb: path.join(home, '.omniroute', 'storage.sqlite'),
    router9Dirs: [
      path.join(home, '.9router'),
      path.join(appData, '9router'),
      path.join(localAppData, '9router'),
    ],
    claudeProjectsDir: path.join(home, '.claude', 'projects'),
    codexSessionsDir: path.join(home, '.codex', 'sessions'),
    opencodeDirs: [...new Set(opencodeDirs)],
  };
}

/**
 * Mask email or user safety identifier for Privacy Mode (e.g. "a***e@example.com", "user-wcir...tchy").
 */
export function maskIdentifier(value) {
  if (!value || typeof value !== 'string') return '***';
  const s = value.trim();
  if (s.includes('@')) {
    const [local, domain] = s.split('@');
    if (local.length <= 2) return `${local[0] || '*'}*@${domain}`;
    return `${local[0]}***${local[local.length - 1]}@${domain}`;
  }
  if (s.length <= 8) return `${s.slice(0, 2)}***`;
  return `${s.slice(0, 6)}...${s.slice(-4)}`;
}

/** Alias preserving explicit email masking intent. */
export function maskEmail(value) {
  return maskIdentifier(value);
}

/** Mask Windows/Unix home username segments inside workspace paths for privacy mode. */
export function maskWorkspacePath(value) {
  if (!value || typeof value !== 'string') return value;
  return value
    .replace(/([A-Za-z]:\\Users\\)([^\\/\r\n]+)/gi, '$1<user>')
    .replace(/(\/(?:Users|home)\/)([^/\r\n]+)/g, '$1<user>');
}

/** Reject dangerous prototype-pollution property keys on untrusted JSON merges. */
export function isSafeObjectKey(key) {
  return key !== '__proto__' && key !== 'constructor' && key !== 'prototype';
}

/**
 * Normalize model slugs for consistent pricing lookup across Antigravity, OmniRoute, OpenRouter, Claude, Codex, OpenCode.
 */
export function normalizeModelId(rawModel) {
  if (!rawModel || typeof rawModel !== 'string') return 'unknown';
  let m = rawModel.trim().toLowerCase();
  if (!m || m === 'auto' || m === 'unknown') return m || 'unknown';
  // Strip common provider prefixes like "google/", "anthropic/", "openai/", "vertex/", "kr/", etc.
  if (m.includes('/')) {
    const parts = m.split('/');
    m = parts[parts.length - 1];
  }
  // Map Antigravity internal variants & reasoning effort suffixes to canonical pricing IDs
  const aliases = {
    'gemini-pro-orchestrator': 'gemini-4-carbon',
    'gemini-pro-orchestrator-neon': 'gemini-4-neon',
    'gemini-pro-orchestrator-g1-pro': 'gemini-4-argon',
    'gemini-pro-orchestrator-argon': 'gemini-4-argon',
    'orchestrator (carbon)': 'gemini-4-carbon',
    'orchestrator (neon)': 'gemini-4-neon',
    'orchestrator (argon)': 'gemini-4-argon',
  };
  if (aliases[m]) return aliases[m];

  // Normalize spaces/parentheses from display names e.g. "Gemini 4 Neon (High)" -> "gemini-4-neon"
  m = m
    .replace(/\((xhigh|high|medium|low|carbon|neon|argon)\)/gi, '$1')
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9._-]/g, '')
    .replace(/-+/g, '-')
    .replace(/-$/, '')
    .replace(/-\d{8}$/, '')
    .replace(/-(xhigh|high|medium|low)$/i, '');

  if (m.startsWith('orchestrator-carbon')) return 'gemini-4-carbon';
  if (m.startsWith('orchestrator-neon')) return 'gemini-4-neon';
  if (m.startsWith('orchestrator-argon')) return 'gemini-4-argon';
  return m || 'unknown';
}

/**
 * Built-in November 2026 baseline model catalog (USD per 1M tokens + context + optional request fee).
 * Live sync (`sync-models`) augments/updates this from OpenRouter, LMSpeed, and TokenPricing.
 */
export const SEED_MODELS = [
  {
    model_id: 'gemini-4-carbon',
    provider: 'google',
    display_name: 'Gemini 4 Carbon',
    context_window: 1048576,
    input_per_1m: 2.0,
    output_per_1m: 10.0,
    cache_read_per_1m: 0.2,
    cache_write_per_1m: 2.5,
    reasoning_per_1m: 10.0,
    request_fee_usd: 0,
    credit_multiplier: 1.0,
  },
  {
    model_id: 'gemini-4-neon',
    provider: 'google',
    display_name: 'Gemini 4 Neon',
    context_window: 1048576,
    input_per_1m: 3.0,
    output_per_1m: 15.0,
    cache_read_per_1m: 0.15,
    cache_write_per_1m: 0.0833,
    reasoning_per_1m: 15.0,
    request_fee_usd: 0,
    credit_multiplier: 0.75,
  },
  {
    model_id: 'gemini-4-argon',
    provider: 'google',
    display_name: 'Gemini 4 Argon',
    context_window: 1000000,
    input_per_1m: 2.0,
    output_per_1m: 10.0,
    cache_read_per_1m: 0.2,
    cache_write_per_1m: 2.5,
    reasoning_per_1m: 10.0,
    request_fee_usd: 0,
    credit_multiplier: 1.0,
  },
  {
    model_id: 'gemini-4-hydrogen',
    provider: 'google',
    display_name: 'Gemini 4 Hydrogen',
    context_window: 1000000,
    input_per_1m: 1.5,
    output_per_1m: 7.5,
    cache_read_per_1m: 0.15,
    cache_write_per_1m: 1.875,
    reasoning_per_1m: 7.5,
    request_fee_usd: 0,
    credit_multiplier: 0.33,
  },
  {
    model_id: 'gemini-3.8-flash',
    provider: 'google',
    display_name: 'Gemini 3.8 Flash',
    context_window: 1000000,
    input_per_1m: 0.3,
    output_per_1m: 1.2,
    cache_read_per_1m: 0.03,
    cache_write_per_1m: 0.375,
    reasoning_per_1m: 1.2,
    request_fee_usd: 0,
    credit_multiplier: 0.1,
  },
  {
    model_id: 'claude-opus-5-5',
    provider: 'anthropic',
    display_name: 'Claude Opus 5.5',
    context_window: 1000000,
    input_per_1m: 4.0,
    output_per_1m: 20.0,
    cache_read_per_1m: 0.4,
    cache_write_per_1m: 5.0,
    reasoning_per_1m: 20.0,
    request_fee_usd: 0,
    credit_multiplier: 3.0,
  },
  {
    model_id: 'claude-sonnet-5-5',
    provider: 'anthropic',
    display_name: 'Claude Sonnet 5.5',
    context_window: 1000000,
    input_per_1m: 2.0,
    output_per_1m: 10.0,
    cache_read_per_1m: 0.2,
    cache_write_per_1m: 2.5,
    reasoning_per_1m: 10.0,
    request_fee_usd: 0,
    credit_multiplier: 1.0,
  },
  {
    model_id: 'claude-fable-5-1',
    provider: 'anthropic',
    display_name: 'Claude Fable 5.1',
    context_window: 1000000,
    input_per_1m: 10.0,
    output_per_1m: 50.0,
    cache_read_per_1m: 1.0,
    cache_write_per_1m: 12.5,
    reasoning_per_1m: 50.0,
    request_fee_usd: 0,
    credit_multiplier: 5.0,
  },
  {
    model_id: 'claude-haiku-5-5',
    provider: 'anthropic',
    display_name: 'Claude Haiku 5.5',
    context_window: 1000000,
    input_per_1m: 0.1,
    output_per_1m: 0.5,
    cache_read_per_1m: 0.01,
    cache_write_per_1m: 0.125,
    reasoning_per_1m: 0.5,
    request_fee_usd: 0,
    credit_multiplier: 0.1,
  },
  {
    model_id: 'gpt-6.1-sol',
    provider: 'openai',
    display_name: 'GPT-6.1 Sol',
    context_window: 1100000,
    input_per_1m: 2.0,
    output_per_1m: 10.0,
    cache_read_per_1m: 0.2,
    cache_write_per_1m: 2.0,
    reasoning_per_1m: 10.0,
    request_fee_usd: 0,
    credit_multiplier: 1.0,
  },
  {
    model_id: 'gpt-6-astra',
    provider: 'openai',
    display_name: 'GPT-6 Astra',
    context_window: 1100000,
    input_per_1m: 10.0,
    output_per_1m: 50.0,
    cache_read_per_1m: 1.0,
    cache_write_per_1m: 10.0,
    reasoning_per_1m: 50.0,
    request_fee_usd: 0,
    credit_multiplier: 3.0,
  },
  {
    model_id: 'gpt-6-sol',
    provider: 'openai',
    display_name: 'GPT-6 Sol',
    context_window: 1000000,
    input_per_1m: 2.0,
    output_per_1m: 10.0,
    cache_read_per_1m: 0.2,
    cache_write_per_1m: 2.0,
    reasoning_per_1m: 10.0,
    request_fee_usd: 0,
    credit_multiplier: 1.0,
  },
  {
    model_id: 'gpt-5.6-sol',
    provider: 'openai',
    display_name: 'GPT-5.6 Sol',
    context_window: 400000,
    input_per_1m: 1.25,
    output_per_1m: 5.0,
    cache_read_per_1m: 0.125,
    cache_write_per_1m: 1.25,
    reasoning_per_1m: 5.0,
    request_fee_usd: 0,
    credit_multiplier: 0.5,
  },
  {
    model_id: 'kimi-k3.1-pro',
    provider: 'moonshot',
    display_name: 'Kimi K3.1 Pro',
    context_window: 1000000,
    input_per_1m: 2.0,
    output_per_1m: 10.0,
    cache_read_per_1m: 0.2,
    cache_write_per_1m: 2.0,
    reasoning_per_1m: 10.0,
    request_fee_usd: 0,
    credit_multiplier: 1.0,
  },
  {
    model_id: 'glm-5.3',
    provider: 'zai',
    display_name: 'GLM 5.3',
    context_window: 1000000,
    input_per_1m: 1.4,
    output_per_1m: 4.4,
    cache_read_per_1m: 0.14,
    cache_write_per_1m: 1.4,
    reasoning_per_1m: 4.4,
    request_fee_usd: 0,
    credit_multiplier: 0.5,
  },
  {
    model_id: 'deepseek-v4-pro',
    provider: 'deepseek',
    display_name: 'DeepSeek V4 Pro',
    context_window: 1000000,
    input_per_1m: 1.32,
    output_per_1m: 3.96,
    cache_read_per_1m: 0.132,
    cache_write_per_1m: 1.32,
    reasoning_per_1m: 3.96,
    request_fee_usd: 0,
    credit_multiplier: 0.5,
  },
  {
    model_id: 'deepseek-v4.1-flash',
    provider: 'deepseek',
    display_name: 'DeepSeek V4.1 Flash',
    context_window: 1000000,
    input_per_1m: 0.3,
    output_per_1m: 1.2,
    cache_read_per_1m: 0.03,
    cache_write_per_1m: 0.3,
    reasoning_per_1m: 1.2,
    request_fee_usd: 0,
    credit_multiplier: 0.1,
  },
  {
    model_id: 'qwen3.8-max',
    provider: 'alibaba',
    display_name: 'Qwen3.8 Max',
    context_window: 1000000,
    input_per_1m: 2.0,
    output_per_1m: 6.0,
    cache_read_per_1m: 0.2,
    cache_write_per_1m: 2.0,
    reasoning_per_1m: 6.0,
    request_fee_usd: 0,
    credit_multiplier: 1.0,
  },
  {
    model_id: 'grok-4.7',
    provider: 'xai',
    display_name: 'Grok 4.7',
    context_window: 500000,
    input_per_1m: 2.0,
    output_per_1m: 6.0,
    cache_read_per_1m: 0.2,
    cache_write_per_1m: 2.0,
    reasoning_per_1m: 6.0,
    request_fee_usd: 0,
    credit_multiplier: 1.0,
  },
  {
    model_id: 'gpt-oss-120b',
    provider: 'openai',
    display_name: 'GPT-OSS 120B',
    context_window: 128000,
    input_per_1m: 0.15,
    output_per_1m: 0.6,
    cache_read_per_1m: 0.015,
    cache_write_per_1m: 0.15,
    reasoning_per_1m: 0.6,
    request_fee_usd: 0,
    credit_multiplier: 0.1,
  },
];
