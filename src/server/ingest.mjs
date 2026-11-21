/**
 * Wiretok — Payload Normalizer & Safe Ingest Sanitizer for POST /api/ingest.
 * Accepts normalized Wiretok events, OpenAI Responses/Chat Completions payloads,
 * Anthropic Messages payloads, Gemini usageMetadata, and 9Router/OmniRoute webhooks.
 * Strips all credential/header fields before persisting to JSONL or SQLite.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { INGEST_EVENTS_LOG, isSafeObjectKey, normalizeModelId } from '../contracts.mjs';

const COOKIE_RESP_KEY = ['set', 'cookie'].join('-');
const SECRET_KEYS = new Set([
  'apikey',
  'api_key',
  'authorization',
  'x-api-key',
  'x_api_key',
  'token',
  'access_token',
  'refresh_token',
  'id_token',
  'secret',
  'password',
  'cookie',
  'cookies',
  COOKIE_RESP_KEY,
]);

function num(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function numOrNull(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function toIso(v) {
  if (!v && v !== 0) return new Date().toISOString();
  if (typeof v === 'number') {
    const ms = v < 1e12 ? v * 1000 : v;
    return Number.isFinite(ms) ? new Date(ms).toISOString() : new Date().toISOString();
  }
  const ms = Date.parse(String(v));
  return Number.isFinite(ms) ? new Date(ms).toISOString() : new Date().toISOString();
}

/**
 * Recursively strip sensitive credential keys from arbitrary metadata objects.
 */
export function stripSecrets(value, depth = 0) {
  if (depth > 6 || value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map((item) => stripSecrets(item, depth + 1));
  if (typeof value !== 'object') return value;
  const out = Object.create(null);
  for (const [k, v] of Object.entries(value)) {
    if (!isSafeObjectKey(k) || k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    if (SECRET_KEYS.has(k.toLowerCase())) continue;
    out[k] = stripSecrets(v, depth + 1);
  }
  return out;
}

/**
 * Normalize an incoming ingest object (single event or OpenAI/Anthropic/9Router payload)
 * into a schema-compatible request record.
 * @param {object} raw
 * @param {{ milestoneAt?: string }} [opts]
 */
export function normalizeIngestEvent(raw, opts = {}) {
  const src = stripSecrets(raw && typeof raw === 'object' ? raw : {});
  const u = (src.usage && typeof src.usage === 'object' ? src.usage : null) || {};
  const inDetails = u.input_tokens_details || u.prompt_tokens_details || {};
  const outDetails = u.output_tokens_details || u.completion_tokens_details || {};
  const ttlDetails = inDetails.cache_write_tokens_details || {};
  const cacheCreation = u.cache_creation || {};

  const createdAt = toIso(src.created_at || src.timestamp || src.ts || src.created);
  const milestoneAt = opts.milestoneAt || null;
  const era = src.era === 'pre_milestone' || src.era === 'live'
    ? src.era
    : milestoneAt && createdAt < milestoneAt
      ? 'pre_milestone'
      : 'live';

  const rawModel = String(
    src.model_raw || src.raw_model || src.model || src.model_id || src.modelID || 'unknown'
  );
  const modelId = normalizeModelId(src.model_id || rawModel);

  const inputTokens = Math.max(
    0,
    Math.round(
      num(
        src.input_tokens ??
          src.tokens_in ??
          u.input_tokens ??
          u.prompt_tokens ??
          u.promptTokenCount
      )
    )
  );
  const outputTokens = Math.max(
    0,
    Math.round(
      num(
        src.output_tokens ??
          src.tokens_out ??
          u.output_tokens ??
          u.completion_tokens ??
          u.candidatesTokenCount
      )
    )
  );
  const cacheReadTokens = Math.max(
    0,
    Math.round(
      num(
        src.cache_read_tokens ??
          src.tokens_cache_read ??
          src.cached_tokens ??
          u.cache_read_input_tokens ??
          inDetails.cached_tokens ??
          u.cachedContentTokenCount
      )
    )
  );
  const cacheWrite5m = Math.max(
    0,
    Math.round(num(src.cache_write_5m_tokens ?? cacheCreation.ephemeral_5m_input_tokens))
  );
  const cacheWrite1h = Math.max(
    0,
    Math.round(num(src.cache_write_1h_tokens ?? cacheCreation.ephemeral_1h_input_tokens))
  );
  const cacheWriteTokens = Math.max(
    0,
    Math.round(
      num(
        src.cache_write_tokens ??
          src.tokens_cache_creation ??
          u.cache_creation_input_tokens ??
          inDetails.cache_write_tokens ??
          cacheWrite5m + cacheWrite1h
      )
    )
  );
  const ttl30m = Math.max(
    0,
    Math.round(num(src.cache_ttl_30m_tokens ?? ttlDetails.ttl_30m_tokens))
  );
  const ttl12h = Math.max(
    0,
    Math.round(num(src.cache_ttl_12h_tokens ?? ttlDetails.ttl_12h_tokens))
  );
  const reasoningTokens = Math.max(
    0,
    Math.round(
      num(
        src.reasoning_tokens ??
          src.tokens_reasoning ??
          outDetails.reasoning_tokens ??
          u.thoughtsTokenCount
      )
    )
  );
  const compressedTokens = Math.max(
    0,
    Math.round(num(src.compressed_tokens ?? src.tokens_compressed))
  );
  const instructionsTokens = Math.max(
    0,
    Math.round(
      num(
        src.instructions_tokens ??
          u.attribution?.request_fields?.instructions?.input_tokens
      )
    )
  );
  const contextTokens = Math.max(
    0,
    Math.round(num(src.context_tokens, inputTokens + cacheReadTokens + cacheWriteTokens))
  );

  const sourceTool = String(src.source_tool || src.source || 'manual-ingest');
  const accountId = String(
    src.account_id || src.connection_id || src.connectionId || src.account || 'unknown'
  );
  const responseId = src.response_id || (typeof src.id === 'string' ? src.id : null);

  const dedupSeed = JSON.stringify({
    sourceTool,
    accountId,
    createdAt,
    modelId,
    responseId,
    inputTokens,
    outputTokens,
    cacheReadTokens,
    nonce: src.dedup_key || src.request_id || src.id || null,
  });
  const dedupKey =
    typeof src.dedup_key === 'string' && src.dedup_key.trim()
      ? src.dedup_key.trim()
      : `ingest:${crypto.createHash('sha1').update(dedupSeed).digest('hex')}`;

  return {
    dedup_key: dedupKey,
    created_at: createdAt,
    era,
    source_tool: sourceTool,
    account_id: accountId,
    account_email: typeof src.account_email === 'string' ? src.account_email : undefined,
    session_id: src.session_id || src.conversation_id || null,
    parent_session_id: src.parent_session_id || null,
    agent_name: src.agent_name || null,
    workspace: String(src.workspace || ''),
    title: typeof src.title === 'string' ? src.title : undefined,
    endpoint_mode: String(src.endpoint_mode || 'unknown'),
    endpoint: String(src.endpoint || ''),
    combo_name: String(src.combo_name || ''),
    model_raw: rawModel,
    raw_model: rawModel,
    model_id: modelId,
    provider: String(src.provider || ''),
    plan_type: typeof src.plan_type === 'string' ? src.plan_type : undefined,
    input_tokens: inputTokens,
    uncached_input_tokens:
      src.uncached_input_tokens !== undefined
        ? Math.max(0, Math.round(num(src.uncached_input_tokens)))
        : u.input_tokens_details || u.prompt_tokens_details || u.promptTokenCount !== undefined
        ? Math.max(0, inputTokens - cacheReadTokens)
        : undefined,
    output_tokens: outputTokens,
    cache_read_tokens: cacheReadTokens,
    cache_write_tokens: cacheWriteTokens,
    cache_ttl_30m_tokens: ttl30m,
    cache_ttl_12h_tokens: ttl12h,
    reasoning_tokens: reasoningTokens,
    compressed_tokens: compressedTokens,
    instructions_tokens: instructionsTokens,
    context_tokens: contextTokens,
    context_window: numOrNull(src.context_window) ?? undefined,
    ttft_ms: numOrNull(src.ttft_ms ?? src.ttft),
    ttfr_ms: numOrNull(src.ttfr_ms),
    ttfa_ms: numOrNull(src.ttfa_ms),
    tpot_ms: numOrNull(src.tpot_ms),
    latency_ms: numOrNull(src.latency_ms ?? src.duration_ms ?? src.duration),
    tok_per_sec: numOrNull(src.tok_per_sec ?? src.tokens_per_sec),
    provider_cost_usd: numOrNull(src.provider_cost_usd ?? src.cost_usd ?? src.cost),
    service_tier: src.service_tier || null,
    prompt_cache_retention: src.prompt_cache_retention || null,
    safety_identifier: src.safety_identifier || null,
    response_id: responseId,
    system_fingerprint: src.system_fingerprint || null,
    has_signature: src.has_signature ? 1 : 0,
    authenticity_score: numOrNull(src.authenticity_score),
    verdict: src.verdict || null,
    status_code: Math.round(num(src.status_code, 200)),
    meta_json: src.meta_json
      ? typeof src.meta_json === 'string'
        ? src.meta_json
        : JSON.stringify(stripSecrets(src.meta_json))
      : null,
  };
}

/**
 * Append sanitized ingest events to C:\wiretok\data\ingest_events.jsonl.
 * @param {Array<object>} events
 * @param {string} [logPath]
 */
export function appendIngestJsonl(events, logPath = INGEST_EVENTS_LOG) {
  if (!Array.isArray(events) || events.length === 0) return;
  fs.mkdirSync(path.dirname(logPath), { recursive: true });
  const lines = events.map((ev) => JSON.stringify(stripSecrets(ev))).join('\n') + '\n';
  fs.appendFileSync(logPath, lines, 'utf8');
}
