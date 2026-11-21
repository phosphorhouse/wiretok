/**
 * Wiretok — Model Fingerprint / Authenticity Engine
 *
 * analyzeForensics(rawTextOrParsed, opts) -> deterministic 0-100 authenticityScore + verdict.
 *
 * Core principle: a model's TEXT self-report ("I am GPT-5.2", "I'm Claude 3") is UNRELIABLE — models
 * routinely mis-identify themselves (stale training data, system-prompt personas). It carries zero
 * positive weight. Authenticity is decided only by WIRE / CRYPTOGRAPHIC evidence that a translating
 * proxy cannot cheaply fabricate: provider-native ID formats + lineage, `usage.attribution`
 * reconciliation, cache-TTL detail fields, Anthropic thinking `signature_delta` cryptograms,
 * `system_fingerprint`, monotonic `sequence_number`s, and provider HTTP headers.
 */
import { createHash, randomUUID } from 'node:crypto';
import { VERDICTS, isSafeObjectKey, normalizeModelId } from '../contracts.mjs';
import { parseSse } from './sse-parser.mjs';

export const ENGINE_VERSION = '1.0.0';

/** Provider family for a model slug. */
export function modelFamily(model) {
  if (!model || typeof model !== 'string') return null;
  const m = normalizeModelId(model);
  if (/^(gpt-|chatgpt|o\d(\b|-|$)|codex|gpt-oss|davinci|text-embedding)/.test(m)) return m.startsWith('gpt-oss') ? 'openai-oss' : 'openai';
  if (/^claude/.test(m)) return 'anthropic';
  if (/^(gemini|gemma|learnlm)/.test(m)) return 'google';
  if (/^(deepseek)/.test(m)) return 'deepseek';
  if (/^(qwen|qwq)/.test(m)) return 'alibaba';
  if (/^(kimi|moonshot)/.test(m)) return 'moonshot';
  if (/^(glm|chatglm|zai)/.test(m)) return 'zai';
  if (/^grok/.test(m)) return 'xai';
  if (/^(llama|muse)/.test(m)) return 'meta';
  if (/^(mistral|mixtral|codestral|magistral|devstral)/.test(m)) return 'mistral';
  if (/^(minimax|abab)/.test(m)) return 'minimax';
  if (/^mimo/.test(m)) return 'xiaomi';
  if (/^step/.test(m)) return 'stepfun';
  return 'other';
}

/** Protocols that are first-party native for each provider family. */
const NATIVE_PROTOCOLS = {
  openai: ['responses', 'chat_completions'],
  anthropic: ['messages'],
  google: ['gemini'],
  deepseek: ['chat_completions', 'messages'],
  alibaba: ['chat_completions'],
  moonshot: ['chat_completions', 'messages'],
  zai: ['chat_completions', 'messages'],
  xai: ['chat_completions', 'responses', 'messages'],
  meta: ['chat_completions'],
  mistral: ['chat_completions'],
  minimax: ['chat_completions', 'messages'],
  xiaomi: ['chat_completions'],
  stepfun: ['chat_completions'],
  'openai-oss': ['chat_completions', 'responses'],
  other: ['chat_completions', 'responses', 'messages', 'gemini'],
};

/** Positive-evidence points a fully native capture typically reaches per protocol (score normalizer). */
export const PROTOCOL_REFERENCE_POINTS = { responses: 95, messages: 75, chat_completions: 50, gemini: 55, unknown: 100 };

const SELF_REPORT_PATTERNS = [
  { family: 'openai', re: /\b(GPT[-\s]?\d+(?:\.\d+)?(?:[-\s]?(?:o|mini|nano|turbo|pro|sol|terra|astra|codex))?|ChatGPT|o[1-9](?:-mini|-pro)?)\b/gi },
  { family: 'anthropic', re: /\b(Claude(?:[-\s](?:Opus|Sonnet|Haiku|Fable|Instant))?(?:[-\s]?\d+(?:[.-]\d+)?)?(?:[-\s](?:Opus|Sonnet|Haiku|Fable))?)\b/gi },
  { family: 'google', re: /\b(Gemini(?:[-\s]\d+(?:\.\d+)?)?(?:[-\s](?:Pro|Flash|Ultra|Carbon|Argon|Hydrogen|Nano))?|Bard|PaLM\s?\d?)\b/gi },
  { family: 'deepseek', re: /\b(DeepSeek(?:[-\s](?:V\d+(?:\.\d+)?|R\d))?)\b/gi },
  { family: 'alibaba', re: /\b(Qwen\s?\d*(?:\.\d+)?(?:[-\s]?(?:Max|Plus|Turbo|Flash))?|Tongyi)\b/gi },
  { family: 'moonshot', re: /\b(Kimi(?:[-\s]K\d+(?:\.\d+)?)?)\b/gi },
  { family: 'zai', re: /\b((?:Chat)?GLM[-\s]?\d+(?:\.\d+)?)\b/gi },
  { family: 'xai', re: /\b(Grok(?:[-\s]\d+(?:\.\d+)?)?)\b/gi },
  { family: 'meta', re: /\b(Llama[-\s]?\d+(?:\.\d+)?|Muse(?:\s(?:Spark|Wonder))?)\b/gi },
  { family: 'mistral', re: /\b(Mistral(?:[-\s](?:Large|Medium|Small))?|Mixtral)\b/gi },
];

const PROVIDER_ORG_PATTERNS = [
  { family: 'openai', re: /\bOpenAI\b/i },
  { family: 'anthropic', re: /\bAnthropic\b/i },
  { family: 'google', re: /\b(Google|DeepMind)\b/i },
  { family: 'deepseek', re: /\bDeepSeek\b/i },
  { family: 'alibaba', re: /\b(Alibaba|Qwen Team)\b/i },
  { family: 'moonshot', re: /\bMoonshot\b/i },
  { family: 'zai', re: /\b(Zhipu|Z\.ai)\b/i },
  { family: 'xai', re: /\bxAI\b/ },
  { family: 'meta', re: /\bMeta\b/ },
];

/** Extract model/provider names the model claims about itself in its TEXT output (unreliable signal). */
export function extractSelfReport(text) {
  const out = { models: [], providers: [], knowledgeCutoff: null, families: [] };
  if (!text || typeof text !== 'string') return out;
  const seen = new Set();
  for (const { family, re } of SELF_REPORT_PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text))) {
      const name = m[1].trim();
      const key = name.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      out.models.push({ name, family });
    }
  }
  for (const { family, re } of PROVIDER_ORG_PATTERNS) if (re.test(text)) out.providers.push(family);
  const cut = text.match(/(?:knowledge\s*cut-?off|training\s*(?:data\s*)?cut-?off)\s*[:\-–]?\s*([A-Za-z]*\s*\d{4}(?:[-/.]\d{1,2})?)/i);
  if (cut) out.knowledgeCutoff = cut[1].trim();
  out.families = [...new Set([...out.models.map((x) => x.family), ...out.providers])];
  return out;
}

const RESP_COOKIE_HDR = ['set', 'cookie'].join('-');

function lowerHeaders(h) {
  const out = Object.create(null);
  if (!h) return out;
  const entries = typeof h.entries === 'function' && !(h instanceof Map) && !Array.isArray(h) ? [...h.entries()] : h instanceof Map ? [...h.entries()] : Object.entries(h);
  for (const [k, v] of entries) {
    const key = String(k).toLowerCase();
    if (!isSafeObjectKey(key) || key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    if (key === 'authorization' || key === 'x-api-key' || key === 'api-key' || key === 'x-goog-api-key' || key === 'cookie' || key === RESP_COOKIE_HDR || key === 'proxy-authorization') continue;
    out[key] = Array.isArray(v) ? v.join(', ') : String(v);
  }
  return out;
}

/** Inspect HTTP response headers for provider-native vs gateway/proxy markers. */
export function analyzeHeaders(headers) {
  const h = lowerHeaders(headers);
  const keys = Object.keys(h);
  const res = { present: keys.length > 0, providerHints: [], gatewayHints: [], notable: {} };
  if (!keys.length) return res;
  const pick = (k) => {
    if (h[k] != null) res.notable[k] = h[k];
  };
  ['x-request-id', 'request-id', 'openai-model', 'openai-organization', 'openai-processing-ms', 'openai-version', 'openai-project', 'anthropic-organization-id', 'cf-ray', 'server', 'via', 'x-goog-request-id', 'x-envoy-upstream-service-time', 'content-type'].forEach(pick);
  for (const k of keys) if (/^(anthropic-ratelimit-|x-ratelimit-|x-litellm-|x-omniroute|x-openrouter|x-9router|x-portkey|helicone-|x-kong-|x-oneapi|x-new-api)/.test(k)) res.notable[k] = h[k];

  if (h['openai-model'] || h['openai-processing-ms'] || h['openai-organization'] || h['openai-version']) res.providerHints.push({ family: 'openai', detail: 'openai-* headers' });
  if (/^req_[0-9a-f]{24,}$/.test(h['x-request-id'] || '')) res.providerHints.push({ family: 'openai', detail: 'x-request-id req_<hex>' });
  if (keys.some((k) => k.startsWith('anthropic-ratelimit-')) || h['anthropic-organization-id']) res.providerHints.push({ family: 'anthropic', detail: 'anthropic-ratelimit-* / organization headers' });
  if (/^req_01[0-9A-Za-z]{20,}$/.test(h['request-id'] || '')) res.providerHints.push({ family: 'anthropic', detail: 'request-id req_01…' });
  if (h['x-goog-request-id'] || /^(ESF|scaffolding on HTTPServer2|Google Frontend)/i.test(h.server || '')) res.providerHints.push({ family: 'google', detail: 'Google frontend headers' });

  for (const k of keys) {
    if (/^x-litellm-/.test(k)) res.gatewayHints.push('litellm');
    else if (/^x-omniroute/.test(k)) res.gatewayHints.push('omniroute');
    else if (/^x-openrouter/.test(k)) res.gatewayHints.push('openrouter');
    else if (/^x-9router/.test(k)) res.gatewayHints.push('9router');
    else if (/^x-portkey/.test(k)) res.gatewayHints.push('portkey');
    else if (/^helicone-/.test(k)) res.gatewayHints.push('helicone');
    else if (/^(x-oneapi|x-new-api)/.test(k)) res.gatewayHints.push('one-api/new-api');
  }
  if (/uvicorn|express|fastapi|gunicorn|werkzeug|hypercorn/i.test(h.server || '')) res.gatewayHints.push(`server:${h.server}`);
  if (h.via) res.gatewayHints.push(`via:${h.via}`);
  res.gatewayHints = [...new Set(res.gatewayHints)];
  return res;
}

/* ------------------------------------------------------------------ */

function addEvidence(list, code, points, detail, kind = 'wire') {
  list.push({ code, points, kind, detail });
}

/**
 * @param {string|Array|object} rawTextOrParsed raw SSE / JSON / chunk array, or a parseSse() result
 * @param {{mode?: string, endpointMode?: string, claimedModel?: string, headers?: object, privacy?: boolean, t0?: number, tEnd?: number, baseUrl?: string}} [opts]
 */
export function analyzeForensics(rawTextOrParsed, opts = {}) {
  const isParsed = rawTextOrParsed && typeof rawTextOrParsed === 'object' && !Array.isArray(rawTextOrParsed) && 'mode' in rawTextOrParsed && 'tokens' in rawTextOrParsed && 'frameCount' in rawTextOrParsed;
  const CONCRETE = ['responses', 'messages', 'chat_completions', 'gemini'];
  // Only a concrete protocol counts as a declared endpoint ('auto', 'unknown', '' etc. are ignored).
  const endpointMode = CONCRETE.includes(opts.endpointMode) ? opts.endpointMode : null; // the endpoint the client actually called
  const parseMode = CONCRETE.includes(opts.mode) ? opts.mode : 'auto';
  const parsed = isParsed ? rawTextOrParsed : parseSse(rawTextOrParsed, { mode: parseMode, privacy: opts.privacy, t0: opts.t0, tEnd: opts.tEnd });
  const mode = parsed.mode;
  const wireModel = parsed.model || null;
  const claimedModel = opts.claimedModel || null;
  const wireFamily = modelFamily(wireModel);
  const claimedFamily = modelFamily(claimedModel);
  const family = wireFamily || claimedFamily;
  const headerInfo = analyzeHeaders(opts.headers);

  const positive = [];
  const negative = [];
  const flags = [];
  const flag = (severity, code, detail) => flags.push({ severity, code, detail });
  let proofs = 0; // count of hard-to-fake wire/crypto proofs

  /* ---------- structural sanity ---------- */
  if (!parsed.frameCount) flag('error', 'NO_FRAMES', 'No SSE frames or JSON bodies could be parsed.');
  if (mode === 'unknown') flag('error', 'UNKNOWN_PROTOCOL', 'Frames do not match Responses, Messages, Chat Completions, or Gemini shapes.');
  if (endpointMode && endpointMode !== 'unknown' && mode !== 'unknown' && endpointMode !== mode) {
    addEvidence(negative, 'ENDPOINT_PROTOCOL_MISMATCH', -25, `Called ${endpointMode} endpoint but stream frames are ${mode}-shaped (protocol translation layer).`);
    flag('warn', 'ENDPOINT_PROTOCOL_MISMATCH', `endpoint=${endpointMode} wire=${mode}`);
  }
  if (parsed.errors?.length) flag('warn', 'STREAM_ERRORS', `${parsed.errors.length} error event(s) in stream.`);
  if (parsed.distinctModels.length > 1) {
    addEvidence(negative, 'MODEL_CHANGED_MIDSTREAM', -15, `Model field changed mid-stream: ${parsed.distinctModels.join(' -> ')}`);
    flag('warn', 'MODEL_CHANGED_MIDSTREAM', parsed.distinctModels.join(', '));
  }
  if (parsed.distinctIds.length > 1 && mode !== 'gemini') {
    addEvidence(negative, 'ID_CHANGED_MIDSTREAM', -15, `Response ID changed mid-stream (${parsed.distinctIds.length} distinct) — frames stitched from multiple upstream calls.`);
    flag('warn', 'ID_CHANGED_MIDSTREAM', parsed.distinctIds.slice(0, 3).join(', '));
  }

  /* ---------- protocol-specific wire evidence ---------- */
  if (mode === 'responses') {
    if (parsed.idFormat === 'openai_resp_hex') {
      addEvidence(positive, 'RESP_ID_NATIVE_FORMAT', 20, `${parsed.id.slice(0, 12)}… resp_ + ${parsed.id.length - 5} lowercase hex chars (OpenAI-native ID format).`);
    } else if (parsed.id) {
      addEvidence(negative, 'RESP_ID_NONSTANDARD', -15, `Responses ID "${parsed.id.slice(0, 24)}" is not resp_<hex>.`);
      flag('warn', 'RESP_ID_NONSTANDARD', parsed.id.slice(0, 32));
    }
    const lin = parsed.id_lineage;
    if (lin && lin.relatedIds > 0 && lin.minSharedPrefix >= 16) {
      addEvidence(positive, 'ID_LINEAGE', 10, `${lin.relatedIds} item/attribution ID(s) share a ${lin.minSharedPrefix}-hex-char prefix with the response ID (server-side ID lineage; translators mint unrelated IDs).`);
      proofs++;
    } else if (lin && lin.relatedIds > 0) {
      addEvidence(negative, 'ID_LINEAGE_BROKEN', -8, `Item IDs share only ${lin.minSharedPrefix} hex chars with response ID.`);
    }
    const att = parsed.attribution;
    if (att && (att.items.length || att.request_fields.length)) {
      addEvidence(positive, 'USAGE_ATTRIBUTION', 20, `usage.attribution present: ${att.items.length} item(s) + request_fields[${att.request_fields.map((f) => f.field).join(',')}] (instructions=${att.instructions_input_tokens} tok).`, 'wire');
      proofs++;
      if (att.input_reconciles && att.output_reconciles) {
        addEvidence(positive, 'ATTRIBUTION_RECONCILES', 10, `Attribution sums exactly: items ${att.items_input_tokens} + fields ${att.request_fields_input_tokens} = ${att.attributed_input_tokens} = usage.input_tokens; output ${att.attributed_output_tokens} = usage.output_tokens.`);
        proofs++;
      } else {
        addEvidence(negative, 'ATTRIBUTION_MISMATCH', -15, `Attribution does not reconcile (input ${att.attributed_input_tokens} vs ${att.reported_input_tokens}, output ${att.attributed_output_tokens} vs ${att.reported_output_tokens}) — rewritten usage.`);
        flag('warn', 'ATTRIBUTION_MISMATCH', `unattributed_input=${att.unattributed_input_tokens}`);
      }
    }
    const det = parsed.usage?.input_tokens_details;
    if (det && det.cache_write_tokens_details && ('ttl_30m_tokens' in det.cache_write_tokens_details || 'ttl_12h_tokens' in det.cache_write_tokens_details)) {
      addEvidence(positive, 'CACHE_TTL_DETAILS', 8, 'usage.input_tokens_details.cache_write_tokens_details.{ttl_30m_tokens, ttl_12h_tokens} present (native extended-cache telemetry).');
    }
    if (parsed.prompt_cache_retention) addEvidence(positive, 'PROMPT_CACHE_RETENTION', 5, `prompt_cache_retention="${parsed.prompt_cache_retention}"${parsed.prompt_cache_key ? ' + prompt_cache_key' : ''}.`);
    else if (parsed.prompt_cache_key) addEvidence(positive, 'PROMPT_CACHE_KEY', 3, 'prompt_cache_key echoed.');
    if (parsed.reasoning && ('context' in parsed.reasoning || 'mode' in parsed.reasoning)) addEvidence(positive, 'REASONING_OBJECT', 4, `reasoning={effort:${parsed.reasoning.effort}, summary:${parsed.reasoning.summary}, context:${parsed.reasoning.context}, mode:${parsed.reasoning.mode}}.`);
    else if (parsed.reasoning) addEvidence(positive, 'REASONING_OBJECT', 2, 'reasoning object echoed.');
    if (parsed.service_tier_history.length > 1) addEvidence(positive, 'SERVICE_TIER_RESOLVED', 3, `service_tier resolved server-side: ${parsed.service_tier_history.join(' -> ')}.`);
    const seq = parsed.sequence;
    if (seq && seq.monotonic && seq.startsAtZero) {
      addEvidence(positive, 'SEQUENCE_MONOTONIC', 5, `sequence_number monotonic ${seq.first}..${seq.last}${seq.missingTotal ? ` (${seq.missingTotal} frame(s) absent from capture)` : ''}.`);
      if (seq.missingTotal) flag('info', 'SEQUENCE_GAP', `Capture skips ${seq.missingTotal} sequence numbers (${seq.gaps.map((g) => `${g.after}->${g.before}`).join(', ')}): delta frames trimmed by capture or filtered by a proxy.`);
    } else if (seq && !seq.monotonic) {
      addEvidence(negative, 'SEQUENCE_DISORDER', -10, 'sequence_number not monotonic (re-ordered or synthesized stream).');
    } else if (!seq && parsed.frameCount > 1) {
      addEvidence(negative, 'SEQUENCE_MISSING', -5, 'Responses frames lack sequence_number.');
    }
    if (Number.isInteger(parsed.created_at) && Number.isInteger(parsed.completed_at)) addEvidence(positive, 'SERVER_TIMESTAMPS', 3, `created_at=${parsed.created_at} completed_at=${parsed.completed_at} (unix seconds).`);
    if (parsed.tool_usage && typeof parsed.tool_usage === 'object') addEvidence(positive, 'TOOL_USAGE_OBJECT', 3, `tool_usage{${Object.keys(parsed.tool_usage).join(',')}} present.`);
    if (parsed.safety_identifier) addEvidence(positive, 'SAFETY_IDENTIFIER', 2, `safety_identifier present (${parsed.safety_identifier_masked ? 'masked' : 'raw'}: ${parsed.safety_identifier}).`);
    if (wireFamily === 'anthropic' || wireFamily === 'google') {
      addEvidence(negative, 'FOREIGN_MODEL_ON_RESPONSES', -20, `${wireModel} served via OpenAI Responses protocol — non-native, translated.`);
      flag('warn', 'PROTOCOL_TRANSLATION', `${wireFamily} model over /v1/responses`);
    }
  }

  if (mode === 'messages') {
    if (parsed.idFormat === 'anthropic_msg') addEvidence(positive, 'MSG_ID_NATIVE_FORMAT', 15, `${parsed.id.slice(0, 10)}… msg_01 + base62 (Anthropic-native ID format).`);
    else if (/^chatcmpl/.test(parsed.id || '')) {
      addEvidence(negative, 'CHATCMPL_ID_ON_MESSAGES', -30, `Messages stream carries OpenAI-style ID "${parsed.id.slice(0, 24)}" — Chat Completions upstream translated to Messages.`);
      flag('error', 'PROTOCOL_TRANSLATION', 'chatcmpl- ID inside /v1/messages stream');
    } else if (parsed.id) {
      addEvidence(negative, 'MSG_ID_NONSTANDARD', -12, `Messages ID "${parsed.id.slice(0, 24)}" is not msg_01<base62>.`);
      flag('warn', 'MSG_ID_NONSTANDARD', parsed.id.slice(0, 32));
    }
    const thinking = parsed.thinking.filter((b) => b.type === 'thinking');
    const signed = thinking.filter((b) => b.signature.plausible);
    if (thinking.length) {
      if (signed.length === thinking.length) {
        addEvidence(positive, 'THINKING_SIGNATURE', 30, `${signed.length} thinking block(s) carry signature_delta cryptograms (${signed.map((b) => `${b.signature.length} chars/${b.signature.decodedBytes} B`).join(', ')}).`, 'crypto');
        proofs += 2;
      } else {
        const missing = thinking.length - signed.length;
        addEvidence(negative, 'THINKING_UNSIGNED', -30, `${missing}/${thinking.length} thinking block(s) lack a valid signature_delta — native Anthropic always signs thinking; translated reasoning cannot forge it.`, 'crypto');
        flag('error', 'THINKING_UNSIGNED', `${missing} unsigned thinking block(s)`);
      }
    }
    if (parsed.redacted_thinking_blocks) {
      addEvidence(positive, 'REDACTED_THINKING', 8, `${parsed.redacted_thinking_blocks} redacted_thinking block(s) (encrypted, Anthropic-native).`, 'crypto');
      proofs++;
    }
    const u = parsed.usage || {};
    if (u.cache_creation && ('ephemeral_5m_input_tokens' in u.cache_creation || 'ephemeral_1h_input_tokens' in u.cache_creation)) {
      addEvidence(positive, 'CACHE_CREATION_TTL', 10, `usage.cache_creation{ephemeral_5m=${u.cache_creation.ephemeral_5m_input_tokens ?? 0}, ephemeral_1h=${u.cache_creation.ephemeral_1h_input_tokens ?? 0}} present.`);
      proofs++;
    }
    if ('cache_read_input_tokens' in u && 'cache_creation_input_tokens' in u) addEvidence(positive, 'CACHE_USAGE_FIELDS', 4, `cache_read_input_tokens=${u.cache_read_input_tokens}, cache_creation_input_tokens=${u.cache_creation_input_tokens}.`);
    const ev = parsed.eventTypes;
    const shapeOk = ev.message_start === 1 && ev.message_stop === 1 && ev.message_delta >= 1 && (ev.content_block_start || 0) === (ev.content_block_stop || 0) && (ev.content_block_start || 0) > 0;
    if (shapeOk) addEvidence(positive, 'EVENT_GRAMMAR', 10, 'message_start → content_block_start/delta/stop (balanced) → message_delta → message_stop grammar intact.');
    else if (parsed.inputFormat === 'sse' || parsed.inputFormat === 'chunks') addEvidence(negative, 'EVENT_GRAMMAR_BROKEN', -8, `Messages event grammar incomplete: ${JSON.stringify(ev)}.`);
    if (ev.ping) addEvidence(positive, 'PING_FRAMES', 2, `${ev.ping} ping frame(s).`);
    if (parsed.tool_calls.some((t) => /^toolu_01/.test(t.id || ''))) addEvidence(positive, 'TOOLU_IDS', 5, 'tool_use IDs use toolu_01… format.');
    else if (parsed.tool_calls.some((t) => /^call_/.test(t.id || ''))) {
      addEvidence(negative, 'CALL_IDS_ON_MESSAGES', -10, 'tool_use IDs use OpenAI call_ format.');
      flag('warn', 'PROTOCOL_TRANSLATION', 'OpenAI call_ IDs in Messages tool_use');
    }
    if (wireFamily && wireFamily !== 'anthropic' && !NATIVE_PROTOCOLS[wireFamily]?.includes('messages')) {
      addEvidence(negative, 'FOREIGN_MODEL_ON_MESSAGES', -20, `${wireModel} served via Anthropic Messages protocol — translated.`);
      flag('warn', 'PROTOCOL_TRANSLATION', `${wireFamily} model over /v1/messages`);
    }
  }

  if (mode === 'chat_completions') {
    if (parsed.idFormat === 'openai_chatcmpl') addEvidence(positive, 'CHATCMPL_ID_FORMAT', 10, `${parsed.id.slice(0, 16)}… chatcmpl-<base62> format.`);
    else if (parsed.idFormat === 'chatcmpl_uuid' || parsed.idFormat === 'chatcmpl_other') addEvidence(positive, 'CHATCMPL_ID_GENERIC', 3, `${parsed.id.slice(0, 20)}… chatcmpl- prefix with non-OpenAI body (vLLM/LiteLLM/gateway style).`);
    else if (parsed.idFormat === 'openrouter_gen') {
      addEvidence(positive, 'GATEWAY_ID', 0, `OpenRouter gen- ID: aggregated gateway response.`);
      flag('info', 'GATEWAY', 'OpenRouter gen- ID');
    } else if (parsed.id) addEvidence(negative, 'CHAT_ID_NONSTANDARD', -5, `Chat ID "${parsed.id.slice(0, 24)}" has no chatcmpl- prefix.`);
    const fps = parsed.distinct_system_fingerprints;
    if (fps.length === 1 && /^fp_[0-9a-f]{8,16}$/.test(fps[0])) {
      addEvidence(positive, 'SYSTEM_FINGERPRINT', 12, `system_fingerprint=${fps[0]} (stable across all chunks).`);
      if (wireFamily === 'openai') proofs++;
    } else if (fps.length > 1) {
      addEvidence(negative, 'SYSTEM_FINGERPRINT_UNSTABLE', -10, `system_fingerprint changed mid-stream: ${fps.join(', ')}.`);
      flag('warn', 'SYSTEM_FINGERPRINT_UNSTABLE', fps.join(', '));
    } else if (fps.length === 1) {
      addEvidence(positive, 'SYSTEM_FINGERPRINT_NONSTANDARD', 2, `system_fingerprint="${fps[0]}" (non-fp_<hex> format).`);
    } else if (wireFamily === 'openai') {
      addEvidence(negative, 'SYSTEM_FINGERPRINT_MISSING', -5, 'OpenAI model without system_fingerprint.');
    }
    const u = parsed.usage || {};
    if (u.prompt_tokens_details && u.completion_tokens_details) addEvidence(positive, 'USAGE_DETAILS', 8, `usage.prompt_tokens_details{cached=${u.prompt_tokens_details.cached_tokens ?? 0}} + completion_tokens_details{reasoning=${u.completion_tokens_details.reasoning_tokens ?? 0}}.`);
    else if (u.prompt_tokens != null) addEvidence(positive, 'USAGE_BASIC', 2, 'Basic prompt/completion usage only.');
    else flag('info', 'NO_USAGE', 'No usage chunk (stream_options.include_usage not set or stripped).');
    if (parsed.extra?.object === 'chat.completion.chunk') addEvidence(positive, 'CHUNK_OBJECT', 2, 'object=chat.completion.chunk.');
    if (parsed.extra?.reasoningField === 'reasoning_content' && (wireFamily === 'openai' || wireFamily === 'anthropic' || claimedFamily === 'openai' || claimedFamily === 'anthropic')) {
      addEvidence(negative, 'REASONING_CONTENT_FIELD', -10, `delta.reasoning_content (DeepSeek/Qwen/Kimi-style field) on a ${wireFamily || claimedFamily} model — gateway translation or substitution.`);
      flag('warn', 'PROTOCOL_TRANSLATION', 'reasoning_content field on openai/anthropic model');
    }
    if (wireFamily === 'anthropic' || wireFamily === 'google') {
      addEvidence(negative, 'FOREIGN_MODEL_ON_CHAT', -15, `${wireModel} served via OpenAI-compatible chat/completions — not the provider's native protocol (signatures/cache-TTL telemetry unavailable).`);
      flag('warn', 'PROTOCOL_TRANSLATION', `${wireFamily} model over /v1/chat/completions`);
    }
  }

  if (mode === 'gemini') {
    const u = parsed.usage || {};
    if ('promptTokenCount' in u && ('candidatesTokenCount' in u || 'totalTokenCount' in u)) addEvidence(positive, 'USAGE_METADATA', 12, `usageMetadata{prompt=${u.promptTokenCount}, candidates=${u.candidatesTokenCount ?? 0}, thoughts=${u.thoughtsTokenCount ?? 0}, cached=${u.cachedContentTokenCount ?? 0}}.`);
    if (u.promptTokensDetails || u.candidatesTokensDetails) addEvidence(positive, 'MODALITY_DETAILS', 4, 'promptTokensDetails modality breakdown present.');
    if (parsed.model) addEvidence(positive, 'MODEL_VERSION', 5, `modelVersion=${parsed.model}.`);
    if (parsed.id && /^[A-Za-z0-9_-]{16,32}$/.test(parsed.id)) addEvidence(positive, 'RESPONSE_ID', 5, `responseId=${parsed.id}.`);
    const sigs = parsed.thinking.filter((b) => b.type === 'thought_signature');
    if (sigs.length && sigs.every((s) => s.signature.plausible)) {
      addEvidence(positive, 'THOUGHT_SIGNATURE', 20, `${sigs.length} thoughtSignature cryptogram(s).`, 'crypto');
      proofs += 2;
    } else if (sigs.length) {
      addEvidence(negative, 'THOUGHT_SIGNATURE_INVALID', -15, 'thoughtSignature present but not valid base64.', 'crypto');
    }
    if (wireFamily && wireFamily !== 'google') {
      addEvidence(negative, 'FOREIGN_MODEL_ON_GEMINI', -20, `${wireModel} served via Gemini protocol.`);
      flag('warn', 'PROTOCOL_TRANSLATION', `${wireFamily} model over gemini protocol`);
    }
  }

  /* ---------- HTTP header evidence ---------- */
  if (headerInfo.present) {
    const matching = headerInfo.providerHints.filter((p) => !family || p.family === family);
    const foreign = headerInfo.providerHints.filter((p) => family && p.family !== family);
    if (matching.length) {
      addEvidence(positive, 'PROVIDER_HEADERS', Math.min(10, 5 * matching.length), matching.map((p) => p.detail).join('; '), 'header');
      proofs++;
    }
    if (foreign.length) {
      addEvidence(negative, 'FOREIGN_PROVIDER_HEADERS', -20, `Headers from ${foreign.map((p) => p.family).join(',')} while model family is ${family}.`, 'header');
      flag('error', 'FOREIGN_PROVIDER_HEADERS', foreign.map((p) => p.detail).join('; '));
    }
    if (headerInfo.gatewayHints.length) flag('info', 'GATEWAY_HEADERS', headerInfo.gatewayHints.join(', '));
    const om = headerInfo.notable['openai-model'];
    if (om && wireModel && normalizeModelId(om) !== normalizeModelId(wireModel) && !normalizeModelId(om).startsWith(normalizeModelId(wireModel))) {
      addEvidence(negative, 'HEADER_MODEL_MISMATCH', -20, `openai-model header "${om}" ≠ body model "${wireModel}".`, 'header');
      flag('error', 'HEADER_MODEL_MISMATCH', `${om} vs ${wireModel}`);
    }
  }

  /* ---------- claimed (requested) model vs wire model ---------- */
  let substitution = null;
  if (claimedModel && wireModel) {
    const c = normalizeModelId(claimedModel);
    const w = normalizeModelId(wireModel);
    const sameish = c === w || w.startsWith(c + '-') || c.startsWith(w + '-') || w.startsWith(c + '.');
    if (!sameish) {
      if (claimedFamily && wireFamily && claimedFamily !== wireFamily && claimedFamily !== 'other' && wireFamily !== 'other') {
        substitution = 'cross_family';
        addEvidence(negative, 'CLAIMED_VS_WIRE_FAMILY', -40, `Requested "${claimedModel}" (${claimedFamily}) but wire reports "${wireModel}" (${wireFamily}).`);
        flag('error', 'MODEL_SUBSTITUTION', `${claimedModel} -> ${wireModel}`);
      } else {
        substitution = 'same_family';
        addEvidence(negative, 'CLAIMED_VS_WIRE_MODEL', -20, `Requested "${claimedModel}" but wire reports "${wireModel}" (same family — tier downgrade/alias routing).`);
        flag('warn', 'MODEL_SUBSTITUTION', `${claimedModel} -> ${wireModel}`);
      }
    }
  } else if (claimedModel && !wireModel) {
    flag('info', 'NO_WIRE_MODEL', 'Stream did not report a model; only the requested model is known.');
  }
  if (claimedFamily && !NATIVE_PROTOCOLS[claimedFamily]?.includes(mode) && mode !== 'unknown' && !(wireFamily && wireFamily !== claimedFamily)) {
    if (!flags.some((f) => f.code === 'PROTOCOL_TRANSLATION')) {
      addEvidence(negative, 'CLAIMED_MODEL_NON_NATIVE_PROTOCOL', -15, `${claimedModel} (${claimedFamily}) requested over ${mode}, which is not its native protocol.`);
      flag('warn', 'PROTOCOL_TRANSLATION', `${claimedFamily} model over ${mode}`);
    }
  }

  /* ---------- self-report (unreliable, informational) ---------- */
  const self = extractSelfReport(parsed.output_text || '');
  const selfModelsNorm = self.models.map((m) => ({ ...m, normalized: normalizeModelId(m.name.replace(/\s+/g, '-')) }));
  const wireNorm = wireModel ? normalizeModelId(wireModel) : null;
  const specific = selfModelsNorm.filter((m) => /\d/.test(m.name));
  const nameMismatch = !!(wireNorm && specific.length && !specific.some((m) => wireNorm.startsWith(m.normalized) || m.normalized.startsWith(wireNorm)));
  const familyConflict = !!(wireFamily && self.families.length && !self.families.includes(wireFamily));
  if (familyConflict) {
    addEvidence(negative, 'SELF_REPORT_FOREIGN_FAMILY', -8, `Model text self-identifies as ${self.families.join('/')} while wire family is ${wireFamily} (weak hint only — personas/system prompts can cause this).`, 'self_report');
    flag('warn', 'SELF_REPORT_FOREIGN_FAMILY', self.models.map((m) => m.name).join(', '));
  }
  const selfReportVsWire = {
    reliability: 'unreliable',
    weight: familyConflict ? -8 : 0,
    selfReportedModels: self.models.map((m) => m.name),
    selfReportedProviders: self.providers,
    selfReportedFamilies: self.families,
    selfReportedKnowledgeCutoff: self.knowledgeCutoff,
    wireModel,
    wireFamily,
    wireProof: positive.filter((e) => e.kind === 'wire' || e.kind === 'crypto' || e.kind === 'header').map((e) => e.code),
    mismatch: nameMismatch || familyConflict,
    familyConflict,
    note: !self.models.length && !self.providers.length
      ? 'No model self-identification found in output text.'
      : nameMismatch && !familyConflict
        ? `Text self-report ${specific.map((m) => `"${m.name}"`).join(', ')} contradicts wire model "${wireModel}". Same provider family: typical stale self-knowledge (models are trained before their own release name exists). Wire telemetry wins; self-report ignored for scoring.`
        : familyConflict
          ? `Text self-report (${self.models.map((m) => m.name).join(', ') || self.providers.join(', ')}) names a different provider family than wire "${wireModel}". Self-report is unreliable but cross-family conflicts merit a manual look.`
          : 'Text self-report is consistent with wire telemetry (still not used as proof).',
  };

  /* ---------- scoring ---------- */
  // Positive points are normalized against the evidence a fully-native capture of that protocol can
  // realistically expose (Responses exposes far more telemetry than Chat Completions), then negative
  // points are applied unscaled. Pure arithmetic => fully deterministic.
  const pos = positive.reduce((s, e) => s + e.points, 0);
  const neg = negative.reduce((s, e) => s + e.points, 0);
  const ref = PROTOCOL_REFERENCE_POINTS[mode] || 100;
  let score = Math.max(0, Math.min(100, Math.round((100 * pos) / ref) + neg));
  if (!parsed.frameCount || mode === 'unknown') score = 0;

  const hasTranslation = flags.some((f) => f.code === 'PROTOCOL_TRANSLATION' || f.code === 'ENDPOINT_PROTOCOL_MISMATCH' || f.code === 'THINKING_UNSIGNED');
  const hasSpoof = flags.some((f) => (f.code === 'MODEL_SUBSTITUTION' && substitution === 'cross_family') || f.code === 'FOREIGN_PROVIDER_HEADERS' || f.code === 'HEADER_MODEL_MISMATCH' || f.code === 'ATTRIBUTION_MISMATCH');
  const hasSubstitution = substitution === 'same_family';

  let verdict;
  if (!parsed.frameCount || mode === 'unknown' || (!wireModel && !parsed.id && pos < 10)) verdict = 'UNVERIFIED';
  else if (hasSpoof || (hasSubstitution && score < 50)) verdict = 'SUSPECTED_SPOOF';
  else if (hasTranslation || hasSubstitution) verdict = 'TRANSLATED_PROXY';
  else if (score >= 80 && proofs >= 2) verdict = 'VERIFIED_NATIVE';
  else if (score >= 55) verdict = 'LIKELY_NATIVE';
  else verdict = 'UNVERIFIED';
  if (!VERDICTS.includes(verdict)) verdict = 'UNVERIFIED';

  const summaryParts = [`${verdict} (${score}/100)`, `${mode}`, wireModel ? `wire=${wireModel}` : 'wire=?'];
  if (claimedModel) summaryParts.push(`claimed=${claimedModel}`);
  if (selfReportVsWire.mismatch) summaryParts.push(`self-report=${selfReportVsWire.selfReportedModels.join('/')} (ignored)`);

  return {
    engineVersion: ENGINE_VERSION,
    authenticityScore: score,
    verdict,
    summary: summaryParts.join(' · '),
    mode,
    endpointMode,
    claimedModel,
    wireModel,
    wireModelNormalized: wireNorm,
    wireFamily,
    claimedFamily,
    proofCount: proofs,
    evidence: {
      positive,
      negative,
      positivePoints: pos,
      negativePoints: neg,
      referencePoints: ref,
    },
    flags,
    selfReportVsWire,
    headers: headerInfo,
    timing: parsed.timing,
    tokens: parsed.tokens,
    usageAttribution: parsed.attribution,
    parsed,
  };
}

function scrubSecrets(text) {
  return String(text ?? '')
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, '$1***')
    .replace(/("?(?:authorization|x-api-key|api[-_]?key|x-goog-api-key)"?\s*[:=]\s*"?)[^"\s,}]+/gi, '$1***')
    .replace(/\b(sk|rk|sess|AIza)[-_A-Za-z0-9]{16,}/g, '***');
}

/** Compact, secret-free analysis JSON (drops raw frames). */
export function compactAnalysis(analysis) {
  const { parsed, ...rest } = analysis;
  const { frames, usage, ...p } = parsed || {};
  return { ...rest, parsed: p };
}

/**
 * Flatten an analysis into a row matching the `sse_forensics` table columns (src/db/schema.mjs).
 * @param {object} analysis analyzeForensics() result
 * @param {{capture_id?: string, created_at?: string, source_tool?: string, base_url?: string, headers?: object, rawExcerpt?: string}} [extra]
 */
export function toForensicRecord(analysis, extra = {}) {
  const p = analysis.parsed || {};
  const t = p.timing || {};
  const tk = p.tokens || {};
  const sigs = (p.thinking || []).filter((b) => b.signature?.present);
  const source = extra.source_tool || 'forensics';
  const capture_id =
    extra.capture_id ||
    (p.id ? `cap_${createHash('sha256').update(`${source}|${p.id}|${p.bytes || 0}|${p.frameCount || 0}`).digest('hex').slice(0, 24)}` : `cap_${randomUUID().replace(/-/g, '').slice(0, 24)}`);
  return {
    capture_id,
    created_at: extra.created_at || new Date().toISOString(),
    source_tool: source,
    endpoint_mode: analysis.mode || 'unknown',
    base_url: extra.base_url ? String(extra.base_url).replace(/([?&](?:key|api_key|token)=)[^&]+/gi, '$1***') : '',
    requested_model: analysis.claimedModel || '',
    wire_model: analysis.wireModel || '',
    self_reported_model: analysis.selfReportVsWire.selfReportedModels.join(', ') || null,
    response_id: p.id || null,
    system_fingerprint: p.system_fingerprint || null,
    service_tier: p.service_tier || null,
    prompt_cache_key: p.prompt_cache_key || null,
    prompt_cache_retention: p.prompt_cache_retention || null,
    safety_identifier: p.safety_identifier || null, // already masked by parser when privacy !== false
    has_signature: sigs.some((b) => b.signature.plausible) ? 1 : 0,
    signature_length: sigs.reduce((s, b) => s + (b.signature.length || 0), 0),
    input_tokens: tk.input_tokens ?? 0,
    output_tokens: tk.output_tokens ?? 0,
    cache_read_tokens: tk.cache_read_tokens ?? 0,
    cache_write_tokens: tk.cache_write_tokens ?? 0,
    cache_ttl_30m_tokens: tk.cache_write_30m_tokens ?? 0,
    cache_ttl_12h_tokens: tk.cache_write_12h_tokens ?? 0,
    reasoning_tokens: tk.reasoning_tokens ?? 0,
    instructions_tokens: p.attribution?.instructions_input_tokens ?? 0,
    ttft_ms: t.ttftMs ?? null,
    ttfr_ms: t.ttfrMs ?? null,
    ttfa_ms: t.ttfaMs ?? null,
    tpot_ms: t.tpotMs ?? null,
    total_ms: t.totalMs ?? null,
    tok_per_sec: t.tokPerSec ?? null,
    chunk_count: t.chunkCount ?? p.frameCount ?? 0,
    jitter_ms: t.jitterMs ?? null,
    authenticity_score: analysis.authenticityScore ?? 0,
    verdict: analysis.verdict || 'UNVERIFIED',
    attribution_json: p.attribution ? JSON.stringify(p.attribution) : null,
    headers_json: extra.headers ? JSON.stringify(analyzeHeaders(extra.headers).notable) : analysis.headers?.present ? JSON.stringify(analysis.headers.notable) : null,
    analysis_json: JSON.stringify(compactAnalysis(analysis)),
    raw_excerpt: extra.rawExcerpt ? scrubSecrets(String(extra.rawExcerpt).slice(0, 4000)) : null,
  };
}

/**
 * Build a normalized `requests`-table event from an analysis (used by the tee proxy).
 * Cost columns are left for the pricing engine.
 */
export function toRequestEvent(analysis, extra = {}) {
  const p = analysis.parsed || {};
  const t = p.timing || {};
  const tk = p.tokens || {};
  const rawModel = analysis.wireModel || analysis.claimedModel || 'unknown';
  const created = extra.created_at || new Date().toISOString();
  const source = extra.source_tool || 'tee-proxy';
  const dedupBase = p.id || extra.capture_id || randomUUID();
  return {
    dedup_key: `${source}:${dedupBase}`,
    created_at: created,
    completed_at: extra.completed_at || created,
    era: 'live',
    source_tool: source,
    account_id: extra.account_id || 'unknown',
    endpoint_mode: analysis.mode || 'unknown',
    endpoint: extra.endpoint || '',
    model_raw: rawModel,
    raw_model: rawModel,
    model_id: normalizeModelId(rawModel),
    provider: analysis.wireFamily || analysis.claimedFamily || 'unknown',
    effort: p.reasoning?.effort || null,
    plan_type: extra.plan_type || 'api',
    input_tokens: tk.input_tokens ?? 0,
    uncached_input_tokens: tk.uncached_input_tokens ?? 0,
    output_tokens: tk.output_tokens ?? 0,
    cache_read_tokens: tk.cache_read_tokens ?? 0,
    cache_write_tokens: tk.cache_write_tokens ?? 0,
    cache_write_5m_tokens: tk.cache_write_5m_tokens ?? 0,
    cache_write_1h_tokens: tk.cache_write_1h_tokens ?? 0,
    cache_ttl_30m_tokens: tk.cache_write_30m_tokens ?? 0,
    cache_ttl_12h_tokens: tk.cache_write_12h_tokens ?? 0,
    reasoning_tokens: tk.reasoning_tokens ?? 0,
    // All four wire protocols (as normalized by sse-parser) report output_tokens INCLUDING reasoning.
    reasoning_included_in_output: true,
    instructions_tokens: p.attribution?.instructions_input_tokens ?? 0,
    context_tokens: tk.input_tokens ?? 0,
    ttft_ms: t.ttftMs ?? null,
    ttfr_ms: t.ttfrMs ?? null,
    ttfa_ms: t.ttfaMs ?? null,
    tpot_ms: t.tpotMs ?? null,
    latency_ms: t.totalMs ?? null,
    tok_per_sec: t.tokPerSec ?? null,
    service_tier: p.service_tier || null,
    prompt_cache_retention: p.prompt_cache_retention || null,
    safety_identifier: p.safety_identifier || null,
    response_id: p.id || null,
    system_fingerprint: p.system_fingerprint || null,
    has_signature: (p.thinking || []).some((b) => b.signature?.plausible) ? 1 : 0,
    authenticity_score: analysis.authenticityScore ?? null,
    verdict: analysis.verdict || null,
    status: extra.status_code && extra.status_code >= 400 ? 'error' : 'ok',
    status_code: extra.status_code ?? 200,
    meta_json: JSON.stringify({ capture_id: extra.capture_id || null, flags: analysis.flags.map((f) => f.code) }),
  };
}

export default analyzeForensics;
