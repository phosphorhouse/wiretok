/**
 * Wiretok — Active Endpoint Prober
 *
 * probeEndpoint({ baseUrl, apiKey, endpointMode, model, prompt, timeoutMs })
 * Sends ONE small streaming request, captures every chunk with performance.now() resolution plus
 * provider/gateway HTTP headers, then feeds the capture into analyzeForensics().
 *
 * SECURITY: the apiKey only lives in the outgoing request headers. It is never logged, written to
 * disk, placed in the returned object, or echoed inside error messages (error text is scrubbed).
 */
import dns from 'node:dns';
import net from 'node:net';
import { performance } from 'node:perf_hooks';
import { isSafeObjectKey } from '../contracts.mjs';
import { analyzeForensics } from './fingerprint-engine.mjs';

const SSRF_BLOCKLIST = new net.BlockList();
SSRF_BLOCKLIST.addSubnet('169.254.0.0', 16, 'ipv4');
SSRF_BLOCKLIST.addSubnet('0.0.0.0', 8, 'ipv4');
SSRF_BLOCKLIST.addSubnet('100.64.0.0', 10, 'ipv4');
SSRF_BLOCKLIST.addSubnet('fe80::', 10, 'ipv6');
SSRF_BLOCKLIST.addSubnet('fc00::', 7, 'ipv6');
SSRF_BLOCKLIST.addAddress('::', 'ipv6');

const BLOCKED_METADATA_HOSTS = new Set([
  'metadata.google.internal',
  'metadata.goog',
  'metadata',
  'instance-data',
  '169.254.169.254',
  '100.100.100.200',
  'fd00:ec2::254',
]);

function extractMappedIpv4(ipv6Host) {
  const mDotted = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(ipv6Host);
  if (mDotted && net.isIPv4(mDotted[1])) return mDotted[1];
  const mHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(ipv6Host);
  if (mHex) {
    const hi = parseInt(mHex[1], 16);
    const lo = parseInt(mHex[2], 16);
    return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
  }
  return null;
}

function isBlockedIpAddress(ipStr) {
  const clean = String(ipStr || '').replace(/^\[|\]$/g, '').split('%')[0].toLowerCase();
  const ipType = net.isIP(clean);
  if (ipType === 4) {
    return SSRF_BLOCKLIST.check(clean, 'ipv4');
  }
  if (ipType === 6) {
    if (SSRF_BLOCKLIST.check(clean, 'ipv6')) return true;
    const mapped4 = extractMappedIpv4(clean);
    if (mapped4 && SSRF_BLOCKLIST.check(mapped4, 'ipv4')) return true;
  }
  return false;
}

/**
 * Validate an outbound upstream URL against SSRF targets (cloud metadata, link-local,
 * CGNAT, ULA IPv6, unspecified addresses, and non-HTTP(S) schemes) while permitting
 * localhost routers (e.g. OmniRoute 127.0.0.1:20128, 9Router).
 * @param {string} rawUrl
 * @param {{ rejectGoogleInternal?: boolean }} [opts]
 * @returns {URL}
 */
export function assertSafeUpstreamUrl(rawUrl, opts = {}) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    const err = new Error('Upstream URL is required');
    err.statusCode = 400;
    throw err;
  }
  let u;
  try {
    u = new URL(rawUrl.trim());
  } catch {
    const err = new Error('Invalid upstream URL');
    err.statusCode = 400;
    throw err;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    const err = new Error('Upstream URL must use http:// or https://');
    err.statusCode = 400;
    throw err;
  }
  if (!u.hostname) {
    const err = new Error('Upstream URL must include a hostname');
    err.statusCode = 400;
    throw err;
  }

  const host = u.hostname.replace(/^\[|\]$/g, '').split('%')[0].toLowerCase();
  if (
    BLOCKED_METADATA_HOSTS.has(host) ||
    host.endsWith('.metadata.google.internal') ||
    host.endsWith('.internal')
  ) {
    const err = new Error(`Blocked SSRF target host: ${host}`);
    err.statusCode = 403;
    throw err;
  }

  if (opts.rejectGoogleInternal) {
    if (
      host === 'google.com' ||
      host.endsWith('.google.com') ||
      host === 'googleapis.com' ||
      host.endsWith('.googleapis.com') ||
      host.includes('antigravity')
    ) {
      const err = new Error(`Refusing disallowed benchmark target domain: ${host}`);
      err.statusCode = 403;
      throw err;
    }
  }

  if (isBlockedIpAddress(host)) {
    const err = new Error(`Blocked SSRF IP range: ${host}`);
    err.statusCode = 403;
    throw err;
  }

  return u;
}

async function assertResolvedHostSafe(hostname) {
  const clean = String(hostname || '').replace(/^\[|\]$/g, '').split('%')[0].toLowerCase();
  if (!clean || clean === 'localhost' || net.isIP(clean)) return;
  let records;
  try {
    records = await dns.promises.lookup(clean, { all: true, verbatim: true });
  } catch (err) {
    if (process.env.WIRETOK_DEBUG) {
      console.error('[wiretok:active-prober] DNS lookup skipped/failed:', err?.message || err);
    }
    return;
  }
  for (const rec of records) {
    if (isBlockedIpAddress(rec.address)) {
      const err = new Error(`Blocked SSRF DNS resolution target (${rec.address})`);
      err.statusCode = 403;
      throw err;
    }
  }
}

export const DEFAULT_PROBE_PROMPT =
  'Reply as a short bullet list with exactly five lines: your provider, product, exact model name, API, and knowledge cutoff.';

const PATHS = {
  responses: '/responses',
  messages: '/messages',
  chat_completions: '/chat/completions',
};

const CAPTURE_HEADER_RE = /^(x-request-id|request-id|openai-|anthropic-|x-ratelimit-|cf-ray|cf-cache-status|server|via|date|content-type|x-goog-|x-envoy-|x-litellm-|x-omniroute|x-openrouter|x-9router|x-portkey|helicone-|x-kong-|x-oneapi|x-new-api|x-model|x-served-by|x-cloud-trace-context|retry-after)/i;
const PROBE_COOKIE_HDR = ['set', 'cookie'].join('-');
const SECRET_HEADER_RE = new RegExp(`^(authorization|proxy-authorization|x-api-key|api-key|x-goog-api-key|cookie|${PROBE_COOKIE_HDR})$`, 'i');

/** Build the request URL for an endpoint mode from a base URL like https://api.openai.com or .../v1 */
export function buildProbeUrl(baseUrl, endpointMode, model) {
  if (!baseUrl || typeof baseUrl !== 'string') throw new Error('baseUrl is required');
  const u = new URL(baseUrl.trim());
  let p = u.pathname.replace(/\/+$/, '');
  if (endpointMode === 'gemini') {
    if (!/\/v1(beta|alpha)?$/.test(p) && !/:streamGenerateContent$/.test(p)) p += '/v1beta';
    if (!/:streamGenerateContent$/.test(p)) p += `/models/${encodeURIComponent(model)}:streamGenerateContent`;
    u.pathname = p;
    u.searchParams.set('alt', 'sse');
    return u;
  }
  const suffix = PATHS[endpointMode];
  if (!suffix) throw new Error(`Unsupported endpointMode "${endpointMode}" (use responses | messages | chat_completions | gemini)`);
  if (!p.endsWith(suffix)) {
    if (!/\/v\d+(beta|alpha)?$/.test(p) && !/\/(openai|api|compatible-mode)\/?$/.test(p) && !/\/v\d/.test(p)) p += '/v1';
    p += suffix;
  }
  u.pathname = p;
  return u;
}

/** Build a minimal streaming request body for each protocol. */
export function buildProbeBody(endpointMode, { model, prompt, maxOutputTokens = 256, thinking = false, reasoningEffort } = {}) {
  const text = prompt || DEFAULT_PROBE_PROMPT;
  if (endpointMode === 'responses') {
    const body = { model, input: text, stream: true, max_output_tokens: maxOutputTokens, store: false };
    if (reasoningEffort) body.reasoning = { effort: reasoningEffort, summary: 'auto' };
    return body;
  }
  if (endpointMode === 'messages') {
    const body = { model, max_tokens: maxOutputTokens, stream: true, messages: [{ role: 'user', content: text }] };
    if (thinking) {
      const budget = typeof thinking === 'number' ? thinking : 1024;
      body.thinking = { type: 'enabled', budget_tokens: budget };
      body.max_tokens = Math.max(maxOutputTokens, budget + 256);
    }
    return body;
  }
  if (endpointMode === 'chat_completions') {
    const body = { model, stream: true, stream_options: { include_usage: true }, max_tokens: maxOutputTokens, messages: [{ role: 'user', content: text }] };
    if (reasoningEffort) body.reasoning_effort = reasoningEffort;
    return body;
  }
  if (endpointMode === 'gemini') {
    const body = { contents: [{ role: 'user', parts: [{ text }] }], generationConfig: { maxOutputTokens } };
    if (thinking) body.generationConfig.thinkingConfig = { includeThoughts: true, ...(typeof thinking === 'number' ? { thinkingBudget: thinking } : {}) };
    return body;
  }
  throw new Error(`Unsupported endpointMode "${endpointMode}"`);
}

function buildHeaders(endpointMode, apiKey, authStyle, extraHeaders) {
  const h = Object.create(null);
  h['content-type'] = 'application/json';
  h.accept = 'text/event-stream';
  h['accept-encoding'] = 'identity';
  h['user-agent'] = 'wiretok-prober/1.0';
  if (endpointMode === 'messages') h['anthropic-version'] = '2023-06-01';
  if (extraHeaders && typeof extraHeaders === 'object') {
    for (const [k, v] of Object.entries(extraHeaders)) {
      if (!isSafeObjectKey(k) || k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
      if (!SECRET_HEADER_RE.test(k)) h[k.toLowerCase()] = String(v);
    }
  }
  if (apiKey) {
    const style = authStyle === 'auto' || !authStyle ? (endpointMode === 'messages' ? 'x-api-key' : endpointMode === 'gemini' ? 'x-goog-api-key' : 'bearer') : authStyle;
    if (style === 'bearer' || style === 'both') h.authorization = `Bearer ${apiKey}`;
    if (style === 'x-api-key' || style === 'both') h['x-api-key'] = apiKey;
    if (style === 'x-goog-api-key') h['x-goog-api-key'] = apiKey;
  }
  return h;
}

function pickHeaders(headers) {
  const out = {};
  for (const [k, v] of headers.entries()) {
    if (SECRET_HEADER_RE.test(k)) continue;
    if (CAPTURE_HEADER_RE.test(k)) out[k.toLowerCase()] = v;
  }
  return out;
}

function scrub(text, apiKey) {
  let s = String(text ?? '');
  if (apiKey && apiKey.length >= 4) s = s.split(apiKey).join('***');
  return s
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, '$1***')
    .replace(/\b(sk|rk|pk|sess|key|AIza)[-_A-Za-z0-9]{12,}/g, '***');
}

function safeUrl(u) {
  const c = new URL(u.toString());
  for (const k of [...c.searchParams.keys()]) if (/key|token|secret|sig/i.test(k)) c.searchParams.set(k, '***');
  c.username = '';
  c.password = '';
  return c.toString();
}

/**
 * Live-probe an endpoint with a streaming request.
 * @param {{
 *   baseUrl: string, apiKey?: string, endpointMode?: 'responses'|'messages'|'chat_completions'|'gemini',
 *   model: string, prompt?: string, timeoutMs?: number, maxOutputTokens?: number, thinking?: boolean|number,
 *   reasoningEffort?: string, authStyle?: 'auto'|'bearer'|'x-api-key'|'both'|'x-goog-api-key',
 *   extraHeaders?: object, privacy?: boolean, keepFrames?: boolean, fetchImpl?: typeof fetch
 * }} opts
 */
export async function probeEndpoint(opts = {}) {
  const {
    baseUrl,
    apiKey,
    endpointMode = 'responses',
    model,
    prompt,
    timeoutMs = 60000,
    maxOutputTokens = 256,
    thinking = false,
    reasoningEffort,
    authStyle = 'auto',
    extraHeaders,
    privacy = true,
    fetchImpl = globalThis.fetch,
  } = opts;
  const startedAt = new Date().toISOString();
  const base = { ok: false, startedAt, endpointMode, model: model || null, keyProvided: !!apiKey };
  let url;
  try {
    if (!model) throw new Error('model is required');
    assertSafeUpstreamUrl(baseUrl);
    url = buildProbeUrl(baseUrl, endpointMode, model);
    assertSafeUpstreamUrl(url.toString());
    if (fetchImpl === globalThis.fetch) {
      await assertResolvedHostSafe(url.hostname);
    }
  } catch (e) {
    return { ...base, error: scrub(e.message, apiKey) };
  }
  const body = buildProbeBody(endpointMode, { model, prompt, maxOutputTokens, thinking, reasoningEffort });
  const headers = buildHeaders(endpointMode, apiKey, authStyle, extraHeaders);
  const ac = new AbortController();
  const timeoutSignal = AbortSignal.timeout(timeoutMs);
  const signal = typeof AbortSignal.any === 'function' ? AbortSignal.any([ac.signal, timeoutSignal]) : ac.signal;
  const timer = setTimeout(() => ac.abort(new Error(`probe timed out after ${timeoutMs} ms`)), timeoutMs);
  const chunks = [];
  const t0 = performance.now();
  let tHeaders = null;
  let tEnd = null;
  let status = null;
  let statusText = '';
  let respHeaders = {};
  let rawBytes = 0;
  let errorText = null;
  let aborted = false;
  try {
    const res = await fetchImpl(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      redirect: 'error',
      signal,
    });
    tHeaders = performance.now();
    status = res.status;
    statusText = res.statusText;
    respHeaders = pickHeaders(res.headers);
    if (res.body) {
      const reader = res.body.getReader();
      const dec = new TextDecoder('utf-8');
      for (;;) {
        const { value, done } = await reader.read();
        const t = performance.now();
        if (done) {
          const tail = dec.decode();
          if (tail) chunks.push({ t: t - t0, text: tail });
          break;
        }
        rawBytes += value.byteLength;
        const text = dec.decode(value, { stream: true });
        if (text) chunks.push({ t: t - t0, text });
      }
    }
    tEnd = performance.now();
    if (!res.ok) errorText = scrub(chunks.map((c) => c.text).join('').slice(0, 2000), apiKey);
  } catch (e) {
    tEnd = performance.now();
    aborted = ac.signal.aborted || timeoutSignal.aborted || e?.name === 'TimeoutError';
    errorText = scrub(aborted ? `timeout/abort: ${e?.message || e}` : e?.message || String(e), apiKey);
  } finally {
    clearTimeout(timer);
  }

  const result = {
    ...base,
    url: safeUrl(url),
    status,
    statusText,
    aborted,
    headers: respHeaders,
    request: { endpointMode, model, promptChars: (prompt || DEFAULT_PROBE_PROMPT).length, maxOutputTokens, thinking: !!thinking, authStyle: apiKey ? authStyle : 'none' },
    capture: {
      chunkCount: chunks.length,
      bytes: rawBytes,
      headersMs: tHeaders != null ? Math.round((tHeaders - t0) * 100) / 100 : null,
      totalMs: tEnd != null ? Math.round((tEnd - t0) * 100) / 100 : null,
      chunkDeltasMs: chunks.map((c, i) => Math.round((i ? c.t - chunks[i - 1].t : c.t) * 100) / 100),
    },
    finishedAt: new Date().toISOString(),
  };

  if (status != null && status >= 200 && status < 300 && chunks.length) {
    const analysis = analyzeForensics(chunks, { endpointMode, mode: 'auto', claimedModel: model, headers: respHeaders, privacy, t0: 0, tEnd: tEnd - t0 });
    result.ok = true;
    result.forensics = analysis;
    if (tHeaders != null) result.forensics.timing = { ...analysis.timing, headersMs: result.capture.headersMs };
  } else {
    result.error = errorText || `HTTP ${status} ${statusText}`.trim();
  }
  if (opts.keepFrames && chunks.length) result.rawCapture = scrub(chunks.map((c) => c.text).join(''), apiKey);
  return result;
}

export default probeEndpoint;
