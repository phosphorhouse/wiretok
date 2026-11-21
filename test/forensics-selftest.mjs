/**
 * Wiretok — Forensics self-test.  Run:  node --no-warnings test/forensics-selftest.mjs [--json]
 * Uses only local fixtures + loopback mock upstreams (no network, no real keys, no DB writes).
 */
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import assert from 'node:assert/strict';
import { ROOT_DIR } from '../src/contracts.mjs';
import { parseSse, analyzeForensics, probeEndpoint, createTeeProxy, toForensicRecord, buildProbeUrl, joinUpstream } from '../src/forensics/index.mjs';

function assertLocalhostUrl(raw) {
  const u = new URL(raw);
  assert.ok(['127.0.0.1', 'localhost', '::1'].includes(u.hostname), `Blocked non-localhost test target: ${u.hostname}`);
  return u.toString();
}

const FIX = path.join(ROOT_DIR, 'test', 'fixtures');
const read = (f) => fs.readFileSync(path.join(FIX, f), 'utf8');
const results = [];
async function test(name, fn) {
  try {
    const info = await fn();
    results.push({ name, ok: true, info });
  } catch (e) {
    results.push({ name, ok: false, error: e.message });
  }
}

/* 1. GPT-6 Astra Responses fixture (MUST DO) */
await test('responses fixture: gpt-6-astra wire telemetry', () => {
  const raw = read('sample_gpt6_astra_responses.sse');
  const p = parseSse(raw);
  assert.equal(p.mode, 'responses');
  assert.equal(p.model, 'gpt-6-astra');
  assert.equal(p.usage.attribution.request_fields.instructions.input_tokens, 39);
  assert.equal(p.usage.input_tokens, 164);
  assert.equal(p.usage.output_tokens, 31);
  assert.equal(p.prompt_cache_retention, '24h');
  assert.equal(p.attribution.items_input_tokens, 125);
  assert.equal(p.attribution.input_reconciles, true);
  assert.equal(p.tokens.cache_write_30m_tokens, 0);
  assert.match(p.id, /^resp_[0-9a-f]+$/);
  assert.equal(p.safety_identifier, 'user-w...tchy');
  const a = analyzeForensics(raw, { endpointMode: 'responses', claimedModel: 'gpt-6-astra' });
  assert.equal(a.selfReportVsWire.mismatch, true);
  assert.ok(a.selfReportVsWire.selfReportedModels.includes('GPT-5.2'));
  assert.equal(a.selfReportVsWire.reliability, 'unreliable');
  assert.ok(a.selfReportVsWire.wireProof.includes('RESP_ID_NATIVE_FORMAT'));
  assert.ok(a.selfReportVsWire.wireProof.includes('USAGE_ATTRIBUTION'));
  assert.equal(a.verdict, 'VERIFIED_NATIVE');
  assert.ok(a.authenticityScore >= 80);
  for (const em of ['auto', 'unknown', '', undefined]) {
    const b = analyzeForensics(raw, { endpointMode: em, mode: em });
    assert.equal(b.verdict, 'VERIFIED_NATIVE', `endpointMode=${em} must not count as a mismatch`);
  }
  const rec = toForensicRecord(a, { source_tool: 'manual-ingest' });
  assert.equal(rec.instructions_tokens, 39);
  assert.ok(!JSON.stringify(rec).includes('user-wcirBGUUtKz6Mw6Z9l1Qtchy'), 'raw safety_identifier leaked');
  return { score: a.authenticityScore, verdict: a.verdict, selfReport: a.selfReportVsWire.selfReportedModels, wire: a.wireModel, attribution: `${p.attribution.items.map((i) => i.input_tokens).join('+')}+instr ${p.attribution.instructions_input_tokens} = ${p.attribution.attributed_input_tokens}`, timing: p.timing };
});

/* 2. Native Anthropic messages with signature_delta */
await test('messages: native claude with signature_delta', () => {
  const raw = read('synthetic_claude_messages_signed.sse');
  const a = analyzeForensics(raw, { endpointMode: 'messages', claimedModel: 'claude-sonnet-5-5' });
  const p = a.parsed;
  assert.equal(p.mode, 'messages');
  assert.equal(p.idFormat, 'anthropic_msg');
  assert.equal(p.thinking[0].signature.plausible, true);
  assert.equal(p.thinking[0].signature.decodedBytes, 384);
  assert.equal(p.usage.cache_creation.ephemeral_5m_input_tokens, 2048);
  assert.equal(p.tokens.cache_read_tokens, 10240);
  assert.equal(p.tokens.input_tokens, 412 + 2048 + 10240);
  assert.equal(p.tokens.output_tokens, 87);
  assert.ok(p.output_text.includes('Claude 3.5 Sonnet'));
  assert.equal(a.verdict, 'VERIFIED_NATIVE');
  assert.equal(a.selfReportVsWire.familyConflict, false);
  assert.equal(a.selfReportVsWire.mismatch, true); // "Claude 3.5 Sonnet" vs claude-sonnet-5-5 (same family, stale)
  return { score: a.authenticityScore, verdict: a.verdict, sig: p.thinking[0].signature };
});

/* 3. Translated messages (chatcmpl- id, unsigned thinking) */
await test('messages: translated proxy detection', () => {
  const a = analyzeForensics(read('synthetic_claude_messages_translated.sse'), { endpointMode: 'messages', claimedModel: 'claude-opus-5-5' });
  const codes = a.flags.map((f) => f.code);
  assert.ok(codes.includes('PROTOCOL_TRANSLATION'));
  assert.ok(codes.includes('THINKING_UNSIGNED'));
  assert.ok(codes.includes('SELF_REPORT_FOREIGN_FAMILY'));
  assert.ok(['TRANSLATED_PROXY', 'SUSPECTED_SPOOF'].includes(a.verdict));
  assert.ok(a.authenticityScore < 30);
  return { score: a.authenticityScore, verdict: a.verdict, flags: codes };
});

/* 4. Chat completions with system_fingerprint */
await test('chat_completions: system_fingerprint + usage details', () => {
  const a = analyzeForensics(read('synthetic_chat_completions_fp.sse'), { endpointMode: 'chat_completions', claimedModel: 'gpt-6.1-sol' });
  const p = a.parsed;
  assert.equal(p.mode, 'chat_completions');
  assert.equal(p.system_fingerprint, 'fp_44709d6fcb');
  assert.equal(p.idFormat, 'openai_chatcmpl');
  assert.equal(p.doneMarker, true);
  assert.equal(p.tokens.input_tokens, 58);
  assert.equal(p.tokens.output_tokens, 24);
  assert.ok(p.output_text.includes('GPT-4o'));
  assert.equal(a.selfReportVsWire.mismatch, true);
  assert.ok(['LIKELY_NATIVE', 'VERIFIED_NATIVE'].includes(a.verdict));
  return { score: a.authenticityScore, verdict: a.verdict };
});

/* 5. Chat completions: claimed claude served over chat (translation) + cross-family substitution */
await test('chat_completions: cross-family substitution => SUSPECTED_SPOOF', () => {
  const a = analyzeForensics(read('synthetic_chat_completions_fp.sse'), { endpointMode: 'chat_completions', claimedModel: 'claude-opus-5-5' });
  assert.equal(a.verdict, 'SUSPECTED_SPOOF');
  return { score: a.authenticityScore, verdict: a.verdict };
});

/* 6. Endpoint/protocol mismatch: called /v1/messages but got chat chunks */
await test('endpoint mismatch => TRANSLATED_PROXY', () => {
  const a = analyzeForensics(read('synthetic_chat_completions_fp.sse'), { endpointMode: 'messages' });
  assert.ok(a.flags.some((f) => f.code === 'ENDPOINT_PROTOCOL_MISMATCH'));
  assert.equal(a.verdict, 'TRANSLATED_PROXY');
  return { score: a.authenticityScore, verdict: a.verdict };
});

/* 7. Gemini */
await test('gemini: thoughts + usageMetadata', () => {
  const a = analyzeForensics(read('synthetic_gemini_thoughts.sse'), { claimedModel: 'gemini-4-hydrogen-high' });
  const p = a.parsed;
  assert.equal(p.mode, 'gemini');
  assert.equal(p.tokens.reasoning_tokens, 64);
  assert.equal(p.tokens.output_tokens, 82);
  assert.ok(p.reasoning_text_chars > 0);
  assert.ok(['LIKELY_NATIVE', 'VERIFIED_NATIVE'].includes(a.verdict));
  return { score: a.authenticityScore, verdict: a.verdict };
});

/* 8. Chunk timing (TTFT/TTFR/TTFA/TPOT/jitter) */
await test('timing from timestamped chunks', () => {
  const raw = read('synthetic_claude_messages_signed.sse');
  const frames = raw.split('\n\n').filter(Boolean);
  const chunks = frames.map((f, i) => ({ t: 100 + i * 20 + (i % 2 ? 3 : 0), text: f + '\n\n' }));
  const p = parseSse(chunks, { t0: 0 });
  assert.equal(p.timing.source, 'chunk_timestamps');
  assert.equal(p.timing.ttfbMs, 100);
  assert.ok(p.timing.ttfrMs > 0 && p.timing.ttfaMs > p.timing.ttfrMs);
  assert.ok(p.timing.tpotMs > 0 && p.timing.tokPerSec > 0 && p.timing.jitterMs >= 0);
  // split across arbitrary byte boundaries must give identical result
  const split = [];
  for (let i = 0; i < raw.length; i += 37) split.push({ t: i, text: raw.slice(i, i + 37) });
  const p2 = parseSse(split);
  assert.equal(p2.output_text, p.output_text);
  assert.equal(p2.thinking[0].signature.length, p.thinking[0].signature.length);
  return p.timing;
});

/* 9. Probe URL building */
await test('buildProbeUrl', () => {
  assert.equal(buildProbeUrl('https://api.openai.com', 'responses').toString(), 'https://api.openai.com/v1/responses');
  assert.equal(buildProbeUrl('https://openrouter.ai/api/v1/', 'chat_completions').toString(), 'https://openrouter.ai/api/v1/chat/completions');
  assert.equal(buildProbeUrl('https://api.anthropic.com/v1', 'messages').toString(), 'https://api.anthropic.com/v1/messages');
  assert.equal(joinUpstream('https://x.example/v1', '/v1/responses?a=1').toString(), 'https://x.example/v1/responses?a=1');
  return 'ok';
});

/* Mock upstream: streams the gpt-6-astra fixture or the claude fixture with small delays. */
const FAKE_KEY = 'sk-tp-SELFTEST-0123456789abcdefSECRET';
const seenAuth = [];
const upstream = http.createServer(async (req, res) => {
  seenAuth.push(req.headers.authorization || req.headers['x-api-key'] || null);
  let body = '';
  for await (const c of req) body += c;
  if (body.includes('"echo-401"')) {
    res.writeHead(401, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: { message: `Incorrect API key provided: ${req.headers.authorization?.slice(7)}` } }));
    return;
  }
  const isMsg = req.url.includes('/messages');
  const raw = read(isMsg ? 'synthetic_claude_messages_signed.sse' : 'sample_gpt6_astra_responses.sse');
  const provHeaders = isMsg
    ? { 'request-id': 'req_011CSHoEeqs5C35K2UUqR7Fy', 'anthropic-ratelimit-requests-remaining': '49' }
    : { 'x-request-id': 'req_0123456789abcdef0123456789abcdef', 'openai-processing-ms': '812' };
  res.writeHead(200, { 'content-type': 'text/event-stream', ...provHeaders, server: 'mock-upstream', 'set-cookie': 'secret=1' });
  for (const f of raw.split('\n\n').filter(Boolean)) {
    res.write(f + '\n\n');
    await new Promise((r) => setTimeout(r, 15));
  }
  res.end();
});
await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
const upPort = upstream.address().port;

/* 10. Live prober against mock upstream (never returns the key) */
await test('probeEndpoint (mock upstream, key never echoed)', async () => {
  const r = await probeEndpoint({ baseUrl: `http://127.0.0.1:${upPort}`, apiKey: FAKE_KEY, endpointMode: 'responses', model: 'gpt-6-astra', timeoutMs: 10000 });
  assert.equal(r.ok, true, r.error);
  assert.equal(seenAuth.at(-1), `Bearer ${FAKE_KEY}`);
  const s = JSON.stringify(r);
  assert.ok(!s.includes(FAKE_KEY), 'API key leaked in probe result');
  assert.ok(!s.includes('secret=1'), 'set-cookie leaked');
  assert.equal(r.forensics.verdict, 'VERIFIED_NATIVE');
  assert.ok(r.forensics.timing.ttfaMs > 0);
  assert.ok(r.capture.chunkCount >= 5);
  return { verdict: r.forensics.verdict, score: r.forensics.authenticityScore, timing: { ttfbMs: r.forensics.timing.ttfbMs, ttfaMs: r.forensics.timing.ttfaMs, totalMs: r.forensics.timing.totalMs, headersMs: r.forensics.timing.headersMs }, headers: r.headers };
});

/* 10b. Error path: upstream echoes the key in a 401 body -> must be scrubbed */
await test('probeEndpoint error path scrubs echoed key', async () => {
  const r = await probeEndpoint({ baseUrl: `http://127.0.0.1:${upPort}/v1`, apiKey: FAKE_KEY, endpointMode: 'chat_completions', model: 'echo-401', timeoutMs: 5000 });
  assert.equal(r.ok, false);
  assert.equal(r.status, 401);
  assert.ok(!JSON.stringify(r).includes(FAKE_KEY), 'API key leaked in error');
  return { status: r.status, error: r.error };
});

/* 11. Tee proxy pass-through + capture (in-memory store, no DB writes) */
await test('tee proxy: pass-through + async capture, secrets stripped', async () => {
  const saved = [];
  let capture;
  const done = new Promise((resolve) => {
    capture = resolve;
  });
  const tee = createTeeProxy({ port: 0, upstreamBaseUrl: `http://127.0.0.1:${upPort}`, store: { save: async (rec, ev) => (saved.push({ rec, ev }), { forensic: true, request: true }) }, onCapture: (c) => capture(c) });
  const info = await tee.listen();
  const res = await fetch(assertLocalhostUrl(`${info.url}/v1/messages`), {
    method: 'POST',
    signal: AbortSignal.timeout(5000),
    headers: { 'content-type': 'application/json', 'x-api-key': FAKE_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: 'claude-sonnet-5-5', stream: true, max_tokens: 64, messages: [{ role: 'user', content: 'hi' }] }),
  });
  const text = await res.text();
  assert.equal(text, read('synthetic_claude_messages_signed.sse'), 'proxy altered bytes');
  assert.equal(seenAuth.at(-1), FAKE_KEY, 'key not forwarded upstream');
  const c = await done;
  await tee.close();
  const s = JSON.stringify({ c: { ...c, analysis: undefined }, saved });
  assert.ok(!s.includes(FAKE_KEY), 'API key leaked in capture');
  assert.equal(c.analysis.verdict, 'VERIFIED_NATIVE');
  assert.equal(saved[0].rec.source_tool, 'tee-proxy');
  assert.equal(saved[0].ev.model_id, 'claude-sonnet-5-5');
  assert.equal(saved[0].rec.has_signature, 1);
  return { verdict: c.analysis.verdict, ttftMs: c.record.ttft_ms, ttfaMs: c.record.ttfa_ms, totalMs: c.record.total_ms, requestEvent: { dedup_key: saved[0].ev.dedup_key, input_tokens: saved[0].ev.input_tokens, output_tokens: saved[0].ev.output_tokens } };
});

upstream.close();

const failed = results.filter((r) => !r.ok);
if (process.argv.includes('--json')) console.log(JSON.stringify({ passed: results.length - failed.length, failed: failed.length, results }, null, 2));
else {
  for (const r of results) console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.name}${r.ok ? '' : `  -> ${r.error}`}`);
  console.log(`\n${results.length - failed.length}/${results.length} passed`);
}
process.exit(failed.length ? 1 : 0);
