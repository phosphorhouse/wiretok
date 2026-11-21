/**
 * Wiretok — Multi-Protocol SSE Parser & Stream Timing
 *
 * Supports four wire protocols (plus auto-detection):
 *   - 'responses'        OpenAI Responses API (/v1/responses)
 *   - 'messages'         Anthropic Messages API (/v1/messages)
 *   - 'chat_completions' OpenAI-compatible Chat Completions (/v1/chat/completions)
 *   - 'gemini'           Google Gemini (streamGenerateContent / alt=sse, or JSON array)
 *
 * Input forms accepted by parseSse():
 *   - raw SSE string
 *   - raw JSON string (non-streaming response object, or a JSON array of stream objects)
 *   - array of chunks: strings, or { t|ts|time: <ms>, text|data|chunk: <string|Buffer|Uint8Array> }
 *
 * Timing definitions (all ms, relative to opts.t0 when given, otherwise the first chunk timestamp):
 *   ttfbMs  — first SSE frame received
 *   ttftMs  — first generated token of ANY kind (reasoning, answer text, or tool-call args)
 *   ttfrMs  — first reasoning / thinking token
 *   ttfaMs  — first visible answer token (output text)
 *   totalMs — last frame (or server completed_at - created_at when no chunk timestamps exist)
 *   tpotMs  — (totalMs - ttftMs) / (outputTokens - 1)
 *   tokPerSec — outputTokens / generation seconds
 *   meanChunkGapMs / jitterMs — mean and population std-dev of gaps between token-bearing frames
 */
import { isSafeObjectKey, maskIdentifier, normalizeModelId } from '../contracts.mjs';

export const PARSE_MODES = /** @type {const} */ (['auto', 'responses', 'messages', 'chat_completions', 'gemini']);

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]+={0,2}$/;

/* ------------------------------------------------------------------ */
/* Low-level incremental SSE frame parser (WHATWG EventSource rules)   */
/* ------------------------------------------------------------------ */

export class SseStreamParser {
  constructor() {
    this._buf = '';
    this._event = '';
    this._data = [];
    this._id = null;
    this._hasField = false;
    this._decoder = new TextDecoder('utf-8');
    /** @type {Array<{event:string,data:string,id:string|null,t:number|null,index:number}>} */
    this.frames = [];
    this.comments = 0;
    this.bytes = 0;
  }

  /**
   * Push a chunk. Returns frames completed by this chunk.
   * @param {string|Uint8Array|Buffer} chunk
   * @param {number|null} [t] timestamp (ms) at which the chunk arrived
   */
  push(chunk, t = null) {
    let text;
    if (typeof chunk === 'string') {
      text = chunk;
      this.bytes += Buffer.byteLength(chunk);
    } else if (chunk) {
      this.bytes += chunk.byteLength ?? chunk.length ?? 0;
      text = this._decoder.decode(chunk, { stream: true });
    } else {
      return [];
    }
    this._buf += text;
    const out = [];
    // Split on any line terminator, keep the trailing partial line in the buffer.
    let start = 0;
    for (let i = 0; i < this._buf.length; i++) {
      const c = this._buf.charCodeAt(i);
      if (c === 10 /* \n */ || c === 13 /* \r */) {
        // A trailing lone \r might be followed by \n in the next chunk; wait for more data.
        if (c === 13 && i === this._buf.length - 1) break;
        const line = this._buf.slice(start, i);
        if (c === 13 && this._buf.charCodeAt(i + 1) === 10) i++;
        start = i + 1;
        const f = this._line(line, t);
        if (f) out.push(f);
      }
    }
    this._buf = this._buf.slice(start);
    return out;
  }

  /** Flush the trailing (unterminated) event at end of stream. */
  end(t = null) {
    const out = [];
    const tail = this._decoder.decode();
    if (tail) this._buf += tail;
    if (this._buf.length) {
      const f = this._line(this._buf, t);
      this._buf = '';
      if (f) out.push(f);
    }
    const f = this._dispatch(t);
    if (f) out.push(f);
    return out;
  }

  _line(line, t) {
    if (line === '') return this._dispatch(t);
    if (line.charCodeAt(0) === 58 /* : */) {
      this.comments++;
      return null;
    }
    const idx = line.indexOf(':');
    let field = idx === -1 ? line : line.slice(0, idx);
    let value = idx === -1 ? '' : line.slice(idx + 1);
    if (value.charCodeAt(0) === 32) value = value.slice(1);
    field = field.trim();
    if (field === 'event') {
      this._event = value;
      this._hasField = true;
    } else if (field === 'data') {
      this._data.push(value);
      this._hasField = true;
    } else if (field === 'id') {
      this._id = value;
      this._hasField = true;
    }
    return null;
  }

  _dispatch(t) {
    if (!this._hasField) return null;
    const frame = {
      event: this._event || 'message',
      data: this._data.join('\n'),
      id: this._id,
      t: typeof t === 'number' && Number.isFinite(t) ? t : null,
      index: this.frames.length,
    };
    this._event = '';
    this._data = [];
    this._hasField = false;
    if (!frame.data && frame.event === 'message') return null;
    this.frames.push(frame);
    return frame;
  }
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function safeJson(s) {
  if (typeof s !== 'string') return s && typeof s === 'object' ? s : null;
  const v = s.trim();
  if (!v || v === '[DONE]') return null;
  try {
    return JSON.parse(v);
  } catch {
    return null;
  }
}

const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const int0 = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);

function chunkText(c) {
  if (c == null) return '';
  if (typeof c === 'string') return c;
  if (c instanceof Uint8Array) return c; // decoded by parser
  if (typeof c === 'object') return c.text ?? c.data ?? c.chunk ?? c.bytes ?? '';
  return String(c);
}

function chunkTime(c) {
  if (c && typeof c === 'object' && !(c instanceof Uint8Array)) {
    const t = c.t ?? c.ts ?? c.time ?? c.at;
    return typeof t === 'number' && Number.isFinite(t) ? t : null;
  }
  return null;
}

/**
 * Convert any accepted input into a list of frames { event, data, id, t, json }.
 */
export function framesFromInput(input) {
  if (input == null) return { frames: [], format: 'empty', bytes: 0 };

  // Already-parsed frames?
  if (Array.isArray(input) && input.length && input[0] && typeof input[0] === 'object' && 'event' in input[0] && 'data' in input[0] && !('text' in input[0])) {
    return { frames: input.map((f, i) => ({ ...f, index: i, json: f.json ?? safeJson(f.data) })), format: 'frames', bytes: 0 };
  }

  if (typeof input === 'string' || Buffer.isBuffer(input) || input instanceof Uint8Array) {
    const text = typeof input === 'string' ? input : Buffer.from(input).toString('utf8');
    const trimmed = text.trimStart();
    // Raw JSON (non-streaming body or Gemini JSON-array stream) when no SSE field lines exist.
    if ((trimmed.startsWith('{') || trimmed.startsWith('[')) && !/^(data|event):/m.test(text)) {
      const j = safeJson(trimmed);
      if (j != null) {
        const arr = Array.isArray(j) ? j : [j];
        return {
          frames: arr.map((o, i) => ({ event: o?.type || 'message', data: JSON.stringify(o), id: null, t: null, index: i, json: o })),
          format: Array.isArray(j) ? 'json_array' : 'json',
          bytes: Buffer.byteLength(text),
        };
      }
    }
    const p = new SseStreamParser();
    p.push(text, null);
    p.end(null);
    return { frames: p.frames.map((f) => ({ ...f, json: safeJson(f.data) })), format: 'sse', bytes: p.bytes };
  }

  if (Array.isArray(input)) {
    // Chunk array. Could also be an array of already-decoded JSON objects.
    if (input.length && input.every((c) => c && typeof c === 'object' && !(c instanceof Uint8Array) && !('text' in c) && !('data' in c) && !('chunk' in c))) {
      return {
        frames: input.map((o, i) => ({ event: o?.type || 'message', data: JSON.stringify(o), id: null, t: null, index: i, json: o })),
        format: 'json_objects',
        bytes: 0,
      };
    }
    const p = new SseStreamParser();
    const rawParts = [];
    for (const c of input) {
      const t = chunkTime(c);
      const tx = chunkText(c);
      p.push(tx, t);
      rawParts.push(typeof tx === 'string' ? Buffer.from(tx, 'utf8') : Buffer.from(tx));
    }
    const lastT = input.length ? chunkTime(input[input.length - 1]) : null;
    p.end(lastT);
    const jsonFallback = p.frames.length ? '' : Buffer.concat(rawParts).toString('utf8');
    if (!p.frames.length && jsonFallback.trim()) {
      const r = framesFromInput(jsonFallback);
      if (r.frames.length) {
        const t = lastT;
        r.frames.forEach((f) => (f.t = t));
        return r;
      }
    }
    return { frames: p.frames.map((f) => ({ ...f, json: safeJson(f.data) })), format: 'chunks', bytes: p.bytes };
  }

  if (typeof input === 'object') {
    return { frames: [{ event: input.type || 'message', data: JSON.stringify(input), id: null, t: null, index: 0, json: input }], format: 'json', bytes: 0 };
  }
  return { frames: [], format: 'unknown', bytes: 0 };
}

/** Detect protocol of a single frame. */
export function detectFrameMode(frame) {
  const ev = frame.event || '';
  const j = frame.json;
  const type = (j && typeof j.type === 'string' && j.type) || ev;
  if (/^response\./.test(type) || (j && j.object === 'response')) return 'responses';
  if (['message_start', 'content_block_start', 'content_block_delta', 'content_block_stop', 'message_delta', 'message_stop', 'ping'].includes(type)) return 'messages';
  if (j && j.type === 'message' && j.role === 'assistant' && Array.isArray(j.content)) return 'messages';
  if (j && (j.object === 'chat.completion.chunk' || j.object === 'chat.completion' || Array.isArray(j.choices))) return 'chat_completions';
  if (j && (Array.isArray(j.candidates) || j.usageMetadata || j.modelVersion)) return 'gemini';
  return null;
}

export function detectMode(frames) {
  const votes = { responses: 0, messages: 0, chat_completions: 0, gemini: 0 };
  for (const f of frames) {
    const m = detectFrameMode(f);
    if (m) votes[m]++;
  }
  let best = 'unknown';
  let max = 0;
  for (const [k, v] of Object.entries(votes)) if (v > max) ((best = k), (max = v));
  return { mode: best, votes };
}

function idFormat(id) {
  if (!id || typeof id !== 'string') return 'none';
  if (/^resp_[0-9a-f]{32,80}$/.test(id)) return 'openai_resp_hex';
  if (/^resp_/.test(id)) return 'resp_other';
  if (/^msg_01[0-9A-Za-z]{20,}$/.test(id)) return 'anthropic_msg';
  if (/^msg_[0-9a-f]{32,80}$/.test(id)) return 'openai_msg_hex';
  if (/^msg_/.test(id)) return 'msg_other';
  if (/^chatcmpl-[A-Za-z0-9]{20,40}$/.test(id)) return 'openai_chatcmpl';
  if (/^chatcmpl-[0-9a-f-]{36}$/i.test(id)) return 'chatcmpl_uuid';
  if (/^chatcmpl-/.test(id)) return 'chatcmpl_other';
  if (/^gen-\d+-[A-Za-z0-9]+$/.test(id)) return 'openrouter_gen';
  if (/^[0-9a-f-]{36}$/i.test(id)) return 'uuid';
  if (/^[A-Za-z0-9_-]{16,40}$/.test(id)) return 'opaque';
  return 'other';
}

export function validateSignature(sig) {
  if (!sig || typeof sig !== 'string') return { present: false, length: 0, base64: false, decodedBytes: 0, plausible: false };
  const s = sig.trim();
  const b64 = BASE64_RE.test(s) && s.length % 4 === 0;
  const b64url = !b64 && BASE64URL_RE.test(s);
  let decodedBytes = 0;
  if (b64 || b64url) {
    try {
      decodedBytes = Buffer.from(s, b64 ? 'base64' : 'base64url').length;
    } catch {
      decodedBytes = 0;
    }
  }
  return {
    present: true,
    length: s.length,
    base64: b64 || b64url,
    encoding: b64 ? 'base64' : b64url ? 'base64url' : 'invalid',
    decodedBytes,
    // Native Anthropic thinking signatures are long opaque cryptograms (hundreds of bytes).
    plausible: (b64 || b64url) && decodedBytes >= 64,
  };
}

function longestCommonPrefix(a, b) {
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  return i;
}

/* ------------------------------------------------------------------ */
/* Protocol accumulators                                               */
/* ------------------------------------------------------------------ */

function newState(mode, opts) {
  return {
    mode,
    id: null,
    ids: new Set(),
    model: null,
    models: new Set(),
    createdAt: null,
    completedAt: null,
    status: null,
    stopReason: null,
    serviceTier: null,
    serviceTierHistory: [],
    promptCacheKey: null,
    promptCacheRetention: null,
    reasoning: null,
    temperature: null,
    topP: null,
    safetyIdentifier: null,
    systemFingerprint: null,
    systemFingerprints: new Set(),
    instructionsChars: null,
    usage: null,
    toolUsage: null,
    outputText: '',
    outputTextFromDone: '',
    reasoningText: '',
    reasoningSummaryParts: 0,
    outputItems: [],
    thinkingBlocks: [],
    redactedThinking: 0,
    toolCalls: [],
    contentBlockTypes: [],
    sequenceNumbers: [],
    eventTypes: {},
    errors: [],
    done: false,
    times: { first: null, last: null, firstToken: null, firstReasoning: null, firstAnswer: null, tokenFrames: [] },
    privacy: opts.privacy !== false,
    extra: {},
  };
}

function markToken(st, t, kind) {
  if (t == null) return;
  const tm = st.times;
  if (tm.firstToken == null) tm.firstToken = t;
  if (kind === 'reasoning' && tm.firstReasoning == null) tm.firstReasoning = t;
  if (kind === 'answer' && tm.firstAnswer == null) tm.firstAnswer = t;
  tm.tokenFrames.push(t);
}

function setModel(st, m) {
  if (m && typeof m === 'string') {
    st.model = m;
    st.models.add(m);
  }
}
function setId(st, id) {
  if (id && typeof id === 'string') {
    if (!st.id) st.id = id;
    st.ids.add(id);
  }
}

/* ---------- OpenAI Responses ---------- */
function absorbResponseObject(st, r) {
  if (!r || typeof r !== 'object') return;
  setId(st, r.id);
  setModel(st, r.model);
  if (num(r.created_at) != null) st.createdAt = r.created_at;
  if (num(r.completed_at) != null) st.completedAt = r.completed_at;
  if (r.status) st.status = r.status;
  if (r.service_tier) {
    st.serviceTier = r.service_tier;
    if (st.serviceTierHistory[st.serviceTierHistory.length - 1] !== r.service_tier) st.serviceTierHistory.push(r.service_tier);
  }
  if (r.prompt_cache_key != null) st.promptCacheKey = r.prompt_cache_key;
  if (r.prompt_cache_retention != null) st.promptCacheRetention = r.prompt_cache_retention;
  if (r.reasoning && typeof r.reasoning === 'object') st.reasoning = { ...r.reasoning };
  if (num(r.temperature) != null) st.temperature = r.temperature;
  if (num(r.top_p) != null) st.topP = r.top_p;
  if (r.safety_identifier) st.safetyIdentifier = r.safety_identifier;
  if (typeof r.instructions === 'string') st.instructionsChars = r.instructions.length;
  if (r.usage && typeof r.usage === 'object') st.usage = r.usage;
  if (r.tool_usage && typeof r.tool_usage === 'object') st.toolUsage = r.tool_usage;
  if (r.error) st.errors.push(r.error);
  for (const k of ['background', 'store', 'truncation', 'parallel_tool_calls', 'tool_choice', 'max_output_tokens', 'previous_response_id', 'text', 'input_transformations']) {
    if (k in r) st.extra[k] = r[k];
  }
  if (Array.isArray(r.output) && r.output.length) {
    for (const item of r.output) absorbOutputItem(st, item, true);
  }
}

function absorbOutputItem(st, item, fromFinal = false) {
  if (!item || typeof item !== 'object') return;
  let rec = st.outputItems.find((x) => x.id && x.id === item.id);
  if (!rec) {
    rec = { id: item.id || null, type: item.type, role: item.role || null, phase: item.phase || null, status: item.status || null, text: '' };
    st.outputItems.push(rec);
  }
  rec.status = item.status || rec.status;
  if (item.type === 'message' && Array.isArray(item.content)) {
    const txt = item.content.filter((c) => c && (c.type === 'output_text' || c.type === 'text')).map((c) => c.text || '').join('');
    if (txt) rec.text = txt;
  } else if (item.type === 'reasoning') {
    rec.encryptedContent = typeof item.encrypted_content === 'string' ? item.encrypted_content.length : 0;
    const sum = Array.isArray(item.summary) ? item.summary.map((s) => s.text || '').join('\n') : '';
    if (sum) rec.text = sum;
  } else if (item.type === 'function_call' || item.type === 'custom_tool_call') {
    rec.name = item.name;
    rec.callId = item.call_id;
    if (!st.toolCalls.some((t) => t.id === (item.call_id || item.id))) st.toolCalls.push({ id: item.call_id || item.id, name: item.name, argsChars: (item.arguments || item.input || '').length });
  } else if (/_call$/.test(item.type || '')) {
    rec.name = item.type;
  }
  if (fromFinal) rec.final = true;
}

function stepResponses(st, f) {
  const j = f.json;
  if (!j) return;
  const type = j.type || f.event;
  if (num(j.sequence_number) != null) st.sequenceNumbers.push(j.sequence_number);
  switch (type) {
    case 'response.created':
    case 'response.in_progress':
    case 'response.completed':
    case 'response.failed':
    case 'response.incomplete':
    case 'response.queued':
      absorbResponseObject(st, j.response);
      if (type !== 'response.created' && type !== 'response.in_progress' && type !== 'response.queued') st.done = true;
      break;
    case 'response.output_item.added':
    case 'response.output_item.done':
      absorbOutputItem(st, j.item);
      if (type === 'response.output_item.done' && j.item?.type === 'message') {
        const rec = st.outputItems.find((x) => x.id === j.item.id);
        if (rec?.text && !st.times.firstAnswer) markToken(st, f.t, 'answer');
      }
      break;
    case 'response.output_text.delta':
      st.outputText += j.delta || '';
      markToken(st, f.t, 'answer');
      break;
    case 'response.refusal.delta':
      st.outputText += j.delta || '';
      markToken(st, f.t, 'answer');
      break;
    case 'response.reasoning_summary_text.delta':
    case 'response.reasoning_text.delta':
    case 'response.reasoning.delta':
      st.reasoningText += j.delta || '';
      markToken(st, f.t, 'reasoning');
      break;
    case 'response.reasoning_summary_part.added':
      st.reasoningSummaryParts++;
      break;
    case 'response.function_call_arguments.delta':
    case 'response.custom_tool_call_input.delta':
      markToken(st, f.t, 'tool');
      break;
    case 'error':
    case 'response.error':
      st.errors.push(j.error || j);
      break;
    default:
      break;
  }
  if (type === 'response.output_text.done' && typeof j.text === 'string' && !st.outputText) st.outputTextFromDone = j.text;
}

/* ---------- Anthropic Messages ---------- */
function stepMessages(st, f) {
  const j = f.json;
  if (!j) return;
  const type = j.type || f.event;
  switch (type) {
    case 'message_start': {
      const m = j.message || {};
      setId(st, m.id);
      setModel(st, m.model);
      if (m.usage) st.usage = { ...m.usage, ...(m.usage.cache_creation ? { cache_creation: { ...m.usage.cache_creation } } : {}) };
      if (m.usage?.service_tier) st.serviceTier = m.usage.service_tier;
      if (m.container) st.extra.container = m.container;
      st.extra.messageStart = true;
      break;
    }
    case 'content_block_start': {
      const b = j.content_block || {};
      st.contentBlockTypes.push(b.type);
      if (b.type === 'thinking') {
        st.thinkingBlocks[j.index] = { index: j.index, type: 'thinking', text: b.thinking || '', signature: b.signature || '' };
      } else if (b.type === 'redacted_thinking') {
        st.redactedThinking++;
        st.thinkingBlocks[j.index] = { index: j.index, type: 'redacted_thinking', text: '', signature: '', dataChars: (b.data || '').length };
      } else if (b.type === 'tool_use' || b.type === 'server_tool_use') {
        st.toolCalls.push({ index: j.index, id: b.id, name: b.name, type: b.type, argsChars: 0 });
      } else if (b.type === 'text' && b.text) {
        st.outputText += b.text;
        markToken(st, f.t, 'answer');
      }
      break;
    }
    case 'content_block_delta': {
      const d = j.delta || {};
      if (d.type === 'thinking_delta') {
        const blk = st.thinkingBlocks[j.index] || (st.thinkingBlocks[j.index] = { index: j.index, type: 'thinking', text: '', signature: '' });
        blk.text += d.thinking || '';
        st.reasoningText += d.thinking || '';
        markToken(st, f.t, 'reasoning');
      } else if (d.type === 'signature_delta') {
        const blk = st.thinkingBlocks[j.index] || (st.thinkingBlocks[j.index] = { index: j.index, type: 'thinking', text: '', signature: '' });
        blk.signature += d.signature || '';
      } else if (d.type === 'text_delta') {
        st.outputText += d.text || '';
        markToken(st, f.t, 'answer');
      } else if (d.type === 'input_json_delta') {
        const tc = st.toolCalls.find((x) => x.index === j.index);
        if (tc) tc.argsChars += (d.partial_json || '').length;
        markToken(st, f.t, 'tool');
      } else if (d.type === 'citations_delta') {
        st.extra.citations = (st.extra.citations || 0) + 1;
      }
      break;
    }
    case 'message_delta': {
      if (j.delta?.stop_reason) st.stopReason = j.delta.stop_reason;
      if (j.usage) {
        const u = Object.assign(Object.create(null), st.usage || {});
        for (const [k, v] of Object.entries(j.usage)) {
          if (!isSafeObjectKey(k) || k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
          if (v == null) continue;
          if (k === 'cache_creation' && typeof v === 'object') {
            const cc = Object.assign(Object.create(null), u.cache_creation || {});
            for (const [ck, cv] of Object.entries(v)) {
              if (!isSafeObjectKey(ck) || ck === '__proto__' || ck === 'constructor' || ck === 'prototype') continue;
              cc[ck] = cv;
            }
            u.cache_creation = cc;
          } else {
            u[k] = v;
          }
        }
        st.usage = u;
      }
      break;
    }
    case 'message_stop':
      st.done = true;
      st.status = st.status || 'completed';
      break;
    case 'error':
      st.errors.push(j.error || j);
      break;
    case 'message': // non-streaming body
      setId(st, j.id);
      setModel(st, j.model);
      st.stopReason = j.stop_reason || null;
      if (j.usage) st.usage = j.usage;
      for (const [i, b] of (j.content || []).entries()) {
        st.contentBlockTypes.push(b.type);
        if (b.type === 'text') st.outputText += b.text || '';
        else if (b.type === 'thinking') {
          st.thinkingBlocks[i] = { index: i, type: 'thinking', text: b.thinking || '', signature: b.signature || '' };
          st.reasoningText += b.thinking || '';
        } else if (b.type === 'redacted_thinking') {
          st.redactedThinking++;
          st.thinkingBlocks[i] = { index: i, type: 'redacted_thinking', text: '', signature: '', dataChars: (b.data || '').length };
        } else if (b.type === 'tool_use') st.toolCalls.push({ index: i, id: b.id, name: b.name, type: b.type, argsChars: JSON.stringify(b.input || {}).length });
      }
      st.done = true;
      break;
    default:
      break;
  }
}

/* ---------- OpenAI-compatible Chat Completions ---------- */
function stepChat(st, f) {
  const j = f.json;
  if (!j) {
    if ((f.data || '').trim() === '[DONE]') st.done = true;
    return;
  }
  if (j.error) st.errors.push(j.error);
  setId(st, j.id);
  setModel(st, j.model);
  if (num(j.created) != null && st.createdAt == null) st.createdAt = j.created;
  if (j.system_fingerprint) {
    st.systemFingerprint = j.system_fingerprint;
    st.systemFingerprints.add(j.system_fingerprint);
  }
  if (j.service_tier) st.serviceTier = j.service_tier;
  if (j.provider) st.extra.provider = j.provider; // OpenRouter-style
  if (j.object) st.extra.object = j.object;
  for (const ch of j.choices || []) {
    const d = ch.delta || ch.message || {};
    const reasoning = d.reasoning_content ?? d.reasoning ?? null;
    if (typeof reasoning === 'string' && reasoning) {
      st.reasoningText += reasoning;
      st.extra.reasoningField = d.reasoning_content != null ? 'reasoning_content' : 'reasoning';
      markToken(st, f.t, 'reasoning');
    }
    if (typeof d.content === 'string' && d.content) {
      st.outputText += d.content;
      markToken(st, f.t, 'answer');
    }
    if (Array.isArray(d.tool_calls)) {
      for (const tc of d.tool_calls) {
        let rec = st.toolCalls.find((x) => x.index === tc.index);
        if (!rec) st.toolCalls.push((rec = { index: tc.index, id: tc.id || null, name: tc.function?.name || null, argsChars: 0 }));
        if (tc.id) rec.id = tc.id;
        if (tc.function?.name) rec.name = tc.function.name;
        rec.argsChars += (tc.function?.arguments || '').length;
      }
      markToken(st, f.t, 'tool');
    }
    if (ch.finish_reason) st.stopReason = ch.finish_reason;
  }
  if (j.usage && typeof j.usage === 'object') st.usage = j.usage;
  if (j.object === 'chat.completion') st.done = true;
}

/* ---------- Google Gemini ---------- */
function stepGemini(st, f) {
  const j = f.json;
  if (!j) return;
  if (j.error) st.errors.push(j.error);
  if (j.responseId) setId(st, j.responseId);
  if (j.modelVersion) setModel(st, j.modelVersion);
  if (j.createTime) st.extra.createTime = j.createTime;
  const c = (j.candidates || [])[0];
  if (c) {
    for (const p of c.content?.parts || []) {
      if (p.thought === true) {
        if (p.text) {
          st.reasoningText += p.text;
          markToken(st, f.t, 'reasoning');
        }
      } else if (typeof p.text === 'string' && p.text) {
        st.outputText += p.text;
        markToken(st, f.t, 'answer');
      }
      if (p.thoughtSignature) {
        st.thinkingBlocks.push({ index: st.thinkingBlocks.length, type: 'thought_signature', text: '', signature: p.thoughtSignature });
      }
      if (p.functionCall) {
        st.toolCalls.push({ id: p.functionCall.id || null, name: p.functionCall.name, argsChars: JSON.stringify(p.functionCall.args || {}).length });
        markToken(st, f.t, 'tool');
      }
    }
    if (c.finishReason) {
      st.stopReason = c.finishReason;
      st.done = true;
    }
  }
  if (j.usageMetadata) st.usage = { ...(st.usage || {}), ...j.usageMetadata };
}

/* ------------------------------------------------------------------ */
/* Normalization                                                       */
/* ------------------------------------------------------------------ */

/** Normalize provider usage into one snake_case token shape aligned with the `requests` table. */
export function normalizeUsage(mode, u) {
  const out = {
    input_tokens: 0,
    output_tokens: 0,
    total_tokens: 0,
    cache_read_tokens: 0,
    cache_write_tokens: 0,
    cache_write_5m_tokens: 0,
    cache_write_1h_tokens: 0,
    cache_write_30m_tokens: 0,
    cache_write_12h_tokens: 0,
    reasoning_tokens: 0,
    uncached_input_tokens: 0,
  };
  if (!u || typeof u !== 'object') return out;
  if (mode === 'responses') {
    out.input_tokens = int0(u.input_tokens);
    out.output_tokens = int0(u.output_tokens);
    out.total_tokens = int0(u.total_tokens) || out.input_tokens + out.output_tokens;
    const d = u.input_tokens_details || {};
    out.cache_read_tokens = int0(d.cached_tokens);
    out.cache_write_tokens = int0(d.cache_write_tokens);
    out.cache_write_30m_tokens = int0(d.cache_write_tokens_details?.ttl_30m_tokens);
    out.cache_write_12h_tokens = int0(d.cache_write_tokens_details?.ttl_12h_tokens);
    out.reasoning_tokens = int0(u.output_tokens_details?.reasoning_tokens);
    out.uncached_input_tokens = Math.max(0, out.input_tokens - out.cache_read_tokens - out.cache_write_tokens);
  } else if (mode === 'messages') {
    // Anthropic: input_tokens EXCLUDES cache reads/writes.
    const base = int0(u.input_tokens);
    out.cache_read_tokens = int0(u.cache_read_input_tokens);
    out.cache_write_5m_tokens = int0(u.cache_creation?.ephemeral_5m_input_tokens);
    out.cache_write_1h_tokens = int0(u.cache_creation?.ephemeral_1h_input_tokens);
    out.cache_write_tokens = int0(u.cache_creation_input_tokens) || out.cache_write_5m_tokens + out.cache_write_1h_tokens;
    out.uncached_input_tokens = base;
    out.input_tokens = base + out.cache_read_tokens + out.cache_write_tokens;
    out.output_tokens = int0(u.output_tokens);
    out.total_tokens = out.input_tokens + out.output_tokens;
  } else if (mode === 'chat_completions') {
    out.input_tokens = int0(u.prompt_tokens);
    out.output_tokens = int0(u.completion_tokens);
    out.total_tokens = int0(u.total_tokens) || out.input_tokens + out.output_tokens;
    out.cache_read_tokens = int0(u.prompt_tokens_details?.cached_tokens) || int0(u.prompt_cache_hit_tokens);
    out.cache_write_tokens = int0(u.prompt_tokens_details?.cache_write_tokens) || int0(u.cache_creation_input_tokens);
    out.reasoning_tokens = int0(u.completion_tokens_details?.reasoning_tokens);
    out.uncached_input_tokens = Math.max(0, out.input_tokens - out.cache_read_tokens - out.cache_write_tokens);
  } else if (mode === 'gemini') {
    out.input_tokens = int0(u.promptTokenCount);
    out.reasoning_tokens = int0(u.thoughtsTokenCount);
    out.output_tokens = int0(u.candidatesTokenCount) + out.reasoning_tokens;
    out.cache_read_tokens = int0(u.cachedContentTokenCount);
    out.total_tokens = int0(u.totalTokenCount) || out.input_tokens + out.output_tokens + int0(u.toolUsePromptTokenCount);
    out.uncached_input_tokens = Math.max(0, out.input_tokens - out.cache_read_tokens);
  }
  return out;
}

/** Summarize OpenAI `usage.attribution` (per-item + request_fields token attribution). */
export function summarizeAttribution(usage, outputItems = []) {
  const a = usage && usage.attribution;
  if (!a || typeof a !== 'object') return null;
  const items = a.items && typeof a.items === 'object' ? a.items : {};
  const fields = a.request_fields && typeof a.request_fields === 'object' ? a.request_fields : {};
  const outputIds = new Set(outputItems.filter((o) => o.id).map((o) => o.id));
  const itemRows = Object.entries(items).map(([id, v]) => ({
    id,
    role: outputIds.has(id) ? 'output' : 'input',
    input_tokens: int0(v?.input_tokens),
    cached_tokens: int0(v?.cached_tokens),
    cache_write_tokens: int0(v?.cache_write_tokens),
    output_tokens: int0(v?.output_tokens),
    content_parts: Array.isArray(v?.content) ? v.content.length : 0,
  }));
  const fieldRows = Object.entries(fields).map(([name, v]) => ({
    field: name,
    input_tokens: int0(v?.input_tokens),
    cached_tokens: int0(v?.cached_tokens),
    cache_write_tokens: int0(v?.cache_write_tokens),
    output_tokens: int0(v?.output_tokens),
  }));
  const sum = (rows, k) => rows.reduce((s, r) => s + r[k], 0);
  const itemsInput = sum(itemRows, 'input_tokens');
  const fieldsInput = sum(fieldRows, 'input_tokens');
  const attributedInput = itemsInput + fieldsInput;
  const attributedOutput = sum(itemRows, 'output_tokens') + sum(fieldRows, 'output_tokens');
  const attributedCached = sum(itemRows, 'cached_tokens') + sum(fieldRows, 'cached_tokens');
  const reportedInput = int0(usage.input_tokens);
  const reportedOutput = int0(usage.output_tokens);
  return {
    items: itemRows,
    request_fields: fieldRows,
    instructions_input_tokens: int0(fields.instructions?.input_tokens),
    items_input_tokens: itemsInput,
    request_fields_input_tokens: fieldsInput,
    attributed_input_tokens: attributedInput,
    attributed_output_tokens: attributedOutput,
    attributed_cached_tokens: attributedCached,
    reported_input_tokens: reportedInput,
    reported_output_tokens: reportedOutput,
    unattributed_input_tokens: reportedInput - attributedInput,
    input_reconciles: attributedInput === reportedInput,
    output_reconciles: attributedOutput === reportedOutput,
  };
}

function computeTiming(st, opts, outputTokens) {
  const tm = st.times;
  const timing = {
    source: 'none',
    ttfbMs: null,
    ttftMs: null,
    ttfrMs: null,
    ttfaMs: null,
    totalMs: null,
    generationMs: null,
    tpotMs: null,
    tokPerSec: null,
    chunkCount: st.frameCount,
    tokenFrameCount: tm.tokenFrames.length,
    meanChunkGapMs: null,
    jitterMs: null,
    maxChunkGapMs: null,
    serverCreatedAt: st.createdAt,
    serverCompletedAt: st.completedAt,
  };
  const r = (v) => (v == null || !Number.isFinite(v) ? null : Math.round(v * 100) / 100);
  if (tm.first != null) {
    const t0 = typeof opts.t0 === 'number' ? opts.t0 : tm.first;
    timing.source = 'chunk_timestamps';
    timing.ttfbMs = r(tm.first - t0);
    timing.ttftMs = tm.firstToken != null ? r(tm.firstToken - t0) : null;
    timing.ttfrMs = tm.firstReasoning != null ? r(tm.firstReasoning - t0) : null;
    timing.ttfaMs = tm.firstAnswer != null ? r(tm.firstAnswer - t0) : null;
    const end = typeof opts.tEnd === 'number' ? Math.max(opts.tEnd, tm.last) : tm.last;
    timing.totalMs = r(end - t0);
    const gaps = [];
    for (let i = 1; i < tm.tokenFrames.length; i++) gaps.push(tm.tokenFrames[i] - tm.tokenFrames[i - 1]);
    if (gaps.length) {
      const mean = gaps.reduce((s, g) => s + g, 0) / gaps.length;
      const variance = gaps.reduce((s, g) => s + (g - mean) ** 2, 0) / gaps.length;
      timing.meanChunkGapMs = r(mean);
      timing.jitterMs = r(Math.sqrt(variance));
      timing.maxChunkGapMs = r(Math.max(...gaps));
    }
    if (timing.ttftMs != null) {
      timing.generationMs = r(timing.totalMs - timing.ttftMs);
      if (outputTokens > 1 && timing.generationMs > 0) timing.tpotMs = r(timing.generationMs / (outputTokens - 1));
      if (outputTokens > 0 && timing.generationMs > 0) timing.tokPerSec = r(outputTokens / (timing.generationMs / 1000));
    }
    if (timing.tokPerSec == null && outputTokens > 0 && timing.totalMs > 0) timing.tokPerSec = r(outputTokens / (timing.totalMs / 1000));
  }
  if (timing.totalMs == null && num(st.createdAt) != null && num(st.completedAt) != null) {
    // Server-side unix-second timestamps (OpenAI Responses created_at / completed_at): coarse 1 s resolution.
    timing.source = 'server_timestamps';
    timing.totalMs = Math.max(0, (st.completedAt - st.createdAt) * 1000);
    timing.resolutionMs = 1000;
    if (outputTokens > 0 && timing.totalMs > 0) {
      timing.tokPerSec = r(outputTokens / (timing.totalMs / 1000));
      if (outputTokens > 1) timing.tpotMs = r(timing.totalMs / outputTokens);
    }
  }
  return timing;
}

function sequenceAnalysis(seqs) {
  if (!seqs.length) return null;
  const gaps = [];
  let monotonic = true;
  let duplicates = 0;
  for (let i = 1; i < seqs.length; i++) {
    const d = seqs[i] - seqs[i - 1];
    if (d <= 0) {
      monotonic = false;
      if (d === 0) duplicates++;
    } else if (d > 1) gaps.push({ after: seqs[i - 1], before: seqs[i], missing: d - 1 });
  }
  return {
    first: seqs[0],
    last: seqs[seqs.length - 1],
    count: seqs.length,
    monotonic,
    startsAtZero: seqs[0] === 0,
    duplicates,
    gaps,
    missingTotal: gaps.reduce((s, g) => s + g.missing, 0),
  };
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

/**
 * Parse an SSE capture into a protocol-normalized forensic record.
 * @param {string|Array|object|Buffer} input
 * @param {{mode?: 'auto'|'responses'|'messages'|'chat_completions'|'gemini', privacy?: boolean, t0?: number, tEnd?: number, keepFrames?: boolean}} [opts]
 */
export function parseSse(input, opts = {}) {
  const { frames, format, bytes } = framesFromInput(input);
  const requested = opts.mode && opts.mode !== 'auto' ? opts.mode : null;
  const detection = detectMode(frames);
  const mode = requested || detection.mode;
  const st = newState(mode, opts);
  st.frameCount = frames.length;
  let doneMarker = false;
  for (const f of frames) {
    const type = (f.json && f.json.type) || f.event || 'message';
    st.eventTypes[type] = (st.eventTypes[type] || 0) + 1;
    if (f.t != null) {
      if (st.times.first == null) st.times.first = f.t;
      st.times.last = f.t;
    }
    if ((f.data || '').trim() === '[DONE]') {
      doneMarker = true;
      continue;
    }
    if (mode === 'responses') stepResponses(st, f);
    else if (mode === 'messages') stepMessages(st, f);
    else if (mode === 'chat_completions') stepChat(st, f);
    else if (mode === 'gemini') stepGemini(st, f);
  }

  // Final assistant text: streamed deltas first, then output_item.done / response.completed output.
  let outputText = st.outputText;
  if (!outputText && st.outputTextFromDone) outputText = st.outputTextFromDone;
  if (!outputText && st.outputItems.length) {
    outputText = st.outputItems.filter((o) => o.type === 'message' && (o.role === 'assistant' || !o.role)).map((o) => o.text || '').join('');
  }
  if (!st.reasoningText && st.outputItems.length) {
    st.reasoningText = st.outputItems.filter((o) => o.type === 'reasoning').map((o) => o.text || '').join('\n');
  }

  const tokens = normalizeUsage(mode, st.usage);
  const attribution = mode === 'responses' ? summarizeAttribution(st.usage, st.outputItems) : null;
  const timing = computeTiming(st, opts, tokens.output_tokens);

  const thinking = st.thinkingBlocks.filter(Boolean).map((b) => ({
    index: b.index,
    type: b.type,
    textChars: (b.text || '').length,
    signature: validateSignature(b.signature),
    ...(b.dataChars != null ? { dataChars: b.dataChars } : {}),
  }));

  // ID lineage: native OpenAI Responses item IDs share a long hex prefix with the response ID.
  let idLineage = null;
  if (st.id && /^resp_[0-9a-f]+$/.test(st.id)) {
    const respHex = st.id.slice(5);
    const relatedIds = [
      ...st.outputItems.map((o) => o.id),
      ...(attribution ? attribution.items.map((i) => i.id) : []),
    ].filter((x) => typeof x === 'string' && /^[a-z]+_[0-9a-f]+$/.test(x));
    const uniq = [...new Set(relatedIds)];
    const prefixes = uniq.map((x) => longestCommonPrefix(respHex, x.slice(x.indexOf('_') + 1)));
    idLineage = {
      respHexLength: respHex.length,
      relatedIds: uniq.length,
      minSharedPrefix: prefixes.length ? Math.min(...prefixes) : 0,
      maxSharedPrefix: prefixes.length ? Math.max(...prefixes) : 0,
    };
  }

  const safety = st.safetyIdentifier ? (st.privacy ? maskIdentifier(st.safetyIdentifier) : st.safetyIdentifier) : null;

  const result = {
    mode,
    requestedMode: opts.mode || 'auto',
    detectedMode: detection.mode,
    modeVotes: detection.votes,
    inputFormat: format,
    bytes,
    frameCount: frames.length,
    eventTypes: st.eventTypes,
    complete: st.done || doneMarker,
    doneMarker,
    id: st.id,
    idFormat: idFormat(st.id),
    distinctIds: [...st.ids],
    model: st.model,
    modelNormalized: st.model ? normalizeModelId(st.model) : null,
    distinctModels: [...st.models],
    created_at: st.createdAt,
    completed_at: st.completedAt,
    status: st.status,
    stop_reason: st.stopReason,
    service_tier: st.serviceTier,
    service_tier_history: st.serviceTierHistory,
    prompt_cache_key: st.promptCacheKey,
    prompt_cache_retention: st.promptCacheRetention,
    reasoning: st.reasoning,
    temperature: st.temperature,
    top_p: st.topP,
    safety_identifier: safety,
    safety_identifier_masked: !!(st.safetyIdentifier && st.privacy),
    system_fingerprint: st.systemFingerprint,
    distinct_system_fingerprints: [...st.systemFingerprints],
    instructions_chars: st.instructionsChars,
    usage: st.usage,
    tokens,
    attribution,
    tool_usage: st.toolUsage,
    output_text: outputText,
    reasoning_text_chars: st.reasoningText.length,
    reasoning_summary_parts: st.reasoningSummaryParts,
    output_items: st.outputItems.map(({ text, ...rest }) => ({ ...rest, textChars: (text || '').length })),
    thinking,
    redacted_thinking_blocks: st.redactedThinking,
    content_block_types: st.contentBlockTypes,
    tool_calls: st.toolCalls,
    sequence: sequenceAnalysis(st.sequenceNumbers),
    id_lineage: idLineage,
    timing,
    errors: st.errors,
    extra: st.extra,
  };
  if (opts.keepFrames) result.frames = frames.map(({ event, data, t }) => ({ event, data, t }));
  if (opts.includeReasoningText) result.reasoning_text = st.reasoningText;
  return result;
}

export default parseSse;
