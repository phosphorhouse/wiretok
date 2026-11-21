// Generates synthetic forensics fixtures (deterministic). Run: node --no-warnings test/fixtures/gen-forensics-fixtures.mjs
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

const dir = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const sse = (event, obj) => `event: ${event}\ndata: ${JSON.stringify(obj)}\n\n`;
const dataOnly = (obj) => `data: ${typeof obj === 'string' ? obj : JSON.stringify(obj)}\n\n`;

// Deterministic pseudo-signature: 384 bytes of sha256 chain, base64.
let buf = Buffer.alloc(0);
let h = Buffer.from('wiretok-signature-seed');
while (buf.length < 384) {
  h = createHash('sha256').update(h).digest();
  buf = Buffer.concat([buf, h]);
}
const signature = buf.subarray(0, 384).toString('base64');

// 1) Native Anthropic /v1/messages with extended thinking + signature_delta
{
  let s = '';
  s += sse('message_start', { type: 'message_start', message: { id: 'msg_01XFDUDYJgAACzvnptvVoYEL', type: 'message', role: 'assistant', model: 'claude-sonnet-5-5', content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 412, cache_creation_input_tokens: 2048, cache_read_input_tokens: 10240, cache_creation: { ephemeral_5m_input_tokens: 2048, ephemeral_1h_input_tokens: 0 }, output_tokens: 1, service_tier: 'standard' } } });
  s += sse('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'thinking', thinking: '', signature: '' } });
  s += sse('ping', { type: 'ping' });
  for (const t of ['The user asks which model', ' I am. I should answer', ' from my system identity.']) s += sse('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'thinking_delta', thinking: t } });
  s += sse('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'signature_delta', signature } });
  s += sse('content_block_stop', { type: 'content_block_stop', index: 0 });
  s += sse('content_block_start', { type: 'content_block_start', index: 1, content_block: { type: 'text', text: '' } });
  for (const t of ['- Anthropic\n', '- Claude\n', '- Claude 3.5 Sonnet\n', '- Messages API\n', '- Knowledge cutoff: 2024-04']) s += sse('content_block_delta', { type: 'content_block_delta', index: 1, delta: { type: 'text_delta', text: t } });
  s += sse('content_block_stop', { type: 'content_block_stop', index: 1 });
  s += sse('message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 87 } });
  s += sse('message_stop', { type: 'message_stop' });
  fs.writeFileSync(path.join(dir, 'synthetic_claude_messages_signed.sse'), s);
}

// 2) Translated /v1/messages: claims claude, chatcmpl- id, thinking WITHOUT signature, OpenAI call_ ids
{
  let s = '';
  s += sse('message_start', { type: 'message_start', message: { id: 'chatcmpl-9f3c2b7e-1a2b-4c3d-8e9f-0a1b2c3d4e5f', type: 'message', role: 'assistant', model: 'claude-opus-5-5', content: [], usage: { input_tokens: 300, output_tokens: 0 } } });
  s += sse('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'thinking', thinking: '' } });
  s += sse('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'thinking_delta', thinking: 'Let me think step by step.' } });
  s += sse('content_block_stop', { type: 'content_block_stop', index: 0 });
  s += sse('content_block_start', { type: 'content_block_start', index: 1, content_block: { type: 'text', text: '' } });
  s += sse('content_block_delta', { type: 'content_block_delta', index: 1, delta: { type: 'text_delta', text: 'I am DeepSeek-V3, created by DeepSeek.' } });
  s += sse('content_block_stop', { type: 'content_block_stop', index: 1 });
  s += sse('message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 22 } });
  s += sse('message_stop', { type: 'message_stop' });
  fs.writeFileSync(path.join(dir, 'synthetic_claude_messages_translated.sse'), s);
}

// 3) Native-looking /v1/chat/completions with system_fingerprint + usage details
{
  const id = 'chatcmpl-B9MBs8CjcvOU2jLn4n570S5qMJKcT';
  const base = { id, object: 'chat.completion.chunk', created: 1795025700, model: 'gpt-6.1-sol-2026-09-30', system_fingerprint: 'fp_44709d6fcb', service_tier: 'default' };
  let s = '';
  s += dataOnly({ ...base, choices: [{ index: 0, delta: { role: 'assistant', content: '', refusal: null }, logprobs: null, finish_reason: null }], usage: null });
  for (const t of ['- OpenAI', '\n- ChatGPT', '\n- GPT-4o', '\n- Chat Completions API', '\n- Knowledge cutoff: 2023-10']) s += dataOnly({ ...base, choices: [{ index: 0, delta: { content: t }, logprobs: null, finish_reason: null }], usage: null });
  s += dataOnly({ ...base, choices: [{ index: 0, delta: {}, logprobs: null, finish_reason: 'stop' }], usage: null });
  s += dataOnly({ ...base, choices: [], usage: { prompt_tokens: 58, completion_tokens: 24, total_tokens: 82, prompt_tokens_details: { cached_tokens: 0, audio_tokens: 0 }, completion_tokens_details: { reasoning_tokens: 0, audio_tokens: 0, accepted_prediction_tokens: 0, rejected_prediction_tokens: 0 } } });
  s += dataOnly('[DONE]');
  fs.writeFileSync(path.join(dir, 'synthetic_chat_completions_fp.sse'), s);
}

// 4) Gemini alt=sse with thought parts + usageMetadata
{
  let s = '';
  s += dataOnly({ candidates: [{ content: { parts: [{ text: 'Considering identity question.', thought: true }], role: 'model' }, index: 0 }], usageMetadata: { promptTokenCount: 40, totalTokenCount: 40 }, modelVersion: 'gemini-4-hydrogen', responseId: 'mF4baPbYEsWNz7IPkPbF2Ak' });
  s += dataOnly({ candidates: [{ content: { parts: [{ text: '- Google\n- Gemini\n', thoughtSignature: signature }], role: 'model' }, index: 0 }], usageMetadata: { promptTokenCount: 40, totalTokenCount: 52 }, modelVersion: 'gemini-4-hydrogen', responseId: 'mF4baPbYEsWNz7IPkPbF2Ak' });
  s += dataOnly({ candidates: [{ content: { parts: [{ text: '- Gemini 2.5 Pro' }], role: 'model' }, finishReason: 'STOP', index: 0 }], usageMetadata: { promptTokenCount: 40, candidatesTokenCount: 18, thoughtsTokenCount: 64, cachedContentTokenCount: 0, totalTokenCount: 122, promptTokensDetails: [{ modality: 'TEXT', tokenCount: 40 }] }, modelVersion: 'gemini-4-hydrogen', responseId: 'mF4baPbYEsWNz7IPkPbF2Ak' });
  fs.writeFileSync(path.join(dir, 'synthetic_gemini_thoughts.sse'), s);
}

console.log('fixtures written to', dir);
