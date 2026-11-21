/**
 * Wiretok — Optional Local Tee Proxy (default http://127.0.0.1:19841)
 *
 * Transparent pass-through: client -> tee -> upstream. Request headers/body are forwarded as-is
 * (only hop-by-hop headers are dropped and accept-encoding is forced to identity so SSE stays
 * parseable). Upstream bytes are written to the client the moment they arrive (no buffering),
 * while a side-channel copy is timestamped with performance.now() and parsed AFTER the response
 * ends (setImmediate) into analyzeForensics() -> `sse_forensics` + `requests`.
 *
 * SECURITY: authorization / x-api-key / api-key / x-goog-api-key / cookie headers are forwarded
 * upstream but NEVER stored, logged, or passed to onCapture.
 */
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { randomUUID } from 'node:crypto';
import { DEFAULT_TEE_PORT, FORENSICS_LOG, isSafeObjectKey } from '../contracts.mjs';
import { assertSafeUpstreamUrl } from './active-prober.mjs';
import { analyzeForensics, toForensicRecord, toRequestEvent } from './fingerprint-engine.mjs';

const COOKIE_HDR = ['set', 'cookie'].join('-');
const HOP_BY_HOP = new Set(['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'te', 'trailer', 'upgrade', 'proxy-authorization', 'proxy-authenticate', 'host', 'content-length']);
const SECRET_HEADERS = new Set(['authorization', 'proxy-authorization', 'x-api-key', 'api-key', 'x-goog-api-key', 'cookie', COOKIE_HDR, 'openai-organization', 'openai-project', 'anthropic-organization-id']);
const MAX_CAPTURE_BYTES = 16 * 1024 * 1024;
const MAX_REQ_CAPTURE_BYTES = 2 * 1024 * 1024;

function debugLog(context, err) {
  if (process.env.WIRETOK_DEBUG) {
    console.error(`[wiretok:tee-proxy:${context}]`, err?.message || err);
  }
}

export function sanitizeHeaders(headers) {
  const out = Object.create(null);
  for (const [k, v] of Object.entries(headers || {})) {
    if (!isSafeObjectKey(k) || k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    const key = k.toLowerCase();
    if (!isSafeObjectKey(key) || SECRET_HEADERS.has(key)) continue;
    out[key] = Array.isArray(v) ? v.join(', ') : String(v);
  }
  return out;
}

export function endpointModeFromPath(p) {
  const s = String(p || '').split('?')[0];
  if (/\/responses(\/|$)/.test(s)) return 'responses';
  if (/\/messages(\/|$)/.test(s) && !/\/threads\//.test(s)) return 'messages';
  if (/\/chat\/completions(\/|$)/.test(s)) return 'chat_completions';
  if (/:(stream)?generateContent/i.test(s)) return 'gemini';
  return 'unknown';
}

/** Join upstream base + incoming path without duplicating a shared version segment (/v1 + /v1/x). */
export function joinUpstream(upstreamBaseUrl, reqUrl) {
  const base = new URL(upstreamBaseUrl);
  const incoming = new URL(reqUrl, 'http://tee.local');
  let basePath = base.pathname.replace(/\/+$/, '');
  let reqPath = incoming.pathname;
  const lastSeg = basePath.split('/').pop();
  if (lastSeg && reqPath.startsWith(`/${lastSeg}/`)) reqPath = reqPath.slice(lastSeg.length + 1);
  const out = new URL(base.origin);
  out.pathname = basePath + reqPath;
  // Keep base query params, then incoming ones.
  base.searchParams.forEach((v, k) => out.searchParams.set(k, v));
  incoming.searchParams.forEach((v, k) => out.searchParams.set(k, v));
  return out;
}

function redactUrl(u) {
  const c = new URL(u.toString());
  for (const k of [...c.searchParams.keys()]) if (/key|token|secret|sig/i.test(k)) c.searchParams.set(k, '***');
  c.username = '';
  c.password = '';
  return c.toString();
}

/** Default persistence: append JSONL to FORENSICS_LOG + best-effort DB insert via src/db facade. */
export function createDefaultStore({ logPath = FORENSICS_LOG, useDb = true } = {}) {
  let dbApi = null;
  let dbHandle = null;
  let dbTried = false;
  async function ensureDb() {
    if (dbTried || !useDb) return dbApi;
    dbTried = true;
    try {
      const mod = await import('../db/index.mjs');
      const open = mod.openDb || mod.openDatabase || mod.getDb || mod.initDb;
      if (typeof open === 'function') {
        dbHandle = await open();
        dbApi = mod;
      }
    } catch (err) {
      debugLog('ensureDb', err);
      dbApi = null;
    }
    return dbApi;
  }
  return {
    async save(record, requestEvent) {
      try {
        await fs.promises.mkdir(path.dirname(logPath), { recursive: true });
        const { analysis_json, ...slim } = record;
        await fs.promises.appendFile(logPath, JSON.stringify({ ...slim, request_event: { dedup_key: requestEvent?.dedup_key } }) + '\n');
      } catch (err) {
        debugLog('saveLog', err);
      }
      const api = await ensureDb();
      const out = { forensic: false, request: false };
      if (api && dbHandle) {
        try {
          if (typeof api.saveForensicCapture === 'function') {
            await api.saveForensicCapture(dbHandle, record);
            out.forensic = true;
          }
        } catch (e) {
          out.forensicError = e.message;
        }
        try {
          if (requestEvent && typeof api.insertRequestBatch === 'function') {
            await api.insertRequestBatch(dbHandle, [requestEvent]);
            out.request = true;
          }
        } catch (e) {
          out.requestError = e.message;
        }
      }
      return out;
    },
    close() {
      try {
        if (dbApi && dbHandle) (dbApi.closeDatabase || dbApi.closeDb)?.(dbHandle);
      } catch (err) {
        debugLog('closeDb', err);
      }
    },
  };
}

/**
 * @param {{
 *   port?: number, host?: string, upstreamBaseUrl: string,
 *   onCapture?: (capture: object) => void|Promise<void>,
 *   persist?: boolean, store?: {save(record, requestEvent): Promise<any>, close?(): void},
 *   privacy?: boolean, keepRawExcerpt?: boolean, timeoutMs?: number
 * }} opts
 * @returns {{ server: http.Server, url: string, port: number, listen(): Promise<object>, close(): Promise<void>, stats: object }}
 */
export function createTeeProxy(opts = {}) {
  const { port = DEFAULT_TEE_PORT, host = '127.0.0.1', upstreamBaseUrl, onCapture, persist = true, privacy = true, keepRawExcerpt = false, timeoutMs = 10 * 60 * 1000 } = opts;
  if (!upstreamBaseUrl) throw new Error('upstreamBaseUrl is required');
  const upstreamBase = assertSafeUpstreamUrl(upstreamBaseUrl);
  const store = opts.store || (persist ? createDefaultStore() : null);
  const stats = { requests: 0, captures: 0, errors: 0, bytesOut: 0, startedAt: new Date().toISOString() };

  const server = http.createServer((req, res) => {
    stats.requests++;
    const t0 = performance.now();
    const createdAt = new Date().toISOString();
    const captureId = `tee_${randomUUID().replace(/-/g, '').slice(0, 24)}`;
    let target;
    try {
      target = joinUpstream(upstreamBaseUrl, req.url || '/');
      assertSafeUpstreamUrl(target.toString());
    } catch (err) {
      debugLog('joinUpstream', err);
      res.writeHead(400, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'bad upstream url' }));
      return;
    }
    if (req.url === '/__tee/health') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, upstream: redactUrl(upstreamBase), stats }));
      return;
    }

    const fwdHeaders = Object.create(null);
    for (const [k, v] of Object.entries(req.headers)) {
      if (!isSafeObjectKey(k) || k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
      if (HOP_BY_HOP.has(k.toLowerCase())) continue;
      fwdHeaders[k] = v;
    }
    fwdHeaders.host = target.host;
    fwdHeaders['accept-encoding'] = 'identity';

    const reqChunks = [];
    let reqBytes = 0;
    const lib = target.protocol === 'https:' ? https : http;
    const upstreamReq = lib.request(
      target,
      { method: req.method, headers: fwdHeaders, timeout: timeoutMs },
      (up) => {
        const tHeaders = performance.now();
        const outHeaders = Object.create(null);
        for (const [k, v] of Object.entries(up.headers)) {
          if (!isSafeObjectKey(k) || k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
          if (k === 'connection' || k === 'keep-alive' || k === 'transfer-encoding') continue;
          outHeaders[k] = v;
        }
        res.writeHead(up.statusCode || 502, up.statusMessage, outHeaders);
        if (typeof res.flushHeaders === 'function') res.flushHeaders();
        res.socket?.setNoDelay?.(true);

        const chunks = [];
        let captured = 0;
        up.on('data', (buf) => {
          res.write(buf); // forward immediately — zero added buffering
          stats.bytesOut += buf.length;
          if (captured < MAX_CAPTURE_BYTES) {
            chunks.push({ t: performance.now() - t0, text: buf });
            captured += buf.length;
          }
        });
        up.on('end', () => {
          res.end();
          const tEnd = performance.now() - t0;
          setImmediate(() => finalize({ up, chunks, tHeaders: tHeaders - t0, tEnd }));
        });
        up.on('error', () => {
          stats.errors++;
          res.destroy();
        });
      },
    );
    upstreamReq.on('timeout', () => upstreamReq.destroy(new Error('upstream timeout')));
    upstreamReq.on('error', (e) => {
      stats.errors++;
      if (!res.headersSent) {
        res.writeHead(502, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: { type: 'tee_upstream_error', message: String(e.message || e).slice(0, 300) } }));
      } else res.destroy();
    });
    req.on('data', (b) => {
      upstreamReq.write(b);
      if (reqBytes < MAX_REQ_CAPTURE_BYTES) reqChunks.push(b);
      reqBytes += b.length;
    });
    req.on('end', () => upstreamReq.end());
    req.on('aborted', () => upstreamReq.destroy());
    res.on('close', () => {
      if (!res.writableEnded) upstreamReq.destroy();
    });

    async function finalize({ up, chunks, tHeaders, tEnd }) {
      try {
        let requestModel = null;
        let streamRequested = null;
        if (reqChunks.length) {
          try {
            const reqJson = JSON.parse(Buffer.concat(reqChunks).toString('utf8'));
            requestModel = typeof reqJson.model === 'string' ? reqJson.model : null;
            streamRequested = reqJson.stream ?? null;
          } catch (err) {
            debugLog('parseReqJson', err);
          }
        }
        const endpointMode = endpointModeFromPath(target.pathname);
        if (!requestModel && endpointMode === 'gemini') {
          const m = target.pathname.match(/\/models\/([^/:]+):/);
          if (m) requestModel = decodeURIComponent(m[1]);
        }
        const respHeaders = sanitizeHeaders(up.headers);
        const ct = String(up.headers['content-type'] || '');
        const parseable = /event-stream|json/i.test(ct) || endpointMode !== 'unknown';
        const capture = {
          capture_id: captureId,
          created_at: createdAt,
          method: req.method,
          path: (req.url || '').split('?')[0],
          upstream: redactUrl(target),
          endpointMode,
          requestModel,
          streamRequested,
          statusCode: up.statusCode,
          requestHeaders: sanitizeHeaders(req.headers),
          responseHeaders: respHeaders,
          requestBytes: reqBytes,
          responseBytes: chunks.reduce((s, c) => s + c.text.length, 0),
          headersMs: Math.round(tHeaders * 100) / 100,
          totalMs: Math.round(tEnd * 100) / 100,
        };
        if (parseable && chunks.length && up.statusCode && up.statusCode < 400) {
          const analysis = analyzeForensics(chunks, { endpointMode: endpointMode === 'unknown' ? undefined : endpointMode, claimedModel: requestModel, headers: respHeaders, privacy, t0: 0, tEnd });
          const record = toForensicRecord(analysis, {
            capture_id: captureId,
            created_at: createdAt,
            source_tool: 'tee-proxy',
            base_url: `${upstreamBase.origin}${upstreamBase.pathname}`,
            headers: respHeaders,
            rawExcerpt: keepRawExcerpt ? Buffer.concat(chunks.map((c) => Buffer.from(c.text))).toString('utf8').slice(0, 4000) : null,
          });
          const requestEvent = analysis.parsed.frameCount && analysis.mode !== 'unknown'
            ? toRequestEvent(analysis, { capture_id: captureId, created_at: createdAt, completed_at: new Date().toISOString(), source_tool: 'tee-proxy', endpoint: `${req.method} ${capture.path}`, status_code: up.statusCode })
            : null;
          capture.analysis = analysis;
          capture.record = record;
          capture.requestEvent = requestEvent;
          if (store) capture.persisted = await store.save(record, requestEvent);
        }
        stats.captures++;
        if (typeof onCapture === 'function') await onCapture(capture);
      } catch (e) {
        stats.errors++;
        if (typeof onCapture === 'function') {
          try {
            await onCapture({ capture_id: captureId, error: String(e?.message || e) });
          } catch (cbErr) {
            debugLog('onCaptureError', cbErr);
          }
        }
      }
    }
  });
  server.keepAliveTimeout = 65_000;
  server.headersTimeout = 70_000;
  server.requestTimeout = 0; // long-lived SSE streams

  const api = {
    server,
    stats,
    host,
    port,
    get url() {
      const addr = server.address();
      return `http://${host}:${addr && typeof addr === 'object' ? addr.port : port}`;
    },
    listen() {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => {
          server.off('error', reject);
          const addr = server.address();
          api.port = typeof addr === 'object' && addr ? addr.port : port;
          resolve({ host, port: api.port, url: `http://${host}:${api.port}`, upstream: redactUrl(upstreamBase) });
        });
      });
    },
    close() {
      return new Promise((resolve) => {
        server.close(() => {
          store?.close?.();
          resolve();
        });
        server.closeAllConnections?.();
      });
    },
  };
  return api;
}

export default createTeeProxy;
