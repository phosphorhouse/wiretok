/**
 * Wiretok — HTTP Static Asset Server, Security Headers, Safe Body Parser, and SSE Broadcast Hub.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { UI_DIR } from '../contracts.mjs';

export const SECURITY_HEADERS = Object.freeze({
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'SAMEORIGIN',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
});

const MIME_TYPES = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.js', 'application/javascript; charset=utf-8'],
  ['.mjs', 'application/javascript; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
  ['.webmanifest', 'application/manifest+json; charset=utf-8'],
  ['.svg', 'image/svg+xml'],
  ['.png', 'image/png'],
  ['.jpg', 'image/jpeg'],
  ['.jpeg', 'image/jpeg'],
  ['.webp', 'image/webp'],
  ['.ico', 'image/x-icon'],
  ['.woff2', 'font/woff2'],
  ['.txt', 'text/plain; charset=utf-8'],
]);

let cachedPreloadJs = null;

function debugLog(context, err) {
  if (process.env.WIRETOK_DEBUG) {
    console.error(`[wiretok:http:${context}]`, err?.message || err);
  }
}

function getPreloadJs() {
  if (cachedPreloadJs !== null) return cachedPreloadJs;
  const candidate = path.join(
    os.homedir(),
    '.gemini',
    'antigravity',
    'lib',
    'node_modules',
    'sidecar_sdk',
    'preload.js'
  );
  try {
    cachedPreloadJs = fs.readFileSync(candidate, 'utf8');
  } catch (err) {
    debugLog('preload', err);
    cachedPreloadJs = 'window.sidecar = window.sidecar || {};\n';
  }
  return cachedPreloadJs;
}

export function sendJson(res, status, data, extraHeaders = {}) {
  if (res.writableEnded) return;
  const body = JSON.stringify(data);
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(body);
}

export function sendProblem(res, status, title, detail, extra = {}, extraHeaders = {}) {
  if (res.writableEnded) return;
  const safeDetail = detail || title;
  const body = JSON.stringify({
    type: `https://httpstatuses.com/${status}`,
    title,
    status,
    detail: safeDetail,
    ok: false,
    error: safeDetail,
    ...extra,
  });
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    'Content-Type': 'application/problem+json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(body);
}

export function sendText(res, status, text, contentType = 'text/plain; charset=utf-8', extraHeaders = {}) {
  if (res.writableEnded) return;
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    'Content-Type': contentType,
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(text);
}

/**
 * Safely parse a JSON request body with bounded byte size.
 * @param {import('node:http').IncomingMessage} req
 * @param {number} [maxBytes]
 */
export function readJsonBody(req, maxBytes = 10 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let settled = false;

    const fail = (status, message) => {
      if (settled) return;
      settled = true;
      const err = new Error(message);
      err.statusCode = status;
      reject(err);
    };

    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        req.destroy();
        fail(413, 'Request body exceeds maximum allowed size');
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (settled) return;
      settled = true;
      const raw = Buffer.concat(chunks).toString('utf8').trim();
      if (!raw) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch (err) {
        debugLog('readJsonBody', err);
        const bad = new Error('Invalid JSON payload');
        bad.statusCode = 400;
        reject(bad);
      }
    });

    req.on('error', (err) => {
      fail(400, err?.message || 'Request stream error');
    });
  });
}

/**
 * Serve static files from UI_DIR (or /preload.js for Antigravity Sidecar compatibility).
 * Prevents directory traversal and symlink escapes outside UI_DIR.
 * @returns {boolean} true if handled, false if 404
 */
export function serveStaticAsset(pathname, res, uiDir = UI_DIR, method = 'GET') {
  if (pathname === '/preload.js') {
    const js = getPreloadJs();
    if (method === 'HEAD') {
      res.writeHead(200, {
        ...SECURITY_HEADERS,
        'Content-Type': 'application/javascript; charset=utf-8',
        'Content-Length': Buffer.byteLength(js),
        'Cache-Control': 'no-store',
      });
      res.end();
      return true;
    }
    sendText(res, 200, js, 'application/javascript; charset=utf-8');
    return true;
  }

  let rel = pathname === '/' || pathname === '' ? 'index.html' : pathname.replace(/^\/+/, '');
  try {
    rel = decodeURIComponent(rel);
  } catch (err) {
    debugLog('decodeURIComponent', err);
    return false;
  }

  const rootResolved = path.resolve(uiDir);
  const target = path.resolve(rootResolved, rel);
  if (target !== rootResolved && !target.startsWith(rootResolved + path.sep)) {
    return false;
  }

  let stat;
  try {
    stat = fs.statSync(target);
  } catch (err) {
    debugLog('statTarget', err);
    return false;
  }

  const filePath = stat.isDirectory() ? path.join(target, 'index.html') : target;
  try {
    const realRoot = fs.realpathSync(rootResolved);
    const realTarget = fs.realpathSync(filePath);
    if (realTarget !== realRoot && !realTarget.startsWith(realRoot + path.sep)) {
      return false;
    }
    const fileStat = fs.statSync(realTarget);
    if (!fileStat.isFile()) return false;

    const ext = path.extname(realTarget).toLowerCase();
    const contentType = MIME_TYPES.get(ext) || 'application/octet-stream';
    const isServiceWorker = path.basename(realTarget) === 'sw.js';
    const data = fs.readFileSync(realTarget);

    const headers = {
      ...SECURITY_HEADERS,
      'Content-Type': contentType,
      'Content-Length': data.length,
      'Cache-Control': isServiceWorker
        ? 'no-cache'
        : ext === '.svg' || ext === '.png' || ext === '.webp' || ext === '.ico' || ext === '.woff2'
        ? 'public, max-age=300'
        : 'no-store',
    };
    if (isServiceWorker) {
      headers['Service-Worker-Allowed'] = '/';
    }

    res.writeHead(200, headers);
    if (method === 'HEAD') {
      res.end();
    } else {
      res.end(data);
    }
    return true;
  } catch (err) {
    debugLog('serveStaticAsset', err);
    return false;
  }
}

/**
 * SSE Broadcast Hub for live telemetry pushes on /api/events.
 * Enforces a hard upper bound on concurrent connected clients.
 */
export function createSseHub(heartbeatMs = 25000, maxClients = 32) {
  const clients = new Set();

  const heartbeat = setInterval(() => {
    for (const res of clients) {
      if (res.writableEnded || res.destroyed) {
        clients.delete(res);
        continue;
      }
      try {
        res.write(':ping\n\n');
      } catch (err) {
        debugLog('sseHeartbeat', err);
        clients.delete(res);
      }
    }
  }, heartbeatMs);
  if (typeof heartbeat.unref === 'function') heartbeat.unref();

  function addClient(req, res, initialPayload = {}) {
    for (const c of clients) {
      if (c.writableEnded || c.destroyed) clients.delete(c);
    }
    if (clients.size >= maxClients) {
      sendProblem(res, 503, 'Service Unavailable', `Too many concurrent SSE clients (max ${maxClients})`);
      return false;
    }

    req.socket?.setTimeout?.(0);
    res.writeHead(200, {
      ...SECURITY_HEADERS,
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    res.write(':ok\n\n');
    res.write(
      `event: connected\ndata: ${JSON.stringify({ ts: new Date().toISOString(), ...initialPayload })}\n\n`
    );
    clients.add(res);

    const cleanup = () => {
      clients.delete(res);
    };
    req.on('close', cleanup);
    req.on('aborted', cleanup);
    res.on('close', cleanup);
    res.on('error', cleanup);
    return true;
  }

  function broadcast(eventName, payload = {}) {
    if (clients.size === 0) return 0;
    const frame = `event: ${eventName}\ndata: ${JSON.stringify({ ts: new Date().toISOString(), ...payload })}\n\n`;
    let sent = 0;
    for (const res of clients) {
      if (res.writableEnded || res.destroyed) {
        clients.delete(res);
        continue;
      }
      try {
        res.write(frame);
        sent += 1;
      } catch (err) {
        debugLog('sseBroadcast', err);
        clients.delete(res);
      }
    }
    return sent;
  }

  function closeAll() {
    clearInterval(heartbeat);
    for (const res of clients) {
      try {
        res.end();
      } catch (err) {
        debugLog('sseClose', err);
      }
    }
    clients.clear();
  }

  return {
    addClient,
    broadcast,
    closeAll,
    get clientCount() {
      return clients.size;
    },
    get maxClients() {
      return maxClients;
    },
  };
}
