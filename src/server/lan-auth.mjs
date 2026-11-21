/**
 * Wiretok — Opt-In PIN-Protected LAN Pairing & Session Auth Manager
 *
 * Security invariants:
 * - Main HTTP server stays bound to 127.0.0.1 unless LAN mode is explicitly enabled.
 * - Host-header allowlist blocks DNS rebinding attacks (403).
 * - Ephemeral 256-bit HMAC secret, 6-digit CSPRNG PIN, 16-byte pairNonce, timingSafeEqual.
 * - Per-IP brute-force rate limiter: 5 failed attempts -> 5-minute lock (429).
 * - Paired LAN clients get HttpOnly; SameSite=Strict; Path=/ cookie and strictly read-only UI/SSE access.
 */
import crypto from 'node:crypto';
import os from 'node:os';
import { encodeQrSvg } from './qr-svg.mjs';

export const LAN_COOKIE_NAME = 'tp_lan_sid';
export const DEFAULT_LAN_PORT = 19842;
const MAX_PIN_ATTEMPTS = 5;
const LOCK_DURATION_MS = 5 * 60 * 1000;
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const MAX_SESSIONS = 64;

/**
 * Return true if socket remoteAddress is a loopback interface IP.
 * NEVER trust X-Forwarded-For or Host header for loopback identity.
 * @param {string|undefined|null} remoteAddress
 */
export function isLoopbackIp(remoteAddress) {
  if (!remoteAddress || typeof remoteAddress !== 'string') return false;
  const ip = remoteAddress.split('%')[0].trim().toLowerCase();
  if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') return true;
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) return true;
  if (/^::ffff:127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) return true;
  return false;
}

/**
 * Normalize socket remote IP for rate-limit buckets.
 */
export function normalizeClientIp(remoteAddress) {
  if (!remoteAddress || typeof remoteAddress !== 'string') return 'unknown';
  const ip = remoteAddress.split('%')[0].trim().toLowerCase();
  return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}

/**
 * Discover active non-internal IPv4 addresses on local network interfaces.
 * Prioritizes private LAN ranges (192.168.*, 10.*, 172.16-31.*) before other interfaces.
 * Excludes link-local 169.254.* addresses.
 * @returns {string[]}
 */
export function getLocalLanIps() {
  const ifaces = os.networkInterfaces();
  const preferred = [];
  const other = [];
  for (const list of Object.values(ifaces)) {
    if (!Array.isArray(list)) continue;
    for (const info of list) {
      if (!info || info.internal || info.family !== 'IPv4') continue;
      const addr = String(info.address || '').trim();
      if (!addr || addr.startsWith('127.') || addr.startsWith('169.254.')) continue;
      if (
        addr.startsWith('192.168.') ||
        addr.startsWith('10.') ||
        /^172\.(?:1[6-9]|2\d|3[01])\./.test(addr)
      ) {
        preferred.push(addr);
      } else {
        other.push(addr);
      }
    }
  }
  return [...new Set([...preferred, ...other])];
}

/**
 * Extract normalized hostname (without port or brackets) from HTTP Host header.
 */
export function parseHostHeaderName(hostHeader) {
  if (!hostHeader || typeof hostHeader !== 'string') return '';
  const trimmed = hostHeader.trim().toLowerCase();
  if (!trimmed) return '';
  if (trimmed.startsWith('[')) {
    const closeIdx = trimmed.indexOf(']');
    return closeIdx > 0 ? trimmed.slice(1, closeIdx) : '';
  }
  const colonIdx = trimmed.indexOf(':');
  return colonIdx >= 0 ? trimmed.slice(0, colonIdx) : trimmed;
}

/**
 * Parse Cookie header safely without prototype pollution.
 */
export function parseCookies(cookieHeader) {
  const out = Object.create(null);
  if (!cookieHeader || typeof cookieHeader !== 'string') return out;
  for (const part of cookieHeader.split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const key = part.slice(0, eq).trim();
    if (!key || key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    out[key] = part.slice(eq + 1).trim();
  }
  return out;
}

/**
 * Construct a strict session cookie string (`HttpOnly; SameSite=Strict; Path=/` + optional `; Secure`).
 */
export function formatSessionCookie(name, value, { maxAgeSec = 43200, secure = false, clear = false } = {}) {
  const attrs = [
    `${name}=${value}`,
    'HttpOnly',
    'SameSite=Strict',
    'Path=/',
    `Max-Age=${clear ? 0 : Math.max(0, Math.round(maxAgeSec))}`,
  ];
  if (secure) attrs.push('Secure');
  return attrs.join('; ');
}

function constantTimeMatchSecret(secretKey, candidate, expected) {
  if (typeof candidate !== 'string' || typeof expected !== 'string') return false;
  const h1 = crypto.createHmac('sha256', secretKey).update(candidate).digest();
  const h2 = crypto.createHmac('sha256', secretKey).update(expected).digest();
  return h1.length === h2.length && crypto.timingSafeEqual(h1, h2);
}

/**
 * Create an isolated LAN auth + rate-limit manager for a Wiretok server instance.
 */
export function createLanAuthManager({ defaultLanPort = DEFAULT_LAN_PORT } = {}) {
  let enabled = false;
  let activePort = defaultLanPort;
  let sharedWithMainServer = false;
  let lanServer = null;
  let hmacSecret = crypto.randomBytes(32);
  let pin = null;
  let pairNonce = null;
  let qrSvg = null;
  let enabledAt = null;
  const sessions = new Map();
  const attemptBuckets = new Map();

  function signSessionId(sid) {
    const sig = crypto.createHmac('sha256', hmacSecret).update(sid).digest('hex');
    return `${sid}.${sig}`;
  }

  function verifyCookieToken(token) {
    if (!enabled || !token || typeof token !== 'string') return null;
    const dot = token.indexOf('.');
    if (dot <= 0) return null;
    const sid = token.slice(0, dot);
    const sig = token.slice(dot + 1);
    const expectedSig = crypto.createHmac('sha256', hmacSecret).update(sid).digest('hex');
    const bufA = Buffer.from(sig, 'utf8');
    const bufB = Buffer.from(expectedSig, 'utf8');
    if (bufA.length !== bufB.length || !crypto.timingSafeEqual(bufA, bufB)) {
      return null;
    }
    const sess = sessions.get(sid);
    if (!sess) return null;
    if (Date.now() > sess.expiresAt) {
      sessions.delete(sid);
      return null;
    }
    sess.lastSeenAt = Date.now();
    return sess;
  }

  function hasValidSession(req) {
    const cookies = parseCookies(req.headers?.cookie);
    const token = cookies[LAN_COOKIE_NAME];
    return Boolean(verifyCookieToken(token));
  }

  function isHostAllowed(req) {
    const hostName = parseHostHeaderName(req.headers?.host);
    if (!hostName) return false;
    if (hostName === '127.0.0.1' || hostName === 'localhost' || hostName === '::1') {
      return true;
    }
    if (enabled) {
      const localIps = getLocalLanIps();
      if (localIps.includes(hostName)) return true;
    }
    return false;
  }

  function buildUrls(portNum, nonce) {
    const ips = getLocalLanIps();
    const hostIp = ips[0] || null;
    const targets = ips.length > 0 ? ips : ['127.0.0.1'];
    const suffix = nonce ? `/?pair=${nonce}` : '/';
    const lanUrls = targets.map((ip) => `http://${ip}:${portNum}${suffix}`);
    return {
      hostIp,
      lanUrls,
      lanUrl: lanUrls[0] || `http://127.0.0.1:${portNum}${suffix}`,
    };
  }

  function rotateCredentials(portNum) {
    hmacSecret = crypto.randomBytes(32);
    pin = String(crypto.randomInt(100000, 1000000));
    pairNonce = crypto.randomBytes(16).toString('hex');
    sessions.clear();
    attemptBuckets.clear();
    activePort = portNum;
    enabled = true;
    enabledAt = new Date().toISOString();
    const { hostIp, lanUrls, lanUrl } = buildUrls(activePort, pairNonce);
    qrSvg = encodeQrSvg(lanUrl);
    return { hostIp, lanUrls, lanUrl };
  }

  function getStatus({ isLoopback = false } = {}) {
    const { hostIp, lanUrls, lanUrl } = enabled
      ? buildUrls(activePort, pairNonce)
      : buildUrls(activePort, null);
    const base = {
      ok: true,
      enabled,
      port: activePort,
      lanPort: activePort,
      hostIp,
      lanUrls,
      lanUrl,
      pairedCount: sessions.size,
      enabledAt,
    };
    if (isLoopback) {
      return {
        ...base,
        pin: enabled ? pin : null,
        pairNonce: enabled ? pairNonce : null,
        qrSvg: enabled ? qrSvg : null,
      };
    }
    return base;
  }

  function checkRateLimit(clientIp) {
    const now = Date.now();
    const bucket = attemptBuckets.get(clientIp);
    if (!bucket) return { limited: false, retryAfterSec: 0 };
    if (bucket.lockedUntil > now) {
      return {
        limited: true,
        retryAfterSec: Math.max(1, Math.ceil((bucket.lockedUntil - now) / 1000)),
      };
    }
    if (bucket.lockedUntil > 0 && bucket.lockedUntil <= now) {
      attemptBuckets.delete(clientIp);
    }
    return { limited: false, retryAfterSec: 0 };
  }

  function verifyPairAttempt(req, { pin: rawPin, nonce } = {}) {
    if (!enabled || !pin) {
      return { ok: false, status: 403, error: 'LAN pairing mode is not enabled' };
    }
    const clientIp = normalizeClientIp(req.socket?.remoteAddress);
    const rate = checkRateLimit(clientIp);
    if (rate.limited) {
      return {
        ok: false,
        status: 429,
        locked: true,
        retryAfterSec: rate.retryAfterSec,
        error: `Too many failed PIN attempts. Try again in ${rate.retryAfterSec}s.`,
      };
    }

    const submittedPin = String(rawPin ?? '').trim();
    const pinValid =
      submittedPin.length === 6 && constantTimeMatchSecret(hmacSecret, submittedPin, pin);
    const nonceValid =
      nonce === undefined ||
      nonce === null ||
      nonce === '' ||
      constantTimeMatchSecret(hmacSecret, String(nonce).trim(), pairNonce || '');

    if (!pinValid || !nonceValid) {
      const now = Date.now();
      const prev = attemptBuckets.get(clientIp) || { count: 0, lockedUntil: 0 };
      const count = prev.count + 1;
      const locked = count >= MAX_PIN_ATTEMPTS;
      const lockedUntil = locked ? now + LOCK_DURATION_MS : 0;
      attemptBuckets.set(clientIp, { count, lockedUntil });
      if (locked) {
        return {
          ok: false,
          status: 429,
          locked: true,
          remainingAttempts: 0,
          retryAfterSec: Math.ceil(LOCK_DURATION_MS / 1000),
          error: 'Too many failed PIN attempts. Locked for 5 minutes.',
        };
      }
      return {
        ok: false,
        status: 401,
        locked: false,
        remainingAttempts: Math.max(0, MAX_PIN_ATTEMPTS - count),
        error: 'Invalid pairing PIN',
      };
    }

    // Success — clear rate bucket and issue signed session cookie
    attemptBuckets.delete(clientIp);
    if (sessions.size >= MAX_SESSIONS) {
      const oldestKey = sessions.keys().next().value;
      if (oldestKey) sessions.delete(oldestKey);
    }
    const sid = crypto.randomBytes(16).toString('hex');
    const now = Date.now();
    sessions.set(sid, {
      ip: clientIp,
      createdAt: now,
      lastSeenAt: now,
      expiresAt: now + SESSION_TTL_MS,
    });
    const token = signSessionId(sid);
    const isHttps =
      Boolean(req.socket?.encrypted) ||
      String(req.headers?.['x-forwarded-proto'] || '').toLowerCase() === 'https';
    const cookieHeader = formatSessionCookie(LAN_COOKIE_NAME, token, {
      maxAgeSec: Math.floor(SESSION_TTL_MS / 1000),
      secure: isHttps,
    });

    return {
      ok: true,
      status: 200,
      cookieHeader,
      pairedCount: sessions.size,
    };
  }

  async function disable() {
    enabled = false;
    pin = null;
    pairNonce = null;
    qrSvg = null;
    enabledAt = null;
    sessions.clear();
    attemptBuckets.clear();
    const srvToClose = lanServer;
    lanServer = null;
    sharedWithMainServer = false;
    if (srvToClose) {
      await new Promise((resolve) => {
        try {
          srvToClose.close(() => resolve());
          srvToClose.closeAllConnections?.();
        } catch (err) {
          if (process.env.WIRETOK_DEBUG) {
            console.error('[wiretok:lan-auth] disable close error:', err?.message || err);
          }
          resolve();
        }
      });
    }
    return getStatus({ isLoopback: true });
  }

  return {
    isEnabled: () => enabled,
    getActivePort: () => activePort,
    getLanServer: () => lanServer,
    setLanServer: (srv, portNum, shared = false) => {
      lanServer = srv;
      activePort = portNum;
      sharedWithMainServer = shared;
    },
    isSharedWithMainServer: () => sharedWithMainServer,
    rotateCredentials,
    getStatus,
    isHostAllowed,
    hasValidSession,
    verifyPairAttempt,
    disable,
  };
}

/**
 * Determine whether a non-loopback client is hard-blocked from an endpoint (`403`).
 * LAN phones are strictly read-only dashboard + SSE viewers.
 * @param {string} method
 * @param {string} pathname
 */
export function isNonLoopbackForbiddenRoute(method, pathname) {
  const m = String(method || 'GET').toUpperCase();
  const p = String(pathname || '/');

  if (
    p === '/api/integrations' ||
    p.startsWith('/api/integrations/') ||
    p === '/api/tee' ||
    p.startsWith('/api/tee/') ||
    p === '/api/forensics/probe' ||
    p === '/api/forensics/speedtest' ||
    p === '/api/lan' ||
    p.startsWith('/api/lan/')
  ) {
    return true;
  }

  if (p.startsWith('/api/') && m !== 'GET' && m !== 'HEAD' && m !== 'OPTIONS') {
    if (p === '/api/auth/pair' && m === 'POST') {
      return false;
    }
    return true;
  }

  return false;
}
