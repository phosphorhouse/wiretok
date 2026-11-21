/**
 * Wiretok — Unified HTTP + SSE Server (`src/server/server.mjs`)
 *
 * Dual-Bind + Opt-In LAN QR Architecture:
 *  - Default HTTP bind stays strictly 127.0.0.1 (port 19840 + optional ANTIGRAVITY_SIDECAR_WEB_PORT).
 *  - Opt-in PIN-protected LAN mode binds 0.0.0.0:19842 (or reuses main port if started with host 0.0.0.0),
 *    enforcing Host-header anti-rebinding, signed HttpOnly cookie sessions, forced privacyMask=true,
 *    and strict read-only access for LAN viewers.
 */
import http from 'node:http';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  DEFAULT_TEE_PORT,
  DEFAULT_WEB_PORT,
  INGEST_EVENTS_LOG,
  UI_DIR,
  VERSION,
} from '../contracts.mjs';
import * as dbApi from '../db/index.mjs';
import { runSyncAll } from '../collectors/index.mjs';
import {
  analyzeForensics,
  assertSafeUpstreamUrl,
  compactAnalysis,
  createTeeProxy,
  probeEndpoint,
  toForensicRecord,
} from '../forensics/index.mjs';
import { configureIntegration, getIntegrationStatusLive } from '../integrations/integrator.mjs';
import {
  SECURITY_HEADERS,
  createSseHub,
  readJsonBody,
  sendJson,
  sendProblem,
  sendText,
  serveStaticAsset,
} from './http-utils.mjs';
import { appendIngestJsonl, normalizeIngestEvent } from './ingest.mjs';
import {
  DEFAULT_LAN_PORT,
  createLanAuthManager,
  isLoopbackIp,
  isNonLoopbackForbiddenRoute,
} from './lan-auth.mjs';

const SYNC_INTERVAL_MS = 6000;
const SSE_MAX_CLIENTS = 32;
const ALLOWED_METHODS_HEADER = 'GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS';
const SET_COOKIE_HEADER = ['Set', 'Cookie'].join('-');

function debugLog(context, err) {
  if (process.env.WIRETOK_DEBUG) {
    console.error(`[wiretok:server:${context}]`, err?.message || err);
  }
}

function configureServerTimeouts(srv) {
  srv.keepAliveTimeout = 65_000;
  srv.headersTimeout = 66_000;
  srv.requestTimeout = 30_000;
}

function quantile(sortedAsc, q) {
  if (!sortedAsc.length) return null;
  if (sortedAsc.length === 1) return sortedAsc[0];
  const pos = (sortedAsc.length - 1) * q;
  const base = Math.floor(pos);
  const rest = pos - base;
  const next = sortedAsc[base + 1] !== undefined ? sortedAsc[base + 1] : sortedAsc[base];
  return sortedAsc[base] + rest * (next - sortedAsc[base]);
}

function meanNums(arr) {
  if (!arr.length) return null;
  return arr.reduce((sum, n) => sum + n, 0) / arr.length;
}

function stdDevNums(arr) {
  if (arr.length < 2) return 0;
  const avg = meanNums(arr);
  const variance = arr.reduce((sum, n) => sum + (n - avg) ** 2, 0) / arr.length;
  return Math.sqrt(variance);
}

function roundMetric(val, decimals = 2) {
  if (val === null || val === undefined || !Number.isFinite(val)) return null;
  const factor = 10 ** decimals;
  return Math.round(val * factor) / factor;
}

function parseFilters(searchParams) {
  const filters = {};
  const strKeys = [
    'era',
    'from',
    'to',
    'accountId',
    'modelId',
    'sourceTool',
    'workspace',
    'sessionId',
    'q',
    'sort',
    'dir',
    'endpointMode',
    'verdict',
  ];
  for (const k of strKeys) {
    const val = searchParams.get(k);
    if (val !== null && val !== '') filters[k] = val;
  }
  const limit = searchParams.get('limit');
  if (limit !== null && limit !== '') filters.limit = Number(limit);
  const offset = searchParams.get('offset');
  if (offset !== null && offset !== '') filters.offset = Number(offset);
  const daysRaw = searchParams.get('days');
  if (daysRaw !== null && daysRaw !== '') {
    const d = Math.round(Number(daysRaw));
    if (Number.isFinite(d) && d > 0) filters.days = Math.min(375, Math.max(1, d));
  }
  const recentLimitRaw = searchParams.get('recentLimit');
  if (recentLimitRaw !== null && recentLimitRaw !== '') {
    const rl = Math.round(Number(recentLimitRaw));
    if (Number.isFinite(rl) && rl > 0) filters.recentLimit = Math.min(50, Math.max(1, rl));
  }
  const pm = searchParams.get('privacyMask');
  if (pm !== null && pm !== '') filters.privacyMask = pm === '1' || pm === 'true';

  if (filters.sort === 'context_pct') filters.sort = 'context_utilization';
  if (filters.sort === 'tokens_per_sec') filters.sort = 'tok_per_sec';
  return filters;
}

function listenOnPort(server, port, host = '127.0.0.1', { allowInUse = false } = {}) {
  return new Promise((resolve, reject) => {
    const onError = (err) => {
      server.removeListener('listening', onListening);
      if (allowInUse && err && err.code === 'EADDRINUSE') {
        resolve({ bound: false, reason: 'EADDRINUSE', port, host });
        return;
      }
      reject(err);
    };
    const onListening = () => {
      server.removeListener('error', onError);
      const addr = server.address();
      resolve({ bound: true, port: addr?.port ?? port, host, server });
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(port, host);
  });
}

function fallbackLiveContext(db, filters) {
  const recentLimit = Math.min(50, Math.max(1, Number(filters?.recentLimit) || 6));
  const result = dbApi.listSessions(db, { era: 'all', limit: Math.max(40, recentLimit + 15), ...filters });
  const activeSessions = result.items.filter(
    (s) =>
      Number(s.killed || 0) === 0 &&
      (s.run_status === 'CASCADE_RUN_STATUS_RUNNING' ||
        Number(s.not_fully_idle || 0) === 1 ||
        ((s.latest_context_tokens || s.peak_context_tokens || 0) > 0 &&
          !String(s.source_tool || '').startsWith('antigravity')))
  );
  const activeIds = new Set(activeSessions.map((s) => s.session_id));
  const recentSessions = result.items
    .filter((s) => !activeIds.has(s.session_id) && Number(s.killed || 0) === 0 && Number(s.nesting_depth || 0) === 0)
    .slice(0, recentLimit);
  return { activeSessions, recentSessions, recentLimit };
}

function forcePrivacyOn(db) {
  if (typeof dbApi.setSetting === 'function') {
    dbApi.setSetting(db, 'privacy_mask', '1');
  } else if (typeof dbApi.setMeta === 'function') {
    dbApi.setMeta(db, 'privacy_mask', '1');
  } else {
    dbApi.updateSettings(db, { privacy_mask: true });
  }
}

/**
 * Start Wiretok HTTP + SSE server.
 * @param {{
 *   port?: number,
 *   host?: string,
 *   dbPath?: string,
 *   uiDir?: string,
 *   enableSyncLoop?: boolean,
 *   syncIntervalMs?: number,
 *   sidecar?: boolean,
 *   quiet?: boolean,
 *   lan?: boolean,
 *   lanPort?: number,
 * }} [opts]
 */
export async function startServer(opts = {}) {
  const host = opts.host || '127.0.0.1';
  const uiDir = opts.uiDir || UI_DIR;
  const ingestLogPath =
    opts.ingestLogPath ||
    (opts.dbPath && opts.dbPath !== ':memory:'
      ? path.join(path.dirname(path.resolve(opts.dbPath)), 'ingest_events.jsonl')
      : opts.dbPath === ':memory:'
      ? null
      : INGEST_EVENTS_LOG);
  const db = dbApi.openDatabase(opts.dbPath);
  const sseHub = createSseHub(25000, SSE_MAX_CLIENTS);
  const defaultLanPort =
    opts.lanPort !== undefined && Number.isInteger(Number(opts.lanPort))
      ? Number(opts.lanPort)
      : DEFAULT_LAN_PORT;
  const lanAuth = createLanAuthManager({ defaultLanPort });

  let syncInProgress = false;
  let syncPending = false;
  let syncPaused = false;
  let activeTee = null;
  let syncDebounceTimer = null;
  let syncInterval = null;
  let closed = false;

  function teeStatus() {
    if (!activeTee) {
      return {
        running: false,
        port: DEFAULT_TEE_PORT,
        upstreamBaseUrl: 'https://api.openai.com/v1',
        url: `http://127.0.0.1:${DEFAULT_TEE_PORT}`,
        startedAt: null,
        stats: null,
      };
    }
    return {
      running: true,
      port: activeTee.port,
      upstreamBaseUrl: activeTee.upstreamBaseUrl,
      url: activeTee.proxy.url || `http://127.0.0.1:${activeTee.port}`,
      startedAt: activeTee.startedAt,
      stats: activeTee.proxy.stats ? { ...activeTee.proxy.stats } : null,
    };
  }

  async function stopTee() {
    if (!activeTee) return;
    const prev = activeTee;
    activeTee = null;
    try {
      await prev.proxy.close();
    } catch (err) {
      debugLog('stopTee', err);
    }
  }

  async function executeSync({ forceBroadcast = false, sources } = {}) {
    if (closed) return { ok: false, skipped: true };
    if (syncInProgress) {
      syncPending = true;
      return { ok: true, queued: true };
    }
    syncInProgress = true;
    try {
      const settings = dbApi.getSettings(db);
      const result = await runSyncAll(db, {
        milestoneAt: settings.milestoneAt,
        sources,
      });
      const totalInserted = Object.values(result.syncedCounts || {}).reduce(
        (sum, n) => sum + (Number(n) || 0),
        0
      );
      if (totalInserted > 0 || (result.quotaRows || 0) > 0 || forceBroadcast) {
        sseHub.broadcast('sync', {
          syncedCounts: result.syncedCounts,
          totalInserted,
          quotaRows: result.quotaRows || 0,
          syncedAt: result.syncedAt,
        });
      }
      return { ok: true, ...result, totalInserted };
    } catch (err) {
      debugLog('executeSync', err);
      return { ok: false, error: err.message };
    } finally {
      syncInProgress = false;
      if (syncPending && !closed) {
        syncPending = false;
        clearTimeout(syncDebounceTimer);
        syncDebounceTimer = setTimeout(() => {
          executeSync().catch((err) => debugLog('syncRetry', err));
        }, 250);
        if (typeof syncDebounceTimer.unref === 'function') syncDebounceTimer.unref();
      }
    }
  }

  function scheduleSync(delayMs = 200) {
    if (closed) return;
    clearTimeout(syncDebounceTimer);
    syncDebounceTimer = setTimeout(() => {
      executeSync().catch((err) => debugLog('scheduledSync', err));
    }, delayMs);
    if (typeof syncDebounceTimer.unref === 'function') syncDebounceTimer.unref();
  }

  async function enableLanMode({ requestedPort } = {}) {
    const mainBoundOnAllInterfaces =
      host === '0.0.0.0' || host === '::' ? boundResults.find((b) => b.bound) : null;

    if (mainBoundOnAllInterfaces && requestedPort === undefined) {
      const mainPort = mainBoundOnAllInterfaces.port;
      lanAuth.setLanServer(null, mainPort, true);
      lanAuth.rotateCredentials(mainPort);
      forcePrivacyOn(db);
      sseHub.broadcast('settings', dbApi.getSettings(db));
      return lanAuth.getStatus({ isLoopback: true });
    }

    const targetPort =
      requestedPort !== undefined && requestedPort !== null && requestedPort !== ''
        ? Number(requestedPort)
        : lanAuth.getLanServer()
        ? lanAuth.getActivePort()
        : defaultLanPort;

    if (!Number.isInteger(targetPort) || targetPort < 0 || targetPort > 65535) {
      const err = new Error('Geçersiz LAN port numarası (0–65535).');
      err.statusCode = 400;
      throw err;
    }

    const existingLanSrv = lanAuth.getLanServer();
    if (existingLanSrv && (requestedPort === undefined || targetPort === lanAuth.getActivePort())) {
      const boundPort = existingLanSrv.address()?.port ?? lanAuth.getActivePort();
      lanAuth.rotateCredentials(boundPort);
      forcePrivacyOn(db);
      sseHub.broadcast('settings', dbApi.getSettings(db));
      return lanAuth.getStatus({ isLoopback: true });
    }

    if (existingLanSrv) {
      await lanAuth.disable();
    }

    const lanSrv = http.createServer(requestHandler);
    configureServerTimeouts(lanSrv);
    const listenRes = await listenOnPort(lanSrv, targetPort, '0.0.0.0', { allowInUse: false });
    lanAuth.setLanServer(lanSrv, listenRes.port, false);
    lanAuth.rotateCredentials(listenRes.port);
    forcePrivacyOn(db);
    sseHub.broadcast('settings', dbApi.getSettings(db));
    return lanAuth.getStatus({ isLoopback: true });
  }

  const requestHandler = async (req, res) => {
    try {
      // 1. Host-header validation (blocks DNS rebinding)
      if (!lanAuth.isHostAllowed(req)) {
        sendProblem(res, 403, 'Forbidden', 'Invalid or disallowed Host header');
        return;
      }

      const reqUrl = new URL(req.url || '/', `http://${req.headers.host || '127.0.0.1'}`);
      const pathname = reqUrl.pathname;
      const method = (req.method || 'GET').toUpperCase();

      if (method === 'TRACE') {
        sendProblem(
          res,
          405,
          'Method Not Allowed',
          'TRACE method is disabled',
          {},
          { Allow: ALLOWED_METHODS_HEADER }
        );
        return;
      }

      if (method === 'OPTIONS') {
        res.writeHead(204, {
          ...SECURITY_HEADERS,
          Allow: ALLOWED_METHODS_HEADER,
          'Cache-Control': 'no-store',
        });
        res.end();
        return;
      }

      // 2. Non-loopback enforcement (read-only + PIN session auth + forced privacy mask)
      const loopback = isLoopbackIp(req.socket?.remoteAddress);
      if (!loopback) {
        if (!lanAuth.isEnabled()) {
          sendProblem(res, 403, 'Forbidden', 'LAN mode is disabled');
          return;
        }
        if (isNonLoopbackForbiddenRoute(method, pathname)) {
          sendProblem(res, 403, 'Forbidden', 'LAN viewers have read-only access');
          return;
        }
        if (
          pathname.startsWith('/api/') &&
          pathname !== '/api/auth/status' &&
          pathname !== '/api/auth/pair' &&
          pathname !== '/api/health'
        ) {
          if (!lanAuth.hasValidSession(req)) {
            sendProblem(res, 401, 'Unauthorized', 'PIN authentication required', {
              requiresPin: true,
            });
            return;
          }
        }
      }

      // SSE live event stream
      if (method === 'GET' && pathname === '/api/events') {
        const settings = dbApi.getSettings(db);
        sseHub.addClient(req, res, {
          milestoneAt: settings.milestoneAt,
          fxUsdTry: settings.fxUsdTry,
          privacyMask: !loopback ? true : settings.privacyMask,
        });
        return;
      }

      // Health endpoint
      if (method === 'GET' && pathname === '/api/health') {
        const ports = boundResults.filter((b) => b.bound).map((b) => b.port);
        if (lanAuth.isEnabled() && lanAuth.getLanServer()) {
          const lp = lanAuth.getActivePort();
          if (lp && !ports.includes(lp)) ports.push(lp);
        }
        sendJson(res, 200, {
          ok: true,
          service: 'wiretok',
          version: VERSION,
          syncInProgress,
          syncPaused,
          teeProxy: teeStatus(),
          sseClients: sseHub.clientCount,
          lanEnabled: lanAuth.isEnabled(),
          ports,
          uptimeSec: Math.round(process.uptime()),
        });
        return;
      }

      // Auth & LAN Pairing
      if (method === 'GET' && pathname === '/api/auth/status') {
        const authenticated = loopback || lanAuth.hasValidSession(req);
        sendJson(res, 200, {
          ok: true,
          authenticated,
          isLoopback: loopback,
          lanEnabled: lanAuth.isEnabled(),
          requiresPin: !loopback && !authenticated,
        });
        return;
      }

      if (method === 'POST' && pathname === '/api/auth/pair') {
        const body = await readJsonBody(req);
        const result = lanAuth.verifyPairAttempt(req, body && typeof body === 'object' ? body : {});
        if (!result.ok) {
          const headers =
            result.status === 429 && result.retryAfterSec
              ? { 'Retry-After': String(result.retryAfterSec) }
              : {};
          sendProblem(
            res,
            result.status,
            result.status === 429 ? 'Too Many Requests' : result.status === 403 ? 'Forbidden' : 'Unauthorized',
            result.error,
            {
              locked: Boolean(result.locked),
              remainingAttempts: result.remainingAttempts ?? null,
              retryAfterSec: result.retryAfterSec ?? null,
            },
            headers
          );
          return;
        }
        sendJson(
          res,
          200,
          { ok: true, authenticated: true, pairedCount: result.pairedCount },
          { [SET_COOKIE_HEADER]: result.cookieHeader }
        );
        return;
      }

      if (method === 'GET' && pathname === '/api/lan/status') {
        sendJson(res, 200, lanAuth.getStatus({ isLoopback: loopback }));
        return;
      }

      if (method === 'POST' && pathname === '/api/lan/enable') {
        if (!loopback) {
          sendProblem(res, 403, 'Forbidden', 'Only loopback clients may enable LAN mode');
          return;
        }
        const body = await readJsonBody(req);
        const requestedPort =
          body && typeof body === 'object' && body.port !== undefined && body.port !== ''
            ? Number(body.port)
            : undefined;
        const status = await enableLanMode({ requestedPort });
        sendJson(res, 200, { ok: true, ...status });
        return;
      }

      if (method === 'POST' && pathname === '/api/lan/disable') {
        if (!loopback) {
          sendProblem(res, 403, 'Forbidden', 'Only loopback clients may disable LAN mode');
          return;
        }
        const status = await lanAuth.disable();
        sendJson(res, 200, { ok: true, ...status });
        return;
      }

      // Overview analytics
      if (method === 'GET' && pathname === '/api/overview') {
        const filters = parseFilters(reqUrl.searchParams);
        if (!loopback) filters.privacyMask = true;
        const days = filters.days ?? 371;
        const ov = dbApi.getOverview(db, { ...filters, days });
        const settings = dbApi.getSettings(db);
        const activeSessions = ov.activeSessions || ov.activeContextSessions || [];
        const recentSessions = ov.recentSessions || [];
        sendJson(res, 200, {
          syncPaused,
          teeProxy: teeStatus(),
          ...ov,
          era: filters.era || 'all',
          privacyMask: !loopback ? true : Boolean(ov.privacyMask ?? settings.privacyMask),
          activeSessions,
          recentSessions,
          activeContextSessions: ov.activeContextSessions || activeSessions,
        });
        return;
      }

      // Requests log
      if (method === 'GET' && pathname === '/api/requests') {
        const filters = parseFilters(reqUrl.searchParams);
        if (!loopback) filters.privacyMask = true;
        const settings = dbApi.getSettings(db);
        const result = dbApi.listRequests(db, filters);
        sendJson(res, 200, {
          rows: result.items,
          requests: result.items,
          total: result.total,
          limit: result.limit,
          offset: result.offset,
          fxUsdTry: settings.fxUsdTry,
          privacyMask: !loopback ? true : Boolean(filters.privacyMask ?? settings.privacyMask),
        });
        return;
      }

      // Sessions & Swarm trees
      if (method === 'GET' && pathname === '/api/sessions') {
        const filters = parseFilters(reqUrl.searchParams);
        if (!loopback) filters.privacyMask = true;
        const settings = dbApi.getSettings(db);
        const result = dbApi.listSessions(db, filters);
        sendJson(res, 200, {
          sessions: result.items,
          activeContextSessions: result.items,
          total: result.total,
          fxUsdTry: settings.fxUsdTry,
          privacyMask: !loopback ? true : Boolean(filters.privacyMask ?? settings.privacyMask),
        });
        return;
      }

      if (method === 'GET' && pathname === '/api/swarm-trees') {
        const filters = parseFilters(reqUrl.searchParams);
        if (!loopback) filters.privacyMask = true;
        const settings = dbApi.getSettings(db);
        const trees = dbApi.getSwarmTrees(db, filters);
        sendJson(res, 200, {
          trees,
          fxUsdTry: settings.fxUsdTry,
          privacyMask: !loopback ? true : Boolean(filters.privacyMask ?? settings.privacyMask),
        });
        return;
      }

      if (method === 'GET' && pathname === '/api/context-live') {
        const filters = parseFilters(reqUrl.searchParams);
        if (!loopback) filters.privacyMask = true;
        const settings = dbApi.getSettings(db);
        const effectivePrivacy =
          !loopback || (filters.privacyMask !== undefined ? filters.privacyMask : settings.privacyMask);
        const live =
          typeof dbApi.getLiveContext === 'function'
            ? dbApi.getLiveContext(db, { ...filters, privacyMask: effectivePrivacy })
            : fallbackLiveContext(db, { ...filters, privacyMask: effectivePrivacy });
        const activeSessions = live.activeSessions || live.sessions || [];
        const recentSessions = live.recentSessions || [];
        sendJson(res, 200, {
          sessions: activeSessions,
          activeSessions,
          recentSessions,
          fxUsdTry: live.fxUsdTry ?? settings.fxUsdTry,
          privacyMask: effectivePrivacy,
          updatedAt: live.updatedAt || new Date().toISOString(),
        });
        return;
      }

      // Accounts
      if (method === 'GET' && pathname === '/api/accounts') {
        const filters = parseFilters(reqUrl.searchParams);
        if (!loopback) filters.privacyMask = true;
        const settings = dbApi.getSettings(db);
        const accounts = dbApi.listAccounts(db, filters);
        sendJson(res, 200, {
          accounts,
          fxUsdTry: settings.fxUsdTry,
          privacyMask: !loopback ? true : Boolean(filters.privacyMask ?? settings.privacyMask),
        });
        return;
      }

      if ((method === 'PATCH' || method === 'PUT' || method === 'POST') && pathname.startsWith('/api/accounts/')) {
        const id = decodeURIComponent(pathname.slice('/api/accounts/'.length));
        if (!id) {
          sendProblem(res, 400, 'Bad Request', 'Missing account ID');
          return;
        }
        const body = await readJsonBody(req);
        const account = dbApi.updateAccount(db, id, body);
        sseHub.broadcast('sync', { kind: 'account_updated', accountId: id });
        sendJson(res, 200, { ok: true, account });
        return;
      }

      // Quotas
      if (method === 'POST' && pathname === '/api/quotas') {
        if (!loopback) {
          sendProblem(res, 403, 'Forbidden', 'Only loopback clients may write quota snapshots');
          return;
        }
        const body = await readJsonBody(req);
        const items = Array.isArray(body)
          ? body
          : Array.isArray(body?.quotas)
          ? body.quotas
          : body && typeof body === 'object' && Object.keys(body).length > 0
          ? [body]
          : [];
        if (items.length === 0) {
          sendProblem(res, 400, 'Bad Request', 'Expected { quotas: [...] } or quota object');
          return;
        }
        let result;
        if (typeof dbApi.upsertQuotaSnapshots === 'function') {
          result = dbApi.upsertQuotaSnapshots(db, items);
        } else {
          db.exec('BEGIN');
          try {
            for (const q of items) dbApi.upsertQuotaSnapshot(db, q);
            db.exec('COMMIT');
            result = { upserted: items.length };
          } catch (err) {
            db.exec('ROLLBACK');
            throw err;
          }
        }
        sseHub.broadcast('sync', { kind: 'quotas_updated', count: items.length });
        sendJson(res, 200, {
          ok: true,
          upserted: result?.upserted ?? result?.count ?? items.length,
        });
        return;
      }

      // Models (pass FULL filters)
      if (method === 'GET' && pathname === '/api/models') {
        const filters = parseFilters(reqUrl.searchParams);
        const settings = dbApi.getSettings(db);
        const modelFilters = {
          ...filters,
          era: filters.era || 'all',
        };
        let models = dbApi.listModels(db, modelFilters);
        if (filters.q) {
          const needle = String(filters.q).toLowerCase();
          models = models.filter((m) =>
            `${m.model_id} ${m.display_name} ${m.provider}`.toLowerCase().includes(needle)
          );
        }
        sendJson(res, 200, {
          models,
          fxUsdTry: settings.fxUsdTry,
        });
        return;
      }

      if (method === 'POST' && pathname === '/api/models/sync') {
        const [modelRes, fxRes] = await Promise.all([
          dbApi.syncLiveModels(db),
          dbApi.syncUsdTry(db, { force: true }),
        ]);
        const models = dbApi.listModels(db, { era: 'all' });
        sseHub.broadcast('sync', { kind: 'models_synced', updated: modelRes.upsertedCount });
        sendJson(res, 200, {
          ok: true,
          updated: modelRes.upsertedCount,
          total: modelRes.totalModels,
          fxUsdTry: fxRes.rate,
          fxSource: fxRes.source,
          sourcesReached: modelRes.sourcesReached,
          models,
        });
        return;
      }

      if ((method === 'PATCH' || method === 'PUT' || method === 'POST') && pathname.startsWith('/api/models/')) {
        const id = decodeURIComponent(pathname.slice('/api/models/'.length));
        if (!id) {
          sendProblem(res, 400, 'Bad Request', 'Missing model ID');
          return;
        }
        const body = await readJsonBody(req);
        const model = dbApi.updateModel(db, id, body);
        sseHub.broadcast('sync', { kind: 'model_updated', modelId: id });
        sendJson(res, 200, { ok: true, model });
        return;
      }

      // Manual sync trigger
      if (method === 'POST' && pathname === '/api/sync') {
        const body = await readJsonBody(req);
        const result = await executeSync({ forceBroadcast: true, sources: body.sources });
        sendJson(res, result.ok ? 200 : 500, result);
        return;
      }

      // Pause / resume automatic periodic sync
      if (method === 'POST' && pathname === '/api/sync/toggle') {
        const body = await readJsonBody(req);
        syncPaused = typeof body.paused === 'boolean' ? body.paused : !syncPaused;
        sseHub.broadcast('settings', { syncPaused });
        sendJson(res, 200, { ok: true, syncPaused });
        return;
      }

      // Local Tee Proxy (:19841) 1-click controls
      if (method === 'GET' && pathname === '/api/tee/status') {
        sendJson(res, 200, { ok: true, ...teeStatus() });
        return;
      }

      if (method === 'POST' && pathname === '/api/tee/start') {
        const body = await readJsonBody(req);
        const portNum = body.port !== undefined && body.port !== '' ? Number(body.port) : DEFAULT_TEE_PORT;
        if (!Number.isInteger(portNum) || portNum < 0 || portNum > 65535) {
          sendProblem(res, 400, 'Bad Request', 'Geçersiz port numarası (0–65535).');
          return;
        }
        const upstreamBaseUrl = String(body.upstreamBaseUrl || 'https://api.openai.com/v1').trim();
        try {
          assertSafeUpstreamUrl(upstreamBaseUrl);
        } catch (err) {
          sendProblem(res, err?.statusCode || 400, 'Bad Request', err?.message || 'Geçersiz Upstream URL.');
          return;
        }

        await stopTee();
        const settings = dbApi.getSettings(db);
        const proxy = createTeeProxy({
          port: portNum,
          host: '127.0.0.1',
          upstreamBaseUrl,
          persist: true,
          privacy: settings.privacyMask,
          store: {
            async save(record, requestEvent) {
              if (closed) return;
              if (record) dbApi.saveForensicCapture(db, record);
              if (requestEvent) dbApi.insertRequestBatch(db, [requestEvent]);
            },
            close() {},
          },
          onCapture: (cap) => {
            if (closed) return;
            if (cap?.record) {
              sseHub.broadcast('forensic', {
                captureId: cap.record.capture_id,
                verdict: cap.analysis?.verdict,
              });
            }
            if (cap?.requestEvent) {
              sseHub.broadcast('sync', { kind: 'tee' });
            }
          },
        });
        try {
          const bound = await proxy.listen();
          activeTee = {
            proxy,
            port: bound.port,
            upstreamBaseUrl,
            startedAt: new Date().toISOString(),
          };
          sseHub.broadcast('settings', { teeRunning: true, teeProxy: teeStatus() });
          sendJson(res, 200, { ok: true, ...teeStatus() });
        } catch (err) {
          try {
            await proxy.close();
          } catch (closeErr) {
            debugLog('teeStartCleanup', closeErr);
          }
          const code = err?.code === 'EADDRINUSE' ? 409 : 500;
          sendProblem(res, code, 'Tee Proxy Error', err?.message || 'Tee proxy başlatılamadı.');
        }
        return;
      }

      if (method === 'POST' && pathname === '/api/tee/stop') {
        await stopTee();
        sseHub.broadcast('settings', { teeRunning: false, teeProxy: teeStatus() });
        sendJson(res, 200, { ok: true, ...teeStatus() });
        return;
      }

      // Historical re-tag
      if (method === 'POST' && pathname === '/api/retag') {
        const body = await readJsonBody(req);
        const scope = body.scope || '';
        const retagOpts = {
          accountId: body.accountId || body.account_id || body.account,
          from: body.from,
          to: body.to,
          workspace: body.workspace,
          sourceTool: body.sourceTool || body.source_tool,
          oldAccountId: body.oldAccountId || body.fromAccountId,
          sessionId: body.sessionId || body.session_id,
          era: body.era,
          onlyUnattributed: body.onlyUnattributed,
        };
        if (scope === 'pre_milestone') {
          retagOpts.era = 'pre_milestone';
        } else if (scope === 'untagged') {
          retagOpts.onlyUnattributed = true;
        } else if (scope === 'all') {
          retagOpts.era = 'all';
          if (
            !retagOpts.from &&
            !retagOpts.to &&
            !retagOpts.workspace &&
            !retagOpts.sourceTool &&
            !retagOpts.oldAccountId &&
            !retagOpts.sessionId
          ) {
            retagOpts.from = '1970-01-01T00:00:00.000Z';
          }
        }
        const result = dbApi.retagLegacy(db, retagOpts);
        sseHub.broadcast('sync', { kind: 'retag', updatedCount: result.updatedRequests });
        sendJson(res, 200, {
          ...result,
          updatedCount: result.updatedRequests,
          updated: result.updatedRequests,
        });
        return;
      }

      // Settings
      if (method === 'GET' && pathname === '/api/settings') {
        const settings = dbApi.getSettings(db);
        sendJson(res, 200, {
          ok: true,
          ...settings,
          privacyMask: !loopback ? true : settings.privacyMask,
          privacy_mask: !loopback ? true : settings.privacy_mask,
        });
        return;
      }

      if (method === 'POST' && pathname === '/api/settings') {
        const body = await readJsonBody(req);
        const updated = dbApi.updateSettings(db, body);
        sseHub.broadcast('settings', updated);
        sendJson(res, 200, { ok: true, ...updated });
        return;
      }

      // Integrations
      if (method === 'GET' && pathname === '/api/integrations') {
        const integrations = await getIntegrationStatusLive();
        sendJson(res, 200, {
          integrations,
          teeProxyPort: DEFAULT_TEE_PORT,
        });
        return;
      }

      if (method === 'POST' && pathname.startsWith('/api/integrations/')) {
        const rawTool = decodeURIComponent(pathname.slice('/api/integrations/'.length));
        const tool = rawTool === 'claude' ? 'claude-code' : rawTool;
        const body = await readJsonBody(req);
        const result = configureIntegration(tool, {
          apply: body.apply === true,
          force: body.force === true,
        });
        sendJson(res, result.ok === false ? 400 : 200, result);
        return;
      }

      // Forensics: Raw SSE inspect
      if (method === 'POST' && pathname === '/api/forensics/inspect') {
        const body = await readJsonBody(req);
        const rawInput = body.rawText ?? body.raw ?? '';
        if (!rawInput || (typeof rawInput === 'string' && !rawInput.trim())) {
          sendProblem(res, 400, 'Bad Request', 'rawText is required');
          return;
        }
        const settings = dbApi.getSettings(db);
        const mode = body.mode || 'auto';
        const rawEp = body.endpointMode;
        const endpointMode = ['responses', 'messages', 'chat_completions', 'gemini'].includes(rawEp)
          ? rawEp
          : undefined;
        const analysis = analyzeForensics(rawInput, {
          mode,
          endpointMode,
          claimedModel: body.claimedModel || '',
          headers: body.headers || {},
          privacy: settings.privacyMask,
        });
        let savedId = null;
        if (body.save) {
          const rec = toForensicRecord(analysis, {
            source_tool: body.source_tool || 'manual-ingest',
            base_url: body.label || '',
            rawExcerpt: typeof rawInput === 'string' ? rawInput.slice(0, 4000) : '',
          });
          const saved = dbApi.saveForensicCapture(db, rec);
          savedId = saved?.capture_id || rec.capture_id;
          sseHub.broadcast('forensic', { captureId: savedId, verdict: analysis.verdict });
        }
        const compact = compactAnalysis(analysis);
        sendJson(res, 200, {
          ok: true,
          analysis: compact,
          savedId,
        });
        return;
      }

      // Forensics: Active live probe (NEVER persist or log apiKey)
      if (method === 'POST' && pathname === '/api/forensics/probe') {
        const body = await readJsonBody(req);
        if (!body.baseUrl || !body.model) {
          sendProblem(res, 400, 'Bad Request', 'baseUrl and model are required');
          return;
        }
        const baseUrl = String(body.baseUrl).trim();
        try {
          assertSafeUpstreamUrl(baseUrl);
        } catch (err) {
          body.apiKey = '';
          sendProblem(res, err?.statusCode || 403, 'Blocked Upstream URL', err?.message || 'Blocked URL');
          return;
        }
        const settings = dbApi.getSettings(db);
        let probe;
        try {
          probe = await probeEndpoint({
            baseUrl,
            apiKey: body.apiKey ? String(body.apiKey) : '',
            endpointMode: body.endpointMode || 'responses',
            model: String(body.model).trim(),
            prompt: body.prompt,
            timeoutMs: Number(body.timeoutMs) || 30000,
            thinking: body.thinking,
            reasoningEffort: body.reasoningEffort,
            authStyle: body.authStyle,
            privacy: settings.privacyMask,
          });
        } finally {
          body.apiKey = '';
        }

        let savedId = null;
        let compact = null;
        if (probe.forensics) {
          compact = compactAnalysis(probe.forensics);
          if (body.save !== false) {
            const rec = toForensicRecord(probe.forensics, {
              source_tool: 'active-prober',
              base_url: probe.url,
              headers: probe.headers,
            });
            const saved = dbApi.saveForensicCapture(db, rec);
            savedId = saved?.capture_id || rec.capture_id;
            sseHub.broadcast('forensic', {
              captureId: savedId,
              verdict: probe.forensics.verdict,
            });
          }
        }

        sendJson(res, probe.ok ? 200 : 502, {
          ok: probe.ok,
          status: probe.status,
          statusText: probe.statusText,
          url: probe.url,
          httpHeaders: probe.headers,
          headers: probe.headers,
          capture: probe.capture,
          analysis: compact,
          savedId,
          error: probe.error || null,
        });
        return;
      }

      // Forensics: 1-Click External Speed Benchmark (LOOPBACK ONLY, NEVER persists apiKey)
      if (method === 'POST' && pathname === '/api/forensics/speedtest') {
        if (!loopback) {
          sendProblem(res, 403, 'Forbidden', 'Speed benchmark is restricted to loopback clients');
          return;
        }
        const body = await readJsonBody(req);
        if (!body.baseUrl || !body.model) {
          sendProblem(res, 400, 'Bad Request', 'baseUrl and model are required');
          return;
        }
        const baseUrl = String(body.baseUrl).trim();
        try {
          assertSafeUpstreamUrl(baseUrl, { rejectGoogleInternal: true });
        } catch (err) {
          body.apiKey = '';
          sendProblem(res, err?.statusCode || 403, 'Blocked Benchmark URL', err?.message || 'Blocked URL');
          return;
        }

        const runs = Math.min(3, Math.max(1, Math.round(Number(body.runs) || 2)));
        const endpointMode = ['responses', 'messages', 'chat_completions', 'gemini'].includes(
          body.endpointMode
        )
          ? body.endpointMode
          : 'chat_completions';
        const model = String(body.model).trim();
        const prompt = body.prompt || 'Reply in 12 words counting from 1 to 10.';
        const timeoutMs = Math.min(30000, Math.max(2000, Number(body.timeoutMs) || 20000));
        const settings = dbApi.getSettings(db);

        const samples = [];
        let lastOkProbe = null;
        let lastError = null;
        let apiKey = body.apiKey ? String(body.apiKey) : '';
        body.apiKey = '';

        try {
          for (let attempt = 0; attempt < runs; attempt++) {
            const p = await probeEndpoint({
              baseUrl,
              apiKey,
              endpointMode,
              model,
              prompt,
              maxOutputTokens: 16,
              timeoutMs,
              authStyle: body.authStyle || 'auto',
              privacy: settings.privacyMask,
            });
            const t = p.forensics?.timing || {};
            const ttftMs = t.ttftMs ?? t.ttfbMs ?? p.capture?.headersMs ?? null;
            samples.push({
              run: attempt + 1,
              ok: p.ok,
              status: p.status,
              ttftMs: roundMetric(ttftMs, 2),
              tpotMs: roundMetric(t.tpotMs, 2),
              tokPerSec: roundMetric(t.tokPerSec, 2),
              jitterMs: roundMetric(t.jitterMs, 2),
              totalMs: roundMetric(t.totalMs ?? p.capture?.totalMs, 2),
              error: p.error || null,
            });
            if (p.ok && p.forensics) {
              lastOkProbe = p;
            } else {
              lastError = p.error || `HTTP ${p.status || 502}`;
            }
          }
        } finally {
          apiKey = '';
          body.apiKey = '';
        }

        const okSamples = samples.filter((s) => s.ok);
        if (okSamples.length === 0 || !lastOkProbe) {
          sendJson(res, 502, {
            ok: false,
            error: lastError || 'Speed benchmark failed',
            runs: 0,
            samples,
          });
          return;
        }

        const ttfts = okSamples.map((s) => s.ttftMs).filter((n) => n !== null).sort((a, b) => a - b);
        const tpots = okSamples.map((s) => s.tpotMs).filter((n) => n !== null);
        const toks = okSamples.map((s) => s.tokPerSec).filter((n) => n !== null);
        const streamJitters = okSamples.map((s) => s.jitterMs).filter((n) => n !== null);
        const jitterVal =
          streamJitters.length > 0
            ? meanNums(streamJitters)
            : ttfts.length > 1
            ? stdDevNums(ttfts)
            : 0;

        const compact = compactAnalysis(lastOkProbe.forensics);
        sendJson(res, 200, {
          ok: true,
          ttftP50Ms: roundMetric(quantile(ttfts, 0.5), 2),
          ttftP95Ms: roundMetric(quantile(ttfts, 0.95), 2),
          tpotAvgMs: roundMetric(meanNums(tpots), 2),
          tokPerSecAvg: roundMetric(meanNums(toks), 2),
          jitterMs: roundMetric(jitterVal, 2),
          runs: okSamples.length,
          requestedRuns: runs,
          samples,
          lastCapture: {
            verdict: compact.verdict,
            authenticityScore: compact.authenticityScore,
            wireModel: compact.wireModel,
            analysis: compact,
          },
        });
        return;
      }

      // Forensics: History
      if (method === 'GET' && pathname === '/api/forensics/history') {
        const filters = parseFilters(reqUrl.searchParams);
        if (!loopback) filters.privacyMask = true;
        const result = dbApi.listForensicCaptures(db, filters);
        sendJson(res, 200, {
          captures: result.items,
          items: result.items,
          total: result.total,
        });
        return;
      }

      // Ingest webhook / manual push
      if (method === 'POST' && pathname === '/api/ingest') {
        const body = await readJsonBody(req);
        if (!body || typeof body !== 'object') {
          sendProblem(res, 400, 'Bad Request', 'Ingest body must be a JSON object or array');
          return;
        }
        const rawList = Array.isArray(body)
          ? body
          : Array.isArray(body.events)
          ? body.events
          : [body];
        const settings = dbApi.getSettings(db);
        const normalized = rawList.map((item) =>
          normalizeIngestEvent(item, { milestoneAt: settings.milestoneAt })
        );
        if (ingestLogPath) {
          appendIngestJsonl(normalized, ingestLogPath);
        }
        const batchRes = dbApi.insertRequestBatch(db, normalized);
        sseHub.broadcast('ingest', {
          inserted: batchRes.inserted,
          updated: batchRes.updated,
          total: batchRes.total,
        });
        sendJson(res, 200, {
          ok: true,
          ...batchRes,
        });
        return;
      }

      // Export CSV / JSON
      if (method === 'GET' && pathname === '/api/export') {
        const filters = parseFilters(reqUrl.searchParams);
        if (!loopback) filters.privacyMask = true;
        const format = String(reqUrl.searchParams.get('format') || 'json').toLowerCase() === 'csv'
          ? 'csv'
          : 'json';
        const payload = dbApi.exportData(db, filters, format);
        const contentType =
          format === 'csv' ? 'text/csv; charset=utf-8' : 'application/json; charset=utf-8';
        sendText(res, 200, payload, contentType, {
          'Content-Disposition': `attachment; filename="wiretok-export.${format}"`,
        });
        return;
      }

      // Static UI assets (GET / HEAD)
      if (method === 'GET' || method === 'HEAD') {
        if (serveStaticAsset(pathname, res, uiDir, method)) {
          return;
        }
      }

      if (pathname.startsWith('/api/')) {
        sendProblem(res, 404, 'Not Found', `Route not found: ${method} ${pathname}`);
        return;
      }

      sendText(res, 404, 'Not Found');
    } catch (err) {
      const status = Number.isInteger(err?.statusCode) ? err.statusCode : 500;
      if (status >= 500 || process.env.WIRETOK_DEBUG) {
        console.error('[wiretok:server:request]', err?.message || err);
      }
      const detail = status >= 500 ? 'Internal Server Error' : err?.message || 'Bad Request';
      sendProblem(res, status, status >= 500 ? 'Internal Server Error' : 'Bad Request', detail);
    }
  };

  // Dual-Bind setup: Sidecar port (required if set) + Standalone port 19840 (ignore EADDRINUSE if secondary)
  const sidecarPortEnv = Number(process.env.ANTIGRAVITY_SIDECAR_WEB_PORT || 0);
  const hasSidecarPort = Number.isInteger(sidecarPortEnv) && sidecarPortEnv > 0;
  const standalonePort = opts.port !== undefined ? Number(opts.port) : DEFAULT_WEB_PORT;

  const targets = [];
  if (hasSidecarPort) {
    targets.push({ port: sidecarPortEnv, allowInUse: false, label: 'sidecar' });
  }
  if (
    Number.isInteger(standalonePort) &&
    standalonePort >= 0 &&
    (!hasSidecarPort || standalonePort !== sidecarPortEnv)
  ) {
    const allowInUse = hasSidecarPort || Boolean(opts.sidecar) || Boolean(opts.allowInUse);
    targets.push({ port: standalonePort, allowInUse, label: 'standalone' });
  }

  const boundResults = [];
  const servers = [];

  for (const t of targets) {
    const srv = http.createServer(requestHandler);
    configureServerTimeouts(srv);
    try {
      const res = await listenOnPort(srv, t.port, host, { allowInUse: t.allowInUse });
      boundResults.push({ ...res, label: t.label });
      if (res.bound) {
        servers.push(srv);
      } else if (!opts.quiet) {
        console.error(
          `[wiretok] ${t.label} port ${host}:${t.port} already in use; continuing on primary port.`
        );
      }
    } catch (err) {
      for (const s of servers) {
        try {
          s.close();
          s.closeAllConnections?.();
        } catch (closeErr) {
          debugLog('bindRollback', closeErr);
        }
      }
      sseHub.closeAll();
      dbApi.closeDatabase(db);
      throw err;
    }
  }

  if (servers.length === 0) {
    sseHub.closeAll();
    dbApi.closeDatabase(db);
    throw new Error(`Unable to bind any HTTP port (${targets.map((t) => t.port).join(', ')})`);
  }

  // Optional startup LAN mode (`wiretok web --lan`)
  let initialLanStatus = null;
  if (opts.lan) {
    try {
      initialLanStatus = await enableLanMode({ requestedPort: opts.lanPort });
    } catch (err) {
      for (const s of servers) {
        try {
          s.close();
          s.closeAllConnections?.();
        } catch (closeErr) {
          debugLog('lanStartRollback', closeErr);
        }
      }
      sseHub.closeAll();
      dbApi.closeDatabase(db);
      throw err;
    }
  }

  // Non-blocking startup sync + FX refresh + debounced 6s loop
  if (opts.enableSyncLoop !== false) {
    const intervalMs = Number(opts.syncIntervalMs) || SYNC_INTERVAL_MS;
    scheduleSync(50);
    dbApi.syncUsdTry(db).catch((err) => debugLog('syncUsdTry', err));
    syncInterval = setInterval(() => {
      if (!syncPaused) executeSync().catch((err) => debugLog('intervalSync', err));
    }, intervalMs);
    if (typeof syncInterval.unref === 'function') syncInterval.unref();
  }

  async function close() {
    if (closed) return;
    closed = true;
    clearTimeout(syncDebounceTimer);
    clearInterval(syncInterval);
    await stopTee();
    await lanAuth.disable();
    sseHub.closeAll();
    await Promise.all(
      servers.map(
        (srv) =>
          new Promise((resolve) => {
            try {
              srv.close(() => resolve());
              srv.closeAllConnections?.();
            } catch (err) {
              debugLog('serverClose', err);
              resolve();
            }
          })
      )
    );
    dbApi.closeDatabase(db);
  }

  if (!opts.quiet) {
    for (const b of boundResults.filter((x) => x.bound)) {
      console.error(`[wiretok] ${b.label} listening on http://${b.host}:${b.port}`);
    }
    if (initialLanStatus) {
      console.error(
        `[wiretok] LAN QR mode enabled on 0.0.0.0:${initialLanStatus.port} | PIN: ${initialLanStatus.pin} | URL: ${initialLanStatus.lanUrl}`
      );
    }
  }

  return {
    db,
    servers,
    boundResults,
    ports: boundResults.filter((b) => b.bound).map((b) => b.port),
    sseHub,
    lanAuth,
    enableLan: enableLanMode,
    disableLan: () => lanAuth.disable(),
    syncNow: executeSync,
    close,
  };
}

function parseCliArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--port' && argv[i + 1]) out.port = Number(argv[++i]);
    else if (a === '--host' && argv[i + 1]) out.host = argv[++i];
    else if (a === '--db' && argv[i + 1]) out.dbPath = argv[++i];
    else if (a === '--sidecar') out.sidecar = true;
    else if (a === '--no-sync') out.enableSyncLoop = false;
    else if (a === '--quiet') out.quiet = true;
    else if (a === '--lan') out.lan = true;
    else if (a === '--lan-port' && argv[i + 1]) out.lanPort = Number(argv[++i]);
  }
  return out;
}

const isMain =
  process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;

if (isMain) {
  const args = parseCliArgs(process.argv.slice(2));
  let handle = null;
  try {
    handle = await startServer(args);
  } catch (err) {
    console.error(`[wiretok] failed to start server: ${err.message}`);
    process.exit(1);
  }

  let shuttingDown = false;
  const shutdown = async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    await handle.close();
    process.exit(0);
  };
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    process.on(sig, shutdown);
  }
}
