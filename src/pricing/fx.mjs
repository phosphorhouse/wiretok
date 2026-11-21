/**
 * Wiretok — USD/TRY Foreign Exchange Sync (6-hour SQLite Meta Cache + Safe Offline Fallback)
 */
import { DEFAULT_FX_USD_TRY, VERSION } from '../contracts.mjs';

const FX_CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours
const FX_API_URL = 'https://open.er-api.com/v6/latest/USD';

function debugLog(context, err) {
  if (process.env.WIRETOK_DEBUG) {
    process.stderr.write(`[wiretok] ${context}: ${err?.message || err}\n`);
  }
}

/**
 * Synchronously read current USD/TRY exchange rate from SQLite `meta`.
 * @param {import('node:sqlite').DatabaseSync} db
 * @returns {number}
 */
export function getUsdTry(db) {
  if (!db) return DEFAULT_FX_USD_TRY;
  try {
    const row = db.prepare(`SELECT value FROM meta WHERE key = ? LIMIT 1`).get('fx_usd_try');
    const parsed = Number(row?.value);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_FX_USD_TRY;
  } catch (err) {
    debugLog('getUsdTry', err);
    return DEFAULT_FX_USD_TRY;
  }
}

/**
 * Fetch and cache live USD/TRY rate from open.er-api.com (cached 6h in `meta`).
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {{ force?: boolean, timeoutMs?: number }} [opts]
 * @returns {Promise<{ rate: number, source: 'cache'|'live'|'fallback', updatedAt: string }>}
 */
export async function syncUsdTry(db, opts = {}) {
  const force = Boolean(opts.force);
  const timeoutMs = Number(opts.timeoutMs) || 6000;
  const currentRate = getUsdTry(db);

  if (db && !force) {
    try {
      const updatedRow = db
        .prepare(`SELECT value FROM meta WHERE key = ? LIMIT 1`)
        .get('fx_updated_at');
      if (updatedRow?.value) {
        const elapsed = Date.now() - Date.parse(updatedRow.value);
        if (Number.isFinite(elapsed) && elapsed >= 0 && elapsed < FX_CACHE_TTL_MS) {
          return {
            rate: currentRate,
            source: 'cache',
            updatedAt: updatedRow.value,
          };
        }
      }
    } catch (err) {
      debugLog('syncUsdTry.cacheRead', err);
    }
  }

  try {
    const res = await fetch(FX_API_URL, {
      headers: { 'User-Agent': `Wiretok/${VERSION}` },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (res.ok) {
      const data = await res.json();
      const liveTry = Number(data?.rates?.TRY);
      if (Number.isFinite(liveTry) && liveTry > 1) {
        const rounded = Number(liveTry.toFixed(4));
        const now = new Date().toISOString();
        if (db) {
          const upsertStmt = db.prepare(`
            INSERT INTO meta (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
          `);
          upsertStmt.run('fx_usd_try', String(rounded), now);
          upsertStmt.run('fx_updated_at', now, now);
        }
        return {
          rate: rounded,
          source: 'live',
          updatedAt: now,
        };
      }
    }
  } catch (err) {
    debugLog('syncUsdTry.fetch', err);
  }

  const fallbackNow = new Date().toISOString();
  return {
    rate: currentRate || DEFAULT_FX_USD_TRY,
    source: 'fallback',
    updatedAt: fallbackNow,
  };
}
