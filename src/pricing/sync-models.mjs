/**
 * Wiretok — Live Multi-Source Model Catalog Synchronizer
 * Fetches OpenRouter, LMSpeed (llms.txt), and TokenPricing (llms.txt) in parallel
 * with a 6-second timeout and safe offline fallback. Never overwrites `is_custom = 1` rows.
 */
import { SEED_MODELS, VERSION, normalizeModelId } from '../contracts.mjs';

const OPENROUTER_MODELS_URL = 'https://openrouter.ai/api/v1/models';
const LMSPEED_LLMS_URL = 'https://lmspeed.net/llms.txt';
const TOKENPRICING_LLMS_URL = 'https://tokenpricing.co/llms.txt';

function parseContextTokens(rawCtx) {
  if (!rawCtx) return null;
  if (typeof rawCtx === 'number' && Number.isFinite(rawCtx) && rawCtx > 0) {
    return Math.round(rawCtx);
  }
  const s = String(rawCtx).trim().toUpperCase();
  const m = s.match(/^([\d.]+)\s*([KM])?$/);
  if (!m) return null;
  const val = Number(m[1]);
  if (!Number.isFinite(val) || val <= 0) return null;
  if (m[2] === 'M') return Math.round(val * 1000000);
  if (m[2] === 'K') return Math.round(val * 1000);
  return Math.round(val);
}

/**
 * Parse LMSpeed `llms.txt` markdown index into normalized model entries.
 * @param {string|null} txt
 */
export function parseLmspeedTxt(txt) {
  if (!txt || typeof txt !== 'string') return [];
  const parsed = [];
  let currentMaker = 'unknown';

  for (const rawLine of txt.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.startsWith('### ')) {
      currentMaker = line.slice(4).trim().toLowerCase();
      continue;
    }
    const m = line.match(
      /^-\s+\[([^\]]+)\]\((https:\/\/lmspeed\.net\/model\/([^)]+?))(?:\.md)?\):\s*(.+)$/
    );
    if (!m || m[1].startsWith('Keyword:') || line.includes('published models classified')) {
      continue;
    }
    const [, displayName, , slug, desc] = m;
    const aaMatch = desc.match(/AA intelligence\s+([\d.]+)/i);
    const speedMatch = desc.match(/([\d.]+)\s*tok\/s/i);
    const ctxMatch = desc.match(/context\s+([\d.]+[KM])/i);
    const priceMatch = desc.match(/input\s+\$([\d.]+).*?\/\s*output\s+\$([\d.]+)/i);

    const inputPer1M = priceMatch ? Number(priceMatch[1]) : null;
    const outputPer1M = priceMatch ? Number(priceMatch[2]) : null;

    parsed.push({
      model_id: normalizeModelId(slug),
      provider: currentMaker.split(/[\s/]+/)[0] || 'unknown',
      display_name: displayName.trim(),
      context_window: parseContextTokens(ctxMatch ? ctxMatch[1] : null),
      input_per_1m: Number.isFinite(inputPer1M) && inputPer1M > 0 ? inputPer1M : null,
      output_per_1m: Number.isFinite(outputPer1M) && outputPer1M > 0 ? outputPer1M : null,
      aa_intelligence: aaMatch ? Number(aaMatch[1]) : null,
      speed_tok_s: speedMatch ? Number(speedMatch[1]) : null,
      source: 'lmspeed',
    });
  }
  return parsed;
}

/**
 * Parse TokenPricing `llms.txt` markdown index into normalized model entries.
 * @param {string|null} txt
 */
export function parseTokenPricingTxt(txt) {
  if (!txt || typeof txt !== 'string') return [];
  const parsed = [];
  let currentProvider = 'unknown';

  for (const rawLine of txt.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.startsWith('## ') || line.startsWith('### ')) {
      currentProvider = line.replace(/^#+\s*/, '').trim().toLowerCase();
      continue;
    }
    // Match markdown bullet or table rows containing $X / $Y or input $X output $Y
    const urlSlugMatch = line.match(
      /^[-*]\s+\[([^\]]+)\]\(https?:\/\/tokenpricing\.co\/([^/]+)\/([^)]+?)(?:\.md)?\):\s*(.+)$/
    );
    const bulletMatch =
      urlSlugMatch ||
      line.match(/^[-*]\s+(?:\[([^\]]+)\]\([^)]*\)|([A-Za-z0-9._\s-]+?))[:|-]\s*(.+)$/);
    if (!bulletMatch) continue;

    let name;
    let slug;
    let vendor;
    let rest;
    if (urlSlugMatch) {
      name = urlSlugMatch[1].trim();
      vendor = urlSlugMatch[2].trim().toLowerCase();
      slug = urlSlugMatch[3].trim().toLowerCase();
      rest = urlSlugMatch[4] || '';
    } else {
      name = (bulletMatch[1] || bulletMatch[2] || '').trim();
      vendor = currentProvider.split(/[\s/()]+/)[0] || 'unknown';
      slug = name;
      rest = bulletMatch[3] || '';
    }
    if (!name || name.length < 2 || name.toLowerCase() === 'all models') continue;

    const pricePair =
      rest.match(/input[:\s]+\$([\d.]+).*?output[:\s]+\$([\d.]+)/i) ||
      rest.match(/\$([\d.]+)\s*\/\s*\$([\d.]+)/);
    if (!pricePair) continue;

    const inPrice = Number(pricePair[1]);
    const outPrice = Number(pricePair[2]);
    if (!Number.isFinite(inPrice) || !Number.isFinite(outPrice) || inPrice <= 0) continue;

    const ctxMatch = rest.match(/([\d.]+[KM])\s*(?:context|ctx|tokens)?/i);
    parsed.push({
      model_id: normalizeModelId(slug),
      provider: vendor,
      display_name: name,
      context_window: parseContextTokens(ctxMatch ? ctxMatch[1] : null),
      input_per_1m: inPrice,
      output_per_1m: outPrice,
      source: 'tokenpricing',
    });
  }
  return parsed;
}

/**
 * Parse OpenRouter `/api/v1/models` JSON response into normalized model entries.
 * @param {object|null} json
 */
export function parseOpenRouterModels(json) {
  const list = Array.isArray(json?.data) ? json.data : [];
  const parsed = [];

  for (const item of list) {
    if (!item?.id) continue;
    const rawId = String(item.id);
    const provider = rawId.includes('/') ? rawId.split('/')[0].toLowerCase() : 'openrouter';
    const modelId = normalizeModelId(rawId);
    if (!modelId || modelId === 'unknown') continue;

    const pPrompt = Number(item.pricing?.prompt);
    const pCompletion = Number(item.pricing?.completion);
    const pCacheRead = Number(item.pricing?.input_cache_read);
    const pCacheWrite = Number(item.pricing?.input_cache_write);
    const pRequest = Number(item.pricing?.request);

    const inputPer1M =
      Number.isFinite(pPrompt) && pPrompt > 0 ? Number((pPrompt * 1e6).toFixed(4)) : null;
    const outputPer1M =
      Number.isFinite(pCompletion) && pCompletion > 0
        ? Number((pCompletion * 1e6).toFixed(4))
        : null;
    if (inputPer1M === null || outputPer1M === null) continue;

    const cacheReadPer1M =
      Number.isFinite(pCacheRead) && pCacheRead >= 0
        ? Number((pCacheRead * 1e6).toFixed(4))
        : Number((inputPer1M * 0.1).toFixed(4));
    const cacheWritePer1M =
      Number.isFinite(pCacheWrite) && pCacheWrite >= 0
        ? Number((pCacheWrite * 1e6).toFixed(4))
        : Number((inputPer1M * 1.25).toFixed(4));
    const requestFeeUsd =
      Number.isFinite(pRequest) && pRequest > 0 ? Number(pRequest.toFixed(6)) : 0;

    const releaseDate =
      item.created && Number.isFinite(Number(item.created))
        ? new Date(Number(item.created) * 1000).toISOString().slice(0, 10)
        : null;

    parsed.push({
      model_id: modelId,
      provider,
      display_name: item.name || rawId,
      context_window: parseContextTokens(item.context_length) || 1000000,
      input_per_1m: inputPer1M,
      output_per_1m: outputPer1M,
      cache_read_per_1m: cacheReadPer1M,
      cache_write_per_1m: cacheWritePer1M,
      reasoning_per_1m: outputPer1M,
      request_fee_usd: requestFeeUsd,
      release_date: releaseDate,
      source: 'openrouter',
    });
  }

  return parsed;
}

/**
 * Fetch OpenRouter, LMSpeed, and TokenPricing in parallel (6s timeout) and upsert into `models`.
 * Never overwrites rows marked `is_custom = 1`.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {{ timeoutMs?: number }} [opts]
 */
export async function syncLiveModels(db, opts = {}) {
  const timeoutMs = Number(opts.timeoutMs) || 6000;
  const headers = { 'User-Agent': `Wiretok/${VERSION}` };

  const [orRes, lmsRes, tpRes] = await Promise.allSettled([
    fetch(OPENROUTER_MODELS_URL, { headers, signal: AbortSignal.timeout(timeoutMs) }).then((r) =>
      r.ok ? r.json() : null
    ),
    fetch(LMSPEED_LLMS_URL, { headers, signal: AbortSignal.timeout(timeoutMs) }).then((r) =>
      r.ok ? r.text() : null
    ),
    fetch(TOKENPRICING_LLMS_URL, { headers, signal: AbortSignal.timeout(timeoutMs) }).then((r) =>
      r.ok ? r.text() : null
    ),
  ]);

  const orModels = orRes.status === 'fulfilled' ? parseOpenRouterModels(orRes.value) : [];
  const lmsModels = lmsRes.status === 'fulfilled' ? parseLmspeedTxt(lmsRes.value) : [];
  const tpModels = tpRes.status === 'fulfilled' ? parseTokenPricingTxt(tpRes.value) : [];

  // Merge catalog: start with SEED_MODELS baseline, then layer TokenPricing, OpenRouter, LMSpeed
  const mergedMap = new Map();

  for (const seed of SEED_MODELS) {
    mergedMap.set(seed.model_id, {
      ...seed,
      aa_intelligence: null,
      aa_coding: null,
      speed_tok_s: null,
      release_date: null,
      source: 'seed',
    });
  }

  const seedIds = new Set(SEED_MODELS.map((s) => s.model_id));

  for (const item of [...tpModels, ...orModels, ...lmsModels]) {
    if (!item?.model_id || item.model_id === 'unknown') continue;
    const existing = mergedMap.get(item.model_id);
    if (!existing) {
      const inRate = item.input_per_1m ?? 2.0;
      const outRate = item.output_per_1m ?? 10.0;
      mergedMap.set(item.model_id, {
        model_id: item.model_id,
        provider: item.provider || 'unknown',
        display_name: item.display_name || item.model_id,
        context_window: item.context_window || 1000000,
        input_per_1m: inRate,
        output_per_1m: outRate,
        cache_read_per_1m: item.cache_read_per_1m ?? Number((inRate * 0.1).toFixed(4)),
        cache_write_per_1m: item.cache_write_per_1m ?? Number((inRate * 1.25).toFixed(4)),
        reasoning_per_1m: item.reasoning_per_1m ?? outRate,
        request_fee_usd: item.request_fee_usd ?? 0,
        credit_multiplier: 1.0,
        aa_intelligence: item.aa_intelligence ?? null,
        aa_coding: item.aa_coding ?? null,
        speed_tok_s: item.speed_tok_s ?? null,
        release_date: item.release_date ?? null,
        source: item.source || 'live',
      });
    } else {
      // Keep official seed API list pricing if item is from tokenpricing minimum-offer feed
      const isSeedAndTp = seedIds.has(item.model_id) && item.source === 'tokenpricing';
      const inRate = isSeedAndTp ? existing.input_per_1m : item.input_per_1m ?? existing.input_per_1m;
      const outRate = isSeedAndTp ? existing.output_per_1m : item.output_per_1m ?? existing.output_per_1m;
      mergedMap.set(item.model_id, {
        ...existing,
        provider:
          existing.provider && existing.provider !== 'unknown'
            ? existing.provider
            : item.provider || 'unknown',
        display_name: existing.display_name || item.display_name || item.model_id,
        context_window: item.context_window || existing.context_window || 1000000,
        input_per_1m: inRate,
        output_per_1m: outRate,
        cache_read_per_1m: isSeedAndTp
          ? existing.cache_read_per_1m
          : item.cache_read_per_1m ??
            existing.cache_read_per_1m ??
            Number((inRate * 0.1).toFixed(4)),
        cache_write_per_1m: isSeedAndTp
          ? existing.cache_write_per_1m
          : item.cache_write_per_1m ??
            existing.cache_write_per_1m ??
            Number((inRate * 1.25).toFixed(4)),
        reasoning_per_1m: isSeedAndTp
          ? existing.reasoning_per_1m
          : item.reasoning_per_1m ?? existing.reasoning_per_1m ?? outRate,
        aa_intelligence: item.aa_intelligence ?? existing.aa_intelligence ?? null,
        speed_tok_s: item.speed_tok_s ?? existing.speed_tok_s ?? null,
        release_date: item.release_date ?? existing.release_date ?? null,
        source: existing.source.includes(item.source)
          ? existing.source
          : `${existing.source}+${item.source}`,
      });
    }
  }

  const now = new Date().toISOString();
  let upsertedCount = 0;

  if (db) {
    // Never overwrite rows where is_custom = 1
    const upsertStmt = db.prepare(`
      INSERT INTO models (
        model_id,
        provider,
        display_name,
        context_window,
        input_per_1m,
        output_per_1m,
        cache_read_per_1m,
        cache_write_per_1m,
        reasoning_per_1m,
        request_fee_usd,
        credit_multiplier,
        aa_intelligence,
        aa_coding,
        speed_tok_s,
        release_date,
        source,
        is_custom,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
      ON CONFLICT(model_id) DO UPDATE SET
        provider = excluded.provider,
        display_name = excluded.display_name,
        context_window = excluded.context_window,
        input_per_1m = excluded.input_per_1m,
        output_per_1m = excluded.output_per_1m,
        cache_read_per_1m = excluded.cache_read_per_1m,
        cache_write_per_1m = excluded.cache_write_per_1m,
        reasoning_per_1m = excluded.reasoning_per_1m,
        aa_intelligence = COALESCE(excluded.aa_intelligence, models.aa_intelligence),
        speed_tok_s = COALESCE(excluded.speed_tok_s, models.speed_tok_s),
        release_date = COALESCE(excluded.release_date, models.release_date),
        source = excluded.source,
        updated_at = excluded.updated_at
      WHERE models.is_custom = 0
    `);

    const metaStmt = db.prepare(`
      INSERT INTO meta (key, value, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
    `);

    db.exec('BEGIN');
    try {
      for (const m of mergedMap.values()) {
        const res = upsertStmt.run(
          m.model_id,
          m.provider || 'unknown',
          m.display_name || m.model_id,
          m.context_window || 1000000,
          m.input_per_1m ?? 2.0,
          m.output_per_1m ?? 10.0,
          m.cache_read_per_1m ?? 0.2,
          m.cache_write_per_1m ?? 2.5,
          m.reasoning_per_1m ?? m.output_per_1m ?? 10.0,
          m.request_fee_usd ?? 0,
          m.credit_multiplier ?? 1.0,
          m.aa_intelligence ?? null,
          m.aa_coding ?? null,
          m.speed_tok_s ?? null,
          m.release_date ?? null,
          m.source || 'seed',
          now
        );
        if (res.changes > 0) upsertedCount += 1;
      }
      metaStmt.run('models_synced_at', now, now);
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  }

  const totalRow = db
    ? db.prepare(`SELECT COUNT(*) AS cnt FROM models`).get()
    : { cnt: mergedMap.size };

  return {
    ok: true,
    syncedAt: now,
    sourcesReached: {
      openrouter: orModels.length,
      lmspeed: lmsModels.length,
      tokenpricing: tpModels.length,
    },
    upsertedCount,
    totalModels: Number(totalRow?.cnt ?? mergedMap.size),
  };
}
