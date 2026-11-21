/**
 * Wiretok — Per-Request Cost, Cache Savings & Subscription Value Engine
 * Reports "API Liste Ederi" (api_list_cost_usd) and "Liste Ederi Çarpanı" (list_value_multiplier).
 */
import { SEED_MODELS, normalizeModelId } from '../contracts.mjs';

const SEED_MAP = new Map(SEED_MODELS.map((m) => [m.model_id, m]));

const FALLBACK_MODEL = {
  model_id: 'unknown',
  provider: 'unknown',
  display_name: 'Unknown Model',
  context_window: 1000000,
  input_per_1m: 2.0,
  output_per_1m: 10.0,
  cache_read_per_1m: 0.2,
  cache_write_per_1m: 2.5,
  reasoning_per_1m: 10.0,
  request_fee_usd: 0,
  credit_multiplier: 1.0,
};

function roundCost(n) {
  const v = Number(n);
  if (!Number.isFinite(v)) return 0;
  return Math.round(v * 1e8) / 1e8;
}

/**
 * Resolve model pricing record from passed row, DB map, or SEED_MODELS fallback.
 * @param {string} rawModel
 * @param {object|Map} [modelRowOrMap]
 */
export function resolveModelPricing(rawModel, modelRowOrMap) {
  const normId = normalizeModelId(rawModel);
  if (modelRowOrMap) {
    if (modelRowOrMap instanceof Map) {
      if (modelRowOrMap.has(normId)) return modelRowOrMap.get(normId);
      if (rawModel && modelRowOrMap.has(rawModel)) return modelRowOrMap.get(rawModel);
    } else if (typeof modelRowOrMap === 'object' && modelRowOrMap.input_per_1m !== undefined) {
      return modelRowOrMap;
    }
  }
  if (SEED_MAP.has(normId)) return SEED_MAP.get(normId);
  // Fuzzy prefix match against SEED_MODELS
  for (const m of SEED_MODELS) {
    if (normId.startsWith(m.model_id) || m.model_id.startsWith(normId)) {
      return m;
    }
  }
  return { ...FALLBACK_MODEL, model_id: normId };
}

/**
 * Compute token breakdown, API list cost, billed cost, and cache/compression savings for a single request event.
 * @param {object} event
 * @param {object} [modelRow]
 * @param {object} [accountRow]
 */
export function computeRequestCost(event = {}, modelRow = null, accountRow = null) {
  const model = resolveModelPricing(
    event.model_id || event.model_raw || event.model || modelRow?.model_id || 'unknown',
    modelRow
  );

  const inputTokens = Math.max(0, Math.round(Number(event.input_tokens ?? event.tokens_in ?? 0) || 0));
  const outputTokens = Math.max(0, Math.round(Number(event.output_tokens ?? event.tokens_out ?? 0) || 0));
  const cacheReadTokens = Math.max(
    0,
    Math.round(Number(event.cache_read_tokens ?? event.tokens_cache_read ?? event.cached_tokens ?? 0) || 0)
  );
  const cacheWriteTokens = Math.max(
    0,
    Math.round(Number(event.cache_write_tokens ?? event.tokens_cache_creation ?? 0) || 0)
  );
  const reasoningTokens = Math.max(
    0,
    Math.round(Number(event.reasoning_tokens ?? event.tokens_reasoning ?? 0) || 0)
  );
  const compressedTokens = Math.max(
    0,
    Math.round(Number(event.compressed_tokens ?? event.tokens_compressed ?? 0) || 0)
  );

  // Determine uncached input tokens
  let uncachedInputTokens;
  if (event.uncached_input_tokens !== undefined && event.uncached_input_tokens !== null) {
    uncachedInputTokens = Math.max(0, Math.round(Number(event.uncached_input_tokens) || 0));
  } else if (event.input_includes_cache === true) {
    uncachedInputTokens = Math.max(0, inputTokens - cacheReadTokens);
  } else {
    uncachedInputTokens = inputTokens;
  }

  const inputPer1M = Number(model.input_per_1m ?? 2.0);
  const outputPer1M = Number(model.output_per_1m ?? 10.0);
  const cacheReadPer1M = Number(model.cache_read_per_1m ?? inputPer1M * 0.1);
  const cacheWritePer1M = Number(model.cache_write_per_1m ?? inputPer1M * 1.25);
  const reasoningPer1M = Number(model.reasoning_per_1m ?? outputPer1M);
  const requestFeeUsd = roundCost(event.request_fee_usd ?? model.request_fee_usd ?? 0);
  const creditMultiplier = Number(event.credit_multiplier ?? model.credit_multiplier ?? 1.0);

  const inputCostUsd = (uncachedInputTokens / 1e6) * inputPer1M;
  const cacheReadCostUsd = (cacheReadTokens / 1e6) * cacheReadPer1M;
  const cacheWriteCostUsd = (cacheWriteTokens / 1e6) * cacheWritePer1M;
  const outputCostUsd = (outputTokens / 1e6) * outputPer1M;
  const reasoningCostUsd = event.reasoning_included_in_output
    ? 0
    : (reasoningTokens / 1e6) * reasoningPer1M;

  const tokenCostUsd = roundCost(
    inputCostUsd + cacheReadCostUsd + cacheWriteCostUsd + outputCostUsd + reasoningCostUsd
  );

  let toolSurchargeUsd = 0;
  if (event.tool_surcharge_usd !== undefined && event.tool_surcharge_usd !== null) {
    toolSurchargeUsd = roundCost(event.tool_surcharge_usd);
  } else if (event.tool_usage && typeof event.tool_usage === 'object') {
    const webSearchCalls = Number(event.tool_usage.web_search || 0);
    const imageGenCalls = Number(event.tool_usage.image_gen || 0);
    toolSurchargeUsd = roundCost(webSearchCalls * 0.01 + imageGenCalls * 0.04);
  }

  const apiListCostUsd = roundCost(tokenCostUsd + requestFeeUsd + toolSurchargeUsd);

  // Plan type resolution: subscription / free vs api
  const planType = event.plan_type || accountRow?.plan_type || 'api';
  const providerCostUsd =
    event.provider_cost_usd !== undefined && event.provider_cost_usd !== null
      ? roundCost(event.provider_cost_usd)
      : null;

  let billedCostUsd = 0;
  if (event.billed_cost_usd !== undefined && event.billed_cost_usd !== null) {
    billedCostUsd = roundCost(event.billed_cost_usd);
  } else if (planType === 'subscription' || planType === 'free') {
    billedCostUsd = 0;
  } else if (providerCostUsd !== null && providerCostUsd >= 0) {
    billedCostUsd = providerCostUsd;
  } else {
    billedCostUsd = apiListCostUsd;
  }

  const rateDiff = Math.max(0, inputPer1M - cacheReadPer1M);
  const cacheSavingsUsd = roundCost((cacheReadTokens * rateDiff) / 1e6);
  const compressionSavingsUsd = roundCost((compressedTokens * inputPer1M) / 1e6);

  const contextWindow = Number(event.context_window ?? model.context_window ?? 1000000) || 1000000;
  const contextTokens =
    event.context_tokens !== undefined && event.context_tokens !== null
      ? Math.max(0, Math.round(Number(event.context_tokens) || 0))
      : uncachedInputTokens + cacheReadTokens + cacheWriteTokens;
  const contextUtilization = contextWindow > 0 ? Math.min(1, contextTokens / contextWindow) : 0;

  return {
    model_id: model.model_id || normalizeModelId(event.model_id || event.model_raw || 'unknown'),
    provider: event.provider || model.provider || 'unknown',
    plan_type: planType,
    input_tokens: inputTokens,
    uncached_input_tokens: uncachedInputTokens,
    output_tokens: outputTokens,
    cache_read_tokens: cacheReadTokens,
    cache_write_tokens: cacheWriteTokens,
    reasoning_tokens: reasoningTokens,
    compressed_tokens: compressedTokens,
    context_tokens: contextTokens,
    context_window: contextWindow,
    context_utilization: Number(contextUtilization.toFixed(4)),
    token_cost_usd: tokenCostUsd,
    request_fee_usd: requestFeeUsd,
    tool_surcharge_usd: toolSurchargeUsd,
    api_list_cost_usd: apiListCostUsd,
    billed_cost_usd: billedCostUsd,
    provider_cost_usd: providerCostUsd,
    cache_savings_usd: cacheSavingsUsd,
    compression_savings_usd: compressionSavingsUsd,
    total_savings_usd: roundCost(cacheSavingsUsd + compressionSavingsUsd),
    credit_multiplier: creditMultiplier,
  };
}

/**
 * Compute subscription & API list value comparison metrics for an account.
 * Strictly reports "API Liste Ederi" and `list_value_multiplier`.
 * @param {number} apiListUsd
 * @param {object} [accountRow]
 */
export function computeAccountValueStats(apiListUsd = 0, accountRow = {}) {
  const cleanApiListUsd = roundCost(apiListUsd);
  const planType = accountRow?.plan_type || 'api';
  const subscriptionFeeUsd = roundCost(
    planType === 'subscription' ? Number(accountRow?.monthly_fee_usd ?? 0) : 0
  );
  const billedUsd = roundCost(accountRow?.billed_cost_usd ?? 0);

  let effectivePaidUsd = 0;
  if (planType === 'subscription') {
    effectivePaidUsd = subscriptionFeeUsd;
  } else if (planType === 'api') {
    effectivePaidUsd = billedUsd > 0 ? billedUsd : cleanApiListUsd;
  } else {
    effectivePaidUsd = 0;
  }

  const denominator = subscriptionFeeUsd > 0 ? subscriptionFeeUsd : effectivePaidUsd;
  const listValueMultiplier =
    denominator > 0 ? Number((cleanApiListUsd / denominator).toFixed(2)) : cleanApiListUsd > 0 ? null : 0;

  return {
    api_list_cost_usd: cleanApiListUsd,
    subscription_fee_usd: subscriptionFeeUsd,
    effective_paid_usd: effectivePaidUsd,
    list_value_multiplier: listValueMultiplier,
    plan_type: planType,
    label_tr: 'API Liste Ederi',
    multiplier_label_tr: 'Liste Ederi Çarpanı',
  };
}
