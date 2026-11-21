/**
 * Wiretok — Forensics unified export.
 *
 *   import { parseSse, analyzeForensics, probeEndpoint, createTeeProxy } from './src/forensics/index.mjs';
 */
export {
  PARSE_MODES,
  SseStreamParser,
  parseSse,
  framesFromInput,
  detectMode,
  detectFrameMode,
  normalizeUsage,
  summarizeAttribution,
  validateSignature,
} from './sse-parser.mjs';

export {
  ENGINE_VERSION,
  analyzeForensics,
  analyzeHeaders,
  extractSelfReport,
  modelFamily,
  toForensicRecord,
  toRequestEvent,
  compactAnalysis,
} from './fingerprint-engine.mjs';

export { probeEndpoint, buildProbeUrl, buildProbeBody, assertSafeUpstreamUrl, DEFAULT_PROBE_PROMPT } from './active-prober.mjs';

export { createTeeProxy, createDefaultStore, sanitizeHeaders, endpointModeFromPath, joinUpstream } from './tee-proxy.mjs';

import { analyzeForensics as _analyze } from './fingerprint-engine.mjs';

/**
 * Convenience: inspect a raw capture (string/chunks) and return the analysis.
 * @param {string|Array|object} raw
 * @param {{mode?: string, endpointMode?: string, claimedModel?: string, headers?: object, privacy?: boolean}} [opts]
 */
export function inspectSse(raw, opts = {}) {
  return _analyze(raw, { ...opts, mode: opts.mode || 'auto' });
}
