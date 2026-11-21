#!/usr/bin/env node
/**
 * Wiretok CLI (`bin/wiretok.mjs`)
 * Full terminal interface + JSON mode (`--json`) for AI agents, skills, and developers.
 */
import fs from 'node:fs';
import path from 'node:path';
import {
  DEFAULT_FX_USD_TRY,
  DEFAULT_TEE_PORT,
  DEFAULT_WEB_PORT,
  VERSION,
} from '../src/contracts.mjs';
import * as dbApi from '../src/db/index.mjs';
import { runSyncAll } from '../src/collectors/index.mjs';
import {
  analyzeForensics,
  compactAnalysis,
  createTeeProxy,
  probeEndpoint,
  toForensicRecord,
} from '../src/forensics/index.mjs';
import {
  configureIntegration,
  getIntegrationStatusLive,
} from '../src/integrations/integrator.mjs';
import { DEFAULT_LAN_PORT } from '../src/server/lan-auth.mjs';
import { startServer } from '../src/server/server.mjs';

const BOOLEAN_FLAGS = new Set([
  'json',
  'all',
  'apply',
  'force',
  'save',
  'no-save',
  'oneliner',
  'dry-run',
  'reset-cursors',
  'no-sync',
  'help',
  'lan',
  'list',
  'set',
  'version',
]);

function debugLog(context, err) {
  if (process.env.WIRETOK_DEBUG) {
    console.error(`[wiretok:cli:${context}]`, err?.message || err);
  }
}

function parseArgs(argv) {
  const positionals = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--') {
      positionals.push(...argv.slice(i + 1));
      break;
    }
    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=');
      if (eq !== -1) {
        flags[arg.slice(2, eq)] = arg.slice(eq + 1);
      } else {
        const key = arg.slice(2);
        const next = argv[i + 1];
        if (
          next !== undefined &&
          !next.startsWith('--') &&
          !BOOLEAN_FLAGS.has(key)
        ) {
          flags[key] = next;
          i += 1;
        } else {
          flags[key] = true;
        }
      }
    } else if (arg === '-h') {
      flags.help = true;
    } else if (arg === '-v') {
      flags.version = true;
    } else {
      positionals.push(arg);
    }
  }
  return { command: positionals[0] || 'status', args: positionals.slice(1), flags };
}

function fmtNum(val, decimals = 0) {
  const n = Number(val);
  if (!Number.isFinite(n)) return '—';
  return n.toLocaleString('en-US', {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  });
}

function fmtTok(val) {
  const n = Number(val);
  if (!Number.isFinite(n)) return '—';
  const a = Math.abs(n);
  if (a >= 1e9) return `${(n / 1e9).toFixed(2)}B`;
  if (a >= 1e6) return `${(n / 1e6).toFixed(2)}M`;
  if (a >= 1e3) return `${(n / 1e3).toFixed(1)}K`;
  return String(Math.round(n));
}

function fmtUsd(val, fx = DEFAULT_FX_USD_TRY, withTry = false) {
  const n = Number(val);
  if (!Number.isFinite(n)) return '—';
  const decimals = Math.abs(n) > 0 && Math.abs(n) < 0.05 ? 4 : 2;
  const usdStr = `$${n.toFixed(decimals)}`;
  if (!withTry) return usdStr;
  const tryVal = n * (Number(fx) || DEFAULT_FX_USD_TRY);
  return `${usdStr} (₺${tryVal.toFixed(2)})`;
}

function pad(str, width, alignRight = false) {
  const s = String(str ?? '');
  if (s.length >= width) return s.slice(0, width);
  const fill = ' '.repeat(width - s.length);
  return alignRight ? fill + s : s + fill;
}

function printTable(columns, rows) {
  if (!rows.length) {
    console.log('(no rows)');
    return;
  }
  const widths = columns.map((col) =>
    Math.max(
      col.label.length,
      ...rows.map((r) => String(col.get(r) ?? '').length)
    )
  );
  const header = columns.map((c, i) => pad(c.label, widths[i], c.right)).join('  ');
  const sep = widths.map((w) => '-'.repeat(w)).join('  ');
  console.log(header);
  console.log(sep);
  for (const r of rows) {
    console.log(columns.map((c, i) => pad(c.get(r), widths[i], c.right)).join('  '));
  }
}

function readStdinSyncSafe() {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) return resolve('');
    const chunks = [];
    process.stdin.on('data', (c) => chunks.push(c));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', (err) => {
      debugLog('stdin', err);
      resolve('');
    });
  });
}

function printHelp() {
  console.log(`Wiretok CLI v${VERSION} — Context, Token, Cache, Cost & SSE Forensics

Usage:
  wiretok <command> [options]

Commands:
  init           One-shot auto-detect local tools, initial sync & setup summary (--apply optional)
  status         Overview KPIs, costs, cache hit %, and active context (--oneliner supported)
  today          Today's token usage and API list value
  accounts       Per-account tokens, cache %, API list value, subscription fee, multiplier, quotas
  models         Model pricing catalog ($/1M, $/req, credit multiplier) and usage
  requests       Request log with per-request cost, context %, TTFT, TPOT, tok/s
  sessions       Active & historical sessions + Swarm cost trees
  live           Active context occupancy monitor (/compact warnings at >=65% and >=80%)
  quota          List or upsert quota snapshots (--list | --set --account <id> ...)
  sync           Incremental read-only sync across Antigravity, OmniRoute, Claude, Codex, OpenCode, 9Router
  sync-models    Fetch live model prices (OpenRouter, LMSpeed, TokenPricing) & USD/TRY FX
  retag          Assign historical/unattributed requests to an account
  inspect-sse    Analyze raw SSE capture file (or '-' for stdin)
  probe          Live endpoint fingerprint probe (API key via --key-env <ENV>)
  tee-proxy      Start local transparent SSE tee proxy (default :${DEFAULT_TEE_PORT})
  integrate      Check or configure tool integration (claude|codex|opencode|9router|omniroute|tee-proxy)
  export         Export requests/summary as CSV or JSON
  web            Start HTTP + SSE dashboard server (default :${DEFAULT_WEB_PORT}, opt-in --lan [--lan-port ${DEFAULT_LAN_PORT}])

Common Flags:
  --json                 Output machine-readable JSON
  --era <live|all>       Filter by post-milestone live era or all history
  --from <ISO/date>      Filter start timestamp
  --to <ISO/date>        Filter end timestamp
  --account <id>         Filter or target account ID
  --model <id>           Filter or probe model ID
  --source <tool>        Filter by source tool
  -v, --version          Print CLI version (${VERSION})
`);
}

function buildFilterOpts(flags) {
  return {
    era: flags.era || 'live',
    from: flags.from,
    to: flags.to,
    accountId: flags.account || flags.accountId,
    modelId: flags.model || flags.modelId,
    sourceTool: flags.source || flags.sourceTool,
    workspace: flags.workspace,
    q: flags.q,
    limit: flags.limit ? Number(flags.limit) : undefined,
    offset: flags.offset ? Number(flags.offset) : undefined,
    sort: flags.sort,
    dir: flags.dir,
  };
}

function upsertQuotasViaApi(db, items) {
  if (typeof dbApi.upsertQuotaSnapshots === 'function') {
    return dbApi.upsertQuotaSnapshots(db, items);
  }
  db.exec('BEGIN');
  try {
    for (const item of items) {
      dbApi.upsertQuotaSnapshot(db, item);
    }
    db.exec('COMMIT');
    return { upserted: items.length };
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

function queryQuotaSnapshots(db, flags) {
  const clauses = [];
  const params = [];
  if (flags.source || flags.sourceTool) {
    clauses.push('source_tool = ?');
    params.push(String(flags.source || flags.sourceTool));
  }
  if (flags.account || flags.accountId) {
    clauses.push('account_id = ?');
    params.push(String(flags.account || flags.accountId));
  }
  if (flags.model || flags.modelId) {
    clauses.push('(model_id = ? OR tier_or_model = ?)');
    const m = String(flags.model || flags.modelId);
    params.push(m, m);
  }
  const whereSql = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  const limit = Math.min(100, Math.max(1, Number(flags.limit) || 50));
  params.push(limit);
  return db
    .prepare(
      `SELECT quota_id, captured_at, source_tool, account_id, provider, model_id, tier_or_model,
              window_key, tokens_used, token_limit, limit_requests, remaining_requests,
              limit_tokens, remaining_tokens, remaining_pct, used_percent,
              window_start, window_reset, reset_at, is_exhausted, status, updated_at
       FROM quota_snapshots
       ${whereSql}
       ORDER BY updated_at DESC, captured_at DESC
       LIMIT ?`
    )
    .all(...params);
}

async function main() {
  const { command, args, flags } = parseArgs(process.argv.slice(2));
  if (flags.version) {
    console.log(VERSION);
    return;
  }
  if (flags.help || command === 'help') {
    printHelp();
    return;
  }

  const jsonMode = Boolean(flags.json);
  const db = dbApi.openDatabase(flags.db);

  try {
    switch (command) {
      case 'init': {
        const settings = dbApi.getSettings(db);
        const syncRes = await runSyncAll(db, {
          milestoneAt: settings.milestoneAt,
          dryRun: Boolean(flags['dry-run']),
        });
        const integrations = await getIntegrationStatusLive();
        const appliedIntegrations = [];
        if (flags.apply) {
          for (const toolInfo of integrations) {
            if (toolInfo.apply_supported && toolInfo.detected && toolInfo.status === 'available') {
              const res = configureIntegration(toolInfo.tool, {
                apply: true,
                force: Boolean(flags.force),
              });
              appliedIntegrations.push(res);
            }
          }
        }
        const ov = dbApi.getOverview(db, { era: flags.era || 'all' });
        const summary = {
          ok: true,
          version: VERSION,
          privacyMask: settings.privacyMask,
          milestoneAt: settings.milestoneAt,
          sync: {
            durationMs: syncRes.durationMs,
            syncedCounts: syncRes.syncedCounts,
            quotaRows: syncRes.quotaRows || 0,
            errors: syncRes.errors || [],
          },
          integrations: integrations.map((i) => ({
            tool: i.tool,
            label: i.label,
            detected: i.detected,
            configured: i.configured,
            status: i.status,
          })),
          appliedIntegrations,
          kpis: ov.kpis,
        };
        if (jsonMode) {
          console.log(JSON.stringify(summary, null, 2));
          break;
        }
        console.log(`=== Wiretok v${VERSION} Init ===`);
        console.log(`Privacy Mask:  ${settings.privacyMask ? 'ON (masked)' : 'OFF'}`);
        console.log(`Milestone:     ${settings.milestoneAt}`);
        console.log(`Synced (${syncRes.durationMs}ms):`);
        for (const [src, cnt] of Object.entries(syncRes.syncedCounts || {})) {
          console.log(`  ${pad(src, 16)} ${fmtNum(cnt)} new`);
        }
        console.log('Detected Tools:');
        for (const i of integrations) {
          console.log(`  ${pad(i.tool, 16)} detected=${i.detected ? 'yes' : 'no'} status=${i.status}`);
        }
        if (appliedIntegrations.length) {
          console.log(`Applied ${appliedIntegrations.length} integration(s).`);
        }
        console.log(`Next: run "wiretok web" (http://127.0.0.1:${DEFAULT_WEB_PORT}) or "wiretok web --lan" for mobile QR.`);
        break;
      }

      case 'status': {
        const era = flags.era || 'live';
        const ov = dbApi.getOverview(db, buildFilterOpts({ ...flags, era }));
        const fx = ov.fxUsdTry || DEFAULT_FX_USD_TRY;
        if (flags.oneliner) {
          const activeList = ov.activeSessions || ov.activeContextSessions || [];
          const active = activeList.find(
            (s) => (s.latest_context_tokens || s.peak_context_tokens || 0) > 0
          );
          const ctxPct = active ? `${Number(active.utilization_pct || 0).toFixed(0)}%` : '0%';
          const k = ov.kpis;
          console.log(
            `Wiretok(${era}): ${fmtTok(k.totalTokens)} tok | ${fmtUsd(k.apiListCostUsd, fx, true)} | Ctx ${ctxPct} | Cache ${k.cacheHitPct}%`
          );
          break;
        }
        if (jsonMode) {
          console.log(JSON.stringify({ version: VERSION, era, ...ov }, null, 2));
          break;
        }
        const k = ov.kpis;
        const pr = ov.perRequestStats;
        console.log(`=== Wiretok v${VERSION} Status [era=${era}] ===`);
        console.log(`Milestone:             ${ov.milestoneAt}`);
        console.log(`FX Rate (USD/TRY):     1 USD = ${fx} TRY`);
        console.log(`Requests:              ${fmtNum(k.totalRequests)}`);
        console.log(
          `Tokens:                ${fmtTok(k.totalTokens)} (in ${fmtTok(k.inputTokens)} | cache_read ${fmtTok(k.cacheReadTokens)} | cache_write ${fmtTok(k.cacheWriteTokens)} | out ${fmtTok(k.outputTokens)} | reason ${fmtTok(k.reasoningTokens)})`
        );
        console.log(`Cache Hit Ratio:       ${k.cacheHitPct}%`);
        console.log(`API Liste Ederi:       ${fmtUsd(k.apiListCostUsd, fx, true)}`);
        console.log(`Effective Paid:        ${fmtUsd(k.effectivePaidUsd, fx, true)} (sub ${fmtUsd(k.subscriptionFeesUsd)} + api ${fmtUsd(k.billedCostUsd)})`);
        console.log(`Liste Ederi Carpani:   ${k.listValueMultiplier !== null ? `${k.listValueMultiplier}x` : '—'}`);
        console.log(`Cache + RTK Savings:   ${fmtUsd(k.totalSavingsUsd, fx, true)}`);
        console.log(
          `Per-Request Cost:      avg ${fmtUsd(pr.avg)} | p50 ${fmtUsd(pr.p50)} | p95 ${fmtUsd(pr.p95)} | max ${fmtUsd(pr.max)}`
        );
        if (k.avgTtftMs !== null || k.avgTokPerSec !== null) {
          console.log(
            `Speed:                 avg TTFT ${k.avgTtftMs ?? '—'} ms | avg ${k.avgTokPerSec ?? '—'} tok/s`
          );
        }
        const liveList = ov.activeSessions || ov.activeContextSessions || [];
        if (liveList.length) {
          const top = liveList[0];
          console.log(
            `Latest Active Context: ${top.source_tool} ${fmtTok(top.latest_context_tokens)}/${fmtTok(top.context_window)} (${top.utilization_pct}%) [${top.warning_level}]`
          );
        }
        break;
      }

      case 'today': {
        const start = new Date();
        start.setHours(0, 0, 0, 0);
        const fromIso = start.toISOString();
        const ov = dbApi.getOverview(db, {
          ...buildFilterOpts({ ...flags, era: flags.era || 'all' }),
          from: fromIso,
        });
        if (jsonMode) {
          console.log(JSON.stringify({ version: VERSION, from: fromIso, ...ov }, null, 2));
          break;
        }
        const k = ov.kpis;
        const fx = ov.fxUsdTry || DEFAULT_FX_USD_TRY;
        console.log(`=== Wiretok Today (since ${fromIso}) ===`);
        console.log(`Requests:        ${fmtNum(k.totalRequests)}`);
        console.log(`Total Tokens:    ${fmtTok(k.totalTokens)} (Cache Hit ${k.cacheHitPct}%)`);
        console.log(`API Liste Ederi: ${fmtUsd(k.apiListCostUsd, fx, true)}`);
        console.log(`Cache Savings:   ${fmtUsd(k.totalSavingsUsd, fx, true)}`);
        console.log(`Avg $/Request:   ${fmtUsd(k.avgCostPerRequestUsd)}`);
        break;
      }

      case 'accounts': {
        const era = flags.era || 'live';
        const settings = dbApi.getSettings(db);
        const accounts = dbApi.listAccounts(db, buildFilterOpts({ ...flags, era }));
        if (jsonMode) {
          console.log(
            JSON.stringify(
              { era, fxUsdTry: settings.fxUsdTry, privacyMask: settings.privacyMask, accounts },
              null,
              2
            )
          );
          break;
        }
        printTable(
          [
            { label: 'Account', get: (a) => a.email_or_label || a.account_id },
            { label: 'Tool', get: (a) => a.source_tool },
            { label: 'Plan', get: (a) => a.plan_type },
            { label: 'Reqs', right: true, get: (a) => fmtNum(a.requests) },
            { label: 'Tokens', right: true, get: (a) => fmtTok(a.total_tokens) },
            { label: 'Cache%', right: true, get: (a) => `${a.cache_hit_pct ?? 0}%` },
            { label: 'API List', right: true, get: (a) => fmtUsd(a.api_list_cost_usd) },
            { label: 'Fee', right: true, get: (a) => fmtUsd(a.subscription_fee_usd) },
            { label: 'Mult', right: true, get: (a) => (a.list_value_multiplier != null ? `${a.list_value_multiplier}x` : '—') },
            { label: 'Avg$/Req', right: true, get: (a) => fmtUsd(a.avg_cost_per_request_usd) },
          ],
          accounts
        );
        break;
      }

      case 'models': {
        const settings = dbApi.getSettings(db);
        const modelFilters = buildFilterOpts({ ...flags, era: flags.era || 'all' });
        let models = dbApi.listModels(db, modelFilters);
        if (flags.q) {
          const needle = String(flags.q).toLowerCase();
          models = models.filter((m) =>
            `${m.model_id} ${m.display_name} ${m.provider}`.toLowerCase().includes(needle)
          );
        }
        if (jsonMode) {
          console.log(JSON.stringify({ fxUsdTry: settings.fxUsdTry, models }, null, 2));
          break;
        }
        printTable(
          [
            { label: 'Model', get: (m) => m.model_id },
            { label: 'Provider', get: (m) => m.provider },
            { label: 'Ctx', right: true, get: (m) => fmtTok(m.context_window) },
            { label: 'In/1M', right: true, get: (m) => `$${m.input_per_1m}` },
            { label: 'Out/1M', right: true, get: (m) => `$${m.output_per_1m}` },
            { label: 'CR/1M', right: true, get: (m) => `$${m.cache_read_per_1m}` },
            { label: 'Reqs', right: true, get: (m) => fmtNum(m.requests) },
            { label: 'API List', right: true, get: (m) => fmtUsd(m.api_list_cost_usd) },
            { label: 'Custom', get: (m) => (m.is_custom ? 'yes' : m.source) },
          ],
          models.slice(0, Number(flags.limit) || 60)
        );
        break;
      }

      case 'requests': {
        const filters = buildFilterOpts({ ...flags, era: flags.era || 'live', limit: flags.limit || 25 });
        const res = dbApi.listRequests(db, filters);
        if (jsonMode) {
          console.log(JSON.stringify(res, null, 2));
          break;
        }
        printTable(
          [
            { label: 'Created', get: (r) => String(r.created_at || '').slice(0, 19).replace('T', ' ') },
            { label: 'Tool', get: (r) => r.source_tool },
            { label: 'Model', get: (r) => r.model_id },
            { label: 'In', right: true, get: (r) => fmtTok(r.input_tokens) },
            { label: 'CR', right: true, get: (r) => fmtTok(r.cache_read_tokens) },
            { label: 'Out', right: true, get: (r) => fmtTok(r.output_tokens) },
            { label: 'Ctx%', right: true, get: (r) => `${r.context_pct ?? 0}%` },
            { label: 'TTFT', right: true, get: (r) => (r.ttft_ms != null ? `${Math.round(r.ttft_ms)}ms` : '—') },
            { label: 'API List', right: true, get: (r) => fmtUsd(r.api_list_cost_usd) },
          ],
          res.items
        );
        console.log(`Showing ${res.items.length} of ${res.total} requests.`);
        break;
      }

      case 'sessions': {
        const filters = buildFilterOpts({ ...flags, era: flags.era || 'live', limit: flags.limit || 25 });
        const res = dbApi.listSessions(db, filters);
        const trees = dbApi.getSwarmTrees(db, filters);
        if (jsonMode) {
          console.log(JSON.stringify({ ...res, swarmTrees: trees }, null, 2));
          break;
        }
        printTable(
          [
            { label: 'Last Event', get: (s) => String(s.last_event_at || '').slice(0, 19).replace('T', ' ') },
            { label: 'Tool', get: (s) => s.source_tool },
            { label: 'Title', get: (s) => String(s.title || s.session_id).slice(0, 32) },
            { label: 'Reqs', right: true, get: (s) => fmtNum(s.total_requests) },
            { label: 'Ctx', right: true, get: (s) => `${fmtTok(s.latest_context_tokens)}/${fmtTok(s.context_window)}` },
            { label: 'Ctx%', right: true, get: (s) => `${s.utilization_pct}%` },
            { label: 'API List', right: true, get: (s) => fmtUsd(s.total_api_list_cost_usd) },
          ],
          res.items
        );
        break;
      }

      case 'live': {
        let active;
        let recent = [];
        if (typeof dbApi.getLiveContext === 'function') {
          const live = dbApi.getLiveContext(db, { era: 'all', limit: Number(flags.limit) || 20 });
          active = live.activeSessions || live.sessions || [];
          recent = live.recentSessions || [];
        } else {
          const res = dbApi.listSessions(db, { era: 'all', limit: Number(flags.limit) || 20 });
          active = res.items.filter(
            (s) =>
              Number(s.killed || 0) === 0 &&
              (s.latest_context_tokens || s.peak_context_tokens || 0) > 0
          );
        }
        if (jsonMode) {
          console.log(
            JSON.stringify(
              { sessions: active, activeSessions: active, recentSessions: recent, updatedAt: new Date().toISOString() },
              null,
              2
            )
          );
          break;
        }
        printTable(
          [
            { label: 'Session', get: (s) => String(s.title || s.session_id).slice(0, 30) },
            { label: 'Tool', get: (s) => s.source_tool },
            { label: 'Model', get: (s) => s.primary_model_id || 'unknown' },
            { label: 'Occupancy', right: true, get: (s) => `${fmtTok(s.latest_context_tokens)}/${fmtTok(s.context_window)}` },
            { label: 'Ctx%', right: true, get: (s) => `${s.utilization_pct}%` },
            { label: 'Cache%', right: true, get: (s) => `${s.cache_hit_pct}%` },
            { label: 'Alert', get: (s) => (s.utilization_pct >= 80 ? 'CRITICAL (/compact)' : s.utilization_pct >= 65 ? 'WARN (/compact)' : 'ok') },
          ],
          active
        );
        break;
      }

      case 'quota': {
        if (flags.set) {
          let items = [];
          if (flags['json-input'] || args[0] === '-') {
            const rawJson = flags['json-input'] || (await readStdinSyncSafe());
            let parsed;
            try {
              parsed = JSON.parse(rawJson);
            } catch (err) {
              throw new Error(`Invalid quota JSON: ${err?.message || err}`);
            }
            items = Array.isArray(parsed)
              ? parsed
              : Array.isArray(parsed?.quotas)
              ? parsed.quotas
              : [parsed];
          } else {
            const item = {
              source_tool: flags.source || flags.sourceTool || 'manual',
              account_id: flags.account || flags.accountId || 'unknown',
              provider: flags.provider || '',
              model_id: flags.model || flags.modelId || '',
              tier_or_model: flags.tier || flags.model || '',
              window_key: flags.window || 'default',
              status: flags.status || 'ok',
            };
            if (flags['quota-id']) item.quota_id = String(flags['quota-id']);
            if (flags.used !== undefined) item.tokens_used = Number(flags.used);
            if (flags.limit !== undefined) item.token_limit = Number(flags.limit);
            if (flags.remaining !== undefined) item.remaining_tokens = Number(flags.remaining);
            if (flags['remaining-pct'] !== undefined) item.remaining_pct = Number(flags['remaining-pct']);
            if (flags['used-pct'] !== undefined) item.used_percent = Number(flags['used-pct']);
            if (flags['reset-at']) item.reset_at = String(flags['reset-at']);
            items = [item];
          }
          const res = upsertQuotasViaApi(db, items);
          const upserted = res?.upserted ?? res?.count ?? items.length;
          if (jsonMode) {
            console.log(JSON.stringify({ ok: true, upserted }, null, 2));
          } else {
            console.log(`Upserted ${upserted} quota snapshot(s).`);
          }
          break;
        }

        const quotas = queryQuotaSnapshots(db, flags);
        if (jsonMode) {
          console.log(JSON.stringify({ quotas }, null, 2));
          break;
        }
        printTable(
          [
            { label: 'Tool', get: (q) => q.source_tool },
            { label: 'Account', get: (q) => q.account_id },
            { label: 'Model/Tier', get: (q) => q.tier_or_model || q.model_id || '—' },
            { label: 'Window', get: (q) => q.window_key || 'default' },
            { label: 'Remain%', right: true, get: (q) => (q.remaining_pct != null ? `${q.remaining_pct}%` : '—') },
            { label: 'Status', get: (q) => (q.is_exhausted ? 'EXHAUSTED' : q.status || 'ok') },
            { label: 'Reset', get: (q) => String(q.reset_at || q.window_reset || '—').slice(0, 19) },
          ],
          quotas
        );
        break;
      }

      case 'sync': {
        if (flags['reset-cursors']) {
          db.prepare('DELETE FROM sync_cursors').run();
        }
        const sources = flags.sources
          ? String(flags.sources).split(',').map((s) => s.trim()).filter(Boolean)
          : undefined;
        const settings = dbApi.getSettings(db);
        const result = await runSyncAll(db, {
          sources,
          milestoneAt: settings.milestoneAt,
          dryRun: Boolean(flags['dry-run']),
        });
        if (jsonMode) {
          console.log(JSON.stringify(result, null, 2));
          break;
        }
        console.log(`Synced in ${result.durationMs}ms at ${result.syncedAt}:`);
        for (const [src, cnt] of Object.entries(result.syncedCounts || {})) {
          console.log(`  ${pad(src, 16)} ${fmtNum(cnt)} new`);
        }
        if (result.quotaRows) console.log(`  quota_snapshots: ${result.quotaRows}`);
        if (result.errors?.length) {
          console.error(`Warnings/Errors (${result.errors.length}):`);
          for (const e of result.errors) console.error(`  - ${e}`);
        }
        break;
      }

      case 'sync-models': {
        const [modelRes, fxRes] = await Promise.all([
          dbApi.syncLiveModels(db),
          dbApi.syncUsdTry(db, { force: true }),
        ]);
        if (jsonMode) {
          console.log(JSON.stringify({ ...modelRes, fx: fxRes }, null, 2));
          break;
        }
        console.log(
          `Models synced: ${modelRes.upsertedCount} updated (${modelRes.totalModels} total) | Sources: OR=${modelRes.sourcesReached.openrouter}, LMS=${modelRes.sourcesReached.lmspeed}, TP=${modelRes.sourcesReached.tokenpricing}`
        );
        console.log(`USD/TRY rate: ${fxRes.rate} (${fxRes.source})`);
        break;
      }

      case 'retag': {
        const accountId = flags.account || flags.accountId || args[0];
        if (!accountId) {
          throw new Error('Missing required --account <id>');
        }
        const scope = flags.scope || '';
        const retagOpts = {
          accountId,
          from: flags.from,
          to: flags.to,
          workspace: flags.workspace,
          sourceTool: flags.source || flags.sourceTool,
          era: flags.era,
        };
        if (scope === 'pre_milestone') retagOpts.era = 'pre_milestone';
        else if (scope === 'untagged') retagOpts.onlyUnattributed = true;
        else if (scope === 'all') {
          retagOpts.era = 'all';
          if (!retagOpts.from && !retagOpts.to && !retagOpts.workspace && !retagOpts.sourceTool) {
            retagOpts.from = '1970-01-01T00:00:00.000Z';
          }
        }
        const res = dbApi.retagLegacy(db, retagOpts);
        if (jsonMode) {
          console.log(JSON.stringify({ ...res, updatedCount: res.updatedRequests }, null, 2));
          break;
        }
        console.log(
          `Re-tagged ${res.updatedRequests} requests and ${res.updatedSessions} sessions to "${res.targetAccountId}".`
        );
        break;
      }

      case 'inspect-sse': {
        const fileTarget = args[0] || flags.file;
        let raw = '';
        if (!fileTarget || fileTarget === '-') {
          raw = await readStdinSyncSafe();
        } else {
          raw = fs.readFileSync(path.resolve(fileTarget), 'utf8');
        }
        if (!raw.trim()) {
          throw new Error('Empty SSE input');
        }
        const mode = flags.mode || 'auto';
        const analysis = analyzeForensics(raw, {
          mode,
          endpointMode: mode !== 'auto' ? mode : undefined,
          claimedModel: flags['claimed-model'] || flags.model || '',
          privacy: true,
        });
        let savedId = null;
        if (flags.save) {
          const rec = toForensicRecord(analysis, {
            source_tool: 'cli-inspect',
            base_url: fileTarget && fileTarget !== '-' ? path.basename(fileTarget) : '',
            rawExcerpt: raw.slice(0, 4000),
          });
          const saved = dbApi.saveForensicCapture(db, rec);
          savedId = saved?.capture_id || rec.capture_id;
        }
        const compact = compactAnalysis(analysis);
        if (jsonMode) {
          console.log(JSON.stringify({ ok: true, analysis: compact, savedId }, null, 2));
          break;
        }
        const p = compact.parsed || {};
        console.log(`=== SSE Forensics ===`);
        console.log(`Verdict:      ${compact.verdict} (${compact.authenticityScore}/100)`);
        console.log(`Mode:         ${compact.mode} | Response ID: ${p.id || '—'} (${p.idFormat || '—'})`);
        console.log(`Wire Model:   ${compact.wireModel || '—'}`);
        console.log(`Self-Report:  ${compact.selfReportVsWire?.selfReportedModels?.join(', ') || 'none'} (mismatch=${compact.selfReportVsWire?.mismatch})`);
        if (p.tokens) {
          console.log(
            `Tokens:       in=${p.tokens.input_tokens} out=${p.tokens.output_tokens} cache_read=${p.tokens.cache_read_tokens} cache_write=${p.tokens.cache_write_tokens} reason=${p.tokens.reasoning_tokens}`
          );
        }
        if (p.attribution) {
          console.log(
            `Attribution:  instructions=${p.attribution.instructions_input_tokens} items_in=${p.attribution.items_input_tokens} reconciles=${p.attribution.input_reconciles}`
          );
        }
        if (p.timing) {
          console.log(
            `Timing:       TTFT=${p.timing.ttftMs ?? '—'}ms TPOT=${p.timing.tpotMs ?? '—'}ms tok/s=${p.timing.tokPerSec ?? '—'}`
          );
        }
        break;
      }

      case 'probe': {
        const baseUrl = flags.url;
        const model = flags.model;
        const endpointMode = flags.mode || 'responses';
        if (!baseUrl || !model) {
          throw new Error('probe requires --url <base> and --model <model>');
        }
        const keyEnv = flags['key-env'];
        const apiKey = keyEnv ? process.env[keyEnv] || '' : '';
        const res = await probeEndpoint({
          baseUrl,
          apiKey,
          endpointMode,
          model,
          prompt: flags.prompt,
          timeoutMs: Number(flags.timeout) || 30000,
          privacy: true,
        });
        let savedId = null;
        if (res.forensics && !flags['no-save']) {
          const rec = toForensicRecord(res.forensics, {
            source_tool: 'cli-probe',
            base_url: res.url,
            headers: res.headers,
          });
          const saved = dbApi.saveForensicCapture(db, rec);
          savedId = saved?.capture_id || rec.capture_id;
        }
        const out = {
          ok: res.ok,
          status: res.status,
          url: res.url,
          headers: res.headers,
          capture: res.capture,
          analysis: res.forensics ? compactAnalysis(res.forensics) : null,
          savedId,
          error: res.error || null,
        };
        if (jsonMode) {
          console.log(JSON.stringify(out, null, 2));
          if (!res.ok) process.exitCode = 1;
          break;
        }
        if (!res.ok) {
          console.error(`Probe failed (${res.status}): ${res.error}`);
          process.exitCode = 1;
          break;
        }
        console.log(
          `Probe OK (${res.status}) -> ${out.analysis.verdict} (${out.analysis.authenticityScore}/100) | wire=${out.analysis.wireModel} | TTFT=${out.analysis.timing?.ttftMs ?? '—'}ms`
        );
        break;
      }

      case 'tee-proxy': {
        const upstream = flags.upstream;
        if (!upstream) {
          throw new Error('tee-proxy requires --upstream <url>');
        }
        const port = Number(flags.port) || DEFAULT_TEE_PORT;
        dbApi.closeDatabase(db);
        const proxy = createTeeProxy({ port, upstreamBaseUrl: upstream, persist: true });
        await proxy.listen();
        console.error(`[wiretok] tee-proxy listening on ${proxy.url} -> ${upstream}`);
        await new Promise((resolve) => {
          const stop = async () => {
            await proxy.close();
            resolve();
          };
          process.once('SIGINT', stop);
          process.once('SIGTERM', stop);
          process.once('SIGHUP', stop);
        });
        return;
      }

      case 'integrate': {
        const rawTool = args[0] || flags.tool;
        if (!rawTool || rawTool === 'status') {
          const list = await getIntegrationStatusLive();
          if (jsonMode) {
            console.log(JSON.stringify({ integrations: list }, null, 2));
            break;
          }
          printTable(
            [
              { label: 'Tool', get: (i) => i.tool },
              { label: 'Status', get: (i) => i.status },
              { label: 'Detected', get: (i) => (i.detected ? 'yes' : 'no') },
              { label: 'Apply', get: (i) => (i.apply_supported ? 'yes' : 'passive') },
              { label: 'Note', get: (i) => String((i.notes && i.notes[0]) || '').slice(0, 60) },
            ],
            list
          );
          break;
        }
        const tool = rawTool === 'claude' ? 'claude-code' : rawTool;
        const result = configureIntegration(tool, {
          apply: Boolean(flags.apply),
          force: Boolean(flags.force),
        });
        if (jsonMode) {
          console.log(JSON.stringify(result, null, 2));
          if (!result.ok) process.exitCode = 1;
          break;
        }
        console.log(`[${result.tool}] ${result.message}`);
        if (result.snippet) console.log(`\nSnippet:\n${result.snippet}`);
        if (!result.ok) process.exitCode = 1;
        break;
      }

      case 'export': {
        const format = String(flags.format || 'json').toLowerCase() === 'csv' ? 'csv' : 'json';
        const data = dbApi.exportData(db, buildFilterOpts({ ...flags, era: flags.era || 'all' }), format);
        if (flags.out) {
          fs.writeFileSync(path.resolve(flags.out), data, 'utf8');
          if (jsonMode) {
            console.log(JSON.stringify({ ok: true, format, out: path.resolve(flags.out) }));
          } else {
            console.error(`Exported ${format.toUpperCase()} to ${path.resolve(flags.out)}`);
          }
        } else {
          process.stdout.write(data + (data.endsWith('\n') ? '' : '\n'));
        }
        break;
      }

      case 'web': {
        dbApi.closeDatabase(db);
        const lanPort = flags['lan-port'] !== undefined ? Number(flags['lan-port']) : DEFAULT_LAN_PORT;
        const handle = await startServer({
          port: flags.port ? Number(flags.port) : DEFAULT_WEB_PORT,
          host: flags.host || '127.0.0.1',
          dbPath: flags.db,
          enableSyncLoop: !flags['no-sync'],
          lan: Boolean(flags.lan),
          lanPort,
        });
        await new Promise((resolve) => {
          const stop = async () => {
            await handle.close();
            resolve();
          };
          process.once('SIGINT', stop);
          process.once('SIGTERM', stop);
          process.once('SIGHUP', stop);
        });
        return;
      }

      default:
        console.error(`Unknown command: ${command}`);
        printHelp();
        process.exitCode = 1;
    }
  } finally {
    dbApi.closeDatabase(db);
  }
}

main().catch((err) => {
  console.error(`tp error: ${err.message}`);
  process.exit(1);
});
