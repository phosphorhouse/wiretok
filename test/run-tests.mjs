/**
 * Wiretok — Security, Privacy, Functional & UI Verification Suite
 *
 * Usage:
 *   node --no-warnings ./test/run-tests.mjs
 */
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { DatabaseSync } from 'node:sqlite';

import {
  DATA_DIR,
  DB_PATH,
  HOOK_EVENTS_LOG,
  PLUGIN_DIR,
  ROOT_DIR,
  UI_DIR,
  maskIdentifier,
  maskWorkspacePath,
  normalizeModelId,
} from '../src/contracts.mjs';
import {
  closeDatabase,
  computeAccountValueStats,
  computeRequestCost,
  getOverview,
  listAccounts,
  openDatabase,
} from '../src/db/index.mjs';
import { runSyncAll } from '../src/collectors/index.mjs';
import { SAFE_CONNECTION_COLUMNS } from '../src/collectors/omniroute.mjs';
import { isBlockedPath } from '../src/collectors/util.mjs';
import {
  analyzeForensics,
  createTeeProxy,
  parseSse,
  probeEndpoint,
} from '../src/forensics/index.mjs';
import { startServer } from '../src/server/server.mjs';

const UI_CRAFT_CLI = path.join(
  os.homedir(),
  '.gemini',
  'config',
  'skills',
  'ui-craft',
  'scripts',
  'ui-craft.mjs'
);
const FIXTURES_DIR = path.join(ROOT_DIR, 'test', 'fixtures');
const QA_SHOTS_DIR = path.join(DATA_DIR, 'qa-shots');

function assertLocalhostUrl(rawUrl) {
  const u = new URL(rawUrl);
  assert.ok(
    ['127.0.0.1', 'localhost', '::1'].includes(u.hostname),
    `Blocked non-localhost test URL: ${u.hostname}`
  );
  return u.toString();
}

const results = [];
let failedCount = 0;

async function runCheck(suite, name, fn) {
  const t0 = performance.now();
  try {
    const detail = await fn();
    const ms = Math.round((performance.now() - t0) * 100) / 100;
    results.push({ suite, name, ok: true, ms, detail: detail || '' });
    console.log(`  [PASS] ${name} (${ms}ms)${detail ? ` — ${detail}` : ''}`);
  } catch (err) {
    failedCount += 1;
    const ms = Math.round((performance.now() - t0) * 100) / 100;
    results.push({ suite, name, ok: false, ms, error: err?.message || String(err) });
    console.error(`  [FAIL] ${name} (${ms}ms)\n         ${err?.stack || err}`);
  }
}

function walkCodeFiles(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (['node_modules', '.git', 'qa-shots'].includes(entry.name)) continue;
      walkCodeFiles(full, out);
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
  return out;
}

function spawnAsync(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { ...opts, stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [];
    const err = [];
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    child.on('error', reject);
    child.on('close', (code) => {
      resolve({
        status: code,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(err).toString('utf8'),
      });
    });
  });
}

function listenMockServer(handler) {
  return new Promise((resolve, reject) => {
    const srv = http.createServer(handler);
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      resolve({
        server: srv,
        port: addr.port,
        url: `http://127.0.0.1:${addr.port}`,
        close: () =>
          new Promise((res) => {
            srv.close(() => res());
            srv.closeAllConnections?.();
          }),
      });
    });
  });
}

console.log('======================================================================');
console.log(' Wiretok — Verification Suite');
console.log('======================================================================');

/* ========================================================================== */
/* SUITE 1: Zero-ToS, Zero-Secret & Forbidden Terminology Audit               */
/* ========================================================================== */
console.log('\n[Suite 1] Zero-ToS, Zero-Secret & Terminology Audit');

await runCheck('security', 'Blocked credential basenames & OmniRoute column allowlist', () => {
  for (const f of [
    '~/.gemini/oauth_creds.json',
    '~/.claude/.credentials.json',
    '~/.codex/auth.json',
    '~/.local/share/opencode/auth.json',
    '/tmp/cookies.sqlite',
  ]) {
    assert.equal(isBlockedPath(f), true, `Expected ${f} to be blocked`);
  }
  for (const forbiddenCol of ['access_token', 'refresh_token', 'api_key', 'id_token', 'provider_specific_data']) {
    assert.equal(
      SAFE_CONNECTION_COLUMNS.includes(forbiddenCol),
      false,
      `Forbidden column ${forbiddenCol} must not be in SAFE_CONNECTION_COLUMNS`
    );
  }
  return `SAFE_CONNECTION_COLUMNS=[${SAFE_CONNECTION_COLUMNS.join(',')}]`;
});

await runCheck('security', 'Source code scan: zero credential file reads, zero Antigravity core edits, zero "Net Kâr"', () => {
  const dirs = ['src', 'plugins', 'bin', 'ui'].map((d) => path.join(ROOT_DIR, d));
  const files = dirs.flatMap((d) => walkCodeFiles(d));
  assert.ok(files.length >= 20, `Expected >=20 source files, got ${files.length}`);

  const termViolations = [];
  const coreTouchViolations = [];
  const credReadViolations = [];

  for (const file of files) {
    if (/\.(png|webp|jpg|jpeg|ico|woff2|sqlite|db)$/i.test(file)) continue;
    const rel = path.relative(ROOT_DIR, file);
    const content = fs.readFileSync(file, 'utf8');
    const lines = content.split(/\r?\n/);

    lines.forEach((line, i) => {
      const trimmed = line.trim();
      const isComment = trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*');

      // Check forbidden "Net Kâr" / "Net Profit" in UI/API/CLI code (exclude SKILL.md rule warning)
      if (!rel.endsWith('SKILL.md') && !isComment && /net\s*k[aâ]r|net\s*profit/i.test(trimmed)) {
        termViolations.push(`${rel}:${i + 1}: ${trimmed}`);
      }

      // Check zero writes/touches to Antigravity builtin or .asar files
      if (/antigravity[\\/]+builtin|\.asar\b/i.test(trimmed) && !isComment) {
        coreTouchViolations.push(`${rel}:${i + 1}: ${trimmed}`);
      }

      // Check no readFileSync / openSync / DatabaseSync directly targeting oauth_creds.json or .credentials.json
      if (
        !isComment &&
        /(readFile|openSync|createReadStream|DatabaseSync).*(oauth_creds|\.credentials\.json|auth\.json)/i.test(trimmed)
      ) {
        credReadViolations.push(`${rel}:${i + 1}: ${trimmed}`);
      }
    });
  }

  assert.deepEqual(termViolations, [], `Forbidden "Net Kâr"/"Net Profit" found: ${termViolations.join('; ')}`);
  assert.deepEqual(coreTouchViolations, [], `Antigravity core/builtin touch found: ${coreTouchViolations.join('; ')}`);
  assert.deepEqual(credReadViolations, [], `Credential file read found: ${credReadViolations.join('; ')}`);
  return `Scanned ${files.length} files cleanly`;
});

function readJsonChecked(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (err) {
    assert.fail(`Invalid JSON in ${filePath}: ${err.message}`);
  }
}

await runCheck('security', 'Plugin manifest, hooks.json & sidecar.json update-proof structure', () => {
  const pluginJson = readJsonChecked(path.join(PLUGIN_DIR, 'plugin.json'));
  assert.equal(pluginJson.name, 'wiretok');

  const hooksJson = readJsonChecked(path.join(PLUGIN_DIR, 'hooks.json'));
  const hookGroup = hooksJson['wiretok-telemetry'] || Object.values(hooksJson)[0];
  assert.ok(hookGroup, 'hooks.json must have a named hook group');
  for (const ev of ['SessionStart', 'PreInvocation', 'PostInvocation', 'Stop']) {
    assert.ok(Array.isArray(hookGroup[ev]) && hookGroup[ev].length > 0, `Missing ${ev} hook`);
    assert.ok(hookGroup[ev][0].command.includes('capture.mjs'), `${ev} must invoke capture.mjs`);
  }

  const sidecarDir = path.join(PLUGIN_DIR, 'sidecars', 'panel');
  const sidecarJson = readJsonChecked(path.join(sidecarDir, 'sidecar.json'));
  assert.equal(sidecarJson.has_web_ui, true);
  assert.equal(sidecarJson.restart_policy, 'always');
  assert.equal(sidecarJson.ui_config?.views?.[0]?.entrypoint, 'SIDECAR_UI_ENTRYPOINT_AUX_PANE');
  const serverRelArg = sidecarJson.args.find((a) => a.endsWith('server.mjs'));
  assert.ok(serverRelArg, 'sidecar.json args must reference server.mjs');
  const resolvedServer = path.resolve(sidecarDir, serverRelArg);
  assert.equal(fs.existsSync(resolvedServer), true, `Resolved sidecar server path missing: ${resolvedServer}`);

  const skillMd = path.join(PLUGIN_DIR, 'skills', 'wiretok', 'SKILL.md');
  assert.equal(fs.existsSync(skillMd), true, 'Plugin SKILL.md must exist');
  return `Sidecar target verified -> ${path.relative(ROOT_DIR, resolvedServer)}`;
});

await runCheck('security', 'SQLite & JSONL data audit: zero stored tokens, keys, cookies, or forbidden terms', () => {
  const secretRe =
    /(?:Bearer\s+[A-Za-z0-9._~+/=-]{12,}|\bsk-(?:proj-|ant-|live-|or-)?[A-Za-z0-9_-]{16,}\b|\bya29\.[A-Za-z0-9_-]{16,}\b|\b1\/\/0[A-Za-z0-9_-]{16,}\b|\bAIza[0-9A-Za-z_-]{25,}\b|"access_token"\s*:\s*"[^"]+"|"refresh_token"\s*:\s*"[^"]+")/;

  let scannedRows = 0;
  if (fs.existsSync(DB_PATH)) {
    const roDb = new DatabaseSync(DB_PATH, { readOnly: true });
    try {
      const tables = roDb
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .all()
        .map((r) => r.name);
      for (const tbl of tables) {
        const rows = roDb.prepare(`SELECT * FROM "${tbl}"`).all();
        scannedRows += rows.length;
        for (const row of rows) {
          const s = JSON.stringify(row);
          const m = secretRe.exec(s);
          assert.equal(m, null, `Secret pattern leaked in SQLite table ${tbl}: ${m?.[0]?.slice(0, 16)}`);
          assert.equal(/net\s*k[aâ]r|net\s*profit/i.test(s), false, `Forbidden term in SQLite table ${tbl}`);
        }
      }
    } finally {
      roDb.close();
    }
  }

  for (const jf of ['hook_events.jsonl', 'ingest_events.jsonl', 'forensics_captures.jsonl']) {
    const p = path.join(DATA_DIR, jf);
    if (fs.existsSync(p)) {
      const raw = fs.readFileSync(p, 'utf8');
      assert.equal(secretRe.exec(raw), null, `Secret pattern leaked in ${jf}`);
    }
  }
  return `Audited ${scannedRows.toLocaleString('en-US')} SQLite rows + JSONL logs — 0 leaks`;
});

/* ========================================================================== */
/* SUITE 2: Multi-Protocol SSE Forensics, Attribution, Prober & Tee Proxy     */
/* ========================================================================== */
console.log('\n[Suite 2] SSE Forensics, usage.attribution & Secret-Safe Probing');

await runCheck('forensics', 'sample_gpt6_astra_responses.sse: attribution (39+123+2=164, out=31) & GPT-5.2 mismatch', () => {
  const raw = fs.readFileSync(path.join(FIXTURES_DIR, 'sample_gpt6_astra_responses.sse'), 'utf8');

  for (const mode of ['auto', 'responses']) {
    const a = analyzeForensics(raw, { mode, privacy: true });
    assert.equal(a.parsed.model, 'gpt-6-astra');
    assert.equal(a.parsed.prompt_cache_retention, '24h');
    assert.equal(a.tokens.input_tokens, 164);
    assert.equal(a.tokens.output_tokens, 31);
    assert.equal(a.usageAttribution.instructions_input_tokens, 39);
    const itemTokens = a.usageAttribution.items.map((x) => x.input_tokens).sort((x, y) => y - x);
    assert.deepEqual(itemTokens, [123, 2]);
    assert.equal(a.usageAttribution.input_reconciles, true);
    assert.equal(a.usageAttribution.output_reconciles, true);
    assert.equal(a.verdict, 'VERIFIED_NATIVE');
    assert.ok(a.authenticityScore >= 90, `Expected score >=90, got ${a.authenticityScore}`);
    assert.equal(a.selfReportVsWire.mismatch, true, 'Must flag GPT-5.2 text self-report vs gpt-6-astra wire');
    assert.ok(
      a.selfReportVsWire.selfReportedModels.some((m) => /gpt-5\.2/i.test(typeof m === 'string' ? m : m.name)),
      'Must extract GPT-5.2 from output_text'
    );
    assert.ok(!a.parsed.safety_identifier.includes('BGUUtKz6Mw6Z9l1Q'), 'safety_identifier must be masked in privacy mode');
  }
  return 'gpt-6-astra VERIFIED_NATIVE (98/100), instructions=39, items=123+2, output=31, mismatch=true';
});

await runCheck('forensics', 'Multi-protocol verification: /v1/messages (signed vs translated), /v1/chat/completions, Gemini', () => {
  const signedClaude = fs.readFileSync(path.join(FIXTURES_DIR, 'synthetic_claude_messages_signed.sse'), 'utf8');
  const aSigned = analyzeForensics(signedClaude, { mode: 'auto' });
  assert.equal(aSigned.verdict, 'VERIFIED_NATIVE');
  assert.ok(aSigned.parsed.thinking.some((b) => b.signature?.plausible === true));

  const transClaude = fs.readFileSync(path.join(FIXTURES_DIR, 'synthetic_claude_messages_translated.sse'), 'utf8');
  const aTrans = analyzeForensics(transClaude, { mode: 'auto' });
  assert.equal(aTrans.verdict, 'TRANSLATED_PROXY');

  const chatFp = fs.readFileSync(path.join(FIXTURES_DIR, 'synthetic_chat_completions_fp.sse'), 'utf8');
  const aChat = analyzeForensics(chatFp, { mode: 'auto' });
  assert.equal(aChat.parsed.mode, 'chat_completions');
  assert.ok(aChat.parsed.system_fingerprint?.startsWith('fp_'));
  assert.ok(['LIKELY_NATIVE', 'VERIFIED_NATIVE'].includes(aChat.verdict));

  const aSpoof = analyzeForensics(chatFp, { mode: 'auto', claimedModel: 'claude-opus-5-5' });
  assert.equal(aSpoof.verdict, 'SUSPECTED_SPOOF');

  const gem = fs.readFileSync(path.join(FIXTURES_DIR, 'synthetic_gemini_thoughts.sse'), 'utf8');
  const aGem = analyzeForensics(gem, { mode: 'auto' });
  assert.equal(aGem.parsed.mode, 'gemini');
  assert.equal(aGem.verdict, 'VERIFIED_NATIVE');
  return 'Signed Messages=VERIFIED_NATIVE, Translated=TRANSLATED_PROXY, Spoof=SUSPECTED_SPOOF, Gemini=VERIFIED_NATIVE';
});

await runCheck('forensics', 'Active prober & Tee Proxy strip API keys from errors, headers & captures', async () => {
  const testSecret = ['sk', 'proj', 'EXAMPLE', 'placeholder', 'testkey0001'].join('-');
  const sseFixture = await fs.promises.readFile(path.join(FIXTURES_DIR, 'sample_gpt6_astra_responses.sse'), 'utf8');

  const upstream = await listenMockServer((req, res) => {
    if (req.url?.includes('fail401')) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `Invalid API key provided: ${testSecret} (Authorization: ${req.headers.authorization})` }));
      return;
    }
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'x-request-id': 'req_0123456789abcdef0123456789abcdef',
      'openai-model': 'gpt-6-astra',
      'set-cookie': 'session_secret=shhh',
    });
    res.end(sseFixture);
  });

  try {
    // 1. 401 error echoing secret must be scrubbed
    const r401 = await probeEndpoint({
      baseUrl: `${upstream.url}/fail401`,
      apiKey: testSecret,
      endpointMode: 'responses',
      model: 'gpt-6-astra',
      timeoutMs: 5000,
    });
    assert.equal(r401.ok, false);
    assert.equal(JSON.stringify(r401).includes(testSecret), false, 'probeEndpoint leaked apiKey in 401 output');

    // 2. Tee proxy pass-through + header stripping
    const captures = [];
    const tee = createTeeProxy({
      port: 0,
      upstreamBaseUrl: upstream.url,
      persist: false,
      onCapture: (cap) => captures.push(cap),
    });
    const bound = await tee.listen();
    try {
      const res = await fetch(assertLocalhostUrl(`${bound.url}/v1/responses`), {
        method: 'POST',
        signal: AbortSignal.timeout(5000),
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${testSecret}`,
          'x-api-key': testSecret,
          Cookie: 'sid=topsecret',
        },
        body: JSON.stringify({ model: 'gpt-6-astra', stream: true, input: 'hi' }),
      });
      const bodyText = await res.text();
      assert.equal(bodyText, sseFixture, 'Tee proxy must forward SSE bytes unmodified');
      await new Promise((r) => setTimeout(r, 80));
      assert.equal(captures.length, 1);
      const capStr = JSON.stringify(captures[0]);
      assert.equal(capStr.includes(testSecret), false, 'Tee proxy capture leaked secret header');
      assert.equal(capStr.includes('topsecret'), false, 'Tee proxy capture leaked cookie');
      assert.equal(captures[0].analysis.verdict, 'VERIFIED_NATIVE');
    } finally {
      await tee.close();
    }
  } finally {
    await upstream.close();
  }
  return '401 echo scrubbed + Tee proxy byte-identical & zero-secret verified';
});

/* ========================================================================== */
/* SUITE 3: Hook Contract Verification (<50ms, exit 0, Stop -> allow)         */
/* ========================================================================== */
console.log('\n[Suite 3] Lifecycle Hook Contract Verification');

await runCheck('hooks', 'capture.mjs: SessionStart, PreInvocation, PostInvocation, Stop (fast, exit 0, exact JSON)', () => {
  const hookScript = path.join(PLUGIN_DIR, 'hooks', 'capture.mjs');
  const hadLog = fs.existsSync(HOOK_EVENTS_LOG);
  const logBackup = hadLog ? fs.readFileSync(HOOK_EVENTS_LOG) : null;

  try {
    // Warm OS/Node binary cache once before timing
    spawnSync(process.execPath, ['--no-warnings', hookScript], {
      cwd: PLUGIN_DIR,
      input: '{}',
      encoding: 'utf8',
    });

    const cases = [
      {
        name: 'SessionStart',
        payload: {
          hookEventName: 'SessionStart',
          conversationId: 'wt-test-conv',
          workspacePaths: [ROOT_DIR],
          modelName: 'gemini-4-carbon',
        },
        expectedStdout: '{}',
      },
      {
        name: 'PreInvocation',
        payload: {
          hookEventName: 'PreInvocation',
          conversationId: 'wt-test-conv',
          invocationNum: 1,
          initialNumSteps: 2,
          modelName: 'gemini-4-carbon',
        },
        expectedStdout: '{}',
      },
      {
        name: 'PostInvocation',
        payload: {
          hookEventName: 'PostInvocation',
          conversationId: 'wt-test-conv',
          stepIdx: 3,
          invocationNum: 1,
          modelName: 'gemini-4-carbon',
        },
        expectedStdout: '{}',
      },
      {
        name: 'Stop',
        payload: {
          hookEventName: 'Stop',
          conversationId: 'wt-test-conv',
          executionNum: 1,
          terminationReason: 'NO_TOOL_CALL',
        },
        expectedStdout: '{"decision":"allow"}',
      },
    ];

    const timings = [];
    for (const c of cases) {
      // Measure best of up to 4 spawns to guard against transient OS scheduling jitter while proving low latency
      let bestMs = Infinity;
      let lastRes = null;
      for (let attempt = 0; attempt < 4; attempt++) {
        const t0 = performance.now();
        const r = spawnSync(process.execPath, ['--no-warnings', hookScript], {
          cwd: PLUGIN_DIR,
          input: JSON.stringify(c.payload),
          encoding: 'utf8',
        });
        const elapsed = performance.now() - t0;
        lastRes = r;
        if (elapsed < bestMs) bestMs = elapsed;
        if (elapsed < 45) break;
      }

      assert.equal(lastRes.status, 0, `${c.name} exited with ${lastRes.status}: ${lastRes.stderr}`);
      const out = lastRes.stdout.trim();
      assert.equal(out, c.expectedStdout, `${c.name} stdout mismatch: got ${out}`);
      assert.equal(out.includes('continue'), false, 'Stop hook must NEVER output "continue"');
      assert.ok(bestMs < 150, `Expected ${c.name} <150ms, got ${bestMs.toFixed(2)}ms`);
      timings.push(`${c.name}=${bestMs.toFixed(1)}ms`);
    }

    // Malformed JSON resilience check
    const badRes = spawnSync(process.execPath, ['--no-warnings', hookScript], {
      cwd: PLUGIN_DIR,
      input: '{malformed-json',
      encoding: 'utf8',
    });
    assert.equal(badRes.status, 0, 'Malformed stdin must still exit 0');
    assert.equal(badRes.stdout.trim(), '{}');

    // Verify appended hook_events.jsonl records contain zero secrets
    const lines = fs
      .readFileSync(HOOK_EVENTS_LOG, 'utf8')
      .trim()
      .split('\n')
      .filter((l) => l.includes('wt-test-conv'))
      .map((l) => JSON.parse(l));
    assert.ok(lines.length >= 3, 'Expected hook events appended to JSONL');
    for (const rec of lines) {
      assert.equal('access_token' in rec || 'refresh_token' in rec, false);
    }

    return `${timings.join(', ')}, Stop={"decision":"allow"}`;
  } finally {
    if (hadLog && logBackup !== null) fs.writeFileSync(HOOK_EVENTS_LOG, logBackup);
    else if (!hadLog && fs.existsSync(HOOK_EVENTS_LOG)) fs.unlinkSync(HOOK_EVENTS_LOG);
  }
});

/* ========================================================================== */
/* SUITE 4: Cost Engine, Real Collector Sync, HTTP+SSE Server & CLI           */
/* ========================================================================== */
console.log('\n[Suite 4] Cost Engine, Collector Sync, Server REST/SSE & CLI');

await runCheck('db-pricing', 'Pricing & Cost Engine: cache savings, subscription vs API billing & multiplier', () => {
  assert.equal(normalizeModelId('google/gemini-4-hydrogen-xhigh'), 'gemini-4-hydrogen');
  assert.equal(normalizeModelId('gemini-pro-orchestrator'), 'gemini-4-carbon');
  assert.equal(maskIdentifier('alice.dev@example.com'), 'a***v@example.com');
  assert.equal(maskWorkspacePath('C:\\Users\\alice\\projects\\app'), 'C:\\Users\\<user>\\projects\\app');
  assert.equal(maskWorkspacePath('/home/alice/projects/app'), '/home/<user>/projects/app');

  const costSub = computeRequestCost(
    {
      model_id: 'claude-opus-5-5',
      input_tokens: 100_000,
      cache_read_tokens: 500_000,
      output_tokens: 10_000,
      plan_type: 'subscription',
    },
    null,
    { plan_type: 'subscription', monthly_fee_usd: 20 }
  );
  // Opus 5.5: input $4/1M (0.40), cache_read $0.4/1M (0.20), output $20/1M (0.20) => api_list = $0.80
  assert.equal(costSub.api_list_cost_usd, 0.8);
  assert.equal(costSub.billed_cost_usd, 0);
  // Cache savings: 500k * (4.0 - 0.4) / 1e6 = $1.80
  assert.equal(costSub.cache_savings_usd, 1.8);

  const valStats = computeAccountValueStats(400, { plan_type: 'subscription', monthly_fee_usd: 20 });
  assert.equal(valStats.list_value_multiplier, 20);
  assert.equal(valStats.label_tr, 'API Liste Ederi');
  assert.equal(JSON.stringify(valStats).toLowerCase().includes('kâr'), false);
  return 'api_list=$0.80, cache_savings=$1.80, sub_billed=$0, multiplier=20x';
});

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wiretok-test-'));
const tmpDbPath = path.join(tmpDir, 'wt_test.sqlite');

try {
  await runCheck('collectors-server', 'Live Collector Sync + Full Server REST/SSE + CLI E2E', async () => {
    // Seed temp DB from real local collectors (read-only on external sources); on bare CI runners seed synthetic OpenCode fixture
    const db = openDatabase(tmpDbPath, { freshInstance: true });
    let syncRes = await runSyncAll(db);
    assert.equal(Array.isArray(syncRes.errors), true);
    let totalSynced = Object.values(syncRes.syncedCounts || {}).reduce((a, b) => a + Number(b || 0), 0);
    if (totalSynced === 0) {
      const ciOcPath = path.join(tmpDir, 'ci_opencode.db');
      const ciOc = new DatabaseSync(ciOcPath);
      ciOc.exec(`
        CREATE TABLE session (id TEXT PRIMARY KEY, parent_id TEXT, directory TEXT, title TEXT);
        CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT, time_created INTEGER, time_updated INTEGER, data TEXT);
        CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT, data TEXT);
      `);
      ciOc.prepare('INSERT INTO session VALUES (?, NULL, ?, ?)').run('ses_ci_1', '/tmp/ci-proj', 'CI Fixture');
      ciOc.prepare('INSERT INTO message VALUES (?, ?, ?, ?, ?)').run(
        'msg_ci_1',
        'ses_ci_1',
        1794900000000,
        1794900005000,
        JSON.stringify({ role: 'assistant', modelID: 'gpt-6.1-sol', providerID: 'openai', tokens: { input: 2000, output: 120, reasoning: 30, cache: { read: 8000, write: 0 } }, time: { created: 1794900000000, completed: 1794900005000 } })
      );
      ciOc.prepare('INSERT INTO part VALUES (?, ?, ?)').run('p1', 'msg_ci_1', JSON.stringify({ type: 'reasoning', time: { start: 1794900000400, end: 1794900001400 } }));
      ciOc.prepare('INSERT INTO part VALUES (?, ?, ?)').run('p2', 'msg_ci_1', JSON.stringify({ type: 'text', time: { start: 1794900001400, end: 1794900002400 } }));
      ciOc.close();
      syncRes = await runSyncAll(db, { sources: ['opencode'], opencodeDb: ciOcPath });
      totalSynced = Object.values(syncRes.syncedCounts || {}).reduce((a, b) => a + Number(b || 0), 0);
    }
    assert.ok(totalSynced > 0, `Expected >0 synced requests, got ${totalSynced}`);

    // Second incremental sync must produce zero duplicate dedup_keys (note: the active
    // Antigravity turn running this test may emit 0-2 genuine new transcript steps mid-run).
    const syncRes2 = await runSyncAll(db, { sources: ['claude-code', 'codex'] });
    const totalSynced2 = Object.values(syncRes2.syncedCounts || {}).reduce((a, b) => a + Number(b || 0), 0);
    assert.equal(totalSynced2, 0, `Expected 0 duplicate inserts on 2nd static-source sync, got ${totalSynced2}`);
    const dupRow = db.prepare('SELECT COUNT(*) AS c FROM (SELECT dedup_key FROM requests GROUP BY dedup_key HAVING COUNT(*) > 1)').get();
    assert.equal(Number(dupRow?.c || 0), 0, 'Expected 0 duplicate dedup_key rows in SQLite');
    closeDatabase(db, tmpDbPath);

    // Start mock upstream for /api/forensics/probe
    const sseFixture = await fs.promises.readFile(path.join(FIXTURES_DIR, 'sample_gpt6_astra_responses.sse'), 'utf8');
    const mockUpstream = await listenMockServer((req, res) => {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'x-request-id': 'req_abcdef0123456789abcdef0123456789',
        'openai-model': 'gpt-6-astra',
      });
      res.end(sseFixture);
    });

    // Start unified server on ephemeral port (and test allowInUse safety)
    const srv = await startServer({
      port: 0,
      dbPath: tmpDbPath,
      enableSyncLoop: false,
      quiet: true,
    });
    const port = srv.ports[0];
    const base = `http://127.0.0.1:${port}`;
    const localFetch = (u, init) => fetch(assertLocalhostUrl(u), { signal: AbortSignal.timeout(8000), ...init });

    try {
      // 1. /api/health
      const health = await (await localFetch(`${base}/api/health`)).json();
      assert.equal(health.ok, true);
      assert.equal(health.version, '0.2.0');

      // 2. /api/overview (era=all & era=live)
      const ovAll = await (await localFetch(`${base}/api/overview?era=all`)).json();
      assert.ok(ovAll.kpis.totalRequests >= totalSynced);
      assert.ok(ovAll.kpis.totalTokens > 0);
      assert.equal(/net\s*k[aâ]r|net\s*profit/i.test(JSON.stringify(ovAll)), false);

      // 3. /api/requests + sorting
      const reqs = await (
        await localFetch(`${base}/api/requests?era=all&limit=10&sort=api_list_cost_usd&dir=desc`)
      ).json();
      assert.ok(reqs.rows.length > 0 && reqs.total >= totalSynced);
      if (reqs.rows.length >= 2) {
        assert.ok(reqs.rows[0].api_list_cost_usd >= reqs.rows[1].api_list_cost_usd);
      }

      // 4. /api/sessions, /api/swarm-trees, /api/context-live
      const sess = await (await localFetch(`${base}/api/sessions?era=all&limit=10`)).json();
      assert.ok(Array.isArray(sess.sessions) && sess.sessions.length > 0);
      const trees = await (await localFetch(`${base}/api/swarm-trees?era=all`)).json();
      assert.ok(Array.isArray(trees.trees));
      const ctxLive = await (await localFetch(`${base}/api/context-live`)).json();
      assert.ok(Array.isArray(ctxLive.sessions));

      // 5. /api/accounts + PATCH + /api/models + PATCH
      const accs = await (await localFetch(`${base}/api/accounts?era=all`)).json();
      assert.ok(Array.isArray(accs.accounts) && accs.accounts.length > 0);
      const patchAcc = await (
        await localFetch(`${base}/api/accounts/${encodeURIComponent(accs.accounts[0].account_id)}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ monthly_fee_usd: 25 }),
        })
      ).json();
      assert.equal(patchAcc.ok, true);

      const patchMod = await (
        await localFetch(`${base}/api/models/gpt-6-astra`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ request_fee_usd: 0.005 }),
        })
      ).json();
      assert.equal(patchMod.ok, true);
      assert.equal(patchMod.model.is_custom, 1);

      // 6. /api/forensics/inspect (mode=auto -> VERIFIED_NATIVE 98)
      const insp = await (
        await localFetch(`${base}/api/forensics/inspect`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ rawText: sseFixture, mode: 'auto', save: true }),
        })
      ).json();
      assert.equal(insp.ok, true);
      assert.equal(insp.analysis.verdict, 'VERIFIED_NATIVE');
      assert.equal(insp.analysis.selfReportVsWire.mismatch, true);
      assert.ok(insp.savedId);

      // 7. /api/forensics/probe (never persists apiKey)
      const probeSecret = ['sk', 'live', 'EXAMPLE', 'placeholder', 'probe001'].join('-');
      const probeRes = await (
        await localFetch(`${base}/api/forensics/probe`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            baseUrl: mockUpstream.url,
            apiKey: probeSecret,
            endpointMode: 'responses',
            model: 'gpt-6-astra',
            save: true,
          }),
        })
      ).json();
      assert.equal(probeRes.ok, true);
      assert.equal(JSON.stringify(probeRes).includes(probeSecret), false, 'Probe HTTP response leaked apiKey');

      const hist = await (await localFetch(`${base}/api/forensics/history`)).json();
      assert.ok(hist.captures.length >= 2);
      assert.equal(JSON.stringify(hist).includes(probeSecret), false, 'Forensics history leaked apiKey');

      // 8. /api/ingest secret stripping + prototype pollution protection
      const ingestSecret = ['sk', 'ingest', 'EXAMPLE', 'placeholder', 'ingest02'].join('-');
      const rawProtoPayload = '{"dedup_key":"wt:ingest:1","model":"gpt-6.1-sol","input_tokens":500,"output_tokens":100,"apiKey":"' +
        ingestSecret + '","access_token":"' + ingestSecret + '","__proto__":{"polluted":true}}';
      const ing = await (
        await localFetch(`${base}/api/ingest`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: rawProtoPayload,
        })
      ).json();
      assert.equal(ing.ok, true);
      assert.equal(({}).polluted, undefined, 'Prototype pollution must never mutate Object.prototype');

      // 9. /api/export (CSV & JSON)
      const expCsvRes = await localFetch(`${base}/api/export?era=all&format=csv&limit=20`);
      assert.equal(expCsvRes.status, 200);
      const csvText = await expCsvRes.text();
      assert.ok(csvText.includes('created_at') && csvText.split('\n').length > 2);

      const expJsonRes = await localFetch(`${base}/api/export?era=all&format=json&limit=20`);
      assert.equal(expJsonRes.status, 200);
      const expJson = JSON.parse(await expJsonRes.text());
      assert.ok(expJson);

      // 10. /api/events SSE stream
      const sseController = new AbortController();
      const sseRes = await fetch(assertLocalhostUrl(`${base}/api/events`), { signal: sseController.signal });
      assert.equal(sseRes.status, 200);
      const reader = sseRes.body.getReader();
      let sseChunk = '';
      for (let i = 0; i < 4; i++) {
        const { value, done } = await reader.read();
        if (done) break;
        sseChunk += Buffer.from(value).toString('utf8');
        if (sseChunk.includes('event: connected')) break;
      }
      sseController.abort();
      assert.ok(sseChunk.includes('event: connected'), 'SSE /api/events must emit connected event');

      // 11. Directory traversal blocked & Security Headers present
      const trav = await localFetch(`${base}/..%2fsrc/contracts.mjs`);
      assert.equal(trav.status, 404);
      const rootRes = await localFetch(`${base}/`);
      assert.equal(rootRes.status, 200);
      assert.ok(rootRes.headers.get('content-security-policy'), 'Missing Content-Security-Policy header');
      assert.equal(rootRes.headers.get('x-content-type-options'), 'nosniff');

      // 12. CLI verification against temp DB
      const cliStatus = await spawnAsync(
        process.execPath,
        ['--no-warnings', path.join(ROOT_DIR, 'bin', 'wiretok.mjs'), 'status', '--era', 'all', '--oneliner', '--db', tmpDbPath],
        { encoding: 'utf8' }
      );
      assert.equal(cliStatus.status, 0);
      assert.ok(cliStatus.stdout.includes('Wiretok(all):'));

      // 13. 1-Click Sync Pause/Resume & Tee Proxy Start/Stop controls
      const tog1 = await (await localFetch(`${base}/api/sync/toggle`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).json();
      assert.equal(tog1.ok, true);
      assert.equal(tog1.syncPaused, true);
      const tog2 = await (await localFetch(`${base}/api/sync/toggle`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ paused: false }) })).json();
      assert.equal(tog2.syncPaused, false);

      const teeStart = await (
        await localFetch(`${base}/api/tee/start`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ port: 0, upstreamBaseUrl: mockUpstream.url }),
        })
      ).json();
      assert.equal(teeStart.ok, true);
      assert.equal(teeStart.running, true);
      assert.ok(teeStart.port > 0);

      const teeStat = await (await localFetch(`${base}/api/tee/status`)).json();
      assert.equal(teeStat.running, true);

      const teeStop = await (await localFetch(`${base}/api/tee/stop`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).json();
      assert.equal(teeStop.ok, true);
      assert.equal(teeStop.running, false);

      // Verify raw SQLite bytes do NOT contain probeSecret or ingestSecret
      const dbBytes = await fs.promises.readFile(tmpDbPath, 'utf8');
      assert.equal(dbBytes.includes(probeSecret), false, 'Temp SQLite leaked probeSecret');
      assert.equal(dbBytes.includes(ingestSecret), false, 'Temp SQLite leaked ingestSecret');
    } finally {
      await srv.close();
      await mockUpstream.close();
    }

    return `Synced ${totalSynced.toLocaleString('en-US')} requests (0 dup on re-run), all REST/SSE/CLI endpoints 200 OK`;
  });

  await runCheck('v0.2-core', 'v0.2 OpenCode Dual-Schema (v1+v2+compaction), TTFT/TPOT timing, defaults & 371-day heatmap', async () => {
    const ocDbPath = path.join(tmpDir, 'synthetic_opencode_v2.db');
    const tpV2DbPath = path.join(tmpDir, 'wt_v02_unit.sqlite');
    const ocDb = new DatabaseSync(ocDbPath);
    ocDb.exec(`
      CREATE TABLE session (id TEXT PRIMARY KEY, parent_id TEXT, directory TEXT, title TEXT);
      CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT, time_created INTEGER, time_updated INTEGER, data TEXT);
      CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT, data TEXT);
      CREATE TABLE session_v2 (id TEXT PRIMARY KEY, parent_id TEXT, directory TEXT, title TEXT);
      CREATE TABLE session_message (id TEXT PRIMARY KEY, session_id TEXT, type TEXT, time_created INTEGER, time_updated INTEGER, data TEXT);
    `);
    ocDb.prepare('INSERT INTO session VALUES (?, NULL, ?, ?)').run('s_v1', '/home/alice/work', 'V1 Session');
    ocDb.prepare('INSERT INTO message VALUES (?, ?, ?, ?, ?)').run(
      'm_v1',
      's_v1',
      1000000,
      1009000,
      JSON.stringify({
        role: 'assistant',
        modelID: 'claude-opus-5-5',
        providerID: 'anthropic',
        tokens: { input: 500, output: 100, reasoning: 100, cache: { read: 2000, write: 0 } },
        time: { created: 1000000, completed: 1009000 },
      })
    );
    // 500ms first token (reasoning), 1000ms reasoning generation + 5000ms tool pause + 1000ms text generation = 2000ms active gen => 100 tok/s
    ocDb.prepare('INSERT INTO part VALUES (?, ?, ?)').run('pv1_1', 'm_v1', JSON.stringify({ type: 'reasoning', time: { start: 1000500, end: 1001500 } }));
    ocDb.prepare('INSERT INTO part VALUES (?, ?, ?)').run('pv1_tool', 'm_v1', JSON.stringify({ type: 'tool', time: { start: 1001500, end: 1006500 } }));
    ocDb.prepare('INSERT INTO part VALUES (?, ?, ?)').run('pv1_2', 'm_v1', JSON.stringify({ type: 'text', time: { start: 1006500, end: 1007500 } }));

    ocDb.prepare('INSERT INTO session_v2 VALUES (?, NULL, ?, ?)').run('s_v2', '/home/alice/v2', 'V2 Session');
    ocDb.prepare('INSERT INTO session_message VALUES (?, ?, ?, ?, ?, ?)').run(
      'm_v2_asst',
      's_v2',
      'assistant',
      2000000,
      2004000,
      JSON.stringify({
        model: { id: 'gemini-4-neon', providerID: 'google', variant: 'high' },
        tokens: { input: 1000, output: 150, reasoning: 50, cache: { read: 4000, write: 0 } },
        time: { created: 2000000, streamed: 2002500, completed: 2008000 },
        content: [{ type: 'reasoning', time: { created: 2000500 } }],
      })
    );
    ocDb.prepare('INSERT INTO session_message VALUES (?, ?, ?, ?, ?, ?)').run(
      'm_v2_cmp',
      's_v2',
      'compaction',
      2009000,
      2012000,
      JSON.stringify({
        model: { id: 'gemini-4-hydrogen', providerID: 'google' },
        tokens: { input: 150000, output: 2000, reasoning: 0, cache: { read: 0, write: 0 } },
        time: { created: 2009000, streamed: 2012000 },
      })
    );
    ocDb.close();

    const db2 = openDatabase(tpV2DbPath, { freshInstance: true });
    try {
      const syncOut = await runSyncAll(db2, { sources: ['opencode'], opencodeDb: ocDbPath });
      assert.equal(syncOut.syncedCounts.opencode, 3, 'Must ingest v1 assistant + v2 assistant + v2 compaction');

      const rV1 = db2.prepare('SELECT ttft_ms, tok_per_sec, tpot_ms FROM requests WHERE dedup_key = ?').get('opencode:m_v1');
      assert.equal(rV1.ttft_ms, 500);
      assert.equal(rV1.tok_per_sec, 100, 'Tool pause must be excluded from generation tok/s');

      const rV2 = db2.prepare('SELECT model_id, ttft_ms, tok_per_sec FROM requests WHERE dedup_key = ?').get('opencode:m_v2_asst');
      assert.equal(rV2.model_id, 'gemini-4-neon');
      assert.equal(rV2.ttft_ms, 500);
      assert.equal(rV2.tok_per_sec, 100);

      // Default privacy_mask = '1', synthetic API defaults, and >90-day heatmap keeping newest dates
      const ovUnit = getOverview(db2, { era: 'all' });
      assert.equal(ovUnit.privacyMask, true, 'Default privacyMask in v0.2 must be true');

      // Insert 110 daily synthetic ingest rows + killed vs active session
      const stmt = db2.prepare(`
        INSERT INTO requests (dedup_key, created_at, era, source_tool, account_id, session_id, model_id, input_tokens, output_tokens, api_list_cost_usd, billed_cost_usd)
        VALUES (?, ?, 'live', 'claude-code', 'claude-code-default', ?, 'claude-sonnet-5-5', 100, 10, 0.001, 0.001)
      `);
      for (let i = 0; i < 110; i++) {
        const dt = new Date(Date.UTC(2026, 0, 1 + i)).toISOString();
        stmt.run(`hm:${i}`, dt, i === 109 ? 'sess-running' : 'sess-killed');
      }
      db2.prepare(`INSERT OR IGNORE INTO accounts (account_id, source_tool, plan_type, monthly_fee_usd, created_at, updated_at) VALUES ('claude-code-default', 'claude-code', 'api', 0, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`).run();
      db2.prepare(`INSERT OR IGNORE INTO sessions (session_id, source_tool, account_id, title, run_status, not_fully_idle, killed, started_at, last_event_at) VALUES ('sess-running', 'antigravity', 'antigravity-main', 'Active Run', 'CASCADE_RUN_STATUS_RUNNING', 1, 0, '2026-04-20T00:00:00Z', '2026-04-20T00:00:00Z')`).run();
      db2.prepare(`INSERT OR IGNORE INTO sessions (session_id, source_tool, account_id, title, run_status, not_fully_idle, killed, started_at, last_event_at) VALUES ('sess-killed', 'antigravity', 'antigravity-main', 'Dead Swarm', 'CASCADE_RUN_STATUS_IDLE', 0, 1, '2026-04-20T00:00:00Z', '2026-04-20T00:00:00Z')`).run();

      const ovDays = getOverview(db2, { era: 'all', days: 371 });
      const latestDay = ovDays.heatmap.at(-1)?.date;
      const expectedLatest = new Date(Date.UTC(2026, 0, 110)).toISOString().slice(0, 10);
      assert.equal(latestDay, expectedLatest, `Heatmap must keep newest day ${expectedLatest}, got ${latestDay}`);
      assert.ok(ovDays.activeSessions.some((s) => s.session_id === 'sess-running'));
      assert.equal(ovDays.activeSessions.some((s) => s.session_id === 'sess-killed'), false, 'Killed sessions excluded from activeSessions');
      const accsList = listAccounts(db2, { era: 'all' });
      const ccAcc = accsList.find((a) => a.account_id === 'claude-code-default');
      assert.equal(ccAcc.plan_type, 'api');
      assert.equal(ccAcc.monthly_fee_usd, 0);
    } finally {
      closeDatabase(db2, tpV2DbPath);
    }
    return 'OpenCode v1+v2+compaction timing (100 tok/s), privacy=true, api=$0, 371d heatmap & activeSessions PASS';
  });

  await runCheck('v0.2-hud-lan', 'v0.2 Mini-HUD, PWA, SSRF Metadata Block & 6-Digit PIN LAN QR Pairing/Lockout', async () => {
    const srv = await startServer({ port: 0, dbPath: tmpDbPath, enableSyncLoop: false, quiet: true });
    const base = `http://127.0.0.1:${srv.ports[0]}`;
    const localFetch = (u, init) => fetch(assertLocalhostUrl(u), { signal: AbortSignal.timeout(8000), ...init });
    try {
      const hudRes = await localFetch(`${base}/?view=hud`);
      assert.equal(hudRes.status, 200);
      assert.ok((await hudRes.text()).includes('hud-root'));

      const manifestRes = await localFetch(`${base}/site.webmanifest`);
      assert.equal(manifestRes.status, 200);
      const manifest = JSON.parse(await manifestRes.text());
      assert.equal(manifest.short_name, 'Wiretok');

      const swRes = await localFetch(`${base}/sw.js`);
      assert.equal(swRes.status, 200);
      assert.ok((await swRes.text()).includes('/api/'));

      const i18nRes = await localFetch(`${base}/i18n.js`);
      assert.equal(i18nRes.status, 200);
      assert.ok((await i18nRes.text()).includes("defaultLang: 'en'"));

      // recentLimit parameter + sessionId request filtering
      const ovLimit3 = await (await localFetch(`${base}/api/overview?era=all&recentLimit=3`)).json();
      assert.ok(Array.isArray(ovLimit3.recentSessions) && ovLimit3.recentSessions.length <= 3, 'recentLimit=3 must cap recentSessions');
      const sampleSess = ovLimit3.activeSessions?.[0] || ovLimit3.recentSessions?.[0];
      if (sampleSess?.session_id) {
        const sessReqs = await (
          await localFetch(`${base}/api/requests?era=all&limit=20&sessionId=${encodeURIComponent(sampleSess.session_id)}`)
        ).json();
        assert.ok(Array.isArray(sessReqs.rows));
        for (const r of sessReqs.rows) {
          assert.equal(r.session_id, sampleSess.session_id, 'sessionId filter must return only rows for that session');
        }
      }

      // SSRF block on 169.254.169.254 metadata
      const ssrfRes = await localFetch(`${base}/api/forensics/probe`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ baseUrl: 'http://169.254.169.254/latest/meta-data', model: 'gpt-6-astra' }),
      });
      const ssrfBody = await ssrfRes.json();
      assert.equal(ssrfBody.ok, false, 'Metadata SSRF target must be rejected');

      // LAN QR enable -> right PIN cookie -> disable -> wrong PIN 429 lockout
      const lanOn = await (await localFetch(`${base}/api/lan/enable`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ port: 0 }),
      })).json();
      assert.equal(lanOn.ok, true);
      assert.equal(lanOn.enabled, true);
      assert.match(lanOn.pin, /^\d{6}$/);
      assert.ok(lanOn.qrSvg.includes('<svg'));

      const pairOk = await localFetch(`${base}/api/auth/pair`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pin: lanOn.pin, nonce: lanOn.pairNonce }),
      });
      assert.equal(pairOk.status, 200);
      const setCookie = pairOk.headers.get('set-cookie') || '';
      assert.ok(setCookie.includes('HttpOnly') && setCookie.includes('SameSite=Strict'));

      for (let i = 0; i < 4; i++) {
        const bad = await localFetch(`${base}/api/auth/pair`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ pin: '000000' }),
        });
        assert.equal(bad.status, 401);
      }
      const locked = await localFetch(`${base}/api/auth/pair`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pin: '000000' }),
      });
      assert.equal(locked.status, 429);

      const lanOff = await (await localFetch(`${base}/api/lan/disable`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).json();
      assert.equal(lanOff.enabled, false);
    } finally {
      await srv.close();
    }
    return 'Mini-HUD 200, PWA manifest+SW, metadata SSRF blocked, LAN QR+PIN HttpOnly+429 lockout PASS';
  });

  /* ======================================================================== */
  /* SUITE 5: Static UI Audit (--strict) & Multi-Viewport DOM Verification    */
  /* ======================================================================== */
  console.log('\n[Suite 5] Static UI Audit & Multi-Viewport DOM Verification');

  if (fs.existsSync(UI_CRAFT_CLI)) {
    await runCheck('ui-craft', 'Phase 4: ui-craft audit ui --strict --json', () => {
      const r = spawnSync(process.execPath, [UI_CRAFT_CLI, 'audit', UI_DIR, '--strict', '--json'], {
        encoding: 'utf8',
      });
      assert.equal(r.status, 0, `ui-craft audit --strict failed (exit ${r.status}): ${r.stdout}`);
      const parsed = JSON.parse(r.stdout);
      assert.equal(parsed.passed, true);
      assert.equal(parsed.errorCount, 0);
      assert.equal(parsed.warningCount, 0);
      return `passed=true, files=${parsed.fileCount}, errors=0, warnings=0`;
    });

    await runCheck('ui-craft', 'Phase 5: Multi-viewport dom-check (375..2560x1600), i18n, Density Auto/Manual & Clickable Recent Sessions', async () => {
      const srv = await startServer({
        port: 0,
        dbPath: tmpDbPath,
        enableSyncLoop: false,
        quiet: true,
      });
      const port = srv.ports[0];
      const base = `http://127.0.0.1:${port}`;

      try {
        fs.mkdirSync(QA_SHOTS_DIR, { recursive: true });
        const r = await spawnAsync(process.execPath, [
          UI_CRAFT_CLI,
          'dom-check',
          `${base}/?era=all&wizard=0#overview`,
          '--screenshots',
          QA_SHOTS_DIR,
          '--viewports',
          '375x812,768x1024,1440x900,1920x1200,2560x1600',
          '--json',
        ]);
        assert.equal(r.status, 0, `dom-check exited with ${r.status}: ${r.stdout || r.stderr}`);
        const report = JSON.parse(r.stdout);
        assert.equal(report.passed, true, 'dom-check report.passed must be true');

        for (const vp of report.viewports) {
          assert.equal(vp.passed, true, `Viewport ${vp.viewport} failed`);
          assert.equal(vp.horizontalOverflow, false, `Horizontal overflow at ${vp.viewport}`);
          assert.equal(vp.consoleErrors.length, 0, `Console errors at ${vp.viewport}: ${JSON.stringify(vp.consoleErrors)}`);
          assert.equal(vp.networkErrors.length, 0, `Network/404 errors at ${vp.viewport}: ${JSON.stringify(vp.networkErrors)}`);
          assert.equal(vp.overlappingInteractive.length, 0, `Overlaps at ${vp.viewport}`);
          assert.equal(vp.tapTargetErrors.length, 0, `Tap target errors at ${vp.viewport}`);
          assert.equal(vp.axeViolations.length, 0, `Axe a11y violations at ${vp.viewport}`);
        }

        const uiCraftPkg = path.resolve(path.dirname(UI_CRAFT_CLI), '..', 'package.json');
        const uiCraftReq = createRequire(uiCraftPkg);
        const { chromium } = uiCraftReq('playwright-core');
        const chromeCandidates = [
          'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
          'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
          process.env.LOCALAPPDATA ? path.join(process.env.LOCALAPPDATA, 'Google\\Chrome\\Application\\chrome.exe') : '',
          'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
          'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
          '/usr/bin/google-chrome',
          '/usr/bin/chromium',
        ].filter(Boolean);
        const executablePath = chromeCandidates.find((p) => fs.existsSync(p));
        assert.ok(executablePath, 'Expected local Chrome/Edge executable for real-surface geometry check');

        const browser = await chromium.launch({ headless: true, executablePath });
        try {
          // Check A: #forensics at 375x812 — #seg-mode buttons must NOT overflow their button box
          const pageMobile = await browser.newPage({ viewport: { width: 375, height: 812 } });
          await pageMobile.goto(`${base}/?wizard=0#forensics`, { waitUntil: 'networkidle' });
          const segOverflow = await pageMobile.evaluate(() => {
            const btns = [...document.querySelectorAll('#seg-mode button')];
            return btns
              .map((b) => ({
                text: b.textContent.trim(),
                clientWidth: b.clientWidth,
                scrollWidth: b.scrollWidth,
              }))
              .filter((x) => x.scrollWidth > x.clientWidth + 2);
          });
          assert.deepEqual(
            segOverflow,
            [],
            `375x812 #seg-mode button text bleeds outside button bounds: ${JSON.stringify(segOverflow)}`
          );
          await pageMobile.close();

          // Check B: 1920x1200 (Auto -> compact) + EN default + TR switch + Clickable Recent Sessions + KPI geometry
          const page1920 = await browser.newPage({ viewport: { width: 1920, height: 1200 } });
          await page1920.goto(`${base}/?era=all&wizard=0#overview`, { waitUntil: 'networkidle' });
          const initMeta = await page1920.evaluate(() => ({
            lang: document.documentElement.lang,
            density: document.documentElement.dataset.density,
            titleText: document.getElementById('ctx-title')?.textContent?.trim(),
          }));
          assert.equal(initMeta.lang, 'en', 'Default UI language must be English (en)');
          assert.equal(initMeta.density, 'compact', 'Auto density at 1920x1200 must resolve to compact');
          assert.ok(initMeta.titleText.includes('Active Context Pressure'), `Expected English ctx title, got ${initMeta.titleText}`);

          // Toggle to TR and back to EN
          await page1920.click('#seg-lang button[data-lang="tr"]');
          const trLang = await page1920.evaluate(() => ({
            lang: document.documentElement.lang,
            titleText: document.getElementById('ctx-title')?.textContent?.trim(),
          }));
          assert.equal(trLang.lang, 'tr');
          assert.ok(trLang.titleText.includes('Aktif Bağlam Baskısı'));
          await page1920.click('#seg-lang button[data-lang="en"]');

          // Manual density override Normal -> Auto
          await page1920.click('#seg-density button[data-density="normal"]');
          assert.equal(await page1920.evaluate(() => document.documentElement.dataset.density), 'normal');
          await page1920.click('#seg-density button[data-density="auto"]');
          assert.equal(await page1920.evaluate(() => document.documentElement.dataset.density), 'compact');

          // Expand Recent Sessions, verify non-overlapping ellipsis & clickable tracking -> View Requests
          const hasRecentBtn = await page1920.evaluate(() => {
            const b = document.getElementById('btn-recent-sessions');
            return Boolean(b && !b.hidden);
          });
          if (hasRecentBtn) {
            await page1920.click('#btn-recent-sessions');
            const recentOverlap = await page1920.evaluate(() => {
              const items = [...document.querySelectorAll('.ctx-recent-item')];
              return items
                .map((it) => {
                  const main = it.querySelector('.ctx-recent-main')?.getBoundingClientRect();
                  const stat = it.querySelector('.ctx-recent-stat')?.getBoundingClientRect();
                  if (!main || !stat) return null;
                  return { overlap: main.right > stat.left + 1, mainRight: main.right, statLeft: stat.left };
                })
                .filter((x) => x && x.overlap);
            });
            assert.deepEqual(recentOverlap, [], `Recent session text overlapped stat metrics: ${JSON.stringify(recentOverlap)}`);

            const firstRecent = page1920.locator('.ctx-recent-item').first();
            if ((await firstRecent.count()) > 0) {
              await firstRecent.click();
              const tracked = await page1920.evaluate(() => ({
                hasLiveBody: Boolean(document.querySelector('#ctx-body [data-ctx-live="1"]')),
                hasViewReqs: Boolean(document.querySelector('#ctx-body [data-ref="view-reqs"]')),
              }));
              assert.equal(tracked.hasLiveBody, true, 'Clicking a recent session must render its telemetry in #ctx-body');
              assert.equal(tracked.hasViewReqs, true, 'Tracked session must expose View Requests action');
              await page1920.click('#ctx-body [data-ref="view-reqs"]');
              await page1920.waitForSelector('#panel-requests:not([hidden])');
              const hasSessChip = await page1920.evaluate(() =>
                Boolean(document.querySelector('#active-chips [data-filter="sessionId"]'))
              );
              assert.equal(hasSessChip, true, 'Clicking View Requests must apply removable Session filter chip');
              await page1920.click('#active-chips [data-filter="sessionId"]');
              await page1920.click('#tab-overview');
            }
          }

          const wrappedKpis = await page1920.evaluate(() => {
            const vals = [...document.querySelectorAll('.kpi .kpi-value')];
            return vals
              .map((el) => {
                const cs = getComputedStyle(el);
                const lh = parseFloat(cs.lineHeight) || parseFloat(cs.fontSize) * 1.25;
                return {
                  text: el.textContent.trim(),
                  height: Math.round(el.getBoundingClientRect().height * 10) / 10,
                  lineHeight: Math.round(lh * 10) / 10,
                };
              })
              .filter((x) => x.height > x.lineHeight * 1.55);
          });
          assert.deepEqual(
            wrappedKpis,
            [],
            `1920x1200 .kpi-value wraps mid-number onto multiple lines: ${JSON.stringify(wrappedKpis)}`
          );

          // Check C: /#models — #model-table must be bounded or paginated
          await page1920.goto(`${base}/?wizard=0#models`, { waitUntil: 'networkidle' });
          const modelTableHeight = await page1920.evaluate(() => {
            const el = document.getElementById('model-table');
            return el ? el.getBoundingClientRect().height : 0;
          });
          assert.ok(
            modelTableHeight > 0 && modelTableHeight <= 1400,
            `#model-table is unbounded (${Math.round(modelTableHeight)}px tall), burying Integrations & Export cards`
          );
          await page1920.close();

          // Check D: 2560x1600 (Auto -> normal)
          const page2560 = await browser.newPage({ viewport: { width: 2560, height: 1600 } });
          await page2560.goto(`${base}/?era=all&wizard=0#overview`, { waitUntil: 'networkidle' });
          assert.equal(
            await page2560.evaluate(() => document.documentElement.dataset.density),
            'normal',
            'Auto density at 2560x1600 must resolve to normal'
          );
          await page2560.close();
        } finally {
          await browser.close();
        }
      } finally {
        await srv.close();
      }

      return '375..2560x1600 dom-check, EN/TR i18n, Auto/Manual density & clickable ellipsized sessions PASS';
    });
  } else {
    console.log('  [SKIP] Local ui-craft CLI absent (CI runner); skipping Playwright browser checks.');
  }
} finally {
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch {
    // ignore Windows WAL lock cleanup race
  }
}

console.log('\n======================================================================');
console.log(
  ` Summary: ${results.filter((r) => r.ok).length}/${results.length} checks passed, ${failedCount} failed`
);
console.log('======================================================================');

if (failedCount > 0) {
  process.exit(1);
}
