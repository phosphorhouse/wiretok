/**
 * Antigravity collector (Antigravity 2.0 / IDE / CLI) — strictly read-only & incremental.
 *
 * Sources
 *  - <root>/brain/<conv>/.system_generated/logs/transcript.jsonl   (PLANNER_RESPONSE steps carry input/cache_read/output tokens)
 *  - <root>/conversation_summaries.db                              (title, workspace_uris, parent, agent_name, group_id, status, not_fully_idle, killed, nesting_depth) [readOnly]
 *  - <root>/brain/<conv>/.system_generated/swarm/members.json      (swarm worker -> model)
 *  - <DATA_DIR>/hook_events.jsonl                                  (live PreInvocation/PostInvocation stamps: timing, model, workspace)
 *  - ~/.gemini/google_accounts.json                                (opt-in ONLY when useGeminiCliEmail=true; never read by default)
 *
 * Never reads oauth_creds.json. Never writes to any Antigravity file.
 */
import fs from 'node:fs';
import path from 'node:path';
import {
  getLocalSourcePaths,
  HOOK_EVENTS_LOG,
  SEED_MODELS,
} from '../contracts.mjs';
import {
  debugLog,
  emptyResult,
  exists,
  fileUriToPath,
  getCursor,
  getMeta,
  hasTable,
  knownModelSet,
  num,
  openReadOnly,
  parseJsonSafe,
  readJsonlIncremental,
  resolveModel,
  statSafe,
  tableColumns,
  toIso,
} from './util.mjs';

const SETTINGS_RE = /`Model Selection` from (.*?) to (.+?)\.\s+(?:No need|If reporting)/s;
const MODEL_NAME_RE = /^[A-Za-z][A-Za-z0-9 .()_\/-]{1,60}$/;

export function parseSettingsChange(content) {
  if (typeof content !== 'string' || !content.includes('USER_SETTINGS_CHANGE')) return null;
  const blocks = content.match(/<USER_SETTINGS_CHANGE>[\s\S]*?<\/USER_SETTINGS_CHANGE>/g);
  if (!blocks) return null;
  let found = null;
  for (const b of blocks) {
    const m = SETTINGS_RE.exec(b);
    if (m && MODEL_NAME_RE.test(m[2].trim())) found = { from: m[1].trim(), to: m[2].trim() };
  }
  return found && found.to && found.to !== 'None' ? found : null;
}

/** ONLY the `active` string is ever extracted from google_accounts.json (opt-in only). */
export function readActiveAccount(file) {
  try {
    const j = parseJsonSafe(fs.readFileSync(file, 'utf8'));
    const a = j && typeof j.active === 'string' ? j.active.trim() : null;
    return a || null;
  } catch (err) {
    debugLog(err, 'readActiveAccount');
    return null;
  }
}

function listConversationDirs(root) {
  const brain = path.join(root, 'brain');
  let names = [];
  try {
    names = fs.readdirSync(brain, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name);
  } catch (err) {
    debugLog(err, 'listConversationDirs');
    return [];
  }
  return names.map((id) => ({ id, dir: path.join(brain, id) }));
}

function safeRead(f) {
  try {
    return fs.readFileSync(f, 'utf8');
  } catch (err) {
    debugLog(err, 'safeRead');
    return '';
  }
}

/** conversation_id -> { model, agent, role } from every swarm/members.json under brain/. */
export function loadSwarmMembers(root) {
  const map = new Map();
  for (const c of listConversationDirs(root)) {
    const f = path.join(c.dir, '.system_generated', 'swarm', 'members.json');
    if (!exists(f)) continue;
    const j = parseJsonSafe(safeRead(f));
    if (!j?.members) continue;
    for (const [name, m] of Object.entries(j.members)) {
      if (!m?.conversation_id) continue;
      const model = m.applied_model || m.desired_model || m.model || null;
      map.set(m.conversation_id, { model, agent: name, role: m.role || null });
    }
  }
  return map;
}

export function loadSummaries(root) {
  const out = new Map();
  const dbFile = path.join(root, 'conversation_summaries.db');
  const db = openReadOnly(dbFile);
  if (!db) return out;
  try {
    const cols = new Set(tableColumns(db, 'conversation_summaries'));
    const want = [
      'conversation_id',
      'title',
      'workspace_uris',
      'parent_conversation_id',
      'agent_name',
      'group_id',
      'source',
      'step_count',
      'status',
      'not_fully_idle',
      'killed',
      'nesting_depth',
      'last_modified_time',
    ];
    const sel = want.filter((c) => cols.has(c));
    if (sel.length && sel.includes('conversation_id')) {
      const orderClause = cols.has('last_modified_time') ? 'ORDER BY last_modified_time DESC ' : '';
      const rows = db
        .prepare(`SELECT ${sel.join(', ')} FROM conversation_summaries ${orderClause}LIMIT 5000`)
        .all();
      for (const r of rows) {
        let ws = null;
        const arr = parseJsonSafe(r.workspace_uris || '[]');
        if (Array.isArray(arr) && arr.length) ws = fileUriToPath(arr[0]);
        out.set(r.conversation_id, {
          title: r.title || null,
          workspace: ws,
          parent: r.parent_conversation_id || null,
          agent_name: r.agent_name || null,
          group_id: r.group_id || null,
          run_status: r.status !== null && r.status !== undefined ? String(r.status) : '',
          not_fully_idle: r.not_fully_idle ? 1 : 0,
          killed: r.killed ? 1 : 0,
          nesting_depth: num(r.nesting_depth, 0),
          last_modified_time: toIso(r.last_modified_time),
        });
      }
    }
    if (hasTable(db, 'conversation_parents')) {
      for (const r of db.prepare('SELECT conversation_id, parent_id FROM conversation_parents LIMIT 5000').all()) {
        const cur = out.get(r.conversation_id);
        if (cur && !cur.parent) cur.parent = r.parent_id;
        else if (!cur) {
          out.set(r.conversation_id, {
            title: null,
            workspace: null,
            parent: r.parent_id,
            agent_name: null,
            group_id: null,
            run_status: '',
            not_fully_idle: 0,
            killed: 0,
            nesting_depth: 0,
            last_modified_time: null,
          });
        }
      }
    }
  } catch (err) {
    debugLog(err, 'loadSummaries');
  } finally {
    try {
      db.close();
    } catch (err) {
      debugLog(err, 'loadSummaries:close');
    }
  }
  return out;
}

/**
 * Live stamps: convId -> sorted [{ ts, step, model, account, hookEventName, invocationNum, initialNumSteps, workspace }]
 * with `.invocations` containing paired PreInvocation/PostInvocation records keyed by (conversationId, invocationNum).
 */
export function loadHookStamps(file = HOOK_EVENTS_LOG) {
  const map = new Map();
  const invMaps = new Map(); // convId -> Map<invocationNum, pairedObj>
  const st = statSafe(file);
  if (!st) return map;
  let text = '';
  try {
    if (st.size > 32 * 1024 * 1024) {
      const fd = fs.openSync(file, 'r');
      try {
        const len = 32 * 1024 * 1024;
        const buf = Buffer.allocUnsafe(len);
        fs.readSync(fd, buf, 0, len, st.size - len);
        text = buf.toString('utf8');
        text = text.slice(text.indexOf('\n') + 1);
      } finally {
        fs.closeSync(fd);
      }
    } else {
      text = fs.readFileSync(file, 'utf8');
    }
  } catch (err) {
    debugLog(err, 'loadHookStamps');
    return map;
  }

  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    const o = parseJsonSafe(line);
    if (!o || typeof o !== 'object') continue;
    const conv = o.conversationId || o.conversation_id || o.session_id || o.sessionId || o.trajectory_id;
    if (!conv) continue;
    const hookEventName = typeof o.hookEventName === 'string' ? o.hookEventName : '';
    const model = o.modelName || o.model_name || o.model_id || o.model || o.selected_model || null;
    const account = o.activeAccount || o.account || o.account_id || o.email || o.active_account || null;
    const workspace = (Array.isArray(o.workspacePaths) && o.workspacePaths[0]) || o.cwd || null;
    const invocationNum = Number.isFinite(Number(o.invocationNum)) && o.invocationNum !== null ? Number(o.invocationNum) : null;
    const initialNumSteps = Number.isFinite(Number(o.initialNumSteps)) && o.initialNumSteps !== null ? Number(o.initialNumSteps) : null;
    const step = o.stepIdx ?? o.step_index ?? o.stepIndex ?? null;
    if (!model && !account && !hookEventName) continue;
    const ts = Number(o.tsMs) || Date.parse(toIso(o.ts || o.timestamp || o.created_at || o.time) || '') || 0;

    const arr = map.get(conv) || [];
    arr.push({
      ts,
      step,
      model,
      account,
      hookEventName,
      invocationNum,
      initialNumSteps,
      workspace,
    });
    map.set(conv, arr);

    if ((hookEventName === 'PreInvocation' || hookEventName === 'PostInvocation') && invocationNum !== null) {
      let imap = invMaps.get(conv);
      if (!imap) {
        imap = new Map();
        invMaps.set(conv, imap);
      }
      let pair = imap.get(invocationNum);
      if (!pair) {
        pair = {
          invocationNum,
          preTsMs: null,
          postTsMs: null,
          initialNumSteps: null,
          step: null,
          model: null,
          account: null,
          workspace: null,
        };
        imap.set(invocationNum, pair);
      }
      if (hookEventName === 'PreInvocation') {
        if (ts && (!pair.preTsMs || ts < pair.preTsMs)) pair.preTsMs = ts;
        if (initialNumSteps !== null) pair.initialNumSteps = initialNumSteps;
      } else if (hookEventName === 'PostInvocation') {
        if (ts && (!pair.postTsMs || ts > pair.postTsMs)) pair.postTsMs = ts;
      }
      if (step !== null && step !== undefined) pair.step = Number(step);
      if (model && !pair.model) pair.model = model;
      if (account && !pair.account) pair.account = account;
      if (workspace && !pair.workspace) pair.workspace = workspace;
    }
  }

  for (const [conv, arr] of map.entries()) {
    arr.sort((a, b) => a.ts - b.ts);
    const imap = invMaps.get(conv);
    arr.invocations = imap
      ? [...imap.values()].sort((a, b) => (a.preTsMs || a.postTsMs || 0) - (b.preTsMs || b.postTsMs || 0))
      : [];
  }
  return map;
}

export function pickStamp(stamps, stepIndex, tsMs) {
  if (!stamps?.length) return { exact: null, before: null, paired: null };
  let exact = null;
  let before = null;
  for (const s of stamps) {
    if (s.step !== null && s.step !== undefined && Number(s.step) === Number(stepIndex) && s.ts && Math.abs(s.ts - tsMs) < 120000) {
      exact = s;
    }
    if (s.ts && s.ts <= tsMs + 1500) before = s;
  }

  let paired = null;
  const invs = Array.isArray(stamps.invocations) ? stamps.invocations : [];
  if (invs.length) {
    // 1. Exact step match
    for (const p of invs) {
      const refTs = p.preTsMs || p.postTsMs || 0;
      if (p.step !== null && Number.isFinite(stepIndex) && Number(p.step) === Number(stepIndex) && refTs && Math.abs(refTs - tsMs) < 120000) {
        paired = p;
        break;
      }
    }
    // 2. initialNumSteps + timestamp containment (resolves even when stepIdx is null!)
    if (!paired && Number.isFinite(stepIndex)) {
      for (const p of invs) {
        if (p.initialNumSteps === null) continue;
        if (stepIndex >= p.initialNumSteps && stepIndex <= p.initialNumSteps + 4) {
          const preOk = !p.preTsMs || p.preTsMs <= tsMs + 1500;
          const postOk = !p.postTsMs || tsMs <= p.postTsMs + 1500;
          if (preOk && postOk) {
            paired = p;
            break;
          }
        }
      }
    }
    // 3. Timestamp containment [preTsMs, postTsMs]
    if (!paired && tsMs) {
      let bestSpan = Infinity;
      for (const p of invs) {
        if (p.preTsMs && p.postTsMs && p.preTsMs - 1500 <= tsMs && tsMs <= p.postTsMs + 1500) {
          const span = Math.max(0, p.postTsMs - p.preTsMs);
          if (span < bestSpan) {
            bestSpan = span;
            paired = p;
          }
        }
      }
    }
    // 4. Closest PreInvocation preceding tsMs within 300s
    if (!paired && tsMs) {
      let bestDelta = Infinity;
      for (const p of invs) {
        if (p.preTsMs && p.preTsMs <= tsMs + 1500) {
          const delta = tsMs - p.preTsMs;
          if (delta <= 300000 && delta < bestDelta) {
            bestDelta = delta;
            paired = p;
          }
        }
      }
    }
  }

  return { exact, before, paired };
}

function defaultAccountMeta(tool) {
  if (tool === 'antigravity') return { id: 'antigravity-main', label: 'Antigravity 2.0' };
  if (tool === 'antigravity-ide') return { id: 'antigravity-ide-main', label: 'Antigravity IDE' };
  if (tool === 'antigravity-cli') return { id: 'antigravity-cli-main', label: 'Antigravity CLI' };
  return { id: `${tool}-main`, label: tool };
}

function peekNextStepCreatedMs(lines, startIdx) {
  for (let j = startIdx + 1; j < lines.length; j++) {
    const txt = lines[j]?.text;
    if (!txt || !txt.trim()) continue;
    const nextObj = parseJsonSafe(txt);
    if (!nextObj) continue;
    const iso = toIso(nextObj.created_at);
    if (iso) {
      const ms = Date.parse(iso);
      if (Number.isFinite(ms)) return ms;
    }
    return null;
  }
  return null;
}

/**
 * @param {import('node:sqlite').DatabaseSync|null} db  wiretok DB (for cursors / milestone / known models); may be null for dry runs
 * @param {{milestoneAt?:string, roots?:string[], antigravityRoots?:Array<{tool:string, dir:string}>, useGeminiCliEmail?:boolean, limitConversations?:number, hookFile?:string}} [opts]
 */
export function collectAntigravity(db, opts = {}) {
  const res = emptyResult('antigravity');
  const paths = getLocalSourcePaths();
  const baseRoots = Array.isArray(opts.antigravityRoots)
    ? opts.antigravityRoots
    : [
        { tool: 'antigravity', dir: paths.antigravityDir },
        { tool: 'antigravity-ide', dir: paths.antigravityIdeDir },
        { tool: 'antigravity-cli', dir: paths.antigravityCliDir },
      ];
  const roots = baseRoots.filter((r) => !opts.roots || opts.roots.includes(r.tool));

  const milestoneIso = opts.milestoneAt || getMeta(db, 'milestone_at') || null;
  const milestoneMs = milestoneIso ? Date.parse(milestoneIso) : null;
  const known = knownModelSet(db);
  const ctxWindow = new Map(SEED_MODELS.map((m) => [m.model_id, m.context_window]));
  try {
    if (db) {
      for (const r of db.prepare('SELECT model_id, context_window FROM models LIMIT 50000').all()) {
        if (r.context_window) ctxWindow.set(r.model_id, r.context_window);
      }
    }
  } catch (err) {
    debugLog(err, 'collectAntigravity:models');
  }

  // Opt-in only: never attribute stale Gemini CLI email to Antigravity 2.0 by default
  const useGeminiCliEmail =
    opts.useGeminiCliEmail === true || process.env.WIRETOK_USE_GEMINI_CLI_EMAIL === '1';
  const activeAccount = useGeminiCliEmail ? readActiveAccount(paths.googleAccountsJson) : null;
  const stampsAll = loadHookStamps(opts.hookFile || HOOK_EVENTS_LOG);

  for (const root of roots) {
    if (!exists(root.dir)) continue;
    const counts = { events: 0, files: 0, filesChanged: 0 };
    const acctDef = defaultAccountMeta(root.tool);
    try {
      const summaries = loadSummaries(root.dir);
      // Emit sessionStates for ALL conversations in summaries so live status flags refresh on every sync
      for (const [convId, s] of summaries.entries()) {
        res.sessionStates.push({
          session_id: convId,
          source_tool: root.tool,
          run_status: s.run_status || '',
          not_fully_idle: s.not_fully_idle ? 1 : 0,
          killed: s.killed ? 1 : 0,
          nesting_depth: num(s.nesting_depth, 0),
          last_modified_time: s.last_modified_time || null,
          title: s.title || null,
          workspace: s.workspace || null,
          parent_session_id: s.parent || null,
          agent_name: s.agent_name || null,
          group_id: s.group_id || null,
        });
      }

      const members = loadSwarmMembers(root.dir);
      const loadedMembers = members;
      const convs = listConversationDirs(root.dir);
      const finalModel = new Map();
      const startIdx = res.events.length;

      for (const conv of convs) {
        try {
          const file = path.join(conv.dir, '.system_generated', 'logs', 'transcript.jsonl');
          if (!exists(file)) continue;
          counts.files++;
          const ckey = `agy:${root.tool}:${conv.id}`;
          const cur = getCursor(db, ckey);
          const r = readJsonlIncremental(file, cur);
          if (!r) continue;
          const state = r.reset ? {} : { ...(cur.extra || {}) };
          if (state.model) finalModel.set(conv.id, { model_id: state.model, effort: state.effort, raw: state.raw_model });
          if (!r.lines.length && !r.reset) continue;
          counts.filesChanged++;
          const sum = summaries.get(conv.id) || {};
          const member = members.get(conv.id) || null;
          const stamps = stampsAll.get(conv.id) || null;

          for (let li = 0; li < r.lines.length; li++) {
            const ln = r.lines[li];
            const t = ln.text;
            if (!t) continue;
            const hasPlanner = t.includes('"PLANNER_RESPONSE"');
            const hasTrigger = t.includes('"USER_INPUT"') || t.includes('"TOOL_RESPONSE"');
            const hasSetting = t.includes('Model Selection');
            if (!hasPlanner && !hasTrigger && !hasSetting) continue;
            const o = parseJsonSafe(t);
            if (!o) continue;

            if (o.type === 'USER_INPUT' || o.type === 'TOOL_RESPONSE') {
              const trigIso = toIso(o.created_at);
              const trigMs = trigIso ? Date.parse(trigIso) : 0;
              if (trigMs) state.lastTriggerMs = trigMs;
            }

            if (hasSetting && o.type === 'USER_INPUT' && typeof o.content === 'string') {
              const ch = parseSettingsChange(o.content);
              if (ch) {
                const rm = resolveModel(ch.to, known);
                state.model = rm.model_id;
                state.effort = rm.effort;
                state.raw_model = ch.to;
              }
            }
            if (hasSetting && state.model) finalModel.set(conv.id, { model_id: state.model, effort: state.effort, raw: state.raw_model });
            if (o.type !== 'PLANNER_RESPONSE') continue;

            // Step indices can restart inside one transcript (context checkpoints / resumed trajectories). Keep the first
            // generation's key exactly `agy:<conv>:<step>`; later generations get a deterministic `~gN` suffix so no request is dropped.
            if (Number.isFinite(o.step_index)) {
              if (state.lastStep !== undefined && o.step_index <= state.lastStep) state.gen = (state.gen || 0) + 1;
              state.lastStep = o.step_index;
            }
            const inTok = num(o.input_tokens);
            const outTok = num(o.output_tokens);
            const cacheRead = num(o.cache_read_tokens);
            if (inTok + outTok + cacheRead <= 0) continue;
            const createdIso = toIso(o.created_at);
            const tsMs = createdIso ? Date.parse(createdIso) : 0;
            const toolCallsCount = Array.isArray(o.tool_calls) ? o.tool_calls.length : 0;

            // Model precedence: exact hook stamp > paired hook invocation > settings change > latest hook stamp > swarm member > unknown
            const { exact, before, paired } = pickStamp(stamps, o.step_index, tsMs);
            let model_id = null;
            let effort = null;
            let raw_model = null;
            let modelSource = null;
            if (exact?.model) {
              const rm = resolveModel(exact.model, known);
              ({ model_id, effort } = rm);
              raw_model = exact.model;
              modelSource = 'hook_exact';
            } else if (paired?.model) {
              const rm = resolveModel(paired.model, known);
              ({ model_id, effort } = rm);
              raw_model = paired.model;
              modelSource = 'hook_paired';
            } else if (state.model) {
              model_id = state.model;
              effort = state.effort;
              raw_model = state.raw_model;
              modelSource = 'settings_change';
            } else if (before?.model) {
              const rm = resolveModel(before.model, known);
              ({ model_id, effort } = rm);
              raw_model = before.model;
              modelSource = 'hook_stamp';
            } else if (member?.model) {
              const rm = resolveModel(member.model, known);
              ({ model_id, effort } = rm);
              raw_model = member.model;
              modelSource = 'swarm_member';
            } else {
              model_id = 'unknown';
              modelSource = 'none';
            }

            // Latency timing: paired PreInvocation/PostInvocation > step_delta_1s fallback (never fabricate ttft_ms)
            let latency_ms = null;
            let latencySource = null;
            if (paired?.preTsMs) {
              if (toolCallsCount === 0 && paired.postTsMs && paired.postTsMs > paired.preTsMs) {
                const dt = paired.postTsMs - paired.preTsMs;
                if (dt >= 1 && dt <= 600000) {
                  latency_ms = Math.round(dt);
                  latencySource = 'hook_pre_post';
                }
              } else if (toolCallsCount > 0) {
                const nextStepCreatedMs = peekNextStepCreatedMs(r.lines, li);
                if (nextStepCreatedMs && nextStepCreatedMs > paired.preTsMs) {
                  const dt = nextStepCreatedMs - paired.preTsMs;
                  if (dt >= 1 && dt <= 600000) {
                    latency_ms = Math.round(dt);
                    latencySource = 'hook_pre_next_step';
                  }
                } else if (tsMs && tsMs > paired.preTsMs) {
                  const dt = tsMs - paired.preTsMs;
                  if (dt >= 1 && dt <= 600000) {
                    latency_ms = Math.round(dt);
                    latencySource = 'hook_pre_step';
                  }
                }
              } else if (tsMs && tsMs > paired.preTsMs) {
                const dt = tsMs - paired.preTsMs;
                if (dt >= 1 && dt <= 600000) {
                  latency_ms = Math.round(dt);
                  latencySource = 'hook_pre_step';
                }
              }
            }
            if (latency_ms === null && state.lastTriggerMs && tsMs > state.lastTriggerMs) {
              const delta = tsMs - state.lastTriggerMs;
              if (delta >= 1000 && delta <= 300000) {
                latency_ms = Math.round(delta);
                latencySource = 'step_delta_1s';
              }
            }
            state.lastTriggerMs = null;

            // Account identity: Antigravity 2.0 defaults to antigravity-main / '' / 'Antigravity 2.0'
            let account_id = acctDef.id;
            let account_email = '';
            let account_label = acctDef.label;
            if (useGeminiCliEmail) {
              const stampAcct =
                exact?.account ||
                paired?.account ||
                (before?.account && tsMs - before.ts < 6 * 3600 * 1000 ? before.account : null);
              const optAcct = stampAcct || activeAccount || null;
              if (optAcct) {
                account_id = optAcct;
                account_email = optAcct.includes('@') ? optAcct : '';
                account_label = optAcct;
              }
            }

            const era = milestoneMs === null || tsMs >= milestoneMs ? 'live' : 'pre_milestone';
            const workspace = sum.workspace || paired?.workspace || exact?.workspace || before?.workspace || null;
            res.events.push({
              dedup_key: `agy:${conv.id}:${o.step_index}${state.gen ? `~g${state.gen}` : ''}`,
              source_tool: root.tool,
              created_at: createdIso,
              completed_at:
                latencySource === 'hook_pre_post' && paired?.postTsMs
                  ? new Date(paired.postTsMs).toISOString()
                  : latencySource === 'hook_pre_next_step' && paired?.preTsMs && latency_ms
                    ? new Date(paired.preTsMs + latency_ms).toISOString()
                    : null,
              session_id: conv.id,
              step_index: o.step_index,
              account_id,
              account_email,
              account_label,
              model_id,
              raw_model,
              provider: model_id.startsWith('claude') ? 'anthropic' : model_id.startsWith('gpt') ? 'openai' : 'google',
              endpoint_mode: 'gemini',
              endpoint: null,
              input_tokens: inTok,
              output_tokens: outTok,
              cache_read_tokens: cacheRead,
              cache_write_tokens: 0,
              reasoning_tokens: 0,
              context_tokens: inTok + cacheRead,
              context_window: ctxWindow.get(model_id) ?? null,
              ttft_ms: null,
              latency_ms,
              status: o.error ? 'error' : 'ok',
              era,
              workspace,
              title: sum.title || null,
              parent_session_id: sum.parent || null,
              agent_name: sum.agent_name || member?.agent || null,
              group_id: sum.group_id || null,
              effort: effort || null,
              run_status: sum.run_status || '',
              not_fully_idle: sum.not_fully_idle ? 1 : 0,
              killed: sum.killed ? 1 : 0,
              nesting_depth: num(sum.nesting_depth, 0),
              meta_json: JSON.stringify({
                model_source: modelSource,
                latency_source: latencySource || undefined,
                tool_calls: toolCallsCount,
                swarm_role: member?.role || undefined,
                run_status: sum.run_status || undefined,
                not_fully_idle: sum.not_fully_idle ? 1 : undefined,
                killed: sum.killed ? 1 : undefined,
                nesting_depth: sum.nesting_depth || undefined,
              }),
            });
            counts.events++;
          }
          res.cursorUpdates.push({
            key: ckey,
            byte_offset: r.newOffset,
            line_no: r.newLineNo,
            mtime_ms: Math.round(r.mtimeMs),
            size: r.size,
            extra: state,
          });
        } catch (e) {
          res.errors.push(`antigravity[${root.tool}/${conv.id}]: ${e.message}`);
        }
      }

      // Children without their own model record (sub-agents, 'inherit') take the nearest ancestor's model.
      for (let i = startIdx; i < res.events.length; i++) {
        const ev = res.events[i];
        if (ev.model_id !== 'unknown') continue;
        let pid = ev.parent_session_id;
        for (let depth = 0; pid && depth < 8; depth++) {
          let m = finalModel.get(pid);
          if (!m) {
            const pc = getCursor(db, `agy:${root.tool}:${pid}`);
            if (pc.extra?.model) m = { model_id: pc.extra.model, effort: pc.extra.effort, raw: pc.extra.raw_model };
          }
          if (!m) {
            const pm = loadedMembers.get(pid);
            if (pm?.model) {
              const rm = resolveModel(pm.model, known);
              m = { model_id: rm.model_id, effort: rm.effort, raw: pm.model };
            }
          }
          if (m) {
            ev.model_id = m.model_id;
            ev.effort = m.effort || null;
            ev.raw_model = m.raw || null;
            ev.context_window = ctxWindow.get(m.model_id) ?? null;
            ev.provider = m.model_id.startsWith('claude') ? 'anthropic' : m.model_id.startsWith('gpt') ? 'openai' : 'google';
            ev.meta_json = ev.meta_json.replace('"model_source":"none"', '"model_source":"inherited_parent"');
            break;
          }
          pid = summaries.get(pid)?.parent || null;
        }
      }
    } catch (e) {
      res.errors.push(`antigravity[${root.tool}]: ${e.message}`);
    }
    res.counts[root.tool] = counts.events;
    res.notes.push(`${root.tool}: ${counts.files} transcripts, ${counts.filesChanged} changed, ${counts.events} new step events`);
  }
  return res;
}
