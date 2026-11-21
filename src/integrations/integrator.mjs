/**
 * External CLI integration helpers.
 *
 *   getIntegrationStatus()                  -> Array<IntegrationStatus>   (sync, read-only, never prints secrets)
 *   getIntegrationStatusLive()              -> same + TCP probes (tee-proxy / OmniRoute port)   (async)
 *   configureIntegration(tool, { apply })   -> { ok, tool, applied, changed, preview, snippet, backupPath, message }
 *
 * Safety:
 *  - Nothing is mutated unless `apply: true`; every mutation first writes a timestamped backup next to the file.
 *  - ~/.claude/settings.json is parsed ONLY to look at `statusLine`; `env`, permissions etc. are preserved verbatim and never echoed.
 *  - ~/.codex/config.toml is scanned ONLY for a top-level `notify =` line. Credentials files are never opened.
 */
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { DEFAULT_TEE_PORT, DEFAULT_WEB_PORT, ROOT_DIR, getLocalSourcePaths } from '../contracts.mjs';
import { debugLog, exists, hasTable, openReadOnly, statSafe } from '../collectors/util.mjs';
import { findOpencodeDb } from '../collectors/external.mjs';

export const INTEGRATION_TOOLS = ['claude-code', 'codex', 'opencode', 'omniroute', '9router', 'tee-proxy', 'antigravity'];

const TP_BIN = path.join(ROOT_DIR, 'bin', 'wiretok.mjs');
const PORTABLE_STATUSLINE_COMMAND = `node --no-warnings "${TP_BIN}" status --oneliner`;
const OMNIROUTE_PORT = 20128;

function isTpOnPath() {
  const pathEnv = process.env.PATH || '';
  const dirs = pathEnv.split(path.delimiter).filter(Boolean);
  const names = process.platform === 'win32' ? ['tp.cmd', 'tp.exe', 'tp.ps1', 'tp'] : ['tp'];
  for (const dir of dirs) {
    for (const name of names) {
      if (exists(path.join(dir, name))) return true;
    }
  }
  return false;
}

function getStatusLineCommand() {
  return isTpOnPath() ? 'wiretok status --oneliner' : PORTABLE_STATUSLINE_COMMAND;
}

function isWiretokStatusLine(statusLine) {
  const cmd = String(statusLine?.command || '');
  return cmd.includes('wiretok status') || (cmd.includes('wiretok.mjs') && cmd.includes('status'));
}

function claudeSettingsPath() {
  return path.join(getLocalSourcePaths().home, '.claude', 'settings.json');
}
function codexConfigPath() {
  return path.join(getLocalSourcePaths().home, '.codex', 'config.toml');
}

function stamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function backupFile(file) {
  const dest = `${file}.wiretok-backup-${stamp()}`;
  fs.copyFileSync(file, dest);
  return dest;
}

/* ---------------- Claude Code ---------------- */

function readClaudeStatusLine() {
  const f = claudeSettingsPath();
  if (!exists(f)) return { file: f, exists: false, statusLine: null, parsed: null };
  try {
    const parsed = JSON.parse(fs.readFileSync(f, 'utf8'));
    return { file: f, exists: true, statusLine: parsed?.statusLine ?? null, parsed };
  } catch (e) {
    return { file: f, exists: true, statusLine: null, parsed: null, parseError: e.message };
  }
}

const claudeSnippet = () => ({ statusLine: { type: 'command', command: getStatusLineCommand(), padding: 0 } });

function statusClaude() {
  const s = readClaudeStatusLine();
  const mine = isWiretokStatusLine(s.statusLine);
  const activeCmd = getStatusLineCommand();
  return {
    tool: 'claude-code',
    label: 'Claude Code',
    detected: s.exists || exists(getLocalSourcePaths().claudeProjectsDir),
    configured: !!mine,
    status: mine ? 'configured' : s.statusLine ? 'conflict' : s.exists ? 'available' : 'not_found',
    apply_supported: true,
    paths: { settings: s.file, projects: getLocalSourcePaths().claudeProjectsDir },
    snippet: JSON.stringify(claudeSnippet(), null, 2),
    notes: [
      s.statusLine && !mine
        ? 'An unrelated statusLine already exists; apply requires force:true (a backup is written first).'
        : `Adds a statusLine that runs \`${activeCmd}\` (portable fallback: \`${PORTABLE_STATUSLINE_COMMAND}\`).`,
      `Optional request-level capture: ANTHROPIC_BASE_URL=http://127.0.0.1:${DEFAULT_TEE_PORT} (tee-proxy).`,
      s.parseError ? `settings.json could not be parsed: ${s.parseError}` : null,
    ].filter(Boolean),
  };
}

function configureClaude({ apply, force }) {
  const s = readClaudeStatusLine();
  const snippet = claudeSnippet();
  const out = {
    ok: true,
    tool: 'claude-code',
    applied: false,
    changed: false,
    file: s.file,
    snippet: JSON.stringify(snippet, null, 2),
    preview: null,
    backupPath: null,
    message: '',
  };
  if (!s.exists) {
    out.preview = `Would create ${s.file} containing:\n${out.snippet}`;
  } else if (s.parseError) {
    out.ok = false;
    out.message = `Refusing to touch settings.json: parse error (${s.parseError}).`;
    return out;
  } else {
    const had = s.statusLine ? JSON.stringify(s.statusLine) : 'none';
    out.preview = `statusLine: ${had}  ->  ${JSON.stringify(snippet.statusLine)}`;
    if (isWiretokStatusLine(s.statusLine)) {
      out.message = 'Already configured.';
      return out;
    }
    if (s.statusLine && !force) {
      out.ok = apply ? false : true;
      out.message = 'A different statusLine exists. Pass { apply: true, force: true } to replace it (backup is created).';
      return out;
    }
  }
  if (!apply) {
    out.message = 'Preview only (apply:false). Nothing was written.';
    return out;
  }
  fs.mkdirSync(path.dirname(s.file), { recursive: true });
  if (s.exists) out.backupPath = backupFile(s.file);
  const next = { ...(s.parsed || {}), ...snippet };
  fs.writeFileSync(s.file, `${JSON.stringify(next, null, 2)}\n`, 'utf8');
  out.applied = true;
  out.changed = true;
  out.message = `statusLine written to ${s.file}${out.backupPath ? ` (backup: ${out.backupPath})` : ''}.`;
  return out;
}

/* ---------------- Codex ---------------- */

const codexNotifyLine = () => `notify = ["node", "--no-warnings", ${JSON.stringify(TP_BIN)}, "sync", "--all"]`;

function codexNotifyState() {
  const f = codexConfigPath();
  if (!exists(f)) return { file: f, exists: false, hasNotify: false, text: '' };
  const text = fs.readFileSync(f, 'utf8');
  return { file: f, exists: true, hasNotify: /^\s*notify\s*=/m.test(text), mine: /wiretok|tp\.mjs/i.test((text.match(/^\s*notify\s*=.*$/m) || [''])[0]), text };
}

function statusCodex() {
  const c = codexNotifyState();
  const paths = getLocalSourcePaths();
  return {
    tool: 'codex',
    label: 'Codex CLI',
    detected: c.exists || exists(paths.codexSessionsDir),
    configured: !!c.mine,
    status: c.mine ? 'configured' : c.hasNotify ? 'conflict' : c.exists ? 'available' : 'not_found',
    apply_supported: true,
    paths: { config: c.file, sessions: paths.codexSessionsDir },
    snippet: codexNotifyLine(),
    notes: [
      c.hasNotify && !c.mine
        ? 'Codex supports a single notify command and one is already set; it will NOT be overwritten. Chain `wiretok sync --all` inside your existing notify wrapper, or sessions are still collected passively from ~/.codex/sessions.'
        : 'notify hook triggers a sync after each Codex turn. Sessions are also collected passively without it.',
    ],
  };
}

function configureCodex({ apply }) {
  const c = codexNotifyState();
  const line = codexNotifyLine();
  const out = { ok: true, tool: 'codex', applied: false, changed: false, file: c.file, snippet: line, preview: null, backupPath: null, message: '' };
  if (c.hasNotify) {
    out.message = c.mine ? 'Already configured.' : 'An existing notify hook is set; refusing to overwrite it. Chain `wiretok sync --all` in your wrapper instead.';
    out.preview = `Add to ${c.file}:\n${line}`;
    out.ok = c.mine || !apply;
    return out;
  }
  out.preview = `Would add to ${c.file} (top level, before the first [table]):\n${line}`;
  if (!apply) {
    out.message = 'Preview only (apply:false). Nothing was written.';
    return out;
  }
  fs.mkdirSync(path.dirname(c.file), { recursive: true });
  let next;
  if (c.exists) {
    out.backupPath = backupFile(c.file);
    const m = /^\s*\[/m.exec(c.text);
    next = m ? `${c.text.slice(0, m.index)}${line}\n${c.text.slice(m.index)}` : `${c.text.replace(/\s*$/, '\n')}${line}\n`;
  } else next = `${line}\n`;
  fs.writeFileSync(c.file, next, 'utf8');
  out.applied = true;
  out.changed = true;
  out.message = `notify hook added to ${c.file}${out.backupPath ? ` (backup: ${out.backupPath})` : ''}.`;
  return out;
}

/* ---------------- OpenCode ---------------- */

function statusOpencode() {
  const paths = getLocalSourcePaths();
  const dbFile = findOpencodeDb(paths.opencodeDirs);
  let messages = null;
  if (dbFile) {
    const db = openReadOnly(dbFile);
    if (db) {
      try {
        let total = 0;
        if (hasTable(db, 'message')) total += Number(db.prepare('SELECT COUNT(*) AS c FROM message').get()?.c) || 0;
        if (hasTable(db, 'session_message')) total += Number(db.prepare('SELECT COUNT(*) AS c FROM session_message').get()?.c) || 0;
        messages = total;
      } catch (err) {
        debugLog(err, 'statusOpencode');
      } finally {
        db.close();
      }
    }
  }
  return {
    tool: 'opencode',
    label: 'OpenCode',
    detected: !!dbFile,
    configured: !!dbFile,
    status: dbFile ? 'configured' : 'not_found',
    apply_supported: false,
    paths: { db: dbFile },
    snippet: `# optional request-level capture through the tee-proxy\nOPENAI_BASE_URL=http://127.0.0.1:${DEFAULT_TEE_PORT}/v1`,
    notes: [
      dbFile
        ? `opencode.db detected (read-only: message/part + session_message/session_v2 tables only${messages !== null ? `, ${messages} messages` : ''}). Credentials/auth tables are never read.`
        : 'opencode.db not found.',
      'No file is modified for OpenCode; collection is passive.',
    ],
  };
}

function configurePassive(tool, statusFn, extra = {}) {
  const st = statusFn();
  return { ok: true, tool, applied: false, changed: false, snippet: st.snippet, preview: st.snippet, backupPath: null, message: `${st.label}: passive integration — nothing to write. ${st.notes[0] || ''}`.trim(), ...extra };
}

/* ---------------- OmniRoute / 9Router / tee-proxy / Antigravity ---------------- */

function statusOmniroute() {
  const f = getLocalSourcePaths().omnirouteDb;
  const st = statSafe(f);
  let rows = null;
  if (st) {
    const db = openReadOnly(f);
    if (db) {
      try {
        if (hasTable(db, 'usage_history')) rows = db.prepare('SELECT COUNT(*) AS c FROM usage_history').get().c;
      } catch (err) {
        debugLog(err, 'statusOmniroute');
      } finally {
        db.close();
      }
    }
  }
  return {
    tool: 'omniroute',
    label: 'OmniRoute',
    detected: !!st,
    configured: !!st,
    status: st ? 'configured' : 'not_found',
    apply_supported: false,
    paths: { db: f },
    snippet: `omniroute serve --headless --port ${OMNIROUTE_PORT}\n# OPENAI_BASE_URL=http://localhost:${OMNIROUTE_PORT}/v1`,
    notes: [
      st ? `storage.sqlite detected (read-only; usage_history rows: ${rows ?? 'n/a'}). Token/key columns are never selected.` : 'storage.sqlite not found — start OmniRoute once.',
    ],
  };
}

function status9Router() {
  const dirs = getLocalSourcePaths().router9Dirs.filter(exists);
  return {
    tool: '9router',
    label: '9Router',
    detected: dirs.length > 0,
    configured: dirs.length > 0,
    status: dirs.length ? 'configured' : 'not_found',
    apply_supported: false,
    paths: { dirs },
    snippet: `# route 9Router traffic through the tee-proxy for request-level telemetry\nOPENAI_BASE_URL=http://127.0.0.1:${DEFAULT_TEE_PORT}/v1`,
    notes: [dirs.length ? '9Router data dir detected (JSONL/SQLite read best-effort).' : '9Router data dir not found (~/.9router, %APPDATA%/9router).'],
  };
}

function statusTee() {
  return {
    tool: 'tee-proxy',
    label: 'Wiretok tee-proxy',
    detected: true,
    configured: false,
    status: 'available',
    apply_supported: false,
    paths: { listen: `127.0.0.1:${DEFAULT_TEE_PORT}` },
    snippet: `OPENAI_BASE_URL=http://127.0.0.1:${DEFAULT_TEE_PORT}/v1\nANTHROPIC_BASE_URL=http://127.0.0.1:${DEFAULT_TEE_PORT}`,
    notes: [`Start with the Wiretok server (tee on 127.0.0.1:${DEFAULT_TEE_PORT}); point any OpenAI/Anthropic-compatible client at it. Authorization headers are stripped before anything is stored. Dashboard: http://127.0.0.1:${DEFAULT_WEB_PORT}.`],
  };
}

function statusAntigravity() {
  const p = getLocalSourcePaths();
  const hooks = path.join(ROOT_DIR, 'plugins', 'wiretok', 'hooks.json');
  return {
    tool: 'antigravity',
    label: 'Antigravity (2.0 / IDE / CLI)',
    detected: exists(p.antigravityDir) || exists(p.antigravityIdeDir) || exists(p.antigravityCliDir),
    configured: exists(hooks),
    status: exists(p.antigravityDir) ? 'configured' : 'not_found',
    apply_supported: false,
    paths: { antigravity: p.antigravityDir, ide: p.antigravityIdeDir, cli: p.antigravityCliDir, hooksPlugin: hooks },
    snippet: `# Antigravity: transcripts are parsed passively; the optional hook plugin lives at\n${path.join(ROOT_DIR, 'plugins', 'wiretok')}`,
    notes: ['Passive: transcript.jsonl + conversation_summaries.db (read-only). Install the wiretok plugin for live PreInvocation/PostInvocation timing & model stamps.'],
  };
}

const STATUS_FNS = {
  'claude-code': statusClaude,
  codex: statusCodex,
  opencode: statusOpencode,
  omniroute: statusOmniroute,
  '9router': status9Router,
  'tee-proxy': statusTee,
  antigravity: statusAntigravity,
};

export function getIntegrationStatus() {
  return INTEGRATION_TOOLS.map((t) => {
    try {
      return STATUS_FNS[t]();
    } catch (e) {
      return { tool: t, label: t, detected: false, configured: false, status: 'error', apply_supported: false, notes: [e.message], snippet: '' };
    }
  });
}

function probePort(port, host = '127.0.0.1', timeoutMs = 400) {
  return new Promise((resolve) => {
    const s = net.connect({ port, host });
    const done = (v) => {
      s.destroy();
      resolve(v);
    };
    s.setTimeout(timeoutMs, () => done(false));
    s.once('connect', () => done(true));
    s.once('error', () => done(false));
  });
}

export async function getIntegrationStatusLive() {
  const list = getIntegrationStatus();
  const [tee, omr] = await Promise.all([probePort(DEFAULT_TEE_PORT), probePort(OMNIROUTE_PORT)]);
  for (const i of list) {
    if (i.tool === 'tee-proxy') {
      i.listening = tee;
      i.configured = tee;
      i.status = tee ? 'configured' : 'available';
    }
    if (i.tool === 'omniroute') i.listening = omr;
  }
  return list;
}

/**
 * @param {string} tool one of INTEGRATION_TOOLS
 * @param {{apply?:boolean, force?:boolean}} [opts]
 */
export function configureIntegration(tool, opts = {}) {
  const apply = opts.apply === true;
  const force = opts.force === true;
  try {
    switch (tool) {
      case 'claude-code':
        return configureClaude({ apply, force });
      case 'codex':
        return configureCodex({ apply });
      case 'opencode':
        return configurePassive(tool, statusOpencode);
      case 'omniroute':
        return configurePassive(tool, statusOmniroute);
      case '9router':
        return configurePassive(tool, status9Router);
      case 'tee-proxy':
        return configurePassive(tool, statusTee);
      case 'antigravity':
        return configurePassive(tool, statusAntigravity);
      default:
        return { ok: false, tool, applied: false, changed: false, message: `Unknown integration "${tool}". Valid: ${INTEGRATION_TOOLS.join(', ')}` };
    }
  } catch (e) {
    return { ok: false, tool, applied: false, changed: false, message: e.message };
  }
}
