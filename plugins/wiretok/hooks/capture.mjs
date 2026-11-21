import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const defaultDataDir = process.env.WIRETOK_DATA_DIR
  ? path.resolve(process.env.WIRETOK_DATA_DIR)
  : path.join(os.homedir(), '.wiretok');
const hookEventsLog = path.join(defaultDataDir, 'hook_events.jsonl');
const googleAccountsJson = path.join(os.homedir(), '.gemini', 'google_accounts.json');

function debugHook(err) {
  if (process.env.WIRETOK_DEBUG === '1') {
    const msg = err instanceof Error ? err.message : String(err || 'unknown error');
    process.stderr.write(`[wiretok:hook] ${msg}\n`);
  }
}

function readStdin() {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) return resolve('');
    const chunks = [];
    let settled = false;
    const done = () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks).toString('utf8'));
    };
    process.stdin.on('data', (chunk) => chunks.push(chunk));
    process.stdin.on('end', done);
    process.stdin.on('error', done);
    setTimeout(done, 800).unref();
  });
}

function readActiveAccountOnly(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    return typeof parsed?.active === 'string' && parsed.active.trim()
      ? parsed.active.trim()
      : null;
  } catch (err) {
    debugHook(err);
    return null;
  }
}

let hookEventName = '';

try {
  const rawStdin = await readStdin();
  const payload = rawStdin && rawStdin.trim() ? JSON.parse(rawStdin) : {};
  hookEventName = typeof payload?.hookEventName === 'string' ? payload.hookEventName : '';
  const activeAccount =
    process.env.WIRETOK_USE_GEMINI_CLI_EMAIL === '1'
      ? readActiveAccountOnly(googleAccountsJson)
      : null;

  const record = {
    ts: new Date().toISOString(),
    tsMs: Date.now(),
    hookEventName,
    conversationId: typeof payload?.conversationId === 'string' ? payload.conversationId : '',
    workspacePaths: Array.isArray(payload?.workspacePaths) ? payload.workspacePaths : [],
    cwd: typeof payload?.cwd === 'string' ? payload.cwd : '',
    transcriptPath: typeof payload?.transcriptPath === 'string' ? payload.transcriptPath : '',
    modelName: typeof payload?.modelName === 'string' ? payload.modelName : '',
    stepIdx: Number.isFinite(payload?.stepIdx) ? payload.stepIdx : null,
    invocationNum: Number.isFinite(payload?.invocationNum) ? payload.invocationNum : null,
    initialNumSteps: Number.isFinite(payload?.initialNumSteps) ? payload.initialNumSteps : null,
    executionNum: Number.isFinite(payload?.executionNum) ? payload.executionNum : null,
    terminationReason: typeof payload?.terminationReason === 'string' ? payload.terminationReason : null,
    activeAccount,
  };

  fs.mkdirSync(defaultDataDir, { recursive: true });
  fs.appendFileSync(hookEventsLog, `${JSON.stringify(record)}\n`, 'utf8');
} catch (err) {
  // Never fail or block the Antigravity agent loop.
  debugHook(err);
}

if (hookEventName === 'Stop') {
  process.stdout.write('{"decision":"allow"}\n');
} else {
  process.stdout.write('{}\n');
}

process.exit(0);
