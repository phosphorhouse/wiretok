#!/usr/bin/env node
/**
 * Wiretok — Zero-VBS Cross-Platform Launcher
 * Verifies Node >= 22, checks whether the local dashboard is already healthy,
 * starts `src/server/server.mjs` detached in the background if needed, waits for
 * `/api/health`, and opens the browser. Prints actionable errors on failure.
 */
import fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { DATA_DIR, DEFAULT_WEB_PORT, ROOT_DIR } from '../src/contracts.mjs';

const __launchDir = path.dirname(fileURLToPath(import.meta.url));
const serverScript = path.resolve(__launchDir, '..', 'src', 'server', 'server.mjs');
const port = Number(process.env.WIRETOK_PORT || DEFAULT_WEB_PORT);
const bindHost = process.env.WIRETOK_HOST || 'localhost';
const baseUrl = `http://${bindHost}:${port}`;
const healthUrl = `${baseUrl}/api/health`;

function assertLocalhostUrl(rawUrl) {
  const u = new URL(rawUrl);
  const h = u.hostname.toLowerCase();
  if (h !== '127.0.0.1' && h !== 'localhost' && h !== '::1') {
    throw new Error(`Refused non-loopback launcher URL: ${u.hostname}`);
  }
  return u.toString();
}

async function isHealthy() {
  try {
    const res = await fetch(assertLocalhostUrl(healthUrl), {
      signal: AbortSignal.timeout(800),
    });
    return res.ok;
  } catch (err) {
    if (process.env.WIRETOK_DEBUG) {
      process.stderr.write(`[wiretok:launcher] health check: ${err?.message || err}\n`);
    }
    return false;
  }
}

function openBrowser(targetUrl) {
  const safeUrl = assertLocalhostUrl(targetUrl);
  if (process.platform === 'win32') {
    const child = spawn('cmd.exe', ['/c', 'start', '', safeUrl], {
      detached: true,
      windowsHide: true,
      stdio: 'ignore',
    });
    child.unref();
    return;
  }
  const opener = process.platform === 'darwin' ? 'open' : 'xdg-open';
  const child = spawn(opener, [safeUrl], { detached: true, stdio: 'ignore' });
  child.unref();
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
  const major = Number(String(process.versions.node || '0').split('.')[0]);
  if (!Number.isFinite(major) || major < 22) {
    process.stderr.write(
      `[Wiretok] Node.js 22+ gereklidir (mevcut surum: v${process.versions.node}). https://nodejs.org\n`
    );
    process.exit(1);
  }

  try {
    await fs.access(serverScript);
  } catch (err) {
    process.stderr.write(
      `[Wiretok] Sunucu dosyasi bulunamadi (${serverScript}): ${err?.message || err}\n` +
        'Lutfen ZIP dosyasini once bir klasore cikarin, ardindan Wiretok Baslat.cmd dosyasini calistirin.\n'
    );
    process.exit(1);
  }

  const noBrowser = process.argv.includes('--no-browser');

  if (await isHealthy()) {
    process.stdout.write(`[Wiretok] Zaten calisiyor -> ${baseUrl}\n`);
    if (!noBrowser) openBrowser(baseUrl);
    return;
  }

  await fs.mkdir(DATA_DIR, { recursive: true });
  const logPath = path.join(DATA_DIR, 'launcher.log');
  const logHandle = await fs.open(logPath, 'w');
  try {
    const child = spawn(process.execPath, ['--no-warnings', serverScript, '--port', String(port)], {
      cwd: ROOT_DIR,
      env: process.env,
      detached: true,
      windowsHide: true,
      stdio: ['ignore', logHandle.fd, logHandle.fd],
    });
    child.unref();
  } finally {
    await logHandle.close();
  }

  process.stdout.write('[Wiretok] Sunucu baslatiliyor...\n');
  for (let i = 0; i < 30; i += 1) {
    await sleep(300);
    if (await isHealthy()) {
      process.stdout.write(`[Wiretok] Hazir -> ${baseUrl}\n`);
      if (!noBrowser) openBrowser(baseUrl);
      return;
    }
  }

  let logTail = '';
  try {
    logTail = (await fs.readFile(logPath, 'utf8')).trim();
  } catch (err) {
    if (process.env.WIRETOK_DEBUG) {
      process.stderr.write(`[wiretok:launcher] log read error: ${err?.message || err}\n`);
    }
  }

  process.stderr.write(
    `[Wiretok] Sunucu ${baseUrl} adresinde 9 saniye icinde ayaga kalkmadi.\n` +
      (logTail ? `--- Log (${logPath}) ---\n${logTail}\n` : `Log dosyasi: ${logPath}\n`)
  );
  process.exit(1);
}

main().catch((err) => {
  process.stderr.write(`[Wiretok] Baslatma hatasi: ${err?.message || err}\n`);
  process.exit(1);
});
