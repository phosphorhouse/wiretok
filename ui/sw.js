/* Wiretok v0.2 — Service Worker (static shell cache ONLY; strict network-only bypass for /api/*) */
'use strict';

const CACHE_NAME = 'wiretok-shell-v0.2.1';
const SHELL_ASSETS = [
  '/',
  '/index.html',
  '/styles.css',
  '/app.js',
  '/icons.js',
  '/i18n.js',
  '/sample-sse.js',
  '/site.webmanifest',
  '/assets/favicon.svg',
  '/assets/favicon-32x32.png',
  '/assets/apple-touch-icon.png',
  '/assets/icon-192.png',
  '/assets/icon-512.png',
  '/assets/emblem.webp',
  '/assets/empty-telemetry.webp',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) => cache.addAll(SHELL_ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys.map((key) => {
            if (key !== CACHE_NAME) {
              return caches.delete(key);
            }
            return Promise.resolve(false);
          })
        )
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/')) return;

  const isShell =
    url.pathname === '/' ||
    url.pathname === '/index.html' ||
    url.pathname === '/styles.css' ||
    url.pathname === '/app.js' ||
    url.pathname === '/icons.js' ||
    url.pathname === '/i18n.js' ||
    url.pathname === '/sample-sse.js' ||
    url.pathname === '/site.webmanifest' ||
    url.pathname.startsWith('/assets/');

  if (!isShell) return;

  event.respondWith(
    fetch(req, { signal: AbortSignal.timeout(5000) })
      .then((networkRes) => {
        if (networkRes && networkRes.status === 200 && networkRes.type === 'basic') {
          const clone = networkRes.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(req, clone));
        }
        return networkRes;
      })
      .catch(() =>
        caches.match(req).then((cached) => {
          if (cached) return cached;
          if (req.mode === 'navigate') {
            return caches.match('/index.html') || caches.match('/');
          }
          return Response.error();
        })
      )
  );
});
