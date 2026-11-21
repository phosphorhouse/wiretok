/* Wiretok v0.2 UI — vanilla ES2022, zero external dependencies, zero innerHTML/outerHTML XSS sinks.
 * Data contract: src/server/server.mjs REST + /api/events (SSE) + BroadcastChannel('wiretok'). */
(() => {
  'use strict';

  /* ------------------------------ DOM & SVG Builders (Zero innerHTML) ------------------------------ */
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const ICONS = window.WT_ICONS || {};
  const ICON_CACHE = new Map();
  const SVG_NS = 'http://www.w3.org/2000/svg';

  function clearEl(el) {
    if (!el) return el;
    while (el.firstChild) el.removeChild(el.firstChild);
    return el;
  }

  function iconEl(name, docRef = document) {
    if (!name || !ICONS[name]) return null;
    let cached = ICON_CACHE.get(name);
    if (!cached) {
      const parsed = new DOMParser().parseFromString(ICONS[name], 'image/svg+xml');
      cached = parsed.documentElement;
      ICON_CACHE.set(name, cached);
    }
    if (!cached) return null;
    return docRef.importNode ? docRef.importNode(cached, true) : cached.cloneNode(true);
  }

  function parseSvgSafe(svgStr, docRef = document) {
    if (!svgStr || typeof svgStr !== 'string') return null;
    const parsed = new DOMParser().parseFromString(svgStr, 'image/svg+xml');
    const root = parsed.documentElement;
    if (!root || root.nodeName.toLowerCase() !== 'svg' || parsed.querySelector('parsererror')) return null;
    for (const bad of root.querySelectorAll('script, foreignObject, iframe, object, embed')) bad.remove();
    for (const el of [root, ...root.querySelectorAll('*')]) {
      for (const attr of Array.from(el.attributes || [])) {
        if (/^on/i.test(attr.name) || /javascript:/i.test(attr.value)) el.removeAttribute(attr.name);
      }
    }
    return docRef.importNode ? docRef.importNode(root, true) : root.cloneNode(true);
  }

  function appendChildren(parent, children, docRef = document) {
    for (const child of children) {
      if (Array.isArray(child)) {
        appendChildren(parent, child, docRef);
      } else if (child !== null && child !== undefined && child !== false && child !== '') {
        if (typeof child === 'object' && 'nodeType' in child) {
          parent.appendChild(child);
        } else {
          parent.appendChild(docRef.createTextNode(String(child)));
        }
      }
    }
  }

  function isSafeKey(key) {
    return key !== '__proto__' && key !== 'constructor' && key !== 'prototype';
  }

  function applyAttrs(el, attrs, isSvg = false) {
    if (!attrs || typeof attrs !== 'object') return;
    for (const [k, val] of Object.entries(attrs)) {
      if (!isSafeKey(k) || val === undefined || val === null || val === false) continue;
      if (k === 'class' || k === 'className') {
        el.setAttribute('class', String(val));
      } else if (k === 'dataset' && typeof val === 'object') {
        for (const [dk, dv] of Object.entries(val)) {
          if (!isSafeKey(dk) || dv === undefined || dv === null) continue;
          const attrName = 'data-' + dk.replace(/[A-Z]/g, (c) => '-' + c.toLowerCase());
          el.setAttribute(attrName, String(dv));
        }
      } else if (k === 'style') {
        if (typeof val === 'object') {
          for (const [sk, sv] of Object.entries(val)) {
            if (!isSafeKey(sk) || sv === undefined || sv === null) continue;
            const propName = sk.startsWith('--') ? sk : sk.replace(/[A-Z]/g, (c) => '-' + c.toLowerCase());
            el.style.setProperty(propName, String(sv));
          }
        } else {
          el.setAttribute('style', String(val));
        }
      } else if (k.startsWith('on') && typeof val === 'function') {
        el.addEventListener(k.slice(2).toLowerCase(), val);
      } else if (!isSvg && (k === 'hidden' || k === 'disabled' || k === 'checked' || k === 'required' || k === 'selected')) {
        if (val) el.setAttribute(k, '');
      } else if (!isSvg && k === 'value') {
        el.setAttribute('value', String(val));
        if ('value' in el) el.value = String(val);
      } else {
        el.setAttribute(k, val === true ? '' : String(val));
      }
    }
  }

  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    applyAttrs(el, attrs, false);
    appendChildren(el, children, document);
    return el;
  }

  function svgEl(tag, attrs, ...children) {
    const el = document.createElementNS(SVG_NS, tag);
    applyAttrs(el, attrs, true);
    appendChildren(el, children, document);
    return el;
  }

  function hydrateIcons(root = document) {
    $$('[data-icon]', root).forEach((el) => {
      const name = el.dataset.icon;
      if (el.dataset.ready === name && el.firstChild) return;
      clearEl(el);
      const svg = iconEl(name, el.ownerDocument || document);
      if (svg) el.appendChild(svg);
      el.dataset.ready = name;
    });
  }

  function setBtnIcon(btn, name) {
    if (!btn) return;
    let holder = btn.querySelector('[data-icon]');
    if (!holder) {
      holder = h('i', { 'data-icon': name });
      btn.insertBefore(holder, btn.firstChild);
    } else {
      holder.dataset.icon = name;
    }
    hydrateIcons(btn);
  }

  /* ------------------------------ Data Helpers ------------------------------ */
  const camel = (s) => s.replace(/_([a-z0-9])/g, (_, c) => c.toUpperCase());
  const snake = (s) => s.replace(/[A-Z]/g, (c) => '_' + c.toLowerCase());

  function v(o, ...keys) {
    if (!o || typeof o !== 'object') return undefined;
    for (const k of keys) {
      for (const kk of [k, camel(k), snake(k)]) {
        if (o[kk] !== undefined && o[kk] !== null) return o[kk];
      }
    }
    return undefined;
  }
  const nn = (o, ...keys) => {
    const x = v(o, ...keys);
    if (x === undefined || x === '') return null;
    const num = Number(x);
    return Number.isFinite(num) ? num : null;
  };
  const n0 = (o, ...keys) => nn(o, ...keys) ?? 0;
  const arr = (x) => (Array.isArray(x) ? x : []);

  /* ------------------------------ State, i18n & Persistence ------------------------------ */
  const I18N = window.WT_I18N || { defaultLang: 'en', supported: ['en', 'tr'], months: {}, weekdays: {}, dict: { en: {}, tr: {} } };
  const SOURCES = [
    ['antigravity', 'Antigravity'],
    ['antigravity-ide', 'Antigravity IDE'],
    ['antigravity-cli', 'Antigravity CLI'],
    ['omniroute', 'OmniRoute'],
    ['9router', '9Router'],
    ['claude-code', 'Claude Code'],
    ['codex', 'Codex'],
    ['opencode', 'OpenCode'],
    ['tee-proxy', 'Tee Proxy'],
    ['manual-ingest', 'Manual Ingest'],
  ];
  const SOURCE_LABEL = Object.fromEntries(SOURCES);
  const RECENT_LIMITS = [3, 6, 12, 24];

  const localHostName = () => location.hostname || 'localhost';
  const localPresetBase = (p) => `${location.protocol}//${localHostName()}:${p}/v1`;
  const SPEED_PRESETS = {
    omniroute: { url: localPresetBase(20128), model: 'gemini-4-hydrogen', mode: 'chat_completions' },
    '9router': { url: localPresetBase(20129), model: 'gemini-4-hydrogen', mode: 'chat_completions' },
    openrouter: { url: 'https://openrouter.ai/api/v1', model: 'openai/gpt-6.1-sol', mode: 'chat_completions' },
    openai: { url: 'https://api.openai.com/v1', model: 'gpt-6.1-sol', mode: 'responses' },
    anthropic: { url: 'https://api.anthropic.com', model: 'claude-sonnet-5-5', mode: 'messages' },
  };

  const stored = (() => {
    try { return JSON.parse(localStorage.getItem('wt.ui') || '{}') || {}; }
    catch { return {}; }
  })();

  const qp = new URLSearchParams(location.search);
  const isHudView = qp.get('view') === 'hud';
  const pairNonceParam = qp.get('pair') || '';

  const state = {
    lang: I18N.supported.includes(stored.lang) ? stored.lang : I18N.defaultLang || 'en',
    density: ['auto', 'compact', 'normal'].includes(stored.density) ? stored.density : 'auto',
    recentLimit: RECENT_LIMITS.includes(Number(stored.recentLimit)) ? Number(stored.recentLimit) : 6,
    era: stored.era === 'all' ? 'all' : 'live',
    cur: stored.cur === 'TRY' ? 'TRY' : 'USD',
    privacy: stored.privacy !== undefined ? Boolean(stored.privacy) : true,
    tab: ['overview', 'accounts', 'requests', 'forensics', 'models'].includes(stored.tab) ? stored.tab : 'overview',
    from: stored.from ? String(stored.from).slice(0, 10) : '',
    to: stored.to ? String(stored.to).slice(0, 10) : '',
    accountId: stored.accountId || '',
    sourceTool: stored.sourceTool || '',
    metric: stored.metric === 'cost' ? 'cost' : 'tokens',
    heatMetric: ['tokens', 'cost', 'requests', 'cache'].includes(stored.heatMetric) ? stored.heatMetric : 'tokens',
    heatWeeks: [15, 26, 53].includes(Number(stored.heatWeeks)) ? Number(stored.heatWeeks) : 53,
    fx: 34.5,
    milestoneAt: null,
    ctxId: null,
    pinnedSessionId: null,
    recentDrawerOpen: false,
    mode: 'auto',
    rq: {
      offset: 0,
      limit: 25,
      total: 0,
      sort: 'created_at:desc',
      expensive: false,
      prevSort: 'created_at:desc',
      q: '',
      modelId: stored.modelId || '',
      sessionId: '',
      sessionTitle: '',
    },
    editAcc: null,
    editModel: null,
    syncPaused: false,
    tee: { running: false, port: 19841, upstreamBaseUrl: 'https://api.openai.com/v1', stats: null },
    guideHidden: (() => {
      try { return localStorage.getItem('wt.guideHidden') === '1'; }
      catch { return false; }
    })(),
    wizardStep: 1,
    requiresPin: false,
  };

  if (I18N.supported.includes(qp.get('lang'))) state.lang = qp.get('lang');
  if (['auto', 'compact', 'normal'].includes(qp.get('density'))) state.density = qp.get('density');
  if (qp.get('era') === 'all' || qp.get('era') === 'live') state.era = qp.get('era');
  if (qp.get('cur') === 'TRY' || qp.get('cur') === 'USD') state.cur = qp.get('cur');
  if (qp.get('privacy') === '1') state.privacy = true;
  if (qp.get('privacy') === '0') state.privacy = false;
  const hashTab = location.hash.slice(1);
  if (['overview', 'accounts', 'requests', 'forensics', 'models'].includes(hashTab)) state.tab = hashTab;

  function t(key, vars) {
    const langDict = (I18N.dict && I18N.dict[state.lang]) || {};
    const enDict = (I18N.dict && I18N.dict.en) || {};
    let str = langDict[key] !== undefined ? langDict[key] : enDict[key] !== undefined ? enDict[key] : key;
    if (vars && typeof vars === 'object') {
      for (const [k, val] of Object.entries(vars)) {
        str = str.replaceAll(`{${k}}`, String(val ?? ''));
      }
    }
    return str;
  }

  function sourceLabel(src) {
    if (!src) return '';
    if (src === 'manual-ingest') return t('src.manualIngest');
    return SOURCE_LABEL[src] || src;
  }

  function localizedSources() {
    return SOURCES.map(([id, lbl]) => [id, id === 'manual-ingest' ? t('src.manualIngest') : lbl]);
  }

  function resolveDensity() {
    if (state.density === 'compact') return 'compact';
    if (state.density === 'normal') return 'normal';
    const w = window.innerWidth || 1440;
    const hPx = window.innerHeight || 900;
    return w >= 520 && w <= 1920 && hPx <= 1220 ? 'compact' : 'normal';
  }

  function applyDensity() {
    const resolved = resolveDensity();
    document.documentElement.dataset.density = resolved;
    $$('#seg-density button').forEach((b) => {
      b.setAttribute('aria-pressed', String(b.dataset.density === state.density));
      if (b.dataset.density === 'auto') {
        const modeTxt = resolved === 'compact' ? t('ctrl.densityCompact') : t('ctrl.densityNormal');
        b.title = `${t('ctrl.densityAuto')} (${modeTxt})`;
      }
    });
  }

  function applyI18n() {
    document.documentElement.lang = state.lang;
    document.title = t('meta.title');
    const descMeta = $('meta[name="description"]');
    if (descMeta) descMeta.setAttribute('content', t('meta.description'));
    $$('[data-i18n]').forEach((el) => {
      el.textContent = t(el.dataset.i18n);
    });
    $$('[data-i18n-placeholder]').forEach((el) => {
      el.setAttribute('placeholder', t(el.dataset.i18nPlaceholder));
    });
    $$('[data-i18n-aria]').forEach((el) => {
      el.setAttribute('aria-label', t(el.dataset.i18nAria));
    });
    $$('[data-i18n-alt]').forEach((el) => {
      el.setAttribute('alt', t(el.dataset.i18nAlt));
    });
    const pbPrompt = $('#pb-prompt');
    if (pbPrompt) {
      const enDef = I18N.dict?.en?.['for.probePromptDefault'] || '';
      const trDef = I18N.dict?.tr?.['for.probePromptDefault'] || '';
      const curVal = pbPrompt.value.trim();
      if (!curVal || curVal === enDef || curVal === trDef) {
        pbPrompt.value = t('for.probePromptDefault');
      }
    }
    $$('#seg-lang button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.lang === state.lang)));
    applyDensity();
  }

  const S = { ov: null, accounts: [], models: [], integrations: [], requests: [], history: [], sessions: [], mq: '', mpage: 0 };
  const compactMq = window.matchMedia('(max-width: 519px)');
  const reducedMotionMq = window.matchMedia('(prefers-reduced-motion: reduce)');
  const modelPage = () => (compactMq.matches ? 8 : 20);
  const bc = typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel('wiretok') : null;
  let pipWindow = null;

  function persist() {
    try {
      localStorage.setItem('wt.ui', JSON.stringify({
        lang: state.lang,
        density: state.density,
        recentLimit: state.recentLimit,
        era: state.era,
        cur: state.cur,
        privacy: state.privacy,
        tab: state.tab,
        from: state.from,
        to: state.to,
        accountId: state.accountId,
        sourceTool: state.sourceTool,
        modelId: state.rq.modelId,
        metric: state.metric,
        heatMetric: state.heatMetric,
        heatWeeks: state.heatWeeks,
      }));
    } catch {
      /* ignore quota/storage block */
    }
  }

  /* ------------------------------ Formatting & 240ms rAF Tween ------------------------------ */
  const locale = () => (state.lang === 'tr' ? 'tr-TR' : 'en-US');
  const nf = (d) => new Intl.NumberFormat(locale(), { minimumFractionDigits: 0, maximumFractionDigits: d });
  const fmtNum = (x, d = 0) => (x === null || x === undefined || !Number.isFinite(x) ? '—' : nf(d).format(x));
  function fmtTok(x) {
    if (x === null || x === undefined || !Number.isFinite(x)) return '—';
    const a = Math.abs(x);
    if (a >= 1e9) return fmtNum(x / 1e9, 2) + (state.lang === 'tr' ? 'Mr' : 'B');
    if (a >= 1e6) return fmtNum(x / 1e6, a >= 1e7 ? 1 : 2) + 'M';
    if (a >= 1e3) return fmtNum(x / 1e3, a >= 1e5 ? 0 : 1) + 'K';
    return fmtNum(Math.round(x));
  }
  const fmtPct = (x, d = 1) =>
    x === null || x === undefined || !Number.isFinite(x)
      ? '—'
      : state.lang === 'tr'
      ? '%' + fmtNum(x, d)
      : fmtNum(x, d) + '%';
  const fmtMs = (x) => (x === null || x === undefined || !Number.isFinite(x) ? '—' : fmtNum(x, x < 100 ? 1 : 0) + ' ms');
  function money(usd) {
    if (usd === null || usd === undefined || !Number.isFinite(usd)) return '—';
    const isTry = state.cur === 'TRY';
    const x = isTry ? usd * state.fx : usd;
    const a = Math.abs(x);
    const d = a === 0 ? 2 : a < 0.01 ? 4 : a < 1 ? 3 : 2;
    return (isTry ? '₺' : '$') + new Intl.NumberFormat(locale(), { minimumFractionDigits: 2, maximumFractionDigits: d }).format(x);
  }
  const fmtDT = (x) => {
    if (!x) return '—';
    const d = new Date(x);
    if (Number.isNaN(d.getTime())) return String(x);
    return d.toLocaleString(locale(), { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };
  const fmtDate = (x) => {
    if (!x) return '—';
    const d = new Date(x);
    return Number.isNaN(d.getTime())
      ? String(x)
      : d.toLocaleString(locale(), { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  };
  function ago(x) {
    if (!x) return '—';
    const s = Math.max(0, (Date.now() - new Date(x).getTime()) / 1000);
    if (!Number.isFinite(s)) return '—';
    if (s < 60) return t('time.secAgo', { n: Math.round(s) });
    if (s < 3600) return t('time.minAgo', { n: Math.round(s / 60) });
    if (s < 86400) return t('time.hrAgo', { n: Math.round(s / 3600) });
    return t('time.dayAgo', { n: Math.round(s / 86400) });
  }
  function countdown(ms) {
    if (!Number.isFinite(ms)) return '—';
    if (ms <= 0) return t('time.reset');
    const s = Math.floor(ms / 1000);
    const d = Math.floor(s / 86400);
    const hr = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sc = s % 60;
    if (d) return `${d}${t('time.d')} ${hr}${t('time.h')}`;
    if (hr) return `${hr}${t('time.h')} ${String(m).padStart(2, '0')}${t('time.m')}`;
    return `${m}${t('time.m')} ${String(sc).padStart(2, '0')}${t('time.s')}`;
  }

  const activeTweens = new WeakMap();
  function tweenNumber(el, targetVal, fmtFn) {
    if (!el) return;
    const prevRaf = activeTweens.get(el);
    if (prevRaf) {
      cancelAnimationFrame(prevRaf);
      activeTweens.delete(el);
    }
    if (targetVal === null || targetVal === undefined || !Number.isFinite(targetVal)) {
      delete el.dataset.numVal;
      el.textContent = fmtFn(targetVal);
      return;
    }
    const prevRaw = el.dataset.numVal;
    const prev = prevRaw !== undefined ? Number(prevRaw) : NaN;
    el.dataset.numVal = String(targetVal);
    if (document.hidden || reducedMotionMq.matches || !Number.isFinite(prev) || Math.abs(targetVal - prev) < 1e-6) {
      el.textContent = fmtFn(targetVal);
      return;
    }
    const dur = 240;
    const start = performance.now();
    const tick = (now) => {
      const t = Math.min(1, Math.max(0, (now - start) / dur));
      const ease = 1 - Math.pow(1 - t, 3);
      const cur = prev + (targetVal - prev) * ease;
      el.textContent = t < 1 ? fmtFn(cur) : fmtFn(targetVal);
      if (t < 1 && !document.hidden && !reducedMotionMq.matches) {
        activeTweens.set(el, requestAnimationFrame(tick));
      } else {
        el.textContent = fmtFn(targetVal);
        activeTweens.delete(el);
      }
    };
    activeTweens.set(el, requestAnimationFrame(tick));
  }

  /* ------------------------------ Privacy Mask ------------------------------ */
  function maskIdentifier(value) {
    if (!value || typeof value !== 'string') return '***';
    const s = value.trim();
    if (s.includes('@')) {
      const [local, domain] = s.split('@');
      if (local.length <= 2) return `${local[0] || '*'}*@${domain}`;
      return `${local[0]}***${local[local.length - 1]}@${domain}`;
    }
    if (s.length <= 8) return `${s.slice(0, 2)}***`;
    return `${s.slice(0, 6)}...${s.slice(-4)}`;
  }
  const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
  const WIN_PATH_RE = /([A-Za-z]:\\Users\\)([^\\/\r\n]+)/gi;
  const UNIX_PATH_RE = /(\/(?:Users|home)\/)([^/\r\n]+)/g;

  function maskText(s) {
    const str = String(s ?? '');
    if (!state.privacy) return str;
    return str
      .replace(EMAIL_RE, (m) => maskIdentifier(m))
      .replace(WIN_PATH_RE, '$1<user>')
      .replace(UNIX_PATH_RE, '$1<user>');
  }

  const accLabel = (a) => {
    const raw = ['email_or_label', 'display_name', 'account_email', 'email', 'label', 'account_id', 'id']
      .map((k) => v(a, k))
      .find((x) => x !== undefined && x !== null && String(x).trim() !== '') ?? '—';
    const str = String(raw);
    if (!state.privacy) return str;
    return str.includes('@') ? maskIdentifier(str) : maskText(str);
  };
  const accId = (a) => String(v(a, 'account_id', 'id') ?? '');

  /* ------------------------------ Modal Accessibility Helper ------------------------------ */
  function syncModalInert() {
    const appShell = $('#app-shell');
    if (!appShell) return;
    const anyOpen = $$('dialog.modal').some((d) => d.open);
    if (anyOpen) {
      appShell.setAttribute('aria-hidden', 'true');
      appShell.inert = true;
    } else {
      appShell.removeAttribute('aria-hidden');
      appShell.inert = false;
    }
  }
  function openModal(dlg) {
    if (!dlg || isHudView) return;
    if (!dlg.open) {
      if (typeof dlg.showModal === 'function') {
        try { dlg.showModal(); } catch { dlg.setAttribute('open', ''); }
      } else {
        dlg.setAttribute('open', '');
      }
    }
    syncModalInert();
  }
  function closeModal(dlg) {
    if (!dlg) return;
    if (dlg.open) {
      if (typeof dlg.close === 'function') {
        try { dlg.close(); } catch { dlg.removeAttribute('open'); }
      } else {
        dlg.removeAttribute('open');
      }
    }
    syncModalInert();
  }

  /* ------------------------------ UI Feedback Helpers ------------------------------ */
  function toast(msg, kind = 'ok') {
    const host = $('#toasts');
    if (!host) return;
    const t = h('div', { class: 'toast', dataset: { kind } }, msg);
    host.appendChild(t);
    setTimeout(() => t.remove(), kind === 'err' ? 6500 : 3500);
  }
  function banner(msg) {
    const b = $('#banner');
    if (!b) return;
    if (!msg) {
      b.hidden = true;
      b.textContent = '';
      return;
    }
    b.hidden = false;
    b.textContent = msg;
  }
  async function busy(btn, fn) {
    if (btn) {
      btn.setAttribute('aria-busy', 'true');
      btn.disabled = true;
    }
    try {
      return await fn();
    } finally {
      if (btn) {
        btn.removeAttribute('aria-busy');
        btn.disabled = false;
      }
    }
  }

  /* ------------------------------ API & Unified Filter Params ------------------------------ */
  async function api(path, opts = {}) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), opts.timeout || 30000);
    try {
      const res = await fetch(path, {
        method: opts.method || 'GET',
        headers: opts.body ? { 'content-type': 'application/json' } : undefined,
        body: opts.body ? JSON.stringify(opts.body) : undefined,
        signal: ctl.signal,
        cache: 'no-store',
      });
      let data = null;
      const text = await res.text();
      try { data = text ? JSON.parse(text) : null; }
      catch { data = { raw: text }; }
      if (res.status === 401 && data && data.requiresPin) {
        state.requiresPin = true;
        showPinGate();
        throw new Error(t('pin.required'));
      }
      if (!res.ok || (data && data.ok === false)) {
        throw new Error((data && (data.error || data.detail || data.message)) || `HTTP ${res.status}`);
      }
      return data;
    } finally {
      clearTimeout(timer);
    }
  }

  function filterParams(extra = {}) {
    const p = new URLSearchParams();
    p.set('era', state.era);
    if (state.from) p.set('from', state.from);
    if (state.to) p.set('to', state.to.length === 10 ? state.to + 'T23:59:59.999Z' : state.to);
    if (state.accountId) p.set('accountId', state.accountId);
    if (state.sourceTool) p.set('sourceTool', state.sourceTool);
    if (state.rq.modelId) p.set('modelId', state.rq.modelId);
    for (const [k, val] of Object.entries(extra)) {
      if (val !== '' && val !== null && val !== undefined) p.set(k, String(val));
    }
    return p;
  }

  /* ------------------------------ Live SSE & BroadcastChannel ------------------------------ */
  const live = { es: null, pollTimer: null, retryTimer: null, refreshTimer: null, mode: 'off', privacySyncDone: false };

  function setLive(mode) {
    live.mode = mode;
    const chip = $('#live-chip');
    const txt = $('#live-chip-text');
    if (!chip || !txt) return;
    chip.dataset.state = state.syncPaused ? 'poll' : mode;
    txt.textContent = state.syncPaused
      ? t('live.paused')
      : mode === 'sse'
      ? t('live.sse')
      : mode === 'poll'
      ? t('live.poll')
      : t('live.offline');
  }

  function scheduleRefresh(delay = 320) {
    clearTimeout(live.refreshTimer);
    live.refreshTimer = setTimeout(() => refreshAll(true), delay);
  }

  function startPolling() {
    if (live.pollTimer) return;
    live.pollTimer = setInterval(() => {
      if (!document.hidden && !state.requiresPin) refreshAll(true);
    }, 6000);
  }
  function stopPolling() {
    clearInterval(live.pollTimer);
    live.pollTimer = null;
  }

  function connectEvents() {
    if (state.requiresPin) return;
    if (!('EventSource' in window)) {
      setLive('poll');
      startPolling();
      return;
    }
    try { live.es?.close(); } catch { /* ignore */ }
    const es = new EventSource('/api/events');
    live.es = es;
    es.onopen = () => {
      setLive('sse');
      stopPolling();
      clearTimeout(live.retryTimer);
    };
    ['connected', 'sync', 'forensic', 'ingest', 'settings', 'quota'].forEach((name) => {
      es.addEventListener(name, (ev) => {
        setLive('sse');
        stopPolling();
        if (name !== 'connected') {
          if (name === 'settings') {
            try { applySettings(JSON.parse(ev.data)); } catch { /* ignore */ }
          }
          scheduleRefresh();
        }
      });
    });
    es.onmessage = () => scheduleRefresh();
    es.onerror = () => {
      try { es.close(); } catch { /* ignore */ }
      setLive(S.ov ? 'poll' : 'off');
      startPolling();
      clearTimeout(live.retryTimer);
      live.retryTimer = setTimeout(connectEvents, 25000);
    };
  }

  function applySettings(d) {
    if (!d || typeof d !== 'object') return;
    const fx = nn(d, 'fxUsdTry', 'fx_usd_try');
    if (fx && fx > 0) state.fx = fx;
    const ms = v(d, 'milestoneAt', 'milestone_at');
    if (ms) state.milestoneAt = ms;
    if (typeof d.syncPaused === 'boolean') state.syncPaused = d.syncPaused;
    if (d.teeProxy && typeof d.teeProxy === 'object') state.tee = { ...state.tee, ...d.teeProxy };
    const pm = v(d, 'privacyMask', 'privacy_mask');
    if (pm !== undefined && pm !== null) {
      state.privacy = pm === true || pm === '1' || pm === 1;
    }
  }

  function broadcastState() {
    if (!bc || !S.ov) return;
    try {
      bc.postMessage({
        type: 'overview',
        ov: S.ov,
        cur: state.cur,
        fx: state.fx,
        privacy: state.privacy,
        lang: state.lang,
        ctxId: state.ctxId,
        pinnedSessionId: state.pinnedSessionId,
      });
    } catch { /* ignore */ }
  }

  if (bc) {
    bc.addEventListener('message', (ev) => {
      const msg = ev.data;
      if (!msg || typeof msg !== 'object') return;
      if (msg.type === 'overview' && msg.ov) {
        S.ov = msg.ov;
        if (msg.cur) state.cur = msg.cur;
        if (msg.fx) state.fx = msg.fx;
        if (typeof msg.privacy === 'boolean') state.privacy = msg.privacy;
        if (msg.lang && I18N.supported.includes(msg.lang) && msg.lang !== state.lang) {
          state.lang = msg.lang;
          applyI18n();
        }
        if (msg.ctxId !== undefined) state.ctxId = msg.ctxId;
        if (msg.pinnedSessionId !== undefined) state.pinnedSessionId = msg.pinnedSessionId;
        renderHudAll();
        if (!isHudView) {
          renderStatic();
          renderOverview();
        }
      }
    });
  }

  /* ------------------------------ Data Loading ------------------------------ */
  async function checkAuthStatus() {
    try {
      const auth = await api('/api/auth/status');
      if (auth && auth.requiresPin) {
        state.requiresPin = true;
        showPinGate();
        return false;
      }
      state.requiresPin = false;
      closeModal($('#pin-dialog'));
      return true;
    } catch {
      return true;
    }
  }

  function showPinGate() {
    const dlg = $('#pin-dialog');
    if (!dlg) return;
    openModal(dlg);
    const inp = $('#pin-input');
    if (inp) inp.focus();
  }

  async function loadOverview() {
    try {
      const ov = await api('/api/overview?' + filterParams({ days: 371, recentLimit: state.recentLimit }).toString());
      S.ov = ov || {};
      if (!live.privacySyncDone) {
        const pm = v(S.ov, 'privacyMask', 'privacy_mask');
        if (pm !== undefined && pm !== null) {
          state.privacy = pm === true || pm === '1' || pm === 1;
        }
        live.privacySyncDone = true;
      }
      applySettings(S.ov);
      banner('');
      renderHudAll();
      if (!isHudView) {
        renderStatic();
        renderOverview();
      }
      broadcastState();
    } catch (err) {
      if (!S.ov) setLive('off');
      if (!isHudView) {
        banner(t('toast.serverErr', { msg: err.message }));
      }
    }
    const footUp = $('#foot-updated');
    if (footUp) footUp.textContent = t('foot.updated', { time: new Date().toLocaleTimeString(locale()) });
  }

  async function loadSessions() {
    try {
      const d = await api('/api/sessions?' + filterParams().toString());
      S.sessions = arr(v(d, 'sessions', 'rows'));
    } catch {
      /* optional endpoint fallback */
    }
  }

  async function loadTab(tab, quiet) {
    if (isHudView || state.requiresPin) return;
    try {
      if (tab === 'accounts') {
        if (state.editAcc && quiet) return;
        const d = await api('/api/accounts?' + filterParams().toString());
        S.accounts = arr(v(d, 'accounts')) || [];
        renderAccounts();
      } else if (tab === 'requests') {
        await loadRequests();
      } else if (tab === 'forensics') {
        const d = await api('/api/forensics/history?' + filterParams().toString());
        S.history = arr(v(d, 'captures', 'history', 'rows'));
        renderHistory();
      } else if (tab === 'models') {
        if (state.editModel && quiet) return;
        const [m, i] = await Promise.all([
          api('/api/models?' + filterParams({ q: S.mq }).toString()).catch(() => ({ models: [] })),
          api('/api/integrations').catch(() => ({ integrations: [] })),
        ]);
        S.models = arr(v(m, 'models'));
        S.integrations = arr(v(i, 'integrations'));
        renderModels();
        renderIntegrations();
      }
    } catch (err) {
      if (!quiet) toast(t('toast.loadErr', { msg: err.message }), 'err');
    }
  }

  async function refreshAll(quiet) {
    if (state.requiresPin) return;
    await loadOverview();
    if (!isHudView) {
      await loadTab(state.tab, quiet);
    }
  }

  /* ------------------------------ Static Controls & Active Chips Strip ------------------------------ */
  function populateSelectOptions(sel, items, firstLabel) {
    if (!sel) return;
    const sig = firstLabel + '|' + items.map(([val, lbl]) => `${val}:${lbl}`).join('|');
    if (sel.dataset.sig === sig) return;
    clearEl(sel);
    if (firstLabel !== null) {
      sel.appendChild(h('option', { value: '' }, firstLabel));
    }
    for (const [val, lbl] of items) {
      sel.appendChild(h('option', { value: val }, lbl));
    }
    sel.dataset.sig = sig;
  }

  function renderActiveChips() {
    const host = $('#active-chips');
    if (!host) return;
    clearEl(host);

    const eraLabel = state.era === 'all' ? t('ctrl.eraAll') : t('ctrl.eraLive');
    host.appendChild(
      h('span', { class: 'filter-chip' }, t('chips.era') + ' ', h('b', null, eraLabel))
    );

    const activeFilters = [];
    if (state.era !== 'live') {
      activeFilters.push(['era', `${t('chips.era')} ${eraLabel}`]);
    }
    if (state.sourceTool) {
      activeFilters.push(['sourceTool', `${t('chips.source')} ${sourceLabel(state.sourceTool)}`]);
    }
    if (state.accountId) {
      const accList = S.accounts.length ? S.accounts : arr(v(S.ov || {}, 'byAccount'));
      const found = accList.find((a) => accId(a) === state.accountId);
      const lbl = found ? accLabel(found) : (state.privacy ? maskIdentifier(state.accountId) : state.accountId);
      activeFilters.push(['accountId', `${t('chips.account')} ${lbl}`]);
    }
    if (state.rq.modelId) {
      activeFilters.push(['modelId', `${t('chips.model')} ${state.rq.modelId}`]);
    }
    if (state.rq.sessionId) {
      const sLbl = maskText(state.rq.sessionTitle || state.rq.sessionId).slice(0, 32);
      activeFilters.push(['sessionId', `${t('chips.session')} ${sLbl}`]);
    }
    if (state.from || state.to) {
      const dateStr = state.from && state.to && state.from === state.to
        ? state.from
        : `${state.from || '…'} – ${state.to || '…'}`;
      activeFilters.push(['date', `${t('chips.date')} ${dateStr}`]);
    }

    for (const [key, label] of activeFilters) {
      const btn = h(
        'button',
        {
          type: 'button',
          class: 'filter-chip-btn tnum',
          dataset: { action: 'clear-filter', filter: key },
          'aria-label': t('chips.removeAria', { label }),
        },
        h('span', null, label),
        iconEl('x')
      );
      host.appendChild(btn);
    }

    if (activeFilters.length > 1) {
      host.appendChild(
        h(
          'button',
          {
            type: 'button',
            class: 'btn btn-sm btn-ghost',
            dataset: { action: 'clear-filter', filter: 'all' },
          },
          iconEl('x'),
          h('span', null, t('chips.clearAll'))
        )
      );
    }

    const badge = $('#filter-count-badge');
    if (badge) {
      const count = activeFilters.filter(([k]) => k !== 'era').length;
      badge.hidden = count === 0;
      badge.textContent = String(count);
    }
  }

  function renderStatic() {
    if (isHudView) return;
    const ov = S.ov || {};
    const openWeb = $('#btn-open-web');
    if (openWeb) openWeb.href = location.origin + '/';
    const footOrigin = $('#foot-origin');
    if (footOrigin) footOrigin.textContent = location.host || localHostName();

    const msNote = $('#milestone-note');
    if (msNote) msNote.textContent = state.milestoneAt ? `${t('ctrl.milestonePrefix')} ${fmtDate(state.milestoneAt)}` : '';
    const fxNote = $('#fx-note');
    if (fxNote) fxNote.textContent = '1 $ = ' + fmtNum(state.fx, 2) + ' ₺';

    $$('#seg-era button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.era === state.era)));
    $$('#seg-cur button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.cur === state.cur)));
    $$('#seg-lang button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.lang === state.lang)));
    applyDensity();
    $$('#seg-heat-metric button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.hmetric === state.heatMetric)));
    $$('#seg-heat-win button').forEach((b) => b.setAttribute('aria-pressed', String(Number(b.dataset.hwin) === state.heatWeeks)));

    const pb = $('#btn-privacy');
    if (pb) {
      pb.setAttribute('aria-pressed', String(state.privacy));
      const pTxt = $('#privacy-text');
      if (pTxt) pTxt.textContent = state.privacy ? t('ctrl.privacyOn') : t('ctrl.privacyOff');
      setBtnIcon(pb, state.privacy ? 'eye-off' : 'eye');
    }
    const wizPrivLbl = $('#wiz-privacy-label');
    if (wizPrivLbl) wizPrivLbl.textContent = state.privacy ? t('ctrl.privacyMaskOn') : t('ctrl.privacyMaskOff');
    const wizPrivBtn = $('#wiz-btn-privacy');
    if (wizPrivBtn) setBtnIcon(wizPrivBtn, state.privacy ? 'eye-off' : 'eye');

    const srcList = localizedSources();
    const srcSel = $('#f-source');
    populateSelectOptions(srcSel, srcList, t('ctrl.allSources'));
    if (srcSel) srcSel.value = state.sourceTool;

    const accList = S.accounts.length ? S.accounts : arr(v(ov, 'byAccount'));
    const accSel = $('#f-account');
    populateSelectOptions(
      accSel,
      accList.map((a) => [accId(a), accLabel(a)]),
      t('ctrl.allAccounts')
    );
    if (accSel) accSel.value = state.accountId;

    const fFrom = $('#f-from');
    if (fFrom) fFrom.value = state.from;
    const fTo = $('#f-to');
    if (fTo) fTo.value = state.to;

    const retagSrc = $('#rt-source');
    populateSelectOptions(retagSrc, srcList, t('ctrl.all'));

    const stFx = $('#st-fx');
    if (stFx) stFx.placeholder = String(state.fx);
    const expCsv = $('#exp-csv');
    if (expCsv) expCsv.href = '/api/export?' + filterParams({ format: 'csv' }).toString();
    const expJson = $('#exp-json');
    if (expJson) expJson.href = '/api/export?' + filterParams({ format: 'json' }).toString();

    renderActiveChips();
    renderSyncControl();
    renderTeeControl();
    renderGuide();
  }

  function renderGuide() {
    const card = $('#quick-guide');
    if (card) card.hidden = Boolean(state.guideHidden);
  }

  function renderSyncControl() {
    const btn = $('#btn-toggle-sync');
    const txt = $('#sync-toggle-text');
    if (!btn || !txt) return;
    const paused = Boolean(state.syncPaused);
    btn.setAttribute('aria-pressed', String(paused));
    btn.classList.toggle('btn-primary', paused);
    txt.textContent = paused ? t('btn.resume') : t('btn.pause');
    setBtnIcon(btn, paused ? 'play' : 'pause');
    setLive(live.mode);
  }

  function renderTeeControl() {
    const tee = state.tee || {};
    const running = Boolean(tee.running);
    const port = Number(tee.port) || 19841;
    const hostLabel = localHostName();
    const badge = $('#tee-badge');
    const btn = $('#tee-toggle');
    const txt = $('#tee-toggle-text');
    const copyBtn = $('#tee-copy');
    const statsEl = $('#tee-stats');
    if (badge) {
      badge.className = 'badge ' + (running ? 'badge-ok' : '');
      clearEl(badge);
      badge.appendChild(h('span', { class: 'tnum' }, running ? t('for.teeRunning', { host: hostLabel, port }) : t('for.teeOff')));
    }
    if (btn && txt) {
      btn.setAttribute('aria-pressed', String(running));
      btn.classList.toggle('btn-primary', !running);
      btn.classList.toggle('btn-danger', running);
      txt.textContent = running ? t('for.teeStop') : t('for.teeStart');
      setBtnIcon(btn, running ? 'square' : 'play');
    }
    if (copyBtn) copyBtn.dataset.copy = localPresetBase(port);
    if (statsEl) {
      const st = tee.stats;
      statsEl.textContent = running && st
        ? t('for.teeStats', { reqs: fmtNum(st.requests || 0), caps: fmtNum(st.captures || 0), errs: fmtNum(st.errors || 0) })
        : t('for.teeIdle');
    }
  }

  /* ------------------------------ Context Pressure & Keyed DOM Patching ------------------------------ */
  function ctxLevel(p) {
    return p >= 80 ? 'crit' : p >= 65 ? 'warn' : 'ok';
  }

  function sessionCtx(s) {
    const tokens = nn(s, 'latest_context_tokens', 'context_tokens', 'peak_context_tokens', 'contextTokens') ?? 0;
    const win = nn(s, 'context_window', 'contextWindow') || 1000000;
    let pct = nn(s, 'utilization_pct', 'context_pct', 'contextPct', 'context_occupancy_pct');
    if (pct === null && win) pct = (tokens / win) * 100;
    pct = pct ?? 0;
    let cache = nn(s, 'cache_hit_pct', 'cacheHitPct');
    if (cache === null) {
      const cr = nn(s, 'cache_read_tokens');
      const inp = nn(s, 'input_tokens');
      if (cr !== null && (inp || cr)) cache = (cr / ((inp || 0) + (cr || 0) || 1)) * 100;
    }
    const to65 = nn(s, 'tokens_to_65_pct', 'tokensTo65Pct') ?? Math.max(0, Math.round(win * 0.65 - tokens));
    const to80 = nn(s, 'tokens_to_80_pct', 'tokensTo80Pct') ?? Math.max(0, Math.round(win * 0.80 - tokens));
    const ttft = nn(s, 'latest_ttft_ms', 'ttft_ms', 'ttftMs');
    const tps = nn(s, 'latest_tok_per_sec', 'tok_per_sec', 'tokens_per_sec', 'tokPerSec');
    return { tokens, win, pct, cache, to65, to80, ttft, tps };
  }

  function getActiveAndRecentSessions() {
    const ov = S.ov || {};
    const rawActive = v(ov, 'activeSessions');
    const rawCtx = arr(v(ov, 'activeContextSessions'));
    const active = (Array.isArray(rawActive)
      ? rawActive
      : rawCtx.filter((s) => !v(s, 'killed') && v(s, 'is_active') !== false)
    ).filter((s) => !v(s, 'killed') && (nn(s, 'latest_context_tokens', 'context_tokens', 'peak_context_tokens') || 0) > 0);

    const rawRecent = v(ov, 'recentSessions');
    const activeIds = new Set(active.map((s) => String(v(s, 'session_id', 'id'))));
    const recent = (Array.isArray(rawRecent)
      ? rawRecent
      : rawCtx.filter((s) => !activeIds.has(String(v(s, 'session_id', 'id'))))
    ).filter((s) => !activeIds.has(String(v(s, 'session_id', 'id'))));

    return { active: active.slice(0, 12), recent: recent.slice(0, state.recentLimit) };
  }

  function renderRecentDrawer(recent) {
    const btn = $('#btn-recent-sessions');
    const lbl = $('#recent-sessions-label');
    const drawer = $('#ctx-recent-drawer');
    if (!btn || !lbl || !drawer) return;
    if (!recent.length) {
      btn.hidden = true;
      drawer.hidden = true;
      return;
    }
    btn.hidden = false;
    btn.setAttribute('aria-expanded', String(state.recentDrawerOpen));
    lbl.textContent = t('ctx.recentBtn', { n: recent.length });
    drawer.hidden = !state.recentDrawerOpen;
    if (!state.recentDrawerOpen) return;

    clearEl(drawer);
    const head = h(
      'div',
      { class: 'ctx-recent-head' },
      h('span', { class: 'muted mono-sm' }, t('ctx.recentHead')),
      h(
        'div',
        { class: 'ctx-recent-count' },
        h('span', { class: 'ctrl-label' }, t('ctx.recentShow')),
        h(
          'div',
          { class: 'seg seg-sm', role: 'group', 'aria-label': t('ctx.recentShow') },
          RECENT_LIMITS.map((lim) =>
            h(
              'button',
              {
                type: 'button',
                class: 'tnum',
                'aria-pressed': String(state.recentLimit === lim),
                dataset: { action: 'set-recent-limit', limit: String(lim) },
              },
              String(lim)
            )
          )
        )
      )
    );
    drawer.appendChild(head);

    const list = h('div', { class: 'ctx-recent-list' });
    for (const s of recent) {
      const c = sessionCtx(s);
      const id = String(v(s, 'session_id', 'id') || '');
      const title = maskText(v(s, 'title') || v(s, 'agent_name') || id);
      const src = sourceLabel(v(s, 'source_tool', 'sourceTool')) || t('ctx.fallbackSession');
      const model = v(s, 'primary_model_id', 'model_id', 'modelId');
      const subParts = [src, model ? maskText(model) : '', ago(v(s, 'last_event_at', 'updated_at'))].filter(Boolean);
      const isSelected = state.pinnedSessionId === id || state.ctxId === id;
      list.appendChild(
        h(
          'button',
          {
            type: 'button',
            class: 'ctx-recent-item',
            title,
            'aria-pressed': String(isSelected),
            dataset: { action: 'ctx', id, recent: '1' },
          },
          h(
            'span',
            { class: 'ctx-recent-main' },
            h('span', { class: 'ctx-recent-title' }, title),
            h('span', { class: 'ctx-recent-sub' }, subParts.join(' · '))
          ),
          h('span', { class: 'ctx-recent-stat mono-sm tnum' }, `${fmtPct(c.pct)} · ${fmtTok(c.tokens)}`)
        )
      );
    }
    drawer.appendChild(list);
  }

  function renderCtx() {
    if (isHudView) return;
    const { active: sessions, recent } = getActiveAndRecentSessions();
    const chips = $('#ctx-chips');
    const body = $('#ctx-body');
    if (!chips || !body) return;

    renderRecentDrawer(recent);

    // If pinned session became active again, promote cleanly back to live tracking
    if (state.pinnedSessionId && sessions.some((s) => String(v(s, 'session_id', 'id')) === state.pinnedSessionId)) {
      state.ctxId = state.pinnedSessionId;
      state.pinnedSessionId = null;
    }
    const pinned = state.pinnedSessionId
      ? recent.find((s) => String(v(s, 'session_id', 'id')) === state.pinnedSessionId) || null
      : null;

    if (!sessions.length && !pinned) {
      clearEl(chips);
      clearEl(body);
      const emptyBox = h(
        'div',
        { class: 'ctx-empty' },
        h('img', {
          src: '/assets/empty-telemetry.webp',
          width: 88,
          height: 66,
          alt: t('ctx.emptyAlt'),
          loading: 'lazy',
          decoding: 'async',
          class: 'ctx-empty-img shrink-0',
        }),
        h(
          'div',
          { class: 'ctx-empty-text min-w-0' },
          h('b', null, t('ctx.emptyTitle')),
          h('span', null, t('ctx.emptySub'))
        ),
        recent.length
          ? h(
              'button',
              { type: 'button', class: 'btn btn-sm', dataset: { action: 'toggle-recent-ctx' } },
              iconEl('history'),
              h('span', { class: 'tnum' }, t('ctx.recentBtn', { n: recent.length }))
            )
          : null
      );
      body.appendChild(emptyBox);
      return;
    }

    const cur = pinned || sessions.find((s) => String(v(s, 'session_id', 'id')) === state.ctxId) || sessions[0];
    const curId = String(v(cur, 'session_id', 'id'));
    state.ctxId = curId;

    // Keyed patch for active session chips
    const existingChips = new Map($$('button[data-id]', chips).map((b) => [b.dataset.id, b]));
    const nextIds = new Set();
    sessions.forEach((s) => {
      const c = sessionCtx(s);
      const id = String(v(s, 'session_id', 'id'));
      nextIds.add(id);
      const src = sourceLabel(v(s, 'source_tool', 'sourceTool')) || t('ctx.fallbackSession');
      const nm = maskText(String(v(s, 'title') || v(s, 'agent_name') || id)).slice(0, 20);
      const label = `${src} · ${nm} · ${fmtPct(c.pct)}`;
      let btn = existingChips.get(id);
      if (!btn) {
        btn = h('button', {
          type: 'button',
          class: 'ctx-chip tnum',
          role: 'tab',
          dataset: { action: 'ctx', id },
        });
        chips.appendChild(btn);
      }
      btn.setAttribute('aria-selected', String(!pinned && id === state.ctxId));
      btn.title = maskText(String(v(s, 'title') || id));
      if (btn.textContent !== label) btn.textContent = label;
    });
    for (const [id, btn] of existingChips.entries()) {
      if (!nextIds.has(id)) btn.remove();
    }

    const c = sessionCtx(cur);
    const lvl = ctxLevel(c.pct);
    const title = maskText(v(cur, 'title') || v(cur, 'session_id', 'id'));
    const compactText = lvl === 'crit'
      ? t('ctx.compactCrit')
      : lvl === 'warn'
      ? t('ctx.compactWarn', { tok: fmtTok(c.to80) })
      : t('ctx.compactOk', { tok: fmtTok(c.to65) });

    // Keyed DOM patch for ctx-body so .meter-fill transitions smoothly via GPU scaleX(var(--p))
    let liveRoot = body.querySelector('[data-ctx-live="1"]');
    if (!liveRoot || liveRoot.dataset.lang !== state.lang) {
      clearEl(body);
      const leftCol = h(
        'div',
        { class: 'min-w-0', dataset: { ctxLive: '1', lang: state.lang } },
        h(
          'div',
          { class: 'ctx-main' },
          h('span', { class: 'ctx-num tnum' }, h('span', { dataset: { ref: 'tok' } }), h('small', { dataset: { ref: 'win' } })),
          h('span', { class: 'ctx-pct tnum', dataset: { ref: 'pct' } }),
          h('span', { class: 'badge', dataset: { ref: 'badge' } }),
          h('span', { class: 'badge badge-info', dataset: { ref: 'pinned-badge' }, hidden: true }, h('span', null, t('ctx.pinnedBadge'))),
          h(
            'div',
            { class: 'ctx-session-actions' },
            h(
              'button',
              { type: 'button', class: 'btn btn-sm', dataset: { action: 'copy', copy: '/compact' }, title: t('ctx.copyCompactTitle') },
              iconEl('copy'),
              h('span', null, t('ctx.copyCompact'))
            ),
            h(
              'button',
              { type: 'button', class: 'btn btn-sm btn-ghost', dataset: { action: 'filter-session', ref: 'view-reqs' } },
              iconEl('list'),
              h('span', null, t('ctx.viewRequests'))
            ),
            h(
              'button',
              { type: 'button', class: 'btn btn-sm btn-ghost', dataset: { action: 'unpin-ctx', ref: 'back-live' }, hidden: true },
              iconEl('activity'),
              h('span', null, t('ctx.backLive'))
            )
          )
        ),
        h(
          'div',
          {
            class: 'meter',
            role: 'meter',
            'aria-valuemin': '0',
            'aria-valuemax': '100',
            'aria-label': t('ctx.meterAria'),
            dataset: { ref: 'meter', level: lvl },
          },
          h('div', { class: 'meter-fill', dataset: { ref: 'fill' }, style: { '--p': '0' } }),
          h('i', { class: 'meter-tick meter-tick-65' }),
          h('i', { class: 'meter-tick meter-tick-80' })
        ),
        h(
          'div',
          { class: 'meter-scale tnum' },
          h('span', null, t('ctx.scale0')),
          h('span', null, t('ctx.scale65')),
          h('span', null, t('ctx.scale80')),
          h('span', null, t('ctx.scale100'))
        )
      );
      const rightCol = h(
        'div',
        { class: 'ctx-meta' },
        h('span', null, t('ctx.metaSession') + ' ', h('b', { dataset: { ref: 'title' } })),
        h('span', null, t('ctx.metaSource') + ' ', h('b', { dataset: { ref: 'source' } })),
        h('span', null, t('ctx.metaModel') + ' ', h('b', { dataset: { ref: 'model' } })),
        h('span', null, t('ctx.metaCompact') + ' ', h('b', { class: 'tnum', dataset: { ref: 'compact' } })),
        h('span', null, t('ctx.metaSpeed') + ' ', h('b', { class: 'tnum', dataset: { ref: 'speed' } })),
        h('span', null, t('ctx.metaCache') + ' ', h('b', { class: 'tnum', dataset: { ref: 'cache' } })),
        h('span', null, t('ctx.metaLastEvent') + ' ', h('b', { class: 'tnum', dataset: { ref: 'ago' } }))
      );
      body.appendChild(leftCol);
      body.appendChild(rightCol);
      liveRoot = leftCol;
    }

    tweenNumber($('[data-ref="tok"]', body), c.tokens, fmtTok);
    const winEl = $('[data-ref="win"]', body);
    if (winEl) winEl.textContent = ' / ' + (c.win ? fmtTok(c.win) : '—');
    tweenNumber($('[data-ref="pct"]', body), c.pct, (x) => fmtPct(x, 1));

    const badgeEl = $('[data-ref="badge"]', body);
    if (badgeEl) {
      const badgeCls = lvl === 'crit' ? 'badge badge-danger' : lvl === 'warn' ? 'badge badge-warn' : 'badge badge-ok';
      const badgeIcon = lvl === 'ok' ? 'circle-check' : 'triangle-alert';
      const badgeTxt = lvl === 'crit' ? t('ctx.crit') : lvl === 'warn' ? t('ctx.warn') : t('ctx.healthy');
      const sig = `${lvl}:${state.lang}`;
      if (badgeEl.dataset.sig !== sig) {
        badgeEl.className = badgeCls;
        badgeEl.dataset.sig = sig;
        clearEl(badgeEl);
        badgeEl.appendChild(iconEl(badgeIcon));
        badgeEl.appendChild(h('span', null, badgeTxt));
      }
    }

    const pinnedBadge = $('[data-ref="pinned-badge"]', body);
    if (pinnedBadge) pinnedBadge.hidden = !pinned;
    const backBtn = $('[data-ref="back-live"]', body);
    if (backBtn) backBtn.hidden = !pinned;
    const viewReqsBtn = $('[data-ref="view-reqs"]', body);
    if (viewReqsBtn) {
      viewReqsBtn.dataset.id = curId;
      viewReqsBtn.dataset.title = String(title);
    }

    const meterEl = $('[data-ref="meter"]', body);
    if (meterEl) {
      meterEl.dataset.level = lvl;
      meterEl.setAttribute('aria-valuenow', String(Math.round(c.pct)));
    }
    const fillEl = $('[data-ref="fill"]', body);
    if (fillEl) {
      fillEl.style.setProperty('--p', Math.min(1, Math.max(0, c.pct / 100)).toFixed(4));
    }

    const setMeta = (ref, val) => {
      const el = $(`[data-ref="${ref}"]`, body);
      if (el && el.textContent !== val) el.textContent = val;
    };
    setMeta('title', String(title).slice(0, 64));
    setMeta('source', sourceLabel(v(cur, 'source_tool', 'sourceTool')) || '—');
    setMeta('model', v(cur, 'primary_model_id', 'model_id', 'modelId') || '—');
    setMeta('compact', compactText);
    const spdParts = [];
    if (c.tps !== null) spdParts.push(`${fmtNum(c.tps, 1)} tok/s`);
    if (c.ttft !== null) spdParts.push(`TTFT ${fmtMs(c.ttft)}`);
    setMeta('speed', spdParts.length ? spdParts.join(' · ') : '—');
    setMeta('cache', fmtPct(c.cache));
    setMeta('ago', ago(v(cur, 'last_event_at', 'lastEventAt', 'updated_at')));
  }

  /* ------------------------------ Floating Turbo Mini-HUD Capsule ------------------------------ */
  function renderHudInto(host) {
    if (!host) return;
    const docRef = host.ownerDocument || document;
    const ov = S.ov || {};
    const k = v(ov, 'kpis') || {};
    const { active, recent } = getActiveAndRecentSessions();
    const pinned = state.pinnedSessionId
      ? recent.find((s) => String(v(s, 'session_id', 'id')) === state.pinnedSessionId) || null
      : null;
    const cur = pinned || active.find((s) => String(v(s, 'session_id', 'id')) === state.ctxId) || active[0] || recent[0] || null;
    const c = cur ? sessionCtx(cur) : { tokens: 0, win: 1000000, pct: 0, to65: 650000, to80: 800000, ttft: nn(k, 'avgTtftMs'), tps: nn(k, 'avgTokPerSec') };
    const lvl = ctxLevel(c.pct);
    const title = cur
      ? maskText(v(cur, 'title') || v(cur, 'agent_name') || v(cur, 'session_id', 'id'))
      : t('hud.waiting');
    const remTxt = c.pct >= 80
      ? t('hud.critNow')
      : c.pct >= 65
      ? t('hud.to80', { tok: fmtTok(c.to80) })
      : t('hud.to65', { tok: fmtTok(c.to65) });
    const tps = c.tps ?? nn(k, 'avgTokPerSec');
    const ttft = c.ttft ?? nn(k, 'avgTtftMs');
    const listCost = nn(k, 'apiListCostUsd');
    const paidCost = nn(k, 'effectivePaidUsd') ?? nn(k, 'billedCostUsd');

    let shell = host.querySelector('[data-hud-shell="1"]');
    if (!shell) {
      clearEl(host);
      const copyBtn = docRef.createElement('button');
      copyBtn.type = 'button';
      copyBtn.className = 'btn btn-sm hud-copy-btn';
      copyBtn.dataset.ref = 'hud-copy';
      copyBtn.title = t('ctx.copyCompactTitle');
      copyBtn.textContent = '/compact';
      copyBtn.addEventListener('click', async () => {
        try {
          await (host.ownerDocument.defaultView || window).navigator.clipboard.writeText('/compact');
          copyBtn.textContent = t('hud.copied');
          setTimeout(() => { copyBtn.textContent = '/compact'; }, 1800);
        } catch {
          copyBtn.textContent = '/compact';
        }
      });

      const dot = docRef.createElement('span');
      dot.className = 'hud-dot';
      dot.dataset.ref = 'hud-dot';

      const titleEl = docRef.createElement('span');
      titleEl.className = 'hud-title';
      titleEl.dataset.ref = 'hud-title';

      const titleWrap = docRef.createElement('div');
      titleWrap.className = 'hud-title-wrap';
      titleWrap.appendChild(dot);
      titleWrap.appendChild(titleEl);

      const pctEl = docRef.createElement('span');
      pctEl.className = 'hud-pct tnum';
      pctEl.dataset.ref = 'hud-pct';

      const topRow = docRef.createElement('div');
      topRow.className = 'hud-top';
      topRow.appendChild(titleWrap);
      topRow.appendChild(pctEl);
      topRow.appendChild(copyBtn);

      const fill = docRef.createElement('div');
      fill.className = 'meter-fill';
      fill.dataset.ref = 'hud-fill';
      fill.style.setProperty('--p', '0');

      const t65 = docRef.createElement('i');
      t65.className = 'meter-tick meter-tick-65';
      const t80 = docRef.createElement('i');
      t80.className = 'meter-tick meter-tick-80';

      const meter = docRef.createElement('div');
      meter.className = 'meter';
      meter.dataset.ref = 'hud-meter';
      meter.appendChild(fill);
      meter.appendChild(t65);
      meter.appendChild(t80);

      const mRem = docRef.createElement('span');
      mRem.className = 'tnum';
      mRem.dataset.ref = 'hud-rem';

      const mSpd = docRef.createElement('span');
      mSpd.className = 'tnum';
      mSpd.dataset.ref = 'hud-spd';

      const mCost = docRef.createElement('span');
      mCost.className = 'tnum';
      mCost.dataset.ref = 'hud-cost';

      const botRow = docRef.createElement('div');
      botRow.className = 'hud-metrics tnum';
      botRow.appendChild(mRem);
      botRow.appendChild(mSpd);
      botRow.appendChild(mCost);

      shell = docRef.createElement('div');
      shell.dataset.hudShell = '1';
      shell.style.display = 'grid';
      shell.style.gap = '6px';
      shell.appendChild(topRow);
      shell.appendChild(meter);
      shell.appendChild(botRow);
      host.appendChild(shell);
    }

    const q = (ref) => shell.querySelector(`[data-ref="${ref}"]`);
    const dotEl = q('hud-dot');
    if (dotEl) {
      dotEl.style.background = lvl === 'crit' ? 'var(--status-danger)' : lvl === 'warn' ? 'var(--status-warning)' : 'var(--status-success)';
    }
    const tEl = q('hud-title');
    if (tEl) tEl.textContent = String(title).slice(0, 34);
    const pEl = q('hud-pct');
    if (pEl) pEl.textContent = fmtPct(c.pct, 1);
    const mEl = q('hud-meter');
    if (mEl) mEl.dataset.level = lvl;
    const fEl = q('hud-fill');
    if (fEl) fEl.style.setProperty('--p', Math.min(1, Math.max(0, c.pct / 100)).toFixed(4));
    const rEl = q('hud-rem');
    if (rEl) rEl.textContent = remTxt;
    const sEl = q('hud-spd');
    if (sEl) sEl.textContent = `${tps !== null ? fmtNum(tps, 1) : '—'} tok/s · ${ttft !== null ? fmtMs(ttft) : '—'}`;
    const cEl = q('hud-cost');
    if (cEl) cEl.textContent = `${money(listCost)} / ${money(paidCost)}`;
  }

  function renderHudAll() {
    const hudRoot = $('#hud-root');
    if (hudRoot && !hudRoot.hidden) {
      renderHudInto(hudRoot);
    }
    if (pipWindow && !pipWindow.closed) {
      const pipHost = pipWindow.document.getElementById('pip-hud-root');
      if (pipHost) renderHudInto(pipHost);
    }
  }

  async function openMiniHud() {
    if ('documentPictureInPicture' in window) {
      try {
        const win = await window.documentPictureInPicture.requestWindow({ width: 340, height: 112 });
        pipWindow = win;
        win.document.documentElement.setAttribute('lang', state.lang);
        win.document.body.className = 'hud-mode tnum';
        for (const sheet of Array.from(document.querySelectorAll('link[rel="stylesheet"], style'))) {
          win.document.head.appendChild(sheet.cloneNode(true));
        }
        const host = win.document.createElement('aside');
        host.id = 'pip-hud-root';
        host.className = 'hud-capsule';
        win.document.body.appendChild(host);
        renderHudInto(host);
        win.addEventListener('pagehide', () => { pipWindow = null; });
        return;
      } catch {
        /* fallback to popup window */
      }
    }
    window.open('/?view=hud', 'wt-hud', 'popup=yes,width=340,height=118');
  }

  /* ------------------------------ Overview & Keyed Bento KPIs ------------------------------ */
  const KPI_DEFS = [
    { key: 'api-list', cls: 'kpi kpi-hero', icon: 'coins', labelKey: 'kpi.apiList' },
    { key: 'effective-paid', cls: 'kpi', icon: 'wallet', labelKey: 'kpi.effectivePaid' },
    { key: 'multiplier', cls: 'kpi kpi-mult', icon: 'layers', labelKey: 'kpi.multiplier' },
    { key: 'cache-savings', cls: 'kpi', icon: 'database', labelKey: 'kpi.cacheSavings' },
    { key: 'avg-req', cls: 'kpi', icon: 'scale', labelKey: 'kpi.avgReq' },
    { key: 'speed', cls: 'kpi', icon: 'zap', labelKey: 'kpi.speed' },
  ];

  function setSubParts(subEl, parts) {
    if (!subEl) return;
    clearEl(subEl);
    appendChildren(subEl, parts);
  }

  function renderOverview() {
    if (isHudView) return;
    renderCtx();
    const ov = S.ov || {};
    const k = v(ov, 'kpis') || {};
    const pr = v(ov, 'perRequestStats') || {};
    const reqs = nn(k, 'totalRequests') ?? n0(k, 'requests');
    const totalTok = nn(k, 'totalTokens') ?? (n0(k, 'inputTokens') + n0(k, 'outputTokens') + n0(k, 'cacheReadTokens') + n0(k, 'cacheWriteTokens'));
    const mult = nn(k, 'listValueMultiplier');
    const hit = nn(k, 'cacheHitPct');
    const avg = nn(k, 'avgCostPerRequestUsd', 'avgCostPerReq') ?? nn(pr, 'avg');
    const p50 = nn(pr, 'p50') ?? nn(k, 'p50CostPerReq');
    const p95 = nn(pr, 'p95') ?? nn(k, 'p95CostPerReq');
    const mx = nn(pr, 'max') ?? nn(k, 'maxCostPerReq');
    const cacheSave = nn(k, 'cacheSavingsUsd');
    const rtkSave = nn(k, 'compressionSavingsUsd', 'rtkSavingsUsd');
    const saveTotal = (cacheSave || 0) + (rtkSave || 0);
    const tokParts = [
      ['bg-input', t('tok.input'), nn(k, 'uncachedInputTokens') ?? n0(k, 'inputTokens')],
      ['bg-cr', t('tok.cacheRead'), n0(k, 'cacheReadTokens')],
      ['bg-cw', t('tok.cacheWrite'), n0(k, 'cacheWriteTokens')],
      ['bg-out', t('tok.output'), n0(k, 'outputTokens')],
      ['bg-rs', t('tok.reasoning'), n0(k, 'reasoningTokens')],
    ];
    const tokSum = tokParts.reduce((s, p) => s + p[2], 0) || 1;

    const grid = $('#kpi-grid');
    if (grid) {
      if (!grid.querySelector('[data-kpi="api-list"]') || grid.dataset.lang !== state.lang) {
        clearEl(grid);
        grid.dataset.lang = state.lang;
        for (const def of KPI_DEFS) {
          grid.appendChild(
            h(
              'div',
              { class: def.cls, dataset: { kpi: def.key } },
              h('div', { class: 'kpi-label' }, iconEl(def.icon), h('span', null, t(def.labelKey))),
              h('div', { class: 'kpi-value tnum', dataset: { ref: 'val' } }, '—'),
              h('div', { class: 'kpi-sub tnum', dataset: { ref: 'sub' } })
            )
          );
        }
        grid.appendChild(
          h(
            'div',
            { class: 'kpi kpi-wide', dataset: { kpi: 'tok-dist' } },
            h('div', { class: 'kpi-label' }, iconEl('layers'), h('span', null, t('kpi.tokDist'))),
            h(
              'div',
              { class: 'tokbar', role: 'img', 'aria-label': t('kpi.tokDistAria'), dataset: { ref: 'tokbar' } },
              tokParts.map((p) => h('i', { class: p[0], dataset: { seg: p[0] } }))
            ),
            h(
              'ul',
              { class: 'legend', dataset: { ref: 'toklegend' } },
              tokParts.map((p) =>
                h('li', null, h('span', { class: `swatch ${p[0]}` }), `${p[1]} `, h('b', { class: 'tnum', dataset: { leg: p[0] } }, '0'))
              )
            )
          )
        );
      }

      const patchKpi = (key, numVal, fmtFn, subNodes) => {
        const card = grid.querySelector(`[data-kpi="${key}"]`);
        if (!card) return;
        tweenNumber(card.querySelector('[data-ref="val"]'), numVal, fmtFn);
        setSubParts(card.querySelector('[data-ref="sub"]'), subNodes);
      };

      patchKpi('api-list', nn(k, 'apiListCostUsd'), money, [
        h('b', { class: 'tnum' }, fmtNum(reqs)),
        ` ${t('kpi.reqsWord')} · `,
        h('b', { class: 'tnum' }, fmtTok(totalTok)),
        ` ${t('kpi.tokensWord')}`,
      ]);
      patchKpi('effective-paid', nn(k, 'effectivePaidUsd') ?? nn(k, 'billedCostUsd'), money, [
        `${t('kpi.subFees')} `,
        h('b', { class: 'tnum' }, money(nn(k, 'subscriptionFeesUsd'))),
        ` ${t('kpi.apiBilled')} `,
        h('b', { class: 'tnum' }, money(nn(k, 'billedCostUsd'))),
      ]);
      patchKpi('multiplier', mult, (x) => (x ? fmtNum(x, 1) + 'x' : '—'), [t('kpi.multFormula')]);
      patchKpi('cache-savings', saveTotal, money, [
        `${t('kpi.cacheWord')} `,
        h('b', { class: 'tnum' }, money(cacheSave)),
        ` · ${t('kpi.rtkWord')} `,
        h('b', { class: 'tnum' }, money(rtkSave)),
        ` · ${t('kpi.hitWord')} `,
        h('b', { class: 'tnum' }, fmtPct(hit)),
      ]);
      patchKpi('avg-req', avg, money, [
        'Avg $/Req · P50 ',
        h('b', { class: 'tnum' }, money(p50)),
        ' · P95 ',
        h('b', { class: 'tnum' }, money(p95)),
        ` · ${t('kpi.maxWord')} `,
        h('b', { class: 'tnum' }, money(mx)),
      ]);
      patchKpi('speed', nn(k, 'avgTtftMs'), fmtMs, [
        h('b', { class: 'tnum' }, fmtNum(nn(k, 'avgTokPerSec'), 1)),
        ` ${t('kpi.avgSpeedSub')}`,
      ]);

      const distCard = grid.querySelector('[data-kpi="tok-dist"]');
      if (distCard) {
        for (const [cls, , count] of tokParts) {
          const seg = distCard.querySelector(`[data-seg="${cls}"]`);
          if (seg) seg.style.width = ((count / tokSum) * 100).toFixed(2) + '%';
          const leg = distCard.querySelector(`[data-leg="${cls}"]`);
          if (leg) tweenNumber(leg, count, fmtTok);
        }
      }
    }

    renderChart();
    renderBreakdown();
    renderHeat();
    renderTree();
  }

  /* ------------------------------ Daily SVG Chart ------------------------------ */
  const SERIES_TOKENS = [
    ['bg-input', 'f-input', 'tok.input', 'inputTokens'],
    ['bg-cr', 'f-cr', 'tok.cacheRead', 'cacheReadTokens'],
    ['bg-cw', 'f-cw', 'tok.cacheWrite', 'cacheWriteTokens'],
    ['bg-out', 'f-out', 'tok.output', 'outputTokens'],
    ['bg-rs', 'f-rs', 'tok.reasoning', 'reasoningTokens'],
  ];
  function dayKey(r) {
    return String(v(r, 'day', 'date', 'bucket', 'period', 'd') ?? '').slice(0, 10);
  }

  function renderChart() {
    const host = $('#chart-daily');
    const legHost = $('#chart-legend');
    if (!host || !legHost) return;
    $$('#seg-metric button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.metric === state.metric)));

    const ts = arr(v(S.ov, 'timeseries'))
      .slice()
      .sort((a, b) => dayKey(a).localeCompare(dayKey(b)))
      .slice(-30);

    clearEl(host);
    clearEl(legHost);
    if (!ts.length) {
      host.appendChild(h('p', { class: 'empty' }, t('chart.empty')));
      return;
    }

    const tokens = state.metric === 'tokens';
    const series = tokens
      ? SERIES_TOKENS.map(([bg, f, labelKey, key]) => ({ bg, f, label: t(labelKey), get: (r) => n0(r, key) }))
      : [
          { bg: 'bg-input', f: 'f-input', label: t('kpi.apiList'), get: (r) => n0(r, 'apiListCostUsd') },
          { bg: 'bg-cw', f: 'f-cw', label: t('kpi.effectivePaid'), get: (r) => n0(r, 'billedCostUsd') },
        ];
    const stacked = tokens;
    const W = 640;
    const H = 230;
    const ml = 50;
    const mr = 8;
    const mt = 10;
    const mb = 26;
    const iw = W - ml - mr;
    const ih = H - mt - mb;
    const totals = ts.map((r) =>
      stacked ? series.reduce((s, x) => s + x.get(r), 0) : Math.max(...series.map((x) => x.get(r)))
    );
    const max = Math.max(...totals, 1e-9);
    const step = iw / ts.length;
    const bw = Math.min(34, step * 0.68);
    const fmtY = (x) => (tokens ? fmtTok(x) : money(x));

    const svg = svgEl('svg', {
      viewBox: `0 0 ${W} ${H}`,
      role: 'group',
      'aria-label': tokens ? t('chart.ariaTokens') : t('chart.ariaCost'),
    });

    for (let i = 0; i <= 4; i++) {
      const y = mt + ih - (ih * i) / 4;
      svg.appendChild(svgEl('line', { class: 'grid-line', x1: ml, x2: W - mr, y1: y, y2: y }));
      svg.appendChild(svgEl('text', { x: ml - 6, y: y + 3, 'text-anchor': 'end' }, fmtY((max * i) / 4)));
    }

    const every = Math.max(1, Math.ceil(ts.length / 8));
    ts.forEach((r, i) => {
      const x = ml + step * i + (step - bw) / 2;
      let y = mt + ih;
      const label = dayKey(r);
      const tip = stacked
        ? series.map((s) => `${s.label}: ${fmtTok(s.get(r))}`).join(' · ')
        : `${t('kpi.apiList')}: ${money(series[0].get(r))} · ${t('kpi.effectivePaid')}: ${money(series[1].get(r))}`;

      const colG = svgEl('g', { class: 'col', tabindex: '0', role: 'img', 'aria-label': `${label} — ${tip}` });
      colG.appendChild(svgEl('title', null, `${label} — ${tip}`));

      if (stacked) {
        series.forEach((s) => {
          const val = s.get(r);
          const barH = (val / max) * ih;
          if (barH > 0) {
            y -= barH;
            colG.appendChild(
              svgEl('rect', {
                class: `bar ${s.f}`,
                x: x.toFixed(1),
                y: y.toFixed(1),
                width: bw.toFixed(1),
                height: barH.toFixed(1),
              })
            );
          }
        });
      } else {
        const a = series[0].get(r);
        const b = series[1].get(r);
        const ha = (a / max) * ih;
        const hb = (b / max) * ih;
        colG.appendChild(
          svgEl('rect', {
            class: 'bar f-input',
            x: x.toFixed(1),
            y: (mt + ih - ha).toFixed(1),
            width: bw.toFixed(1),
            height: ha.toFixed(1),
          })
        );
        if (hb > 0) {
          colG.appendChild(
            svgEl('rect', {
              class: 'bar f-cw',
              x: (x + bw * 0.25).toFixed(1),
              y: (mt + ih - hb).toFixed(1),
              width: (bw * 0.5).toFixed(1),
              height: hb.toFixed(1),
            })
          );
        }
      }
      svg.appendChild(colG);
      if (i % every === 0) {
        svg.appendChild(
          svgEl(
            'text',
            { x: (x + bw / 2).toFixed(1), y: H - 8, 'text-anchor': 'middle' },
            `${label.slice(8, 10)}.${label.slice(5, 7)}`
          )
        );
      }
    });

    host.appendChild(svg);
    for (const s of series) {
      legHost.appendChild(h('li', null, h('span', { class: `swatch ${s.bg}` }), s.label));
    }
  }

  /* ------------------------------ Keyed Breakdown Ranks (GPU scaleX(var(--p))) ------------------------------ */
  function patchRankGroup(host, groupKey, title, rows, keyFn, nameFn, valFn, subFn) {
    let section = host.querySelector(`[data-rank-group="${groupKey}"]`);
    if (!section) {
      section = h('div', { class: 'rank', dataset: { rankGroup: groupKey } });
      host.appendChild(section);
    }
    clearEl(section);
    section.appendChild(h('div', { class: 'rank-title' }, title));
    if (!rows.length) {
      section.appendChild(h('p', { class: 'empty' }, t('breakdown.empty')));
      return;
    }
    const max = Math.max(...rows.map(valFn), 1e-9);
    for (const r of rows) {
      const nm = maskText(nameFn(r));
      const ratio = Math.min(1, Math.max(0.02, valFn(r) / max));
      section.appendChild(
        h(
          'div',
          { class: 'rank-row', dataset: { rankKey: keyFn(r) } },
          h('span', { class: 'rank-name', title: nm }, nm),
          h('span', { class: 'rank-val tnum' }, subFn(r)),
          h('div', { class: 'rank-bar' }, h('i', { style: { '--p': ratio.toFixed(4) } }))
        )
      );
    }
  }

  function renderBreakdown() {
    const host = $('#breakdown');
    if (!host) return;
    const byModel = arr(v(S.ov, 'byModel'))
      .slice()
      .sort((a, b) => n0(b, 'apiListCostUsd') - n0(a, 'apiListCostUsd'))
      .slice(0, 6);
    const bySource = arr(v(S.ov, 'bySource'))
      .slice()
      .sort((a, b) => n0(b, 'apiListCostUsd') - n0(a, 'apiListCostUsd'))
      .slice(0, 6);
    const tok = (r) =>
      nn(r, 'totalTokens') ??
      (n0(r, 'inputTokens') + n0(r, 'outputTokens') + n0(r, 'cacheReadTokens') + n0(r, 'cacheWriteTokens'));

    patchRankGroup(
      host,
      'model',
      t('breakdown.byModel'),
      byModel,
      (r) => String(v(r, 'model_id', 'key', 'id') || ''),
      (r) => v(r, 'display_name') || v(r, 'model_id', 'key', 'id') || '—',
      (r) => n0(r, 'apiListCostUsd'),
      (r) => `${money(nn(r, 'apiListCostUsd'))} · ${fmtTok(tok(r))}`
    );
    patchRankGroup(
      host,
      'source',
      t('breakdown.bySource'),
      bySource,
      (r) => String(v(r, 'source_tool', 'key', 'id') || ''),
      (r) => sourceLabel(v(r, 'source_tool', 'key', 'id')) || '—',
      (r) => n0(r, 'apiListCostUsd'),
      (r) => `${money(nn(r, 'apiListCostUsd'))} · ${fmtTok(tok(r))}`
    );
  }

  /* ------------------------------ GitHub / Claude Configurable Activity Heatmap ------------------------------ */
  const heatDayMap = new Map();

  function heatValForMetric(d, metric) {
    if (!d) return 0;
    if (metric === 'cost') return d.listCost;
    if (metric === 'requests') return d.reqs;
    if (metric === 'cache') return d.cachePct;
    return d.tokens;
  }

  function heatLevelForDay(d, metric, p95) {
    if (!d || (d.tokens <= 0 && d.reqs <= 0 && d.listCost <= 0)) return 0;
    if (metric === 'cache') {
      const c = d.cachePct;
      if (c <= 0) return 0;
      if (c < 25) return 1;
      if (c < 50) return 2;
      if (c < 75) return 3;
      return 4;
    }
    const val = heatValForMetric(d, metric);
    if (val <= 0 || p95 <= 0) return 0;
    const ratio = Math.min(1, val / p95);
    return Math.min(4, Math.max(1, Math.ceil(Math.sqrt(ratio) * 4)));
  }

  function renderHeat() {
    const host = $('#heatmap');
    const noteEl = $('#heat-note');
    if (!host) return;

    $$('#seg-heat-metric button').forEach((b) =>
      b.setAttribute('aria-pressed', String(b.dataset.hmetric === state.heatMetric))
    );
    $$('#seg-heat-win button').forEach((b) =>
      b.setAttribute('aria-pressed', String(Number(b.dataset.hwin) === state.heatWeeks))
    );

    const rawHeat = arr(v(S.ov, 'heatmap'));
    const rawTs = arr(v(S.ov, 'timeseries'));
    const src = rawHeat.length >= rawTs.length ? rawHeat : rawTs;

    heatDayMap.clear();
    for (const r of src) {
      const key = dayKey(r);
      if (!key) continue;
      const tokens =
        nn(r, 'totalTokens', 'tokens') ??
        (n0(r, 'inputTokens') + n0(r, 'outputTokens') + n0(r, 'cacheReadTokens') + n0(r, 'cacheWriteTokens'));
      const reqs = n0(r, 'requests', 'count');
      const listCost = n0(r, 'api_list_cost_usd', 'apiListCostUsd');
      const paidCost = n0(r, 'billed_cost_usd', 'billedCostUsd');
      const cr = n0(r, 'cache_read_tokens', 'cacheReadTokens');
      const uncached = nn(r, 'uncached_input_tokens', 'uncachedInputTokens') ?? n0(r, 'input_tokens', 'inputTokens');
      const hitExplicit = nn(r, 'cache_hit_pct', 'cacheHitPct');
      const cur = heatDayMap.get(key) || {
        tokens: 0,
        reqs: 0,
        listCost: 0,
        paidCost: 0,
        cr: 0,
        uncached: 0,
        explicitHit: null,
      };
      cur.tokens += tokens;
      cur.reqs += reqs;
      cur.listCost += listCost;
      cur.paidCost += paidCost;
      cur.cr += cr;
      cur.uncached += uncached;
      if (hitExplicit !== null) cur.explicitHit = hitExplicit;
      heatDayMap.set(key, cur);
    }

    for (const d of heatDayMap.values()) {
      const denom = d.cr + d.uncached;
      d.cachePct = d.explicitHit !== null ? d.explicitHit : denom > 0 ? (d.cr / denom) * 100 : 0;
    }

    const weeks = state.heatWeeks;
    const metric = state.heatMetric;
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const dow = (today.getDay() + 6) % 7; // Mon=0..Sun=6
    const start = new Date(today);
    start.setDate(start.getDate() - ((weeks - 1) * 7 + dow));

    // Compute P95 over non-zero days in window
    const windowVals = [];
    for (let i = 0; i < weeks * 7; i++) {
      const dt = new Date(start);
      dt.setDate(start.getDate() + i);
      if (dt > today) break;
      const key = `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, '0')}-${String(dt.getDate()).padStart(2, '0')}`;
      const info = heatDayMap.get(key);
      const val = heatValForMetric(info, metric);
      if (val > 0) windowVals.push(val);
    }
    windowVals.sort((a, b) => a - b);
    const p95 = windowVals.length
      ? windowVals[Math.min(windowVals.length - 1, Math.floor(windowVals.length * 0.95))]
      : 0;

    const metricLabel = {
      tokens: t('heat.mTokens'),
      cost: t('heat.mCost'),
      requests: t('heat.mRequests'),
      cache: t('heat.mCache'),
    }[metric];
    if (noteEl) noteEl.textContent = t('heat.note', { w: weeks, metric: metricLabel });

    const monthsList = (I18N.months && I18N.months[state.lang]) || I18N.months?.en || ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const weekdaysList = (I18N.weekdays && I18N.weekdays[state.lang]) || I18N.weekdays?.en || ['Mon', '', 'Wed', '', 'Fri', '', ''];

    const monthsRow = h('div', { class: 'heat-months', 'aria-hidden': 'true' });
    const grid = h('div', {
      class: 'heat-grid',
      role: 'group',
      'aria-label': t('heat.aria', { w: weeks, metric: metricLabel }),
    });

    let lastMonth = -1;
    let lastLabelCol = -4;
    for (let col = 0; col < weeks; col++) {
      const colStart = new Date(start);
      colStart.setDate(start.getDate() + col * 7);
      const m = colStart.getMonth();
      let monthTxt = '';
      if (m !== lastMonth && col - lastLabelCol >= 3) {
        monthTxt = monthsList[m];
        lastMonth = m;
        lastLabelCol = col;
      } else if (m !== lastMonth) {
        lastMonth = m;
      }
      monthsRow.appendChild(h('span', { class: 'heat-month-lbl' }, monthTxt));

      for (let row = 0; row < 7; row++) {
        const dt = new Date(start);
        dt.setDate(start.getDate() + col * 7 + row);
        if (dt > today) {
          grid.appendChild(h('span', { class: 'heat-cell-pad', 'aria-hidden': 'true' }));
          continue;
        }
        const key = `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, '0')}-${String(dt.getDate()).padStart(2, '0')}`;
        const info = heatDayMap.get(key);
        const lvl = heatLevelForDay(info, metric, p95);
        const isSel = state.from === key && state.to === key;
        const summary = info
          ? t('heat.summary', { date: key, tok: fmtTok(info.tokens), cost: money(info.listCost), reqs: fmtNum(info.reqs), cache: fmtPct(info.cachePct) })
          : t('heat.noActivity', { date: key });
        grid.appendChild(
          h('button', {
            type: 'button',
            class: 'heat-cell' + (isSel ? ' is-selected' : ''),
            dataset: { date: key, l: String(lvl), action: 'heat-day' },
            style: { '--col': String(col) },
            'aria-label': summary,
          })
        );
      }
    }

    const daysCol = h(
      'div',
      { class: 'heat-days', 'aria-hidden': 'true' },
      weekdaysList.map((wd) => h('span', null, wd))
    );

    const board = h('div', { class: 'heat-board' }, monthsRow, h('div', { class: 'heat-body' }, daysCol, grid));
    const foot = h(
      'div',
      { class: 'heat-foot' },
      h('span', null, t('heat.footHint')),
      h(
        'div',
        { class: 'heat-legend' },
        h('span', null, metric === 'cache' ? fmtPct(0, 0) : t('heat.less')),
        h('span', { class: 'heat-legend-swatch', dataset: { l: '0' } }),
        h('span', { class: 'heat-legend-swatch', dataset: { l: '1' } }),
        h('span', { class: 'heat-legend-swatch', dataset: { l: '2' } }),
        h('span', { class: 'heat-legend-swatch', dataset: { l: '3' } }),
        h('span', { class: 'heat-legend-swatch', dataset: { l: '4' } }),
        h('span', null, metric === 'cache' ? (state.lang === 'tr' ? '%75+' : '75%+') : t('heat.more'))
      )
    );

    clearEl(host);
    host.appendChild(board);
    host.appendChild(foot);
  }

  function showHeatTooltip(cell) {
    const pop = $('#heat-pop');
    if (!pop || !cell) return;
    const key = cell.dataset.date;
    if (!key) return;
    const info = heatDayMap.get(key) || { tokens: 0, reqs: 0, listCost: 0, paidCost: 0, cachePct: 0 };
    clearEl(pop);
    pop.appendChild(h('div', { class: 'heat-pop-date tnum' }, key));
    pop.appendChild(
      h('div', { class: 'heat-pop-row tnum' }, h('span', null, t('heat.popTokens')), h('b', null, fmtTok(info.tokens)))
    );
    pop.appendChild(
      h(
        'div',
        { class: 'heat-pop-row tnum' },
        h('span', null, t('heat.popCost')),
        h('b', null, `${money(info.listCost)} / ${money(info.paidCost)}`)
      )
    );
    pop.appendChild(
      h('div', { class: 'heat-pop-row tnum' }, h('span', null, t('heat.popReqs')), h('b', null, fmtNum(info.reqs)))
    );
    pop.appendChild(
      h('div', { class: 'heat-pop-row tnum' }, h('span', null, t('heat.popCache')), h('b', null, fmtPct(info.cachePct)))
    );
    pop.appendChild(h('div', { class: 'heat-pop-hint' }, t('heat.popHint')));
    pop.hidden = false;

    const r = cell.getBoundingClientRect();
    const popW = 236;
    const popH = 128;
    const tx = Math.min(window.innerWidth - popW - 10, Math.max(10, r.left + r.width / 2 - popW / 2));
    const ty = r.top > popH + 16 ? r.top - popH - 8 : r.bottom + 8;
    pop.style.setProperty('--tx', `${Math.round(tx)}px`);
    pop.style.setProperty('--ty', `${Math.round(ty)}px`);
  }

  function hideHeatTooltip() {
    const pop = $('#heat-pop');
    if (pop) pop.hidden = true;
  }

  /* ------------------------------ Swarm & Subagent Cost Tree ------------------------------ */
  function buildTree(nodes) {
    const hasChildren = nodes.some((x) => Array.isArray(x.children));
    if (hasChildren) return nodes;
    const byId = new Map(nodes.map((x) => [String(v(x, 'session_id', 'id')), { ...x, children: [] }]));
    const roots = [];
    for (const nd of byId.values()) {
      const p = v(nd, 'parent_session_id');
      if (p && byId.has(String(p))) byId.get(String(p)).children.push(nd);
      else roots.push(nd);
    }
    return roots;
  }
  const nodeCost = (nd) =>
    nn(nd, 'tree_api_list_cost_usd', 'rollup_cost_usd', 'total_cost_usd', 'total_api_list_cost_usd', 'api_list_cost_usd', 'cost_usd') ?? 0;

  function renderNodeEl(nd, depth) {
    const rawTitle = v(nd, 'title') || v(nd, 'agent_name') || String(v(nd, 'session_id', 'id') || '—').slice(0, 12);
    const title = maskText(rawTitle);
    const tok = nn(nd, 'tree_tokens', 'rollup_tokens', 'total_tokens', 'tokens');
    const reqs = nn(nd, 'tree_requests', 'requests', 'request_count', 'rollup_requests', 'total_requests');
    const agent = v(nd, 'agent_name');
    const kids = arr(nd.children);
    const subParts = [
      agent && agent !== rawTitle ? maskText(agent) : '',
      reqs !== null ? `${fmtNum(reqs)} ${t('kpi.reqsWord')}` : '',
      tok !== null ? `${fmtTok(tok)} ${t('kpi.tokensWord')}` : '',
      kids.length ? t('tree.subagents', { n: kids.length }) : '',
    ].filter(Boolean);

    const li = h(
      'li',
      null,
      h(
        'div',
        { class: 'tree-node' },
        h('span', { class: 'tree-title', title }, title),
        h('span', { class: 'tree-cost tnum' }, money(nodeCost(nd))),
        h('span', { class: 'tree-sub tnum' }, subParts.join(' · '))
      )
    );
    if (kids.length && depth < 3) {
      li.appendChild(h('ul', null, kids.slice(0, 20).map((c) => renderNodeEl(c, depth + 1))));
    }
    return li;
  }

  function renderTree() {
    const host = $('#swarm-tree');
    const note = $('#tree-note');
    if (!host) return;
    const trees = buildTree(arr(v(S.ov, 'swarmTrees')));
    if (note) note.textContent = trees.length ? t('tree.roots', { n: trees.length }) : '';
    clearEl(host);
    if (!trees.length) {
      host.appendChild(h('p', { class: 'empty' }, t('tree.empty')));
      return;
    }
    const sorted = trees
      .filter((tNode) => arr(tNode.children).length)
      .concat(trees.filter((tNode) => !arr(tNode.children).length))
      .slice(0, 12);
    host.appendChild(h('ul', null, sorted.map((tNode) => renderNodeEl(tNode, 0))));
  }

  /* ------------------------------ Accounts & Inline 1-Click Billing Switcher ------------------------------ */
  function quotaFor(id, acc) {
    const own = arr(acc && acc.quotas);
    return (
      (own.length ? own : arr(v(S.ov, 'quotas')))
        .filter((q) => String(v(q, 'account_id')) === id)
        .sort((a, b) => String(v(b, 'captured_at') || '').localeCompare(String(v(a, 'captured_at') || '')))[0] || null
    );
  }
  function accountRows() {
    const stats = new Map(arr(v(S.ov, 'byAccount')).map((r) => [accId(r), r]));
    const base = S.accounts.length ? S.accounts : arr(v(S.ov, 'byAccount'));
    return base.map((a) => ({ ...(stats.get(accId(a)) || {}), ...a }));
  }

  function renderAccounts() {
    const host = $('#acc-table');
    const note = $('#acc-note');
    if (!host) return;
    const rows = accountRows();
    if (note) note.textContent = rows.length ? t('acc.count', { n: rows.length }) : '';

    const sel = $('#rt-account');
    if (sel) {
      const prev = sel.value;
      populateSelectOptions(
        sel,
        rows.map((a) => [
          accId(a),
          `${accLabel(a)} · ${sourceLabel(v(a, 'source_tool'))}`,
        ]),
        null
      );
      if (prev) sel.value = prev;
    }

    clearEl(host);
    if (!rows.length) {
      host.appendChild(h('p', { class: 'empty pad' }, t('acc.empty')));
      return;
    }

    const head = [
      t('acc.colAccount'),
      t('acc.colPlan'),
      t('acc.colTokens'),
      t('acc.colCache'),
      t('acc.colList'),
      t('acc.colFee'),
      t('acc.colMult'),
      t('acc.colAvg'),
      t('acc.colQuota'),
      t('acc.colBudget'),
      '',
    ];
    const thead = h(
      'thead',
      null,
      h(
        'tr',
        null,
        head.map((lbl, i) =>
          h(
            'th',
            { scope: 'col', class: i > 1 && i < 10 ? 'num' : undefined },
            lbl || h('span', { class: 'sr-only' }, t('acc.colAction'))
          )
        )
      )
    );

    const tbody = h('tbody');
    rows.forEach((a) => {
      const id = accId(a);
      const tok =
        nn(a, 'total_tokens') ??
        (n0(a, 'input_tokens') + n0(a, 'output_tokens') + n0(a, 'cache_read_tokens') + n0(a, 'cache_write_tokens'));
      let hit = nn(a, 'cache_hit_pct');
      if (hit === null) {
        const cr = n0(a, 'cache_read_tokens');
        const inp = n0(a, 'input_tokens');
        hit = cr + inp ? (cr / (cr + inp)) * 100 : null;
      }
      const list = nn(a, 'api_list_cost_usd');
      const fee = nn(a, 'monthly_fee_usd', 'subscription_fee_usd');
      const mult = nn(a, 'list_value_multiplier');
      const multTxt = mult ? fmtNum(mult, mult < 10 ? 2 : 1) + 'x' : '—';
      const reqs = n0(a, 'requests');
      const avg = nn(a, 'avg_cost_per_request_usd', 'avg_cost_per_req') ?? (reqs && list !== null ? list / reqs : null);
      const q = quotaFor(id, a);
      const reset = q ? Date.parse(v(q, 'window_reset', 'reset_at') || '') : NaN;
      const quotaNodes = [];
      if (q) {
        if (v(q, 'is_exhausted')) {
          quotaNodes.push(h('span', { class: 'badge badge-danger' }, h('span', null, t('acc.exhausted'))), ' ');
        }
        if (nn(q, 'remaining_pct') !== null) {
          quotaNodes.push(`${fmtPct(nn(q, 'remaining_pct'), 0)} ${t('acc.left')} · `);
        }
        quotaNodes.push(
          h(
            'span',
            { class: 'tnum', dataset: { until: Number.isFinite(reset) ? String(reset) : '' } },
            Number.isFinite(reset) ? countdown(reset - Date.now()) : '—'
          )
        );
      } else {
        quotaNodes.push('—');
      }

      const dB = nn(a, 'daily_budget_usd');
      const mB = nn(a, 'monthly_budget_usd');
      const plan = v(a, 'plan_type') || 'api';

      const inlinePlanSeg = h(
        'div',
        { class: 'seg seg-sm', role: 'group', 'aria-label': t('acc.planAria', { name: accLabel(a) }) },
        [
          ['api', t('acc.planApi')],
          ['subscription', t('acc.planSub')],
          ['free', t('acc.planFree')],
        ].map(([pKey, pLbl]) =>
          h(
            'button',
            {
              type: 'button',
              'aria-pressed': String(plan === pKey),
              dataset: { action: 'set-plan', id, plan: pKey, fee: String(fee ?? 0) },
            },
            pLbl
          )
        )
      );

      const tr = h(
        'tr',
        null,
        h(
          'td',
          { class: 'cell-first', dataset: { label: t('acc.colAccount') } },
          h(
            'div',
            { class: 'cell-main' },
            h('b', null, accLabel(a)),
            h('small', null, sourceLabel(v(a, 'source_tool')))
          )
        ),
        h('td', { dataset: { label: t('acc.lblPlan') } }, inlinePlanSeg),
        h('td', { class: 'num tnum', dataset: { label: t('acc.colTokens') } }, fmtTok(tok)),
        h('td', { class: 'num tnum', dataset: { label: t('acc.colCache') } }, fmtPct(hit)),
        h('td', { class: 'num tnum', dataset: { label: t('acc.colList') } }, money(list)),
        h('td', { class: 'num tnum', dataset: { label: t('acc.colFee') } }, fee ? money(fee) + t('acc.perMonth') : '—'),
        h('td', { class: 'num tnum', dataset: { label: t('acc.colMult') } }, multTxt),
        h('td', { class: 'num tnum', dataset: { label: t('acc.colAvg') } }, money(avg)),
        h('td', { class: 'num tnum', dataset: { label: t('acc.colQuota') } }, quotaNodes),
        h(
          'td',
          { class: 'num tnum', dataset: { label: t('acc.colBudget') } },
          dB || mB
            ? `${dB ? t('acc.dayPrefix') + money(dB) : ''}${dB && mB ? ' · ' : ''}${mB ? t('acc.monthPrefix') + money(mB) : ''}`
            : '—'
        ),
        h(
          'td',
          { dataset: { label: t('acc.colAction') } },
          h(
            'button',
            {
              type: 'button',
              class: 'btn btn-sm',
              dataset: { action: 'edit-acc', id },
              'aria-expanded': String(state.editAcc === id),
            },
            iconEl('save'),
            h('span', null, t('btn.edit'))
          )
        )
      );
      tbody.appendChild(tr);

      if (state.editAcc === id) {
        const editRow = h(
          'tr',
          { class: 'row-edit' },
          h(
            'td',
            { colspan: String(head.length) },
            h(
              'form',
              { class: 'form-grid', dataset: { form: 'acc', id }, autocomplete: 'off' },
              h(
                'label',
                { class: 'field' },
                h('span', null, t('acc.lblLabel')),
                h('input', {
                  name: 'email_or_label',
                  type: 'text',
                  value: String(v(a, 'email_or_label', 'account_email') || ''),
                })
              ),
              h(
                'label',
                { class: 'field' },
                h('span', null, t('acc.lblPlan')),
                h(
                  'select',
                  { name: 'plan_type' },
                  h('option', { value: 'api', selected: plan === 'api' }, t('acc.planApiFull')),
                  h('option', { value: 'subscription', selected: plan === 'subscription' }, t('acc.planSubFull')),
                  h('option', { value: 'free', selected: plan === 'free' }, t('acc.planFree'))
                )
              ),
              h(
                'label',
                { class: 'field' },
                h('span', null, t('acc.lblFee')),
                h('input', {
                  name: 'monthly_fee_usd',
                  type: 'number',
                  step: '0.01',
                  min: '0',
                  inputmode: 'decimal',
                  class: 'tnum',
                  value: String(fee ?? 0),
                })
              ),
              h(
                'label',
                { class: 'field' },
                h('span', null, t('acc.lblDailyBudget')),
                h('input', {
                  name: 'daily_budget_usd',
                  type: 'number',
                  step: '0.01',
                  min: '0',
                  inputmode: 'decimal',
                  class: 'tnum',
                  value: String(dB ?? 0),
                })
              ),
              h(
                'label',
                { class: 'field' },
                h('span', null, t('acc.lblMonthlyBudget')),
                h('input', {
                  name: 'monthly_budget_usd',
                  type: 'number',
                  step: '0.01',
                  min: '0',
                  inputmode: 'decimal',
                  class: 'tnum',
                  value: String(mB ?? 0),
                })
              ),
              h(
                'div',
                { class: 'form-actions' },
                h('button', { type: 'submit', class: 'btn btn-primary' }, iconEl('save'), h('span', null, t('btn.save'))),
                h(
                  'button',
                  { type: 'button', class: 'btn btn-ghost', dataset: { action: 'cancel-acc' } },
                  iconEl('x'),
                  h('span', null, t('btn.cancel'))
                )
              )
            )
          )
        );
        tbody.appendChild(editRow);
      }
    });

    host.appendChild(h('table', { class: 'tbl stack' }, thead, tbody));
  }

  /* ------------------------------ Requests ------------------------------ */
  async function loadRequests() {
    const [sort, dir] = state.rq.sort.split(':');
    const d = await api(
      '/api/requests?' +
        filterParams({
          limit: state.rq.limit,
          offset: state.rq.offset,
          sort,
          dir,
          q: state.rq.q,
          modelId: state.rq.modelId,
          sessionId: state.rq.sessionId,
        }).toString()
    );
    S.requests = arr(v(d, 'rows', 'requests'));
    state.rq.total = n0(d, 'total');
    renderRequests();
  }

  function renderRequests() {
    const host = $('#req-table');
    if (!host) return;
    const p95 = nn(v(S.ov, 'kpis') || {}, 'p95CostPerReq') ?? nn(v(S.ov, 'perRequestStats') || {}, 'p95');

    const ms = $('#rq-model');
    const models = arr(v(S.ov, 'byModel'))
      .map((r) => String(v(r, 'model_id', 'key', 'id') ?? ''))
      .filter(Boolean);
    populateSelectOptions(
      ms,
      models.map((m) => [m, m]),
      t('req.allModels')
    );
    if (ms) ms.value = state.rq.modelId;

    const rqSort = $('#rq-sort');
    if (rqSort) rqSort.value = state.rq.sort;
    const rqExp = $('#rq-expensive');
    if (rqExp) rqExp.setAttribute('aria-pressed', String(state.rq.expensive));

    const tot = state.rq.total;
    const from = tot ? state.rq.offset + 1 : 0;
    const to = Math.min(tot, state.rq.offset + state.rq.limit);
    const reqCount = $('#req-count');
    if (reqCount) reqCount.textContent = t('req.count', { from: fmtNum(from), to: fmtNum(to), total: fmtNum(tot) });
    const rqPage = $('#rq-page');
    if (rqPage) {
      rqPage.textContent = t('req.page', {
        cur: fmtNum(Math.floor(state.rq.offset / state.rq.limit) + 1),
        pages: fmtNum(Math.max(1, Math.ceil(tot / state.rq.limit))),
      });
    }
    const rqPrev = $('#rq-prev');
    if (rqPrev) rqPrev.disabled = state.rq.offset <= 0;
    const rqNext = $('#rq-next');
    if (rqNext) rqNext.disabled = state.rq.offset + state.rq.limit >= tot;

    clearEl(host);
    if (!S.requests.length) {
      host.appendChild(h('p', { class: 'empty pad' }, t('req.empty')));
      return;
    }

    const head = [
      t('req.colTime'),
      t('req.colModel'),
      t('req.colTokens'),
      t('req.colCtx'),
      t('req.colTtft'),
      t('req.colTpot'),
      t('req.colTps'),
      t('req.colCost'),
    ];
    const thead = h(
      'thead',
      null,
      h('tr', null, head.map((lbl, i) => h('th', { scope: 'col', class: i > 1 ? 'num' : undefined }, lbl)))
    );

    const tbody = h('tbody');
    S.requests.forEach((r) => {
      const out = n0(r, 'output_tokens');
      const cr = n0(r, 'cache_read_tokens');
      const cw = n0(r, 'cache_write_tokens');
      const rs = n0(r, 'reasoning_tokens');
      const inp = nn(r, 'uncached_input_tokens') ?? Math.max(0, n0(r, 'input_tokens') - cr - cw);
      const sum = inp + out + cr + cw + rs || 1;
      const ctxTok = nn(r, 'context_tokens');
      const win = nn(r, 'context_window');
      const ctxPct = nn(r, 'context_pct') ?? (ctxTok !== null && win ? (ctxTok / win) * 100 : null);
      const ttft = nn(r, 'ttft_ms');
      const lat = nn(r, 'latency_ms');
      const gen = lat !== null && ttft !== null ? Math.max(0, lat - ttft) : null;
      const genTok = out + rs;
      const tpot = nn(r, 'tpot_ms') ?? (gen !== null && genTok > 0 ? gen / genTok : null);
      const tps = nn(r, 'tokens_per_sec', 'tok_per_sec') ?? (gen && genTok > 0 ? genTok / (gen / 1000) : null);
      const cost = nn(r, 'api_list_cost_usd', 'cost_usd');
      const hot = p95 && cost !== null ? (cost >= p95 * 2 ? 'cost-hotter' : cost >= p95 ? 'cost-hot' : '') : '';
      const model = v(r, 'model_id') || v(r, 'raw_model') || '—';
      const acct = v(r, 'account_email', 'account_id');
      const srcName = sourceLabel(v(r, 'source_tool'));
      const acctDisp = acct ? ' · ' + (state.privacy ? maskIdentifier(String(acct)) : String(acct)) : '';
      const ctxSub = maskText(String(v(r, 'title') || v(r, 'workspace') || v(r, 'session_id') || '')).slice(0, 44);

      tbody.appendChild(
        h(
          'tr',
          null,
          h(
            'td',
            { class: 'cell-first', dataset: { label: t('req.colTime') } },
            h('div', { class: 'cell-main' }, h('b', { class: 'tnum' }, fmtDT(v(r, 'created_at'))), h('small', null, srcName + acctDisp))
          ),
          h(
            'td',
            { dataset: { label: t('req.colModel') } },
            h('div', { class: 'cell-main' }, h('b', null, maskText(model)), h('small', null, ctxSub))
          ),
          h(
            'td',
            { class: 'num tnum', dataset: { label: t('req.colTokens') } },
            h(
              'div',
              { class: 'cell-main' },
              h('b', { class: 'tnum' }, fmtTok(inp + out + cr + cw + rs)),
              h(
                'small',
                { class: 'tnum' },
                `${t('tok.shortInput')} ${fmtTok(inp)} · ${t('tok.shortCache')} ${fmtTok(cr)} · ${t('tok.shortOutput')} ${fmtTok(out)}${rs ? ` · ${t('tok.shortReasoning')} ${fmtTok(rs)}` : ''}`
              ),
              h(
                'span',
                { class: 'tokbar', role: 'img', 'aria-label': t('kpi.tokDistAria') },
                h('i', { class: 'bg-input', style: { width: ((inp / sum) * 100).toFixed(1) + '%' } }),
                h('i', { class: 'bg-cr', style: { width: ((cr / sum) * 100).toFixed(1) + '%' } }),
                h('i', { class: 'bg-cw', style: { width: ((cw / sum) * 100).toFixed(1) + '%' } }),
                h('i', { class: 'bg-out', style: { width: ((out / sum) * 100).toFixed(1) + '%' } }),
                h('i', { class: 'bg-rs', style: { width: ((rs / sum) * 100).toFixed(1) + '%' } })
              )
            )
          ),
          h(
            'td',
            { class: 'num tnum', dataset: { label: t('req.colCtx') } },
            h('span', { class: ctxPct >= 80 ? 'cost-hotter' : ctxPct >= 65 ? 'cost-hot' : '' }, fmtPct(ctxPct))
          ),
          h('td', { class: 'num tnum', dataset: { label: t('req.colTtft') } }, ttft !== null ? fmtNum(ttft, ttft < 100 ? 1 : 0) : '—'),
          h('td', { class: 'num tnum', dataset: { label: t('req.colTpot') } }, tpot !== null ? fmtNum(tpot, 1) : '—'),
          h('td', { class: 'num tnum', dataset: { label: t('req.colTps') } }, tps !== null ? fmtNum(tps, 1) : '—'),
          h('td', { class: 'num tnum', dataset: { label: t('req.colCost') } }, h('span', { class: hot }, money(cost)))
        )
      );
    });

    host.appendChild(h('table', { class: 'tbl stack' }, thead, tbody));
  }

  /* ------------------------------ SSE Forensics & Live Speed Benchmark ------------------------------ */
  function verdictMeta(key) {
    const map = {
      VERIFIED_NATIVE: ['for.vVerified', 'badge-ok', 'shield-check'],
      LIKELY_NATIVE: ['for.vLikely', 'badge-ok', 'circle-check'],
      TRANSLATED_PROXY: ['for.vTranslated', 'badge-warn', 'route'],
      SUSPECTED_SPOOF: ['for.vSpoof', 'badge-danger', 'triangle-alert'],
      UNVERIFIED: ['for.vUnverified', '', 'circle-x'],
    };
    const hit = map[key];
    return hit ? [t(hit[0]), hit[1], hit[2]] : [key, '', 'circle-x'];
  }
  const MODEL_CLAIM_RE =
    /\b(gpt[-\s]?[\w.]+|claude[-\s]?[\w.]+|gemini[-\s]?[\w.]+|kimi[-\s]?[\w.]+|glm[-\s]?[\w.]+|qwen[\w.-]*|deepseek[-\s]?[\w.]+|grok[-\s]?[\w.]+|llama[-\s]?[\w.]+)\b/gi;
  const normName = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9.]+/g, '-').replace(/^-|-$/g, '');

  function kvEl(label, val) {
    const txt = val === null || val === undefined || val === '' ? '—' : maskText(val);
    return h('div', null, h('dt', null, label), h('dd', { class: 'tnum' }, txt));
  }

  function buildAnalysisDom(res, headers) {
    const A = v(res, 'analysis') || res || {};
    const P = A.parsed && typeof A.parsed === 'object' ? { ...A, ...A.parsed } : A;
    const score = nn(A, 'authenticityScore', 'authenticity_score', 'score');
    const verdictKey = String(v(A, 'verdict') || 'UNVERIFIED');
    const vd = verdictMeta(verdictKey);
    const level = score === null ? 'warn' : score >= 75 ? 'ok' : score >= 45 ? 'warn' : 'crit';
    const C = 2 * Math.PI * 42;
    const dash = score === null ? 0 : (C * Math.max(0, Math.min(100, score))) / 100;
    const model = v(P, 'model');
    const text = String(v(P, 'output_text', 'outputText') || '');

    const sr = v(A, 'selfReportVsWire', 'self_report_vs_wire') || {};
    let claimed = v(sr, 'selfReportedModels', 'claimed', 'claims', 'claimedModels', 'selfReport', 'self_report', 'textClaims');
    if (typeof claimed === 'string') claimed = [claimed];
    if (!Array.isArray(claimed)) claimed = [];
    claimed = claimed.map((c) => (typeof c === 'object' ? v(c, 'model', 'name', 'text') : c)).filter(Boolean);
    if (!claimed.length && text) {
      claimed = [...new Set((text.match(MODEL_CLAIM_RE) || []).map((x) => x.trim()))].slice(0, 5);
    }
    const wireModel = v(sr, 'wireModel', 'wire_model', 'wire') ?? model;
    const wireModelStr = typeof wireModel === 'object' ? v(wireModel, 'model', 'name') : wireModel;
    const srMismatch = v(sr, 'mismatch', 'mismatched', 'conflict', 'detected');
    const mismatch =
      typeof srMismatch === 'boolean'
        ? srMismatch
        : claimed.length > 0 &&
          Boolean(wireModelStr) &&
          !claimed.some((c) => normName(wireModelStr).includes(normName(c)) || normName(c).includes(normName(wireModelStr)));

    const wireFacts = [];
    if (v(P, 'id')) {
      const idStr = `${v(P, 'id')}${
        v(P, 'idFormat')
          ? ' (' + (typeof v(P, 'idFormat') === 'object' ? JSON.stringify(v(P, 'idFormat')) : v(P, 'idFormat')) + ')'
          : ''
      }`;
      wireFacts.push(t('for.factRespId', { id: idStr }));
    }
    if (v(P, 'attribution')) wireFacts.push(t('for.factAttr'));
    if (v(P, 'prompt_cache_retention')) wireFacts.push(`prompt_cache_retention: ${v(P, 'prompt_cache_retention')}`);
    if (v(P, 'system_fingerprint')) wireFacts.push(`system_fingerprint: ${v(P, 'system_fingerprint')}`);
    if (v(P, 'service_tier')) wireFacts.push(`service_tier: ${v(P, 'service_tier')}`);
    if (Array.isArray(v(P, 'thinking')) && v(P, 'thinking').length) wireFacts.push(t('for.factThinking'));
    const wireCodes = arr(v(sr, 'wireProof', 'wire_proof'));
    if (wireCodes.length) wireFacts.push(t('for.factWireCodes', { codes: wireCodes.join(', ') }));
    const note = v(sr, 'note', 'message', 'summary', 'explanation');

    const ringSvg = svgEl(
      'svg',
      { viewBox: '0 0 100 100', 'aria-hidden': 'true' },
      svgEl('circle', { class: 'track', cx: '50', cy: '50', r: '42' }),
      svgEl('circle', {
        class: 'val',
        cx: '50',
        cy: '50',
        r: '42',
        'stroke-dasharray': `${dash.toFixed(2)} ${C.toFixed(2)}`,
      })
    );

    const scoreSec = h(
      'div',
      { class: 'sse-sec' },
      h(
        'div',
        { class: 'score-row' },
        h(
          'div',
          {
            class: 'score-ring',
            dataset: { level },
            role: 'img',
            'aria-label': t('for.scoreAria', { score: score ?? '—' }),
          },
          ringSvg,
          h('b', { class: 'tnum' }, score === null ? '—' : fmtNum(score))
        ),
        h(
          'div',
          { class: 'score-meta' },
          h('span', { class: 'lbl' }, t('for.scoreLabel')),
          h('span', { class: `badge ${vd[1]}` }, iconEl(vd[2]), h('span', null, vd[0])),
          h(
            'span',
            { class: 'mono-sm muted tnum' },
            t('for.frames', {
              verdict: verdictKey,
              mode: v(P, 'mode') || v(P, 'detectedMode') || '—',
              n: fmtNum(n0(P, 'frameCount')),
            })
          )
        )
      )
    );

    const evObj = v(A, 'evidence');
    const evidence = Array.isArray(evObj)
      ? evObj
      : [
          ...arr(evObj && evObj.positive).map((e) => ({ ...e, pass: true })),
          ...arr(evObj && evObj.negative).map((e) => ({ ...e, pass: false })),
        ];

    const proofSec = h(
      'div',
      { class: 'sse-sec' },
      h('h4', { class: 'sec-title' }, t('for.proofTitle')),
      h(
        'div',
        { class: 'proof' },
        h(
          'div',
          { class: 'proof-col' + (mismatch ? ' warn' : '') },
          h('h4', null, t('for.claimHead')),
          h('div', { class: 'big' }, claimed.length ? maskText(claimed.join(', ')) : '—'),
          h('ul', null, h('li', null, t('for.claimNote')))
        ),
        h(
          'div',
          { class: 'proof-col ok' },
          h('h4', null, t('for.wireHead')),
          h('div', { class: 'big' }, maskText(wireModelStr || '—')),
          h(
            'ul',
            null,
            wireFacts.length
              ? wireFacts.map((f) => h('li', null, maskText(f)))
              : h('li', null, t('for.wireNone'))
          )
        )
      ),
      h(
        'div',
        { class: 'notice' + (mismatch ? '' : ' ok') },
        mismatch
          ? [
              t('for.mismatchA'),
              h('b', null, maskText(claimed.join(', '))),
              t('for.mismatchB'),
              h('b', null, maskText(wireModelStr)),
              t('for.mismatchC'),
            ]
          : claimed.length
          ? t('for.matchOk')
          : t('for.noClaim'),
        note ? ' ' + maskText(note) : ''
      ),
      evidence.length
        ? h(
            'ul',
            { class: 'proof-col' },
            evidence.slice(0, 24).map((e) => {
              if (typeof e === 'string') return h('li', null, maskText(e));
              const lbl = v(e, 'label', 'name', 'code', 'id', 'check') || '';
              const detail = v(e, 'detail', 'message', 'note', 'reason') || '';
              const pts = nn(e, 'points', 'delta', 'weight');
              const ok = v(e, 'pass', 'ok', 'passed');
              return h(
                'li',
                null,
                ok === true ? '+ ' : ok === false ? '− ' : '',
                h('b', null, maskText(lbl)),
                pts !== null ? h('span', { class: 'mono-sm tnum' }, ` (${pts > 0 ? '+' : ''}${fmtNum(pts)}) `) : ' ',
                maskText(detail)
              );
            })
          )
        : null
    );

    const at = v(P, 'attribution');
    let wfNode = h('p', { class: 'empty' }, t('for.wfEmpty'));
    if (at) {
      const instr = n0(at, 'instructions_input_tokens');
      const items = Math.max(0, n0(at, 'items_input_tokens'));
      const rest = Math.max(0, n0(at, 'request_fields_input_tokens') - instr);
      const outp = n0(at, 'attributed_output_tokens');
      const parts = [
        ['bg-input', 'Instructions', instr],
        ['bg-cr', 'Input Items', items + rest],
        ['bg-out', 'Output', outp],
      ];
      const sum = parts.reduce((s, p) => s + p[2], 0) || 1;
      wfNode = h(
        'div',
        { class: 'fall' },
        h(
          'div',
          { class: 'fall-bar', role: 'img', 'aria-label': t('for.wfTitle') },
          parts.map((p) => h('i', { class: p[0], style: { width: ((p[2] / sum) * 100).toFixed(2) + '%' } }))
        ),
        h(
          'div',
          { class: 'fall-legend' },
          parts.map((p) =>
            h('div', null, h('span', { class: `swatch ${p[0]}` }), h('span', null, p[1]), h('span', { class: 'tnum' }, fmtNum(p[2])))
          )
        ),
        h(
          'div',
          { class: 'meta-grid' },
          kvEl(t('for.wfRepIn'), fmtNum(n0(at, 'reported_input_tokens'))),
          kvEl(t('for.wfAttrIn'), fmtNum(n0(at, 'attributed_input_tokens'))),
          kvEl(t('for.wfRepOut'), fmtNum(n0(at, 'reported_output_tokens'))),
          kvEl(t('for.wfAttrOut'), fmtNum(outp))
        ),
        h(
          'div',
          { class: 'head-actions' },
          v(at, 'input_reconciles')
            ? h('span', { class: 'badge badge-ok' }, iconEl('circle-check'), h('span', null, t('for.wfInOk')))
            : h('span', { class: 'badge badge-warn' }, iconEl('triangle-alert'), h('span', null, t('for.wfInBad'))),
          v(at, 'output_reconciles')
            ? h('span', { class: 'badge badge-ok' }, iconEl('circle-check'), h('span', null, t('for.wfOutOk')))
            : h('span', { class: 'badge badge-warn' }, iconEl('triangle-alert'), h('span', null, t('for.wfOutBad')))
        )
      );
    }

    const T = v(P, 'tokens') || {};
    const usage = v(P, 'usage') || {};
    const cacheSec = h(
      'div',
      { class: 'sse-sec' },
      h('h4', { class: 'sec-title' }, t('for.cacheTitle')),
      h(
        'dl',
        { class: 'meta-grid' },
        kvEl('prompt_cache_retention', v(P, 'prompt_cache_retention')),
        kvEl(t('for.cacheRead'), fmtNum(nn(T, 'cache_read_tokens'))),
        kvEl(t('for.cacheWrite'), fmtNum(nn(T, 'cache_write_tokens'))),
        kvEl(t('for.cache30m'), fmtNum(nn(T, 'cache_write_30m_tokens'))),
        kvEl(t('for.cache12h'), fmtNum(nn(T, 'cache_write_12h_tokens'))),
        kvEl(
          t('for.cache5m1h'),
          nn(T, 'cache_write_5m_tokens') || nn(T, 'cache_write_1h_tokens')
            ? `${fmtNum(nn(T, 'cache_write_5m_tokens'))} / ${fmtNum(nn(T, 'cache_write_1h_tokens'))}`
            : null
        ),
        kvEl(t('for.cacheIn'), fmtNum(nn(T, 'input_tokens') ?? nn(usage, 'input_tokens', 'prompt_tokens'))),
        kvEl(t('for.cacheOut'), fmtNum(nn(T, 'output_tokens') ?? nn(usage, 'output_tokens', 'completion_tokens'))),
        kvEl(t('for.cacheThink'), fmtNum(nn(T, 'reasoning_tokens')))
      )
    );

    const tm = v(P, 'timing') || {};
    const tim = [
      ['TTFT', nn(tm, 'ttftMs'), 'ms'],
      ['TTFR', nn(tm, 'ttfrMs'), 'ms'],
      ['TTFA', nn(tm, 'ttfaMs'), 'ms'],
      ['TPOT', nn(tm, 'tpotMs'), 'ms/tok'],
      ['tok/s', nn(tm, 'tokPerSec'), ''],
      [t('for.timTotal'), nn(tm, 'totalMs'), 'ms'],
      [t('for.timChunks'), nn(tm, 'chunkCount'), ''],
      [t('for.timJitter'), nn(tm, 'jitterMs'), 'ms'],
    ];
    const timSec = h(
      'div',
      { class: 'sse-sec' },
      h('h4', { class: 'sec-title' }, t('for.timTitle')),
      h(
        'dl',
        { class: 'meta-grid' },
        tim.map(([l, x, u]) => kvEl(l, x === null ? null : `${fmtNum(x, x < 100 ? 1 : 0)} ${u}`.trim()))
      ),
      tim.slice(0, 5).every((tmRow) => tmRow[1] === null)
        ? h('p', { class: 'muted' }, t('for.timHint'))
        : null
    );

    const flags = arr(v(A, 'flags')).slice(0, 8);
    const flagSec = flags.length
      ? h(
          'div',
          { class: 'sse-sec' },
          h('h4', { class: 'sec-title' }, t('for.flagsTitle')),
          h(
            'ul',
            { class: 'proof-col' },
            flags.map((f) =>
              h(
                'li',
                null,
                h(
                  'span',
                  {
                    class:
                      'badge ' + (/crit|error|high/i.test(String(v(f, 'severity', 'level'))) ? 'badge-danger' : 'badge-warn'),
                  },
                  h('span', null, maskText(v(f, 'code') || ''))
                ),
                ' ',
                maskText(v(f, 'detail', 'message') || '')
              )
            )
          )
        )
      : null;

    const hdrSec =
      headers && typeof headers === 'object' && Object.keys(headers).length
        ? h(
            'div',
            { class: 'sse-sec' },
            h('h4', { class: 'sec-title' }, t('for.headersTitle')),
            h(
              'dl',
              { class: 'meta-grid' },
              Object.entries(headers)
                .slice(0, 12)
                .map(([k2, v2]) => kvEl(k2, String(v2)))
            )
          )
        : null;

    const errs = arr(v(P, 'errors'));
    const errSec = errs.length
      ? h(
          'div',
          { class: 'notice bad' },
          errs.slice(0, 5).map((e) => h('div', null, maskText(typeof e === 'string' ? e : JSON.stringify(e))))
        )
      : null;

    return h(
      'div',
      null,
      scoreSec,
      proofSec,
      h('div', { class: 'sse-sec' }, h('h4', { class: 'sec-title' }, t('for.wfTitle')), wfNode),
      cacheSec,
      timSec,
      flagSec,
      hdrSec,
      errSec
    );
  }

  function renderHistory() {
    const host = $('#forensic-history');
    if (!host) return;
    clearEl(host);
    if (!S.history.length) {
      host.appendChild(h('p', { class: 'empty pad' }, t('for.historyEmpty')));
      return;
    }
    const head = [
      t('for.colTime'),
      t('for.colModel'),
      t('for.colMode'),
      t('for.colScore'),
      t('for.colVerdict'),
      t('for.colTtft'),
    ];
    const thead = h(
      'thead',
      null,
      h('tr', null, head.map((lbl, i) => h('th', { scope: 'col', class: i === 3 || i === 5 ? 'num' : undefined }, lbl)))
    );
    const tbody = h(
      'tbody',
      null,
      S.history.slice(0, 40).map((c) => {
        const ts = v(c, 'created_at', 'captured_at');
        const vk = String(v(c, 'verdict') || 'UNVERIFIED');
        const vd = verdictMeta(vk);
        const score = nn(c, 'authenticity_score', 'score');
        return h(
          'tr',
          null,
          h(
            'td',
            { class: 'cell-first', dataset: { label: t('for.colTime') } },
            h(
              'div',
              { class: 'cell-main' },
              h('b', { class: 'tnum' }, fmtDT(ts)),
              h('small', null, maskText(v(c, 'label', 'base_url', 'source_tool') || ''))
            )
          ),
          h('td', { dataset: { label: t('for.colModel') } }, maskText(v(c, 'wire_model', 'model_id', 'model', 'requested_model') || '—')),
          h('td', { dataset: { label: t('for.colMode') } }, maskText(v(c, 'endpoint_mode', 'mode') || '—')),
          h('td', { class: 'num tnum', dataset: { label: t('for.colScore') } }, score === null ? '—' : fmtNum(score)),
          h('td', { dataset: { label: t('for.colVerdict') } }, h('span', { class: `badge ${vd[1]}` }, h('span', null, vd[0]))),
          h('td', { class: 'num tnum', dataset: { label: t('for.colTtft') } }, fmtMs(nn(c, 'ttft_ms')))
        );
      })
    );
    host.appendChild(h('table', { class: 'tbl stack' }, thead, tbody));
  }

  async function analyzeSse(btn) {
    const raw = ($('#sse-raw')?.value || '').trim();
    if (!raw) {
      toast(t('toast.ssePaste'), 'err');
      return;
    }
    const resHost = $('#sse-result');
    await busy(btn, async () => {
      try {
        const res = await api('/api/forensics/inspect', {
          method: 'POST',
          body: { rawText: raw, raw, mode: state.mode, save: Boolean($('#sse-save')?.checked) },
        });
        if (resHost) {
          clearEl(resHost);
          resHost.appendChild(buildAnalysisDom(res));
        }
        if ($('#sse-save')?.checked) loadTab('forensics', true);
      } catch (err) {
        if (resHost) {
          clearEl(resHost);
          resHost.appendChild(h('div', { class: 'notice bad' }, t('toast.analyzeErr', { msg: err.message })));
        }
      }
    });
  }

  async function runProbe() {
    const btn = $('#pb-submit');
    const status = $('#pb-status');
    const resHost = $('#probe-result');
    if (status) status.textContent = t('for.probeRunning');
    await busy(btn, async () => {
      try {
        const res = await api('/api/forensics/probe', {
          method: 'POST',
          timeout: 90000,
          body: {
            baseUrl: ($('#pb-url')?.value || '').trim(),
            apiKey: $('#pb-key')?.value || '',
            endpointMode: $('#pb-mode')?.value || 'responses',
            model: ($('#pb-model')?.value || '').trim(),
            prompt: $('#pb-prompt')?.value || '',
            save: true,
          },
        });
        if ($('#pb-key')) $('#pb-key').value = '';
        if (status) status.textContent = t('for.probeDone');
        if (resHost) {
          clearEl(resHost);
          resHost.appendChild(h('div', { class: 'sse-sec' }, buildAnalysisDom(res, v(res, 'httpHeaders', 'headers'))));
        }
        loadTab('forensics', true);
      } catch (err) {
        if (status) status.textContent = '';
        if (resHost) {
          clearEl(resHost);
          resHost.appendChild(h('div', { class: 'notice bad' }, t('toast.probeErr', { msg: err.message })));
        }
      }
    });
  }

  async function runSpeedTest() {
    const btn = $('#sp-submit');
    const status = $('#sp-status');
    const resHost = $('#speedtest-result');
    if (status) status.textContent = t('for.speedRunning');
    await busy(btn, async () => {
      try {
        const res = await api('/api/forensics/speedtest', {
          method: 'POST',
          timeout: 90000,
          body: {
            baseUrl: ($('#sp-url')?.value || '').trim(),
            apiKey: $('#sp-key')?.value || '',
            endpointMode: $('#sp-mode')?.value || 'chat_completions',
            model: ($('#sp-model')?.value || '').trim(),
            runs: Math.min(3, Math.max(1, Number($('#sp-runs')?.value) || 2)),
          },
        });
        if ($('#sp-key')) $('#sp-key').value = '';
        if (status) status.textContent = t('for.speedDone');

        const ttftP50 = nn(res, 'ttftP50Ms', 'ttft_p50_ms');
        const ttftP95 = nn(res, 'ttftP95Ms', 'ttft_p95_ms');
        const tpot = nn(res, 'tpotAvgMs', 'tpot_avg_ms', 'tpotMs');
        const tps = nn(res, 'tokPerSecAvg', 'tok_per_sec_avg', 'tokPerSec');
        const jitter = nn(res, 'jitterMs', 'jitter_ms');
        const cap = v(res, 'lastCapture') || res || {};
        const vk = String(v(cap, 'verdict') || 'UNVERIFIED');
        const vd = verdictMeta(vk);
        const score = nn(cap, 'authenticityScore', 'authenticity_score');
        const wireModel = v(cap, 'wireModel', 'wire_model') || ($('#sp-model')?.value || '');

        if (resHost) {
          clearEl(resHost);
          resHost.appendChild(
            h(
              'div',
              { class: 'sse-sec' },
              h(
                'div',
                { class: 'head-actions' },
                h('span', { class: `badge ${vd[1]}` }, iconEl(vd[2]), h('span', null, vd[0])),
                score !== null ? h('span', { class: 'mono-sm tnum' }, t('for.speedAuth', { score: fmtNum(score) })) : null,
                wireModel ? h('span', { class: 'mono-sm muted' }, t('for.speedWire', { model: maskText(wireModel) })) : null
              ),
              h(
                'div',
                { class: 'speed-grid tnum' },
                h(
                  'div',
                  { class: 'speed-box' },
                  h('span', null, t('for.speedTtft')),
                  h('b', { class: 'tnum' }, `${fmtMs(ttftP50)} / ${fmtMs(ttftP95)}`)
                ),
                h(
                  'div',
                  { class: 'speed-box' },
                  h('span', null, t('for.speedTpot')),
                  h('b', { class: 'tnum' }, tpot !== null ? `${fmtNum(tpot, 1)} ms` : '—')
                ),
                h(
                  'div',
                  { class: 'speed-box' },
                  h('span', null, t('for.speedTps')),
                  h('b', { class: 'tnum' }, tps !== null ? `${fmtNum(tps, 1)} tok/s` : '—')
                ),
                h(
                  'div',
                  { class: 'speed-box' },
                  h('span', null, t('for.speedJitter')),
                  h('b', { class: 'tnum' }, fmtMs(jitter))
                )
              )
            )
          );
        }
        loadTab('forensics', true);
      } catch (err) {
        if (status) status.textContent = '';
        if (resHost) {
          clearEl(resHost);
          resHost.appendChild(h('div', { class: 'notice bad' }, t('toast.speedErr', { msg: err.message })));
        }
      }
    });
  }

  /* ------------------------------ Models & Integrations ------------------------------ */
  const PRICE_FIELDS = [
    ['input_per_1m', 'mod.colIn'],
    ['cache_read_per_1m', 'mod.colCr'],
    ['cache_write_per_1m', 'mod.colCw'],
    ['output_per_1m', 'mod.colOut'],
    ['reasoning_per_1m', 'mod.colThink'],
  ];
  const fmtPrice = (x) => (x === null ? '—' : '$' + fmtNum(x, x < 1 ? 3 : 2));

  function renderModels() {
    const host = $('#model-table');
    if (!host) return;
    const q = S.mq.toLowerCase();
    const all = S.models.filter(
      (m) => !q || `${v(m, 'model_id')} ${v(m, 'display_name')} ${v(m, 'provider')}`.toLowerCase().includes(q)
    );
    const pages = Math.max(1, Math.ceil(all.length / modelPage()));
    S.mpage = Math.min(Math.max(0, S.mpage), pages - 1);
    const rows = all.slice(S.mpage * modelPage(), (S.mpage + 1) * modelPage());
    const mdPage = $('#md-page');
    if (mdPage) mdPage.textContent = t('mod.page', { n: fmtNum(all.length), cur: fmtNum(S.mpage + 1), pages: fmtNum(pages) });
    const mdPrev = $('#md-prev');
    if (mdPrev) mdPrev.disabled = S.mpage <= 0;
    const mdNext = $('#md-next');
    if (mdNext) mdNext.disabled = S.mpage >= pages - 1;

    clearEl(host);
    if (!rows.length) {
      host.appendChild(h('p', { class: 'empty pad' }, t('mod.empty')));
      return;
    }

    const head = [
      t('mod.colModel'),
      t('mod.colCtx'),
      ...PRICE_FIELDS.map((p) => t(p[1])),
      t('mod.colReq'),
      t('mod.colMult'),
      t('mod.colStatus'),
      '',
    ];
    const thead = h(
      'thead',
      null,
      h(
        'tr',
        null,
        head.map((lbl, i) =>
          h(
            'th',
            { scope: 'col', class: i > 0 && i < head.length - 2 ? 'num' : undefined },
            lbl || h('span', { class: 'sr-only' }, t('acc.colAction'))
          )
        )
      )
    );

    const srcNameMap = {
      seed: t('mod.srcSeed'),
      openrouter: 'OpenRouter',
      lmspeed: 'LMSpeed',
      tokenpricing: 'TokenPricing',
      custom: t('mod.srcCustom'),
    };

    const tbody = h('tbody');
    rows.forEach((m) => {
      const id = String(v(m, 'model_id'));
      const edit = state.editModel === id;
      const custom = Number(v(m, 'is_custom')) === 1 || v(m, 'is_custom') === true;
      const makeInput = (name, val, step) =>
        h('input', {
          class: 'inline-input tnum',
          name,
          type: 'number',
          step,
          min: '0',
          inputmode: 'decimal',
          value: String(val ?? 0),
          'aria-label': name,
        });

      const priceCells = PRICE_FIELDS.map(([key, labelKey]) =>
        h(
          'td',
          {
            class: 'num tnum' + (key === 'cache_write_per_1m' || key === 'reasoning_per_1m' ? ' opt' : ''),
            dataset: { label: `${t(labelKey)} $/1M` },
          },
          edit ? makeInput(key, nn(m, key), '0.001') : fmtPrice(nn(m, key))
        )
      );

      const srcKey = String(v(m, 'source') || 'seed').toLowerCase();
      const tr = h(
        'tr',
        edit ? { dataset: { editModel: id } } : null,
        h(
          'td',
          { class: 'cell-first', dataset: { label: t('mod.colModel') } },
          h(
            'div',
            { class: 'cell-main' },
            h('b', null, maskText(v(m, 'display_name') || id)),
            h('small', null, `${maskText(v(m, 'provider') || '')} · ${maskText(id)}`)
          )
        ),
        h(
          'td',
          { class: 'num opt tnum', dataset: { label: t('mod.colCtx') } },
          edit ? makeInput('context_window', nn(m, 'context_window'), '1000') : fmtTok(nn(m, 'context_window'))
        ),
        priceCells,
        h(
          'td',
          { class: 'num tnum', dataset: { label: t('mod.colReq') } },
          edit
            ? makeInput('request_fee_usd', nn(m, 'request_fee_usd'), '0.0001')
            : nn(m, 'request_fee_usd')
            ? '$' + fmtNum(nn(m, 'request_fee_usd'), 4)
            : '—'
        ),
        h(
          'td',
          { class: 'num tnum', dataset: { label: t('mod.colMult') } },
          edit
            ? makeInput('credit_multiplier', nn(m, 'credit_multiplier'), '0.01')
            : nn(m, 'credit_multiplier') !== null
            ? fmtNum(nn(m, 'credit_multiplier'), 2) + 'x'
            : '—'
        ),
        h(
          'td',
          { dataset: { label: t('mod.colStatus') } },
          h(
            'span',
            { class: 'badge ' + (custom ? 'badge-custom' : 'badge-info') },
            h('span', null, custom ? t('mod.srcCustom') : srcNameMap[srcKey] || String(v(m, 'source')))
          )
        ),
        h(
          'td',
          { dataset: { label: t('acc.colAction') } },
          edit
            ? [
                h(
                  'button',
                  { type: 'button', class: 'btn btn-sm btn-primary', dataset: { action: 'save-model', id } },
                  iconEl('save'),
                  h('span', null, t('btn.save'))
                ),
                ' ',
                h(
                  'button',
                  { type: 'button', class: 'btn btn-sm btn-ghost', dataset: { action: 'cancel-model' } },
                  iconEl('x'),
                  h('span', null, t('btn.cancel'))
                ),
              ]
            : h(
                'button',
                { type: 'button', class: 'btn btn-sm', dataset: { action: 'edit-model', id } },
                iconEl('tag'),
                h('span', null, t('mod.editPrice'))
              )
        )
      );
      tbody.appendChild(tr);
    });

    host.appendChild(h('table', { class: 'tbl stack' }, thead, tbody));
  }

  const INTEGRATIONS = [
    ['antigravity', 'Antigravity Sidecar', 'int.antigravity', 'bot'],
    ['omniroute', 'OmniRoute', 'int.omniroute', 'route'],
    ['9router', '9Router', 'int.9router', 'server'],
    ['claude-code', 'Claude Code', 'int.claudeCode', 'terminal'],
    ['codex', 'Codex', 'int.codex', 'terminal'],
    ['opencode', 'OpenCode', 'int.opencode', 'terminal'],
    ['tee-proxy', 'Tee Proxy (:19841)', 'int.teeProxy', 'radio'],
  ];

  function renderIntegrations() {
    const host = $('#int-grid');
    if (!host) return;
    clearEl(host);
    const byId = new Map(S.integrations.map((i) => [String(v(i, 'tool', 'id', 'key')), i]));
    INTEGRATIONS.forEach(([id, name, descKey, ic]) => {
      const info = byId.get(id) || null;
      const st = info ? String(v(info, 'status') || 'unknown') : 'unknown';
      const label = t(`int.${st}`) !== `int.${st}` ? t(`int.${st}`) : st;
      const cls = st === 'configured' ? 'badge-ok' : st === 'conflict' ? 'badge-warn' : st === 'available' ? 'badge-info' : '';
      const notes = info ? arr(v(info, 'notes')).slice(0, 2) : [];
      const support = info ? v(info, 'apply_supported', 'applySupported') !== false : true;
      const isTee = id === 'tee-proxy';
      const teeRunning = isTee && Boolean(state.tee?.running);
      const badgeCls = isTee ? (teeRunning ? 'badge-ok' : 'badge-info') : cls;
      const badgeLabel = isTee
        ? teeRunning
          ? t('int.teeRun', { port: state.tee.port || 19841 })
          : t('int.teeReady')
        : label;

      const primaryBtn = isTee
        ? h(
            'button',
            {
              type: 'button',
              class: 'btn btn-sm ' + (teeRunning ? 'btn-danger' : 'btn-primary'),
              dataset: { action: 'tee-toggle' },
            },
            iconEl(teeRunning ? 'square' : 'play'),
            h('span', null, teeRunning ? t('int.stop') : t('int.start'))
          )
        : h(
            'button',
            {
              type: 'button',
              class: 'btn btn-sm btn-primary',
              dataset: { action: 'int-apply', id, status: st },
              disabled: !support,
            },
            iconEl('plug'),
            h('span', null, t('int.connect'))
          );

      host.appendChild(
        h(
          'div',
          { class: 'int-card', dataset: { int: id } },
          h('div', { class: 'int-head' }, iconEl(ic), h('h4', null, name)),
          h('p', null, t(descKey)),
          h('div', null, h('span', { class: `badge ${badgeCls}` }, h('span', null, badgeLabel))),
          notes.length ? h('p', { class: 'muted' }, notes.map((x) => maskText(x)).join(' ')) : null,
          h(
            'div',
            { class: 'form-actions' },
            primaryBtn,
            h(
              'button',
              { type: 'button', class: 'btn btn-sm', dataset: { action: 'int-preview', id } },
              iconEl('terminal'),
              h('span', null, t('int.showCmd'))
            )
          ),
          h('pre', { class: 'int-out', hidden: true })
        )
      );
    });
  }

  async function runIntegration(id, apply, btn) {
    const card = $(`[data-int="${CSS.escape(id)}"]`);
    const out = card ? $('.int-out', card) : null;
    const body = { apply };
    if (apply && btn.dataset.status === 'conflict') {
      if (!window.confirm(t('int.confirmForce'))) return;
      body.force = true;
    }
    await busy(btn, async () => {
      try {
        const res = await api('/api/integrations/' + encodeURIComponent(id), { method: 'POST', body });
        const parts = [v(res, 'message'), v(res, 'preview'), v(res, 'snippet')].filter((x) => typeof x === 'string' && x);
        const info =
          v(res, 'integration', 'status') && typeof v(res, 'integration', 'status') === 'object'
            ? v(res, 'integration', 'status')
            : res;
        const snip = parts.length
          ? parts
          : [typeof v(info, 'snippet') === 'string' ? v(info, 'snippet') : JSON.stringify(res, null, 2)];
        if (out) {
          out.hidden = false;
          out.textContent = snip.join('\n\n');
        }
        toast(apply ? t('toast.intDone') : t('toast.intPreview'));
        if (apply) loadTab('models', true);
      } catch (err) {
        if (out) {
          out.hidden = false;
          out.textContent = 'Error: ' + err.message;
        }
        toast(t('toast.intErr', { msg: err.message }), 'err');
      }
    });
  }

  /* ------------------------------ 4-Step Setup Wizard Dialog ------------------------------ */
  function renderWizardStep() {
    const step = state.wizardStep;
    const ind = $('#wiz-step-indicator');
    if (ind) ind.textContent = t('wiz.step', { step });
    const prog = $('#wiz-progress');
    if (prog) prog.setAttribute('aria-valuenow', String(step));
    $$('#wiz-progress .wiz-dot').forEach((d) => {
      d.classList.toggle('is-active', Number(d.dataset.wstep) === step);
    });
    $$('#wiz-body .wiz-step').forEach((s) => {
      s.hidden = Number(s.dataset.step) !== step;
    });
    const prevBtn = $('#wiz-prev');
    if (prevBtn) prevBtn.disabled = step <= 1;
    const nextBtn = $('#wiz-next');
    if (nextBtn) nextBtn.hidden = step >= 4;
    const doneBtn = $('#wiz-done');
    if (doneBtn) doneBtn.hidden = step < 4;
  }

  function openSetupWizard(step = 1) {
    state.wizardStep = step;
    renderWizardStep();
    openModal($('#setup-wizard'));
  }

  function finishSetupWizard() {
    try { localStorage.setItem('wt.wizardDone', '1'); } catch { /* ignore */ }
    closeModal($('#setup-wizard'));
  }

  /* ------------------------------ Mobile LAN QR Pairing Dialog ------------------------------ */
  function renderLanStatus(data) {
    const enabled = Boolean(v(data, 'enabled'));
    const pin = v(data, 'pin') || '——————';
    const urls = arr(v(data, 'lanUrls'));
    const urlText = v(data, 'lanUrl') || urls[0] || (enabled ? `${location.protocol}//${v(data, 'hostIp') || localHostName()}:${v(data, 'port') || 19842}` : '—');
    const paired = n0(data, 'pairedCount');
    const qrSvgStr = v(data, 'qrSvg');

    const badge = $('#lan-status-badge');
    if (badge) {
      badge.className = 'badge ' + (enabled ? 'badge-ok' : '');
      clearEl(badge);
      badge.appendChild(h('span', null, enabled ? t('lan.on') : t('lan.off')));
    }
    const pinEl = $('#lan-pin-code');
    if (pinEl) pinEl.textContent = enabled ? String(pin) : '——————';
    const urlEl = $('#lan-url-text');
    if (urlEl) urlEl.textContent = urlText;
    const pairedEl = $('#lan-paired-count');
    if (pairedEl) pairedEl.textContent = t('lan.pairedCount', { n: fmtNum(paired) });

    const disableBtn = $('#lan-disable');
    if (disableBtn) disableBtn.hidden = !enabled;
    const enableBtn = $('#lan-enable');
    if (enableBtn) {
      const span = enableBtn.querySelector('span');
      if (span) span.textContent = enabled ? t('lan.rotate') : t('lan.enable');
    }

    const qrBox = $('#lan-qr-box');
    if (qrBox) {
      clearEl(qrBox);
      const svgNode = enabled && qrSvgStr ? parseSvgSafe(qrSvgStr, document) : null;
      if (svgNode) {
        qrBox.appendChild(svgNode);
      } else {
        qrBox.appendChild(
          h('span', { class: 'muted mono-sm', style: { textAlign: 'center' } }, enabled ? t('lan.qrReady') : t('lan.lanOff'))
        );
      }
    }
  }

  async function openLanDialog() {
    openModal($('#lan-dialog'));
    try {
      const st = await api('/api/lan/status');
      renderLanStatus(st);
    } catch (err) {
      toast(t('toast.lanErr', { msg: err.message }), 'err');
    }
  }

  /* ------------------------------ Tabs & Mobile Bottom Nav ------------------------------ */
  function showTab(tab, focus) {
    state.tab = tab;
    persist();
    if (location.hash.slice(1) !== tab) history.replaceState(null, '', '#' + tab);
    $$('#tabs [role="tab"]').forEach((b) => {
      const on = b.dataset.tab === tab;
      b.setAttribute('aria-selected', String(on));
      b.tabIndex = on ? 0 : -1;
      if (on) {
        b.scrollIntoView({ block: 'nearest', inline: 'center' });
        if (focus) b.focus();
      }
    });
    $$('#mobile-nav .mob-tab').forEach((b) => {
      const on = b.dataset.tab === tab;
      if (on) b.setAttribute('aria-current', 'page');
      else b.removeAttribute('aria-current');
    });
    $$('.panel').forEach((p) => {
      p.hidden = p.id !== 'panel-' + tab;
    });
    if (tab === 'overview') renderOverview();
    else loadTab(tab);
  }

  /* ------------------------------ Event Delegation & Actions ------------------------------ */
  async function onAction(el) {
    const act = el.dataset.action;
    if (act === 'ctx') {
      const id = el.dataset.id;
      const isRecent = el.dataset.recent === '1';
      state.ctxId = id;
      state.pinnedSessionId = isRecent ? id : null;
      renderCtx();
      renderHudAll();
      broadcastState();
    } else if (act === 'unpin-ctx') {
      state.pinnedSessionId = null;
      state.ctxId = null;
      renderCtx();
      renderHudAll();
      broadcastState();
    } else if (act === 'filter-session') {
      const id = el.dataset.id;
      if (!id) return;
      const title = el.dataset.title || id;
      state.rq.sessionId = id;
      state.rq.sessionTitle = title;
      state.rq.offset = 0;
      renderStatic();
      showTab('requests');
      toast(t('toast.sessionFiltered', { title: maskText(title).slice(0, 36) }));
    } else if (act === 'set-recent-limit') {
      const lim = Number(el.dataset.limit);
      if (!RECENT_LIMITS.includes(lim)) return;
      state.recentLimit = lim;
      persist();
      await loadOverview();
    } else if (act === 'toggle-recent-ctx') {
      state.recentDrawerOpen = !state.recentDrawerOpen;
      renderCtx();
    } else if (act === 'copy') {
      try {
        await navigator.clipboard.writeText(el.dataset.copy);
        toast(t('toast.copied', { val: el.dataset.copy }));
      } catch {
        toast(t('toast.copyErr', { val: el.dataset.copy }), 'err');
      }
    } else if (act === 'clear-filter') {
      const f = el.dataset.filter;
      if (f === 'era') state.era = 'live';
      else if (f === 'sourceTool') state.sourceTool = '';
      else if (f === 'accountId') state.accountId = '';
      else if (f === 'modelId') state.rq.modelId = '';
      else if (f === 'sessionId') {
        state.rq.sessionId = '';
        state.rq.sessionTitle = '';
      } else if (f === 'date') {
        state.from = '';
        state.to = '';
      } else if (f === 'all') {
        state.era = 'live';
        state.sourceTool = '';
        state.accountId = '';
        state.rq.modelId = '';
        state.rq.sessionId = '';
        state.rq.sessionTitle = '';
        state.from = '';
        state.to = '';
      }
      state.rq.offset = 0;
      persist();
      renderStatic();
      await refreshAll();
    } else if (act === 'heat-day') {
      const date = el.dataset.date;
      if (!date) return;
      hideHeatTooltip();
      state.from = date;
      state.to = date;
      state.rq.offset = 0;
      persist();
      renderStatic();
      showTab('requests');
      await refreshAll();
      toast(t('toast.dayFiltered', { date }));
    } else if (act === 'set-plan') {
      const id = el.dataset.id;
      const newPlan = el.dataset.plan;
      if (!id || !newPlan) return;
      const curFee = Number(el.dataset.fee) || 0;
      const body = {
        plan_type: newPlan,
        monthly_fee_usd: newPlan === 'subscription' ? (curFee > 0 ? curFee : 20) : 0,
      };
      await busy(el, async () => {
        try {
          await api('/api/accounts/' + encodeURIComponent(id), { method: 'PATCH', body });
          const planLbl = newPlan === 'subscription' ? t('acc.planSubFull') : newPlan === 'free' ? t('acc.planFree') : t('acc.planApi');
          toast(t('toast.planUpdated', { plan: planLbl }));
          await loadOverview();
          await loadTab('accounts');
        } catch (err) {
          toast(t('toast.planErr', { msg: err.message }), 'err');
        }
      });
    } else if (act === 'edit-acc') {
      state.editAcc = state.editAcc === el.dataset.id ? null : el.dataset.id;
      renderAccounts();
    } else if (act === 'cancel-acc') {
      state.editAcc = null;
      renderAccounts();
    } else if (act === 'edit-model') {
      state.editModel = el.dataset.id;
      renderModels();
    } else if (act === 'cancel-model') {
      state.editModel = null;
      renderModels();
    } else if (act === 'save-model') {
      const tr = el.closest('tr');
      const body = {};
      $$('input', tr).forEach((i) => {
        body[i.name] = Number(i.value);
      });
      await busy(el, async () => {
        try {
          await api('/api/models/' + encodeURIComponent(el.dataset.id), { method: 'PATCH', body });
          state.editModel = null;
          toast(t('toast.modelSaved'));
          await loadTab('models');
          await loadOverview();
        } catch (err) {
          toast(t('toast.saveErr', { msg: err.message }), 'err');
        }
      });
    } else if (act === 'int-apply') {
      await runIntegration(el.dataset.id, true, el);
    } else if (act === 'int-preview') {
      await runIntegration(el.dataset.id, false, el);
    } else if (act === 'goto-tab') {
      showTab(el.dataset.tab || 'overview');
    } else if (act === 'tee-toggle') {
      await toggleTeeProxy(el);
    }
  }

  async function toggleTeeProxy(btn) {
    const running = Boolean(state.tee?.running);
    await busy(btn, async () => {
      try {
        if (running) {
          const r = await api('/api/tee/stop', { method: 'POST', body: {} });
          state.tee = { ...state.tee, ...r, running: false };
          toast(t('toast.teeStopped'));
        } else {
          const upstreamBaseUrl = ($('#tee-upstream')?.value || 'https://api.openai.com/v1').trim();
          const port = Number($('#tee-port')?.value) || 19841;
          const r = await api('/api/tee/start', { method: 'POST', body: { port, upstreamBaseUrl } });
          state.tee = { ...state.tee, ...r, running: true };
          toast(t('toast.teeStarted', { url: localPresetBase(state.tee.port) }));
        }
        renderTeeControl();
        if (state.tab === 'models') renderIntegrations();
      } catch (err) {
        toast(t('toast.teeErr', { msg: err.message }), 'err');
      }
    });
  }

  async function togglePrivacy() {
    state.privacy = !state.privacy;
    persist();
    renderStatic();
    renderOverview();
    renderHudAll();
    ({ accounts: renderAccounts, requests: renderRequests, forensics: renderHistory, models: renderModels })[state.tab]?.();
    broadcastState();
    api('/api/settings', { method: 'POST', body: { privacy_mask: state.privacy ? '1' : '0' } }).catch(() => {});
  }

  function setLanguage(lang) {
    if (!I18N.supported.includes(lang) || lang === state.lang) return;
    state.lang = lang;
    persist();
    applyI18n();
    renderStatic();
    renderOverview();
    renderHudAll();
    renderWizardStep();
    ({ accounts: renderAccounts, requests: renderRequests, forensics: renderHistory, models: () => { renderModels(); renderIntegrations(); } })[state.tab]?.();
    broadcastState();
  }

  function bind() {
    document.addEventListener('click', (ev) => {
      const el = ev.target.closest('[data-action]');
      if (el) onAction(el);
    });

    const heatHost = $('#heatmap');
    if (heatHost) {
      heatHost.addEventListener('pointerover', (ev) => {
        const cell = ev.target.closest('.heat-cell[data-date]');
        if (cell) showHeatTooltip(cell);
      });
      heatHost.addEventListener('pointerout', (ev) => {
        const cell = ev.target.closest('.heat-cell[data-date]');
        if (cell) hideHeatTooltip();
      });
      heatHost.addEventListener('focusin', (ev) => {
        const cell = ev.target.closest('.heat-cell[data-date]');
        if (cell) showHeatTooltip(cell);
      });
      heatHost.addEventListener('focusout', () => hideHeatTooltip());
    }

    document.addEventListener('submit', async (ev) => {
      const f = ev.target;
      if (f.dataset.form === 'acc') {
        ev.preventDefault();
        const fd = new FormData(f);
        const body = {
          email_or_label: String(fd.get('email_or_label') || ''),
          plan_type: String(fd.get('plan_type')),
          monthly_fee_usd: Number(fd.get('monthly_fee_usd')),
          daily_budget_usd: Number(fd.get('daily_budget_usd')),
          monthly_budget_usd: Number(fd.get('monthly_budget_usd')),
        };
        try {
          await api('/api/accounts/' + encodeURIComponent(f.dataset.id), { method: 'PATCH', body });
          state.editAcc = null;
          toast(t('toast.accSaved'));
          await loadOverview();
          await loadTab('accounts');
        } catch (err) {
          toast(t('toast.saveErr', { msg: err.message }), 'err');
        }
      }
    });

    $('#seg-era')?.addEventListener('click', (ev) => {
      const b = ev.target.closest('button[data-era]');
      if (!b) return;
      state.era = b.dataset.era;
      state.rq.offset = 0;
      persist();
      renderStatic();
      refreshAll();
    });

    $('#seg-cur')?.addEventListener('click', (ev) => {
      const b = ev.target.closest('button[data-cur]');
      if (!b) return;
      state.cur = b.dataset.cur;
      persist();
      renderStatic();
      renderOverview();
      renderHudAll();
      broadcastState();
      if (state.tab === 'accounts') renderAccounts();
      else if (state.tab === 'requests') renderRequests();
    });

    $('#seg-lang')?.addEventListener('click', (ev) => {
      const b = ev.target.closest('button[data-lang]');
      if (b) setLanguage(b.dataset.lang);
    });

    $('#seg-density')?.addEventListener('click', (ev) => {
      const b = ev.target.closest('button[data-density]');
      if (!b) return;
      state.density = b.dataset.density;
      persist();
      applyDensity();
    });

    let resizeTimer;
    window.addEventListener('resize', () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        if (state.density === 'auto') applyDensity();
      }, 120);
    }, { passive: true });

    $('#btn-privacy')?.addEventListener('click', togglePrivacy);
    $('#wiz-btn-privacy')?.addEventListener('click', togglePrivacy);
    $('#btn-recent-sessions')?.addEventListener('click', () => {
      state.recentDrawerOpen = !state.recentDrawerOpen;
      renderCtx();
    });
    $('#btn-mini-hud')?.addEventListener('click', openMiniHud);
    $('#wiz-btn-hud')?.addEventListener('click', openMiniHud);
    $('#btn-lan-qr')?.addEventListener('click', openLanDialog);
    $('#wiz-btn-lan')?.addEventListener('click', () => {
      closeModal($('#setup-wizard'));
      openLanDialog();
    });

    // Setup wizard controls
    $('#btn-open-wizard')?.addEventListener('click', () => openSetupWizard(1));
    $('#btn-guide-wizard')?.addEventListener('click', () => openSetupWizard(1));
    $('#btn-show-guide')?.addEventListener('click', () => {
      state.guideHidden = false;
      try { localStorage.removeItem('wt.guideHidden'); } catch { /* ignore */ }
      renderGuide();
      openSetupWizard(1);
    });
    $('#wiz-close')?.addEventListener('click', finishSetupWizard);
    $('#wiz-done')?.addEventListener('click', finishSetupWizard);
    $('#wiz-prev')?.addEventListener('click', () => {
      state.wizardStep = Math.max(1, state.wizardStep - 1);
      renderWizardStep();
    });
    $('#wiz-next')?.addEventListener('click', () => {
      state.wizardStep = Math.min(4, state.wizardStep + 1);
      renderWizardStep();
    });

    // LAN QR Dialog controls
    $('#lan-close')?.addEventListener('click', () => closeModal($('#lan-dialog')));
    $('#lan-enable')?.addEventListener('click', (ev) =>
      busy(ev.currentTarget, async () => {
        try {
          const r = await api('/api/lan/enable', { method: 'POST', body: {} });
          renderLanStatus(r);
          state.privacy = true;
          renderStatic();
          toast(t('toast.lanOn'));
        } catch (err) {
          toast(t('toast.lanOnErr', { msg: err.message }), 'err');
        }
      })
    );
    $('#lan-disable')?.addEventListener('click', (ev) =>
      busy(ev.currentTarget, async () => {
        try {
          await api('/api/lan/disable', { method: 'POST', body: {} });
          renderLanStatus({ enabled: false, pairedCount: 0 });
          toast(t('toast.lanOff'));
        } catch (err) {
          toast(t('toast.lanOffErr', { msg: err.message }), 'err');
        }
      })
    );

    // PIN Gate form
    $('#pin-form')?.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const pin = ($('#pin-input')?.value || '').trim();
      const st = $('#pin-status');
      if (st) st.textContent = t('pin.verifying');
      await busy($('#pin-submit'), async () => {
        try {
          await api('/api/auth/pair', { method: 'POST', body: { pin, nonce: pairNonceParam || undefined } });
          state.requiresPin = false;
          if (st) st.textContent = '';
          closeModal($('#pin-dialog'));
          toast(t('toast.pinOk'));
          connectEvents();
          await refreshAll();
        } catch (err) {
          if (st) st.textContent = err.message;
        }
      });
    });

    const filt = () => {
      state.from = $('#f-from')?.value || '';
      state.to = $('#f-to')?.value || '';
      state.sourceTool = $('#f-source')?.value || '';
      state.accountId = $('#f-account')?.value || '';
      state.rq.offset = 0;
      persist();
      renderStatic();
      refreshAll();
    };
    ['#f-from', '#f-to', '#f-source', '#f-account'].forEach((s) => $(s)?.addEventListener('change', filt));

    $('#btn-reset-filters')?.addEventListener('click', () => {
      state.from = '';
      state.to = '';
      state.sourceTool = '';
      state.accountId = '';
      state.rq.modelId = '';
      state.rq.sessionId = '';
      state.rq.sessionTitle = '';
      state.rq.offset = 0;
      persist();
      renderStatic();
      refreshAll();
    });
    $('#btn-filters')?.addEventListener('click', (ev) => {
      const open = $('#filters')?.classList.toggle('is-open');
      ev.currentTarget.setAttribute('aria-expanded', String(Boolean(open)));
    });

    const doSync = (btn) =>
      busy(btn, async () => {
        try {
          const r = await api('/api/sync', { method: 'POST', timeout: 120000 });
          const counts = v(r, 'syncedCounts') || {};
          const total = Object.values(counts).reduce((s, x) => s + (Number(x) || 0), 0);
          const msg = t('toast.syncDone', { n: fmtNum(total) });
          toast(msg);
          const wizSt = $('#wiz-sync-status');
          if (wizSt) wizSt.textContent = msg;
          await refreshAll(true);
        } catch (err) {
          toast(t('toast.syncErr', { msg: err.message }), 'err');
        }
      });

    const doModelSync = (btn) =>
      busy(btn, async () => {
        try {
          const r = await api('/api/models/sync', { method: 'POST', timeout: 60000 });
          toast(t('toast.modelsSynced', { u: fmtNum(n0(r, 'updated')), t: fmtNum(n0(r, 'total')) }));
          await loadOverview();
          if (state.tab === 'models') await loadTab('models');
        } catch (err) {
          toast(t('toast.modelsErr', { msg: err.message }), 'err');
        }
      });

    $('#btn-sync')?.addEventListener('click', (ev) => doSync(ev.currentTarget));
    $('#wiz-btn-sync')?.addEventListener('click', (ev) => doSync(ev.currentTarget));
    $('#btn-toggle-sync')?.addEventListener('click', (ev) =>
      busy(ev.currentTarget, async () => {
        try {
          const r = await api('/api/sync/toggle', { method: 'POST', body: {} });
          state.syncPaused = Boolean(r.syncPaused);
          renderSyncControl();
          toast(state.syncPaused ? t('toast.syncPaused') : t('toast.syncResumed'));
        } catch (err) {
          toast(t('toast.opErr', { msg: err.message }), 'err');
        }
      })
    );
    $('#btn-hide-guide')?.addEventListener('click', () => {
      state.guideHidden = true;
      try { localStorage.setItem('wt.guideHidden', '1'); } catch { /* ignore */ }
      renderGuide();
    });

    $('#tee-preset')?.addEventListener('change', (ev) => {
      const val = ev.target.value;
      if (val && val !== 'custom' && $('#tee-upstream')) $('#tee-upstream').value = val;
    });
    $('#tee-toggle')?.addEventListener('click', (ev) => toggleTeeProxy(ev.currentTarget));

    $('#sp-preset')?.addEventListener('change', (ev) => {
      const p = SPEED_PRESETS[ev.target.value];
      if (!p) return;
      if ($('#sp-url')) $('#sp-url').value = p.url;
      if ($('#sp-model')) $('#sp-model').value = p.model;
      if ($('#sp-mode')) $('#sp-mode').value = p.mode;
    });
    $('#speedtest-form')?.addEventListener('submit', (ev) => {
      ev.preventDefault();
      runSpeedTest();
    });

    $('#btn-model-sync')?.addEventListener('click', (ev) => doModelSync(ev.currentTarget));
    $('#md-sync')?.addEventListener('click', (ev) => doModelSync(ev.currentTarget));

    const tabs = $('#tabs');
    if (tabs) {
      tabs.addEventListener('click', (ev) => {
        const b = ev.target.closest('[role="tab"]');
        if (b) showTab(b.dataset.tab);
      });
      tabs.addEventListener('keydown', (ev) => {
        const list = $$('[role="tab"]', tabs);
        const i = list.findIndex((b) => b.getAttribute('aria-selected') === 'true');
        let j = i;
        if (ev.key === 'ArrowRight') j = (i + 1) % list.length;
        else if (ev.key === 'ArrowLeft') j = (i - 1 + list.length) % list.length;
        else if (ev.key === 'Home') j = 0;
        else if (ev.key === 'End') j = list.length - 1;
        else return;
        ev.preventDefault();
        showTab(list[j].dataset.tab, true);
      });
    }

    $('#seg-metric')?.addEventListener('click', (ev) => {
      const b = ev.target.closest('button[data-metric]');
      if (!b) return;
      state.metric = b.dataset.metric;
      persist();
      renderChart();
    });

    $('#seg-heat-metric')?.addEventListener('click', (ev) => {
      const b = ev.target.closest('button[data-hmetric]');
      if (!b) return;
      state.heatMetric = b.dataset.hmetric;
      persist();
      renderHeat();
    });
    $('#seg-heat-win')?.addEventListener('click', (ev) => {
      const b = ev.target.closest('button[data-hwin]');
      if (!b) return;
      state.heatWeeks = Number(b.dataset.hwin) || 53;
      persist();
      renderHeat();
    });

    let qTimer;
    $('#rq-q')?.addEventListener('input', (ev) => {
      clearTimeout(qTimer);
      qTimer = setTimeout(() => {
        state.rq.q = ev.target.value.trim();
        state.rq.offset = 0;
        loadTab('requests');
      }, 300);
    });
    $('#rq-model')?.addEventListener('change', (ev) => {
      state.rq.modelId = ev.target.value;
      state.rq.offset = 0;
      persist();
      renderStatic();
      loadTab('requests');
    });
    $('#rq-sort')?.addEventListener('change', (ev) => {
      state.rq.sort = ev.target.value;
      state.rq.expensive = false;
      state.rq.offset = 0;
      loadTab('requests');
    });
    $('#rq-expensive')?.addEventListener('click', () => {
      state.rq.expensive = !state.rq.expensive;
      if (state.rq.expensive) {
        state.rq.prevSort = state.rq.sort;
        state.rq.sort = 'api_list_cost_usd:desc';
        state.rq.limit = 50;
      } else {
        state.rq.sort = state.rq.prevSort;
        state.rq.limit = 25;
      }
      state.rq.offset = 0;
      loadTab('requests');
    });
    $('#rq-prev')?.addEventListener('click', () => {
      state.rq.offset = Math.max(0, state.rq.offset - state.rq.limit);
      loadTab('requests');
    });
    $('#rq-next')?.addEventListener('click', () => {
      state.rq.offset += state.rq.limit;
      loadTab('requests');
    });

    $('#retag-form')?.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const accountId = $('#rt-account')?.value;
      if (!accountId) {
        toast(t('toast.retagSelect'), 'err');
        return;
      }
      const lbl = $('#rt-account')?.selectedOptions[0]?.textContent || accountId;
      if (!window.confirm(t('toast.retagConfirm', { acc: state.privacy ? maskIdentifier(lbl) : lbl }))) return;
      await busy($('#rt-submit'), async () => {
        try {
          const r = await api('/api/retag', {
            method: 'POST',
            body: {
              accountId,
              from: $('#rt-from')?.value || undefined,
              to: $('#rt-to')?.value ? $('#rt-to').value + 'T23:59:59.999Z' : undefined,
              workspace: ($('#rt-workspace')?.value || '').trim() || undefined,
              sourceTool: $('#rt-source')?.value || undefined,
              scope: $('#rt-scope')?.value,
            },
          });
          const msg = t('toast.retagDone', { n: fmtNum(n0(r, 'updatedCount', 'updated')) });
          const rtRes = $('#rt-result');
          if (rtRes) rtRes.textContent = msg;
          toast(msg);
          await refreshAll(true);
        } catch (err) {
          const rtRes = $('#rt-result');
          if (rtRes) rtRes.textContent = '';
          toast(t('toast.retagErr', { msg: err.message }), 'err');
        }
      });
    });

    $('#seg-mode')?.addEventListener('click', (ev) => {
      const b = ev.target.closest('button[data-mode]');
      if (!b) return;
      state.mode = b.dataset.mode;
      $$('#seg-mode button').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
    });
    $('#sse-sample')?.addEventListener('click', () => {
      if ($('#sse-raw')) $('#sse-raw').value = window.WT_SAMPLE_SSE || '';
      state.mode = 'auto';
      $$('#seg-mode button').forEach((x) => x.setAttribute('aria-pressed', String(x.dataset.mode === 'auto')));
      toast(t('toast.sampleLoaded'));
    });
    $('#sse-analyze')?.addEventListener('click', (ev) => analyzeSse(ev.currentTarget));
    $('#probe-form')?.addEventListener('submit', (ev) => {
      ev.preventDefault();
      runProbe();
    });
    $('#fh-refresh')?.addEventListener('click', () => loadTab('forensics'));

    $('#md-q')?.addEventListener('input', (ev) => {
      S.mq = ev.target.value.trim();
      S.mpage = 0;
      renderModels();
    });
    compactMq.addEventListener('change', () => {
      if (state.tab === 'models') renderModels();
    });
    $('#md-prev')?.addEventListener('click', () => {
      S.mpage -= 1;
      state.editModel = null;
      renderModels();
    });
    $('#md-next')?.addEventListener('click', () => {
      S.mpage += 1;
      state.editModel = null;
      renderModels();
    });

    $('#settings-form')?.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const body = {};
      const fx = Number($('#st-fx')?.value);
      if ($('#st-fx')?.value && fx > 0) body.fx_usd_try = fx;
      if (($('#st-milestone')?.value || '').trim()) body.milestone_at = $('#st-milestone').value.trim();
      if (!Object.keys(body).length) {
        toast(t('toast.settingsEmpty'), 'err');
        return;
      }
      try {
        const r = await api('/api/settings', { method: 'POST', body });
        applySettings(r);
        const stRes = $('#st-result');
        if (stRes) stRes.textContent = t('set.saved');
        toast(t('toast.settingsSaved'));
        renderStatic();
        await loadOverview();
      } catch (err) {
        toast(t('toast.saveErr', { msg: err.message }), 'err');
      }
    });

    $$('dialog.modal').forEach((dlg) => {
      dlg.addEventListener('close', syncModalInert);
      dlg.addEventListener('cancel', () => setTimeout(syncModalInert, 0));
    });

    setInterval(() => {
      if (document.hidden) return;
      $$('[data-until]').forEach((el) => {
        const tsVal = Number(el.dataset.until);
        if (tsVal) el.textContent = countdown(tsVal - Date.now());
      });
    }, 1000);

    window.addEventListener('scroll', () => {
      document.body.classList.toggle('is-scrolled', window.scrollY > 4);
    }, { passive: true });
    window.addEventListener('hashchange', () => {
      const hTab = location.hash.slice(1);
      if (['overview', 'accounts', 'requests', 'forensics', 'models'].includes(hTab) && hTab !== state.tab) {
        showTab(hTab);
      }
    });
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden && live.mode !== 'sse' && !state.requiresPin) refreshAll(true);
    });
  }

  /* ------------------------------ Service Worker & Init ------------------------------ */
  function registerPwaServiceWorker() {
    if (!('serviceWorker' in navigator)) return;
    const isLocal =
      location.protocol === 'https:' ||
      location.hostname === 'localhost' ||
      location.hostname === '127.0.0.1';
    if (!isLocal) return;
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  }

  async function init() {
    document.body.style.fontVariantNumeric = 'tabular-nums';
    applyI18n();
    if (isHudView) {
      document.body.classList.add('hud-mode');
      const hudRoot = $('#hud-root');
      if (hudRoot) {
        hudRoot.hidden = false;
        renderHudInto(hudRoot);
      }
      connectEvents();
      await loadOverview();
      return;
    }

    hydrateIcons();
    bind();
    renderStatic();
    showTab(state.tab);
    registerPwaServiceWorker();

    try {
      const wizDone = localStorage.getItem('wt.wizardDone') === '1';
      if (!wizDone && qp.get('wizard') !== '0') {
        openSetupWizard(1);
      }
    } catch { /* ignore */ }

    const authed = await checkAuthStatus();
    if (!authed) return;

    connectEvents();
    await refreshAll();
    loadSessions();
    if (state.tab !== 'accounts') {
      await loadTab('accounts', true);
      renderStatic();
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
