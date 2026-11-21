---
name: wiretok
description: >-
  Query live AI token usage, cache hit efficiency, context window occupancy,
  per-request USD/TRY cost, subscription list-value multiplier, account quotas,
  TTFT/TPOT speed telemetry, and multi-protocol SSE model fingerprint forensics
  across Antigravity 2.0, OmniRoute, 9Router, Claude Code, Codex, and OpenCode.
---

# Wiretok Skill (`v0.2`)

Wiretok tracks passive, update-proof telemetry in `~/.wiretok/wiretok.sqlite` across Antigravity 2.0, Antigravity IDE/CLI, OmniRoute, 9Router, Claude Code, Codex, OpenCode, and raw SSE captures.

Resolve the CLI cleanly using global `tp` or relative to `$PLUGIN_ROOT`:

```bash
TP="node --no-warnings \"$PLUGIN_ROOT/../../bin/wiretok.mjs\""
# or if installed globally: tp <subcommand> --json
```

## Quick CLI Commands (Always pass `--json` for structured facts)

- **Overall summary (`live` since milestone or `all` history):**
  `wiretok status --era live --json` · `wiretok status --era all --json`
- **Today's spend, tokens & speed:**
  `wiretok today --json`
- **Per-account breakdown (tokens, cache hit %, API list value, plan/fee, multiplier):**
  `wiretok accounts --era all --json`
- **Live active context pressure (`tokens_to_65_pct`, `tokens_to_80_pct`, `/compact` warnings, live `tok/s`):**
  `wiretok live --json`
- **Model catalog & live pricing:**
  `tp models --json`
- **Most expensive or slowest recent requests:**
  `tp requests --limit 25 --sort api_list_cost_usd --dir desc --json`
- **Sessions & Swarm cost trees:**
  `tp sessions --limit 20 --json`
- **Incremental sync across all local sources (OpenCode v1+v2, Antigravity summaries/hooks, Claude/Codex, OmniRoute):**
  `wiretok sync --all --json`
- **Quotas / first-time init / web dashboard (`127.0.0.1:19840`, optional `--lan` QR):**
  `wiretok quota --list --json` · `wiretok init --json` · `wiretok web --port 19840`
- **Re-tag history to an account:**
  `wiretok retag --account <id> [--from ISO] [--to ISO] [--workspace path] --json`
- **SSE fingerprint inspection or live endpoint probe (key read from env var, never stored):**
  `wiretok inspect-sse <file> --mode auto --json`
  `wiretok probe --url <base> --mode <responses|messages|chat_completions> --model <m> --key-env <ENV_VAR> --json`

## Answering User Questions

1. **Spend / Token / Account questions:** Run `wiretok sync --all --json` (if stale) then `wiretok accounts --era all --json` or `wiretok status --era all --json`. Always report USD (`$`) and TRY (`₺` via `fxUsdTry`), **`API Liste Ederi`** (`api_list_cost_usd`), **`Gerçek Ödenen`** (`billed_cost_usd` / `effective_paid_usd`), and **`Liste Ederi Çarpanı`** (`list_value_multiplier`). **Never** label subscription value comparisons as "Net Kâr" or "Net Profit".
2. **Context pressure / `/compact` checks:** Run `wiretok live --json` and report `utilization_pct`, `tokens_to_65_pct` / `tokens_to_80_pct`, and `latest_tok_per_sec` / `latest_ttft_ms`. Also remind users of the **Floating Mini-HUD** (`/?view=hud` / PiP button) or Sidecar `[Wiretok](sidecar://wiretok/panel/)`.
3. **Model authenticity / SSE forensics:** Run `wiretok inspect-sse <path> --json` or `wiretok probe ... --json` and separate text self-reports from wire-level evidence (`resp_` IDs, `usage.attribution`, Anthropic `signature`, `system_fingerprint`, `TTFT`/`TPOT`/`tok/s`).
