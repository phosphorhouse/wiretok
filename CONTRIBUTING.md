# Contributing to Wiretok

Thank you for contributing to Wiretok!

## Requirements

- **Node.js `>= 22.0.0`** (uses built-in `node:sqlite` — zero native C++ build dependencies!)
- **Zero external npm runtime dependencies** (keeps install instant and supply-chain surface minimal).

## Development & Verification

```bash
npm test
node --no-warnings bin/wiretok.mjs status --era all
```

### Pull Request Checklist

1. Run `npm test` cleanly on Windows or Linux/macOS.
2. Never add dependencies requiring binary compilation unless strictly justified.
3. Never read credential/OAuth files or weaken SSRF/loopback/secret-scrubbing checks.
4. Keep pricing terminology accurate (`API List Cost` / `API Liste Ederi`, `Actual Paid` / `Gerçek Ödenen`, `List Value Multiplier` / `Liste Ederi Çarpanı` — never call subscription estimates "net profit").
5. Keep all Antigravity integrations 100% update-proof via standard plugin directories (never patch binaries or `.asar` bundles).
