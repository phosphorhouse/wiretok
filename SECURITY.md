# Security Policy

## Architectural Privacy & Safety Guarantees

Wiretok is built as a local-first, passive telemetry and protocol inspection suite:

1. **Zero Credential Harvesting:** Collectors never read OAuth credentials, cookies, session tokens, or API secret columns (`oauth_creds.json`, `.credentials.json`, `auth.json`, or `storage.sqlite` secret columns).
2. **Loopback-First Server:** By default, the dashboard HTTP/SSE server and Tee Proxy bind strictly to `127.0.0.1` (`localhost`).
3. **PIN-Protected Read-Only LAN Pairing:** Opt-in phone/LAN viewing generates a one-time 6-digit PIN + 256-bit HMAC `HttpOnly; SameSite=Strict` cookie, enforces privacy masking, rate-limits failed PIN guesses (5 attempts / 5 minutes), and permanently restricts state-changing integrations, proxy controls, and active probes to `127.0.0.1` / `::1`.
4. **SSRF & Secret Redaction:** Active probes and Tee Proxy targets enforce `net.BlockList` checks against cloud metadata (`169.254.0.0/16`) and link-local ranges, disable HTTP redirects, and scrub `Authorization`, `x-api-key`, `Set-Cookie`, and echoed secrets before persisting metadata.

## Reporting a Vulnerability

Please open a private security advisory on GitHub rather than filing a public issue with reproducer tokens or personal telemetry logs.
