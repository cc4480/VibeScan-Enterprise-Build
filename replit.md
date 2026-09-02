# Seclayer

A website and vulnerability scanning SaaS that runs black-box security scans and produces plain-English reports powered by DeepSeek AI.

## Run & Operate

| Command | Purpose |
|---|---|
| `pnpm --filter @workspace/api-server run dev` | Start API server (port 8080) |
| `pnpm --filter @workspace/vibescan run dev` | Start frontend (port 18425 via artifact router, 5000 for webview) |
| `pnpm --filter @workspace/db run db:push` | Push Drizzle schema to DB |
| `pnpm --filter @workspace/api-server run typecheck` | TypeScript check (API only) |
| `pnpm --filter @workspace/db run build && pnpm --filter @workspace/api-zod run build && pnpm --filter @workspace/api-client-react run build && pnpm --filter @workspace/replit-auth-web run build` | Build shared lib `.d.ts` files (required before full typecheck on fresh clone) |

Required env vars (secrets):
- `PORT` — the API server throws at boot without it (`8080` locally; the Vite
  dev server proxies `/api` there). Injected by the artifact router on Replit.
- `DATABASE_URL` — auto-provisioned by Replit PostgreSQL
- `DEEPSEEK_API_KEY` — fallback AI analysis key for Deep scan reports, used when a user hasn't set their own key in Settings
- `ENCRYPTION_KEY` — 32-byte base64 AES-256 key, encrypts user-supplied secrets (BYO DeepSeek key) at rest. Generate with `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`. Without it, the Settings → DeepSeek key feature returns 503.
- `RESEND_API_KEY` — Email notifications (report ready, CVE alerts)
- `STRIPE_SECRET_KEY` — Payments. Dormant: scans are free during early access,
  so nothing in the request path reaches Stripe. `DISABLE_PAYMENTS` is no
  longer read by any code — it survives only in `.replit`'s userenv.

### Local (non-Replit) development

Replit injects the above as real environment variables; running elsewhere
(e.g. a local Windows/Mac/Linux machine) needs its own PostgreSQL 16 instance
and a `.env` file (see `.env.example`) — `.env` is gitignored, never commit
it. The API server's `start` script loads it with Node's
`--env-file-if-exists=../../.env`; real environment variables take precedence,
so the file is inert on Replit. Nothing else reads it — `db:push` shells out to
drizzle-kit, which sees only the shell environment, so export `DATABASE_URL`
for that command. Verified working on Windows as of 2026-08; `lib/db/drizzle.config.ts` and
`pnpm-workspace.yaml`'s `overrides` needed fixes for Windows path separators
and previously-stripped `win32-*-msvc` optional binaries (`rollup`,
`@tailwindcss/oxide`, `lightningcss`) respectively — both now resolve
correctly cross-platform.

## Deploying (non-Replit)

Production runs on Docker Compose — see `DEPLOY.md`. `Dockerfile`,
`compose.yaml` and `deploy/Caddyfile` are the deployment surface; `.replit` and
the `.replit-artifact/` configs are for Replit **development** only and are not
used in production.

Note `APP_ORIGIN` is a build arg, not just an env var: `vite.config.ts` bakes it
into index.html, the sitemap and robots.txt at build time, so a domain change
needs a rebuilt image.

## Stack

- **Frontend**: React 19 + Vite 7, Tailwind CSS, Wouter (routing), TanStack Query
- **Backend**: Express 5, TypeScript (ESM), pino logging, pg-boss job queue
- **Database**: PostgreSQL 16 via Drizzle ORM
- **Build**: pnpm workspaces monorepo, esbuild for API bundling
- **Runtime**: Node 24, NixOS (stable-25_05)

## Where things live

```
artifacts/
  api-server/      — Express API (src/routes, src/lib, src/middlewares)
  vibescan/        — React frontend (src/pages, src/components)
  mockup-sandbox/  — Design component preview server
lib/
  api-client-react/ — Generated API client + custom fetch
  api-zod/          — Shared Zod schemas (source of truth for API contracts)
  db/               — Drizzle schema + migrations (schema at lib/db/src/schema/)
  replit-auth-web/  — Auth utilities (not used — app uses UUID tokens)
```

## Architecture decisions

- **Artifact router handles external routing**: The Replit artifact router (`REPLIT_ARTIFACT_ROUTER`) proxies `/api` to Express (port 8080) and `/` to Vite (port 18425). The `Start application` webview workflow runs Vite on port 5000 for the Replit preview pane.
- **No login required**: Auth is a UUID token auto-generated in `localStorage` (`vibescan_client_token`). The `authMiddleware` reads it from the `Authorization: Bearer` header.
- **Graceful degradation**: All three external services (DeepSeek, Resend, Stripe) check for their env var and skip with a warning if not set — the app remains fully functional.
- **Payments dormant**: scans are free during early access, so the Stripe route and webhook are unreachable from the scan flow. Reviving billing means restoring the checkout branch in `routes/scans.ts`, not just setting `STRIPE_SECRET_KEY`.
- **Job queue**: pg-boss runs inside the API server process, handling async scan jobs and the EOL/CVE refresh scheduler.

## Product

Everything is free during early access — `POST /scans` queues immediately and
returns `checkoutUrl: null`; the `pack_5`/`pack_20` tiers are rejected at the
route. The tier column and Stripe plumbing remain for a future revival.

- **Basic scan**: headers, SSL/TLS, DNS, tech fingerprint
- **Deep scan**: adds JS secret scanning, path traversal, and the site crawler,
  with a DeepSeek AI report
- **Monitor**: Continuous monitoring with weekly rescans and CVE-triggered alerts via email
- **Reports**: Graded A–F with CVSS scores, remediation steps, and paste-ready AI fix prompt
- **Settings**: users can add their own DeepSeek API key (`/settings`) to use their own account's credits for Deep scan AI analysis instead of the shared server key — encrypted at rest, never re-displayed after saving

## User preferences

- Keep `DISABLE_PAYMENTS=true` in development `.replit` userenv

## Scanner false-positive prevention

The product differentiates on signal quality — a wolf-crying scanner trains
non-technical users to ignore real findings. These rules apply to every new
probe or pattern added to the scanner:

- **SPA / multi-tenant catch-all suppression** (`spaCatchAll.ts`, shared by
  the path-probe engine and the API-docs probe): before path probing, hit a
  random nonexistent path. If it returns HTTP 200, fingerprint the response
  (body length + `<title>`). Any subsequent probe result within 3% body
  length or with the same title is suppressed as a catch-all false positive,
  not a real finding. Without this, any SPA with client-side routing (or a
  multi-tenant platform like GitHub, where an arbitrary path segment renders
  a normal 200 page) false-positives on nearly every probed path.
- **GraphQL confirmation**: requires `data.__typename` to be a string
  (unique to GraphQL — no REST API returns this) or an `errors[].locations`
  array (GraphQL-spec-only field). Paths `/api` and `/query` are excluded —
  too generic, they'd match any REST API.
- **Session vs. non-session cookies**: cookies are classified by name
  pattern (`session`, `token`, `jwt`, `sid`, `PHPSESSID`, etc.) before
  flagging missing Secure/HttpOnly/SameSite flags — a non-session cookie
  (UI-state flag, analytics ID) missing these flags is scored low/info, not
  high/medium, since there's no session to actually hijack.
- **Key/token classification** (jsScanner + Supabase/Firebase probes):
  `pk_live_`/`pk_test_` (Stripe), `sb_publishable_*` (Supabase),
  Mapbox `pk.ey…`, Sentry DSNs, and Firebase `AIza…` keys are public-by-design
  and never flagged on their own — only the resulting data exposure (e.g. an
  open Supabase table) is a finding. `sk_live_`, `sb_secret_*`, Mapbox
  `sk.ey…`, and Sentry auth tokens are flagged Critical/High immediately.
- **Entropy validation**: generic password/secret-key patterns require
  Shannon entropy ≥2.5–3.0 bits/char (`shannonEntropy()` in `jsScanner.ts`)
  before matching — placeholders and repeating strings score below that.
- **Confidence is numeric (0–100)**: ≥85 means directly observed/confirmed
  (a real HTTP response returned the data); never emit ≥85 for a pattern-only
  match with no behavioral confirmation.
- **Structural markers over keyword matches**: e.g. phpMyAdmin/Adminer
  require an actual login-form field name, not just the tool's name
  appearing on the page (a GitHub org page for the real phpMyAdmin project
  mentions "phpMyAdmin" too). `crossdomain.xml` is only flagged for genuine
  wildcard access, not mere presence of the file.

## SSRF guard (scan targets and webhooks)

The scanner fetches user-supplied URLs from inside our own network and quotes
responses back in report `evidence`, so an unguarded target is an open proxy
into the deployment. `ssrfGuard.ts` is the single implementation — do not add a
second copy:

- `checkScanTarget(url)` — http/https + public-host check, called by
  `POST /scans` and `POST /monitor/subscriptions` before a job is queued, and
  again at the top of `runScan()` so no internal caller bypasses it.
- `checkHostname(host)` — host-only check. `webhook.ts` layers its https-only
  rule on top (a token must not leave in cleartext); scan targets allow http
  because a plaintext target is itself a finding.
- Blocks loopback, RFC 1918, link-local/IMDS (169.254.169.254), CGNAT,
  IPv6 ULA/link-local, IPv4-mapped IPv6, `.local`/`.internal`, and public
  hostnames whose A/AAAA records point anywhere internal. **Fails closed** on
  DNS failure.
- `runScan()` re-checks after redirects: `redirect: "follow"` means a public
  host can bounce the scanner to an internal one, and every probe downstream
  runs against `finalUrl`.
- Not covered: DNS rebinding between check and connect. Closing that needs
  connection-level pinning of the resolved IP.

## Rate limiting and client identity

Client tokens are self-minted UUIDs (`authMiddleware` auto-creates a user from
any valid v4), so per-user limits are unenforceable — anything that needs to
resist abuse counts against the client address instead.

- `clientIp.ts` owns address resolution. Never read `x-forwarded-for` directly:
  clients set it. `configureTrustProxy()` applies `TRUST_PROXY` (hop count;
  default 1 in production, 0 in dev) and everything else uses `req.ip`.
- `rateLimit.ts` is a sliding-window limiter, in-process. Applied to
  `POST /scans`, `POST /monitor/subscriptions` and the manual monitor rescan.
  Blocked requests are deliberately not counted, or a caller hammering a blocked
  endpoint would push their own retry time out indefinitely.
- The guarantee holds only when the app is unreachable except through the proxy.
  `compose.yaml` gives `app` no published port for exactly this reason, and
  `deploy/Caddyfile` overwrites `X-Forwarded-For` rather than appending.
- Adding a middleware to a route widens `req.params` to `string | string[]` in
  Express's types — hence the `String(req.params.id)` in the monitor rescan route.

## Gotchas

- **Shared libs must be built before typecheck on a fresh clone** — `lib/db`, `lib/api-zod`, `lib/api-client-react`, and `lib/replit-auth-web` all use TypeScript project references and must have their `dist/` emitted first. Each has a `build` script (`tsc -p tsconfig.json`). The `typecheck` workflow does this automatically.
- API server build step is part of `pnpm run dev` (builds then starts) — cold starts take ~5s
- `NODE_TLS_REJECT_UNAUTHORIZED=0` is set in dev userenv (Replit internal TLS) — never set this in production
- Vite runs on port 18425 (artifact router) AND port 5000 (webview) simultaneously — both are separate workflow instances
- The artifact router config lives in `artifacts/*/replit-artifact/artifact.toml` — do not delete these files
- **Avoid runtime (value) imports from `scanner.ts` in modules with standalone unit tests** — `scanner.ts` transitively imports `@workspace/db`, which throws at import time if `DATABASE_URL` isn't set. `crawler.test.ts` doesn't set it, so a value import (e.g. importing a helper function) breaks that whole test file even though the function itself doesn't touch the DB. `import type { ... }` is erased at compile time and is safe; small pure-logic helpers shared between the two are duplicated instead (see `INFRA_COOKIE_NAMES` / `SESSION_COOKIE_PATTERN` — both intentionally copy-pasted between `scanner.ts` and `crawler.ts` with a "must match" comment, rather than imported)
- **Mocking `fetch` in Vitest**: use `vi.stubGlobal("fetch", vi.fn())` + `vi.unstubAllGlobals()` in `afterEach` — not `vi.spyOn(globalThis, "fetch")`, which wraps the existing property while the module under test closed over its own reference to `globalThis.fetch` at import time, so the spy silently doesn't apply. For network-failure tests use `vi.mocked(fetch).mockRejectedValue(new Error(...))`, not a synchronous throw in `mockImplementation` (it propagates out of the test instead of being caught by the module's try/catch). `fetch`'s first arg is `string | URL | Request` — convert with `String(input)`, not `input.toString()` (throws if `input` is undefined).

## Pointers

- DB schema: `lib/db/src/schema/` (`auth.ts`, `vibescan.ts`, re-exported from `index.ts`)
- API routes: `artifacts/api-server/src/routes/index.ts`
- Scan engine: `artifacts/api-server/src/lib/scanner.ts`
- AI analysis: `artifacts/api-server/src/lib/deepseek.ts`
- User-supplied secret encryption: `artifacts/api-server/src/lib/crypto.ts`
- BYO DeepSeek key settings: `artifacts/api-server/src/routes/settings.ts`, `artifacts/vibescan/src/pages/settings.tsx`
- SPA/multi-tenant catch-all detection (shared by the path-probe engine and the API-docs probe): `artifacts/api-server/src/lib/spaCatchAll.ts`
- API contract source of truth: `lib/api-spec/openapi.yaml` — after editing, regenerate with `pnpm --filter @workspace/api-spec run codegen`, then rebuild `lib/api-zod` and `lib/api-client-react` (their `dist/*.d.ts` is what typecheck actually reads, not `src` directly)
- Continuous Monitoring v2 schema: `monitor_score_history` (per-scan grade/riskScore snapshot), `monitor_regressions` (checks newly failing vs. the previous scan), `cert_expiry_alerts` (dedup table). Rescan cadence is risk-adaptive — `computeNextScanAt(grade)` in `monitorScheduler.ts` schedules A-grade sites every 14 days, B/C every 7, D/F every 3; a 6-hour sweep picks up any subscription past its `nextScanAt`. Outbound webhooks (`webhook.ts`) fire Slack-compatible JSON for `cve_alert`, `regression_detected`, `cert_expiry`, `scan_complete` with a single retry.
