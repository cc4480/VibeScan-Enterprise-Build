# SecScan

A website and vulnerability scanning SaaS that runs black-box security scans and produces plain-English reports powered by DeepSeek AI.

## Run & Operate

| Command | Purpose |
|---|---|
| `pnpm --filter @workspace/api-server run dev` | Start API server (port 8080) |
| `pnpm --filter @workspace/vibescan run dev` | Start frontend (port 18425) |
| `pnpm --filter @workspace/db run db:push` | Push Drizzle schema to DB |
| `pnpm --filter @workspace/api-server run typecheck` | TypeScript check (API only) |
| `pnpm --filter @workspace/db run build && pnpm --filter @workspace/api-zod run build && pnpm --filter @workspace/api-client-react run build` | Build shared lib `.d.ts` files (required before full typecheck on fresh clone) |

Required env vars (secrets):
- `PORT` — the API server throws at boot without it (`8080` locally; the Vite
  dev server proxies `/api` there).
- `DATABASE_URL` — PostgreSQL connection string
- `DEEPSEEK_API_KEY` — the AI analysis key. `callDeepSeek` reads this and only this; without it the scan completes and the report simply carries no AI section.
- `ENCRYPTION_KEY` — 32-byte base64 AES-256-GCM key. Seals **scan credentials** at rest (`lib/crypto.ts`, used by `lib/scanCredentials.ts`); the worker nulls the column once the scan ends, on both the success and failure paths. Generate with `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`. Without it, credentialed scanning is unavailable; anonymous scanning is unaffected.
- `RESEND_API_KEY` — Email notifications (report ready, CVE alerts)
- `STRIPE_SECRET_KEY` + `STRIPE_WEBHOOK_SECRET` — payments; set both or neither (see `deploy/PAYMENTS-GO-LIVE.md`)

### Local development

A local Windows/Mac/Linux machine needs its own PostgreSQL 16 instance
and a `.env` file (see `.env.example`) — `.env` is gitignored, never commit
it. The API server's `start` script loads it with Node's
`--env-file-if-exists=../../.env`; real environment variables take precedence,
so the file is inert where the platform injects its own. Nothing else reads it — `db:push` shells out to
drizzle-kit, which sees only the shell environment, so export `DATABASE_URL`
for that command. Verified working on Windows as of 2026-08; `lib/db/drizzle.config.ts` and
`pnpm-workspace.yaml`'s `overrides` needed fixes for Windows path separators
and previously-stripped `win32-*-msvc` optional binaries (`rollup`,
`@tailwindcss/oxide`, `lightningcss`) respectively — both now resolve
correctly cross-platform.

## Deploying

Production runs on Railway behind Cloudflare (`deploy/railway/README.md`); the
self-hosted path is Docker Compose (`DOCKER.md`, `deploy/README.md`). `Dockerfile`,
`docker-compose.yml` and `deploy/Caddyfile` are the deployment surface.

Note `APP_ORIGIN` is a build arg, not just an env var: `vite.config.ts` bakes it
into index.html, the sitemap and robots.txt at build time, so a domain change
needs a rebuilt image.

## Stack

- **Frontend**: React 19 + Vite 7, Tailwind CSS, Wouter (routing), TanStack Query
- **Backend**: Express 5, TypeScript (ESM), pino logging, pg-boss job queue
- **Database**: PostgreSQL 16 via Drizzle ORM
- **Build**: pnpm workspaces monorepo, esbuild for API bundling
- **Runtime**: Node 24

## Where things live

```
artifacts/
  api-server/      — Express API (src/routes, src/lib, src/middlewares)
  vibescan/        — React frontend (src/pages, src/components)
lib/
  api-client-react/ — Generated API client + custom fetch
  api-zod/          — Shared Zod schemas (source of truth for API contracts)
  db/               — Drizzle schema + migrations (schema at lib/db/src/schema/)
```

## Architecture decisions

- **Dev routing**: the Vite dev server (port 18425) proxies `/api` to Express (port 8080). In production Express serves the built frontend itself.
- **Accounts**: sign-up needs an emailed code (`routes/accountSignup.ts`); sessions are cookies. The old anonymous `Authorization: Bearer <user id>` path only honours rows that already exist and can be closed (`LEGACY_BEARER_SUNSET`, `ALLOW_LEGACY_ANONYMOUS_BEARER`; see `deploy/railway/README.md`).
- **Sign-in lockout (accepted trade-off)**: ten wrong passwords for an email address lock that address out of sign-in for 15 minutes, from any IP (`routes/accountSession.ts`; `MAX_ATTEMPTS` and `WINDOW_MS` in `accountShared.ts`). The lock is keyed on the submitted email, not the client, because a per-IP limit alone lets guesses spread across addresses and still reach one account. The cost: an attacker can keep a victim out of their own account for 15 minutes by guessing wrong. We accept that. The lock is short, the reply is the same whether or not the account exists, and the per-IP limit still applies on top. Do not change this without a replacement for the per-account guard.
- **Graceful degradation**: All three external services (DeepSeek, Resend, Stripe) check for their env var and skip with a warning if not set — the app remains fully functional.
- **Payments**: on exactly when `STRIPE_SECRET_KEY` (and `STRIPE_WEBHOOK_SECRET`) are set. Checkout sells one plan, SecScan Unlimited ($19/month, unlimited scans, 5 sites); credit packs are withdrawn from sale (still credited if an old checkout is paid); the webhook applies each Stripe event exactly once (see `lib/billing.ts`). Setup: `deploy/PAYMENTS-GO-LIVE.md`.
- **Two processes, one image**: `src/index.ts` (the `web` tier) serves the API and frontend and only enqueues; `src/secscan.ts` runs the pg-boss worker, the monitor scheduler, the EOL/CVE refresh, and owns Chromium. The only channel between them is the `scan-job` queue in Postgres. Do not add Playwright imports to anything reachable from `index.ts`.

## Product

3 free scans per account per calendar month (UTC); then the plan's included scans, then credits.
`POST /scans` spends in that order and records the source on `scans.paid_with`;
a scan that fails later is refunded to it. The `tier` column is legacy.

- **One scan, not tiers**: `routes/scans.ts` pins every run to `tier = "deep"`.
  What varies is *access* — domain verification unlocks active probing,
  credentials unlock the surface behind the login, a second account unlocks A01,
  and `OOB_BASE_URL` unlocks A10. `basic` survives only so older rows stay readable.
- **Monitor**: Continuous monitoring with weekly rescans and CVE-triggered alerts via email
- **Reports**: Graded A–F with CVSS scores, remediation steps, and paste-ready AI fix prompt

## User preferences


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
  Shannon entropy ≥2.5–3.0 bits/char (`shannonEntropy()` in `secretPlaceholders.ts`)
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
  `POST /scans` and `POST /monitor/subscriptions` before a job is queued.
- `lib/http.ts` re-checks with `checkUrlSafe` on **every** request it issues and
  on every redirect hop, so no internal caller can bypass the guard by reaching
  a probe directly. That is where the defence-in-depth actually lives — not at
  the top of `runScan()`, which does not call it. (`scanner.ts` imported
  `checkScanTarget`/`checkHostname` without ever calling them; the dead imports
  are gone.)
- `checkHostname(host)` — host-only check. `webhook.ts` layers its https-only
  rule on top (a token must not leave in cleartext); scan targets allow http
  because a plaintext target is itself a finding.
- Blocks loopback, RFC 1918, link-local/IMDS (169.254.169.254), CGNAT,
  IPv6 ULA/link-local, IPv4-mapped IPv6, `.local`/`.internal`, and public
  hostnames whose A/AAAA records point anywhere internal. **Fails closed** on
  DNS failure.
- Redirects are re-checked per hop in `lib/http.ts`: `redirect: "follow"` means
  a public host can bounce the scanner to an internal one, and every probe
  downstream runs against `finalUrl`.
- **DNS rebinding** (a name that answers a public address to the check and a
  private one to the connection). The check resolves a name and judges the answer,
  so each connection that carries traffic also has to vet the address it opens to.
  `pinnedDispatcher.ts` does that: its `dns.lookup` refuses any name with a private
  answer and hands the socket the address it judged. Pinned:
  - every request the scanner makes through `lib/http.ts` (`scanFetch`, which the
    probes use), including each redirect hop;
  - the uptime checks (`monitorPulse.ts`) and the certificate check
    (`monitorPulseCert.ts`);
  - the TLS configuration check (`tlsCheck.ts`), the mail-server TLS probe
    (`mailTlsProbe.ts`, which takes no opt-out) and the vetted HTTP proxy
    (`vettedProxy.ts`);
  - webhooks and domain-verification fetches, through `strictDispatcher`, which
    refuses private addresses even when `ALLOW_PRIVATE_SCAN_TARGETS` is set.

  Not pinned:
  - Browser requests (`browserGuard.ts`): each request and redirect is checked by
    name, but Chromium resolves the name again. WebSocket connections from the
    page are checked the same way. `browserGuard.ts` records this as a known limit.
  - Direct `fetch` calls in the Supabase, Firebase and BaaS probes
    (`supabase-probes-core.ts`, `firebase-probes.ts`, `baasDepth.ts`). Their hosts
    are fixed vendor names (`<project>.supabase.co`, Google's Firestore API), so no
    attacker-chosen address is reached, but the connection is not pinned.

## Rate limiting and client identity

Client tokens are self-minted UUIDs. `authMiddleware` does not create a user
from an unknown UUID: a bearer token that matches no existing row is treated as
unauthenticated. Existing anonymous rows are still honoured, and the legacy bearer
path stays open by default unless `ALLOW_LEGACY_ANONYMOUS_BEARER=false` or
`LEGACY_BEARER_SUNSET=<ISO date>` closes it (`lib/legacyBearer.ts`). A user id is
not a secret, so per-user limits are still unenforceable — anything that needs to
resist abuse counts against the client address instead.

- `clientIp.ts` owns address resolution. Never read `x-forwarded-for` directly:
  clients set it. `configureTrustProxy()` applies `TRUST_PROXY` (hop count;
  default 1 in production, 0 in dev) and everything else uses `req.ip`.
- `rateLimit.ts` is a sliding-window limiter, in-process. Applied to
  `POST /scans`, `POST /monitor/subscriptions` and the manual monitor rescan.
  Blocked requests are deliberately not counted, or a caller hammering a blocked
  endpoint would push their own retry time out indefinitely.
- The guarantee holds only when the app is unreachable except through the proxy.
  `docker-compose.yml` gives `app` no published port for exactly this reason, and
  `deploy/Caddyfile` overwrites `X-Forwarded-For` rather than appending.
- Adding a middleware to a route widens `req.params` to `string | string[]` in
  Express's types — hence the `String(req.params.id)` in the monitor rescan route.

## Migrations

Migrations live in `lib/db/migrations/` (Drizzle).

- A migration that changes a column or table a deployed version still reads must
  be expand/contract: add the new column or table first, have the code write both
  and read the new one, backfill, and drop the old one only in a later release,
  once no running code reads it.
- A migration that drops a column or a table breaks rollback to any earlier code
  that still reads it. Rolling back the code does not roll back the schema.
- Past migrations are not edited. One that has run anywhere is history; a
  correction is a new migration.
- Rollback implies a forward fix. The answer to a bad migration is a new migration
  or a code fix, not reverting the file.

The trade-off is visible in `0026_share_token_hash.sql`. It hashes report share
tokens and drops the plaintext `token` column in the same migration. Existing
links keep working, because each hash is computed from the current token before the
column goes, but code from before that release, which reads `report_shares.token`,
cannot run against this schema. Splitting it into expand (add `token_hash`, backfill)
and contract (drop `token`) releases would have kept rollback open.

## Gotchas

- **Shared libs must be built before typecheck on a fresh clone** — `lib/db`, `lib/api-zod` and `lib/api-client-react` all use TypeScript project references and must have their `dist/` emitted first. Each has a `build` script (`tsc -p tsconfig.json`). The `typecheck` workflow does this automatically.
- API server build step is part of `pnpm run dev` (builds then starts) — cold starts take ~5s
- **Avoid runtime (value) imports from `scanner.ts` in modules with standalone unit tests** — `scanner.ts` transitively imports `@workspace/db`, which throws at import time if `DATABASE_URL` isn't set. `crawler.test.ts` doesn't set it, so a value import (e.g. importing a helper function) breaks that whole test file even though the function itself doesn't touch the DB. `import type { ... }` is erased at compile time and is safe; small pure-logic helpers shared between the two are duplicated instead (see `INFRA_COOKIE_NAMES` / `SESSION_COOKIE_PATTERN` — both intentionally copy-pasted between `scanner.ts` and `crawler.ts` with a "must match" comment, rather than imported)
- **Mocking `fetch` in Vitest**: use `vi.stubGlobal("fetch", vi.fn())` + `vi.unstubAllGlobals()` in `afterEach` — not `vi.spyOn(globalThis, "fetch")`, which wraps the existing property while the module under test closed over its own reference to `globalThis.fetch` at import time, so the spy silently doesn't apply. For network-failure tests use `vi.mocked(fetch).mockRejectedValue(new Error(...))`, not a synchronous throw in `mockImplementation` (it propagates out of the test instead of being caught by the module's try/catch). `fetch`'s first arg is `string | URL | Request` — convert with `String(input)`, not `input.toString()` (throws if `input` is undefined).

## Pointers

- DB schema: `lib/db/src/schema/` (`auth.ts`, `vibescan.ts`, re-exported from `index.ts`)
- API routes: `artifacts/api-server/src/routes/index.ts`
- Scan engine: `artifacts/api-server/src/lib/scanner.ts`
- AI analysis: `artifacts/api-server/src/lib/deepseek.ts`
- Scan-credential encryption: `artifacts/api-server/src/lib/crypto.ts` (AES-256-GCM),
  used only by `lib/scanCredentials.ts`. There is no BYO-DeepSeek-key feature in
  this repo and no `routes/settings.ts` — that belongs to **Seclayer**
  (`seclayer.io2026`, `server/routes/account.ts`). Prose gets ported between the
  two repos by hand; check the code before trusting a pointer that crosses over.
- SPA/multi-tenant catch-all detection (shared by the path-probe engine and the API-docs probe): `artifacts/api-server/src/lib/spaCatchAll.ts`
- API contract source of truth: `lib/api-spec/openapi.yaml` — after editing, regenerate with `pnpm --filter @workspace/api-spec run codegen`, then rebuild `lib/api-zod` and `lib/api-client-react` (their `dist/*.d.ts` is what typecheck actually reads, not `src` directly)
- Continuous Monitoring v2 schema: `monitor_score_history` (per-scan grade/riskScore snapshot), `monitor_regressions` (checks newly failing vs. the previous scan), `cert_expiry_alerts` (dedup table). Rescan cadence is risk-adaptive — `computeNextScanAt(grade)` in `monitorScheduler.ts` schedules A-grade sites every 14 days, B/C every 7, D/F every 3; a 6-hour sweep picks up any subscription past its `nextScanAt`. Outbound webhooks (`webhook.ts`) fire Slack-compatible JSON for `cve_alert`, `regression_detected`, `cert_expiry`, `scan_complete` with a single retry.
