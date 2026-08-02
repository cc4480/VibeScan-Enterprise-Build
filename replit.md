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
- `DATABASE_URL` — auto-provisioned by Replit PostgreSQL
- `DEEPSEEK_API_KEY` — fallback AI analysis key for Deep scan reports, used when a user hasn't set their own key in Settings
- `ENCRYPTION_KEY` — 32-byte base64 AES-256 key, encrypts user-supplied secrets (BYO DeepSeek key) at rest. Generate with `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`. Without it, the Settings → DeepSeek key feature returns 503.
- `RESEND_API_KEY` — Email notifications (report ready, CVE alerts)
- `STRIPE_SECRET_KEY` — Payments (set `DISABLE_PAYMENTS=true` in dev to skip)

### Local (non-Replit) development

Replit injects the above as real environment variables; running elsewhere
(e.g. a local Windows/Mac/Linux machine) needs its own PostgreSQL 16 instance
and a `.env` file (see `.env.example`) — `.env` is gitignored, never commit
it. Verified working on Windows as of 2026-08; `lib/db/drizzle.config.ts` and
`pnpm-workspace.yaml`'s `overrides` needed fixes for Windows path separators
and previously-stripped `win32-*-msvc` optional binaries (`rollup`,
`@tailwindcss/oxide`, `lightningcss`) respectively — both now resolve
correctly cross-platform.

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
- **Payments gated**: `DISABLE_PAYMENTS=true` disables Stripe in development. Set to `false` in production after configuring `STRIPE_SECRET_KEY`.
- **Job queue**: pg-boss runs inside the API server process, handling async scan jobs and the EOL/CVE refresh scheduler.

## Product

- **Free tier**: Basic black-box scan (headers, SSL/TLS, tech fingerprint)
- **Paid tiers**: Deep scan with DeepSeek AI report, scan credit packs (5 or 20)
- **Monitor**: Continuous monitoring with weekly rescans and CVE-triggered alerts via email
- **Reports**: Graded A–F with CVSS scores, remediation steps, and paste-ready AI fix prompt
- **Settings**: users can add their own DeepSeek API key (`/settings`) to use their own account's credits for Deep scan AI analysis instead of the shared server key — encrypted at rest, never re-displayed after saving

## User preferences

- Keep `DISABLE_PAYMENTS=true` in development `.replit` userenv

## Gotchas

- **Shared libs must be built before typecheck on a fresh clone** — `lib/db`, `lib/api-zod`, `lib/api-client-react`, and `lib/replit-auth-web` all use TypeScript project references and must have their `dist/` emitted first. Each has a `build` script (`tsc -p tsconfig.json`). The `typecheck` workflow does this automatically.
- API server build step is part of `pnpm run dev` (builds then starts) — cold starts take ~5s
- `NODE_TLS_REJECT_UNAUTHORIZED=0` is set in dev userenv (Replit internal TLS) — never set this in production
- Vite runs on port 18425 (artifact router) AND port 5000 (webview) simultaneously — both are separate workflow instances
- The artifact router config lives in `artifacts/*/replit-artifact/artifact.toml` — do not delete these files
- **Avoid runtime (value) imports from `scanner.ts` in modules with standalone unit tests** — `scanner.ts` transitively imports `@workspace/db`, which throws at import time if `DATABASE_URL` isn't set. `crawler.test.ts` doesn't set it, so a value import (e.g. importing a helper function) breaks that whole test file even though the function itself doesn't touch the DB. `import type { ... }` is erased at compile time and is safe; small pure-logic helpers shared between the two are duplicated instead (see `INFRA_COOKIE_NAMES` / `SESSION_COOKIE_PATTERN` — both intentionally copy-pasted between `scanner.ts` and `crawler.ts` with a "must match" comment, rather than imported)

## Pointers

- DB schema: `lib/db/src/schema/` (`auth.ts`, `vibescan.ts`, re-exported from `index.ts`)
- API routes: `artifacts/api-server/src/routes/index.ts`
- Scan engine: `artifacts/api-server/src/lib/scanner.ts`
- AI analysis: `artifacts/api-server/src/lib/deepseek.ts`
- User-supplied secret encryption: `artifacts/api-server/src/lib/crypto.ts`
- BYO DeepSeek key settings: `artifacts/api-server/src/routes/settings.ts`, `artifacts/vibescan/src/pages/settings.tsx`
- SPA/multi-tenant catch-all detection (shared by the path-probe engine and the API-docs probe): `artifacts/api-server/src/lib/spaCatchAll.ts`
- API contract source of truth: `lib/api-spec/openapi.yaml` — after editing, regenerate with `pnpm --filter @workspace/api-spec run codegen`, then rebuild `lib/api-zod` and `lib/api-client-react` (their `dist/*.d.ts` is what typecheck actually reads, not `src` directly)
