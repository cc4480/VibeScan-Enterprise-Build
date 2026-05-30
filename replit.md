# VibeScan

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
- `DEEPSEEK_API_KEY` — AI analysis in Deep scan reports
- `RESEND_API_KEY` — Email notifications (report ready, CVE alerts)
- `STRIPE_SECRET_KEY` — Payments (set `DISABLE_PAYMENTS=true` in dev to skip)

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
  db/               — Drizzle schema + migrations (schema at lib/db/src/schema.ts)
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

## User preferences

- Keep `DISABLE_PAYMENTS=true` in development `.replit` userenv

## Gotchas

- **Shared libs must be built before typecheck on a fresh clone** — `lib/db`, `lib/api-zod`, `lib/api-client-react`, and `lib/replit-auth-web` all use TypeScript project references and must have their `dist/` emitted first. Each has a `build` script (`tsc -p tsconfig.json`). The `typecheck` workflow does this automatically.
- API server build step is part of `pnpm run dev` (builds then starts) — cold starts take ~5s
- `NODE_TLS_REJECT_UNAUTHORIZED=0` is set in dev userenv (Replit internal TLS) — never set this in production
- Vite runs on port 18425 (artifact router) AND port 5000 (webview) simultaneously — both are separate workflow instances
- The artifact router config lives in `artifacts/*/replit-artifact/artifact.toml` — do not delete these files

## Pointers

- DB schema: `lib/db/src/schema.ts`
- API routes: `artifacts/api-server/src/routes/index.ts`
- Scan engine: `artifacts/api-server/src/lib/scanner.ts`
- AI analysis: `artifacts/api-server/src/lib/deepseek.ts`
