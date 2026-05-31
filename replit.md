# Seclayer

Pay-per-scan black-box penetration testing SaaS for vibe coders. Users paste a URL, choose a tier, pay, and receive a plain-English security report powered by DeepSeek AI.

## Stack

- **Monorepo tool**: pnpm workspaces
- **Node.js version**: 24
- **Package manager**: pnpm
- **Frontend**: React + Vite (artifacts/vibescan)
- **API**: Express 5 (artifacts/api-server)
- **Auth**: Replit Auth (OIDC/PKCE) — NOT Clerk
- **Database**: Replit PostgreSQL + Drizzle ORM — NOT Supabase
- **AI**: DeepSeek AI (model: deepseek-chat, endpoint: https://api.deepseek.com/v1/chat/completions, env: DEEPSEEK_API_KEY) — NOT Claude/Anthropic
- **Queue**: pg-boss (PostgreSQL-backed job queue) — NOT Redis/BullMQ
- **Payments**: Stripe (manual keys: STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET) — Replit integration was dismissed, use env secrets
- **Validation**: Zod (zod/v4), drizzle-zod
- **API codegen**: Orval (from OpenAPI spec)
- **TypeScript version**: 5.9

## Pricing Tiers

- Basic Scan: $29 (headers + SSL + tech fingerprint)
- Deep Scan: $79 (all Basic + deeper analysis + DeepSeek AI report)
- 5-Scan Pack: $99 credits (5 Deep Scan credits)
- 20-Scan Pack: $299 credits (20 Deep Scan credits)

## Structure

```text
vibescan/
├── artifacts/
│   ├── api-server/         # Express API server (port 8080)
│   │   └── src/
│   │       ├── app.ts          # CORS, raw body, auth middleware, routes
│   │       ├── routes/         # auth, scans, reports, credits, scan/webhook
│   │       ├── middlewares/    # authMiddleware.ts
│   │       └── lib/
│   │           ├── auth.ts     # OIDC session management
│   │           ├── stripe.ts   # Stripe client + PRICE_MAP
│   │           ├── queue.ts    # pg-boss singleton + enqueueScan()
│   │           ├── scanner.ts  # HTTP security scanner (headers/TLS/CORS/cookies)
│   │           ├── deepseek.ts # DeepSeek AI client (overallRisk/priorities/quickWins)
│   │           └── worker.ts   # pg-boss worker: queued→scanning→analyzing→complete
│   └── vibescan/           # React+Vite frontend (previewPath: /)
│       └── src/
│           ├── pages/      # landing, dashboard, scan-form, report-viewer
│           ├── components/ # layout, protected-route
│           └── lib/utils.ts
├── lib/
│   ├── api-spec/           # OpenAPI spec + Orval codegen config
│   ├── api-client-react/   # Generated React Query hooks
│   ├── api-zod/            # Generated Zod schemas from OpenAPI
│   ├── db/                 # Drizzle ORM schema + DB connection
│   │   └── src/schema/
│   │       ├── auth.ts         # users, sessions tables
│   │       └── vibescan.ts     # scans, reports, credits tables
│   └── replit-auth-web/    # useAuth() hook for OIDC login/logout
└── scripts/                # Utility scripts
```

## Scan Worker Flow

1. User submits URL + tier → POST /api/scans
2. If credits available → deduct credit, mark paid, enqueue immediately
3. If no credits → create Stripe Checkout Session → redirect to Stripe
4. On `checkout.session.completed` webhook → mark paid, enqueue, mark queued
5. pg-boss worker picks up job:
   - `queued → scanning`: fetch target URL, analyze headers/TLS/cookies/CORS
   - `scanning → analyzing`: call DeepSeek AI (deep/pack tiers only)
   - `analyzing → complete`: write report to DB, mark scan complete
   - Any error → `failed` with error message
6. Dashboard polls `/api/scans/:id/status` every 3s while in-flight

## Security Checks Implemented

- HTTPS / TLS enforcement (Critical if no HTTPS)
- HTTP Strict Transport Security (HSTS)
- Content-Security-Policy (including unsafe-inline/unsafe-eval detection)
- X-Frame-Options / clickjacking protection
- X-Content-Type-Options: nosniff
- Referrer-Policy
- Permissions-Policy / Feature-Policy
- CORS wildcard origin (Access-Control-Allow-Origin: *)
- Server version disclosure
- X-Powered-By technology disclosure
- Cookie flags: Secure, HttpOnly, SameSite
- Mixed content detection (HTTP resources on HTTPS pages)
- Technology fingerprinting (15+ frameworks/servers)

## Auth Flow

Replit OIDC (not Clerk). The auth lib (`lib/replit-auth-web`) exports `useAuth()` with `login()` and `logout()` that redirect to `/api/login` and `/api/logout`. Sessions are stored in the `sessions` table.

## Key Env Vars

- `DATABASE_URL` — auto-provided by Replit
- `REPL_ID` — Replit OIDC client ID (auto-provided)
- `DEEPSEEK_API_KEY` — for AI scan analysis (user must set)
- `STRIPE_SECRET_KEY` — for Stripe payments (user must set)
- `STRIPE_WEBHOOK_SECRET` — for Stripe webhook verification (user must set)

## Webhook URL

`POST /api/scan/webhook` — Stripe webhook endpoint. Requires `express.raw()` middleware (configured in app.ts before `express.json()`).

## TypeScript Project References

Every lib package has `composite: true`. Build order: run `npx tsc -b tsconfig.json` from root to emit declarations for all libs before typechecking individual artifacts.

Typecheck command: `pnpm --filter @workspace/api-server run typecheck && pnpm --filter @workspace/vibescan run typecheck`

## Task Status

- [x] Task 1: Foundation, Auth, Landing Page — COMPLETE
- [x] Task 2: Stripe Payments & Scan Queue — COMPLETE
- [x] Task 3: Scan Worker Engine & DeepSeek Report Generation — COMPLETE
- [x] Task 4: Polish & Production Readiness — COMPLETE

## Task 4 Polish Applied

- **Security headers** on all API responses: X-Content-Type-Options, X-Frame-Options: DENY, X-XSS-Protection, Referrer-Policy, Permissions-Policy, Content-Security-Policy; HSTS in production
- **Grade badge** in dashboard Security column — colorized letter grade (A/B/C/D/F) fetched from the status polling endpoint (GET /api/scans/:id/status returns `grade`)
- **Auto-redirect to report** when scan transitions from in-progress to `complete` (via `wasPolling` ref + `setLocation`)
- **OG/SEO meta tags** in index.html (Open Graph, Twitter Card, description, theme-color)
- **.env.example** at project root with all env vars documented

## For Production

1. Set `DEEPSEEK_API_KEY` secret in the Replit Secrets panel
2. Set `STRIPE_SECRET_KEY` secret for payments
3. Set `STRIPE_WEBHOOK_SECRET` and point Stripe dashboard webhook to `https://<domain>/api-server/api/scan/webhook`
4. Set `RESEND_API_KEY` for email notifications on Deep/Pack scan completion (optional)
5. Set `APP_ORIGIN` to the production URL for email links
