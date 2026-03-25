# VibeScan

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
- Deep Scan: $79 (all Basic + deeper analysis + email report)
- 5-Scan Pack: $99 credits
- 20-Scan Pack: $299 credits

## Structure

```text
vibescan/
├── artifacts/
│   ├── api-server/         # Express API server (port 8080)
│   │   └── src/
│   │       ├── app.ts          # CORS, auth middleware, routes
│   │       ├── routes/         # auth, scans, reports, credits
│   │       ├── middlewares/    # authMiddleware.ts
│   │       └── lib/auth.ts     # OIDC session management
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

## Auth Flow

Replit OIDC (not Clerk). The auth lib (`lib/replit-auth-web`) exports `useAuth()` with `login()` and `logout()` that redirect to `/api/login` and `/api/logout`. Sessions are stored in the `sessions` table.

## Key Env Vars

- `DATABASE_URL` — auto-provided by Replit
- `REPL_ID` — Replit OIDC client ID (auto-provided)
- `DEEPSEEK_API_KEY` — for AI scan analysis
- `STRIPE_SECRET_KEY` — for Stripe payments (must be set as secret)
- `STRIPE_WEBHOOK_SECRET` — for Stripe webhook verification (must be set as secret)

## TypeScript Project References

Every lib package has `composite: true`. Build order: run `npx tsc -b tsconfig.json` from root to emit declarations for all libs before typechecking individual artifacts.

Typecheck command: `pnpm --filter @workspace/api-server run typecheck && pnpm --filter @workspace/vibescan run typecheck`

## Task Status

- [x] Task 1: Foundation, Auth, Landing Page — COMPLETE
- [ ] Task 2: Stripe Payments & Scan Queue — PENDING
- [ ] Task 3: Scan Worker Engine & DeepSeek Report Generation — PENDING
- [ ] Task 4: Polish & Production Readiness — PENDING

## Note on Stripe Integration

The Replit Stripe connector was dismissed. Use `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` environment secrets manually. When implementing Task 2, ask the user to provide their Stripe keys via the secrets panel.
