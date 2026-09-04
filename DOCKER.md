# Running Seclayer with Docker

The stack is three containers:

| Service | What it is | Port | Chromium |
| --- | --- | --- | --- |
| `seclayer` | Express API + the pre-built SPA | published | no |
| `secscan` | the scanner worker | none | yes |
| `db` | Postgres 16 | none | — |

`seclayer` serves the frontend itself in production, so there is no separate web
container. It never runs a scan: it writes the job to the pg-boss `scan-job`
queue in Postgres and `secscan` picks it up. That queue is the only runtime
coupling between the two, so either can be restarted or redeployed alone, and
`secscan` can be scaled independently:

```bash
docker compose --env-file .env.docker up -d --scale secscan=3
```

Because nothing reachable from the web entrypoint imports Playwright, only the
`secscan` image carries Chromium.

## Quick start

```bash
cp .env.docker.example .env.docker      # fill it in — see the notes in the file
docker compose --env-file .env.docker --profile setup run --rm --build db-migrate
docker compose --env-file .env.docker up -d --build
```

Then open `http://localhost:8090` (or whatever `APP_PORT` you set).

`db-migrate` applies the committed migrations in `lib/db/migrations`, in order,
exactly once each. Run it before first boot and again after any schema change.
It is safe to re-run — applying nothing is the normal outcome. It runs from the
*builder* stage because the migration tooling is a dev dependency and is
deliberately absent from the slim runtime images.

**Upgrading a database that was built with the old `db:push` flow** — it already
has the tables migration `0000` creates, so the migrator would stop on
`relation "auth_tokens" already exists`. Record the migration as applied without
running it, once, and only when the live schema matches the current schema files:

```bash
docker compose --env-file .env.docker --profile baseline run --rm --build db-baseline
```

Then `db-migrate` behaves normally from that point on. On a fresh database, skip
this entirely.

### Changing the schema

Edit the schema files, then generate the SQL and commit it alongside the change:

```bash
DATABASE_URL=... pnpm --filter @workspace/db run db:generate
```

Read the generated file before committing it. `db:push` still exists for local
iteration, but it diffs against the live database and applies what it infers —
including drops — so it must not be pointed at production.

**`--build` on that first command is not optional.** `docker compose run`
reuses an existing image rather than rebuilding it, so after a schema change it
will happily apply the *previous* schema and report "Changes applied". The app
then starts against a database missing its newest columns and fails at runtime
with `column "…" does not exist` — a failure that looks like an application bug
and is not one.

## Required configuration

Everything is documented inline in `.env.docker.example`. The three that have
no safe default:

| Variable | Why |
| --- | --- |
| `POSTGRES_PASSWORD` | Real credential, even though the db is not published. |
| `ENCRYPTION_KEY` | 32 random bytes, base64. Encrypts user-supplied secrets. **Changing it makes every previously stored user secret undecryptable.** |
| `APP_ORIGIN` | Your public URL, no trailing slash. Used to build links in email. |

`DEEPSEEK_API_KEY` is not strictly required to boot, but without it Deep scans
complete while their AI analysis fails with a 401, so reports arrive missing
their plain-English write-up — the thing the tier is sold on.

### Which service reads what

`docker-compose.yml` passes each service only the variables its own bundle
reads, so a value set on the wrong one is silently ignored:

| Variable | seclayer | secscan |
| --- | :---: | :---: |
| `DATABASE_URL`, `ENCRYPTION_KEY`, `APP_ORIGIN`, `RESEND_API_KEY` | ✓ | ✓ |
| `PORT`, `TRUST_PROXY`, `CORS_EXTRA_ORIGINS`, `STRIPE_*` | ✓ | |
| `DEEPSEEK_API_KEY`, `OOB_BASE_URL` | | ✓ |

Two consequences worth knowing before you debug either one:

- **`ENCRYPTION_KEY` must be identical on both.** The web tier encrypts scan
  credentials when the scan is created; the scanner decrypts them when it runs.
  A mismatch does not fail at startup — it fails at scan time, on the
  authenticated scans that need it most.
- **`OOB_BASE_URL` is set on `secscan` but must point at `seclayer`.** The
  scanner plants the callback URL; the web tier serves the `/api/oob` route the
  target calls back to.

## Deploying to a VPS (IONOS)

1. **DNS** — point an `A` record for your domain at the server's IPv4 address
   (and `AAAA` for IPv6 if you have one).

2. **Server prep** — install Docker Engine and the compose plugin, then clone
   the repo and create `.env.docker` with `APP_ORIGIN` and `CORS_EXTRA_ORIGINS`
   set to `https://your-domain`.

3. **Start it** — run the same three commands as above. `docker-compose.yml`
   already binds the published port to `127.0.0.1` only, so the app is
   reachable exclusively through the proxy you set up in the next step — no
   edit needed here.

4. **TLS + reverse proxy** — terminate TLS in front of the app. Caddy is the
   least work because it obtains and renews certificates automatically:

   ```caddyfile
   your-domain.example {
       reverse_proxy 127.0.0.1:8090
   }
   ```

   Caddy sets `X-Forwarded-Proto` and `X-Forwarded-For` by default; nginx needs
   them added explicitly.

### Before you take real traffic

- **`TRUST_PROXY` must match your proxy layout.** Behind a TLS-terminating
  proxy Express otherwise sees a plain HTTP hop, so `req.protocol` is `http`
  and the session cookie is issued without the `Secure` flag. `app.ts` reads
  `TRUST_PROXY` (hop count; compose defaults it to `1` for a single
  nginx/Caddy). It is intentionally not `true` — the `/login` rate limiter keys
  on `X-Forwarded-For`, and trusting every hop would let a client spoof that
  header and sidestep the limit. If you add another proxy layer, raise the
  number to match; after any change, confirm the session cookie comes back
  marked `Secure`.

- **CORS** — `app.ts` carries a hardcoded allowlist of the original
  `*.replit.app` / `vibescan.app` origins. Your domain only gets through via
  `CORS_EXTRA_ORIGINS`.

- **Email is not configured until you set `RESEND_API_KEY`.** Accounts work
  without it, but verification and password-reset links are minted and then
  silently not delivered — the mailer logs a warning and returns. Nobody can
  recover a forgotten password until this is set, so treat it as required
  before real users arrive, along with a correct `APP_ORIGIN`, which is what
  builds the link in those emails.

- **Accounts are additive, not a gate.** Signing up is optional: an anonymous
  visitor is a real user with real scans, identified by a UUID their browser
  keeps in `localStorage`. Registering converts that identity in place, so the
  scans they already ran come with them, and the browser token stops working
  from that moment. This is deliberate — requiring a login before the first
  scan costs conversions on a pay-per-scan product. If you would rather gate
  it, that is a change to `ProtectedRoute`.

- **`/api/login` is the old Replit OIDC route and cannot work off Replit.** It
  is reachable only from an explicit "Sign in instead" link and answers 500.
  Removing it is tidy-up, not a blocker.

- **SSRF detection is off until a target can call back to you.** The scanner
  finds SSRF by planting a URL and waiting for the target's *server* to fetch
  it, so it needs an address reachable from the internet. It uses
  `OOB_BASE_URL`, falling back to `APP_ORIGIN`. A localhost value is rejected
  rather than planted as a callback that could only fail, so on a dev box the
  check is simply skipped and no SSRF finding can ever be reported. Once
  `APP_ORIGIN` is your real domain this works with no extra configuration; set
  `OOB_BASE_URL` only if callbacks should land somewhere other than the app's
  own origin. Nothing warns you that the check was skipped, so if SSRF
  findings never appear, check this first.

- **Payments are not implemented.** Every scan is queued free of charge, and
  `DISABLE_PAYMENTS` does not change that — the Stripe webhook that credits an
  account exists, but nothing creates a Checkout Session for a customer to pay
  through. Setting it to `false` only logs a warning at startup. Build checkout
  before advertising a paid tier.

## Operations

```bash
# logs — one service at a time, or omit the name for all three
docker compose --env-file .env.docker logs -f seclayer
docker compose --env-file .env.docker logs -f secscan

# redeploy after a code change
git pull && docker compose --env-file .env.docker up -d --build

# apply a schema change
docker compose --env-file .env.docker --profile setup run --rm --build db-migrate

# back up the database on demand (the backup service also runs on a timer)
docker compose --env-file .env.docker exec db \
  pg_dump -U vibescan vibescan > backup-$(date +%F).sql

# list the automatic backups
docker compose --env-file .env.docker exec backup ls -lh /backups
```

Postgres data lives in the named volume `pgdata` and survives
`docker compose down`. It does **not** survive `docker compose down -v` — that
deletes the volume and every scan and report with it.

## Image notes

- The base is Debian (`bookworm`), not Alpine. `pnpm-workspace.yaml` strips
  every `*-musl` native variant through `overrides`, so the frontend build
  cannot resolve its platform binaries on a musl base.
- esbuild produces two bundles from one package: `dist/index.mjs` (seclayer)
  and `dist/secscan.mjs` (secscan), with `playwright` as the sole external.
  Both images are built from a shared `runtime-base` stage and diverge only
  after it.
- Only the `secscan` stage installs `playwright` plus a matching Chromium.
  **Keep the pinned version in the `Dockerfile` in step with the `playwright`
  dependency in `artifacts/api-server/package.json`** — if they drift, Chromium
  fails to launch and scans silently skip JS rendering rather than erroring.
- `scanCredentials.ts` imports Playwright lazily, inside the one function that
  needs a browser. That is what keeps Chromium out of the web image even though
  the web tier imports that module for its credential-encryption helpers. A
  static import at the top of that file would silently undo it; `grep playwright
  artifacts/api-server/dist/index.mjs` should return nothing.
- `secscan` gets `shm_size: 1gb`. Chromium crashes on content-heavy pages with
  Docker's 64 MB default.
- Both containers run as the unprivileged `node` user.
