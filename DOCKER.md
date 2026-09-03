# Running Seclayer with Docker

The stack is two containers: `app` (Express API + the pre-built SPA, one
process) and `db` (Postgres 16). The API server serves the frontend itself in
production, so there is no separate web container.

## Quick start

```bash
cp .env.docker.example .env.docker      # fill it in — see the notes in the file
docker compose --env-file .env.docker --profile setup run --rm --build db-push
docker compose --env-file .env.docker up -d --build
```

Then open `http://localhost:8090` (or whatever `APP_PORT` you set).

`db-push` applies the Drizzle schema and must be run once before first boot,
and again after any schema change. It runs from the *builder* stage because
`drizzle-kit` is a dev dependency and is deliberately absent from the slim
runtime image.

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

- **Payments** default to `DISABLE_PAYMENTS=true`, which queues scans without
  charging. Set it to `false` and supply the Stripe keys to actually bill.

## Operations

```bash
# logs
docker compose --env-file .env.docker logs -f app

# redeploy after a code change
git pull && docker compose --env-file .env.docker up -d --build

# apply a schema change
docker compose --env-file .env.docker --profile setup run --rm --build db-push

# back up the database
docker compose --env-file .env.docker exec db \
  pg_dump -U vibescan vibescan > backup-$(date +%F).sql
```

Postgres data lives in the named volume `pgdata` and survives
`docker compose down`. It does **not** survive `docker compose down -v` — that
deletes the volume and every scan and report with it.

## Image notes

- The base is Debian (`bookworm`), not Alpine. `pnpm-workspace.yaml` strips
  every `*-musl` native variant through `overrides`, so the frontend build
  cannot resolve its platform binaries on a musl base.
- esbuild bundles the whole API server into one `dist/index.mjs`, with
  `playwright` as the sole external. The runtime stage therefore installs
  `playwright` plus a matching Chromium. **Keep the pinned version in the
  `Dockerfile` in step with the `playwright` dependency in
  `artifacts/api-server/package.json`** — if they drift, Chromium fails to
  launch and scans silently skip JS rendering rather than erroring.
- The container runs as the unprivileged `node` user.
