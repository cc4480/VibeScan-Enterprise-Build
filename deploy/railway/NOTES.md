# What the Railway setup actually did, and what bit

Written while doing it, on 4 September 2026. The runbook in `README.md` says
what to do; this says why some of it is phrased the way it is.

## The start command is not read from railway.json here

`seclayer.json` and `secscan.json` exist and are correct, and setting
`RAILWAY_CONFIG_PATH` as a service variable **did not apply them**. The service
kept the Dockerfile's default `CMD`, which is the *scanner* — so the web service
came up as a second scanner, with no HTTP listener, and its public URL returned
502 with "Application failed to respond".

Nothing in the logs says "wrong entrypoint". The evidence was that the seclayer
service's own logs read `secscan ready — waiting for scan jobs`, and its stack
traces pointed at `src/secscan.ts`.

The fix that worked was setting the start command on the service instance
directly:

```bash
railway api 'mutation {
  serviceInstanceUpdate(
    environmentId: "<env-id>",
    serviceId: "<service-id>",
    input: {
      startCommand: "node --enable-source-maps artifacts/api-server/dist/index.mjs",
      healthcheckPath: "/api/healthz",
      healthcheckTimeout: 60
    }
  )
}'
```

The dashboard equivalent is Settings → Deploy → Custom Start Command. Either
way, **verify it took** rather than assuming:

```bash
railway api 'query { service(id: "<service-id>") { serviceInstances { edges { node {
  startCommand healthcheckPath } } } } }'
```

`railway up` reads `.railwayignore`, so the repo has one — the `.gitignore`
fallback would have covered `.env`, but secrets should not depend on an
inherited default.

## `railway redeploy` will not pick up a config change

It replays the existing deployment, including the start command captured when
that deployment was created. After changing the start command, `redeploy`
produced another SUCCESS that was still running the old entrypoint.

A *new* deployment is required: `railway up`, or `railway redeploy --from-source`
where the source is reachable.

## Run migrations before the services first boot, not after

Both services started against an empty database and logged
`relation "eol_cache" does not exist` at length. They degrade correctly — the
scanner fell back to bundled EOL data and still registered on the queue — but
the daily EOL refresh then fails to persist until the next run, so the first
day's data is bundled rather than fresh.

Restarting after migrating clears it. Better: migrate first.

## Migrating needs a temporary route to the database

`DATABASE_URL` on a Railway Postgres resolves to `postgres.railway.internal`,
which only exists inside Railway's network — `railway run` injects it locally
and the migration fails with `ENOTFOUND`. And the runtime images cannot migrate
themselves: the migration tooling is a dev dependency, deliberately absent.

What worked was a TCP proxy, used and then removed:

```bash
# create
railway api 'mutation { tcpProxyCreate(input: {
  applicationPort: 5432, environmentId: "<env-id>", serviceId: "<postgres-service-id>"
}) { id domain proxyPort } }'

# migrate against postgresql://postgres:<POSTGRES_PASSWORD>@<domain>:<proxyPort>/railway
DATABASE_URL=... pnpm --filter @workspace/db run db:migrate

# delete — do not leave the database exposed
railway api 'mutation { tcpProxyDelete(id: "<proxy-id>") }'
```

Leaving the proxy in place would leave Postgres reachable from the internet with
nothing but its password in front of it. Delete it when the migration is done,
and confirm: `railway variables --service Postgres --kv | grep PUBLIC` should
find nothing.

## The GitHub source is configured but not usable yet

Both services have `source.repo` set to `cc4480/VibeScan-Enterprise-Build`, and
deploying from it fails with "Repository not found or is not accessible" — the
repository is private and Railway's GitHub App has not been granted access.

Everything currently deployed was uploaded with `railway up`, which works but
means no automatic deploy on push. Install the app at
<https://github.com/apps/railway/installations/new>, grant it that repository,
and the configured source starts working.

## Transform Rules are not on the Free plan

The origin-secret design assumed Cloudflare could attach a header. On this
account the Rules section offers only Redirect Rules, Cache Rules, Page Rules,
Bulk Redirects and Snippets — there is no Request Header Transform Rule, so the
secret could never be set in the first place.

The app now proves the hop itself, by checking the last X-Forwarded-For entry
against Cloudflare's published ranges. That entry is written by Railway rather
than the client, so it cannot be forged. Verified against the live deployment:
eight requests sent straight to the Railway hostname, each claiming a different
CF-Connecting-IP, all counted against one identity — five 400s then 429s, rather
than eight separate 400s.

The secret remains supported as a second proof for accounts that do have
Transform Rules, but it is optional.

## The CLI echoes variable values

`railway add --variables "K=V"` prints each pair back as it runs, so anything
passed that way ends up in terminal output and shell history. `ENCRYPTION_KEY`
and `CLOUDFLARE_ORIGIN_SECRET` were set this way during setup and should be
rotated before the origin secret starts protecting anything:

```bash
railway variables --service seclayer --set "CLOUDFLARE_ORIGIN_SECRET=$(openssl rand -hex 32)"
```

Rotating `ENCRYPTION_KEY` is free only while no scan credentials are stored. It
becomes irreversible the moment one is: every stored secret is encrypted with it.

## Verified working

- Postgres, `seclayer` and `secscan` all Online; 16 tables, 1 migration recorded
- `seclayer` serves `/api/healthz`, the SPA, `robots.txt` and `sitemap.xml`,
  with `secscan.us` already in the generated URLs
- Chromium launches on Railway — `Headless browser initialised`
- A scan submitted to `seclayer` was picked up by `secscan` through the queue
  and finished: status `complete`, progress 100, grade A
