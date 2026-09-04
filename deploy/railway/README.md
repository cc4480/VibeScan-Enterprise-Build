# Deploying secscan.us on Railway behind Cloudflare

Railway runs the two services and Postgres; Cloudflare fronts the domain. The
compose file is not used — Railway builds the Dockerfile directly — so the
services are configured individually.

One difference from a server you own is worth understanding before you start,
because it changes a security setting rather than just a deployment step. See
[Caller identity](#caller-identity-on-a-platform) below.

## Services

Three, in one Railway project:

| Service    | Source                | Start command                                    | Public domain |
| ---------- | --------------------- | ------------------------------------------------ | ------------- |
| `postgres` | Railway Postgres      | —                                                | no            |
| `seclayer` | this repo, `Dockerfile` | `node --enable-source-maps artifacts/api-server/dist/index.mjs` | **yes** — secscan.us |
| `secscan`  | this repo, `Dockerfile` | (leave default)                                  | no            |

Both application services build the same Dockerfile and differ only in what they
run. Railway builds a Dockerfile's final stage, which is `secscan` — that image
carries Chromium *and* both entrypoints, so the web service overrides the start
command to run its own.

The cost of that is the web service carrying a browser it never launches: about
1.4 GB of image it does not need. On a server you own, the two images are built
separately and the web one is 354 MB. If that matters more than the simplicity,
see [Deploying prebuilt images](#deploying-prebuilt-images-instead) at the end.

---

> **Read [`NOTES.md`](NOTES.md) first.** It records what actually happened
> running this against a real account, including three things that cost time:
> the start command is not picked up from `railway.json` via
> `RAILWAY_CONFIG_PATH`, `railway redeploy` does not apply a config change, and
> migrations have to run before the services first boot.

## Config as code

`seclayer.json` and `secscan.json` in this directory carry each service's build
and deploy settings, so the start commands and health check are versioned rather
than typed into the dashboard and forgotten. Point each service at its file:

    Service → Settings → Config-as-code → Path:  deploy/railway/seclayer.json

Two things Railway does differently from the compose deployment, both harmless
once known:

- **Railway ignores the Dockerfile `HEALTHCHECK`.** It runs its own HTTP probe
  against `healthcheckPath` instead. So `seclayer` is health-checked on
  `/api/healthz`, and the heartbeat probe built for `secscan` does not apply
  there — Railway watches the process rather than the file. The heartbeat still
  works, and still matters, under compose.
- **`secscan` declares no health check path**, because it has no HTTP listener.
  Do not add one; Railway would mark a perfectly healthy worker as failing.

## 1. Create the project and database

Railway → New Project → **Deploy PostgreSQL**. Rename it `postgres`.

Railway exposes `DATABASE_URL` on that service. You will reference it from the
other two rather than copying the value.

## 2. Create the `seclayer` service

New service → **GitHub Repo** → this repository, branch `fix/dashboard-scan-flicker`
(or `master` once merged).

**Settings → Deploy → Custom Start Command:**

```
node --enable-source-maps artifacts/api-server/dist/index.mjs
```

**Settings → Networking → Generate Domain.** Railway gives it a
`*.up.railway.app` hostname. Keep it: you need it for the Cloudflare CNAME, and
it stays reachable — which is the reason for the origin secret below.

**Variables:**

```ini
DATABASE_URL=${{postgres.DATABASE_URL}}
ENCRYPTION_KEY=<openssl rand -base64 32>
APP_ORIGIN=https://secscan.us
TRUST_PROXY=2
BEHIND_CLOUDFLARE=true
CLOUDFLARE_ORIGIN_SECRET=<openssl rand -hex 32>
RESEND_API_KEY=<optional>
STRIPE_SECRET_KEY=<optional>
```

Do not set `PORT`; Railway injects it and the app reads it.

`${{postgres.DATABASE_URL}}` is Railway's reference syntax — it keeps working if
the database credentials rotate.

## 3. Create the `secscan` service

New service → same repository. Leave the start command alone; the image already
runs the scanner.

**Do not generate a domain for it.** It has no HTTP listener; work reaches it
only through the job queue in Postgres.

**Variables:**

```ini
DATABASE_URL=${{postgres.DATABASE_URL}}
ENCRYPTION_KEY=<the same value as seclayer>
APP_ORIGIN=https://secscan.us
DEEPSEEK_API_KEY=<optional>
RESEND_API_KEY=<optional>
OOB_BASE_URL=
```

`ENCRYPTION_KEY` **must match** seclayer's. The web tier encrypts scan
credentials when a scan is created and the scanner decrypts them when it runs; a
mismatch fails at scan time rather than at startup, on exactly the authenticated
scans that need it.

**Memory:** Chromium needs room. Give this service at least 2 GB. It is the one
service where the default may not be enough, and the symptom is scans dying
partway rather than a clear error.

## 4. Apply the schema

Migrations are not run automatically — running them on boot races when a service
has more than one replica. Run them once, from your machine:

```bash
npm i -g @railway/cli
railway link                 # pick the project
railway run --service seclayer pnpm --filter @workspace/db run db:migrate
```

Re-run this after any schema change. Applying nothing is the normal outcome.

> Moving an existing database that was built with the old `db:push` flow? Run
> `db:baseline` **once** first, or the migrator stops on
> `relation "auth_tokens" already exists`.

Confirm the app is alive on its Railway domain before touching DNS:

```bash
curl -s https://<your-service>.up.railway.app/api/healthz    # {"status":"ok"}
```

## 5. Cloudflare

**Add the site.** Cloudflare → Add a site → `secscan.us` → Free. It returns two
nameservers.

**Switch nameservers at IONOS.** IONOS → Domains → `secscan.us` → Nameservers →
use your own → enter Cloudflare's two, replacing the `ui-dns.*` set. Confirm:

```bash
dig NS secscan.us +short      # expect the cloudflare.com nameservers
```

**Add the domain in Railway first.** seclayer → Settings → Networking → Custom
Domain → `secscan.us`. Railway shows the CNAME target to use.

**Then add the DNS record in Cloudflare**, initially **unproxied** (grey cloud):

| Type  | Name | Content                    | Proxy |
| ----- | ---- | -------------------------- | ----- |
| CNAME | `@`  | the target Railway gave you | grey  |

Grey first so Railway can complete its own certificate issuance — behind the
proxy that validation can fail confusingly. Wait for Railway to show the domain
as active and for `https://secscan.us` to load.

**Then turn the proxy on** (orange cloud) and set **SSL/TLS → Full (strict)**.
Never **Flexible**: it leaves Cloudflare speaking plain HTTP to Railway while
showing visitors a padlock, which is worse than no TLS because it looks fine.

## 6. Caller identity on a platform

Nothing to configure. This section explains why, because the mechanism is not
obvious and someone will otherwise "simplify" it away.

On a server you own, the origin is firewalled to Cloudflare's IP ranges, so a
request arriving at all proves it came through Cloudflare. **Railway has no such
firewall** — the `*.up.railway.app` hostname stays publicly reachable, and a
request sent straight to it can carry any `CF-Connecting-IP` its sender likes.
Believing that header would hand an attacker a fresh identity per request and
defeat every per-IP limit in the app, including the one on `/login`.

The app settles it without help from Cloudflare. The chain is:

```
client → Cloudflare → Railway's router → seclayer
```

Each hop appends the address it saw to `X-Forwarded-For`, so the **last** entry
is written by Railway, not by the client — it is the address Railway's router
observed, which for a proxied request is a Cloudflare edge. A client can prepend
anything it likes to that header and still cannot control its final entry. The
app checks that entry against Cloudflare's published ranges, which it refreshes
daily and falls back to a bundled copy for.

Failing to prove it is safe rather than fatal: the app falls back to `req.ip`,
which Express derives from the same header honouring `TRUST_PROXY`. Nothing is
rejected on this basis, so Railway's health checks keep working.

`CLOUDFLARE_ORIGIN_SECRET` still works as a second, stronger proof — Cloudflare
attaches it with a Request Header Transform Rule and the app compares it in
constant time. It is optional, and it is **not available on the Free plan**,
whose Rules section offers only Redirect Rules, Cache Rules, Page Rules, Bulk
Redirects and Snippets. Skip it unless you are on a plan that has it.

### Verify it

```bash
# Straight at Railway, each request claiming a different client address.
# They must all count against ONE identity: five 400s, then 429s.
# Eight distinct 400s would mean the forged header is being believed.
for i in $(seq 1 8); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST \
    -H "Authorization: Bearer $(uuidgen)" \
    -H "Content-Type: application/json" \
    -H "CF-Connecting-IP: 203.0.113.$i" \
    -d '{"targetUrl":"http://10.0.0.1/"}' \
    https://<your-service>.up.railway.app/api/scans
done
```

Removing Railway's generated domain once the custom domain works closes the door
further, and costs nothing but the ability to reach the service without DNS.

## 7. Verify

```bash
curl -sI https://secscan.us | head -5
curl -s  https://secscan.us/api/healthz
```

By hand: sign in and confirm the session cookie comes back marked `Secure`. If
it does not, `TRUST_PROXY` does not match the number of proxies in front —
Cloudflare plus Railway's router is two. Then submit a scan and watch the
`secscan` service logs to confirm the job crosses from web tier to scanner.

## 8. Email

`reports@secscan.us` is the From address, and Resend will not send from a domain
it has not verified — until it is, every report email fails silently.

Add the domain in Resend and copy its DKIM, SPF and DMARC records into
Cloudflare DNS. These must be **unproxied** (grey cloud): they are TXT lookups,
not HTTP.

## 9. Google Search Console

Use a **Domain property** (`secscan.us`), not a URL prefix — it covers every
subdomain and both schemes, and verifies by DNS, so it survives redeploys.

1. Search Console → Add property → Domain → `secscan.us`
2. Copy the `TXT` record
3. Cloudflare DNS → add it at `@`, unproxied
4. Verify

Then **Sitemaps** → submit `https://secscan.us/sitemap.xml`, and **URL
Inspection** → request indexing for `/` and `/learn`.

`robots.txt` deliberately disallows `/dashboard`, `/scan`, `/report/` and
`/monitor`. Search Console will list them as excluded; that is intended.

## Backups

The compose stack includes a backup service. **Railway deployments do not** —
Railway takes its own Postgres backups, and how far back they go depends on your
plan. Check that before you have data worth losing, and take your own dump on a
schedule if the retention is not enough:

```bash
railway run --service postgres pg_dump > backup-$(date +%F).sql
```

## Deploying prebuilt images instead

The web image only avoids carrying Chromium when the two images are built
separately, which the CI workflow already does — it publishes
`seclayer` and `secscan` to ghcr.io on every push to master.

Once that workflow is on GitHub, you can point each Railway service at its image
instead of at the repo (Railway → New → Docker Image), which restores the 354 MB
web image and skips building on Railway entirely. The packages must be public,
or Railway needs a registry token.

That workflow is not in the branch yet: pushing it needs `workflow` scope on the
GitHub token. Until then, build from the repo as described above.
