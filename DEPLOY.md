# Deploying SecScan

Docker Compose deployment onto any Linux host, with a domain registered at
IONOS pointed at it.

## Before you start: what IONOS is and isn't providing here

Registering a domain at IONOS gives you the **name**, not somewhere to run this.
SecScan needs a long-running Node process (the pg-boss job queue and the
monitor/CVE schedulers live inside the API process), PostgreSQL 16, and
Chromium for headless SPA rendering. That means a machine you get root on.

- **IONOS VPS / Cloud Server** — works. This is the tier to buy. Start around
  4 GB RAM: Chromium is the memory-hungry part, and deep scans run it.
- **IONOS MyWebsite Now / Now Shop** — website *builders*. They cannot run this
  app: no Node runtime, no Docker, no PostgreSQL, no root. If these were bought
  intending to host SecScan, they don't serve that purpose.
- **IONOS Mail Business** — useful, but for a different job: it gives you a
  mailbox on your domain. Report email is sent through Resend, not this.

The stack below is host-agnostic. IONOS VPS is the natural pairing since the
domain is already there, but any Linux box with Docker works identically.

## 1. Point the domain at your server

In the IONOS control panel, under **Domains & SSL → your domain → DNS**, set:

| Type | Host name | Value | TTL |
|---|---|---|---|
| `A` | `@` | your server's IPv4 | 1 hour |
| `A` | `www` | your server's IPv4 | 1 hour |
| `AAAA` | `@` | your server's IPv6 (if it has one) | 1 hour |

Delete any parking-page or forwarding records IONOS added at signup — a
redirect left in place will fight the site and break certificate issuance.

Wait for the record to propagate before step 4. Certificate issuance fails if
the name doesn't yet resolve to the server:

```bash
dig +short secscan.us      # must print your server's IP
```

You own four names (`secscan.store`, `.info`, `.us`, `.me`). Pick **one** as the
canonical origin — that is what `APP_ORIGIN` becomes. Point the others at the
server too if you want them to redirect, but don't serve the site from more
than one: duplicate content across domains splits your search ranking.

## 2. Prepare the server

```bash
ssh root@your-server

curl -fsSL https://get.docker.com | sh
systemctl enable --now docker

# Only 80, 443 and SSH should be reachable. PostgreSQL must never be exposed —
# compose keeps it on an internal network, and this is the backstop.
ufw allow OpenSSH && ufw allow 80/tcp && ufw allow 443/tcp && ufw --force enable
```

## 3. Configure

```bash
git clone https://github.com/cc4480/VibeScan-Enterprise-Build.git seclayer
cd seclayer
cp .env.example .env
```

Edit `.env`. The four that matter:

```ini
APP_ORIGIN=https://secscan.us          # your chosen domain, no trailing slash
POSTGRES_PASSWORD=<openssl rand -base64 24>
TLS_EMAIL=you@example.com              # Let's Encrypt expiry notices
ENCRYPTION_KEY=<node -e "console.log(require('crypto').randomBytes(32).toString('base64'))">
```

`ENCRYPTION_KEY` encrypts users' own DeepSeek API keys at rest. **Losing it
makes every stored key undecryptable** — back it up somewhere other than the
server. Without it, the app still runs; the Settings key feature returns 503.

Optional: `DEEPSEEK_API_KEY` (AI report analysis on deep scans — without it
scans complete and skip the AI section), `RESEND_API_KEY` (email notifications).

## 4. Deploy

```bash
docker compose up -d --build
```

First build takes several minutes. Compose brings up PostgreSQL, waits for it
to be healthy, applies the database schema as a one-shot `migrate` service,
then starts the app and Caddy. Caddy obtains the TLS certificate on first
request — both ports 80 and 443 must be open, because the HTTP-01 challenge
uses port 80 even though the site is HTTPS-only.

```bash
docker compose ps                        # app should read "healthy"
curl https://secscan.us/api/healthz      # {"status":"ok"}
docker compose logs -f app
```

## 5. Confirm it actually works

```bash
# The scanner must reject internal targets — if this returns 201, stop and
# investigate: the deployment is an open proxy into your own network.
curl -s -X POST https://secscan.us/api/scans \
  -H "Authorization: Bearer $(uuidgen)" -H 'Content-Type: application/json' \
  -d '{"targetUrl":"http://169.254.169.254/","tier":"basic"}'
# expected: {"error":"Target resolves to a private, loopback, or link-local address."}
```

```bash
# Rate limiting must survive a caller rotating both their token and a spoofed
# X-Forwarded-For. With the defaults the 6th request in an hour is refused.
for i in $(seq 1 6); do
  curl -s -o /dev/null -w "%{http_code} " -X POST https://secscan.us/api/scans \
    -H "Authorization: Bearer $(uuidgen)" -H 'Content-Type: application/json' \
    -H "X-Forwarded-For: 198.51.100.$i" \
    -d '{"targetUrl":"https://example.com/","tier":"basic"}'
done; echo
# expected: 201 201 201 201 201 429   — if every one is 201, the app is seeing
# the spoofed header: check TRUST_PROXY and that app's port is not published.
```

Then open the site and run a scan against a domain you own, end to end.

## Operating it

**Updating.** `APP_ORIGIN` is compiled into the frontend bundle, so a domain
change needs a rebuild, not just a restart:

```bash
git pull && docker compose up -d --build
```

**Backups.** Everything durable is in the `db` volume.

```bash
docker compose exec -T db pg_dump -U seclayer seclayer | gzip > backup-$(date +%F).sql.gz
```

Restore into a running stack:

```bash
gunzip -c backup-2026-09-02.sql.gz | docker compose exec -T db psql -U seclayer seclayer
```

Store `ENCRYPTION_KEY` with the backups, or the restored DeepSeek keys are
unreadable.

**Logs.** `docker compose logs -f app`. JSON lines from pino; `LOG_LEVEL=debug`
in `.env` for more.

## Things to know before taking real traffic

- **Scan creation is rate limited per client address** — 5/hour and 20/day by
  default (`SCAN_LIMIT_PER_HOUR`, `SCAN_LIMIT_PER_DAY`). Client tokens are
  self-minted UUIDs, so the address is the only identity worth counting.
  Counters are in-process: they reset on restart, and running more than one app
  container would need shared storage instead.

  The limit depends on the app seeing the caller's real address, which is what
  `TRUST_PROXY` configures. **Do not publish the app's port** — the shipped
  compose stack deliberately gives the `app` service no `ports:` mapping, so it
  is reachable only through Caddy, which overwrites `X-Forwarded-For` with the
  real peer. Expose the app directly with `TRUST_PROXY=1` and callers can set
  that header themselves for a fresh bucket per request, bypassing the limit
  entirely.
- **Bundled CVE/EOL data ages.** The app logs a warning past 90 days and
  refreshes daily from endoflife.date; if that fetch is blocked outbound, it
  silently keeps serving stale data.
- **Outbound scanning may look hostile to your provider.** Port scans and path
  probing from a VPS can trigger abuse detection. Check your host's AUP, and
  expect to answer the occasional complaint.
- **`.env` holds live secrets.** It is gitignored — keep it that way, and keep
  the server's own shell access tight.
