# Deploying secscan.us on IONOS behind Cloudflare

> **Using Railway instead?** Follow [`railway/README.md`](railway/README.md).
> It differs in more than the hosting steps: a managed platform keeps a publicly
> reachable hostname, so the origin cannot be firewalled to Cloudflare and
> caller identity needs a shared secret instead. This document assumes a server
> you control.

The order below is not arbitrary. Two steps are easy to do early and painful to
undo: pointing DNS at a server that is not serving yet, and switching Cloudflare
to strict TLS before the origin has a certificate it will accept.

## Before you start

**You need an IONOS VPS or dedicated server with root access.** The stack is
Docker Compose — Postgres, the web tier, the scanner and a backup service — and
IONOS shared web hosting cannot run it. As of writing, `secscan.us` resolves to
`74.208.236.81`, which serves the IONOS Apache parking page, so nothing of yours
is deployed yet.

If you have only the domain and shared hosting, the options are to add a VPS, or
to deploy the containers on a container host (Fly, Render, Railway) and point
Cloudflare at that instead. Everything below except "Prepare the server" applies
either way.

What you should have in hand:

- Root SSH access to a Linux server (Ubuntu 22.04 or 24.04 assumed below)
- The `secscan.us` domain at IONOS — already true
- A Cloudflare account (the free plan is sufficient)
- A Resend account, if report emails should actually send
- A DeepSeek API key, if reports should include the AI write-up

---

## 1. Prepare the server

```bash
# Docker Engine + compose plugin
curl -fsSL https://get.docker.com | sh

# Caddy, as the TLS terminator in front of the app
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
  | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install -y caddy ufw

# SSH must be allowed before ufw is enabled, or the next reboot locks you out.
sudo ufw allow OpenSSH
sudo ufw --force enable
```

## 2. Bring the app up on the server

```bash
git clone https://github.com/cc4480/VibeScan-Enterprise-Build.git
cd VibeScan-Enterprise-Build
cp .env.docker.example .env.docker
```

Edit `.env.docker`. The values that matter:

```ini
POSTGRES_PASSWORD=<a long random string>
ENCRYPTION_KEY=<32 random bytes, base64 — see below>
APP_ORIGIN=https://secscan.us
CORS_EXTRA_ORIGINS=
TRUST_PROXY=2
BEHIND_CLOUDFLARE=true
DEEPSEEK_API_KEY=<optional>
RESEND_API_KEY=<optional>
```

Generate the encryption key with `openssl rand -base64 32`. **Keep it.** It
encrypts stored scan credentials, and changing it makes every previously stored
secret undecryptable.

`TRUST_PROXY=2` because there will be two proxies in front: Cloudflare, then
Caddy. `BEHIND_CLOUDFLARE=true` is safe to set now and only takes effect for
caller identification once step 6 makes it true in practice.

```bash
# Apply the schema. On a brand-new database this is all you need.
docker compose --env-file .env.docker --profile setup run --rm --build db-migrate

docker compose --env-file .env.docker up -d --build
docker compose --env-file .env.docker ps        # all four should be healthy
curl -s localhost:8090/api/healthz               # {"status":"ok"}
```

> If you are moving an existing database that was built with the old `db:push`
> flow, run `--profile baseline run --rm --build db-baseline` **once** before
> `db-migrate`, or the migrator stops on `relation "auth_tokens" already exists`.

## 3. Add the site to Cloudflare

In the Cloudflare dashboard: **Add a site** → `secscan.us` → Free plan. Cloudflare
scans the existing records and gives you two nameservers such as
`xxx.ns.cloudflare.com`.

Check the imported records before continuing and delete anything pointing at the
IONOS parking page.

## 4. Switch the nameservers at IONOS

IONOS → Domains → `secscan.us` → Nameservers → use your own, and enter the two
Cloudflare nameservers, replacing the `ui-dns.*` set.

Propagation is usually minutes and occasionally hours. Cloudflare emails you
when the zone goes active. Confirm with:

```bash
dig NS secscan.us +short     # expect the cloudflare.com nameservers
```

## 5. DNS records and the origin certificate

In Cloudflare **DNS**, with the orange cloud **on** (proxied) for both:

| Type | Name  | Content            |
| ---- | ----- | ------------------ |
| A    | `@`   | your server's IPv4 |
| A    | `www` | your server's IPv4 |

In **SSL/TLS → Origin Server → Create Certificate**, accept the defaults
(15 years, `secscan.us` and `*.secscan.us`). Copy both files to the server:

```bash
sudo nano /etc/caddy/origin.pem     # paste the certificate
sudo nano /etc/caddy/origin.key     # paste the private key
sudo chown root:caddy /etc/caddy/origin.*
sudo chmod 640 /etc/caddy/origin.*

sudo cp deploy/Caddyfile /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Only now set **SSL/TLS → Overview → Full (strict)**.

Doing it in the other order gives you a period where Cloudflare cannot validate
the origin and the site returns 526. Never use **Flexible**: it leaves Cloudflare
speaking plain HTTP to your server while showing visitors a padlock, which is
worse than no TLS because it looks fine.

## 6. Close the origin to everything but Cloudflare

```bash
sudo ./deploy/cloudflare-firewall.sh --dry-run   # read this first
sudo ./deploy/cloudflare-firewall.sh
```

This is what makes `BEHIND_CLOUDFLARE=true` honest. That setting tells the app to
identify callers by `CF-Connecting-IP`; without this firewall, anyone who learns
the origin address can send that header themselves and walk past every per-IP
limit in the application.

Confirm SSH still works **from a second terminal** before closing the one you ran
it in.

## 7. Verify

```bash
curl -sI https://secscan.us | head -5                    # 200, via Cloudflare
curl -s https://secscan.us/api/healthz                    # {"status":"ok"}
curl -sI https://www.secscan.us | grep -i location        # redirects to apex
curl -sI http://<origin-ip> --max-time 5                  # should now fail
```

Two things worth checking by hand:

- Sign in and confirm the session cookie comes back marked `Secure`. If it does
  not, `TRUST_PROXY` does not match the number of proxies actually in front.
- Submit a scan and watch `docker compose logs -f secscan` to confirm the job
  crosses from the web tier to the scanner.

## 8. Email, if reports should send

`reports@secscan.us` is the From address. Resend will not send from a domain it
has not verified, so until this is done every report email fails silently.

In Resend, add the domain and copy the DKIM, SPF and DMARC records it gives you
into Cloudflare DNS. These are the one set of records that must be **unproxied**
(grey cloud) — they are TXT and MX lookups, not HTTP.

## 9. Google Search Console

Use a **Domain property** (`secscan.us`), not a URL prefix. It covers every
subdomain and both schemes, and verifies by DNS, which survives redeploys.

1. Search Console → Add property → Domain → `secscan.us`
2. Copy the `TXT` record it shows
3. Cloudflare DNS → add that TXT at `@`, unproxied
4. Back in Search Console, click Verify

If you would rather not use DNS, set `GOOGLE_SITE_VERIFICATION` in `.env.docker`
to the token from Google's HTML-file method (the part after `google` in
`googleXXXX.html`) and restart the web tier — the server will answer that path.

Then:

- **Sitemaps** → submit `https://secscan.us/sitemap.xml`
- **URL Inspection** → request indexing for `/` and `/learn`

`robots.txt` deliberately disallows `/dashboard`, `/scan`, `/report/` and
`/monitor`. Search Console will report them as excluded; that is intended, not a
problem to fix. Shared reports under `/s/` are allowed.

## Afterwards

- Copy the `backups` volume off the machine on a schedule. The backup service
  protects you from a bad migration, not from losing the server.
- Re-run `cloudflare-firewall.sh` after Cloudflare changes its published ranges.
- The scanner reaches the internet directly, not through Cloudflare. Outbound
  traffic is unaffected by any of the above.
