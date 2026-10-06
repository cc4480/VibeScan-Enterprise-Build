# Running every app at home with Docker (Windows)

This folder moves the five apps that ran on Railway onto one Windows computer:

| App | Repository | Public address (example) | Inside the stack |
|---|---|---|---|
| SecScan web + API | VibeScan-Enterprise-Build | secscan.us | `secscan-web:8080` |
| SecScan scanner | VibeScan-Enterprise-Build | (no address) | `secscan-worker` |
| secscan.info | secscan-info | secscan.info | `secscan-info:8080` |
| seclayer | seclayer.io2026 | seclayer.app | `seclayer:3000` |
| complyscan | complyscan | your complyscan domain | `complyscan:5000` |
| complyscan nightly re-scan | complyscan | (no address) | `complyscan-rescan` |
| SEO-scan-Pro | SEO-scan-Pro | your SEO-scan-Pro domain | `seoscan:3000` |

Plus one PostgreSQL (a separate database and login per app), a nightly backup
of every database, and a **Cloudflare Tunnel**: the only way in from the
internet. The tunnel connects outwards from your computer to Cloudflare, so you
open no ports on your router and your home IP address never appears in DNS.

## Before you start: what changes when it runs at home

- **The computer must stay on and online.** When it sleeps, restarts for
  Windows Update, or loses power or internet, all five sites are down until it
  is back. Step 9 sets Windows up to keep it running.
- **Scans come from your home internet connection.** SecScan, seclayer and
  SEO-scan-Pro fetch the sites people scan. That traffic now leaves from your
  home IP address. Active attack probes still only run against domains the user
  has verified, but a site owner who sees a scan can complain to your internet
  provider. If that becomes a problem, this same setup runs unchanged on a
  rented Linux server.
- **Backups live on the same disk until you copy them off.** Step 10.

Nothing on Railway changes until step 7. Keep Railway running until everything
here has worked for a day.

## What you need

- Windows 10 or 11 with 16 GB of memory (8 GB is too little for all five apps)
- About 30 GB of free disk space
- The Cloudflare account that already holds your domains
- Access to the Railway projects, to copy settings and data

## 1. Install Docker Desktop and give it enough memory

1. Install Docker Desktop: <https://www.docker.com/products/docker-desktop/>.
   Keep the default "Use WSL 2" option. Restart when it asks.
2. Docker Desktop on Windows gets half your memory by default (8 GB). The apps
   need more. Open Notepad, paste the two lines below, and save the file as
   `.wslconfig` in your user folder (`C:\Users\<your name>\.wslconfig`, with
   "Save as type: All files" so Notepad does not add `.txt`):

   ```ini
   [wsl2]
   memory=12GB
   ```

3. Open PowerShell and run `wsl --shutdown`, then start Docker Desktop again.
4. Docker Desktop → Settings → General → tick **Start Docker Desktop when you
   sign in to your computer**.

Check it works: in PowerShell, `docker info` prints a page of details ending
without an error.

## 2. Install Git and get the code

1. Install Git for Windows: <https://git-scm.com/download/win> (the defaults
   are fine).
2. In PowerShell:

   ```powershell
   mkdir C:\apps
   cd C:\apps
   git clone -c core.autocrlf=false https://github.com/cc4480/VibeScan-Enterprise-Build.git
   cd C:\apps\VibeScan-Enterprise-Build\deploy\home-server
   powershell -ExecutionPolicy Bypass -File .\setup.ps1
   ```

   `-c core.autocrlf=false` matters: it keeps the scripts that run inside the
   containers in the line-ending format Linux needs. Git may open a browser
   window to sign in to GitHub the first time (the repositories are private).

`setup.ps1` clones the other four repositories into `C:\apps`, creates `.env`
with new random database passwords, and creates one settings file per app in
the `env` folder. Running it again later is safe: it updates the code and never
overwrites settings you have filled in.

## 3. Copy each app's settings from Railway

For each app, open its Railway service → **Variables** → **Raw Editor**, and
copy the values into the matching file in
`C:\apps\VibeScan-Enterprise-Build\deploy\home-server\env\`:

| Railway service | File |
|---|---|
| secscan → web | `env\secscan.env` (the scanner reads the same file) |
| seclayer | `env\seclayer.env` |
| complyscan → web | `env\complyscan.env` (the nightly re-scan reads the same file) |
| SEO-scan-Pro | `env\seoscan.env` |

secscan.info needs no settings.

Rules that matter:

- **Copy secrets exactly.** `ENCRYPTION_KEY` (SecScan and complyscan),
  `FLASK_SECRET_KEY` (complyscan) and `JWT_SECRET` (SEO-scan-Pro) must be the
  same values as on Railway. A new value cannot read data already stored, or
  signs everyone out.
- **Never copy `RAILWAY_*` variables.**
- `DATABASE_URL`, `PORT` and the proxy settings are set by
  `docker-compose.yml`. If you paste them, they are ignored.
- Each file explains which values are required. Lines starting with `#` are
  off; remove the `#` to use one.

## 4. Copy each database from Railway

Do this before starting the apps for the first time. For each app with a
database, run (from the `home-server` folder):

```powershell
powershell -ExecutionPolicy Bypass -File .\migrate-db.ps1 -App secscan
powershell -ExecutionPolicy Bypass -File .\migrate-db.ps1 -App seclayer
powershell -ExecutionPolicy Bypass -File .\migrate-db.ps1 -App complyscan
powershell -ExecutionPolicy Bypass -File .\migrate-db.ps1 -App seoscan
```

Each one asks for that app's Railway database address: open the **Postgres**
service the app uses on Railway → Variables → copy `DATABASE_PUBLIC_URL`, and
paste it when asked (it is not shown on screen). The secscan project has two
Postgres services: copy from the one the app uses. To see which, open the
secscan **web** service → Variables → **Raw Editor**: its `DATABASE_URL` line
reads `${{<name>.DATABASE_URL}}`, and `<name>` is the Postgres service to copy
from.

The script copies everything, keeps a copy of the data in the `migration`
folder, and tells you how many tables arrived.

At the end you may see two or three errors that say **must be owner of
extension**. Those are expected and harmless. Any error about a table, sequence
or index is not: stop and ask for help, and keep Railway running.

Railway keeps running while you do this, so anything written there afterwards
is not in your copy. Step 7 copies each database once more, right before that
app switches over.

## 5. Start everything and check it on this computer

```powershell
docker compose up -d --build
```

The first build takes 10 to 20 minutes (it downloads Chromium for three of the
apps). Later starts take seconds. Then:

```powershell
docker compose ps
```

Every app should say `running` (some also say `healthy` after a minute).
`complyscan-rescan` is Railway's `rescan-cron`: it waits and runs once a day at
00:00 UTC, like on Railway; `docker compose logs complyscan-rescan` shows how
long until the next run.

Open each app in your browser on this computer:

| App | Address on this computer |
|---|---|
| SecScan | <http://localhost:8090> |
| secscan.info | <http://localhost:8091> |
| seclayer | <http://localhost:8092> |
| complyscan | <http://localhost:8093> |
| SEO-scan-Pro | <http://localhost:8094> |

These addresses work only on this computer, not from other devices or the
internet. Sign-in may not work here, because the apps expect their real
domains: that is fine, and step 7 checks it properly. If an app is not
`running`, look at its messages: `docker compose logs seclayer` (use the name
from the "Inside the stack" column above).

## 6. Create the Cloudflare Tunnel

1. Cloudflare dashboard → **Zero Trust** → **Networks** → **Tunnels** →
   **Create a tunnel** → **Cloudflared** → name it `home` → Save.
2. On the "Install and run a connector" page, choose any operating system and
   copy only the long token after `--token` in the command shown.
3. Open `.env` in Notepad. Paste the token after `CLOUDFLARE_TUNNEL_TOKEN=`,
   and remove the `#` in front of `COMPOSE_PROFILES=tunnel`. Save.
4. `docker compose up -d`

Back in the dashboard, the tunnel shows a connector as **Healthy** after a few
seconds. Nothing uses it yet.

## 7. Switch each domain over, one at a time

Start with secscan.info (no database, nothing to lose), then the others. For
each app:

1. **Final data copy** (not for secscan.info): run that app's
   `migrate-db.ps1` again with `-Force`, so the home copy has everything
   Railway has right now:
   `powershell -ExecutionPolicy Bypass -File .\migrate-db.ps1 -App seclayer -Force`
   then `docker compose up -d`.
2. **Remove the old DNS record**: Cloudflare → your domain → **DNS** → delete
   the record for that hostname (the CNAME that points at Railway).
3. **Point it at the tunnel**: Zero Trust → Networks → Tunnels → `home` →
   **Public Hostname** → **Add a public hostname**. Enter the hostname, choose
   type **HTTP**, and for the URL use the "Inside the stack" value from the
   first table, for example `secscan-web:8080`. Save. Cloudflare creates the
   DNS record itself.
4. **Check** the site in your browser (on your phone's mobile data too, to be
   sure it is not cached), sign in, and use it.

| Hostname | Service URL |
|---|---|
| `secscan.info` | `secscan-info:8080` |
| `secscan.us` | `secscan-web:8080` |
| `seclayer.app` | `seclayer:3000` |
| complyscan's domain | `complyscan:5000` |
| SEO-scan-Pro's domain | `seoscan:3000` |

If a domain also uses `www.`, add a second public hostname for it with the same
service URL, unless a Cloudflare Redirect Rule already sends `www` to the bare
domain (secscan.info has one).

For complyscan, nothing extra: until Railway is turned off, its `rescan-cron`
keeps re-scanning Railway's copy of the data and the home one re-scans the home
copy. Neither sends email, so the two do not get in each other's way.

For SecScan, also start a scan and watch it run:
`docker compose logs -f secscan-worker` (Ctrl+C stops watching, not the app).

If something is wrong, put the old record back: delete the public hostname
from the tunnel and re-create the DNS record that pointed at Railway. Railway is
still running, so it takes over again within minutes.

## 8. Turn Railway off (whenever you decide)

Nothing here requires it, and nothing in this folder changes anything on
Railway. When you choose to, after every app has worked from home for at least
a day, remove each service in Railway. Keep the files in the `migration`
folder: they are the last copy of each Railway database.

## 9. Keep the computer running

- Windows Settings → System → Power → **Screen and sleep**: set "When plugged
  in, put my device to sleep after" to **Never**. The screen may still turn off.
- Windows Update → Advanced options → **Active hours**: set them so restarts
  happen when traffic is lowest.
- After any restart: sign in to Windows (or turn on automatic sign-in), Docker
  Desktop starts, and every app starts by itself.

## 10. Backups

The `backup` container saves every database once a day into the `backups`
folder next to this file, and deletes copies older than 14 days. Those are
normal files: **copy the `backups` folder somewhere else every week** (a USB
drive, or a cloud-synced folder such as OneDrive). A backup on the same disk is
lost with the disk.

To restore one app's database from a backup file, stop that app, then:

```powershell
docker compose stop seclayer
docker compose cp .\backups\seclayer-20261006-030000.dump db:/tmp/restore.dump
docker compose exec db pg_restore -U postgres -d seclayer --clean --if-exists --no-owner --role=seclayer /tmp/restore.dump
docker compose up -d seclayer
```

## Day to day

| To | Run (in the `home-server` folder) |
|---|---|
| See what is running | `docker compose ps` |
| Read an app's messages | `docker compose logs --tail 100 secscan-web` |
| Restart one app | `docker compose restart seclayer` |
| Update all apps to the latest code | `powershell -ExecutionPolicy Bypass -File .\setup.ps1` then `docker compose up -d --build` |
| Stop everything | `docker compose down` (data is kept) |

Never run `docker compose down -v`: `-v` deletes the database.

## When something goes wrong

- **`\r: not found` or `bad interpreter` in a build or log**: a repository was
  cloned with Windows line endings. Delete that folder under `C:\apps` and run
  `setup.ps1` again (it clones with the right setting).
- **An app keeps restarting with "out of memory", or the computer slows to a
  crawl**: check `.wslconfig` from step 1, or lower
  `SECSCAN_SCAN_CONCURRENCY` in `.env` to 2 and run `docker compose up -d`.
- **seclayer says "The server does not support SSL connections"**: the
  database was started without the settings in `docker-compose.yml`. Run
  `docker compose up -d db` and then `docker compose restart seclayer`.
- **"port is already allocated"**: another program uses 8090–8094 on this
  computer. Change the first number of that app's `ports:` line in
  `docker-compose.yml` (for example `127.0.0.1:9090:8080`).
- **The tunnel shows "Inactive"**: `docker compose logs cloudflared`. An
  "invalid token" message means the token in `.env` was copied incompletely.
