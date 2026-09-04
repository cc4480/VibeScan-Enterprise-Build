#!/usr/bin/env bash
#
# Creates the Railway project: Postgres, seclayer, secscan.
#
#   railway login          # once, in your own terminal — it opens a browser
#   ./deploy/railway/setup.sh
#
# Safe to read before running. It creates resources on your Railway account and
# creates nothing else; it does not touch DNS, Cloudflare or the repository.
#
# Secrets are generated here rather than typed. ENCRYPTION_KEY is written to a
# file outside the repository and never printed: it encrypts stored scan
# credentials, and if you lose it every credential already stored becomes
# undecryptable. Back that file up somewhere you would still have after losing
# this machine.

set -euo pipefail

REPO="cc4480/VibeScan-Enterprise-Build"
BRANCH="${BRANCH:-fix/dashboard-scan-flicker}"
PROJECT="${PROJECT:-secscan}"
APP_ORIGIN="${APP_ORIGIN:-https://secscan.us}"
SECRETS_FILE="${SECRETS_FILE:-$HOME/.secscan-railway-secrets}"

command -v railway >/dev/null || { echo "railway CLI not found: npm i -g @railway/cli" >&2; exit 1; }

if ! railway whoami >/dev/null 2>&1; then
  echo "Not logged in. Run 'railway login' in your own terminal first." >&2
  exit 1
fi
echo "Authenticated as: $(railway whoami 2>&1)"

# ── Secrets ─────────────────────────────────────────────────────────────────
# Reuse them if this has been run before, so a re-run does not orphan the
# credentials already encrypted with the previous key.
if [[ -f "$SECRETS_FILE" ]]; then
  echo "Reusing secrets from $SECRETS_FILE"
  # shellcheck disable=SC1090
  source "$SECRETS_FILE"
else
  echo "Generating secrets → $SECRETS_FILE"
  ENCRYPTION_KEY="$(openssl rand -base64 32)"
  CLOUDFLARE_ORIGIN_SECRET="$(openssl rand -hex 32)"
  umask 077
  cat > "$SECRETS_FILE" <<EOF
# secscan.us — Railway. Generated $(date -Is).
# ENCRYPTION_KEY encrypts stored scan credentials. Losing it makes every
# credential already stored permanently undecryptable. Back this file up.
ENCRYPTION_KEY='${ENCRYPTION_KEY}'
CLOUDFLARE_ORIGIN_SECRET='${CLOUDFLARE_ORIGIN_SECRET}'
EOF
fi

# ── Project ─────────────────────────────────────────────────────────────────
# The CLI remembers a project link per directory in ~/.railway/config.json, and
# `railway add` targets whatever is linked. Treating "something is linked" as
# "the right thing is linked" is how resources end up attached to an unrelated
# project that happens to be live — so the link is checked by name, and a
# mismatch stops rather than guesses.
LINKED="$(railway status --json 2>/dev/null | node -e "
  let s='';
  process.stdin.on('data', d => s += d).on('end', () => {
    try { console.log(JSON.parse(s).name ?? ''); } catch { console.log(''); }
  });
" 2>/dev/null || true)"

if [[ -n "$LINKED" && "$LINKED" != "$PROJECT" ]]; then
  echo "This directory is linked to the Railway project '${LINKED}', not '${PROJECT}'." >&2
  echo "Refusing to add resources to it. Run 'railway unlink' first, or set" >&2
  echo "PROJECT='${LINKED}' if that really is where these services belong." >&2
  exit 1
fi

if [[ "$LINKED" == "$PROJECT" ]]; then
  echo "Already linked to '${PROJECT}' — reusing it."
else
  echo "Creating project '${PROJECT}'…"
  railway init --name "${PROJECT}"
fi

echo "Adding Postgres…"
railway add --database postgres

# ── seclayer: the web tier ──────────────────────────────────────────────────
# DATABASE_URL uses Railway's reference syntax so it keeps working when the
# database credentials rotate. PORT is deliberately unset: Railway injects it.
echo "Creating seclayer…"
railway add \
  --service seclayer \
  --repo "${REPO}" \
  --branch "${BRANCH}" \
  --variables 'DATABASE_URL=${{Postgres.DATABASE_URL}}' \
  --variables "ENCRYPTION_KEY=${ENCRYPTION_KEY}" \
  --variables "APP_ORIGIN=${APP_ORIGIN}" \
  --variables "TRUST_PROXY=2" \
  --variables "BEHIND_CLOUDFLARE=true" \
  --variables "CLOUDFLARE_ORIGIN_SECRET=${CLOUDFLARE_ORIGIN_SECRET}" \
  --variables "RAILWAY_CONFIG_PATH=deploy/railway/seclayer.json"

# ── secscan: the scanner ────────────────────────────────────────────────────
# Same ENCRYPTION_KEY as seclayer, or credentialed scans fail at scan time
# rather than at startup. No domain, no PORT: work arrives only via the queue.
echo "Creating secscan…"
railway add \
  --service secscan \
  --repo "${REPO}" \
  --branch "${BRANCH}" \
  --variables 'DATABASE_URL=${{Postgres.DATABASE_URL}}' \
  --variables "ENCRYPTION_KEY=${ENCRYPTION_KEY}" \
  --variables "APP_ORIGIN=${APP_ORIGIN}" \
  --variables "RAILWAY_CONFIG_PATH=deploy/railway/secscan.json"

echo
echo "Created. What is left, in order:"
echo
echo "  1. Give secscan at least 2 GB of memory (dashboard → secscan → Settings)."
echo "     Chromium is the one service where the default may not be enough."
echo
echo "  2. Generate the public domain for seclayer only:"
echo "       railway domain --service seclayer"
echo
echo "  3. Apply the schema once the database is up:"
echo "       railway run --service seclayer pnpm --filter @workspace/db run db:migrate"
echo
echo "  4. Confirm it is alive, then follow deploy/railway/README.md from step 5"
echo "     for Cloudflare, the origin-secret Transform Rule, email and Search Console."
echo
echo "  Secrets: ${SECRETS_FILE} — back this up."
