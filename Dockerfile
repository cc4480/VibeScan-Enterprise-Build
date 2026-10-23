# syntax=docker/dockerfile:1

# ─────────────────────────────────────────────────────────────────────────────
# Builder
#
# glibc (bookworm), NOT Alpine. pnpm-workspace.yaml removes every *-musl native
# variant via `overrides` (@tailwindcss/oxide-linux-x64-musl,
# rollup-linux-x64-musl, …), so on a musl base the frontend build cannot
# resolve its platform binaries and fails.
# ─────────────────────────────────────────────────────────────────────────────
FROM node:24-bookworm@sha256:14078204b6bb268c107ceff6d3c43f45a888105e5c2b18b14c32b3409d93a1b0 AS builder

WORKDIR /app
ENV CI=true

RUN corepack enable

COPY . .

RUN pnpm install --frozen-lockfile

# -r runs in topological order, so the lib packages (db, api-zod,
# api-client-react) are compiled before the two apps that
# import their type output.
#
# The root `build` script also runs a typecheck first; it is deliberately not
# used here so that a pre-existing type error cannot block producing an image.
#
# APP_ORIGIN is baked into the frontend at build time (vite.config.ts writes it into index.html,
# sitemap.xml and robots.txt), so it must be an ARG, not only a runtime env var. It is a public
# URL, not a secret. Being declared in this stage only, it does not reach the runtime images.
ARG APP_ORIGIN=https://secscan.us
RUN pnpm -r --if-present run build

# Prerender the public pages (home, learn, about, bot, privacy, terms) in headless
# Chromium, so crawlers that run no JavaScript get the page and not an empty div.
# The browser lives only in this builder stage and is never copied into an image.
# The whole step is best-effort: the download comes from cdn.playwright.dev, which
# has failed mid-build before, and a missing prerender only means those pages are
# served as they were. It must never be the reason a deploy fails.
RUN ( for attempt in 1 2 3; do \
        pnpm --filter @workspace/api-server exec playwright install --with-deps chromium && break; \
        echo "playwright browser install failed (attempt $attempt/3); retrying in 15s"; \
        sleep 15; \
      done; \
      pnpm --filter @workspace/api-server run prerender ) \
    || echo "prerender skipped"


# ─────────────────────────────────────────────────────────────────────────────
# Runtime base — everything both apps need, and nothing either one does not.
#
# web and secscan are built from the same workspace but deploy as two
# separate images. They share this base so a change to the Node version or the
# bundle layout cannot drift between them.
# ─────────────────────────────────────────────────────────────────────────────
FROM node:24-bookworm-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5 AS runtime-base

ENV NODE_ENV=production

WORKDIR /app

# Both entrypoints (index.mjs and secscan.mjs) live in this directory; each image
# runs only its own. The unused bundle costs a couple of MB and keeps this layer
# identical between the two images, which is worth more than trimming it.
COPY --from=builder /app/artifacts/api-server/dist ./artifacts/api-server/dist

# The committed migrations. Both entrypoints apply them on boot (see
# lib/db/src/bootMigrate.ts), which is what removed the hand-run,
# expose-Postgres-to-the-internet procedure that used to be the only way schema
# reached production.
#
# They must be real files in the image: the server ships as an esbuild bundle,
# which carries no non-JS assets, and drizzle's migrator reads the .sql files
# and meta/_journal.json from disk at runtime. resolveMigrationsDir() finds them
# relative to WORKDIR (/app), NOT relative to the bundle — import.meta.url there
# points at dist/, where these have never been.
#
# In runtime-base rather than a single stage because both services migrate, and
# because Railway builds only the final stage whatever the service is named
# (see the note below).
COPY --from=builder /app/lib/db/migrations ./lib/db/migrations

# The frontend lives in the shared base rather than only in the web stage.
# It costs the scanner image a couple of megabytes of static files it will never
# serve, and buys the ability to run either entrypoint from either image — which
# is what lets a platform that builds a Dockerfile without choosing a target
# (Railway, for one) run both services from one build.
COPY --from=builder /app/artifacts/vibescan/dist/public ./artifacts/vibescan/dist/public

# In production app.ts serves the SPA itself. It resolves the static directory
# relative to dist/index.mjs, which makes the copied layout load-bearing; set
# the path explicitly so a future layout change cannot silently 404 the frontend.
ENV FRONTEND_STATIC_DIR=/app/artifacts/vibescan/dist/public

# index.ts throws unless PORT is set. It lives here rather than on the web stage
# so that every runtime image can boot the web entrypoint — which matters
# because a service whose start command names index.mjs may be running an image
# built from a different stage than intended.
ENV PORT=8080


# ─────────────────────────────────────────────────────────────────────────────
# web — the web tier
#
# No Playwright and no Chromium: nothing reachable from src/index.ts imports
# them. That is enforced by the bundle, not by convention — `grep playwright
# dist/index.mjs` returns nothing, and the lazy import in scanCredentials.ts is
# what keeps it that way.
# ─────────────────────────────────────────────────────────────────────────────
FROM runtime-base AS web

USER node

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/api/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# index.ts throws unless PORT is set; runtime-base sets it for every image.
CMD ["node", "--enable-source-maps", "artifacts/api-server/dist/index.mjs"]


# ─────────────────────────────────────────────────────────────────────────────
# A note on stage selection, because the obvious assumption is wrong
#
# Railway does NOT choose a build target by matching stage name to service name.
# Verified from build logs on 2026-09-09: the web service, named `web`, built
# `builder` -> `runtime-base` -> `secscan` and nothing else. The `web` stage
# below was not built at all. Railway builds the FINAL stage and ignores the
# rest, whatever the service is called.
#
# That is survivable only because of the deliberate choice in runtime-base:
# both entrypoints and the frontend live there, so either image runs either
# process, and the web service names index.mjs in its start command. The cost
# is that the public web tier ships Chromium it never uses.
#
# The `web` stage is still real and still used — docker-compose.yml builds it
# with `target: web`, and that is the deployment path where the Chromium
# separation is actually enforced.
#
# Before reordering stages: the FINAL stage must stay `secscan`. The scanner
# has no start command and runs whatever CMD the image carries, so if a web
# stage were last the scanner would silently become a second web tier and
# queued scans would never be claimed. That has happened.
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# secscan — the scanner tier
#
# This is the image that carries Chromium. It has no HTTP listener: work arrives
# only through the pg-boss `scan-job` queue, so there is no port to expose and
# no endpoint to health-check.
# ─────────────────────────────────────────────────────────────────────────────
FROM runtime-base AS secscan

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# esbuild bundles the scanner into dist/secscan.mjs with one exception:
# `playwright` is listed in build.mjs `external`, so it must be a real package
# at runtime, alongside a Chromium build matching the library version. Keep this
# version in step with the `playwright` dependency in artifacts/api-server.
#
# Without this the worker still starts, but logs "Failed to launch headless
# browser — SPA rendering disabled" and silently skips JS rendering during
# scans, which is a core capability for scanning single-page apps.
#
# The browser download is retried: it pulls from cdn.playwright.dev, which has
# been observed failing DNS resolution mid-build (ENOTFOUND) while the npm
# registry resolved fine in the same step. One transient blip should not fail
# an otherwise good image build.
RUN npm install --no-save --omit=dev playwright@1.64.0 \
 && for attempt in 1 2 3; do \
      npx playwright install --with-deps chromium && break; \
      echo "playwright browser install failed (attempt $attempt/3); retrying in 15s"; \
      [ "$attempt" = 3 ] && exit 1; \
      sleep 15; \
    done \
 && chmod -R a+rX /ms-playwright \
 && npm cache clean --force \
 && rm -rf /var/lib/apt/lists/*

USER node

# secscan has no port, so liveness comes from the heartbeat the worker writes
# once it is registered and able to take jobs. start-period covers the browser
# install and first queue connection; an idle scanner is healthy, a silent one
# is not.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD ["node", "artifacts/api-server/dist/healthcheck-secscan.mjs"]

CMD ["node", "--enable-source-maps", "artifacts/api-server/dist/secscan.mjs"]

