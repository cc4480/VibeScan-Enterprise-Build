# syntax=docker/dockerfile:1

# ─────────────────────────────────────────────────────────────────────────────
# Builder
#
# glibc (bookworm), NOT Alpine. pnpm-workspace.yaml removes every *-musl native
# variant via `overrides` (@tailwindcss/oxide-linux-x64-musl,
# rollup-linux-x64-musl, …), so on a musl base the frontend build cannot
# resolve its platform binaries and fails.
# ─────────────────────────────────────────────────────────────────────────────
FROM node:24-bookworm AS builder

WORKDIR /app
ENV CI=true

RUN corepack enable

COPY . .

RUN pnpm install --frozen-lockfile

# -r runs in topological order, so the lib packages (db, api-zod,
# api-client-react, replit-auth-web) are compiled before the two apps that
# import their type output. mockup-sandbox is an unrelated demo artifact and is
# excluded to keep the build lean.
#
# The root `build` script also runs a typecheck first; it is deliberately not
# used here so that a pre-existing type error cannot block producing an image.
RUN pnpm -r --if-present --filter '!@workspace/mockup-sandbox' run build


# ─────────────────────────────────────────────────────────────────────────────
# Runtime base — everything both apps need, and nothing either one does not.
#
# seclayer and secscan are built from the same workspace but deploy as two
# separate images. They share this base so a change to the Node version or the
# bundle layout cannot drift between them.
# ─────────────────────────────────────────────────────────────────────────────
FROM node:24-bookworm-slim AS runtime-base

ENV NODE_ENV=production

WORKDIR /app

# Both entrypoints (index.mjs and secscan.mjs) live in this directory; each image
# runs only its own. The unused bundle costs a couple of MB and keeps this layer
# identical between the two images, which is worth more than trimming it.
COPY --from=builder /app/artifacts/api-server/dist ./artifacts/api-server/dist

# The frontend lives in the shared base rather than only in the seclayer stage.
# It costs the scanner image a couple of megabytes of static files it will never
# serve, and buys the ability to run either entrypoint from either image — which
# is what lets a platform that builds a Dockerfile without choosing a target
# (Railway, for one) run both services from one build.
COPY --from=builder /app/artifacts/vibescan/dist/public ./artifacts/vibescan/dist/public

# In production app.ts serves the SPA itself. It resolves the static directory
# relative to dist/index.mjs, which makes the copied layout load-bearing; set
# the path explicitly so a future layout change cannot silently 404 the frontend.
ENV FRONTEND_STATIC_DIR=/app/artifacts/vibescan/dist/public


# ─────────────────────────────────────────────────────────────────────────────
# seclayer — the web tier
#
# No Playwright and no Chromium: nothing reachable from src/index.ts imports
# them. That is enforced by the bundle, not by convention — `grep playwright
# dist/index.mjs` returns nothing, and the lazy import in scanCredentials.ts is
# what keeps it that way.
# ─────────────────────────────────────────────────────────────────────────────
FROM runtime-base AS seclayer

ENV PORT=8080

USER node

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/api/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# index.ts throws unless PORT is set; ENV PORT above satisfies it.
CMD ["node", "--enable-source-maps", "artifacts/api-server/dist/index.mjs"]


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
RUN npm install --no-save --omit=dev playwright@1.62.1 \
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


# ─────────────────────────────────────────────────────────────────────────────
# seclayer-app — alias for the standalone seclayer.app Railway project
#
# Railway selects a Docker build target by matching the stage name to the
# service name, falling back to the last stage in the file (secscan) when
# nothing matches. The service in the seclayer.app project is named
# "seclayer-app", not "seclayer", so with no matching stage it was silently
# building the scanner image instead of the web tier — a background worker
# with no HTTP listener, requiring DATABASE_URL, deployed as the public web
# app. This stage exists only to give it a name match. Keep it last in the
# file for the same reason: any other platform that builds this Dockerfile
# without choosing a target should still get seclayer, not secscan.
# ─────────────────────────────────────────────────────────────────────────────
FROM seclayer AS seclayer-app
