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
# web and secscan are built from the same workspace but deploy as two
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
# Name aliases — so a Railway service resolves to the web tier by name
#
# Railway picks a build target by matching the stage name to the service name.
# A service whose name matches no stage builds the FINAL stage instead, which is
# the scanner — that is how a queue worker with no HTTP listener once got
# deployed as the public web app. These aliases exist only to give such names
# something to match.
#
# `seclayer` is transitional: the SecScan project's web service is still called
# that, and this keeps it matching the web tier until it is renamed. Remove this
# alias once the Railway service is renamed to `web`.
#
# `seclayer-app` dates from when the seclayer.app service built from THIS repo.
# It now builds from seclayer.io2026 and has its own Dockerfile, so this alias
# is very likely dead — left in place rather than removed blind.
#
# It deliberately is NOT last. The final stage is the fallback for any service
# Railway cannot name-match, and that fallback has to be the scanner: the web
# services name index.mjs in their start command and boot correctly from any
# runtime image, while the scanner service has no start command and so runs
# whatever CMD the image carries. With the web tier last, the scanner silently
# became a second web tier and every queued scan sat unclaimed forever.
# ─────────────────────────────────────────────────────────────────────────────
FROM web AS seclayer
FROM web AS seclayer-app

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

