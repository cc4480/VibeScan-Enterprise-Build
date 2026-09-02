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
# Runtime
# ─────────────────────────────────────────────────────────────────────────────
FROM node:24-bookworm-slim AS runtime

ENV NODE_ENV=production \
    PORT=8080 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

# esbuild bundles the entire API server into dist/index.mjs with one exception:
# `playwright` is listed in build.mjs `external`, so it must be a real package
# at runtime, alongside a Chromium build matching the library version. Keep this
# version in step with the `playwright` dependency in artifacts/api-server.
#
# Without this the server still starts, but logs "Failed to launch headless
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

COPY --from=builder /app/artifacts/api-server/dist ./artifacts/api-server/dist
COPY --from=builder /app/artifacts/vibescan/dist/public ./artifacts/vibescan/dist/public

# In production app.ts serves the SPA itself. It resolves the static directory
# relative to dist/index.mjs, which makes the copied layout load-bearing; set
# the path explicitly so a future layout change cannot silently 404 the frontend.
ENV FRONTEND_STATIC_DIR=/app/artifacts/vibescan/dist/public

USER node

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/api/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# index.ts throws unless PORT is set; ENV PORT above satisfies it.
CMD ["node", "--enable-source-maps", "artifacts/api-server/dist/index.mjs"]
