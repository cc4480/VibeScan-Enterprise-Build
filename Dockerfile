# Seclayer — production image.
#
# Chromium drives the base-image choice: the scanner renders JavaScript-heavy
# SPAs headlessly, and Chromium's system library set (~30 shared objects) is
# tedious and fragile to assemble by hand. Microsoft's Playwright image ships
# exactly the set matching the pinned Playwright version, and already carries
# Node 24 and corepack — so both stages use it. Sharing one base means the build
# and runtime Node versions cannot drift, the layers are shared rather than
# duplicated, and the build pulls nothing from Docker Hub (which rate-limits
# anonymous pulls, a common cause of CI/deploy failures).
#
# APP_ORIGIN must be passed at BUILD time, not just run time: the frontend bakes
# it into canonical links, Open Graph tags, JSON-LD and the sitemap, and those
# are static by the time the container starts.

ARG PLAYWRIGHT_VERSION=1.62.1

# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM mcr.microsoft.com/playwright:v${PLAYWRIGHT_VERSION}-noble AS builder

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
# pnpm refuses to purge node_modules without a TTY; a build has none, which
# makes the --prod re-resolve below abort with ERR_PNPM_ABORTED_REMOVE_MODULES_DIR_NO_TTY.
ENV CI=true
RUN corepack enable

WORKDIR /app

# Manifests first so the dependency layer caches independently of source edits.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc tsconfig.base.json tsconfig.json ./
COPY artifacts/api-server/package.json      artifacts/api-server/
COPY artifacts/vibescan/package.json        artifacts/vibescan/
COPY artifacts/mockup-sandbox/package.json  artifacts/mockup-sandbox/
COPY lib/api-client-react/package.json      lib/api-client-react/
COPY lib/api-spec/package.json              lib/api-spec/
COPY lib/api-zod/package.json               lib/api-zod/
COPY lib/db/package.json                    lib/db/
COPY lib/replit-auth-web/package.json       lib/replit-auth-web/
COPY scripts/package.json                   scripts/

# --ignore-scripts: nothing here needs postinstall, and it keeps Playwright from
# pulling a second browser download into the build layer.
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm install --frozen-lockfile --ignore-scripts

COPY . .

# Shared libs use TypeScript project references — their dist/*.d.ts is what the
# app packages compile against, so these must be emitted first.
RUN pnpm --filter @workspace/db run build \
 && pnpm --filter @workspace/api-zod run build \
 && pnpm --filter @workspace/api-client-react run build \
 && pnpm --filter @workspace/replit-auth-web run build

ARG APP_ORIGIN=https://secscan.us
ENV APP_ORIGIN=${APP_ORIGIN}
ENV NODE_ENV=production

RUN pnpm --filter @workspace/vibescan run build \
 && pnpm --filter @workspace/api-server run build

# Re-resolve to production dependencies only, for copying into the runtime stage.
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm install --frozen-lockfile --prod --ignore-scripts

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM mcr.microsoft.com/playwright:v${PLAYWRIGHT_VERSION}-noble AS runtime

ENV NODE_ENV=production
# PLAYWRIGHT_BROWSERS_PATH is set by the base image (/ms-playwright); browser.ts
# discovers the installed chromium-<rev> directory under it rather than assuming
# a revision, so the two stay in step across base-image bumps.
ENV PORT=8080
ENV FRONTEND_STATIC_DIR=/app/artifacts/vibescan/dist/public

WORKDIR /app

# The API is bundled by esbuild into dist/index.mjs, but packages listed as
# `external` in build.mjs (playwright, pg-native and friends) still resolve from
# node_modules at run time.
COPY --from=builder /app/node_modules                        ./node_modules
COPY --from=builder /app/artifacts/api-server/node_modules   ./artifacts/api-server/node_modules
COPY --from=builder /app/artifacts/api-server/dist           ./artifacts/api-server/dist
COPY --from=builder /app/artifacts/vibescan/dist/public      ./artifacts/vibescan/dist/public
COPY --from=builder /app/lib                                 ./lib
COPY --from=builder /app/package.json                        ./package.json

# The base image ships a `pwuser`; run as it rather than root. Chromium's
# sandbox needs no write access to the app tree.
RUN chown -R pwuser:pwuser /app
USER pwuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/api/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "--enable-source-maps", "artifacts/api-server/dist/index.mjs"]
