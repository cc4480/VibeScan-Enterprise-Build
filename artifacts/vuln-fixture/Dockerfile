# syntax=docker/dockerfile:1
#
# Hardened, standalone image for the vuln-fixture — used both for local
# cross-scanner benchmark runs and, hardened further at the ORCHESTRATION
# layer (see deploy/secscan-me/), as the public secscan.me benchmark target.
#
# Deliberately isolated from the rest of the monorepo at the IMAGE level:
# `pnpm deploy` below produces a self-contained directory holding only this
# package and its resolved dependencies (just `express`), so the runtime
# image never has api-server, vibescan, or anything that talks to a real
# database, a real Stripe key, or any other product secret — even by
# accident, even if this Dockerfile is copied and misused. A public target
# should have nothing worth stealing in the same container as the bugs it
# advertises.
#
# This Dockerfile hardens the CONTAINER (non-root, read-only rootfs, no
# extra capabilities). It intentionally does NOT harden the network: a
# public deployment's egress restriction belongs at the orchestration layer
# (Fly.io/Railway network policy, or a sidecar proxy), not baked into an
# image that local benchmark runs also use unrestricted. See
# deploy/secscan-me/README.md for that half.

# ─────────────────────────────────────────────────────────────────────────────
# Deploy — isolate this one workspace package into a self-contained folder.
# glibc (bookworm), matching the root Dockerfile's own reasoning: some
# workspace devDependencies resolve *-musl native binaries that don't exist
# on Alpine once pnpm-workspace.yaml's overrides strip the non-matching ones.
# ─────────────────────────────────────────────────────────────────────────────
FROM node:24-bookworm AS deploy

WORKDIR /repo
ENV CI=true
RUN corepack enable

COPY . .
RUN pnpm install --frozen-lockfile
# Compile TS -> JS here, in the builder, where tsc is available — the
# deployed folder below is --prod only and never sees a TypeScript compiler.
RUN pnpm --filter @workspace/vuln-fixture run build
RUN pnpm --filter @workspace/vuln-fixture deploy --prod /out
# `pnpm deploy` copies package.json + node_modules but not build output that
# lives outside them; bring dist/ across explicitly.
RUN cp -r artifacts/vuln-fixture/dist /out/dist

# ─────────────────────────────────────────────────────────────────────────────
# Runtime — nothing but the deployed package. No shell utilities beyond what
# the base image ships, no monorepo, no other workspace's code or secrets.
# ─────────────────────────────────────────────────────────────────────────────
FROM node:24-bookworm-slim AS runtime

# A dedicated, unprivileged, home-less user — never the image's default
# `node` account, so a CVE targeting a *known* default user/uid in a public
# base image gets nothing extra from matching it.
RUN groupadd --gid 10001 fixture \
    && useradd --uid 10001 --gid fixture --no-create-home --shell /usr/sbin/nologin fixture

WORKDIR /app
COPY --from=deploy --chown=fixture:fixture /out /app

USER fixture
ENV NODE_ENV=production
EXPOSE 4100

# --read-only at `docker run` / the platform's container spec is what makes
# the root filesystem actually immutable; this HEALTHCHECK and the process
# below don't need to write anywhere, so no writable tmpfs is declared here
# — add one only if a future route needs it, deliberately.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD node -e "fetch('http://127.0.0.1:4100/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/server.js"]
