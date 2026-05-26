# ── Stage 1: install dependencies ────────────────────────────────────────────
FROM node:24-alpine AS deps
RUN corepack enable pnpm

WORKDIR /app
COPY pnpm-workspace.yaml pnpm-lock.yaml ./
COPY package.json ./
COPY tsconfig.base.json tsconfig.json ./
COPY lib/db/package.json ./lib/db/
COPY lib/api-zod/package.json ./lib/api-zod/
COPY lib/api-client-react/package.json ./lib/api-client-react/
COPY lib/auth-web/package.json ./lib/auth-web/
COPY artifacts/api-server/package.json ./artifacts/api-server/

RUN pnpm install --frozen-lockfile

# ── Stage 2: build ────────────────────────────────────────────────────────────
FROM deps AS builder

COPY lib/ ./lib/
COPY artifacts/api-server/ ./artifacts/api-server/

RUN pnpm --filter @workspace/api-server run build

# ── Stage 3: runtime ──────────────────────────────────────────────────────────
FROM node:24-alpine AS runtime

WORKDIR /app
ENV NODE_ENV=production

COPY --from=builder /app/artifacts/api-server/dist ./dist
# pino transports are externalised by esbuild; copy them from the build stage
COPY --from=builder /app/node_modules ./node_modules

EXPOSE 8080

CMD ["node", "--enable-source-maps", "./dist/index.mjs"]
