import express, { type Express } from "express";
import cors, { type CorsOptions } from "cors";
import cookieParser from "cookie-parser";
import pinoHttp from "pino-http";
import { existsSync } from "node:fs";
import nodePath from "node:path";
import { fileURLToPath } from "node:url";
import { createProxyMiddleware } from "http-proxy-middleware";
import router from "./routes";
import { logger } from "./lib/logger";
import { authMiddleware } from "./middlewares/authMiddleware";

const __dirname = nodePath.dirname(fileURLToPath(import.meta.url));

// CSP for the frontend SPA — no unsafe-inline in script-src because Vite's
// production bundle uses only external JS files.  style-src keeps unsafe-inline
// for Tailwind's runtime class injection.
const FRONTEND_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self' data:",
  "img-src 'self' data: https: blob:",
  "connect-src 'self' https: wss: ws:",
  "worker-src 'self' blob:",
  "frame-ancestors 'none'",
  "object-src 'none'",
  "base-uri 'self'",
].join("; ");

// Explicit CORS allowlist — never reflect the incoming Origin blindly.
// In dev, also allow *.replit.dev preview domains.
const CORS_ALLOWLIST: (string | RegExp)[] = [
  "https://vibe-scan.replit.app",
  "https://vibescan.app",
  ...(process.env.CORS_EXTRA_ORIGINS?.split(",").map((o) => o.trim()).filter(Boolean) ?? []),
  ...(process.env.NODE_ENV !== "production" ? [/\.replit\.dev$/] : []),
];

const corsOptions: CorsOptions = {
  credentials: true,
  origin(origin, callback) {
    // Same-origin browser requests have no Origin header — always allow.
    if (!origin) return callback(null, true);
    const allowed = CORS_ALLOWLIST.some((pattern) =>
      typeof pattern === "string" ? pattern === origin : pattern.test(origin),
    );
    callback(null, allowed ? origin : false);
  },
};

const app: Express = express();

// Hide "X-Powered-By: Express" — no reason to advertise the server tech.
app.disable("x-powered-by");

// ── Security response headers — set before all routes ────────────────────────
// In production Express owns everything (API + static frontend) so we set
// headers on every response.
//
// In development Express proxies non-API traffic to the Vite dev server.
// Vite injects an inline <script type="module"> preamble that React Fast
// Refresh needs.  If Express also sets `script-src 'self'` (no unsafe-inline)
// on those proxied responses the browser sees TWO CSP headers and enforces
// the union — the restrictive Express header wins and blocks the preamble,
// causing the "@vitejs/plugin-react can't detect preamble" runtime error.
// Fix: in dev mode skip CSP and cross-origin isolation headers on frontend
// routes; Vite's own headers (which include 'unsafe-inline') take effect.
const isProd = process.env.NODE_ENV === "production";

app.use((req, res, next) => {
  const isApi = req.path.startsWith("/api");

  // Safe headers that don't interfere with Vite HMR in any environment.
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");

  if (isApi) {
    // API responses: strict no-content CSP in all environments.
    res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
    res.setHeader("X-Frame-Options", "DENY");
    // All API responses must not be cached — scan results and report data are
    // user-specific and time-sensitive; a stale cache would show outdated findings.
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    if (isProd) {
      res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
    }
  } else if (isProd) {
    // Production frontend: full SPA CSP + cross-origin isolation.
    // In dev these are omitted so Vite's own headers apply unmolested.
    res.setHeader("Content-Security-Policy", FRONTEND_CSP);
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    res.setHeader("Cross-Origin-Embedder-Policy", "credentialless");
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
  }

  next();
});

app.use(
  pinoHttp({
    logger,
    serializers: {
      req(req) {
        return {
          id: req.id,
          method: req.method,
          url: req.url?.split("?")[0],
        };
      },
      res(res) {
        return {
          statusCode: res.statusCode,
        };
      },
    },
  }),
);

// CORS is scoped to /api only — static frontend files are same-origin and
// don't need CORS headers.  Applying cors() globally was what caused the
// "Origin reflection + credentials" critical finding.
app.use("/api", cors(corsOptions));

app.use(cookieParser());

// Stripe webhook needs raw body BEFORE json() middleware
app.use(
  "/api/scan/webhook",
  express.raw({ type: "application/json" }),
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(authMiddleware);

app.use("/api", router);

// ── Frontend serving ──────────────────────────────────────────────────────────
// Development:  forward all non-API traffic to the Vite dev server (port 18425)
//               so HMR and fast-refresh work.
// Production:   serve the pre-built Vite bundle; SPA fallback rewrites unknown
//               paths to index.html so client-side routing (/report/123) works.
//
// dotfiles: "allow" is required so /.well-known/security.txt is served —
// express.static silently ignores dot-directories by default.
if (process.env.NODE_ENV !== "production") {
  const viteTarget = `http://localhost:${process.env.VITE_PORT ?? "18425"}`;
  logger.info({ viteTarget }, "Dev mode: proxying frontend to Vite");

  app.use(
    createProxyMiddleware({
      target: viteTarget,
      changeOrigin: false,
      ws: true,
    }),
  );
} else {
  const staticDir = nodePath.resolve(
    process.cwd(),
    process.env.FRONTEND_STATIC_DIR ?? "artifacts/vibescan/dist/public",
  );

  if (existsSync(staticDir)) {
    logger.info({ staticDir }, "Production: serving static frontend");
    app.use(express.static(staticDir, { dotfiles: "allow" }));
    // SPA fallback — client-side routes (e.g. /report/abc) must receive index.html
    app.get(/.*/, (_req, res) => {
      res.sendFile(nodePath.join(staticDir, "index.html"));
    });
  } else {
    logger.warn({ staticDir }, "Frontend static dir not found — frontend will not be served");
  }
}

export default app;
