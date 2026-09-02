import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
import type { Plugin } from "vite";

// index.html carries an inline <script> that repairs a half-initialised React
// DevTools hook (added in 71fca36 — without it the Replit dev environment fails
// to render at all). Production CSP is `script-src 'self'` with no nonce, so the
// browser blocks it and logs a violation on every page load; the shim is a dev
// concern and does nothing in production anyway. Strip it from the build rather
// than weakening the CSP to admit it.
// The public origin is baked into the bundle at build time: canonical links,
// Open Graph URLs, JSON-LD @ids, the sitemap and robots.txt all have to name
// the domain the site is actually served from. Getting this wrong is not
// cosmetic — a canonical tag pointing at a domain you do not own tells search
// engines the content belongs to someone else.
const APP_ORIGIN = (process.env.APP_ORIGIN ?? "https://secscan.us").replace(/\/$/, "");

// The origin the source files were authored against.
const PLACEHOLDER_ORIGIN = "https://seclayer.io";
const PLACEHOLDER_DOMAIN = "seclayer.io";
const APP_DOMAIN = APP_ORIGIN.replace(/^https?:\/\//, "");

/**
 * Both forms have to be rewritten: the full origin in canonical/OG/JSON-LD URLs,
 * and the bare domain, which appears in contact email addresses
 * ("reports@seclayer.io"). Origin first — otherwise the bare-domain pass would
 * corrupt the scheme-qualified occurrences.
 */
function applyOrigin(text: string): string {
  return text
    .split(PLACEHOLDER_ORIGIN)
    .join(APP_ORIGIN)
    .split(PLACEHOLDER_DOMAIN)
    .join(APP_DOMAIN);
}

/** Rewrite the authored origin to the configured one in index.html. */
function applyOriginToHtml(): Plugin {
  return {
    name: "apply-origin-to-html",
    transformIndexHtml(html) {
      return applyOrigin(html);
    },
  };
}

/**
 * Same rewrite for files served verbatim out of public/ — they bypass the
 * bundle entirely, so they are patched in the output directory after the copy.
 */
function applyOriginToPublicFiles(): Plugin {
  const targets = ["robots.txt", "sitemap.xml", "llms.txt"];
  return {
    name: "apply-origin-to-public-files",
    apply: "build",
    async closeBundle() {
      const { readFile, writeFile } = await import("node:fs/promises");
      const outDir = path.resolve(import.meta.dirname, "dist/public");
      for (const name of targets) {
        const file = path.join(outDir, name);
        try {
          const original = await readFile(file, "utf8");
          const rewritten = applyOrigin(original);
          if (rewritten !== original) await writeFile(file, rewritten);
        } catch {
          // A missing public file is not a build failure.
        }
      }
    },
  };
}

function stripDevtoolsShim(): Plugin {
  return {
    name: "strip-devtools-hook-shim",
    apply: "build",
    transformIndexHtml(html) {
      return html.replace(
        /\s*<script>\s*\(function \(\) \{[\s\S]*?__REACT_DEVTOOLS_GLOBAL_HOOK__[\s\S]*?\}\)\(\);?\s*<\/script>/,
        "",
      );
    },
  };
}

// Security headers for the Vite preview server (production build previews only).
// Dev server intentionally has NO custom headers — the Express API server
// applies the full header set in production, and injecting a CSP from Vite in
// dev mode causes the "@vitejs/plugin-react can't detect preamble" error because
// the browser enforces the union of any duplicate CSP headers.
const isProduction = process.env.NODE_ENV === "production";
const securityHeaders: Record<string, string> = isProduction
  ? {
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
      "X-Frame-Options": "DENY",
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Resource-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "credentialless",
      "Content-Security-Policy": [
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
      ].join("; "),
    }
  : {};

// PORT and BASE_PATH are injected by the artifact router via artifact.toml [services.env].
// Defaults match the artifact.toml values so the config also works when run directly.
const port = Number(process.env.PORT ?? "18425");
const basePath = process.env.BASE_PATH ?? "/";

export default defineConfig({
  base: basePath,
  define: {
    __APP_ORIGIN__: JSON.stringify(APP_ORIGIN),
  },
  plugins: [
    stripDevtoolsShim(),
    applyOriginToHtml(),
    applyOriginToPublicFiles(),
    react(),
    tailwindcss(),
    runtimeErrorOverlay(),
    ...(process.env.NODE_ENV !== "production" &&
    process.env.REPL_ID !== undefined
      ? [
          await import("@replit/vite-plugin-cartographer").then((m) =>
            m.cartographer({
              root: path.resolve(import.meta.dirname, ".."),
            }),
          ),
          await import("@replit/vite-plugin-dev-banner").then((m) =>
            m.devBanner(),
          ),
        ]
      : []),
  ],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "src"),
    },
    dedupe: ["react", "react-dom"],
  },
  root: path.resolve(import.meta.dirname),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true,
  },
  server: {
    port,
    host: "0.0.0.0",
    allowedHosts: true,
    fs: {
      strict: true,
      deny: ["**/.*"],
    },
    headers: securityHeaders,
    proxy: {
      "/api": {
        target: "http://localhost:8080",
        changeOrigin: true,
      },
    },
  },
  preview: {
    port,
    host: "0.0.0.0",
    allowedHosts: true,
    headers: securityHeaders,
  },
});
