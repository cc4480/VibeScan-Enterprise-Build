/** The frontend Content-Security-Policy and the CORS allowlist. */
import { type CorsOptions } from "cors";
import { APP_ORIGIN } from "./lib/appOrigin";

// CSP for the frontend SPA — no unsafe-inline in script-src because Vite's
// production bundle uses only external JS files.
//
// style-src MUST keep 'unsafe-inline'. Verified against the production build:
// the HTML shell has no inline styles, but bundled runtime libraries inject
// <style> elements via document.createElement("style") at load time —
// html2canvas + jsPDF (report PDF export) and chart/animation libs in the main
// bundle. style-src governs those injections, so dropping 'unsafe-inline'
// silently breaks PDF export and some UI styling. The only correct way to
// remove it is nonce-based CSP, which requires injecting a per-response nonce
// into server-rendered markup — not possible while the built index.html is
// served as a static file. Reported as information that needs verification (CSS-injection only;
// script-src is clean, so no JS execution risk).
export const FRONTEND_CSP = [
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
//
// The production origin is derived from APP_ORIGIN rather than hardcoded, so
// moving the site to a new domain is a configuration change rather than a code
// change. Anything else that
// still needs access goes in CORS_EXTRA_ORIGINS.
//
// www is included alongside the bare domain because a redirect from www to
// apex happens at the CDN, and a browser that resolves www first would
// otherwise have its preflight rejected before the redirect is followed.
export function withWww(origin: string): string[] {
  try {
    const url = new URL(origin);
    if (url.hostname.startsWith("www.")) return [origin];
    return [origin, `${url.protocol}//www.${url.hostname}`];
  } catch {
    return [origin];
  }
}

export const CORS_ALLOWLIST: (string | RegExp)[] = [
  ...withWww(APP_ORIGIN),
  ...(process.env.CORS_EXTRA_ORIGINS?.split(",").map((o) => o.trim()).filter(Boolean) ?? []),
  ...(process.env.NODE_ENV !== "production" ? [/^http:\/\/localhost(:\d+)?$/] : []),
];

export const corsOptions: CorsOptions = {
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
