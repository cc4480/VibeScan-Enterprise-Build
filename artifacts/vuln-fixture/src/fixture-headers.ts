import type { Express } from "express";
import { type Response } from "express";

/** Site-wide response headers, the unflagged session cookie, and OPTIONS on any path. */


export function mountHeaders(app: Express): void {
  // ─────────────────────────────────────────────────────────────────────────────
  // Response headers — the site-wide (scanner.ts) findings.
  //
  // CSP: bare wildcard in script-src (High), unsafe-inline/unsafe-eval (Medium),
  // no object-src 'none' (Medium), no base-uri (Low), inline styles allowed (Low).
  // No HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP,
  // COEP, CORP, or Cache-Control — all omitted, all Info/Low/Medium findings.
  // Server + X-Powered-By: end-of-life version banners for cveCheck.ts.
  // ─────────────────────────────────────────────────────────────────────────────
  app.use((req, res, next) => {
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' *; style-src 'self' 'unsafe-inline'",
    );
    res.setHeader("Server", "nginx/1.14.0"); // CVE-2021-23017
    res.setHeader("X-Powered-By", "PHP/5.6.40"); // EOL

    // Wildcard CORS when no Origin header (the passive, scanner.ts finding);
    // reflect-with-credentials when one is sent (the active, probes.ts Critical
    // finding — checkActiveCors). Same misconfiguration most real ones are:
    // `res.header('Access-Control-Allow-Origin', req.headers.origin || '*')`
    // plus a blanket `Access-Control-Allow-Credentials: true`.
    const origin = req.headers.origin;
    res.setHeader("Access-Control-Allow-Origin", typeof origin === "string" ? origin : "*");
    res.setHeader("Access-Control-Allow-Credentials", "true");

    next();
  });

  // A session cookie missing every flag (Secure, HttpOnly, SameSite), set on
  // every response so both the root scan and the crawler's per-page check see it.
  app.use((req, res, next) => {
    res.setHeader("Set-Cookie", "theme=dark; Path=/");
    next();
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // OPTIONS on any path — dangerous HTTP methods (probes.ts: TRACE, CONNECT,
  // PUT/DELETE). Plain middleware rather than a wildcard route: Express 5's
  // path-to-regexp no longer accepts a bare "*" route pattern.
  // ─────────────────────────────────────────────────────────────────────────────
  app.use((req, res, next) => {
    if (req.method !== "OPTIONS") {
      next();
      return;
    }
    res.setHeader("Allow", "GET, HEAD, POST, PUT, DELETE, TRACE, CONNECT, OPTIONS");
    res.status(204).end();
  });
}
