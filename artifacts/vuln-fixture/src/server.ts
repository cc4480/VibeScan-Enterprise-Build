import { mountInfra } from "./fixture-infra.js";
import { SESSIONS } from "./fixture-sessions.js";
import { mountHeaders } from "./fixture-headers.js";
import { mountAssets } from "./fixture-assets.js";
import { mountPages } from "./fixture-pages.js";
import { mountSsrf } from "./fixture-ssrf.js";
import { mountApp } from "./fixture-app.js";
import { mountRecords } from "./fixture-records.js";
import { mountTail } from "./fixture-tail.js";
import express, { type Request, type Response } from "express";
import { mountInjectionExtras } from "./injection-extra-routes.js";
import { mountGraphqlExtras } from "./graphql-extra-routes.js";
import { mountRuntimeApi } from "./runtime-api-routes.js";
import { mountAccountAiRace, SUPPORT_JS } from "./account-ai-race-routes.js";
import { mountEdgeCases } from "./account-ai-race-edge-routes.js";

/**
 * A deliberately vulnerable app. Every route below plants one real instance of
 * a finding secscan.us's scanner checks for — read from the check's own source
 * and detection logic, not guessed, and self-tested against the real regexes
 * before this file existed (see scripts/self-test-*.ts and README.md).
 *
 * This is infrastructure for testing the scanner, not a product to ship: it is
 * never built by the root `build` script and its dist is never copied into the
 * Docker image (see Dockerfile — only api-server/dist and vibescan/dist/public
 * are copied out of the builder stage).
 *
 * TWO deployment modes, not one:
 *
 *   1. Local / CI (the default, no extra env vars). Unrestricted — including
 *      the SSRF endpoint, which is how scripts/verify-vuln-fixture.ts and the
 *      cross-scanner benchmark in scripts/benchmark/ prove that finding today.
 *      Never point this mode at a shared or public host.
 *
 *   2. Public benchmark target (secscan-me/, not this package). Same code,
 *      started with SSRF_PROBE_ALLOWLIST set — see the comment on
 *      /api/webhook-preview below. That is the ONLY behavioural difference; a
 *      route added here without checking whether it can reach the network on
 *      a caller-supplied host is a mode-2 regression, not just a mode-1 one.
 *
 * Every route's endpoint AND parameter name are also either linked from the
 * homepage nav or deliberately left unlinked — see the comment above <nav> —
 * because a public benchmark target that only SecScan's own wordlist can find
 * in full is not a neutral one. Keep that split intact when adding a route.
 */













const app = express();
app.use(express.json());
app.disable("x-powered-by");
mountInfra(app);

mountHeaders(app);

mountAssets(app);

mountPages(app);

// ─────────────────────────────────────────────────────────────────────────────
// Reflected XSS + SQL injection (injectionProbe.ts), and doubles as the
// read-shaped POST /api/search endpoint apiProbe.ts discovers from the spec
// (READ_SHAPED matches "search" in the path).
// ─────────────────────────────────────────────────────────────────────────────
function searchHandler(req: Request, res: Response) {
  const q = String((req.method === "GET" ? req.query.q : req.body?.q) ?? "");
  // Input carrying markup is reflected as HTML (the XSS). It is checked first because the
  // XSS probe's payload also contains a quote, which would otherwise take the SQL-error
  // branch below and come back as text/plain, where it is not exploitable.
  if (!q.includes("<") && q.includes("'")) {
    // A believable SQLite error, matched by injectionProbe's SQL_ERROR_SIGNATURES.
    res.status(500).type("text/plain").send(`SQLITE_ERROR: near "'": syntax error while compiling: SELECT * FROM records WHERE name = '${q}'`);
    return;
  }
  // Reflected, unescaped — the XSS.
  res.type("text/html").send(`<html><body><h1>Results for: ${q}</h1><p>No records found.</p></body></html>`);
}
mountInjectionExtras(app);
mountRuntimeApi(app);
mountGraphqlExtras(app);
// Edge-case twins first: they answer only on their own hosts/paths and pass everything else through.
mountEdgeCases(app, SESSIONS);
mountAccountAiRace(app, SESSIONS);
app.get("/assets/support.js", (_req, res) => { res.type("application/javascript").send(SUPPORT_JS); });
app.get("/search", searchHandler);
app.post("/api/search", searchHandler);
mountSsrf(app);

mountApp(app);

mountRecords(app);

mountTail(app);

const PORT = Number(process.env.PORT ?? 4100);
app.listen(PORT, () => {
  console.log(`[vuln-fixture] listening on http://127.0.0.1:${PORT}`);
});
