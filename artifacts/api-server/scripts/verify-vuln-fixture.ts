/**
 * Points the REAL scanner — passive, active, and credentialed with two
 * accounts — at artifacts/vuln-fixture and reports which of its planted
 * findings were actually detected.
 *
 * This is the detection-check.ts idea at the scale of the full check list: a
 * target whose faults are known exactly, so what comes back can be verified
 * rather than trusted. See artifacts/vuln-fixture/README.md for the full list
 * of what is and is not covered, and why.
 *
 * Usage:
 *   1. In one terminal: pnpm --filter @workspace/vuln-fixture run start
 *   2. In another:
 *        DATABASE_URL=postgres://localhost/whatever \
 *          npx tsx artifacts/api-server/scripts/verify-vuln-fixture.ts
 *
 * Exit code is non-zero when something planted was missed.
 */
process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = "true";
process.env["DATABASE_URL"] ??= "postgres://localhost/verify-vuln-fixture";

import { runScan } from "../src/lib/scanner.js";
import { isOobConfigured } from "../src/lib/oobServer.js";
import { initBrowser, closeBrowser } from "../src/lib/browser.js";
import { verifyActingProbes } from "./verify-acting-probes.js";

const TARGET = process.argv.slice(2).find((a) => !a.startsWith("--")) ?? "http://127.0.0.1:4100";

/** Every finding this fixture is designed to produce, grouped by the module that owns it. */
const EXPECTED: Array<{ module: string; label: string; match: RegExp }> = [
  // ── scanner.ts (root headers/cookies) ───────────────────────────────────
  { module: "scanner.ts", label: "CSP script-src wildcard", match: /CSP script-src Contains Wildcard/i },
  { module: "scanner.ts", label: "Weak CSP (unsafe-inline/eval)", match: /Weak Content-Security-Policy/i },
  { module: "scanner.ts", label: "CSP missing object-src", match: /object-src/i },
  { module: "scanner.ts", label: "CSP missing base-uri", match: /base-uri/i },
  { module: "scanner.ts", label: "Missing X-Content-Type-Options", match: /X-Content-Type-Options/i },
  { module: "scanner.ts", label: "Missing Referrer-Policy", match: /Referrer-Policy Header/i },
  { module: "scanner.ts", label: "Missing Permissions-Policy", match: /Permissions-Policy Header/i },
  { module: "scanner.ts", label: "Missing COOP/COEP/CORP", match: /Cross-Origin-(Opener|Embedder|Resource)-Policy/i },
  { module: "scanner.ts", label: "Wildcard CORS (passive)", match: /Permissive CORS Policy/i },
  { module: "scanner.ts", label: "Session cookie missing Secure/HttpOnly/SameSite", match: /Session Cookie Missing|Cookie Missing SameSite/i },
  { module: "scanner.ts", label: "Server version disclosure", match: /Server Version Disclosure/i },
  { module: "scanner.ts", label: "X-Powered-By disclosure", match: /X-Powered-By/i },
  // NOT expected, and this is correct, not a gap — see README "Verified
  // absent by design":
  //   - "CSP allows inline styles" is an `else if` after the weak-CSP
  //     (script-src) finding, which this fixture also triggers; the two are
  //     mutually exclusive by the check's own design.
  //   - "Missing HSTS" / "Missing Cache-Control" are both gated on `isHttps`
  //     in scanner.ts, and this fixture runs on plain HTTP deliberately.
  //   - "Rate Limiting Not Advertised in Response Headers" (the header
  //     heuristic) is deliberately dropped by scanner.ts whenever the
  //     behavioural burst test in apiProbe.ts also fired — which it does here
  //     ("No Rate Limiting Observed on Sensitive API Endpoints" below) — so seeing the
  //     stronger finding and not the weaker one is the dedup working.
  { module: "cveCheck.ts", label: "Nginx EOL/CVE", match: /Nginx.*(?:CVE|End-of-Life)/i },
  { module: "cveCheck.ts", label: "PHP EOL", match: /PHP .* is End-of-Life/i },

  // ── probes.ts (active) ───────────────────────────────────────────────────
  { module: "probes.ts", label: "CORS credentials allowed from arbitrary origin", match: /CORS Misconfiguration — Credentials Allowed/i },
  { module: "probes.ts", label: "Write HTTP methods advertised", match: /Write HTTP Methods Advertised/i },
  { module: "probes.ts", label: "TRACE enabled", match: /TRACE Method Enabled/i },
  { module: "probes.ts", label: "CONNECT enabled", match: /CONNECT Method Enabled/i },
  { module: "probes.ts", label: "Open redirect", match: /Open Redirect Vulnerability/i },
  { module: "probes.ts", label: "robots.txt discloses sensitive paths", match: /robots\.txt Discloses/i },
  { module: "probes.ts", label: "Missing SRI", match: /Subresource Integrity/i },
  { module: "probes.ts", label: "Flask/Werkzeug debugger exposed", match: /Werkzeug Interactive Debugger/i },
  { module: "probes.ts", label: "Directory listing enabled", match: /Directory Listing Enabled/i },
  { module: "probes.ts", label: "Missing security.txt", match: /Missing security\.txt/i },

  // ── crawler.ts / crawler-data.ts (inner routes) ─────────────────────────
  { module: "crawler.ts", label: "CSP missing on internal route", match: /Content-Security-Policy Missing on.*Internal Route/i },

  // ── deserializationProbe.ts (CWE-502) ───────────────────────────────────
  // Tracked here rather than under scanner.ts because the probe is only
  // reached from crawler.ts, so the cookies are planted on /app/dashboard.
  //
  // Added 2026-09-20, closing the last check in SCAN_CHECKS.md that had never
  // been observed firing anywhere: not in this fixture, and zero times across
  // all 50 corpus runs. It had only ever been exercised by unit tests, which
  // made it indistinguishable from a check that no longer worked — the same
  // shape as the two production false negatives this fixture exists to catch.
  { module: "deserializationProbe.ts", label: "Java serialized object in a cookie", match: /Insecure Deserialization Exposure \(Java object/i },
  { module: "deserializationProbe.ts", label: "Ruby Marshal object in a cookie", match: /Insecure Deserialization Exposure \(Ruby \(Marshal\) object/i },
  { module: "deserializationProbe.ts", label: "Python pickle object in a cookie", match: /Insecure Deserialization Exposure \(Python \(pickle\) object/i },
  { module: "deserializationProbe.ts", label: "PHP serialized object in a cookie (URL-decoded)", match: /Insecure Deserialization Exposure \(PHP object/i },
  { module: "crawler-data.ts", label: ".env exposed on inner route", match: /Environment File Exposed on Inner Route/i },
  { module: "crawler-data.ts", label: "git exposed on inner route", match: /Git Repository Exposed on Inner Route/i },
  { module: "crawler-data.ts", label: "config exposed on inner route", match: /Configuration File Exposed on Inner Route/i },
  { module: "crawler-data.ts", label: "API docs exposed on inner route", match: /API Documentation Exposed on Inner Route/i },
  { module: "crawler-data.ts", label: "debug.log exposed on inner route", match: /Debug Log Exposed on Inner Route/i },
  { module: "crawler-data.ts", label: "GraphQL exposed on inner route", match: /GraphQL Endpoint Exposed on Inner Route/i },

  // ── probes-data.ts (sensitive files) — a sample, not all 78 ─────────────
  { module: "probes-data.ts", label: ".env exposed", match: /Environment File Exposed \(\.env\)/i },
  { module: "probes-data.ts", label: "wp-config.php exposed", match: /WordPress Config File Exposed/i },
  { module: "probes-data.ts", label: "id_rsa exposed", match: /SSH Private Key Exposed/i },
  { module: "probes-data.ts", label: "git repo exposed (root)", match: /^Git Repository Exposed$/i },
  { module: "probes-data.ts", label: "terraform state exposed", match: /Terraform State File Exposed/i },
  { module: "probes-data.ts", label: "actuator/env exposed", match: /Spring Boot Actuator \/env Exposed/i },
  { module: "probes-data.ts", label: "phpMyAdmin exposed", match: /phpMyAdmin Database Admin Exposed/i },
  { module: "probes-data.ts", label: "crossdomain.xml wildcard", match: /Permissive crossdomain\.xml Policy/i },
  { module: "probes-data.ts", label: "xmlrpc.php enabled", match: /WordPress XML-RPC Enabled/i },
  { module: "probes-data.ts", label: ".htpasswd exposed", match: /htpasswd Password File Exposed/i },
  { module: "probes-data.ts", label: "backup archive exposed", match: /Backup Archive Exposed/i },

  // ── secret-pattern-data.ts (jsScanner) — a sample ───────────────────────
  { module: "jsScanner", label: "AWS access key in JS", match: /AWS Access Key ID Found in Client Code/i },
  { module: "jsScanner", label: "Stripe live key in JS", match: /Stripe Live Secret Key Exposed/i },
  { module: "jsScanner", label: "GitHub PAT in JS", match: /GitHub Personal Access Token Exposed/i },
  { module: "jsScanner", label: "DB connection string in JS", match: /Database Connection URL with Credentials/i },
  { module: "jsScanner", label: "hardcoded JWT in JS", match: /Hardcoded JWT Token in Source/i },
  { module: "jsScanner", label: "private key in JS", match: /Private Key Exposed in JavaScript/i },
  { module: "jsScanner", label: "Slack bot token in JS", match: /Slack Bot\/OAuth Token Exposed/i },
  { module: "jsScanner", label: "Supabase sb_secret_ key in JS", match: /Supabase Service Role Key Exposed \(sb_secret_\)/i },
  { module: "jsScanner", label: "Supabase service_role key in JS", match: /Supabase Service Role Key Exposed in JavaScript/i },
  { module: "jsScanner", label: "Twilio SID and secret in JS", match: /Twilio API Key SID and Secret Exposed/i },
  { module: "jsScanner", label: "JWT naming an account but no principal", match: /JWT-Shaped Publishable Key in Client Code/i },

  // ── nextjsProbe.ts ───────────────────────────────────────────────────────
  { module: "nextjsProbe.ts", label: "Stripe key in __NEXT_DATA__", match: /Stripe Live Secret Key in __NEXT_DATA__/i },
  { module: "nextjsProbe.ts", label: "AWS key in __NEXT_DATA__", match: /AWS Access Key ID in __NEXT_DATA__/i },
  { module: "nextjsProbe.ts", label: "DB conn string in __NEXT_DATA__", match: /Database Connection String in __NEXT_DATA__/i },

  // ── jwtAnalysis.ts ───────────────────────────────────────────────────────
  { module: "jwtAnalysis.ts", label: "alg:none JWT", match: /JWT Using alg:none/i },
  { module: "jwtAnalysis.ts", label: "JWT no expiry", match: /JWT Token Has No Expiry/i },
  { module: "jwtAnalysis.ts", label: "JWT excessive lifetime", match: /JWT Token Lifetime Is .* Days/i },
  { module: "jwtAnalysis.ts", label: "sensitive data in JWT payload", match: /Sensitive Data Stored in JWT Payload/i },

  // ── aiFeatureProbe.ts (ai-widget.js is vulnerable; ai-chat.js is its clean twin)
  { module: "aiFeatureProbe.ts", label: "AI provider called from the browser", match: /AI Provider Called Directly From the Browser/i },
  { module: "aiFeatureProbe.ts", label: "AI system prompt in client code", match: /AI System Prompt Shipped in Client-Side Code/i },

  // ── sourceMaps.ts ────────────────────────────────────────────────────────
  { module: "sourceMaps.ts", label: "source map exposed", match: /Source Map Exposed/i },

  // ── apiDocsProbe.ts ──────────────────────────────────────────────────────
  { module: "apiDocsProbe.ts", label: "OpenAPI spec exposed", match: /Exposed API Documentation/i },
  // ── healthEndpointProbe.ts (the clean /api/health must be passed over) ──
  { module: "healthEndpointProbe.ts", label: "Health endpoint discloses runtime details", match: /Health Endpoint Discloses Runtime Details/i },

  // ── graphqlProbe.ts (needs --active) ────────────────────────────────────
  { module: "graphqlProbe.ts", label: "GraphQL introspection enabled", match: /GraphQL Introspection Enabled/i },
  { module: "graphqlExtra.ts", label: "GraphQL query batching enabled", match: /GraphQL Query Batching Enabled/i },
  { module: "graphqlExtra.ts", label: "GraphQL IDE exposed", match: /GraphQL IDE Exposed/i },
  { module: "graphqlProbe.ts", label: "GraphQL field suggestions leak", match: /Field Suggestions Enabled/i },

  // ── injectionProbe.ts (needs --active) ──────────────────────────────────
  { module: "injectionProbe.ts", label: "Reflected XSS", match: /Reflected Cross-Site Scripting/i },
  { module: "injectionExtra.ts", label: "Server-side template injection", match: /Server-Side Template Injection/i },
  { module: "injectionExtra.ts", label: "HTTP header injection (CRLF)", match: /HTTP Header Injection/i },
  { module: "promptInjectionProbe.ts", label: "LLM prompt injection extracts the system prompt", match: /LLM Prompt Injection Extracts the System Prompt/i },
  { module: "raceConditionProbe.ts", label: "Race condition on a one-time action", match: /Race Condition Allows a One-Time Action/i },
  { module: "injectionProbe.ts", label: "SQL injection (error-based)", match: /SQL Injection \(Error-Based\)/i },

  // ── pathTraversal.ts (needs --active) ───────────────────────────────────
  { module: "pathTraversal.ts", label: "Path traversal / LFI", match: /Path Traversal.*LFI/i },

  // ── ssrfProbe.ts (needs --active AND a reachable OOB_BASE_URL/APP_ORIGIN —
  // this is the one check in this file that needs a real second HTTP server
  // actually listening for the callback, not just runScan called as a library.
  // See vuln-fixture/README.md, "Not covered" — this was moved out of there
  // once this fired for real against a live collector, not asserted from
  // reading the code. ) ─────────────────────────────────────────────────────
  { module: "ssrfProbe.ts", label: "SSRF confirmed via out-of-band callback", match: /Server-Side Request Forgery \(SSRF\)/i },

  // ── apiProbe.ts (needs credentials; cross-account needs --secondary) ────
  { module: "apiProbe.ts", label: "API served without authentication", match: /API Endpoints Served Without Authentication/i },
  { module: "apiProbe.ts", label: "Sensitive fields returned by API", match: /Sensitive Fields Returned by the API/i },
  { module: "apiProbe.ts", label: "Write endpoint reachable without auth (BFLA)", match: /Write Endpoints Reachable Without Authentication/i },
  // POST /api/users declares a "role" body field in the fixture's spec. Read from the contract,
  // never sent; this used to be missed because the check ran only on read-shaped endpoints.
  { module: "apiProbe.ts", label: "Mass assignment (privilege field on create)", match: /Privilege Fields Accepted in Request Bodies/i },
  { module: "apiProbe.ts", label: "SQL injection in API parameter", match: /SQL Injection in API Parameters/i },
  { module: "apiProbe.ts", label: "API records readable by another account", match: /API Records Readable by Another Account/i },

  // ── accessControlProbe.ts (needs credentials + secondary) ───────────────
  { module: "accessControlProbe.ts", label: "IDOR (page-level)", match: /Broken Object-Level Authorisation/i },
  { module: "accessControlProbe.ts", label: "Records enumerable by editing the identifier", match: /Records Enumerable by Editing/i },
];

async function main(): Promise<void> {
  const primary = { cookie: "session=alice-session-token" };
  const secondary = { cookie: "session=bob-session-token" };

  console.log(`[verify] scanning ${TARGET} (active + credentialed, two accounts)`);
  await initBrowser();
  const result = await runScan(TARGET, "deep", true, { credentials: primary, secondary }, null, undefined, { raceConditionTesting: true });

  await closeBrowser();

  const names = result.vulnerabilities.map((v) => v.name);
  console.log(`\nFindings returned: ${result.vulnerabilities.length}\n`);

  // SSRF needs a second real HTTP server actually listening for the callback
  // — runScan calling registerOobToken is not enough by itself. Requiring it
  // unconditionally would turn the README's own quick-verify command (a bogus
  // DATABASE_URL, no OOB_BASE_URL) into a permanent failure for everyone who
  // has not also stood up that second server, so it drops out of scope here
  // rather than counting as missed.
  const oobReady = isOobConfigured();
  const expected = EXPECTED.filter((e) => e.module !== "ssrfProbe.ts" || oobReady);
  const skipped = EXPECTED.filter((e) => e.module === "ssrfProbe.ts" && !oobReady);

  const found: typeof EXPECTED = [];
  const missed: typeof EXPECTED = [];
  for (const e of expected) {
    (names.some((n) => e.match.test(n)) ? found : missed).push(e);
  }

  if (skipped.length) {
    console.log(`[verify] OOB_BASE_URL/APP_ORIGIN not configured for a reachable callback — skipping:`);
    for (const e of skipped) console.log(`  [SKIPPED] ${e.module.padEnd(24)} ${e.label}`);
    console.log("");
  }

  console.log(`Detected ${found.length}/${expected.length}:\n`);
  for (const e of found) console.log(`  [FOUND ] ${e.module.padEnd(24)} ${e.label}`);
  if (missed.length) {
    console.log("");
    for (const e of missed) console.log(`  [MISSED] ${e.module.padEnd(24)} ${e.label}`);
  }

  // Clean twins: safe routes doing the same job as vulnerable ones. Any finding whose
  // text names one of them is a false positive, and fails the run like a missed check.
  // Found only by watching the rendered page make its own requests (apiRuntime.ts).
  const runtimeFound = result.vulnerabilities.some((v) => `${v.evidence ?? ""} ${v.description}`.includes("/api/runtime/lookup"));
  console.log(`  [${runtimeFound ? "FOUND " : "MISSED"}] apiRuntime.ts            API discovered only at runtime`);

  // The edge cases (account-ai-race-edge-routes.ts) are clean twins too: none of them may be named by a finding.
  // /api/voucher/redeem is NOT one: it is a real race, checked by verify-acting-probes.ts.
  const CLEAN_TWINS = [
    "/api/graphql", "/hello?", "/lang2?", "echoq", "/assets/ai-chat.js", "/api/chat", "/api/promo/claim",
    "/api/faq/ask", "/api/sales/ask", "/api/kb/ask", "/api/reward/redeem", "/api/gift/claim",
    "/uploads/config.json",
  ];
  const falseAlarms = result.vulnerabilities.filter((v) => CLEAN_TWINS.some((t) => `${v.evidence ?? ""} ${v.description}`.includes(t)));
  if (falseAlarms.length) {
    console.log("");
    for (const v of falseAlarms) console.log(`  [FALSE ALARM] ${v.name}: names a clean twin`);
  }

  // Each acting probe against its vulnerable route and its clean twin, one at a time.
  const acting = await verifyActingProbes(TARGET);
  console.log("");
  for (const c of acting) console.log(`  [${c.ok ? "FOUND " : "MISSED"}] ${c.module.padEnd(24)} ${c.label}${c.ok || !c.detail ? "" : ` (${c.detail})`}`);
  const actingFailed = acting.filter((c) => !c.ok);

  if (process.argv.includes("--list")) {
    console.log("\nEvery finding returned:");
    for (const v of result.vulnerabilities.sort((a, b) => a.severity.localeCompare(b.severity))) {
      console.log(`  [${v.severity.toUpperCase().padEnd(8)}] ${v.name}`);
    }
  }

  if (!runtimeFound) {
    console.log("\nThe API that only a running browser can find was not tested. Is Chromium installed (npx playwright install chromium)?");
    process.exit(1);
  }
  if (falseAlarms.length > 0) {
    console.log(`\n${falseAlarms.length} finding(s) named a clean twin: a false positive.`);
    process.exit(1);
  }
  if (actingFailed.length > 0) {
    console.log(`\n${actingFailed.length} acting-probe check(s) failed.`);
    process.exit(1);
  }
  if (missed.length > 0) {
    console.log(`\n${missed.length} planted finding(s) not detected. See README.md before assuming the fixture is wrong.`);
    process.exit(1);
  }
  console.log("\nPASS — every planted finding this scan mode covers was detected.");
}

void main().catch((err) => {
  console.error(err);
  process.exit(2);
});
