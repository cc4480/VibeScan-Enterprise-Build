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
  //     ("API Endpoints Without Rate Limiting" below) — so seeing the
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
  { module: "jsScanner", label: "AWS access key in JS", match: /AWS Access Key ID Exposed/i },
  { module: "jsScanner", label: "Stripe live key in JS", match: /Stripe Live Secret Key Exposed/i },
  { module: "jsScanner", label: "GitHub PAT in JS", match: /GitHub Personal Access Token Exposed/i },
  { module: "jsScanner", label: "DB connection string in JS", match: /Database Connection URL with Credentials/i },
  { module: "jsScanner", label: "hardcoded JWT in JS", match: /Hardcoded JWT Token in Source/i },
  { module: "jsScanner", label: "private key in JS", match: /Private Key Exposed in JavaScript/i },

  // ── nextjsProbe.ts ───────────────────────────────────────────────────────
  { module: "nextjsProbe.ts", label: "Stripe key in __NEXT_DATA__", match: /Stripe Live Secret Key in __NEXT_DATA__/i },
  { module: "nextjsProbe.ts", label: "AWS key in __NEXT_DATA__", match: /AWS Access Key ID in __NEXT_DATA__/i },
  { module: "nextjsProbe.ts", label: "DB conn string in __NEXT_DATA__", match: /Database Connection String in __NEXT_DATA__/i },

  // ── jwtAnalysis.ts ───────────────────────────────────────────────────────
  { module: "jwtAnalysis.ts", label: "alg:none JWT", match: /JWT Using alg:none/i },
  { module: "jwtAnalysis.ts", label: "JWT no expiry", match: /JWT Token Has No Expiry/i },
  { module: "jwtAnalysis.ts", label: "JWT excessive lifetime", match: /JWT Token Lifetime Is .* Days/i },
  { module: "jwtAnalysis.ts", label: "sensitive data in JWT payload", match: /Sensitive Data Stored in JWT Payload/i },

  // ── sourceMaps.ts ────────────────────────────────────────────────────────
  { module: "sourceMaps.ts", label: "source map exposed", match: /Source Map Exposed/i },

  // ── apiDocsProbe.ts ──────────────────────────────────────────────────────
  { module: "apiDocsProbe.ts", label: "OpenAPI spec exposed", match: /Exposed API Documentation/i },

  // ── graphqlProbe.ts (needs --active) ────────────────────────────────────
  { module: "graphqlProbe.ts", label: "GraphQL introspection enabled", match: /GraphQL Introspection Enabled/i },
  { module: "graphqlProbe.ts", label: "GraphQL field suggestions leak", match: /Field Suggestions Enabled/i },

  // ── injectionProbe.ts (needs --active) ──────────────────────────────────
  { module: "injectionProbe.ts", label: "Reflected XSS", match: /Reflected Cross-Site Scripting/i },
  { module: "injectionProbe.ts", label: "SQL injection (error-based)", match: /SQL Injection \(Error-Based\)/i },

  // ── pathTraversal.ts (needs --active) ───────────────────────────────────
  { module: "pathTraversal.ts", label: "Path traversal / LFI", match: /Path Traversal.*LFI/i },

  // ── apiProbe.ts (needs credentials; cross-account needs --secondary) ────
  { module: "apiProbe.ts", label: "API served without authentication", match: /API Endpoints Served Without Authentication/i },
  { module: "apiProbe.ts", label: "Sensitive fields returned by API", match: /Sensitive Fields Returned by the API/i },
  { module: "apiProbe.ts", label: "Write endpoint reachable without auth (BFLA)", match: /Write Endpoints Reachable Without Authentication/i },
  // NOT expected: privilegeFieldsAccepted() correctly identifies "role" as
  // privileged on POST /api/users from the spec alone (confirmed directly,
  // not through a full scan), but runApiProbes only evaluates endpoints
  // matching isReadShaped (search/query/filter/lookup/find/list/report/
  // graphql/validate/preview/check in the path) — by design, since it also
  // gates body-injection testing, and a POST that changes data must not be
  // probed by sending it a body. That filter runs before the privilege-field
  // check too, even though the latter never sends a request. An ordinary
  // signup/create endpoint is exactly where a mass-assignment bug usually
  // lives, and it is exactly the shape excluded — a real scanner gap, not a
  // fixture bug. See README "Known limitations".
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
  const result = await runScan(TARGET, "deep", true, { credentials: primary, secondary }, null);

  const names = result.vulnerabilities.map((v) => v.name);
  console.log(`\nFindings returned: ${result.vulnerabilities.length}\n`);

  const found: typeof EXPECTED = [];
  const missed: typeof EXPECTED = [];
  for (const e of EXPECTED) {
    (names.some((n) => e.match.test(n)) ? found : missed).push(e);
  }

  console.log(`Detected ${found.length}/${EXPECTED.length}:\n`);
  for (const e of found) console.log(`  [FOUND ] ${e.module.padEnd(24)} ${e.label}`);
  if (missed.length) {
    console.log("");
    for (const e of missed) console.log(`  [MISSED] ${e.module.padEnd(24)} ${e.label}`);
  }

  if (process.argv.includes("--list")) {
    console.log("\nEvery finding returned:");
    for (const v of result.vulnerabilities.sort((a, b) => a.severity.localeCompare(b.severity))) {
      console.log(`  [${v.severity.toUpperCase().padEnd(8)}] ${v.name}`);
    }
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
