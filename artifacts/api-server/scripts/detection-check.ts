/**
 * Detection validation.
 *
 * Every other check in this repo asks "does the scanner stay quiet when it
 * should?". This asks the opposite question, which nothing else does: given a
 * target with known, deliberately planted flaws, does the scanner find them?
 *
 * A scanner that reports nothing has a perfect false-positive rate. After a
 * long run of false-positive fixes, that is the failure mode to guard against,
 * and only a target whose faults are known in advance can measure it.
 *
 * This serves a local fixture with a fixed list of planted flaws, scans it with
 * active probing on (we own the target), and reports which flaws were found and
 * which were missed. Ground truth lives in EXPECTED below.
 *
 *   node artifacts/api-server/scripts/detection-check.mjs
 *
 * Exit code is non-zero when something planted was missed, so it can gate CI.
 */
import { createServer } from "node:http";

import { createServer as _c } from "node:http";
process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = "true";
process.env["DATABASE_URL"] ??= "postgres://localhost/detection-check";

import { runScan } from "../src/lib/scanner.js";

// ── The fixture: a small site that is wrong in specific, known ways ──────────

const INLINE_SECRETS = `
  // Not AWS's documented AKIAIOSFODNN7EXAMPLE: that contains "EXAMPLE" and the
  // scanner correctly suppresses placeholder keys, so planting it tested the
  // false-positive guard rather than detection.
  const AWS_KEY = "AKIA3XKWQZJ7NRVB4TMD";
  const cfg = { apiUrl: "https://api.example.com" };
  const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTg4MTQiLCJlbWFpbCI6Im9wc0BleGFtcGxlLmNvbSIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTU0NjMwMDgwMH0.ccccccccccccccccccccccccccccccccccccccccccc";
`;

const HOME = `<!doctype html>
<html><head><title>Detection Fixture</title></head>
<body>
  <h1>Fixture</h1>
  <a href="/inner">inner page</a>
  <script src="/app.js"></script>
  <script>${INLINE_SECRETS}</script>
  <script src="https://cdn.example.net/analytics.js"></script>
</body></html>`;

const SOURCE_MAP = JSON.stringify({
  version: 3,
  sources: ["src/app.ts", "src/billing.ts"],
  sourcesContent: ["export const a = 1;", "const STRIPE = 'sk_live_x';"],
  mappings: "AAAA",
});

const OPENAPI = JSON.stringify({
  openapi: "3.0.0",
  info: { title: "Fixture API", version: "1.0.0", description: "Deliberately exposed contract for detection testing." },
  paths: {
    "/orders": { get: { summary: "List orders", parameters: [{ name: "limit", in: "query" }] } },
    "/customers": { get: { summary: "List customers" }, post: { summary: "Create" } },
  },
});

const routes = {
  "/": { body: HOME, ct: "text/html" },
  "/inner": { body: "<html><head><title>Inner</title></head><body>inner</body></html>", ct: "text/html" },
  "/app.js": { body: `console.log(1);\n//# sourceMappingURL=/app.js.map`, ct: "application/javascript" },
  "/app.js.map": { body: SOURCE_MAP, ct: "application/json" },
  "/.env": { body: "DB_PASSWORD=hunter2\nSTRIPE_SECRET_KEY=sk_live_abcdefghijklmnop\nAPI_TOKEN=xyz\n", ct: "text/plain" },
  "/.git/HEAD": { body: "ref: refs/heads/main\n", ct: "text/plain" },
  "/openapi.json": { body: OPENAPI, ct: "application/json" },
  "/robots.txt": { body: "User-agent: *\nDisallow: /admin\nDisallow: /backup\n", ct: "text/plain" },
};

const server = createServer((req, res) => {
  const path = (req.url ?? "/").split("?")[0];
  const hit = routes[path];

  // Headers deliberately omitted: CSP, X-Frame-Options, X-Content-Type-Options,
  // Referrer-Policy, Permissions-Policy, HSTS. Present and wrong: Server and
  // X-Powered-By version disclosure, wildcard CORS, and three bad cookies.
  const headers = {
    "content-type": hit ? hit.ct : "text/plain",
    server: "nginx/1.14.0",
    "x-powered-by": "PHP/5.6.40",
    "access-control-allow-origin": "*",
  };
  if (path === "/") {
    headers["set-cookie"] = [
      "sessionid=abc123; Path=/",              // no Secure, no HttpOnly, no SameSite
      "auth_token=zzz; Path=/",                // same
      "theme=dark; Path=/",                    // non-session, less severe
    ];
  }

  res.writeHead(hit ? 200 : 404, headers);
  res.end(hit ? hit.body : "Not Found");
});

/** What is actually wrong with the fixture. Each entry must be detected. */
const EXPECTED = [
  { id: "no-https", label: "Plaintext HTTP (no HTTPS)", match: /HTTPS|Plaintext/i },
  { id: "csp", label: "Missing Content-Security-Policy", match: /Missing Content-Security-Policy/i },
  { id: "xfo", label: "Missing clickjacking protection", match: /Clickjacking|X-Frame-Options/i },
  { id: "xcto", label: "Missing X-Content-Type-Options", match: /X-Content-Type-Options/i },
  { id: "referrer", label: "Missing Referrer-Policy", match: /Referrer-Policy/i },
  { id: "permissions", label: "Missing Permissions-Policy", match: /Permissions-Policy/i },
  { id: "cookie-secure", label: "Session cookie missing Secure", match: /Session Cookie Missing Secure/i },
  { id: "cookie-httponly", label: "Session cookie missing HttpOnly", match: /Session Cookie Missing HttpOnly/i },
  { id: "cookie-samesite", label: "Session cookie missing SameSite", match: /Session Cookie Missing SameSite/i },
  { id: "cors", label: "Wildcard CORS origin", match: /CORS/i },
  { id: "server-version", label: "Server version disclosure", match: /Server (Version|Header)|Version Disclosure/i },
  { id: "powered-by", label: "X-Powered-By disclosure", match: /X-Powered-By/i },
  { id: "env-file", label: "Exposed .env file", match: /\.env|Environment File/i },
  { id: "git", label: "Exposed .git repository", match: /Git Repo|\.git/i },
  { id: "sourcemap", label: "Exposed JavaScript source map", match: /Source Map/i },
  { id: "aws-key", label: "AWS access key in JavaScript", match: /AWS Access Key/i },
  { id: "jwt", label: "Hardcoded JWT carrying an identity claim", match: /JWT/i },
  { id: "openapi", label: "Exposed OpenAPI specification", match: /API Documentation|OpenAPI/i },
  { id: "robots", label: "robots.txt discloses sensitive paths", match: /robots\.txt/i },
];

const port = await new Promise((resolve) => {
  server.listen(0, "127.0.0.1", () => resolve(server.address().port));
});
const target = `http://127.0.0.1:${port}/`;
console.log(`[detection] fixture on ${target}`);
console.log(`[detection] ${EXPECTED.length} planted flaws to find\n`);

let result;
try {
  result = await runScan(target, "deep", true, undefined, null);
} finally {
  server.close();
}

const names = result.vulnerabilities.map((v) => `${v.name} :: ${v.category}`);
const found = [];
const missed = [];
for (const e of EXPECTED) {
  (names.some((n) => e.match.test(n)) ? found : missed).push(e);
}

console.log(`Findings returned: ${result.vulnerabilities.length}`);
for (const sev of ["critical", "high", "medium", "low", "info"]) {
  const n = result.vulnerabilities.filter((v) => v.severity === sev).length;
  if (n) console.log(`  ${sev.padEnd(9)} ${n}`);
}

console.log(`\nDetected ${found.length}/${EXPECTED.length} planted flaws:`);
for (const e of found) console.log(`  [FOUND ] ${e.label}`);
if (missed.length) {
  console.log("");
  for (const e of missed) console.log(`  [MISSED] ${e.label}`);
}

if (process.argv.includes("--list")) {
  console.log("\nEvery finding returned:");
  for (const v of result.vulnerabilities.sort((a, b) => a.severity.localeCompare(b.severity))) {
    console.log(`  [${v.severity.toUpperCase().padEnd(8)}] ${v.name}`);
  }
}

if (missed.length) {
  console.error(`\nFAIL — ${missed.length} planted flaw(s) not detected.`);
  process.exit(1);
}
console.log("\nPASS — every planted flaw was detected.");
