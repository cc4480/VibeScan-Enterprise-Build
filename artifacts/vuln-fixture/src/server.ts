/**
 * A deliberately vulnerable app. Every route below plants one real instance of
 * a finding secscan.us's scanner checks for — read from the check's own source
 * and detection logic, not guessed, and self-tested against the real regexes
 * before this file existed (see scripts/self-test-*.ts and README.md).
 *
 * This is infrastructure for testing the scanner, not a product to ship: it is
 * never built by the root `build` script and its dist is never copied into the
 * Docker image (see Dockerfile — only api-server/dist and vibescan/dist/public
 * are copied out of the builder stage). Deploy it only somewhere you control,
 * scan it only with the ownership-verification flow this product already
 * requires for active probing, and never point it at a shared or public host.
 */
import express, { type Request, type Response } from "express";
import { SENSITIVE_PATHS } from "./sensitive-paths.js";
import {
  SECRETS_JS,
  NEXT_DATA_PROPS,
  OPENAPI_SPEC,
  JWT_ALG_NONE,
  JWT_NO_EXPIRY,
  JWT_EXCESSIVE_LIFETIME,
  JWT_SENSITIVE_PAYLOAD,
  STRIPE_SOURCEMAP_KEY,
} from "./secrets.js";

const app = express();
app.use(express.json());
app.disable("x-powered-by"); // Express's own default; we set our own EOL banner below.

// ── In-memory "accounts", so a two-account credentialed scan has something to
// compare. Session tokens are fixed strings rather than anything issued at
// request time, so a verify script can hold both without driving a login form.
const SESSIONS: Record<string, { id: string; email: string }> = {
  "alice-session-token": { id: "1001", email: "alice@example.com" },
  "bob-session-token": { id: "1002", email: "bob@example.com" },
};

function sessionFromCookie(req: Request): { id: string; email: string } | null {
  const cookie = req.headers.cookie ?? "";
  const match = /session=([^;]+)/.exec(cookie);
  return (match && SESSIONS[match[1]!]) || null;
}

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

// ─────────────────────────────────────────────────────────────────────────────
// robots.txt — discloses sensitive-looking paths (probes.ts checkRobotsTxt).
// No security.txt anywhere: that finding is "missing", so it is earned by
// omission, not a route.
// ─────────────────────────────────────────────────────────────────────────────
app.get("/robots.txt", (_req, res) => {
  res.type("text/plain").send(
    "User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /internal-api\nDisallow: /.env\nDisallow: /staging\n",
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// Root OpenAPI doc — apiDocsProbe.ts "Exposed API Documentation".
// ─────────────────────────────────────────────────────────────────────────────
app.get("/openapi.json", (_req, res) => res.json(OPENAPI_SPEC));

// ─────────────────────────────────────────────────────────────────────────────
// JS bundle — secret-pattern-data.ts (jsScanner), external-file path, plus a
// source map reference (sourceMaps.ts) whose map embeds a secret too.
// ─────────────────────────────────────────────────────────────────────────────
app.get("/assets/app.js", (_req, res) => {
  res.type("application/javascript").send(SECRETS_JS + "\n//# sourceMappingURL=/assets/app.js.map\n");
});
app.get("/assets/app.js.map", (_req, res) => {
  res.json({
    version: 3,
    sources: ["src/app.ts", "src/billing.ts"],
    sourcesContent: [
      "export const a = 1;",
      `export const STRIPE_SECRET = '${STRIPE_SOURCEMAP_KEY}';`,
    ],
    mappings: "AAAA",
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Home page: __NEXT_DATA__ (nextjsProbe.ts), JWTs (jwtAnalysis.ts), links for
// the crawler to find (/app/dashboard for crawler-data.ts's inner-route
// probes, /account/1001 for accessControlProbe.ts, /uploads/ for directory
// listing), no Open Graph / Twitter Card / JSON-LD (structuredData.ts INFO
// findings, earned by omission).
// ─────────────────────────────────────────────────────────────────────────────
// checkOpenRedirect tests the SCAN TARGET URL itself with each known redirect
// parameter appended — not a separate path — so this has to live on "/".
const OPEN_REDIRECT_PARAM_NAMES = [
  "redirect", "url", "next", "goto", "return", "returnUrl", "returnTo",
  "r", "redirect_uri", "callback", "continue", "dest", "destination", "forward",
];

app.get("/", (req, res) => {
  const target = (Object.entries(req.query).find(([k]) => OPEN_REDIRECT_PARAM_NAMES.includes(k)) ?? [])[1];
  if (typeof target === "string") {
    res.redirect(302, target);
    return;
  }
  res.send(`<!doctype html>
<html><head><title>Fixture</title>
<script id="__NEXT_DATA__" type="application/json">${JSON.stringify(NEXT_DATA_PROPS)}</script>
</head><body>
<div id="__next"></div>
<h1>vuln-fixture</h1>
<nav>
  <a href="/app/dashboard">Dashboard</a>
  <a href="/account/1001">My account</a>
  <a href="/uploads/">Uploads</a>
  <a href="/search?q=test">Search</a>
</nav>
<!-- Session tokens, visible in page HTML: jwtAnalysis.ts reads headers + html -->
<span data-token="${JWT_ALG_NONE}"></span>
<span data-token="${JWT_NO_EXPIRY}"></span>
<span data-token="${JWT_EXCESSIVE_LIFETIME}"></span>
<span data-token="${JWT_SENSITIVE_PAYLOAD}"></span>
<script src="/assets/app.js"></script>
<script src="https://cdn.example.net/analytics.js"></script>
</body></html>`);
});

// ─────────────────────────────────────────────────────────────────────────────
// Sensitive file exposure — every path in probes-data.ts, matched exactly.
// Anything not in the map below falls through to the catch-all 404 at the
// bottom, deliberately: a real 404 for everything else is what keeps
// detectCatchAll from seeing a catch-all shape here at all, so none of these
// get suppressed as "just the SPA shell".
// ─────────────────────────────────────────────────────────────────────────────
for (const [path, file] of Object.entries(SENSITIVE_PATHS)) {
  app.get(path, (_req, res) => {
    res.type(file.contentType ?? "text/plain").send(file.body);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// crossdomain.xml also needs the wildcard-DELETE... no: served above via the
// sensitive-paths loop. Directory listing (probes.ts checkDirectoryListing) —
// one of DIRECTORY_LISTING_DIRS with an autoindex-shaped body.
// ─────────────────────────────────────────────────────────────────────────────
app.get("/uploads/", (_req, res) => {
  res.type("text/html").send(
    `<html><head><title>Index of /uploads/</title></head><body><h1>Index of /uploads/</h1>` +
      `<a href="?C=N;O=D">Name</a>\n<a href="../">[To Parent Directory]</a>\n` +
      `<a href="invoice-2026-01.pdf">invoice-2026-01.pdf</a> 14-Jan-2026 03:11 84K\n</body></html>`,
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// Error disclosure (probes.ts checkErrorDisclosure) — the Flask/Werkzeug
// debugger fingerprint, on every otherwise-unmatched path. This is what makes
// the catch-all check itself safe: it fires only when a RANDOM nonexistent
// path returns the leak and the real homepage does not, so it has to live in
// the 404 handler at the bottom, not on a named route. See the end of this
// file.
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Path traversal (pathTraversal.ts) — one of PROBE_ENDPOINTS + PROBE_PARAMS,
// unsanitised. classifyTraversalBody looks for `root:x:0:0:` — any ".." in the
// param serves it; a benign value serves an ordinary "not found".
// ─────────────────────────────────────────────────────────────────────────────
app.get("/download", (req, res) => {
  const file = String(req.query.file ?? "");
  if (file.includes("..")) {
    res.type("text/plain").send(
      "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n",
    );
  } else {
    res.status(200).type("text/plain").send(`File not found: ${file}`);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Reflected XSS + SQL injection (injectionProbe.ts), and doubles as the
// read-shaped POST /api/search endpoint apiProbe.ts discovers from the spec
// (READ_SHAPED matches "search" in the path).
// ─────────────────────────────────────────────────────────────────────────────
function searchHandler(req: Request, res: Response) {
  const q = String((req.method === "GET" ? req.query.q : req.body?.q) ?? "");
  if (q.includes("'")) {
    // A believable SQLite error, matched by injectionProbe's SQL_ERROR_SIGNATURES.
    res.status(500).type("text/plain").send(`SQLITE_ERROR: near "'": syntax error while compiling: SELECT * FROM records WHERE name = '${q}'`);
    return;
  }
  // Reflected, unescaped — the XSS.
  res.type("text/html").send(`<html><body><h1>Results for: ${q}</h1><p>No records found.</p></body></html>`);
}
app.get("/search", searchHandler);
app.post("/api/search", searchHandler);

// ─────────────────────────────────────────────────────────────────────────────
// GraphQL (graphqlProbe.ts) — introspection enabled, field-suggestion leak.
// ─────────────────────────────────────────────────────────────────────────────
function graphqlIntrospectionResult() {
  // hasIntrospectionData requires >=10 types — "real introspection returns 15+
  // built-in types minimum" — so this has to include the spec's own
  // meta-types, not just the schema's own object types, or a real introspection
  // response still reads as "not introspection" to the check.
  const builtIns = ["String", "Int", "Boolean", "ID", "Float", "__Schema", "__Type", "__Field", "__InputValue", "__EnumValue", "__TypeKind", "__Directive", "__DirectiveLocation"];
  return {
    data: {
      __schema: {
        queryType: { name: "Query" },
        types: [
          { name: "Query", kind: "OBJECT" },
          { name: "User", kind: "OBJECT" },
          { name: "Record", kind: "OBJECT" },
          ...builtIns.map((name) => ({ name, kind: name.startsWith("__") ? "OBJECT" : "SCALAR" })),
        ],
      },
    },
  };
}
app.post("/graphql", (req, res) => {
  const query = String(req.body?.query ?? "");
  if (/__schema/.test(query)) {
    res.json(graphqlIntrospectionResult());
    return;
  }
  // graphqlProbe.ts's BOGUS_FIELD_QUERY is exactly this field name — matched
  // literally rather than guessed, since a plausible-looking guess (an
  // "unknown username field" story) is still wrong if it isn't the string the
  // check actually sends.
  if (/nonExistentFieldSecScanProbe/.test(query)) {
    res.json({
      errors: [{ message: 'Cannot query field "nonExistentFieldSecScanProbe" on type "Query". Did you mean "record"?', locations: [{ line: 1, column: 3 }] }],
    });
    return;
  }
  res.json({ data: { __typename: "Query" } });
});
// crawler-data.ts's inner-route GraphQL check is a GET to {dir}/graphql,
// expecting either __typename/__schema JSON or a non-empty top-level errors
// array — real GraphQL servers answer a GET the same way.
app.get("/app/graphql", (_req, res) => {
  res.json({ errors: [{ message: "Must provide query string." }] });
});

// ─────────────────────────────────────────────────────────────────────────────
// crawler-data.ts inner-route probes, nested under /app/ so the directory
// prefix isn't "/" (which would just collide with the root-level findings
// above). /app/dashboard is the page linked from home and actually crawled;
// the rest are the sibling files the crawler probes once it's there.
// ─────────────────────────────────────────────────────────────────────────────
app.get("/app/dashboard", (_req, res) => {
  // Also misses a header the root has (CSP), for crawler.ts's own
  // "Content-Security-Policy Missing on Internal Routes" finding.
  res.removeHeader("Content-Security-Policy");
  res.type("text/html").send(`<!doctype html><html><head><title>Dashboard</title></head><body><h1>Dashboard</h1></body></html>`);
});
app.get("/app/.env", (_req, res) => {
  res.type("text/plain").send("DB_PASSWORD=hunter2\nAPI_KEY=fake-not-real-0000000000\n");
});
app.get("/app/swagger.json", (_req, res) => res.json({ swagger: "2.0", info: { title: "App API" }, paths: {} }));
app.get("/app/openapi.json", (_req, res) => res.json({ openapi: "3.0.0", info: { title: "App API" }, paths: {} }));
app.get("/app/api-docs", (_req, res) => res.json({ openapi: "3.0.0", paths: { "/x": {} } }));
app.get("/app/.git/HEAD", (_req, res) => res.type("text/plain").send("ref: refs/heads/main\n"));
app.get("/app/config.json", (_req, res) => res.json({ apiUrl: "https://api.internal.example", featureFlags: { newUi: true } }));
app.get("/app/debug.log", (_req, res) => {
  res.type("text/plain").send("[DEBUG] request received\n[ERROR] unhandled exception in handler\n[WARN] retrying\n".repeat(3));
});

// ─────────────────────────────────────────────────────────────────────────────
// accessControlProbe.ts — an HTML page naming a record (/account/1001), whose
// content ignores both the caller's identity and the id in the URL: any
// signed-in session sees account #1001's data, and any nearby id
// (mutateIdentifiers) does too, so this covers both IDOR and "records
// enumerable by editing the identifier" from the one bug. Anonymous is denied.
// ─────────────────────────────────────────────────────────────────────────────
app.get("/account/:id", (req, res) => {
  const session = sessionFromCookie(req);
  if (!session) {
    res.status(401).type("text/html").send(
      `<html><body><h1>Sign in required</h1><form><input type="password" name="password"></form><p>You must log in to view this account.</p></body></html>`,
    );
    return;
  }
  // Deliberately does not check whether req.params.id belongs to `session` —
  // that is the bug. Always renders account #1001 regardless of who asked or
  // which id was in the URL.
  res.type("text/html").send(
    `<html><body><h1>Account #1001</h1><p>Name: Alice Example</p><p>Email: alice@example.com</p>` +
      `<p>SSN: 078-05-1120</p><p>Plan: Enterprise</p><p>Balance: $4,213.00</p></body></html>`,
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// apiProbe.ts — the OpenAPI-declared /api/records/{id}. GET returns sensitive
// fields to ANYONE (no auth check at all, and ignores identity — both the
// "served without authentication" and the API-level IDOR finding come from
// this one handler). DELETE/PATCH on a nonexistent id return 404 without
// checking auth first — the BFLA finding.
// ─────────────────────────────────────────────────────────────────────────────
const RECORDS: Record<string, unknown> = {
  "1": { id: "1", owner: "alice@example.com", email: "alice@example.com", password_hash: "$2b$10$fakeHashNotReal000000000000000000000", ssn: "078-05-1120", balance: 4213 },
};

app.get("/api/records/:id", (req, res) => {
  // No auth check, and always the same record regardless of :id — the API
  // equivalent of the /account/:id bug above, and what makes both the
  // unauthenticated-access and cross-account comparisons fire from one route.
  res.json(RECORDS["1"]);
});
app.delete("/api/records/:id", (req, res) => {
  // Auth is never checked. The lookup runs first, so a nonexistent id 404s
  // regardless of who is asking — the exact BFLA signature apiProbe.ts tests
  // for: authorization would have to run before this to matter.
  if (!RECORDS[req.params.id]) {
    res.status(404).json({ error: "not found" });
    return;
  }
  delete RECORDS[req.params.id];
  res.status(204).end();
});
app.patch("/api/records/:id", (req, res) => {
  if (!RECORDS[req.params.id]) {
    res.status(404).json({ error: "not found" });
    return;
  }
  Object.assign(RECORDS[req.params.id] as object, req.body ?? {});
  res.json(RECORDS[req.params.id]);
});

// ─────────────────────────────────────────────────────────────────────────────
// apiProbe.ts mass assignment — the OpenAPI spec already declares "role" on
// this body, which is what the check reads; this handler also actually
// applies it, so the bug is real and not just declared.
// ─────────────────────────────────────────────────────────────────────────────
app.post("/api/users", (req, res) => {
  const { email, role } = req.body ?? {};
  res.status(201).json({ id: "1003", email, role: role ?? "user" });
});

// ─────────────────────────────────────────────────────────────────────────────
// Login, for a real credentialed scan (session cookie / login-form mode)
// rather than the verify script's direct-credential path. Two fixed accounts.
// ─────────────────────────────────────────────────────────────────────────────
app.get("/login", (_req, res) => {
  res.type("text/html").send(
    `<html><body><form method="post" action="/login"><input name="email"><input name="password" type="password"><button type="submit">Sign in</button></form></body></html>`,
  );
});
app.post("/login", express.urlencoded({ extended: false }), (req, res) => {
  const email = String(req.body?.email ?? "");
  const token = email === "bob@example.com" ? "bob-session-token" : "alice-session-token";
  res.setHeader("Set-Cookie", `session=${token}; Path=/`);
  res.redirect(302, "/account/1001");
});

// ─────────────────────────────────────────────────────────────────────────────
// 404 for everything else — real, not a catch-all shell, EXCEPT for the
// error-disclosure probe: a random nonexistent path must leak the Werkzeug
// fingerprint (probes.ts checkErrorDisclosure), while the homepage baseline
// must not carry it, which it doesn't (this only runs when nothing else
// matched, so "/" never reaches here).
// ─────────────────────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(500).type("text/html").send(
    `<html><body><h1>Internal Server Error</h1><pre>Traceback (most recent call last):\n  File "/app/main.py", line 42, in handle\n    raise Exception("unhandled")\nwerkzeug.debug: Debugger caught an exception in handle (${req.path})</pre></body></html>`,
  );
});

const PORT = Number(process.env.PORT ?? 4100);
app.listen(PORT, () => {
  console.log(`[vuln-fixture] listening on http://127.0.0.1:${PORT}`);
});
