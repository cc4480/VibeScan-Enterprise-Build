# vuln-fixture

A deliberately vulnerable app that plants a real instance of every
HTTP-observable finding secscan.us's scanner checks for — built to answer
"is there anything else to check?" with a target whose faults are known
exactly, rather than by inference from third-party sites.

**This is test infrastructure, not a product.** It is never built by the root
`build` script (no `build` script is defined, so `pnpm -r --if-present run
build` skips it) and its `dist` is never copied into the Docker image — the
Dockerfile only copies `api-server/dist` and `vibescan/dist/public` out of the
builder stage. Run it only where you control network access to it, and only
scan it under the same ownership-verification discipline the product already
requires for active probing. Never deploy it publicly.

## Running it

```
pnpm --filter @workspace/vuln-fixture run start
```

Listens on `http://127.0.0.1:4100` (override with `PORT`).

## Verifying coverage

```
DATABASE_URL=postgres://localhost/whatever \
  npx tsx artifacts/api-server/scripts/verify-vuln-fixture.ts
```

Runs the real scanner — active probing on, two credentialed accounts — against
the fixture and reports which of the tracked findings were detected,
the same shape as `detection-check.ts` and `live-scan.ts`. Exit code is
non-zero on any miss. `--list` prints every finding actually returned.

## What every value in here is

Every secret, key, and token planted below matches a real vendor's format
closely enough for the detection regex to fire (checked against the actual
regex source in `secret-pattern-data.ts` / `nextjsProbe.ts`, not guessed —
see `scripts/self-test-secrets.ts` and `scripts/self-test-nextdata-jwt.ts`),
but none of them are live: no prefix, account ID, or length corresponds to
anything anyone controls. `hunter2` shows up as a planted password
repeatedly — it is the well-known placeholder from the
[bash.org #102876](http://bash.org/?102876) joke, not an attempt at
plausibility.

## Covered — verified by running the real scanner

Every module in `SCAN_CHECKS.md` that detects something over HTTP, checked
by running `verify-vuln-fixture.ts` (or the check's real logic directly)
against this fixture and confirming the finding actually comes back — not
just "should, based on reading the code":

| Module | What's planted |
|---|---|
| `scanner.ts` | Weak/wildcard CSP, missing directive checks, every missing security header (HSTS, XCTO, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP, Cache-Control), a session cookie missing every flag, wildcard CORS, EOL `Server`/`X-Powered-By` banners |
| `cveCheck.ts` | nginx 1.14.0 (flagged against the current top entry in `NGINX_VULN_RANGES` — CVE-2026-42533 as of the 2026-09-21 review, since that entry's threshold is checked first and 1.14.0 falls below it too), PHP 5.6.40 (EOL) |
| `probes.ts` | Active-CORS credentials-from-arbitrary-origin, TRACE/CONNECT/write methods advertised, open redirect (on the scan target URL itself — see note below), sensitive `robots.txt` disclosure, missing SRI, the Werkzeug debugger fingerprint, directory listing, missing `security.txt`, no rate-limit headers |
| `crawler.ts` / `crawler-data.ts` | An inner route (`/app/dashboard`) missing a header the root has, plus `.env`/git/config/API-docs/debug-log/GraphQL exposure nested under it |
| `probes-data.ts` | All 78 sensitive paths, each serving content shaped to pass that path's own `validate()` (verified: `sensitive-paths.ts` diffs to an exact match against the source list) |
| `secret-pattern-data.ts` (jsScanner) | All 35 secret patterns, in an external JS file so the non-inline path is exercised too |
| `nextjsProbe.ts` | All 9 `__NEXT_DATA__` secret patterns |
| `jwtAnalysis.ts` | `alg:none`, no-expiry, HS256-without-expiry, excessive lifetime (10 years), sensitive payload fields |
| `sourceMaps.ts` | An exposed `.js.map` with `sourcesContent` containing a secret |
| `apiDocsProbe.ts` | A root-level OpenAPI spec |
| `graphqlProbe.ts` | Introspection enabled, field-suggestion leak (needs `--active`) |
| `injectionProbe.ts` | Reflected XSS and error-based SQLi on `/search` (needs `--active`) |
| `pathTraversal.ts` | `/download?file=../../../etc/passwd` (needs `--active`) |
| `ssrfProbe.ts` | `GET /api/webhook-preview?url=` does a real server-side fetch of the caller's URL, no allowlist — confirmed via an actual callback to the collector, not asserted from reading the code (needs `--active` AND a reachable `OOB_BASE_URL`/`APP_ORIGIN`; see `verify-vuln-fixture.ts`) |
| `apiProbe.ts` | Missing auth, over-exposed sensitive fields, BFLA (write reachable unauthenticated), mass assignment (a `role` field the spec declares and the handler actually applies), API-level IDOR, SQL injection in a declared parameter — all via an OpenAPI spec at `/openapi.json` describing `/api/records/{id}`, `/api/search`, `/api/users` |
| `accessControlProbe.ts` | Page-level IDOR and identifier-enumeration on `/account/:id`, which ignores both the caller's session and the `:id` in the URL |
| `deserializationProbe.ts` | Four `Set-Cookie` values on `/app/dashboard`, each a real serialized object carrying `{"user":"admin"}` — Java (`AC ED 00 05`), Ruby Marshal (`04 08`), Python pickle (protocol 2), and a URL-encoded PHP object. Planted on a crawled inner route because the probe is only reached from `crawler.ts`; a root-page cookie never passes through it |

## Not covered, and why — this needs infrastructure an app cannot provide

These modules check something outside the application server itself. Planting
them needs real external infrastructure, which is a decision to make
separately, not a gap in this fixture:

| Module | What it actually checks | What would be needed |
|---|---|---|
| `dnsChecks.ts` | SPF/DMARC/DNSSEC records | A domain with deliberately-misconfigured DNS zone records |
| `mailTls.ts` | STARTTLS / cert expiry on the domain's MX | A real mail server, reachable on port 25 |
| `subdomain-service-data.ts` | A dangling CNAME pointing at an unclaimed cloud resource | A real DNS zone and an actually-abandoned cloud service registration |
| `recon-data.ts` | Open ports for MongoDB/Redis/Elasticsearch/etc. | Real listeners on those ports, several privileged (23, 445, 3389) |
| `storageProbe.ts` | Public S3/GCS/Azure bucket listings | Real cloud storage accounts with public buckets |
| `baasProbes.ts`, `firebase-probes.ts`, `supabase-probes.ts` | Misconfigured third-party BaaS backends | Real Appwrite/PocketBase/Firebase/Supabase projects, deliberately misconfigured |

## Known limitations of what's verified

- **All 78 `probes-data.ts` paths are served correctly**, but `verify-vuln-fixture.ts` only asserts a sample (~10) by name — checking all 78 individually would make the script itself the thing most likely to have a typo. The full list is cross-checked structurally instead: `sensitive-paths.ts` is diffed against the source's path list on every edit (see git history), so nothing is missing or misspelled, but "present" isn't the same guarantee as "this exact one was independently confirmed to fire."
- **`--active` is required** for GraphQL, injection, and path-traversal findings — run the verify script against a target the product's `activeProbeGate` would also allow, or use `live-scan.ts --active` directly.
- **Rate limiting and BFLA (`apiProbe.ts`) need `MAX_ENDPOINTS_TESTED`/burst budgets** to actually reach `/api/records/{id}` — if the scan's endpoint or param budgets change, re-run the verify script rather than assuming these still fire.
