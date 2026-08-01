# Seclayer — Full Scan Test Reference

Complete catalogue of every security check performed by the engine. Organised by module. Each entry lists the methodology, what triggers a finding, and the severity range.

---

## Stage Architecture

**Tier legend:** ★ = both Basic & Deep  |  ◆ = Deep only

```
Target URL
    │
    ├─ Stage 1: Passive header + HTML analysis ★         (scanner.ts)
    │
    ├─ Stage 2: Parallel active probes
    │     ├─ probes.ts            ★  HTTP file/method/redirect/CORS probes
    │     ├─ dnsChecks.ts         ★  DNS-over-HTTPS email security checks
    │     ├─ jsScanner.ts         ◆  JavaScript secret scanning (deep only)
    │     ├─ jwtAnalysis.ts       ★  JWT structural analysis (passive)
    │     ├─ graphqlProbe.ts      ★  GraphQL endpoint + introspection
    │     ├─ baasProbes.ts        ★  Supabase / PocketBase / Appwrite / Firebase
    │     ├─ subdomainTakeover.ts ★  CNAME dangling detection (19 services)
    │     ├─ pathTraversal.ts     ◆  LFI active probing (deep only)
    │     ├─ sourceMaps.ts        ★  .map file exposure
    │     ├─ apiDocsProbe.ts      ★  OpenAPI / Swagger UI exposure
    │     ├─ nextjsProbe.ts       ★  __NEXT_DATA__ secret scanning (passive)
    │     ├─ storageProbe.ts      ★  S3 / GCS / Azure public listing
    │     ├─ crawler.ts           ★  High-value path probing always; inner page
    │     │                          crawl up to 20 pages on deep tier only
    │     └─ cveCheck.ts          ★  OSV.dev CVE + EOL version lookup
    │
    └─ Stage 3: Worker-level checks (run from worker.ts, not runScan)
          ├─ ssllabs.ts           ★  SSL Labs API TLS assessment (starts in
          │                          parallel with Stage 1, waits up to 120s)
          └─ recon.ts             ★  DNS enumeration, subdomain discovery via
                                     crt.sh + brute-force, TCP port scan (30 ports)
```

False-positive philosophy: every check requires a **positive confirmation signal** — not just a non-200 absence or a keyword match. Findings cite the exact HTTP response, header value, or decoded data that triggered them.

---

## 1. Transport Security — `scanner.ts`

Passive analysis of the initial HTTP response headers and page HTML.

| Check | Trigger | Severity |
|-------|---------|----------|
| No HTTPS / Plaintext HTTP | Protocol is `http://` | Critical |
| HTTP Strict-Transport-Security missing | HTTPS site, no `Strict-Transport-Security` header, not on HSTS preload list | Medium |
| HSTS `max-age` too short | `max-age` < 6 months (15 552 000 s) | Low |
| HSTS missing `includeSubDomains` | Header present but subdomain flag absent | Info |
| Content-Security-Policy missing | No `Content-Security-Policy` or `Content-Security-Policy-Report-Only` | High |
| CSP allows `unsafe-inline` | `script-src` or `default-src` contains `'unsafe-inline'` | Medium |
| CSP allows `unsafe-eval` | `script-src` or `default-src` contains `'unsafe-eval'` | Medium |
| X-Frame-Options missing | No `X-Frame-Options` and no `frame-ancestors` in CSP | Medium |
| X-Content-Type-Options missing | No `X-Content-Type-Options: nosniff` | Low |
| Referrer-Policy missing | No `Referrer-Policy` header | Low |
| Permissions-Policy missing | No `Permissions-Policy` or `Feature-Policy` | Info |
| CORS wildcard | `Access-Control-Allow-Origin: *` on non-public API | Medium |
| Server version disclosure | `Server` header contains version number (e.g. `nginx/1.18.0`) | Low |
| X-Powered-By disclosure | `X-Powered-By` header present (e.g. `Express`, `PHP/8.1`) | Info |
| Cookie missing `Secure` flag | `Set-Cookie` without `Secure` (skips infra cookies: `__cf_bm`, `_ga`, etc.) | High |
| Cookie missing `HttpOnly` flag | `Set-Cookie` without `HttpOnly` | Medium |
| Cookie missing `SameSite` | `Set-Cookie` without `SameSite` | Medium |
| Mixed content | HTTP resource referenced on HTTPS page | Medium |
| Technology fingerprinting | Detected frameworks/servers surfaced in report (not a vulnerability) | Info |

**HSTS preload list awareness:** Before flagging a missing HSTS or HTTP redirect issue, the engine queries `hstspreload.org` and checks a hardcoded list of Chrome built-in preloaded domains (`google.com`, `github.com`, `stripe.com`, etc.) to suppress false positives for domains that enforce HTTPS at the browser level.

---

## 2. Active HTTP Probes — `probes.ts`

All probes run concurrently via `Promise.allSettled`. Every finding requires a content-validated positive response — not just an HTTP 200.

### 2.1 Sensitive File Exposure

Probes 50+ paths. Each has a `validate()` function that inspects the response body to confirm actual content before filing a finding.

| Path | Finding | Severity |
|------|---------|----------|
| `/.git/HEAD` | Git repository exposed — reconstruct full source history | Critical |
| `/.git/config` | Git config exposed — remote URLs + stored credentials | High |
| `/.svn/entries` | SVN repository exposed | High |
| `/.hg/requires` | Mercurial repository exposed | High |
| `/.env` | Environment file — all secrets in plaintext | Critical |
| `/.env.local` | Local env override exposed | Critical |
| `/.env.production` | Production env file exposed | Critical |
| `/.env.backup` | Backup env file | Critical |
| `/.env.staging` | Staging env file | High |
| `/wp-config.php` | WordPress DB credentials + secret keys | Critical |
| `/phpinfo.php`, `/info.php` | PHP info page — full env dump including `$_ENV` secrets | High |
| `/config.php` | PHP config file with DB credentials | Critical |
| `/configuration.php` | Joomla configuration | Critical |
| `/settings.php` | Drupal settings + DB credentials | Critical |
| `/backup.sql`, `/dump.sql`, `/db.sql`, `/database.sql` | Raw database export downloadable | Critical |
| `/backup.zip`, `/backup.tar.gz` | Backup archive with source + credentials | Critical |
| `/swagger.json`, `/openapi.json` | API spec — full endpoint blueprint | Medium |
| `/swagger-ui.html`, `/api-docs` | Interactive API docs | Medium |
| `/graphql` | GraphQL endpoint accessible | Medium |
| `/actuator/env` | Spring Boot actuator — dumps ALL env vars + secrets | Critical |
| `/actuator/configprops` | Spring Boot config properties | Critical |
| `/actuator/beans` | Spring Boot bean graph | Medium |
| `/config.json` | Config file with connection strings | High |
| `/Dockerfile` | Container build config + ARG secrets | Medium |
| `/docker-compose.yml` | Service config + hardcoded env vars | High |
| `/package.json` | Dependency tree — CVE fingerprinting surface | Info |
| `/web.config` | IIS config — connection strings + auth settings | High |
| `/config/database.yml` | Rails DB credentials for all environments | Critical |
| `/config/secrets.yml` | Rails `secret_key_base` + all secrets | Critical |
| `/local_settings.py` | Django local settings — `SECRET_KEY` + DB creds | Critical |
| `/storage/logs/laravel.log` | Laravel log — stack traces with file paths + SQL | High |
| `/debug.log` | Generic debug log | Medium |
| `/.gitignore` | Reveals names of sensitive untracked files on server | Info |
| `/server-status` | Apache server-status — live request URIs + tokens in URLs | Medium |
| `/.DS_Store` | macOS metadata — discloses directory tree | Info |

### 2.2 HTTP Methods

Sends `OPTIONS` to the target, then actively tests `TRACE` and `PUT`.

| Method | Trigger | Severity |
|--------|---------|----------|
| `TRACE` enabled | Server echoes request back (XST attack vector) | Medium |
| `PUT` enabled | Server responds 200/201/204 to `PUT /vibescan-probe-…` | High |
| `DELETE` enabled | Advertised in `Allow` header | Medium |
| `CONNECT` / `PATCH` dangerous use | Advertised without expected context | Low |

### 2.3 Active CORS Testing

Sends a request with `Origin: https://evil-attacker-seclayer.io` and checks whether the server reflects it.

| Scenario | Trigger | Severity |
|----------|---------|----------|
| Reflected origin + `Access-Control-Allow-Credentials: true` | Server echoes any origin AND allows credentials | Critical |
| Reflected origin without credentials | Server echoes any origin (no allowlist) | Medium |

### 2.4 Open Redirect

Tests common redirect params (`url`, `redirect`, `next`, `return`, `goto`, `redir`, `target`, `destination`, `continue`, `forward`, `r`, `u`, `to`) with `https://evil-attacker-seclayer.io` as the value. Confirmed only when `Location` header matches the injected URL.

| Severity | Trigger |
|----------|---------|
| Medium | Redirect to injected external URL confirmed via `Location` header |

### 2.5 robots.txt Analysis

Fetches `/robots.txt` and extracts `Disallow:` paths matching sensitive patterns (`/admin`, `/backup`, `/api/`, `/.env`, `/logs/`, etc.).

| Severity | Trigger |
|----------|---------|
| Info | ≥1 sensitive path found in `Disallow:` directives |

### 2.6 Subresource Integrity (SRI)

Parses `<script src>` and `<link href stylesheet>` tags. Flags external (cross-origin) resources without an `integrity=` attribute. Suppresses resources whose URL contains a content hash in the filename (webpack chunks, Vite assets) — those are content-addressed and SRI-redundant.

| Severity | Trigger |
|----------|---------|
| Medium | ≥1 external script/stylesheet missing `integrity=` and `crossorigin=` |

### 2.7 Error Page Disclosure

Requests a guaranteed-404 path (`/_vibescan-{timestamp}-not-a-real-path`) and scans the response body.

| Leak Type | Severity |
|-----------|----------|
| Flask/Werkzeug interactive debugger (RCE possible) | Critical |
| Node.js / Python / PHP / Java / ASP.NET stack trace with file paths | Medium |
| Django `DEBUG=True`, Laravel Whoops, Symfony debug | Medium |

### 2.8 HTTP → HTTPS Redirect

Only runs when the scan target is already HTTPS (confirming HTTPS works). Follows up to 5 redirect hops from `http://{hostname}/` to check if the chain ever reaches `https://`. Suppresses finding for HSTS-preloaded domains.

| Severity | Trigger |
|----------|---------|
| Medium | HTTP chain never reaches HTTPS after 5 hops |

### 2.9 Rate Limiting Detection

Inspects response headers for standard rate-limit signals (`X-RateLimit-Limit`, `RateLimit-Limit`, `Retry-After`) and infrastructure signals (`cf-ray` for Cloudflare, `x-amz-cf-id` for CloudFront, Azure Front Door headers, GFE markers, Akamai).

| Severity | Trigger |
|----------|---------|
| Low (confidence 52%) | No rate-limit headers AND no CDN/WAF infrastructure signals |

### 2.10 Clickjacking Verification

Checks `X-Frame-Options` for non-standard values that browsers may ignore.

| Severity | Trigger |
|----------|---------|
| Medium | `X-Frame-Options` set to anything other than `DENY` or `SAMEORIGIN` |

### 2.11 Directory Listing

Probes 15 common directories (`/uploads/`, `/files/`, `/backup/`, `/logs/`, `/assets/`, `/data/`, `/tmp/`, etc.) and looks for directory listing fingerprints (`Index of /`, Apache `<pre>` listing format, IIS listing markers).

| Severity | Trigger |
|----------|---------|
| High | Directory listing fingerprint confirmed in response body |

---

## 3. DNS Security — `dnsChecks.ts`

All queries use Cloudflare DNS-over-HTTPS (`cloudflare-dns.com/dns-query`). Never fires on IP addresses or localhost. SPF/DMARC checks run on the apex domain (e.g. `api.app.example.com` → `example.com`).

### 3.1 SPF

| Check | Trigger | Severity |
|-------|---------|----------|
| Missing SPF record | No `v=spf1` TXT record; domain has MX records | High |
| Missing SPF record | No `v=spf1` TXT record; no MX records | Medium |
| SPF `+all` | Record ends with `+all` (any sender authorized) | Critical |
| SPF `?all` | Record ends with `?all` (neutral — no enforcement) | Medium |
| SPF lookup limit | Estimated DNS lookups > 8 (RFC limit is 10) | Low |

### 3.2 DMARC

| Check | Trigger | Severity |
|-------|---------|----------|
| Missing DMARC | No `v=DMARC1` TXT record at `_dmarc.{domain}` | High |
| `p=none` | Policy exists but monitoring-only | Medium |
| Missing `rua=` | No aggregate report address | Info |

### 3.3 DKIM

Probes 30+ selectors in parallel (`default`, `google`, `selector1`, `selector2`, date-stamped selectors like `20250601`, service-specific: `sendgrid`, `mailgun`, `mandrill`, etc.). Suppressed automatically when DMARC is enforcing (`p=quarantine`/`p=reject`) since the domain must have DKIM under a non-probed selector.

| Check | Trigger | Severity |
|-------|---------|----------|
| No DKIM found | Zero selectors return a DKIM TXT record, at least one DNS query succeeded | Low |

### 3.4 DNSSEC

| Check | Trigger | Severity |
|-------|---------|----------|
| DNSSEC not enabled | No `DNSKEY` records on the domain | Info |

---

## 4. JavaScript Secret Scanning — `jsScanner.ts`

Runs on deep-tier scans only. Fetches up to 8 external JS files (max 512 KB each) plus all inline `<script>` blocks. Shannon entropy filtering removes low-entropy placeholder strings. Each pattern has a `validate()` function for false-positive suppression.

| Secret | Pattern Basis | Severity |
|--------|--------------|----------|
| AWS Access Key ID | `AKIA[0-9A-Z]{16}` | Critical |
| AWS Secret Access Key | Variable-name context + 40-char base64 value | Critical |
| Google API Key | `AIza[0-9A-Za-z-_]{35}` | High |
| Google OAuth Client Secret | `GOCSPX-[0-9A-Za-z-_]{28}` | Critical |
| Stripe Live Secret Key | `sk_live_[…]{24+}` | Critical |
| Stripe Test Secret Key | `sk_test_[…]{24+}` (pattern confirmation issue) | Medium |
| Stripe Webhook Secret | `whsec_[…]{32+}` | High |
| GitHub PAT | `gh[pousr]_[…]{36+}` | Critical |
| GitHub Fine-Grained Token | `github_pat_[…]{82+}` | Critical |
| Slack Bot/OAuth Token | `xox[baprs]-…-…` | High |
| Slack Incoming Webhook URL | `hooks.slack.com/services/T…/B…/…` | Medium |
| Twilio API Key | `SK[0-9a-f]{32}` | High |
| Supabase Service Role Key | `sb_secret_[…]{20+}` (new June 2025 format) | Critical |
| Sentry Auth Token (new) | `sntrys_eyJ[…].[…].[…]` JWT-style | Critical |
| Sentry Auth Token (legacy) | 64-char hex in explicit Sentry key context | Critical |
| SendGrid API Key | `SG.[…]{22}.[…]{43}` | High |
| Mailchimp API Key | 32-hex + `-us{N}` in explicit key context | High |
| Cryptographic Private Key | `-----BEGIN … PRIVATE KEY-----` | Critical |
| Firebase Config Block | `firebaseConfig = { apiKey: … }` | Info |
| Hardcoded JWT | `eyJ…eyJ…[sig]` > 60 chars | High |
| Hardcoded Password | `password: "…"` with entropy ≥ 2.5 bits/char | High |
| Hardcoded Secret/Token | `secret`/`api_key`/`access_token`: `"…"` with entropy ≥ 3.0 | Medium |
| Internal IP in code context | RFC-1918 IP in variable/URL assignment context | Low |
| OpenAI API Key | `sk-proj-[…]{50+}` or legacy `sk-…T3BlbkFJ…` | Critical |
| Anthropic API Key | `sk-ant-[api03/admin]-[…]{90+}` | Critical |
| Resend API Key | `re_[a-zA-Z0-9]{32+}` | High |

**Note:** Sentry DSNs are intentionally NOT flagged — they are public ingest-only identifiers. `sb_publishable_*` keys are not flagged — they are anon-key equivalents and public by design.

---

## 5. JWT Analysis — `jwtAnalysis.ts`

Passive extraction of JWTs from response headers and HTML/JS (no extra HTTP requests). Processes up to 10 unique tokens. Deduplicates by finding name.

| Check | Trigger | Severity |
|-------|---------|----------|
| `alg:none` — signature bypass | JWT header `alg` is `none` or empty | Critical |
| Empty signature segment | Non-none `alg` but signature part is `""` | Critical |
| Missing `exp` claim | JWT payload has no `exp` field | High |
| Excessive token lifetime | `exp - iat > 365 days` | Medium |
| HS256 without expiry | `alg: HS256` + no `exp` (offline brute-force risk) | High |
| Sensitive data in payload | Payload keys match: `password`, `secret`, `api_key`, `access_token`, `credit_card`, `ssn`, `private_key`, etc. | Medium |

---

## 6. GraphQL Security — `graphqlProbe.ts`

Discovers GraphQL endpoints from inline JS variable patterns (`graphqlUrl`, `GRAPHQL_ENDPOINT`, `hasuraUrl`) and a curated path list (`/graphql`, `/api/graphql`, `/v1/graphql`, `/graphql/v1`, `/graphql/v2`). Endpoints are confirmed by querying `{ __typename }` and verifying the response shape — REST APIs returning `{"data":{}}` are not confused with GraphQL because they won't have `data.__typename` as a string.

| Check | Trigger | Severity |
|-------|---------|----------|
| GraphQL introspection enabled | `__schema.types` returns ≥ 10 types | High |
| Field suggestions enabled | GraphQL `errors[].message` contains "Did you mean" with GraphQL-spec `locations` array | Low |

---

## 7. BaaS Security — `baasProbes.ts`

All four BaaS providers run concurrently. All read probes are non-destructive. Write probes use `Prefer: tx=rollback` for instant database-level rollback.

### 7.1 Supabase

Detects Supabase from inline JS: legacy JWT key patterns, new `sb_publishable_*` / `sb_secret_*` key formats (June 2025+), and project URL.

#### Key Classification

| Key Type | Detection | Severity |
|----------|-----------|----------|
| `sb_publishable_*` | Public-by-design anon key (new format) | Info |
| `sb_secret_*` | Admin-tier, BYPASSRLS — must never be in frontend | Critical |
| Legacy JWT with `role: service_role` | Decoded from JWT payload — BYPASSRLS | Critical |
| Legacy JWT with `role: anon` | Expected; security depends on RLS | (no finding) |

#### Active Probes (all run concurrently via `Promise.allSettled`)

**Probe 1 — Targeted Read Access (High-Sensitivity Tables)**

Sends `GET /rest/v1/{table}?limit=1` with the anon key for each table:

`users`, `profiles`, `payments`, `customers`, `settings`, `secrets`, `passwords`, `admins`, `admin_users`, `posts`, `articles`, `products`, `orders`, `messages`, `content`

- **False-positive prevention:** Only flags when the response is HTTP 200 AND the body is a non-empty JSON array (`data.length > 0`). A 200 returning `[]` (RLS allowing the query but no data returned) is NOT flagged.
- **Severity:** Critical
- **Finding:** "Unauthenticated Data Exposure on '{table}'"
- **Cap:** 5 findings maximum

**Probe 2 — Admin API Privilege Escalation (CVE-2025-48757)**

```
GET /auth/v1/admin/users
apikey: <anon_key>
Authorization: Bearer <anon_key>
```

- **Trigger:** HTTP 200 or 201 — the anon key reached an admin-only GoTrue endpoint
- **Severity:** Critical (CVSS 10.0)
- **Finding:** "CVE-2025-48757 — Supabase Privilege Escalation: Anon Key Has Admin Access"
- **Context:** A Supabase GoTrue patch regression where misconfigured middleware grants the anonymous key service_role-level access, exposing all user records (emails, phone numbers, metadata)

**Probe 3 — OpenAPI Schema Introspection + Write Exposure DAST**

Step 1: Fetch `GET /rest/v1/` to retrieve the PostgREST OpenAPI specification.

Step 2: Parse `paths` object and filter tables advertising `POST` or `PATCH` methods. Apply `WRITE_SUPPRESSION_LIST` to remove known Supabase-internal tables:

`schema_migrations`, `spatial_ref_sys`, `geography_columns`, `geometry_columns`, `raster_columns`, `raster_overviews`, `pg_stat_statements`, `buckets`, `objects`, `s3_multipart_uploads`, `audit_log_entries`, `flow_state`, `identities`, `mfa_amr_claims`, `mfa_challenges`, `mfa_factors`, `one_time_tokens`, `refresh_tokens`, `saml_providers`, `saml_relay_states`, `sessions`, `sso_domains`, `sso_providers`

Step 3: For each remaining table, fire a dry-run POST concurrently:

```http
POST /rest/v1/{table}
apikey: <anon_key>
Authorization: Bearer <anon_key>
Content-Type: application/json
Prefer: tx=rollback,return=minimal

{"_vibe_scan_dry_run": true}
```

- **Evaluation:** Any response that is **NOT** `401`, `403`, `404`, or `405` is a confirmed write path. A `400 Bad Request` is a positive signal — it means RLS allowed the request through and only the schema validator rejected the dummy payload.
- **Severity:** Critical
- **Finding:** "Confirmed Write Exposure — Unauthenticated INSERT on '{table}'"
- **Cap:** 5 write findings maximum

### 7.2 PocketBase

Detected via `new PocketBase("…")` constructor in JS or `pb.authStore`/`pb.collection` markers. Confirmed by `GET /api/health` returning a valid PocketBase health response.

Probes collections: `users`, `posts`, `articles`, `products`, `orders`, `messages`, `profiles`, `content`, `records`, `items`

| Trigger | Severity |
|---------|----------|
| `GET /api/collections/{col}/records?perPage=1` → 200 + records present | Critical |
| `GET /api/collections/{col}/records?perPage=1` → 200 + no records | High |

### 7.3 Appwrite

Detected via `APPWRITE_ENDPOINT`/`setEndpoint()` + `APPWRITE_PROJECT_ID`/`setProject()` + presence of "Appwrite" string. Confirmed by `/health` endpoint.

Probes collections: `users`, `posts`, `products`, `orders`, `messages`

| Trigger | Severity |
|---------|----------|
| `GET /databases/default/collections/{col}/documents` with project header → 200 + documents | Critical |
| → 200 + no documents | High |

### 7.4 Firebase Firestore

Detected via `AIza…` API key + `projectId` + `authDomain`/`storageBucket`/`messagingSenderId`/`firebaseio.com` (requires at least one additional Firebase marker to avoid false positives on unrelated `apiKey`/`projectId` fields).

Probes collections: `users`, `posts`, `messages`, `orders`, `profiles`

```
GET https://firestore.googleapis.com/v1/projects/{id}/databases/(default)/documents/{col}?key={apiKey}&pageSize=1
```

| Trigger | Severity |
|---------|----------|
| 200 + documents returned | Critical |
| 200 + no documents | High |

---

## 8. Subdomain Takeover — `subdomainTakeover.ts`

Resolves the target hostname's CNAME chain (up to 5 hops) via Cloudflare DoH. If the final CNAME matches a known cloud service pattern AND the HTTP response from that target contains an unclaimed-resource fingerprint, the finding fires.

| Service | Fingerprint Example | Severity |
|---------|-------------------|----------|
| AWS S3 | `NoSuchBucket` / `The specified bucket does not exist` | Critical |
| Heroku | `No such app` / `there is no app configured at that hostname` | Critical |
| GitHub Pages | `There isn't a GitHub Pages site here` | Critical |
| Netlify | `Not Found - Request ID` | Critical |
| Vercel | `The deployment could not be found` | Critical |
| Azure App Service | `404 Web Site not found` | Critical |
| Fastly | `Fastly error: unknown domain` | Critical |
| Shopify | `Sorry, this shop is currently unavailable` | High |
| Ghost Pro | `The thing you were looking for is no longer here` | High |
| Surge.sh | `project not found` | High |
| Cargo | `If you're moving your domain away from Cargo` | High |
| Readme.io | `Project doesnt exist` | High |
| Pantheon | `404 error unknown site` | High |
| Squarespace | `No Such Account` | High |
| Tumblr | `There's nothing here` | Medium |
| WP Engine | `The site you were looking for couldn't be found` | High |
| Fly.io | `404 Not Found` | High |
| Render | `There is no site here` | High |
| Railway | `Application not found` | High |

---

## 9. Path Traversal / LFI — `pathTraversal.ts`

*Deep-tier scans only.*

Builds candidate `(path, param)` pairs from:
1. File-related query params on the target URL (`file`, `page`, `path`, `include`, `template`, `view`, `doc`, `document`, `src`, `dir`, etc.)
2. Same params found in in-page links (first 50 KB of HTML)
3. Common file-serving endpoints probed with known param names (`/download`, `/file`, `/include`, `/load`, `/view`, `/serve`, `/template`, `/render`)

Sends traversal payloads (`../../../etc/passwd`, `....//....//etc/passwd`, encoded variants, Windows `..\..\windows\win.ini`).

**Confirmation only** when response body contains definitive file content:
- Linux: `/etc/passwd` `root:` entry
- Windows: `[boot loader]` or `[operating systems]` markers from `win.ini`

| Severity | Trigger |
|----------|---------|
| Critical | Confirmed traversal reaching system file |

---

## 10. Source Map Exposure — `sourceMaps.ts`

Extracts `<script src="…">` tags, fetches up to 8 external JS files. For each:
1. Requests `{url}.map` directly
2. Reads the last 512 bytes for a `//# sourceMappingURL=…` comment pointing to a named `.map` file
3. Requests the referenced map file

Finding confirmed only when the response is valid source-map JSON with a non-empty `sources` array or `sourcesContent` present.

| Severity | Trigger |
|----------|---------|
| High | Valid source map returned — full un-minified source code accessible |

---

## 11. API Documentation Exposure — `apiDocsProbe.ts`

Probes 15+ paths. Each has a strict content validator to avoid flagging documentation sites, marketing pages, or wikis.

| Path Category | Validation | Severity |
|--------------|-----------|----------|
| `swagger.json`, `openapi.json`, `openapi.yaml`, `api-spec.json`, `api-spec.yaml` | Requires `"openapi": "3.x"` or `"swagger": "2.x"` + `paths` + `info` | Medium |
| `/swagger-ui.html`, `/docs/swagger`, `/swagger`, `/api/swagger-ui` | Requires `swagger-ui-bundle.js` or `swagger-ui-dist` script reference in HTML | Medium |
| `/api/docs`, `/v1/docs`, `/api/v1/docs`, `/v2/docs`, `/api/v2/docs` | Requires OpenAPI version string + `paths` key (excludes `/docs` alone — Docusaurus/GitBook false positive) | Medium |
| ReDoc | `redoc.min.js` or `<redoc ` tag in page | Low |

---

## 12. Next.js `__NEXT_DATA__` Scanning — `nextjsProbe.ts`

Passive — reads the already-fetched HTML. Only runs when `__NEXT_DATA__`, `_next/static`, or `next.js` markers are detected. Extracts the `<script id="__NEXT_DATA__">` JSON blob and scans for secrets that `getServerSideProps` accidentally serialized into the page.

| Secret | Severity |
|--------|----------|
| Stripe Live Secret Key (`sk_live_…`) | Critical |
| Supabase Service Role JWT (`service_role`) | Critical |
| Cryptographic Private Key | Critical |
| AWS Access Key ID | Critical |
| AWS Secret Access Key | Critical |
| GitHub PAT / Fine-grained token | Critical |
| Database connection string (Postgres, MySQL, MongoDB, Redis) with credentials | Critical |
| SendGrid API Key | High |
| Slack Bot/OAuth Token | High |

Matched values are partially redacted in evidence (`abc12345…[redacted]…xyz`).

---

## 13. Cloud Storage Listing — `storageProbe.ts`

Extracts bucket/container references from HTML + inline JS. Runs all listing checks concurrently. Confirmed only when the cloud provider's XML/JSON listing format is present in the response body.

| Provider | Detection | List URL | Confirmation |
|----------|-----------|---------|-------------|
| AWS S3 | `*.s3.amazonaws.com` (path-style + virtual-hosted) | `?list-type=2&max-keys=5` | `<ListBucketResult>` or `<Contents>` |
| Google Cloud Storage | `storage.googleapis.com/{bucket}` or `{bucket}.storage.googleapis.com` | `?maxResults=5` | `"kind":"storage#objects"` or GCS XML |
| Azure Blob | `{account}.blob.core.windows.net/{container}` | `?restype=container&comp=list&maxresults=5` | `<EnumerationResults>` or `<Blobs>` |

| Severity | Trigger |
|----------|---------|
| High | Listing confirmed — full bucket/container contents enumerable |

---

## 14. Deep Crawl — `crawler.ts`

Follows same-domain `<a href>` links, then for each inner page:
- Checks security headers (reports gaps vs. the root page — catches CDN bypasses on `/api/*` routes)
- Probes sensitive files relative to the discovered path
- Checks cookie flags

Additionally probes high-value paths regardless of whether they appear in HTML:

`/admin`, `/administrator`, `/wp-admin`, `/api`, `/api/v1`, `/api/v2`, `/api/v3`, `/graphql`, `/gql`, `/health`, `/healthz`, `/status`, `/ping`, `/ready`, `/live`, `/login`, `/auth`, `/signin`, `/dashboard`, `/metrics`, `/debug`, `/console`

Skips paths matching `logout|signout|delete|remove|destroy|unsubscribe|reset|drop`.

---

## 15. CVE & EOL Version Detection — `cveCheck.ts`

Extracts versioned software from HTML meta tags, inline JS, and response headers. Queries the [OSV.dev API](https://osv.dev) for known vulnerabilities. Results cached in-process per `(package, version, ecosystem)`.

**Frontend libraries** (from HTML/JS):

`jQuery`, `Bootstrap`, `Lodash`, `Moment.js`, `Vue.js`, `Angular`, `React` (CDN-hosted)

**CMS platforms** (from HTML meta tags + URL patterns):

`WordPress`, `Drupal`, `Joomla`

**Server software** (from response headers):

`PHP`, `Nginx`, `Apache HTTPD`, `IIS`, `OpenResty` — checked against EOL dates fetched from [endoflife.date](https://endoflife.date)

| Finding | Trigger | Severity |
|---------|---------|----------|
| Known CVE | OSV.dev returns ≥1 vulnerability for the detected version | High–Critical (based on CVSS) |
| End-of-life software | Detected version past EOL date (no patches ever again) | High |

---

## 16. SSL Labs TLS Assessment — `ssllabs.ts`

Started in parallel with the Stage 1 header scan from the worker (not from `runScan`), so it runs concurrently with the entire probe suite. Polls the [SSL Labs API v3](https://api.ssllabs.com/api/v3) until the assessment completes or a 120-second timeout is reached. Only runs on HTTPS targets.

The SSL Labs grade overrides the basic TLS detection grade from `scanner.ts`.

| Finding | Trigger | Severity |
|---------|---------|----------|
| Weak TLS — Grade C | SSL Labs returns `C` | Medium |
| Weak TLS — Grade D | SSL Labs returns `D` (outdated protocols, weak ciphers) | High |
| Weak TLS — Grade F | SSL Labs returns `F` (broken cipher suites, certificate failure) | Critical |
| Grade T | Trust issue (self-signed / expired cert) — surfaced as part of TLS grade | — |

If the SSL Labs API is unavailable or times out, the engine falls back to the basic TLS detection (HTTPS present/absent) from `scanner.ts` with no gap in coverage.

---

## 17. Reconnaissance — `recon.ts`

Runs from the worker concurrently with the entire probe suite. SSRF-protected: the target hostname is resolved to an IP before port scanning; if the resolved IP is in an RFC-1918, loopback, or link-local range, the port scan is skipped.

### 17.1 DNS Enumeration

Queries all standard record types via Cloudflare DoH: `A`, `AAAA`, `MX`, `NS`, `TXT` (SPF/DMARC), `SOA`, `CAA`. Results are stored in the report for context (not findings on their own).

### 17.2 Subdomain Discovery

Two concurrent methods:
1. **Certificate Transparency** — queries `crt.sh` for the apex domain; resolves up to 100 discovered subdomains
2. **DNS brute-force** — checks 30 common wordlist prefixes (`www`, `api`, `app`, `admin`, `panel`, `dashboard`, `portal`, `vpn`, `dev`, `staging`, `test`, `mail`, `smtp`, `ftp`, `git`, `cdn`, `cloud`, `remote`, `secure`, `mx`, `mail2`, `support`, `help`, `status`, `docs`, `beta`, `internal`, `mobile`, `shop`, `payments`)

Results (hostname + IP + CNAME if applicable + source) are stored in the report. No findings are raised for discovered subdomains themselves — the subdomain takeover probe (`subdomainTakeover.ts`) handles that.

### 17.3 Port Scan

TCP-connect scan of 30 ports with banner grabbing. Each connection is capped at 2 seconds. **Dangerous** ports produce first-class vulnerabilities merged into the scan findings:

| Port | Service | Severity | Reason |
|------|---------|----------|--------|
| 23 | Telnet | Critical | Transmits credentials in plaintext |
| 445 | SMB | Critical | EternalBlue / ransomware vector (WannaCry/NotPetya) |
| 2375 | Docker API (unencrypted) | Critical | No-auth container escape → full host compromise |
| 6379 | Redis | Critical | Often no-auth; full DB read/write |
| 3306 | MySQL | High | Direct DB access from internet |
| 1433 | MSSQL | High | Direct DB access / brute-force target |
| 1521 | Oracle DB | High | Direct DB listener exposure |
| 3389 | RDP | High | Brute-force / BlueKeep vector |
| 5432 | PostgreSQL | High | Direct DB access from internet |
| 5984 | CouchDB | High | Often no-auth (CVE-2017-12635) |
| 9200 | Elasticsearch | High | Often no-auth; full index read/write |
| 11211 | Memcached | High | No-auth; DDoS amplification vector |
| 27017 | MongoDB | High | Often no-auth (MongoDB ransomware campaigns) |
| 2376 | Docker API (TLS) | Medium | Remote Docker access — restrict to known IPs |

**Non-dangerous** ports (21/FTP, 22/SSH, 25/SMTP, 53/DNS, 80/HTTP, 110/POP3, 143/IMAP, 443/HTTPS, 465/SMTPS, 587/SMTP-Sub, 993/IMAPS, 995/POP3S, 3000/dev, 4443/alt-HTTPS, 8000/8080/8443/8888/9000 alt-HTTP) are recorded in the report as open-port context without raising findings.

---

## Scoring

Every finding is assigned:
- **Severity:** `critical` / `high` / `medium` / `low` / `info`
- **CWE ID:** MITRE Common Weakness Enumeration reference
- **CVSS Score:** 0–10 base score
- **WSTG ID:** OWASP Web Security Testing Guide reference (where applicable)
- **Confidence:** 0–100 (auto-enriched via `scoring.ts`). Findings below the confidence threshold are displayed with a lower-confidence indicator in the report.

**Grade calculation:** Weighted sum of vulnerability severities → letter grade A–F displayed in the dashboard and monitoring history.
