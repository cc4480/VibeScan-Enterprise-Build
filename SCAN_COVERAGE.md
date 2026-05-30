# VibeScan — Complete Check Coverage

## Module 1 — HTTP Response Headers
*Runs on every scan (Basic + Deep). Inspects the response from a single GET to the target URL.*

| # | Check | Severity if failing |
|---|---|---|
| 1 | HTTPS enforcement (plain HTTP served) | Critical |
| 2 | HTTP Strict Transport Security (HSTS) present | Medium |
| 3 | HSTS preload status (via hstspreload.org API) | Low |
| 4 | Content-Security-Policy present | High |
| 5 | CSP contains `unsafe-inline` | Medium |
| 6 | CSP contains `unsafe-eval` | Medium |
| 7 | X-Frame-Options present (clickjacking) | Medium |
| 8 | X-Content-Type-Options: nosniff | Low |
| 9 | Referrer-Policy present | Low |
| 10 | Permissions-Policy present | Low |
| 11 | Cross-Origin-Opener-Policy (COOP) | Info |
| 12 | Cross-Origin-Embedder-Policy (COEP) | Info |
| 13 | Cross-Origin-Resource-Policy (CORP) | Info |
| 14 | CORS wildcard `Access-Control-Allow-Origin: *` | Medium |
| 15 | Server header version number disclosure | Info |
| 16 | X-Powered-By header disclosure | Info |
| 17 | X-XSS-Protection explicitly disabled | Info |
| 18 | Cache-Control headers missing | Info |
| 19 | Mixed content (HTTP resources on HTTPS page) | Medium |

**Cookie analysis** — runs per cookie in Set-Cookie:

| # | Check | Severity if failing |
|---|---|---|
| 20 | Cookie missing `Secure` flag | Medium |
| 21 | Cookie missing `HttpOnly` flag | Medium |
| 22 | Cookie missing `SameSite` attribute | Low |

---

## Module 2 — Technology Fingerprinting
*Passive. Detects ~60 technologies from headers, cookies, and HTML.*

Categories: web servers (Nginx, Apache, IIS, Caddy, Gunicorn…), CDNs (Cloudflare, Vercel, Netlify, AWS CloudFront, Fastly, Azure…), CMS platforms (WordPress, Drupal, Joomla, Ghost, Shopify, Wix, Squarespace, Webflow…), JS frameworks (React, Vue, Angular, Next.js, Nuxt, Svelte, Remix, Astro, Gatsby…), CSS frameworks (Tailwind, Bootstrap, Bulma), analytics (GA, GTM, Hotjar, Mixpanel, Segment), and more.

---

## Module 3 — DNS Security
*Uses Cloudflare DNS-over-HTTPS — no account needed.*

| # | Check | Severity if failing |
|---|---|---|
| 23 | SPF record present | High (or Medium if no MX) |
| 24 | SPF uses `+all` (allows any sender) | Critical |
| 25 | SPF uses `?all` (neutral, no enforcement) | Medium |
| 26 | SPF exceeds 10 DNS lookup limit | Low |
| 27 | DMARC record present | High |
| 28 | DMARC policy is `p=none` (monitoring only) | Medium |
| 29 | DMARC missing aggregate report address `rua=` | Info |
| 30 | DKIM records present (probes 30 selectors) | Low |
| 31 | DNSSEC enabled | Info |

---

## Module 4 — Active HTTP Probes
*Makes individual HTTP requests to specific paths/endpoints.*

### 4a. Sensitive File Exposure
Probes ~75 paths for publicly accessible files.

| Category | Examples |
|---|---|
| Source control | `.git/config`, `.gitignore` |
| Environment files | `.env`, `.env.local`, `.env.production`, `.env.backup` |
| Infrastructure | `docker-compose.yml`, `Dockerfile`, `docker-compose.override.yml` |
| Credentials | `/.htpasswd` |
| Admin panels | `/admin`, `/wp-admin`, `/phpmyadmin`, `/adminer` |
| Spring Boot Actuators | `/actuator/env`, `/actuator/health`, `/actuator/beans`, `/actuator/mappings`, `/actuator/heapdump`, `/actuator/loggers`, `/actuator/metrics` |
| API documentation | `/swagger.json`, `/openapi.json`, `/api-docs`, `/graphql`, `/api/swagger.json`, `/api/v1/swagger.json`, `/api/v2/swagger.json` |
| IDE configs | `.vscode/settings.json`, `.idea/workspace.xml` |
| YAML configs | `config.yaml`, `config.yml`, `app.yaml` |
| Java internals | `/WEB-INF/web.xml`, `/WEB-INF/classes/application.properties` |
| WordPress | `/xmlrpc.php` |
| Server diagnostics | `/server-info`, `/nginx_status` |

| # | Check | Severity |
|---|---|---|
| 32 | Each confirmed sensitive file hit | Critical → Info (varies per file type) |

### 4b. HTTP Methods (OPTIONS probe)

| # | Check | Severity |
|---|---|---|
| 33 | HTTP TRACE enabled (Cross-Site Tracing / XST) | Medium |
| 34 | Dangerous methods advertised (PUT, DELETE, PATCH) | High |
| 35 | HTTP CONNECT enabled | Medium |

### 4c–4l. Individual Probes

| # | Check | Severity |
|---|---|---|
| 36 | Active CORS — arbitrary origin reflection | High |
| 37 | Active CORS — null origin accepted | Medium |
| 38 | Open redirect via common parameters | Medium |
| 39 | robots.txt exposes sensitive paths | Low |
| 40 | Subresource Integrity (SRI) missing on CDN scripts | Medium |
| 41 | Error/debug information disclosure | Medium |
| 42 | HTTPS redirect not enforced (HTTP stays HTTP) | High |
| 43 | Rate limiting absent on root endpoint | Low |
| 44 | X-Frame-Options misconfigured (non-DENY/SAMEORIGIN value) | Medium |
| 45–59 | Directory listing on 15 common dirs (`/uploads/`, `/logs/`, `/backup/`, etc.) | Medium |
| 60 | `security.txt` missing (RFC 9116) | Info |

---

## Module 5 — Known CVE / Version Matching
*Detects versioned software and queries OSV.dev.*

| # | Check | Severity |
|---|---|---|
| 61 | Detected library version queried against OSV.dev CVE database | Critical → Low (per CVE CVSS) |
| 62 | PHP end-of-life version check (5.x, 7.0–7.3) | Critical / High |
| 63 | Apache end-of-life version check (1.x, 2.2) | Critical / High |
| 64 | Nginx end-of-life version check | High |
| 65 | IIS 6.0 — CVE-2017-7269 (RCE via WebDAV, CVSS 9.8) | Critical |

---

## Module 6 — JWT Analysis
*Passive — extracts tokens from headers and HTML, no extra requests.*

| # | Check | Severity |
|---|---|---|
| 66 | `alg:none` — signature verification bypass | Critical |
| 67 | Empty signature segment (unsigned token accepted) | Critical |
| 68 | Missing `exp` claim (never expires) | High |
| 69 | Excessively long lifetime (>365 days) | Medium |
| 70 | HS256 without expiry (offline brute-force risk) | High |
| 71 | Sensitive data in JWT payload (passwords, tokens, etc.) | Medium |

---

## Module 7 — Subdomain Takeover
*Follows CNAME chains and checks 19 cloud service fingerprints.*

| # | Services Checked | Severity |
|---|---|---|
| 72 | AWS S3, Heroku, GitHub Pages, Netlify, Vercel, Azure, Fastly, Shopify, Ghost Pro, Surge.sh, Cargo, Readme.io, Pantheon, Squarespace, Tumblr, WP Engine, Fly.io, Render, Railway | Critical |

---

## Module 8 — Vibe-Stack Database Security *(NEW — both tiers)*
*Detects Supabase and Firebase backends from the JS bundle, then actively tests their live API.*

### 8a. Supabase

| # | Check | Severity |
|---|---|---|
| 73 | Supabase **service_role key** in client-side JS (bypasses all RLS) | Critical |
| 74 | Tables returning rows to unauthenticated anon-key requests — **CVE-2025-48757** | Critical |
| 75 | Tables accessible unauthenticated but currently empty (RLS still missing) | High |
| 76 | Tables accepting unauthenticated INSERT writes *(Deep only)* | Critical |
| 77 | Storage bucket list exposed to anon key | Medium |
| 78 | Supabase detected, RLS appears configured (informational) | Info |

*Detection: extracts `supabaseUrl` + anon key from JS bundle, hits PostgREST OpenAPI spec to enumerate up to 12 tables, tests each with real API calls. Anon key is NOT flagged — it is public by design.*

*Write probe safety: INSERT uses `{"__vibescan_probe__": true}` — a field that cannot exist in any real schema. A 400/422 response proves auth was bypassed without creating a row. A 201 (row created) triggers immediate cleanup by returned ID. No PATCH or DELETE is ever sent against existing rows.*

### 8b. Firebase

| # | Check | Severity |
|---|---|---|
| 79 | Firestore returns documents to unauthenticated requests | Critical |
| 80 | Firebase Realtime Database returns data to unauthenticated requests | Critical |
| 81 | Firebase detected, rules appear restrictive (informational) | Info |

*Tests 20 common collection names against the Firestore REST API. Firebase API key is NOT flagged as a secret — it identifies the project and is public by design.*

---

## Module 9 — Source Map Exposure
*Checks each JS bundle (up to 8 files) for accessible `.map` files.*

| # | Check | Severity |
|---|---|---|
| 73 | `.map` file directly accessible alongside JS bundle | High |
| 74 | `sourceMappingURL` comment points to accessible map file | High |

---

## Module 9 — JavaScript Secret Scanning ⚡ *Deep scans only*
*Scans inline scripts + up to 8 external JS files (up to 512 KB each).*

| # | Secret Pattern | Severity |
|---|---|---|
| 75 | AWS Access Key ID | Critical |
| 76 | AWS Secret Access Key | Critical |
| 77 | Google API Key | High |
| 78 | Google OAuth Client Secret | Critical |
| 79 | Stripe Live Secret Key | Critical |
| 80 | Stripe Test Secret Key | Medium |
| 81 | Stripe Webhook Secret | High |
| 82 | GitHub Personal Access Token | Critical |
| 83 | GitHub Fine-Grained Token | Critical |
| 84 | Slack Bot/OAuth Token | High |
| 85 | Slack Incoming Webhook URL | Medium |
| 86 | Twilio API Key | High |
| 87 | SendGrid API Key | High |
| 88 | Mailchimp API Key | High |
| 89 | RSA / EC / SSH Private Key | Critical |
| 90 | Firebase API Key (open security rules risk) | Info |
| 91 | Hardcoded JWT token | High |
| 92 | Hardcoded password | High |
| 93 | Hardcoded secret / API key (generic pattern) | Medium |
| 94 | Internal IP address exposed | Low |
| 95 | Mapbox access token | Medium |

---

## Module 10 — Path Traversal ⚡ *Deep scans only*
*Active probing of URL query parameters with `../` traversal payloads.*

| # | Check | Severity |
|---|---|---|
| 96 | Path traversal / Local File Inclusion (LFI) on URL parameters | Critical |

---

## Module 11 — Site Crawler ⚡ *Deep scans only*
*Crawls up to 20 internal pages and re-runs header + cookie checks on each.*

| # | Check |
|---|---|
| 97+ | All header and cookie checks (#1–22) repeated per crawled page |

---

## Summary

| Tier | Unique check types | Approximate HTTP requests |
|---|---|---|
| **Basic** | ~73 | ~100–150 |
| **Deep** | ~97+ | ~300–500+ (crawl + JS fetches + path probes) |

## Grading Formula

Risk score accumulates per finding: **Critical = +30, High = +15, Medium = +5, Low = +1**.

| Score | Grade |
|---|---|
| 0–10 | A |
| 11–25 | B |
| 26–45 | C |
| 46–65 | D |
| 66+ | F |
