# False-positive audit

Findings from pointing the passive scanner at well-secured third-party sites via
`scripts/live-scan.ts`. On targets like these a correct scan returns few findings
and zero false ones, so every actionable finding is checked by hand against the
live response.

Run it before releasing scanner changes:

```
DATABASE_URL=postgres://localhost/anything \
  npx tsx artifacts/api-server/scripts/live-scan.ts https://github.com
```

`DATABASE_URL` only has to be *set* — the scanner module imports the db layer at
load time. It is never read by a passive scan.

## 2026-09-07

Targets: google.com, github.com, cloudflare.com, mozilla.org.

### Fixed

| Finding | Target | Why it was wrong |
|---|---|---|
| `Non-Session Cookie Readable by JavaScript` on `NID` | google.com | `analyzeCookies` re-split a flattened `Set-Cookie` on `/\n|,(?=[^;])/`. The comma inside `expires=Tue, 09-Mar-2027` matches, shearing the cookie so every attribute after the date is invisible. NID *does* carry HttpOnly. Hit any cookie whose `expires=` precedes its flags — most of them. Now uses the already-split list from `getSetCookie()`. |
| `Missing Secure Flag` reported twice for one cookie | google.com | Root cookies analysed in `scanner.ts`, inner pages in `crawler.ts`, with the crawl's dedup set starting empty. Now seeded from the root's cookies. |
| `No Rate Limiting Detected` | github.com | Header-absence check. GitHub enforces at the edge and exposes no rate-limit headers on HTML. `x-github-edge-region` / `x-github-request-id` added to the infrastructure allowlist, alongside the existing Cloudflare/Akamai/CloudFront/Azure/Google entries. |

| `CSP script-src Contains Wildcard — XSS Protection Bypassed` (**HIGH**) | cloudflare.com, mozilla.org | The check matched any `*` anywhere in the directive, so ordinary allowlist entries (`https://*.onetrust.com`, `*.google-analytics.com`) tripped it. Nearly every CSP that loads analytics has one, so well-built policies were reported HIGH. Now only a bare `*` (optionally scheme-prefixed) is reported. |
| `Missing security.txt` evidence said "not found" | mozilla.org | The FINDING was right — mozilla.org's file is not RFC 9116 (`Email:`/`Main info:` rather than `Contact:`/`Expires:`). The evidence was hardcoded to "not found" regardless, so anyone verifying saw a file at HTTP 200 and concluded the scanner was broken. Evidence now reports what each path actually returned. |

### Open

_None currently. Re-run the scanner against these targets after any scanner change._

### Shipped

`c94fd75` deployed to secscan.us on 2026-09-07 — web tier (`seclayer` service,
deployment `9860786a`) then worker (`secscan`, `13c194c0`), in that order,
because the worker enforces the domain-verification gate and will block active
probes while the `/domains` page that satisfies it is not yet served.

Run counts before -> after on the four audit targets:

| Target | Findings | Actionable |
|---|---|---|
| google.com | 15 -> 13 | 7 -> 6 |
| github.com | 12 -> 11 | 6 -> 5 |
| cloudflare.com | 9 -> 8 | 5 -> 4 |
| mozilla.org | 8 -> 7 | 4 -> 3 |

### Checked and correct — do not "fix" these

| Finding | Target | Verified |
|---|---|---|
| `Content-Security-Policy is report-only` | google.com | Only `Content-Security-Policy-Report-Only` is sent; report-only enforces nothing. |
| `Missing X-Content-Type-Options` / `Referrer-Policy` / `Permissions-Policy` | google.com | Genuinely absent from the response. |
| `Non-Session Cookie Missing Secure Flag` — NID | google.com | Google serves NID **without** `Secure` to a non-browser UA, and *with* it to Chrome. Checking in a browser shows the opposite of what the scanner saw. Do not "correct" this from a browser check. |
| `X-Frame-Options missing on 2 internal routes` | google.com | `/intl/en/policies/privacy/` and `/terms/` return 200 `text/html` with no XFO. Not redirects. |
| Header findings on `/healthz` | github.com | Genuinely `Content-Type: text/html` with an HTML body, so the "HTML documents only" rule correctly includes it. Arguably over-severe at HIGH for a static health page, but not false. |
