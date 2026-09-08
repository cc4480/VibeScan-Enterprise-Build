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

## 2026-09-08 — 30-site corpus round

Thirty sites across six sectors, scanned passively to build a published baseline.
The point was to measure, not to hunt; the hunt happened anyway. One finding —
**"Missing SPF Record — Email Spoofing Possible", HIGH, against www.gov.uk** —
turned out to contain three separate bugs, and GOV.UK publishes `v=spf1 -all` at
`gov.uk` and `p=reject` at `_dmarc.gov.uk`. It is the single most email-secure
domain a UK scan is likely to encounter, and we reported it as having neither.

Every one of the three is the same underlying error the audit has now recorded
four times: **reading the presence of a response as the meaning of the
response.** STARTTLS read reachability as an answer; the WAF detector read
`x-datadome` presence as "blocked"; `security.txt` reported "not found"
regardless; and here, DNS answers were read without checking what they were.

### Fixed

| Finding | Target | Why it was wrong |
|---|---|---|
| `Missing SPF Record` + `Missing DMARC Record` (both **HIGH**) | www.gov.uk | `toEmailDomain` derived the email domain by counting label lengths: `uk` is 2 characters and `gov` is 3, so it took the `.co.uk` branch, and with only 3 labels it returned the hostname **unchanged**. SPF was looked up at `www.gov.uk` and DMARC at `_dmarc.www.gov.uk` — neither of which exists. `www.bbc.co.uk` escaped only because it has four labels. Replaced with a walk up the ancestor chain that accepts a record found at any parent, which is what RFC 7489 says a receiver does anyway. |
| Severity escalated Medium → **HIGH** on the same finding | www.gov.uk | `dnsQuery` returned the whole DoH answer section without filtering on record type. An MX query for `www.gov.uk` answers with two **CNAME** records (type 5) pointing at Fastly and no MX at all; `mxAnswers.length > 0` read that as "domain actively sends email". Answers are now filtered to the type that was asked for. |
| Evidence claimed `Status: NOERROR (domain exists)` | www.gov.uk | Hardcoded into the evidence string. `_dmarc.www.gov.uk` is NXDOMAIN. The function's own doc comment already said a missing-record finding may only be reported when status is 0 — the code checked only for -1. NXDOMAIN now suppresses the finding, and evidence prints the status the resolver actually returned plus every name queried. |

The test fixtures could not have caught any of this: `dohResponse()` built answers
with no `type` field at all, so a CNAME-counted-as-MX was unrepresentable. The
helper now emits realistic answers and six regression tests cover the three bugs.

### Open

_None currently. Re-run the scanner against these targets after any scanner change._

### Checked and correct — corpus round

| Finding | Target | Verified |
|---|---|---|
| `Missing DMARC Record` | european-union.europa.eu | Genuinely absent. `_dmarc.europa.eu` is NXDOMAIN on both Cloudflare and Google resolvers, and `europa.eu` has real MX records (pphosted, Outlook). The finding stands. |
| `JavaScript Source Map Exposed` | about.gitlab.com | Real. `https://about.gitlab.com/_nuxt/Dtrxhrnz.js.map` returns HTTP 200, 2.95 MB, 301 source files with `sourcesContent` included. |
| `JavaScript Source Map Exposed` | archive.org | Real, HTTP 200, 25 KB — but the map covers a vendored `lit` polyfill, so what is exposed is a public library's source, not the operator's. True finding, arguably over-severe at HIGH. |

### Known-weak, not yet fixed

**`No Rate Limiting Detected` fired on 15 of 30 sites**, including Stripe,
Wikipedia and GOV.UK. Verified by hand: stripe.com really does send no
rate-limit headers at all. So the check is literally accurate and its name is
not — it detects that rate limiting is *not advertised*, which is the normal
configuration, and asserts that it is *absent*. It carries confidence 52 and
LOW severity, which is the scanner hedging on a signal it cannot actually
observe. Excluded from the published baseline. Either the finding should be
renamed to what it measures, or it should not be a finding.

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

### Caught before shipping — mail transport probe (2026-09-07)

The one false positive in this audit that was never released, because it was
found by pointing the new detector at known-good targets before committing it.

**`Mail Server Does Not Offer STARTTLS` on cloudflare.com.** Wrong: its MX
advertises STARTTLS on port 25 and presents a certificate valid for 162 days.

The detector probed 25, 587 and 465 on each MX host and gated its finding on
whether a port was *reachable*. Cloudflare's MX completes the TCP handshake on
587 and then resets before answering `EHLO`, so `starttlsAdvertised` stayed
`null` — the probe learned nothing. Reachability was being read as an answer,
so silence scored as "no STARTTLS".

**It fired on some runs and not others**, depending on when the reset landed.
That is worse than a consistent false positive: it cannot be reproduced by
whoever disputes the report, and re-running the scan "fixes" it.

Two fixes, both in `src/lib/mailTls.ts`:

1. Only ports that actually answered `EHLO` count as evidence
   (`starttlsAdvertised !== null`). Unreachable was already excluded; silent-
   after-connect now is too. Regression test: *"stays silent when a host
   connected but never answered EHLO"*.
2. Probe port 25 only. An MX is an inbound relay — every message the world
   sends to the domain arrives on 25, so 25 alone answers the question. 587 and
   465 are submission ports for the domain's own authenticated users and
   normally live on a different hostname. They measured nothing here and cost
   ~5s of every scan (Google firewalls both; Cloudflare resets 587).

Verified over 3 rounds against google.com, github.com, cloudflare.com,
mozilla.org, example.com: 0 findings every round, and scan cost fell from a flat
6.1s to 0.3–2.0s. One round caught mozilla's `alt2` MX going quiet mid-probe and
correctly stayed silent — the false-positive path exercised live.

### Caught before shipping — WAF interception (2026-09-07)

Found the same way: pointing the new structured-data checks at real sites and
reading the output.

**stackoverflow.com and npmjs.com were reported as excluded from search
indexes, with no Open Graph tags and no structured data.** All four statements
are true — of the Cloudflare "Just a moment..." interstitial those sites return
to the scanner, which carries `noindex,nofollow` and no metadata. None of them
is true of the sites themselves.

This is broader than structured data. When an edge answers instead of the
origin, EVERY content-derived check describes the interstitial: CSP, cookies,
security headers, SRI, inline scripts, technology fingerprint. The report reads
as a scan of the customer's site and is a scan of a WAF error page.

`src/lib/challengePage.ts` recognises the interception from vendor
fingerprints — challenge-platform script paths, anchored interstitial titles,
vendor headers — and the scan reports it once as a Scan Coverage finding saying
plainly which findings can no longer be trusted. The structured-data module
returns nothing at all in that case.

Detection is strict on purpose: calling a real page a challenge page would
suppress genuine findings, which is worse than the bug being fixed. A large
document that merely loads a bot-protection script is not a challenge, a 403
that returns a real access-denied page is not a challenge, and "just a moment"
in body copy is not a challenge.

**Then the detector itself produced a false positive, and it was the same
mistake in a new place.** nytimes.com was flagged as intercepted on
`x-datadome: protected` — a header DataDome sets on ALLOWED traffic. Its real
1.3MB homepage, two JSON-LD blocks and all, was sitting in the response body.
Fixed by matching the header's value rather than its presence; `re` is now
required on every header signal so the shortcut cannot be taken again.

Verified across 15 sites (google, github, cloudflare, mozilla, stackoverflow,
npm, reddit, amazon.co.uk, bbc, wikipedia, vercel, nytimes, gov.uk, shopify,
MDN): zero findings above INFO, the two Cloudflare interstitials correctly
identified, every real page correctly left alone.

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
