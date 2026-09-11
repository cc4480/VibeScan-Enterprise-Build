# False-positive audit

Findings from pointing the passive scanner at well-secured third-party sites via
`scripts/live-scan.ts`. On targets like these a correct scan returns few findings
and zero false ones, so every actionable finding is checked by hand against the
live response.

Scores and grades for every run live in `SCAN-RESULTS.md` beside this file.
This document records what was wrong; that one records what was returned.

Run it before releasing scanner changes:

```
DATABASE_URL=postgres://localhost/anything \
  npx tsx artifacts/api-server/scripts/live-scan.ts https://github.com
```

`DATABASE_URL` only has to be *set* — the scanner module imports the db layer at
load time. It is never read by a passive scan.

## 2026-09-10 — 38-target re-scan

Three actionable findings were new against the earlier rounds. Two were real.
The third was real too, and its evidence said otherwise.

### Fixed

| Finding | Target | Why it was wrong |
|---|---|---|
| `X-Frame-Options / frame-ancestors Missing on 5 Internal Routes` | www.paypal.com | The detection was correct and the **evidence refuted it**. `buildHeaderGapVulns` printed `new URL(p).pathname`, dropping the query. PayPal links every internal page as `…/giving?locale.x=en_US`, and that URL answers with an 1818-byte CSP carrying no `frame-ancestors`; the bare `…/giving` answers with a *different* 2277-byte CSP that has it. The crawl fetched the linked form and observed the gap correctly. Anyone verifying the finding as this audit requires — take the path, fetch it, read the header — landed on the other URL, found the header present, and would have "fixed" a working check. Evidence now carries `pathname + search`. |

I nearly did exactly that. The first four checks (browser UA, scanner UA, ten
repeats, the scanner's own fetch layer) all said `frame-ancestors` was present,
and the finding looked plainly false. It was the *trailing-slash* variant test
that showed PayPal serves two different CSPs, and PayPal's own HTML that showed
which one the crawler had been given.

**An evidence string is a claim that can be checked. If it points somewhere the
scanner did not look, it does not merely fail to support the finding — it argues
against it.** That is worse than no evidence, and it is the one defect in this
document that would have caused a correct check to be deleted.

### Checked and correct — 2026-09-10 round

| Finding | Target | Verified |
|---|---|---|
| `Missing DMARC Record` (High) | european-union.europa.eu | Genuinely absent. `_dmarc.european-union.europa.eu` and `_dmarc.europa.eu` both answer NXDOMAIN (status 3) on Cloudflare DoH, and `europa.eu` publishes real MX (pphosted, Outlook). Same conclusion as the corpus round. |
| `X-Frame-Options / frame-ancestors Missing` — 3 of the 5 paypal.com routes | www.paypal.com | `/manage-money`, `/ways-to-pay/add-payment-method` and `/manage-money/direct-deposit` genuinely lack `frame-ancestors` in every variant tested, with no `X-Frame-Options` header. |
| `Content-Security-Policy Missing on 8 Internal Routes` (High) | www.reddit.com | **Did not reproduce.** Six repeats each of `/`, `/login` and `/dashboard` through the scanner's own fetch layer returned an identical 161-byte CSP every time; `/administrator`, `/auth` and `/signin` all carry it too. Only `/live` genuinely lacks one, and `/admin` is a 404 the crawler already excludes. The scan recorded no rate-limit or challenge signal, root CSP was present (or the gap finding could not have fired), and reddit answered in 18.5s across 14 pages. Cause unknown. **Left alone** — a check is not changed on a finding that cannot be reproduced, and the probable explanation is a degraded edge response during the probe burst, which is a property of the target that night, not of the scanner. Re-check on the next round. |

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

### Fixed — second pass, from the verification run

Re-running the corpus after the DNS fixes surfaced three more, one of them
introduced by the fix itself. This is the argument for re-running rather than
trusting a green suite.

| Finding | Target | Why it was wrong |
|---|---|---|
| `DNSSEC Not Enabled` | www.nasa.gov | **Introduced by the record-type filter above.** DNSKEY lives at the zone apex, and `checkDnssec` asked the scanned hostname: `www.nasa.gov` answers with one CNAME and no DNSKEY, while `nasa.gov` is properly signed. Before answers were filtered by type, that CNAME was counted as a DNSKEY and the check passed for entirely the wrong reason — a hidden false negative that the filter converted into a visible false positive. The corpus went from 13/30 to 26/29 in one run, which is what made it obvious. Now walks to the apex. Verified after: nasa.gov's finding is gone, and stripe.com, wikipedia.org and github.com genuinely publish no DNSKEY, so the higher figure is the true one. |
| `No Rate Limiting Detected` | 15 of 30 sites | Asserted something a passive GET cannot observe. stripe.com sends no rate-limit headers at all and unquestionably rate-limits; rate limiting lives on login and API routes, not the homepage, and CDNs throttle silently. The infrastructure allowlist had already been patched twice — Google server tokens, then GitHub's edge — which is the shape of a check chasing an unobservable property one vendor at a time. Renamed to `Rate Limiting Not Advertised in Response Headers` and dropped to INFO, weight 0. |
| `Hardcoded JWT Token in Source` (**HIGH**) | nytimes.com | An Iterate survey widget's `apiKey` inside Google Tag Manager, payload `{"company_id":"…","iat":…}`. Publishable by design, the same category as the Supabase anon key already excluded. Two entries now share the regex and split on whether the payload carries a principal claim — `sub`, `user_id`, `email`, `role`, `scope`. With one it is a credential leak at HIGH; with none it is an account identifier, reported at INFO so the signal survives without the accusation. |
| Every content-derived finding | etsy.com, ebay.com, amazon.co.uk, stackoverflow.com, reuters.com | Naming untrusted findings in a coverage note was not enough — the report still told Etsy it was missing CSP and serving a wildcard CORS policy, both true only of Cloudflare's interstitial. Twelve of eighteen findings on that scan described a page Etsy never served. Findings are now withheld unless their source never read the intercepted response: DNS, email authentication, mail transport. etsy.com goes from 18 findings to 4, all four genuinely about Etsy. |

`toEmailDomain` was deleted rather than patched. Guessing a registrable domain
from label lengths is what produced the GOV.UK failure in the first place.

### Result

| Target | Before | After |
|---|---|---|
| www.gov.uk | 12 findings, 3 actionable | 7 findings, 0 actionable |
| www.etsy.com | 18 findings, 6 actionable | 4 findings, 1 actionable |
| stackoverflow.com | 13 findings, 4 actionable | 3 findings, 0 actionable |

686 tests pass, including twelve new regressions across these six bugs.

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
