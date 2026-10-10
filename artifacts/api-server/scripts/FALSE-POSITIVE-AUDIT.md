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

## 2026-10-09 (later) — hand check of the categories earlier rounds did not verify

Eight sites (nextjs.org, vuejs.org, linear.app, hubspot.com, plaid.com, bolt.new, cursor.com, huggingface.co), one
page each plus a few routes, scanned live and every claim recomputed with plain fetch and no scanner code. Passive only.

**Agreed:** weak CSP (including HubSpot, whose `unsafe-inline` beside a nonce and `strict-dynamic` is correctly ignored
and which is flagged only for the `unsafe-eval` that stays in effect), `object-src` and `base-uri` on all 8, non-session
cookie flags (plaid, cursor), source maps (hubspot and plaid return 200 with valid JSON and `sourcesContent`), and the
"missing on N internal routes" findings on every route re-fetched. No CVE finding appeared on any of the 8, so
version-to-CVE matching was not exercised.

### Fixed

| Was reported | Benign trigger | Now |
|---|---|---|
| `Session Cookie Missing HttpOnly Flag` (MEDIUM) | bolt.new's `ajs_session_id`, a Segment analytics id the vendor script has to read | Analytics identifiers (`ajs_`, `_hj`, `mp_`, `amplitude_`, `ph_phc_`, `_pk_`, `_ga`, `_gid`) are not session cookies; they are judged as non-session, as `ajs_anonymous_id` already was |
| `External Resources Missing SRI` told the site to add `integrity` | AWS WAF's `challenge.js` on `<id>.edge.sdk.awswaf.com`, which cannot be pinned | Not reported, like the other bot-protection tags (`DYNAMIC_SUFFIXES`) |
| The same, with pinning advice | Fathom's `cdn.usefathom.com/script.js`, edited in place | Still reported, with the vendor-updated advice |
| The same | HubSpot's own `hsappstatic.net` and `hs-banner.com` | Counted as HubSpot's own CDN (`OWNED_CDNS`) |

Each has a test that fails on the old code and a twin showing a real session cookie or a real third party is still reported.

### Narrowed on purpose

- A session cookie whose name starts with an analytics prefix (`ajs_`, `_hj`, `mp_`, `_ga` and the rest) is no longer
  treated as a login cookie, so a real one named that way would be missed.

## 2026-10-09 — code review against seclayer's fixes, and the fixes

A code-only round: each false-positive class fixed in seclayer was checked against this scanner, and
every claim below was reproduced by calling the real check code on a benign input (the clickjacking
cases through a loopback server) before it was changed. No live sites were scanned.

### Fixed

| Was reported | Benign trigger | Now |
|---|---|---|
| `X-Frame-Options Header Misconfigured` (MEDIUM) | The header sent twice, which fetch joins as `SAMEORIGIN, SAMEORIGIN` (app and proxy both add it) | Values are split, lowercased and de-duplicated as the HTML spec does (`xfoBlocksFraming`): the same duplicate rule as `nosniff` |
| The same (MEDIUM) | Legacy `ALLOW-FROM` kept next to CSP `frame-ancestors` | Not judged: browsers that support CSP ignore X-Frame-Options when `frame-ancestors` is set. The check computed this and never used it |
| `Apache Server Info Page Exposed` (MEDIUM) | A bot or game-server dashboard at `/server-info` with a "Server Settings" heading | Needs "Apache Server Information", or "Server Settings" with mod_info's "Module Name:" entries |
| `jQuery 1.12.4 — Known Vulnerability` and the like | A changelog sentence, an install snippet shown as escaped text, a download link, page-state JSON | Versions come only from what the page loads or runs: real `<script src>` / `<link href>` tags, import maps, executable inline scripts and styles, generator meta tags |
| `Bootstrap 2.10.0 — Known Vulnerability` | `react-bootstrap@2.10.0` | A package whose name ends in the library's name is a different package (`(?<![\w-])`); same for `isomorphic-dompurify`, `chartjs-adapter-moment` |
| Bootstrap CVEs | A Bootstrap stylesheet with no Bootstrap JavaScript | Bootstrap needs its script loaded; every advisory is in its JavaScript plugins |
| Library CVEs at the wrong version | A WordPress theme's `bootstrap.min.css?ver=1.0.0` (the theme's version) | `?ver=` is trusted only on `wp-includes` paths, where core registers the library's real version |
| "WordPress 3.7.1" in the technology list | WordPress core's `jquery.min.js?ver=3.7.1`, which is jQuery's version | That pattern no longer sets the WordPress version |
| `TLS Certificate Expires Soon` with "renewal is not working" | Any healthy short-lived certificate (Let's Encrypt's 6-day profile) | The window is the last third of the certificate's lifetime, capped at 14 days; a 90-day certificate is judged as before |

Each fix has a test that fails on the old code and a twin showing the real problem is still reported:
`probesHttp.clickjacking.test.ts`, `cveCheckVersions.test.ts`, `probes-data.test.ts` (`/server-info`),
`tlsCheckFindings.test.ts`.

### Narrowed on purpose (a real problem in these shapes can now be missed)

- A library version that appears only in non-executable markup (prose, `<pre>`, JSON data blocks, HTML
  comments, `<a href>`) is no longer read.
- A WordPress theme or plugin that passes a library's real version in `?ver=` outside `wp-includes`
  is missed.
- A page that ships Bootstrap's JavaScript inside its own bundle, with only the Bootstrap stylesheet
  visible, is not reported.

### Not verified, or still open

- `TRACE` is still reported from the `Allow` header without confirming the server honours it. Not a
  confirmed false positive; confirming would mean sending the method.

## 2026-10-05 (later) — 50 companies not tested before

`sweep-lists/2026-10-05-companies-50.txt`: 50 sites with no overlap with any earlier sweep or with the
20 guard targets, grouped by what each group stresses (AI app builders and BaaS, framework docs, SaaS
marketing, PaaS, identity vendors, fintech, consumer apps, media, retail, government/education/health).
Passive only. Raw output: `scan-results/2026-10-05-companies-50.json`. All 50 scans completed.

**Withheld as bot challenges, correctly:** lovable.dev, canva.com, coinbase.com, nih.gov, mayoclinic.org.

**Independent re-derivation.** For every site the scan reported on, the live response was fetched again
with the scanner's User-Agent and these claims recomputed without any scanner code: missing CSP (9),
missing `nosniff` (14), missing clickjacking protection (7), HSTS max-age too short (2), missing DMARC
(3), DMARC `p=none` (3), DMARC without `rua` (1), missing SPF (2), SPF `?all` (3). **Every one agreed.**
Nine sites refused the plain re-fetch (403, 406, 429) and were not re-derived: salesforce, intuit,
spotify, airbnb, cdc.gov, mit.edu, lovable, coinbase, mayoclinic. Three sites looked like a missed
"Missing CSP" (replit.com, netflix.com, booking.com): all three send only
`Content-Security-Policy-Report-Only`, which the scanner reports as "not enforced", correctly.

**Not hand-checked this round:** SRI (19 sites), weak CSP (19), `object-src` and `base-uri` (21 and 20),
non-session cookie findings, technology and CVE matches, source maps, and the "on N internal routes"
findings. Earlier rounds verified the logic behind these; nothing here re-verified them site by site.

### Fixed: an AWS WAF challenge with a `<noscript>` heading was graded as the site

booking.com answers the scanner with HTTP 202 and a 3.9 KB AWS WAF stub: an empty title, an empty
`#challenge-container`, `challenge.js`, `AwsWafIntegration` calls and
`<noscript><h1>JavaScript is disabled</h1>...`. The detector already knows the AWS WAF SDK, but only on a
"stub document", and `isStubDocument` took the `<h1>` for page structure. The scan reported 12 findings
(5 actionable) about the interstitial. `<noscript>` content now counts for neither structure nor visible
text. Real capture saved as `__fixtures__/aws-waf-challenge-booking.html`; the detection test fails on
the old code, and two clean twins (a real page loading the AWS WAF SDK with a noscript fallback) stay
unflagged. Re-scan: 3 findings, 0 actionable, "intercepted by a bot-protection challenge".

### Coverage gap, not a bug

`renderedWithBrowser` is false for every site in every sweep to date (0 of 20, 30 and 50). None of these
sites serves an empty single-page-app shell, so the headless-browser path, which matters most for sites
built with Lovable, Bolt and similar tools, is never exercised by the sweep. A future list needs a few
client-rendered app shells that do not challenge the scanner.

## 2026-10-05 — passive sweep of the 20 guard sites, plus the TLS and mail checks

Same 20 targets and mode as 2026-09-30 (`live-scan.ts`, passive). Raw output:
`scan-results/2026-10-05-guards-20.json`. The new TLS configuration check (2026-10-05) and the mail
transport check run in the worker, not in `runScan`, so `live-scan.ts` never exercises them; they were
run separately against the same 20 sites: `scan-results/2026-10-05-tls-mail-20.json`.

**Against 2026-09-30:** unchanged. Every difference was a route count inside a finding's name ("on 9
Internal Routes" now "on 8"), dropbox swapping one info finding for another, and paypal losing one info
note. stackoverflow.com and npmjs.com are no longer on the list (they answer this scanner with a
challenge); pypi.org and rubygems.org replaced them. etsy, nytimes and reddit are withheld as bot
challenges and report only the coverage notes, as intended.

**New targets, checked against the live response (scanner User-Agent):** all findings on pypi.org and
rubygems.org reproduced, apart from the one below. `/search/` on pypi has no CSP or Referrer-Policy;
rubygems `/admin` is a real login page and lacks `nosniff`; pypi's root has no `Cache-Control`.

**TLS and mail transport:** 18 of 20 sites produced no TLS finding; the two that did
(google.com, mozilla.org: "Deprecated TLS Protocol Versions Accepted") were re-tested with plain
`openssl s_client -tls1 / -tls1_1` in a container: both complete TLS 1.0 and 1.1 handshakes, and
github.com, which the scanner passed, refuses them with a protocol-version alert. True positives. No
mail-transport findings on any site (port 25 was reachable from the test machine for at least
google's MX; a host that does not answer produces no finding by design).

### Fixed: inner-page cookie check disagreed with the root check

Found on pypi.org. `/account/login/` clears `user_id__insecure` (`Max-Age=0`, `expires` in 1997) and the
crawler reported it as "Non-Session Cookie Readable by JavaScript on Inner Page". The root-page check
already skips a cookie the server is clearing; the crawler's `checkPageCookies` and
`seedCookieIssuesFromRoot` did not, and tested flags with `/secure/i` and `/httponly/i` over the whole
Set-Cookie line. That also matched the word in the cookie's *name*: with the name `user_id__insecure`
the cookie counted as `Secure`, so a live cookie of that name without the flag would never have been
reported. Both now use `parseSetCookie`, as the root scan does. Tests fail on the old code (deleted
cookie, live cookie with "insecure" in its name, `secure_pref` / `httponly_hint`, and the root seeding)
and a clean twin keeps the real findings.

### Left as is

- pypi.org "JavaScript Source Map Exposed" (High): the map exists and embeds `sourcesContent`, as
  reported. pypi's code is open source, which the scanner cannot know; the rating follows the existing
  rule (a map is rated by whose code it embeds).
- pypi.org SRI on `analytics.python.org`: a different registrable domain from pypi.org, so third-party
  by the scanner's rule; arguable, not wrong.

## 2026-09-30 (evening) — full passive sweep after the probe-review fixes

Live sweep, passive only: the 30-site list from 2026-09-24 plus the 20 guard targets built into
`live-scan.ts`. Raw output: `scan-results/2026-09-30-sweep-30.json` and `2026-09-30-guards-20.json`.
Actionable findings on the 30 sites went from 98 to 92. Every difference from 2026-09-24 was checked
against the live response with the scanner's own User-Agent, and the remaining header-based findings
were re-derived independently (CSP, nosniff, clickjacking, base-uri, cookies, HTTP redirect). The
findings not header-based (source maps, DMARC, the internal-route findings) were checked by hand.
Not re-checked: technology fingerprints, the CVE and end-of-life matches, and the JSON-LD notes.

### Fixed since the last sweep, and confirmed correct now

| Was reported | Target | Why it was wrong |
|---|---|---|
| Weak CSP (Medium) | archive.org | `script-src` holds only origins and `'wasm-unsafe-eval'`. |
| Weak CSP (Medium) | bbc.co.uk | `'unsafe-inline'` sits beside `'strict-dynamic'` and a nonce, so browsers ignore it. |
| Missing `nosniff` (Medium) | figma.com | The header is sent twice; the old exact match read it as invalid. |
| Missing SRI (Medium) | cloudflare, dropbox, europa.eu, stripe | The scripts are the site's own subdomain or CDN. Dropbox's one real third-party script carries `integrity`. |
| SPF over the lookup limit | nasa.gov, etsy.com | 9 and 10 lookups; IPv6 ranges were being counted. |
| Non-session cookie without `Secure` | theguardian.com | The named cookies were `max-age=0` deletions; the live ones have `Secure`. |
| Permissive CORS (Medium) | zoom.us | `ACAO: *` with no credentials is Info now. |

### New and real

npmjs.com now returns its real page to the scanner instead of a Cloudflare challenge, so four findings appeared: `script-src` has `'unsafe-inline'` with no nonce or hash, no `base-uri`, no Referrer-Policy, no Permissions-Policy. All four confirmed by hand. Cloudflare decides per client whether to challenge: `npmjs.com` answered 200 while `www.npmjs.com` in the guard run was still intercepted (and withheld correctly). Seven targets were intercepted and withheld in the 30-site run: amazon.co.uk, apnews, ebay, etsy, nytimes, reuters, stackoverflow.

### Checked and correct — do not "fix"

- Missing CSP (High) on european-union.europa.eu, fastly, nasa.gov, shopify, slack, wikipedia, zoom: no CSP header and no CSP meta tag on the final response.
- CSP missing on internal routes (bbc, vercel, cloudflare, github): reproduced on the live routes. github's is `/healthz`, which answers `text/html`.
- Missing `nosniff` (8 sites), missing clickjacking protection (5 sites), Weak CSP (10 sites), missing `base-uri` and `object-src`: an independent re-derivation agreed with the scanner on every one.
- `http://archive.org` answers 200 with no redirect. `_dmarc.european-union.europa.eu` and `_dmarc.europa.eu` are both NXDOMAIN.
- The three source maps exist, return 200 and embed source text (see the severity question below).

### Open items from this round — fixed the same day

Each has a clean-twin test that fails on the old code, and a test that the real problem is still found.

1. **gitlab.com "Missing Content-Security-Policy" (High).** A policy delivered in `<meta http-equiv="Content-Security-Policy">` is now read (`extractMetaCsp`), analysed like a header's, and quoted as a meta tag in the evidence. gitlab.com now reports what is true: `unsafe-inline` and `unsafe-eval` in `script-src` (Medium) and `object-src https: http:` (Medium). A commented-out tag and a Report-Only tag are not treated as policies. Clickjacking still reads headers only, correctly, because a meta tag cannot carry `frame-ancestors`.
2. **zoom.us SRI listing `st1.zoom.us`.** The address the user asked to scan now also counts as first-party (`requestedUrl` reaches `expectsIntegrity`). Only the real third party, `cdn.bc0a.com`, is reported. A lookalike such as `zoom.us.evil.example` is still a stranger.
3. **Source-map severity.** A map is rated by whose code it embeds. Fewer than three own files and under 5% of the sources, or a map served from a `/vendor/` path, is now a Low "Third-Party Library Code" finding that says how many files are the site's own. archive.org went from High to Low. fastly.com now shows both maps its pages expose: the library one as Low, and a second one holding `SearchCombobox.astro`, the site's own component, as High. The earlier run only reported the first map it found.

### Found by the re-sweep, and fixed: a resolver error read as "no SPF record"

Scanning nasa.gov ten times gave "Missing SPF Record" (Medium) on one run in five. nasa.gov's TXT lookup returns SERVFAIL about one time in ten. `findUpChain` decided "absent" from the first name only (www.nasa.gov, a clean NOERROR with no TXT) and ignored that the parent, where the record lives, had errored. Now any resolver error up the chain makes the answer inconclusive, and `dnsQuery` retries a SERVFAIL once. Ten of ten scans clean afterwards. The same chain code serves DMARC, so it could have produced the same false claim there.

### Re-sweep after the fixes

`scan-results/2026-09-30-sweep-30-after-fixes.json`. The differences from the run above are the fixes: gitlab, archive.org, fastly and zoom as described. apnews.com happened to be served its real page this time instead of a challenge, which added seven findings that an independent fetch agreed with. The fixture gate stayed at 82/82.

### Verification pass, same day, after the fixes

The whole result set (30 sites and 20 guard targets) was re-checked independently rather than trusted. An independent fetch with the scanner's User-Agent recomputed every header finding (CSP present or weak, `base-uri`, `object-src`, `nosniff`, clickjacking, Referrer-Policy, Permissions-Policy) on 38 targets, the cookie-attribute findings on 39, the small header findings (Server, X-Powered-By, Cache-Control, COOP/COEP/CORP, CORS, HSTS), DNSSEC on every apex that was flagged (36), DMARC `rua`, Open Graph, Twitter cards, structured data, security.txt, robots.txt, OpenAPI and rate-limit headers on 39. The intercepted targets are withheld by design and were not checked; apnews.com answered the verifier with a challenge and was skipped.

Two more false positives, both Info, both fixed with tests that fail on the old code:

- **`Missing security.txt` on npmjs.com.** Cloudflare answered the scanner HTTP 403 on both paths while `/.well-known/security.txt` is a valid file. A refusal, timeout, 429 or 5xx on either path now means "could not tell", and no finding is raised. Only definitive answers (404, or a page without RFC 9116 fields) still report it.
- **`robots.txt Discloses Sensitive Application Paths` on wikipedia.org.** `/admin/i` matched inside `Administratoren`, `Adminkandidaturen` and `Requests_for_adminship`, which are discussion pages about the role. The keywords now match as whole path tokens. Every path the finding named on the other sites (`/admin/`, `/wp-admin/post.php`, `*/store/admin`, `/fizzy/admin`, `/web.config`, `/config/newrelic/prod`) still matches.

Checked and correct, not false positives:
- google.com's CSP is `Content-Security-Policy-Report-Only` only, and is reported as report-only, not missing.
- dropbox.com's `object-src` is limited to itself and its own static hosts; the scanner not flagging it is defensible.
- google.com "No Structured Data Found" says "No `<script type="application/ld+json">` blocks", which is exact. The page's schema.org microdata is not JSON-LD.
- microsoft.com `CAS_PROGRAM` is a real `Set-Cookie: …; secure; SameSite=None` without `HttpOnly`, sent when the request carries `Accept-Language`.
- linkedin.com `fid` and microsoft.com `bStore` (inner pages) reproduce: no `Secure`. LinkedIn's `JSESSIONID` missing `HttpOnly` is real (recorded as such in an earlier round).
- Info findings for DNSSEC (36 of 36), Open Graph, Twitter cards and structured data all matched the live pages.
- The `Missing SPF Record` on nasa.gov in the after-fixes JSON predates the SPF fix and is that flake; ten later scans were clean.

### Resolved afterwards: SRI on vendor-updated tags

- The finding stays for provider-updated marketing tags (gitlab: bizible, marketo; nasa: dap.digitalgov.gov, parsely; slack: clearbit): a compromised vendor does run code on the page. Only the advice changed. Those tags are marked `[vendor-updated tag]` in the evidence and the solution says to self-host a pinned copy or limit the tag with CSP and page scope, not to add `integrity`, which would break it at the next vendor update. Domain list: `VENDOR_UPDATED_DOMAINS` in `src/lib/sriPolicy.ts`. Do not suppress the finding for these hosts.
- `assets.guim.co.uk` is the Guardian's own CDN (`OWNED_CDNS`), so it is no longer flagged.
- Nothing else from the sweep is open.

### Technology / CVE / SRI sweep, same day (14 targets, `scan-results/2026-09-30-sweep-tech-14.json`)

- SRI wording checked live: gitlab (bizible, marketo), nasa (dap, parsely) and slack (clearbit) carry `[vendor-updated tag]` and the self-host/CSP advice; slack's ordinary CloudFront snippet in the same finding stays unmarked.
- **Fixed:** `Server Version Disclosure` fired on any digit, so php.net's `Server: BunnyCDN-HOU1-893` (a CDN edge-node id) was reported as a software version. It now needs `name/1.2`-style or dotted version text (`carriesSoftwareVersion`).
- **Checked and correct:** nginx.org `Server: nginx/1.31.3`; jquery.com `X-Powered-By: PHP/8.4.26`; python.org jQuery 1.8.2 with CVE-2012-6708 and CVE-2019-11358 (the page loads `/static/js/libs/jquery-1.8.2.min.js` and the googleapis copy).
- Not testable: apnews.com and npmjs.com were challenged again (Cloudflare), drupal.org redirected to new.drupal.org with nothing to report.

### Guard-list swap, same day (`scan-results/2026-09-30-swap-4.json`)

- `live-scan.ts` default targets: npmjs.com and stackoverflow.com (both answer this scanner with a Cloudflare challenge, so a scan of them tests nothing) were replaced by pypi.org and rubygems.org. The challenge-withholding rule keeps its unit tests (`challengePage.test.ts`). apnews.com is dropped from ad-hoc sweeps for the same reason; aljazeera.com and pbs.org stand in.
- All four new targets verified against live responses (headers, cookies, and the non-header checks): no disagreements.
- Checked and correct, do not "fix": pypi.org source map (`warehouse.a67d9eb4.js.map`, 101 sources of which 49 are the site's own, full `sourcesContent`) is correctly High; pypi `Disallow: /admin/` is really in robots.txt; rubygems `/admin` returns 200 and a static HTML login/422 page with no X-Content-Type-Options or Referrer-Policy, while `/` has both, so the two "Internal Route" findings are true (same shape as google.com's /terms).
- Baselines for the new targets: pypi 10 findings / 2 actionable, rubygems 12 / 4, aljazeera 10 / 4, pbs 15 / 8.

Guard baselines after this round: google 15/6, github 11/5 (unchanged); cloudflare 7/2 (was 8/4) and mozilla 6/2 (was 7/3), both from the SRI fix above.

## 2026-09-30 — code review of every probe family, and the fixes

Not a live sweep. Six reviewers each took a family of checks (new acting probes, passive
checks, active probes) and fed the real functions realistic BENIGN responses through mocked
fetch, looking for a finding that fires on a healthy site. Every item below was reproduced
before it was fixed, and every fix has a clean-twin test that failed on the old code plus a test
that the real problem is still found. The vulnerable-fixture gate stayed at 82/82 with no false
alarms, and its planted inner config was changed to a genuinely sensitive one (the old plant was
public runtime config, which was the false positive itself) with a public-config twin added.

### Fixed

| Area | Benign input that produced a finding | Now |
|---|---|---|
| Secrets | `NEXT_PUBLIC_*` public keys (Stripe pk, Supabase anon, Firebase, Mapbox, PostHog) | Not flagged; real secrets under those names still are |
| Secrets | Dev compose passwords, SQL comments, UI/validation text as "passwords", a hash as an AWS secret, the jwt.io sample token | Not flagged |
| Secrets | A bare AWS key ID, Twilio SID, Firebase config block | Titled and rated for what was seen (Low/Info) |
| Technology | Prose or links naming Shopify, Wix, Ghost, Bolt.new, Segment, Stripe, Python; `gunicorn`, `sessionid`, `Apache-Coyote` | Tags need structural evidence (asset URL, generator meta, header, cookie) |
| WAF | A vendor bot-protection script tag on an ordinary page graded the whole report N/A | Only a stub or challenge page counts |
| Versions | PHP 8.2 called End-of-Life before its EOL date; distro-packaged nginx/Apache/PHP called vulnerable | Judged by date; distro banners get a low-confidence verify note |
| Access control | Same app shell for every id, public numbered pages, the same login used as both accounts | Suppressed; identical accounts refused at scan creation |
| API | Unrouted DELETE answering 404, public GETs, a 12-request burst | Only 2xx or validation-level replies count; rate limit is Info on sensitive endpoints only |
| Race | A generic JSON 403/429 as the sixth reply | Inconclusive unless the reply says the action was already used |
| BaaS | `200 []` from an RLS-protected table, public catalogue rows, PocketBase/Appwrite empty lists | Info (public, empty) or hedged; sensitive rows stay Critical |
| Takeover | A live host whose 404 or copy mentions the provider | Needs the provider's unclaimed-resource page; Netlify and Fly.io are hedged |
| Attribution | Third-party GraphQL hosts and unowned public buckets filed against the customer | Own host only; unowned buckets are hedged Low |
| SSRF | The scanner following an open redirect onto its own collector | Redirects are not followed when planting |
| XSS | Reflection inside a script string, comment, textarea or title | Needs a reflected closer that breaks out |
| Redirect / CORS | A query string carrying the payload; reflected Origin without credentials | Landing host is checked; credential-less reflection is Low |
| Crawler | Inner-route `/config.json`, `/.env`, debug log and API-doc probes without catch-all or HTML guards | Same guards and structural validators as root probing |
| Headers | CSP with a nonce or `strict-dynamic`, `wasm-unsafe-eval`, duplicate `nosniff`, homepage `ACAO: *`, mixed content under `upgrade-insecure-requests` | Directives are parsed |
| TLS | A grade "A" shown when SSL Labs timed out | No grade is shown |
| DNS | IPv6 ranges counted as SPF lookups; DKIM checked against `co.uk` | Whole terms only; small public-suffix helper; DKIM hedged |
| Other | JSON-LD "internal hostname" on version strings, source maps without `sourcesContent`, AI SDK default base URLs, deleted cookies | Parsed or downgraded |

### Narrowed on purpose (a real problem in these shapes can now be missed)

- An access-control or anonymous-read app that renders the same record for any id, including a
  made-up one, is suppressed.
- An unauthenticated DELETE that answers 404 for a missing id is no longer reported; only
  idempotent-delete style success counts.
- Inner-route `.env` mixed with non-`KEY=VALUE` lines, `config.json` without credential-shaped keys, and a
  debug log with fewer than two log-shaped lines are missed.
- A bucket whose first 100 objects are all static assets reads as Info even if a sensitive file
  sits further in.

### Not verified, or still open

- Whether PostgREST validates columns before row-level security. An ambiguous 400 to the write probe is
  now an Info note, not Critical.
- The unclaimed-page texts for Vercel, Ghost, Tumblr, Readme, Heroku and GitHub Pages were written
  from memory of each provider's page, not fetched. The Resend key format likewise.
- There is no version floor for CVE-2026-42533 (nginx) or CVE-2026-34356 (Apache) in the repo, and
  none was invented. nginx 1.29.8 still matches CVE-2026-42533 at hedged Medium until the real ranges are added.
- The Google Analytics, jQuery, Lodash, Alpine and HTMX technology rules still match loosely.
- The 30-day certificate-expiry alert cannot tell a Let's Encrypt certificate about to auto-renew;
  the monitor stores only the expiry date. Not changed.
- A session cookie missing `SameSite` stays Medium: Firefox and Safari do not reliably default to Lax.

## 2026-09-24 — 30-site re-sweep, and a false positive on amazon.co.uk

Re-ran the Sept 8 thirty-site list on the current scanner, to replace a published
snapshot that predated several fixes. Every one of the 16 high findings was then checked
by hand against the live site (browser and plain user agent, DNS over Cloudflare DoH);
the 82 medium and low findings were **not** re-checked this round.

**Sixteen of the 17 highs the first pass returned were true. One finding set was false:
amazon.co.uk, five findings including one of the highs, about a page Amazon never published.**

### Fixed

| Finding | Target | Why it was wrong |
|---|---|---|
| `Missing Content-Security-Policy` (HIGH) plus four smaller header findings | amazon.co.uk | The scan recorded HTTP 200, `server: AkamaiGHost`, no structured data and no Open Graph tags: the shape of an interstitial. Amazon serves non-browser clients either a 2 KB Akamai Bot Manager page (proof-of-work posted to `/_sec/verify?provider=interstitial`, reloads with a `bm-verify` token) or a 4 KB "Continue shopping" robot check whose form posts to `/errors_page/validateCaptcha`. `detectChallengePage` recognised neither: its Akamai signal only matched Akamai's *error* host, and the robot check's title is just "Amazon.co.uk". Both are now matched on fingerprints that only those pages carry, with five regression tests, two of which make sure a real page that merely mentions the words, or links to the endpoint from a large document, is left alone. amazon.co.uk went from 12 findings to 2 and is ungraded. Amazon also answers with the AWS WAF `x-amzn-waf-action: challenge` form, which was already covered, so which variant a given run hits varies. |
| Technology "Ghost" on every Akamai-fronted site | amazon.co.uk | `/ghost/i.test(server)` matched `AkamaiGHost`. Technology names feed the CVE monitor's keyword list, so any monitored Akamai site could have been sent Ghost CMS advisories. Now word-bounded, with a test that `AkamaiGHost` is not Ghost and a bare `Ghost` still is. |

The first pass of the sweep is what made both visible: an interstitial detector proven on
Cloudflare, DataDome and one AWS WAF variant had never seen Amazon's other two.

### Checked and correct — 2026-09-24 round

| Finding | Target | Verified |
|---|---|---|
| `Missing Content-Security-Policy` (HIGH) | european-union.europa.eu, fastly.com, gitlab.com, nasa.gov, shopify.com, slack.com, wikipedia.org, zoom.us | Real. HTTP 200 on both user agents, no CSP header. |
| `CSP Missing on N Internal Routes` (HIGH) | bbc.co.uk, cloudflare.com, github.com, vercel.com | Real. Root sends a CSP; the routes re-fetched (two or three each) return 200 with none. cloudflare's `/de-de/` answered 403 to the check and was not counted. |
| `JavaScript Source Map Exposed` (HIGH) | fastly.com, gitlab.com, archive.org | Real. HTTP 200, 126, 301 and 3 source files with content included. archive.org's is a vendored `lit` polyfill, so the exposure is a public library; HIGH is arguably too much, as recorded on 2026-09-08. |
| `Missing DMARC Record` (HIGH) | european-union.europa.eu | Real. `_dmarc.european-union.europa.eu` and `_dmarc.europa.eu` both NXDOMAIN; `europa.eu` publishes MX. Absent from the Sept 8 snapshot for a reason not established here. |

Confirms two earlier fixes held: `Permissive crossdomain.xml Policy` (theguardian.com) and
the exposed OpenAPI spec (cloudflare, vercel) no longer appear at Medium.

`live-scan.ts` on the four guarded sites after the change: google 15/6, github 11/5,
mozilla 7/3, cloudflare 8/3. cloudflare's recorded baseline was 8/4; the difference is the
OpenAPI reclassification to Info on 2026-09-12, not a regression.

### Note on `render-scan-report.mjs`

Its header stated "Every actionable finding here was verified by hand" on every run,
including runs where nobody had looked. It now prints what the caller passes with
`--verified "..."`, defaulting to "none has been individually checked by hand", and no
longer says every finding can be reproduced with `curl` (some sites answer a scanner and a
browser differently, as reddit does).

## 2026-09-19 — full sweep, and the reddit CSP question answered

Ahead of the deploy, and the first round to cover the active probes as well as the
passive ones. Three sources of evidence: the 20-target passive corpus, `--active`
against both owned domains, and the local fixture whose faults are known exactly.

**80 actionable findings across 20 passive targets, eight HIGH, every one true.
Four more across two active targets, all true. No false positive was found in any
of the three.** The changes below are hardening, not corrections: two close shapes
that produce a disputable finding, and one fixes a severity that asserted more than
the check can know. All 19 planted flaws still detected afterwards.

### The reddit CSP finding — resolved, and it is real

`Content-Security-Policy Missing on N Internal Routes` on reddit was recorded on
2026-09-10 as **"Did not reproduce… Cause unknown. Left alone… Re-check on the
next round."** This is that re-check.

Four repeats of seven paths through the scanner's own fetch layer:

```
/               200 csp=161b | csp=161b | csp=161b | csp=161b
/wp-admin       200 csp=161b | csp=161b | csp=161b | csp=161b
/administrator  200 csp=161b | csp=161b | csp=ABSENT | csp=ABSENT
/graphql        200 csp=ABSENT | csp=161b | csp=161b | csp=161b
/api            200 csp=161b | csp=161b | csp=161b | csp=ABSENT
/live           200 csp=ABSENT | csp=ABSENT | csp=ABSENT | csp=ABSENT
```

reddit's edge emits the header on some responses and not others, on the same path,
seconds apart, through one UA. So the 2026-09-10 conclusion — a degraded response
on the night — was half right: the flapping is real, but it is a standing property
of the target, not that evening's weather. The check was reporting what the server
actually sent, and `/live` is consistently absent exactly as that round found.

A header present on half of responses protects half of them, so this is a true
finding. It is also, in its single-observation form, the kind nobody can reproduce
— which this audit records repeatedly as the worst thing to ship.

**Do not "fix" this check.** `curl` is not a valid way to check it: reddit answers
a plain curl UA with `403 Blocked` on these paths, which looks like a catch-all
bug and is not one. Use the scanner's own fetch layer, several times.

### Fixed

| Finding | Target | Why it was wrong |
|---|---|---|
| Header-gap findings rested on one observation | www.reddit.com | A gap reported at up to HIGH was recorded from a single response. Against a flapping origin that yields a finding the customer disproves by hand on their first retry. `confirmHeaderGaps` now re-fetches every candidate path and keeps only gaps still there on the second look. reddit went 13 routes → 6; the genuinely-absent routes are untouched — github's `/healthz`, cloudflare's nine locale paths, vercel's eight and bbc's three all still report. Confirmation can only remove a gap, never add one, and an unconfirmable gap (budget spent, network error, error status) keeps the original observation rather than trading this false positive for a silent false negative. |
| `Insecure Deserialization Exposure` markers were not anchored | none yet — latent | The comment above `MARKERS` claimed they were "anchored to each format's magic bytes, not loose base64". Three were not. `BAh` and `gA[JNQU]` are three characters, so unanchored they match anywhere inside any long base64 cookie, and a HIGH CWE-502 accusation then rests on a coincidence. reddit's `loid` cookie carries a Fernet token whose base64 decodes to `gAAAAAB` — one character off the pickle marker, mid-value. Magic bytes only mean anything at the start of a value, so the three base64 markers now require a non-base64 boundary, and the evidence quotes the magic rather than the boundary character it consumed. Corpus fired this zero times before and after. |
| `Dangerous HTTP Methods Advertised` was HIGH / CVSS 7.5 | none in corpus — see basis | An `Allow` header says a method EXISTS at a path, never that authorization does not guard it. The finding's own description conceded this ("if not properly guarded by application-level authorization") while scoring 7.5, so every REST API that correctly implements guarded `PUT`/`DELETE` was handed a HIGH for being well-formed — the same error as crossdomain.xml, the OpenAPI spec and the rate-limit check. Confirming it would mean sending an unauthenticated `PUT`/`DELETE` at a stranger's server, which this scanner does not do, so the honest output is the observation plus what to check. Now `Write HTTP Methods Advertised`, MEDIUM / 5.3. **Basis is weaker than the rest of this table:** no corpus target advertises a write method (only dropbox sends `Allow` at all — `GET, HEAD, POST`), so this is calibration from the code and from precedent in this document, not from a reproduction. |

### Checked and correct — 2026-09-19 round

Every HIGH in the corpus, hand-verified. Root vs route compared with the same UA.

| Finding | Target | Verified |
|---|---|---|
| `CSP Missing on 8 Internal Routes` | vercel.com | Real, and new to this document. Root sends a CSP; `/home` and `/ai-sdk` send none. The same eight routes also lack XFO, X-Content-Type-Options and Referrer-Policy, which is what a differently-configured edge looks like rather than a scanner artefact. |
| `CSP Missing on 3 Internal Routes` | www.bbc.co.uk | Real. Root sends a CSP; `/sounds` and `/accessibility/` send none. |
| `Missing Content-Security-Policy` | www.netlify.com, www.wikipedia.org, www.microsoft.com | Real. All three send zero CSP headers on the root. |
| `CSP Missing on 1 Internal Route` (`/healthz`) | github.com | Unchanged from 2026-09-07, and survives the new confirmation pass. |
| `CSP Missing on 9 Internal Routes` | www.cloudflare.com | Unchanged from 2026-09-12, and survives the confirmation pass. |

Counts match the baselines this document already recorded, which is the evidence
that nothing regressed: github 11/5, stackoverflow 3/0, etsy 4/1, nytimes 3/0,
npmjs 2/0. google is 15/6 against a recorded 13/6 — the two added findings are
from probes shipped on 2026-09-15, not a regression.

### The active half, 2026-09-19 — also clean

The passive corpus reports "Active security testing was skipped" on 20 of 20
targets, so every previous round in this document verified only half the engine.
The noisiest detectors in any scanner — injection, path traversal, API auth and
access control — had never been swept for false positives at all.

`--active` against both allowlisted owned domains. **secscan.us: 4 findings,
3 actionable. seclayer.app: 2 findings, 1 actionable. Zero false positives.**
Every one checked by hand:

| Finding | Target | Verified |
|---|---|---|
| `API Endpoints Without Rate Limiting` (MEDIUM) | secscan.us | Real. `GET /api/auth/user` answered 15 of 15 rapid requests with 200 and never a 429. Note this check EARNS its severity where the old passive one did not: it sends the requests and reports what came back, rather than reading a header's absence as an answer. |
| `DMARC Policy Set to None` (MEDIUM) | secscan.us, seclayer.app | Real. `_dmarc.secscan.us` is `v=DMARC1; p=none; rua=…; fo=1`, confirmed against Cloudflare DoH independently of the scanner. Monitoring only, no enforcement. |
| `CSP Allows Inline Styles` (LOW) | secscan.us | Real. The live header carries `style-src 'self' 'unsafe-inline'`. |
| `DNSSEC Not Enabled` (INFO) | secscan.us | Real. Zero DNSKEY answers, NOERROR. |

**The injection, path-traversal, IDOR, BFLA and mass-assignment probes returned
nothing against either app.** That is the result worth having from this round: the
detectors most likely to cry wolf stayed silent on two real applications.

The rate-limit finding is also the round's evidence that the check discriminates
rather than accusing everything. It did NOT fire on seclayer.app — because
`/api/auth/user` is a 404 there, so the API surface discovery found no endpoint to
test. Fires where there is something to test, silent where there is not.

Still unexercised after this round: **SSRF and the out-of-band collector.**
`live-scan.ts` calls `runScan` with `scanId` null, and SSRF detection is skipped
when that and a callback host are both absent (scanner.ts). Nothing in any round of
this document has ever tested it.

### Ground truth, from the fixture

`detection-check.ts` plants 19 flaws and asks only whether each was found. It
returns **34** findings and has never looked at the other fifteen — which, on a
target whose faults are known exactly, is the strongest false-positive evidence
available anywhere in this repo. Run with `--list` it prints them.

Checked: `Nginx 1.14.0 — CVE-2021-23017` and `PHP 5.6.40 is End-of-Life` are both
true of what the fixture serves, which incidentally verifies CVE and EOL matching
against known input for the first time. The INFO remainder (COOP/COEP/CORP,
security.txt, structured data, Open Graph) carries zero weight.

(As checked on the date above. `NGINX_VULN_RANGES` was reviewed 2026-09-21 and
now reports nginx 1.14.0 against a newer CVE, CVE-2026-42533, whose fix-version
threshold is higher and is checked first — the finding still fires on the same
input, this is a record of which specific CVE ID it named that day, not a
current claim.)

**One thing to weigh, not a false positive:** a single planted hardcoded JWT
produces three separate HIGH findings — `Hardcoded JWT Token in Source`,
`JWT Token Has No Expiry` and `JWT Uses HS256 Without Expiry`. That is 45 risk
points and a two-grade move from one defect, and the last two overlap almost
entirely, both being about the missing `exp`. Each statement is true; whether one
token should be three HIGHs is a granularity decision, so it is recorded here
rather than changed.

### Not a false positive — found while generating this round's raw output

**Inner-page cookie findings were quoting the cookie's VALUE in their evidence.**
Not a detection error, so it does not belong in the table above, but it was found
by reading this round's `--json` output and it is the more serious defect.

`SCAN-RESULTS.md` states that `Set-Cookie` values in the committed runs "are
replaced with `<redacted>`; names and flags are untouched, which is all the cookie
findings are derived from." The committed 2026-09-10 file does show
`fid=<redacted>`, `loid=<redacted>` — but nothing in the repository performed that
redaction, so it had been done by hand, and this round's fresh output carried real
`fid=`, `loid=` and `session_tracker=` values in full.

That matters well beyond these artifacts, because report evidence is durable and
shareable: it is stored in the `reports` table, rendered into the emailed PDF, and
readable by anyone holding a share link — which the privacy page tells people to
treat as public. On a **credentialed** scan the scanner is signed in, so the value
being quoted is a live authenticated session token.

`crawler.ts` was the only path doing it. `scanner.ts` already reports root-page
cookie findings by name alone, and `deserializationProbe.ts` redacts explicitly,
so this was an oversight in one of three sibling paths rather than a decision.
`redactCookieValue` now replaces the value and keeps every attribute, which is the
shape SCAN-RESULTS.md already described. Finding counts are unchanged on reddit
(17/6) and linkedin (16/7) — the flags the findings read are all still there.

The claim in SCAN-RESULTS.md is now true by construction rather than by hand.

### Open

`scanner.ts` swallows sixteen probe families into `[]` on failure with no log and
no report annotation, so a crashed probe family is indistinguishable from a clean
result. That is the false-negative mirror of everything in this document and is
not addressed here.

`External Resources Missing Subresource Integrity` (MEDIUM) fires on 9 of 20
targets and treats any `hostname !== baseHost` as third-party, so a site's own CDN
subdomain — `static.licdn.com` on linkedin.com — is judged identically to a
stranger's script, while the compliance mapping it carries (ASVS V10.3.2) is
explicitly about *third-party* scripts. Separating the two needs a public-suffix
list; deriving a registrable domain by hand is what `toEmailDomain` did, and this
document records deleting it for exactly that. Left alone deliberately.

## 2026-09-12 — pre-marketing FP sweep

Swept the corpus again ahead of positioning both products on a no-false-positives
claim. Two actionable findings were false; both are the same underlying error the
audit keeps recording — **reading the presence of a response as the meaning of
the response** — and both are now fixed and re-verified against the live targets.

### Fixed

| Finding | Target | Why it was wrong |
|---|---|---|
| `Permissive crossdomain.xml Policy` (MEDIUM, CVSS 6.5) | www.nytimes.com | Fired on `<site-control permitted-cross-domain-policies="all">` while the finding's own description claims "access from all domains (*)". nytimes has NO bare `domain="*"` — every `allow-access-from` is scoped to `*.nytimes.com`. `permitted-cross-domain-policies="all"` is a META-policy (it governs whether sub-path policy files may exist), it is Flash's own default when the element is absent, and with Flash EOL since 2020 it warrants no medium CORS finding. The check now fires ONLY on a genuine `domain="*"`. |
| `Exposed API Documentation — OpenAPI JSON spec` (MEDIUM, CVSS 5.3) | vercel.com, www.cloudflare.com, www.netlify.com | The evidence ("spec structure validated") only confirmed the spec was real, never that exposing it was a mistake. Publishing an OpenAPI spec is mainstream intentional practice — Cloudflare's is literally titled "Cloudflare Public Site API", Vercel's is their 10 MB public API doc — and the endpoints it documents still enforce their own auth, so the spec describes the surface rather than opening it. Reclassified: a spec file is now **INFO** ("confirm this is intended; if it's an internal/admin API, remove it"), an interactive "Try It Out" UI is **LOW**. |

### Checked and correct — 2026-09-12 round

| Finding | Target | Verified |
|---|---|---|
| `Content-Security-Policy Missing on 1 Internal Route` — `/healthz` (HIGH) | github.com | Real. `/healthz` returns `text/html` with no CSP while the root serves `default-src 'none'; base-uri 'self'`. An HTML endpoint missing the policy the rest of the site enforces. |
| `Content-Security-Policy Missing on 9 Internal Routes` — locale paths (HIGH) | www.cloudflare.com | Real. Root serves `default-src 'self'`; `/es-es/`, `/fr-fr/` and the other locale routes carry no CSP header at all. Verified per-path against the live response. |
| `Session Cookie Missing HttpOnly Flag` — `JSESSIONID` (MEDIUM) | www.linkedin.com | Real. Live `Set-Cookie` is `JSESSIONID=…; SameSite=None; Path=/; Domain=.www.linkedin.com; Secure` — no `HttpOnly`. A session-shaped cookie readable by JS, correctly reported. |

**The crossdomain fix is the same lesson as the PayPal `frame-ancestors` fix and
the GOV.UK SPF fix: an evidence string that points somewhere the target does not
match does not merely fail to support the finding — it argues against it.** Here
the description asserted "access from all domains" against a site that allows
none.

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
