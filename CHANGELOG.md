# Changelog

Notable changes to the SecScan engine. Commit messages carry the full reasoning
for each change; this collects what shipped and why it mattered.

## 2026-10-01

Scans of real apps came back looking alike because, in several common setups, the
scanner was not reading the app at all. This release makes it say so, and makes
every report show its work.

### Fixed

- **Hosting-platform and sign-in pages graded as the app** (`platformGate.ts`).
  Vercel Deployment Protection, Cloudflare Access, a redirect to Google, Microsoft,
  Auth0, Clerk, Okta, GitHub or Replit sign-in, and platform "no app running" pages
  (Vercel `x-vercel-error: DEPLOYMENT_*`, Railway fallback, Render, Heroku, GitHub
  Pages) were scanned as if they were the customer's app, so every app behind one
  got the same 11 to 13 findings. They are now withheld like a bot challenge, the
  scan is not graded, and the report names what answered.
- **Browser identified itself under an old name.** The headless browser sent
  `VibeScan-Security-Bot` while every other request and the `/bot` page say
  `SecScan-Security-Bot`, so a site that allowed the documented name challenged the
  browser. It now uses `SCANNER_USER_AGENT`.
- **Headless-only challenges served with HTTP 200** replaced the real page. A
  render that meets a challenge the plain request did not is now set aside with a
  "Browser Rendering Was Not Used" note (the HTTP >= 400 case came with the
  catch-all fixes below). Vercel's Security Checkpoint is recognised as a challenge.
- **Rate-limit burst on session reads.** `GET /api/auth/session` (NextAuth) was
  burst-tested and reported as unthrottled; session, CSRF and logout endpoints are
  no longer treated as sign-in routes.
- **Mass assignment on create endpoints was never checked.** Privilege fields
  declared in a published spec are now read on every endpoint, not only
  read-shaped ones. The vuln fixture now verifies 88 of 88.
- **security.txt evidence on catch-all hosts** says the site answered with its app
  shell instead of implying a file exists.
- Merged from the 2026-10-01 audit branches: catch-all hosts no longer produce the
  BFLA, unauthenticated-API, rate-limit, XML-RPC and VS Code false positives; the XSS
  evidence names the path that reflected; a failed browser render no longer replaces
  the page; GitHub Pages and Rails technology tags need real markers; scan evidence
  keeps 4,000 characters; CI installs Chromium; four secret patterns have real plants.
- **Technology tags from loose matches.** jQuery, Lodash, Alpine.js, HTMX and
  Google Analytics were tagged when their name appeared in page text; they now need
  a script path or an API call that only the library makes.
- **Certificate expiry alert on auto-renewing certificates.** A 90-day certificate
  (Let's Encrypt and other ACME issuers) renews itself at about 30 days left, so the
  30-day warning fired on every cycle for nothing. Certificates of 100 days or less
  now warn at 14 and 7 days only; yearly certificates keep the 30-day warning.
- **Language, theme and consent cookies** (`lang=en`, `NEXT_LOCALE`, `theme`,
  `cookieconsent_status` and similar) are meant to be read by the page and no longer
  draw a "readable by JavaScript" finding. Secure and SameSite still apply.
- **A session cookie without SameSite is Low, not Medium.** Chrome and Edge already
  treat it as SameSite=Lax; the finding now says the gap is Firefox and Safari and
  that it is a missing safety net, not a demonstrated CSRF.

### Added

- **"Withheld from this report"**: every finding the scan produced and did not
  report, with the reason, and what answered instead of the app when something did.
- **"How this was found"** on every finding: the check that raised it, whether it
  only observed or sent test requests, the requests the evidence records, and what
  the confidence number means. The main report now shows the "See it yourself"
  command the shared report already had.
- **"Not tested" instead of "ran, 0 findings"** for checks with nothing to test
  (no JWT, no Next.js data, no Supabase/Firebase config, no bucket, no manifest, no
  scripts), each with the reason.
- A scan whose start page answered an error, or that was redirected to another
  site, says so in the report.
- The PDF download and the printed report carry the withheld list too.
- On a scan where a sign-in wall, platform page or bot challenge answered, the
  "What this scan tested" list no longer says checks "ran" against the app. Every
  check that read that page shows "not tested on the app" with the reason; DNS,
  mail transport, subdomain takeover and GitHub checks, which never read it, stay
  as they were.
- An informational note no longer marks an OWASP category red. A lone "COEP header
  not set" (info) made Security Misconfiguration read "1 flagged" on an A-graded
  report; it now shows as a grey info note and the category is judged by its tests.
- The Supabase RLS probe says "not tested" when the page has no Supabase project.
- CI runs the 114 database tests against a real Postgres instead of skipping them.

## 2026-09-07

Seventeen changes, and the theme of nearly all of them is the same: the scanner
was reporting things that were not true. A false positive costs more than a
missed finding, because it teaches the reader to distrust the whole report — so
most of the day went on finding them, and on building the means to keep finding
them.

### Added

- **Mail transport security** (`mailTls.ts`, 3 findings). Probes port 25 on each
  MX host: does it advertise STARTTLS, and is its certificate valid. SPF and
  DMARC say who *may* send mail as a domain; nothing until now said whether that
  mail is encrypted in transit. A site can score an A on HTTPS while its
  password-reset mail is relayed in cleartext. — `41b8831`
- **Structured data and social metadata** (`structuredData.ts`, 9 findings).
  Schema.org / JSON-LD validation and Open Graph coverage, split by severity:
  internal hostnames leaked through JSON-LD, social assets loaded over `http://`
  from an HTTPS page, and a canonical tag pointing at a domain the operator does
  not own are real exposure. Missing `og:image` and absent `twitter:card` are
  presentation quality and are INFO at weight 0 — a site with no social preview
  must never grade as less secure than one with it, or the grade stops meaning
  security. — `32ab1a7`
- **Bot-protection challenge detection** (`challengePage.ts`). Recognises when an
  edge answered instead of the origin, and says so once, plainly, naming the
  findings that can no longer be trusted. — `32ab1a7`
- **False-positive runner** (`scripts/live-scan.ts`) and
  `scripts/FALSE-POSITIVE-AUDIT.md`. Points the passive scanner at well-secured
  third-party sites, where the correct answer is few findings and zero false
  ones, and records every actionable finding checked by hand. — `5ace8c6`
- **Retest procedure** (`scripts/RETEST.md`). — `93e3de2`, `a536728`
- **CI on every push** (`.github/workflows/ci.yml`), so the test suite stops
  being something you have to remember to run. — `69dc5ad`

### Fixed — false positives

- **`Set-Cookie` mis-parsing invented HttpOnly and Secure failures.** A
  flattened header was re-split on `/\n|,(?=[^;])/`, and the comma inside
  `expires=Tue, 09-Mar-2027` matched — shearing the cookie so every attribute
  after the date became invisible. It hit any cookie whose `expires=` precedes
  its flags, which is most of them. — `df270de`
- **CSP `script-src` wildcard reported HIGH on well-built policies.** The check
  matched any `*` anywhere in the directive, so ordinary allowlist entries
  (`https://*.onetrust.com`) tripped it. Nearly every CSP that loads analytics
  has one. Now only a bare `*` is reported. — `a843b31`
- **The SPA catch-all shell read as an exposed sensitive file.** — `62fe706`
- **Public infrastructure JWTs treated as session credentials.** — `e2fffa2`,
  `0082b12`
- **Technology fingerprinting fired on generic class names and prose.** —
  `2b1365c`
- **Subdomain-takeover and public API-key false positives.** — `83d477a`
- **`Missing security.txt` evidence said "not found" regardless.** The finding
  was correct; the evidence was hardcoded, so anyone verifying saw a file at
  HTTP 200 and concluded the scanner was broken. — `a843b31`

Three more were caught before they ever shipped, by pointing a new detector at
known-good targets before committing it: a STARTTLS failure on cloudflare.com
that fired only on some runs (an MX that completes the TCP handshake then goes
silent was being read as an answer), WAF interstitials attributed to
stackoverflow.com and npmjs.com, and then the interception detector making the
same class of mistake itself on nytimes.com — matching `x-datadome` by presence
when DataDome sets that header on *allowed* traffic.

### Fixed — reliability

- **The scan worker no longer dies when a target mishandles its connection.** —
  `557b308`
- **Three stale claims corrected in the docs and landing page.** — `576922b`

### Verified

Across 15 real sites (google, github, cloudflare, mozilla, stackoverflow, npm,
reddit, amazon.co.uk, bbc, wikipedia, vercel, nytimes, gov.uk, shopify, MDN):
zero findings above INFO on the new checks, both Cloudflare interstitials
caught, every real page left alone. Finding counts on the four audit targets
fell as the false positives came out — google.com 15 → 13, github.com 12 → 11,
cloudflare.com 9 → 8, mozilla.org 8 → 7.

### Known gaps

- `scanner.ts` — 1,154 lines and 31 findings — has no test file of its own.
  Six modules (`storageProbe`, `sourceMaps`, `graphqlProbe`, `baasProbes`,
  `apiDocsProbe`, `recon-data`) carry 24 findings that no test reaches at all,
  because their only importer is `scanner.ts`.
- `41b8831` and `32ab1a7` are not recorded as deployed. The audit's ship log
  ends at `c94fd75`.
