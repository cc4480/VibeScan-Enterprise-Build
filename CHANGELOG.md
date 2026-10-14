# Changelog

Notable changes to the SecScan engine. Commit messages carry the full reasoning
for each change; this collects what shipped and why it mattered.

## 2026-10-14

### Performance

- **No part of the app blurs what is behind it, and long reports paint far less.** A background blur makes the browser
  re-blur everything under it as you scroll, and a report with many of them can flicker or leave sections blank on some
  graphics setups (every card and panel blinked on one). Cards, panels, the header, the mobile menu and the feedback
  button are now solid, a little more opaque to keep the look, and the page background is its own layer. Long lists are
  drawn a page at a time: a group shows its first 25 findings with "Show 25 more" and "Show all N", the report's
  side card lists the 12 most severe findings and says how many more there are, and off-screen finding cards are not
  painted. Measured on a 150-finding report: blurred layers 6 to 0, page height 14,000 px to 3,900 px, cards drawn 151 to 26.

- **Public-repository scans no longer share GitHub's 60-calls-an-hour limit.** Reading a public repository sent no
  credentials, so every user's scans together were limited to 60 GitHub API calls an hour for the server's address (about
  thirty scans). An optional `GITHUB_PUBLIC_API_TOKEN` (a read-only token for public repositories) raises that to 5,000. It
  goes only to api.github.com, never to the file host, and a repository that is private is still refused.

- **A first visit downloads half as much.** Every page used to ship in one 1.38 MB script (399 kB compressed), so the
  landing page paid for the dashboard, report viewer and settings too. The signed-in pages now load when first opened:
  the main file is 636 kB (201 kB compressed) and the landing page loads that one script alone. The public pages stay in
  the main file, so they are still prerendered and paint at once. A tab left open across a deploy, which would ask for a
  file that no longer exists, reloads once by itself instead of showing an error. Two billing files that re-exported each
  other across chunks (a build warning about load order) now import directly.

### Reports

- **A repository-only scan gives a fix prompt.** It is built from the findings themselves, with no AI call, so it
  costs nothing beyond the scan. It speaks of the repository (not a web app), lists the files each finding is in, merges
  the one-per-file findings of a rule into one entry, puts information-only findings under "lower priority", asks the tool
  to check whether a value in a test file is real before changing it, and never includes a matched value. The report
  page shows it as the "Fix with your AI coding tool" card (and the MCP report includes it); the "AI Analysis" card is
  not shown for a repository scan, since nothing there was written by AI.

- **A long list of findings no longer shows blank gaps or flickers.** Each finding card was a blurred "glass" layer that
  also faded in from invisible. On a report with dozens of findings that meant dozens of blurred layers, which can make
  a browser stop painting part of the page or flicker when it is clicked, and cards that start invisible stay blank in a
  tab that is not showing (animations pause there). Finding cards are now flat (no background blur), only the first
  eight fade in, and a group of more than eight information-only findings starts closed (one click opens it).

- **The live scan terminal shows what a repository scan is doing, with real numbers.** A repository read (alone, or
  added to a website scan) now reports its steps as they happen: the file listing ("624 files found, 544 to read, left
  alone: 4 binary files, 76 in vendored or fixture folders"), the reading in about ten stages ("300 of 544 read, 2.1 MB"),
  then each of the five checks with its file and finding counts, or "not run: no matching files" when it had nothing to
  look at. The steps are for the display only and are not added to the report's list of tests. A repository-only scan names
  the repository, uses repository wording and totals (not the website catalogue of checks), and its closing line counts
  only its own steps. The report cover no longer shows the website-only "Also detected" box for a repository scan, and its
  "grade includes N heuristic findings" notice counts only findings that carry weight (information findings do not).

- **Scan a GitHub repository on its own, with no website.** The scan page has a "GitHub repository only" choice
  (a private repository works through the connected GitHub App, as before). A repository address where the website
  goes is read as a repository-only scan: it spends one scan, counts against the same daily limit and queue, and skips
  every site step (page fetch, TLS, reconnaissance, probes, browser). The report is the Source code section, a grade and
  a summary that says it did not test a running site; the website-only parts (OWASP panel, pages scanned, tech profile,
  monitoring offer) are left out. A repository that cannot be read (private and not shared, or missing) fails the scan
  and gives the scan back instead of reporting nothing. No database change: such a scan is the one whose address and
  repository are the same github.com/owner/repo URL.

- **The repository scan reads every text file, with no limit on repository size.** It used to open only five kinds of
  file (config and env files, SQL migrations, CI files, npm manifests, JS/TS source) and stopped at 300 files and 160
  source files, so a 624-file repository was 168 files read. Now every text file is read and checked for secrets
  whatever its language (Python, Go, Markdown, scripts, tests); only binary files (images, fonts, archives),
  lockfiles (read for dependencies only) and vendored folders such as node_modules are left out. There is no file
  count or total-bytes cap; one file over 10 MB is listed as skipped. Memory stays flat on any size: files are read
  in batches of 100, the per-file checks run and release each batch, and only migrations, CI files and manifests are
  kept for the checks that need them side by side. A repository whose file list GitHub cuts off at 100,000 entries is
  walked folder by folder instead. The dependency check no longer stops at 150 packages (ceiling 5,000), looks up 12 at a
  time, and reads every package-lock.json in the repository instead of the first.

- **Fewer false positives now that every file is read.** Reading all files turned a security tool's own test fixtures
  into four "critical" findings and a grade of F. A secret-shaped value in a test, mock, example or docs file is now
  shown as information under its own name ("in a test or example file"), as is one whose surrounding code calls it
  forged, fake, dummy, a fixture, an example or a probe. The config-secret reader, built for config files, no longer
  reports a shell command (`$(openssl rand -hex 32)`), a function call or an environment read (`clean(process.env.X)`)
  as a value, and in source files it accepts only quoted literals. The Source code section now says how many files were
  left alone on purpose (binary files, vendored and fixture folders), so "read 544 of 624" explains itself.

- **A "Source code" section in the report when a repository was scanned.** The repository scan always ran its
  five checks, but the saved report kept only "ran, 0 findings", so a clean repository left no trace of what
  was read. The test record now keeps the repository, how it was read (public, or through the GitHub App),
  files read of files in the repository, what was left out by the limits, and each check's file and finding
  counts. The report page, shared report, PDF/print, copied Markdown and the MCP report text all show it,
  including the findings read from the repository and a plain "not read" message when a private repository
  could not be opened. Reports from before this say the check ran but what it read was not recorded.
- The "private or missing repository" message no longer says only public repositories can be read; it says to
  connect GitHub and choose the repository.

### GitHub connection

- **Connect GitHub now starts by asking GitHub who you are, then installs only if nothing is found.** Someone who
  had already installed the App was sent to GitHub's settings page with no way back to SecScan, so nothing was
  connected. The trip is now authorise, then (only if no installation exists) the install page, then authorise
  and list again; a second empty answer is "none", not another trip. "Add or change repositories" goes straight
  to GitHub's repository chooser (`/api/github/connect?manage=1`). Needs `https://secscan.us/api/github/callback`
  among the App's Callback URLs.
- Installations and repositories are read across all pages (up to 1,000), not just the first 100.
- Each connection reports how it stands (`ok`, `gone` when the App was uninstalled, `unavailable` when GitHub
  could not be asked) and the scan form says which, instead of showing an empty list for all three.

### SEO

- **Public pages are prerendered for crawlers that run no JavaScript.** Home, `/learn`, `/about`, `/bot`,
  `/privacy` and `/terms` were an empty `<div id="root">` until React ran, which is all most AI crawlers
  ever saw. The Docker build now renders them in headless Chromium (`scripts/prerender-public.mjs`) and
  the server places each page's markup in the root container. `/learn` also gets every check written out
  in its `<noscript>` block. The step is best-effort: if the browser cannot be installed or a page fails
  to render, that page is served as before and the build still succeeds.
- **Every documented check has its own page** at `/learn/<id>` (19 of them, e.g. `/learn/hsts`). Each opens
  with the plain answer, has its own title, description, canonical, breadcrumb, TechArticle and a two-question
  FAQ in the structured data, is prerendered like the pages above, and is in the sitemap. The build writes
  the list of valid ids (`prerender/checks.json`); the server answers 404 for any other `/learn/<id>`.
- **`/llms-full.txt`**: the full text of every check in one Markdown file for language models, built from the
  same data as the page and linked from `llms.txt`.
- `/learn` carries TechArticle markup with the date it was last reviewed (a test keeps it equal to the date
  the page shows).
- The homepage meta description is 155 characters (was 204), and `/oauth/` and `/feedback` are in the
  `robots.txt` Disallow list.

## 2026-10-13

### Security

- **Connections are pinned for webhooks, domain verification and monitor pulses.** The SSRF check
  resolved a hostname and `fetch` then resolved it again, so a DNS-rebinding record could pass the
  check and be connected to. Webhooks and domain verification now connect through `strictDispatcher`
  (private addresses refused at connect time, even with `ALLOW_PRIVATE_SCAN_TARGETS`); the pulse uses
  the scanner's dispatcher.
- **Free scans and the daily limit hold under concurrent requests.** Both were counted from scan rows
  written later, so parallel requests all passed. They are now checked under a per-user lock at insert.
  A deleted account's free scans used that month are remembered (a keyed hash of the email, purged after
  the month) so signing up again does not reset them. Migration 0030.
- **Deleting an account needs an emailed code**, not only a session, and runs in one transaction.
- **Sign-in:** an account is locked for 15 minutes after 10 failed passwords from any addresses.
- **Emails escape dynamic values** (alert emails and the account heading).
- **`ENCRYPTION_KEY_PREVIOUS`** lets the encryption key be rotated without losing stored logins.
- Smaller: report, share and badge routes answer 404 for a malformed or foreign id; `GET /logout` ignores
  cross-site requests; the Postgres pool handles idle-client errors; public share and badge reads are
  rate limited; `GET /scans` returns the newest 200 (`?limit=` up to 500); checkout return URLs always
  use `APP_ORIGIN`.

### Changed

- **Dependency advisories cleared.** `vite`, `vitest`, `esbuild` (the override pinned 0.27.3) and the
  transitive `postcss`, `nanoid`, `lodash`, `browserslist`, `@babel/core`, `source-map-js` and
  `postcss-selector-parser` are on patched versions. `pnpm audit` went from 24 advisories to 1
  (`braces` under the dev-only proxy, no patched release exists). The duplicate `drizzle-orm` copies are
  gone, so the type check is clean again.
- **One universal fix prompt for every AI coding tool.** The report's fix prompt used to be
  written differently for each detected platform (Lovable, Bolt, Next.js for "Cursor or Claude
  Code", WordPress and so on), and the report page wrapped it again per tool, one wrapper telling
  Claude Code to use a `/edit` command that does not exist. A report cannot know which assistant
  its reader pastes into, and the reader may use several (Claude Code, Cursor, Codex, GitHub
  Copilot, Windsurf, Grok Build, Gemini, ChatGPT, Lovable, Bolt, Replit, v0). The prompt now names
  no tool and uses none of a tool's commands, @-mentions or modes. Each finding has Problem, Fix,
  Where to look and Check; a secret comes first with a rotate instruction; the close asks for a
  list of changes, what could not be fixed, and a build or test run. What the scan detects about the
  stack is kept, but only as short STACK NOTES (where fixes live on that platform), the same facts
  as before. The report card shows one prompt with one Copy button and no tool picker. The
  template fallback and the MCP report text say the same. `detectedAgent` stays in the API.

## 2026-10-05

### Changed

- **TLS is now checked by the scanner itself; the SSL Labs grade is opt-in.** Audit
  finding #10: the scan called the Qualys SSL Labs API v3 on every scan, but Qualys
  deprecated v3 from 2024-01-01, v4 needs a registered email, and their terms require
  permission for commercial use. Every HTTPS scan now runs a "TLS configuration
  check" (`tlsCheck.ts`, node:tls): which of TLS 1.0 to 1.3 the server accepts, the
  cipher suite it chooses, and its certificate (expiry, hostname, chain trust, key
  size, signature hash). It goes through the same address vetting as the rest of the
  scanner (private targets and rebinding answers are refused) with an 8-second
  timeout per handshake. TLS 1.0/1.1 are best effort: a version the scanner's OpenSSL
  cannot offer is reported as "could not test", never "not supported". It gives no
  letter grade. SSL Labs runs only when `SSLLABS_ENABLED=true`; with it off the report
  has no TLS grade and no failed "SSL Labs" line, where before a scan that SSL Labs
  could not assess listed it as failed.
  New findings: Deprecated TLS Protocol Versions Accepted (medium), TLS Certificate
  Expired / Not Yet Valid / Does Not Match the Hostname, Self-Signed TLS Certificate
  and TLS Certificate Not Trusted (high), TLS Certificate Chain Incomplete, Key Too
  Short, Signed With a Weak Hash and Weak Cipher Suite Negotiated (medium), TLS
  Certificate Expires Soon (under 14 days) and Cipher Suite Without Forward Secrecy
  (low).

## 2026-10-02

### Fixed

- **Takeover signatures and the nginx floor checked against their sources.**
  Fastly, Squarespace and WP Engine are listed "Not vulnerable" by
  can-i-take-over-xyz, so their not-found pages are now reported only as unverified
  candidates (medium, low confidence). Ghost and Readme.io also match the pages that
  list currently shows. CVE-2026-42533 now starts at nginx 0.9.6, as the CVE record
  does, and says a restart is the base impact (code execution needs ASLR off or
  bypassed). Not covered: nginx 1.31.2, which a single ceiling cannot express.
- **Technology, secret and challenge rules checked against public rule sets**
  (webappanalyzer, TruffleHog, wafw00f). `x-amz-request-id` no longer names
  CloudFront (it is AWS in general; `x-amz-cf-id` is CloudFront's). WordPress,
  Joomla, Angular and Google Tag Manager need an asset or attribute, not the words
  in prose. Express and Next.js `X-Powered-By` matches are anchored. Replit,
  Railway, Netlify and Base44 are named from the signals webappanalyzer lists. The
  two-part Resend key must be base58 (8 + 24), as TruffleHog's detector has it.
  Sucuri's block page is recognised by its title or stylesheet, not the product
  name; PerimeterX and Vercel gain the block text and path wafw00f lists.
- **A page that only talks about Next.js is no longer called "this Next.js page".**
  Found in a secscan.us PDF (2026-10-02): the Next.js probe took the words
  "Next.js" in page copy for a Next.js page, so a Vite app got the skip reason
  "this Next.js page has no __NEXT_DATA__ block". It now needs the `__NEXT_DATA__`
  script, a `/_next/static/` asset or the `#__next` element.

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
- **Scan notes listed as confirmed findings.** The scan's own remarks about itself
  ("Active security testing was skipped for this scan", "Scan reached a sign-in page,
  not the app") are recorded as Info findings in the category "Scan Coverage", and every
  report listed them under "Confirmed findings, act on these" and counted them in
  "N confirmed" and "100% high-confidence". They now sit apart under "About this scan"
  on the report, the shared report, the printed report, the PDF and the Markdown copy,
  and the finding counts in their headings and lists leave them out. A scan with notes
  and no findings says "No findings were reported" and points at the notes, not a green
  all-clear. The totals the server computes leave them out too: Total Findings, the
  severity counts under the grade, the shared report's footer and the executive summary
  (for scans from now on; a saved report keeps the totals stored with it), and the
  report email, the monitor history count, the API scan summary (`scanNotes` carries
  their number) and the MCP report text, which lists the notes apart from the findings.
- **"How this was found" listed no requests for several active tests.** The panel read
  only lines that begin with a method and an address, and the injection, path-traversal
  and LLM tests write `Endpoint: /search?q=<payload>` or `Request: POST https://...`. It
  reads both now, and for an active test whose evidence has no request line it says so
  instead of staying silent.
- **"Which check raised this was not recorded" on findings from a busy test.** A test
  record kept the names of its first 40 findings. The sensitive-file test raises 78 on
  the vuln fixture, so 38 findings (8 of them Critical) showed no check. It keeps up
  to 500.

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
- CI runs the fixture gate: the real scanner, active tests and two accounts included, against
  the vulnerable fixture, and fails the build when a planted finding is missed. It runs in
  about ten seconds on a developer machine and had not run in CI before.
- **A TLS grade below A says why.** A B or A- from SSL Labs came with no reason
  anywhere in the report. A new informational finding, "TLS Grade Below A (SSL Labs)",
  lists what SSL Labs reported (obsolete protocols still accepted, no forward secrecy,
  RC4, known attacks) and links the full SSL Labs report. When SSL Labs names no
  cause, it says so rather than guess. C and below keep their own finding, which now
  carries the same reasons. The check count is now 144.

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
