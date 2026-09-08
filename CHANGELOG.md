# Changelog

Notable changes to the SecScan engine. Commit messages carry the full reasoning
for each change; this collects what shipped and why it mattered.

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
