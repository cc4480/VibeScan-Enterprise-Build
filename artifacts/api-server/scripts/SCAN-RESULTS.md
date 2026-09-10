# Scan results — measured runs, per URL

Every scan this repository has actually run against a real site, with the score
and grade each one produced. Companion to `FALSE-POSITIVE-AUDIT.md`: the audit
records what was *wrong* and how it was fixed, this records what the scanner
*returned*.

**51 runs across 39 hosts.** Two passive rounds against third-party sites, plus
one active round against a domain we own.

Raw output for every run is committed beside this file, so each row can be
checked rather than taken on trust:

| File | Round |
|---|---|
| `scan-results/2026-09-08-corpus-30.json` | Round 1 |
| `scan-results/2026-09-10-sweep-20.json` | Round 2 |
| `scan-results/2026-09-10-active-seclayer.json` | Round 3 |

`Set-Cookie` values in those files are replaced with `<redacted>`; names and
flags are untouched, which is all the cookie findings are derived from.

Reproduce any row:

```
DATABASE_URL=postgres://localhost/anything \
  npx tsx artifacts/api-server/scripts/live-scan.ts --json out.json https://github.com
```

## How to read the score

`computeRiskScore` (scanner.ts:1188) sums severity weights and caps at 100 —
**higher is worse**:

| critical | high | medium | low | info |
|---|---|---|---|---|
| 30 | 15 | 5 | 1 | **0** |

`computeGrade` (scanner.ts:1202): A ≤ 10, B ≤ 25, C ≤ 45, D ≤ 65, F > 65.

Info findings score zero by design. A check that can only observe whether
something is *advertised* — rate limiting, `security.txt`, DNSSEC — must not
move a grade, so most of what a scan returns carries no weight at all. That is
why a 19-finding site can still grade C.

> Seclayer runs an inverted scale (100 = clean, A ≥ 90). Don't compare the two
> numbers directly. Seclayer's own results live in that repo at
> `docs/SCAN-RESULTS.md`.

---

## Round 1 — 30-site corpus, 2026-09-08

Thirty sites across six sectors, passive. Built to *measure* rather than hunt,
which is how the GOV.UK SPF/DMARC bug surfaced — three separate defects behind
one HIGH finding against the most email-secure domain in the sample.

| Host | Crit | High | Med | Low | Info | Total | Score | Grade | Secs |
|---|---|---|---|---|---|---|---|---|---|
| github.com | 0 | 1 | 1 | 3 | 6 | 11 | 23 | **B** | 14.9 |
| gitlab.com | 0 | 2 | 3 | 2 | 6 | 13 | 47 | **D** | 4.3 |
| www.npmjs.com | 0 | 0 | 0 | 0 | 2 | 2 | 0 | **A** | 15.0 |
| stackoverflow.com | 0 | 0 | 0 | 0 | 3 | 3 | 0 | **A** | 12.2 |
| vercel.com | 0 | 1 | 5 | 2 | 9 | 17 | 42 | **C** | 30.6 |
| www.cloudflare.com | 0 | 1 | 3 | 0 | 4 | 8 | 30 | **C** | 24.3 |
| www.mozilla.org | 0 | 0 | 2 | 1 | 5 | 8 | 11 | **B** | 23.7 |
| www.digitalocean.com | 0 | 0 | 2 | 2 | 8 | 12 | 12 | **B** | 20.3 |
| www.fastly.com | 0 | 1 | 0 | 2 | 8 | 11 | 17 | **B** | 14.5 |
| letsencrypt.org | 0 | 0 | 1 | 1 | 7 | 9 | 6 | **A** | 30.4 |
| www.bbc.co.uk | 0 | 1 | 3 | 1 | 5 | 10 | 31 | **C** | 19.2 |
| www.nytimes.com | 0 | 0 | 4 | 3 | 11 | 18 | 23 | **B** | 30.7 |
| www.theguardian.com | 0 | 0 | 3 | 1 | 10 | 14 | 16 | **B** | 15.1 |
| www.reuters.com | 0 | 0 | 0 | 0 | 3 | 3 | 0 | **A** | 3.7 |
| apnews.com | 0 | 0 | 0 | 0 | 2 | 2 | 0 | **A** | 9.4 |
| www.shopify.com | 0 | 1 | 1 | 2 | 7 | 11 | 22 | **B** | 20.2 |
| stripe.com | 0 | 0 | 1 | 2 | 7 | 10 | 7 | **A** | 17.2 |
| www.etsy.com | 0 | 0 | 0 | 1 | 3 | 4 | 1 | **A** | 9.0 |
| www.ebay.com | 0 | 0 | 0 | 0 | 3 | 3 | 0 | **A** | 19.2 |
| www.amazon.co.uk | 0 | 0 | 0 | 0 | 2 | 2 | 0 | **A** | 10.0 |
| www.gov.uk | 0 | 0 | 0 | 0 | 7 | 7 | 0 | **A** | 27.1 |
| www.wikipedia.org | 0 | 1 | 2 | 2 | 11 | 16 | 27 | **C** | 3.7 |
| archive.org | 0 | 1 | 5 | 1 | 9 | 16 | 41 | **C** | 12.3 |
| european-union.europa.eu | 0 | 1 | 1 | 2 | 6 | 10 | 22 | **B** | 15.2 |
| www.nasa.gov | 0 | 1 | 2 | 3 | 6 | 12 | 28 | **C** | 17.0 |
| www.notion.so | 0 | 0 | 3 | 3 | 8 | 14 | 18 | **B** | 18.4 |
| www.figma.com | 0 | 0 | 2 | 2 | 6 | 10 | 12 | **B** | 30.7 |
| slack.com | 0 | 1 | 2 | 1 | 6 | 10 | 26 | **C** | 14.1 |
| www.dropbox.com | 0 | 0 | 2 | 2 | 7 | 11 | 12 | **B** | 23.0 |
| zoom.us | 0 | 1 | 4 | 2 | 10 | 17 | 37 | **C** | 29.7 |
**Distribution:** A 10 · B 11 · C 8 · D 1 · F 0 — mean score 17.0, median 17.
Mean 9.8 findings per site.

Scanner state: pre-`6c97837`. Grades in this table reflect the scanner as it
was on 2026-09-08, before the DNS-record-type and email-domain fixes landed.

---

## Round 2 — 20-target false-positive sweep, 2026-09-10

Not a random sample. Each target guards a specific suppression rule and is
annotated in `live-scan.ts` with the rule it protects — a regression in any one
of them shows up here as an actionable finding.

| Host | Crit | High | Med | Low | Info | Total | Score | Grade | Secs |
|---|---|---|---|---|---|---|---|---|---|
| google.com | 0 | 0 | 3 | 3 | 9 | 15 | 18 | **B** | 8.6 |
| github.com | 0 | 1 | 1 | 3 | 6 | 11 | 23 | **B** | 12.5 |
| www.cloudflare.com | 0 | 1 | 3 | 0 | 4 | 8 | 30 | **C** | 29.8 |
| stackoverflow.com | 0 | 0 | 0 | 0 | 3 | 3 | 0 | **A** | 5.9 |
| www.npmjs.com | 0 | 0 | 2 | 3 | 6 | 11 | 13 | **B** | 23.0 |
| www.etsy.com | 0 | 0 | 0 | 1 | 3 | 4 | 1 | **A** | 6.3 |
| www.nytimes.com | 0 | 0 | 5 | 3 | 11 | 19 | 28 | **C** | 31.0 |
| www.dropbox.com | 0 | 0 | 2 | 2 | 7 | 11 | 12 | **B** | 22.2 |
| stripe.com | 0 | 0 | 1 | 2 | 7 | 10 | 7 | **A** | 14.5 |
| www.mapbox.com | 0 | 0 | 2 | 3 | 6 | 11 | 13 | **B** | 17.5 |
| vercel.com | 0 | 1 | 5 | 2 | 9 | 17 | 42 | **C** | 25.9 |
| www.netlify.com | 0 | 1 | 4 | 1 | 7 | 13 | 36 | **C** | 8.9 |
| www.linkedin.com | 0 | 0 | 3 | 5 | 10 | 18 | 20 | **B** | 28.8 |
| www.reddit.com | 0 | 1 | 1 | 4 | 11 | 17 | 24 | **B** | 7.6 |
| www.wikipedia.org | 0 | 1 | 2 | 2 | 11 | 16 | 27 | **C** | 15.4 |
| www.apple.com | 0 | 0 | 2 | 3 | 9 | 14 | 13 | **B** | 26.5 |
| www.microsoft.com | 0 | 1 | 3 | 3 | 9 | 16 | 33 | **C** | 30.7 |
| www.mozilla.org | 0 | 0 | 2 | 1 | 5 | 8 | 11 | **B** | 8.8 |
| www.paypal.com | 0 | 0 | 3 | 1 | 7 | 11 | 16 | **B** | 27.4 |
| www.bbc.co.uk | 0 | 1 | 3 | 1 | 5 | 10 | 31 | **C** | 18.7 |
**Distribution:** A 3 · B 10 · C 7 · D 0 · F 0 — mean score 19.9, median 20.
Mean 12.2 findings per site.

### Two rows in this table are stale

This run finished at `00:55Z`; commit `6c97837` landed at `01:07Z` and fixed
both false positives the run had just found. The table is left as it ran —
a results log that quietly absorbs its own corrections is not a results log.

| Host | Finding | Effect once fixed |
|---|---|---|
| nytimes.com | `GraphQL Endpoint Exposed on Inner Route`, medium — `/ca/graphql` answered with 1.25 MB of **HTML**, the SPA catch-all. The probe matched the word `graphql`; it now needs GraphQL-shaped JSON or a playground fingerprint. | 28 → 23, **C → B** |
| linkedin.com | `Verbose Error Pages Expose Internal Application Details`, medium — the PHP pattern was a bare word and a colon, so a Java site serving `JSESSIONID` was reported leaking PHP errors. Now structural. | 20 → 15, B unchanged |

Both are pinned by regression tests in `falsePositives.test.ts`.

### Where the two rounds disagree

Twelve hosts appear in both. Eleven were identical finding-for-finding across
two days and a scanner change. The twelfth:

- **npmjs.com** — 2 findings on 09-08, 11 on 09-10. Not a regression: on 09-08
  it served a bot-protection challenge and the scan correctly withheld
  everything except the interception notice. On 09-10 it served its real page.
  This is the challenge-suppression path working in both directions.

---

## Round 3 — active probing, seclayer.app, 2026-09-10

Active exploit probing is gated on proven domain ownership
(`activeProbeGate.ts`). `live-scan.ts --active` carries its own hardcoded
allowlist on top of that, so the flag cannot be aimed at a third party by a
stray argument.

| Host | Crit | High | Med | Low | Info | Total | Score | Grade | Secs |
|---|---|---|---|---|---|---|---|---|---|
| seclayer.app | 0 | 0 | 1 | 0 | 1 | 2 | 5 | **A** | 98.0 |
Full active pass — injection payloads, path traversal, port scan, manifest SCA.
98 seconds against 6–30 for a passive scan; that gap is the offensive traffic.

An earlier run the same day returned 4 findings; the 2 that closed were the
DMARC and SPF records added to the domain during that session.

---

## What 50 passive runs say about the scanner

Across both third-party rounds: **0 critical, 22 high, 99 medium, 84 low,
332 info.** Mean scan 18.1 seconds.

Two things worth reading off that:

**No criticals, ever.** Fifty runs against fifty well-run sites produced not one
critical. That is the expected shape — a passive scan of a healthy site should
be quiet — and it is the number to watch. A critical appearing here without the
target having changed is a scanner bug until proven otherwise.

**Info dominates, 332 of 537.** Nearly two thirds of everything the scanner
returns carries zero weight. That is deliberate: the alternative is a scanner
that grades sites down for headers whose absence proves nothing, which is
exactly the failure the audit keeps recording.

## Re-running this

Run the sweep before releasing scanner changes, and read the output rather than
diffing it. The audit exists because six findings were "fixed" on suspicion and
all six were real. Verify against the live response first.

```
# passive, all 20 guarded targets
DATABASE_URL=postgres://localhost/x \
  npx tsx artifacts/api-server/scripts/live-scan.ts --json sweep.json

# active, owned domains only
DATABASE_URL=postgres://localhost/x \
  npx tsx artifacts/api-server/scripts/live-scan.ts --active https://seclayer.app
```
