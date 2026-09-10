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

### Seven of these sites were never seen

`*` marks a site that answered with a bot-protection interstitial instead of
its own page. The scanner withholds every finding read from such a response, so
those rows show two or three findings and nothing actionable.

**That is suppressed coverage, not a clean result**, and it is why those rows
carry no score and no grade. Scoring them would have produced seven A grades
meaning "we never got in" — indistinguishable, on the page, from seven A grades
meaning "this site is well configured". Their counts are not comparable with the
rest of the table.

| Host | Crit | High | Med | Low | Info | Total | Score | Grade | Secs |
|---|---|---|---|---|---|---|---|---|---|
| github.com | 0 | 1 | 1 | 3 | 6 | 11 | 23 | **B** | 14.9 |
| gitlab.com | 0 | 2 | 3 | 2 | 6 | 13 | 47 | **D** | 4.3 |
| npmjs.com * | 0 | 0 | 0 | 0 | 2 | 2 | — | — | 15.0 |
| stackoverflow.com * | 0 | 0 | 0 | 0 | 3 | 3 | — | — | 12.2 |
| vercel.com | 0 | 1 | 5 | 2 | 9 | 17 | 42 | **C** | 30.6 |
| cloudflare.com | 0 | 1 | 3 | 0 | 4 | 8 | 30 | **C** | 24.3 |
| mozilla.org | 0 | 0 | 2 | 1 | 5 | 8 | 11 | **B** | 23.7 |
| digitalocean.com | 0 | 0 | 2 | 2 | 8 | 12 | 12 | **B** | 20.3 |
| fastly.com | 0 | 1 | 0 | 2 | 8 | 11 | 17 | **B** | 14.5 |
| letsencrypt.org | 0 | 0 | 1 | 1 | 7 | 9 | 6 | **A** | 30.4 |
| bbc.co.uk | 0 | 1 | 3 | 1 | 5 | 10 | 31 | **C** | 19.2 |
| nytimes.com | 0 | 0 | 4 | 3 | 11 | 18 | 23 | **B** | 30.7 |
| theguardian.com | 0 | 0 | 3 | 1 | 10 | 14 | 16 | **B** | 15.1 |
| reuters.com * | 0 | 0 | 0 | 0 | 3 | 3 | — | — | 3.7 |
| apnews.com * | 0 | 0 | 0 | 0 | 2 | 2 | — | — | 9.4 |
| shopify.com | 0 | 1 | 1 | 2 | 7 | 11 | 22 | **B** | 20.2 |
| stripe.com | 0 | 0 | 1 | 2 | 7 | 10 | 7 | **A** | 17.2 |
| etsy.com * | 0 | 0 | 0 | 1 | 3 | 4 | — | — | 9.0 |
| ebay.com * | 0 | 0 | 0 | 0 | 3 | 3 | — | — | 19.2 |
| amazon.co.uk * | 0 | 0 | 0 | 0 | 2 | 2 | — | — | 10.0 |
| gov.uk | 0 | 0 | 0 | 0 | 7 | 7 | 0 | **A** | 27.1 |
| wikipedia.org | 0 | 1 | 2 | 2 | 11 | 16 | 27 | **C** | 3.7 |
| archive.org | 0 | 1 | 5 | 1 | 9 | 16 | 41 | **C** | 12.3 |
| european-union.europa.eu | 0 | 1 | 1 | 2 | 6 | 10 | 22 | **B** | 15.2 |
| nasa.gov | 0 | 1 | 2 | 3 | 6 | 12 | 28 | **C** | 17.0 |
| notion.so | 0 | 0 | 3 | 3 | 8 | 14 | 18 | **B** | 18.4 |
| figma.com | 0 | 0 | 2 | 2 | 6 | 10 | 12 | **B** | 30.7 |
| slack.com | 0 | 1 | 2 | 1 | 6 | 10 | 26 | **C** | 14.1 |
| dropbox.com | 0 | 0 | 2 | 2 | 7 | 11 | 12 | **B** | 23.0 |
| zoom.us | 0 | 1 | 4 | 2 | 10 | 17 | 37 | **C** | 29.7 |

Scanner state: pre-`6c97837`. Grades in this table reflect the scanner as it
was on 2026-09-08, before the DNS-record-type and email-domain fixes landed.

---

## Round 2 — 20-target false-positive sweep, 2026-09-10

Not a random sample. Each target guards a specific suppression rule and is
annotated in `live-scan.ts` with the rule it protects — a regression in any one
of them shows up here as an actionable finding.

Two sites (`*`) answered with an interstitial and are ungraded, on the same
reasoning as Round 1. Both are in the list precisely *because* they serve
challenges — checking that the withholding still works is their job.

| Host | Crit | High | Med | Low | Info | Total | Score | Grade | Secs |
|---|---|---|---|---|---|---|---|---|---|
| google.com | 0 | 0 | 3 | 3 | 9 | 15 | 18 | **B** | 8.6 |
| github.com | 0 | 1 | 1 | 3 | 6 | 11 | 23 | **B** | 12.5 |
| cloudflare.com | 0 | 1 | 3 | 0 | 4 | 8 | 30 | **C** | 29.8 |
| stackoverflow.com * | 0 | 0 | 0 | 0 | 3 | 3 | — | — | 5.9 |
| npmjs.com | 0 | 0 | 2 | 3 | 6 | 11 | 13 | **B** | 23.0 |
| etsy.com * | 0 | 0 | 0 | 1 | 3 | 4 | — | — | 6.3 |
| nytimes.com | 0 | 0 | 5 | 3 | 11 | 19 | 28 | **C** | 31.0 |
| dropbox.com | 0 | 0 | 2 | 2 | 7 | 11 | 12 | **B** | 22.2 |
| stripe.com | 0 | 0 | 1 | 2 | 7 | 10 | 7 | **A** | 14.5 |
| mapbox.com | 0 | 0 | 2 | 3 | 6 | 11 | 13 | **B** | 17.5 |
| vercel.com | 0 | 1 | 5 | 2 | 9 | 17 | 42 | **C** | 25.9 |
| netlify.com | 0 | 1 | 4 | 1 | 7 | 13 | 36 | **C** | 8.9 |
| linkedin.com | 0 | 0 | 3 | 5 | 10 | 18 | 20 | **B** | 28.8 |
| reddit.com | 0 | 1 | 1 | 4 | 11 | 17 | 24 | **B** | 7.6 |
| wikipedia.org | 0 | 1 | 2 | 2 | 11 | 16 | 27 | **C** | 15.4 |
| apple.com | 0 | 0 | 2 | 3 | 9 | 14 | 13 | **B** | 26.5 |
| microsoft.com | 0 | 1 | 3 | 3 | 9 | 16 | 33 | **C** | 30.7 |
| mozilla.org | 0 | 0 | 2 | 1 | 5 | 8 | 11 | **B** | 8.8 |
| paypal.com | 0 | 0 | 3 | 1 | 7 | 11 | 16 | **B** | 27.4 |
| bbc.co.uk | 0 | 1 | 3 | 1 | 5 | 10 | 31 | **C** | 18.7 |

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
332 info.** Mean scan 18.1 seconds. 41 of the 50 runs reached the site's own
page; 9 were withheld at an interstitial.

Two things worth reading off that:

**No criticals, ever.** Forty-one runs that actually reached a well-run site
produced not one critical. That is the expected shape — a passive scan of a
healthy site should be quiet — and it is the number to watch. A critical
appearing here without the target having changed is a scanner bug until proven
otherwise.

It is also, on its own, worth nothing: **a scanner that reports nothing would
produce exactly this page.** Quiet output and broken detection are
indistinguishable from the outside. What separates them is
`scripts/detection-check.ts`, which scans a fixture wrong in 19 deliberate ways
and fails the build if any go unfound. Read that alongside this.

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
