# Cross-scanner benchmark

Runs OWASP ZAP, Nuclei and SecScan against the same target — `artifacts/vuln-fixture`,
an application whose faults are known exactly — and scores all three against the same
ground truth.

```bash
# 1. Start the target
pnpm --filter @workspace/vuln-fixture run start

# 2. Run everything, and get a fast (regex-scored) result
pnpm --filter @workspace/api-server run benchmark

# Re-score existing raw output without re-scanning
pnpm --filter @workspace/api-server run benchmark -- --score-only

# 3. For a number worth publishing, replace the regex scoring with blind
#    semantic adjudication — see "Which scorer to trust" below
pnpm --filter @workspace/api-server run benchmark:packet
#   -> hand benchmark-out/judge-packet.json to three independent adjudicators
#      per ADJUDICATOR-PROMPT.md, save their output as verdict-1/2/3.json
pnpm --filter @workspace/api-server run benchmark:score
```

Raw output from every tool is written to `benchmark-out/` **unchanged**, so the scoring
can be re-run, disputed, or redone by somebody else with a different mapping.

---

## Which scorer to trust

`run-benchmark.ts`'s regex matchers in `ground-truth.ts` are fast and fine for
iterating — checking whether a ground-truth change moved a number while you're editing
it. They are **not** trustworthy enough to publish from on their own.

Evidence: three successive rounds of "fix a regex, re-score" moved ZAP's detection rate
from 59.5% to 47.3% to 31.1%, with the underlying scan data never changing once across
any of them. A benchmark author scoring a competitor's tool with hand-written patterns
is exactly the setup that makes a result impossible to trust — ours included, however
careful the patterns.

`build-judge-packet.ts` / `score-consensus.ts` replace the regex with semantic
judgment: the three tools are relabelled Tool A/B/C, three independent adjudicators
each decide — blind to which tool is which — whether a tool's reported findings
demonstrate detection of each fault, and `score-consensus.ts` reports **agreement
before it reports a score**. If the adjudicators disagree on a large share of their
calls, the benchmark is measuring the adjudicator, not the scanners, and nothing from
it should be published until that is resolved.

This does not make the result independently verified. Three adjudicators run this way
share whatever blind spots the model itself has — see the caveat in
`ADJUDICATOR-PROMPT.md`. It is a real improvement over hand-written regexes, not a
substitute for the actual goal: a public target anyone can score without trusting our
process at all. See the top-level project plan.

---

## A discoverability bug this benchmark itself found (fixed 2026-09-22)

The first run of this benchmark scored ZAP at 18/74 blind-adjudicated (24.3%) and
Nuclei at 9/74 (12.2%) against SecScan's 68/74. Before publishing that, the raw ZAP
crawl log was checked against the ground truth — and ZAP had never once requested
`/download`, `/login` or `/app/graphql`. Not "visited and missed": never asked for the
URL, because nothing on the fixture's homepage linked to them. SecScan "found" the
path-traversal fault at `/download` from a hardcoded wordlist in `pathTraversal.ts`,
not by crawling to it.

That is not a detection win. It is SecScan knowing its own fixture's paths — and it
would have made every number from this benchmark, published or not, defensible only by
people who already trusted us.

Fixed in `artifacts/vuln-fixture/src/server.ts`: every route that is a genuine app
feature is now linked from `<nav>`, so any ordinary crawler finds it the way SecScan
does. Routes that are deliberately hidden — `/admin`, `/backup`, `/staging` and the
`SENSITIVE_PATHS` block — stay unlinked on purpose: those represent paths a real
attacker finds by forced-browsing a wordlist, which is a genuine, fair, and
**disclosed** capability difference between tools (see below), not a fairness bug.

The fixture's own file header now documents this split (search for "Discoverability
policy") so it does not regress the next time a route is added.

**Still not addressed:** ZAP's default `zap-full-scan.py` invocation does not enable
its Forced Browse add-on, so ZAP's score on the deliberately-hidden paths reflects
ZAP's small built-in list of common files, not its full forced-browsing capability.
Nuclei's file-fuzzing templates are enabled by default and do reflect its full
capability there. This asymmetry is disclosed, not corrected — correcting it means
configuring ZAP's Forced Browse add-on with a comparable wordlist, which has not been
done yet.

---

## Read this before quoting a number from it

### The fixture is SecScan's own checklist made executable

This is the bias that matters, and no amount of careful methodology removes it. The
fixture was built to contain the faults SecScan checks for. That makes it an excellent
instrument for its actual purpose — measuring SecScan's **false negatives**, which
nothing else can measure — and an inherently favourable test for SecScan in any
comparison.

A tool scoring lower here has not been shown to be worse. It has been shown to overlap
less with SecScan's checklist. Those are different claims and only the second one is
supported.

### So the report also prints what each tool found that we did not plant

For every tool, `benchmark-report.json` lists `notInGroundTruth` — findings it reported
that are not in our ground truth at all. That list is the honest counterweight to the
detection rate, and on this fixture it is **expected** to contain things SecScan does not
check for. Read it before concluding anything.

### Matching is deliberately generous to the other tools

Each ground-truth item carries a matcher per tool, run against a haystack built from
everything that tool said about a finding — name, description, evidence, template id,
tags, matched URL. Where a tool reports something broader than the planted fault (a
general "CSP header issues" against a specific missing directive), **it is credited**.

When in doubt, credit the other tool. A benchmark that has to be read charitably to be
believed is worth nothing.

The report prints the exact text that satisfied each matcher, not just a tick, so every
credit is checkable.

### Some faults need equipment a tool was not given

Seven ground-truth items carry a `needs` field: two authenticated sessions, the OpenAPI
spec, or a reachable out-of-band collector. SecScan is given these because the fixture
was built alongside it. ZAP can be given an OpenAPI spec and authentication through its
addons and was **not** configured with them here.

That is a real limitation of this run, stated rather than hidden. A fair head-to-head on
the API items would require configuring ZAP's `openapi` and authentication addons, and
until that is done those rows should be read as "not configured to find it", not "failed
to find it".

---

## What each tool was run with

| Tool | Invocation | Mode |
|---|---|---|
| **SecScan** | `live-scan.ts --active` | Full active pass, credentialed, against a target it owns |
| **OWASP ZAP** | `zap-full-scan.py -j` | Passive + active scan, AJAX spider enabled |
| **Nuclei** | `-severity info,low,medium,high,critical` | All templates at every severity |

ZAP is run in **full-scan** mode rather than baseline, because baseline is passive-only
and would have been the weak configuration. Nuclei is run across every severity for the
same reason. Exact versions are recorded in the report.

---

## Files

| File | What it is |
|---|---|
| `ground-truth.ts` | The planted faults, scanner-neutral, with a matcher per tool and the category/`needs` metadata both scorers read. **This file is the benchmark** — everything else is plumbing. |
| `run-benchmark.ts` | Orchestrates the scanner runs, normalises output, regex-scores, writes `benchmark-report.json`. Fast, not publishable on its own — see "Which scorer to trust". |
| `build-judge-packet.ts` | Blinds the three tools to Tool A/B/C, writes `judge-packet.json` (hand to adjudicators) and `judge-key.json` (do not). |
| `ADJUDICATOR-PROMPT.md` | The standing instructions given to each blind adjudicator, verbatim. |
| `score-consensus.ts` | Reads three `verdict-N.json` files, reports agreement, then the unanimous and majority scores, unblinded. |
| `benchmark-out/zap.json` | ZAP's raw report |
| `benchmark-out/nuclei.jsonl` | Nuclei's raw output |
| `benchmark-out/secscan.json` | SecScan's raw output |
| `benchmark-out/benchmark-report.json` | Regex-scored comparison (`run-benchmark.ts`) |
| `benchmark-out/judge-packet.json` / `judge-key.json` | The blinded packet and the (secret) tool assignment |
| `benchmark-out/verdict-1/2/3.json` | Each adjudicator's verdicts |
| `benchmark-out/consensus.json` | The publishable result — agreement rate, unanimous score, majority score |

---

## Disputing a result

Every credit and every miss traces to a regex in `ground-truth.ts` and a line in the raw
output kept beside it. If a mapping is wrong, change it and re-run with `--score-only`;
the numbers move and the reasoning stays visible.

That is the standard this benchmark asks of itself, and the same standard it asks of
anyone publishing a competing one.
