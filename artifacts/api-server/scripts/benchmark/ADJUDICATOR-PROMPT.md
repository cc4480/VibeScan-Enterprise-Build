# Blind adjudication — standing instructions

Give an adjudicator **only** `judge-packet.json` and this file. Nothing else from this
repository — not `ground-truth.ts`, not a previous mapping, not this benchmark's own
README. An adjudicator who has seen a prior attempt at the mapping is anchored on it,
which defeats the point of running a second one.

Three adjudicators run independently, in parallel, with no visibility into each other's
verdicts. `score-consensus.ts` computes agreement and the unanimous/majority scores
afterward — nothing about the adjudication itself should be aware that a consensus step
follows.

---

## The prompt

> You are adjudicating a security-scanner detection benchmark. Be rigorous and
> sceptical.
>
> Read `judge-packet.json`. It is your only input. Do not search for or open any
> other file.
>
> A deliberately vulnerable web application was built with a known list of planted
> faults (`faults` in the packet). Three scanners were each pointed at it. For each
> tool you are given the DISTINCT finding names it reported
> (`tools["Tool A"].distinct_findings`, etc.).
>
> For every fault, decide for each of Tool A, Tool B and Tool C whether that tool's
> reported findings show it DETECTED that specific fault.
>
> **The standard — apply it strictly and identically to all three tools:**
>
> - Credit only when a reported finding IDENTIFIES THAT SPECIFIC FAULT. Operating in
>   the same subject area is not detection.
> - Detecting that something EXISTS is not detecting that it is MISCONFIGURED.
>   "GraphQL API detected" is not "GraphQL introspection is enabled". "Swagger
>   detected" is not "the API returns sensitive fields".
> - Finding a marker of one technology is not finding the equivalent in another. A
>   Java-serialization alert is not detection of Ruby, Python or PHP deserialization.
> - A single broad finding MAY legitimately cover several specific faults — one "CSP
>   directives missing" alert can reasonably cover several individual
>   missing-directive faults. Use judgement; say so in your reason.
> - Version disclosure is NOT end-of-life analysis. A version banner is not an EOL
>   or CVE finding unless the finding says so.
> - Watch for misleading substrings. "Misconfiguration" contains "config". "Source
>   File Inclusion" is not "Local File Inclusion". Judge meaning, not letters.
> - Some faults carry a `note` saying special equipment may be needed (credentials,
>   an API spec, an out-of-band collector). If a tool did not report it, that is
>   still "no" — but set `"equipped": false` so it can be reported separately.
>
> You have no information about which tool is which product, and you do not need
> it. Judge every tool by exactly the same standard.
>
> Write your verdicts as JSON to the path you are given. Format — one object per
> fault, all faults in the packet, no omissions:
>
> ```json
> {
>   "verdicts": [
>     {
>       "id": "<fault id>",
>       "A": "yes" | "no" | "unclear",
>       "B": "yes" | "no" | "unclear",
>       "C": "yes" | "no" | "unclear",
>       "A_match": "<the exact finding name that justifies a yes, else null>",
>       "B_match": "<same, else null>",
>       "C_match": "<same, else null>",
>       "equipped": true,
>       "reason": "<one short sentence, only where a call was difficult>"
>     }
>   ]
> }
> ```
>
> Use "unclear" genuinely — where a reasonable person could go either way — rather
> than guessing. That signal matters more than a tidy score.

---

## Known limitation of this method

Adjudicators run this way are not independent experts — they are instances of one
model, sharing weights and priors. Blinding removes the incentive to favour a known
tool; it does not remove correlated misjudgement. A high agreement rate between them
means the scoring is *stable*, not that it is *correct*. `score-consensus.ts` reports
agreement before it reports a score, in that order, for that reason.

If this benchmark's numbers are ever challenged, the strongest response is not
"our adjudicators agreed" — it is "run it yourself": see the top-level project plan
for why a public target with a published manifest matters more than any adjudication
process run internally.
