# Scanner retest procedure

How to re-prove the false-positive fixes and catch regressions. Run this before
shipping any scanner change.

The five false positives fixed on 2026-09-07 all shipped and survived because
nothing routinely pointed the scanner at known-good sites and read the output.
They were only ever found by someone disputing a report. This procedure is the
fix for that, and matters more than any individual bug it caught.

---

## Run it

```
DATABASE_URL=postgres://localhost/anything \
  npx tsx artifacts/api-server/scripts/live-scan.ts \
    https://www.google.com https://github.com \
    https://www.cloudflare.com https://www.mozilla.org
```

`DATABASE_URL` only has to be **set**, not reachable — the scanner module
imports the db layer at load time and never queries it during a passive scan.

Passive only. Active exploit probing is gated behind domain-ownership
verification in the product and must never be aimed at sites you do not own.

---

## Expected counts

The baseline as of `c94fd75`, re-confirmed unchanged after the mail-TLS probe
landed. A jump means something regressed; a drop is worth
understanding rather than celebrating, since it may mean a real detector
stopped firing.

| Target | Findings | Actionable |
|---|---|---|
| google.com | 13 | 6 |
| github.com | 11 | 5 |
| cloudflare.com | 8 | 4 |
| mozilla.org | 7 | 3 |

---

## Regression checks

Each of these fired before the fix and must not fire again.

**Cookie attributes after `expires=` must stay visible.**
google.com's `NID` must NOT be reported as "Readable by JavaScript" — it carries
`HttpOnly`. If it is, `Set-Cookie` is being re-split on commas somewhere and the
comma inside `expires=Tue, 09-Mar-2027` is shearing cookies in half again. Use
the already-split list from `getSetCookie()`, never a flattened header string.

**One cookie defect, one finding.**
No cookie may appear both as "Missing X" and "Missing X on Inner Page". The
crawl's dedup set is seeded from the root response for exactly this reason.

**CSP allowlist entries are not wildcards.**
cloudflare.com and mozilla.org must NOT be reported as
"CSP script-src Contains Wildcard — XSS Protection Bypassed". Both list ~20
named origins, some with subdomain wildcards like `https://*.onetrust.com`. Only
a bare `*`, optionally scheme-prefixed, allows scripts from anywhere. Nearly
every CSP that loads analytics has a subdomain wildcard, so a regression here is
loud, HIGH severity, and wrong on well-built policies.

**Infrastructure rate limiting counts as rate limiting.**
github.com must NOT be reported as "No Rate Limiting Detected". It enforces at
the edge and exposes no rate-limit headers on HTML; `x-github-edge-region` /
`x-github-request-id` are in the allowlist alongside Cloudflare, Akamai,
CloudFront, Azure and Google.

**A mail host that goes quiet is not a mail host without STARTTLS.**
cloudflare.com must NOT be reported as "Mail Server Does Not Offer STARTTLS".
Its MX completes the TCP handshake on 587 and then resets before answering
`EHLO`. Only ports where `starttlsAdvertised` is an actual boolean count as
evidence; `null` means the probe learned nothing. This one is easy to
reintroduce by "simplifying" the filter to `reachable`, and the resulting bug is
intermittent — it depends on when the reset lands, so it survives a re-run.

Probe port 25 only. Adding 587/465 back costs ~5s on every scan and measures
nothing: an MX is an inbound relay, and submission ports live elsewhere.

**Evidence must describe what actually happened.**
mozilla.org's security.txt finding is CORRECT — the file exists but is not
RFC 9116 (`Email:` / `Main info:` rather than `Contact:` / `Expires:`). The
evidence must say "HTTP 200, but no RFC 9116 fields", never "not found". A
correct finding with false evidence gets disputed exactly like a false positive
and costs the same trust.

---

## Verifying a suspected false positive

**Use the scanner's own User-Agent, not a browser's.** Targets vary responses by
UA and that difference is exactly where these mistakes live.

The trap that nearly cost a correct detector: google.com serves `NID` **without**
`Secure` to a non-browser UA and **with** it to Chrome. Checking in DevTools
shows the opposite of what the scanner saw, and the obvious conclusion — that
the scanner is wrong — is itself wrong.

```
curl -sI -A "<the scanner UA>" https://target/ | tr -d '\r' | grep -i set-cookie
```

Before changing a detector, check `FALSE-POSITIVE-AUDIT.md`. Its "Checked and
correct" section lists findings that look false and are not.

---

## After fixing

1. `npx vitest run` in `artifacts/api-server` — 613 passing as of the mail-TLS work.
2. Re-run the live scan and compare against the counts above.
3. Update `FALSE-POSITIVE-AUDIT.md`: move the entry to Fixed, record the new
   counts, and add anything checked-and-correct so nobody "fixes" it later.
4. Deploy **web tier before worker** (`seclayer` service, then `secscan`) — the
   worker enforces the domain-verification gate and will block active probes
   while the `/domains` page that satisfies it is not yet being served.
