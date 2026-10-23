# Scan results

Passive scans of 36 sites, captured 2026-09-10. Every actionable finding here was verified by hand against the live site. That the scanner still detects real vulnerabilities is shown separately in [DETECTION-VALIDATION.md](DETECTION-VALIDATION.md), because a scanner that reports nothing would also produce a clean-looking page like this one.

Passive means HTTP GETs and DNS lookups against publicly served pages. No authentication was attempted, no parameters were manipulated, and no state was altered on any site. Every finding below can be reproduced by anyone with `curl` or `dig`.

**401 findings across 36 sites, 151 of them above Info.** 0 critical, 17 high, 70 medium, 64 low, 250 info. 375 pages fetched in total.

Not reached, and therefore not included:

- `https://www.fastly.com` — Failed to reach target URL: fetch failed
- `https://www.mozilla.org` — Failed to reach target URL: fetch failed

## Read this before comparing sites

6 of these sites answered with a bot-protection interstitial rather than their own page: `amazon.co.uk`, `apnews.com`, `ebay.com`, `etsy.com`, `reuters.com`, `stackoverflow.com`. The scanner withholds every finding read from such a response, so those sites show only a handful of findings and often zero actionable ones. **That is suppressed coverage, not a clean result** — it means their page was never seen. Their counts are not comparable with the rest.

## Every site

| Site | Score | Grade | Findings | Actionable | Critical | High | Medium | Low | Info | Detail |
|---|---:|:--:|---:|---:|---:|---:|---:|---:|---:|---|
| amazon.co.uk * | — | — | 2 | 0 | 0 | 0 | 0 | 0 | 2 | [detail](scans/amazon.co.uk.md) |
| apnews.com * | — | — | 2 | 0 | 0 | 0 | 0 | 0 | 2 | [detail](scans/apnews.com.md) |
| apple.com | 13 | B | 14 | 5 | 0 | 0 | 2 | 3 | 9 | [detail](scans/apple.com.md) |
| archive.org | 36 | C | 15 | 6 | 0 | 1 | 4 | 1 | 9 | [detail](scans/archive.org.md) |
| bbc.co.uk | 31 | C | 10 | 5 | 0 | 1 | 3 | 1 | 5 | [detail](scans/bbc.co.uk.md) |
| cloudflare.com | 30 | C | 8 | 4 | 0 | 1 | 3 | 0 | 4 | [detail](scans/cloudflare.com.md) |
| digitalocean.com | 12 | B | 12 | 4 | 0 | 0 | 2 | 2 | 8 | [detail](scans/digitalocean.com.md) |
| dropbox.com | 12 | B | 12 | 4 | 0 | 0 | 2 | 2 | 8 | [detail](scans/dropbox.com.md) |
| ebay.com * | — | — | 3 | 0 | 0 | 0 | 0 | 0 | 3 | [detail](scans/ebay.com.md) |
| etsy.com * | — | — | 4 | 1 | 0 | 0 | 0 | 1 | 3 | [detail](scans/etsy.com.md) |
| european-union.europa.eu | 37 | C | 12 | 5 | 0 | 2 | 1 | 2 | 7 | [detail](scans/european-union.europa.eu.md) |
| figma.com | 12 | B | 10 | 4 | 0 | 0 | 2 | 2 | 6 | [detail](scans/figma.com.md) |
| github.com | 23 | B | 11 | 5 | 0 | 1 | 1 | 3 | 6 | [detail](scans/github.com.md) |
| gitlab.com | 47 | D | 13 | 7 | 0 | 2 | 3 | 2 | 6 | [detail](scans/gitlab.com.md) |
| google.com | 18 | B | 15 | 6 | 0 | 0 | 3 | 3 | 9 | [detail](scans/google.com.md) |
| gov.uk | 0 | A | 7 | 0 | 0 | 0 | 0 | 0 | 7 | [detail](scans/gov.uk.md) |
| letsencrypt.org | 6 | A | 9 | 2 | 0 | 0 | 1 | 1 | 7 | [detail](scans/letsencrypt.org.md) |
| linkedin.com | 15 | B | 16 | 7 | 0 | 0 | 2 | 5 | 9 | [detail](scans/linkedin.com.md) |
| mapbox.com | 13 | B | 11 | 5 | 0 | 0 | 2 | 3 | 6 | [detail](scans/mapbox.com.md) |
| microsoft.com | 33 | C | 16 | 7 | 0 | 1 | 3 | 3 | 9 | [detail](scans/microsoft.com.md) |
| nasa.gov | 28 | C | 12 | 6 | 0 | 1 | 2 | 3 | 6 | [detail](scans/nasa.gov.md) |
| netlify.com | 36 | C | 13 | 6 | 0 | 1 | 4 | 1 | 7 | [detail](scans/netlify.com.md) |
| notion.so | 18 | B | 14 | 6 | 0 | 0 | 3 | 3 | 8 | [detail](scans/notion.so.md) |
| npmjs.com | 13 | B | 12 | 5 | 0 | 0 | 2 | 3 | 7 | [detail](scans/npmjs.com.md) |
| nytimes.com | 18 | B | 17 | 6 | 0 | 0 | 3 | 3 | 11 | [detail](scans/nytimes.com.md) |
| paypal.com | 16 | B | 12 | 4 | 0 | 0 | 3 | 1 | 8 | [detail](scans/paypal.com.md) |
| reddit.com | 24 | B | 17 | 6 | 0 | 1 | 1 | 4 | 11 | [detail](scans/reddit.com.md) |
| reuters.com * | — | — | 3 | 0 | 0 | 0 | 0 | 0 | 3 | [detail](scans/reuters.com.md) |
| shopify.com | 22 | B | 12 | 4 | 0 | 1 | 1 | 2 | 8 | [detail](scans/shopify.com.md) |
| slack.com | 26 | C | 10 | 4 | 0 | 1 | 2 | 1 | 6 | [detail](scans/slack.com.md) |
| stackoverflow.com * | — | — | 3 | 0 | 0 | 0 | 0 | 0 | 3 | [detail](scans/stackoverflow.com.md) |
| stripe.com | 7 | A | 10 | 3 | 0 | 0 | 1 | 2 | 7 | [detail](scans/stripe.com.md) |
| theguardian.com | 16 | B | 14 | 4 | 0 | 0 | 3 | 1 | 10 | [detail](scans/theguardian.com.md) |
| vercel.com | 42 | C | 17 | 8 | 0 | 1 | 5 | 2 | 9 | [detail](scans/vercel.com.md) |
| wikipedia.org | 27 | C | 16 | 5 | 0 | 1 | 2 | 2 | 11 | [detail](scans/wikipedia.org.md) |
| zoom.us | 37 | C | 17 | 7 | 0 | 1 | 4 | 2 | 10 | [detail](scans/zoom.us.md) |

**Grades, over the 30 sites actually reached:** A 3 · B 15 · C 11 · D 1 · F 0 — mean score 22.3.

Score is `computeRiskScore`: critical 30, high 15, medium 5, low 1, **info 0** — higher is worse, capped at 100. Grade is `computeGrade`: A ≤ 10, B ≤ 25, C ≤ 45, D ≤ 65, F above. Info scoring zero is why a site with a dozen findings can still grade A.

`*` answered with a bot-protection interstitial; see above.

## What came up most often

Across the 30 sites whose own pages were seen.

| Finding | Severity | Sites | CWE |
|---|---|---:|---|
| Active security testing was skipped for this scan | Info | 30/30 | — |
| Missing Cross-Origin-Embedder-Policy (COEP) | Info | 30/30 | CWE-346 |
| Missing Cross-Origin-Resource-Policy (CORP) | Info | 28/30 | CWE-346 |
| Missing Cross-Origin-Opener-Policy (COOP) | Info | 25/30 | CWE-346 |
| Missing Permissions-Policy Header | Low | 21/30 | CWE-16 |
| DNSSEC Not Enabled | Info | 21/30 | CWE-350 |
| Missing Referrer-Policy Header | Low | 17/30 | CWE-200 |
| Non-Session Cookie Readable by JavaScript | Info | 17/30 | CWE-1004 |
| External Resources Missing Subresource Integrity (SRI) | Medium | 16/30 | CWE-353 |
| Rate Limiting Not Advertised in Response Headers | Info | 15/30 | CWE-307 |
| Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src) | Medium | 14/30 | CWE-79 |
| Missing X-Content-Type-Options: nosniff | Medium | 12/30 | CWE-16 |
| Missing Content-Security-Policy (CSP) | High | 9/30 | CWE-79 |
| CSP Missing base-uri Directive | Low | 9/30 | CWE-79 |
| Non-Session Cookie Missing SameSite Attribute | Info | 9/30 | CWE-352 |
| Missing security.txt (RFC 9116) | Info | 9/30 | CWE-205 |
| Incomplete Open Graph Metadata | Info | 8/30 | — |
| Missing Clickjacking Protection (X-Frame-Options) | Medium | 7/30 | CWE-1021 |
| No Structured Data Found | Info | 7/30 | — |
| Non-Session Cookie Readable by JavaScript on Inner Page | Info | 7/30 | CWE-1004 |
| Non-Session Cookie Missing Secure Flag | Low | 6/30 | CWE-614 |
| Twitter Card Metadata Absent | Info | 6/30 | — |
| robots.txt Discloses Sensitive Application Paths | Info | 6/30 | CWE-200 |
| CSP Missing object-src 'none' Directive | Medium | 5/30 | CWE-79 |
| Content-Security-Policy Allows Inline Styles (unsafe-inline in style-src) | Low | 4/30 | CWE-79 |
| Exposed API Documentation — OpenAPI JSON spec at /openapi.json | Medium | 3/30 | CWE-200 |
| X-Powered-By Header Discloses Technology Stack | Info | 3/30 | CWE-200 |
| Missing Cache-Control Headers | Info | 3/30 | CWE-524 |
| JavaScript Source Map Exposed — Full Source Code Accessible | High | 2/30 | CWE-540 |
| Content-Security-Policy Missing on 8 Internal Routes | High | 2/30 | CWE-79 |
| X-Frame-Options / frame-ancestors Missing on 2 Internal Routes | Medium | 2/30 | CWE-1021 |
| Non-Session Cookie Missing Secure Flag on Inner Page | Low | 2/30 | CWE-614 |
| Server Version Disclosure | Info | 2/30 | CWE-200 |
| DMARC Record Missing Aggregate Report Address (rua=) | Info | 2/30 | CWE-778 |
| Content-Security-Policy Missing on 3 Internal Routes | High | 1/30 | CWE-79 |
| Content-Security-Policy Missing on 9 Internal Routes | High | 1/30 | CWE-79 |
| Missing DMARC Record — No Email Authentication Enforcement | High | 1/30 | CWE-290 |
| Content-Security-Policy Missing on 1 Internal Route | High | 1/30 | CWE-79 |
| HTTP Traffic Not Redirected to HTTPS | Medium | 1/30 | CWE-319 |
| X-Content-Type-Options Missing on 2 Internal Routes | Medium | 1/30 | CWE-16 |
| X-Content-Type-Options Missing on 1 Internal Route | Medium | 1/30 | CWE-16 |
| Content-Security-Policy is report-only (not enforced) | Medium | 1/30 | CWE-79 |
| Session Cookie Missing HttpOnly Flag | Medium | 1/30 | CWE-1004 |
| X-Frame-Options / frame-ancestors Missing on 5 Internal Routes | Medium | 1/30 | CWE-1021 |
| Session Cookie Missing HttpOnly Flag on Inner Page | Medium | 1/30 | CWE-1004 |
| Permissive crossdomain.xml Policy | Medium | 1/30 | CWE-942 |
| X-Content-Type-Options Missing on 8 Internal Routes | Medium | 1/30 | CWE-16 |
| X-Frame-Options / frame-ancestors Missing on 8 Internal Routes | Medium | 1/30 | CWE-1021 |
| Permissive CORS Policy (Wildcard Origin) | Medium | 1/30 | CWE-942 |
| Referrer-Policy Missing on 3 Internal Routes | Low | 1/30 | CWE-200 |
| Referrer-Policy Missing on 1 Internal Route | Low | 1/30 | CWE-200 |
| SPF Record Exceeds DNS Lookup Limit | Low | 1/30 | CWE-290 |
| Referrer-Policy Missing on 8 Internal Routes | Low | 1/30 | CWE-200 |
| Page Excluded From Search Indexes | Info | 1/30 | — |
| API Key in Client Code (verify restrictions) | Info | 1/30 | CWE-798 |

