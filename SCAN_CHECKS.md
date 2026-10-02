# SecScan — Check Index

<!-- GENERATED FILE — do not edit by hand.
     Regenerate with: node artifacts/api-server/scripts/check-index.mjs -->

Every finding the scanner can emit, read out of `artifacts/api-server/src/lib`. This is the
complete list; [SCAN_COVERAGE.md](SCAN_COVERAGE.md) is the readable one, grouped by module with
the Basic/Deep tier and the methodology behind each group.

**315 findings across 60 modules**, in 38 categories. 85 critical, 73 high, 55 medium, 32 low, 70 info.

A finding is a distinct name the scanner can put in a report, which is not the same as a check
type: the data-table modules below define many findings from one piece of detection logic —
`probes-data` is one path probe applied to 0 paths. Where a check emits two severities depending on context (a session cookie versus an
ordinary one), both are shown and it is counted at the higher.

## Coverage

`direct` — the module has its own test file. `indirect` — a test file imports it, or a tested
module does. `none` — neither, so no test exercises it at all.

| Module | Findings | Lines | Tests | Coverage |
|---|---:|---:|---:|---|
| `recon-data.ts` | 14 | 178 | 12 | direct |
| `nextjsProbe.ts` | 9 | 255 | 8 | direct |
| `structuredData.ts` | 9 | 285 | 36 | direct |
| `crawler-data.ts` | 8 | 181 | 35 | direct |
| `scannerCspChecks.ts` | 7 | 155 | 10 | direct |
| `scannerHeaderChecks.ts` | 7 | 142 | 3 | direct |
| `jwtAnalysis.ts` | 6 | 267 | 9 | direct |
| `scannerCoverage.ts` | 6 | 216 | 1 | direct |
| `storageProbe.ts` | 5 | 254 | 11 | direct |
| `firebase-probes.ts` | 4 | 301 | 8 | direct |
| `baasDepth.ts` | 3 | 148 | 11 | direct |
| `isolationHeaders.ts` | 3 | 77 | 4 | direct |
| `mailTls.ts` | 3 | 139 | 13 | direct |
| `probesSupabase.ts` | 3 | 164 | 1 | direct |
| `aiFeatureProbe.ts` | 2 | 152 | 21 | direct |
| `baasProbes.ts` | 2 | 166 | 11 | direct |
| `graphqlExtra.ts` | 2 | 105 | 8 | direct |
| `graphqlProbe.ts` | 2 | 256 | 12 | direct |
| `injectionExtra.ts` | 2 | 140 | 9 | direct |
| `injectionProbe.ts` | 2 | 283 | 13 | direct |
| `scanner.ts` | 2 | 388 | 6 | direct |
| `sourceMaps.ts` | 2 | 236 | 19 | direct |
| `supabase-probes.ts` | 2 | 104 | 7 | direct |
| `apiDocsProbe.ts` | 1 | 129 | 9 | direct |
| `crossAccountStep.ts` | 1 | 172 | 16 | direct |
| `deserializationProbe.ts` | 1 | 105 | 9 | direct |
| `dnsChecks.ts` | 1 | 163 | 39 | direct |
| `healthEndpointProbe.ts` | 1 | 114 | 10 | direct |
| `pathTraversal.ts` | 1 | 195 | 4 | direct |
| `promptInjectionProbe.ts` | 1 | 214 | 26 | direct |
| `raceConditionProbe.ts` | 1 | 181 | 21 | direct |
| `ssrfProbe.ts` | 1 | 200 | 7 | direct |
| `probes-data-vcs.ts` | 24 | 244 | — | indirect, via probes-data.test.ts (split from probes-data) |
| `probes-data-config.ts` | 23 | 273 | — | indirect, via probes-data.test.ts (split from probes-data) |
| `secret-pattern-vendors.ts` | 21 | 247 | — | indirect, via secret-pattern-data.test.ts (split from secret-pattern-data) |
| `subdomain-service-data.ts` | 19 | 172 | — | indirect, via subdomainTakeover.test.ts |
| `probes-data-server.ts` | 17 | 177 | — | indirect, via probes-data.test.ts (split from probes-data) |
| `probes-data-infra.ts` | 14 | 148 | — | indirect, via probes-data.test.ts (split from probes-data) |
| `dnsChecksMail.ts` | 8 | 205 | — | indirect, via dnsChecks.test.ts (split from dnsChecks) |
| `apiProbeFindings.ts` | 7 | 215 | — | indirect, via apiProbe.test.ts (split from apiProbe) |
| `probesHttp.ts` | 7 | 218 | — | indirect, via probes.test.ts (split from probes) |
| `secret-pattern-generic.ts` | 7 | 144 | — | indirect, via secret-pattern-data.test.ts (split from secret-pattern-data) |
| `supabase-probes-report.ts` | 7 | 234 | — | indirect, via supabase-probes.test.ts (split from supabase-probes) |
| `scannerCookies.ts` | 6 | 205 | — | indirect, via scanner.test.ts (split from scanner) |
| `crawlerHeaders.ts` | 5 | 202 | — | indirect, via crawler.test.ts (split from crawler) |
| `cveCheckLocal.ts` | 5 | 225 | — | indirect, via cveCheck.test.ts (split from cveCheck) |
| `secret-pattern-ai.ts` | 5 | 62 | — | indirect, via secret-pattern-generic.test.ts |
| `accessControlFindings.ts` | 3 | 129 | — | indirect, via accessControlProbe.test.ts |
| `probesFiles.ts` | 3 | 266 | — | indirect, via probes.test.ts (split from probes) |
| `probesPage.ts` | 3 | 244 | — | indirect, via probes.test.ts (split from probes) |
| `scannerTransportChecks.ts` | 3 | 70 | — | indirect, via scanner.test.ts (split from scanner) |
| `baasProbesPocketbase.ts` | 2 | 133 | — | indirect, via baasProbes.test.ts (split from baasProbes) |
| `crawlerCookies.ts` | 2 | 178 | — | indirect, via crawler.test.ts (split from crawler) |
| `scannerPageChecks.ts` | 2 | 56 | — | indirect, via scanner.test.ts (split from scanner) |
| `secret-pattern-jwt.ts` | 2 | 81 | — | indirect, via secret-pattern-generic.test.ts |
| `workerAi.ts` | 2 | 100 | — | indirect, via worker.test.ts (split from worker) |
| `bannerRules.ts` | 1 | 112 | — | indirect, via cveCheckLocal.test.ts, cveCheckVersions.test.ts |
| `githubFindings.ts` | 1 | 60 | — | indirect, via githubSourceProbe.test.ts |
| `probesSri.ts` | 1 | 79 | — | indirect, via probes.test.ts (split from probes) |
| `workerSideChecks.ts` | 1 | 125 | — | indirect, via worker.test.ts (split from worker) |

## Findings by module

### `accessControlFindings.ts`

*3 findings · 129 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Broken Object-Level Authorisation (IDOR) | Critical | Broken Access Control | 8.1 | CWE-639 | WSTG-ATHZ-04 |
| Records Enumerable by Editing the Identifier | Critical | Broken Access Control | 8.6 | CWE-639 | WSTG-ATHZ-04 |
| Records Readable Without Signing In | High | Broken Access Control | 7.5 | CWE-306 | WSTG-ATHZ-02 |

### `aiFeatureProbe.ts`

*2 findings · 152 lines · 21 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| AI Provider Called Directly From the Browser | Low | AI Feature Security | 3.7 | CWE-522 | WSTG-CONF-04 |
| AI System Prompt Shipped in Client-Side Code | Low | AI Feature Security | 3.7 | CWE-200 | WSTG-CONF-04 |

### `apiDocsProbe.ts`

*1 findings · 129 lines · 9 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Exposed API Documentation — ${label} at ${path} | Info / Low | Information Disclosure | 0 | CWE-200 | WSTG-CONF-02 |

### `apiProbeFindings.ts`

*7 findings · 215 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| API Records Readable by Another Account | Critical | Broken Access Control | 8.1 | CWE-639 | WSTG-ATHZ-04 |
| SQL Injection in API Parameters | Critical | Injection | 9.8 | CWE-89 | WSTG-INPV-05 |
| Write Endpoints Reachable Without Authentication | Critical | Broken Access Control | 9.1 | CWE-862 | WSTG-ATHZ-02 |
| API Endpoints Served Without Authentication | High | Broken Access Control | 7.5 | CWE-306 | WSTG-ATHZ-01 |
| Sensitive Fields Returned by the API | High | Information Disclosure | 7.5 | CWE-213 | WSTG-ATHZ-04 |
| Privilege Fields Accepted in Request Bodies | Medium | Broken Access Control | 6.5 | CWE-915 | WSTG-BUSL-01 |
| No Rate Limiting Observed on Sensitive API Endpoints | Info | Security Misconfiguration | 0 | CWE-770 | WSTG-ATHN-04 |

### `baasDepth.ts`

*3 findings · 148 lines · 11 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Firebase Storage Files Listable Without Authentication | High | Broken Access Control | 7.5 | CWE-284 | WSTG-ATHZ-01 |
| Supabase Storage Files Listable Without Authentication | Medium | Information Disclosure | 5.3 | CWE-200 | WSTG-CONF-04 |
| Supabase Email Confirmation Disabled | Low | Authentication | 3.7 | — | WSTG-IDNT-02 |

### `baasProbes.ts`

*2 findings · 166 lines · 11 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Appwrite — Collections Returned Empty Document Lists (Inconclusive) | Info | BaaS Misconfiguration | 0 | — | — |
| Appwrite — Public Content Readable Without Authentication on '${coll}' / Appwrite — Unauthenticated Document Read on '${coll}' | Info / Critical | BaaS Misconfiguration | 0 | — | — |

### `baasProbesPocketbase.ts`

*2 findings · 133 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| PocketBase — Collections Returned Empty Lists (Inconclusive) | Info | BaaS Misconfiguration | 0 | — | — |
| PocketBase — Public Content in '${col}' Collection Readable Without Authentication / PocketBase — Unauthenticated Access to '${col}' Collection | Info / Critical | BaaS Misconfiguration | 0 | — | — |

### `bannerRules.ts`

*1 findings · 112 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| ${shown} — Verify Distro Package Against ${r.cve} | Low | Outdated Software | — | CWE-1104 | — |

### `crawler-data.ts`

*8 findings · 181 lines · 35 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Environment File Exposed on Inner Route | Critical | Credential Exposure | 9.1 | CWE-312 | WSTG-CONF-04 |
| Configuration File Exposed on Inner Route | High | Information Disclosure | 6.5 | CWE-200 | WSTG-CONF-04 |
| Git Repository Exposed on Inner Route | High | Source Code Exposure | 8.1 | CWE-538 | WSTG-CONF-04 |
| Debug Log Exposed on Inner Route | Medium | Information Disclosure | 5.3 | CWE-532 | WSTG-CONF-04 |
| GraphQL Endpoint Exposed on Inner Route | Medium | Information Disclosure | 5.3 | CWE-200 | WSTG-CONF-04 |
| API Documentation Exposed on Inner Route | Info | Information Disclosure | 0 | CWE-200 | WSTG-CONF-04 |
| API Documentation Exposed on Inner Route (OpenAPI) | Info | Information Disclosure | 0 | CWE-200 | WSTG-CONF-04 |
| API Documentation Exposed on Inner Route (Swagger) | Info | Information Disclosure | 0 | CWE-200 | WSTG-CONF-04 |

### `crawlerCookies.ts`

*2 findings · 178 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Session Cookie Missing Secure Flag on Inner Page / Non-Session Cookie Missing Secure Flag on Inner Page | High / Low | Session Management | 6.5 | CWE-614 | WSTG-SESS-02 |
| Session Cookie Missing HttpOnly Flag on Inner Page / Non-Session Cookie Readable by JavaScript on Inner Page | Medium / Info | Session Management | 5.3 | CWE-1004 | WSTG-SESS-02 |

### `crawlerHeaders.ts`

*5 findings · 202 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Content-Security-Policy Missing on Internal Routes | High | Security Header Inconsistency | 7.2 | CWE-79 | WSTG-CONF-12 |
| X-Content-Type-Options Missing on Internal Routes | Medium | Security Header Inconsistency | 4.3 | CWE-16 | WSTG-CONF-07 |
| X-Frame-Options / frame-ancestors Missing on Internal Routes | Medium | Security Header Inconsistency | 4.3 | CWE-1021 | WSTG-CLNT-09 |
| Referrer-Policy Missing on Internal Routes | Low | Security Header Inconsistency | 3.1 | CWE-200 | WSTG-CONF-07 |
| Strict-Transport-Security Missing on Internal Routes | Low | Security Header Inconsistency | 3.1 | CWE-523 | WSTG-CONF-07 |

### `crossAccountStep.ts`

*1 findings · 172 lines · 16 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| A disposable test account was created on your site during this scan / A disposable test account may have been created on your site by this scan | Info | Scan Coverage | — | — | — |

### `cveCheckLocal.ts`

*5 findings · 225 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Microsoft IIS ${d.version} — CVE-2017-7269 (End-of-Life) | Critical | Outdated Software | 9.8 | CWE-119 | — |
| PHP ${d.version} is End-of-Life | High | Outdated Software | 7.5 | CWE-1104 | — |
| Apache HTTPD ${d.version} — End-of-Life Release Branch | Medium | Outdated Software | 6.5 | CWE-1104 | WSTG-INFO-02 |
| Nginx ${d.version} — End-of-Life Release Cycle | Medium | Outdated Software | 6.5 | CWE-1104 | — |
| PHP ${d.version} Reaches End-of-Life in ${eol.label} | Info | Outdated Software | — | CWE-1104 | — |

### `deserializationProbe.ts`

*1 findings · 105 lines · 9 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Insecure Deserialization Exposure (${m.format} object in cookie "${name}") | High | Insecure Deserialization | 8.1 | CWE-502 | WSTG-BUSL-06 |

### `dnsChecks.ts`

*1 findings · 163 lines · 39 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| DNSSEC Not Enabled | Info | DNS Security | — | CWE-345 | — |

### `dnsChecksMail.ts`

*8 findings · 205 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| SPF Record Uses +all (Allows Any Sender) | Critical | Email Security | 9.1 | CWE-290 | — |
| Missing DMARC Record — No Email Authentication Enforcement | High | Email Security | 7.5 | CWE-290 | — |
| Missing SPF Record — Email Spoofing Possible | High / Medium | Email Security | 7.5 | CWE-290 | — |
| DMARC Policy Set to None (Monitoring Only — No Enforcement) | Medium | Email Security | 5.3 | CWE-290 | — |
| SPF Record Uses ?all (Neutral — No Enforcement) | Medium | Email Security | 5.3 | CWE-290 | — |
| No DKIM Records Found Under Common Selectors | Low | Email Security | — | CWE-345 | — |
| SPF Record Exceeds DNS Lookup Limit | Low | Email Security | — | CWE-290 | — |
| DMARC Record Missing Aggregate Report Address (rua=) | Info | Email Security | — | CWE-778 | — |

### `firebase-probes.ts`

*4 findings · 301 lines · 8 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Firebase Realtime Database Open to Unauthenticated Access | Critical | Broken Access Control | 9.8 | CWE-284 | WSTG-ATHZ-01 |
| Firestore Security Rules Allow Unauthenticated Read Access | Critical | Broken Access Control | 9.3 | CWE-284 | WSTG-ATHZ-01 |
| Firebase Backend Detected — Firestore Rules Appear Restrictive | Info | Technology Fingerprint | 0 | — | — |
| Firestore Public Content Collection Readable Without Authentication | Info | Information Disclosure | 0 | — | — |

### `githubFindings.ts`

*1 findings · 60 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| GitHub source scan covered only part of the repository | Info | Scan Coverage | — | — | — |

### `graphqlExtra.ts`

*2 findings · 105 lines · 8 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| GraphQL IDE Exposed | Medium | API Security | 5.3 | CWE-489 | WSTG-CONF-05 |
| GraphQL Query Batching Enabled | Low | API Security | 3.7 | CWE-770 | WSTG-BUSL-05 |

### `graphqlProbe.ts`

*2 findings · 256 lines · 12 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| GraphQL Introspection Enabled in Production | Medium | API Security | 5.3 | CWE-200 | WSTG-INFO-01 |
| GraphQL Field Suggestions Enabled ("Did you mean…" Leaks) | Low | API Security | 3.7 | CWE-209 | — |

### `healthEndpointProbe.ts`

*1 findings · 114 lines · 10 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Health Endpoint Discloses Runtime Details | Info | Information Disclosure | — | CWE-200 | WSTG-INFO-02 |

### `injectionExtra.ts`

*2 findings · 140 lines · 9 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Server-Side Template Injection | Critical | Injection | 9.8 | CWE-1336 | WSTG-INPV-18 |
| HTTP Header Injection (CRLF) | Medium | Injection | 6.1 | CWE-113 | WSTG-INPV-15 |

### `injectionProbe.ts`

*2 findings · 283 lines · 13 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| SQL Injection (Error-Based) | Critical | Injection | 9.8 | CWE-89 | WSTG-INPV-05 |
| Reflected Cross-Site Scripting (XSS) | High | Injection | 6.1 | CWE-79 | WSTG-INPV-01 |

### `isolationHeaders.ts`

*3 findings · 77 lines · 4 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Missing Cross-Origin-Embedder-Policy (COEP) | Info | Browser Feature Control | — | CWE-16 | WSTG-CONF-07 |
| Missing Cross-Origin-Opener-Policy (COOP) | Info | Browser Feature Control | — | CWE-16 | WSTG-CONF-07 |
| Missing Cross-Origin-Resource-Policy (CORP) | Info | Browser Feature Control | — | CWE-16 | WSTG-CONF-07 |

### `jwtAnalysis.ts`

*6 findings · 267 lines · 9 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| JWT Has Empty Signature — Possible Verification Bypass | Critical | Session Management | 9.8 | CWE-347 | WSTG-SESS-10 |
| JWT Using alg:none — Signature Verification Bypass | Critical | Session Management | 9.8 | CWE-347 | WSTG-SESS-10 |
| JWT Token Has No Expiry (exp Claim Missing) | High | Session Management | 7.5 | CWE-613 | WSTG-SESS-10 |
| JWT Uses HS256 Without Expiry — Offline Brute-Force Risk | High | Session Management | 7.5 | CWE-327 | WSTG-SESS-10 |
| JWT Token Lifetime Is ${days} Days — Excessive | Medium | Session Management | 5.3 | CWE-613 | WSTG-SESS-10 |
| Sensitive Data Stored in JWT Payload | Medium | Session Management | 5.3 | CWE-312 | WSTG-SESS-10 |

### `mailTls.ts`

*3 findings · 139 lines · 13 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Mail Server TLS Certificate Expired | High | Mail Transport Security | 7.4 | CWE-324 | WSTG-CRYP-01 |
| Mail Server Does Not Offer STARTTLS | Medium | Mail Transport Security | 5.9 | CWE-319 | WSTG-CRYP-01 |
| Mail Server TLS Certificate Expiring Soon | Low | Mail Transport Security | 3.1 | CWE-324 | WSTG-CRYP-01 |

### `nextjsProbe.ts`

*9 findings · 255 lines · 8 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| AWS Access Key ID in __NEXT_DATA__ | Critical | Secret Exposed in Page HTML | 9.8 | CWE-312 | — |
| AWS Secret Access Key in __NEXT_DATA__ | Critical | Secret Exposed in Page HTML | 9.8 | CWE-312 | — |
| GitHub Token in __NEXT_DATA__ | Critical | Secret Exposed in Page HTML | 9.1 | CWE-312 | — |
| Hardcoded Database Connection String in __NEXT_DATA__ | Critical | Secret Exposed in Page HTML | 9.8 | CWE-312 | — |
| Private Key in __NEXT_DATA__ | Critical | Secret Exposed in Page HTML | 10 | CWE-321 | — |
| Stripe Live Secret Key in __NEXT_DATA__ | Critical | Secret Exposed in Page HTML | 9.8 | CWE-312 | — |
| Supabase Service Role Key in __NEXT_DATA__ | Critical | Secret Exposed in Page HTML | 9.8 | CWE-312 | — |
| SendGrid API Key in __NEXT_DATA__ | High | Secret Exposed in Page HTML | 8.1 | CWE-312 | — |
| Slack Token in __NEXT_DATA__ | High | Secret Exposed in Page HTML | 8.1 | CWE-312 | — |

### `pathTraversal.ts`

*1 findings · 195 lines · 4 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Path Traversal / Local File Inclusion (LFI) | Critical | Information Disclosure | 9.8 | CWE-22 | WSTG-AUTHZ-01 |

### `probes-data-config.ts`

*23 findings · 273 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Django Local Settings Exposed | Critical | Credential Exposure | 9.1 | CWE-312 | — |
| Rails Database Config Exposed | Critical | Credential Exposure | 9.8 | CWE-312 | — |
| Rails Secrets File Exposed | Critical | Credential Exposure | 9.8 | CWE-312 | — |
| Configuration File Exposed (config.json) | High | Information Disclosure | 7.5 | CWE-200 | — |
| Dev Environment File Exposed (.env.dev) | High | Credential Exposure | 7.5 | CWE-312 | — |
| Development Environment File Exposed (.env.development) | High | Credential Exposure | 7.5 | CWE-312 | — |
| Docker Compose Config Exposed | High | Information Disclosure | 7.5 | CWE-200 | — |
| IIS Web Configuration Exposed | High | Information Disclosure | 7.5 | CWE-200 | — |
| Laravel Log File Exposed | High | Information Disclosure | 7.5 | CWE-532 | — |
| Local Development Overrides Exposed (.env.development.local) | High | Credential Exposure | 7.5 | CWE-312 | — |
| Apache Server Status Page Exposed | Medium | Information Disclosure | 5.3 | CWE-200 | — |
| CircleCI Configuration Exposed | Medium | Information Disclosure | 5.3 | CWE-200 | — |
| Debug Log File Exposed | Medium | Information Disclosure | 6.5 | CWE-532 | — |
| Dockerfile Exposed | Medium | Information Disclosure | 5.3 | CWE-200 | — |
| Drone CI Configuration Exposed | Medium | Information Disclosure | 5.3 | CWE-200 | — |
| GitLab CI/CD Configuration Exposed | Medium | Information Disclosure | 5.3 | CWE-200 | — |
| Jenkinsfile CI/CD Configuration Exposed | Medium | Information Disclosure | 5.3 | CWE-200 | — |
| Permissive crossdomain.xml Policy | Medium | CORS Misconfiguration | 6.5 | CWE-942 | — |
| Test Environment File Exposed (.env.test) | Medium | Credential Exposure | 5.3 | CWE-312 | — |
| Travis CI Configuration Exposed | Medium | Information Disclosure | 5.3 | CWE-200 | — |
| macOS .DS_Store File Exposed | Low | Information Disclosure | — | CWE-200 | — |
| .gitignore Exposes Sensitive Path Names | Info | Information Disclosure | — | CWE-200 | — |
| Package Manifest Exposed (package.json) | Info | Information Disclosure | — | CWE-200 | — |

### `probes-data-infra.ts`

*14 findings · 148 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| AWS Credentials File Exposed | Critical | Credential Exposure | 9.8 | CWE-312 | — |
| Kubernetes Config File Exposed — Cluster Credentials | Critical | Credential Exposure | 9.8 | CWE-312 | — |
| SSH Private Key Exposed (.ssh/id_rsa) | Critical | Credential Exposure | 10 | CWE-312 | — |
| SSH Private Key Exposed (id_rsa) | Critical | Credential Exposure | 10 | CWE-312 | — |
| Terraform State File Exposed — Infrastructure Secrets | Critical | Credential Exposure | 9.8 | CWE-312 | — |
| Adminer Database Admin Tool Exposed | High | Information Disclosure | 8.1 | CWE-200 | — |
| Bash History File Exposed | High | Information Disclosure | 7.5 | CWE-200 | — |
| phpMyAdmin Database Admin Exposed | High | Information Disclosure | 8.1 | CWE-200 | — |
| npm package-lock.json Exposed | Info | Information Disclosure | — | CWE-200 | — |
| PHP composer.lock Exposed | Info | Information Disclosure | — | CWE-200 | — |
| Python Pipfile.lock Exposed | Info | Information Disclosure | — | CWE-200 | — |
| Python requirements.txt Exposed | Info | Information Disclosure | — | CWE-200 | — |
| Ruby Gemfile.lock Exposed | Info | Information Disclosure | — | CWE-200 | — |
| yarn.lock Dependency Lockfile Exposed | Info | Information Disclosure | — | CWE-200 | — |

### `probes-data-server.ts`

*17 findings · 177 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Apache .htpasswd Password File Exposed | Critical | Credential Exposure | 9.1 | CWE-312 | — |
| Spring Application Properties Exposed (WEB-INF/classes/application.properties) | Critical | Credential Exposure | 9.8 | CWE-312 | — |
| Spring Boot Heap Dump Endpoint Exposed — Full Memory Snapshot | Critical | Credential Exposure | 9.8 | CWE-200 | — |
| Java Web Application Config (WEB-INF/web.xml) Exposed | High | Information Disclosure | 7.5 | CWE-200 | — |
| YAML Configuration File Exposed (config.yaml) | High | Information Disclosure | 7.5 | CWE-200 | — |
| YAML Configuration File Exposed (config.yml) | High | Information Disclosure | 7.5 | CWE-200 | — |
| Apache Server Info Page Exposed | Medium | Information Disclosure | 5.3 | CWE-200 | — |
| Google App Engine Configuration Exposed (app.yaml) | Medium | Information Disclosure | 5.3 | CWE-200 | — |
| Spring Boot Loggers Endpoint Exposed | Medium | Information Disclosure | 5.3 | CWE-200 | — |
| WordPress XML-RPC Enabled — Brute Force Amplification Vector | Medium | Brute Force Protection | 7.5 | CWE-307 | — |
| JetBrains IDE Workspace Config Exposed | Low | Information Disclosure | — | CWE-200 | — |
| Nginx Status Page Exposed | Low | Information Disclosure | — | CWE-200 | — |
| Spring Boot Metrics Endpoint Exposed | Low | Information Disclosure | — | CWE-200 | — |
| VS Code Workspace Settings Exposed | Low | Information Disclosure | — | CWE-200 | — |
| API Documentation Exposed (/api/swagger.json) | Info | Information Disclosure | 0 | CWE-200 | — |
| API v1 Documentation Exposed | Info | Information Disclosure | 0 | CWE-200 | — |
| API v2 Documentation Exposed | Info | Information Disclosure | 0 | CWE-200 | — |

### `probes-data-vcs.ts`

*24 findings · 244 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Backup Archive Exposed | Critical | Source Code Exposure | 9.1 | CWE-552 | — |
| Backup Archive Exposed (.tar.gz) | Critical | Source Code Exposure | 9.1 | CWE-552 | — |
| Backup Environment File Exposed | Critical | Credential Exposure | 9.1 | CWE-312 | — |
| Database Backup Exposed | Critical | Data Exposure | 9.8 | CWE-552 | — |
| Database Dump Exposed | Critical | Data Exposure | 9.8 | CWE-552 | — |
| Database Export Exposed | Critical | Data Exposure | 9.8 | CWE-552 | — |
| Database File Exposed | Critical | Data Exposure | 9.8 | CWE-552 | — |
| Drupal Settings File Exposed | Critical | Credential Exposure | 9.8 | CWE-312 | — |
| Environment File Exposed (.env.local) | Critical | Credential Exposure | 9.8 | CWE-312 | — |
| Environment File Exposed (.env) | Critical | Credential Exposure | 9.8 | CWE-312 | — |
| Git Repository Exposed | Critical | Source Code Exposure | 9.8 | CWE-538 | — |
| Joomla Configuration Exposed | Critical | Credential Exposure | 9.8 | CWE-312 | — |
| PHP Config File Exposed | Critical | Credential Exposure | 9.1 | CWE-312 | — |
| Production Environment File Exposed (.env.production) | Critical | Credential Exposure | 9.8 | CWE-312 | — |
| Spring Boot Actuator /env Exposed | Critical | Credential Exposure | 9.8 | CWE-200 | — |
| Spring Boot Config Properties Exposed | Critical | Credential Exposure | 9.1 | CWE-200 | — |
| WordPress Config File Exposed (wp-config.php) | Critical | Credential Exposure | 9.8 | CWE-312 | — |
| Git Config Exposed | High | Source Code Exposure | 7.5 | CWE-538 | — |
| Mercurial Repository Exposed | High | Source Code Exposure | 7.5 | CWE-538 | — |
| PHP Info Page Exposed | High | Information Disclosure | 7.5 | CWE-200 | — |
| PHP Info Page Exposed (info.php) | High | Information Disclosure | 7.5 | CWE-200 | — |
| Staging Environment File Exposed | High | Credential Exposure | 8.2 | CWE-312 | — |
| SVN Repository Exposed | High | Source Code Exposure | 7.5 | CWE-538 | — |
| Spring Boot Beans Exposed | Medium | Information Disclosure | 5.3 | CWE-200 | — |

### `probesFiles.ts`

*3 findings · 266 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Directory Listing Enabled | Medium | Information Disclosure | 5.3 | CWE-548 | WSTG-CONF-04 |
| Missing security.txt (RFC 9116) | Info | Information Disclosure | 0 | CWE-205 | — |
| robots.txt Discloses Sensitive Application Paths | Info | Information Disclosure | — | CWE-200 | WSTG-INFO-01 |

### `probesHttp.ts`

*7 findings · 218 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| CORS Misconfiguration — Credentials Allowed from Arbitrary Origin | Critical | CORS Misconfiguration | 9.1 | CWE-942 | WSTG-CONF-07 |
| HTTP CONNECT Method Enabled | Medium | HTTP Security | 6.1 | CWE-441 | WSTG-CONF-06 |
| HTTP TRACE Method Enabled (Cross-Site Tracing) | Medium | HTTP Security | 5.8 | CWE-16 | WSTG-CONF-06 |
| Open Redirect Vulnerability | Medium | Unvalidated Redirects | 6.1 | CWE-601 | WSTG-CLNT-04 |
| Write HTTP Methods Advertised (${dangerousMethods.join(", ")}) | Medium | HTTP Security | 5.3 | CWE-650 | WSTG-CONF-06 |
| X-Frame-Options Header Misconfigured | Medium | UI Security | 4.3 | CWE-1021 | WSTG-CLNT-09 |
| CORS — Origin Reflected Without Credentials | Low | CORS Misconfiguration | 3.7 | CWE-942 | WSTG-CONF-07 |

### `probesPage.ts`

*3 findings · 244 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Flask/Werkzeug Interactive Debugger Exposed (Remote Code Execution) / Verbose Error Pages Expose Internal Application Details | Critical / Medium | Information Disclosure | 10 | — | WSTG-CONF-02 |
| HTTP Traffic Not Redirected to HTTPS | Medium | Transport Security | 5.3 | CWE-319 | WSTG-CONF-07 |
| Rate Limiting Not Advertised in Response Headers | Info | Brute Force Protection | 0 | CWE-307 | WSTG-ATHN-03 |

### `probesSri.ts`

*1 findings · 79 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| External Resources Missing Subresource Integrity (SRI) | Medium | Supply Chain Security | 6.1 | CWE-353 | WSTG-CONF-04 |

### `probesSupabase.ts`

*3 findings · 164 lines · 1 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Supabase Tables Exposed — Row Level Security (RLS) Disabled | Critical | Database Security | 9.8 | CWE-862 | WSTG-ATHZ-01 |
| Supabase Detected — Verify Row Level Security (RLS) | Info | Database Security | 0 | — | WSTG-ATHZ-01 |
| Supabase Public Content Tables Readable Without Authentication | Info | Database Security | 0 | — | WSTG-ATHZ-01 |

### `promptInjectionProbe.ts`

*1 findings · 214 lines · 26 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| LLM Prompt Injection Extracts the System Prompt | Medium | AI Feature Security | 5.3 | CWE-1427 | WSTG-BUSL-01 |

### `raceConditionProbe.ts`

*1 findings · 181 lines · 21 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Race Condition Allows a One-Time Action to Succeed Multiple Times | High | Business Logic | 6.5 | CWE-362 | WSTG-BUSL-03 |

### `recon-data.ts`

*14 findings · 178 lines · 12 tests · emitted by `recon.ts`.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Docker API (unencrypted) Exposed on Port 2375 | Critical | Exposed Service | 10 | CWE-284 | — |
| Elasticsearch Exposed on Port 9200 | Critical | Exposed Service | 9.8 | CWE-284 | — |
| MongoDB Exposed on Port 27017 | Critical | Exposed Service | 10 | CWE-284 | — |
| Redis Exposed on Port 6379 | Critical | Exposed Service | 10 | CWE-284 | — |
| SMB Exposed on Port 445 | Critical | Exposed Service | 10 | CWE-284 | — |
| Telnet Exposed on Port 23 | Critical | Exposed Service | 9.8 | CWE-319 | — |
| CouchDB Exposed on Port 5984 | High | Exposed Service | 7.5 | CWE-284 | — |
| Memcached Exposed on Port 11211 | High | Exposed Service | 8.1 | CWE-284 | — |
| MSSQL Exposed on Port 1433 | High | Exposed Service | 8.1 | CWE-284 | — |
| MySQL Exposed on Port 3306 | High | Exposed Service | 8.1 | CWE-284 | — |
| Oracle DB Exposed on Port 1521 | High | Exposed Service | 8.1 | CWE-284 | — |
| PostgreSQL Exposed on Port 5432 | High | Exposed Service | 8.1 | CWE-284 | — |
| RDP Exposed on Port 3389 | High | Exposed Service | 8.1 | CWE-284 | — |
| Docker API (TLS) Exposed on Port 2376 | Medium | Exposed Service | 5.9 | CWE-284 | — |

### `scanner.ts`

*2 findings · 388 lines · 6 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| ${unrunFamilies.length} check group${unrunFamilies.length > 1 ? "s" : ""} could not be completed | Info | Scan Coverage | — | — | — |
| Browser Rendering Was Not Used | Info | Scan Coverage | — | — | — |

### `scannerCookies.ts`

*6 findings · 205 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Session Cookie Missing Secure Flag | High | Session Management | 6.5 | CWE-614 | WSTG-SESS-02 |
| Session Cookie Missing HttpOnly Flag | Medium | Session Management | 5.3 | CWE-1004 | WSTG-SESS-02 |
| Non-Session Cookie Missing Secure Flag | Low | Session Management | 3.1 | CWE-614 | WSTG-SESS-02 |
| Session Cookie Missing SameSite Attribute | Low | CSRF Protection | 3.1 | CWE-352 | WSTG-SESS-02 |
| Non-Session Cookie Missing SameSite Attribute | Info | CSRF Protection | 2.1 | CWE-352 | WSTG-SESS-02 |
| Non-Session Cookie Readable by JavaScript | Info | Session Management | 2.6 | CWE-1004 | WSTG-SESS-02 |

### `scannerCoverage.ts`

*6 findings · 216 lines · 1 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Active security testing was skipped for this scan | Info | Scan Coverage | — | — | — |
| Scan followed a redirect to a different site | Info | Scan Coverage | — | — | — |
| Scan reached a sign-in page, not the app / The hosting platform answered, not the app | Info | Scan Coverage | — | — | — |
| Scan session expired before the scan finished | Info | Scan Coverage | — | — | — |
| Scan started from an error response | Info | Scan Coverage | — | — | — |
| Scan was intercepted by a bot-protection challenge | Info | Scan Coverage | — | — | — |

### `scannerCspChecks.ts`

*7 findings · 155 lines · 10 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| CSP script-src Contains Wildcard — XSS Protection Bypassed | High | Injection Defense | 7.2 | CWE-79 | WSTG-CONF-12 |
| Missing Content-Security-Policy (CSP) | High | Injection Defense | 7.2 | CWE-79 | WSTG-CONF-12 |
| Content-Security-Policy is report-only (not enforced) | Medium | Injection Defense | 5.3 | CWE-79 | WSTG-CONF-12 |
| CSP Missing object-src 'none' Directive | Medium | Injection Defense | 4.3 | CWE-79 | WSTG-CONF-12 |
| Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src) | Medium | Injection Defense | 5.4 | CWE-79 | WSTG-CONF-12 |
| Content-Security-Policy Allows Inline Styles (unsafe-inline in style-src) | Low | Injection Defense | 3.1 | CWE-79 | WSTG-CONF-12 |
| CSP Missing base-uri Directive | Low | Injection Defense | 3.5 | CWE-79 | WSTG-CONF-12 |

### `scannerHeaderChecks.ts`

*7 findings · 142 lines · 3 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Missing Clickjacking Protection (X-Frame-Options) | Medium | UI Security | 4.3 | CWE-1021 | WSTG-CLNT-09 |
| Missing X-Content-Type-Options: nosniff | Medium | Content Sniffing | 4.3 | CWE-16 | WSTG-CONF-07 |
| Missing Permissions-Policy Header | Low | Browser Feature Control | 2.4 | CWE-16 | WSTG-CONF-07 |
| Missing Referrer-Policy Header | Low | Information Disclosure | 3.1 | CWE-200 | WSTG-CONF-07 |
| Permissive CORS Policy (Wildcard Origin) | Low / Info | CORS Misconfiguration | — | CWE-942 | WSTG-CONF-07 |
| Server Version Disclosure | Info | Information Disclosure | — | CWE-200 | WSTG-INFO-02 |
| X-Powered-By Header Discloses Technology Stack | Info | Information Disclosure | — | CWE-200 | WSTG-INFO-09 |

### `scannerPageChecks.ts`

*2 findings · 56 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Mixed Content (HTTP Resources on HTTPS Page) | Medium / Low | Transport Security | 5.9 | CWE-311 | WSTG-CRYP-01 |
| Missing Cache-Control Headers | Info | Information Disclosure | — | CWE-524 | WSTG-CONF-07 |

### `scannerTransportChecks.ts`

*3 findings · 70 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| No HTTPS / Plaintext HTTP | Critical | Transport Security | 9.1 | CWE-319 | WSTG-CRYP-01 |
| Missing HTTP Strict-Transport-Security (HSTS) | Medium | Transport Security | 5.3 | CWE-523 | WSTG-CONF-07 |
| HSTS max-age Too Short | Low | Transport Security | 3.1 | CWE-523 | WSTG-CONF-07 |

### `secret-pattern-ai.ts`

*5 findings · 62 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Anthropic (Claude) API Key Exposed | Critical | — | 9.8 | CWE-798 | — |
| OpenAI API Key Exposed | Critical | — | 9.8 | CWE-798 | — |
| ElevenLabs API Key Exposed | High | — | 8.1 | CWE-798 | — |
| Replicate API Token Exposed | High | — | 8.1 | CWE-798 | — |
| Resend API Key Exposed | High | — | 8.1 | CWE-798 | — |

### `secret-pattern-generic.ts`

*7 findings · 144 lines · no test file · emitted by `jsScanner.ts`.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Database Connection URL with Credentials Exposed | Critical | Exposed Secrets / Credentials | 10 | CWE-312 | — |
| Secret Environment Variable Leaked in Frontend Bundle | Critical | Exposed Secrets / Credentials | 9.5 | CWE-312 | — |
| Hardcoded Password in Source Code | High | Exposed Secrets / Credentials | 7.5 | CWE-259 | — |
| Hardcoded Secret or Auth Token in Source | Medium | Exposed Secrets / Credentials | 6.5 | CWE-798 | — |
| Internal IP Address Exposed | Low | Exposed Secrets / Credentials | 3.1 | CWE-200 | — |
| API Key in Client Code (verify restrictions) | Info | Exposed Secrets / Credentials | 0 | CWE-798 | — |
| Mapbox Public Token — Restrict to Your Domain | Info | Exposed Secrets / Credentials | 2.6 | CWE-200 | — |

### `secret-pattern-jwt.ts`

*2 findings · 81 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Hardcoded JWT Token in Source | High | — | 8.1 | CWE-798 | — |
| JWT-Shaped Publishable Key in Client Code (verify it is not a credential) | Info | — | 0 | CWE-798 | — |

### `secret-pattern-vendors.ts`

*21 findings · 247 lines · no test file · emitted by `jsScanner.ts`.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| AWS Secret Access Key Exposed | Critical | Exposed Secrets / Credentials | 9.8 | CWE-798 | — |
| GitHub Fine-Grained Access Token Exposed | Critical | Exposed Secrets / Credentials | 9.1 | CWE-798 | — |
| GitHub Personal Access Token Exposed | Critical | Exposed Secrets / Credentials | 9.1 | CWE-798 | — |
| Google OAuth Client Secret Exposed | Critical | Exposed Secrets / Credentials | 9.1 | CWE-798 | — |
| Private Key Exposed in JavaScript | Critical | Exposed Secrets / Credentials | 10 | CWE-321 | — |
| Sentry Auth Token Exposed | Critical | Exposed Secrets / Credentials | 8.5 | CWE-798 | — |
| Sentry Auth Token Exposed (legacy format) | Critical | Exposed Secrets / Credentials | 8.5 | CWE-798 | — |
| Stripe Live Secret Key Exposed | Critical | Exposed Secrets / Credentials | 9.8 | CWE-798 | — |
| Supabase Service Role Key Exposed (sb_secret_) | Critical | Exposed Secrets / Credentials | 10 | CWE-798 | — |
| Supabase Service Role Key Exposed in JavaScript | Critical | Exposed Secrets / Credentials | 10 | CWE-522 | — |
| Mailchimp API Key Exposed | High | Exposed Secrets / Credentials | 7.5 | CWE-798 | — |
| SendGrid API Key Exposed | High | Exposed Secrets / Credentials | 8.1 | CWE-798 | — |
| Slack Bot/OAuth Token Exposed | High | Exposed Secrets / Credentials | 8.1 | CWE-798 | — |
| Stripe Webhook Secret Exposed | High | Exposed Secrets / Credentials | 8.1 | CWE-798 | — |
| Twilio API Key SID and Secret Exposed | High | Exposed Secrets / Credentials | 8.1 | CWE-798 | — |
| Slack Incoming Webhook URL Exposed | Medium | Exposed Secrets / Credentials | 5.3 | CWE-798 | — |
| Stripe Test-Mode Secret Key in Client Code | Medium | Exposed Secrets / Credentials | 5.3 | CWE-798 | — |
| AWS Access Key ID Found in Client Code | Low | Exposed Secrets / Credentials | 3.7 | CWE-200 | — |
| Firebase Configuration Found in Client Code | Info | Exposed Secrets / Credentials | 3.1 | CWE-798 | — |
| Google API Key in Client Code (verify referrer restrictions) | Info | Exposed Secrets / Credentials | 0 | CWE-798 | — |
| Twilio API Key SID Found in Client Code | Info | Exposed Secrets / Credentials | 0 | CWE-200 | — |

### `sourceMaps.ts`

*2 findings · 236 lines · 19 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| JavaScript Source Map Exposed — Full Source Code Accessible / JavaScript Source Map Exposed — Source File Names Only | High / Low | Source Code Exposure | 7.5 | CWE-540 | WSTG-CONF-04 |
| JavaScript Source Map Exposed — Third-Party Library Code | Low | Source Code Exposure | 3.1 | CWE-540 | WSTG-CONF-04 |

### `ssrfProbe.ts`

*1 findings · 200 lines · 7 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Server-Side Request Forgery (SSRF) | Critical | Server-Side Request Forgery | 9.1 | CWE-918 | WSTG-INPV-19 |

### `storageProbe.ts`

*5 findings · 254 lines · 11 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Public Azure Blob Container Listing — '${label}' | High | — | 7.5 | — | — |
| Public GCS Bucket Listing — '${label}' | High | — | 7.5 | — | — |
| Public S3 Bucket Listing — '${label}' | High | — | 7.5 | — | — |
| Public ${provider} Bucket Referenced by This Page — '${label}' | Low | — | 3.7 | — | — |
| Public ${provider} Listing of Static Assets — '${label}' | Info | — | 0 | — | — |

### `structuredData.ts`

*9 findings · 285 lines · 36 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Canonical URL Points to an External Domain | Low | Information Disclosure | 3.1 | CWE-200 | WSTG-CONF-04 |
| Internal Hostname Exposed in Structured Data | Low | Information Disclosure | 3.7 | CWE-200 | WSTG-INFO-05 |
| Social Preview Asset Referenced Over HTTP | Low | Transport Security | 3.1 | CWE-311 | WSTG-CRYP-03 |
| Incomplete Open Graph Metadata | Info | Structured Data | 0 | — | — |
| Malformed JSON-LD Structured Data | Info | Structured Data | 0 | — | — |
| No Structured Data Found | Info | Structured Data | 0 | — | — |
| Page Excluded From Search Indexes | Info | Structured Data | 0 | — | — |
| Structured Data Missing @context or @type | Info | Structured Data | 0 | — | — |
| Twitter Card Metadata Absent | Info | Structured Data | 0 | — | — |

### `subdomain-service-data.ts`

*19 findings · 172 lines · no test file · emitted by `subdomainTakeover.ts`.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| AWS S3 | Critical | DNS Security | 9.1 | CWE-350 | — |
| Azure App Service | Critical | DNS Security | 9.1 | CWE-350 | — |
| Fastly | Critical | DNS Security | 9.1 | CWE-350 | — |
| GitHub Pages | Critical | DNS Security | 9.1 | CWE-350 | — |
| Heroku | Critical | DNS Security | 9.1 | CWE-350 | — |
| Netlify | Critical | DNS Security | 9.1 | CWE-350 | — |
| Vercel | Critical | DNS Security | 9.1 | CWE-350 | — |
| Cargo | High | DNS Security | 8.1 | CWE-350 | — |
| Fly.io | High | DNS Security | 8.1 | CWE-350 | — |
| Ghost Pro | High | DNS Security | 8.1 | CWE-350 | — |
| Pantheon | High | DNS Security | 8.1 | CWE-350 | — |
| Railway | High | DNS Security | 8.1 | CWE-350 | — |
| Readme.io | High | DNS Security | 8.1 | CWE-350 | — |
| Render | High | DNS Security | 8.1 | CWE-350 | — |
| Shopify | High | DNS Security | 8.1 | CWE-350 | — |
| Squarespace | High | DNS Security | 8.1 | CWE-350 | — |
| Surge.sh | High | DNS Security | 8.1 | CWE-350 | — |
| WP Engine | High | DNS Security | 8.1 | CWE-350 | — |
| Tumblr | Medium | DNS Security | 6.5 | CWE-350 | — |

### `supabase-probes.ts`

*2 findings · 104 lines · 7 tests.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Supabase Storage Bucket List Exposed Without Authentication | Medium | Information Disclosure | 5.3 | CWE-200 | WSTG-CONF-04 |
| Supabase Backend Detected | Info | Technology Fingerprint | 0 | — | — |

### `supabase-probes-report.ts`

*7 findings · 234 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| Supabase Service Role Key Exposed in Client-Side Code | Critical | Exposed Secrets / Credentials | 10 | CWE-522 | WSTG-CONF-04 |
| Supabase Tables Accept Unauthenticated Writes | Critical | Broken Access Control | 9.3 | CWE-284 | WSTG-ATHZ-01 |
| Supabase Tables Readable Without Authentication (CVE-2025-48757) | Critical | Broken Access Control | 9.3 | CWE-284 | WSTG-ATHZ-01 |
| Supabase Backend Detected — RLS Appears Configured | Info | Technology Fingerprint | 0 | — | — |
| Supabase Public Content Tables Readable Without Authentication | Info | Information Disclosure | 0 | — | — |
| Supabase Tables Returned Empty Results To Anonymous Requests (Inconclusive) | Info | Broken Access Control | 0 | — | — |
| Supabase Write Access Not Confirmed (Inconclusive Probe Response) | Info | Broken Access Control | 0 | — | — |

### `workerAi.ts`

*2 findings · 100 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| AI analysis could not be completed for this scan | Info | Scan Coverage | — | — | — |
| Written analysis is turned off in your settings | Info | Scan Coverage | — | — | — |

### `workerSideChecks.ts`

*1 findings · 125 lines · no test file.*

| Finding | Severity | Category | CVSS | CWE | WSTG |
|---|---|---|---:|---|---|
| TLS Grade Below A (SSL Labs) | Info | Transport Security | 0 | CWE-326 | — |

## How this was read

Regex over the source, matching the scanner's own approach to HTML. It holds because the
finding literals are uniform; the assumptions are:

- A finding is an object literal carrying `severity:` with one of the five levels.
- Its name comes from `name:` in the same literal, or in a constant it spreads (`...NOTE`) — or `header:`, for the header-gap table whose names are composed at the emit site.
- A ternary severity or name means the check emits two variants (session vs non-session cookies, for example).

Every finding resolved to a name, so none of these currently fails.

