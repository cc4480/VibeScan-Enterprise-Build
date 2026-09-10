# google.com

- Requested: `https://google.com`
- Final URL: `https://www.google.com/`
- HTTP 200, 3 inner page(s) fetched, 29.6s
- 15 findings, 6 above Info
- Risk score 18/100 — grade B

### Content-Security-Policy is report-only (not enforced)

**Medium** · CWE-79 · CVSS 5.3 · WSTG-CONF-12 · Injection Defense

```
GET https://www.google.com/
Content-Security-Policy: (absent)
Content-Security-Policy-Report-Only: object-src 'none';base-uri 'self';script-src 'nonce-2_nr4i9fVIrGtnd9Wb3wLA' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/ot
```

### Missing X-Content-Type-Options: nosniff

**Medium** · CWE-16 · CVSS 4.3 · WSTG-CONF-07 · Content Sniffing

```
GET https://www.google.com/
X-Content-Type-Options: (header absent from response)
```

### X-Frame-Options / frame-ancestors Missing on 2 Internal Routes

**Medium** · CWE-1021 · CVSS 4.3 · WSTG-CLNT-09 · Security Header Inconsistency

```
Routes missing X-Frame-Options / frame-ancestors:
  • /intl/en/policies/privacy/ (crawled)
  • /intl/en/policies/terms/ (crawled)
```

### Missing Permissions-Policy Header

**Low** · CWE-16 · CVSS 2.4 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.google.com/
Permissions-Policy: (header absent from response)
```

### Missing Referrer-Policy Header

**Low** · CWE-200 · CVSS 3.1 · WSTG-CONF-07 · Information Disclosure

```
GET https://www.google.com/
Referrer-Policy: (header absent from response)
```

### Non-Session Cookie Missing Secure Flag

**Low** · CWE-614 · CVSS 3.1 · WSTG-SESS-02 · Session Management

```
Affected cookie: NID
```

### Active security testing was skipped for this scan

**Info** · Scan Coverage

```
No verified ownership on record for this domain at scan time.
```

### DNSSEC Not Enabled

**Info** · CWE-350 · DNS Security

```
No DNSKEY records found for www.google.com or google.com (NOERROR (name exists)).
```

### Incomplete Open Graph Metadata

**Info** · CVSS 0 · Structured Data

```
og:title: (absent)
og:description: (absent)
og:image: (absent)
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.google.com/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.google.com/
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.google.com/
Cross-Origin-Resource-Policy: (header absent from response)
```

### No Structured Data Found

**Info** · CVSS 0 · Structured Data

```
No <script type="application/ld+json"> blocks in https://www.google.com/
```

### Non-Session Cookie Missing SameSite Attribute

**Info** · CWE-352 · CVSS 2.1 · WSTG-SESS-02 · CSRF Protection

```
Affected cookie: NID
```

### Non-Session Cookie Readable by JavaScript

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
Affected cookie: __Secure-STRP
```

