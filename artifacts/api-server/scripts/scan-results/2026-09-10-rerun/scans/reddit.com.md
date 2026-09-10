# reddit.com

- Requested: `https://www.reddit.com`
- HTTP 200, 14 inner page(s) fetched, 18.5s
- 17 findings, 6 above Info
- Risk score 24/100 — grade B

### Content-Security-Policy Missing on 8 Internal Routes

**High** · CWE-79 · CVSS 7.2 · WSTG-CONF-12 · Security Header Inconsistency

```
Routes missing Content-Security-Policy:
  • /administrator (probed)
  • /live (probed)
  • /login (probed)
  • /auth (probed)
  • /signin (probed)
  • /dashboard (probed)
  … and 2 more
```

### Session Cookie Missing HttpOnly Flag on Inner Page

**Medium** · CWE-1004 · CVSS 5.3 · WSTG-SESS-02 · Session Management

```
[Direct probe] GET https://www.reddit.com/live
Set-Cookie: session_tracker=fmgibeanjhhpoepdmr.0.1789084283985.Z0FBQUFBQnFvMEo4RU9BS3VKcVBlWjd3S3FGMkFycm14R3Utb1h5OVFTSXVYUjg0cl9XOUNRbHByaUh6RnFrOWlWZE4xQ1UzTnlrbDlkM1p2SXdNUW9XVGNBY0NGNmNJWWlIeWJXbTZjd3l4MFN2OEg1QXBpTUM1a0I2LWd5S2hiZzdVTzlZY3k4VTM; Domain=reddit.com; Max-Age=7199; Path=/; expires=Fri, 11-Sep-2026 01:51:24 GMT; secure; SameSite=None; Secure
```

### Content-Security-Policy Allows Inline Styles (unsafe-inline in style-src)

**Low** · CWE-79 · CVSS 3.1 · WSTG-CONF-12 · Injection Defense

```
GET https://www.reddit.com/
Content-Security-Policy: default-src 'none'; script-src 'nonce-e106cb61-2d32-4da3-8ac2-4f915c5762a2'; style-src 'unsafe-inline'; img-src https://www.redditstatic.com; form-action 'self';
(unsafe-inline in style-src only — script-src is clean, no JS execution risk)
```

### CSP Missing base-uri Directive

**Low** · CWE-79 · CVSS 3.5 · WSTG-CONF-12 · Injection Defense

```
GET https://www.reddit.com/
Content-Security-Policy: default-src 'none'; script-src 'nonce-e106cb61-2d32-4da3-8ac2-4f915c5762a2'; style-src 'unsafe-inline'; img-src https://www.redditstatic.com; form-action 'self';
(base-uri directive absent)
```

### Missing Permissions-Policy Header

**Low** · CWE-16 · CVSS 2.4 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.reddit.com/
Permissions-Policy: (header absent from response)
```

### Missing Referrer-Policy Header

**Low** · CWE-200 · CVSS 3.1 · WSTG-CONF-07 · Information Disclosure

```
GET https://www.reddit.com/
Referrer-Policy: (header absent from response)
```

### Active security testing was skipped for this scan

**Info** · Scan Coverage

```
No verified ownership on record for this domain at scan time.
```

### DNSSEC Not Enabled

**Info** · CWE-350 · DNS Security

```
No DNSKEY records found for www.reddit.com or reddit.com (NOERROR (name exists)).
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
GET https://www.reddit.com/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.reddit.com/
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.reddit.com/
Cross-Origin-Resource-Policy: (header absent from response)
```

### No Structured Data Found

**Info** · CVSS 0 · Structured Data

```
No <script type="application/ld+json"> blocks in https://www.reddit.com/
```

### Non-Session Cookie Missing SameSite Attribute

**Info** · CWE-352 · CVSS 2.1 · WSTG-SESS-02 · CSRF Protection

```
Affected cookie: edgebucket
```

### Non-Session Cookie Readable by JavaScript

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
Affected cookie: edgebucket
```

### Non-Session Cookie Readable by JavaScript on Inner Page

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
[Direct probe] GET https://www.reddit.com/live
Set-Cookie: loid=000000002mjjrbzck2.2.1789084283976.Z0FBQUFBQnFvMEo4RzE2MUNyek5Yb3FmeFRtdFQxcTJmMjJEeDZxYUxBQmVpd1VyOElpcG5uY3VHYW83bDU5Ympxbmt3cEk4Si1NV3dmNkFYVkw5eEQtNEVmYm1KS3RBUU94MHB5amM4LU9Ma011ZzhYWVFJYUgtQ2VUX0VBbEF6NmNqakd0eDhoZGU; Domain=reddit.com; Max-Age=63071999; Path=/; expires=Sat, 09-Sep-2028 23:51:24 GMT; secure; SameSite=None; Secure
```

### Non-Session Cookie Readable by JavaScript on Inner Page

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
[Direct probe] GET https://www.reddit.com/live
Set-Cookie: csv=2; Max-Age=63072000; Domain=.reddit.com; Path=/; Secure; SameSite=None
```

