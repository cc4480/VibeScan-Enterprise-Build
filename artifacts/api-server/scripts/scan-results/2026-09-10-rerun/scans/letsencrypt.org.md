# letsencrypt.org

- Requested: `https://letsencrypt.org`
- HTTP 200, 4 inner page(s) fetched, 30.5s
- 9 findings, 2 above Info
- Risk score 6/100 — grade A

### Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)

**Medium** · CWE-79 · CVSS 5.4 · WSTG-CONF-12 · Injection Defense

```
GET https://letsencrypt.org/
Content-Security-Policy: default-src 'none'; font-src 'self' https://doublethedonation.com https://rsms.me http://rsms.me ; style-src 'self' 'unsafe-inline' https://donorbox.org https://doublethedonation.com https://rsms.me http://rsms.me ; script-src 'unsafe-eval' 'unsafe-inline' 'self' data: https://www.google-analytics.com https://www.googleadservices.com https://www.googletagmanager.com https://cdn.jsdelivr.net http://cdn.jsdelivr.net https://googleads.g.doubleclick.net https://donorbox.org https://doublethedonation.com https://js.stripe.com https://jspm.dev ht
```

### CSP Missing base-uri Directive

**Low** · CWE-79 · CVSS 3.5 · WSTG-CONF-12 · Injection Defense

```
GET https://letsencrypt.org/
Content-Security-Policy: default-src 'none'; font-src 'self' https://doublethedonation.com https://rsms.me http://rsms.me ; style-src 'self' 'unsafe-inline' https://donorbox.org https://doublethedonation.com https://rsms.me http://rsms.me ; script-src 'unsafe-eval' 'unsafe-inline' 'self' data: https://www.google-analytics.com https://www.googleadservices.com https://www.googletagmanager.com https://cdn.jsdelivr.net http://cdn.jsdelivr.net https://googleads.g.doubleclick.net https://donorbox.org https://doublethedonation.com https://js.stripe.com https://jspm.dev ht
```

### Active security testing was skipped for this scan

**Info** · Scan Coverage

```
No verified ownership on record for this domain at scan time.
```

### DNSSEC Not Enabled

**Info** · CWE-350 · DNS Security

```
No DNSKEY records found for letsencrypt.org (NOERROR (name exists)).
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://letsencrypt.org/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://letsencrypt.org/
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://letsencrypt.org/
Cross-Origin-Resource-Policy: (header absent from response)
```

### Rate Limiting Not Advertised in Response Headers

**Info** · CWE-307 · CVSS 0 · WSTG-ATHN-03 · Brute Force Protection

```
GET https://letsencrypt.org/
No rate-limit headers on this response (checked: X-RateLimit-Limit, RateLimit-Limit, Retry-After, and common CDN/WAF infrastructure signals)
This observes the homepage response only, and cannot show whether login or API routes are throttled.
```

### Twitter Card Metadata Absent

**Info** · CVSS 0 · Structured Data

```
twitter:card: (absent)
```

