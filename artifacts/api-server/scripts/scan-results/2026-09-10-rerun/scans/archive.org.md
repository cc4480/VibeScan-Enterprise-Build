# archive.org

- Requested: `https://archive.org`
- HTTP 200, 1 inner page(s) fetched, 8.8s
- 15 findings, 6 above Info
- Risk score 36/100 — grade C

### JavaScript Source Map Exposed — Full Source Code Accessible

**High** · CWE-540 · CVSS 7.5 · WSTG-CONF-04 · Source Code Exposure

```
Source map URL: https://archive.org/offshoot_assets/vendor/lit/polyfill-support.js.map
Source files mapped: 3
Full source content (sourcesContent) included.
```

### HTTP Traffic Not Redirected to HTTPS

**Medium** · CWE-319 · CVSS 5.3 · WSTG-CONF-07 · Transport Security

```
GET http://archive.org/ (followed up to 5 redirect hops)
Result: request chain never reached https://archive.org/
HSTS preload list: not preloaded
```

### Missing Clickjacking Protection (X-Frame-Options)

**Medium** · CWE-1021 · CVSS 4.3 · WSTG-CLNT-09 · UI Security

```
GET https://archive.org/
X-Frame-Options: (header absent)
CSP frame-ancestors: (not present in Content-Security-Policy)
```

### Missing X-Content-Type-Options: nosniff

**Medium** · CWE-16 · CVSS 4.3 · WSTG-CONF-07 · Content Sniffing

```
GET https://archive.org/
X-Content-Type-Options: (header absent from response)
```

### Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)

**Medium** · CWE-79 · CVSS 5.4 · WSTG-CONF-12 · Injection Defense

```
GET https://archive.org/
Content-Security-Policy: report-uri https://archive.org/services/csp-report; base-uri 'self'; default-src *; img-src * data: blob:; object-src 'none'; media-src * blob:; connect-src * data: blob:; worker-src 'self' blob:; script-src https://archive.org/offshoot_assets/ https://*.archive.org/offshoot_assets/ https://offshoot.prod.archive.org/offshoot_assets/ https://archive.org/includes/ https://*.archive.org/includes/ https://offshoot.prod.archive.org/includes/ https://archive.org/components/ https://*.archive.org/components/ https://offshoot.prod.archive.org/component
```

### Missing Permissions-Policy Header

**Low** · CWE-16 · CVSS 2.4 · WSTG-CONF-07 · Browser Feature Control

```
GET https://archive.org/
Permissions-Policy: (header absent from response)
```

### Active security testing was skipped for this scan

**Info** · Scan Coverage

```
No verified ownership on record for this domain at scan time.
```

### DNSSEC Not Enabled

**Info** · CWE-350 · DNS Security

```
No DNSKEY records found for archive.org (NOERROR (name exists)).
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
GET https://archive.org/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://archive.org/
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://archive.org/
Cross-Origin-Resource-Policy: (header absent from response)
```

### No Structured Data Found

**Info** · CVSS 0 · Structured Data

```
No <script type="application/ld+json"> blocks in https://archive.org/
```

### Rate Limiting Not Advertised in Response Headers

**Info** · CWE-307 · CVSS 0 · WSTG-ATHN-03 · Brute Force Protection

```
GET https://archive.org/
No rate-limit headers on this response (checked: X-RateLimit-Limit, RateLimit-Limit, Retry-After, and common CDN/WAF infrastructure signals)
This observes the homepage response only, and cannot show whether login or API routes are throttled.
```

### Server Version Disclosure

**Info** · CWE-200 · WSTG-INFO-02 · Information Disclosure

```
GET https://archive.org/
Server: nginx/1.31.3
```

