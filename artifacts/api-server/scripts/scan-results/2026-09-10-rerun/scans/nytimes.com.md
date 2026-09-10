# nytimes.com

- Requested: `https://www.nytimes.com`
- HTTP 200, 3 inner page(s) fetched, 30.4s
- 17 findings, 6 above Info
- Risk score 18/100 — grade B

### CSP Missing object-src 'none' Directive

**Medium** · CWE-79 · CVSS 4.3 · WSTG-CONF-12 · Injection Defense

```
GET https://www.nytimes.com/
Content-Security-Policy: upgrade-insecure-requests; default-src data: 'unsafe-inline' 'unsafe-eval' https: nytresource:; script-src data: 'unsafe-inline' 'unsafe-eval' https: blob: nytresource:; style-src data: 'unsafe-inline' https: nytresource:; img-src data: https: blob: android-webview-video-poster: nytresource:; font-src data: https: nytresource:; connect-src data: https: wss: blob: nytresource:; media-src data: https: blob: nytresource:; object-src https:; child-src https: data: blob: nytresource:; form-action https: nytimes: nytcooking: nytxwd:; report-uri h
```

### External Resources Missing Subresource Integrity (SRI)

**Medium** · CWE-353 · CVSS 6.1 · WSTG-CONF-04 · Supply Chain Security

```
<script/link src="https://static01.nyt.com/video-static/betamax/player-BBowVWE5.js" (no integrity= attribute)>
<script/link src="https://static01.nyt.com/video-static/betamax/cover-0.3.28-h8C8He0b.js" (no integrity= attribute)>
<script/link src="https://static01.nyt.com/video-static/betamax/poster-0.3.28-LihBkboI.js" (no integrity= attribute)>
<script/link src="https://static01.nyt.com/video-static/betamax/overlay-controls-0.3.28-BLNvt-8d.js" (no integrity= attribute)>
<script/link src="https://www.googletagmanager.com/gtm.js?id=GTM-P528B3&gtm_auth=tfAzqo1rYDLgYhmTnSjPqw&gtm_preview=env-130&gt
```

### Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)

**Medium** · CWE-79 · CVSS 5.4 · WSTG-CONF-12 · Injection Defense

```
GET https://www.nytimes.com/
Content-Security-Policy: upgrade-insecure-requests; default-src data: 'unsafe-inline' 'unsafe-eval' https: nytresource:; script-src data: 'unsafe-inline' 'unsafe-eval' https: blob: nytresource:; style-src data: 'unsafe-inline' https: nytresource:; img-src data: https: blob: android-webview-video-poster: nytresource:; font-src data: https: nytresource:; connect-src data: https: wss: blob: nytresource:; media-src data: https: blob: nytresource:; object-src https:; child-src https: data: blob: nytresource:; form-action https: nytimes: nytcooking: nytxwd:; report-uri h
```

### CSP Missing base-uri Directive

**Low** · CWE-79 · CVSS 3.5 · WSTG-CONF-12 · Injection Defense

```
GET https://www.nytimes.com/
Content-Security-Policy: upgrade-insecure-requests; default-src data: 'unsafe-inline' 'unsafe-eval' https: nytresource:; script-src data: 'unsafe-inline' 'unsafe-eval' https: blob: nytresource:; style-src data: 'unsafe-inline' https: nytresource:; img-src data: https: blob: android-webview-video-poster: nytresource:; font-src data: https: nytresource:; connect-src data: https: wss: blob: nytresource:; media-src data: https: blob: nytresource:; object-src https:; child-src https: data: blob: nytresource:; form-action https: nytimes: nytcooking: nytxwd:; report-uri h
```

### Missing Referrer-Policy Header

**Low** · CWE-200 · CVSS 3.1 · WSTG-CONF-07 · Information Disclosure

```
GET https://www.nytimes.com/
Referrer-Policy: (header absent from response)
```

### Non-Session Cookie Missing Secure Flag

**Low** · CWE-614 · CVSS 3.1 · WSTG-SESS-02 · Session Management

```
Affected cookies: nyt-gdpr, nyt-geo, nyt-s-present
```

### Active security testing was skipped for this scan

**Info** · Scan Coverage

```
No verified ownership on record for this domain at scan time.
```

### DNSSEC Not Enabled

**Info** · CWE-350 · DNS Security

```
No DNSKEY records found for www.nytimes.com or nytimes.com (NOERROR (name exists)).
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.nytimes.com/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.nytimes.com/
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.nytimes.com/
Cross-Origin-Resource-Policy: (header absent from response)
```

### Missing security.txt (RFC 9116)

**Info** · CWE-205 · CVSS 0 · Information Disclosure

```
GET https://www.nytimes.com/.well-known/security.txt → no response
GET https://www.nytimes.com/security.txt → no response
```

### Non-Session Cookie Missing SameSite Attribute

**Info** · CWE-352 · CVSS 2.1 · WSTG-SESS-02 · CSRF Protection

```
Affected cookies: nyt-gdpr, nyt-geo, nyt-s-present
```

### Non-Session Cookie Readable by JavaScript

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
Affected cookies: nyt-a, datadome, nyt-gdpr, nyt-purr, nyt-geo, nyt.et.dd, datadome, nyt-s-present, nyt-traceid
```

### Rate Limiting Not Advertised in Response Headers

**Info** · CWE-307 · CVSS 0 · WSTG-ATHN-03 · Brute Force Protection

```
GET https://www.nytimes.com/
No rate-limit headers on this response (checked: X-RateLimit-Limit, RateLimit-Limit, Retry-After, and common CDN/WAF infrastructure signals)
This observes the homepage response only, and cannot show whether login or API routes are throttled.
```

### robots.txt Discloses Sensitive Application Paths

**Info** · CWE-200 · WSTG-INFO-01 · Information Disclosure

```
GET https://www.nytimes.com/robots.txt → HTTP 200
Disallow: /athletic/wp/wp-admin/
Disallow: /wirecutter/wp-admin/
```

### Twitter Card Metadata Absent

**Info** · CVSS 0 · Structured Data

```
twitter:card: (absent)
```

