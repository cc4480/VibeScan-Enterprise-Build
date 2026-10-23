# netlify.com

- Requested: `https://www.netlify.com`
- HTTP 200, 4 inner page(s) fetched, 9.1s
- 13 findings, 6 above Info
- Risk score 36/100 — grade C

### Missing Content-Security-Policy (CSP)

**High** · CWE-79 · CVSS 7.2 · WSTG-CONF-12 · Injection Defense

```
GET https://www.netlify.com/
Content-Security-Policy: (header absent from response)
```

### Exposed API Documentation — OpenAPI JSON spec at /openapi.json

**Medium** · CWE-200 · CVSS 5.3 · WSTG-CONF-02 · Information Disclosure

```
GET https://www.netlify.com/openapi.json
HTTP 200 — OpenAPI JSON spec confirmed (spec structure validated)
```

### External Resources Missing Subresource Integrity (SRI)

**Medium** · CWE-353 · CVSS 6.1 · WSTG-CONF-04 · Supply Chain Security

```
<script/link src="https://cdn.cookielaw.org/consent/5dec0507-5e89-4bb4-8f2d-0872be7dd9dd/OtAutoBlock.js" (no integrity= attribute)>
<script/link src="https://cdn.cookielaw.org/scripttemplates/otSDKStub.js" (no integrity= attribute)>
<script/link src="https://js.hsforms.net/forms/v2.js" (no integrity= attribute)>
<script/link src="//js.hs-scripts.com/7477936.js" (no integrity= attribute)>
```

### Missing Clickjacking Protection (X-Frame-Options)

**Medium** · CWE-1021 · CVSS 4.3 · WSTG-CLNT-09 · UI Security

```
GET https://www.netlify.com/
X-Frame-Options: (header absent)
CSP frame-ancestors: (not present in Content-Security-Policy)
```

### Missing X-Content-Type-Options: nosniff

**Medium** · CWE-16 · CVSS 4.3 · WSTG-CONF-07 · Content Sniffing

```
GET https://www.netlify.com/
X-Content-Type-Options: (header absent from response)
```

### Missing Referrer-Policy Header

**Low** · CWE-200 · CVSS 3.1 · WSTG-CONF-07 · Information Disclosure

```
GET https://www.netlify.com/
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
No DNSKEY records found for www.netlify.com or netlify.com (NOERROR (name exists)).
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.netlify.com/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.netlify.com/
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.netlify.com/
Cross-Origin-Resource-Policy: (header absent from response)
```

### Missing security.txt (RFC 9116)

**Info** · CWE-205 · CVSS 0 · Information Disclosure

```
GET https://www.netlify.com/.well-known/security.txt → HTTP 404
GET https://www.netlify.com/security.txt → HTTP 404
```

### Rate Limiting Not Advertised in Response Headers

**Info** · CWE-307 · CVSS 0 · WSTG-ATHN-03 · Brute Force Protection

```
GET https://www.netlify.com/
No rate-limit headers on this response (checked: X-RateLimit-Limit, RateLimit-Limit, Retry-After, and common CDN/WAF infrastructure signals)
This observes the homepage response only, and cannot show whether login or API routes are throttled.
```

