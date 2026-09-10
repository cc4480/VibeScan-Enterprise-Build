# dropbox.com

- Requested: `https://www.dropbox.com`
- HTTP 200, 11 inner page(s) fetched, 16.2s
- 12 findings, 4 above Info
- Risk score 12/100 — grade B

### External Resources Missing Subresource Integrity (SRI)

**Medium** · CWE-353 · CVSS 6.1 · WSTG-CONF-04 · Supply Chain Security

```
<script/link src="https://cfl.dropboxstatic.com/static/atlas/warp/warp_page_edison_rspb_fallback/e_metaserver__static__js__warp__warp_page_edison-vflX9Cd3m.js" (no integrity= attribute)>
```

### Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)

**Medium** · CWE-79 · CVSS 5.4 · WSTG-CONF-12 · Injection Defense

```
GET https://www.dropbox.com/
Content-Security-Policy: base-uri 'self'; child-src https://www.dropbox.com/static/serviceworker/ blob:; connect-src https://* ws://127.0.0.1:*/ws blob: wss://dsimports.dropbox.com/; default-src 'none'; font-src 'self' data: https://*; form-action 'self' https://www.dropbox.com/ https://dl-web.dropbox.com/ https://photos.dropbox.com/ https://paper.dropbox.com/ https://showcase.dropbox.com/ https://www.hellofax.com/ https://app.hellofax.com/ https://www.hellosign.com/ https://app.hellosign.com/ https://docsend.com/ https://www.docsend.com/ https://help.dropbox.com/
```

### Missing Permissions-Policy Header

**Low** · CWE-16 · CVSS 2.4 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.dropbox.com/
Permissions-Policy: (header absent from response)
```

### Non-Session Cookie Missing Secure Flag

**Low** · CWE-614 · CVSS 3.1 · WSTG-SESS-02 · Session Management

```
Affected cookie: locale
```

### Active security testing was skipped for this scan

**Info** · Scan Coverage

```
No verified ownership on record for this domain at scan time.
```

### DNSSEC Not Enabled

**Info** · CWE-350 · DNS Security

```
No DNSKEY records found for www.dropbox.com or dropbox.com (NOERROR (name exists)).
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.dropbox.com/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.dropbox.com/
Cross-Origin-Resource-Policy: (header absent from response)
```

### Non-Session Cookie Missing SameSite Attribute

**Info** · CWE-352 · CVSS 2.1 · WSTG-SESS-02 · CSRF Protection

```
Affected cookie: locale
```

### Non-Session Cookie Readable by JavaScript

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
Affected cookie: locale
```

### Rate Limiting Not Advertised in Response Headers

**Info** · CWE-307 · CVSS 0 · WSTG-ATHN-03 · Brute Force Protection

```
GET https://www.dropbox.com/
No rate-limit headers on this response (checked: X-RateLimit-Limit, RateLimit-Limit, Retry-After, and common CDN/WAF infrastructure signals)
This observes the homepage response only, and cannot show whether login or API routes are throttled.
```

### Twitter Card Metadata Absent

**Info** · CVSS 0 · Structured Data

```
twitter:card: (absent)
```

