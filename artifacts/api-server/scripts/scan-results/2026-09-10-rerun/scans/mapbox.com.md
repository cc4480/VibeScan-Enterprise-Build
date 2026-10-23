# mapbox.com

- Requested: `https://www.mapbox.com`
- HTTP 200, 20 inner page(s) fetched, 15.6s
- 11 findings, 5 above Info
- Risk score 13/100 — grade B

### CSP Missing object-src 'none' Directive

**Medium** · CWE-79 · CVSS 4.3 · WSTG-CONF-12 · Injection Defense

```
GET https://www.mapbox.com/
Content-Security-Policy: frame-ancestors 'self'
(object-src directive absent — plugin content unrestricted)
```

### External Resources Missing Subresource Integrity (SRI)

**Medium** · CWE-353 · CVSS 6.1 · WSTG-CONF-04 · Supply Chain Security

```
<script/link src="https://static-assets.mapbox.com/www/scripts/analytics.js" (no integrity= attribute)>
<script/link src="https://cdn.cookielaw.org/consent/8b2986c7-1b66-4d3e-aa3e-d5851e622616/OtAutoBlock.js" (no integrity= attribute)>
<script/link src="https://cdn.cookielaw.org/scripttemplates/otSDKStub.js" (no integrity= attribute)>
<script/link src="https://www.googletagmanager.com/gtag/js?id=AW-16617866687" (no integrity= attribute)>
<script/link src="https://www.googletagmanager.com/gtag/js?id=G-K0D3QK4GKE" (no integrity= attribute)>
```

### CSP Missing base-uri Directive

**Low** · CWE-79 · CVSS 3.5 · WSTG-CONF-12 · Injection Defense

```
GET https://www.mapbox.com/
Content-Security-Policy: frame-ancestors 'self'
(base-uri directive absent)
```

### Missing Permissions-Policy Header

**Low** · CWE-16 · CVSS 2.4 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.mapbox.com/
Permissions-Policy: (header absent from response)
```

### Missing Referrer-Policy Header

**Low** · CWE-200 · CVSS 3.1 · WSTG-CONF-07 · Information Disclosure

```
GET https://www.mapbox.com/
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
No DNSKEY records found for www.mapbox.com or mapbox.com (NOERROR (name exists)).
```

### Missing Cache-Control Headers

**Info** · CWE-524 · WSTG-CONF-07 · Information Disclosure

```
GET https://www.mapbox.com/
Cache-Control: (header absent)
Pragma: (header absent)
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.mapbox.com/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.mapbox.com/
Cross-Origin-Resource-Policy: (header absent from response)
```

### Missing security.txt (RFC 9116)

**Info** · CWE-205 · CVSS 0 · Information Disclosure

```
GET https://www.mapbox.com/.well-known/security.txt → HTTP 404
GET https://www.mapbox.com/security.txt → HTTP 404
```

