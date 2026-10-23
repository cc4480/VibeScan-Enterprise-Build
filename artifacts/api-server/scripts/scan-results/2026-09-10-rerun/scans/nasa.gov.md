# nasa.gov

- Requested: `https://www.nasa.gov`
- HTTP 200, 3 inner page(s) fetched, 16.9s
- 12 findings, 6 above Info
- Risk score 28/100 — grade C

### Missing Content-Security-Policy (CSP)

**High** · CWE-79 · CVSS 7.2 · WSTG-CONF-12 · Injection Defense

```
GET https://www.nasa.gov/
Content-Security-Policy: (header absent from response)
```

### External Resources Missing Subresource Integrity (SRI)

**Medium** · CWE-353 · CVSS 6.1 · WSTG-CONF-04 · Supply Chain Security

```
<script/link src="https://dap.digitalgov.gov/Universal-Federated-Analytics-Min.js?agency=NASA&#038;pga4=G-82GWVTTXCZ" (no integrity= attribute)>
<script/link src="https://cdn.parsely.com/keys/nasa.gov/p.js?ver=3.23.6" (no integrity= attribute)>
```

### Missing X-Content-Type-Options: nosniff

**Medium** · CWE-16 · CVSS 4.3 · WSTG-CONF-07 · Content Sniffing

```
GET https://www.nasa.gov/
X-Content-Type-Options: (header absent from response)
```

### Missing Permissions-Policy Header

**Low** · CWE-16 · CVSS 2.4 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.nasa.gov/
Permissions-Policy: (header absent from response)
```

### Missing Referrer-Policy Header

**Low** · CWE-200 · CVSS 3.1 · WSTG-CONF-07 · Information Disclosure

```
GET https://www.nasa.gov/
Referrer-Policy: (header absent from response)
```

### SPF Record Exceeds DNS Lookup Limit

**Low** · CWE-290 · Email Security

```
TXT record: v=spf1 include:_spf-4a.nasa.gov include:_spf-4b.nasa.gov include:_spf-4c.nasa.gov include:_spf-4d.nasa.gov include:_spf-4g.nasa.gov include:_spf-4m.nasa.gov include:_spf-4x.nasa.gov include:_spf-6a.nasa.gov include:spf.protection.outlook.com -all
Estimated DNS lookups: ~9
```

### Active security testing was skipped for this scan

**Info** · Scan Coverage

```
No verified ownership on record for this domain at scan time.
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.nasa.gov/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.nasa.gov/
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.nasa.gov/
Cross-Origin-Resource-Policy: (header absent from response)
```

### Missing security.txt (RFC 9116)

**Info** · CWE-205 · CVSS 0 · Information Disclosure

```
GET https://www.nasa.gov/.well-known/security.txt → HTTP 404
GET https://www.nasa.gov/security.txt → HTTP 404
```

### Rate Limiting Not Advertised in Response Headers

**Info** · CWE-307 · CVSS 0 · WSTG-ATHN-03 · Brute Force Protection

```
GET https://www.nasa.gov/
No rate-limit headers on this response (checked: X-RateLimit-Limit, RateLimit-Limit, Retry-After, and common CDN/WAF infrastructure signals)
This observes the homepage response only, and cannot show whether login or API routes are throttled.
```

