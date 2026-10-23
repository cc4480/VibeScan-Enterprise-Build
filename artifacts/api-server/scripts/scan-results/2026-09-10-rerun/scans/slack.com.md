# slack.com

- Requested: `https://slack.com`
- HTTP 200, 15 inner page(s) fetched, 14.1s
- 10 findings, 4 above Info
- Risk score 26/100 — grade C

### Missing Content-Security-Policy (CSP)

**High** · CWE-79 · CVSS 7.2 · WSTG-CONF-12 · Injection Defense

```
GET https://slack.com/
Content-Security-Policy: (header absent from response)
```

### External Resources Missing Subresource Integrity (SRI)

**Medium** · CWE-353 · CVSS 6.1 · WSTG-CONF-04 · Supply Chain Security

```
<script/link src="https://cdn.cookielaw.org/scripttemplates/otSDKStub.js" (no integrity= attribute)>
<script/link src="https://reveal.clearbit.com/v1/companies/reveal?variable=reveal&amp;authorization=pk_7144fadb90a8fdd9c89e1395ff4171a3" (no integrity= attribute)>
<script/link src="https://d34u8crftukxnk.cloudfront.net/snippets/11179690159.js" (no integrity= attribute)>
```

### Missing X-Content-Type-Options: nosniff

**Medium** · CWE-16 · CVSS 4.3 · WSTG-CONF-07 · Content Sniffing

```
GET https://slack.com/
X-Content-Type-Options: (header absent from response)
```

### Missing Permissions-Policy Header

**Low** · CWE-16 · CVSS 2.4 · WSTG-CONF-07 · Browser Feature Control

```
GET https://slack.com/
Permissions-Policy: (header absent from response)
```

### Active security testing was skipped for this scan

**Info** · Scan Coverage

```
No verified ownership on record for this domain at scan time.
```

### Missing Cache-Control Headers

**Info** · CWE-524 · WSTG-CONF-07 · Information Disclosure

```
GET https://slack.com/
Cache-Control: (header absent)
Pragma: (header absent)
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://slack.com/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://slack.com/
Cross-Origin-Resource-Policy: (header absent from response)
```

### Non-Session Cookie Readable by JavaScript

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
Affected cookies: utm, b, x
```

### Rate Limiting Not Advertised in Response Headers

**Info** · CWE-307 · CVSS 0 · WSTG-ATHN-03 · Brute Force Protection

```
GET https://slack.com/
No rate-limit headers on this response (checked: X-RateLimit-Limit, RateLimit-Limit, Retry-After, and common CDN/WAF infrastructure signals)
This observes the homepage response only, and cannot show whether login or API routes are throttled.
```

