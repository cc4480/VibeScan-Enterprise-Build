# stripe.com

- Requested: `https://stripe.com`
- HTTP 200, 21 inner page(s) fetched, 24.0s
- 10 findings, 3 above Info
- Risk score 7/100 — grade A

### External Resources Missing Subresource Integrity (SRI)

**Medium** · CWE-353 · CVSS 6.1 · WSTG-CONF-04 · Supply Chain Security

```
<script/link src="https://b.stripecdn.com/mkt-ssr-statics/assets/_next/static/KIm4Qs1OubWHytHN%2BpjGfS/Yvbe9P49jxhNP%2BvvN%2B44%3D/_buildManifest.js" (no integrity= attribute)>
<script/link src="https://b.stripecdn.com/mkt-ssr-statics/assets/_next/static/KIm4Qs1OubWHytHN%2BpjGfS/Yvbe9P49jxhNP%2BvvN%2B44%3D/_ssgManifest.js" (no integrity= attribute)>
```

### Content-Security-Policy Allows Inline Styles (unsafe-inline in style-src)

**Low** · CWE-79 · CVSS 3.1 · WSTG-CONF-12 · Injection Defense

```
GET https://stripe.com/
Content-Security-Policy: base-uri 'none'; child-src 'none'; connect-src https://c.increment.com https://c.stripe.dev https://c.stripe.global https://c.stripe.partners blob: https://b.stripecdn.com https://errors.stripe.com https://ext.stripe.com https://r.stripe.com https://stripe-images.s3.us-west-1.amazonaws.com https://stripe.com 'self'; default-src 'none'; font-src https://b.stripecdn.com 'self'; form-action https://stripe.com 'self'; frame-ancestors https://app.contentful.com 'self'; frame-src https://b.stripecdn.com https://js.stripe.com https://support-conversati
```

### Missing Permissions-Policy Header

**Low** · CWE-16 · CVSS 2.4 · WSTG-CONF-07 · Browser Feature Control

```
GET https://stripe.com/
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
No DNSKEY records found for stripe.com (NOERROR (name exists)).
```

### Missing Cache-Control Headers

**Info** · CWE-524 · WSTG-CONF-07 · Information Disclosure

```
GET https://stripe.com/
Cache-Control: (header absent)
Pragma: (header absent)
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://stripe.com/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://stripe.com/
Cross-Origin-Resource-Policy: (header absent from response)
```

### Non-Session Cookie Readable by JavaScript

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
Affected cookie: cid
```

### Rate Limiting Not Advertised in Response Headers

**Info** · CWE-307 · CVSS 0 · WSTG-ATHN-03 · Brute Force Protection

```
GET https://stripe.com/
No rate-limit headers on this response (checked: X-RateLimit-Limit, RateLimit-Limit, Retry-After, and common CDN/WAF infrastructure signals)
This observes the homepage response only, and cannot show whether login or API routes are throttled.
```

