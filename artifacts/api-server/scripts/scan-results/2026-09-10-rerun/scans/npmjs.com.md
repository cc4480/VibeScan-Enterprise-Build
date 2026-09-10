# npmjs.com

- Requested: `https://www.npmjs.com`
- HTTP 200, 1 inner page(s) fetched, 8.8s
- 12 findings, 5 above Info
- Risk score 13/100 — grade B

### External Resources Missing Subresource Integrity (SRI)

**Medium** · CWE-353 · CVSS 6.1 · WSTG-CONF-04 · Supply Chain Security

```
<script/link src="https://fonts.googleapis.com/css?family=Arimo|Poppins:400,600,700&amp;display=swap" (no integrity= attribute)>
```

### Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)

**Medium** · CWE-79 · CVSS 5.4 · WSTG-CONF-12 · Injection Defense

```
GET https://www.npmjs.com/
Content-Security-Policy: connect-src 'self' checkout.stripe.com https://checkout.stripe.com https://billing.stripe.com/session https://api.funcaptcha.com https://api.arkoselabs.com https://api-js.datadome.co https://ct.captcha-delivery.com sentry.io api.github.com www.npmjs.com static-production.npmjs.com;default-src 'none';img-src * data: https://*.stripe.com;script-src 'self' data: 'unsafe-inline' https://checkout.stripe.com/checkout.js https://checkout.stripe.com https://js.stripe.com/v3 https://octocaptcha.com https://ct.captcha-delivery.com https://static-produc
```

### CSP Missing base-uri Directive

**Low** · CWE-79 · CVSS 3.5 · WSTG-CONF-12 · Injection Defense

```
GET https://www.npmjs.com/
Content-Security-Policy: connect-src 'self' checkout.stripe.com https://checkout.stripe.com https://billing.stripe.com/session https://api.funcaptcha.com https://api.arkoselabs.com https://api-js.datadome.co https://ct.captcha-delivery.com sentry.io api.github.com www.npmjs.com static-production.npmjs.com;default-src 'none';img-src * data: https://*.stripe.com;script-src 'self' data: 'unsafe-inline' https://checkout.stripe.com/checkout.js https://checkout.stripe.com https://js.stripe.com/v3 https://octocaptcha.com https://ct.captcha-delivery.com https://static-produc
```

### Missing Permissions-Policy Header

**Low** · CWE-16 · CVSS 2.4 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.npmjs.com/
Permissions-Policy: (header absent from response)
```

### Missing Referrer-Policy Header

**Low** · CWE-200 · CVSS 3.1 · WSTG-CONF-07 · Information Disclosure

```
GET https://www.npmjs.com/
Referrer-Policy: (header absent from response)
```

### Active security testing was skipped for this scan

**Info** · Scan Coverage

```
No verified ownership on record for this domain at scan time.
```

### Incomplete Open Graph Metadata

**Info** · CVSS 0 · Structured Data

```
og:title: (absent)
og:description: (absent)
og:image: https://static-production.npmjs.com/a12c728e90758ccd16976b394b964317.png
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.npmjs.com/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.npmjs.com/
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.npmjs.com/
Cross-Origin-Resource-Policy: (header absent from response)
```

### Missing security.txt (RFC 9116)

**Info** · CWE-205 · CVSS 0 · Information Disclosure

```
GET https://www.npmjs.com/.well-known/security.txt → HTTP 403
GET https://www.npmjs.com/security.txt → HTTP 429
```

### No Structured Data Found

**Info** · CVSS 0 · Structured Data

```
No <script type="application/ld+json"> blocks in https://www.npmjs.com/
```

