# paypal.com

- Requested: `https://www.paypal.com`
- Final URL: `https://www.paypal.com/us/home`
- HTTP 200, 17 inner page(s) fetched, 31.5s
- 12 findings, 4 above Info
- Risk score 16/100 — grade B

### External Resources Missing Subresource Integrity (SRI)

**Medium** · CWE-353 · CVSS 6.1 · WSTG-CONF-04 · Supply Chain Security

```
<script/link src="https://www.paypalobjects.com/webcaptcha/ngrlCaptcha.min.js" (no integrity= attribute)>
<script/link src="https://www.paypalobjects.com/globalnav/js/main-CH85OB_2.js" (no integrity= attribute)>
<script/link src="https://www.paypalobjects.com/ppcmsnodeweb/pp-com-components/pp-com-components-B7ISRYOV.js" (no integrity= attribute)>
<script/link src="https://www.paypalobjects.com/ppcmsnodeweb/pp-com-components/datadog-Db9jLZ1x.js" (no integrity= attribute)>
<script/link src="https://www.paypalobjects.com/martech/tm/paypal/gtm-bootstrap.js" (no integrity= attribute)>
```

### Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)

**Medium** · CWE-79 · CVSS 5.4 · WSTG-CONF-12 · Injection Defense

```
GET https://www.paypal.com/us/home
Content-Security-Policy: default-src 'self' https://*.paypal.com https://*.paypalobjects.com 'unsafe-inline'; style-src 'self' https://*.paypal.com https://*.paypalobjects.com 'unsafe-inline'; script-src 'nonce-MzVmY2JkODUtYTE4OS00OWJlLWI4ZDEtZWVlNDM4OWZkMjg0' 'self' 'unsafe-inline' https://*.paypal.com https://*.paypalobjects.com https://ad.doubleclick.net https://ade.googlesyndication.com https://adservice.google.com https://analytics.tiktok.com https://connect.facebook.net https://googleads.g.doubleclick.net https://googletagmanager.com https://pagead2.goo
```

### X-Frame-Options / frame-ancestors Missing on 5 Internal Routes

**Medium** · CWE-1021 · CVSS 4.3 · WSTG-CLNT-09 · Security Header Inconsistency

```
Routes missing X-Frame-Options / frame-ancestors:
  • /us/digital-wallet/send-receive-money/giving (crawled)
  • /us/digital-wallet/send-receive-money/start-selling (crawled)
  • /us/digital-wallet/manage-money (crawled)
  • /us/digital-wallet/ways-to-pay/add-payment-method (crawled)
  • /us/digital-wallet/manage-money/direct-deposit (crawled)
```

### Missing Referrer-Policy Header

**Low** · CWE-200 · CVSS 3.1 · WSTG-CONF-07 · Information Disclosure

```
GET https://www.paypal.com/us/home
Referrer-Policy: (header absent from response)
```

### Active security testing was skipped for this scan

**Info** · Scan Coverage

```
No verified ownership on record for this domain at scan time.
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.paypal.com/us/home
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.paypal.com/us/home
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.paypal.com/us/home
Cross-Origin-Resource-Policy: (header absent from response)
```

### Non-Session Cookie Missing SameSite Attribute

**Info** · CWE-352 · CVSS 2.1 · WSTG-SESS-02 · CSRF Protection

```
Affected cookies: LANG, ts, ts_c
```

### Non-Session Cookie Readable by JavaScript

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
Affected cookie: ts_c
```

### Non-Session Cookie Readable by JavaScript on Inner Page

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
GET https://www.paypal.com/us/digital-wallet/send-receive-money/giving
Set-Cookie: enforce_policy=gdpr_v2.1; Max-Age=31536000; Domain=.paypal.com; Path=/; Expires=Fri, 10 Sep 2027 23:50:59 GMT; Secure; SameSite=None
```

### Rate Limiting Not Advertised in Response Headers

**Info** · CWE-307 · CVSS 0 · WSTG-ATHN-03 · Brute Force Protection

```
GET https://www.paypal.com/us/home
No rate-limit headers on this response (checked: X-RateLimit-Limit, RateLimit-Limit, Retry-After, and common CDN/WAF infrastructure signals)
This observes the homepage response only, and cannot show whether login or API routes are throttled.
```

