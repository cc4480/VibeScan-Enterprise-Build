# cloudflare.com

- Requested: `https://www.cloudflare.com`
- HTTP 200, 10 inner page(s) fetched, 29.8s
- 8 findings, 4 above Info
- Risk score 30/100 — grade C

### Content-Security-Policy Missing on 9 Internal Routes

**High** · CWE-79 · CVSS 7.2 · WSTG-CONF-12 · Security Header Inconsistency

```
Routes missing Content-Security-Policy:
  • /es-es/ (crawled)
  • /fr-fr/ (crawled)
  • /de-de/ (crawled)
  • /it-it/ (crawled)
  • /pt-br/ (crawled)
  • /zh-cn/ (crawled)
  … and 3 more
```

### Exposed API Documentation — OpenAPI JSON spec at /openapi.json

**Medium** · CWE-200 · CVSS 5.3 · WSTG-CONF-02 · Information Disclosure

```
GET https://www.cloudflare.com/openapi.json
HTTP 200 — OpenAPI JSON spec confirmed (spec structure validated)
```

### External Resources Missing Subresource Integrity (SRI)

**Medium** · CWE-353 · CVSS 6.1 · WSTG-CONF-04 · Supply Chain Security

```
<script/link src="https://ot.www.cloudflare.com/ot/scripttemplates/otSDKStub.js" (no integrity= attribute)>
```

### Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)

**Medium** · CWE-79 · CVSS 5.4 · WSTG-CONF-12 · Injection Defense

```
GET https://www.cloudflare.com/
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://static.cloudflareinsights.com https://static-staging.cloudflareinsights.com https://challenges.cloudflare.com https://*.onetrust.com https://cdn.cookielaw.org https://ot.www.cloudflare.com https://www.googletagmanager.com https://tagmanager.google.com https://www.googleadservices.com https://googleads.g.doubleclick.net https://adservice.google.com https://cdn.bizible.com https://js.adsrvr.org https://*.marketo.net https://platform.twitter.com https://static.ads-t
```

### Active security testing was skipped for this scan

**Info** · Scan Coverage

```
No verified ownership on record for this domain at scan time.
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.cloudflare.com/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Non-Session Cookie Readable by JavaScript

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
Affected cookie: kndctr_8AD56F28618A50850A495FB6_AdobeOrg_identity
```

### Non-Session Cookie Readable by JavaScript on Inner Page

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
GET https://www.cloudflare.com/es-es/
Set-Cookie: _cfms_willow=enable; Max-Age=1209600; path=/; domain=.www.cloudflare.com; SameSite=Strict; Secure
```

