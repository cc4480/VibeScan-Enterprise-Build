# theguardian.com

- Requested: `https://www.theguardian.com`
- Final URL: `https://www.theguardian.com/us`
- HTTP 200, 17 inner page(s) fetched, 17.0s
- 14 findings, 4 above Info
- Risk score 16/100 — grade B

### External Resources Missing Subresource Integrity (SRI)

**Medium** · CWE-353 · CVSS 6.1 · WSTG-CONF-04 · Supply Chain Security

```
<script/link src="https://assets.guim.co.uk/polyfill.io/v3/polyfill.min.js?rum=0&features=es6%2Ces7%2Ces2017%2Ces2018%2Ces2019%2Cdefault-3.6%2CHTMLPictureElement%2CIntersectionObserver%2CIntersectionObserverEntry%2CURLSearchParams%2Cfetch%2CNodeList.prototype.forEach%2Cnavigator.sendBeacon%2Cperformance.now%2CPromise.allSettled&flags=gated&callback=guardianPolyfilled&unknown=polyfill&cacheClear=1" (no integrity= attribute)>
```

### Permissive crossdomain.xml Policy

**Medium** · CWE-942 · CVSS 6.5 · WSTG-CONF-04 · CORS Misconfiguration

```
GET https://www.theguardian.com/crossdomain.xml → HTTP 200 (1,408 bytes)
Content-Type: text/xml; charset=utf-8
```

### Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)

**Medium** · CWE-79 · CVSS 5.4 · WSTG-CONF-12 · Injection Defense

```
GET https://www.theguardian.com/us
Content-Security-Policy: upgrade-insecure-requests; default-src https:; script-src https: 'unsafe-inline' 'unsafe-eval' blob: 'unsafe-inline'; style-src https: 'unsafe-inline'; img-src https: data: blob:; media-src https: data: blob:; font-src 'self' https://assets.guim.co.uk https://pasteup.guim.co.uk https://interactive.guim.co.uk https://dashboard.ophan.co.uk https://cdn.braze.eu data:; connect-src https: wss: blob:; child-src https: blob:; object-src 'none'; base-uri 'none'
(unsafe-inline or unsafe-eval present in script-src — inline script execution is p
```

### Non-Session Cookie Missing Secure Flag

**Low** · CWE-614 · CVSS 3.1 · WSTG-SESS-02 · Session Management

```
Affected cookies: gu_client_ab_tests, gu_v2_mvt_id
```

### Active security testing was skipped for this scan

**Info** · Scan Coverage

```
No verified ownership on record for this domain at scan time.
```

### DNSSEC Not Enabled

**Info** · CWE-350 · DNS Security

```
No DNSKEY records found for www.theguardian.com or theguardian.com (NOERROR (name exists)).
```

### Incomplete Open Graph Metadata

**Info** · CVSS 0 · Structured Data

```
og:title: (absent)
og:description: (absent)
og:image: (absent)
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.theguardian.com/us
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.theguardian.com/us
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.theguardian.com/us
Cross-Origin-Resource-Policy: (header absent from response)
```

### No Structured Data Found

**Info** · CVSS 0 · Structured Data

```
No <script type="application/ld+json"> blocks in https://www.theguardian.com/us
```

### Non-Session Cookie Missing SameSite Attribute

**Info** · CWE-352 · CVSS 2.1 · WSTG-SESS-02 · CSRF Protection

```
Affected cookies: gu_client_ab_tests, gu_client_ab_tests, gu_v2_mvt_id, gu_v2_mvt_id, GU_mvt_id, GU_geo_country, GU_geo_country_region
```

### Non-Session Cookie Readable by JavaScript

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
Affected cookies: gu_client_ab_tests, gu_client_ab_tests, gu_v2_mvt_id, gu_v2_mvt_id, GU_mvt_id, GU_geo_country, GU_geo_country_region
```

### Rate Limiting Not Advertised in Response Headers

**Info** · CWE-307 · CVSS 0 · WSTG-ATHN-03 · Brute Force Protection

```
GET https://www.theguardian.com/us
No rate-limit headers on this response (checked: X-RateLimit-Limit, RateLimit-Limit, Retry-After, and common CDN/WAF infrastructure signals)
This observes the homepage response only, and cannot show whether login or API routes are throttled.
```

