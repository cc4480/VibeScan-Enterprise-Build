# bbc.co.uk

- Requested: `https://www.bbc.co.uk`
- HTTP 200, 22 inner page(s) fetched, 18.1s
- 10 findings, 5 above Info
- Risk score 31/100 — grade C

### Content-Security-Policy Missing on 3 Internal Routes

**High** · CWE-79 · CVSS 7.2 · WSTG-CONF-12 · Security Header Inconsistency

```
Routes missing Content-Security-Policy:
  • /accessibility/ (crawled)
  • /schedules/p00fzl9m (crawled)
  • /sounds (crawled)
```

### Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)

**Medium** · CWE-79 · CVSS 5.4 · WSTG-CONF-12 · Injection Defense

```
GET https://www.bbc.co.uk/
Content-Security-Policy: default-src 'none'; script-src 'strict-dynamic' 'nonce-5Z+Cfyg0dNKDaVaP7SUPkH68uayQOEv6qWRaIt7ARF5zpaNACU' 'self' 'report-sample' 'unsafe-inline' cdn.syndication.twimg.com connect.facebook.net c.files.bbci.co.uk emp.bbci.co.uk mybbc-analytics.files.bbci.co.uk nav.files.bbci.co.uk news.files.bbci.co.uk platform.twitter.com public.flourish.studio static.bbc.co.uk static.bbci.co.uk static.chartbeat.com static2.chartbeat.com www.bbc.co.uk www.instagram.com www.ons.gov.uk gn-web-assets.api.bbc.com www.google-analytics.com bitesize.files.bbci.co.uk
```

### X-Content-Type-Options Missing on 2 Internal Routes

**Medium** · CWE-16 · CVSS 4.3 · WSTG-CONF-07 · Security Header Inconsistency

```
Routes missing X-Content-Type-Options:
  • /accessibility/ (crawled)
  • /sounds (crawled)
```

### X-Frame-Options / frame-ancestors Missing on 2 Internal Routes

**Medium** · CWE-1021 · CVSS 4.3 · WSTG-CLNT-09 · Security Header Inconsistency

```
Routes missing X-Frame-Options / frame-ancestors:
  • /accessibility/ (crawled)
  • /sounds (crawled)
```

### Referrer-Policy Missing on 3 Internal Routes

**Low** · CWE-200 · CVSS 3.1 · WSTG-CONF-07 · Security Header Inconsistency

```
Routes missing Referrer-Policy:
  • /accessibility/ (crawled)
  • /schedules/p00fzl9m (crawled)
  • /sounds (crawled)
```

### Active security testing was skipped for this scan

**Info** · Scan Coverage

```
No verified ownership on record for this domain at scan time.
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.bbc.co.uk/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.bbc.co.uk/
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.bbc.co.uk/
Cross-Origin-Resource-Policy: (header absent from response)
```

### Rate Limiting Not Advertised in Response Headers

**Info** · CWE-307 · CVSS 0 · WSTG-ATHN-03 · Brute Force Protection

```
GET https://www.bbc.co.uk/
No rate-limit headers on this response (checked: X-RateLimit-Limit, RateLimit-Limit, Retry-After, and common CDN/WAF infrastructure signals)
This observes the homepage response only, and cannot show whether login or API routes are throttled.
```

