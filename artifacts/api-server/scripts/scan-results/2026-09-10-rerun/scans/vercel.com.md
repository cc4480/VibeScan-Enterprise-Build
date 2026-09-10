# vercel.com

- Requested: `https://vercel.com`
- HTTP 200, 26 inner page(s) fetched, 17.1s
- 17 findings, 8 above Info
- Risk score 42/100 — grade C

### Content-Security-Policy Missing on 8 Internal Routes

**High** · CWE-79 · CVSS 7.2 · WSTG-CONF-12 · Security Header Inconsistency

```
Routes missing Content-Security-Policy:
  • /home (crawled)
  • /ai-sdk (crawled)
  • /ai-gateway (crawled)
  • /sandbox (crawled)
  • /passport (crawled)
  • /connect (crawled)
  … and 2 more
```

### CSP Missing object-src 'none' Directive

**Medium** · CWE-79 · CVSS 4.3 · WSTG-CONF-12 · Injection Defense

```
GET https://vercel.com/
Content-Security-Policy: default-src 'self' vercel.com *.vercel.com assets.vercel.com *.vercel.sh vercel.live wss://*.vercel.com *.codesandbox.io localhost:* chrome-extension://* https://www.youtube-nocookie.com https://risk.clearbit.com https://react-tweet.vercel.app/*;script-src 'self' 'unsafe-eval' 'unsafe-inline' 'inline-speculation-rules' https://snap.licdn.com https://www.youtube.com cdn.vercel-insights.com va.vercel-scripts.com vercel.com *.vercel.com assets.vercel.com *.vercel.sh vercel.live wss://*.vercel.com *.codesandbox.io localhost:* chrome-extension://* ht
```

### Exposed API Documentation — OpenAPI JSON spec at /openapi.json

**Medium** · CWE-200 · CVSS 5.3 · WSTG-CONF-02 · Information Disclosure

```
GET https://vercel.com/openapi.json
HTTP 200 — OpenAPI JSON spec confirmed (spec structure validated)
```

### Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)

**Medium** · CWE-79 · CVSS 5.4 · WSTG-CONF-12 · Injection Defense

```
GET https://vercel.com/
Content-Security-Policy: default-src 'self' vercel.com *.vercel.com assets.vercel.com *.vercel.sh vercel.live wss://*.vercel.com *.codesandbox.io localhost:* chrome-extension://* https://www.youtube-nocookie.com https://risk.clearbit.com https://react-tweet.vercel.app/*;script-src 'self' 'unsafe-eval' 'unsafe-inline' 'inline-speculation-rules' https://snap.licdn.com https://www.youtube.com cdn.vercel-insights.com va.vercel-scripts.com vercel.com *.vercel.com assets.vercel.com *.vercel.sh vercel.live wss://*.vercel.com *.codesandbox.io localhost:* chrome-extension://* ht
```

### X-Content-Type-Options Missing on 8 Internal Routes

**Medium** · CWE-16 · CVSS 4.3 · WSTG-CONF-07 · Security Header Inconsistency

```
Routes missing X-Content-Type-Options:
  • /home (crawled)
  • /ai-sdk (crawled)
  • /ai-gateway (crawled)
  • /sandbox (crawled)
  • /passport (crawled)
  • /connect (crawled)
  … and 2 more
```

### X-Frame-Options / frame-ancestors Missing on 8 Internal Routes

**Medium** · CWE-1021 · CVSS 4.3 · WSTG-CLNT-09 · Security Header Inconsistency

```
Routes missing X-Frame-Options / frame-ancestors:
  • /home (crawled)
  • /ai-sdk (crawled)
  • /ai-gateway (crawled)
  • /sandbox (crawled)
  • /passport (crawled)
  • /connect (crawled)
  … and 2 more
```

### CSP Missing base-uri Directive

**Low** · CWE-79 · CVSS 3.5 · WSTG-CONF-12 · Injection Defense

```
GET https://vercel.com/
Content-Security-Policy: default-src 'self' vercel.com *.vercel.com assets.vercel.com *.vercel.sh vercel.live wss://*.vercel.com *.codesandbox.io localhost:* chrome-extension://* https://www.youtube-nocookie.com https://risk.clearbit.com https://react-tweet.vercel.app/*;script-src 'self' 'unsafe-eval' 'unsafe-inline' 'inline-speculation-rules' https://snap.licdn.com https://www.youtube.com cdn.vercel-insights.com va.vercel-scripts.com vercel.com *.vercel.com assets.vercel.com *.vercel.sh vercel.live wss://*.vercel.com *.codesandbox.io localhost:* chrome-extension://* ht
```

### Referrer-Policy Missing on 8 Internal Routes

**Low** · CWE-200 · CVSS 3.1 · WSTG-CONF-07 · Security Header Inconsistency

```
Routes missing Referrer-Policy:
  • /home (crawled)
  • /ai-sdk (crawled)
  • /ai-gateway (crawled)
  • /sandbox (crawled)
  • /passport (crawled)
  • /connect (crawled)
  … and 2 more
```

### Active security testing was skipped for this scan

**Info** · Scan Coverage

```
No verified ownership on record for this domain at scan time.
```

### DNSSEC Not Enabled

**Info** · CWE-350 · DNS Security

```
No DNSKEY records found for vercel.com (NOERROR (name exists)).
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://vercel.com/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://vercel.com/
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://vercel.com/
Cross-Origin-Resource-Policy: (header absent from response)
```

### Non-Session Cookie Readable by JavaScript

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
Affected cookies: _v-anonymous-id, _v-anonymous-id-renewed
```

### Non-Session Cookie Readable by JavaScript on Inner Page

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
[Direct probe] GET https://vercel.com/admin
Set-Cookie: _v-consent=%7B%22essential%22%3Atrue%2C%22analytics%22%3Atrue%2C%22marketing%22%3Atrue%2C%22functional%22%3Atrue%2C%22version%22%3A1%7D; Path=/; Max-Age=31536000; SameSite=Lax; Secure; Domain=.vercel.com
```

### Rate Limiting Not Advertised in Response Headers

**Info** · CWE-307 · CVSS 0 · WSTG-ATHN-03 · Brute Force Protection

```
GET https://vercel.com/
No rate-limit headers on this response (checked: X-RateLimit-Limit, RateLimit-Limit, Retry-After, and common CDN/WAF infrastructure signals)
This observes the homepage response only, and cannot show whether login or API routes are throttled.
```

### X-Powered-By Header Discloses Technology Stack

**Info** · CWE-200 · WSTG-INFO-09 · Information Disclosure

```
GET https://vercel.com/
X-Powered-By: Next.js, Payload
```

