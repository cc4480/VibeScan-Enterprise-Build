# wikipedia.org

- Requested: `https://www.wikipedia.org`
- HTTP 200, 0 inner page(s) fetched, 9.4s
- 16 findings, 5 above Info
- Risk score 27/100 — grade C

### Missing Content-Security-Policy (CSP)

**High** · CWE-79 · CVSS 7.2 · WSTG-CONF-12 · Injection Defense

```
GET https://www.wikipedia.org/
Content-Security-Policy: (header absent from response)
```

### Missing Clickjacking Protection (X-Frame-Options)

**Medium** · CWE-1021 · CVSS 4.3 · WSTG-CLNT-09 · UI Security

```
GET https://www.wikipedia.org/
X-Frame-Options: (header absent)
CSP frame-ancestors: (not present in Content-Security-Policy)
```

### Missing X-Content-Type-Options: nosniff

**Medium** · CWE-16 · CVSS 4.3 · WSTG-CONF-07 · Content Sniffing

```
GET https://www.wikipedia.org/
X-Content-Type-Options: (header absent from response)
```

### Missing Permissions-Policy Header

**Low** · CWE-16 · CVSS 2.4 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.wikipedia.org/
Permissions-Policy: (header absent from response)
```

### Missing Referrer-Policy Header

**Low** · CWE-200 · CVSS 3.1 · WSTG-CONF-07 · Information Disclosure

```
GET https://www.wikipedia.org/
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
No DNSKEY records found for www.wikipedia.org or wikipedia.org (NOERROR (name exists)).
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.wikipedia.org/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.wikipedia.org/
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.wikipedia.org/
Cross-Origin-Resource-Policy: (header absent from response)
```

### Non-Session Cookie Missing SameSite Attribute

**Info** · CWE-352 · CVSS 2.1 · WSTG-SESS-02 · CSRF Protection

```
Affected cookies: WMF-Last-Access, WMF-Last-Access-Global, GeoIP
```

### Non-Session Cookie Readable by JavaScript

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
Affected cookies: GeoIP, NetworkProbeLimit
```

### Rate Limiting Not Advertised in Response Headers

**Info** · CWE-307 · CVSS 0 · WSTG-ATHN-03 · Brute Force Protection

```
GET https://www.wikipedia.org/
No rate-limit headers on this response (checked: X-RateLimit-Limit, RateLimit-Limit, Retry-After, and common CDN/WAF infrastructure signals)
This observes the homepage response only, and cannot show whether login or API routes are throttled.
```

### robots.txt Discloses Sensitive Application Paths

**Info** · CWE-200 · WSTG-INFO-01 · Information Disclosure

```
GET https://www.wikipedia.org/robots.txt → HTTP 200
Disallow: /wiki/Wikipedia:Administratoren/Probleme/
Disallow: /wiki/Wikipedia:Adminkandidaturen/
Disallow: /wiki/Wikipedia:Administratoren/Notizen/
Disallow: /wiki/Wikipedia_Diskussion:Adminkandidaturen/
Disallow: /wiki/Wikipedia:Requests_for_adminship/
Disallow: /wiki/Wikipedia%3ARequests_for_adminship/
Disallow: /wiki/Wikipedia:Administratorer
Disallow: /wiki/Wikipedia%3AAdministratorer
```

### Server Version Disclosure

**Info** · CWE-200 · WSTG-INFO-02 · Information Disclosure

```
GET https://www.wikipedia.org/
Server: mw-web.codfw.main-6cccd68dbd-lslft
```

### Twitter Card Metadata Absent

**Info** · CVSS 0 · Structured Data

```
twitter:card: (absent)
```

