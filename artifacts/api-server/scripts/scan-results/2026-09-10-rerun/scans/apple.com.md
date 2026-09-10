# apple.com

- Requested: `https://www.apple.com`
- HTTP 200, 22 inner page(s) fetched, 21.6s
- 14 findings, 5 above Info
- Risk score 13/100 — grade B

### CSP Missing object-src 'none' Directive

**Medium** · CWE-79 · CVSS 4.3 · WSTG-CONF-12 · Injection Defense

```
GET https://www.apple.com/
Content-Security-Policy: default-src 'self' blob: data: *.akamaized.net *.apple.com *.apple-mapkit.com *.cdn-apple.com *.organicfruitapps.com; child-src blob: mailto: embed.music.apple.com embed.podcasts.apple.com https://recyclingprogram.apple.com https://smb.apple.com https://nova.apple.com swdlp.apple.com www.apple.com www.instagram.com platform.twitter.com www.youtube-nocookie.com; img-src 'unsafe-inline' blob: data: *.apple.com *.apple-mapkit.com *.cdn-apple.com *.mzstatic.com; script-src 'unsafe-inline' 'unsafe-eval' blob: *.apple.com *.apple-mapkit.com www.ins
```

### Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)

**Medium** · CWE-79 · CVSS 5.4 · WSTG-CONF-12 · Injection Defense

```
GET https://www.apple.com/
Content-Security-Policy: default-src 'self' blob: data: *.akamaized.net *.apple.com *.apple-mapkit.com *.cdn-apple.com *.organicfruitapps.com; child-src blob: mailto: embed.music.apple.com embed.podcasts.apple.com https://recyclingprogram.apple.com https://smb.apple.com https://nova.apple.com swdlp.apple.com www.apple.com www.instagram.com platform.twitter.com www.youtube-nocookie.com; img-src 'unsafe-inline' blob: data: *.apple.com *.apple-mapkit.com *.cdn-apple.com *.mzstatic.com; script-src 'unsafe-inline' 'unsafe-eval' blob: *.apple.com *.apple-mapkit.com www.ins
```

### CSP Missing base-uri Directive

**Low** · CWE-79 · CVSS 3.5 · WSTG-CONF-12 · Injection Defense

```
GET https://www.apple.com/
Content-Security-Policy: default-src 'self' blob: data: *.akamaized.net *.apple.com *.apple-mapkit.com *.cdn-apple.com *.organicfruitapps.com; child-src blob: mailto: embed.music.apple.com embed.podcasts.apple.com https://recyclingprogram.apple.com https://smb.apple.com https://nova.apple.com swdlp.apple.com www.apple.com www.instagram.com platform.twitter.com www.youtube-nocookie.com; img-src 'unsafe-inline' blob: data: *.apple.com *.apple-mapkit.com *.cdn-apple.com *.mzstatic.com; script-src 'unsafe-inline' 'unsafe-eval' blob: *.apple.com *.apple-mapkit.com www.ins
```

### Missing Permissions-Policy Header

**Low** · CWE-16 · CVSS 2.4 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.apple.com/
Permissions-Policy: (header absent from response)
```

### Non-Session Cookie Missing Secure Flag

**Low** · CWE-614 · CVSS 3.1 · WSTG-SESS-02 · Session Management

```
Affected cookie: geo
```

### Active security testing was skipped for this scan

**Info** · Scan Coverage

```
No verified ownership on record for this domain at scan time.
```

### DNSSEC Not Enabled

**Info** · CWE-350 · DNS Security

```
No DNSKEY records found for www.apple.com or apple.com (NOERROR (name exists)).
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.apple.com/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.apple.com/
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.apple.com/
Cross-Origin-Resource-Policy: (header absent from response)
```

### Non-Session Cookie Missing SameSite Attribute

**Info** · CWE-352 · CVSS 2.1 · WSTG-SESS-02 · CSRF Protection

```
Affected cookie: geo
```

### Non-Session Cookie Readable by JavaScript

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
Affected cookie: geo
```

### Rate Limiting Not Advertised in Response Headers

**Info** · CWE-307 · CVSS 0 · WSTG-ATHN-03 · Brute Force Protection

```
GET https://www.apple.com/
No rate-limit headers on this response (checked: X-RateLimit-Limit, RateLimit-Limit, Retry-After, and common CDN/WAF infrastructure signals)
This observes the homepage response only, and cannot show whether login or API routes are throttled.
```

### Twitter Card Metadata Absent

**Info** · CVSS 0 · Structured Data

```
twitter:card: (absent)
```

