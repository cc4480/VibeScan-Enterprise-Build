# figma.com

- Requested: `https://www.figma.com`
- HTTP 200, 7 inner page(s) fetched, 31.0s
- 10 findings, 4 above Info
- Risk score 12/100 — grade B

### Missing X-Content-Type-Options: nosniff

**Medium** · CWE-16 · CVSS 4.3 · WSTG-CONF-07 · Content Sniffing

```
GET https://www.figma.com/
X-Content-Type-Options: nosniff, nosniff
(must be exactly "nosniff")
```

### Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)

**Medium** · CWE-79 · CVSS 5.4 · WSTG-CONF-12 · Injection Defense

```
GET https://www.figma.com/
Content-Security-Policy: default-src 'self' https://accounts.google.com/gsi/ ; script-src 'self' 'unsafe-eval' 'unsafe-inline' https://platform.twitter.com/js/ https://platform.twitter.com/widgets.js https://player.vimeo.com/api/player.js https://www.youtube.com/iframe_api https://www.youtube.com/s/player/ https://accounts.google.com/gsi/client https://adora-cdn.com/adora-start.js https://decagon.ai ; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com/ https://accounts.google.com/gsi/style ; object-src 'none' ; base-uri 'self' ; font-src 'self' https://fon
```

### Missing Permissions-Policy Header

**Low** · CWE-16 · CVSS 2.4 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.figma.com/
Permissions-Policy: (header absent from response)
```

### Missing Referrer-Policy Header

**Low** · CWE-200 · CVSS 3.1 · WSTG-CONF-07 · Information Disclosure

```
GET https://www.figma.com/
Referrer-Policy: (header absent from response)
```

### Active security testing was skipped for this scan

**Info** · Scan Coverage

```
No verified ownership on record for this domain at scan time.
```

### DMARC Record Missing Aggregate Report Address (rua=)

**Info** · CWE-778 · Email Security

```
TXT record: v=DMARC1; p=quarantine;
```

### DNSSEC Not Enabled

**Info** · CWE-350 · DNS Security

```
No DNSKEY records found for www.figma.com or figma.com (NOERROR (name exists)).
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.figma.com/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.figma.com/
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.figma.com/
Cross-Origin-Resource-Policy: (header absent from response)
```

