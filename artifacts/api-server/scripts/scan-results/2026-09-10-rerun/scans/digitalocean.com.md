# digitalocean.com

- Requested: `https://www.digitalocean.com`
- HTTP 200, 10 inner page(s) fetched, 23.2s
- 12 findings, 4 above Info
- Risk score 12/100 — grade B

### Missing X-Content-Type-Options: nosniff

**Medium** · CWE-16 · CVSS 4.3 · WSTG-CONF-07 · Content Sniffing

```
GET https://www.digitalocean.com/
X-Content-Type-Options: (header absent from response)
```

### Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)

**Medium** · CWE-79 · CVSS 5.4 · WSTG-CONF-12 · Injection Defense

```
GET https://www.digitalocean.com/
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.googletagmanager.com https://segment.digitalocean.com consent.trustarc.com *.trustarc.com https://fast.wistia.com https://fast.wistia.net https://capture.navattic.com https://digitalocean.navattic.com https://boards.greenhouse.io https://*.ondigitalocean.app https://assets.digitalocean.com https://www.google-analytics.com https://*.google-analytics.com https://www.googleadservices.com https://googleads.g.doubleclick.net https://*.amplitude.com https://chall
```

### Missing Permissions-Policy Header

**Low** · CWE-16 · CVSS 2.4 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.digitalocean.com/
Permissions-Policy: (header absent from response)
```

### Missing Referrer-Policy Header

**Low** · CWE-200 · CVSS 3.1 · WSTG-CONF-07 · Information Disclosure

```
GET https://www.digitalocean.com/
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
No DNSKEY records found for www.digitalocean.com or digitalocean.com (NOERROR (name exists)).
```

### Incomplete Open Graph Metadata

**Info** · CVSS 0 · Structured Data

```
og:title: AI-Native Cloud | DigitalOcean
og:description: Run AI products in production with a unified stack for agents, inference, and cloud—built for control, performance, and economics at scale.
og:image: (absent)
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.digitalocean.com/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.digitalocean.com/
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.digitalocean.com/
Cross-Origin-Resource-Policy: (header absent from response)
```

### No Structured Data Found

**Info** · CVSS 0 · Structured Data

```
No <script type="application/ld+json"> blocks in https://www.digitalocean.com/
```

### X-Powered-By Header Discloses Technology Stack

**Info** · CWE-200 · WSTG-INFO-09 · Information Disclosure

```
GET https://www.digitalocean.com/
X-Powered-By: Next.js
```

