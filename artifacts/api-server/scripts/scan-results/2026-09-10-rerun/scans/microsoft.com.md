# microsoft.com

- Requested: `https://www.microsoft.com`
- Final URL: `https://www.microsoft.com/en-us`
- HTTP 200, 2 inner page(s) fetched, 30.7s
- 16 findings, 7 above Info
- Risk score 33/100 — grade C

### Missing Content-Security-Policy (CSP)

**High** · CWE-79 · CVSS 7.2 · WSTG-CONF-12 · Injection Defense

```
GET https://www.microsoft.com/en-us
Content-Security-Policy: (header absent from response)
```

### External Resources Missing Subresource Integrity (SRI)

**Medium** · CWE-353 · CVSS 6.1 · WSTG-CONF-04 · Supply Chain Security

```
<script/link src="https://rum.hlx.page/.rum/@adobe/helix-rum-js@%5E2/dist/micro.js" (no integrity= attribute)>
<script/link src="https://uhf.microsoft.com/statics/20260910.10.32/js/entry.js" (no integrity= attribute)>
<script/link src="https://wcpstatic.microsoft.com/mscc/lib/v2/wcp-consent.js" (no integrity= attribute)>
```

### Missing Clickjacking Protection (X-Frame-Options)

**Medium** · CWE-1021 · CVSS 4.3 · WSTG-CLNT-09 · UI Security

```
GET https://www.microsoft.com/en-us
X-Frame-Options: (header absent)
CSP frame-ancestors: (not present in Content-Security-Policy)
```

### Missing X-Content-Type-Options: nosniff

**Medium** · CWE-16 · CVSS 4.3 · WSTG-CONF-07 · Content Sniffing

```
GET https://www.microsoft.com/en-us
X-Content-Type-Options: (header absent from response)
```

### Missing Permissions-Policy Header

**Low** · CWE-16 · CVSS 2.4 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.microsoft.com/en-us
Permissions-Policy: (header absent from response)
```

### Missing Referrer-Policy Header

**Low** · CWE-200 · CVSS 3.1 · WSTG-CONF-07 · Information Disclosure

```
GET https://www.microsoft.com/en-us
Referrer-Policy: (header absent from response)
```

### Non-Session Cookie Missing Secure Flag on Inner Page

**Low** · CWE-614 · CVSS 3.1 · WSTG-SESS-02 · Session Management

```
GET https://www.microsoft.com/en-us/windows/
Set-Cookie: bStore=Y; expires=Thu, 10-Sep-2026 23:48:43 GMT
```

### Active security testing was skipped for this scan

**Info** · Scan Coverage

```
No verified ownership on record for this domain at scan time.
```

### DNSSEC Not Enabled

**Info** · CWE-350 · DNS Security

```
No DNSKEY records found for www.microsoft.com or microsoft.com (NOERROR (name exists)).
```

### Incomplete Open Graph Metadata

**Info** · CVSS 0 · Structured Data

```
og:title: Microsoft – AI, Cloud, Productivity, Computing, Gaming & Apps
og:description: Explore Microsoft products and services and support for your home or business. Shop Microsoft 365, Copilot, Teams, Xbox, Windows, Azure, Surface and more.
og:image: (absent)
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.microsoft.com/en-us
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.microsoft.com/en-us
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.microsoft.com/en-us
Cross-Origin-Resource-Policy: (header absent from response)
```

### Non-Session Cookie Readable by JavaScript

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
Affected cookie: CAS_PROGRAM
```

### Non-Session Cookie Readable by JavaScript on Inner Page

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
GET https://www.microsoft.com/en-us/windows/
Set-Cookie: bStore=Y; expires=Thu, 10-Sep-2026 23:48:43 GMT
```

### robots.txt Discloses Sensitive Application Paths

**Info** · CWE-200 · WSTG-INFO-01 · Information Disclosure

```
GET https://www.microsoft.com/robots.txt → HTTP 200
Disallow: /wp-admin/post.php
```

