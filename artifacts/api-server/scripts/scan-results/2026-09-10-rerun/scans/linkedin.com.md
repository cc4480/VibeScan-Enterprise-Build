# linkedin.com

- Requested: `https://www.linkedin.com`
- HTTP 200, 21 inner page(s) fetched, 22.7s
- 16 findings, 7 above Info
- Risk score 15/100 — grade B

### External Resources Missing Subresource Integrity (SRI)

**Medium** · CWE-353 · CVSS 6.1 · WSTG-CONF-04 · Supply Chain Security

```
<script/link src="https://static.licdn.com/aero-v1/sc/h/adw9198j9tbn2slxohhkorxy1" (no integrity= attribute)>
<script/link src="https://static.licdn.com/aero-v1/sc/h/dtrv9swzghlxpyzfyk2gsgbur" (no integrity= attribute)>
```

### Session Cookie Missing HttpOnly Flag

**Medium** · CWE-1004 · CVSS 5.3 · WSTG-SESS-02 · Session Management

```
Affected cookie: JSESSIONID
```

### Content-Security-Policy Allows Inline Styles (unsafe-inline in style-src)

**Low** · CWE-79 · CVSS 3.1 · WSTG-CONF-12 · Injection Defense

```
GET https://www.linkedin.com/
Content-Security-Policy: default-src 'none'; connect-src 'self' *.licdn.com *.linkedin.com cdn.linkedin.oribi.io dpm.demdex.net/id lnkd.demdex.net blob: accounts.google.com/gsi/ linkedin.sc.omtrdc.net/b/ss/ v.clarity.ms/collect *.microsoft.com *.adnxs.com *.tealiumiq.com login.microsoftonline.com bat.bing.com lnkd.tt.omtrdc.net/rest/v1/delivery www.google.com google.com adservice.google.com pagead2.googlesyndication.com td.doubleclick.net www.googletagmanager.com www.googleadservices.com ad.doubleclick.net googleads.g.doubleclick.net ade.googlesyndication.com *.fl
```

### CSP Missing base-uri Directive

**Low** · CWE-79 · CVSS 3.5 · WSTG-CONF-12 · Injection Defense

```
GET https://www.linkedin.com/
Content-Security-Policy: default-src 'none'; connect-src 'self' *.licdn.com *.linkedin.com cdn.linkedin.oribi.io dpm.demdex.net/id lnkd.demdex.net blob: accounts.google.com/gsi/ linkedin.sc.omtrdc.net/b/ss/ v.clarity.ms/collect *.microsoft.com *.adnxs.com *.tealiumiq.com login.microsoftonline.com bat.bing.com lnkd.tt.omtrdc.net/rest/v1/delivery www.google.com google.com adservice.google.com pagead2.googlesyndication.com td.doubleclick.net www.googletagmanager.com www.googleadservices.com ad.doubleclick.net googleads.g.doubleclick.net ade.googlesyndication.com *.fl
```

### Missing Permissions-Policy Header

**Low** · CWE-16 · CVSS 2.4 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.linkedin.com/
Permissions-Policy: (header absent from response)
```

### Missing Referrer-Policy Header

**Low** · CWE-200 · CVSS 3.1 · WSTG-CONF-07 · Information Disclosure

```
GET https://www.linkedin.com/
Referrer-Policy: (header absent from response)
```

### Non-Session Cookie Missing Secure Flag on Inner Page

**Low** · CWE-614 · CVSS 3.1 · WSTG-SESS-02 · Session Management

```
GET https://www.linkedin.com/signup
Set-Cookie: fid=AQGVl9Hrn2H_HAAAAaCNuHQRpyBxEzHIUNVHQIZPcJvYzXNQLEJMnJDUr7cf9crMLzKs-328YsMxkg; Max-Age=604800; Expires=Thu, 17 Sep 2026 23:47:51 GMT; Path=/
```

### Active security testing was skipped for this scan

**Info** · Scan Coverage

```
No verified ownership on record for this domain at scan time.
```

### DNSSEC Not Enabled

**Info** · CWE-350 · DNS Security

```
No DNSKEY records found for www.linkedin.com or linkedin.com (NOERROR (name exists)).
```

### Incomplete Open Graph Metadata

**Info** · CVSS 0 · Structured Data

```
og:title: LinkedIn: Log In or Sign Up
og:description: 1 billion members | Manage your professional identity. Build and engage with your professional network. Access knowledge, insights and opportunities.
og:image: (absent)
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.linkedin.com/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.linkedin.com/
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.linkedin.com/
Cross-Origin-Resource-Policy: (header absent from response)
```

### Non-Session Cookie Readable by JavaScript

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
Affected cookies: lang, bcookie, lidc
```

### Non-Session Cookie Readable by JavaScript on Inner Page

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
GET https://www.linkedin.com/signup
Set-Cookie: fid=AQGVl9Hrn2H_HAAAAaCNuHQRpyBxEzHIUNVHQIZPcJvYzXNQLEJMnJDUr7cf9crMLzKs-328YsMxkg; Max-Age=604800; Expires=Thu, 17 Sep 2026 23:47:51 GMT; Path=/
```

### robots.txt Discloses Sensitive Application Paths

**Info** · CWE-200 · WSTG-INFO-01 · Information Disclosure

```
GET https://www.linkedin.com/robots.txt → HTTP 200
Disallow: /fizzy/admin
Disallow: /fizzy/admin
Disallow: /fizzy/admin
Disallow: /fizzy/admin
Disallow: /fizzy/admin
Disallow: /fizzy/admin
Disallow: /fizzy/admin
Disallow: /fizzy/admin
```

