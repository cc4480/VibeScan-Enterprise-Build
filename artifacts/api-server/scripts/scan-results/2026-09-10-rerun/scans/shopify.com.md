# shopify.com

- Requested: `https://www.shopify.com`
- HTTP 200, 22 inner page(s) fetched, 17.1s
- 12 findings, 4 above Info
- Risk score 22/100 — grade B

### Missing Content-Security-Policy (CSP)

**High** · CWE-79 · CVSS 7.2 · WSTG-CONF-12 · Injection Defense

```
GET https://www.shopify.com/
Content-Security-Policy: (header absent from response)
```

### Missing Clickjacking Protection (X-Frame-Options)

**Medium** · CWE-1021 · CVSS 4.3 · WSTG-CLNT-09 · UI Security

```
GET https://www.shopify.com/
X-Frame-Options: (header absent)
CSP frame-ancestors: (not present in Content-Security-Policy)
```

### Missing Permissions-Policy Header

**Low** · CWE-16 · CVSS 2.4 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.shopify.com/
Permissions-Policy: (header absent from response)
```

### Missing Referrer-Policy Header

**Low** · CWE-200 · CVSS 3.1 · WSTG-CONF-07 · Information Disclosure

```
GET https://www.shopify.com/
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
No DNSKEY records found for www.shopify.com or shopify.com (NOERROR (name exists)).
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.shopify.com/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.shopify.com/
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.shopify.com/
Cross-Origin-Resource-Policy: (header absent from response)
```

### Missing security.txt (RFC 9116)

**Info** · CWE-205 · CVSS 0 · Information Disclosure

```
GET https://www.shopify.com/.well-known/security.txt → no response
GET https://www.shopify.com/security.txt → HTTP 404
```

### Non-Session Cookie Readable by JavaScript

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
Affected cookie: _shopify_essential_
```

### robots.txt Discloses Sensitive Application Paths

**Info** · CWE-200 · WSTG-INFO-01 · Information Disclosure

```
GET https://www.shopify.com/robots.txt → HTTP 200
Disallow: */stock-photos/admin
Disallow: */store/admin
Disallow: /*/admin/
```

