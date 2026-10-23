# european-union.europa.eu

- Requested: `https://european-union.europa.eu`
- Final URL: `https://european-union.europa.eu/select-language?destination=/node/1`
- HTTP 200, 11 inner page(s) fetched, 21.6s
- 12 findings, 5 above Info
- Risk score 37/100 — grade C

### Missing Content-Security-Policy (CSP)

**High** · CWE-79 · CVSS 7.2 · WSTG-CONF-12 · Injection Defense

```
GET https://european-union.europa.eu/select-language?destination=/node/1
Content-Security-Policy: (header absent from response)
```

### Missing DMARC Record — No Email Authentication Enforcement

**High** · CWE-290 · CVSS 7.5 · Email Security

```
DNS TXT queries: _dmarc.european-union.europa.eu, _dmarc.europa.eu
Status: NXDOMAIN (name does not exist)
No v=DMARC1 record found at the host or any parent domain
```

### External Resources Missing Subresource Integrity (SRI)

**Medium** · CWE-353 · CVSS 6.1 · WSTG-CONF-04 · Supply Chain Security

```
<script/link src="https://ec.europa.eu/wel/surveys/wr_survey01/wr_survey.js" (no integrity= attribute)>
<script/link src="https://webtools.europa.eu/load.js" (no integrity= attribute)>
```

### Missing Permissions-Policy Header

**Low** · CWE-16 · CVSS 2.4 · WSTG-CONF-07 · Browser Feature Control

```
GET https://european-union.europa.eu/select-language?destination=/node/1
Permissions-Policy: (header absent from response)
```

### Missing Referrer-Policy Header

**Low** · CWE-200 · CVSS 3.1 · WSTG-CONF-07 · Information Disclosure

```
GET https://european-union.europa.eu/select-language?destination=/node/1
Referrer-Policy: (header absent from response)
```

### Active security testing was skipped for this scan

**Info** · Scan Coverage

```
No verified ownership on record for this domain at scan time.
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://european-union.europa.eu/select-language?destination=/node/1
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://european-union.europa.eu/select-language?destination=/node/1
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://european-union.europa.eu/select-language?destination=/node/1
Cross-Origin-Resource-Policy: (header absent from response)
```

### Missing security.txt (RFC 9116)

**Info** · CWE-205 · CVSS 0 · Information Disclosure

```
GET https://european-union.europa.eu/.well-known/security.txt → HTTP 429
GET https://european-union.europa.eu/security.txt → HTTP 429
```

### Page Excluded From Search Indexes

**Info** · CVSS 0 · Structured Data

```
<meta name="robots" content="noindex follow">
```

### robots.txt Discloses Sensitive Application Paths

**Info** · CWE-200 · WSTG-INFO-01 · Information Disclosure

```
GET https://european-union.europa.eu/robots.txt → HTTP 200
Disallow: /web.config
Disallow: /admin/
Disallow: /index.php/admin/
```

