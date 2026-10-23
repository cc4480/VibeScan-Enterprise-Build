# gitlab.com

- Requested: `https://gitlab.com`
- Final URL: `https://about.gitlab.com/`
- HTTP 200, 1 inner page(s) fetched, 5.1s
- 13 findings, 7 above Info
- Risk score 47/100 — grade D

### JavaScript Source Map Exposed — Full Source Code Accessible

**High** · CWE-540 · CVSS 7.5 · WSTG-CONF-04 · Source Code Exposure

```
Source map URL: https://about.gitlab.com/_nuxt/CXEEYWBo.js.map
Source files mapped: 301
Full source content (sourcesContent) included.
```

### Missing Content-Security-Policy (CSP)

**High** · CWE-79 · CVSS 7.2 · WSTG-CONF-12 · Injection Defense

```
GET https://about.gitlab.com/
Content-Security-Policy: (header absent from response)
```

### External Resources Missing Subresource Integrity (SRI)

**Medium** · CWE-353 · CVSS 6.1 · WSTG-CONF-04 · Supply Chain Security

```
<script/link src="https://cdn.cookielaw.org/consent/7f944245-c5cd-4eed-a90e-dd955adfdd08/OtAutoBlock.js" (no integrity= attribute)>
<script/link src="https://cdn.cookielaw.org/scripttemplates/otSDKStub.js" (no integrity= attribute)>
<script/link src="https://geolocation.onetrust.com/cookieconsentpub/v1/geo/location/geofeed" (no integrity= attribute)>
<script/link src="https://cdn.bizible.com/scripts/bizible.js" (no integrity= attribute)>
<script/link src="https://munchkin.marketo.net/munchkin.js" (no integrity= attribute)>
```

### Missing Clickjacking Protection (X-Frame-Options)

**Medium** · CWE-1021 · CVSS 4.3 · WSTG-CLNT-09 · UI Security

```
GET https://about.gitlab.com/
X-Frame-Options: (header absent)
CSP frame-ancestors: (not present in Content-Security-Policy)
```

### Missing X-Content-Type-Options: nosniff

**Medium** · CWE-16 · CVSS 4.3 · WSTG-CONF-07 · Content Sniffing

```
GET https://about.gitlab.com/
X-Content-Type-Options: (header absent from response)
```

### Missing Permissions-Policy Header

**Low** · CWE-16 · CVSS 2.4 · WSTG-CONF-07 · Browser Feature Control

```
GET https://about.gitlab.com/
Permissions-Policy: (header absent from response)
```

### Missing Referrer-Policy Header

**Low** · CWE-200 · CVSS 3.1 · WSTG-CONF-07 · Information Disclosure

```
GET https://about.gitlab.com/
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
No DNSKEY records found for about.gitlab.com or gitlab.com (NOERROR (name exists)).
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://about.gitlab.com/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://about.gitlab.com/
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://about.gitlab.com/
Cross-Origin-Resource-Policy: (header absent from response)
```

### Missing security.txt (RFC 9116)

**Info** · CWE-205 · CVSS 0 · Information Disclosure

```
GET https://about.gitlab.com/.well-known/security.txt → HTTP 404
GET https://about.gitlab.com/security.txt → HTTP 404
```

