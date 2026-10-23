# zoom.us

- Requested: `https://zoom.us`
- Final URL: `https://www.zoom.com/`
- HTTP 200, 21 inner page(s) fetched, 18.8s
- 17 findings, 7 above Info
- Risk score 37/100 — grade C

### Missing Content-Security-Policy (CSP)

**High** · CWE-79 · CVSS 7.2 · WSTG-CONF-12 · Injection Defense

```
GET https://www.zoom.com/
Content-Security-Policy: (header absent from response)
```

### External Resources Missing Subresource Integrity (SRI)

**Medium** · CWE-353 · CVSS 6.1 · WSTG-CONF-04 · Supply Chain Security

```
<script/link src="https://cdn.cookielaw.org/scripttemplates/otSDKStub.js" (no integrity= attribute)>
<script/link src="https://cdn.bc0a.com/autopilot/f00000000314502/autopilot_sdk.js" (no integrity= attribute)>
<script/link src="https://st1.zoom.us/homepage/20260908-1234/primary/dist/main.js" (no integrity= attribute)>
<script/link src="https://st1.zoom.us/homepage/20260908-1234/primary/dist/js/utilities/swiper-bundle.min.js" (no integrity= attribute)>
<script/link src="https://st1.zoom.us/homepage/20260908-1234/primary/dist/js/utilities/my-notes-video.js" (no integrity= attribute)>
```

### Missing Clickjacking Protection (X-Frame-Options)

**Medium** · CWE-1021 · CVSS 4.3 · WSTG-CLNT-09 · UI Security

```
GET https://www.zoom.com/
X-Frame-Options: (header absent)
CSP frame-ancestors: (not present in Content-Security-Policy)
```

### Missing X-Content-Type-Options: nosniff

**Medium** · CWE-16 · CVSS 4.3 · WSTG-CONF-07 · Content Sniffing

```
GET https://www.zoom.com/
X-Content-Type-Options: (header absent from response)
```

### Permissive CORS Policy (Wildcard Origin)

**Medium** · CWE-942 · CVSS 6.5 · WSTG-CONF-07 · CORS Misconfiguration

```
GET https://www.zoom.com/
Access-Control-Allow-Origin: *
```

### Missing Permissions-Policy Header

**Low** · CWE-16 · CVSS 2.4 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.zoom.com/
Permissions-Policy: (header absent from response)
```

### Missing Referrer-Policy Header

**Low** · CWE-200 · CVSS 3.1 · WSTG-CONF-07 · Information Disclosure

```
GET https://www.zoom.com/
Referrer-Policy: (header absent from response)
```

### Active security testing was skipped for this scan

**Info** · Scan Coverage

```
No verified ownership on record for this domain at scan time.
```

### API Key in Client Code (verify restrictions)

**Info** · CWE-798 · CVSS 0 · WSTG-CONF-04 · Exposed Secrets / Credentials

```
Source: inline <script> block
Match (redacted): apiKey...fbc'
Context: ...window.dataLayer = window.dataLayer || [];   window.__zoomCoveoConfig = {   userLocale: 'en-us',   apiKey: 'xxf1623479-48a6-4dce-8475-28e0b0720fbc',   coreScriptSrc: 'https://st1.zoom.us/homepage/2026...
```

### DNSSEC Not Enabled

**Info** · CWE-350 · DNS Security

```
No DNSKEY records found for www.zoom.com or zoom.com (NOERROR (name exists)).
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.zoom.com/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.zoom.com/
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing security.txt (RFC 9116)

**Info** · CWE-205 · CVSS 0 · Information Disclosure

```
GET https://www.zoom.com/.well-known/security.txt → HTTP 404
GET https://www.zoom.com/security.txt → HTTP 404
```

### Non-Session Cookie Readable by JavaScript on Inner Page

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
GET https://www.zoom.com/en/contact/contact-sales/
Set-Cookie: EPiStateMarker=true; path=/; secure
```

### Non-Session Cookie Readable by JavaScript on Inner Page

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
GET https://www.zoom.com/en/contact/contact-sales/
Set-Cookie: .EPiForm_BID=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; secure
```

### Non-Session Cookie Readable by JavaScript on Inner Page

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
GET https://www.zoom.com/en/contact/contact-sales/
Set-Cookie: .EPiForm_VisitorIdentifier=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; secure
```

### Non-Session Cookie Readable by JavaScript on Inner Page

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
GET https://www.zoom.com/en/products/virtual-meetings/
Set-Cookie: _zm_visitor_guid=fd40224a5778409aa1e64ad69de617b7; max-age=31536000; domain=.zoom.com; path=/; secure; samesite=none
```

