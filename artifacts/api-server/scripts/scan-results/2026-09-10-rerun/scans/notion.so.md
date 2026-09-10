# notion.so

- Requested: `https://www.notion.so`
- Final URL: `https://www.notion.com/`
- HTTP 200, 18 inner page(s) fetched, 27.1s
- 14 findings, 6 above Info
- Risk score 18/100 — grade B

### CSP Missing object-src 'none' Directive

**Medium** · CWE-79 · CVSS 4.3 · WSTG-CONF-12 · Injection Defense

```
GET https://www.notion.com/
Content-Security-Policy: script-src 'self' 'unsafe-inline' 'unsafe-eval' https://gist.github.com https://apis.google.com https://cdn.amplitude.com https://api.amplitude.com https://dev-embed.notion.co https://embed.notion.co https://static.zdassets.com https://api.smooch.io	 https://solve-widget.forethought.ai https://decagon.ai https://http-inputs-notion.splunkcloud.com https://*.sentry.io https://checkout.stripe.com https://js.stripe.com https://embed.typeform.com https://admin.typeform.com https://ucv.bynder.com https://js.sentry-cdn.com https://js.chilipiper.com
```

### Missing X-Content-Type-Options: nosniff

**Medium** · CWE-16 · CVSS 4.3 · WSTG-CONF-07 · Content Sniffing

```
GET https://www.notion.com/
X-Content-Type-Options: (header absent from response)
```

### Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)

**Medium** · CWE-79 · CVSS 5.4 · WSTG-CONF-12 · Injection Defense

```
GET https://www.notion.com/
Content-Security-Policy: script-src 'self' 'unsafe-inline' 'unsafe-eval' https://gist.github.com https://apis.google.com https://cdn.amplitude.com https://api.amplitude.com https://dev-embed.notion.co https://embed.notion.co https://static.zdassets.com https://api.smooch.io	 https://solve-widget.forethought.ai https://decagon.ai https://http-inputs-notion.splunkcloud.com https://*.sentry.io https://checkout.stripe.com https://js.stripe.com https://embed.typeform.com https://admin.typeform.com https://ucv.bynder.com https://js.sentry-cdn.com https://js.chilipiper.com
```

### CSP Missing base-uri Directive

**Low** · CWE-79 · CVSS 3.5 · WSTG-CONF-12 · Injection Defense

```
GET https://www.notion.com/
Content-Security-Policy: script-src 'self' 'unsafe-inline' 'unsafe-eval' https://gist.github.com https://apis.google.com https://cdn.amplitude.com https://api.amplitude.com https://dev-embed.notion.co https://embed.notion.co https://static.zdassets.com https://api.smooch.io	 https://solve-widget.forethought.ai https://decagon.ai https://http-inputs-notion.splunkcloud.com https://*.sentry.io https://checkout.stripe.com https://js.stripe.com https://embed.typeform.com https://admin.typeform.com https://ucv.bynder.com https://js.sentry-cdn.com https://js.chilipiper.com
```

### Missing Permissions-Policy Header

**Low** · CWE-16 · CVSS 2.4 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.notion.com/
Permissions-Policy: (header absent from response)
```

### Non-Session Cookie Missing Secure Flag

**Low** · CWE-614 · CVSS 3.1 · WSTG-SESS-02 · Session Management

```
Affected cookies: notion_browser_id, notion_check_cookie_consent
```

### Active security testing was skipped for this scan

**Info** · Scan Coverage

```
No verified ownership on record for this domain at scan time.
```

### DMARC Record Missing Aggregate Report Address (rua=)

**Info** · CWE-778 · Email Security

```
TXT record: v=DMARC1; p=reject
```

### Missing Cross-Origin-Embedder-Policy (COEP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.notion.com/
Cross-Origin-Embedder-Policy: (header absent from response)
```

### Missing Cross-Origin-Opener-Policy (COOP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.notion.com/
Cross-Origin-Opener-Policy: (header absent from response)
```

### Missing Cross-Origin-Resource-Policy (CORP)

**Info** · CWE-346 · WSTG-CONF-07 · Browser Feature Control

```
GET https://www.notion.com/
Cross-Origin-Resource-Policy: (header absent from response)
```

### Non-Session Cookie Missing SameSite Attribute

**Info** · CWE-352 · CVSS 2.1 · WSTG-SESS-02 · CSRF Protection

```
Affected cookies: notion_browser_id, notion_check_cookie_consent
```

### Non-Session Cookie Readable by JavaScript

**Info** · CWE-1004 · CVSS 2.6 · WSTG-SESS-02 · Session Management

```
Affected cookies: notion_browser_id, notion_check_cookie_consent
```

### X-Powered-By Header Discloses Technology Stack

**Info** · CWE-200 · WSTG-INFO-09 · Information Disclosure

```
GET https://www.notion.com/
X-Powered-By: Next.js
```

